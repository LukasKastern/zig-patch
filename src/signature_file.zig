const std = @import("std");

const BlockHash = @import("block.zig").BlockHash;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const WeakHashType = @import("block.zig").WeakHashType;
const ProgressCallback = @import("operations.zig").ProgressCallback;

pub const SignatureBlock = struct {
    file_idx: u32,
    block_idx: u32,
    hash: BlockHash,
};

pub const SignatureFile = struct {
    const Directory = struct {
        path: []u8,
        permissions: u8,
    };

    const SymLink = struct {
        source: []u8,
        target: []u8,
        permissions: u8,
    };

    pub const File = struct {
        name: []const u8,
        size: usize,
        permissions: u8,
    };

    allocator: std.mem.Allocator,
    directories: std.ArrayList(Directory),
    sym_links: std.ArrayList(SymLink),
    files: std.ArrayList(File),
    blocks: std.ArrayList(SignatureBlock),
    path_name_buffer: [512]u8 = undefined,

    // We reserve this buffer for signature file related allocations.
    signature_file_allocator: std.heap.StackFallbackAllocator(1024 * 1024 * 8),

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.signature_file_allocator.fallback_allocator = allocator;
        signature_file.allocator = signature_file.signature_file_allocator.get();
        signature_file.files = std.ArrayList(File).init(signature_file.allocator);
        signature_file.directories = std.ArrayList(Directory).init(signature_file.allocator);
        signature_file.sym_links = std.ArrayList(SymLink).init(signature_file.allocator);
        signature_file.blocks = std.ArrayList(SignatureBlock).init(signature_file.allocator);
        return signature_file;
    }

    fn deallocateBuffers(self: *SignatureFile) void {
        for (self.directories.items) |directory| {
            self.allocator.free(directory.path);
        }

        for (self.files.items) |file| {
            self.allocator.free(file.name);
        }

        self.sym_links.clearRetainingCapacity();
        self.directories.clearRetainingCapacity();
        self.files.clearRetainingCapacity();
        self.blocks.clearRetainingCapacity();
    }

    pub fn deinit(self: *SignatureFile) void {
        self.deallocateBuffers();

        self.files.deinit();
        self.sym_links.deinit();
        self.blocks.deinit();
        self.directories.deinit();

        self.signature_file_allocator.fallback_allocator.destroy(self);
    }

    const CalculateHashData = struct {

        // We schedule our work in Batches that attempt to process this amount of blocks at once.
        // This tries to strike a balance between repeated open/write/reads of files and the cost of hashing the content.
        const BlocksPerBatchOfWork = 4;

        task: ThreadPool.Task,
        blocks: *std.atomic.Atomic(usize),
        are_batches_done: *std.atomic.Atomic(u32),
        file_idx: u32,
        batch_in_file: usize,
        signature_file: *SignatureFile,
        dir: std.fs.Dir,

        out_hashes: [CalculateHashData.BlocksPerBatchOfWork]BlockHash,
        num_processed_blocks: usize,

        const Self = @This();

        fn calculate_hash(task: *ThreadPool.Task) void {
            var calculate_hash_data_task = @fieldParentPtr(Self, "task", task);
            calculate_hash_impl(calculate_hash_data_task) catch unreachable;
        }

        fn calculate_hash_impl(self: *Self) !void {
            const signature_file = self.signature_file.files.items[self.file_idx];

            const start_block_idx = self.batch_in_file * CalculateHashData.BlocksPerBatchOfWork;
            const read_offset = start_block_idx * BlockSize;

            var file = try self.dir.openFile(signature_file.name, .{});
            defer file.close();

            var buffer: [BlockSize * CalculateHashData.BlocksPerBatchOfWork]u8 = undefined;
            try file.seekTo(read_offset);
            var read_bytes = try file.read(&buffer);

            std.debug.assert(read_bytes > 0);

            var processed_blocks: u32 = 0;
            while (processed_blocks < CalculateHashData.BlocksPerBatchOfWork) : (processed_blocks += 1) {
                const block_start_idx_in_buffer = processed_blocks * BlockSize;
                var remaining_bytes = read_bytes - block_start_idx_in_buffer;

                var block_data = buffer[block_start_idx_in_buffer .. block_start_idx_in_buffer + @min(BlockSize, remaining_bytes)];

                var rolling_hash: RollingHash = .{};
                rolling_hash.recompute(block_data);

                self.out_hashes[processed_blocks].weak_hash = rolling_hash.hash;

                std.crypto.hash.Md5.hash(block_data, &self.out_hashes[processed_blocks].strong_hash, .{});

                // var signature_block: SignatureBlock = .{ .file_idx = self.file_idx, .block_idx = start_block_idx + processed_blocks, .hash = block_hash };

                // hashes.appendAssumeCapacity(signature_block);

                // If this was the last block break out of the batch.
                if (remaining_bytes <= BlockSize) {
                    break;
                }
            }

            self.num_processed_blocks = processed_blocks + 1;

            if (self.blocks.fetchSub(1, .Release) == 1) {
                self.are_batches_done.store(1, .Release);
                std.Thread.Futex.wake(self.are_batches_done, 1);
            }
        }
    };

    pub fn generateFromFolder(self: *SignatureFile, dir: std.fs.Dir, thread_pool: *ThreadPool, on_progress: ?ProgressCallback) !void {
        self.deallocateBuffers();

        var root_dir = dir;

        var empty_path: [0]u8 = undefined;

        try self.generateFromFolderImpl(root_dir, &empty_path);

        var num_batches_of_work: usize = 0;
        var num_blocks: usize = 0;

        for (self.files.items) |signature_file| {
            if (signature_file.size == 0) {
                continue;
            }

            var blocks_in_file = @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(signature_file.size)) / BlockSize)));
            num_blocks += blocks_in_file;

            num_batches_of_work += blocks_in_file / CalculateHashData.BlocksPerBatchOfWork;

            if (blocks_in_file % CalculateHashData.BlocksPerBatchOfWork != 0) {
                num_batches_of_work += 1;
            }
        }

        var batches_remaining = std.atomic.Atomic(usize).init(num_batches_of_work);
        var are_batches_done = std.atomic.Atomic(u32).init(0);

        var tasks = try self.allocator.alloc(CalculateHashData, num_batches_of_work);
        defer self.allocator.free(tasks);

        var batch = ThreadPool.Batch{};
        var file_idx: u32 = 0;

        var batch_in_file: u32 = 0;
        var batch_idx: u32 = 0;

        while (batch_idx < num_batches_of_work) : (batch_idx += 1) {
            if (@as(usize, @intCast(batch_in_file)) * BlockSize * CalculateHashData.BlocksPerBatchOfWork >= self.files.items[file_idx].size) {
                file_idx += 1;
                batch_in_file = 0;
            }

            while (self.files.items[file_idx].size == 0) {
                file_idx += 1;
            }

            var current_file = self.files.items[file_idx];

            std.debug.assert(current_file.size > 0);

            tasks[batch_idx] = CalculateHashData{
                .task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash },
                .blocks = &batches_remaining,
                .are_batches_done = &are_batches_done,
                .file_idx = file_idx,
                .batch_in_file = batch_in_file,
                .signature_file = self,
                .num_processed_blocks = 0,
                .dir = root_dir,
                .out_hashes = undefined,
            };

            batch.push(ThreadPool.Batch.from(&tasks[batch_idx].task));

            batch_in_file += 1;
        }

        thread_pool.schedule(batch);

        try self.blocks.ensureTotalCapacity(num_blocks);

        var num_batches_remaining = batches_remaining.load(.Acquire);
        while (num_batches_remaining > 0 and are_batches_done.load(.Acquire) == 0) {
            if (on_progress) |progress_callback_unwrapped| {
                var elapsed_progress = (1.0 - @as(f32, @floatFromInt(num_batches_remaining)) / @as(f32, @floatFromInt(num_batches_of_work))) * 100;
                progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Hashing Blocks");
            }

            std.time.sleep(std.time.ns_per_ms * 100);
            num_batches_remaining = batches_remaining.load(.Acquire);
        }

        for (tasks) |calculate_hash_data| {
            const start_block_idx = calculate_hash_data.batch_in_file * CalculateHashData.BlocksPerBatchOfWork;

            for (calculate_hash_data.out_hashes[0..calculate_hash_data.num_processed_blocks], 0..) |hash, idx| {
                self.blocks.appendAssumeCapacity(.{ .file_idx = calculate_hash_data.file_idx, .block_idx = @as(u32, @intCast(start_block_idx)) + @as(u32, @intCast(idx)), .hash = hash });
            }
        }

        std.log.info("Blocks are done", .{});
    }

    fn generateFromFolderImpl(self: *SignatureFile, directory: std.fs.Dir, parent_path: []u8) !void {
        var iteratable_dir = try directory.makeOpenPathIterable("", .{});
        defer iteratable_dir.close();

        var iterator = iteratable_dir.iterate();

        while (try iterator.next()) |entry| {
            var full_entry_name = try directory.realpath(entry.name, &self.path_name_buffer);

            var entry_path: []u8 = undefined;

            if (parent_path.len > 0) {
                entry_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ parent_path, entry.name });
            } else {
                entry_path = try std.fmt.allocPrint(self.allocator, "{s}", .{entry.name});
            }

            switch (entry.kind) {
                .directory => {
                    var nested_dir = try directory.openDir(entry.name, .{});
                    defer nested_dir.close();

                    try self.generateFromFolderImpl(nested_dir, entry_path);
                    try self.directories.append(.{ .path = entry_path, .permissions = 0 });
                },
                .file => {
                    var file = try directory.openFile(entry.name, .{});
                    defer file.close();

                    try self.files.append(.{ .name = entry_path, .size = try file.getEndPos(), .permissions = 0 });
                },
                else => {
                    std.log.warn("Found unsupported file type={}, at path={s}", .{ entry.kind, full_entry_name });
                },
            }
        }
    }

    pub fn validateFolderMatchesSignature(self: *SignatureFile, reference_folder: std.fs.Dir) bool {
        for (self.directories.items) |directory| {
            reference_folder.access(directory.path, .{}) catch |e| {
                switch (e) {
                    else => return false,
                }
            };
        }

        for (self.files.items) |file| {
            reference_folder.access(file.name, .{}) catch |e| {
                switch (e) {
                    else => return false,
                }
            };
        }

        //TODO: Validate that all blocks match

        return true;
    }

    const SerializationVersion = 4;
    const TypeTag = "SignatureFile";
    const Endian = std.builtin.Endian.Big;

    pub fn saveSignature(self: *SignatureFile, writer: anytype) !void {
        try writer.writeInt(usize, TypeTag.len, Endian);
        try writer.writeAll(TypeTag);
        try writer.writeInt(usize, SerializationVersion, Endian);

        try writer.writeInt(usize, self.directories.items.len, Endian);
        for (self.directories.items) |directory| {
            // Write Length of the path
            try writer.writeInt(usize, directory.path.len, Endian);
            try writer.writeAll(directory.path);

            try writer.writeInt(u8, directory.permissions, Endian);
        }

        try writer.writeInt(usize, self.files.items.len, Endian);
        for (self.files.items) |signature_file| {
            // Write Length of the path
            try writer.writeInt(usize, signature_file.name.len, Endian);
            try writer.writeAll(signature_file.name);

            try writer.writeInt(usize, signature_file.size, Endian);
            try writer.writeInt(u8, signature_file.permissions, Endian);
        }

        try writer.writeInt(usize, self.blocks.items.len, Endian);
        for (self.blocks.items) |block| {
            try writer.writeInt(u32, block.file_idx, Endian);
            try writer.writeInt(u32, block.block_idx, Endian);
            try writer.writeInt(WeakHashType, block.hash.weak_hash, Endian);
            try writer.writeAll(&block.hash.strong_hash);
        }
    }

    pub fn loadSignature(reader: anytype, allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try SignatureFile.init(allocator);
        errdefer signature_file.deinit();

        // var out_file = try std.fs.openFileAbsolute(target_path, .{});
        // defer out_file.close();

        // const BufferedFileReader = std.io.BufferedReader(1200, std.fs.File.Reader);
        // var buffered_file_reader: BufferedFileReader = .{
        //     .unbuffered_reader = out_file.reader(),
        // };
        // var reader = buffered_file_reader.reader();

        var read_buffer: [1028]u8 = undefined;

        var type_tag_len = try reader.readInt(usize, Endian);

        try reader.readNoEof(read_buffer[0..type_tag_len]);

        if (!std.mem.eql(u8, TypeTag, read_buffer[0..type_tag_len])) {
            return error.FileTypeTagMismatch;
        }

        var version = try reader.readInt(usize, Endian);

        if (version != SerializationVersion) {
            return error.SerializationVersionMismatch;
        }

        const num_directories = try reader.readInt(usize, Endian);
        try signature_file.directories.resize(num_directories);

        var total_allocated_len: usize = 0;
        for (signature_file.directories.items) |*directory| {
            const path_length = try reader.readInt(usize, Endian);

            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            directory.path = path_buffer;

            directory.permissions = try reader.readInt(u8, Endian);
        }

        const num_files = try reader.readInt(usize, Endian);
        try signature_file.files.resize(num_files);

        for (signature_file.files.items) |*file| {
            const path_length = try reader.readInt(usize, Endian);

            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            file.name = path_buffer;
            file.size = try reader.readInt(usize, Endian);
            file.permissions = try reader.readInt(u8, Endian);
        }

        std.log.info("len={}", .{total_allocated_len});
        const num_blocks = try reader.readInt(usize, Endian);
        try signature_file.blocks.resize(num_blocks);

        for (signature_file.blocks.items) |*block| {
            block.file_idx = try reader.readInt(u32, Endian);
            block.block_idx = try reader.readInt(u32, Endian);
            block.hash.weak_hash = try reader.readInt(WeakHashType, Endian);
            try reader.readNoEof(&block.hash.strong_hash);
        }

        return signature_file;
    }
};

test "signature file should be same after serialization/deserialization" {
    var signature_file = try SignatureFile.init(std.testing.allocator);
    defer signature_file.deinit();

    var file_name_a = try std.testing.allocator.alloc(u8, "a.data".len);
    std.mem.copy(u8, file_name_a, "a.data");

    var file_name_b = try std.testing.allocator.alloc(u8, "b.data".len);
    std.mem.copy(u8, file_name_b, "b.data");

    try signature_file.files.append(.{
        .name = file_name_a,
        .size = BlockSize * 2,
        .permissions = 45,
    });
    try signature_file.files.append(.{
        .name = file_name_b,
        .size = BlockSize * 4,
        .permissions = 20,
    });

    var dir_name_a = try std.testing.allocator.alloc(u8, "directory_a".len);
    std.mem.copy(u8, dir_name_a, "directory_a");

    var dir_name_b = try std.testing.allocator.alloc(u8, "directory_b".len);
    std.mem.copy(u8, dir_name_b, "directory_b");

    try signature_file.directories.append(.{
        .path = dir_name_a,
        .permissions = 64,
    });
    try signature_file.directories.append(.{
        .path = dir_name_b,
        .permissions = 5,
    });

    var hashes: [6]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 35, 1, 46, 21, 84, 231, 1, 45, 0, 1, 154, 21, 84, 154, 1, 85 },
    };

    hashes[1] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 78, 1, 99, 21, 84, 1, 33, 45, 120, 1, 54, 21, 84, 154, 1, 5 },
    };

    hashes[2] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 32, 1, 54, 21, 84, 57, 1, 67, 84, 1, 64, 21, 84, 54, 1, 45 },
    };

    hashes[3] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 5, 1, 245, 21, 84, 231, 154, 45, 120, 1, 154, 21, 84, 154, 1, 235 },
    };

    hashes[4] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 46, 76, 56, 21, 84, 57, 54, 45, 21, 1, 64, 21, 84, 57, 1, 47 },
    };

    hashes[5] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 123, 1, 123, 21, 78, 50, 54, 45, 81, 1, 54, 21, 84, 47, 1, 47 },
    };

    var signature_blocks: [6]SignatureBlock = undefined;
    signature_blocks[0] = .{ .file_idx = 5, .block_idx = 6, .hash = hashes[0] };
    signature_blocks[1] = .{ .file_idx = 6, .block_idx = 5, .hash = hashes[1] };
    signature_blocks[2] = .{ .file_idx = 7, .block_idx = 4, .hash = hashes[2] };
    signature_blocks[3] = .{ .file_idx = 8, .block_idx = 3, .hash = hashes[3] };
    signature_blocks[4] = .{ .file_idx = 9, .block_idx = 2, .hash = hashes[4] };
    signature_blocks[5] = .{ .file_idx = 10, .block_idx = 1, .hash = hashes[5] };

    try signature_file.blocks.appendSlice(&signature_blocks);

    var buffer: [1200]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    var writer = stream.writer();
    try signature_file.saveSignature(writer);

    try stream.seekTo(0);
    var reader = stream.reader();

    var deserialized_signature_file = try SignatureFile.loadSignature(reader, std.testing.allocator);
    defer deserialized_signature_file.deinit();

    try std.testing.expectEqual(signature_file.directories.items.len, deserialized_signature_file.directories.items.len);
    try std.testing.expectEqual(signature_file.files.items.len, deserialized_signature_file.files.items.len);
    try std.testing.expectEqual(signature_file.blocks.items.len, deserialized_signature_file.blocks.items.len);

    for (signature_file.directories.items, 0..) |directory, idx| {
        try std.testing.expectEqual(directory.permissions, deserialized_signature_file.directories.items[idx].permissions);
        try std.testing.expectEqualSlices(u8, directory.path, deserialized_signature_file.directories.items[idx].path);
    }

    for (signature_file.files.items, 0..) |file, idx| {
        try std.testing.expectEqual(file.permissions, deserialized_signature_file.files.items[idx].permissions);
        try std.testing.expectEqualSlices(u8, file.name, deserialized_signature_file.files.items[idx].name);
    }

    for (signature_file.blocks.items, 0..) |block, idx| {
        try std.testing.expectEqual(block.file_idx, deserialized_signature_file.blocks.items[idx].file_idx);
        try std.testing.expectEqual(block.block_idx, deserialized_signature_file.blocks.items[idx].block_idx);

        try std.testing.expectEqual(block.hash.weak_hash, deserialized_signature_file.blocks.items[idx].hash.weak_hash);
        try std.testing.expectEqualSlices(u8, &block.hash.strong_hash, &deserialized_signature_file.blocks.items[idx].hash.strong_hash);
    }
}
