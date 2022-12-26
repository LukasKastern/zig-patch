const std = @import("std");
const BlockHash = @import("block.zig").BlockHash;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const WeakHashType = @import("block.zig").WeakHashType;

pub const SignatureBlock = struct {
    file_idx: usize,
    block_idx: usize,
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

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.allocator = allocator;
        signature_file.files = std.ArrayList(File).init(allocator);
        signature_file.directories = std.ArrayList(Directory).init(allocator);
        signature_file.sym_links = std.ArrayList(SymLink).init(allocator);
        signature_file.blocks = std.ArrayList(SignatureBlock).init(allocator);
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

        self.allocator.destroy(self);
    }

    const CalculateHashData = struct {
        task: ThreadPool.Task,
        block_idx: usize,
        blocks: *std.atomic.Atomic(usize),
        are_blocks_done: *std.atomic.Atomic(u32),
        file_idx: usize,
        block_idx_in_file: usize,
        signature_file: *SignatureFile,
        dir: std.fs.Dir,

        per_thread_block_hashes: std.ArrayList(std.ArrayList(SignatureBlock)),

        const Self = @This();

        fn calculate_hash(task: *ThreadPool.Task) void {
            var calculate_hash_data_task = @fieldParentPtr(Self, "task", task);
            calculate_hash_impl(calculate_hash_data_task) catch unreachable;
        }

        fn calculate_hash_impl(self: *Self) !void {
            const signature_file = self.signature_file.files.items[self.file_idx];
            const read_offset = self.block_idx_in_file * BlockSize;

            var file = try self.dir.openFile(signature_file.name, .{});
            defer file.close();

            var buffer: [BlockSize]u8 = undefined;
            try file.seekTo(read_offset);
            var read_bytes = try file.read(&buffer);

            var rolling_hash: RollingHash = .{};
            rolling_hash.recompute(buffer[0..read_bytes]);

            var block_hash: BlockHash = .{
                .weak_hash = rolling_hash.hash,
                .strong_hash = undefined,
            };

            std.crypto.hash.Md5.hash(buffer[0..read_bytes], &block_hash.strong_hash, .{});

            var signature_block: SignatureBlock = .{ .file_idx = self.file_idx, .block_idx = self.block_idx_in_file, .hash = block_hash };

            var thread_idx = ThreadPool.Thread.current.?.idx;
            var hashes = &self.per_thread_block_hashes.items[thread_idx];
            hashes.appendAssumeCapacity(signature_block);

            if (self.blocks.fetchSub(1, .Release) == 1) {
                self.are_blocks_done.store(1, .Release);
                std.Thread.Futex.wake(self.are_blocks_done, 1);
            }
        }
    };

    pub fn generateFromFolder(self: *SignatureFile, dir: std.fs.Dir, thread_pool: *ThreadPool) !void {
        self.deallocateBuffers();

        var root_dir = dir;

        var empty_path: [0]u8 = undefined;

        try self.generateFromFolderImpl(root_dir, &empty_path);

        var num_blocks: usize = 0;

        for (self.files.items) |signature_file| {
            num_blocks += @floatToInt(usize, @ceil(@intToFloat(f64, signature_file.size) / BlockSize));
        }

        var blocks_remaining = std.atomic.Atomic(usize).init(num_blocks);
        var are_blocks_done = std.atomic.Atomic(u32).init(0);

        var tasks = try self.allocator.alloc(CalculateHashData, num_blocks);
        defer self.allocator.free(tasks);

        var per_thread_block_hashes = std.ArrayList(std.ArrayList(SignatureBlock)).init(self.allocator);
        defer per_thread_block_hashes.deinit();

        try per_thread_block_hashes.resize(thread_pool.num_threads);
        for (per_thread_block_hashes.items) |*item| {
            item.* = try std.ArrayList(SignatureBlock).initCapacity(self.allocator, num_blocks);
        }

        defer {
            for (per_thread_block_hashes.items) |*item| {
                item.deinit();
            }
        }

        var batch = ThreadPool.Batch{};
        var file_idx: usize = 0;
        var block_idx_in_file: usize = 0;
        var block_idx: usize = 0;

        while (block_idx < num_blocks) : (block_idx += 1) {
            var current_file = self.files.items[file_idx];

            if (block_idx_in_file * BlockSize > current_file.size) {
                file_idx += 1;
                block_idx_in_file = 0;
            }

            tasks[block_idx] = CalculateHashData{
                .task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash },
                .block_idx = block_idx,
                .blocks = &blocks_remaining,
                .are_blocks_done = &are_blocks_done,

                .file_idx = file_idx,
                .block_idx_in_file = block_idx_in_file,
                .signature_file = self,
                .per_thread_block_hashes = per_thread_block_hashes,
                .dir = root_dir,
            };

            batch.push(ThreadPool.Batch.from(&tasks[block_idx].task));

            block_idx_in_file += 1;
        }

        thread_pool.schedule(batch);

        try self.blocks.ensureTotalCapacity(num_blocks);

        while (blocks_remaining.load(.Acquire) > 0 and are_blocks_done.load(.Acquire) == 0) {
            std.Thread.Futex.wait(&are_blocks_done, 0);
        }

        for (per_thread_block_hashes.items) |item| {
            self.blocks.appendSliceAssumeCapacity(item.items);
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
                .Directory => {
                    var nested_dir = try directory.openDir(entry.name, .{});
                    defer nested_dir.close();

                    try self.generateFromFolderImpl(nested_dir, entry_path);
                    try self.directories.append(.{ .path = entry_path, .permissions = 0 });
                },
                .File => {
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
            try writer.writeInt(usize, block.file_idx, Endian);
            try writer.writeInt(usize, block.block_idx, Endian);
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

        for (signature_file.directories.items) |*directory| {
            const path_length = try reader.readInt(usize, Endian);

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

            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            file.name = path_buffer;
            file.size = try reader.readInt(usize, Endian);
            file.permissions = try reader.readInt(u8, Endian);
        }

        const num_blocks = try reader.readInt(usize, Endian);
        try signature_file.blocks.resize(num_blocks);

        for (signature_file.blocks.items) |*block| {
            block.file_idx = try reader.readInt(usize, Endian);
            block.block_idx = try reader.readInt(usize, Endian);
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

    for (signature_file.directories.items) |directory, idx| {
        try std.testing.expectEqual(directory.permissions, deserialized_signature_file.directories.items[idx].permissions);
        try std.testing.expectEqualSlices(u8, directory.path, deserialized_signature_file.directories.items[idx].path);
    }

    for (signature_file.files.items) |file, idx| {
        try std.testing.expectEqual(file.permissions, deserialized_signature_file.files.items[idx].permissions);
        try std.testing.expectEqualSlices(u8, file.name, deserialized_signature_file.files.items[idx].name);
    }

    for (signature_file.blocks.items) |block, idx| {
        try std.testing.expectEqual(block.file_idx, deserialized_signature_file.blocks.items[idx].file_idx);
        try std.testing.expectEqual(block.block_idx, deserialized_signature_file.blocks.items[idx].block_idx);

        try std.testing.expectEqual(block.hash.weak_hash, deserialized_signature_file.blocks.items[idx].hash.weak_hash);
        try std.testing.expectEqualSlices(u8, &block.hash.strong_hash, &deserialized_signature_file.blocks.items[idx].hash.strong_hash);
    }
}
