const std = @import("std");
const BlockHash = @import("block.zig").BlockHash;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const WeakHashType = @import("block.zig").WeakHashType;
const ProgressCallback = @import("operations.zig").ProgressCallback;

const PatchIO = @import("io/patch_io.zig");

pub const SignatureBlock = struct {
    file_idx: u32,
    block_idx: u32,
    hash: BlockHash,
};

pub const SignatureFile = struct {
    const Directory = struct {
        path: []const u8,
    };

    pub const File = struct {
        name: []const u8,
        size: usize,
    };

    const SignatureFileData = union(enum) {
        InMemorySignatureFile: struct {
            directories: std.ArrayList(Directory),
            files: std.ArrayList(File),
        },

        OnDiskSignatureFile: struct {
            io: PatchIO,
            locked_directory: PatchIO.LockedDirectory,
        },
    };

    allocator: std.mem.Allocator,

    data: ?SignatureFileData,
    blocks: std.ArrayList(SignatureBlock),

    // We reserve this buffer for signature file related allocations.
    signature_file_allocator: std.heap.StackFallbackAllocator(1024 * 1024 * 8),

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.signature_file_allocator.fallback_allocator = allocator;
        signature_file.allocator = signature_file.signature_file_allocator.get();
        signature_file.data = null;
        signature_file.blocks = std.ArrayList(SignatureBlock).init(signature_file.allocator);
        return signature_file;
    }

    pub fn numFiles(self: *SignatureFile) usize {
        if (self.data) |signature_file_data| {
            switch (signature_file_data) {
                .InMemorySignatureFile => |mem| return mem.files.items.len,
                .OnDiskSignatureFile => |on_disk| return on_disk.locked_directory.files.items.len,
            }
        } else {
            return 0;
        }
    }

    pub fn numDirectories(self: *const SignatureFile) usize {
        if (self.data) |signature_file_data| {
            switch (signature_file_data) {
                .InMemorySignatureFile => |mem| return mem.directories.items.len,
                .OnDiskSignatureFile => |on_disk| return on_disk.locked_directory.directories.items.len,
            }
        } else {
            return 0;
        }
    }

    pub fn getFile(self: *const SignatureFile, idx: usize) File {
        if (self.data) |signature_file_data| {
            switch (signature_file_data) {
                .InMemorySignatureFile => |mem| return mem.files.items[idx],
                .OnDiskSignatureFile => |on_disk| return .{
                    .size = on_disk.locked_directory.files.items[idx].size,
                    .name = on_disk.locked_directory.files.items[idx].resolvePath(on_disk.locked_directory),
                },
            }
        } else @panic("Idx out of bounds");
    }

    pub fn getDirectory(self: *const SignatureFile, idx: usize) Directory {
        if (self.data) |signature_file_data| {
            switch (signature_file_data) {
                .InMemorySignatureFile => |mem| return mem.directories.items[idx],
                .OnDiskSignatureFile => |on_disk| return .{
                    .path = on_disk.locked_directory.directories.items[idx].resolvePath(on_disk.locked_directory),
                },
            }
        } else @panic("Idx out of bounds");
    }

    fn deallocateBuffers(self: *SignatureFile) void {
        if (self.data) |signature_file_data| {
            switch (signature_file_data) {
                .InMemorySignatureFile => |*in_memory| {
                    for (in_memory.directories.items) |directory| {
                        self.allocator.free(directory.path);
                    }

                    for (in_memory.files.items) |file| {
                        self.allocator.free(file.name);
                    }

                    in_memory.files.deinit();
                    in_memory.directories.deinit();
                },
                .OnDiskSignatureFile => |*on_disk| {
                    on_disk.io.unlockDirectory(on_disk.locked_directory);
                },
            }
        }

        self.data = null;
        self.blocks.clearRetainingCapacity();
    }

    pub fn deinit(self: *SignatureFile) void {
        self.deallocateBuffers();

        self.blocks.deinit();
        self.signature_file_allocator.fallback_allocator.destroy(self);
    }

    const CalculateHashData = struct {

        // We schedule our work in Batches that attempt to process this amount of blocks at once.
        // This tries to strike a balance between repeated open/write/reads of files and the cost of hashing the content.
        const BlocksPerBatchOfWork = 2;

        buffer: []u8,

        is_done: *std.atomic.Atomic(u32),

        read_bytes: usize,

        task: ThreadPool.Task,

        out_hashes: [CalculateHashData.BlocksPerBatchOfWork]BlockHash,
        num_processed_blocks: usize,

        const Self = @This();

        fn calculate_hash(task: *ThreadPool.Task) void {
            var calculate_hash_data_task = @fieldParentPtr(Self, "task", task);
            calculate_hash_impl(calculate_hash_data_task) catch unreachable;
        }

        fn calculate_hash_impl(self: *Self) !void {
            std.debug.assert(self.read_bytes > 0);

            var processed_blocks: u32 = 0;
            while (processed_blocks < CalculateHashData.BlocksPerBatchOfWork) : (processed_blocks += 1) {
                const block_start_idx_in_buffer = processed_blocks * BlockSize;
                var remaining_bytes = self.read_bytes - block_start_idx_in_buffer;

                var block_data = self.buffer[block_start_idx_in_buffer .. block_start_idx_in_buffer + @min(BlockSize, remaining_bytes)];

                var rolling_hash: RollingHash = .{};
                rolling_hash.recompute(block_data);

                self.out_hashes[processed_blocks].weak_hash = rolling_hash.hash;

                std.crypto.hash.Md5.hash(block_data, &self.out_hashes[processed_blocks].strong_hash, .{});

                // If this was the last block break out of the batch.
                if (remaining_bytes <= BlockSize) {
                    break;
                }
            }

            self.num_processed_blocks = processed_blocks + 1;

            _ = self.is_done.fetchSub(1, .Release);
        }
    };

    pub fn generateFromFolder(self: *SignatureFile, dir: []const u8, thread_pool: *ThreadPool, on_progress: ?ProgressCallback, patch_io: *PatchIO) !void {
        self.deallocateBuffers();

        var locked_folder = patch_io.lockDirectory(dir, self.allocator) catch |e| {
            std.log.err("Failed to lock directory \"{s}\". Error: {s}", .{ dir, @errorName(e) });
            return error.SignatureFolderError;
        };

        errdefer patch_io.unlockDirectory(locked_folder);

        self.data = .{ .OnDiskSignatureFile = .{ .locked_directory = locked_folder, .io = patch_io.* } };

        var num_blocks: usize = 0;
        var num_total_read_batches: usize = 0;

        const read_buffer_size = BlockSize * CalculateHashData.BlocksPerBatchOfWork * 8;

        for (locked_folder.files.items) |signature_file| {
            if (signature_file.size == 0) {
                continue;
            }

            var blocks_in_file = @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(signature_file.size)) / BlockSize)));
            num_blocks += blocks_in_file;

            num_total_read_batches += signature_file.size / read_buffer_size;

            if (signature_file.size % read_buffer_size != 0) {
                num_total_read_batches += 1;
            }
        }

        try self.blocks.ensureTotalCapacity(num_blocks);

        var file_idx: u64 = 0;
        var batch_in_file: u64 = 0;

        const num_read_buffers = 4;

        const ReadBuffer = struct {
            buffer_data: [read_buffer_size]u8,
            is_reading: bool,
            read_start_time: i128,
            batch_in_file: usize,
            file_idx: usize,
            read_len: usize,
            thread_pool: *ThreadPool,
            is_calculating_hashes: bool,

            remaining_workers: std.atomic.Atomic(u32),

            tasks: [(read_buffer_size / (CalculateHashData.BlocksPerBatchOfWork * BlockSize))]CalculateHashData,
        };

        var read_buffers = try std.ArrayList(ReadBuffer).initCapacity(self.allocator, num_read_buffers);
        defer read_buffers.deinit();
        try read_buffers.resize(num_read_buffers);

        var available_read_buffers = try std.ArrayList(usize).initCapacity(self.allocator, num_read_buffers);
        defer available_read_buffers.deinit();

        for (0..num_read_buffers, read_buffers.items) |idx, *read_buffer| {
            available_read_buffers.appendAssumeCapacity(idx);

            read_buffer.is_reading = false;
            read_buffer.remaining_workers = std.atomic.Atomic(u32).init(0);
            read_buffer.thread_pool = thread_pool;
            read_buffer.is_calculating_hashes = false;

            for (&read_buffer.tasks, 0..) |*task, task_idx| {
                task.task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash };
                task.is_done = &read_buffer.remaining_workers;

                var byte_start_offset = CalculateHashData.BlocksPerBatchOfWork * BlockSize * task_idx;
                task.buffer = read_buffer.buffer_data[byte_start_offset .. byte_start_offset + BlockSize * CalculateHashData.BlocksPerBatchOfWork];
            }
        }

        var read_batch: usize = 0;

        const IOCallbackWrapper = struct {
            pub fn onReadComplete(ctx: *anyopaque) void {
                var read_buffer = @as(*ReadBuffer, @ptrCast(@alignCast(ctx)));

                const bytes_per_worker = CalculateHashData.BlocksPerBatchOfWork * BlockSize;
                var num_batches_to_schedule = read_buffer.read_len / bytes_per_worker;

                if (read_buffer.read_len % bytes_per_worker != 0) {
                    num_batches_to_schedule += 1;
                }

                var batch = ThreadPool.Batch{};

                var remaining_bytes = read_buffer.read_len;

                for (read_buffer.tasks[0..num_batches_to_schedule]) |*task| {
                    task.read_bytes = @min(remaining_bytes, bytes_per_worker);

                    if (remaining_bytes >= bytes_per_worker) {
                        remaining_bytes -= bytes_per_worker;
                    }

                    var task_batch = ThreadPool.Batch.from(&task.task);
                    batch.push(task_batch);
                }

                read_buffer.is_calculating_hashes = true;
                read_buffer.remaining_workers.store(@as(u32, @intCast(num_batches_to_schedule)), .Monotonic);
                read_buffer.thread_pool.schedule(batch);
            }
        };

        var time_since_last_progress_callback = std.time.nanoTimestamp();

        while (self.blocks.items.len != num_blocks) {
            while (available_read_buffers.items.len > 0 and read_batch < num_total_read_batches) {
                var read_buffer_idx = available_read_buffers.orderedRemove(available_read_buffers.items.len - 1);
                var read_buffer = &read_buffers.items[read_buffer_idx];

                if (@as(usize, @intCast(batch_in_file)) * read_buffer_size >= locked_folder.files.items[file_idx].size) {
                    file_idx += 1;
                    batch_in_file = 0;
                }

                while (locked_folder.files.items[file_idx].size == 0) {
                    file_idx += 1;
                }

                var current_file = locked_folder.files.items[file_idx];

                var remaining_len = current_file.size - @as(usize, @intCast(batch_in_file)) * read_buffer_size;
                var len_to_read = @min(remaining_len, read_buffer_size);
                var read_offset = batch_in_file * read_buffer_size;

                read_buffer.read_start_time = std.time.nanoTimestamp();
                read_buffer.is_reading = true;
                read_buffer.batch_in_file = batch_in_file;
                read_buffer.file_idx = file_idx;
                read_buffer.read_len = len_to_read;

                try patch_io.readFile(current_file.handle, read_offset, read_buffer.buffer_data[0..len_to_read], IOCallbackWrapper.onReadComplete, read_buffer);
                batch_in_file += 1;
                read_batch += 1;
            }

            patch_io.tick();

            for (read_buffers.items, 0..) |*read_buffer, idx| {
                if (read_buffer.is_calculating_hashes and read_buffer.remaining_workers.load(.Acquire) == 0) {
                    read_buffer.is_calculating_hashes = false;
                    available_read_buffers.appendAssumeCapacity(idx);

                    const bytes_per_worker = CalculateHashData.BlocksPerBatchOfWork * BlockSize;
                    var num_batches_to_schedule = read_buffer.read_len / bytes_per_worker;

                    if (read_buffer.read_len % bytes_per_worker != 0) {
                        num_batches_to_schedule += 1;
                    }

                    var block_offset = read_buffer.batch_in_file * (read_buffer_size / BlockSize);

                    for (read_buffer.tasks[0..num_batches_to_schedule]) |*task| {
                        for (task.out_hashes[0..task.num_processed_blocks]) |hash| {
                            self.blocks.appendAssumeCapacity(.{ .file_idx = @as(u32, @intCast(read_buffer.file_idx)), .block_idx = @as(u32, @intCast(block_offset)), .hash = hash });
                            block_offset += 1;
                        }
                    }
                }
            }

            if (on_progress) |progress_callback_unwrapped| {
                var now = std.time.nanoTimestamp();
                var elapsed_time = now - time_since_last_progress_callback;

                if (elapsed_time > 100 * std.time.ns_per_ms) {
                    time_since_last_progress_callback = now;
                    var elapsed_progress = (@as(f32, @floatFromInt(self.blocks.items.len)) / @as(f32, @floatFromInt(num_blocks))) * 100;
                    progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Hashing Blocks");
                }
            }
        }

        std.debug.assert(self.blocks.items.len == num_blocks);

        std.log.info("Blocks are done", .{});
    }

    pub fn validateFolderMatchesSignature(self: *SignatureFile, reference_folder: std.fs.Dir) bool {
        for (0..self.numDirectories()) |directory_idx| {
            var directory = self.getDirectory(directory_idx);
            reference_folder.access(directory.path, .{}) catch |e| {
                switch (e) {
                    else => return false,
                }
            };
        }

        for (0..self.numFiles()) |file_idx| {
            var file = self.getFile(file_idx);
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

        try writer.writeInt(usize, self.numDirectories(), Endian);
        for (0..self.numDirectories()) |directory_idx| {
            var directory = self.getDirectory(directory_idx);

            // Write Length of the path
            try writer.writeInt(usize, directory.path.len, Endian);
            try writer.writeAll(directory.path);
        }

        try writer.writeInt(usize, self.numFiles(), Endian);
        for (0..self.numFiles()) |file_idx| {
            var file = self.getFile(file_idx);

            // Write Length of the path
            var path = file.name;
            try writer.writeInt(usize, path.len, Endian);
            try writer.writeAll(path);

            try writer.writeInt(usize, file.size, Endian);
        }

        try writer.writeInt(usize, self.blocks.items.len, Endian);
        for (self.blocks.items) |block| {
            try writer.writeInt(u32, block.file_idx, Endian);
            try writer.writeInt(u32, block.block_idx, Endian);
            try writer.writeInt(WeakHashType, block.hash.weak_hash, Endian);
            try writer.writeAll(&block.hash.strong_hash);
        }
    }

    pub fn initializeToEmptyInMemoryFile(self: *SignatureFile) !void {
        self.deallocateBuffers();

        self.data = .{ .InMemorySignatureFile = .{
            .directories = std.ArrayList(Directory).init(self.allocator),
            .files = std.ArrayList(File).init(self.allocator),
        } };
    }

    pub fn loadSignature(reader: anytype, allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try SignatureFile.init(allocator);
        errdefer signature_file.deinit();

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

        signature_file.data = .{
            .InMemorySignatureFile = .{
                .directories = try std.ArrayList(Directory).initCapacity(signature_file.allocator, num_directories),
                .files = std.ArrayList(File).init(signature_file.allocator),
            },
        };

        var signature_data = &signature_file.data.?.InMemorySignatureFile;
        var total_allocated_len: usize = 0;

        for (0..num_directories) |_| {
            const path_length = try reader.readInt(usize, Endian);
            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            signature_file.data.?.InMemorySignatureFile.directories.appendAssumeCapacity(
                .{
                    .path = path_buffer,
                },
            );
        }

        const num_files = try reader.readInt(usize, Endian);

        try signature_data.files.resize(num_files);

        for (signature_data.files.items) |*file| {
            const path_length = try reader.readInt(usize, Endian);

            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            file.name = path_buffer;
            file.size = try reader.readInt(usize, Endian);
        }

        // std.log.info("len={}", .{total_allocated_len});
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

    try signature_file.initializeToEmptyInMemoryFile();

    var file_name_a = try std.testing.allocator.alloc(u8, "a.data".len);
    std.mem.copy(u8, file_name_a, "a.data");

    var file_name_b = try std.testing.allocator.alloc(u8, "b.data".len);
    std.mem.copy(u8, file_name_b, "b.data");

    _ = signature_file.numFiles();

    try signature_file.data.?.InMemorySignatureFile.files.append(.{
        .name = file_name_a,
        .size = BlockSize * 2,
    });
    try signature_file.data.?.InMemorySignatureFile.files.append(.{
        .name = file_name_b,
        .size = BlockSize * 4,
    });

    var dir_name_a = try std.testing.allocator.alloc(u8, "directory_a".len);
    std.mem.copy(u8, dir_name_a, "directory_a");

    var dir_name_b = try std.testing.allocator.alloc(u8, "directory_b".len);
    std.mem.copy(u8, dir_name_b, "directory_b");

    try signature_file.data.?.InMemorySignatureFile.directories.append(.{
        .path = dir_name_a,
    });
    try signature_file.data.?.InMemorySignatureFile.directories.append(.{
        .path = dir_name_b,
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

    try std.testing.expectEqual(signature_file.numDirectories(), deserialized_signature_file.numDirectories());
    try std.testing.expectEqual(signature_file.numFiles(), deserialized_signature_file.numFiles());
    try std.testing.expectEqual(signature_file.blocks.items.len, deserialized_signature_file.blocks.items.len);

    for (0..signature_file.numDirectories()) |idx| {
        var directory = signature_file.getDirectory(idx);
        try std.testing.expectEqualSlices(u8, directory.path, deserialized_signature_file.getDirectory(idx).path);
    }

    for (0..signature_file.numFiles()) |idx| {
        var file = signature_file.getFile(idx);
        try std.testing.expectEqualSlices(u8, file.name, deserialized_signature_file.getFile(idx).name);
    }

    for (signature_file.blocks.items, 0..) |block, idx| {
        try std.testing.expectEqual(block.file_idx, deserialized_signature_file.blocks.items[idx].file_idx);
        try std.testing.expectEqual(block.block_idx, deserialized_signature_file.blocks.items[idx].block_idx);

        try std.testing.expectEqual(block.hash.weak_hash, deserialized_signature_file.blocks.items[idx].hash.weak_hash);
        try std.testing.expectEqualSlices(u8, &block.hash.strong_hash, &deserialized_signature_file.blocks.items[idx].hash.strong_hash);
    }
}
