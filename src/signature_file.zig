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
        path: []u8,
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

    signature_file_data: ?SignatureFileData,
    blocks: std.ArrayList(SignatureBlock),

    // We reserve this buffer for signature file related allocations.
    signature_file_allocator: std.heap.StackFallbackAllocator(1024 * 1024 * 8),

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.signature_file_allocator.fallback_allocator = allocator;
        signature_file.allocator = signature_file.signature_file_allocator.get();
        signature_file.signature_file_data = null;
        signature_file.blocks = std.ArrayList(SignatureBlock).init(signature_file.allocator);
        return signature_file;
    }

    fn deallocateBuffers(self: *SignatureFile) void {
        if (self.signature_file_data) |signature_file_data| {
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

        self.signature_file_data = null;
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
        const BlocksPerBatchOfWork = 128;

        buffer: [BlockSize * CalculateHashData.BlocksPerBatchOfWork]u8,

        is_done: std.atomic.Atomic(u32),

        tasks_to_schedule: *ThreadPool.Batch,

        batch_in_file: usize,
        file_idx: usize,

        read_bytes: usize,

        task: ThreadPool.Task,

        out_hashes: [CalculateHashData.BlocksPerBatchOfWork]BlockHash,
        num_processed_blocks: usize,

        thread_pool: *ThreadPool,

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

                var block_data = self.buffer[block_start_idx_in_buffer .. block_start_idx_in_buffer + std.math.min(BlockSize, remaining_bytes)];

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

            self.is_done.store(1, .Release);

            // if (self.blocks.fetchSub(1, .Release) == 1) {
            //     self.are_batches_done.store(1, .Release);
            // }
        }
    };

    pub fn generateFromFolder(self: *SignatureFile, dir: []const u8, thread_pool: *ThreadPool, on_progress: ?ProgressCallback, patch_io: *PatchIO) !void {
        self.deallocateBuffers();

        var locked_folder = patch_io.lockDirectory(dir, self.allocator) catch {
            return error.SignatureFolderNotFound;
        };

        errdefer patch_io.unlockDirectory(locked_folder);

        self.signature_file_data = .{ .OnDiskSignatureFile = .{ .locked_directory = locked_folder, .io = patch_io.* } };

        var dir_handle = try std.fs.cwd().openDir(dir, .{});
        defer dir_handle.close();

        var num_batches_of_work: usize = 0;
        var num_blocks: usize = 0;

        for (locked_folder.files.items) |signature_file| {
            if (signature_file.size == 0) {
                continue;
            }

            var blocks_in_file = @floatToInt(usize, @ceil(@intToFloat(f64, signature_file.size) / BlockSize));
            num_blocks += blocks_in_file;

            num_batches_of_work += blocks_in_file / CalculateHashData.BlocksPerBatchOfWork;

            if (blocks_in_file % CalculateHashData.BlocksPerBatchOfWork != 0) {
                num_batches_of_work += 1;
            }
        }

        try self.blocks.ensureTotalCapacity(num_blocks);
        const num_parallel_buffers = 16;

        var tasks = try self.allocator.alloc(CalculateHashData, num_parallel_buffers);
        defer self.allocator.free(tasks);

        for (tasks) |*task| {
            task.thread_pool = thread_pool;
            task.task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash };
        }

        var available_task_slots = try std.ArrayList(usize).initCapacity(self.allocator, num_parallel_buffers);
        defer available_task_slots.deinit();

        for (0..num_parallel_buffers) |idx| {
            available_task_slots.appendAssumeCapacity(idx);
        }

        var next_batch_idx: usize = 0;

        var file_idx: u64 = 0;

        var batch_in_file: u64 = 0;

        var tasks_to_schedule: ThreadPool.Batch = .{};

        while (self.blocks.items.len != num_blocks) {
            if (on_progress) |progress_callback_unwrapped| {
                _ = progress_callback_unwrapped;
                // var elapsed_progress = (@intToFloat(f32, self.blocks.items.len) / @intToFloat(f32, num_blocks)) * 100;
                // progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Hashing Blocks");
            }

            // Tick PatchIO to populate any newly populated buffers
            patch_io.tick(10);

            // We have buffers to read into available.
            while (next_batch_idx < num_batches_of_work and available_task_slots.items.len > 0) {
                var slot_idx = available_task_slots.orderedRemove(available_task_slots.items.len - 1);
                var task = &tasks[slot_idx];

                if (@intCast(usize, batch_in_file) * BlockSize * CalculateHashData.BlocksPerBatchOfWork >= locked_folder.files.items[file_idx].size) {
                    file_idx += 1;
                    batch_in_file = 0;
                }

                while (locked_folder.files.items[file_idx].size == 0) {
                    file_idx += 1;
                }

                var current_file = locked_folder.files.items[file_idx];

                const IOCallbackWrapper = struct {
                    pub fn onReadComplete(ctx: *anyopaque) void {
                        var calculate_hash_data = @ptrCast(*CalculateHashData, @alignCast(@alignOf(*CalculateHashData), ctx));

                        var batch = ThreadPool.Batch.from(&calculate_hash_data.task);
                        calculate_hash_data.tasks_to_schedule.push(batch);
                    }
                };

                var remaining_len = current_file.size - @intCast(usize, batch_in_file) * BlockSize * CalculateHashData.BlocksPerBatchOfWork;
                var len_to_read = std.math.min(remaining_len, BlockSize * CalculateHashData.BlocksPerBatchOfWork);
                var read_offset = batch_in_file * BlockSize * CalculateHashData.BlocksPerBatchOfWork;

                task.tasks_to_schedule = &tasks_to_schedule;
                task.file_idx = file_idx;
                task.is_done = std.atomic.Atomic(u32).init(0);
                task.read_bytes = len_to_read;
                task.batch_in_file = batch_in_file;

                try patch_io.readFile(current_file, read_offset, task.buffer[0..len_to_read], IOCallbackWrapper.onReadComplete, task);
                next_batch_idx += 1;
                batch_in_file += 1;
            }

            if (tasks_to_schedule.len > 0) {
                thread_pool.schedule(tasks_to_schedule);
                tasks_to_schedule = .{};
            }

            for (tasks, 0..) |*task, idx| {
                if (task.is_done.load(.Acquire) == 1) {
                    const start_block_idx = task.batch_in_file * CalculateHashData.BlocksPerBatchOfWork;

                    var expected_num_processed_blocks = @floatToInt(usize, @ceil(@intToFloat(f64, task.read_bytes) / BlockSize));
                    std.debug.assert(expected_num_processed_blocks == task.num_processed_blocks);

                    for (task.out_hashes[0..task.num_processed_blocks], 0..) |hash, block_idx| {
                        self.blocks.appendAssumeCapacity(.{ .file_idx = @intCast(u32, task.file_idx), .block_idx = @intCast(u32, start_block_idx) + @intCast(u32, block_idx), .hash = hash });
                    }

                    available_task_slots.appendAssumeCapacity(idx);
                    task.is_done.store(0, .Release);
                }
            }
        }

        std.debug.assert(self.blocks.items.len == num_blocks);

        // while (batch_idx < num_batches_of_work) : (batch_idx += 1) {
        //     if (@intCast(usize, batch_in_file) * BlockSize * CalculateHashData.BlocksPerBatchOfWork >= locked_folder.files.items[file_idx].size) {
        //         file_idx += 1;
        //         batch_in_file = 0;
        //     }

        //     while (locked_folder.files.items[file_idx].size == 0) {
        //         file_idx += 1;
        //     }

        //     var current_file = locked_folder.files.items[file_idx];

        //     std.debug.assert(current_file.size > 0);

        //     tasks[batch_idx] = CalculateHashData{
        //         .task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash },
        //         .blocks = &batches_remaining,
        //         .are_batches_done = &are_batches_done,
        //         .file_idx = file_idx,
        //         .batch_in_file = batch_in_file,
        //         .signature_file = self,
        //         .num_processed_blocks = 0,
        //         .dir = dir_handle,
        //         .out_hashes = undefined,
        //     };

        //     batch.push(ThreadPool.Batch.from(&tasks[batch_idx].task));

        //     batch_in_file += 1;
        // }

        // thread_pool.schedule(batch);

        // try self.blocks.ensureTotalCapacity(num_blocks);

        // var num_batches_remaining = batches_remaining.load(.Acquire);
        // while (num_batches_remaining > 0 and are_batches_done.load(.Acquire) == 0) {
        //     if (on_progress) |progress_callback_unwrapped| {
        //         var elapsed_progress = (1.0 - @intToFloat(f32, num_batches_remaining) / @intToFloat(f32, num_batches_of_work)) * 100;
        //         progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Hashing Blocks");
        //     }

        //     std.time.sleep(std.time.ns_per_ms * 100);
        //     num_batches_remaining = batches_remaining.load(.Acquire);
        // }

        // for (tasks) |calculate_hash_data| {
        //     const start_block_idx = calculate_hash_data.batch_in_file * CalculateHashData.BlocksPerBatchOfWork;

        //     for (calculate_hash_data.out_hashes[0..calculate_hash_data.num_processed_blocks], 0..) |hash, idx| {
        //         self.blocks.appendAssumeCapacity(.{ .file_idx = calculate_hash_data.file_idx, .block_idx = @intCast(u32, start_block_idx) + @intCast(u32, idx), .hash = hash });
        //     }
        // }

        std.log.info("Blocks are done", .{});
    }

    pub fn validateFolderMatchesSignature(self: *SignatureFile, reference_folder: std.fs.Dir) bool {
        var in_memory_signature = self.signature_file_data.?.InMemorySignatureFile;

        for (in_memory_signature.directories.items) |directory| {
            reference_folder.access(directory.path, .{}) catch |e| {
                switch (e) {
                    else => return false,
                }
            };
        }

        for (in_memory_signature.files.items) |file| {
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

        var signature_file_data = self.signature_file_data.?.OnDiskSignatureFile;

        try writer.writeInt(usize, signature_file_data.locked_directory.directories.items.len, Endian);
        for (signature_file_data.locked_directory.directories.items) |directory| {
            var path = directory.resolvePath(signature_file_data.locked_directory);
            // Write Length of the path

            try writer.writeInt(usize, path.len, Endian);
            try writer.writeAll(path);
        }

        try writer.writeInt(usize, signature_file_data.locked_directory.files.items.len, Endian);
        for (signature_file_data.locked_directory.files.items) |signature_file| {
            // Write Length of the path
            var path = signature_file.resolvePath(signature_file_data.locked_directory);
            try writer.writeInt(usize, path.len, Endian);
            try writer.writeAll(path);

            try writer.writeInt(usize, signature_file.size, Endian);
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

        signature_file.signature_file_data = .{ .InMemorySignatureFile = .{
            .directories = try std.ArrayList(Directory).initCapacity(signature_file.allocator, num_directories),
            .files = undefined,
        } };

        var signature_data = &signature_file.signature_file_data.?.InMemorySignatureFile;

        var total_allocated_len: usize = 0;
        for (signature_data.directories.items) |*directory| {
            const path_length = try reader.readInt(usize, Endian);

            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            directory.path = path_buffer;
        }

        const num_files = try reader.readInt(usize, Endian);

        signature_data.files = try std.ArrayList(File).initCapacity(signature_file.allocator, num_files);

        for (signature_data.files.items) |*file| {
            const path_length = try reader.readInt(usize, Endian);

            total_allocated_len += path_length;
            var path_buffer = try signature_file.allocator.alloc(u8, path_length);
            errdefer signature_file.allocator.free(path_buffer);

            try reader.readNoEof(path_buffer[0..path_length]);
            file.name = path_buffer;
            file.size = try reader.readInt(usize, Endian);
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
    });
    try signature_file.files.append(.{
        .name = file_name_b,
        .size = BlockSize * 4,
    });

    var dir_name_a = try std.testing.allocator.alloc(u8, "directory_a".len);
    std.mem.copy(u8, dir_name_a, "directory_a");

    var dir_name_b = try std.testing.allocator.alloc(u8, "directory_b".len);
    std.mem.copy(u8, dir_name_b, "directory_b");

    try signature_file.directories.append(.{
        .path = dir_name_a,
    });
    try signature_file.directories.append(.{
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

    try std.testing.expectEqual(signature_file.directories.items.len, deserialized_signature_file.directories.items.len);
    try std.testing.expectEqual(signature_file.files.items.len, deserialized_signature_file.files.items.len);
    try std.testing.expectEqual(signature_file.blocks.items.len, deserialized_signature_file.blocks.items.len);

    for (signature_file.directories.items, 0..) |directory, idx| {
        try std.testing.expectEqualSlices(u8, directory.path, deserialized_signature_file.directories.items[idx].path);
    }

    for (signature_file.files.items, 0..) |file, idx| {
        try std.testing.expectEqualSlices(u8, file.name, deserialized_signature_file.files.items[idx].name);
    }

    for (signature_file.blocks.items, 0..) |block, idx| {
        try std.testing.expectEqual(block.file_idx, deserialized_signature_file.blocks.items[idx].file_idx);
        try std.testing.expectEqual(block.block_idx, deserialized_signature_file.blocks.items[idx].block_idx);

        try std.testing.expectEqual(block.hash.weak_hash, deserialized_signature_file.blocks.items[idx].hash.weak_hash);
        try std.testing.expectEqualSlices(u8, &block.hash.strong_hash, &deserialized_signature_file.blocks.items[idx].hash.strong_hash);
    }
}
