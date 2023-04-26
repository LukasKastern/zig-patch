const SignatureFile = @import("signature_file.zig").SignatureFile;
const BlockPatching = @import("block_patching.zig");
const std = @import("std");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const MaxDataOperationLength = @import("block_patching.zig").MaxDataOperationLength;
const PatchHeader = @import("patch_header.zig").PatchHeader;
const BlockSize = @import("block.zig").BlockSize;
const Compression = @import("compression/compression.zig").Compression;
const CreatePatchStats = @import("operations.zig").OperationStats.CreatePatchStats;
const ProgressCallback = @import("operations.zig").ProgressCallback;

const PatchFileInfo = struct {
    file_idx: usize,
    file_part_idx: usize,
};

const PatchFileData = struct {
    file_info: PatchFileInfo,
    operations: std.ArrayList(BlockPatching.PatchOperation),
};

const PatchFileIO = struct {
    const WritePatchFile = *const fn (patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void;
    const ReadPatchFile = *const fn (patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize;

    write_patch_file: WritePatchFile,
    read_patch_file: ReadPatchFile,
};

pub const DefaultMaxWorkUnitSize = BlockSize * 100;

const CreatePatchOptions = struct {
    max_work_unit_size: usize = DefaultMaxWorkUnitSize,
    staging_dir: std.fs.Dir,
    build_dir: std.fs.Dir,
};

const CreatePatchOperationsOptions = struct {
    patch_file_io: *PatchFileIO,
    create_patch_options: CreatePatchOptions,
};

fn ParallelList(comptime T: type) type {
    return struct {
        const Self = @This();

        per_thread_lists: []std.ArrayList(T),
        allocator: std.mem.Allocator,

        fn init(allocator: std.mem.Allocator, max_threads: usize) !Self {
            return initCapacity(allocator, max_threads, 0);
        }

        fn initCapacity(allocator: std.mem.Allocator, max_threads: usize, initial_capacity: usize) !Self {
            var self: Self = .{
                .allocator = allocator,
                .per_thread_lists = try allocator.alloc(std.ArrayList(T), max_threads),
            };

            for (self.per_thread_lists) |*list| {
                list.* = try std.ArrayList(T).initCapacity(allocator, initial_capacity);
            }

            return self;
        }

        fn deinit(self: *Self) void {
            for (self.per_thread_lists) |list| {
                list.deinit();
            }

            self.allocator.free(self.per_thread_lists);
        }

        fn getList(self: *Self, idx: usize) *std.ArrayList(T) {
            return &self.per_thread_lists[idx];
        }

        fn flattenParallelList(self: *Self, allocator: std.mem.Allocator) ![]T {
            var num_elements: usize = 0;

            for (self.per_thread_lists) |list| {
                num_elements += list.items.len;
            }

            var flattened_array = try allocator.alloc(T, num_elements);

            var idx: usize = 0;

            for (self.per_thread_lists) |list| {
                for (list.items) |list_element| {
                    flattened_array[idx] = list_element;
                    idx += 1;
                }
            }

            return flattened_array;
        }
    };
}

pub fn createPatch(thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOptions, stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
    const PerPatchPartStagingFolderIO = struct {
        file_io: PatchFileIO,
        staging_dir: std.fs.Dir,
        build_dir: std.fs.Dir,
        signature_file: *SignatureFile,
        max_work_unit_size: usize,
        fallback_allocator: std.mem.Allocator,

        operation_data: [][]u8,

        fn write(patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);

            var operation_data = self.operation_data[ThreadPool.Thread.current.?.idx];

            var file_name_buffer: [128]u8 = undefined;
            var name = std.fmt.bufPrint(&file_name_buffer, "File_{}_Part_{}", .{ patch_data.file_info.file_idx, patch_data.file_info.file_part_idx }) catch return error.WritePatchError;

            var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(operation_data);
            var operation_allocator = fixed_buffer_allocator.allocator();
            const serialized_data_op_size = 16;

            const max_operation_header_size = @ceil(@intToFloat(f32, self.max_work_unit_size) / BlockSize * serialized_data_op_size);
            const max_operation_output_size = self.max_work_unit_size + @floatToInt(usize, max_operation_header_size);

            var patch_operations_buffer = operation_allocator.alloc(u8, max_operation_output_size) catch unreachable;

            var fixed_buffer_stream = std.io.fixedBufferStream(patch_operations_buffer[0..]);
            var fixed_buffer_writer = fixed_buffer_stream.writer();

            // Serialize all operations into our fixed_memory_buffer.
            // We do not write them to the file directly since we first want to have the data go through our compression.
            BlockPatching.saveOperations(patch_data.operations, fixed_buffer_writer) catch unreachable;

            var deflating_stack_allocator = std.heap.stackFallback(DefaultMaxWorkUnitSize, self.fallback_allocator);
            var deflating_allocator = deflating_stack_allocator.get();

            var deflating = Compression.Deflating.init(Compression.Default, deflating_allocator) catch unreachable;
            defer deflating.deinit();

            var deflated_bufer = operation_allocator.alloc(u8, self.max_work_unit_size + 1024) catch unreachable;

            var deflated_data = deflating.deflateBuffer(fixed_buffer_stream.buffer[0..fixed_buffer_stream.pos], deflated_bufer) catch unreachable;

            var fs_file = self.staging_dir.createFile(name, .{}) catch unreachable;
            defer fs_file.close();

            fs_file.writeAll(deflated_data) catch unreachable;
        }

        fn read(patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);
            var file = self.signature_file.files.items[file_info.file_idx];

            var fs_file = self.build_dir.openFile(file.name, .{}) catch return error.ReadPatchError;
            defer fs_file.close();

            fs_file.seekTo(file_info.file_part_idx * self.max_work_unit_size) catch return error.ReadPatchError;

            return fs_file.read(read_buffer) catch return error.ReadPatchError;
        }
    };

    const per_thread_bytes = DefaultMaxWorkUnitSize * 3;

    var operation_data = try allocator.alloc(u8, thread_pool.num_threads * per_thread_bytes);
    defer allocator.free(operation_data);

    var per_thread_buffers = try allocator.alloc([]u8, thread_pool.num_threads);
    defer allocator.free(per_thread_buffers);

    for (per_thread_buffers, 0..) |*buffer, idx| {
        buffer.* = operation_data[idx * per_thread_bytes .. idx * per_thread_bytes + per_thread_bytes];
    }

    var staging_folder = options.staging_dir;

    // zig fmt: off
    var staging_folder_io: PerPatchPartStagingFolderIO = .{ 
        .signature_file = new_signature,
        // .allocator = allocator, 
        .file_io = .{
            .write_patch_file = &PerPatchPartStagingFolderIO.write,
            .read_patch_file = &PerPatchPartStagingFolderIO.read,
        }, 
        .build_dir = options.build_dir,
        .staging_dir = staging_folder,
        .max_work_unit_size = options.max_work_unit_size,
        .fallback_allocator = allocator,
        .operation_data = per_thread_buffers,
    };
    // zig fmt: on

    // To allow better parallization we split files up into batches of MaxWorkUnitSize.
    try createPerFilePatchOperations(thread_pool, new_signature, old_signature, allocator, .{ .patch_file_io = &staging_folder_io.file_io, .create_patch_options = options }, stats, progress_callback);

    // Once all the required operations have been generated we assemble the individual operations into one patch file.
    try assemblePatchFromFiles(new_signature, old_signature, staging_folder, allocator, options, stats, progress_callback);
}

fn numPatchFilesNeeded(signature: *SignatureFile, work_unit_size: usize) usize {
    var num_patch_files: usize = 0;

    for (signature.files.items) |file| {
        num_patch_files += @floatToInt(usize, @ceil(@intToFloat(f64, file.size) / @intToFloat(f64, work_unit_size)));
    }

    return num_patch_files;
}

fn numRealFilesInPatch(signature: *SignatureFile) usize {
    var num_patch_files: usize = 0;

    for (signature.files.items) |file| {
        if (file.size > 0) {
            num_patch_files += 1;
        }
    }

    return num_patch_files;
}

pub fn assemblePatchFromFiles(new_signature: *SignatureFile, old_signature: *SignatureFile, staging_dir: std.fs.Dir, allocator: std.mem.Allocator, options: CreatePatchOptions, stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
    var patch = try staging_dir.createFile("Patch.pwd", .{});
    defer patch.close();

    var patch_writer = patch.writer();

    var read_buffer = try allocator.alloc(u8, options.max_work_unit_size + 8096);
    defer allocator.free(read_buffer);

    var patch_file = try PatchHeader.init(new_signature, old_signature, allocator);
    defer patch_file.deinit();

    var num_files = numRealFilesInPatch(new_signature);
    try patch_file.sections.resize(num_files);

    try patch.seekTo(0);

    const BufferedFileWriter = std.io.BufferedWriter(1200, std.fs.File.Writer);
    var buffered_file_writer: BufferedFileWriter = .{
        .unbuffered_writer = patch_writer,
    };

    var buffered_writer = buffered_file_writer.writer();

    if (progress_callback) |progress_callback_unwrapped| {
        progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, 0.0, "Assembling Patch");
    }

    // Write the header once without the actual file data.
    // The file data will be populated in the loop below.
    // Once all the data is written we go back to the start of the file and write the proper data.
    try patch_file.savePatchHeader(buffered_writer);
    try buffered_file_writer.flush();

    var reserved_header_bytes = try patch.getPos();

    var offset_in_file: usize = reserved_header_bytes;

    var file_idx: usize = 0;
    var file_idx_in_patch: usize = 0;

    while (file_idx_in_patch < num_files) : (file_idx_in_patch += 1) {
        var file = new_signature.files.items[file_idx];

        if (progress_callback) |progress_callback_unwrapped| {
            var progress = @intToFloat(f32, file_idx_in_patch) / @intToFloat(f32, num_files);
            progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, progress * 100.0, "Assembling Patch");
        }

        while (file.size == 0) {
            file_idx += 1;

            if (file_idx == num_files)
                break;

            file = new_signature.files.items[file_idx];
        }

        var num_parts = @floatToInt(usize, @ceil(@intToFloat(f64, file.size) / @intToFloat(f64, options.max_work_unit_size)));

        patch_file.sections.items[file_idx_in_patch] = .{ .file_idx = file_idx, .operations_start_pos_in_file = offset_in_file };

        var num_patch_file: usize = 0;
        while (num_patch_file < num_parts) : (num_patch_file += 1) {
            var file_name_buffer: [128]u8 = undefined;
            var name = std.fmt.bufPrint(&file_name_buffer, "File_{}_Part_{}", .{ file_idx, num_patch_file }) catch return error.WritePatchError;

            var fs_part = staging_dir.openFile(name, .{}) catch |e| {
                switch (e) {
                    else => {
                        std.log.err("Failed to open patch file {s}, error {}", .{ file_name_buffer, e });
                        return error.FailedToOpenPatchFile;
                    },
                }
            };

            defer fs_part.close();

            var read_bytes = try fs_part.readAll(read_buffer);
            std.debug.assert(read_bytes == try fs_part.getEndPos());

            try buffered_writer.writeIntBig(usize, read_bytes);
            try buffered_writer.writeAll(read_buffer[0..read_bytes]);

            offset_in_file += read_bytes + @sizeOf(usize);
        }

        file_idx += 1;
    }

    try buffered_file_writer.flush();

    try patch.seekTo(0);
    try patch_file.savePatchHeader(buffered_writer);
    try buffered_file_writer.flush();

    if (try patch.getPos() != reserved_header_bytes) {
        return error.ReservedHeaderSizeMismatchesWrittenLen;
    }

    if (stats) |stats_unwrapped| {
        stats_unwrapped.total_patch_size_bytes = offset_in_file;
    }
}

const PerFileOperationData = struct {
    last_partial_block_backing_buffer: [BlockSize]u8,
    last_partial_block: ?[]u8,
    patch_operations: std.ArrayList(BlockPatching.PatchOperation),
};

pub fn createPerFilePatchOperations(thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOperationsOptions, patch_stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
    var anchored_block_map = try AnchoredBlocksMap.init(old_signature.*, allocator);
    defer anchored_block_map.deinit();

    _ = options;
    _ = patch_stats;
    _ = progress_callback;
    _ = thread_pool;
    _ = new_signature;

}

// pub fn createPerFilePatchOperations(thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOperationsOptions, patch_stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
//     var num_patch_files: usize = numPatchFilesNeeded(new_signature, options.create_patch_options.max_work_unit_size);

//     var anchored_block_map = try AnchoredBlocksMap.init(old_signature.*, allocator);
//     defer anchored_block_map.deinit();

//     const GeneratePatchTask = struct {
//         const Self = @This();

//         task: ThreadPool.Task,
//         file_info: PatchFileInfo,
//         new_signature_file: *SignatureFile,
//         old_signature_file: *SignatureFile,
//         are_patches_done: *std.atomic.Atomic(u32),
//         remaining_patches: *std.atomic.Atomic(usize),
//         io: *PatchFileIO,
//         block_map: *AnchoredBlocksMap,

//         per_thread_buffers: [][]u8,

//         per_thread_stats: ?[]PerThreadStats,

//         pub const PerThreadStats = struct {
//             changed_blocks: usize,
//             total_blocks: usize,
//             new_bytes: usize,
//         };

//         fn generatePatch(task: *ThreadPool.Task) void {
//             var generate_patch_task_data = @fieldParentPtr(Self, "task", task);
//             generatePatchImpl(generate_patch_task_data) catch |e| {
//                 std.log.err("Error occured while trying to generate path error={s}\n", .{@errorName(e)});
//                 unreachable;
//             };
//         }

//         fn generatePatchImpl(self: *Self) !void {
//             var buffer = self.per_thread_buffers[ThreadPool.Thread.current.?.idx];
//             var read_len = try self.io.read_patch_file(self.io, self.file_info, buffer);

//             if (read_len == 0) {
//                 return error.ReadingPatchFileFailed;
//             }

//             var patch_operations_buffer: [8000]u8 = undefined;
//             var patch_operation_fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&patch_operations_buffer);
//             var alloc = patch_operation_fixed_buffer_allocator.allocator();

//             var generated_operations = try BlockPatching.generateOperationsForBuffer(buffer[0..read_len], self.block_map.*, MaxDataOperationLength, alloc);

//             if (self.per_thread_stats) |per_thread_stats_unwrapped| {
//                 var thread_stats_data = &per_thread_stats_unwrapped[ThreadPool.Thread.current.?.idx];
//                 var changed_blocks = &thread_stats_data.changed_blocks;
//                 var total_blocks = &thread_stats_data.total_blocks;
//                 var new_bytes = &thread_stats_data.new_bytes;

//                 for (generated_operations.items) |operation| {
//                     switch (operation) {
//                         .Data => |data| {
//                             var blocks_in_data_op = @ceil(@intToFloat(f64, data.len) / @intToFloat(f64, BlockSize));
//                             // std.log.info("Data found in {} and part {}, blocks: {}", .{ self.file_info.file_idx, self.file_info.file_part_idx, blocks_in_data_op });
//                             changed_blocks.* += @floatToInt(usize, blocks_in_data_op);
//                             total_blocks.* += @floatToInt(usize, blocks_in_data_op);
//                             new_bytes.* += data.len;
//                         },
//                         .BlockRange => {
//                             total_blocks.* += operation.BlockRange.block_span;
//                         },
//                         else => {
//                             return error.UnexpectedOperation;
//                         },
//                     }
//                 }
//             }

//             try self.io.write_patch_file(self.io, .{
//                 .operations = generated_operations,
//                 .file_info = self.file_info,
//             });

//             if (self.remaining_patches.fetchSub(1, .Release) == 1) {
//                 self.are_patches_done.store(1, .Release);
//                 std.Thread.Futex.wake(self.are_patches_done, 1);
//             }
//         }
//     };

//     var tasks = try allocator.alloc(GeneratePatchTask, num_patch_files);
//     defer allocator.free(tasks);

//     var patches_remaining = std.atomic.Atomic(usize).init(num_patch_files);
//     var are_patches_done = std.atomic.Atomic(u32).init(0);

//     var per_thread_buffers = try allocator.alloc([]u8, thread_pool.num_threads);
//     defer allocator.free(per_thread_buffers);

//     for (per_thread_buffers) |*thread_buffer| {
//         thread_buffer.* = try allocator.alloc(u8, options.create_patch_options.max_work_unit_size);
//     }

//     defer {
//         for (per_thread_buffers) |thread_buffer| {
//             allocator.free(thread_buffer);
//         }
//     }

//     var per_thread_stats: ?[]GeneratePatchTask.PerThreadStats = null;

//     if (patch_stats != null) {
//         per_thread_stats = try allocator.alloc(GeneratePatchTask.PerThreadStats, thread_pool.num_threads);

//         for (per_thread_stats.?) |*stat| {
//             stat.* = .{
//                 .changed_blocks = 0,
//                 .total_blocks = 0,
//                 .new_bytes = 0,
//             };
//         }
//     }

//     defer {
//         if (per_thread_stats) |stats| {
//             allocator.free(stats);
//         }
//     }

//     var batch = ThreadPool.Batch{};

//     var part_idx: usize = 0;
//     var file_idx: usize = 0;
//     var patch_file_idx: usize = 0;
//     while (patch_file_idx < num_patch_files) : (patch_file_idx += 1) {
//         if (part_idx * options.create_patch_options.max_work_unit_size > new_signature.files.items[file_idx].size) {
//             part_idx = 0;
//             file_idx += 1;

//             while (new_signature.files.items[file_idx].size == 0) {
//                 file_idx += 1;
//             }
//         }

//         tasks[patch_file_idx] = .{
//             .task = ThreadPool.Task{ .callback = GeneratePatchTask.generatePatch },
//             .file_info = .{
//                 .file_idx = file_idx,
//                 .file_part_idx = part_idx,
//             },
//             .new_signature_file = new_signature,
//             .old_signature_file = old_signature,
//             .remaining_patches = &patches_remaining,
//             .are_patches_done = &are_patches_done,
//             .io = options.patch_file_io,
//             .per_thread_buffers = per_thread_buffers,
//             .block_map = anchored_block_map,
//             .per_thread_stats = per_thread_stats,
//         };

//         batch.push(ThreadPool.Batch.from(&tasks[patch_file_idx].task));

//         part_idx += 1;
//     }

//     thread_pool.schedule(batch);

//     var current_num_patches_remaining = patches_remaining.load(.Acquire);
//     while (current_num_patches_remaining != 0 and are_patches_done.load(.Acquire) == 0) {
//         if (progress_callback) |progress_callback_unwrapped| {
//             var elapsed_progress = (1.0 - @intToFloat(f32, current_num_patches_remaining) / @intToFloat(f32, num_patch_files)) * 100;
//             progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Generating Patches");
//         }

//         std.time.sleep(std.time.ns_per_ms * 100);
//         current_num_patches_remaining = patches_remaining.load(.Acquire);
//     }

//     if (per_thread_stats) |per_thread_stats_unwrapped| {
//         var stats = patch_stats.?;
//         for (per_thread_stats_unwrapped) |thread_stats| {
//             stats.changed_blocks += thread_stats.changed_blocks;
//             stats.total_blocks += thread_stats.total_blocks;
//             stats.num_new_bytes += thread_stats.new_bytes;
//         }
//     }
// }

test "two files with no previous signature should result in two data operation patches" {
    var old_signature = try SignatureFile.init(std.testing.allocator);
    defer old_signature.deinit();

    var new_signature = try SignatureFile.init(std.testing.allocator);
    defer new_signature.deinit();

    const file_size = 1200;

    try new_signature.files.append(.{
        .name = try std.testing.allocator.alloc(u8, 1),
        .size = file_size,
        .permissions = 0,
    });

    try new_signature.files.append(.{
        .name = try std.testing.allocator.alloc(u8, 1),
        .size = file_size,
        .permissions = 0,
    });

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    const PatchFileIOMock = struct {
        const MockedFileWriteData = struct {
            info: PatchFileInfo,
            operations: std.ArrayList(BlockPatching.PatchOperation),
        };

        file_io: PatchFileIO,

        patches: ParallelList(MockedFileWriteData),
        allocator: std.mem.Allocator,

        fn seedFromFileInfo(file_info: PatchFileInfo) usize {
            return (file_info.file_idx + 4) * file_info.file_idx + file_info.file_part_idx * 4;
        }

        fn write(patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);

            var mocked_write_data: MockedFileWriteData = .{
                .operations = std.ArrayList(BlockPatching.PatchOperation).initCapacity(self.allocator, patch_data.operations.items.len) catch unreachable,
                .info = patch_data.file_info,
            };

            for (patch_data.operations.items) |operation| {
                var copied_operation = operation;

                if (copied_operation == .Data) {
                    copied_operation = BlockPatching.PatchOperation{ .Data = self.allocator.alloc(u8, copied_operation.Data.len) catch unreachable };
                    std.mem.copy(u8, copied_operation.Data, operation.Data);
                }

                mocked_write_data.operations.appendAssumeCapacity(copied_operation);
            }

            var patch_list = self.patches.getList(ThreadPool.Thread.current.?.idx);
            patch_list.append(mocked_write_data) catch unreachable;
        }

        fn read(patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize {
            _ = patch_file_io;

            var prng = std.rand.DefaultPrng.init(seedFromFileInfo(file_info));
            var random = prng.random();

            var idx: usize = 0;
            while (idx < file_size) : (idx += 1) {
                read_buffer[idx] = random.int(u8);
            }

            return file_size;
        }
    };

    // zig fmt: off
    var io_mock: PatchFileIOMock = .{ 
        .allocator = std.testing.allocator, 
        .file_io = .{
            .write_patch_file = &PatchFileIOMock.write,
            .read_patch_file = &PatchFileIOMock.read,
        }, 
        .patches = try ParallelList(PatchFileIOMock.MockedFileWriteData).init(std.testing.allocator, thread_pool.max_threads) 
    };
    // zig fmt: on

    defer {
        for (io_mock.patches.per_thread_lists) |per_thread_list| {
            for (per_thread_list.items) |patch| {
                for (patch.operations.items) |operation| {
                    if (operation == .Data) {
                        io_mock.allocator.free(operation.Data);
                    }
                }

                patch.operations.deinit();
            }
        }

        io_mock.patches.deinit();
    }

    var create_patch_options: CreatePatchOptions = .{ .staging_dir = undefined, .build_dir = undefined };

    try createPerFilePatchOperations(&thread_pool, new_signature, old_signature, std.testing.allocator, .{ .patch_file_io = &io_mock.file_io, .create_patch_options = create_patch_options }, null, null);

    var patches = try io_mock.patches.flattenParallelList(std.testing.allocator);
    defer std.testing.allocator.free(patches);

    try std.testing.expectEqual(@as(usize, 2), patches.len);

    for (patches) |patch| {
        try std.testing.expectEqual(@as(usize, 1), patch.operations.items.len);

        var operation = patch.operations.items[0];

        try std.testing.expect(operation == .Data);

        var prng = std.rand.DefaultPrng.init(PatchFileIOMock.seedFromFileInfo(patch.info));
        var random = prng.random();

        var idx: usize = 0;
        while (idx < file_size) : (idx += 1) {
            try std.testing.expectEqual(random.int(u8), operation.Data[idx]);
        }
    }

    const ShutdownTaskData = struct {
        task: ThreadPool.Task,
        pool: *ThreadPool,

        fn shutdownThreadpool(task: *ThreadPool.Task) void {
            var shutdown_task_data = @fieldParentPtr(@This(), "task", task);
            shutdown_task_data.pool.shutdown();
        }
    };

    var shutdown_task_data = ShutdownTaskData{
        .task = ThreadPool.Task{ .callback = ShutdownTaskData.shutdownThreadpool },
        .pool = &thread_pool,
    };

    thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
    defer ThreadPool.deinit(&thread_pool);
}
