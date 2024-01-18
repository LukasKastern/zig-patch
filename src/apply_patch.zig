const std = @import("std");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const FileSection = @import("patch_header.zig").FileSection;
const SignatureFile = @import("signature_file.zig").SignatureFile;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const PatchGeneration = @import("patch_generation.zig");
const BlockPatching = @import("block_patching.zig");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const AnchoredBlock = @import("anchored_blocks_map.zig").AnchoredBlock;
const BlockSize = @import("block.zig").BlockSize;
const Compression = @import("compression/compression.zig").Compression;
const ApplyPatchStats = @import("operations.zig").OperationStats.ApplyPatchStats;
const ProgressCallback = @import("operations.zig").ProgressCallback;
const PatchIO = @import("io/patch_io.zig");

pub fn createFileStructure(target_dir: std.fs.Dir, patch: *PatchHeader) !void {
    const old_signature = patch.old;
    const new_signature = patch.new;

    // Delete all files that do not exist anymore
    for (0..old_signature.numFiles()) |file_idx| {
        var file = old_signature.getFile(file_idx);

        var does_file_still_exist = false;

        for (0..new_signature.numFiles()) |new_signature_file_idx| {
            var new_signature_file = new_signature.getFile(new_signature_file_idx);
            does_file_still_exist = does_file_still_exist or std.mem.eql(u8, new_signature_file.name, file.name);
        }

        if (!does_file_still_exist) {
            try target_dir.deleteFile(file.name);
        }
    }

    // Delete all directories that do not exist anymore
    for (0..old_signature.numDirectories()) |directory_idx| {
        var directory = old_signature.getDirectory(directory_idx);
        var does_dir_still_exist = false;

        for (0..new_signature.numDirectories()) |new_directory_file_idx| {
            var new_directory_file = new_signature.getDirectory(new_directory_file_idx);

            does_dir_still_exist = does_dir_still_exist or std.mem.eql(u8, new_directory_file.path, directory.path);
        }

        if (!does_dir_still_exist) {
            //TODO: Should we check if the directory is empty (lukas)?
            try target_dir.deleteTree(directory.path);
        }
    }

    // Now reverse the order operation and create all directories + files that did not exist in the old signature
    for (0..new_signature.numDirectories()) |directory_idx| {
        var directory = new_signature.getDirectory(directory_idx);
        var did_dir_exist = false;

        for (0..old_signature.numDirectories()) |old_directory_file_idx| {
            var old_directory_file = old_signature.getDirectory(old_directory_file_idx);
            did_dir_exist = did_dir_exist or std.mem.eql(u8, old_directory_file.path, directory.path);
        }

        if (!did_dir_exist) {
            try target_dir.makePath(directory.path);
        }
    }

    for (0..new_signature.numFiles()) |file_idx| {
        var file = new_signature.getFile(file_idx);
        var did_file_exist = false;

        for (0..old_signature.numFiles()) |old_file_idx| {
            var old_file = old_signature.getFile(old_file_idx);
            did_file_exist = did_file_exist or std.mem.eql(u8, old_file.name, file.name);
        }

        if (!did_file_exist) {
            var new_file_fs = try target_dir.createFile(file.name, .{});
            new_file_fs.close();
        }
    }
}

const ApplyPatchTask = struct {
    const Self = @This();

    task: ThreadPool.Task,
    are_sections_done: *std.atomic.Atomic(u32),
    sections_remaining: *std.atomic.Atomic(usize),

    old_signature: *SignatureFile,
    anchored_blocks_map: *AnchoredBlocksMap,

    source_dir: ?std.fs.Dir,
    target_dir: std.fs.Dir,
    per_thread_patch_files: []std.fs.File,
    section: FileSection,
    file: SignatureFile.File,

    per_thread_operations_buffer: [][]u8,
    per_thread_read_buffers: [][]u8,

    per_thread_applied_bytes: []usize,

    fn applyPatch(task: *ThreadPool.Task) void {
        var apply_patch_task_data = @fieldParentPtr(Self, "task", task);
        applyPatchImpl(apply_patch_task_data) catch |e| {
            std.log.err("Error occurred while applying patch, error={s}", .{@errorName(e)});
            unreachable;
        };
    }

    fn applyPatchImpl(self: *Self) !void {
        var patch_file = self.per_thread_patch_files[ThreadPool.Thread.current.?.idx];

        try patch_file.seekTo(self.section.operations_start_pos_in_file);

        var operations_buffer = self.per_thread_operations_buffer[ThreadPool.Thread.current.?.idx];

        var num_patch_sections = @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(self.file.size)) / @as(f64, @floatFromInt(PatchGeneration.DefaultMaxWorkUnitSize)))));

        var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(operations_buffer);

        var file_reader = patch_file.reader();

        var target_file = try self.target_dir.openFile(self.file.name, .{
            .mode = .write_only,
        });

        defer target_file.close();
        try target_file.setEndPos(self.file.size);

        var target_file_writer = target_file.writer();

        var applied_bytes = &self.per_thread_applied_bytes[ThreadPool.Thread.current.?.idx];

        var patch_section_idx: usize = 0;
        while (patch_section_idx < num_patch_sections) : (patch_section_idx += 1) {
            fixed_buffer_allocator.reset();

            var operations_allocator = fixed_buffer_allocator.allocator();
            var compressed_section_size = try file_reader.readIntBig(usize);

            var compressed_data_buffer = try operations_allocator.alloc(u8, compressed_section_size);
            try file_reader.readNoEof(compressed_data_buffer);

            var inflating = try Compression.Infalting.init(Compression.Default, operations_allocator);
            defer inflating.deinit();

            var inflated_buffer = try operations_allocator.alloc(u8, PatchGeneration.DefaultMaxWorkUnitSize + 256);

            try inflating.inflateBuffer(compressed_data_buffer, inflated_buffer);

            var inflated_buffer_stream = std.io.fixedBufferStream(inflated_buffer);
            var inflated_reader = inflated_buffer_stream.reader();

            var operations = try BlockPatching.loadOperations(operations_allocator, inflated_reader);

            for (operations.items) |operation| {
                if (operation == .Data) {
                    try target_file_writer.writeAll(operation.Data);
                    applied_bytes.* += operation.Data.len;
                } else if (operation == .BlockRange) {
                    var block_range = operation.BlockRange;
                    var block = self.anchored_blocks_map.getBlock(block_range.file_index, block_range.block_index);

                    var old_signature_file_data = self.old_signature.data.?.InMemorySignatureFile;

                    var src_file = old_signature_file_data.files.items[block.file_index];
                    var file = try self.source_dir.?.openFile(src_file.name, .{});
                    defer file.close();

                    try file.seekTo(block_range.block_index * BlockSize);
                    var reader = file.reader();

                    var read_buffer = self.per_thread_read_buffers[ThreadPool.Thread.current.?.idx];
                    var read_bytes = read_buffer[0..(BlockSize - block.short_size)];

                    try reader.readNoEof(read_bytes);
                    try target_file_writer.writeAll(read_bytes);
                }
            }
        }

        if (self.sections_remaining.fetchSub(1, .Release) == 1) {
            self.are_sections_done.store(1, .Release);
            std.Thread.Futex.wake(self.are_sections_done, 1);
        }
    }
};

// pub fn applyPatch(working_dir: std.fs.Dir, source_dir: ?std.fs.Dir, target_dir: std.fs.Dir, patch_file_path: []const u8, patch: *PatchHeader, thread_pool: *ThreadPool, allocator: std.mem.Allocator, progress_callback: ?ProgressCallback, stats: ?*ApplyPatchStats) !void {
//     var per_thread_operations_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
//     defer allocator.free(per_thread_operations_buffer);

//     for (per_thread_operations_buffer) |*operations_buffer| {
//         operations_buffer.* = try allocator.alloc(u8, PatchGeneration.DefaultMaxWorkUnitSize * 6 + 8096);
//     }

//     defer {
//         for (per_thread_operations_buffer) |operations_buffer| {
//             allocator.free(operations_buffer);
//         }
//     }

//     var per_thread_read_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
//     defer allocator.free(per_thread_read_buffer);

//     for (per_thread_read_buffer) |*operations_buffer| {
//         operations_buffer.* = try allocator.alloc(u8, BlockSize);
//     }

//     defer {
//         for (per_thread_read_buffer) |operations_buffer| {
//             allocator.free(operations_buffer);
//         }
//     }

//     var per_thread_patch_files = try allocator.alloc(std.fs.File, thread_pool.max_threads);
//     defer allocator.free(per_thread_patch_files);

//     for (per_thread_patch_files) |*per_thread_patch_file| {
//         per_thread_patch_file.* = try working_dir.openFile(patch_file_path, .{});
//     }

//     defer {
//         for (per_thread_patch_files) |*per_thread_patch_file| {
//             per_thread_patch_file.close();
//         }
//     }

//     var per_thread_applied_bytes = try allocator.alloc(usize, thread_pool.max_threads);
//     defer allocator.free(per_thread_applied_bytes);

//     for (per_thread_applied_bytes) |*applied_bytes| {
//         applied_bytes.* = 0;
//     }

//     var tasks = try allocator.alloc(ApplyPatchTask, patch.sections.items.len);
//     defer allocator.free(tasks);

//     var anchored_blocks_map = try AnchoredBlocksMap.init(patch.old, allocator);
//     defer anchored_blocks_map.deinit();

//     var batch = ThreadPool.Batch{};

//     var sections_remaining = std.atomic.Atomic(usize).init(patch.sections.items.len);
//     var are_sections_done = std.atomic.Atomic(u32).init(0);

//     var task_idx: usize = 0;
//     while (task_idx < patch.sections.items.len) : (task_idx += 1) {
//         var section = patch.sections.items[task_idx];

//         tasks[task_idx] = .{
//             .per_thread_applied_bytes = per_thread_applied_bytes,
//             .per_thread_read_buffers = per_thread_read_buffer,
//             .old_signature = patch.old,
//             .anchored_blocks_map = anchored_blocks_map,
//             .source_dir = source_dir,
//             .per_thread_operations_buffer = per_thread_operations_buffer,
//             .section = patch.sections.items[task_idx],
//             .target_dir = target_dir,
//             .are_sections_done = &are_sections_done,
//             .sections_remaining = &sections_remaining,
//             .per_thread_patch_files = per_thread_patch_files,
//             .task = ThreadPool.Task{ .callback = ApplyPatchTask.applyPatch },
//             .file = patch.new.getFile(section.file_idx),
//         };

//         batch.push(ThreadPool.Batch.from(&tasks[task_idx].task));
//     }

//     thread_pool.schedule(batch);

//     var num_sections_remaining = sections_remaining.load(.acquire);
//     while (num_sections_remaining != 0 and are_sections_done.load(.acquire) == 0) {
//         if (progress_callback) |progress_callback_unwrapped| {
//             var elapsed_progress = (1.0 - @as(f32, @floatfromint(num_sections_remaining)) / @as(f32, @floatfromint(patch.sections.items.len))) * 100;
//             progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "merging patch sections");
//         }

//         std.time.sleep(std.time.ns_per_ms * 100);
//         num_sections_remaining = sections_remaining.load(.acquire);
//     }

//     if (stats) |stats_unwrapped| {
//         stats_unwrapped.total_patch_size_bytes = 0;

//         for (per_thread_applied_bytes) |applied_bytes| {
//             stats_unwrapped.total_patch_size_bytes += applied_bytes;
//         }
//     }
// }

pub fn applyPatch(
    working_dir: std.fs.Dir,
    source_dir: ?std.fs.Dir,
    target_dir: std.fs.Dir,
    patch_file_path: []const u8,
    patch: *PatchHeader,
    thread_pool: *ThreadPool,
    allocator: std.mem.Allocator,
    progress_callback: ?ProgressCallback,
    patch_io: *PatchIO,
    patch_file: std.fs.File,
    stats: ?*ApplyPatchStats,
) !void {
    _ = stats;
    _ = patch_io;
    _ = progress_callback;
    _ = patch_file_path;
    _ = target_dir;
    _ = source_dir;
    _ = working_dir;

    const DefaultMaxWorkUnitSize = BlockSize * 128;
    const MaxOperationOverhead = 1024;
    const MaxOperationOutputSize = DefaultMaxWorkUnitSize + MaxOperationOverhead;

    const PatchReadBuffer = struct {
        data: [DefaultMaxWorkUnitSize]u8,
        is_ready: bool,
        read_start_time: i128,
    };

    const WriteBuffer = struct {
        data: [DefaultMaxWorkUnitSize]u8,
        is_io_pending: bool,
    };
    _ = WriteBuffer;

    const ApplyPatchOperation = struct {
        const Self = @This();

        task: ThreadPool.Task,
        start_time: i128,

        patch_buffer: []u8,
        original_file_buffer: []u8,
        out_buffer: ?usize,

        last_read_block_in_original_file: usize,

        next_start_section: usize,

        has_active_task: std.atomic.Atomic(bool).init(false),

        fn applyPatchOperation(task: *ThreadPool.Task) void {
            var apply_patch_operation = @as(*Self, @ptrCast(task));
            _ = apply_patch_operation;
        }
    };

    // These values should probably be made part of the patch file

    _ = MaxOperationOutputSize;
    // const WriteBufferSize = MaxOperationOutputSize * 10;

    const num_read_buffers = thread_pool.num_threads * 2;
    var read_buffers = try allocator.alloc(PatchReadBuffer, num_read_buffers);
    defer allocator.free(read_buffers);

    var available_read_buffers = try std.ArrayList(usize).initCapacity(allocator, num_read_buffers);
    defer available_read_buffers.deinit();

    for (0..num_read_buffers) |idx| {
        available_read_buffers.appendAssumeCapacity(idx);
    }
    const max_simulatenous_apply_patch_operations = thread_pool.max_threads * 2;
    var operation_slots = try allocator.alloc(ApplyPatchOperation, max_simulatenous_apply_patch_operations);
    defer allocator.free(operation_slots);

    var available_operation_slots = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_apply_patch_operations);
    defer available_operation_slots.deinit();

    for (0..max_simulatenous_apply_patch_operations) |idx| {
        available_operation_slots.appendAssumeCapacity(idx);
    }

    var active_apply_patch_operations = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_apply_patch_operations);
    defer active_apply_patch_operations.deinit();

    var has_more_operations_to_complete = true;
    var min_next_file_idx = 0;
    var last_operation_section_idx_in_patch = 0;

    var patch_file_handle = patch_file.handle;
    _ = patch_file_handle;

    apply_patch_loop: while (true) {
        find_new_operations: while (has_more_operations_to_complete and available_operation_slots.items.len > 0) {
            var next_section = blk: {
                for (patch.sections.items[last_operation_section_idx_in_patch..]) |section| {
                    if (section.file_idx >= min_next_file_idx) {
                        break :blk section;
                    }
                }

                break :find_new_operations;
            };

            min_next_file_idx = next_section.file_idx + 1;

            var slot = available_operation_slots.orderedRemove(available_operation_slots.items.len - 1);
            active_apply_patch_operations.appendAssumeCapacity(slot);

            operation_slots[slot] = .{
                .task = .{
                    .callback = ApplyPatchTask.applyPatchTask,
                },
                .start_time = std.time.nanoTimestamp(),
            };
        }

        process_running_operations: for (active_apply_patch_operations.items) |apply_patch_operation_idx| {
            var apply_patch_operation = operation_slots[apply_patch_operation_idx];

            if (!apply_patch_operation.has_active_task.load(.Acquire)) {
                var current_section_idx = apply_patch_operation.next_start_section - 1;
                var current_section = patch.sections.items[current_section_idx];

                if (apply_patch_operation.patch_buffer == null) {
                    // Load the block we are gonna work on.
                    // patch_io.readFile()
                }

                var needs_to_read_from_original = current_section.first_block_taken_from_reference != ~@as(usize, 0);

                if (apply_patch_operation.original_file_buffer == null and needs_to_read_from_original) {
                    const start_block = @max(current_section.first_block_taken_from_reference, apply_patch_operation.last_read_block_in_original_file);
                    var blocks_to_read = current_section.last_block_taken_from_reference - start_block;

                    //TODO: Take this from somewhere
                    var read_buffer: []u8 = undefined;

                    // Don't read more blocks than we can fit into our read_buffer.
                    blocks_to_read = @min(read_buffer.len / BlockSize, blocks_to_read);

                    apply_patch_operation.last_read_block_in_original_file = start_block + blocks_to_read;
                    @panic("Not implemented");
                }

                if (apply_patch_operation.out_buffer == null) {}

                // patch_io.readFile(, , , , )
                // patch_io.readFile(, , , , )
            }

            break :process_running_operations;
        }

        break :apply_patch_loop;
    }

    // var per_thread_operations_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    // defer allocator.free(per_thread_operations_buffer);

    // for (per_thread_operations_buffer) |*operations_buffer| {
    //     operations_buffer.* = try allocator.alloc(u8, PatchGeneration.DefaultMaxWorkUnitSize * 6 + 8096);
    // }

    // defer {
    //     for (per_thread_operations_buffer) |operations_buffer| {
    //         allocator.free(operations_buffer);
    //     }
    // }

    // var per_thread_read_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    // defer allocator.free(per_thread_read_buffer);

    // for (per_thread_read_buffer) |*operations_buffer| {
    //     operations_buffer.* = try allocator.alloc(u8, BlockSize);
    // }

    // defer {
    //     for (per_thread_read_buffer) |operations_buffer| {
    //         allocator.free(operations_buffer);
    //     }
    // }

    // var per_thread_patch_files = try allocator.alloc(std.fs.File, thread_pool.max_threads);
    // defer allocator.free(per_thread_patch_files);

    // for (per_thread_patch_files) |*per_thread_patch_file| {
    //     per_thread_patch_file.* = try working_dir.openFile(patch_file_path, .{});
    // }

    // defer {
    //     for (per_thread_patch_files) |*per_thread_patch_file| {
    //         per_thread_patch_file.close();
    //     }
    // }

    // var per_thread_applied_bytes = try allocator.alloc(usize, thread_pool.max_threads);
    // defer allocator.free(per_thread_applied_bytes);

    // for (per_thread_applied_bytes) |*applied_bytes| {
    //     applied_bytes.* = 0;
    // }

    // var tasks = try allocator.alloc(ApplyPatchTask, patch.sections.items.len);
    // defer allocator.free(tasks);

    // var anchored_blocks_map = try AnchoredBlocksMap.init(patch.old, allocator);
    // defer anchored_blocks_map.deinit();

    // var batch = ThreadPool.Batch{};

    // var sections_remaining = std.atomic.Atomic(usize).init(patch.sections.items.len);
    // var are_sections_done = std.atomic.Atomic(u32).init(0);

    // var task_idx: usize = 0;
    // while (task_idx < patch.sections.items.len) : (task_idx += 1) {
    //     var section = patch.sections.items[task_idx];

    //     tasks[task_idx] = .{
    //         .per_thread_applied_bytes = per_thread_applied_bytes,
    //         .per_thread_read_buffers = per_thread_read_buffer,
    //         .old_signature = patch.old,
    //         .anchored_blocks_map = anchored_blocks_map,
    //         .source_dir = source_dir,
    //         .per_thread_operations_buffer = per_thread_operations_buffer,
    //         .section = patch.sections.items[task_idx],
    //         .target_dir = target_dir,
    //         .are_sections_done = &are_sections_done,
    //         .sections_remaining = &sections_remaining,
    //         .per_thread_patch_files = per_thread_patch_files,
    //         .task = ThreadPool.Task{ .callback = ApplyPatchTask.applyPatch },
    //         .file = patch.new.getFile(section.file_idx),
    //     };

    //     batch.push(ThreadPool.Batch.from(&tasks[task_idx].task));
    // }

    // thread_pool.schedule(batch);

    // var num_sections_remaining = sections_remaining.load(.acquire);
    // while (num_sections_remaining != 0 and are_sections_done.load(.acquire) == 0) {
    //     if (progress_callback) |progress_callback_unwrapped| {
    //         var elapsed_progress = (1.0 - @as(f32, @floatfromint(num_sections_remaining)) / @as(f32, @floatfromint(patch.sections.items.len))) * 100;
    //         progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "merging patch sections");
    //     }

    //     std.time.sleep(std.time.ns_per_ms * 100);
    //     num_sections_remaining = sections_remaining.load(.acquire);
    // }

    // if (stats) |stats_unwrapped| {
    //     stats_unwrapped.total_patch_size_bytes = 0;

    //     for (per_thread_applied_bytes) |applied_bytes| {
    //         stats_unwrapped.total_patch_size_bytes += applied_bytes;
    //     }
    // }
}
