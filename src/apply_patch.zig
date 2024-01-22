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

const ApplyPatchOperation = struct {
    const State = enum {
        Idle,
        ReadingFile,
        Inflating,
        Writing,
    };

    state: State,

    file_idx: usize,

    current_section: usize,

    last_section_idx_in_patch: ?usize,

    read_buffer: []u8,
    is_read_buffer_rdy: bool,

    inflated_buffer: []u8,

    inflate_task: ThreadPool.Task,

    is_inflate_done: std.atomic.Atomic(u32),

    operations_iterator: BlockPatching.SerializedOperationIterator,

    active_patch_operation: ?struct {
        operation: BlockPatching.PatchOperation,
    },

    per_thread_data: struct {
        inflation_buffer: []const []u8,
    },
};

fn inflateBuffer(task: *ThreadPool.Task) void {
    var self = @fieldParentPtr(ApplyPatchOperation, "inflate_task", task);
    inflateBufferImpl(self) catch |e| {
        switch (e) {
            else => {
                std.log.err("Error {s} occured during inflateBuffer task", .{@errorName(e)});
                unreachable;
            },
        }
    };
}

fn inflateBufferImpl(self: *ApplyPatchOperation) !void {

    //TODO: Can we preallocate the worst case memory?
    var inflating = try Compression.Infalting.init(Compression.Default, std.heap.c_allocator);

    var read_buffer_stream = std.io.fixedBufferStream(self.read_buffer);

    var counting_reader = std.io.countingReader(read_buffer_stream.reader());

    var compressed_section_size = try counting_reader.reader().readIntBig(usize);

    var compressed_buffer = self.read_buffer[counting_reader.bytes_read .. counting_reader.bytes_read + compressed_section_size];

    try inflating.inflateBuffer(compressed_buffer, self.inflated_buffer);

    self.operations_iterator = try BlockPatching.SerializedOperationIterator.init(self.inflated_buffer);
    self.is_inflate_done.store(1, .Release);
}

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
    _ = progress_callback;
    _ = patch_file_path;
    _ = target_dir;
    _ = source_dir;
    _ = working_dir;
    var patch_file_len = try patch_file.getEndPos();
    _ = patch_file_len;

    var patch_file_handle = patch_file.handle;

    const MaxConcurrentPatchOperations = thread_pool.num_threads;

    var patch_operations = try allocator.alloc(ApplyPatchOperation, MaxConcurrentPatchOperations);
    defer allocator.free(patch_operations);

    var available_operation_slots = try std.ArrayList(usize).initCapacity(allocator, MaxConcurrentPatchOperations);
    defer available_operation_slots.deinit();

    const DefaultMaxWorkUnitSize = BlockSize * 128;
    const MaxOperationOverhead = 1024;
    const MaxOperationOutputSize = DefaultMaxWorkUnitSize + MaxOperationOverhead;

    var per_thread_inflation_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    defer allocator.free(per_thread_inflation_buffer);

    for (per_thread_inflation_buffer) |*inflation_buffer| {
        inflation_buffer.* = try allocator.alloc(u8, DefaultMaxWorkUnitSize * 4);
    }

    defer {
        for (per_thread_inflation_buffer) |inflation_buffer| {
            allocator.free(inflation_buffer);
        }
    }

    for (0..MaxConcurrentPatchOperations) |idx| {
        available_operation_slots.appendAssumeCapacity(idx);

        patch_operations[idx].read_buffer = try allocator.alloc(u8, MaxOperationOutputSize);
        patch_operations[idx].inflated_buffer = try allocator.alloc(u8, MaxOperationOutputSize);
        patch_operations[idx].inflate_task = .{
            .callback = inflateBuffer,
        };
        patch_operations[idx].per_thread_data = .{
            .inflation_buffer = per_thread_inflation_buffer,
        };
    }

    defer {
        for (0..MaxConcurrentPatchOperations) |idx| {
            allocator.free(patch_operations[idx].read_buffer);
            allocator.free(patch_operations[idx].inflated_buffer);
        }
    }

    var running_operations = try std.ArrayList(usize).initCapacity(allocator, MaxConcurrentPatchOperations);
    defer running_operations.deinit();

    var num_files_with_data = blk: {
        var counter: usize = 0;
        for (0..patch.new.numFiles()) |file_idx| {
            if (patch.new.getFile(file_idx).size > 0) {
                counter += 1;
            }
        }
        break :blk counter;
    };

    var last_used_file_idx_in_patch: usize = 0;
    var num_files_processed: usize = 0;

    apply_patch_loop: while (true) {
        while (available_operation_slots.items.len > 0 and num_files_processed < num_files_with_data) {
            const operation_slot_idx = available_operation_slots.orderedRemove(available_operation_slots.items.len - 1);
            var operation = &patch_operations[operation_slot_idx];

            // Skip empty files
            while (patch.new.getFile(last_used_file_idx_in_patch).size == 0) {
                last_used_file_idx_in_patch += 1;
            }

            operation.file_idx = last_used_file_idx_in_patch;
            operation.current_section = 0;
            operation.is_read_buffer_rdy = false;
            operation.state = .Idle;
            operation.last_section_idx_in_patch = null;

            running_operations.appendAssumeCapacity(operation_slot_idx);

            last_used_file_idx_in_patch += 1;
            num_files_processed += 1;
        }

        for (running_operations.items) |running_operation| {
            var operation = &patch_operations[running_operation];

            switch (operation.state) {
                .Idle => {
                    var section_idx_in_patch = blk: {
                        // Start searching for the next section based on the last idx we had in the patch.
                        var last_section = operation.last_section_idx_in_patch orelse 0;
                        for (patch.sections.items[last_section..], 0..) |section, idx| {
                            if (section.file_idx == operation.current_section) {
                                break :blk last_section + idx;
                            }
                        }
                        break :blk ~@as(usize, 0);
                    };

                    if (section_idx_in_patch == ~@as(usize, 0)) {
                        std.log.err(
                            "Failed to find section [{}] for file with idx [{}]",
                            .{ operation.current_section, operation.file_idx },
                        );
                        return error.ReadPatchError;
                    }

                    std.log.info("Section idx: {}", .{section_idx_in_patch});

                    var offset = patch.sections.items[section_idx_in_patch].operations_start_pos_in_file;

                    var size = blk: {
                        var file = patch.new.getFile(operation.file_idx);

                        break :blk @min(
                            file.size - DefaultMaxWorkUnitSize * operation.current_section,
                            DefaultMaxWorkUnitSize,
                        );
                    };

                    const ApplyPatchReadCallback = struct {
                        fn callback(ctx: *anyopaque) void {
                            var op: *ApplyPatchOperation = @ptrCast(@alignCast(ctx));
                            op.is_read_buffer_rdy = true;
                        }
                    };

                    std.log.info("Reading from offset: {}", .{offset});

                    operation.state = .ReadingFile;

                    try patch_io.readFile(
                        patch_file_handle,
                        offset,
                        operation.read_buffer[0..size],
                        ApplyPatchReadCallback.callback,
                        operation,
                    );
                },
                .ReadingFile => {
                    if (operation.is_read_buffer_rdy) {
                        operation.is_read_buffer_rdy = false;
                        operation.state = .Inflating;
                        operation.is_inflate_done.store(0, .Release);
                        thread_pool.schedule(ThreadPool.Batch.from(&operation.inflate_task));
                    }
                },
                .Inflating => {
                    if (operation.is_inflate_done.load(.Acquire) == 1) {
                        operation.state = .Writing;
                    }
                },
                .Writing => {
                    if (operation.active_patch_operation == null) {
                        // Get next operation from iterator.
                        if (operation.operations_iterator.nextOperation()) |patch_op| {
                            switch (patch_op) {
                                .Data => |data_op| {
                                    _ = data_op;

                                    // Write to file bla bla

                                    operation.active_patch_operation = .{
                                        .operation = patch_op,
                                    };
                                },
                                else => unreachable, //TODO:
                            }
                        } else {
                            std.log.info("Operation iterator done. Chose next section. bla bla", .{});
                        }
                    }
                },
            }
        }

        continue :apply_patch_loop;
    }

    // const DefaultMaxWorkUnitSize = BlockSize * 128;
    // const MaxOperationOverhead = 1024;
    // const MaxOperationOutputSize = DefaultMaxWorkUnitSize + MaxOperationOverhead;

    // const ReadBufferOperation = struct {
    //     backing_buffer: []u8,

    //     read_buffer: []u8,

    //     first_section: usize,

    //     num_sections: usize,

    //     is_done_reading: bool,

    //     last_scheduled_inflate_operation: usize,

    //     // When zero the reading buffer can be recycled.
    //     remaining_inflate_operations: std.atomic.Atomic(u32),
    // };

    // const InflatePatchOperation = struct {
    //     read_buffer: *ReadBufferOperation,
    //     section: usize,

    //     working_buffer: []u8,

    //     out_operations: ?std.ArrayList(BlockPatching.PatchOperation),
    // };

    // const PatchFileOperation = struct {
    //     const PatchFileReadData = struct {
    //         first_section: usize,
    //         num_sections: usize,
    //         data: []const u8,
    //     };

    //     const InflatePatchData = struct {
    //         data_to_inflate: []const u8,
    //         inflated_data: []const u8,
    //     };

    //     file_idx: usize,

    //     // Holds the current read operation for the file.
    //     next_read_data: PatchFileReadData,

    //     // Holds the current decompression operation for the file.
    //     inflate_patch_data: InflatePatchData,

    //     // Final patch data after decompression.
    //     deflated_patch_data: []const u8,

    //     const WritePatchData = struct {};
    // };
    // _ = PatchFileOperation;

    // const NumParallelInflateOperations = thread_pool.max_threads * 2;
    // var inflate_operations = try allocator.alloc(InflatePatchOperation, NumParallelInflateOperations);
    // _ = inflate_operations;

    // const InflateSection = struct {};
    // _ = InflateSection;

    // const WriteBuffer = struct {
    //     data: [DefaultMaxWorkUnitSize]u8,
    //     is_io_pending: bool,
    // };
    // _ = WriteBuffer;

    // const MaxSizeToReadFromPatchAtOnce = MaxOperationOutputSize * thread_pool.max_threads;
    // const NumReadBuffers = 1;

    // var patch_read_buffers = try allocator.alloc(ReadBufferOperation, NumReadBuffers);
    // defer allocator.free(patch_read_buffers);

    // for (patch_read_buffers) |*patch_read_buffer| {
    //     patch_read_buffer.backing_buffer = try allocator.alloc(u8, MaxSizeToReadFromPatchAtOnce);
    // }
    // defer {
    //     for (patch_read_buffers) |patch_read_buffer| {
    //         allocator.free(patch_read_buffer.backing_buffer);
    //     }
    // }

    // var available_read_buffers = try std.ArrayList(usize).initCapacity(allocator, NumReadBuffers);
    // defer available_read_buffers.deinit();

    // for (0..NumReadBuffers) |i| {
    //     available_read_buffers.appendAssumeCapacity(i);
    // }

    // var running_read_buffers = try std.ArrayList(usize).initCapacity(allocator, NumReadBuffers);
    // defer running_read_buffers.deinit();

    // var patch_file_len = try patch_file.getEndPos();

    // var patch_file_handle = patch_file.handle;

    // var next_section: usize = 0;
    // while (true) {
    //     // schedule_reads_from_patch
    //     while (next_section < patch.sections.items.len and available_read_buffers.items.len > 0) {
    //         var read_buffer_idx = available_read_buffers.orderedRemove(available_read_buffers.items.len - 1);
    //         var read_buffer_operation = &patch_read_buffers[read_buffer_idx];
    //         var remaining_space_in_read_buffer = read_buffer_operation.backing_buffer.len;

    //         var first_section = next_section;
    //         var num_sections = @as(usize, 0);

    //         find_blocks_to_read: while (true) {
    //             var section_len: usize = 0;
    //             if (next_section + 1 < patch.sections.items.len) {
    //                 section_len = patch.sections.items[next_section + 1].operations_start_pos_in_file -
    //                     patch.sections.items[next_section].operations_start_pos_in_file;
    //             } else {
    //                 section_len = patch_file_len - patch.sections.items[next_section].operations_start_pos_in_file;
    //             }

    //             if (section_len < remaining_space_in_read_buffer) {
    //                 num_sections += 1;
    //                 next_section += 1;

    //                 remaining_space_in_read_buffer -= section_len;
    //             } else {
    //                 if (num_sections == 0) {
    //                     // We couldn't fit a single operation into our buffer.
    //                     std.log.warn("Couldn't read section [{}]. The patch might be corrupt.", .{next_section});
    //                     return error.FailedToReadSection;
    //                 }

    //                 break :find_blocks_to_read;
    //             }
    //         }

    //         read_buffer_operation.* = ReadBufferOperation{
    //             .first_section = first_section,
    //             .num_sections = num_sections,
    //             .backing_buffer = read_buffer_operation.backing_buffer,
    //             .read_buffer = read_buffer_operation.backing_buffer[0 .. read_buffer_operation.backing_buffer.len - remaining_space_in_read_buffer],
    //             .is_done_reading = false,
    //             .remaining_inflate_operations = std.atomic.Atomic(u32).init(@intCast(num_sections)),
    //             .last_scheduled_inflate_operation = 0,
    //         };

    //         const ReadBufferIoCallback = struct {
    //             fn onIoComplete(ctx: *anyopaque) void {
    //                 var operation: *ReadBufferOperation = @alignCast(@ptrCast(ctx));
    //                 operation.is_done_reading = true;
    //             }
    //         };

    //         try patch_io.readFile(
    //             patch_file_handle,
    //             patch.sections.items[first_section].operations_start_pos_in_file,
    //             read_buffer_operation.read_buffer,
    //             ReadBufferIoCallback.onIoComplete,
    //             read_buffer_operation,
    //         );
    //     }

    //     // inflate patch sections

    //     if (running_read_buffers.items.len > 0) {
    //         schedule_inflate: for (running_read_buffers.items) |running_read_buffer_operation| {
    //             var read_buffer_operation = &patch_read_buffers[running_read_buffer_operation];

    //             if (read_buffer_operation.is_done_reading) {
    //                 for (read_buffer_operation.first_section..read_buffer_operation.first_section +
    //                     read_buffer_operation.num_sections) |section|
    //                 {
    //                     _ = section;
    //                     // Find file patch operation that belongs to this section and add it to pending operations to write.

    //                 }
    //             } else {

    //                 // Inflate operations inbetween different read batches has to happen in order.
    //                 // The reasoning behind this is that we have a limimted amount of inflate slots.
    //                 // If we happen to inflate a block that is
    //                 break :schedule_inflate;
    //             }
    //         }
    //     }
    // }

    // const ApplyPatchState = struct {};

    // const ApplyPatchOperation = struct {
    //     const Self = @This();

    //     task: ThreadPool.Task,
    //     start_time: i128,

    //     patch_buffer: []u8,
    //     original_file_buffer: []u8,
    //     out_buffer: ?usize,

    //     last_read_block_in_original_file: usize,

    //     next_start_section: usize,

    //     has_active_task: std.atomic.Atomic(bool).init(false),

    //     fn applyPatchOperation(task: *ThreadPool.Task) void {
    //         var apply_patch_operation = @as(*Self, @ptrCast(task));
    //         _ = apply_patch_operation;
    //     }
    // };

    // // These values should probably be made part of the patch file

    // _ = MaxOperationOutputSize;
    // // const WriteBufferSize = MaxOperationOutputSize * 10;

    // const num_read_buffers = thread_pool.num_threads * 2;
    // var read_buffers = try allocator.alloc(PatchReadBuffer, num_read_buffers);
    // defer allocator.free(read_buffers);

    // var available_read_buffers = try std.ArrayList(usize).initCapacity(allocator, num_read_buffers);
    // defer available_read_buffers.deinit();

    // for (0..num_read_buffers) |idx| {
    //     available_read_buffers.appendAssumeCapacity(idx);
    // }
    // const max_simulatenous_apply_patch_operations = thread_pool.max_threads * 2;
    // var operation_slots = try allocator.alloc(ApplyPatchOperation, max_simulatenous_apply_patch_operations);
    // defer allocator.free(operation_slots);

    // var available_operation_slots = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_apply_patch_operations);
    // defer available_operation_slots.deinit();

    // for (0..max_simulatenous_apply_patch_operations) |idx| {
    //     available_operation_slots.appendAssumeCapacity(idx);
    // }

    // var active_apply_patch_operations = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_apply_patch_operations);
    // defer active_apply_patch_operations.deinit();

    // var has_more_operations_to_complete = true;
    // var min_next_file_idx = 0;
    // var last_operation_section_idx_in_patch = 0;

    // apply_patch_loop: while (true) {
    //     find_new_operations: while (has_more_operations_to_complete and available_operation_slots.items.len > 0) {
    //         var next_section = blk: {
    //             for (patch.sections.items[last_operation_section_idx_in_patch..]) |section| {
    //                 if (section.file_idx >= min_next_file_idx) {
    //                     break :blk section;
    //                 }
    //             }

    //             break :find_new_operations;
    //         };

    //         min_next_file_idx = next_section.file_idx + 1;

    //         var slot = available_operation_slots.orderedRemove(available_operation_slots.items.len - 1);
    //         active_apply_patch_operations.appendAssumeCapacity(slot);

    //         operation_slots[slot] = .{
    //             .task = .{
    //                 .callback = ApplyPatchTask.applyPatchTask,
    //             },
    //             .start_time = std.time.nanoTimestamp(),
    //         };
    //     }

    //     process_running_operations: for (active_apply_patch_operations.items) |apply_patch_operation_idx| {
    //         var apply_patch_operation = operation_slots[apply_patch_operation_idx];

    //         if (!apply_patch_operation.has_active_task.load(.Acquire)) {
    //             var current_section_idx = apply_patch_operation.next_start_section - 1;
    //             var current_section = patch.sections.items[current_section_idx];

    //             if (apply_patch_operation.patch_buffer == null) {
    //                 // Load the block we are gonna work on.
    //                 // patch_io.readFile()
    //             }

    //             var needs_to_read_from_original = current_section.first_block_taken_from_reference != ~@as(usize, 0);

    //             if (apply_patch_operation.original_file_buffer == null and needs_to_read_from_original) {
    //                 const start_block = @max(current_section.first_block_taken_from_reference, apply_patch_operation.last_read_block_in_original_file);
    //                 var blocks_to_read = current_section.last_block_taken_from_reference - start_block;

    //                 //TODO: Take this from somewhere
    //                 var read_buffer: []u8 = undefined;

    //                 // Don't read more blocks than we can fit into our read_buffer.
    //                 blocks_to_read = @min(read_buffer.len / BlockSize, blocks_to_read);

    //                 apply_patch_operation.last_read_block_in_original_file = start_block + blocks_to_read;
    //                 @panic("Not implemented");
    //             }

    //             if (apply_patch_operation.out_buffer == null) {}

    //             // patch_io.readFile(, , , , )
    //             // patch_io.readFile(, , , , )
    //         }

    //         break :process_running_operations;
    //     }

    //     break :apply_patch_loop;
    // }

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
