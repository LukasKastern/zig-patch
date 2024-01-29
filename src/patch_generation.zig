const SignatureFile = @import("signature_file.zig").SignatureFile;
const BlockPatching = @import("block_patching.zig");
const std = @import("std");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const MaxDataOperationLength = @import("block_patching.zig").MaxDataOperationLength;

const PatchHeader = @import("patch_header.zig").PatchHeader;
const BlockSize = @import("block.zig").BlockSize;
const CompressionImplementation = @import("compression/compression.zig").CompressionImplementation;
const Compression = @import("compression/compression.zig").Compression;
const CreatePatchStats = @import("operations.zig").OperationStats.CreatePatchStats;
const ProgressCallback = @import("operations.zig").ProgressCallback;
const PatchIO = @import("io/patch_io.zig");

pub const DefaultMaxWorkUnitSize = BlockSize * 128;
pub const ChunkFileEveryWorkUnits = 5;

const CreatePatchOptions = struct {
    max_work_unit_size: usize = DefaultMaxWorkUnitSize,
    staging_dir: std.fs.Dir,
    build_dir: std.fs.Dir,
    compression: CompressionImplementation,
};

pub fn createPatchV2(patch_io: *PatchIO, thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOptions, stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
    var anchored_block_map = try AnchoredBlocksMap.init(old_signature, allocator);
    defer anchored_block_map.deinit();

    //TODO: This should be MaxWorkUnitSize / MaxDataOpLen or something like that
    const MaxOperationOverhead = 1024;
    const MaxOperationOutputSize = DefaultMaxWorkUnitSize + MaxOperationOverhead;
    const WriteBufferSize = MaxOperationOutputSize * 10;

    const WriteBuffer = struct {
        buffer: [WriteBufferSize]u8,
        written_bytes: usize,

        start_sequence: usize,

        sequence_offsets: std.ArrayList(usize),

        file_idx: usize,

        is_io_pending: bool,
        is_task_done: bool,
        has_pending_write: *bool,

        write_start_time: i128,

        const InvalidRangeOperation = ~@as(usize, 0);
    };

    const ReadBuffer = struct {
        data: [DefaultMaxWorkUnitSize]u8,
        is_ready: bool,
        read_start_time: i128,
    };

    const num_read_buffers = thread_pool.num_threads * 2;

    const PerThreadWorkingBufferSize = DefaultMaxWorkUnitSize * 2;

    const PatchGenerationTaskState = struct {
        read_buffers: []ReadBuffer,
        per_thread_working_buffers: [][PerThreadWorkingBufferSize]u8,
        signature: *const SignatureFile,
        block_map: *AnchoredBlocksMap,
    };

    var task_state = try allocator.create(PatchGenerationTaskState);
    defer allocator.destroy(task_state);

    task_state.read_buffers = try allocator.alloc(ReadBuffer, num_read_buffers);
    defer allocator.free(task_state.read_buffers);

    var available_read_buffers = try std.ArrayList(usize).initCapacity(allocator, num_read_buffers);
    defer available_read_buffers.deinit();

    for (0..num_read_buffers) |idx| {
        available_read_buffers.appendAssumeCapacity(idx);
    }

    const ActivePatchGenerationOperation = struct {
        target_file: usize,
        sequence: usize,
        next_sequence: usize,
        start_sequence: usize,
        num_bytes_to_process: usize = 0,

        current_read_buffer: ?usize,
        next_read_buffer: ?usize,

        first_sequence_patch_file_idx: usize,

        write_buffer: ?*WriteBuffer,

        has_active_task: std.atomic.Atomic(u32),

        task: ThreadPool.Task,

        state: *PatchGenerationTaskState,

        generate_operations_state: BlockPatching.GenerateOperationsState,

        start_time: i128,

        compression: CompressionImplementation,

        stats: struct {
            total_blocks: usize = 0,
            changed_blocks: usize = 0,
            num_new_bytes: usize = 0,
            num_bytes_read: usize = 0,
        },

        const Self = @This();

        pub fn generatePatchTask(task: *ThreadPool.Task) void {
            var self = @fieldParentPtr(Self, "task", task);

            var file = self.state.signature.getFile(self.target_file);
            var current_start_offset = self.sequence * DefaultMaxWorkUnitSize;
            var file_size = file.size;

            var remaining_len = file_size - current_start_offset;
            var is_last_sequence = remaining_len <= DefaultMaxWorkUnitSize;
            _ = is_last_sequence;

            var data_buffer = &self.state.read_buffers[self.current_read_buffer.?];
            self.generate_operations_state.in_buffer = data_buffer.data[0..self.num_bytes_to_process];

            var temp_buffer = &self.state.per_thread_working_buffers[ThreadPool.Thread.current.?.idx];
            var temp_allocator = std.heap.FixedBufferAllocator.init(temp_buffer);

            var operations = BlockPatching.generateOperationsForBuffer(
                self.state.block_map.*,
                &self.generate_operations_state,
                temp_allocator.allocator(),
                MaxDataOperationLength,
            ) catch |e| {
                switch (e) {
                    else => {
                        std.log.err("Generate operations failed. Error: {s}", .{@errorName(e)});
                        unreachable;
                    },
                }
            };

            var operations_buffer = temp_allocator.allocator().alloc(u8, DefaultMaxWorkUnitSize + BlockSize + 2048) catch unreachable;
            var fixed_buffer_stream = std.io.fixedBufferStream(operations_buffer);

            // Update Stats
            {
                for (operations.items) |operation| {
                    switch (operation) {
                        .Data => |data| {
                            var blocks_in_data_op = @ceil(@as(f64, @floatFromInt(data.len)) / @as(f64, @floatFromInt(BlockSize)));
                            // std.log.info("Data found in {} and part {}, blocks: {}", .{ self.file_info.file_idx, self.file_info.file_part_idx, blocks_in_data_op });
                            self.stats.changed_blocks += @as(usize, @intFromFloat(blocks_in_data_op));
                            self.stats.total_blocks += @as(usize, @intFromFloat(blocks_in_data_op));
                            self.stats.num_new_bytes += data.len;
                        },
                        .BlockRange => {
                            self.stats.total_blocks += operation.BlockRange.block_span;
                        },
                        .Invalid => {
                            unreachable;
                        },
                    }
                }
            }

            // std.debug.assert(self.stats.num_new_bytes <= self.num_bytes_to_process + prev_step_bytes);

            // Write operations to the temp buffer.
            {
                var fixed_buffer_writer = fixed_buffer_stream.writer();

                // Serialize all operations into our fixed_memory_buffer.
                // We do not write them to the file directly since we first want to have the data go through our compression.
                BlockPatching.saveOperations(operations, fixed_buffer_writer) catch |e| {
                    switch (e) {
                        else => {
                            std.log.err("Failed to save operations. Error: {s}", .{@errorName(e)});
                            unreachable;
                        },
                    }
                };
            }

            // Compress the operations_buffer into the write_buffer
            {
                //TODO: Can we use a fallback allocator?
                var deflating_allocator = std.heap.c_allocator;

                var deflating = Compression.Deflating.init(self.compression, deflating_allocator) catch unreachable;
                defer deflating.deinit();

                var prev_offset = self.write_buffer.?.written_bytes;
                var deflated_data = deflating.deflateBuffer(
                    fixed_buffer_stream.buffer[0..fixed_buffer_stream.pos],
                    self.write_buffer.?.buffer[prev_offset + @sizeOf(usize) ..],
                ) catch unreachable;

                // Write the total compressed size which we need to inflate the data when applying the patch.
                {
                    var write_buffer_stream = std.io.fixedBufferStream(self.write_buffer.?.buffer[prev_offset .. prev_offset + @sizeOf(usize)]);
                    write_buffer_stream.writer().writeIntBig(usize, deflated_data.len) catch unreachable;
                }

                self.write_buffer.?.sequence_offsets.appendAssumeCapacity(prev_offset);

                self.write_buffer.?.written_bytes = prev_offset + deflated_data.len + @sizeOf(usize);
            }

            var first_range_operation_block = WriteBuffer.InvalidRangeOperation;
            var last_range_operation_block = WriteBuffer.InvalidRangeOperation;

            for (operations.items) |operation| {
                switch (operation) {
                    .BlockRange => |range_op| {
                        if (first_range_operation_block == WriteBuffer.InvalidRangeOperation) {
                            first_range_operation_block = range_op.block_index;
                        }

                        last_range_operation_block = range_op.block_index + range_op.block_span;

                        self.stats.total_blocks += operation.BlockRange.block_index;
                    },
                    else => {},
                }
            }

            self.has_active_task.store(0, .Release);
        }
    };

    const max_simulatenous_patch_generation_operations = thread_pool.max_threads * 2;

    var operation_slots = try allocator.alloc(ActivePatchGenerationOperation, max_simulatenous_patch_generation_operations);
    defer allocator.free(operation_slots);

    var available_operation_slots = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_patch_generation_operations);
    defer available_operation_slots.deinit();

    for (0..max_simulatenous_patch_generation_operations) |idx| {
        available_operation_slots.appendAssumeCapacity(idx);
    }

    const ProgressOperationData = ProgressCallback.CallbackData.CreatePatchData.OperationData;
    var progress_operation_data_array = try std.ArrayList(ProgressOperationData).initCapacity(
        allocator,
        max_simulatenous_patch_generation_operations,
    );
    defer progress_operation_data_array.deinit();

    var active_patch_generation_operations = try std.ArrayList(usize).initCapacity(allocator, max_simulatenous_patch_generation_operations);
    defer active_patch_generation_operations.deinit();

    task_state.signature = new_signature;
    task_state.block_map = anchored_block_map;
    task_state.per_thread_working_buffers = try allocator.alloc([PerThreadWorkingBufferSize]u8, thread_pool.max_threads * 2);
    defer allocator.free(task_state.per_thread_working_buffers);

    const max_num_write_buffers = thread_pool.max_threads * 2;

    var write_buffers = try std.ArrayList(*WriteBuffer).initCapacity(allocator, max_num_write_buffers);
    defer {
        for (write_buffers.items) |buffer| {
            buffer.sequence_offsets.deinit();
            allocator.destroy(buffer);
        }

        write_buffers.deinit();
    }

    var next_file_idx: usize = 0;
    var patch_file_idx: usize = 0;

    var num_operations_needed = blk: {
        var num_operations: usize = 0;
        for (0..new_signature.numFiles()) |file_idx| {
            var file = new_signature.getFile(file_idx);
            var file_size = file.size;

            const per_operation_size = DefaultMaxWorkUnitSize * ChunkFileEveryWorkUnits;
            num_operations += @divTrunc(file_size, per_operation_size);

            if (file_size % per_operation_size != 0) {
                num_operations += 1;
            }
        }

        break :blk num_operations;
    };

    var finished_operations: usize = 0;

    var patch_header = try PatchHeader.init(new_signature, old_signature, options.compression, allocator);
    defer patch_header.deinit();

    const patch_handle = try patch_io.createFile(options.staging_dir.fd, "Patch.pwd");

    const patch = std.fs.File{ .handle = patch_handle };
    defer patch.close();

    var last_progress_reported_at = std.time.nanoTimestamp();

    var patch_file_offset: usize = blk: {
        var num_sections: usize = 0;

        // Reserve the maximum amount of sections that our patch file could end up having.
        var file_idx: usize = 0;
        while (file_idx < new_signature.numFiles()) : (file_idx += 1) {
            if (new_signature.getFile(file_idx).size != 0) {
                const file_size = new_signature.getFile(file_idx).size;

                num_sections += @divTrunc(file_size, DefaultMaxWorkUnitSize);

                if (file_size % DefaultMaxWorkUnitSize != 0) {
                    num_sections += 1;
                }
            }
        }

        try patch_header.sections.resize(num_sections);
        defer patch_header.sections.resize(0) catch unreachable;

        var counting_writer = std.io.CountingWriter(@TypeOf(std.io.null_writer)){
            .bytes_written = 0,
            .child_stream = std.io.null_writer,
        };
        try patch_header.savePatchHeader(counting_writer.writer());
        break :blk counting_writer.bytes_written;
    };

    var has_pending_write = false;

    var file_chunk_sequence: usize = 0;

    generate_patch_loop: while (true) {
        if (next_file_idx < new_signature.numFiles() or active_patch_generation_operations.items.len > 0) {
            while (available_operation_slots.items.len > 0) {
                while (next_file_idx < new_signature.numFiles()) {
                    if (new_signature.getFile(next_file_idx).size != 0) {
                        break;
                    }

                    next_file_idx += 1;
                }

                if (next_file_idx == new_signature.numFiles()) {
                    // Reached last operation.
                    break;
                }

                var file = new_signature.getFile(next_file_idx);
                _ = file;

                var slot = available_operation_slots.orderedRemove(available_operation_slots.items.len - 1);
                active_patch_generation_operations.appendAssumeCapacity(slot);

                operation_slots[slot] = .{
                    .state = task_state,
                    .next_sequence = file_chunk_sequence * ChunkFileEveryWorkUnits,
                    .target_file = next_file_idx,
                    .sequence = file_chunk_sequence * ChunkFileEveryWorkUnits,
                    .start_sequence = file_chunk_sequence * ChunkFileEveryWorkUnits,
                    .write_buffer = null,
                    .current_read_buffer = null,
                    .next_read_buffer = null,
                    .first_sequence_patch_file_idx = patch_file_idx,
                    .has_active_task = std.atomic.Atomic(u32).init(0),
                    .task = .{
                        .callback = ActivePatchGenerationOperation.generatePatchTask,
                    },
                    .generate_operations_state = undefined,
                    .stats = .{},
                    .start_time = std.time.nanoTimestamp(),
                    .compression = options.compression,
                };

                const desired_num_bytes_to_process = ChunkFileEveryWorkUnits * DefaultMaxWorkUnitSize;
                var file_size = new_signature.getFile(next_file_idx).size;
                const generate_operations_size = @min(file_size - desired_num_bytes_to_process * file_chunk_sequence, desired_num_bytes_to_process);
                operation_slots[slot].generate_operations_state.init(generate_operations_size);

                file_chunk_sequence += 1;

                if (file_chunk_sequence * DefaultMaxWorkUnitSize * ChunkFileEveryWorkUnits > file_size) {
                    patch_file_idx += @as(usize, @intFromFloat(@ceil(@as(f32, @floatFromInt(file_size)) / DefaultMaxWorkUnitSize)));
                    next_file_idx += 1;
                    file_chunk_sequence = 0;
                }
            }

            schedule_buffer_reads: for (active_patch_generation_operations.items) |operation_idx| {
                if (available_read_buffers.items.len == 0) {
                    break :schedule_buffer_reads;
                }

                var active_operation = &operation_slots[operation_idx];

                if (active_operation.next_read_buffer == null) {
                    var current_start_offset = active_operation.next_sequence * DefaultMaxWorkUnitSize;
                    var file_size = new_signature.getFile(active_operation.target_file).size;

                    const num_processed_sequences = active_operation.next_sequence - active_operation.start_sequence;
                    if (current_start_offset >= file_size or num_processed_sequences >= ChunkFileEveryWorkUnits) {
                        // We already reached the end of the file.
                        // Meaning it doesn't need another buffer.
                        continue;
                    }

                    var num_bytes_to_read = @min(DefaultMaxWorkUnitSize, file_size - current_start_offset);

                    active_operation.next_read_buffer = available_read_buffers.orderedRemove(available_read_buffers.items.len - 1);
                    var read_buffer = &task_state.read_buffers[active_operation.next_read_buffer.?];
                    read_buffer.is_ready = false;

                    const IOCallbackWrapper = struct {
                        pub fn ioCallback(ctx: *anyopaque) void {
                            var buffer = @as(*ReadBuffer, @ptrCast(@alignCast(ctx)));
                            buffer.is_ready = true;

                            var read_end_time = std.time.nanoTimestamp();
                            std.log.debug(
                                "Waited {}ms for buffer of {} bytes",
                                .{ @divTrunc(read_end_time - buffer.read_start_time, std.time.ns_per_ms), buffer.data.len },
                            );
                        }
                    };

                    read_buffer.read_start_time = std.time.nanoTimestamp();

                    std.log.debug("Reading buffer for file: {}, chunk: {}", .{ active_operation.target_file, active_operation.start_sequence / ChunkFileEveryWorkUnits });
                    var file_handle = new_signature.data.?.OnDiskSignatureFile.locked_directory.files.items[active_operation.target_file].handle;
                    try patch_io.readFile(file_handle, current_start_offset, read_buffer.data[0..num_bytes_to_read], IOCallbackWrapper.ioCallback, read_buffer);
                }
            }

            var idx: isize = 0;
            schedule_operations: while (idx < active_patch_generation_operations.items.len) : (idx += 1) {
                var operation_idx = active_patch_generation_operations.items[@as(usize, @intCast(idx))];

                var active_operation = &operation_slots[operation_idx];
                var is_task_running = active_operation.has_active_task.load(.Acquire) != 0;

                if (is_task_running) {
                    continue :schedule_operations;
                }

                var next_start_offset = active_operation.next_sequence * DefaultMaxWorkUnitSize;
                var file_size = new_signature.getFile(active_operation.target_file).size;

                // Free the previously worked on buffer.
                if (active_operation.current_read_buffer) |last_buffer| {
                    available_read_buffers.appendAssumeCapacity(last_buffer);
                    active_operation.current_read_buffer = null;

                    var write_buffer = active_operation.write_buffer.?;

                    const num_processed_sequences = active_operation.next_sequence - active_operation.start_sequence;

                    var is_operation_done = num_processed_sequences >= ChunkFileEveryWorkUnits or
                        next_start_offset > file_size;
                    {
                        var can_write_buffer_fit_another_patch = write_buffer.buffer.len - write_buffer.written_bytes > MaxOperationOutputSize;

                        write_buffer.is_task_done = is_operation_done or !can_write_buffer_fit_another_patch;

                        if (write_buffer.is_task_done) {
                            active_operation.write_buffer = null;
                        }
                    }

                    if (is_operation_done) {
                        if (stats) |stats_unwrapped| {
                            stats_unwrapped.total_blocks += active_operation.stats.total_blocks;
                            stats_unwrapped.num_new_bytes += active_operation.stats.num_new_bytes;
                            stats_unwrapped.changed_blocks += active_operation.stats.changed_blocks;
                        }

                        active_operation.stats = .{};
                        std.debug.assert(active_operation.generate_operations_state.tail ==
                            active_operation.generate_operations_state.file_size);

                        std.debug.assert(active_operation.next_read_buffer == null);

                        std.log.debug(
                            "Operation for file: {} completed in {}ms",
                            .{ active_operation.target_file, @divTrunc(std.time.nanoTimestamp() - active_operation.start_time, std.time.ns_per_ms) },
                        );

                        active_operation.write_buffer = null;

                        available_operation_slots.appendAssumeCapacity(operation_idx);
                        _ = active_patch_generation_operations.swapRemove(@as(usize, @intCast(idx)));
                        idx -= 1;

                        finished_operations += 1;
                        continue :schedule_operations;
                    }
                }

                // If the next buffer is ready schedule the processing task.
                if (active_operation.next_read_buffer) |next_buffer| {
                    if (task_state.read_buffers[next_buffer].is_ready) {
                        if (active_operation.write_buffer == null) {
                            active_operation.write_buffer = blk: {
                                var maybe_write_buffer: ?*WriteBuffer = null;

                                for (write_buffers.items) |write_buffer| {
                                    if (!write_buffer.is_io_pending) {
                                        maybe_write_buffer = write_buffer;
                                        write_buffer.start_sequence = active_operation.next_sequence;
                                        write_buffer.sequence_offsets.clearRetainingCapacity();
                                        write_buffer.written_bytes = 0;
                                        break;
                                    }
                                }

                                if (maybe_write_buffer == null and write_buffers.items.len <= max_num_write_buffers) {
                                    maybe_write_buffer = try allocator.create(WriteBuffer);
                                    maybe_write_buffer.?.* = .{
                                        .written_bytes = 0,
                                        .is_io_pending = true,
                                        .is_task_done = false,
                                        .buffer = undefined,
                                        .has_pending_write = undefined,
                                        .write_start_time = undefined,
                                        .file_idx = 0,
                                        .start_sequence = active_operation.next_sequence,
                                        .sequence_offsets = try std.ArrayList(usize).initCapacity(allocator, 32),
                                    };
                                    try write_buffers.append(maybe_write_buffer.?);
                                }

                                break :blk maybe_write_buffer;
                            };
                        }

                        if (active_operation.write_buffer) |write_buffer| {
                            write_buffer.is_io_pending = true;
                            write_buffer.is_task_done = false;

                            write_buffer.file_idx = active_operation.target_file;

                            active_operation.current_read_buffer = next_buffer;
                            active_operation.next_read_buffer = null;

                            active_operation.sequence = active_operation.next_sequence;
                            active_operation.next_sequence += 1;

                            active_operation.has_active_task.store(1, .Release);

                            try active_operation.write_buffer.?.sequence_offsets.ensureTotalCapacity(
                                active_operation.write_buffer.?.sequence_offsets.items.len + 1,
                            );

                            var current_start_offset = active_operation.sequence * DefaultMaxWorkUnitSize;

                            var num_bytes_to_read = @min(DefaultMaxWorkUnitSize, file_size - current_start_offset);
                            active_operation.num_bytes_to_process = num_bytes_to_read;

                            active_operation.stats.num_bytes_read += num_bytes_to_read;

                            thread_pool.schedule(ThreadPool.Batch.from(&active_operation.task));
                        }
                    }
                }
            }
        }

        // Update progress
        {
            if (progress_callback) |progress_callback_unwrapped| {
                if (std.time.nanoTimestamp() > last_progress_reported_at + std.time.ns_per_ms * 500) {
                    last_progress_reported_at = std.time.nanoTimestamp();
                    progress_operation_data_array.clearRetainingCapacity();
                    for (active_patch_generation_operations.items) |operation_idx| {
                        var active_operation = &operation_slots[operation_idx];

                        const file = new_signature.getFile(active_operation.target_file);
                        var total_num_sequences_in_file = @divTrunc(file.size, DefaultMaxWorkUnitSize);
                        if (file.size % DefaultMaxWorkUnitSize != 0) {
                            total_num_sequences_in_file += 1;
                        }

                        const last_sequence = @min(
                            active_operation.start_sequence + ChunkFileEveryWorkUnits,
                            total_num_sequences_in_file,
                        );

                        var state = blk: {
                            const StateNamespace = ProgressCallback.CallbackData.CreatePatchData.OperationState;
                            var has_task = active_operation.has_active_task.load(.Acquire) != 0;
                            if (has_task) {
                                break :blk StateNamespace.processing;
                            } else {
                                if (active_operation.next_read_buffer) |read_buffer_idx| {
                                    var read_buffer = task_state.read_buffers[read_buffer_idx];

                                    if (!read_buffer.is_ready) {
                                        break :blk StateNamespace.reading;
                                    }
                                }

                                break :blk StateNamespace.waiting;
                            }
                        };

                        var progress = 1 - (@as(f32, @floatFromInt(last_sequence)) - @as(f32, @floatFromInt(active_operation.sequence))) / ChunkFileEveryWorkUnits;

                        progress_operation_data_array.appendAssumeCapacity(.{
                            .file_idx = active_operation.target_file,
                            .chunk_idx = @divTrunc(active_operation.start_sequence, ChunkFileEveryWorkUnits),
                            .progress = progress,
                            .file = file,
                            .state = state,
                        });
                    }

                    var pending_writes = blk: {
                        var writes: usize = 0;
                        for (write_buffers.items) |buffer| {
                            if (buffer.is_task_done and buffer.is_io_pending) {
                                writes += 1;
                            }
                        }

                        break :blk writes;
                    };

                    std.log.debug("Pending writes: {}. Available Reads: {}. Num active ops: {}", .{ pending_writes, available_read_buffers.items.len, progress_operation_data_array.items.len });

                    var progress_data = ProgressCallback.CallbackData{
                        .creating_patch = .{
                            .operations = progress_operation_data_array,
                            .finished_operations = finished_operations,
                            .total_operations = num_operations_needed,
                        },
                    };
                    progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, &progress_data);
                }
            }
        }

        if (!has_pending_write) write_buffer_to_disk: {
            var buffer_to_write = blk: {
                var buffer_to_write: ?*WriteBuffer = null;

                for (write_buffers.items) |write_buffer| {
                    if (!write_buffer.is_task_done) {
                        continue;
                    }

                    if (!write_buffer.is_io_pending) {
                        continue;
                    }

                    buffer_to_write = write_buffer;
                }

                break :blk buffer_to_write;
            };

            if (buffer_to_write == null) {
                break :write_buffer_to_disk;
            }

            var write_buffer = buffer_to_write.?;

            // Write the patch file to disk.
            const IOWriteCallbackWrapper = struct {
                pub fn ioCallback(ctx: *anyopaque) void {
                    var buffer = @as(*WriteBuffer, @ptrCast(@alignCast(ctx)));
                    std.debug.assert(buffer.is_io_pending);

                    buffer.is_task_done = false;
                    buffer.is_io_pending = false;

                    buffer.has_pending_write.* = false;
                    std.log.debug("Wrote buffer of {}bytes in {}ms", .{ buffer.written_bytes, @divTrunc(std.time.nanoTimestamp() - buffer.write_start_time, std.time.ns_per_ms) });
                    buffer.written_bytes = ~@as(usize, 0);
                }
            };

            has_pending_write = true;

            write_buffer.write_start_time = std.time.nanoTimestamp();
            write_buffer.has_pending_write = &has_pending_write;

            var prev_offset = patch_file_offset;
            patch_file_offset += write_buffer.written_bytes;

            for (write_buffer.sequence_offsets.items, 0..) |sequence_offset, idx| {
                patch_header.sections.appendAssumeCapacity(
                    .{
                        .operations_start_pos_in_file = prev_offset + sequence_offset, // This needs to be taken from the write buffer offset
                        .file_idx = write_buffer.file_idx,
                        .sequence_idx = write_buffer.start_sequence + idx,
                    },
                );
            }

            try patch_io.writeFile(
                patch_handle,
                prev_offset,
                write_buffer.buffer[0..write_buffer.written_bytes],
                IOWriteCallbackWrapper.ioCallback,
                write_buffer,
            );
        }

        // Check if we are done generating the patch.
        {
            var has_pending_writes = false;
            for (write_buffers.items) |write_buffer| {
                has_pending_writes = has_pending_writes or write_buffer.is_io_pending;
            }

            var has_more_operations = active_patch_generation_operations.items.len != 0 or next_file_idx < new_signature.numFiles();

            if (!has_pending_writes and !has_more_operations) {
                break :generate_patch_loop;
            }
        }

        patch_io.tick();
    }

    // Serialize patch header
    {
        var counting_writer = std.io.CountingWriter(@TypeOf(std.io.null_writer)){
            .bytes_written = 0,
            .child_stream = std.io.null_writer,
        };
        try patch_header.savePatchHeader(counting_writer.writer());

        var patch_header_mem = try allocator.alloc(u8, counting_writer.bytes_written);
        defer allocator.free(patch_header_mem);

        var stream = std.io.fixedBufferStream(patch_header_mem);
        try patch_header.savePatchHeader(stream.writer());

        var is_done = false;
        const WriteHeaderCallback = struct {
            fn callback(ctx: *anyopaque) void {
                var is_done_from_ctx: *bool = @ptrCast(ctx);
                is_done_from_ctx.* = true;
            }
        };

        // Writing the file from zero with the proper section count will lead to some garbage data inbetween the end of our newly written data.
        // And the first written section. But that shouldn't be a problem.
        try patch_io.writeFile(
            patch_handle,
            0,
            patch_header_mem,
            WriteHeaderCallback.callback,
            &is_done,
        );

        while (!is_done) {
            patch_io.tick();
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }

    if (stats) |stats_unwrapped| {
        stats_unwrapped.total_patch_size_bytes = patch_file_offset;
    }
}
