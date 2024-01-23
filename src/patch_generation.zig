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
const PatchIO = @import("io/patch_io.zig");

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

pub const DefaultMaxWorkUnitSize = BlockSize * 128;

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

pub fn createPatchV2(patch_io: *PatchIO, thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOptions, stats: ?*CreatePatchStats, progress_callback: ?ProgressCallback) !void {
    var anchored_block_map = try AnchoredBlocksMap.init(old_signature, allocator);
    defer anchored_block_map.deinit();
    const ProgressData = struct {
        progress_callback: ?ProgressCallback,
        total_num_tasks: usize,
        tasks_completed: usize,
    };

    //TODO: This should be MaxWorkUnitSize / MaxDataOpLen or something like
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
        progress_data: *ProgressData,
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

        current_read_buffer: ?usize,
        next_read_buffer: ?usize,

        first_sequence_patch_file_idx: usize,

        write_buffer: ?*WriteBuffer,

        has_active_task: std.atomic.Atomic(u32),

        task: ThreadPool.Task,

        state: *PatchGenerationTaskState,

        generate_operations_state: BlockPatching.GenerateOperationsState,

        start_time: i128,

        stats: struct {
            total_blocks: usize = 0,
            changed_blocks: usize = 0,
            num_new_bytes: usize = 0,
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
            self.generate_operations_state.in_buffer = &data_buffer.data;

            var temp_buffer = &self.state.per_thread_working_buffers[ThreadPool.Thread.current.?.idx];
            var temp_allocator = std.heap.FixedBufferAllocator.init(temp_buffer);

            var operations = BlockPatching.generateOperationsForBufferIncremental(
                self.state.block_map.*,
                &self.generate_operations_state,
                temp_allocator.allocator(),
                MaxDataOperationLength,
            ) catch unreachable;

            var operations_buffer = temp_allocator.allocator().alloc(u8, DefaultMaxWorkUnitSize + 2048) catch unreachable;
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

                var deflating = Compression.Deflating.init(Compression.Default, deflating_allocator) catch unreachable;
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

    var progress_data = ProgressData{
        .progress_callback = progress_callback,
        .total_num_tasks = numTasksNeeded(new_signature, DefaultMaxWorkUnitSize),
        .tasks_completed = 0,
    };

    var patch_header = try PatchHeader.init(new_signature, old_signature, allocator);
    defer patch_header.deinit();

    const patch_handle = try patch_io.createFile(options.staging_dir.fd, "Patch.pwd");

    const patch = std.fs.File{ .handle = patch_handle };
    defer patch.close();

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

        std.log.info("Num sections: {}", .{num_sections});
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

                var slot = available_operation_slots.orderedRemove(available_operation_slots.items.len - 1);
                active_patch_generation_operations.appendAssumeCapacity(slot);

                operation_slots[slot] = .{
                    .state = task_state,
                    .next_sequence = 0,
                    .target_file = next_file_idx,
                    .sequence = 0,
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
                };
                operation_slots[slot].generate_operations_state.init(file.size);

                var file_size = new_signature.getFile(next_file_idx).size;
                patch_file_idx += @as(usize, @intFromFloat(@ceil(@as(f32, @floatFromInt(file_size)) / DefaultMaxWorkUnitSize)));

                next_file_idx += 1;
            }

            schedule_buffer_reads: for (active_patch_generation_operations.items) |operation_idx| {
                if (available_read_buffers.items.len == 0) {
                    break :schedule_buffer_reads;
                }

                var active_operation = &operation_slots[operation_idx];

                if (active_operation.next_read_buffer == null) {
                    var current_start_offset = active_operation.next_sequence * DefaultMaxWorkUnitSize;
                    var file_size = new_signature.getFile(active_operation.target_file).size;

                    if (current_start_offset >= file_size) {
                        // We already reached the end of the file.
                        // Meaning it doesn't need another buffer.
                        continue;
                    }

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

                    std.log.debug("Reading buffer for file: {}", .{active_operation.target_file});
                    var file_handle = new_signature.data.?.OnDiskSignatureFile.locked_directory.files.items[active_operation.target_file].handle;
                    try patch_io.readFile(file_handle, current_start_offset, &read_buffer.data, IOCallbackWrapper.ioCallback, read_buffer);
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

                    var is_operation_done = next_start_offset >= file_size;

                    {
                        var can_write_buffer_fit_another_patch = write_buffer.buffer.len - write_buffer.written_bytes > MaxOperationOutputSize;

                        write_buffer.is_task_done = is_operation_done or !can_write_buffer_fit_another_patch;

                        if (write_buffer.is_task_done) {
                            active_operation.write_buffer = null;
                        }
                    }

                    progress_data.tasks_completed += 1;

                    if (stats) |stats_unwrapped| {
                        stats_unwrapped.total_blocks += active_operation.stats.total_blocks;
                        stats_unwrapped.num_new_bytes += active_operation.stats.num_new_bytes;
                        stats_unwrapped.changed_blocks += active_operation.stats.changed_blocks;
                    }

                    if (is_operation_done) {
                        std.log.debug(
                            "Operation for file: {} completed in {}ms",
                            .{ active_operation.target_file, @divTrunc(std.time.nanoTimestamp() - active_operation.start_time, std.time.ns_per_ms) },
                        );

                        active_operation.write_buffer = null;

                        available_operation_slots.appendAssumeCapacity(operation_idx);
                        _ = active_patch_generation_operations.swapRemove(@as(usize, @intCast(idx)));
                        idx -= 1;
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
                                        .progress_data = &progress_data,
                                        .has_pending_write = undefined,
                                        .write_start_time = undefined,
                                        .file_idx = 0,
                                        .start_sequence = 0,
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
                            write_buffer.written_bytes = 0;

                            if (write_buffer.start_sequence == 0) {
                                write_buffer.start_sequence = active_operation.next_sequence;
                            }

                            write_buffer.file_idx = active_operation.target_file;

                            active_operation.current_read_buffer = next_buffer;
                            active_operation.next_read_buffer = null;

                            active_operation.sequence = active_operation.next_sequence;
                            active_operation.next_sequence += 1;

                            active_operation.has_active_task.store(1, .Release);

                            thread_pool.schedule(ThreadPool.Batch.from(&active_operation.task));
                        }
                    }
                }
            }
        }

        if (progress_data.progress_callback) |progress_callback_unwrapped| {
            var elapsed_progress = (@as(f32, @floatFromInt(progress_data.tasks_completed)) / @as(f32, @floatFromInt(progress_data.total_num_tasks))) * 100;
            progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Generating Patches");
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

                    if (buffer_to_write) |unwrapped_buffer| {
                        // Buffers that point towards the same file need to be written in order.
                        // This is required by the way the patch is applied.
                        if (unwrapped_buffer.file_idx == write_buffer.file_idx and unwrapped_buffer.start_sequence > write_buffer.start_sequence) {
                            buffer_to_write = write_buffer;
                        }
                    } else {
                        buffer_to_write = write_buffer;
                    }
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

                    var write_end_time = std.time.nanoTimestamp();

                    if (buffer.file_idx == 0 and buffer.start_sequence == 0) {
                        std.log.info(
                            "Wrote {} bytes in {}ms {any}",
                            .{
                                buffer.written_bytes,
                                @divTrunc(write_end_time - buffer.write_start_time, std.time.ns_per_ms),
                                buffer.buffer[0..buffer.written_bytes],
                            },
                        );
                    }

                    buffer.written_bytes = ~@as(usize, 0);
                }
            };

            has_pending_write = true;

            write_buffer.write_start_time = std.time.nanoTimestamp();
            write_buffer.has_pending_write = &has_pending_write;

            var prev_offset = patch_file_offset;
            patch_file_offset += write_buffer.written_bytes;

            for (write_buffer.sequence_offsets.items) |sequence_offset| {
                // std.log.info("Section: {}", .{patch_header.sections.items.len});
                patch_header.sections.appendAssumeCapacity(
                    .{
                        .operations_start_pos_in_file = prev_offset + sequence_offset, // This needs to be taken from the write buffer offset
                        .file_idx = write_buffer.file_idx,
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
}

fn numTasksNeeded(signature: *SignatureFile, work_unit_size: usize) usize {
    var num_patch_files: usize = 0;

    var file_idx: usize = 0;
    while (file_idx < signature.numFiles()) : (file_idx += 1) {
        var file = signature.getFile(file_idx);
        num_patch_files += @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(file.size)) / @as(f64, @floatFromInt(work_unit_size)))));
    }

    return num_patch_files;
}

// test "two files with no previous signature should result in two data operation patches" {
//     var old_signature = try SignatureFile.init(std.testing.allocator);
//     defer old_signature.deinit();

//     var new_signature = try SignatureFile.init(std.testing.allocator);
//     defer new_signature.deinit();

//     const file_size = 1200;

//     try new_signature.files.append(.{
//         .name = try std.testing.allocator.alloc(u8, 1),
//         .size = file_size,
//         .permissions = 0,
//     });

//     try new_signature.files.append(.{
//         .name = try std.testing.allocator.alloc(u8, 1),
//         .size = file_size,
//         .permissions = 0,
//     });

//     var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
//     thread_pool.spawnThreads();

//     const PatchFileIOMock = struct {
//         const MockedFileWriteData = struct {
//             info: PatchFileInfo,
//             operations: std.ArrayList(BlockPatching.PatchOperation),
//         };

//         file_io: PatchFileIO,

//         patches: ParallelList(MockedFileWriteData),
//         allocator: std.mem.Allocator,

//         fn seedFromFileInfo(file_info: PatchFileInfo) usize {
//             return (file_info.file_idx + 4) * file_info.file_idx + file_info.file_part_idx * 4;
//         }

//         fn write(patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void {
//             var self = @fieldParentPtr(@This(), "file_io", patch_file_io);

//             var mocked_write_data: MockedFileWriteData = .{
//                 .operations = std.ArrayList(BlockPatching.PatchOperation).initCapacity(self.allocator, patch_data.operations.items.len) catch unreachable,
//                 .info = patch_data.file_info,
//             };

//             for (patch_data.operations.items) |operation| {
//                 var copied_operation = operation;

//                 if (copied_operation == .Data) {
//                     copied_operation = BlockPatching.PatchOperation{ .Data = self.allocator.alloc(u8, copied_operation.Data.len) catch unreachable };
//                     std.mem.copy(u8, copied_operation.Data, operation.Data);
//                 }

//                 mocked_write_data.operations.appendAssumeCapacity(copied_operation);
//             }

//             var patch_list = self.patches.getList(ThreadPool.Thread.current.?.idx);
//             patch_list.append(mocked_write_data) catch unreachable;
//         }

//         fn read(patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize {
//             _ = patch_file_io;

//             var prng = std.rand.DefaultPrng.init(seedFromFileInfo(file_info));
//             var random = prng.random();

//             var idx: usize = 0;
//             while (idx < file_size) : (idx += 1) {
//                 read_buffer[idx] = random.int(u8);
//             }

//             return file_size;
//         }
//     };

//     // zig fmt: off
//     var io_mock: PatchFileIOMock = .{
//         .allocator = std.testing.allocator,
//         .file_io = .{
//             .write_patch_file = &PatchFileIOMock.write,
//             .read_patch_file = &PatchFileIOMock.read,
//         },
//         .patches = try ParallelList(PatchFileIOMock.MockedFileWriteData).init(std.testing.allocator, thread_pool.max_threads)
//     };
//     // zig fmt: on

//     defer {
//         for (io_mock.patches.per_thread_lists) |per_thread_list| {
//             for (per_thread_list.items) |patch| {
//                 for (patch.operations.items) |operation| {
//                     if (operation == .Data) {
//                         io_mock.allocator.free(operation.Data);
//                     }
//                 }

//                 patch.operations.deinit();
//             }
//         }

//         io_mock.patches.deinit();
//     }

//     var create_patch_options: CreatePatchOptions = .{ .staging_dir = undefined, .build_dir = undefined };

//     try createPerFilePatchOperations(&thread_pool, new_signature, old_signature, std.testing.allocator, .{ .patch_file_io = &io_mock.file_io, .create_patch_options = create_patch_options }, null, null);

//     var patches = try io_mock.patches.flattenParallelList(std.testing.allocator);
//     defer std.testing.allocator.free(patches);

//     try std.testing.expectEqual(@as(usize, 2), patches.len);

//     for (patches) |patch| {
//         try std.testing.expectEqual(@as(usize, 1), patch.operations.items.len);

//         var operation = patch.operations.items[0];

//         try std.testing.expect(operation == .Data);

//         var prng = std.rand.DefaultPrng.init(PatchFileIOMock.seedFromFileInfo(patch.info));
//         var random = prng.random();

//         var idx: usize = 0;
//         while (idx < file_size) : (idx += 1) {
//             try std.testing.expectEqual(random.int(u8), operation.Data[idx]);
//         }
//     }

//     const ShutdownTaskData = struct {
//         task: ThreadPool.Task,
//         pool: *ThreadPool,

//         fn shutdownThreadpool(task: *ThreadPool.Task) void {
//             var shutdown_task_data = @fieldParentPtr(@This(), "task", task);
//             shutdown_task_data.pool.shutdown();
//         }
//     };

//     var shutdown_task_data = ShutdownTaskData{
//         .task = ThreadPool.Task{ .callback = ShutdownTaskData.shutdownThreadpool },
//         .pool = &thread_pool,
//     };

//     thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
//     defer ThreadPool.deinit(&thread_pool);
// }
