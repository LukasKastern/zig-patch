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

pub fn createFileStructure(patch_io: *PatchIO, target_dir: std.fs.Dir, patch: *PatchHeader, allocator: std.mem.Allocator) !std.ArrayList(PatchIO.PlatformHandle) {
    const new_signature = patch.new;

    var dir_lookup = std.StringHashMap(PatchIO.PlatformHandle).init(allocator);
    defer dir_lookup.deinit();

    var patch_files = try std.ArrayList(PatchIO.PlatformHandle).initCapacity(allocator, patch.new.numFiles());
    errdefer {
        for (patch_files.items) |handle| {
            patch_io.closeHandle(handle);
        }
        patch_files.deinit();
    }

    var directories = try std.ArrayList(PatchIO.PlatformHandle).initCapacity(allocator, patch.new.numDirectories());
    defer {
        for (directories.items) |dir| {
            patch_io.closeHandle(dir);
        }
        directories.deinit();
    }

    for (0..new_signature.numDirectories()) |directory_idx| {
        var directory = new_signature.getDirectory(directory_idx);

        // Get first directory delimiter.
        var last_index_maybe = std.mem.lastIndexOfLinear(u8, directory.path[0 .. directory.path.len - 1], "/");
        var parent_directory: PatchIO.PlatformHandle = target_dir.fd;
        var directory_name = directory.path;

        if (last_index_maybe) |last_index| {
            var looking_for = directory.path[0 .. last_index + 1];
            parent_directory = dir_lookup.get(looking_for) orelse {
                std.log.err("Couldn't find parent directory for {s}. Patch might be corrupt. {s}", .{ directory.path, looking_for });
                return error.ParentDirectoryNotFound;
            };

            directory_name = directory.path[last_index + 1 ..];
        }

        // Remove path end.
        directory_name = directory_name[0 .. directory_name.len - 1];

        var dir_handle = try patch_io.createDirectory(parent_directory, directory_name);
        try dir_lookup.put(directory.path, dir_handle);
        directories.appendAssumeCapacity(dir_handle);
    }

    for (0..new_signature.numFiles()) |file_idx| {
        var file = new_signature.getFile(file_idx);

        var last_index_maybe = std.mem.lastIndexOfLinear(u8, file.name[0 .. file.name.len - 1], "/");
        var parent_directory: PatchIO.PlatformHandle = target_dir.fd;

        var file_name = file.name;
        if (last_index_maybe) |last_index| {
            var looking_for = file.name[0 .. last_index + 1];

            parent_directory = dir_lookup.get(looking_for) orelse {
                std.log.err("Couldn't find parent directory for {s}. Patch might be corrupt. {s}", .{ file.name, looking_for });
                return error.ParentDirectoryNotFound;
            };

            file_name = file.name[last_index + 1 ..];
        }

        patch_files.appendAssumeCapacity(try patch_io.createFile(parent_directory, file_name));
    }

    return patch_files;
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

    patched_file_handle: PatchIO.PlatformHandle,
    patch_file_offset: usize,

    active_patch_operation: ?struct {
        operation: BlockPatching.PatchOperation,
        is_write_pending: bool,
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
    defer inflating.deinit();

    var read_buffer_stream = std.io.fixedBufferStream(self.read_buffer);

    var counting_reader = std.io.countingReader(read_buffer_stream.reader());

    var compressed_section_size = try counting_reader.reader().readIntBig(usize);

    var compressed_buffer = self.read_buffer[counting_reader.bytes_read .. counting_reader.bytes_read + compressed_section_size];

    try inflating.inflateBuffer(compressed_buffer, self.inflated_buffer);

    try self.operations_iterator.init(self.inflated_buffer);
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
    patch_files: std.ArrayList(PatchIO.PlatformHandle),
) !void {
    _ = target_dir;
    _ = progress_callback;
    _ = patch_file_path;
    _ = source_dir;
    _ = working_dir;

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
            operation.patch_file_offset = 0;
            operation.active_patch_operation = null;

            operation.patched_file_handle = patch_files.items[last_used_file_idx_in_patch];

            running_operations.appendAssumeCapacity(operation_slot_idx);

            last_used_file_idx_in_patch += 1;
            num_files_processed += 1;
        }

        var running_operation_idx: isize = 0;
        while (running_operation_idx < running_operations.items.len) : (running_operation_idx += 1) {
            var running_operation = running_operations.items[@intCast(running_operation_idx)];

            var operation = &patch_operations[running_operation];

            switch (operation.state) {
                .Idle => {
                    var section_idx_in_patch = blk: {
                        // Start searching for the next section based on the last idx we had in the patch.
                        var last_section = operation.last_section_idx_in_patch orelse 0;
                        for (patch.sections.items[last_section..], 0..) |section, idx| {
                            if (section.file_idx == operation.file_idx) {
                                break :blk last_section + idx;
                            }
                        }
                        break :blk ~@as(usize, 0);
                    };

                    if (section_idx_in_patch == ~@as(usize, 0)) {
                        // No more sections remaining for this patch.
                        available_operation_slots.appendAssumeCapacity(running_operation);
                        _ = running_operations.swapRemove(@intCast(running_operation_idx));
                        running_operation_idx -= 1;
                        continue;
                    }

                    operation.last_section_idx_in_patch = section_idx_in_patch;

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
                        if (try operation.operations_iterator.nextOperation()) |patch_op| {
                            switch (patch_op) {
                                .Data => |data_op| {
                                    const WriteDataIoCallback = struct {
                                        fn callback(ctx: *anyopaque) void {
                                            var op: *ApplyPatchOperation = @ptrCast(@alignCast(ctx));
                                            op.active_patch_operation = null;
                                        }
                                    };

                                    operation.active_patch_operation = .{
                                        .operation = patch_op,
                                        .is_write_pending = true,
                                    };

                                    try patch_io.writeFile(
                                        operation.patched_file_handle,
                                        operation.patch_file_offset,
                                        data_op,
                                        WriteDataIoCallback.callback,
                                        operation,
                                    );

                                    operation.patch_file_offset += data_op.len;

                                    if (stats) |stats_unwrapped| {
                                        stats_unwrapped.total_patch_size_bytes += data_op.len;
                                    }
                                },
                                else => unreachable, //TODO:
                            }
                        } else {
                            operation.last_section_idx_in_patch.? += 1;
                            operation.state = .Idle;
                        }
                    }
                },
            }
        }

        patch_io.tick();

        if (num_files_processed == num_files_with_data and running_operations.items.len == 0) {
            break :apply_patch_loop;
        } else {
            continue :apply_patch_loop;
        }
    }
}
