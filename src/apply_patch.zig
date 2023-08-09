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

pub fn applyPatch(working_dir: std.fs.Dir, source_dir: ?std.fs.Dir, target_dir: std.fs.Dir, patch_file_path: []const u8, patch: *PatchHeader, thread_pool: *ThreadPool, allocator: std.mem.Allocator, progress_callback: ?ProgressCallback, stats: ?*ApplyPatchStats) !void {
    var per_thread_operations_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    defer allocator.free(per_thread_operations_buffer);

    for (per_thread_operations_buffer) |*operations_buffer| {
        operations_buffer.* = try allocator.alloc(u8, PatchGeneration.DefaultMaxWorkUnitSize * 6 + 8096);
    }

    defer {
        for (per_thread_operations_buffer) |operations_buffer| {
            allocator.free(operations_buffer);
        }
    }

    var per_thread_read_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    defer allocator.free(per_thread_read_buffer);

    for (per_thread_read_buffer) |*operations_buffer| {
        operations_buffer.* = try allocator.alloc(u8, BlockSize);
    }

    defer {
        for (per_thread_read_buffer) |operations_buffer| {
            allocator.free(operations_buffer);
        }
    }

    var per_thread_patch_files = try allocator.alloc(std.fs.File, thread_pool.max_threads);
    defer allocator.free(per_thread_patch_files);

    for (per_thread_patch_files) |*per_thread_patch_file| {
        per_thread_patch_file.* = try working_dir.openFile(patch_file_path, .{});
    }

    defer {
        for (per_thread_patch_files) |*per_thread_patch_file| {
            per_thread_patch_file.close();
        }
    }

    var per_thread_applied_bytes = try allocator.alloc(usize, thread_pool.max_threads);
    defer allocator.free(per_thread_applied_bytes);

    for (per_thread_applied_bytes) |*applied_bytes| {
        applied_bytes.* = 0;
    }

    var tasks = try allocator.alloc(ApplyPatchTask, patch.sections.items.len);
    defer allocator.free(tasks);

    var anchored_blocks_map = try AnchoredBlocksMap.init(patch.old, allocator);
    defer anchored_blocks_map.deinit();

    var batch = ThreadPool.Batch{};

    var sections_remaining = std.atomic.Atomic(usize).init(patch.sections.items.len);
    var are_sections_done = std.atomic.Atomic(u32).init(0);

    var task_idx: usize = 0;
    while (task_idx < patch.sections.items.len) : (task_idx += 1) {
        var section = patch.sections.items[task_idx];

        // zig fmt: off
        tasks[task_idx] = .{ 
            .per_thread_applied_bytes = per_thread_applied_bytes, 
            .per_thread_read_buffers = per_thread_read_buffer, 
            .old_signature = patch.old, 
            .anchored_blocks_map = anchored_blocks_map, 
            .source_dir = source_dir, 
            .per_thread_operations_buffer = per_thread_operations_buffer, 
            .section = patch.sections.items[task_idx], 
            .target_dir = target_dir, 
            .are_sections_done = &are_sections_done, 
            .sections_remaining = &sections_remaining, 
            .per_thread_patch_files = per_thread_patch_files, 
            .task = ThreadPool.Task{ .callback = ApplyPatchTask.applyPatch }, 
            .file = patch.new.getFile(section.file_idx),
        };
        // zig fmt: on

        batch.push(ThreadPool.Batch.from(&tasks[task_idx].task));
    }

    thread_pool.schedule(batch);

    var num_sections_remaining = sections_remaining.load(.Acquire);
    while (num_sections_remaining != 0 and are_sections_done.load(.Acquire) == 0) {
        if (progress_callback) |progress_callback_unwrapped| {
            var elapsed_progress = (1.0 - @as(f32, @floatFromInt(num_sections_remaining)) / @as(f32, @floatFromInt(patch.sections.items.len))) * 100;
            progress_callback_unwrapped.callback(progress_callback_unwrapped.user_object, elapsed_progress, "Merging Patch Sections");
        }

        std.time.sleep(std.time.ns_per_ms * 100);
        num_sections_remaining = sections_remaining.load(.Acquire);
    }

    if (stats) |stats_unwrapped| {
        stats_unwrapped.total_patch_size_bytes = 0;

        for (per_thread_applied_bytes) |applied_bytes| {
            stats_unwrapped.total_patch_size_bytes += applied_bytes;
        }
    }
}
