const std = @import("std");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const FileSection = @import("patch_header.zig").FileSection;
const SignatureFile = @import("signature_file.zig").SignatureFile;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const PatchGeneration = @import("patch_generation.zig");
const BlockPatching = @import("block_patching.zig");

pub fn createFileStructure(target_dir: std.fs.Dir, patch: *PatchHeader) !void {
    const old_signature = patch.old;
    const new_signature = patch.new;

    // Delete all files that do not exist anymore
    for (old_signature.files.items) |file| {
        var does_file_still_exist = false;

        for (new_signature.files.items) |new_signature_file| {
            does_file_still_exist = does_file_still_exist or std.mem.eql(u8, new_signature_file.name, file.name);
        }

        if (!does_file_still_exist) {
            try target_dir.deleteFile(file.name);
        }
    }

    // Delete all directories that do not exist anymore
    for (old_signature.directories.items) |directory| {
        var does_dir_still_exist = false;

        for (new_signature.directories.items) |new_directory_file| {
            does_dir_still_exist = does_dir_still_exist or std.mem.eql(u8, new_directory_file.path, directory.path);
        }

        if (!does_dir_still_exist) {
            //TODO: Should we check if the directory is empty (lukas)?
            try target_dir.deleteTree(directory.path);
        }
    }

    // Now reverse the order operation and create all directories + files that did not exist in the old signature
    for (new_signature.directories.items) |directory| {
        var did_dir_exist = false;

        for (old_signature.directories.items) |old_directory_file| {
            did_dir_exist = did_dir_exist or std.mem.eql(u8, old_directory_file.path, directory.path);
        }

        if (!did_dir_exist) {
            try target_dir.makePath(directory.path);
        }
    }

    for (new_signature.files.items) |file| {
        var did_file_exist = false;

        for (old_signature.files.items) |old_file| {
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

    target_dir: std.fs.Dir,
    per_thread_patch_files: []std.fs.File,
    section: FileSection,
    file: SignatureFile.File,

    per_thread_operations_buffer: [][]u8,

    fn applyPatch(task: *ThreadPool.Task) void {
        var apply_patch_task_data = @fieldParentPtr(Self, "task", task);
        applyPatchImpl(apply_patch_task_data) catch unreachable;
    }

    fn applyPatchImpl(self: *Self) !void {
        var patch_file = self.per_thread_patch_files[ThreadPool.Thread.current.?.idx];

        try patch_file.seekTo(self.section.operations_start_pos_in_file);

        var operations_buffer = self.per_thread_operations_buffer[ThreadPool.Thread.current.?.idx];

        var num_patch_sections = @floatToInt(usize, @ceil(@intToFloat(f64, self.file.size) / @intToFloat(f64, PatchGeneration.DefaultMaxWorkUnitSize)));

        var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(operations_buffer);

        var file_reader = patch_file.reader();

        // std.debug.print("{} patches for file {s}\n", .{ num_patch_sections, self.file.name });

        var target_file = try self.target_dir.openFile(self.file.name, .{
            .mode = .write_only,
        });
        defer target_file.close();

        var target_file_writer = target_file.writer();

        var patch_section_idx: usize = 0;
        while (patch_section_idx < num_patch_sections) : (patch_section_idx += 1) {
            fixed_buffer_allocator.reset();
            var operations_allocator = fixed_buffer_allocator.allocator();
            var operations = try BlockPatching.loadOperations(operations_allocator, file_reader);

            for (operations.items) |operation| {
                if (operation == .Data) {
                    try target_file_writer.writeAll(operation.Data);
                }
            }
        }

        if (self.sections_remaining.fetchSub(1, .Release) == 1) {
            self.are_sections_done.store(1, .Release);
            std.Thread.Futex.wake(self.are_sections_done, 1);
        }
    }
};

pub fn applyPatch(working_dir: std.fs.Dir, target_dir: std.fs.Dir, patch_file_path: []const u8, patch: *PatchHeader, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    var per_thread_operations_buffer = try allocator.alloc([]u8, thread_pool.max_threads);
    defer allocator.free(per_thread_operations_buffer);

    for (per_thread_operations_buffer) |*operations_buffer| {
        operations_buffer.* = try allocator.alloc(u8, PatchGeneration.DefaultMaxWorkUnitSize + 8096);
    }

    defer {
        for (per_thread_operations_buffer) |operations_buffer| {
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

    var tasks = try allocator.alloc(ApplyPatchTask, patch.sections.items.len);
    defer allocator.free(tasks);

    var batch = ThreadPool.Batch{};

    var sections_remaining = std.atomic.Atomic(usize).init(patch.sections.items.len);
    var are_sections_done = std.atomic.Atomic(u32).init(0);

    var task_idx: usize = 0;
    while (task_idx < patch.sections.items.len) : (task_idx += 1) {
        var section = patch.sections.items[task_idx];

        tasks[task_idx] = .{ .per_thread_operations_buffer = per_thread_operations_buffer, .section = patch.sections.items[task_idx], .target_dir = target_dir, .are_sections_done = &are_sections_done, .sections_remaining = &sections_remaining, .per_thread_patch_files = per_thread_patch_files, .task = ThreadPool.Task{ .callback = ApplyPatchTask.applyPatch }, .file = patch.new.files.items[section.file_idx] };

        batch.push(ThreadPool.Batch.from(&tasks[task_idx].task));
    }

    thread_pool.schedule(batch);

    while (sections_remaining.load(.Acquire) != 0 and are_sections_done.load(.Acquire) == 0) {
        std.Thread.Futex.wait(&are_sections_done, 0);
    }
}
