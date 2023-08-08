const std = @import("std");
const time = std.time;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const ApplyPatch = @import("apply_patch.zig");
const SignatureFile = @import("signature_file.zig").SignatureFile;
const PatchGeneration = @import("patch_generation.zig");
const utils = @import("utils.zig");
const PatchIO = @import("io/patch_io.zig");

pub const ProgressCallback = struct {
    user_object: *anyopaque,
    callback: *const fn (*anyopaque, f32, ?[]const u8) void,
};

pub const OperationStats = struct {
    pub const ApplyPatchStats = struct {
        num_files: usize = 0,
        num_directories: usize = 0,
        total_patch_size_bytes: usize = 0,
    };

    pub const CreatePatchStats = struct {
        changed_blocks: usize = 0,
        total_blocks: usize = 0,
        total_signature_folder_size_bytes: usize = 0,
        num_new_bytes: usize = 0,
        total_patch_size_bytes: usize = 0,
    };

    pub const MakeSignatureStats = struct {
        total_signature_folder_size_bytes: usize = 0,
        num_files: usize = 0,
        num_directories: usize = 0,
    };

    apply_patch_stats: ?ApplyPatchStats = null,
    create_patch_stats: ?CreatePatchStats = null,
    make_signature_stats: ?MakeSignatureStats = null,
    total_operation_time: f64 = 0,
};

pub const OperationConfig = struct {
    thread_pool: *ThreadPool,
    allocator: std.mem.Allocator,
    working_dir: std.fs.Dir,
    progress_callback: ?ProgressCallback = null,
};

pub fn applyPatch(patch_file_path: []const u8, folder_to_patch: []const u8, config: OperationConfig, stats: ?*OperationStats) !void {
    var allocator = config.allocator;
    var thread_pool = config.thread_pool;
    var cwd: std.fs.Dir = config.working_dir;

    var timer = try time.Timer.start();
    var start_sample = timer.read();

    var patch_file = cwd.openFile(patch_file_path, .{}) catch |e| {
        switch (e) {
            else => {
                std.log.err("Failed to open patch file, error => {}", .{e});
                return error.FailedToOpenPatchFile;
            },
        }
    };

    defer patch_file.close();

    var patch_file_reader = patch_file.reader();

    var patch = PatchHeader.loadPatchHeader(allocator, patch_file_reader) catch |e| {
        switch (e) {
            else => {
                std.log.err("Failed to deserialize patch file, error => {}", .{e});
                return error.FailedToLoadPatchHeader;
            },
        }
    };

    defer patch.deinit();
    defer patch.new.deinit();
    defer patch.old.deinit();

    var apply_patch_stats: ?*OperationStats.ApplyPatchStats = null;

    if (stats) |stats_unwrapped| {
        stats_unwrapped.apply_patch_stats = .{ .num_files = patch.new.numFiles(), .num_directories = patch.new.numDirectories() };
        apply_patch_stats = &stats_unwrapped.apply_patch_stats.?;
    }

    var validate_source_folder = patch.old.blocks.items.len > 0;

    var staging_folder_path_buffer: [1024]u8 = undefined;

    var tmp_folder: ?std.fs.Dir = try findPatchStagingDir(cwd);
    defer {
        if (tmp_folder) |*tmp_unwrapped| {
            tmp_unwrapped.close();
        }
    }

    var tmp_folder_path = try tmp_folder.?.realpath("", &staging_folder_path_buffer);

    var source_folder: ?std.fs.Dir = null;
    defer {
        if (source_folder) |*source_folder_unwrapped| {
            source_folder_unwrapped.close();
        }
    }

    var source_folder_with_err = cwd.openDir(folder_to_patch, .{});

    if (source_folder_with_err) |folder_without_err| {
        source_folder = folder_without_err;
    } else |err| {
        switch (err) {
            error.FileNotFound => {
                // Not finding the directory will fail further down in case we need the source folder.
                // If the patch doesn't require a reference this error is okay.
            },
            else => {
                std.log.err("Failed to open source folder, error => {}", .{err});
                return error.FailedToOpenSourceFolder;
            },
        }
    }

    if (validate_source_folder) {
        if (source_folder == null or !@call(.never_inline, SignatureFile.validateFolderMatchesSignature, .{ patch.old, source_folder.? })) {
            std.log.err("Source folder doesn't match reference that the patch was generated from", .{});
            return error.SignatureMismatch;
        }
    }

    if (source_folder) |source_folde_unwrapped| {
        // Copy the folder to patch into our temporary staging folder.
        try @call(.never_inline, utils.copyFolder, .{ tmp_folder.?, source_folde_unwrapped });
    }

    try @call(.never_inline, ApplyPatch.createFileStructure, .{ tmp_folder.?, patch });

    try @call(.never_inline, ApplyPatch.applyPatch, .{ cwd, source_folder, tmp_folder.?, patch_file_path, patch, thread_pool, allocator, config.progress_callback, apply_patch_stats });

    if (source_folder) |*source_folder_unwrapped| {
        // If we already have a folder at the source path we back it up.

        source_folder_unwrapped.close();
        source_folder = null;
        try cwd.deleteTree(folder_to_patch);
    }

    tmp_folder.?.close();
    tmp_folder = null;
    try cwd.rename(tmp_folder_path, folder_to_patch);

    var end_sample = timer.read();
    std.log.info("Applied Patch in {d:2}ms", .{(@as(f64, @floatFromInt(end_sample)) - @as(f64, @floatFromInt(start_sample))) / 1000000});

    if (stats) |*operation_stats| {
        operation_stats.*.total_operation_time = (@as(f64, @floatFromInt(end_sample)) - @as(f64, @floatFromInt(start_sample))) / 1000000;
    }
}

fn findPatchStagingDir(cwd: std.fs.Dir) !std.fs.Dir {
    const MaxAttempts = 50;

    var dir = cwd;

    var attempt: usize = 0;

    var print_buffer: [128]u8 = undefined;

    while (attempt < MaxAttempts) : (attempt += 1) {
        var path_str = try std.fmt.bufPrint(&print_buffer, "PatchTemp_{}", .{attempt});

        dir.makeDir(path_str) catch |make_err| {
            switch (make_err) {
                error.PathAlreadyExists => {
                    // If the path already exists we try to delete it first erasing all file previously stored in it.
                    dir.deleteTree(path_str) catch |delete_err| {
                        switch (delete_err) {
                            else => {
                                continue;
                            },
                        }
                    };

                    // And then recreate it.
                    dir.makeDir(path_str) catch |err| {
                        switch (err) {
                            else => {
                                continue;
                            },
                        }
                    };
                },
                else => {
                    continue;
                },
            }
        };

        return dir.openDir(path_str, .{});
    }

    return error.NoSuitableStagingPathFound;
}

pub fn createPatch(source_folder_path: []const u8, previous_signature: ?[]const u8, config: OperationConfig, stats: ?*OperationStats) !void {
    var allocator = config.allocator;
    var thread_pool = config.thread_pool;
    var cwd: std.fs.Dir = config.working_dir;

    var open_dir = cwd.openDir(source_folder_path, .{}) catch {
        std.log.err("Specified target folder \"{s}\" could not be opened, make sure it exists", .{source_folder_path});
        return error.TargetFolderError;
    };

    defer open_dir.close();

    var timer = try time.Timer.start();
    var start_sample = timer.read();

    var prev_signature_file: ?*SignatureFile = null;
    defer {
        if (prev_signature_file) |sign_file| {
            sign_file.deinit();
        }
    }

    if (previous_signature == null) {
        std.log.warn("{s}", .{"No previous signature specified. A full patch will be generated. Specify a previous signature using --previous_signature <path>"});
        prev_signature_file = try SignatureFile.init(allocator);
        try prev_signature_file.?.initializeToEmptyInMemoryFile();
    } else {
        var out_file = try cwd.openFile(previous_signature.?, .{});
        defer out_file.close();

        const BufferedFileReader = std.io.BufferedReader(1200, std.fs.File.Reader);
        var buffered_file_reader: BufferedFileReader = .{
            .unbuffered_reader = out_file.reader(),
        };
        var reader = buffered_file_reader.reader();

        prev_signature_file = SignatureFile.loadSignature(reader, allocator) catch |e| {
            switch (e) {
                else => {
                    std.log.err("Failed to load previous signature file at path {s}, error={}", .{ previous_signature.?, e });
                    return error.ReferenceSignatureLoadFailed;
                },
            }
        };

        var post_signature_load_time = timer.read();
        std.log.info("Loaded Previous Signature in {d:2}ms", .{(@as(f64, @floatFromInt(post_signature_load_time)) - @as(f64, @floatFromInt(start_sample))) / 1000000});
    }

    var staging_patch_path_buffer: [512]u8 = undefined;
    var staging_dir_path: []u8 = undefined;

    {
        var staging_dir = try findPatchStagingDir(cwd);
        defer staging_dir.close();

        var new_signature_file = try SignatureFile.init(allocator);
        defer new_signature_file.deinit();

        std.log.info("Generating Signature from {s}...", .{source_folder_path});

        var patch_io = try PatchIO.init(allocator);
        defer patch_io.deinit();

        var src_folder_temp_buffer: [1024]u8 = undefined;
        var abs_src_folder_path = try cwd.realpath(source_folder_path, &src_folder_temp_buffer);

        var generate_signature_start_sample = timer.read();
        try new_signature_file.generateFromFolder(abs_src_folder_path, thread_pool, config.progress_callback, &patch_io);
        var generate_signature_finish_sample = timer.read();

        std.log.info("Generated Signature in {d:2}ms", .{(@as(f64, @floatFromInt(generate_signature_finish_sample)) - @as(f64, @floatFromInt(generate_signature_start_sample))) / 1000000});

        std.log.info("Creating Patch...", .{});

        var create_patch_stats: ?*OperationStats.CreatePatchStats = null;

        if (stats) |stats_unwrapped| {
            stats_unwrapped.create_patch_stats = .{};
            create_patch_stats = &stats_unwrapped.create_patch_stats.?;

            for (0..new_signature_file.numFiles()) |file_idx| {
                var file = new_signature_file.getFile(file_idx);
                create_patch_stats.?.total_signature_folder_size_bytes += file.size;
            }
        }

        var create_patch_start_sample = timer.read();
        try PatchGeneration.createPatchV2(&patch_io, thread_pool, new_signature_file, prev_signature_file.?, allocator, .{ .build_dir = open_dir, .staging_dir = staging_dir }, create_patch_stats, config.progress_callback);
        var create_patch_finish_sample = timer.read();

        if (stats) |*operation_stats| {
            operation_stats.*.total_operation_time = (@as(f64, @floatFromInt(create_patch_finish_sample)) - @as(f64, @floatFromInt(create_patch_start_sample))) / 1000000;
        }

        staging_dir_path = try staging_dir.realpath("", &staging_patch_path_buffer);

        var src_patch_path_buffer: [512]u8 = undefined;
        var src_patch_path = try std.fmt.bufPrint(&src_patch_path_buffer, "{s}/Patch.pwd", .{staging_dir_path});

        var dst_patch_path_buffer: [512]u8 = undefined;
        var dst_patch_path = try std.fmt.bufPrint(&dst_patch_path_buffer, "{s}/../Patch.pwd", .{staging_dir_path});

        try std.os.rename(src_patch_path, dst_patch_path);
    }

    try std.fs.deleteTreeAbsolute(staging_dir_path);
    std.log.info("The patch was generated successfully", .{});
}

pub fn makeSignature(folder_to_make_signature_of: []const u8, output_path: []const u8, config: OperationConfig, stats: ?*OperationStats) !void {
    var timer = try time.Timer.start();
    var make_signature_start_sample = timer.read();

    var signature_file = try SignatureFile.init(config.allocator);
    defer signature_file.deinit();

    var target_dir = try config.working_dir.openDir(folder_to_make_signature_of, .{});
    defer target_dir.close();

    var file = try config.working_dir.createFile(output_path, .{});
    defer file.close();

    var patch_io = try PatchIO.init(config.allocator);
    defer patch_io.deinit();

    try signature_file.generateFromFolder(folder_to_make_signature_of, config.thread_pool, config.progress_callback, &patch_io);

    const BufferedFileWriter = std.io.BufferedWriter(1200, std.fs.File.Writer);
    var buffered_file_writer: BufferedFileWriter = .{
        .unbuffered_writer = file.writer(),
    };

    var writer = buffered_file_writer.writer();

    try signature_file.saveSignature(writer);
    try buffered_file_writer.flush();

    var make_signature_finish_sample = timer.read();

    if (stats) |*operation_stats| {
        operation_stats.*.total_operation_time = (@as(f64, @floatFromInt(make_signature_finish_sample)) - @as(f64, @floatFromInt(make_signature_start_sample))) / 1000000;

        var total_signature_folder_size_bytes: usize = 0;

        for (0..signature_file.numFiles()) |signature_file_elem_idx| {
            var signature_file_elem = signature_file.getFile(signature_file_elem_idx);
            total_signature_folder_size_bytes += signature_file_elem.size;
        }

        var make_signature_stats: OperationStats.MakeSignatureStats = .{
            .num_files = signature_file.numFiles(),
            .num_directories = signature_file.numDirectories(),
            .total_signature_folder_size_bytes = total_signature_folder_size_bytes,
        };

        operation_stats.*.make_signature_stats = make_signature_stats;
    }
}
