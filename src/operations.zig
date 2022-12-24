const std = @import("std");
const time = std.time;
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const ApplyPatch = @import("apply_patch.zig");
const SignatureFile = @import("signature_file.zig").SignatureFile;
const PatchGeneration = @import("patch_generation.zig");

pub const OperationConfig = struct {
    thread_pool: *ThreadPool,
    allocator: std.mem.Allocator,
    working_dir: std.fs.Dir,
};

pub fn applyPatch(patch_file_path: []const u8, folder_to_patch: ?[]const u8, patched_output_path: []const u8, config: OperationConfig) !void {
    var allocator = config.allocator;
    var thread_pool = config.thread_pool;
    var cwd: std.fs.Dir = config.working_dir;

    var timer = try time.Timer.start();
    var start_sample = timer.read();

    var patch_file = cwd.openFile(patch_file_path, .{}) catch |e| {
        switch (e) {
            else => {
                std.log.err("Failed to open patch file, error => {}", .{e});
                return;
            },
        }
    };

    defer patch_file.close();

    var patch_file_reader = patch_file.reader();

    var patch = PatchHeader.loadPatchHeader(allocator, patch_file_reader) catch |e| {
        switch (e) {
            else => {
                std.log.err("Failed to deserialize patch file, error => {}", .{e});
                return;
            },
        }
    };

    defer patch.deinit();
    defer patch.new.deinit();
    defer patch.old.deinit();

    var validate_source_folder = patch.old.blocks.items.len > 0 or patch.old.directories.items.len > 0 or patch.old.files.items.len > 0;

    if (validate_source_folder) {
        if (folder_to_patch == null) {
            std.log.err("No --source_folder <str> passed to apply. But the specified patch requires a reference folder.", .{});
            return;
        }

        var source_folder = std.fs.openDirAbsolute(folder_to_patch.?, .{}) catch |e| {
            switch (e) {
                else => {
                    std.log.err("Failed to open soource folder, error => {}", .{e});
                    return;
                },
            }
        };
        defer source_folder.close();

        if (!patch.old.validateFolderMatchesSignature(source_folder)) {
            std.log.err("Source folder doesn't match reference that the patch was generated from", .{});
            return;
        }
    }

    cwd.deleteTree(patched_output_path) catch |e| {
        switch (e) {
            error.BadPathName => {
                // All good!
            },

            // error.DirNotEmpty => {
            //     std.log.err("Cannot use specified target folder since it's not empty.", .{});
            //     return error.FailedToDeleteTargetDir;
            // },
            else => {
                std.log.err("DeleteDir failed with error={}", .{e});
                return error.FailedToDeleteTargetDir;
            },
        }
    };

    cwd.makeDir(patched_output_path) catch |e| {
        switch (e) {
            error.PathAlreadyExists => {
                std.log.err("Failed to delete target folder. Make sure it's empty!", .{});
                return error.FailedToDeleteTargetDir;
            },
            else => {
                std.log.err("Failed to create target folder. Error={}", .{e});
                return;
            },
        }
    };

    var target_dir = try cwd.openDir(patched_output_path, .{});
    defer target_dir.close();

    try ApplyPatch.createFileStructure(target_dir, patch);

    try ApplyPatch.applyPatch(target_dir, patch_file_path, patch, thread_pool, allocator);
    var end_sample = timer.read();

    std.log.info("Applied Patch in {d:2}ms", .{(@intToFloat(f64, end_sample) - @intToFloat(f64, start_sample)) / 1000000});
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

pub fn createPatch(source_folder_path: []const u8, previous_patch_path: ?[]const u8, config: OperationConfig) !void {
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

    if (previous_patch_path == null) {
        std.log.warn("{s}\n\n", .{"No previous patch specified. A full patch will be generated. Specify a previous patch using --previous_patch <path>"});
        prev_signature_file = try SignatureFile.init(allocator);
    } else {
        var out_file = try std.fs.openFileAbsolute(previous_patch_path.?, .{});
        defer out_file.close();

        const BufferedFileReader = std.io.BufferedReader(1200, std.fs.File.Reader);
        var buffered_file_reader: BufferedFileReader = .{
            .unbuffered_reader = out_file.reader(),
        };
        var reader = buffered_file_reader.reader();

        prev_signature_file = SignatureFile.loadSignature(reader, allocator) catch |err| {
            std.log.err("Failed to load previous signature file at path {s}, error={}", .{ previous_patch_path.?, err });
            return error.ReferenceSignatureLoadFailed;
        };

        var post_signature_load_time = timer.read();
        std.log.info("Loaded Previous Signature in {d:2}ms", .{(@intToFloat(f64, post_signature_load_time) - @intToFloat(f64, start_sample)) / 1000000});
    }

    var staging_patch_path_buffer: [512]u8 = undefined;
    var staging_dir_path: []u8 = undefined;

    {
        var staging_dir = try findPatchStagingDir(cwd);
        defer staging_dir.close();

        var new_signature_file = try SignatureFile.init(allocator);
        defer new_signature_file.deinit();

        std.log.info("Generating Signature from {s}...", .{source_folder_path});

        var generate_signature_start_sample = timer.read();
        try new_signature_file.generateFromFolder(open_dir, thread_pool);
        var generate_signature_finish_sample = timer.read();

        std.log.info("Generated Signature in {d:2}ms", .{(@intToFloat(f64, generate_signature_finish_sample) - @intToFloat(f64, generate_signature_start_sample)) / 1000000});

        std.log.info("Creating Patch...", .{});

        var create_patch_start_sample = timer.read();
        try PatchGeneration.createPatch(thread_pool, new_signature_file, prev_signature_file.?, allocator, .{ .build_dir = open_dir, .staging_dir = staging_dir });
        var create_patch_finish_sample = timer.read();

        std.log.info("Created Patch in {d:2}ms", .{(@intToFloat(f64, create_patch_finish_sample) - @intToFloat(f64, create_patch_start_sample)) / 1000000});

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
