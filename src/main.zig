const std = @import("std");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const SignatureFile = @import("signature_file.zig").SignatureFile;
const WeakHashType = @import("block.zig").WeakHashType;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const AnchoredBlock = @import("anchored_blocks_map.zig").AnchoredBlock;
const time = std.time;
const BlockPatching = @import("block_patching.zig");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const PatchGeneration = @import("patch_generation.zig");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const ApplyPatch = @import("apply_patch.zig");

const clap = @import("clap");

const ShutdownTaskData = struct {
    task: ThreadPool.Task,
    pool: *ThreadPool,
};

fn shutdownThreadpool(task: *ThreadPool.Task) void {
    var shutdown_task_data = @fieldParentPtr(ShutdownTaskData, "task", task);
    shutdown_task_data.pool.shutdown();
}

fn show_main_help() noreturn {
    std.debug.print("{s}", .{
        \\wharf-zig creates delta diffs from build directories and applies them
        \\
        \\Available commands: create, apply, help
        \\
        \\Put the `--help` flag after the command to get command-specific
        \\help.
        \\
        \\Examples:
        \\
        \\ ./wharf-zig create 
        \\ ./wharf-zig apply 
        \\
        \\
    });
    std.os.exit(0);
}

const CommandLineCommand = enum {
    create,
    apply,
    help,
};

fn findPatchStagingDir() !std.fs.Dir {
    const MaxAttempts = 50;

    var dir = std.fs.cwd();

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

fn create(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary = "Creates a patch from an existing directory.";

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message.
        \\-f, --folder <str>             Name of the folder to create the diff from.
        \\-p, --previous_patch <str>     Name of the previous patch from which the diff will be created.
        \\
    );

    var diag: clap.Diagnostic = undefined;
    var parsed_args = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        // Report any useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };

    if (parsed_args.args.help) {
        std.debug.print("{s}\n\n", .{summary});
        clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{}) catch {};
        std.debug.print("\n", .{});
        std.os.exit(0);
        return;
    }

    var folder = parsed_args.args.folder;
    var previous_patch = parsed_args.args.previous_patch;

    if (folder == null) {
        std.log.err("{s}\n\n", .{"Create needs to know which folder to create the patch from, specify the folder using --folder <path> "});
        return;
    }

    var open_dir = std.fs.openDirAbsolute(folder.?, .{}) catch {
        std.log.err("Specified target folder \"{s}\" could not be opened, make sure it exists", .{folder.?});
        return;
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

    if (previous_patch == null) {
        std.log.warn("{s}\n\n", .{"No previous patch specified. A full patch will be generated. Specify a previous patch using --previous_patch <path>"});
        prev_signature_file = try SignatureFile.init(allocator);
    } else {
        var out_file = try std.fs.openFileAbsolute(previous_patch.?, .{});
        defer out_file.close();

        const BufferedFileReader = std.io.BufferedReader(1200, std.fs.File.Reader);
        var buffered_file_reader: BufferedFileReader = .{
            .unbuffered_reader = out_file.reader(),
        };
        var reader = buffered_file_reader.reader();

        prev_signature_file = SignatureFile.loadSignature(reader, allocator) catch |err| {
            std.log.err("Failed to load previous signature file at path {s}, error={}", .{ previous_patch.?, err });
            std.os.exit(1);
        };

        var post_signature_load_time = timer.read();
        std.log.info("Loaded Previous Signature in {d:2}ms", .{(@intToFloat(f64, post_signature_load_time) - @intToFloat(f64, start_sample)) / 1000000});
    }

    var staging_patch_path_buffer: [512]u8 = undefined;
    var staging_dir_path: []u8 = undefined;

    {
        var staging_dir = try findPatchStagingDir();
        defer staging_dir.close();

        var new_signature_file = try SignatureFile.init(allocator);
        defer new_signature_file.deinit();

        std.log.info("Generating Signature from {s}...", .{folder.?});

        var generate_signature_start_sample = timer.read();
        try new_signature_file.generateFromFolder(folder.?, thread_pool);
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

fn apply(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary = "Applies a patch previously generated via create.";

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message.
        \\-p, --patch <str>              Path to the patch that should be applied.
        \\-s, --source_folder <str>      Path of the previous build that the patch will be applied to.
        \\-t, --target_folder <str>      Path to the folder where the patched build will be stored.
    );

    var diag: clap.Diagnostic = undefined;
    var parsed_args = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        // Report any useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };

    if (parsed_args.args.help) {
        std.debug.print("{s}\n\n", .{summary});
        clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{}) catch {};
        std.debug.print("\n", .{});
        std.os.exit(0);
        return;
    }

    if (parsed_args.args.patch == null) {
        std.log.err("Please pass a patch file generated thorugh create via the --patch <str> param", .{});
        std.os.exit(0);
        return;
    }

    var timer = try time.Timer.start();
    var start_sample = timer.read();

    var patch_file = std.fs.openFileAbsolute(parsed_args.args.patch.?, .{}) catch |e| {
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
        if (parsed_args.args.source_folder == null) {
            std.log.err("No --source_folder <str> passed to apply. But the specified patch requires a reference folder.", .{});
            return;
        }

        var source_folder = std.fs.openDirAbsolute(parsed_args.args.source_folder.?, .{}) catch |e| {
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

    if (parsed_args.args.target_folder == null) {
        std.log.err("No --target_folder <str> passed to apply. Please specify it to tell wharf-zig where to place the build.", .{});
        return;
    }

    std.fs.deleteTreeAbsolute(parsed_args.args.target_folder.?) catch |e| {
        switch (e) {
            error.FileNotFound => {
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

    std.fs.makeDirAbsolute(parsed_args.args.target_folder.?) catch |e| {
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

    var target_dir = try std.fs.openDirAbsolute(parsed_args.args.target_folder.?, .{});
    defer target_dir.close();

    try ApplyPatch.createFileStructure(target_dir, patch);

    try ApplyPatch.applyPatch(target_dir, parsed_args.args.patch.?, patch, thread_pool, allocator);
    var end_sample = timer.read();

    std.log.info("Applied Patch in {d:2}ms", .{(@intToFloat(f64, end_sample) - @intToFloat(f64, start_sample)) / 1000000});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();

    _ = args_it.skip();

    const command_name = args_it.next() orelse show_main_help();

    const command = std.meta.stringToEnum(CommandLineCommand, command_name) orelse show_main_help();

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    switch (command) {
        .create => {
            try create(&args_it, &thread_pool, allocator);
        },
        .apply => {
            try apply(&args_it, &thread_pool, allocator);
        },
        .help => {
            show_main_help();
        },
    }

    var shutdown_task_data = ShutdownTaskData{
        .task = ThreadPool.Task{ .callback = shutdownThreadpool },
        .pool = &thread_pool,
    };

    thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
    defer ThreadPool.deinit(&thread_pool);
}

test {
    std.testing.refAllDecls(@import("anchored_blocks_map.zig"));
    std.testing.refAllDecls(@import("rolling_hash.zig"));
    std.testing.refAllDecls(@import("block_patching.zig"));
    std.testing.refAllDecls(@import("signature_file.zig"));
    std.testing.refAllDecls(@import("patch_generation.zig"));
    std.testing.refAllDecls(@import("patch_header.zig"));
}

//
