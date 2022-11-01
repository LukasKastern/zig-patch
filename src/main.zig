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

fn apply() void {}

fn create(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary = "Creates a patch from an existing directory.";

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message
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

    var new_signature_file = try SignatureFile.init(allocator);
    defer new_signature_file.deinit();

    std.log.info("Generating Signature from {s}...", .{folder.?});

    var generate_signature_start_sample = timer.read();
    try new_signature_file.generateFromFolder(folder.?, thread_pool);
    var generate_signature_finish_sample = timer.read();

    std.log.info("Generated Signature in {d:2}ms", .{(@intToFloat(f64, generate_signature_finish_sample) - @intToFloat(f64, generate_signature_start_sample)) / 1000000});

    std.log.info("Creating Patch...", .{});

    const staging_dir_path = "E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674";

    var create_patch_start_sample = timer.read();
    try PatchGeneration.createPatch(thread_pool, new_signature_file, prev_signature_file.?, allocator, .{ .staging_dir = std.mem.span(staging_dir_path) });
    var create_patch_finish_sample = timer.read();

    std.log.info("Created Patch in {d:2}ms", .{(@intToFloat(f64, create_patch_finish_sample) - @intToFloat(f64, create_patch_start_sample)) / 1000000});
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
            // apply();
        },
        .help => {
            show_main_help();
        },
    }

    // var timer = try time.Timer.start();

    // var file = try std.fs.openFileAbsolute("E:/JourneeDevelopment/WindowsNoEditor/Journee_Unreal/Binaries/Win64/Journee_Unreal.pdb", .{});
    // defer file.close();

    // var signature_file = try SignatureFile.init(allocator);
    // defer signature_file.deinit();
    // // var before_read = timer.read();
    // // try signature_file.generateFromFolder("E:/JourneeDevelopment/WindowsNoEditor", &thread_pool);
    // var after_read = timer.read();
    // // std.log.info("bytes in {d:2}ms", .{(@intToFloat(f64, after_read) - @intToFloat(f64, before_read)) / 1000000});
    // // _ = timer;
    // // try signature_file.saveSignatureToFile("E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674/Journee_Unreal.pwr.sig");
    // var sign = try SignatureFile.loadSignatureFromFile("E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674/Journee_Unreal.pwr.sig", allocator);
    // defer sign.deinit();

    // var after_signature = timer.read();
    // std.log.info("Wrote signature file in {d:2}ms", .{(@intToFloat(f64, after_signature) - @intToFloat(f64, after_read)) / 1000000});

    var shutdown_task_data = ShutdownTaskData{
        .task = ThreadPool.Task{ .callback = shutdownThreadpool },
        .pool = &thread_pool,
    };

    thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
    defer ThreadPool.deinit(&thread_pool);

    // // Generate patch operations for all files

    // // var end_pos = try file.getEndPos();
    // // var buffer = try allocator.alloc(u8, end_pos / 2);
    // // var out = try file.read(buffer);
    // // defer allocator.free(buffer);

    // // // var signature_file = try SignatureFile.init(allocator);
    // // // var block_map = try AnchoredBlocksMap.init(signature_file.*, allocator);

    // // // var operation = try BlockPatching.generateOperationsForBuffer(buffer, block_map.*, BlockPatching.MaxDataOperationLength, allocator);

    // // var created_file = try std.fs.createFileAbsolute("E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674/Journee_Unreal.pdb", .{});
    // // try created_file.writeAll(buffer);

    // // std.log.info("Out{} Read {} bytes in {d:2}ms", .{ out, end_pos, (@intToFloat(f64, after_read) - @intToFloat(f64, before_read)) / 1000000 });

    // // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    // std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // // stdout is for the actual output of your application, for example if you
    // // are implementing gzip, then only the compressed bytes should be sent to
    // // stdout, not any debugging messages.
    // const stdout_file = std.io.getStdOut().writer();
    // var bw = std.io.bufferedWriter(stdout_file);
    // const stdout = bw.writer();

    // try stdout.print("Run `zig build test` to run the tests.\n", .{});

    // try bw.flush(); // don't forget to flush!
}

test {
    std.testing.refAllDecls(@import("anchored_blocks_map.zig"));
    std.testing.refAllDecls(@import("rolling_hash.zig"));
    std.testing.refAllDecls(@import("block_patching.zig"));
    std.testing.refAllDecls(@import("signature_file.zig"));
    std.testing.refAllDecls(@import("patch_generation.zig"));
}

//
