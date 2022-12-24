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
const operations = @import("operations.zig");

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

    try operations.createPatch(folder.?, previous_patch, thread_pool, allocator);
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

    if (parsed_args.args.target_folder == null) {
        std.log.err("No --target_folder <str> passed to apply. Please specify it to tell wharf-zig where to place the build.", .{});
        return;
    }

    try operations.applyPatch(parsed_args.args.patch.?, parsed_args.args.source_folder, parsed_args.args.target_folder.?, thread_pool, allocator);
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
