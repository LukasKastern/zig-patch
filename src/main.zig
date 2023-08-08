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
const OperationStats = operations.OperationStats;
const builtin = @import("builtin");

const clap = @import("clap");

const bytes_to_MiB = 1_048_576;

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
        \\zig-patch creates delta diffs from build directories and applies them
        \\
        \\Available commands: create, apply, help
        \\
        \\Put the `--help` flag after the command to get command-specific
        \\help.
        \\
        \\Examples:
        \\
        \\ ./zig-patch create 
        \\ ./zig-patch apply 
        \\ ./zig-patch make_signature
        \\
        \\
    });
    std.os.exit(0);
}

const CommandLineCommand = enum {
    create,
    apply,
    make_signature,
    help,
};

fn create(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary = "Creates a patch from an existing directory.";

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message.
        \\-f, --source_folder <str>      Path to the folder to create the diff from.
        \\-s, --signature_file <str>     Signature file to which the Patch will be created.
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

    var folder = parsed_args.args.source_folder;
    var previous_signature = parsed_args.args.signature_file;

    if (folder == null) {
        std.log.err("{s}\n\n", .{"Create needs to know which folder to create the patch from, specify the folder using --source_folder <path> "});
        return;
    }

    const CreatePatchPrintHelper = struct {
        const Self = @This();

        const CreatePatchState = enum {
            None,
            HashingSource,
            GeneratingPatch,
            AssemblingPatch,
        };

        state: CreatePatchState = .None,
        source_folder: []const u8,

        fn onMakeSignatureProgress(print_helper_opaque: *anyopaque, progress: f32, progress_str: ?[]const u8) void {
            const stdout = std.io.getStdErr().writer();

            var print_helper = @as(*Self, @ptrCast(@alignCast(print_helper_opaque)));

            const progress_str_to_state = [_][]const u8{ "", "Hashing Blocks", "Generating Patches", "Assembling Patch" };

            if (progress_str) |progress_str_value| {
                var new_state: CreatePatchState = .None;

                inline for (progress_str_to_state, 0..) |state_progress_str, idx| {
                    if (std.mem.eql(u8, state_progress_str, progress_str_value)) {
                        new_state = @as(CreatePatchState, @enumFromInt(idx));
                    }
                }

                if (print_helper.state != new_state) {
                    print_helper.state = new_state;

                    switch (new_state) {
                        .None => {},
                        .HashingSource => {
                            stdout.print("\r∙ Hashing                   \n", .{}) catch {};
                        },
                        .GeneratingPatch => {
                            stdout.print("\r∙ Calculating Patch         \n", .{}) catch {};
                        },
                        .AssemblingPatch => {
                            stdout.print("\r∙ Assembling Patch          \n", .{}) catch {};
                        },
                    }
                }
            }

            stdout.print("\r{d:.2}%             ", .{progress}) catch {};
        }
    };

    var print_helper = CreatePatchPrintHelper{ .source_folder = parsed_args.args.source_folder.? };

    var stats: OperationStats = .{};

    // zig fmt: off
    try operations.createPatch(folder.?, previous_signature, .{
        .working_dir = std.fs.cwd(),
        .thread_pool = thread_pool,
        .allocator = allocator,
        .progress_callback = .{.user_object = &print_helper, .callback = CreatePatchPrintHelper.onMakeSignatureProgress}
    }, &stats);
    // zig fmt: on

    var create_patch_stats = stats.create_patch_stats.?;

    var total_blocks = if (create_patch_stats.total_blocks == 0) 1 else create_patch_stats.total_blocks;

    var changed_blocks_percentage = @as(f64, @floatFromInt(create_patch_stats.changed_blocks)) / @as(f64, @floatFromInt(total_blocks)) * 100;

    _ = changed_blocks_percentage;
    {
        const stdout = std.io.getStdErr().writer();

        const new_bytes_percentage = @as(f32, @floatFromInt(create_patch_stats.num_new_bytes)) / @as(f32, @floatFromInt(create_patch_stats.total_signature_folder_size_bytes));
        const reused_percentage = 1.0 - new_bytes_percentage;

        var new_data_size_MiB = @as(f32, @floatFromInt(create_patch_stats.num_new_bytes)) / bytes_to_MiB;

        var total_patch_size_MiB = @as(f32, @floatFromInt(create_patch_stats.total_patch_size_bytes)) / bytes_to_MiB;
        var percentage_of_full_size = @as(f32, @floatFromInt(create_patch_stats.total_patch_size_bytes)) / @as(f32, @floatFromInt(create_patch_stats.total_signature_folder_size_bytes));

        stdout.print("\r√ Re-used {d:.2}% of old, added {d:.2} MiB fresh data\n", .{ reused_percentage * 100, new_data_size_MiB }) catch {};

        stdout.print("√ {d:.2} MiB patch ({d:.2}% of the full size) in {d:.2}s\n", .{ total_patch_size_MiB, percentage_of_full_size * 100, stats.total_operation_time / std.time.ms_per_s }) catch {};
    }
}

fn apply(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary = "Applies a patch previously generated via create.";

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message.
        \\-p, --patch <str>              Path to the patch that should be applied.
        \\-t, --target_folder <str>      Path to the folder to patch.
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
        std.log.err("Please pass a patch file generated through create via the --patch <str> param", .{});
        std.os.exit(0);
        return;
    }

    if (parsed_args.args.target_folder == null) {
        std.log.err("No --target_folder <str> passed to apply. Please specify it to tell zig-patch where to place the build.", .{});
        return;
    }

    {
        const stdout = std.io.getStdErr().writer();
        try stdout.print("∙ Applying Patch\n", .{});
    }

    const MakeSignaturePrintHelper = struct {
        const Self = @This();

        fn onMakeSignatureProgress(user_object: *anyopaque, progress: f32, progress_str: ?[]const u8) void {
            const stdout = std.io.getStdErr().writer();
            stdout.print("\r{d:.2}%             ", .{progress}) catch {};

            _ = progress_str;
            _ = user_object;
        }
    };

    var stats: OperationStats = .{};

    var print_helper = MakeSignaturePrintHelper{};

    // zig fmt: off
    try operations.applyPatch(parsed_args.args.patch.?, parsed_args.args.target_folder.?, .{
        .working_dir = std.fs.cwd(),
        .thread_pool = thread_pool,
        .allocator = allocator,
        .progress_callback = .{ .user_object = &print_helper, .callback = MakeSignaturePrintHelper.onMakeSignatureProgress }
    }, &stats);
    // zig fmt: on

    {
        var apply_patch_stats = stats.apply_patch_stats.?;
        const stdout = std.io.getStdErr().writer();

        var total_patch_size_MiB = apply_patch_stats.total_patch_size_bytes / bytes_to_MiB;
        try stdout.print("\r√ Applied {d:.2} MiB ({} files, {} dirs) in {d:.2}s\n", .{ total_patch_size_MiB, apply_patch_stats.num_files, apply_patch_stats.num_directories, stats.total_operation_time / std.time.ms_per_s });
    }
}

fn make_signature(args_it: anytype, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !void {
    const summary =
        \\Makes a signature file from a folder.
        \\Patches use signature files as a base/previous version to which the diff will be calculated.
    ;

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                     Display this help message.
        \\-t, --source_folder <str>      Path of the folder to create the signature file from.
        \\-o, --output_file <str>        Output path of the generated file.
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

    if (parsed_args.args.source_folder == null) {
        std.log.err("No --source_folder <str> passed to make_signature. Please specify it to tell zig-patch what folder to create the signature from.", .{});
        return;
    }

    if (parsed_args.args.output_file == null) {
        std.log.err("No --output_file <str> passed to make_signature. Please specify it to tell zig-patch where to place the resulting signature file.", .{});
        return;
    }

    {
        const stdout = std.io.getStdErr().writer();
        try stdout.print("∙ Hashing {s}\n", .{parsed_args.args.source_folder.?});
    }

    const MakeSignaturePrintHelper = struct {
        const Self = @This();

        fn onMakeSignatureProgress(user_object: *anyopaque, progress: f32, progress_str: ?[]const u8) void {
            const stdout = std.io.getStdErr().writer();
            stdout.print("\r{d:.2}%             ", .{progress}) catch {};

            _ = progress_str;
            _ = user_object;
        }
    };

    var print_helper = MakeSignaturePrintHelper{};
    var operation_stats: OperationStats = .{};

    try operations.makeSignature(parsed_args.args.source_folder.?, parsed_args.args.output_file.?, .{ .working_dir = std.fs.cwd(), .thread_pool = thread_pool, .allocator = allocator, .progress_callback = .{ .user_object = &print_helper, .callback = MakeSignaturePrintHelper.onMakeSignatureProgress } }, &operation_stats);

    {
        const stdout = std.io.getStdErr().writer();

        var make_signature_stats = operation_stats.make_signature_stats.?;

        var folder_size_GiB = @as(f32, @floatFromInt(make_signature_stats.total_signature_folder_size_bytes)) / 1_073_741_824.0;

        stdout.print("\r√ {d:.2}GiB ({} files, {} directories) @ {d:.2}GiB/s            \n", .{ folder_size_GiB, make_signature_stats.num_files, make_signature_stats.num_directories, operation_stats.total_operation_time / std.time.ms_per_s }) catch {};
    }
}

pub const std_options = struct {
    // Set the log level to error
    pub const log_level = .warn;
};

pub fn main() !void {
    // Enable utf-8 console output
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleOutputCP(65001);
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{ .verbose_log = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();

    _ = args_it.skip();

    const command_name = args_it.next() orelse show_main_help();

    const command = std.meta.stringToEnum(CommandLineCommand, command_name) orelse show_main_help();

    var thread_pool = ThreadPool.init(.{ .max_threads = 6 });
    thread_pool.spawnThreads();

    switch (command) {
        .create => {
            try create(&args_it, &thread_pool, allocator);
        },
        .apply => {
            try apply(&args_it, &thread_pool, allocator);
        },
        .make_signature => {
            try make_signature(&args_it, &thread_pool, allocator);
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
    std.testing.refAllDecls(@import("compression/compression.zig"));
    std.testing.refAllDecls(@import("e2e_tests.zig"));
}
