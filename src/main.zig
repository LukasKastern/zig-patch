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

const ShutdownTaskData = struct {
    task: ThreadPool.Task,
    pool: *ThreadPool,
};

fn shutdownThreadpool(task: *ThreadPool.Task) void {
    var shutdown_task_data = @fieldParentPtr(ShutdownTaskData, "task", task);
    shutdown_task_data.pool.shutdown();
}

pub fn main() !void {
    var timer = try time.Timer.start();

    var file = try std.fs.openFileAbsolute("E:/JourneeDevelopment/WindowsNoEditor/Journee_Unreal/Binaries/Win64/Journee_Unreal.pdb", .{});
    defer file.close();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    var signature_file = try SignatureFile.init(allocator);
    defer signature_file.deinit();

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    var before_read = timer.read();
    try signature_file.generateFromFolder("E:/JourneeDevelopment/WindowsNoEditor", &thread_pool);
    var after_read = timer.read();
    std.log.info("bytes in {d:2}ms", .{(@intToFloat(f64, after_read) - @intToFloat(f64, before_read)) / 1000000});

    try signature_file.saveSignatureToFile("E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674/Journee_Unreal.pwr.sig");

    var shutdown_task_data = ShutdownTaskData{
        .task = ThreadPool.Task{ .callback = shutdownThreadpool },
        .pool = &thread_pool,
    };

    thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
    defer ThreadPool.deinit(&thread_pool);

    // Generate patch operations for all files

    // var end_pos = try file.getEndPos();
    // var buffer = try allocator.alloc(u8, end_pos / 2);
    // var out = try file.read(buffer);
    // defer allocator.free(buffer);

    // // var signature_file = try SignatureFile.init(allocator);
    // // var block_map = try AnchoredBlocksMap.init(signature_file.*, allocator);

    // // var operation = try BlockPatching.generateOperationsForBuffer(buffer, block_map.*, BlockPatching.MaxDataOperationLength, allocator);

    // var created_file = try std.fs.createFileAbsolute("E:/Personal/wharf-zig/wharf-zig/zig-out/bin/generation_staging_folder_5646515674/Journee_Unreal.pdb", .{});
    // try created_file.writeAll(buffer);

    // std.log.info("Out{} Read {} bytes in {d:2}ms", .{ out, end_pos, (@intToFloat(f64, after_read) - @intToFloat(f64, before_read)) / 1000000 });

    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
}

test {
    std.testing.refAllDecls(@import("anchored_blocks_map.zig"));
    std.testing.refAllDecls(@import("rolling_hash.zig"));
    std.testing.refAllDecls(@import("block_patching.zig"));
}

//
