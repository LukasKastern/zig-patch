const std = @import("std");
const operations = @import("operations.zig");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const SignatureFile = @import("signature_file.zig").SignatureFile;
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const AnchoredBlock = @import("anchored_blocks_map.zig").AnchoredBlock;
const SignatureBlock = @import("signature_file.zig").SignatureBlock;
const time = std.time;

const GenerateFolderOptions = struct {
    min_files: usize = 1,
    max_files: usize = 10,

    min_directories: usize = 0,
    max_directories: usize = 5,

    min_depth: usize = 0,
    max_depth: usize = 3,

    min_file_size: usize = 0,
    max_file_size: usize = 64 * 256,
};

// Fills the given buffer with a random sequence of lowercase letter a-z.
fn GeneratePathName(rand: std.rand.Random, buffer: []u8) void {
    for (buffer) |*element| {
        element.* = rand.intRangeAtMost(u8, 97, 122);
    }
}

fn generateFile(rand: std.rand.Random, file: std.fs.File, file_size: usize) !void {
    var start_num = rand.int(usize);
    var written_idx: usize = 0;

    const BufferedFileWriter = std.io.BufferedWriter(1200, std.fs.File.Writer);
    var buffered_file_writer: BufferedFileWriter = .{
        .unbuffered_writer = file.writer(),
    };

    var writer = buffered_file_writer.writer();

    var num = start_num;
    while (written_idx < file_size) : (written_idx += 1) {
        var result: usize = 0;

        if (!@addWithOverflow(usize, num, 56484, &result))
            result = num + 56484;

        if (!@mulWithOverflow(usize, num, 2, &result))
            result = num * 2;

        try writer.writeIntBig(usize, num);
    }

    try buffered_file_writer.flush();
}

fn generateTestFolder(seed: u64, directory: std.fs.Dir, opt: GenerateFolderOptions) !void {
    var prng = std.rand.DefaultPrng.init(seed);
    var random = prng.random();

    const GenerateImpl = struct {
        pub fn Generate(rand: std.rand.Random, dir: std.fs.Dir, options: GenerateFolderOptions) !void {
            var num_files_to_gen = rand.intRangeAtMost(usize, options.min_files, options.max_files);

            var file_idx: usize = 0;
            while (file_idx < num_files_to_gen) : (file_idx += 1) {
                var path_buffer: [16]u8 = undefined;
                GeneratePathName(rand, &path_buffer);

                var file = try dir.createFile(&path_buffer, .{});
                defer file.close();

                const file_size = rand.intRangeAtMost(usize, options.min_file_size, options.max_file_size);

                try generateFile(rand, file, file_size);
            }

            var depth = rand.intRangeAtMost(usize, options.min_depth, options.max_depth);

            if (depth == 0) {
                return;
            }

            var num_directories_to_gen = rand.intRangeAtMost(usize, options.min_directories, options.max_directories);

            var modifiedOptions = options;
            modifiedOptions.max_depth -= 1;

            if (modifiedOptions.min_depth > 0) {
                modifiedOptions.min_depth -= 1;
            }

            var directory_idx: usize = 0;
            while (directory_idx < num_directories_to_gen) : (directory_idx += 1) {
                var path_buffer: [16]u8 = undefined;
                GeneratePathName(rand, &path_buffer);

                try dir.makeDir(&path_buffer);
                var child_dir = try dir.openDir(&path_buffer, .{});
                defer child_dir.close();

                try Generate(rand, child_dir, modifiedOptions);
            }
        }
    };

    try GenerateImpl.Generate(random, directory, opt);
}

fn areDirectoriesEqual(lhs_dir: std.fs.Dir, rhs_dir: std.fs.Dir, thread_pool: *ThreadPool, allocator: std.mem.Allocator) !bool {
    var lhs_signature = try SignatureFile.init(allocator);
    defer lhs_signature.deinit();

    try lhs_signature.generateFromFolder(lhs_dir, thread_pool);

    var rhs_signature = try SignatureFile.init(allocator);
    defer rhs_signature.deinit();

    try rhs_signature.generateFromFolder(rhs_dir, thread_pool);

    const lhs_directories = lhs_signature.directories;
    const rhs_directories = rhs_signature.directories;

    if (lhs_directories.items.len != rhs_directories.items.len) {
        return false;
    }

    for (lhs_directories.items) |lhs_directory, idx| {
        var rhs_directory = rhs_directories.items[idx];

        if (!std.mem.eql(u8, lhs_directory.path, rhs_directory.path)) {
            return false;
        }

        if (lhs_directory.permissions != rhs_directory.permissions) {
            return false;
        }
    }

    const lhs_files = lhs_signature.files;
    const rhs_files = rhs_signature.files;

    if (lhs_files.items.len != rhs_files.items.len) {
        return false;
    }

    for (lhs_files.items) |lhs_file, idx| {
        var rhs_file = rhs_files.items[idx];

        if (!std.mem.eql(u8, lhs_file.name, rhs_file.name)) {
            return false;
        }

        if (lhs_file.permissions != rhs_file.permissions) {
            return false;
        }

        if (lhs_file.size != rhs_file.size) {
            std.debug.print("File {s} expected size of {} but is {}\n", .{ lhs_file.name, lhs_file.size, rhs_file.size });
            return false;
        }
    }

    const lhs_blocks = lhs_signature.blocks;
    const rhs_blocks = rhs_signature.blocks;

    if (lhs_blocks.items.len != rhs_blocks.items.len) {
        return false;
    }

    var rhs_anchored_blockmap = try AnchoredBlocksMap.init(rhs_signature.*, allocator);
    defer rhs_anchored_blockmap.deinit();

    for (lhs_blocks.items) |lhs_block| {
        var rhs_block: AnchoredBlock = rhs_anchored_blockmap.getBlock(lhs_block.file_idx, lhs_block.block_idx);

        if (!std.mem.eql(u8, &lhs_block.hash.strong_hash, &rhs_block.hash.strong_hash)) {
            return false;
        }
    }

    return true;
}

test "Full patch should match source folder" {
    const cwd = std.fs.cwd();
    const TestRootPath = "temp/CreateAndApplyFullPatchTest";
    cwd.makeDir("temp") catch |err| {
        switch (err) {
            error.PathAlreadyExists => {},
            else => {
                return error.CouldntCreateTemp;
            },
        }
    };

    try cwd.deleteTree(TestRootPath);
    try cwd.makeDir(TestRootPath);
    var test_root_dir = try cwd.openDir(TestRootPath, .{});
    defer test_root_dir.close();

    var src_folder_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ TestRootPath, "Original" });
    defer std.testing.allocator.free(src_folder_path);

    var target_folder_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ TestRootPath, "Patched" });
    defer std.testing.allocator.free(target_folder_path);

    // Create the source folder
    {
        try cwd.makeDir(src_folder_path);
        var src_folder = try cwd.openDir(src_folder_path, .{});
        defer src_folder.close();

        try generateTestFolder(12587, src_folder, .{});
    }

    // Create the target folder
    {
        try cwd.makeDir(target_folder_path);
        var target_folder = try cwd.openDir(target_folder_path, .{});
        defer target_folder.close();
    }

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    var operation_config: operations.OperationConfig = .{
        .working_dir = test_root_dir,
        .thread_pool = &thread_pool,
        .allocator = std.testing.allocator,
    };

    try operations.createPatch("Original", null, operation_config);
    try operations.applyPatch("Patch.pwd", "Patched", operation_config);

    {
        var src_folder = try cwd.openDir(src_folder_path, .{});
        defer src_folder.close();

        var target_folder = try cwd.openDir(target_folder_path, .{});
        defer target_folder.close();

        try std.testing.expect(try areDirectoriesEqual(src_folder, target_folder, &thread_pool, std.testing.allocator));
    }
}

// Generate two identical folders.
// Create a signature from one folder.
// Remove and modify some files from the other one.
// Apply patch and check that both folders are the same.
test "Patch should delete/create files and folders" {
    var timer = try time.Timer.start();
    var start_sample = timer.read();

    var prng = std.rand.DefaultPrng.init(14123);
    var random = prng.random();

    const cwd = std.fs.cwd();
    const TestRootPath = "temp/DeleteAndCreateContent";
    cwd.makeDir("temp") catch |err| {
        switch (err) {
            error.PathAlreadyExists => {},
            else => {
                return error.CouldntCreateTemp;
            },
        }
    };

    try cwd.deleteTree(TestRootPath);
    try cwd.makeDir(TestRootPath);
    var test_root_dir = try cwd.openDir(TestRootPath, .{});
    defer test_root_dir.close();

    var original_folder_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ TestRootPath, "Original" });
    defer std.testing.allocator.free(original_folder_path);

    var modified_folder_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ TestRootPath, "Modified" });
    defer std.testing.allocator.free(modified_folder_path);

    // Create the source folder
    {
        try cwd.makeDir(original_folder_path);
        var src_folder = try cwd.openDir(original_folder_path, .{});
        defer src_folder.close();

        try generateTestFolder(12587, src_folder, .{ .min_depth = 2, .max_depth = 3 });
    }

    // Create the modified folder
    {
        try cwd.makeDir(modified_folder_path);
        var modified_folder = try cwd.openDir(modified_folder_path, .{});
        defer modified_folder.close();

        try generateTestFolder(12587, modified_folder, .{ .min_depth = 2, .max_depth = 3 });
    }

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    var operation_config: operations.OperationConfig = .{
        .working_dir = test_root_dir,
        .thread_pool = &thread_pool,
        .allocator = std.testing.allocator,
    };

    try operations.makeSignature("Original", "OriginalSignature", operation_config);
    {
        var modified_folder = try cwd.openDir(modified_folder_path, .{});
        defer modified_folder.close();

        // Modify the target folder a bit.
        {
            var files_to_delete = std.ArrayList([]u8).init(std.testing.allocator);
            defer {
                for (files_to_delete.items) |file| {
                    std.testing.allocator.free(file);
                }
                defer files_to_delete.deinit();
            }

            var directories_to_delete = std.ArrayList([]u8).init(std.testing.allocator);
            defer directories_to_delete.deinit();

            const Operations = struct {
                const Self = @This();
                const OperationFileTypes = enum { None, Delete, Modify, Create };

                files_to_delete: std.ArrayList([]u8),
                directories_to_delete: std.ArrayList([]u8),
                files_to_modify: std.ArrayList([]u8),
                file_to_create: std.ArrayList([]u8),

                allocator: std.mem.Allocator,

                pub fn init(allocator: std.mem.Allocator) !*Self {
                    var ops = try allocator.create(Self);
                    ops.allocator = allocator;
                    ops.files_to_delete = std.ArrayList([]u8).init(allocator);
                    ops.directories_to_delete = std.ArrayList([]u8).init(allocator);
                    ops.files_to_modify = std.ArrayList([]u8).init(allocator);
                    ops.file_to_create = std.ArrayList([]u8).init(allocator);
                    return ops;
                }

                pub fn deinit(ops: *Self) void {
                    ops.files_to_delete.deinit();
                    ops.directories_to_delete.deinit();
                    ops.files_to_modify.deinit();
                    ops.file_to_create.deinit();
                    ops.allocator.destroy(ops);
                }
            };

            var ops = try Operations.init(std.testing.allocator);
            defer {
                for (ops.directories_to_delete.items) |dir| {
                    ops.allocator.free(dir);
                }

                for (ops.file_to_create.items) |file| {
                    ops.allocator.free(file);
                }

                for (ops.files_to_delete.items) |file| {
                    ops.allocator.free(file);
                }

                for (ops.files_to_modify.items) |file| {
                    ops.allocator.free(file);
                }

                ops.deinit();
            }

            const DetermineFileOperations = struct {
                fn findOperationsForDirectory(dir: std.fs.Dir, rand: std.rand.Random, operations_collection: *Operations) !void {
                    var iteratable_dir = try dir.makeOpenPathIterable("", .{});
                    defer iteratable_dir.close();

                    var dir_iterator = iteratable_dir.iterate();

                    var full_dir_path = try dir.realpathAlloc(std.testing.allocator, "");
                    defer std.testing.allocator.free(full_dir_path);

                    while (try dir_iterator.next()) |entry| {
                        switch (entry.kind) {
                            .File => {
                                var file_operation_idx = @intToEnum(Operations.OperationFileTypes, rand.intRangeAtMost(u8, 0, 5));

                                switch (file_operation_idx) {
                                    .Delete => {
                                        var full_file_name = try dir.realpathAlloc(std.testing.allocator, entry.name);
                                        try operations_collection.files_to_delete.append(full_file_name);
                                    },
                                    .Create => {
                                        var path_buffer: [16]u8 = undefined;
                                        GeneratePathName(rand, &path_buffer);

                                        var full_file_name = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ full_dir_path, &path_buffer });
                                        try operations_collection.file_to_create.append(full_file_name);
                                    },
                                    .Modify => {
                                        var full_file_name = try dir.realpathAlloc(std.testing.allocator, entry.name);
                                        try operations_collection.files_to_modify.append(full_file_name);
                                    },
                                    else => {},
                                }
                            },
                            .Directory => {
                                if (rand.float(f32) > 0.8) {
                                    var full_file_name = try dir.realpathAlloc(std.testing.allocator, entry.name);
                                    try operations_collection.directories_to_delete.append(full_file_name);
                                }

                                var opened_dir = try dir.openDir(entry.name, .{});
                                defer opened_dir.close();
                                try findOperationsForDirectory(opened_dir, rand, operations_collection);
                            },
                            else => {},
                        }
                    }
                }
            };

            try DetermineFileOperations.findOperationsForDirectory(modified_folder, random, ops);

            for (ops.files_to_delete.items) |file| {
                std.fs.deleteFileAbsolute(file) catch |e| {
                    switch (e) {
                        else => {},
                    }
                };
            }

            for (ops.file_to_create.items) |file| {
                var created_file = try std.fs.createFileAbsolute(file, .{});
                defer created_file.close();

                var file_size = random.intRangeAtMost(usize, 0, 64 * 256);
                try generateFile(random, created_file, file_size);
            }

            for (ops.files_to_modify.items) |file| {
                var file_to_modify = try std.fs.openFileAbsolute(file, .{ .mode = .read_write });
                defer file_to_modify.close();

                var end_pos = try file_to_modify.getEndPos();

                var file_size = @intCast(isize, end_pos) + random.intRangeAtMost(isize, -1000, 5000);

                if (file_size < 0) {
                    try file_to_modify.setEndPos(0);
                } else {
                    try generateFile(random, file_to_modify, @intCast(usize, file_size));
                    try file_to_modify.setEndPos(@intCast(usize, file_size));
                }
            }

            for (ops.directories_to_delete.items) |directory| {
                std.fs.deleteTreeAbsolute(directory) catch |e| {
                    switch (e) {
                        else => {},
                    }
                };
            }
        }
    }

    var pre_create_patch = timer.read();
    try operations.createPatch("Modified", "OriginalSignature", operation_config);
    var create_patch_sample = timer.read();
    std.debug.print("Creating patch took {d:2}ms", .{(@intToFloat(f64, create_patch_sample) - @intToFloat(f64, pre_create_patch)) / 1000000});

    try operation_config.working_dir.rename("Patch.pwd", "PatchToModified.pwd");
    try operations.applyPatch("PatchToModified.pwd", "Original", operation_config);

    var end_sample = timer.read();
    std.debug.print("Did test in {d:2}ms", .{(@intToFloat(f64, end_sample) - @intToFloat(f64, start_sample)) / 1000000});

    {
        var src_folder = try cwd.openDir(original_folder_path, .{});
        defer src_folder.close();

        var target_folder = try cwd.openDir(modified_folder_path, .{});
        defer target_folder.close();

        try std.testing.expect(try areDirectoriesEqual(src_folder, target_folder, &thread_pool, std.testing.allocator));
    }
}
