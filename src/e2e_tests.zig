const std = @import("std");
const operations = @import("operations.zig");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const SignatureFile = @import("signature_file.zig").SignatureFile;

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

fn generateTestFolder(seed: u64, directory: std.fs.Dir, opt: GenerateFolderOptions) !void {
    var prng = std.rand.DefaultPrng.init(seed);
    var random = prng.random();

    const GenerateImpl = struct {

        // Fills the given buffer with a random sequence of lowercase letter a-z.
        fn GeneratePathName(rand: std.rand.Random, buffer: []u8) void {
            for (buffer) |*element| {
                element.* = rand.intRangeAtMost(u8, 97, 122);
            }
        }

        pub fn Generate(rand: std.rand.Random, dir: std.fs.Dir, options: GenerateFolderOptions) !void {
            var num_files_to_gen = rand.intRangeAtMost(usize, options.min_files, options.max_files);

            var file_idx: usize = 0;
            while (file_idx < num_files_to_gen) : (file_idx += 1) {
                var path_buffer: [16]u8 = undefined;
                GeneratePathName(rand, &path_buffer);

                var file = try dir.createFile(&path_buffer, .{});
                defer file.close();

                const file_size = rand.intRangeAtMost(usize, options.min_file_size, options.max_file_size);

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
            }

            var depth = rand.intRangeAtMost(usize, options.min_depth, options.max_depth);

            if (depth == 0) {
                return;
            }

            var num_directories_to_gen = rand.intRangeAtMost(usize, options.min_directories, options.max_directories);

            var modifiedOptions = options;
            modifiedOptions.max_depth -= 1;

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
            return false;
        }
    }

    const lhs_blocks = lhs_signature.blocks;
    const rhs_blocks = rhs_signature.blocks;

    if (lhs_blocks.items.len != rhs_blocks.items.len) {
        return false;
    }

    for (lhs_blocks.items) |lhs_block, idx| {
        var rhs_block = rhs_blocks.items[idx];

        if (lhs_block.file_idx != rhs_block.file_idx) {
            return false;
        }

        if (lhs_block.block_idx != rhs_block.block_idx) {
            return false;
        }

        if (lhs_block.hash.weak_hash != rhs_block.hash.weak_hash) {
            return false;
        }

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

    var thread_pool = ThreadPool.init(.{ .max_threads = 1 });
    thread_pool.spawnThreads();

    var operation_config: operations.OperationConfig = .{
        .working_dir = test_root_dir,
        .thread_pool = &thread_pool,
        .allocator = std.testing.allocator,
    };

    try operations.createPatch("Original", null, operation_config);
    try operations.applyPatch("Patch.pwd", null, "Patched", operation_config);

    {
        var src_folder = try cwd.openDir(src_folder_path, .{});
        defer src_folder.close();

        var target_folder = try cwd.openDir(target_folder_path, .{});
        defer target_folder.close();

        try std.testing.expect(try areDirectoriesEqual(src_folder, target_folder, &thread_pool, std.testing.allocator));
    }
}
