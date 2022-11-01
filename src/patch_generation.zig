const SignatureFile = @import("signature_file.zig").SignatureFile;
const BlockPatching = @import("block_patching.zig");
const std = @import("std");
const ThreadPool = @import("zap/thread_pool_go_based.zig");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const MaxDataOperationLength = @import("block_patching.zig").MaxDataOperationLength;

const PatchFileInfo = struct {
    file_idx: usize,
    file_part_idx: usize,
};

const PatchFileData = struct {
    file_info: PatchFileInfo,
    operations: std.ArrayList(BlockPatching.PatchOperation),
};

const PatchFileIO = struct {
    const WritePatchFile = *const fn (patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void;
    const ReadPatchFile = *const fn (patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize;

    write_patch_file: WritePatchFile,
    read_patch_file: ReadPatchFile,
};

const DefaultMaxWorkUnitSize = 1024 * 1024 * 25;

const CreatePatchOptions = struct {
    max_work_unit_size: usize = DefaultMaxWorkUnitSize,
    staging_dir: [:0]const u8,
};

const CreatePatchOperationsOptions = struct {
    patch_file_io: *PatchFileIO,
    create_patch_options: CreatePatchOptions,
};

fn ParallelList(comptime T: type) type {
    return struct {
        const Self = @This();

        per_thread_lists: []std.ArrayList(T),
        allocator: std.mem.Allocator,

        fn init(allocator: std.mem.Allocator, max_threads: usize) !Self {
            return initCapacity(allocator, max_threads, 0);
        }

        fn initCapacity(allocator: std.mem.Allocator, max_threads: usize, initial_capacity: usize) !Self {
            var self: Self = .{
                .allocator = allocator,
                .per_thread_lists = try allocator.alloc(std.ArrayList(T), max_threads),
            };

            for (self.per_thread_lists) |*list| {
                list.* = try std.ArrayList(T).initCapacity(allocator, initial_capacity);
            }

            return self;
        }

        fn deinit(self: *Self) void {
            for (self.per_thread_lists) |list| {
                list.deinit();
            }

            self.allocator.free(self.per_thread_lists);
        }

        fn getList(self: *Self, idx: usize) *std.ArrayList(T) {
            return &self.per_thread_lists[idx];
        }

        fn flattenParallelList(self: *Self, allocator: std.mem.Allocator) ![]T {
            var num_elements: usize = 0;

            for (self.per_thread_lists) |list| {
                num_elements += list.items.len;
            }

            var flattened_array = try allocator.alloc(T, num_elements);

            var idx: usize = 0;

            for (self.per_thread_lists) |list| {
                for (list.items) |list_element| {
                    flattened_array[idx] = list_element;
                    idx += 1;
                }
            }

            return flattened_array;
        }
    };
}

pub fn createPatch(thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOptions) !void {
    const PerPatchPartStagingFolderIO = struct {
        file_io: PatchFileIO,
        allocator: std.mem.Allocator,
        staging_dir: std.fs.Dir,
        signature_file: *SignatureFile,
        max_work_unit_size: usize,

        fn write(patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);

            var file_name_buffer: [128]u8 = undefined;
            var name = std.fmt.bufPrint(&file_name_buffer, "File_{}_Part_{}", .{ patch_data.file_info.file_idx, patch_data.file_info.file_part_idx }) catch return error.WritePatchError;

            var fs_file = self.staging_dir.createFile(name, .{}) catch return error.WritePatchError;
            defer fs_file.close();

            var writer = fs_file.writer();
            BlockPatching.saveOperations(patch_data.operations, writer) catch return error.WritePatchError;
        }

        fn read(patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);
            var file = self.signature_file.files.items[file_info.file_idx];

            var fs_file = std.fs.openFileAbsolute(file.name, .{}) catch return error.ReadPatchError;
            defer fs_file.close();

            fs_file.seekTo(file_info.file_part_idx * self.max_work_unit_size) catch return error.ReadPatchError;

            return fs_file.read(read_buffer) catch return error.ReadPatchError;
        }
    };

    try std.fs.makeDirAbsolute(options.staging_dir);
    var staging_folder = try std.fs.openDirAbsolute(options.staging_dir, .{});
    defer staging_folder.close();

    // zig fmt: off
    var staging_folder_io: PerPatchPartStagingFolderIO = .{ 
        .signature_file = new_signature,
        .allocator = allocator, 
        .file_io = .{
            .write_patch_file = &PerPatchPartStagingFolderIO.write,
            .read_patch_file = &PerPatchPartStagingFolderIO.read,
        }, 
        .staging_dir = staging_folder,
        .max_work_unit_size = options.max_work_unit_size,
    };
    // zig fmt: on

    try createPerFilePatchOperations(thread_pool, new_signature, old_signature, allocator, .{ .patch_file_io = &staging_folder_io.file_io, .create_patch_options = options });
    try assemblePatchFromFiles(new_signature, old_signature, staging_folder, allocator, options);
}

fn numPatchFilesNeeded(signature: *SignatureFile, work_unit_size: usize) usize {
    var num_patch_files: usize = 0;

    for (signature.files.items) |file| {
        num_patch_files += @floatToInt(usize, @ceil(@intToFloat(f64, file.size) / @intToFloat(f64, work_unit_size)));
    }

    return num_patch_files;
}

pub fn assemblePatchFromFiles(new_signature: *SignatureFile, old_signature: *SignatureFile, staging_dir: std.fs.Dir, allocator: std.mem.Allocator, options: CreatePatchOptions) !void {
    var num_patch_files: usize = numPatchFilesNeeded(new_signature, options.max_work_unit_size);

    var patch = try staging_dir.createFile("Patch.pwd", .{});
    defer patch.close();

    var read_buffer = try allocator.alloc(u8, options.max_work_unit_size);
    defer allocator.free(read_buffer);

    _ = old_signature;

    var part_idx: usize = 0;
    var file_idx: usize = 0;
    var patch_file_idx: usize = 0;
    while (patch_file_idx < num_patch_files) : (patch_file_idx += 1) {
        if (part_idx * options.max_work_unit_size > new_signature.files.items[file_idx].size) {
            part_idx = 0;
            file_idx += 1;

            while (new_signature.files.items[file_idx].size == 0) {
                file_idx += 1;
            }
        }

        var file_name_buffer: [128]u8 = undefined;
        var name = std.fmt.bufPrint(&file_name_buffer, "File_{}_Part_{}", .{ file_idx, part_idx }) catch return error.WritePatchError;

        var fs_part = try staging_dir.openFile(name, .{});
        defer fs_part.close();

        var read_bytes = try fs_part.readAll(read_buffer);
        try patch.writeAll(read_buffer[0..read_bytes]);

        part_idx += 1;
    }
}

pub fn createPerFilePatchOperations(thread_pool: *ThreadPool, new_signature: *SignatureFile, old_signature: *SignatureFile, allocator: std.mem.Allocator, options: CreatePatchOperationsOptions) !void {
    var num_patch_files: usize = numPatchFilesNeeded(new_signature, options.create_patch_options.max_work_unit_size);

    var anchored_block_map = try AnchoredBlocksMap.init(old_signature.*, allocator);
    defer anchored_block_map.deinit();

    const GeneratePatchTask = struct {
        const Self = @This();

        task: ThreadPool.Task,
        file_info: PatchFileInfo,
        new_signature_file: *SignatureFile,
        old_signature_file: *SignatureFile,
        are_patches_done: *std.atomic.Atomic(u32),
        remaining_patches: *std.atomic.Atomic(usize),
        io: *PatchFileIO,
        block_map: *AnchoredBlocksMap,

        per_thread_buffers: [][]u8,

        fn generatePatch(task: *ThreadPool.Task) void {
            var generate_patch_task_data = @fieldParentPtr(Self, "task", task);
            generatePatchImpl(generate_patch_task_data) catch unreachable;
        }

        fn generatePatchImpl(self: *Self) !void {
            var buffer = self.per_thread_buffers[ThreadPool.Thread.current.?.idx];
            var read_len = try self.io.read_patch_file(self.io, self.file_info, buffer);

            if (read_len == 0) {
                return error.ReadingPatchFileFailed;
            }

            var patch_operations_buffer: [2400]u8 = undefined;
            var patch_operation_fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&patch_operations_buffer);
            var alloc = patch_operation_fixed_buffer_allocator.allocator();

            var generated_operations = try BlockPatching.generateOperationsForBuffer(buffer[0..read_len], self.block_map.*, MaxDataOperationLength, alloc);

            try self.io.write_patch_file(self.io, .{
                .operations = generated_operations,
                .file_info = self.file_info,
            });

            if (self.remaining_patches.fetchSub(1, .Release) == 1) {
                self.are_patches_done.store(1, .Release);
                std.Thread.Futex.wake(self.are_patches_done, 1);
            }
        }
    };

    var batch = ThreadPool.Batch{};

    var tasks = try allocator.alloc(GeneratePatchTask, num_patch_files);
    defer allocator.free(tasks);

    var patches_remaining = std.atomic.Atomic(usize).init(num_patch_files);
    var are_patches_done = std.atomic.Atomic(u32).init(0);

    var per_thread_buffers = try allocator.alloc([]u8, thread_pool.num_threads);
    defer allocator.free(per_thread_buffers);

    for (per_thread_buffers) |*thread_buffer| {
        thread_buffer.* = try allocator.alloc(u8, options.create_patch_options.max_work_unit_size);
    }

    defer {
        for (per_thread_buffers) |thread_buffer| {
            allocator.free(thread_buffer);
        }
    }

    var part_idx: usize = 0;
    var file_idx: usize = 0;
    var patch_file_idx: usize = 0;
    while (patch_file_idx < num_patch_files) : (patch_file_idx += 1) {
        if (part_idx * options.create_patch_options.max_work_unit_size > new_signature.files.items[file_idx].size) {
            part_idx = 0;
            file_idx += 1;

            while (new_signature.files.items[file_idx].size == 0) {
                file_idx += 1;
            }
        }

        tasks[patch_file_idx] = .{
            .task = ThreadPool.Task{ .callback = GeneratePatchTask.generatePatch },
            .file_info = .{
                .file_idx = file_idx,
                .file_part_idx = part_idx,
            },
            .new_signature_file = new_signature,
            .old_signature_file = old_signature,
            .remaining_patches = &patches_remaining,
            .are_patches_done = &are_patches_done,
            .io = options.patch_file_io,
            .per_thread_buffers = per_thread_buffers,
            .block_map = anchored_block_map,
        };

        batch.push(ThreadPool.Batch.from(&tasks[patch_file_idx].task));

        part_idx += 1;
    }

    thread_pool.schedule(batch);

    while (patches_remaining.load(.Acquire) != 0 and are_patches_done.load(.Acquire) == 0) {
        std.Thread.Futex.wait(&are_patches_done, 0);
    }
}

test "two files with no previous signature should result in two data operation patches" {
    var old_signature = try SignatureFile.init(std.testing.allocator);
    defer old_signature.deinit();

    var new_signature = try SignatureFile.init(std.testing.allocator);
    defer new_signature.deinit();

    const file_size = 1200;

    try new_signature.files.append(.{
        .name = try std.testing.allocator.alloc(u8, 1),
        .size = file_size,
        .permissions = 0,
    });

    try new_signature.files.append(.{
        .name = try std.testing.allocator.alloc(u8, 1),
        .size = file_size,
        .permissions = 0,
    });

    var thread_pool = ThreadPool.init(.{ .max_threads = 16 });
    thread_pool.spawnThreads();

    const PatchFileIOMock = struct {
        const MockedFileWriteData = struct {
            info: PatchFileInfo,
            operations: std.ArrayList(BlockPatching.PatchOperation),
        };

        file_io: PatchFileIO,

        patches: ParallelList(MockedFileWriteData),
        allocator: std.mem.Allocator,

        fn seedFromFileInfo(file_info: PatchFileInfo) usize {
            return (file_info.file_idx + 4) * file_info.file_idx + file_info.file_part_idx * 4;
        }

        fn write(patch_file_io: *PatchFileIO, patch_data: PatchFileData) error{WritePatchError}!void {
            var self = @fieldParentPtr(@This(), "file_io", patch_file_io);

            var mocked_write_data: MockedFileWriteData = .{
                .operations = std.ArrayList(BlockPatching.PatchOperation).initCapacity(self.allocator, patch_data.operations.items.len) catch unreachable,
                .info = patch_data.file_info,
            };

            for (patch_data.operations.items) |operation| {
                var copied_operation = operation;

                if (copied_operation == .Data) {
                    copied_operation = BlockPatching.PatchOperation{ .Data = self.allocator.alloc(u8, copied_operation.Data.len) catch unreachable };
                    std.mem.copy(u8, copied_operation.Data, operation.Data);
                }

                mocked_write_data.operations.appendAssumeCapacity(copied_operation);
            }

            var patch_list = self.patches.getList(ThreadPool.Thread.current.?.idx);
            patch_list.append(mocked_write_data) catch unreachable;
        }

        fn read(patch_file_io: *PatchFileIO, file_info: PatchFileInfo, read_buffer: []u8) error{ReadPatchError}!usize {
            _ = patch_file_io;

            var prng = std.rand.DefaultPrng.init(seedFromFileInfo(file_info));
            var random = prng.random();

            var idx: usize = 0;
            while (idx < file_size) : (idx += 1) {
                read_buffer[idx] = random.int(u8);
            }

            return file_size;
        }
    };

    // zig fmt: off
    var io_mock: PatchFileIOMock = .{ 
        .allocator = std.testing.allocator, 
        .file_io = .{
            .write_patch_file = &PatchFileIOMock.write,
            .read_patch_file = &PatchFileIOMock.read,
        }, 
        .patches = try ParallelList(PatchFileIOMock.MockedFileWriteData).init(std.testing.allocator, thread_pool.max_threads) 
    };
    // zig fmt: on

    defer {
        for (io_mock.patches.per_thread_lists) |per_thread_list| {
            for (per_thread_list.items) |patch| {
                for (patch.operations.items) |operation| {
                    if (operation == .Data) {
                        io_mock.allocator.free(operation.Data);
                    }
                }

                patch.operations.deinit();
            }
        }

        io_mock.patches.deinit();
    }

    try createPerFilePatchOperations(&thread_pool, new_signature, old_signature, std.testing.allocator, .{ .patch_file_io = &io_mock.file_io });

    var patches = try io_mock.patches.flattenParallelList(std.testing.allocator);
    defer std.testing.allocator.free(patches);

    try std.testing.expectEqual(@as(usize, 2), patches.len);

    for (patches) |patch| {
        try std.testing.expectEqual(@as(usize, 1), patch.operations.items.len);

        var operation = patch.operations.items[0];

        try std.testing.expect(operation == .Data);

        var prng = std.rand.DefaultPrng.init(PatchFileIOMock.seedFromFileInfo(patch.info));
        var random = prng.random();

        var idx: usize = 0;
        while (idx < file_size) : (idx += 1) {
            try std.testing.expectEqual(random.int(u8), operation.Data[idx]);
        }
    }

    const ShutdownTaskData = struct {
        task: ThreadPool.Task,
        pool: *ThreadPool,

        fn shutdownThreadpool(task: *ThreadPool.Task) void {
            var shutdown_task_data = @fieldParentPtr(@This(), "task", task);
            shutdown_task_data.pool.shutdown();
        }
    };

    var shutdown_task_data = ShutdownTaskData{
        .task = ThreadPool.Task{ .callback = ShutdownTaskData.shutdownThreadpool },
        .pool = &thread_pool,
    };

    thread_pool.schedule(ThreadPool.Batch.from(&shutdown_task_data.task));
    defer ThreadPool.deinit(&thread_pool);
}
