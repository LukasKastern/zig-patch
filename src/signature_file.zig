const std = @import("std");
const BlockHash = @import("block.zig").BlockHash;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const ThreadPool = @import("zap/thread_pool_go_based.zig");

pub const SignatureFile = struct {
    const Directory = struct {
        path: []u8,
        permissions: u8,
    };

    const SymLink = struct {
        source: []u8,
        target: []u8,
        permissions: u8,
    };

    const File = struct {
        name: []const u8,
        size: usize,
        permissions: u8,
    };

    allocator: std.mem.Allocator,
    directories: std.ArrayList(Directory),
    sym_links: std.ArrayList(SymLink),
    files: std.ArrayList(File),
    blocks: std.ArrayList(BlockHash),
    path_name_buffer: [512]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.allocator = allocator;
        signature_file.files = std.ArrayList(File).init(allocator);
        signature_file.directories = std.ArrayList(Directory).init(allocator);
        signature_file.sym_links = std.ArrayList(SymLink).init(allocator);
        signature_file.blocks = std.ArrayList(BlockHash).init(allocator);
        return signature_file;
    }

    fn deallocateBuffers(self: *SignatureFile) void {
        for (self.directories.items) |directory| {
            self.allocator.free(directory.path);
        }

        for (self.files.items) |file| {
            self.allocator.free(file.name);
        }

        self.sym_links.clearRetainingCapacity();
        self.directories.clearRetainingCapacity();
        self.files.clearRetainingCapacity();
        self.blocks.clearRetainingCapacity();
    }

    pub fn deinit(self: *SignatureFile) void {
        self.deallocateBuffers();

        self.files.deinit();
        self.sym_links.deinit();
        self.blocks.deinit();
        self.directories.deinit();

        self.allocator.destroy(self);
    }

    const CalculateHashData = struct {
        task: ThreadPool.Task,
        block_idx: usize,
        blocks: *std.atomic.Atomic(usize),
        are_blocks_done: *std.atomic.Atomic(u32),
        file_idx: usize,
        block_idx_in_file: usize,
        signature_file: *SignatureFile,

        per_thread_block_hashes: std.ArrayList(std.ArrayList(BlockHash)),

        const Self = @This();

        fn calculate_hash(task: *ThreadPool.Task) void {
            var calculate_hash_data_task = @fieldParentPtr(Self, "task", task);
            calculate_hash_impl(calculate_hash_data_task) catch unreachable;
        }

        fn calculate_hash_impl(self: *Self) !void {
            const signature_file = self.signature_file.files.items[self.file_idx];
            const read_offset = self.block_idx_in_file * BlockSize;

            var file = try std.fs.openFileAbsolute(signature_file.name, .{});
            defer file.close();

            var buffer: [BlockSize]u8 = undefined;
            try file.seekTo(read_offset);
            _ = try file.read(&buffer);

            var rolling_hash: RollingHash = .{};
            rolling_hash.recompute(&buffer);

            var block_hash: BlockHash = .{
                .weak_hash = rolling_hash.hash,
                .strong_hash = undefined,
            };

            std.crypto.hash.Md5.hash(&buffer, &block_hash.strong_hash, .{});

            var thread_idx = ThreadPool.Thread.current.?.idx;
            var hashes = &self.per_thread_block_hashes.items[thread_idx];
            hashes.appendAssumeCapacity(block_hash);

            if (self.blocks.fetchSub(1, .Release) == 1) {
                self.are_blocks_done.store(1, .Release);
                std.Thread.Futex.wake(self.are_blocks_done, 1);
            }
        }
    };

    pub fn generateFromFolder(self: *SignatureFile, directory: []const u8, thread_pool: *ThreadPool) !void {
        self.deallocateBuffers();

        var root_dir = try std.fs.openDirAbsolute(directory, .{});
        defer root_dir.close();

        try self.generateFromFolderImpl(root_dir);

        var num_blocks: usize = 0;

        for (self.files.items) |signature_file| {
            num_blocks += @floatToInt(usize, @ceil(@intToFloat(f64, signature_file.size) / BlockSize));
        }

        var blocks_remaining = std.atomic.Atomic(usize).init(num_blocks);
        var are_blocks_done = std.atomic.Atomic(u32).init(0);

        var tasks = try self.allocator.alloc(CalculateHashData, num_blocks);
        defer self.allocator.free(tasks);

        var per_thread_block_hashes = std.ArrayList(std.ArrayList(BlockHash)).init(self.allocator);
        defer per_thread_block_hashes.deinit();

        try per_thread_block_hashes.resize(thread_pool.num_threads);
        for (per_thread_block_hashes.items) |*item| {
            item.* = try std.ArrayList(BlockHash).initCapacity(self.allocator, num_blocks);
        }

        defer {
            for (per_thread_block_hashes.items) |*item| {
                item.deinit();
            }
        }

        var batch = ThreadPool.Batch{};
        var file_idx: usize = 0;
        var block_idx_in_file: usize = 0;
        var block_idx: usize = 0;

        while (block_idx < num_blocks) : (block_idx += 1) {
            var current_file = self.files.items[file_idx];

            if (block_idx_in_file * BlockSize > current_file.size) {
                file_idx += 1;
                block_idx_in_file = 0;
            }

            tasks[block_idx] = CalculateHashData{
                .task = ThreadPool.Task{ .callback = CalculateHashData.calculate_hash },
                .block_idx = block_idx,
                .blocks = &blocks_remaining,
                .are_blocks_done = &are_blocks_done,

                .file_idx = file_idx,
                .block_idx_in_file = block_idx_in_file,
                .signature_file = self,
                .per_thread_block_hashes = per_thread_block_hashes,
            };

            batch.push(ThreadPool.Batch.from(&tasks[block_idx].task));

            block_idx_in_file += 1;
        }

        thread_pool.schedule(batch);

        try self.blocks.ensureTotalCapacity(num_blocks);

        while (are_blocks_done.load(.Acquire) == 0) {
            std.Thread.Futex.wait(&are_blocks_done, 0);
        }

        for (per_thread_block_hashes.items) |item| {
            self.blocks.appendSliceAssumeCapacity(item.items);
        }

        std.log.info("Blocks are done", .{});
    }

    fn generateFromFolderImpl(self: *SignatureFile, directory: std.fs.Dir) !void {
        var iteratable_dir = try directory.makeOpenPathIterable("", .{});
        var iterator = iteratable_dir.iterate();

        while (try iterator.next()) |entry| {
            var full_entry_name = try directory.realpath(entry.name, &self.path_name_buffer);

            switch (entry.kind) {
                .Directory => {
                    var nested_dir = try directory.openDir(entry.name, .{});
                    defer nested_dir.close();

                    try self.generateFromFolderImpl(nested_dir);
                    try self.directories.append(.{ .path = try directory.realpathAlloc(self.allocator, entry.name), .permissions = 0 });
                },
                .File => {
                    var file = try directory.openFile(entry.name, .{});
                    defer file.close();

                    try self.files.append(.{ .name = try directory.realpathAlloc(self.allocator, entry.name), .size = try file.getEndPos(), .permissions = 0 });
                },
                else => {
                    std.log.warn("Found unsupported file type={}, at path={s}", .{ entry.kind, full_entry_name });
                },
            }
        }
    }

    pub fn saveSignatureToFile(self: *SignatureFile, target_path: []const u8) !void {
        _ = self;
        var file = try std.fs.createFileAbsolute(target_path, .{});
        defer file.close();

        var buffer: [32]u8 = undefined;
        _ = try file.write(&buffer);
    }
};
