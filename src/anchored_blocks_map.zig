const std = @import("std");
const SignatureFile = @import("signature_file.zig").SignatureFile;
const SignatureBlock = @import("signature_file.zig").SignatureBlock;
const BlockSize = @import("block.zig").BlockSize;
const BlockHash = @import("block.zig").BlockHash;
const WeakHashType = @import("block.zig").WeakHashType;

pub const AnchoredBlock = struct {
    file_index: usize,
    block_index: usize,
    short_size: usize,
    hash: BlockHash,
};

pub const AnchoredBlocksMap = struct {
    const HashMapEntry = union(enum) {
        BoundedBlocks: std.BoundedArray(usize, 4),
        FallbackBlocks: std.ArrayList(usize),
    };

    const HashMapType = std.AutoHashMap(WeakHashType, HashMapEntry);

    allocator: std.mem.Allocator,
    underlying_hash_map: HashMapType,
    all_blocks: std.ArrayList(AnchoredBlock),

    // Index of the start of each file in the all blocks array.
    block_start_by_file: std.ArrayList(usize),

    const Self = @This();

    pub fn init(signature_file: SignatureFile, allocator: std.mem.Allocator) !*Self {
        var self = try allocator.create(AnchoredBlocksMap);
        self.allocator = allocator;
        self.underlying_hash_map = HashMapType.init(allocator);

        var signature_file_data = &signature_file.signature_file_data.?.InMemorySignatureFile;

        self.all_blocks = try std.ArrayList(AnchoredBlock).initCapacity(allocator, signature_file.blocks.items.len);
        self.block_start_by_file = try std.ArrayList(usize).initCapacity(allocator, signature_file_data.files.items.len);

        try self.all_blocks.resize(signature_file.blocks.items.len);
        try self.block_start_by_file.resize(signature_file_data.files.items.len);

        var current_block_start: usize = 0;

        for (self.block_start_by_file.items, 0..) |*element, idx| {
            var file = signature_file_data.files.items[idx];
            element.* = current_block_start;

            var num_blocks_per_file = @floatToInt(usize, @ceil(@intToFloat(f64, file.size) / BlockSize));
            current_block_start += num_blocks_per_file;
        }

        for (signature_file.blocks.items) |block| {
            var start_idx = self.block_start_by_file.items[block.file_idx];

            var file_size = signature_file_data.files.items[block.file_idx].size;

            self.all_blocks.items[start_idx + block.block_idx] = anchoredBlockFromSignatureBlock(file_size, block);
        }

        try self.underlying_hash_map.ensureTotalCapacity(@truncate(u32, signature_file.blocks.items.len));
        try self.anchorBlockHashes();

        return self;
    }

    pub fn deinit(self: *Self) void {
        var keys = self.underlying_hash_map.keyIterator();

        while (keys.next()) |key| {
            if (self.underlying_hash_map.get(key.*)) |value| {
                switch (value) {
                    .FallbackBlocks => |fallback| {
                        fallback.deinit();
                    },
                    .BoundedBlocks => {},
                }
            }
        }

        self.all_blocks.deinit();
        self.block_start_by_file.deinit();

        self.underlying_hash_map.deinit();
        self.allocator.destroy(self);
    }

    pub fn getBlock(self: Self, file_idx: usize, block_idx: usize) AnchoredBlock {
        var start_idx = self.block_start_by_file.items[file_idx];
        return self.all_blocks.items[start_idx + block_idx];
    }

    pub fn getAnchoredBlock(self: Self, hash: BlockHash, preferred_file_idx: usize, short_size: usize) ?AnchoredBlock {
        var best_block: ?AnchoredBlock = null;

        if (self.underlying_hash_map.get(hash.weak_hash)) |blocks| {
            var block_slice: []const usize = switch (blocks) {
                .BoundedBlocks => |bounded_blocks| bounded_blocks.slice(),
                .FallbackBlocks => |fallback_blocks| fallback_blocks.items,
            };

            for (block_slice) |block_idx| {
                var block = self.all_blocks.items[block_idx];

                // Only match blocks with the same length.
                if (block.short_size != short_size) {
                    continue;
                }

                const strong_hash_matches = std.mem.eql(u8, &block.hash.strong_hash, &hash.strong_hash);

                if (strong_hash_matches and (best_block == null or block.file_index == preferred_file_idx)) {
                    best_block = block;
                }
            }
        }

        return best_block;
    }

    pub fn hasAnchoredBlocksForWeakHash(self: Self, weak_hash: WeakHashType) bool {
        return self.underlying_hash_map.contains(weak_hash);
    }

    fn anchoredBlockFromSignatureBlock(file_size: usize, signature_block: SignatureBlock) AnchoredBlock {
        var left_over_bytes = std.math.min(BlockSize, file_size - BlockSize * @intCast(usize, signature_block.block_idx));

        return .{
            .file_index = signature_block.file_idx,
            .block_index = signature_block.block_idx,
            .short_size = BlockSize - left_over_bytes,
            .hash = signature_block.hash,
        };
    }

    fn anchorBlockHashes(self: *AnchoredBlocksMap) !void {

        // We append the blocks to the hashmap trying to fit them into the preallocated "BoundedBlocks"
        // If that's not possible because we have too many overlapping weak hashes we heap allocate a buffer to store them.
        for (self.all_blocks.items, 0..) |block, idx| {
            var blocks = self.underlying_hash_map.getOrPutAssumeCapacity(block.hash.weak_hash);

            if (!blocks.found_existing) {
                blocks.value_ptr.* = .{ .BoundedBlocks = .{} };
            }

            switch (blocks.value_ptr.*) {
                .BoundedBlocks => |*bounded_blocks| {
                    bounded_blocks.append(idx) catch {
                        var fallback_blocks = try std.ArrayList(usize).initCapacity(self.allocator, bounded_blocks.len * 2);
                        fallback_blocks.appendSliceAssumeCapacity(bounded_blocks.slice());
                        fallback_blocks.appendAssumeCapacity(idx);
                        blocks.value_ptr.* = .{ .FallbackBlocks = fallback_blocks };
                    };
                },
                .FallbackBlocks => |*fallback_blocks| {
                    try fallback_blocks.append(idx);
                },
            }
        }
    }
};

test "Simple signature file should be anchored" {
    var signature_file = try SignatureFile.init(std.testing.allocator);
    defer signature_file.deinit();

    var file_name_a = try std.testing.allocator.alloc(u8, "a.data".len);
    std.mem.copy(u8, file_name_a, "a.data");

    var file_name_b = try std.testing.allocator.alloc(u8, "b.data".len);
    std.mem.copy(u8, file_name_b, "b.data");

    try signature_file.files.append(.{
        .name = file_name_a,
        .size = BlockSize * 2,
        .permissions = 0,
    });
    try signature_file.files.append(.{
        .name = file_name_b,
        .size = BlockSize * 2,
        .permissions = 0,
    });

    var hashes: [4]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 5, 1, 245, 21, 84, 231, 154, 45, 120, 1, 154, 21, 84, 154, 1, 235 },
    };
    hashes[1] = .{
        .weak_hash = 16,
        .strong_hash = [16]u8{ 123, 1, 123, 21, 78, 50, 54, 45, 81, 1, 54, 21, 84, 47, 1, 47 },
    };
    hashes[2] = .{
        .weak_hash = 20,
        .strong_hash = [16]u8{ 46, 76, 56, 21, 84, 57, 54, 45, 21, 1, 64, 21, 84, 57, 1, 47 },
    };
    hashes[3] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 32, 1, 54, 21, 84, 57, 1, 67, 84, 1, 64, 21, 84, 54, 1, 45 },
    };

    var signature_blocks: [4]SignatureBlock = undefined;
    signature_blocks[0] = .{ .file_idx = 0, .block_idx = 0, .hash = hashes[0] };
    signature_blocks[1] = .{ .file_idx = 0, .block_idx = 1, .hash = hashes[1] };
    signature_blocks[2] = .{ .file_idx = 1, .block_idx = 0, .hash = hashes[2] };
    signature_blocks[3] = .{ .file_idx = 1, .block_idx = 1, .hash = hashes[3] };

    try signature_file.blocks.appendSlice(&signature_blocks);

    var anchored_hash_map = try AnchoredBlocksMap.init(signature_file.*, std.testing.allocator);
    defer anchored_hash_map.deinit();

    for (hashes) |hash| {
        if (anchored_hash_map.getAnchoredBlock(hash, 0, 0)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u8, &hash.strong_hash, &block.hash.strong_hash);
        } else {
            try std.testing.expect(false);
        }
    }
}

test "Blocks with same strong hash should be picked based on the preferred file" {
    var signature_file = try SignatureFile.init(std.testing.allocator);
    defer signature_file.deinit();

    var file_name_a = try std.testing.allocator.alloc(u8, "a.data".len);
    std.mem.copy(u8, file_name_a, "a.data");

    var file_name_b = try std.testing.allocator.alloc(u8, "b.data".len);
    std.mem.copy(u8, file_name_b, "b.data");

    try signature_file.files.append(.{
        .name = file_name_a,
        .size = BlockSize * 2,
        .permissions = 0,
    });
    try signature_file.files.append(.{
        .name = file_name_b,
        .size = BlockSize * 2,
        .permissions = 0,
    });

    var hashes: [4]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 5, 1, 54, 21, 84, 57, 42, 45, 81, 1, 56, 21, 84, 57, 1, 67 },
    };
    hashes[1] = .{
        .weak_hash = 16,
        .strong_hash = [16]u8{ 84, 1, 56, 21, 84, 57, 1, 46, 21, 1, 64, 21, 84, 54, 1, 45 },
    };

    hashes[2] = hashes[0];
    hashes[3] = hashes[1];

    var signature_blocks: [4]SignatureBlock = undefined;
    signature_blocks[0] = .{ .file_idx = 0, .block_idx = 0, .hash = hashes[0] };
    signature_blocks[1] = .{ .file_idx = 0, .block_idx = 1, .hash = hashes[1] };
    signature_blocks[2] = .{ .file_idx = 1, .block_idx = 0, .hash = hashes[2] };
    signature_blocks[3] = .{ .file_idx = 1, .block_idx = 1, .hash = hashes[3] };

    try signature_file.blocks.appendSlice(signature_blocks[0..]);

    var anchored_hash_map = try AnchoredBlocksMap.init(signature_file.*, std.testing.allocator);
    defer anchored_hash_map.deinit();

    {
        var hash = hashes[0];
        if (anchored_hash_map.getAnchoredBlock(hash, 0, 0)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u8, &hash.strong_hash, &block.hash.strong_hash);
            try std.testing.expectEqual(block.file_index, 0);
        } else {
            try std.testing.expect(false);
        }
    }

    // Same hash but prefer second file
    {
        var hash = hashes[0];
        if (anchored_hash_map.getAnchoredBlock(hash, 1, 0)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u8, &hash.strong_hash, &block.hash.strong_hash);
            try std.testing.expectEqual(block.file_index, 1);
        } else {
            try std.testing.expect(false);
        }
    }
}
