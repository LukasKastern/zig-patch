const std = @import("std");
const SignatureFile = @import("signature_file.zig").SignatureFile;
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
    const HashMapType = std.AutoHashMap(WeakHashType, *std.ArrayList(AnchoredBlock));

    allocator: std.mem.Allocator,
    underlying_hash_map: HashMapType,

    const Self = @This();

    pub fn init(signature_file: SignatureFile, allocator: std.mem.Allocator) !*Self {
        var self = try allocator.create(AnchoredBlocksMap);
        self.allocator = allocator;
        self.underlying_hash_map = HashMapType.init(allocator);
        try self.underlying_hash_map.ensureTotalCapacity(@truncate(u32, signature_file.blocks.items.len));
        try self.anchorBlockHashes(signature_file);

        return self;
    }

    pub fn deinit(self: *Self) void {
        var keys = self.underlying_hash_map.keyIterator();

        while (keys.next()) |key| {
            if (self.underlying_hash_map.get(key.*)) |value| {
                value.deinit();
                self.allocator.destroy(value);
            }
        }

        self.underlying_hash_map.deinit();
        self.allocator.destroy(self);
    }

    pub fn getAnchoredBlock(self: Self, hash: BlockHash, preferred_file_idx: usize) ?AnchoredBlock {
        var best_block: ?AnchoredBlock = null;

        if (self.underlying_hash_map.get(hash.weak_hash)) |blocks| {
            for (blocks.items) |block| {
                const strong_hash_matches = std.mem.eql(u32, &block.hash.strong_hash, &hash.strong_hash);

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

    fn addAnchoredBlock(self: *Self, anchored_block: AnchoredBlock) !void {
        var blocks: *std.ArrayList(AnchoredBlock) = undefined;

        if (self.underlying_hash_map.get(anchored_block.hash.weak_hash)) |already_existing_blocks| {
            blocks = already_existing_blocks;
        } else {
            blocks = try self.allocator.create(std.ArrayList(AnchoredBlock));
            blocks.* = std.ArrayList(AnchoredBlock).init(self.allocator);
            self.underlying_hash_map.putAssumeCapacity(anchored_block.hash.weak_hash, blocks);
        }

        try blocks.append(anchored_block);
    }

    fn anchorBlockHashes(anchored_hashes: *AnchoredBlocksMap, signature_file: SignatureFile) !void {
        var file_index: usize = 0;
        var block_index: usize = 0;
        var byte_offset: isize = 0;

        for (signature_file.blocks.items) |block| {
            var file = signature_file.files.items[file_index];

            if (file.size - byte_offset <= 0) {
                byte_offset = 0;
                block_index = 0;
                file_index += 1;

                file = signature_file.files.items[file_index];
            }

            // zig fmt: off
            var anchored_block: AnchoredBlock = .{
                .file_index = file_index,
                .block_index = block_index,
                .short_size = @intCast(usize, BlockSize - std.math.min(BlockSize, file.size - byte_offset)),
                .hash = block
            };
            // zig fmt: on

            try anchored_hashes.addAnchoredBlock(anchored_block);

            byte_offset += BlockSize;
            block_index += 1;
        }
    }
};

test "Simple signature file should be anchored" {
    var signature_file = try SignatureFile.init(std.testing.allocator);
    defer signature_file.deinit();

    try signature_file.files.append(.{
        .name = "a.data",
        .size = BlockSize * 2,
        .permissions = 0,
    });
    try signature_file.files.append(.{
        .name = "b.data",
        .size = BlockSize * 2,
        .permissions = 0,
    });

    var hashes: [4]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [8]u32{ 5, 1, 564, 21, 84, 547, 45612, 45 },
    };
    hashes[1] = .{
        .weak_hash = 16,
        .strong_hash = [8]u32{ 123123, 1, 123, 21, 78570, 547, 564, 456123 },
    };
    hashes[2] = .{
        .weak_hash = 20,
        .strong_hash = [8]u32{ 456, 786, 56, 21, 84, 547, 564, 45 },
    };
    hashes[3] = .{
        .weak_hash = 8,
        .strong_hash = [8]u32{ 846321, 1, 564, 21, 84, 547, 1, 4567 },
    };

    try signature_file.blocks.appendSlice(hashes[0..]);

    var anchored_hash_map = try AnchoredBlocksMap.init(signature_file.*, std.testing.allocator);
    defer anchored_hash_map.deinit();

    for (hashes) |hash| {
        if (anchored_hash_map.getAnchoredBlock(hash, 0)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u32, &hash.strong_hash, &block.hash.strong_hash);
        } else {
            try std.testing.expect(false);
        }
    }
}

test "Blocks with same strong hash should be picked based on the preferred file" {
    var signature_file = try SignatureFile.init(std.testing.allocator);
    defer signature_file.deinit();

    try signature_file.files.append(.{
        .name = "a.data",
        .size = BlockSize * 2,
        .permissions = 0,
    });
    try signature_file.files.append(.{
        .name = "b.data",
        .size = BlockSize * 2,
        .permissions = 0,
    });

    var hashes: [4]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [8]u32{ 5, 1, 564, 21, 84, 547, 45612, 45 },
    };
    hashes[1] = .{
        .weak_hash = 16,
        .strong_hash = [8]u32{ 123123, 1, 123, 21, 78570, 547, 564, 456123 },
    };

    hashes[2] = hashes[0];
    hashes[3] = hashes[1];

    try signature_file.blocks.appendSlice(hashes[0..]);

    var anchored_hash_map = try AnchoredBlocksMap.init(signature_file.*, std.testing.allocator);
    defer anchored_hash_map.deinit();

    {
        var hash = hashes[0];
        if (anchored_hash_map.getAnchoredBlock(hash, 0)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u32, &hash.strong_hash, &block.hash.strong_hash);
            try std.testing.expectEqual(block.file_index, 0);
        } else {
            try std.testing.expect(false);
        }
    }

    // Same hash but prefer second file
    {
        var hash = hashes[0];
        if (anchored_hash_map.getAnchoredBlock(hash, 1)) |block| {
            try std.testing.expectEqual(hash.weak_hash, block.hash.weak_hash);
            try std.testing.expectEqualSlices(u32, &hash.strong_hash, &block.hash.strong_hash);
            try std.testing.expectEqual(block.file_index, 1);
        } else {
            try std.testing.expect(false);
        }
    }
}
