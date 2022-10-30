const WeakHashType = @import("block.zig").WeakHashType;
const BlockSize = @import("block.zig").BlockSize;

const std = @import("std");

pub const RollingHash = struct {
    state_0: u32 = 0,
    state_1: u32 = 0,
    hash: WeakHashType = 0,

    const _M: u32 = 1 << 16;

    pub fn next(self: *RollingHash, buffer: []u8, tail: usize, head: usize) void {
        var a_push: u32 = buffer[head];
        var a_pop: u32 = buffer[tail];
        self.state_0 = (self.state_0 -% a_pop +% a_push) % _M;
        self.state_1 = (self.state_1 -% @intCast(u32, head - (tail)) *% a_pop +% self.state_0);

        self.hash = self.state_0 +% _M *% self.state_1;
    }

    pub fn recompute(self: *RollingHash, block: []u8) void {
        var a: u32 = 0;
        var b: u32 = 0;

        const span = @intCast(u32, block.len - 1);
        for (block) |val, idx| {
            a +%= val;

            var index = (@intCast(u32, idx));
            var multiplier = (span - index + 1);

            var value_to_add = val *% multiplier;

            b +%= value_to_add;
        }

        self.hash = (a % _M) + (_M * (b % _M));
        self.state_0 = a % _M;
        self.state_1 = b % _M;
    }
};

test "Recomputed hash should match rolling hash" {
    var buffer: [BlockSize * 2]u8 = undefined;

    var rand = std.rand.DefaultPrng.init(365654);

    for (buffer) |*item| {
        item.* = rand.random().int(u8); // @truncate(u8, (idx * idx + 5) % 255);
    }

    var hash: RollingHash = .{};

    var tail: u32 = 0;
    var head: u32 = 0;

    var recomputed_hash: RollingHash = .{};

    while (head < buffer.len) {
        if (tail == head) {
            head += BlockSize;
            hash.recompute(buffer[tail..head]);
        } else {
            hash.next(&buffer, tail - 1, head - 1);
        }

        tail += 1;
        head += 1;
    }

    recomputed_hash.recompute(buffer[buffer.len - BlockSize - 1 .. buffer.len - 1]);
    try std.testing.expectEqual(recomputed_hash.hash, hash.hash);
}
