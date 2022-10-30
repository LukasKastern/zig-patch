pub const WeakHashType = u32;

pub const BlockHash = struct {
    weak_hash: WeakHashType,
    strong_hash: [16]u8,
};

pub const BlockSize = 64 * 1024;
