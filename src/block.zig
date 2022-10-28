pub const WeakHashType = u32;

pub const BlockHash = struct {
    weak_hash: WeakHashType,
    strong_hash: [8]u32,
};

pub const BlockSize = 64 * 1024;
