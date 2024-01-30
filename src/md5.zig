const c = @cImport(@cInclude("md5.h"));

pub fn hash(b: []const u8, out: *[16]u8) void {
    var res = c.md5(out, b.ptr, b.len);
    if (res != 0) {
        unreachable;
    }
}
