const zlib = @cImport({
    @cInclude("zlib.h");
});

const std = @import("std");
const compression = @import("compression.zig");

const ZlibAllocator = struct {
    const Self = @This();

    backing_allocator: std.mem.Allocator,

    pub export fn allocZlib(self_opaque: ?*anyopaque, items: c_uint, size: c_uint) ?*anyopaque {
        if (self_opaque) |self_opaque_safe| {
            var self = @as(*Self, @ptrCast(@alignCast(self_opaque_safe)));

            var size_to_alloc = items * size;

            // We add the size of the allocation as a header to it.
            // That way we can rebuild the slice when trying to free the memory later.
            var data = self.backing_allocator.alignedAlloc(u8, @alignOf(usize), size_to_alloc + @sizeOf(usize)) catch {
                std.log.err("Brotli allocation of {} bytes failed", .{size_to_alloc});
                return null;
            };

            var allocation_size = @as(*usize, @ptrCast(@alignCast(data.ptr)));
            allocation_size.* = size_to_alloc;

            return data.ptr + @sizeOf(usize);
        }

        std.log.err("ZLib alloc called with null instance", .{});
        return null;
    }

    pub export fn freeZlib(self_opaque: ?*anyopaque, ptr: ?*anyopaque) void {
        if (ptr == null) {
            return;
        }

        var ptr_u8 = @as([*]u8, @ptrCast(@alignCast(ptr.?)));
        var ptr_beginning_of_size = ptr_u8 - @sizeOf(usize);
        var allocation_size = @as(*usize, @ptrCast(@alignCast(ptr_beginning_of_size)));

        var slice = ptr_beginning_of_size[0..(allocation_size.* + @sizeOf(usize))];

        if (self_opaque) |self_opaque_safe| {
            var self = @as(*Self, @ptrCast(@alignCast(self_opaque_safe)));
            self.backing_allocator.free(slice);
        }
    }
};

pub const ZlibCompression = struct {
    const ZlibDeflate = struct {
        compression_impl: compression.DeflateImpl,
        allocator: std.mem.Allocator,
        zlib_allocator: ZlibAllocator,

        state: zlib.z_stream,

        pub fn init(allocator: std.mem.Allocator) !*ZlibDeflate {
            var deflate = try allocator.create(ZlibDeflate);
            errdefer allocator.destroy(deflate);

            deflate.zlib_allocator = .{
                .backing_allocator = allocator,
            };

            deflate.state = std.mem.zeroInit(zlib.z_stream, .{});
            deflate.state.zalloc = ZlibAllocator.allocZlib;
            deflate.state.zfree = ZlibAllocator.freeZlib;
            deflate.state.@"opaque" = &deflate.zlib_allocator;

            const quality_level = 5;

            if (zlib.deflateInit(&deflate.state, quality_level) != zlib.Z_OK) {
                return error.ZLibInitializationFailed;
            }

            deflate.compression_impl = .{ .deflate_buffer = &ZlibDeflate.deflateStream };
            deflate.allocator = allocator;

            return deflate;
        }

        pub fn deinit(deflate: *ZlibDeflate) void {
            var result = zlib.deflateEnd(&deflate.state);
            std.debug.assert(result == zlib.Z_OK);

            deflate.allocator.destroy(deflate);
        }

        pub fn deflateStream(impl: *compression.DeflateImpl, input: []u8, output: []u8) error{DeflateError}![]u8 {
            var deflate = @fieldParentPtr(ZlibDeflate, "compression_impl", impl);

            deflate.state.avail_in = @as(c_uint, @intCast(input.len));
            deflate.state.next_in = input.ptr;
            deflate.state.avail_out = @as(c_uint, @intCast(output.len));
            deflate.state.next_out = output.ptr;

            var deflate_res = zlib.deflate(&deflate.state, zlib.Z_FINISH);

            if (deflate_res != zlib.Z_STREAM_END) {
                std.log.err("Zlib deflate resulted in err={}, msg={s}", .{ deflate_res, deflate.state.msg });
                return error.DeflateError;
            }

            const total_out = deflate.state.total_out;
            return output[0..total_out];
        }
    };

    const ZlibInflate = struct {
        compression_impl: compression.InflateImpl,
        allocator: std.mem.Allocator,
        zlib_allocator: ZlibAllocator,
        state: zlib.z_stream,

        pub fn init(allocator: std.mem.Allocator) !*ZlibInflate {
            var inflate = try allocator.create(ZlibInflate);
            errdefer allocator.destroy(inflate);

            inflate.zlib_allocator = .{
                .backing_allocator = allocator,
            };

            inflate.allocator = allocator;

            inflate.state = std.mem.zeroInit(zlib.z_stream, .{});
            inflate.state.zalloc = ZlibAllocator.allocZlib;
            inflate.state.zfree = ZlibAllocator.freeZlib;
            inflate.state.@"opaque" = &inflate.zlib_allocator;

            if (zlib.inflateInit(&inflate.state) != zlib.Z_OK) {
                return error.ZLibInitializationFailed;
            }

            inflate.compression_impl = .{ .inflate_buffer = inflateStream };

            return inflate;
        }

        pub fn deinit(inflate: *ZlibInflate) void {
            var result = zlib.inflateEnd(&inflate.state);
            std.debug.assert(result == zlib.Z_OK);

            inflate.allocator.destroy(inflate);
        }

        pub fn inflateStream(impl: *compression.InflateImpl, input: []u8, output: []u8) error{InflateError}!void {
            var inflate_impl = @fieldParentPtr(ZlibInflate, "compression_impl", impl);
            inflate_impl.state.avail_in = @as(c_uint, @intCast(input.len));
            inflate_impl.state.next_in = input.ptr;
            inflate_impl.state.avail_out = @as(c_uint, @intCast(output.len));
            inflate_impl.state.next_out = output.ptr;

            var inflate_res = zlib.inflate(&inflate_impl.state, zlib.Z_FINISH);

            if (inflate_res != zlib.Z_STREAM_END) {
                std.log.err("Zlib inflate resulted in err={}, msg={s}", .{ inflate_res, inflate_impl.state.msg });
                return error.InflateError;
            }
        }
    };

    pub fn initDeflateImpl(allocator: std.mem.Allocator) !*compression.DeflateImpl {
        var deflate = try ZlibDeflate.init(allocator);
        return &deflate.compression_impl;
    }

    pub fn deinitDeflateImpl(impl: *compression.DeflateImpl) void {
        var deflate_impl = @fieldParentPtr(ZlibDeflate, "compression_impl", impl);
        deflate_impl.deinit();
    }

    pub fn initInflateImpl(allocator: std.mem.Allocator) !*compression.InflateImpl {
        var inflate = try ZlibInflate.init(allocator);
        return &inflate.compression_impl;
    }

    pub fn deinitInflateImpl(impl: *compression.InflateImpl) void {
        var inflate_impl = @fieldParentPtr(ZlibInflate, "compression_impl", impl);
        inflate_impl.deinit();
    }
};
