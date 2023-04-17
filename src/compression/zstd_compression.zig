const zstd = @cImport({
    @cInclude("zstd.h");
});

const std = @import("std");
const compression = @import("compression.zig");

// const ZlibAllocator = struct {
//     const Self = @This();

//     backing_allocator: std.mem.Allocator,

//     pub export fn allocZlib(self_opaque: ?*anyopaque, items: c_uint, size: c_uint) ?*anyopaque {
//         if (self_opaque) |self_opaque_safe| {
//             var self = @ptrCast(*Self, @alignCast(@alignOf(Self), self_opaque_safe));

//             var size_to_alloc = items * size;

//             // We add the size of the allocation as a header to it.
//             // That way we can rebuild the slice when trying to free the memory later.
//             var data = self.backing_allocator.alignedAlloc(u8, @alignOf(usize), size_to_alloc + @sizeOf(usize)) catch {
//                 std.log.err("Brotli allocation of {} bytes failed", .{size_to_alloc});
//                 return null;
//             };

//             var allocation_size = @ptrCast(*usize, @alignCast(@alignOf(usize), data.ptr));
//             allocation_size.* = size_to_alloc;

//             return data.ptr + @sizeOf(usize);
//         }

//         std.log.err("ZLib alloc called with null instance", .{});
//         return null;
//     }

//     pub export fn freeZlib(self_opaque: ?*anyopaque, ptr: ?*anyopaque) void {
//         if (ptr == null) {
//             return;
//         }

//         var ptr_u8 = @ptrCast([*]u8, @alignCast(@alignOf(u8), ptr.?));
//         var ptr_beginning_of_size = ptr_u8 - @sizeOf(usize);
//         var allocation_size = @ptrCast(*usize, @alignCast(@alignOf(usize), ptr_beginning_of_size));

//         var slice = ptr_beginning_of_size[0..(allocation_size.* + @sizeOf(usize))];

//         if (self_opaque) |self_opaque_safe| {
//             var self = @ptrCast(*Self, @alignCast(@alignOf(Self), self_opaque_safe));
//             self.backing_allocator.free(slice);
//         }
//     }
// };

pub const ZstdCompression = struct {
    const ZstdDeflate = struct {
        compression_impl: compression.DeflateImpl,
        allocator: std.mem.Allocator,
        // Zstd_allocator: ZstdAllocator,

        // state: Zstd.z_stream,

        pub fn init(allocator: std.mem.Allocator) !*ZstdDeflate {
            var deflate = try allocator.create(ZstdDeflate);
            errdefer allocator.destroy(deflate);

            // deflate.Zstd_allocator = .{
            // .backing_allocator = allocator,
            // };

            // deflate.state = std.mem.zeroInit(Zstd.z_stream, .{});
            // deflate.state.zalloc = ZstdAllocator.allocZstd;
            // deflate.state.zfree = ZstdAllocator.freeZstd;
            // deflate.state.@"opaque" = &deflate.Zstd_allocator;

            // const quality_level = 2;
            // if (Zstd.deflateInit(&deflate.state, quality_level) != Zstd.Z_OK) {
            // return error.ZstdInitializationFailed;
            // }

            deflate.compression_impl = .{ .deflate_buffer = &ZstdDeflate.deflateStream };
            deflate.allocator = allocator;

            return deflate;
        }

        pub fn deinit(deflate: *ZstdDeflate) void {
            // var result = Zstd.deflateEnd(&deflate.state);
            // std.debug.assert(result == Zstd.Z_OK);

            deflate.allocator.destroy(deflate);
        }

        pub fn deflateStream(impl: *compression.DeflateImpl, input: []u8, output: []u8) error{DeflateError}![]u8 {
            var deflate = @fieldParentPtr(ZstdDeflate, "compression_impl", impl);
            _ = deflate;

            var err = zstd.ZSTD_compress(output.ptr, output.len, input.ptr, input.len, 4);

            if (zstd.ZSTD_isError(err) != 0) {
                return error.DeflateError;
            }

            return output[0..err];
        }
    };

    const ZstdInflate = struct {
        compression_impl: compression.InflateImpl,
        allocator: std.mem.Allocator,
        // Zstd_allocator: ZstdAllocator,
        // state: Zstd.z_stream,

        pub fn init(allocator: std.mem.Allocator) !*ZstdInflate {
            var inflate = try allocator.create(ZstdInflate);
            errdefer allocator.destroy(inflate);

            // inflate.Zstd_allocator = .{
            // .backing_allocator = allocator,
            // };

            inflate.allocator = allocator;

            // inflate.state = std.mem.zeroInit(Zstd.z_stream, .{});
            // inflate.state.zalloc = ZstdAllocator.allocZstd;
            // inflate.state.zfree = ZstdAllocator.freeZstd;
            // inflate.state.@"opaque" = &inflate.Zstd_allocator;

            // if (Zstd.inflateInit(&inflate.state) != Zstd.Z_OK) {
            // return error.ZstdInitializationFailed;
            // }

            inflate.compression_impl = .{ .inflate_buffer = inflateStream };

            return inflate;
        }

        pub fn deinit(inflate: *ZstdInflate) void {
            // var result = Zstd.inflateEnd(&inflate.state);
            // std.debug.assert(result == Zstd.Z_OK);

            inflate.allocator.destroy(inflate);
        }

        pub fn inflateStream(impl: *compression.InflateImpl, input: []u8, output: []u8) error{InflateError}!void {
            var inflate_impl = @fieldParentPtr(ZstdInflate, "compression_impl", impl);
            _ = inflate_impl;

            var err = zstd.ZSTD_decompress(output.ptr, output.len, input.ptr, input.len);
            if (zstd.ZSTD_isError(err) != 0) {
                return error.InflateError;
            }

            // inflate_impl.state.avail_in = @intCast(c_uint, input.len);
            // inflate_impl.state.next_in = input.ptr;
            // inflate_impl.state.avail_out = @intCast(c_uint, output.len);
            // inflate_impl.state.next_out = output.ptr;

            // var inflate_res = Zstd.inflate(&inflate_impl.state, Zstd.Z_FINISH);

            // if (inflate_res != Zstd.Z_STREAM_END) {
            // std.log.err("Zstd inflate resulted in err={}, msg={s}", .{ inflate_res, inflate_impl.state.msg });
            // return error.InflateError;
            // }
        }
    };

    pub fn initDeflateImpl(allocator: std.mem.Allocator) !*compression.DeflateImpl {
        var deflate = try ZstdDeflate.init(allocator);
        return &deflate.compression_impl;
    }

    pub fn deinitDeflateImpl(impl: *compression.DeflateImpl) void {
        var deflate_impl = @fieldParentPtr(ZstdDeflate, "compression_impl", impl);
        deflate_impl.deinit();
    }

    pub fn initInflateImpl(allocator: std.mem.Allocator) !*compression.InflateImpl {
        var inflate = try ZstdInflate.init(allocator);
        return &inflate.compression_impl;
    }

    pub fn deinitInflateImpl(impl: *compression.InflateImpl) void {
        var inflate_impl = @fieldParentPtr(ZstdInflate, "compression_impl", impl);
        inflate_impl.deinit();
    }
};
