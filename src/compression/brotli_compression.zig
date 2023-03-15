const brotli = @cImport({
    @cInclude("brotli/encode.h");
    @cInclude("brotli/decode.h");
});

const std = @import("std");
const compression = @import("compression.zig");

const BrotliAllocator = struct {
    const Self = @This();

    backing_allocator: std.mem.Allocator,

    pub export fn alloc(self_opaque: ?*anyopaque, size: usize) ?*anyopaque {
        if (self_opaque) |self_opaque_safe| {
            var self = @ptrCast(*Self, @alignCast(@alignOf(Self), self_opaque_safe));

            // We add the size of the allocation as a header to it.
            // That way we can rebuild the slice when trying to free the memory later.
            var data = self.backing_allocator.alignedAlloc(u8, @alignOf(usize), size + @sizeOf(usize)) catch {
                std.log.err("Brotli allocation of {} bytes failed", .{size});
                return null;
            };

            var allocation_size = @ptrCast(*usize, @alignCast(@alignOf(usize), data.ptr));
            allocation_size.* = size;

            return data.ptr + @sizeOf(usize);
        }

        std.log.err("Brotli alloc called with null instance", .{});
        return null;
    }

    pub export fn free(self_opaque: ?*anyopaque, ptr: ?*anyopaque) void {
        if (ptr == null) {
            return;
        }

        var ptr_u8 = @ptrCast([*]u8, @alignCast(@alignOf(u8), ptr.?));
        var ptr_beginning_of_size = ptr_u8 - @sizeOf(usize);
        var allocation_size = @ptrCast(*usize, @alignCast(@alignOf(usize), ptr_beginning_of_size));

        var slice = ptr_beginning_of_size[0..(allocation_size.* + @sizeOf(usize))];

        if (self_opaque) |self_opaque_safe| {
            var self = @ptrCast(*Self, @alignCast(@alignOf(Self), self_opaque_safe));
            self.backing_allocator.free(slice);
        }
    }
};

pub const BrotliCompression = struct {
    const BrotliDeflate = struct {
        compression_impl: compression.DeflateImpl,
        allocator: std.mem.Allocator,
        brotli_allocator: BrotliAllocator,
        encoder_instance: *brotli.BrotliEncoderState,

        pub fn init(allocator: std.mem.Allocator) !*BrotliDeflate {
            var deflate = try allocator.create(BrotliDeflate);
            errdefer allocator.destroy(deflate);

            deflate.brotli_allocator = .{
                .backing_allocator = allocator,
            };

            var encoderInstance = brotli.BrotliEncoderCreateInstance(BrotliAllocator.alloc, BrotliAllocator.free, &deflate.brotli_allocator);
            if (encoderInstance == null) {
                return error.BrotliEncoderInitializationFailed;
            }
            errdefer brotli.BrotliEncoderDestroyInstance(encoderInstance);

            deflate.encoder_instance = encoderInstance.?;
            deflate.compression_impl = .{ .deflate_buffer = &BrotliDeflate.deflateStream };
            deflate.allocator = allocator;

            var window_bits = brotli.BROTLI_DEFAULT_WINDOW;
            var mode = @intCast(c_uint, brotli.BROTLI_DEFAULT_MODE);
            var quality: usize = 2;

            _ = brotli.BrotliEncoderSetParameter(deflate.encoder_instance, brotli.BROTLI_PARAM_LGWIN, @intCast(u32, window_bits));
            _ = brotli.BrotliEncoderSetParameter(deflate.encoder_instance, brotli.BROTLI_PARAM_QUALITY, @intCast(u32, quality));
            _ = brotli.BrotliEncoderSetParameter(deflate.encoder_instance, brotli.BROTLI_PARAM_MODE, mode);

            return deflate;
        }

        pub fn deinit(deflate: *BrotliDeflate) void {
            brotli.BrotliEncoderDestroyInstance(deflate.encoder_instance);
            deflate.allocator.destroy(deflate);
        }

        pub fn deflateStream(impl: *compression.DeflateImpl, input: []u8, output: []u8) error{DeflateError}![]u8 {
            var deflate = @fieldParentPtr(BrotliDeflate, "compression_impl", impl);

            var available_in = input.len;
            var next_in = @ptrCast([*c]u8, input.ptr);
            var available_out = output.len;
            var next_out = @ptrCast([*c]u8, output.ptr);
            var total_out: usize = 0;
            _ = brotli.BrotliEncoderSetParameter(deflate.encoder_instance, brotli.BROTLI_PARAM_SIZE_HINT, @intCast(u32, input.len));

            var result = brotli.BrotliEncoderCompressStream(deflate.encoder_instance, brotli.BROTLI_OPERATION_FINISH, &available_in, &next_in, &available_out, &next_out, &total_out);

            if (result == 0) {
                return error.DeflateError;
            }

            return output[0..total_out];
        }
    };

    const BrotliInflate = struct {
        compression_impl: compression.InflateImpl,
        allocator: std.mem.Allocator,
        brotli_allocator: BrotliAllocator,
        decoder_instance: *brotli.BrotliDecoderState,

        pub fn init(allocator: std.mem.Allocator) !*BrotliInflate {
            var inflate = try allocator.create(BrotliInflate);
            errdefer allocator.destroy(inflate);

            inflate.brotli_allocator = .{
                .backing_allocator = allocator,
            };

            inflate.allocator = allocator;

            var decoder_instance = brotli.BrotliDecoderCreateInstance(BrotliAllocator.alloc, BrotliAllocator.free, &inflate.brotli_allocator);
            if (decoder_instance == null) {
                return error.BrotliEncoderInitializationFailed;
            }
            errdefer brotli.BrotliDecoderDestroyInstance(decoder_instance);

            inflate.decoder_instance = decoder_instance.?;
            inflate.compression_impl = .{ .inflate_buffer = inflateStream };

            return inflate;
        }

        pub fn deinit(inflate: *BrotliInflate) void {
            brotli.BrotliDecoderDestroyInstance(inflate.decoder_instance);
            inflate.allocator.destroy(inflate);
        }

        pub fn inflateStream(impl: *compression.InflateImpl, input: []u8, output: []u8) error{InflateError}!void {
            var inflate_impl = @fieldParentPtr(BrotliInflate, "compression_impl", impl);

            var total_out: usize = 0;
            var available_in = input.len;
            var next_in = @ptrCast([*c]u8, input.ptr);
            var available_out = output.len;
            var next_out = @ptrCast([*c]u8, output.ptr);

            var decompress_result = brotli.BrotliDecoderDecompressStream(inflate_impl.decoder_instance, &available_in, &next_in, &available_out, &next_out, &total_out);

            if (decompress_result == 0 or total_out > output.len) {
                return error.InflateError;
            }
        }
    };

    pub fn initDeflateImpl(allocator: std.mem.Allocator) !*compression.DeflateImpl {
        var deflate = try BrotliDeflate.init(allocator);
        return &deflate.compression_impl;
    }

    pub fn deinitDeflateImpl(impl: *compression.DeflateImpl) void {
        var deflate_impl = @fieldParentPtr(BrotliDeflate, "compression_impl", impl);
        deflate_impl.deinit();
    }

    pub fn initInflateImpl(allocator: std.mem.Allocator) !*compression.InflateImpl {
        var inflate = try BrotliInflate.init(allocator);
        return &inflate.compression_impl;
    }

    pub fn deinitInflateImpl(impl: *compression.InflateImpl) void {
        var inflate_impl = @fieldParentPtr(BrotliInflate, "compression_impl", impl);
        inflate_impl.deinit();
    }
};

test "Try Initialize Brotli" {
    var brotli_allocator: BrotliAllocator = .{
        .backing_allocator = std.testing.allocator,
    };

    var encoderInstance = brotli.BrotliEncoderCreateInstance(BrotliAllocator.alloc, BrotliAllocator.free, &brotli_allocator);
    defer brotli.BrotliEncoderDestroyInstance(encoderInstance);

    try std.testing.expect(encoderInstance != null);

    var allocation = @ptrCast(?*u8, BrotliAllocator.alloc(&brotli_allocator, 32));
    defer BrotliAllocator.free(&brotli_allocator, allocation);
}