const std = @import("std");
const BrotliCompression = @import("brotli_compression.zig").BrotliCompression;
const ZlibCompression = @import("zlib_compression.zig").ZlibCompression;

pub const DeflateImpl = struct {
    const DeflateBuffer = *const fn (impl: *DeflateImpl, input: []u8, output: []u8) error{DeflateError}![]u8;
    // const InfalteStream = *const fn () error{InflateError}!usize;
    deflate_buffer: DeflateBuffer,
};

pub const InflateImpl = struct {
    const InflateBuffer = *const fn (impl: *InflateImpl, input: []u8, output: []u8) error{InflateError}!void;
    // const InfalteStream = *const fn () error{InflateError}!usize;
    inflate_buffer: InflateBuffer,
};

const CompressionImplementation = enum {
    None,
    Brotli,
    Zlib,
    Invalid,
};

pub const NoOpCompression = struct {
    const NoOpDeflate = struct {
        compression_impl: DeflateImpl,
        allocator: std.mem.Allocator,

        pub fn deflateStream(impl: *DeflateImpl, input: []u8, output: []u8) error{DeflateError}![]u8 {
            _ = impl;

            std.mem.copy(u8, output, input);
            return output;
        }
    };

    const NoOpInflate = struct {
        compression_impl: InflateImpl,
        allocator: std.mem.Allocator,

        pub fn inflateStream(impl: *InflateImpl, input: []u8, output: []u8) error{InflateError}!void {
            _ = impl;
            std.mem.copy(u8, output, input[0..output.len]);
        }
    };

    pub fn initDeflateImpl(allocator: std.mem.Allocator) !*DeflateImpl {
        var no_op_deflate = try allocator.create(NoOpDeflate);
        no_op_deflate.allocator = allocator;
        no_op_deflate.compression_impl = .{ .deflate_buffer = &NoOpDeflate.deflateStream };
        return &no_op_deflate.compression_impl;
    }

    pub fn deinitDeflateImpl(impl: *DeflateImpl) void {
        var deflate_impl = @fieldParentPtr(NoOpDeflate, "compression_impl", impl);
        deflate_impl.allocator.destroy(deflate_impl);
    }

    pub fn initInflateImpl(allocator: std.mem.Allocator) !*InflateImpl {
        var no_op_inflate = try allocator.create(NoOpInflate);
        no_op_inflate.allocator = allocator;
        no_op_inflate.compression_impl = .{ .inflate_buffer = &NoOpInflate.inflateStream };
        return &no_op_inflate.compression_impl;
    }

    pub fn deinitInflateImpl(impl: *InflateImpl) void {
        var inflate_impl = @fieldParentPtr(NoOpInflate, "compression_impl", impl);
        inflate_impl.allocator.destroy(inflate_impl);
    }
};

pub const Compression = struct {
    pub const Default = .Zlib;
    pub const Deflating = struct {
        impl: *DeflateImpl,
        implementation_method: CompressionImplementation,

        pub fn init(implementation: CompressionImplementation, allocator: std.mem.Allocator) !Deflating {
            switch (implementation) {
                .None => {
                    return .{
                        .impl = try NoOpCompression.initDeflateImpl(allocator),
                        .implementation_method = implementation,
                    };
                },
                .Brotli => {
                    return .{
                        .impl = try BrotliCompression.initDeflateImpl(allocator),
                        .implementation_method = implementation,
                    };
                },
                .Zlib => {
                    return .{
                        .impl = try ZlibCompression.initDeflateImpl(allocator),
                        .implementation_method = implementation,
                    };
                },
                else => {
                    return error.CompressionMethodNotImplemented;
                },
            }
        }

        pub fn deinit(deflating: Deflating) void {
            switch (deflating.implementation_method) {
                .None => {
                    NoOpCompression.deinitDeflateImpl(deflating.impl);
                },
                .Brotli => {
                    BrotliCompression.deinitDeflateImpl(deflating.impl);
                },
                .Zlib => {
                    ZlibCompression.deinitDeflateImpl(deflating.impl);
                },
                else => {},
            }
        }

        pub fn deflateBuffer(deflating: Deflating, input: []u8, output: []u8) ![]u8 {

            // The output buffer should at least be able to hold all the input elements.
            if (output.len < input.len) {
                return error.OutputBufferTooSmall;
            }

            return try deflating.impl.deflate_buffer(deflating.impl, input, output);
        }
    };

    pub const Infalting = struct {
        impl: *InflateImpl,
        implementation_method: CompressionImplementation,

        pub fn init(implementation: CompressionImplementation, allocator: std.mem.Allocator) !Infalting {
            switch (implementation) {
                .None => {
                    return .{
                        .impl = try NoOpCompression.initInflateImpl(allocator),
                        .implementation_method = implementation,
                    };
                },
                .Brotli => {
                    return .{
                        .impl = try BrotliCompression.initInflateImpl(allocator),
                        .implementation_method = implementation,
                    };
                },
                .Zlib => {
                    return .{ .impl = try ZlibCompression.initInflateImpl(allocator), .implementation_method = implementation };
                },
                else => {
                    return error.CompressionMethodNotImplemented;
                },
            }
        }

        pub fn deinit(infalting: Infalting) void {
            switch (infalting.implementation_method) {
                .None => {
                    NoOpCompression.deinitInflateImpl(infalting.impl);
                },
                .Brotli => {
                    BrotliCompression.deinitInflateImpl(infalting.impl);
                },
                .Zlib => {
                    ZlibCompression.deinitInflateImpl(infalting.impl);
                },
                else => {},
            }
        }

        pub fn inflateBuffer(inflate: Infalting, input: []u8, output: []u8) !void {
            return try inflate.impl.inflate_buffer(inflate.impl, input, output);
        }
    };
};

test {
    std.testing.refAllDecls(@import("./brotli_compression.zig"));
}

test "Deflated then Infalted buffer should be the same" {
    var prng = std.rand.DefaultPrng.init(897123);
    var rand = prng.random();
    const implementations = [_]CompressionImplementation{ .None, .Brotli, .Zlib };

    for (implementations) |implementation| {
        var input: [2048]u8 = undefined;
        var out_buffer: [2048 + 64]u8 = undefined;
        var deflated_elments: []u8 = undefined;

        for (input) |*item| {
            item.* = rand.int(u8);
        }

        var input_copy: [2048]u8 = undefined;
        std.mem.copy(u8, &input_copy, &input);

        // First we compress our elements
        {
            var deflating = try Compression.Deflating.init(implementation, std.testing.allocator);
            defer deflating.deinit();

            deflated_elments = try deflating.deflateBuffer(&input, &out_buffer);
        }

        // Then we decompress them again
        {
            var inflate = try Compression.Infalting.init(implementation, std.testing.allocator);
            defer inflate.deinit();

            try inflate.inflateBuffer(deflated_elments, out_buffer[0..input.len]);
        }

        try std.testing.expectEqualSlices(u8, &input_copy, out_buffer[0..input.len]);
    }
}
