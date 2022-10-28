const std = @import("std");
const BlockHash = @import("block.zig").BlockHash;

pub const SignatureFile = struct {
    const Directory = struct {
        path: []u8,
        permissions: u8,
    };

    const SymLinks = struct {
        source: []u8,
        target: []u8,
        permissions: u8,
    };

    const File = struct {
        name: []const u8,
        size: isize,
        permissions: u8,
    };

    allocator: std.mem.Allocator,
    directories: std.ArrayList(Directory),
    sym_links: std.ArrayList(SymLinks),
    files: std.ArrayList(File),
    blocks: std.ArrayList(BlockHash),

    pub fn init(allocator: std.mem.Allocator) !*SignatureFile {
        var signature_file = try allocator.create(SignatureFile);
        signature_file.allocator = allocator;
        signature_file.files = std.ArrayList(File).init(allocator);
        signature_file.directories = std.ArrayList(Directory).init(allocator);
        signature_file.sym_links = std.ArrayList(SymLinks).init(allocator);
        signature_file.blocks = std.ArrayList(BlockHash).init(allocator);
        return signature_file;
    }

    pub fn deinit(self: *SignatureFile) void {
        self.files.deinit();
        self.sym_links.deinit();
        self.blocks.deinit();
        self.allocator.destroy(self);
    }
};
