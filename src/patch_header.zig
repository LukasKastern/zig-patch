const SignatureFile = @import("signature_file.zig").SignatureFile;
const SignatureBlock = @import("signature_file.zig").SignatureBlock;
const Operation = @import("block_patching.zig").PatchOperation;
const std = @import("std");
const BlockHash = @import("block.zig").BlockHash;

pub const FileSection = struct {
    file_idx: usize,
    operations_start_pos_in_file: usize,
};

pub const PatchHeader = struct {
    old: *SignatureFile,
    new: *SignatureFile,
    sections: std.ArrayList(FileSection),
    allocator: std.mem.Allocator,

    const SerializationVersion = 1;
    const TypeTag = "Patch";
    const Endian = std.builtin.Endian.Big;

    const Self = @This();

    pub fn init(new_signature: *SignatureFile, previous_signature: *SignatureFile, allocator: std.mem.Allocator) !*Self {
        var patch_header = try allocator.create(Self);
        errdefer patch_header.deinit();

        patch_header.allocator = allocator;
        patch_header.sections = std.ArrayList(FileSection).init(allocator);

        patch_header.new = new_signature;
        patch_header.old = previous_signature;

        return patch_header;
    }

    pub fn deinit(self: *Self) void {
        self.sections.deinit();
        self.allocator.destroy(self);
    }

    pub fn savePatchHeader(self: *PatchHeader, writer: anytype) !void {
        try writer.writeInt(usize, TypeTag.len, Endian);
        try writer.writeAll(TypeTag);
        try writer.writeInt(usize, SerializationVersion, Endian);

        try self.old.saveSignature(writer);
        try self.new.saveSignature(writer);

        try writer.writeInt(usize, self.sections.items.len, Endian);

        for (self.sections.items) |section| {
            try writer.writeInt(usize, section.file_idx, Endian);
            try writer.writeInt(usize, section.operations_start_pos_in_file, Endian);
        }
    }

    pub fn loadPatchHeader(allocator: std.mem.Allocator, reader: anytype) !*Self {
        var read_buffer: [1028]u8 = undefined;

        var type_tag_len = try reader.readInt(usize, Endian);

        try reader.readNoEof(read_buffer[0..type_tag_len]);

        if (!std.mem.eql(u8, TypeTag, read_buffer[0..type_tag_len])) {
            return error.FileTypeTagMismatch;
        }

        var version = try reader.readInt(usize, Endian);

        if (version != SerializationVersion) {
            return error.SerializationVersionMismatch;
        }

        var old_signature = try SignatureFile.loadSignature(reader, allocator);
        errdefer old_signature.deinit();

        var new_signature = try SignatureFile.loadSignature(reader, allocator);
        errdefer new_signature.deinit();

        var patch_header = try PatchHeader.init(new_signature, old_signature, allocator);
        errdefer patch_header.deinit();

        var num_section = try reader.readInt(usize, Endian);

        try patch_header.sections.resize(num_section);

        for (patch_header.sections.items) |*section| {
            section.file_idx = try reader.readInt(usize, Endian);
            section.operations_start_pos_in_file = try reader.readInt(usize, Endian);
        }

        return patch_header;
    }
};

test "deserialized patch header should match original header" {
    var old_signature = try SignatureFile.init(std.testing.allocator);
    defer old_signature.deinit();

    var new_signature = try SignatureFile.init(std.testing.allocator);
    defer new_signature.deinit();

    var patch_header = try PatchHeader.init(new_signature, old_signature, std.testing.allocator);
    defer patch_header.deinit();

    try patch_header.sections.append(.{ .file_idx = 1, .operations_start_pos_in_file = 25 });
    try patch_header.sections.append(.{ .file_idx = 2, .operations_start_pos_in_file = 26 });
    try patch_header.sections.append(.{ .file_idx = 3, .operations_start_pos_in_file = 27 });
    try patch_header.sections.append(.{ .file_idx = 4, .operations_start_pos_in_file = 28 });
    try patch_header.sections.append(.{ .file_idx = 5, .operations_start_pos_in_file = 29 });

    var hashes: [6]BlockHash = undefined;
    hashes[0] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 35, 1, 46, 21, 84, 231, 1, 45, 0, 1, 154, 21, 84, 154, 1, 85 },
    };

    hashes[1] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 78, 1, 99, 21, 84, 1, 33, 45, 120, 1, 54, 21, 84, 154, 1, 5 },
    };

    hashes[2] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 32, 1, 54, 21, 84, 57, 1, 67, 84, 1, 64, 21, 84, 54, 1, 45 },
    };

    hashes[3] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 5, 1, 245, 21, 84, 231, 154, 45, 120, 1, 154, 21, 84, 154, 1, 235 },
    };

    hashes[4] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 46, 76, 56, 21, 84, 57, 54, 45, 21, 1, 64, 21, 84, 57, 1, 47 },
    };

    hashes[5] = .{
        .weak_hash = 8,
        .strong_hash = [16]u8{ 123, 1, 123, 21, 78, 50, 54, 45, 81, 1, 54, 21, 84, 47, 1, 47 },
    };

    var signature_blocks: [6]SignatureBlock = undefined;
    signature_blocks[0] = .{ .file_idx = 5, .block_idx = 6, .hash = hashes[0] };
    signature_blocks[1] = .{ .file_idx = 6, .block_idx = 5, .hash = hashes[1] };
    signature_blocks[2] = .{ .file_idx = 7, .block_idx = 4, .hash = hashes[2] };
    signature_blocks[3] = .{ .file_idx = 8, .block_idx = 3, .hash = hashes[3] };
    signature_blocks[4] = .{ .file_idx = 9, .block_idx = 2, .hash = hashes[4] };
    signature_blocks[5] = .{ .file_idx = 10, .block_idx = 1, .hash = hashes[5] };

    try patch_header.old.blocks.appendSlice(&signature_blocks);

    var buffer: [1200]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    var writer = stream.writer();
    try patch_header.savePatchHeader(writer);

    try stream.seekTo(0);
    var reader = stream.reader();

    var deserialized_patch_header = try PatchHeader.loadPatchHeader(std.testing.allocator, reader);
    defer deserialized_patch_header.deinit();
    defer deserialized_patch_header.new.deinit();
    defer deserialized_patch_header.old.deinit();

    try std.testing.expectEqual(patch_header.old.numDirectories(), deserialized_patch_header.old.numDirectories());
    try std.testing.expectEqual(patch_header.old.numFiles(), deserialized_patch_header.old.numFiles());
    try std.testing.expectEqual(patch_header.old.blocks.items.len, deserialized_patch_header.old.blocks.items.len);

    try std.testing.expectEqual(patch_header.new.numDirectories(), deserialized_patch_header.new.numDirectories());
    try std.testing.expectEqual(patch_header.new.numFiles(), deserialized_patch_header.new.numFiles());
    try std.testing.expectEqual(patch_header.new.blocks.items.len, deserialized_patch_header.new.blocks.items.len);

    try std.testing.expectEqual(patch_header.sections.items.len, deserialized_patch_header.sections.items.len);

    for (patch_header.sections.items, 0..) |section, idx| {
        var deserialized_section = deserialized_patch_header.sections.items[idx];
        try std.testing.expectEqual(section.file_idx, deserialized_section.file_idx);
        try std.testing.expectEqual(section.operations_start_pos_in_file, deserialized_section.operations_start_pos_in_file);
    }
}
