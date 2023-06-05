const std = @import("std");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const SignatureFile = @import("signature_file.zig").SignatureFile;
const WeakHashType = @import("block.zig").WeakHashType;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const AnchoredBlock = @import("anchored_blocks_map.zig").AnchoredBlock;
const BlockHash = @import("block.zig").BlockHash;

pub const MaxDataOperationLength = 1024 * 1024 * 4;

pub const BlockRangeOperation = struct {
    file_index: usize,
    block_index: usize,
    block_span: usize,
};

pub const PatchOperation = union(enum) { Invalid: void, BlockRange: BlockRangeOperation, Data: []u8 };

pub fn generateOperationsForBuffer(buffer: []u8, block_map: AnchoredBlocksMap, max_operation_len: usize, allocator: std.mem.Allocator) !std.ArrayList(PatchOperation) {
    const max_operations = @floatToInt(usize, @ceil(@intToFloat(f64, buffer.len) / @intToFloat(f64, BlockSize)));
    var patch_operations = try std.ArrayList(PatchOperation).initCapacity(allocator, max_operations);

    var tail: usize = 0;
    var head: usize = 0;
    var owed_data_tail: usize = 0;

    var rolling_hash: RollingHash = .{};

    var jump_to_next_block = true;

    while (tail <= buffer.len) {
        if (jump_to_next_block) {
            head = std.math.min(head + BlockSize, buffer.len);

            if (tail == head) {
                break;
            }
            rolling_hash.recompute(buffer[tail..head]);
            jump_to_next_block = false;
        } else {
            rolling_hash.next(buffer, tail - 1, head - 1);
        }

        std.debug.assert(head - tail <= BlockSize);

        var hash = rolling_hash.hash;

        var known_block: ?AnchoredBlock = null;

        if (block_map.hasAnchoredBlocksForWeakHash(hash)) {
            @setRuntimeSafety(false);
            // Hash found. Calculate MD5 and see if we match with a known block.

            var block_hash: BlockHash = .{ .weak_hash = hash, .strong_hash = undefined };

            std.crypto.hash.Md5.hash(buffer[tail..head], &block_hash.strong_hash, .{});

            var block_size = head - tail;
            var short_size = BlockSize - block_size;

            //TODO: Add the preferred file idx here (lukas)
            known_block = block_map.getAnchoredBlock(block_hash, 0, short_size);
        }

        if (known_block) |block| {
            if (tail != owed_data_tail) {
                try patch_operations.append(.{ .Data = buffer[owed_data_tail..tail] });
                // std.log.err("Appending OwedTail {}:{}", .{ owed_data_tail, tail });
            }

            //TODO: Check if last operation is the same. If so merge span. (lukas)
            try patch_operations.append(.{ .BlockRange = .{ .file_index = block.file_index, .block_index = block.block_index, .block_span = 1 } });

            owed_data_tail = head;
            tail = head;
            jump_to_next_block = true;
        } else {
            tail += 1;
            head = std.math.min(head + 1, buffer.len);
            const reached_end_of_buffer = tail == head;
            const can_omit_data_op = owed_data_tail != tail;
            const needs_to_omit_data_op = reached_end_of_buffer or (tail - owed_data_tail >= max_operation_len);

            if (can_omit_data_op and needs_to_omit_data_op) {
                var slice = buffer[owed_data_tail..tail];

                try patch_operations.append(.{ .Data = slice });

                // std.log.err("Appending Block {}:{}", .{ owed_data_tail, tail });
                owed_data_tail = tail;
            }
        }
    }

    return patch_operations;
}

const IncrementalState = struct {
    is_valid: bool,
    tail: usize,
    head: usize,
    owed_data_tail: usize,
    rolling_hash: RollingHash,
    jump_to_next_block: bool,

    // backing_buffer: [BlockSize]u8,
    // buffer: []u8,
};

const BlockBuffer = struct {
    const Self = @This();

    file_start_offset: usize,
    file_len: usize,
    buffers: []u8,

    pub fn getBlock(self: Self, backing_buffer: []u8, tail: usize, head: usize) ![]u8 {
        // var read_pos: usize = 0;

        var total_buffers_len: usize = 0;
        for (self.buffers) |buffer| {
            total_buffers_len += buffer.len;
        }

        if (tail < self.file_start_offset) {
            return error.OutOfRange;
        }

        if (tail > head) {
            return error.OutOfRange;
        }

        if (head > self.file_start_offset + total_buffers_len) {
            return error.OutOfRange;
        }

        var total_buffer_range = head - tail;

        if (backing_buffer.len < total_buffer_range) {
            return error.OutOfRange;
        }

        var offset_in_buffers: usize = 0;
        var start_buffer_idx: ?usize = null;
        for (self.buffers, 0..) |buffer, buffer_idx| {
            if (tail > offset_in_buffers + self.file_start_offset) {
                offset_in_buffers += buffer.len;
                continue;
            }

            start_buffer_idx = buffer_idx;
            break;
        }

        std.debug.assert(start_buffer_idx != null);

        var copied_bytes: usize = 0;
        for (self.buffers[start_buffer_idx..]) |buffer| {
            var start: usize = 0;
            if (copied_bytes == 0) {
                start = tail - (offset_in_buffers + self.file_start_offset);
            }

            var num_bytes_to_copy: usize = std.math.min(buffer.len - start, total_buffer_range - copied_bytes);

            std.mem.copy(backing_buffer[copied_bytes..], buffer[start .. start + num_bytes_to_copy]);
            copied_bytes += num_bytes_to_copy;
        }

        std.debug.assert(copied_bytes == total_buffer_range);
        return backing_buffer[0..total_buffer_range];
    }
};

pub fn generateOperationsForBufferIncremental(state: *IncrementalState, buffers: []u8, first_buffer_offset_in_file: usize, file_len: usize, block_map: AnchoredBlocksMap, max_operation_len: usize, allocator: std.mem.Allocator) !std.ArrayList(PatchOperation) {
    // const max_operations = @floatToInt(usize, @ceil(@intToFloat(f64, buffer.len) / @intToFloat(f64, BlockSize)));
    var patch_operations = try std.ArrayList(PatchOperation).initCapacity(allocator, 1);

    var tail: *usize = &state.tail;
    var head: *usize = &state.head;
    var owed_data_tail: *usize = &state.owed_data_tail;

    var rolling_hash: *RollingHash = &state.rolling_hash;

    var jump_to_next_block: *bool = &state.jump_to_next_block;

    // var last_buffer_len: usize = 0;

    if (!state.is_valid) {
        state.* = .{ .is_valid = true, .tail = 0, .head = 0, .owed_data_tail = 0, .jump_to_next_block = true, .rolling_hash = .{} };
    }

    if (tail.* < first_buffer_offset_in_file) {
        return error.InvalidIncrementalState;
    }

    var buffers_len: usize = buffers.len;

    // var current_block_backing_buffer: *[BlockSize]u8 = &state.backing_buffer;
    // var current_block: *[]u8 = &state.buffer;

    var process_up_to_this = first_buffer_offset_in_file + buffers_len;

    // var block: [BlockSize]u8 = undefined;
    // var block_len: usize = 0;

    while (tail.* <= process_up_to_this) {
        if (jump_to_next_block.*) {
            var next_block_head = std.math.min(head.* + BlockSize, file_len);

            if (next_block_head > process_up_to_this) {
                return error.NeedsMoreData;
            }

            head.* = std.math.min(head.* + BlockSize, file_len);

            if (tail == head) {
                break;
            }

            // var desired_buffer_size = head - tail;

            // block_len = 0;

            // if (tail < first_buffer_offset_in_file) {
            //     var num_byte_from_previous_buffer = tail - first_buffer_offset_in_file;
            //     block_len = num_byte_from_previous_buffer;
            //     std.mem.copy(block[block_len..], state.buffer[BlockSize - num_byte_from_previous_buffer ..]);
            // }

            // std.mem.copy(block[block_len..], state.buffer[desired_buffer_size - block_len]);

            // std.debug.assert(desired_buffer_size == block_len);

            // rolling_hash.recompute(block[0..block_len]);
            jump_to_next_block.* = false;
        } else {
            // rolling_hash.next(buffer, tail - 1, head - 1);
        }

        std.debug.assert(head.* - tail.* <= BlockSize);

        var hash = rolling_hash.hash;

        var known_block: ?AnchoredBlock = null;

        if (block_map.hasAnchoredBlocksForWeakHash(hash)) {
            @setRuntimeSafety(false);
            // Hash found. Calculate MD5 and see if we match with a known block.

            var block_hash: BlockHash = .{ .weak_hash = hash, .strong_hash = undefined };

            // std.crypto.hash.Md5.hash(buffer[tail..head], &block_hash.strong_hash, .{});

            var block_size = head.* - tail.*;
            var short_size = BlockSize - block_size;

            //TODO: Add the preferred file idx here (lukas)
            known_block = block_map.getAnchoredBlock(block_hash, 0, short_size);
        }

        if (known_block) |block| {
            if (tail.* != owed_data_tail.*) {
                // try patch_operations.append(.{ .Data = buffer[owed_data_tail..tail] });
                // std.log.err("Appending OwedTail {}:{}", .{ owed_data_tail, tail });
            }

            //TODO: Check if last operation is the same. If so merge span. (lukas)
            try patch_operations.append(.{ .BlockRange = .{ .file_index = block.file_index, .block_index = block.block_index, .block_span = 1 } });

            owed_data_tail.* = head.*;
            tail.* = head.*;
            jump_to_next_block.* = true;
        } else {
            tail.* += 1;
            // head = std.math.min(head + 1, buffer.len);
            const reached_end_of_buffer = tail.* == head.*;
            const can_omit_data_op = owed_data_tail.* != tail.*;
            const needs_to_omit_data_op = reached_end_of_buffer or (tail.* - owed_data_tail.* >= max_operation_len);

            if (can_omit_data_op and needs_to_omit_data_op) {
                // var slice = buffer[owed_data_tail..tail];

                // try patch_operations.append(.{ .Data = slice });

                // std.log.err("Appending Block {}:{}", .{ owed_data_tail, tail });
                owed_data_tail = tail;
            }
        }
    }

    return patch_operations;
}

test "Test Block buffer" {}

// test "Generating operations incrementally should rebuild orignal buffer" {
//     const max_operation_len: usize = 512;

//     const buffer_size = @trunc(@intToFloat(f64, max_operation_len) * 4);
//     var original_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
//     defer std.testing.allocator.free(original_buffer);

//     var rebuilt_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
//     defer std.testing.allocator.free(rebuilt_buffer);

//     var rand = std.rand.DefaultPrng.init(365654);

//     for (original_buffer, 0..) |*item, idx| {
//         item.* = rand.random().int(u8);
//         rebuilt_buffer[idx] = 0;
//     }

//     const empty_signature_file = try SignatureFile.init(std.testing.allocator);
//     defer empty_signature_file.deinit();

//     const anchored_block_map = try AnchoredBlocksMap.init(empty_signature_file.*, std.testing.allocator);
//     defer anchored_block_map.deinit();

//     var incremental_state: IncrementalState = undefined;
//     incremental_state.is_valid = false;

//     var operations = try generateOperationsForBufferIncremental(&incremental_state, &.{original_buffer}, 0, 0, anchored_block_map.*, max_operation_len, std.testing.allocator);
//     defer operations.deinit();

//     var offset: usize = 0;

//     try std.testing.expect(operations.items.len > 0);
//     for (operations.items) |operation| {
//         try std.testing.expect(operation == .Data);
//         std.mem.copy(u8, rebuilt_buffer[offset..], operation.Data);
//         offset += operation.Data.len;
//     }

//     try std.testing.expectEqualSlices(u8, original_buffer, rebuilt_buffer);
// }
test "Operations for buffer without Reference should rebuild the original buffer" {
    const max_operation_len: usize = 512;

    const buffer_size = @trunc(@intToFloat(f64, max_operation_len) * 1);
    var original_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(original_buffer);

    var rebuilt_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(rebuilt_buffer);

    var rand = std.rand.DefaultPrng.init(365654);

    for (original_buffer, 0..) |*item, idx| {
        item.* = rand.random().int(u8);
        rebuilt_buffer[idx] = 0;
    }

    const empty_signature_file = try SignatureFile.init(std.testing.allocator);
    defer empty_signature_file.deinit();

    try empty_signature_file.initializeToEmptyInMemoryFile();

    const anchored_block_map = try AnchoredBlocksMap.init(empty_signature_file, std.testing.allocator);
    defer anchored_block_map.deinit();

    var operations = try generateOperationsForBuffer(original_buffer, anchored_block_map.*, max_operation_len, std.testing.allocator);
    defer operations.deinit();

    var offset: usize = 0;

    try std.testing.expect(operations.items.len > 0);
    for (operations.items) |operation| {
    try std.testing.expect(operation == .Data);
    std.mem.copy(u8, rebuilt_buffer[offset..], operation.Data);
    offset += operation.Data.len;
    }

    try std.testing.expectEqualSlices(u8, original_buffer, rebuilt_buffer);
}

test "Operations for buffer without Reference should rebuild the original buffer - with fractional buffer size of max operation length" {
    const max_operation_len: usize = 512;

    const buffer_size = @trunc(@intToFloat(f64, max_operation_len) * 3.564);
    var original_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(original_buffer);

    var rebuilt_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(rebuilt_buffer);

    var rand = std.rand.DefaultPrng.init(1238721);

    for (original_buffer, 0..) |*item, idx| {
        item.* = rand.random().int(u8);
        rebuilt_buffer[idx] = 0;
    }

    const empty_signature_file = try SignatureFile.init(std.testing.allocator);
    defer empty_signature_file.deinit();

    try empty_signature_file.initializeToEmptyInMemoryFile();

    const anchored_block_map = try AnchoredBlocksMap.init(empty_signature_file, std.testing.allocator);
    defer anchored_block_map.deinit();

    var operations = try generateOperationsForBuffer(original_buffer, anchored_block_map.*, max_operation_len, std.testing.allocator);
    defer operations.deinit();

    var offset: usize = 0;

    try std.testing.expect(operations.items.len > 0);
    for (operations.items) |operation| {
        try std.testing.expect(operation == .Data);
        std.mem.copy(u8, rebuilt_buffer[offset..], operation.Data);
        offset += operation.Data.len;
    }

    try std.testing.expectEqualSlices(u8, original_buffer, rebuilt_buffer);
}

const Endian = std.builtin.Endian.Big;

// This is the minimum size an operation can take up in serialized memory.
pub fn minPerOperationSize() usize {
    return @sizeOf(usize) * 3;
}

pub fn saveOperations(operations: std.ArrayList(PatchOperation), writer: anytype) !void {
    try writer.writeInt(usize, operations.items.len, Endian);

    for (operations.items) |operation| {
        switch (operation) {
            .Data => |data| {
                try writer.writeInt(usize, 1, Endian);
                try writer.writeInt(usize, data.len, Endian);
                try writer.writeAll(data);
            },
            .BlockRange => |range| {
                try writer.writeInt(usize, 2, Endian);
                try writer.writeInt(usize, range.file_index, Endian);
                try writer.writeInt(usize, range.block_index, Endian);
                try writer.writeInt(usize, range.block_span, Endian);
            },
            else => return error.UnknownOperationTypeFound,
        }
    }
}

pub fn loadOperations(allocator: std.mem.Allocator, reader: anytype) !std.ArrayList(PatchOperation) {
    var num_operations = try reader.readInt(usize, Endian);

    if (num_operations > 100000) {
        std.log.err("Invalid num operations", .{});
    }

    var operations = try std.ArrayList(PatchOperation).initCapacity(allocator, num_operations);
    errdefer operations.deinit();

    var operation_idx: usize = 0;
    while (operation_idx < num_operations) : (operation_idx += 1) {
        var operation_type_raw = try reader.readInt(usize, Endian);
        var operation: PatchOperation = undefined;

        if (operation_type_raw == 1) {
            var data_len = try reader.readInt(usize, Endian);
            var data = try allocator.alloc(u8, data_len);

            try reader.readNoEof(data[0..data_len]);

            operation = PatchOperation{
                .Data = data,
            };
        } else if (operation_type_raw == 2) {
            var file_idx = try reader.readInt(usize, Endian);
            var block_idx = try reader.readInt(usize, Endian);
            var block_span = try reader.readInt(usize, Endian);

            operation = PatchOperation{
                .BlockRange = .{ .file_index = file_idx, .block_index = block_idx, .block_span = block_span },
            };
        }

        try operations.append(operation);
    }

    return operations;
}

test "operations should be same after deserialization" {
    var operations = std.ArrayList(PatchOperation).init(std.testing.allocator);
    defer operations.deinit();

    try operations.append(.{
        .BlockRange = .{ .file_index = 1, .block_index = 2, .block_span = 4 },
    });

    var operation_data: [256]u8 = undefined;
    var operation_data_2: [512]u8 = undefined;

    try operations.append(.{ .Data = &operation_data });

    try operations.append(.{
        .BlockRange = .{ .file_index = 1, .block_index = 2, .block_span = 4 },
    });

    try operations.append(.{ .Data = &operation_data_2 });

    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    var writer = stream.writer();

    try saveOperations(operations, writer);

    var written_end_pos = try stream.getPos();
    try stream.seekTo(0);

    var reader = stream.reader();

    var loaded_operations = try loadOperations(std.testing.allocator, reader);
    defer loaded_operations.deinit();

    defer {
        for (loaded_operations.items) |operation| {
            if (operation == .Data) {
                std.testing.allocator.free(operation.Data);
            }
        }
    }

    try std.testing.expectEqual(written_end_pos, try stream.getPos());
    try std.testing.expectEqual(operations.items.len, loaded_operations.items.len);

    for (operations.items, 0..) |operation, idx| {
        var loaded_operation = loaded_operations.items[idx];

        if (operation == .BlockRange) {
            try std.testing.expectEqual(operation.BlockRange.file_index, loaded_operation.BlockRange.file_index);
            try std.testing.expectEqual(operation.BlockRange.block_index, loaded_operation.BlockRange.block_index);
            try std.testing.expectEqual(operation.BlockRange.block_span, loaded_operation.BlockRange.block_span);
        } else if (operation == .Data) {
            try std.testing.expectEqualSlices(u8, operation.Data, loaded_operation.Data);
        } else {
            try std.testing.expect(false);
        }
    }
}
