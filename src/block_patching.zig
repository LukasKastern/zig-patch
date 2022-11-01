const std = @import("std");
const AnchoredBlocksMap = @import("anchored_blocks_map.zig").AnchoredBlocksMap;
const SignatureFile = @import("signature_file.zig").SignatureFile;
const WeakHashType = @import("block.zig").WeakHashType;
const BlockSize = @import("block.zig").BlockSize;
const RollingHash = @import("rolling_hash.zig").RollingHash;
const AnchoredBlock = @import("anchored_blocks_map.zig").AnchoredBlock;

pub const MaxDataOperationLength = 1024 * 1024 * 4;

pub const BlockRangeOperation = struct {
    file_index: usize,
    block_index: usize,
    block_span: usize,
};

pub const PatchOperation = union(enum) { Invalid: void, BlockRange: BlockRangeOperation, Data: []u8 };

pub fn generateOperationsForBuffer(buffer: []u8, block_map: AnchoredBlocksMap, max_operation_len: usize, allocator: std.mem.Allocator) !std.ArrayList(PatchOperation) {
    const max_operations = @floatToInt(usize, @ceil(@intToFloat(f64, buffer.len) / @intToFloat(f64, max_operation_len)));
    var patch_operations = try std.ArrayList(PatchOperation).initCapacity(allocator, max_operations);

    var tail: usize = 0;
    var head: usize = 0;
    var owed_data_tail: usize = 0;

    var rolling_hash: RollingHash = .{};

    var jump_to_next_block = true;

    while (tail <= buffer.len) {
        if (jump_to_next_block) {
            head = std.math.min(head + BlockSize, buffer.len);
            rolling_hash.recompute(buffer[tail..head]);
            jump_to_next_block = false;
        } else {
            rolling_hash.next(buffer, tail - 1, head - 1);
        }

        var hash = rolling_hash.hash;

        var known_block: ?AnchoredBlock = null;

        if (block_map.hasAnchoredBlocksForWeakHash(hash)) {
            // Hash found. Calculate MD5 and see if we match with a known block.
        }

        if (known_block) |block| {
            if (tail != owed_data_tail) {
                patch_operations.appendAssumeCapacity(.{ .Data = buffer[owed_data_tail..tail] });
            }

            //TODO: Check if last operation is the same. If so merge span. (lukas)
            patch_operations.appendAssumeCapacity(.{ .BlockRange = .{ .file_index = block.file_index, .block_index = block.block_index, .block_span = 1 } });

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
                patch_operations.appendAssumeCapacity(.{ .Data = buffer[owed_data_tail..tail] });
                owed_data_tail = tail;
            }
        }
    }

    return patch_operations;
}

test "Operations for buffer without Reference should rebuild the original buffer" {
    const max_operation_len: usize = 512;

    const buffer_size = @trunc(@intToFloat(f64, max_operation_len) * 4);
    var original_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(original_buffer);

    var rebuilt_buffer: []u8 = try std.testing.allocator.alloc(u8, buffer_size);
    defer std.testing.allocator.free(rebuilt_buffer);

    var rand = std.rand.DefaultPrng.init(365654);

    for (original_buffer) |*item, idx| {
        item.* = rand.random().int(u8);
        rebuilt_buffer[idx] = 0;
    }

    const empty_signature_file = try SignatureFile.init(std.testing.allocator);
    defer empty_signature_file.deinit();

    const anchored_block_map = try AnchoredBlocksMap.init(empty_signature_file.*, std.testing.allocator);
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

    for (original_buffer) |*item, idx| {
        item.* = rand.random().int(u8);
        rebuilt_buffer[idx] = 0;
    }

    const empty_signature_file = try SignatureFile.init(std.testing.allocator);
    defer empty_signature_file.deinit();

    const anchored_block_map = try AnchoredBlocksMap.init(empty_signature_file.*, std.testing.allocator);
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

pub fn saveOperations(operations: std.ArrayList(PatchOperation), writer: anytype) !void {
    try writer.writeInt(usize, operations.items.len, Endian);

    for (operations.items) |operation| {
        switch (operation) {
            .Data => |data| {
                try writer.writeAll(data);
            },
            .BlockRange => |range| {
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

    var operations = try std.ArrayList(PatchOperation).initCapacity(num_operations, allocator);
    errdefer operations.deinit();

    var operation_idx: usize = 0;
    while (operation_idx < num_operations) : (operation_idx += 1) {
        var operation_type_raw = try reader.readInt(usize, Endian);

        var operation_type = @intToEnum(PatchOperation, operation_type_raw);
        var operation: PatchOperation = undefined;

        switch (operation_type) {
            .Data => {
                var data_len = try reader.readInt(usize, Endian);
                var data = try allocator.alloc(u8, data_len);

                try reader.readNoEof(data[0..data_len]);

                operation = PatchOperation{
                    .Data = data,
                };
            },
            .BlockRange => {
                var file_idx = try reader.readInt(usize, Endian);
                var block_idx = try reader.readInt(usize, Endian);
                var block_span = try reader.readInt(usize, Endian);

                operation = PatchOperation{
                    .BlockRange = .{ .file_index = file_idx, .block_index = block_idx, .block_span = block_span },
                };
            },
            else => return error.UnknownOperationTypeFound,
        }

        operations.appendAssumeCapacity(operation);
    }

    return operations;
}
