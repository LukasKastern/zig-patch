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

pub const PatchOperation = union(enum) {
    Invalid: void,
    BlockRange: BlockRangeOperation,
    Data: []const u8,
};

pub fn generateOperationsForBuffer(buffer: []u8, block_map: AnchoredBlocksMap, max_operation_len: usize, allocator: std.mem.Allocator) !std.ArrayList(PatchOperation) {
    const max_operations = @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(buffer.len)) / @as(f64, @floatFromInt(BlockSize)))));
    var patch_operations = try std.ArrayList(PatchOperation).initCapacity(allocator, max_operations);

    var tail: usize = 0;
    var head: usize = 0;
    var owed_data_tail: usize = 0;

    var rolling_hash: RollingHash = .{};

    var jump_to_next_block = true;

    while (tail <= buffer.len) {
        if (jump_to_next_block) {
            head = @min(head + BlockSize, buffer.len);

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
            head = @min(head + 1, buffer.len);
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

pub const GenerateOperationsState = struct {

    // User supplied data for the input of the incremental generation.
    in_buffer: []u8,

    previous_step_start: usize = 0,
    previous_step_data_tail: []u8,
    previous_step_data_tail_backing_buffer: [BlockSize]u8,

    file_size: usize = 0,
    tail: usize = 0,
    head: usize = 0,
    last_value: u32 = 0,
    owed_data_tail: usize = 0,
    rolling_hash: RollingHash = .{},

    jump_to_next_block: bool = false,

    pub fn isDone(state: *const GenerateOperationsState) bool {
        return state.tail == state.file_size;
    }

    pub fn prepareForNextIteration(state: *GenerateOperationsState, operations: *std.ArrayList(PatchOperation), allocator: std.mem.Allocator) !void {

        // Emit data op of current owed data tail
        if (state.tail != state.owed_data_tail) {
            var file_slice = blk: {
                var data_len = state.tail - state.owed_data_tail;

                var empty_slice: [0]u8 = undefined;

                // First try to get the file slice as a reference.
                // If that is not possible we allocate the required memory.
                var slice = state.getFileSlice(state.owed_data_tail, &empty_slice, data_len) catch err_blk: {
                    var new_data_op = try allocator.alloc(u8, data_len);
                    break :err_blk state.getFileSlice(state.owed_data_tail, new_data_op, data_len) catch unreachable;
                };

                break :blk slice;
            };

            try operations.append(.{ .Data = file_slice });
            state.owed_data_tail = state.tail;
        }

        // Put the remaining data into the state buffer.
        const num_remaining_bytes = state.head - state.tail;

        // Adjust the start position by the bytes we processed.
        state.previous_step_start += state.in_buffer.len - num_remaining_bytes;

        state.previous_step_data_tail = state.previous_step_data_tail_backing_buffer[0..num_remaining_bytes];

        const slice_from_in_buffer = state.in_buffer[state.in_buffer.len - num_remaining_bytes ..];

        std.mem.copy(u8, state.previous_step_data_tail, slice_from_in_buffer);
        state.in_buffer = &[_]u8{};
    }

    pub fn init(state: *GenerateOperationsState, file_len: usize) void {
        state.file_size = file_len;
        state.tail = 0;
        state.head = 0;
        state.owed_data_tail = 0;
        state.rolling_hash = .{};
        state.previous_step_start = 0;
        state.previous_step_data_tail = &[_]u8{};
        state.in_buffer = &[_]u8{};
        state.jump_to_next_block = true;
    }

    pub fn getFileSlice(state: *const GenerateOperationsState, start: usize, backing_buffer: []u8, desired_size: usize) ![]u8 {
        const distance_from_prev = start - state.previous_step_start;
        const bytes_from_prev = @as(isize, @intCast(state.previous_step_data_tail.len)) -
            @as(isize, @intCast(distance_from_prev));

        var out_slice: []u8 = undefined;

        if (bytes_from_prev > 0) {
            const prev_data_len = state.previous_step_data_tail.len;
            const num_bytes_to_copy = @min(@as(usize, @intCast(bytes_from_prev)), desired_size);
            const prev_slice_start = prev_data_len - @as(usize, @intCast(bytes_from_prev));
            const prev_data_slice = state.previous_step_data_tail[prev_slice_start .. prev_slice_start + num_bytes_to_copy];

            if (backing_buffer.len < desired_size) {
                return error.BackingBufferTooSmall;
            }

            out_slice = backing_buffer[0..desired_size];
            std.mem.copy(u8, out_slice, prev_data_slice);
        }

        // Take the rest of the bytes from the current in_buffer.
        {
            const in_buffer_start_in_file = state.previous_step_start + state.previous_step_data_tail.len;

            const in_buffer_copy_start = if (bytes_from_prev > 0) 0 else start - in_buffer_start_in_file;

            const actual_copied_bytes_from_prev = @as(usize, @intCast(@max(bytes_from_prev, 0)));
            const bytes_to_copy = desired_size - actual_copied_bytes_from_prev;

            if (in_buffer_copy_start + bytes_to_copy > state.in_buffer.len) {
                return error.MoreDataNeeded;
            }

            var in_buffer_slice = state.in_buffer[in_buffer_copy_start .. in_buffer_copy_start + bytes_to_copy];

            // If we do not have to assemble a custom block using the backing buffer we directly reference the data from the in_buffer.
            if (bytes_from_prev <= 0) {
                out_slice = in_buffer_slice;
            } else {
                std.mem.copy(u8, out_slice[actual_copied_bytes_from_prev..], in_buffer_slice);
            }
        }

        return out_slice;
    }
};

pub fn generateOperationsForBufferIncremental(block_map: AnchoredBlocksMap, state: *GenerateOperationsState, allocator: std.mem.Allocator, max_operation_len: usize) !std.ArrayList(PatchOperation) {
    const max_operations = @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(state.in_buffer.len)) / @as(f64, @floatFromInt(BlockSize))))) + 1;
    var patch_operations = try std.ArrayList(PatchOperation).initCapacity(allocator, max_operations);

    var current_block_backing_buffer: [BlockSize]u8 = undefined;
    var current_block: []u8 = undefined;

    while (state.tail < state.file_size) {
        if (state.jump_to_next_block) {
            var new_head = @min(state.head + BlockSize, state.file_size);

            if (state.tail == new_head) {
                break;
            }

            current_block = state.getFileSlice(state.tail, &current_block_backing_buffer, new_head - state.tail) catch |e| {
                switch (e) {
                    error.MoreDataNeeded => {
                        try state.prepareForNextIteration(&patch_operations, allocator);
                        return patch_operations;
                    },
                    else => unreachable,
                }
            };

            state.head = new_head;

            state.rolling_hash.recompute(current_block);

            state.jump_to_next_block = false;
        } else {
            current_block = state.getFileSlice(state.tail, &current_block_backing_buffer, state.head - state.tail) catch |e| {
                switch (e) {
                    error.MoreDataNeeded => {
                        try state.prepareForNextIteration(&patch_operations, allocator);
                        return patch_operations;
                    },
                    else => unreachable,
                }
            };

            const distance = state.head - state.tail;
            const last_value = state.last_value;

            const new_value = if (current_block.len > 0) current_block[current_block.len - 1] else 0;
            //TODO: Make this incremental again.
            state.rolling_hash.nextImpl(@as(u32, @intCast(last_value)), new_value, distance);

            // rolling_hash.next(current_block, tail - 1, head - 1);
        }

        std.debug.assert(current_block.len > 0);
        std.debug.assert(state.head - state.tail <= BlockSize);

        var hash = state.rolling_hash.hash;

        var known_block: ?AnchoredBlock = null;

        if (block_map.hasAnchoredBlocksForWeakHash(hash)) {
            // @setRuntimeSafety(false);
            // Hash found. Calculate MD5 and see if we match with a known block.

            var block_hash: BlockHash = .{
                .weak_hash = hash,
                .strong_hash = undefined,
            };

            std.crypto.hash.Md5.hash(current_block, &block_hash.strong_hash, .{});

            var block_size = state.head - state.tail;
            var short_size = BlockSize - block_size;

            //TODO: Add the preferred file idx here (lukas)
            known_block = block_map.getAnchoredBlock(block_hash, 0, short_size);
        }

        if (known_block) |block| {
            if (state.tail != state.owed_data_tail) {
                var file_slice = blk: {
                    var data_len = state.tail - state.owed_data_tail;

                    var empty_slice: [0]u8 = undefined;

                    // First try to get the file slice as a reference.
                    // If that is not possible we allocate the required memory.
                    var slice = state.getFileSlice(state.owed_data_tail, &empty_slice, data_len) catch err_blk: {
                        var new_data_op = try allocator.alloc(u8, data_len);
                        break :err_blk state.getFileSlice(state.owed_data_tail, new_data_op, data_len) catch unreachable;
                    };

                    break :blk slice;
                };

                try patch_operations.append(.{ .Data = file_slice });
            }

            //TODO: Check if last operation is the same. If so merge span. (lukas)
            try patch_operations.append(.{
                .BlockRange = .{
                    .file_index = block.file_index,
                    .block_index = block.block_index,
                    .block_span = 1,
                },
            });

            state.owed_data_tail = state.head;
            state.tail = state.head;
            state.jump_to_next_block = true;
        } else {
            const reached_end_of_buffer = state.tail == state.head;
            const can_omit_data_op = state.owed_data_tail != state.tail;
            const needs_to_omit_data_op = reached_end_of_buffer or (state.tail - state.owed_data_tail >= max_operation_len);

            if (can_omit_data_op and needs_to_omit_data_op) {
                //TODO: Remove the duplicates of this code.
                var file_slice = blk: {
                    var data_len = state.tail - state.owed_data_tail;

                    var empty_slice: [0]u8 = undefined;

                    // First try to get the file slice as a reference.
                    // If that is not possible we allocate the required memory.
                    var slice = state.getFileSlice(state.owed_data_tail, &empty_slice, data_len) catch err_blk: {
                        var new_data_op = try allocator.alloc(u8, data_len);
                        break :err_blk state.getFileSlice(state.owed_data_tail, new_data_op, data_len) catch unreachable;
                    };

                    break :blk slice;
                };

                try patch_operations.append(.{ .Data = file_slice });

                // std.log.err("Appending Block {}:{}", .{ owed_data_tail, tail });
                state.owed_data_tail = state.tail;
            }

            // Step to next byte.
            state.last_value = current_block[0];
            state.tail += 1;
            state.head = @min(state.head + 1, state.file_size);
        }
    }

    if (state.owed_data_tail != state.tail) {
        var file_slice = blk: {
            var data_len = state.tail - state.owed_data_tail;

            var empty_slice: [0]u8 = undefined;

            // First try to get the file slice as a reference.
            // If that is not possible we allocate the required memory.
            var slice = state.getFileSlice(state.owed_data_tail, &empty_slice, data_len) catch err_blk: {
                var new_data_op = try allocator.alloc(u8, data_len);
                break :err_blk state.getFileSlice(state.owed_data_tail, new_data_op, data_len) catch unreachable;
            };

            break :blk slice;
        };

        try patch_operations.append(.{ .Data = file_slice });
        state.owed_data_tail = state.tail;
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

    const buffer_size = @trunc(@as(f64, @floatFromInt(max_operation_len)) * 1);
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

    const buffer_size = @trunc(@as(f64, @floatFromInt(max_operation_len)) * 3.564);
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

pub const SerializedOperationIterator = struct {
    const Self = @This();

    operations: []const u8,

    next_operation: usize,
    num_operations: usize,

    stream: std.io.FixedBufferStream([]const u8),
    reader: std.io.FixedBufferStream([]const u8).Reader,

    pub fn init(self: *SerializedOperationIterator, serialized_operations: []const u8) !void {
        var stream = std.io.fixedBufferStream(serialized_operations);

        self.* = .{
            .stream = stream,
            .num_operations = undefined,
            .next_operation = 0,
            .operations = serialized_operations,
            .reader = undefined,
        };

        self.reader = self.stream.reader();
        self.num_operations = try self.reader.readInt(usize, Endian);
    }

    pub fn nextOperation(self: *Self) !?PatchOperation {
        if (self.next_operation >= self.num_operations) {
            return null;
        }

        self.next_operation += 1;

        var operation_type_raw = try self.reader.readInt(usize, Endian);
        var operation: PatchOperation = undefined;

        if (operation_type_raw == 1) {
            var data_len = try self.reader.readInt(usize, Endian);

            operation = PatchOperation{
                .Data = self.stream.buffer[self.stream.pos .. self.stream.pos + data_len],
            };
            self.stream.pos += data_len;
        } else if (operation_type_raw == 2) {
            var file_idx = try self.reader.readInt(usize, Endian);
            var block_idx = try self.reader.readInt(usize, Endian);
            var block_span = try self.reader.readInt(usize, Endian);

            operation = PatchOperation{
                .BlockRange = .{ .file_index = file_idx, .block_index = block_idx, .block_span = block_span },
            };
        } else {
            return error.FoundInvalidOperation;
        }

        return operation;
    }
};

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
