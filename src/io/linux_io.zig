const std = @import("std");
const PatchIO = @import("patch_io.zig");
const PlatformHandle = PatchIO.PlatformHandle;

const linux = struct {
    pub usingnamespace std.os.linux.syscalls;
    pub usingnamespace std.os.linux;
    pub usingnamespace @cImport(@cInclude("aio.h"));
};

const Self = @This();

allocator: std.mem.Allocator,
working_dir: std.fs.Dir,
implementation: PatchIO.Implementation,

operation_slots: [MaxSimulatenousOperations]Operation,
available_operation_slots: std.ArrayList(usize),
active_operations: std.ArrayList(usize),

const Operation = struct {
    aio: linux.aiocb,
    callback: *const fn (*anyopaque) void,
    callback_context: *anyopaque,
};

const MaxSimulatenousOperations = 63;

pub fn lockDirectory(implementation: PatchIO.Implementation, path: []const u8, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.LockedDirectory {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));
    _ = self; // autofix

    const path_c = std.os.toPosixPath(path) catch return PatchIO.PatchIOErrors.FailedToOpenDir;

    var buf: [4096]u8 align(1) = undefined;

    var open_dir_res = linux.open(path_c[0..], 0, linux.O.RDONLY);

    var root_directory = switch (linux.getErrno(open_dir_res)) {
        .SUCCESS => @as(linux.fd_t, @intCast(open_dir_res)),
        else => return PatchIO.PatchIOErrors.FailedToOpenDir,
    };

    defer _ = linux.close(root_directory);

    var path_buffer = allocator.alloc(u8, 4096) catch return PatchIO.PatchIOErrors.OutOfMemory;
    var path_buffer_offset: usize = 0;

    var locked_dir: PatchIO.LockedDirectory = .{
        .path_buffer = undefined,
        .handle = undefined,
        .files = std.ArrayList(PatchIO.FileInfo).init(allocator),
        .directories = std.ArrayList(PatchIO.DirectoryInfo).init(allocator),
        .allocator = allocator,
    };
    locked_dir.handle = root_directory;

    var directories_allocator = std.heap.stackFallback(4096, allocator);

    var directories_to_iterate = std.ArrayList(PlatformHandle).initCapacity(directories_allocator.get(), 32) catch return PatchIO.PatchIOErrors.OutOfMemory;
    directories_to_iterate.append(root_directory) catch return PatchIO.PatchIOErrors.OutOfMemory;

    while (directories_to_iterate.items.len > 0) {
        var dir = directories_to_iterate.items[0];
        const rc = linux.getdents64(dir, &buf, buf.len);
        switch (linux.getErrno(rc)) {
            .SUCCESS => {},
            else => |err| return {
                std.log.err(("GetDents64 failed with error: {}"), .{err});
                return PatchIO.PatchIOErrors.Unexpected;
            },
        }

        if (rc == 0) {
            _ = directories_to_iterate.orderedRemove(0);
            continue;
        }

        const PathHandle = struct {
            offset: u32,
            len: u32,
        };

        var parent_dir_path = blk: {
            for (locked_dir.directories.items) |d| {
                if (d.handle == dir) {
                    break :blk PathHandle{
                        .offset = d.path_offset,
                        .len = d.path_len,
                    };
                }
            }

            break :blk PathHandle{ .offset = @as(u32, 0), .len = @as(u32, 0) };
        };

        var idx: usize = 0;
        while (idx < rc) {
            const linux_entry = @as(*align(1) linux.dirent64, @ptrCast(&buf[idx]));
            idx += linux_entry.reclen();

            const name = std.mem.sliceTo(@as([*:0]u8, @ptrCast(&linux_entry.d_name)), 0);

            if (linux_entry.d_type != linux.DT.DIR and linux_entry.d_type != linux.DT.REG) {
                continue;
            }

            // skip . and .. entries
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
                continue;
            }

            var handle_res = linux.openat(dir, name, 0, linux.O.RDONLY);
            var current_entry_handle = switch (linux.getErrno(handle_res)) {
                .SUCCESS => @as(PlatformHandle, @intCast(handle_res)),
                else => |err| {
                    std.log.err(("openAt failed with error: {}"), .{err});
                    return PatchIO.PatchIOErrors.Unexpected;
                },
            };

            if (parent_dir_path.len + 1 + name.len + path_buffer_offset > path_buffer.len) {
                path_buffer = allocator.realloc(path_buffer, path_buffer.len * 2) catch return PatchIO.PatchIOErrors.OutOfMemory;
            }

            var prev_path_buffer_offset = path_buffer_offset;

            if (parent_dir_path.len > 0) {
                std.mem.copy(
                    u8,
                    path_buffer[path_buffer_offset .. path_buffer_offset + parent_dir_path.len],
                    path_buffer[parent_dir_path.offset .. parent_dir_path.offset + parent_dir_path.len],
                );
                path_buffer_offset += parent_dir_path.len;

                path_buffer[path_buffer_offset] = '/';
                path_buffer_offset += 1;
            }

            std.mem.copy(u8, path_buffer[path_buffer_offset .. path_buffer_offset + name.len], name);
            path_buffer_offset += name.len;

            switch (linux_entry.d_type) {
                linux.DT.DIR => {
                    locked_dir.directories.append(.{
                        .handle = current_entry_handle,
                        .path_offset = @intCast(prev_path_buffer_offset),
                        .path_len = @intCast(path_buffer_offset - prev_path_buffer_offset),
                    }) catch return PatchIO.PatchIOErrors.OutOfMemory;

                    directories_to_iterate.append(current_entry_handle) catch return PatchIO.PatchIOErrors.OutOfMemory;
                },
                linux.DT.REG => {
                    var stats = std.mem.zeroes(linux.Stat);

                    switch (linux.getErrno(linux.fstat(current_entry_handle, &stats))) {
                        .SUCCESS => {},
                        else => {
                            return PatchIO.PatchIOErrors.Unexpected;
                        },
                    }

                    locked_dir.files.append(.{
                        .handle = current_entry_handle,
                        .path_offset = @intCast(prev_path_buffer_offset),
                        .path_len = @intCast(path_buffer_offset - prev_path_buffer_offset),
                        .size = @intCast(stats.size),
                    }) catch return PatchIO.PatchIOErrors.OutOfMemory;
                },
                else => continue,
            }
        }
    }

    locked_dir.path_buffer = path_buffer;
    return locked_dir;
}

fn readFile(implementation: PatchIO.Implementation, handle: PlatformHandle, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    while (self.available_operation_slots.items.len == 0) {
        self.implementation.tick(implementation);
    }

    var operation_slot_idx = self.available_operation_slots.swapRemove(self.available_operation_slots.items.len - 1);
    errdefer self.available_operation_slots.appendAssumeCapacity(operation_slot_idx);

    var operation_slot = &self.operation_slots[operation_slot_idx];

    operation_slot.callback = callback;
    operation_slot.callback_context = callback_ctx;
    operation_slot.aio = std.mem.zeroInit(linux.aiocb, .{
        .aio_fildes = handle,
        .aio_buf = @as(?*volatile anyopaque, @ptrCast(buffer.ptr)),
        .aio_nbytes = buffer.len,
        .aio_offset = @as(c_long, @intCast(offset)),
    });

    if (linux.aio_read(&operation_slot.aio) != 0) {
        return PatchIO.PatchIOErrors.Unexpected;
    }

    self.active_operations.appendAssumeCapacity(operation_slot_idx);
}

fn writeFile(implementation: PatchIO.Implementation, handle: PlatformHandle, offset: usize, buffer: []const u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    while (self.available_operation_slots.items.len == 0) {
        self.implementation.tick(implementation);
    }

    var operation_slot_idx = self.available_operation_slots.swapRemove(self.available_operation_slots.items.len - 1);
    errdefer self.available_operation_slots.appendAssumeCapacity(operation_slot_idx);

    var operation_slot = &self.operation_slots[operation_slot_idx];

    operation_slot.callback = callback;
    operation_slot.callback_context = callback_ctx;
    operation_slot.aio = std.mem.zeroInit(linux.aiocb, .{
        .aio_fildes = handle,
        .aio_buf = @as(?*volatile anyopaque, @ptrCast(@constCast(buffer.ptr))),
        .aio_nbytes = buffer.len,
        .aio_offset = @as(c_long, @intCast(offset)),
    });

    if (linux.aio_write(&operation_slot.aio) != 0) {
        return PatchIO.PatchIOErrors.Unexpected;
    }

    self.active_operations.appendAssumeCapacity(operation_slot_idx);
}

fn tick(implementation: PatchIO.Implementation) void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    var idx: isize = 0;
    while (idx < self.active_operations.items.len) : (idx += 1) {
        var operation_idx = self.active_operations.items[@intCast(idx)];
        var operation = &self.operation_slots[operation_idx];

        switch (@as(linux.E, @enumFromInt(linux.aio_error(&operation.aio)))) {
            .INPROGRESS => {},
            else => |res| {
                _ = linux.aio_return(&operation.aio);

                if (res != .SUCCESS) {
                    //TODO: How should we handle failing async reads?
                    std.log.err("Read failed", .{});
                }

                operation.callback(operation.callback_context);

                _ = self.active_operations.swapRemove(@intCast(idx));
                self.available_operation_slots.appendAssumeCapacity(operation_idx);
                idx -= 1;
            },
        }
    }
}

fn destroy(implementation: PatchIO.Implementation) void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    self.available_operation_slots.deinit();
    self.active_operations.deinit();

    self.allocator.destroy(self);
}

fn unlockDirectory(implementation: PatchIO.Implementation, locked_directory: PatchIO.LockedDirectory) void {
    _ = implementation;
    for (locked_directory.files.items) |file| {
        _ = linux.close(file.handle);
    }

    for (locked_directory.directories.items) |dir| {
        _ = linux.close(dir.handle);
    }

    _ = linux.close(locked_directory.handle);

    locked_directory.files.deinit();
    locked_directory.directories.deinit();
    locked_directory.allocator.free(locked_directory.path_buffer);
}

fn createFile(implementation: PatchIO.Implementation, parent_dir: PlatformHandle, file_path: []const u8) PatchIO.PatchIOErrors!PatchIO.PlatformHandle {
    _ = implementation; // autofix

    const path_c = std.os.toPosixPath(file_path) catch return PatchIO.PatchIOErrors.FailedToOpenDir;
    var result = linux.openat(parent_dir, path_c[0..], linux.O.RDWR | linux.O.CREAT, linux.S.IRWXU);
    switch (linux.getErrno(result)) {
        .SUCCESS => {
            return @intCast(result);
        },
        else => {
            return PatchIO.PatchIOErrors.Unexpected;
        },
    }
}

fn createDirectory(implementation: PatchIO.Implementation, parent_dir: PlatformHandle, file_path: []const u8) PatchIO.PatchIOErrors!PatchIO.PlatformHandle {
    return createFile(implementation, parent_dir, file_path);
}

fn openFile(implementation: PatchIO.Implementation, parent_dir: PlatformHandle, file_path: []const u8) PatchIO.PatchIOErrors!PatchIO.PlatformHandle {
    _ = implementation; // autofix

    const path_c = std.os.toPosixPath(file_path) catch return PatchIO.PatchIOErrors.FailedToOpenDir;
    var result = linux.openat(parent_dir, path_c[0..], linux.O.RDWR, linux.S.IRWXU);
    switch (linux.getErrno(result)) {
        .SUCCESS => {
            return @intCast(result);
        },
        else => {
            return PatchIO.PatchIOErrors.Unexpected;
        },
    }
}

fn closeHandle(implementation: PatchIO.Implementation, handle: PlatformHandle) void {
    _ = implementation;
    _ = linux.close(handle);
}

pub fn create(working_dir: std.fs.Dir, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.Implementation {
    var self = allocator.create(Self) catch return error.OutOfMemory;

    self.* = .{
        .allocator = allocator,
        .working_dir = working_dir,
        .implementation = undefined,
        .operation_slots = undefined,
        .active_operations = std.ArrayList(usize).initCapacity(allocator, MaxSimulatenousOperations) catch return PatchIO.PatchIOErrors.OutOfMemory,
        .available_operation_slots = std.ArrayList(usize).initCapacity(allocator, MaxSimulatenousOperations) catch return PatchIO.PatchIOErrors.OutOfMemory,
    };

    for (0..MaxSimulatenousOperations) |i| {
        self.available_operation_slots.appendAssumeCapacity(i);
    }

    self.implementation = .{
        .instance_data = self,
        .lock_directory = lockDirectory,
        .unlock_directory = unlockDirectory,
        .destroy = destroy,
        .create_file = createFile,
        .create_directory = createDirectory,
        .open_file = openFile,
        .read_file = readFile,
        .write_file = writeFile,
        .tick = tick,
        .close_handle = closeHandle,
    };

    return self.implementation;
}
