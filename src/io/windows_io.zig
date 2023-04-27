const std = @import("std");
const PatchIO = @import("patch_io.zig");

const windows = std.os.windows;
const ntdll = windows.ntdll;

const FileInformationBufferSize = 4096;
const DefaultPathBufferSize = 1024 * 1024;

const ntdll_extra = struct {
    pub extern "ntdll" fn NtOpenFile(
        FileHandle: *windows.HANDLE,
        DesiredAccess: windows.ACCESS_MASK,
        ObjectAttributes: *windows.OBJECT_ATTRIBUTES,
        IoStatusBlock: *windows.IO_STATUS_BLOCK,
        ShareAccess: windows.ULONG,
        OpenOptions: windows.ULONG,
    ) callconv(windows.WINAPI) windows.NTSTATUS;

    pub extern "ntdll" fn NtReadFile(
        FileHandle: windows.HANDLE,
        Event: ?windows.HANDLE,
        ApcRoutine: ?windows.IO_APC_ROUTINE,
        ApcContext: ?*anyopaque,
        IoStatusBlock: *windows.IO_STATUS_BLOCK,
        Buffer: ?*const anyopaque,
        Length: windows.ULONG,
        ByteOffset: ?*const windows.LARGE_INTEGER,
        Key: ?*windows.ULONG,
    ) callconv(windows.WINAPI) windows.NTSTATUS;
};

const kernel32_extra = struct {
    pub extern "kernel32" fn CreateFileA(
        lpFileName: [*:0]const u8,
        dwDesiredAccess: windows.DWORD,
        dwShareMode: windows.DWORD,
        lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
        dwCreationDisposition: windows.DWORD,
        dwFlagsAndAttributes: windows.DWORD,
        hTemplateFile: ?windows.HANDLE,
    ) callconv(windows.WINAPI) windows.HANDLE;

    pub extern "kernel32" fn SetEvent(
        event: windows.HANDLE,
    ) callconv(windows.WINAPI) windows.BOOL;

    pub extern "kernel32" fn ReadFileEx(in_hFile: windows.HANDLE, out_lpBuffer: [*]u8, in_nNumberOfBytesToRead: windows.DWORD, in_out_lpOverlapped: ?*windows.OVERLAPPED, lpCompletionRoutine: windows.LPOVERLAPPED_COMPLETION_ROUTINE) callconv(windows.WINAPI) windows.BOOL;
};

const Operation = union(enum) {
    ReadFile: struct {
        file_info: PatchIO.FileInfo,
        offset: i64,
        buffer: []u8,
        io_status_block: windows.IO_STATUS_BLOCK,
        overlapped: windows.OVERLAPPED,
    },
};

const ActiveOperation = struct {
    operation: Operation,
    callback: *const fn (*anyopaque) void,
    callback_context: *anyopaque,
};

const OperationSlot = struct {
    operation_event: windows.HANDLE,
    pending_operation: ?ActiveOperation,
};

const PendingOperation = struct {
    operation_idx: usize,
    event_handle: windows.HANDLE,
};

const MaxSimulatenousOperations = 63;

const Self = @This();

allocator: std.mem.Allocator,

operation_slots: [MaxSimulatenousOperations]OperationSlot,
available_operation_slots: std.ArrayList(usize),
pending_operations: std.MultiArrayList(PendingOperation),
completion_port: windows.HANDLE,

pub fn lockDirectoryRecursively(implementation: PatchIO.Implementation, path: []const u8, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.LockedDirectory {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    var locked_dir: PatchIO.LockedDirectory = .{
        .path_buffer = undefined,
        .handle = undefined,
        .files = std.ArrayList(PatchIO.FileInfo).init(allocator),
        .directories = std.ArrayList(PatchIO.DirectoryInfo).init(allocator),
        .allocator = allocator,
    };

    var cwd = std.fs.cwd();
    var target_dir = cwd.openIterableDir(path, .{}) catch return error.FailedToOpenDir;

    locked_dir.handle = target_dir.dir.fd;
    errdefer {
        _ = ntdll.NtClose(locked_dir.handle);
    }

    var status_block: windows.IO_STATUS_BLOCK = undefined;
    var file_information_buf: [FileInformationBufferSize]u8 align(@alignOf(std.os.windows.FILE_DIRECTORY_INFORMATION)) = undefined;

    var file_name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;

    var path_buffer_offset: u32 = 0;
    var path_buffer_size: u32 = DefaultPathBufferSize;

    var path_buffer = try allocator.alloc(u8, path_buffer_size);
    errdefer allocator.free(path_buffer);

    const DirectoryToQuery = struct {
        handle: windows.HANDLE,
        path_offset: u32,
        path_len: u32,
    };

    var directories_to_query = std.ArrayList(DirectoryToQuery).init(allocator);
    defer directories_to_query.deinit();

    try directories_to_query.append(.{
        .handle = target_dir.dir.fd,
        .path_offset = 0,
        .path_len = 0,
    });

    while (directories_to_query.items.len > 0) {
        var directory = directories_to_query.orderedRemove(0);
        var is_first_iteration = true;

        std.mem.copy(u8, &file_name_buffer, path_buffer[directory.path_offset .. directory.path_offset + directory.path_len]);
        const file_name_base_offset = directory.path_len;

        query: while (true) {
            // zig fmt: off
            var status = ntdll.NtQueryDirectoryFile(directory.handle, 
                null, 
                null, 
                null, 
                &status_block, 
                &file_information_buf,  
                file_information_buf.len, 
                .FileDirectoryInformation, 
                windows.FALSE, // Single Result
                null, 
                if(is_first_iteration) windows.TRUE else windows.FALSE // Restart iteration
            );
            // zig fmt: on

            is_first_iteration = false;

            switch (status) {
                .SUCCESS => {
                    var offset: usize = 0;

                    file_iteration: while (true) {
                        var file_info = @ptrCast(*std.os.windows.FILE_DIRECTORY_INFORMATION, @alignCast(@alignOf(*std.os.windows.FILE_DIRECTORY_INFORMATION), &file_information_buf[offset]));
                        offset += file_info.NextEntryOffset;

                        var file_name = @ptrCast([*]u16, &file_info.FileName)[0 .. file_info.FileNameLength / 2];

                        var is_standard_directory = false;

                        if (file_name.len == 1 and file_name[0] == 46) {
                            is_standard_directory = true;
                        } else if (file_name.len == 2 and file_name[0] == 46 and file_name[1] == 46) {
                            is_standard_directory = true;
                        }

                        if (!is_standard_directory) {
                            var end_idx = std.unicode.utf16leToUtf8(file_name_buffer[file_name_base_offset..], file_name) catch return error.Unexpected;
                            end_idx += file_name_base_offset;

                            if (file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
                                file_name_buffer[end_idx] = '/';
                                end_idx += 1;
                            }

                            if (end_idx + path_buffer_offset > path_buffer_size) {
                                path_buffer_size *= 2;
                                path_buffer = try allocator.realloc(path_buffer, path_buffer_size);
                            }

                            std.mem.copy(u8, path_buffer[path_buffer_offset..], file_name_buffer[0..end_idx]);
                            var prev_offset = path_buffer_offset;
                            path_buffer_offset += @intCast(u32, end_idx);

                            var file_handle: windows.HANDLE = undefined;

                            // var file_io: windows.IO_STATUS_BLOCK = undefined;

                            var temp_create_file_buffer: [512]u8 = undefined;
                            var bytes_to_copy = "D:/Projects/Journee/seat/JourneeBUild3/Windows/";
                            std.mem.copy(u8, &temp_create_file_buffer, bytes_to_copy);

                            var path_bufff = path_buffer[prev_offset .. prev_offset + end_idx];

                            std.mem.copy(u8, temp_create_file_buffer[bytes_to_copy.len..], path_bufff);
                            temp_create_file_buffer[bytes_to_copy.len + end_idx] = 0;

                            // file_handle = kernel32_extra.CreateFileA(@ptrCast([*:0]u8, &temp_create_file_buffer), windows.GENERIC_READ, windows.FILE_SHARE_READ, null, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, null);

                            var is_directory = file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0;
                            var attributes: u32 = if (is_directory) windows.FILE_FLAG_BACKUP_SEMANTICS else windows.FILE_ATTRIBUTE_NORMAL;
                            file_handle = kernel32_extra.CreateFileA(@ptrCast([*:0]u8, &temp_create_file_buffer), windows.GENERIC_READ, windows.FILE_SHARE_READ, null, windows.OPEN_EXISTING, attributes | windows.FILE_FLAG_OVERLAPPED, null);
                            // std.log.yerr("Error={}", .{windows.kernel32.GetLastError()});

                            if (file_handle == windows.INVALID_HANDLE_VALUE) {
                                return error.Unexpected;
                            }

                            _ = self;
                            if (file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY == 0) {
                                // _ = windows.CreateIoCompletionPort(file_handle, self.completion_port, undefined, undefined) catch undefined;
                            }

                            if (is_directory) {
                                try directories_to_query.append(.{ .handle = file_handle, .path_offset = prev_offset, .path_len = @intCast(u32, end_idx) });

                                try locked_dir.directories.append(.{
                                    .handle = file_handle,
                                    .path_offset = prev_offset,
                                    .path_len = @intCast(u32, end_idx),
                                });
                            } else {
                                try locked_dir.files.append(.{
                                    .handle = file_handle,
                                    .path_offset = prev_offset,
                                    .path_len = @intCast(u32, end_idx),
                                    .size = @intCast(u64, file_info.EndOfFile),
                                });
                            }
                        }

                        if (file_info.NextEntryOffset == 0) {
                            break :file_iteration;
                        }
                    }

                    continue :query;
                },
                .NO_MORE_FILES => break :query,
                .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
                .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
                else => return windows.unexpectedStatus(status),
            }
        }
    }

    locked_dir.path_buffer = path_buffer;
    return locked_dir;
}

fn unlockDirectory(implementation: PatchIO.Implementation, locked_directory: PatchIO.LockedDirectory) void {
    _ = implementation;

    for (locked_directory.files.items) |file| {
        _ = ntdll.NtClose(file.handle);
    }

    for (locked_directory.directories.items) |dir| {
        _ = ntdll.NtClose(dir.handle);
    }

    _ = ntdll.NtClose(locked_directory.handle);

    locked_directory.files.deinit();
    locked_directory.directories.deinit();
    locked_directory.allocator.free(locked_directory.path_buffer);
}

fn destroy(implementation: PatchIO.Implementation) void {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    self.available_operation_slots.deinit();
    for (0..MaxSimulatenousOperations) |idx| {
        windows.CloseHandle(self.operation_slots[idx].operation_event);
    }

    self.pending_operations.deinit(self.allocator);
    self.allocator.destroy(self);
}

fn addPendingOperation(self: *Self, operation_idx: usize) void {
    var operation = &self.operation_slots[operation_idx];
    self.pending_operations.appendAssumeCapacity(.{ .operation_idx = operation_idx, .event_handle = operation.operation_event });
}

fn readFile(implementation: PatchIO.Implementation, file_info: PatchIO.FileInfo, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    // If there are no slots left we keep ticking until one becomes available.
    while (self.available_operation_slots.items.len == 0) {
        implementation.tick(implementation, 10);
    }

    var slot_idx = self.available_operation_slots.orderedRemove(self.available_operation_slots.items.len - 1);
    var operation = &self.operation_slots[slot_idx];

    std.debug.assert(operation.pending_operation == null);

    operation.pending_operation = .{
        .operation = .{ .ReadFile = .{
            .file_info = file_info,
            .offset = @intCast(i64, offset),
            .buffer = buffer,
            .io_status_block = undefined,
            .overlapped = windows.OVERLAPPED{
                .Internal = 0,
                .InternalHigh = 0,
                .DUMMYUNIONNAME = .{
                    .DUMMYSTRUCTNAME = .{
                        .Offset = @truncate(u32, offset),
                        .OffsetHigh = @truncate(u32, offset >> 32),
                    },
                },
                .hEvent = null,
            },
        } },
        .callback = callback,
        .callback_context = callback_ctx,
    };

    var read_file_op = &operation.pending_operation.?.operation.ReadFile;
    read_file_op.overlapped.hEvent = operation.operation_event;

    // var nt_result = ntdll_extra.NtReadFile(file_info.handle, null, null, null, &read_file_op.io_status_block, read_file_op.buffer.ptr, @intCast(u32, read_file_op.buffer.len), &read_file_op.offset, null);

    // const IOCompletedCallback = extern struct {
    //     fn overlappedCallback(
    //         dwErrorCode: windows.DWORD,
    //         dwNumberOfBytesTransfered: windows.DWORD,
    //         lpOverlapped: *windows.OVERLAPPED,
    //     ) callconv(.C) void {
    //         _ = dwErrorCode;
    //         _ = dwNumberOfBytesTransfered;

    //         _ = kernel32_extra.SetEvent(lpOverlapped.hEvent.?);
    //     }
    // };

    // var success =  kernel32_extra.ReadFileEx(file_info.handle, read_file_op.buffer.ptr, @intCast(u32, read_file_op.buffer.len), &read_file_op.overlapped, IOCompletedCallback.overlappedCallback);

    var len_to_read = @intCast(u32, read_file_op.buffer.len);

    if (len_to_read % 512 != 0) {
        len_to_read += (512 - len_to_read % 512);
    }

    _ = windows.kernel32.ReadFile(file_info.handle, read_file_op.buffer.ptr, len_to_read, null, &read_file_op.overlapped);

    var last_err = windows.kernel32.GetLastError();
    switch (last_err) {
        .SUCCESS => {
            // addPendingOperation(self, slot_idx);

            operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);
            operation.pending_operation = null;
            self.available_operation_slots.appendAssumeCapacity(slot_idx);
        },
        .IO_PENDING => {
            addPendingOperation(self, slot_idx);
        },
        else => {
            std.log.err("ReadFileErr={}", .{last_err});
            operation.pending_operation = null;
            self.available_operation_slots.appendAssumeCapacity(slot_idx);
            return error.Unexpected;
        },
    }
}

fn tick(implementation: PatchIO.Implementation, sleep_for_ms: usize) void {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    var remaining_sleep_time: u32 = @intCast(u32, sleep_for_ms);

    wait_on_operations: while (true) {
        var events = self.pending_operations.items(.event_handle);

        if (events.len == 0) {
            break :wait_on_operations;
        }

        var result = windows.WaitForMultipleObjectsEx(events, false, remaining_sleep_time, true) catch |e| {
            switch (e) {
                else => {
                    break :wait_on_operations;
                },
            }
        };

        remaining_sleep_time = 0;

        var pending_operation_data = self.pending_operations.get(result);
        var operation = &self.operation_slots[pending_operation_data.operation_idx];

        operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);

        operation.pending_operation = null;
        self.available_operation_slots.appendAssumeCapacity(pending_operation_data.operation_idx);
        self.pending_operations.swapRemove(result);
    }
}

pub fn create(allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.Implementation {
    var self = allocator.create(Self) catch return error.OutOfMemory;

    // zig fmt: off
    self.* = .{ 
        .allocator = allocator, 
        .operation_slots = undefined,
        .available_operation_slots = std.ArrayList(usize).initCapacity(allocator, MaxSimulatenousOperations) catch return error.Unexpected,
        .pending_operations = std.MultiArrayList(PendingOperation){}, 
        .completion_port = try windows.CreateIoCompletionPort(windows.INVALID_HANDLE_VALUE, null, 0, 1)
    };
    // zig fmt: on

    try self.pending_operations.ensureTotalCapacity(allocator, MaxSimulatenousOperations);

    for (0..MaxSimulatenousOperations) |idx| {
        self.available_operation_slots.appendAssumeCapacity(idx);
        self.operation_slots[idx] = .{
            .pending_operation = null,
            .operation_event = windows.CreateEventEx(null, &[0]u8{}, 0, windows.EVENT_ALL_ACCESS) catch return error.Unexpected,
        };
    }

    return .{
        .instance_data = self,
        .lock_directory = lockDirectoryRecursively,
        .unlock_directory = unlockDirectory,
        .destroy = destroy,
        .read_file = readFile,
        .tick = tick,
    };
}
