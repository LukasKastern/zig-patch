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
    },
};

const ActiveOperation = struct {
    operation: Operation,
    callback: *const fn (*anyopaque) void,
    callback_context: *anyopaque,
    overlapped: windows.OVERLAPPED,
    slot_idx: usize,
};

const OperationSlot = struct {
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

                            var is_directory = file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0;
                            var nt_name = windows.UNICODE_STRING{
                                .Length = @intCast(c_ushort, file_info.FileNameLength),
                                .MaximumLength = @intCast(c_ushort, file_info.FileNameLength),
                                .Buffer = file_name.ptr,
                            };
                            var attr = windows.OBJECT_ATTRIBUTES{
                                .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
                                .RootDirectory = directory.handle,
                                .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
                                .ObjectName = &nt_name,
                                .SecurityDescriptor = null,
                                .SecurityQualityOfService = null,
                            };

                            var file_handle: windows.HANDLE = undefined;

                            var file_io: windows.IO_STATUS_BLOCK = undefined;
                            const rc = ntdll.NtCreateFile(
                                &file_handle,
                                windows.FILE_READ_DATA | windows.FILE_WRITE_DATA, //DesiredAccess
                                &attr,
                                &file_io,
                                null, //AllocationSize
                                0, // FileAttributes
                                windows.FILE_SHARE_READ, // ShareAccess
                                windows.FILE_OPEN, // CreateDisposition
                                0, // CreateOptions
                                null, //EaBuffer
                                0, //EaLength
                            );

                            if (rc != .SUCCESS) {
                                return windows.unexpectedStatus(rc);
                            }

                            if (!is_directory) {
                                _ = windows.CreateIoCompletionPort(file_handle, self.completion_port, undefined, undefined) catch undefined;
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

    self.allocator.destroy(self);
}

fn readFile(implementation: PatchIO.Implementation, file_info: PatchIO.FileInfo, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    // If there are no slots left we keep ticking until one becomes available.
    while (self.available_operation_slots.items.len == 0) {
        implementation.tick(implementation);
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
        } },
        .callback = callback,
        .callback_context = callback_ctx,
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
        .slot_idx = slot_idx,
    };

    var read_file_op = &operation.pending_operation.?.operation.ReadFile;
    operation.pending_operation.?.overlapped.hEvent = null;

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

    _ = windows.kernel32.ReadFile(file_info.handle, read_file_op.buffer.ptr, len_to_read, null, &operation.pending_operation.?.overlapped);

    var last_err = windows.kernel32.GetLastError();
    switch (last_err) {
        .SUCCESS => {
            operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);
            operation.pending_operation = null;
            self.available_operation_slots.appendAssumeCapacity(slot_idx);
        },
        .IO_PENDING => {},
        else => {
            operation.pending_operation = null;
            self.available_operation_slots.appendAssumeCapacity(slot_idx);
            return error.Unexpected;
        },
    }
}

fn tick(implementation: PatchIO.Implementation) void {
    var self = @ptrCast(*Self, @alignCast(@alignOf(*Self), implementation.instance_data));

    var entries: [64]windows.OVERLAPPED_ENTRY = undefined;
    var num_entries_removed: u32 = 0;
    _ = windows.kernel32.GetQueuedCompletionStatusEx(self.completion_port, &entries, entries.len, &num_entries_removed, 0, windows.TRUE);

    for (entries[0..num_entries_removed]) |entry| {
        var parent_ptr = @fieldParentPtr(ActiveOperation, "overlapped", entry.lpOverlapped);
        var slot_idx = parent_ptr.slot_idx;

        var operation = &self.operation_slots[slot_idx];

        operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);

        operation.pending_operation = null;
        self.available_operation_slots.appendAssumeCapacity(slot_idx);
    }
}

pub fn create(allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.Implementation {
    var self = allocator.create(Self) catch return error.OutOfMemory;

    // zig fmt: off
    self.* = .{ 
        .allocator = allocator, 
        .operation_slots = undefined,
        .available_operation_slots = std.ArrayList(usize).initCapacity(allocator, MaxSimulatenousOperations) catch return error.Unexpected,
        .completion_port = try windows.CreateIoCompletionPort(windows.INVALID_HANDLE_VALUE, null, 0, 16)
    };
    // zig fmt: on

    for (0..MaxSimulatenousOperations) |idx| {
        self.available_operation_slots.appendAssumeCapacity(idx);
        self.operation_slots[idx] = .{
            .pending_operation = null,
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
