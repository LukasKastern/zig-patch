const std = @import("std");
const PatchIO = @import("patch_io.zig");
const PlatformHandle = PatchIO.PlatformHandle;
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

    pub extern "kernel32" fn CreateFileMappingA(in_hFile: windows.HANDLE, attributes: ?*windows.SECURITY_ATTRIBUTES, flProtect: windows.DWORD, dwMaximumSizeHigh: windows.DWORD, dwMaximumSizeLow: windows.DWORD, lpName: ?windows.LPCSTR) callconv(windows.WINAPI) ?windows.HANDLE;

    pub extern "kernel32" fn MapViewOfFile(hFileMappingObject: windows.HANDLE, dwDesiredAccess: windows.DWORD, dwFileOffsetHigh: windows.DWORD, dwFileOffsetLow: windows.DWORD, dwNumberOfBytesToMap: windows.SIZE_T) callconv(windows.WINAPI) ?windows.LPVOID;

    pub extern "kernel32" fn UnmapViewOfFile(lpBaseAddress: windows.LPCVOID) callconv(windows.WINAPI) windows.BOOL;
};

const Operation = union(enum) {
    ReadFile: struct {
        file_info: PlatformHandle,
        offset: i64,
        buffer: []u8,
        io_status_block: windows.IO_STATUS_BLOCK,
    },

    WriteFile: struct {
        file_info: PlatformHandle,
        offset: i64,
        buffer: []u8,
        io_status_block: windows.IO_STATUS_BLOCK,
    },

    CopyRange: struct {
        allocator: std.mem.Allocator,
        out_file: PlatformHandle,
        in_file: PlatformHandle,
        out_file_offset: usize,
        in_file_offset: usize,
        buffer: []u8,
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
    self: *Self,
    pending_operation: ?ActiveOperation,
};

const PendingOperation = struct {
    operation_idx: usize,
    event_handle: windows.HANDLE,
};

const MaxSimulatenousOperations = 63;

const Self = @This();

allocator: std.mem.Allocator,

working_dir: std.fs.Dir,
operation_slots: [MaxSimulatenousOperations]OperationSlot,
available_operation_slots: std.ArrayList(usize),
completion_port: windows.HANDLE,
implementation: PatchIO.Implementation,

pub fn lockDirectoryRecursively(implementation: PatchIO.Implementation, path: []const u8, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.LockedDirectory {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    var locked_dir: PatchIO.LockedDirectory = .{
        .path_buffer = undefined,
        .handle = undefined,
        .files = std.ArrayList(PatchIO.FileInfo).init(allocator),
        .directories = std.ArrayList(PatchIO.DirectoryInfo).init(allocator),
        .allocator = allocator,
    };

    var target_dir = self.working_dir.openIterableDir(path, .{}) catch return error.FailedToOpenDir;

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
                        var file_info = @as(*std.os.windows.FILE_DIRECTORY_INFORMATION, @ptrCast(@alignCast(&file_information_buf[offset])));
                        offset += file_info.NextEntryOffset;

                        var file_name = @as([*]u16, @ptrCast(&file_info.FileName))[0 .. file_info.FileNameLength / 2];

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
                            path_buffer_offset += @as(u32, @intCast(end_idx));

                            var is_directory = file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0;
                            var nt_name = windows.UNICODE_STRING{
                                .Length = @as(c_ushort, @intCast(file_info.FileNameLength)),
                                .MaximumLength = @as(c_ushort, @intCast(file_info.FileNameLength)),
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
                                windows.GENERIC_READ | @as(windows.ULONG, if (is_directory) windows.SYNCHRONIZE else windows.FILE_FLAG_OVERLAPPED), //DesiredAccess
                                &attr,
                                &file_io,
                                null, //AllocationSize
                                windows.FILE_ATTRIBUTE_NORMAL, // FileAttributes
                                windows.FILE_SHARE_READ, // ShareAccess
                                windows.FILE_OPEN, // CreateDisposition
                                if (is_directory) windows.FILE_SYNCHRONOUS_IO_NONALERT else 0, // CreateOptions
                                null, //EaBuffer
                                0, //EaLength
                            );

                            if (rc != .SUCCESS) {
                                std.log.err("NtCreateFile for {s} failed with error {}", .{ file_name_buffer[0..end_idx], rc });
                                return error.Unexpected;
                            }

                            if (!is_directory) {
                                _ = windows.CreateIoCompletionPort(file_handle, self.completion_port, 1, 0) catch unreachable;
                                try locked_dir.files.append(.{
                                    .handle = file_handle,
                                    .path_offset = prev_offset,
                                    .path_len = @as(u32, @intCast(end_idx)),
                                    .size = @as(u64, @intCast(file_info.EndOfFile)),
                                });
                            } else {
                                try directories_to_query.append(.{ .handle = file_handle, .path_offset = prev_offset, .path_len = @as(u32, @intCast(end_idx)) });

                                try locked_dir.directories.append(.{
                                    .handle = file_handle,
                                    .path_offset = prev_offset,
                                    .path_len = @as(u32, @intCast(end_idx)),
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
                else => std.log.warn("Unexpected NTStatus when querying directory: 0x{x}\n", .{@intFromEnum(status)}),
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
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    self.available_operation_slots.deinit();

    self.allocator.destroy(self);
}

fn readFile(implementation: PatchIO.Implementation, handle: PlatformHandle, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    // If there are no slots left we keep ticking until one becomes available.
    while (self.available_operation_slots.items.len == 0) {
        implementation.tick(implementation);
    }

    var slot_idx = self.available_operation_slots.orderedRemove(self.available_operation_slots.items.len - 1);
    var operation = &self.operation_slots[slot_idx];

    std.debug.assert(operation.pending_operation == null);

    operation.pending_operation = .{
        .operation = .{
            .ReadFile = .{
                .file_info = handle,
                .offset = @as(i64, @intCast(offset)),
                .buffer = buffer,
                .io_status_block = undefined,
            },
        },
        .callback = callback,
        .callback_context = callback_ctx,
        .overlapped = windows.OVERLAPPED{
            .Internal = 0,
            .InternalHigh = 0,
            .DUMMYUNIONNAME = .{
                .DUMMYSTRUCTNAME = .{
                    .Offset = @as(u32, @truncate(offset)),
                    .OffsetHigh = @as(u32, @truncate(offset >> 32)),
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

    var len_to_read = @as(u32, @intCast(read_file_op.buffer.len));

    if (len_to_read % 512 != 0) {
        len_to_read += (512 - len_to_read % 512);
    }

    if (windows.kernel32.ReadFile(handle, read_file_op.buffer.ptr, len_to_read, null, &operation.pending_operation.?.overlapped) != 0) {
        operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);
        operation.pending_operation = null;
        self.available_operation_slots.appendAssumeCapacity(slot_idx);
        return;
    }

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

fn writeFile(implementation: PatchIO.Implementation, handle: PlatformHandle, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque) PatchIO.PatchIOErrors!void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    // If there are no slots left we keep ticking until one becomes available.
    while (self.available_operation_slots.items.len == 0) {
        implementation.tick(implementation);
    }

    var slot_idx = self.available_operation_slots.orderedRemove(self.available_operation_slots.items.len - 1);
    var operation = &self.operation_slots[slot_idx];

    std.debug.assert(operation.pending_operation == null);

    operation.pending_operation = .{
        .operation = .{
            .WriteFile = .{
                .file_info = handle,
                .offset = @as(i64, @intCast(offset)),
                .buffer = buffer,
                .io_status_block = undefined,
            },
        },
        .callback = callback,
        .callback_context = callback_ctx,
        .overlapped = windows.OVERLAPPED{
            .Internal = 0,
            .InternalHigh = 0,
            .DUMMYUNIONNAME = .{
                .DUMMYSTRUCTNAME = .{
                    .Offset = @as(u32, @truncate(offset)),
                    .OffsetHigh = @as(u32, @truncate(offset >> 32)),
                },
            },
            .hEvent = null,
        },
        .slot_idx = slot_idx,
    };

    var write_file_op = &operation.pending_operation.?.operation.WriteFile;
    operation.pending_operation.?.overlapped.hEvent = null;

    var was_successful = windows.kernel32.WriteFile(
        handle,
        write_file_op.buffer.ptr,
        @as(u32, @intCast(write_file_op.buffer.len)),
        null,
        &operation.pending_operation.?.overlapped,
    );

    if (was_successful != 0) {
        operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);
        operation.pending_operation = null;
        self.available_operation_slots.appendAssumeCapacity(slot_idx);
        return;
    }

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

pub fn mergeFiles(implementation: PatchIO.Implementation, out_file: PlatformHandle, in_files: []PlatformHandle, total_bytes_to_copy: usize, callback: *const fn (*anyopaque) void, callback_ctx: *anyopaque, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    var out_file_zig_std = std.fs.File{ .handle = out_file };
    var file_len = out_file_zig_std.getEndPos() catch return PatchIO.PatchIOErrors.Unexpected;
    out_file_zig_std.setEndPos(total_bytes_to_copy + file_len) catch return PatchIO.PatchIOErrors.Unexpected;

    var mapped_file_maybe = kernel32_extra.CreateFileMappingA(out_file, null, windows.PAGE_READWRITE, 0, 0, null);
    if (mapped_file_maybe == null) {
        var last_err = windows.kernel32.GetLastError();
        std.log.err("Failed to CreateFileMapping for output. Error: {}", .{last_err});
        return error.Unexpected;
    }

    var mapped_file = mapped_file_maybe.?;
    defer windows.CloseHandle(mapped_file);

    var out_data_ptr_maybe = kernel32_extra.MapViewOfFile(mapped_file, windows.SECTION_MAP_WRITE, 0, 0, file_len + total_bytes_to_copy);
    if (out_data_ptr_maybe == null) {
        var last_err = windows.kernel32.GetLastError();
        std.log.err("Failed to MapViewOfFile for output. Error: {}", .{last_err});
        return error.Unexpected;
    }

    var out_data_ptr = out_data_ptr_maybe.?;
    defer _ = kernel32_extra.UnmapViewOfFile(out_data_ptr);

    var write_offset: usize = file_len;
    for (in_files) |in_file| {
        var in_file_zig_std = std.fs.File{ .handle = in_file };
        var in_file_len = in_file_zig_std.getEndPos() catch return error.Unexpected;

        var mapped_in_file_maybe = kernel32_extra.CreateFileMappingA(in_file, null, windows.PAGE_READONLY, 0, 0, null);
        if (mapped_in_file_maybe == null) {
            var last_err = windows.kernel32.GetLastError();
            std.log.err("Failed to CreateFileMapping for input. Error: {}", .{last_err});
            return error.Unexpected;
        }

        var mapped_in_file = mapped_in_file_maybe.?;
        defer windows.CloseHandle(mapped_in_file);

        var in_data_ptr_maybe = kernel32_extra.MapViewOfFile(mapped_in_file, windows.SECTION_MAP_READ, 0, 0, in_file_len);
        if (in_data_ptr_maybe == null) {
            var last_err = windows.kernel32.GetLastError();
            std.log.err("Failed to MapViewOfFile for input. Error: {}", .{last_err});
            return error.Unexpected;
        }

        var in_data_ptr = in_data_ptr_maybe.?;
        defer _ = kernel32_extra.UnmapViewOfFile(in_data_ptr);

        @memcpy(@as([*]u8, @ptrCast(out_data_ptr))[write_offset .. write_offset + in_file_len], @as([*]u8, @ptrCast(in_data_ptr))[0..in_file_len]);
        write_offset += in_file_len;
    }

    _ = allocator;
    _ = callback;
    _ = callback_ctx;
    _ = self;
}

pub fn createFile(implementation: PatchIO.Implementation, parent_dir: PlatformHandle, file_path: []const u8) PatchIO.PatchIOErrors!PatchIO.PlatformHandle {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    const path_w = windows.sliceToPrefixedFileW(file_path) catch return PatchIO.PatchIOErrors.OutOfMemory;
    var span = path_w.span();

    var nt_name = windows.UNICODE_STRING{
        .Length = @as(c_ushort, @intCast(span.len * 2)),
        .MaximumLength = @as(c_ushort, @intCast(span.len * 2)),
        .Buffer = @constCast(&path_w.data),
    };

    var attr = windows.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
        .RootDirectory = parent_dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: windows.HANDLE = undefined;

    var file_io: windows.IO_STATUS_BLOCK = undefined;

    const rc = ntdll.NtCreateFile(
        &file_handle,
        windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES | @as(windows.ULONG, windows.FILE_FLAG_OVERLAPPED), //DesiredAccess
        &attr,
        &file_io,
        null, //AllocationSize
        0, // FileAttributes
        windows.FILE_SHARE_READ, // ShareAccess
        windows.FILE_CREATE, // CreateDisposition
        0, // CreateOptions
        null, //EaBuffer
        0, //EaLength
    );

    if (rc != .SUCCESS) {
        return windows.unexpectedStatus(rc);
    }

    _ = windows.CreateIoCompletionPort(file_handle, self.completion_port, 1, 0) catch unreachable;

    return file_handle;
}

pub fn openFile(implementation: PatchIO.Implementation, parent_dir: PlatformHandle, file_path: []const u8) PatchIO.PatchIOErrors!PatchIO.PlatformHandle {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    const path_w = windows.sliceToPrefixedFileW(file_path) catch return PatchIO.PatchIOErrors.OutOfMemory;
    var span = path_w.span();

    var nt_name = windows.UNICODE_STRING{
        .Length = @as(c_ushort, @intCast(span.len * 2)),
        .MaximumLength = @as(c_ushort, @intCast(span.len * 2)),
        .Buffer = @constCast(&path_w.data),
    };

    var attr = windows.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
        .RootDirectory = parent_dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: windows.HANDLE = undefined;

    var file_io: windows.IO_STATUS_BLOCK = undefined;

    const rc = ntdll.NtCreateFile(
        &file_handle,
        windows.GENERIC_READ | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES | @as(windows.ULONG, windows.FILE_FLAG_OVERLAPPED) | windows.SYNCHRONIZE, //DesiredAccess
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

    _ = windows.CreateIoCompletionPort(file_handle, self.completion_port, 1, 0) catch unreachable;

    return file_handle;
}

fn tick(implementation: PatchIO.Implementation) void {
    var self = @as(*Self, @ptrCast(@alignCast(implementation.instance_data)));

    var entries: [64]windows.OVERLAPPED_ENTRY = std.mem.zeroes([64]windows.OVERLAPPED_ENTRY);
    var num_entries_removed: u32 = 0;
    if (windows.kernel32.GetQueuedCompletionStatusEx(self.completion_port, &entries, entries.len, &num_entries_removed, 0, windows.TRUE) == 0) {
        return;
    }

    for (entries[0..num_entries_removed]) |*entry| {
        var parent_ptr = @fieldParentPtr(ActiveOperation, "overlapped", entry.lpOverlapped);
        var slot_idx = parent_ptr.slot_idx;

        var operation = &self.operation_slots[slot_idx];

        operation.pending_operation.?.callback(operation.pending_operation.?.callback_context);

        operation.pending_operation = null;
        self.available_operation_slots.appendAssumeCapacity(slot_idx);
    }
}

pub fn create(working_dir: std.fs.Dir, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.Implementation {
    var self = allocator.create(Self) catch return error.OutOfMemory;

    // zig fmt: off
    self.* = .{ 
        .allocator = allocator, 
        .working_dir = working_dir,
        .operation_slots = undefined,
        .available_operation_slots = std.ArrayList(usize).initCapacity(allocator, MaxSimulatenousOperations) catch return error.Unexpected,
        .completion_port = try windows.CreateIoCompletionPort(windows.INVALID_HANDLE_VALUE, null, 0, 1),
        .implementation = undefined,
    };
    // zig fmt: on

    for (0..MaxSimulatenousOperations) |idx| {
        self.available_operation_slots.appendAssumeCapacity(idx);
        self.operation_slots[idx] = .{
            .pending_operation = null,
            .self = self,
        };
    }

    self.implementation = .{
        .instance_data = self,
        .lock_directory = lockDirectoryRecursively,
        .unlock_directory = unlockDirectory,
        .destroy = destroy,
        .create_file = createFile,
        .open_file = openFile,
        .read_file = readFile,
        .write_file = writeFile,
        .merge_files = mergeFiles,
        .tick = tick,
    };

    return self.implementation;
}
