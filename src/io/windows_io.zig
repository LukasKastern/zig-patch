const std = @import("std");
const PatchIO = @import("patch_io.zig");

const windows = std.os.windows;
const ntdll = windows.ntdll;

const FileInformationBufferSize = 4096;
const DefaultPathBufferSize = 1024 * 1024;

const Self = @This();

allocator: std.mem.Allocator,

pub fn lockDirectoryRecursively(implementation: PatchIO.Implementation, path: []const u8, allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.LockedDirectory {
    _ = implementation;

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
                          
                            if (file_info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
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
    self.allocator.destroy(self);
}

pub fn create(allocator: std.mem.Allocator) PatchIO.PatchIOErrors!PatchIO.Implementation {
    var self = allocator.create(Self) catch return error.OutOfMemory;
    self.* = .{ .allocator = allocator };

    return .{
        .instance_data = self,
        .lock_directory = lockDirectoryRecursively,
        .unlock_directory = unlockDirectory,
        .destroy = destroy,
    };
}
