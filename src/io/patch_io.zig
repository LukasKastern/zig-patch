const std = @import("std");

const PlatformIO = if (builtin.os.tag == .windows) @import("windows_io.zig") else @import("linux_io.zig");

const builtin = @import("builtin");

pub const PlatformHandle = if (builtin.os.tag == .windows) *anyopaque else i32;

pub const FileInfo = struct {
    const SelfFile = @This();

    handle: PlatformHandle,

    // Offset+Size of the path in the LockedDirectory name_buffer.
    path_offset: u32,
    path_len: u32,

    size: u64,

    pub fn resolvePath(self: SelfFile, directory: LockedDirectory) []const u8 {
        return directory.path_buffer[self.path_offset .. self.path_offset + self.path_len];
    }
};

pub const DirectoryInfo = struct {
    const SelfDir = @This();

    handle: PlatformHandle,

    // Offset+Size of the path in the LockedDirectory name_buffer.
    path_offset: u32,
    path_len: u32,

    pub fn resolvePath(self: SelfDir, directory: LockedDirectory) []const u8 {
        return directory.path_buffer[self.path_offset .. self.path_offset + self.path_len];
    }
};

pub const LockedDirectory = struct {
    allocator: std.mem.Allocator,
    handle: PlatformHandle,
    files: std.ArrayList(FileInfo),
    directories: std.ArrayList(DirectoryInfo),
    path_buffer: []u8,
};

pub const PatchIOErrors = error{ OutOfMemory, FailedToOpenDir, FileNotFound, Unexpected };

pub const Implementation = struct {
    const ImplSelf = @This();

    instance_data: *anyopaque,
    lock_directory: *const fn (ImplSelf, []const u8, std.mem.Allocator) PatchIOErrors!LockedDirectory,
    unlock_directory: *const fn (ImplSelf, locked_directory: LockedDirectory) void,
    destroy: *const fn (ImplSelf) void,
    create_file: *const fn (ImplSelf, PlatformHandle, []const u8) PatchIOErrors!PlatformHandle,
    create_directory: *const fn (ImplSelf, PlatformHandle, []const u8) PatchIOErrors!PlatformHandle,
    open_file: *const fn (ImplSelf, PlatformHandle, []const u8) PatchIOErrors!PlatformHandle,
    read_file: *const fn (ImplSelf, PlatformHandle, usize, []u8, *const fn (*anyopaque) void, *anyopaque) PatchIOErrors!void,
    write_file: *const fn (ImplSelf, PlatformHandle, usize, []const u8, *const fn (*anyopaque) void, *anyopaque) PatchIOErrors!void,
    tick: *const fn (ImplSelf) void,
    close_handle: *const fn (ImplSelf, PlatformHandle) void,
};

const Self = @This();

impl: Implementation,

pub fn init(working_dir: std.fs.Dir, allocator: std.mem.Allocator) PatchIOErrors!Self {
    return .{
        .impl = try PlatformIO.create(working_dir, allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.impl.destroy(self.impl);
}

// Locks are directory and returns a directory information structure.
pub fn lockDirectory(self: *const Self, path: []const u8, allocator: std.mem.Allocator) PatchIOErrors!LockedDirectory {
    return self.impl.lock_directory(self.impl, path, allocator);
}

pub fn unlockDirectory(self: *const Self, locked_dir: LockedDirectory) void {
    return self.impl.unlock_directory(self.impl, locked_dir);
}

pub fn readFile(self: *Self, handle: PlatformHandle, offset: usize, buffer: []u8, callback: *const fn (*anyopaque) void, callback_context: *anyopaque) PatchIOErrors!void {
    return self.impl.read_file(self.impl, handle, offset, buffer, callback, callback_context);
}

pub fn tick(self: *Self) void {
    return self.impl.tick(self.impl);
}

pub fn writeFile(self: *Self, handle: PlatformHandle, offset: usize, buffer: []const u8, callback: *const fn (*anyopaque) void, callback_context: *anyopaque) PatchIOErrors!void {
    return self.impl.write_file(self.impl, handle, offset, buffer, callback, callback_context);
}

pub fn createFile(self: *Self, parent_dir: PlatformHandle, file_path: []const u8) PatchIOErrors!PlatformHandle {
    return self.impl.create_file(self.impl, parent_dir, file_path);
}

pub fn createDirectory(self: *Self, parent_dir: PlatformHandle, directory_name: []const u8) PatchIOErrors!PlatformHandle {
    return self.impl.create_directory(self.impl, parent_dir, directory_name);
}

pub fn closeHandle(self: *Self, handle: PlatformHandle) void {
    self.impl.close_handle(self.impl, handle);
}

pub fn openFile(self: *Self, parent_dir: PlatformHandle, file_path: []const u8) PatchIOErrors!PlatformHandle {
    return self.impl.open_file(self.impl, parent_dir, file_path);
}

test "Locking directory should return correct files" {
    var io = try init(std.fs.cwd(), std.testing.allocator);
    defer io.deinit();

    // Create test data
    {
        const cwd = std.fs.cwd();

        try cwd.deleteTree("test");

        try cwd.makeDir("test");
        try cwd.makeDir("test/test_dir");

        var file_nested = try cwd.createFile("test/test_dir/file_in_nested_dir.txt", .{});
        defer file_nested.close();

        var file_one = try cwd.createFile("test/file_one.txt", .{});
        defer file_one.close();

        var file_two = try cwd.createFile("test/file_two.txt", .{});
        defer file_two.close();
    }

    var locked_dir = try io.lockDirectory("test", std.testing.allocator);
    defer io.unlockDirectory(locked_dir);

    try std.testing.expectEqual(@as(usize, 3), locked_dir.files.items.len);
    try std.testing.expectEqualSlices(u8, "file_one.txt", locked_dir.files.items[0].resolvePath(locked_dir));
    try std.testing.expectEqualSlices(u8, "file_two.txt", locked_dir.files.items[1].resolvePath(locked_dir));
    try std.testing.expectEqualSlices(u8, "test_dir/file_in_nested_dir.txt", locked_dir.files.items[2].resolvePath(locked_dir));

    try std.testing.expectEqual(@as(usize, 1), locked_dir.directories.items.len);
    try std.testing.expectEqualSlices(u8, "test_dir/", locked_dir.directories.items[0].resolvePath(locked_dir));
}
