// IO Use Cases by zig-patch:
// 1. Scan a directory to create a signature from it
// 2. Read files from that scanned directory
// 3. When applying a patch we lock and copy a directory

const std = @import("std");
const WindowsIO = @import("windows_io.zig");

pub const PlatformHandle = *anyopaque;

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
};

const Self = @This();

impl: Implementation,

pub fn init(allocator: std.mem.Allocator) PatchIOErrors!Self {
    return .{
        .impl = try WindowsIO.create(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.impl.destroy(self.impl);
}

// Locks are directory and returns a directory information structure.
pub fn lockDirectory(self: *Self, path: []const u8, allocator: std.mem.Allocator) PatchIOErrors!LockedDirectory {
    return self.impl.lock_directory(self.impl, path, allocator);
}

pub fn unlockDirectory(self: *Self, locked_dir: LockedDirectory) void {
    return self.impl.unlock_directory(self.impl, locked_dir);
}

test "Locking directory should return correct files" {
    var io = try init(std.testing.allocator);
    defer io.deinit();

    // // Create test data
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
