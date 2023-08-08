const std = @import("std");

pub fn copyFolder(dst: std.fs.Dir, src: std.fs.Dir) !void {
    var tmp_buffer: [1024]u8 = undefined;
    var tmp_allocator = std.heap.FixedBufferAllocator.init(&tmp_buffer);

    var src_name_buffer: [1024]u8 = undefined;
    var src_full_path = try src.realpath("", &src_name_buffer);

    var directories = std.ArrayList(std.fs.Dir).init(tmp_allocator.allocator());
    try directories.append(src);

    var directory_name_buffer: [1024]u8 = undefined;

    var relative_name_buffer: [1024]u8 = undefined;

    while (directories.items.len > 0) {
        var directory = directories.orderedRemove(0);

        var nested_directory_full_name = try directory.realpath("", &directory_name_buffer);

        var is_root_dir = std.mem.eql(u8, src_full_path, nested_directory_full_name);

        defer {
            // We don't want to close the src directory
            if (!is_root_dir) {
                directory.close();
            }
        }

        var relative_name_allocator = std.heap.FixedBufferAllocator.init(&relative_name_buffer);

        var rel_dir_path = try std.fs.path.relative(relative_name_allocator.allocator(), src_full_path, nested_directory_full_name);

        if (rel_dir_path.len > 0) {
            try dst.makePath(rel_dir_path);
        }

        var current_dst_dir: std.fs.Dir = if (is_root_dir) dst else try dst.openDir(rel_dir_path, .{});

        defer {
            if (!is_root_dir) {
                current_dst_dir.close();
            }
        }

        var iteratable_dir = try directory.makeOpenPathIterable("", .{});
        defer iteratable_dir.close();

        var dir_iterator = iteratable_dir.iterate();

        while (try dir_iterator.next()) |entry| {
            switch (entry.kind) {
                .file => {
                    try directory.copyFile(entry.name, current_dst_dir, entry.name, .{});
                },
                .directory => {
                    var nested_dir = try directory.openDir(entry.name, .{});
                    try directories.append(nested_dir);
                },
                else => {},
            }
        }
    }
}
