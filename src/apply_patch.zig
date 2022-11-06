const std = @import("std");
const PatchHeader = @import("patch_header.zig").PatchHeader;
const SignatureFile = @import("signature_file.zig").SignatureFile;

pub fn createFileStructure(target_dir: std.fs.Dir, patch: *PatchHeader) !void {
    const old_signature = patch.old;
    const new_signature = patch.new;

    // Delete all files that do not exist anymore
    for (old_signature.files.items) |file| {
        var does_file_still_exist = false;

        for (new_signature.files.items) |new_signature_file| {
            does_file_still_exist = does_file_still_exist or std.mem.eql(u8, new_signature_file.name, file.name);
        }

        if (!does_file_still_exist) {
            try target_dir.deleteFile(file.name);
        }
    }

    // Delete all directories that do not exist anymore
    for (old_signature.directories.items) |directory| {
        var does_dir_still_exist = false;

        for (new_signature.directories.items) |new_directory_file| {
            does_dir_still_exist = does_dir_still_exist or std.mem.eql(u8, new_directory_file.path, directory.path);
        }

        if (!does_dir_still_exist) {
            //TODO: Should we check if the directory is empty (lukas)?
            try target_dir.deleteTree(directory.path);
        }
    }

    // Now reverse the order operation and create all directories + files that did not exist in the old signature
    for (new_signature.directories.items) |directory| {
        var did_dir_exist = false;

        for (old_signature.directories.items) |old_directory_file| {
            did_dir_exist = did_dir_exist or std.mem.eql(u8, old_directory_file.path, directory.path);
        }

        if (!did_dir_exist) {
            //TODO: Should we check if the directory is empty (lukas)?
            try target_dir.makePath(directory.path);
        }
    }

    for (new_signature.files.items) |file| {
        var did_file_exist = false;

        for (old_signature.files.items) |old_file| {
            did_file_exist = did_file_exist or std.mem.eql(u8, old_file.name, file.name);
        }

        if (!did_file_exist) {
            //TODO: Should we check if the directory is empty (lukas)?
            var new_file_fs = try target_dir.createFile(file.name, .{});
            new_file_fs.close();
        }
    }
}
