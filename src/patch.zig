const SignatureFile = @import("signature_file.zig").SignatureFile;
const Operation = @import("block_patching.zig").PatchOperation;

const DeletedFile = union(enum) { Invalid: void, File: []const u8, Data: []u8 };

const Patch = struct {
    const FileSection = std.ArrayList(Operation);

    old: SignatureFile,
    new: SignatureFile,

    sections: FileSection,
};
