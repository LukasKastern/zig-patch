const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});

    var clap = b.dependency("zig_clap", .{
        .target = target,
        .optimize = mode,
    }).module("clap");

    var zlib_dep = b.dependency("zlib", .{
        .target = target,
        .optimize = mode,
    });

    var brotli_dep = b.dependency("brotli", .{
        .target = target,
        .optimize = mode,
    });

    var brotli_common = brotli_dep.artifact("brotlicommon");
    var brotli_enc = brotli_dep.artifact("brotliencoder");
    var brotli_dec = brotli_dep.artifact("brotlidec");

    const exe = b.addExecutable(.{ .name = "zig-patch", .root_source_file = .{ .path = "src/main.zig" }, .target = target, .optimize = mode });

    const zstd = b.dependency("zstd", .{
        .target = target,
        .optimize = mode,
    }).artifact("zstd");

    b.installArtifact(exe);

    exe.linkLibrary(zstd);
    exe.linkLibrary(brotli_common);
    exe.linkLibrary(brotli_enc);
    exe.linkLibrary(brotli_dec);
    exe.linkLibrary(zlib_dep.artifact("z"));
    // exe.addIncludePath(.{ .path = zstd_root });

    const md5_lib = b.addStaticLibrary(.{
        .name = "md5",
        .target = target,
        .optimize = .ReleaseFast,
    });
    md5_lib.addIncludePath(.{ .path = "./src/md5" });
    md5_lib.addCSourceFiles(&.{"src/md5/md5.cpp"}, &.{ "-fno-rtti", "-fno-exceptions" });
    md5_lib.linkLibCpp();

    exe.linkLibrary(md5_lib);
    exe.addIncludePath(.{ .path = "./src/md5/" });

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_exe = b.addTest(.{ .name = "test", .target = target, .optimize = mode, .root_source_file = .{ .path = "src/main.zig" } });
    test_exe.linkLibrary(brotli_common);
    test_exe.linkLibrary(brotli_enc);
    test_exe.linkLibrary(brotli_dec);
    test_exe.linkLibrary(zlib_dep.artifact("z"));
    test_exe.linkLibrary(zstd);
    // test_exe.addIncludePath(.{ .path = zstd_root });
    test_exe.dwarf_format = .@"32";

    const install_test = b.addInstallArtifact(test_exe, .{});

    { // >>> TEST - BUILD ONLY >>>
        const install_test_step = b.step("build-test", "Build unit tests");
        install_test_step.dependOn(&install_test.step);
    } // <<< TEST - BUILD ONLY <<<

    { // >>> TEST - BUILD AND RUN >>>
        const run_test_cmd = b.addRunArtifact(test_exe);
        run_test_cmd.step.dependOn(&install_test.step);

        const run_test_step = b.step("test", "Run unit tests");
        run_test_step.dependOn(&run_test_cmd.step);
    } // <<< TEST - BUILD AND RUN <<<

    exe.addModule("clap", clap);
}
