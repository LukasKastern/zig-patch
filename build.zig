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

    var clap = b.dependency("zig_clap", .{}).module("clap");

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

    const zstd = b.addStaticLibrary(.{
        .name = "zstd",
        .target = target,
        .optimize = mode,
    });

    zstd.linkLibC();

    const zstd_root = "third_party/zstd-dev/lib/";

    zstd.addCSourceFiles(&.{
        zstd_root ++ "/common/debug.c",
        zstd_root ++ "/common/entropy_common.c",
        zstd_root ++ "/common/error_private.c",
        zstd_root ++ "/common/fse_decompress.c",
        zstd_root ++ "/common/pool.c",
        zstd_root ++ "/common/threading.c",
        zstd_root ++ "/common/xxhash.c",
        zstd_root ++ "/common/zstd_common.c",

        zstd_root ++ "/compress/fse_compress.c",
        zstd_root ++ "/compress/hist.c",
        zstd_root ++ "/compress/huf_compress.c",
        zstd_root ++ "/compress/zstd_compress.c",
        zstd_root ++ "/compress/zstd_compress_literals.c",
        zstd_root ++ "/compress/zstd_compress_sequences.c",
        zstd_root ++ "/compress/zstd_compress_superblock.c",
        zstd_root ++ "/compress/zstd_double_fast.c",
        zstd_root ++ "/compress/zstd_fast.c",
        zstd_root ++ "/compress/zstd_lazy.c",
        zstd_root ++ "/compress/zstd_ldm.c",
        zstd_root ++ "/compress/zstd_opt.c",
        zstd_root ++ "/compress/zstdmt_compress.c",

        zstd_root ++ "/decompress/huf_decompress.c",
        zstd_root ++ "/decompress/zstd_ddict.c",
        zstd_root ++ "/decompress/zstd_decompress.c",
        zstd_root ++ "/decompress/zstd_decompress_block.c",
    }, &.{});

    zstd.addIncludePath(.{ .path = zstd_root });

    const exe = b.addExecutable(.{ .name = "zig-patch", .root_source_file = .{ .path = "src/main.zig" }, .target = target, .optimize = mode });

    b.installArtifact(exe);

    exe.linkLibrary(zstd);
    exe.linkLibrary(brotli_common);
    exe.linkLibrary(brotli_enc);
    exe.linkLibrary(brotli_dec);
    exe.linkLibrary(zlib_dep.artifact("z"));
    exe.addIncludePath(.{ .path = zstd_root });

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
    test_exe.addIncludePath(.{ .path = zstd_root });

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
