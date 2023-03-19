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

    exe.install();

    exe.linkLibrary(brotli_common);
    exe.linkLibrary(brotli_enc);
    exe.linkLibrary(brotli_dec);
    exe.linkLibrary(zlib_dep.artifact("z"));

    const run_cmd = exe.run();
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

    const install_test = b.addInstallArtifact(test_exe);

    { // >>> TEST - BUILD ONLY >>>
        const install_test_step = b.step("build-test", "Build unit tests");
        install_test_step.dependOn(&install_test.step);
    } // <<< TEST - BUILD ONLY <<<

    { // >>> TEST - BUILD AND RUN >>>
        const run_test_cmd = test_exe.run();
        run_test_cmd.step.dependOn(&install_test.step);

        const run_test_step = b.step("test", "Run unit tests");
        run_test_step.dependOn(&run_test_cmd.step);
    } // <<< TEST - BUILD AND RUN <<<

    var clap = b.dependency("zig_clap", .{}).module("clap");
    exe.addModule("clap", clap);
}
