const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("wharf-zig", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_exe = b.addTestExe("test", "src/main.zig");
    const install_test = b.addInstallArtifact(test_exe);

    { // >>> TEST - BUILD ONLY >>>
        test_exe.setTarget(target);
        test_exe.setBuildMode(mode);

        const install_test_step = b.step("build-test", "Build unit tests");
        install_test_step.dependOn(&install_test.step);

        //const main_tests = b.addTest("src/tests.zig");
        //install_test_step.dependOn(&main_tests.step);
    } // <<< TEST - BUILD ONLY <<<

    { // >>> TEST - BUILD AND RUN >>>
        const run_test_cmd = test_exe.run();
        run_test_cmd.step.dependOn(&install_test.step);

        // Test executables need the zig command/path as the first argument.
        // Not passing it here because it's done implicitely.
        // run_test_cmd.addArg("zig");

        const run_test_step = b.step("test", "Run unit tests");
        run_test_step.dependOn(&run_test_cmd.step);
    } // <<< TEST - BUILD AND RUN <<<

}
