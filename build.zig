const std = @import("std");
const zlib = @import("third_party/zig-zlib/zlib.zig");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});

    var brotli = b.addStaticLibrary(.{ .name = "Brotli", .target = target, .optimize = .ReleaseFast });

    brotli.addCSourceFiles(&.{
        "third_party\\brotli-master\\c\\common\\constants.c",
        "third_party\\brotli-master\\c\\common\\context.c",
        "third_party\\brotli-master\\c\\common\\dictionary.c",
        "third_party\\brotli-master\\c\\common\\platform.c",
        "third_party\\brotli-master\\c\\common\\shared_dictionary.c",
        "third_party\\brotli-master\\c\\common\\transform.c",

        "third_party\\brotli-master\\c\\dec\\bit_reader.c",
        "third_party\\brotli-master\\c\\dec\\decode.c",
        "third_party\\brotli-master\\c\\dec\\huffman.c",
        "third_party\\brotli-master\\c\\dec\\state.c",

        "third_party\\brotli-master\\c\\enc\\backward_references_hq.c",
        "third_party\\brotli-master\\c\\enc\\backward_references.c",
        "third_party\\brotli-master\\c\\enc\\bit_cost.c",
        "third_party\\brotli-master\\c\\enc\\block_splitter.c",
        "third_party\\brotli-master\\c\\enc\\brotli_bit_stream.c",
        "third_party\\brotli-master\\c\\enc\\cluster.c",
        "third_party\\brotli-master\\c\\enc\\command.c",
        "third_party\\brotli-master\\c\\enc\\compound_dictionary.c",
        "third_party\\brotli-master\\c\\enc\\compress_fragment_two_pass.c",
        "third_party\\brotli-master\\c\\enc\\compress_fragment.c",
        "third_party\\brotli-master\\c\\enc\\dictionary_hash.c",
        "third_party\\brotli-master\\c\\enc\\encode.c",
        "third_party\\brotli-master\\c\\enc\\encoder_dict.c",
        "third_party\\brotli-master\\c\\enc\\entropy_encode.c",
        "third_party\\brotli-master\\c\\enc\\fast_log.c",
        "third_party\\brotli-master\\c\\enc\\histogram.c",
        "third_party\\brotli-master\\c\\enc\\literal_cost.c",
        "third_party\\brotli-master\\c\\enc\\memory.c",
        "third_party\\brotli-master\\c\\enc\\metablock.c",
        "third_party\\brotli-master\\c\\enc\\static_dict.c",
        "third_party\\brotli-master\\c\\enc\\utf8_util.c",
    }, &.{});
    brotli.addIncludePath("third_party\\brotli-master\\c\\include");
    brotli.linkLibC();
    brotli.install();

    const exe = b.addExecutable(.{ .name = "wharf-zig", .root_source_file = .{ .path = "src/main.zig" }, .target = target, .optimize = mode });

    exe.addIncludePath("third_party\\brotli-master\\c\\include");
    exe.addIncludePath("third_party\\zig-zlib\\zlib");
    exe.install();

    var lib = zlib.create(b, target, mode);
    exe.linkLibrary(brotli);
    exe.linkLibrary(lib.step);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_exe = b.addTest(.{ .name = "test", .target = target, .optimize = mode, .kind = .test_exe, .root_source_file = .{ .path = "src/main.zig" } });
    test_exe.linkLibrary(brotli);
    test_exe.addIncludePath("third_party\\brotli-master\\c\\include");
    test_exe.addIncludePath("third_party\\zig-zlib\\zlib");

    test_exe.linkLibrary(lib.step);

    const install_test = b.addInstallArtifact(test_exe);

    { // >>> TEST - BUILD ONLY >>>
        // test_exe.setTarget(target);
        // test_exe.setBuildMode(mode);

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
    
    var clap = b.dependency("zig_clap", .{}).module("clap");
    exe.addModule("clap", clap);
}
