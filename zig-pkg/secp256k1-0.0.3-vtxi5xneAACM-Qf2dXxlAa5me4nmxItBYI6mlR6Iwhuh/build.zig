const std = @import("std");

fn buildSecp256k1(libsecp_c: *std.Build.Dependency, b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "libsecp",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/secp256k1.zig"),
        }),
    });

    lib.root_module.addIncludePath(libsecp_c.path(""));
    lib.root_module.addIncludePath(libsecp_c.path("src"));
    lib.root_module.addIncludePath(libsecp_c.path("include"));

    lib.root_module.addCSourceFiles(.{
        .root = libsecp_c.path(""),
        .flags = &.{
            "-DENABLE_MODULE_RECOVERY=1",
            "-DENABLE_MODULE_SCHNORRSIG=1",
            "-DENABLE_MODULE_ECDH=1",
            "-DENABLE_MODULE_EXTRAKEYS=1",
        },
        .files = &.{
            "./src/secp256k1.c",
            "./src/precomputed_ecmult.c",
            "./src/precomputed_ecmult_gen.c",
        },
    });
    lib.root_module.addCMacro("USE_FIELD_10X26", "1");
    lib.root_module.addCMacro("USE_SCALAR_8X32", "1");
    lib.root_module.addCMacro("USE_ENDOMORPHISM", "1");
    lib.root_module.addCMacro("USE_NUM_NONE", "1");
    lib.root_module.addCMacro("USE_FIELD_INV_BUILTIN", "1");
    lib.root_module.addCMacro("USE_SCALAR_INV_BUILTIN", "1");

    lib.installHeadersDirectory(libsecp_c.path("src"), "", .{ .include_extensions = &.{".h"} });
    lib.installHeadersDirectory(libsecp_c.path("include/"), "", .{ .include_extensions = &.{".h"} });
    lib.root_module.linkSystemLibrary("c", .{});

    return lib;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libsecp_c = b.dependency("libsecp256k1", .{});

    const libsecp256k1 = buildSecp256k1(libsecp_c, b, target, optimize);

    const module = b.addModule("secp256k1", .{
        .root_source_file = b.path("src/secp256k1.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addIncludePath(libsecp_c.path("/"));
    module.addIncludePath(libsecp_c.path("src/"));
    module.linkLibrary(libsecp256k1);

    b.installArtifact(libsecp256k1);

    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/secp256k1.zig"),
            .target = target,
        }),
    });
    lib_unit_tests.root_module.linkLibrary(libsecp256k1);
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const example_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples.zig"),
            .target = target,
        }),
    });
    example_tests.root_module.linkLibrary(libsecp256k1);
    const run_example_test = b.addRunArtifact(example_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_example_test.step);
}
