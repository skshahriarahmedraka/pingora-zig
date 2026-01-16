//! pingora-zig build configuration
//!
//! Build system for the Pingora Zig port - a high-performance proxy framework.
//!
//! Ported from: https://github.com/cloudflare/pingora

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options
    const enable_openssl = b.option(bool, "openssl", "Enable OpenSSL TLS support") orelse true;

    // Main library module
    const lib_mod = b.addModule("pingora", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    // websocket.zig uses zlib for RFC 7692 permessage-deflate
    lib_unit_tests.linkSystemLibrary("z");
    lib_unit_tests.linkLibC();

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // OpenSSL TLS tests (separate to allow running without OpenSSL)
    if (enable_openssl) {
        const tls_test_mod = b.addModule("tls_test", .{
            .root_source_file = b.path("src/openssl.zig"),
            .target = target,
            .optimize = optimize,
        });

        const tls_tests = b.addTest(.{
            .root_module = tls_test_mod,
        });

        // Link OpenSSL
        tls_tests.linkSystemLibrary("ssl");
        tls_tests.linkSystemLibrary("crypto");
        tls_tests.linkLibC();

        const run_tls_tests = b.addRunArtifact(tls_tests);

        const tls_test_step = b.step("test-tls", "Run TLS/OpenSSL integration tests");
        tls_test_step.dependOn(&run_tls_tests.step);
    }

    // Benchmark module
    const bench_mod = b.addModule("bench", .{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast, // Always optimize benchmarks
    });

    // Benchmark executable
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });

    const run_bench = b.addRunArtifact(bench_exe);

    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);

    // Install benchmark executable
    b.installArtifact(bench_exe);
}
