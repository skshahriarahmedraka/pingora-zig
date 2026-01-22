//! pingora-zig build configuration
//!
//! Build system for the Pingora Zig port - a high-performance proxy framework.
//!
//! Ported from: https://github.com/cloudflare/pingora
//!
//! Build targets:
//!   zig build              - Build the library
//!   zig build test         - Run unit tests
//!   zig build test-tls     - Run TLS/OpenSSL tests
//!   zig build test-quiche  - Run QUIC/HTTP3 tests (requires quiche)
//!   zig build bench        - Run benchmarks
//!   zig build example-simple-proxy      - Build simple reverse proxy example
//!   zig build example-load-balancing    - Build load balancing proxy example
//!   zig build example-caching           - Build caching proxy example
//!   zig build examples                  - Build all examples
//!
//! Build options:
//!   -Dopenssl=true/false   - Enable/disable OpenSSL TLS support (default: true)
//!   -Dquiche=true/false    - Enable/disable quiche QUIC/HTTP3 support (default: false)
//!   -Dbrotli=true/false    - Enable/disable Brotli compression (default: false)

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options
    const enable_openssl = b.option(bool, "openssl", "Enable OpenSSL TLS support") orelse true;
    const enable_quiche = b.option(bool, "quiche", "Enable quiche QUIC/HTTP3 support") orelse false;
    const enable_brotli = b.option(bool, "brotli", "Enable Brotli compression support") orelse false;

    // Create build options for conditional compilation
    const options = b.addOptions();
    options.addOption(bool, "enable_brotli", enable_brotli);

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

    // Link brotli if enabled
    if (enable_brotli) {
        lib_unit_tests.linkSystemLibrary("brotlienc");
        lib_unit_tests.linkSystemLibrary("brotlidec");
    }

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

    // Quiche QUIC/HTTP3 tests (separate to allow running without quiche)
    if (enable_quiche) {
        const quiche_test_mod = b.addModule("quiche_test", .{
            .root_source_file = b.path("src/quiche_ffi.zig"),
            .target = target,
            .optimize = optimize,
        });

        const quiche_tests = b.addTest(.{
            .root_module = quiche_test_mod,
        });

        // Link quiche and its dependencies
        quiche_tests.linkSystemLibrary("quiche");
        quiche_tests.linkLibC();

        const run_quiche_tests = b.addRunArtifact(quiche_tests);

        const quiche_test_step = b.step("test-quiche", "Run QUIC/HTTP3 quiche integration tests");
        quiche_test_step.dependOn(&run_quiche_tests.step);
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

    // ============================================
    // Example executables
    // ============================================

    // Helper function to create example executable
    const ExampleConfig = struct {
        name: []const u8,
        source: []const u8,
        description: []const u8,
    };

    const examples = [_]ExampleConfig{
        .{
            .name = "example-simple-proxy",
            .source = "examples/simple_reverse_proxy.zig",
            .description = "Build simple reverse proxy example",
        },
        .{
            .name = "example-load-balancing",
            .source = "examples/load_balancing_proxy.zig",
            .description = "Build load balancing proxy example",
        },
        .{
            .name = "example-caching",
            .source = "examples/caching_proxy.zig",
            .description = "Build caching proxy example",
        },
    };

    // Create a step that builds all examples
    const examples_step = b.step("examples", "Build all examples");

    inline for (examples) |example| {
        // Create module for this example
        const example_mod = b.addModule(example.name, .{
            .root_source_file = b.path(example.source),
            .target = target,
            .optimize = optimize,
        });

        // Add dependency on the main library
        example_mod.addImport("pingora", lib_mod);

        // Create executable
        const example_exe = b.addExecutable(.{
            .name = example.name,
            .root_module = example_mod,
        });

        // Link required system libraries
        example_exe.linkSystemLibrary("z");
        example_exe.linkLibC();

        if (enable_openssl) {
            example_exe.linkSystemLibrary("ssl");
            example_exe.linkSystemLibrary("crypto");
        }

        if (enable_brotli) {
            example_exe.linkSystemLibrary("brotlienc");
            example_exe.linkSystemLibrary("brotlidec");
        }

        // Install the example executable
        b.installArtifact(example_exe);

        // Create individual build step for this example
        const example_step = b.step(example.name, example.description);
        example_step.dependOn(&example_exe.step);

        // Add to the "examples" step
        examples_step.dependOn(&example_exe.step);
    }

    // ============================================
    // Run example targets
    // ============================================

    // Add run targets for examples
    inline for (examples) |example| {
        const run_name = "run-" ++ example.name;
        const run_desc = "Run " ++ example.name;

        // Create module for run target
        const run_mod = b.addModule(run_name, .{
            .root_source_file = b.path(example.source),
            .target = target,
            .optimize = optimize,
        });
        run_mod.addImport("pingora", lib_mod);

        const run_exe = b.addExecutable(.{
            .name = run_name,
            .root_module = run_mod,
        });

        run_exe.linkSystemLibrary("z");
        run_exe.linkLibC();

        if (enable_openssl) {
            run_exe.linkSystemLibrary("ssl");
            run_exe.linkSystemLibrary("crypto");
        }

        if (enable_brotli) {
            run_exe.linkSystemLibrary("brotlienc");
            run_exe.linkSystemLibrary("brotlidec");
        }

        const run_artifact = b.addRunArtifact(run_exe);

        // Allow passing arguments to the example
        if (b.args) |args| {
            run_artifact.addArgs(args);
        }

        const run_step = b.step(run_name, run_desc);
        run_step.dependOn(&run_artifact.step);
    }
}
