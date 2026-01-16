//! pingora-zig: Benchmarks
//!
//! Benchmark suite for measuring performance of various components.
//! Run with: zig build bench

const std = @import("std");
const lru = @import("lru.zig");
const tinyufo = @import("tinyufo.zig");
const ketama = @import("ketama.zig");

const Timer = std.time.Timer;

/// Number of iterations for benchmarks
const BENCH_ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 10_000;

fn formatDuration(ns: u64) struct { f64, []const u8 } {
    if (ns < 1_000) {
        return .{ @floatFromInt(ns), "ns" };
    } else if (ns < 1_000_000) {
        return .{ @as(f64, @floatFromInt(ns)) / 1_000.0, "µs" };
    } else if (ns < 1_000_000_000) {
        return .{ @as(f64, @floatFromInt(ns)) / 1_000_000.0, "ms" };
    } else {
        return .{ @as(f64, @floatFromInt(ns)) / 1_000_000_000.0, "s" };
    }
}

fn printResult(name: []const u8, total_ns: u64, iterations: usize) void {
    const per_op_ns = total_ns / iterations;
    const total = formatDuration(total_ns);
    const per_op = formatDuration(per_op_ns);
    const ops_per_sec = if (per_op_ns > 0) @as(u64, @intFromFloat(1_000_000_000.0 / @as(f64, @floatFromInt(per_op_ns)))) else 0;

    std.debug.print("  {s:<35} {d:>8.2} {s:<3} total, {d:>8.2} {s:<3}/op, {d:>12} ops/sec\n", .{
        name,
        total[0],
        total[1],
        per_op[0],
        per_op[1],
        ops_per_sec,
    });
}

/// Benchmark LRU operations
fn benchmarkLru(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== LRU Benchmarks ===\n", .{});

    // Setup
    var lru_cache = lru.Lru(u64, 8).init(allocator, 100_000);
    defer lru_cache.deinit();

    // Warmup
    for (0..WARMUP_ITERATIONS) |i| {
        _ = try lru_cache.admit(@intCast(i), @intCast(i), 1);
    }

    // Benchmark admit
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = try lru_cache.admit(@intCast(i + WARMUP_ITERATIONS), @intCast(i), 1);
        }
        const elapsed = timer.read();
        printResult("admit (new keys)", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark admit (existing keys - update)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = try lru_cache.admit(@intCast(i % WARMUP_ITERATIONS), @intCast(i), 1);
        }
        const elapsed = timer.read();
        printResult("admit (existing keys)", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark peek
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = lru_cache.peek(@intCast(i % WARMUP_ITERATIONS));
        }
        const elapsed = timer.read();
        printResult("peek", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark promote
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = lru_cache.promote(@intCast(i % WARMUP_ITERATIONS));
        }
        const elapsed = timer.read();
        printResult("promote", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark TinyUFO operations
fn benchmarkTinyUfo(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== TinyUFO Benchmarks ===\n", .{});

    // Setup
    var cache = try tinyufo.TinyUfo(u64, u64).init(allocator, 50_000, 10_000);
    defer cache.deinit();

    // Warmup - populate cache
    for (0..WARMUP_ITERATIONS) |i| {
        var evicted = try cache.put(@intCast(i), @intCast(i), 1);
        evicted.deinit(allocator);
    }

    // Benchmark put (new keys)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var evicted = try cache.put(@intCast(i + WARMUP_ITERATIONS * 10), @intCast(i), 1);
            evicted.deinit(allocator);
        }
        const elapsed = timer.read();
        printResult("put (with eviction)", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (hits)
    {
        // Re-populate for consistent hit rate
        for (0..1000) |i| {
            var evicted = try cache.put(@intCast(i), @intCast(i), 1);
            evicted.deinit(allocator);
        }

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = cache.get(&@as(u64, @intCast(i % 1000)));
        }
        const elapsed = timer.read();
        printResult("get (cache hits)", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (misses)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = cache.get(&@as(u64, @intCast(i + 10_000_000)));
        }
        const elapsed = timer.read();
        printResult("get (cache misses)", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Ketama consistent hashing
fn benchmarkKetama(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== Ketama Benchmarks ===\n", .{});

    // Setup - create a ring with multiple nodes
    var buckets: [10]ketama.Bucket = undefined;
    for (0..10) |i| {
        const port: u16 = @intCast(8000 + i);
        buckets[i] = ketama.Bucket.init(
            std.net.Address.parseIp4("127.0.0.1", port) catch unreachable,
            1,
        );
    }

    var ring = try ketama.Continuum.init(allocator, &buckets);
    defer ring.deinit();

    std.debug.print("  Ring size: {} points\n", .{ring.len()});

    // Benchmark node lookup
    {
        var timer = try Timer.start();
        var key_buf: [32]u8 = undefined;
        for (0..BENCH_ITERATIONS) |i| {
            const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
            _ = ring.node(key);
        }
        const elapsed = timer.read();
        printResult("node lookup", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark node iterator
    {
        var timer = try Timer.start();
        var key_buf: [32]u8 = undefined;
        for (0..BENCH_ITERATIONS) |i| {
            const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
            var iter = ring.nodeIter(key);
            // Get first 3 nodes (common pattern for replicas)
            _ = iter.next();
            _ = iter.next();
            _ = iter.next();
        }
        const elapsed = timer.read();
        printResult("node iterator (3 nodes)", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark LinkedList operations
fn benchmarkLinkedList(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== LinkedList Benchmarks ===\n", .{});

    const LinkedList = lru.LinkedList;
    var list = LinkedList.init(allocator);
    defer list.deinit();

    // Warmup
    for (0..WARMUP_ITERATIONS) |i| {
        _ = try list.pushHead(@intCast(i));
    }

    // Benchmark pushHead
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = try list.pushHead(@intCast(i + WARMUP_ITERATIONS));
        }
        const elapsed = timer.read();
        printResult("pushHead", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark popTail
    {
        var timer = try Timer.start();
        var count: usize = 0;
        for (0..BENCH_ITERATIONS) |_| {
            if (list.popTail()) |_| {
                count += 1;
            }
        }
        const elapsed = timer.read();
        printResult("popTail", elapsed, count);
    }
}

pub fn main() !void {
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║                    pingora-zig Benchmarks                        ║\n", .{});
    std.debug.print("║                  Iterations: {d:<10}                          ║\n", .{BENCH_ITERATIONS});
    std.debug.print("╚══════════════════════════════════════════════════════════════════╝\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try benchmarkLru(allocator);
    try benchmarkTinyUfo(allocator);
    try benchmarkKetama(allocator);
    try benchmarkLinkedList(allocator);

    std.debug.print("\n=== Benchmark Complete ===\n\n", .{});
}
