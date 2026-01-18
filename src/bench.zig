//! pingora-zig: Comprehensive Benchmarks
//!
//! Benchmark suite for measuring performance of all components.
//! Outputs JSON for comparison with Rust Pingora benchmarks.
//!
//! Run with: zig build bench
//! Run with JSON output: zig build bench -- --json
//!
//! Benchmarked modules:
//! - LRU Cache
//! - TinyUFO Cache
//! - Ketama Consistent Hashing
//! - LinkedList
//! - Cache (CacheKey, CacheLock, CachePredictor)
//! - Load Balancer
//! - HTTP Headers
//! - HTTP Parsing
//! - Connection Pool
//! - Memory Cache
//! - Timeout/Timer
//! - Compression
//! - WebSocket
//! - HTTP/2 (HPACK)
//! - QPACK

const std = @import("std");
const lru = @import("lru.zig");
const tinyufo = @import("tinyufo.zig");
const ketama = @import("ketama.zig");
const cache = @import("cache.zig");
const load_balancer = @import("load_balancer.zig");
const http = @import("http.zig");
const http_parser = @import("http_parser.zig");
const pool = @import("pool.zig");
const memory_cache = @import("memory_cache.zig");
const timeout = @import("timeout.zig");
const compression = @import("compression.zig");
const websocket = @import("websocket.zig");
const http2 = @import("http2.zig");
const qpack = @import("qpack.zig");

const Timer = std.time.Timer;
const Allocator = std.mem.Allocator;

/// Number of iterations for benchmarks
const BENCH_ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 10_000;
const LARGE_BENCH_ITERATIONS: usize = 1_000_000;

/// Benchmark result for JSON output
const BenchResult = struct {
    name: []const u8,
    category: []const u8,
    iterations: usize,
    total_ns: u64,
    per_op_ns: u64,
    ops_per_sec: u64,
};

/// Global results storage
var results: std.ArrayListUnmanaged(BenchResult) = .{};
var results_allocator: Allocator = undefined;
var json_output: bool = false;

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

fn recordResult(category: []const u8, name: []const u8, total_ns: u64, iterations: usize) void {
    const per_op_ns = if (iterations > 0) total_ns / iterations else 0;
    const ops_per_sec = if (per_op_ns > 0) @as(u64, @intFromFloat(1_000_000_000.0 / @as(f64, @floatFromInt(per_op_ns)))) else 0;

    results.append(results_allocator, .{
        .name = name,
        .category = category,
        .iterations = iterations,
        .total_ns = total_ns,
        .per_op_ns = per_op_ns,
        .ops_per_sec = ops_per_sec,
    }) catch {};

    if (!json_output) {
        const total = formatDuration(total_ns);
        const per_op = formatDuration(per_op_ns);
        std.debug.print("  {s:<40} {d:>8.2} {s:<3} total, {d:>8.2} {s:<3}/op, {d:>12} ops/sec\n", .{
            name,
            total[0],
            total[1],
            per_op[0],
            per_op[1],
            ops_per_sec,
        });
    }
}

fn printResult(name: []const u8, total_ns: u64, iterations: usize) void {
    const per_op_ns = total_ns / iterations;
    const total = formatDuration(total_ns);
    const per_op = formatDuration(per_op_ns);
    const ops_per_sec = if (per_op_ns > 0) @as(u64, @intFromFloat(1_000_000_000.0 / @as(f64, @floatFromInt(per_op_ns)))) else 0;

    std.debug.print("  {s:<40} {d:>8.2} {s:<3} total, {d:>8.2} {s:<3}/op, {d:>12} ops/sec\n", .{
        name,
        total[0],
        total[1],
        per_op[0],
        per_op[1],
        ops_per_sec,
    });
}

/// Benchmark LRU operations
fn benchmarkLru(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== LRU Benchmarks ===\n", .{});

    // Setup
    var lru_cache = lru.Lru(u64, 8).init(allocator, 100_000);
    defer lru_cache.deinit();

    // Warmup
    for (0..WARMUP_ITERATIONS) |i| {
        _ = try lru_cache.admit(@intCast(i), @intCast(i), 1);
    }

    // Benchmark admit (new keys)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = try lru_cache.admit(@intCast(i + WARMUP_ITERATIONS), @intCast(i), 1);
        }
        const elapsed = timer.read();
        recordResult("lru", "admit_new", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark admit (existing keys - update)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = try lru_cache.admit(@intCast(i % WARMUP_ITERATIONS), @intCast(i), 1);
        }
        const elapsed = timer.read();
        recordResult("lru", "admit_existing", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark peek
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = lru_cache.peek(@intCast(i % WARMUP_ITERATIONS));
        }
        const elapsed = timer.read();
        recordResult("lru", "peek", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark promote
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = lru_cache.promote(@intCast(i % WARMUP_ITERATIONS));
        }
        const elapsed = timer.read();
        recordResult("lru", "promote", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark TinyUFO operations
fn benchmarkTinyUfo(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== TinyUFO Benchmarks ===\n", .{});

    // Setup
    var ufo_cache = try tinyufo.TinyUfo(u64, u64).init(allocator, 50_000, 10_000);
    defer ufo_cache.deinit();

    // Warmup - populate cache
    for (0..WARMUP_ITERATIONS) |i| {
        var evicted = try ufo_cache.put(@intCast(i), @intCast(i), 1);
        evicted.deinit(allocator);
    }

    // Benchmark put (new keys)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var evicted = try ufo_cache.put(@intCast(i + WARMUP_ITERATIONS * 10), @intCast(i), 1);
            evicted.deinit(allocator);
        }
        const elapsed = timer.read();
        recordResult("tinyufo", "put_eviction", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (hits)
    {
        // Re-populate for consistent hit rate
        for (0..1000) |i| {
            var evicted = try ufo_cache.put(@intCast(i), @intCast(i), 1);
            evicted.deinit(allocator);
        }

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = ufo_cache.get(&@as(u64, @intCast(i % 1000)));
        }
        const elapsed = timer.read();
        recordResult("tinyufo", "get_hit", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (misses)
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = ufo_cache.get(&@as(u64, @intCast(i + 10_000_000)));
        }
        const elapsed = timer.read();
        recordResult("tinyufo", "get_miss", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Ketama consistent hashing
fn benchmarkKetama(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Ketama Benchmarks ===\n", .{});

    // Setup - create a ring with 100 nodes (like Rust benchmark)
    var buckets: [100]ketama.Bucket = undefined;
    for (0..100) |i| {
        const port: u16 = @intCast(6443);
        const ip_last: u8 = @intCast((i % 254) + 1);
        buckets[i] = ketama.Bucket.init(
            std.net.Address.parseIp4(&[_]u8{ '1', '2', '7', '.', '0', '.', '0', '.', '0' + ip_last }, port) catch 
                std.net.Address.parseIp4("127.0.0.1", port) catch unreachable,
            1,
        );
    }

    // Benchmark continuum creation
    {
        var timer = try Timer.start();
        for (0..1000) |_| {
            var ring = ketama.Continuum.init(allocator, &buckets) catch continue;
            ring.deinit();
        }
        const elapsed = timer.read();
        recordResult("ketama", "create_continuum", elapsed, 1000);
    }

    var ring = try ketama.Continuum.init(allocator, &buckets);
    defer ring.deinit();

    if (!json_output) std.debug.print("  Ring size: {} points\n", .{ring.len()});

    // Benchmark node lookup (hash)
    {
        var timer = try Timer.start();
        var key_buf: [32]u8 = undefined;
        for (0..BENCH_ITERATIONS) |i| {
            const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
            _ = ring.node(key);
        }
        const elapsed = timer.read();
        recordResult("ketama", "node_hash", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark node iterator (3 nodes for replicas)
    {
        var timer = try Timer.start();
        var key_buf: [32]u8 = undefined;
        for (0..BENCH_ITERATIONS) |i| {
            const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
            var iter = ring.nodeIter(key);
            _ = iter.next();
            _ = iter.next();
            _ = iter.next();
        }
        const elapsed = timer.read();
        recordResult("ketama", "node_iter_3", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark LinkedList operations
fn benchmarkLinkedList(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== LinkedList Benchmarks ===\n", .{});

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
        recordResult("linkedlist", "push_head", elapsed, BENCH_ITERATIONS);
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
        recordResult("linkedlist", "pop_tail", elapsed, count);
    }
}

/// Benchmark Cache operations
fn benchmarkCache(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Cache Benchmarks ===\n", .{});

    // Benchmark CacheKey creation
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var key_buf: [64]u8 = undefined;
            const key_str = std.fmt.bufPrint(&key_buf, "namespace:primary:{d}:variant", .{i}) catch unreachable;
            const key = cache.CacheKey.fromSlice(key_str);
            std.mem.doNotOptimizeAway(&key);
        }
        const elapsed = timer.read();
        recordResult("cache", "key_create", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark CacheLock operations
    {
        var cache_lock = cache.CacheLock.init(allocator, 1000);
        defer cache_lock.deinit();

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var key_buf: [64]u8 = undefined;
            const key_str = std.fmt.bufPrint(&key_buf, "test:key:{d}", .{i}) catch unreachable;
            var key = cache.CacheKey.fromSlice(key_str);
            var locked = cache_lock.lock(&key, false) catch continue;
            if (locked.isWrite()) {
                cache_lock.release(&key, &locked.write, .done);
            }
            locked.deinit();
        }
        const elapsed = timer.read();
        recordResult("cache", "lock_unlock", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark CachePredictor
    {
        var predictor = cache.CachePredictor.init(allocator, 10000, null) catch return;
        defer predictor.deinit();

        // Populate predictor
        for (0..1000) |i| {
            var key_buf: [64]u8 = undefined;
            const key_str = std.fmt.bufPrint(&key_buf, "pred:key:{d}", .{i}) catch unreachable;
            var key = cache.CacheKey.fromSlice(key_str);
            _ = predictor.markUncacheable(&key, .origin_not_cache);
        }

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var key_buf: [64]u8 = undefined;
            const key_str = std.fmt.bufPrint(&key_buf, "pred:key:{d}", .{i % 1000}) catch unreachable;
            var key = cache.CacheKey.fromSlice(key_str);
            _ = predictor.cacheablePrediction(&key);
        }
        const elapsed = timer.read();
        recordResult("cache", "predictor_check", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Load Balancer operations
fn benchmarkLoadBalancer(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Load Balancer Benchmarks ===\n", .{});
    _ = allocator;

    // Benchmark Backend creation
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            const backend = load_balancer.Backend.new("127.0.0.1", 8080) catch continue;
            std.mem.doNotOptimizeAway(&backend);
        }
        const elapsed = timer.read();
        recordResult("loadbalancer", "backend_create", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark Backend hash
    {
        const backend = load_balancer.Backend.new("127.0.0.1", 8080) catch return;
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            const hash = backend.hashKey();
            std.mem.doNotOptimizeAway(&hash);
        }
        const elapsed = timer.read();
        recordResult("loadbalancer", "backend_hash", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark health state transitions
    {
        var backend = load_balancer.Backend.new("127.0.0.1", 8080) catch return;
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            if (i % 2 == 0) {
                _ = backend.markHealthy(2);
            } else {
                _ = backend.markUnhealthy(2);
            }
        }
        const elapsed = timer.read();
        recordResult("loadbalancer", "health_transition", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark HTTP Header operations
fn benchmarkHttpHeaders(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== HTTP Header Benchmarks ===\n", .{});

    // Benchmark request header creation
    {
        var timer = try Timer.start();
        for (0..10000) |_| {
            var req = http.RequestHeader.build(allocator, .GET, "/api/v1/users", null) catch continue;
            req.deinit();
        }
        const elapsed = timer.read();
        recordResult("http", "request_create", elapsed, 10000);
    }

    // Benchmark header append
    {
        var req = http.RequestHeader.build(allocator, .GET, "/test", null) catch return;
        defer req.deinit();

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            req.appendHeader("X-Custom-Header", "some-value") catch continue;
        }
        const elapsed = timer.read();
        recordResult("http", "header_append", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark header lookup
    {
        var req = http.RequestHeader.build(allocator, .GET, "/test", null) catch return;
        defer req.deinit();
        req.appendHeader("Content-Type", "application/json") catch {};
        req.appendHeader("Authorization", "Bearer token123") catch {};
        req.appendHeader("Accept", "application/json") catch {};

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = req.headers.get("Authorization");
        }
        const elapsed = timer.read();
        recordResult("http", "header_lookup", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark HTTP Parsing
fn benchmarkHttpParsing(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== HTTP Parsing Benchmarks ===\n", .{});
    _ = allocator;

    const sample_request =
        "GET /api/v1/users?page=1&limit=10 HTTP/1.1\r\n" ++
        "Host: api.example.com\r\n" ++
        "User-Agent: Mozilla/5.0\r\n" ++
        "Accept: application/json\r\n" ++
        "Accept-Language: en-US,en;q=0.9\r\n" ++
        "Accept-Encoding: gzip, deflate, br\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIs\r\n" ++
        "Cache-Control: no-cache\r\n" ++
        "\r\n";

    const sample_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json; charset=utf-8\r\n" ++
        "Content-Length: 1234\r\n" ++
        "Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n" ++
        "Server: nginx/1.24.0\r\n" ++
        "Cache-Control: max-age=3600\r\n" ++
        "ETag: \"abc123\"\r\n" ++
        "X-Request-Id: req-12345\r\n" ++
        "\r\n";

    // Benchmark request parsing
    {
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = http_parser.parseRequest(sample_request, &headers_buf) catch continue;
        }
        const elapsed = timer.read();
        recordResult("http_parser", "parse_request", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark response parsing
    {
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = http_parser.parseResponse(sample_response, &headers_buf) catch continue;
        }
        const elapsed = timer.read();
        recordResult("http_parser", "parse_response", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark full request parsing with struct
    {
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = http_parser.parseRequestFull(sample_request, &headers_buf) catch continue;
        }
        const elapsed = timer.read();
        recordResult("http_parser", "parse_request_full", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Connection Pool operations
fn benchmarkConnectionPool(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Connection Pool Benchmarks ===\n", .{});

    const ConnectionPool = pool.ConnectionPool(u64, u64);

    // Benchmark pool creation
    {
        var timer = try Timer.start();
        for (0..10000) |_| {
            var p = ConnectionPool.init(allocator, 1000);
            p.deinit();
        }
        const elapsed = timer.read();
        recordResult("pool", "create_pool", elapsed, 10000);
    }

    // Benchmark put operations
    {
        var p = ConnectionPool.init(allocator, 10000);
        defer p.deinit();

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = p.put(@intCast(i % 100), @intCast(i));
        }
        const elapsed = timer.read();
        recordResult("pool", "put", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get operations
    {
        var p = ConnectionPool.init(allocator, 10000);
        defer p.deinit();

        // Pre-populate
        for (0..1000) |i| {
            _ = p.put(@intCast(i % 100), @intCast(i));
        }

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = p.get(@intCast(i % 100));
        }
        const elapsed = timer.read();
        recordResult("pool", "get", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark ConnectionMeta operations
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            var meta = pool.ConnectionMeta.init(@intCast(i));
            meta.markUsed();
            _ = meta.age();
            std.mem.doNotOptimizeAway(&meta);
        }
        const elapsed = timer.read();
        recordResult("pool", "meta_ops", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Timeout operations
fn benchmarkTimeout(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Timeout Benchmarks ===\n", .{});

    // Benchmark Time creation and operations
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const t = timeout.Time.fromMs(@intCast(i));
            _ = t.notAfter(@intCast(i + 1000));
            std.mem.doNotOptimizeAway(&t);
        }
        const elapsed = timer.read();
        recordResult("timeout", "time_create", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark TimerManager creation
    {
        var timer = try Timer.start();
        for (0..10000) |_| {
            var tm = timeout.TimerManager.init(allocator);
            tm.deinit();
        }
        const elapsed = timer.read();
        recordResult("timeout", "manager_create", elapsed, 10000);
    }

    // Benchmark Time comparisons
    {
        const t1 = timeout.Time.fromMs(1000);
        const t2 = timeout.Time.fromMs(2000);

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = t1.eql(t2);
            _ = t1.lessThan(t2);
            _ = t1.notAfter(1500);
        }
        const elapsed = timer.read();
        recordResult("timeout", "time_compare", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Compression operations
fn benchmarkCompression(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Compression Benchmarks ===\n", .{});
    _ = allocator;

    // Benchmark algorithm parsing from Accept-Encoding
    {
        const accept_encodings = [_][]const u8{
            "gzip, deflate, br",
            "br;q=1.0, gzip;q=0.8, *;q=0.1",
            "identity",
            "gzip",
            "zstd, gzip, deflate",
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const ae = accept_encodings[i % accept_encodings.len];
            _ = compression.Algorithm.fromAcceptEncoding(ae);
        }
        const elapsed = timer.read();
        recordResult("compression", "parse_accept_encoding", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark content type checking
    {
        const content_types = [_][]const u8{
            "text/html; charset=utf-8",
            "application/json",
            "image/png",
            "text/css",
            "application/octet-stream",
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const ct = content_types[i % content_types.len];
            _ = compression.isCompressibleContentType(ct);
        }
        const elapsed = timer.read();
        recordResult("compression", "check_compressible", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark ResponseCompressionCtx
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            var ctx = compression.ResponseCompressionCtx.init(std.heap.page_allocator);
            ctx.negotiateEncoding("gzip, deflate, br");
            ctx.setLevel(.default);
            ctx.deinit();
        }
        const elapsed = timer.read();
        recordResult("compression", "ctx_negotiate", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark WebSocket operations
fn benchmarkWebSocket(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== WebSocket Benchmarks ===\n", .{});
    _ = allocator;

    // Benchmark frame header parsing
    {
        // Sample binary frame header (FIN=1, opcode=binary, no mask, length=126 bytes)
        const frame_data = [_]u8{ 0x82, 0x7E, 0x00, 0x7E };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            const header = websocket.FrameHeader.parse(&frame_data);
            std.mem.doNotOptimizeAway(&header);
        }
        const elapsed = timer.read();
        recordResult("websocket", "parse_header", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark frame header building
    {
        var buf: [14]u8 = undefined;

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const len = websocket.FrameBuilder.buildHeader(&buf, .binary, @intCast(i % 65536), true, null);
            std.mem.doNotOptimizeAway(&len);
        }
        const elapsed = timer.read();
        recordResult("websocket", "build_header", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark mask/unmask operations
    {
        var data: [256]u8 = undefined;
        for (&data, 0..) |*b, i| b.* = @truncate(i);
        const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            websocket.applyMask(&data, mask_key);
        }
        const elapsed = timer.read();
        recordResult("websocket", "mask_256b", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark close code validation
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const code: u16 = @truncate(i % 5000);
            _ = websocket.CloseCode.isValid(code);
        }
        const elapsed = timer.read();
        recordResult("websocket", "validate_close_code", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark HTTP/2 operations
fn benchmarkHttp2(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== HTTP/2 Benchmarks ===\n", .{});

    // Benchmark frame header parsing
    {
        // Sample HEADERS frame header
        const frame_bytes = [9]u8{ 0x00, 0x00, 0x1D, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01 };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            const header = http2.FrameHeader.parse(&frame_bytes);
            std.mem.doNotOptimizeAway(&header);
        }
        const elapsed = timer.read();
        recordResult("http2", "parse_frame_header", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark frame header serialization
    {
        var buf: [9]u8 = undefined;
        const header = http2.FrameHeader{
            .length = 100,
            .frame_type = .headers,
            .flags = http2.FrameFlags.END_HEADERS,
            .stream_id = 1,
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            header.serialize(&buf);
        }
        const elapsed = timer.read();
        recordResult("http2", "serialize_frame_header", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark Huffman encoding length calculation
    {
        const test_strings = [_][]const u8{
            "www.example.com",
            "application/json",
            "/api/v1/users",
            "Mozilla/5.0 (compatible)",
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const s = test_strings[i % test_strings.len];
            _ = http2.HuffmanEncoder.encodedLength(s);
        }
        const elapsed = timer.read();
        recordResult("http2", "huffman_encoded_len", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark Huffman encoding
    {
        var buf: [256]u8 = undefined;
        const test_str = "www.example.com";

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            _ = http2.HuffmanEncoder.encode(test_str, &buf);
        }
        const elapsed = timer.read();
        recordResult("http2", "huffman_encode", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark Settings creation and serialization
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            var settings = http2.Settings{
                .max_concurrent_streams = 100,
                .initial_window_size = 65535,
            };
            var buf: [36]u8 = undefined;
            _ = settings.serialize(&buf);
            std.mem.doNotOptimizeAway(&settings);
        }
        const elapsed = timer.read();
        recordResult("http2", "settings_create", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark HPACK integer encoding
    {
        var buf: [10]u8 = undefined;

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = http2.HpackEncoder.encodeInteger(@intCast(i % 10000), 7, 0x00, &buf);
        }
        const elapsed = timer.read();
        recordResult("http2", "hpack_encode_int", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark Huffman decoder
    {
        var decoder = http2.HuffmanDecoder.init(allocator);
        // Pre-encoded "www.example.com"
        const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };

        var timer = try Timer.start();
        for (0..10000) |_| {
            if (decoder.decode(&encoded)) |decoded| {
                allocator.free(decoded);
            } else |_| {}
        }
        const elapsed = timer.read();
        recordResult("http2", "huffman_decode", elapsed, 10000);
    }
}

/// Benchmark QPACK operations
fn benchmarkQpack(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== QPACK Benchmarks ===\n", .{});
    _ = allocator;

    // Benchmark integer encoding
    {
        var buf: [10]u8 = undefined;

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = qpack.encodeInteger(@intCast(i % 10000), 6, 0x00, &buf);
        }
        const elapsed = timer.read();
        recordResult("qpack", "encode_integer", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark integer decoding
    {
        // Encoded integers with 6-bit prefix
        const encoded_ints = [_][]const u8{
            &[_]u8{0x1F},                         // 31
            &[_]u8{ 0x3F, 0x00 },                 // 63
            &[_]u8{ 0x3F, 0x81, 0x00 },           // 192
            &[_]u8{ 0x3F, 0xE1, 0x07 },           // 1024
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const enc = encoded_ints[i % encoded_ints.len];
            _ = qpack.decodeInteger(enc, 6);
        }
        const elapsed = timer.read();
        recordResult("qpack", "decode_integer", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark static table lookup
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            if (qpack.StaticTable.get(@intCast(i % 99))) |entry| {
                std.mem.doNotOptimizeAway(&entry);
            }
        }
        const elapsed = timer.read();
        recordResult("qpack", "static_table_lookup", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark static table name search
    {
        const names = [_][]const u8{
            ":method",
            ":path",
            ":status",
            "content-type",
            "content-length",
        };

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            const name = names[i % names.len];
            _ = qpack.StaticTable.findName(name);
        }
        const elapsed = timer.read();
        recordResult("qpack", "static_table_find", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark HeaderField size calculation
    {
        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |_| {
            const field = qpack.HeaderField{ .name = "content-type", .value = "application/json" };
            _ = field.size();
        }
        const elapsed = timer.read();
        recordResult("qpack", "header_field_size", elapsed, BENCH_ITERATIONS);
    }
}

/// Benchmark Memory Cache operations
fn benchmarkMemoryCache(allocator: Allocator) !void {
    if (!json_output) std.debug.print("\n=== Memory Cache Benchmarks ===\n", .{});

    const MemCache = memory_cache.MemoryCache(u64, u64);

    // Benchmark cache creation
    {
        var timer = try Timer.start();
        for (0..1000) |_| {
            var mc = MemCache.init(allocator, 10000) catch continue;
            mc.deinit();
        }
        const elapsed = timer.read();
        recordResult("memory_cache", "create", elapsed, 1000);
    }

    // Benchmark put with TTL
    {
        var mc = try MemCache.init(allocator, 100000);
        defer mc.deinit();

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            mc.put(@intCast(i), @intCast(i), 60 * std.time.ns_per_s) catch continue;
        }
        const elapsed = timer.read();
        recordResult("memory_cache", "put_ttl", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (hits)
    {
        var mc = try MemCache.init(allocator, 100000);
        defer mc.deinit();

        // Pre-populate
        for (0..10000) |i| {
            mc.put(@intCast(i), @intCast(i), 60 * std.time.ns_per_s) catch continue;
        }

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = mc.get(@intCast(i % 10000));
        }
        const elapsed = timer.read();
        recordResult("memory_cache", "get_hit", elapsed, BENCH_ITERATIONS);
    }

    // Benchmark get (misses)
    {
        var mc = try MemCache.init(allocator, 10000);
        defer mc.deinit();

        var timer = try Timer.start();
        for (0..BENCH_ITERATIONS) |i| {
            _ = mc.get(@intCast(i + 1000000));
        }
        const elapsed = timer.read();
        recordResult("memory_cache", "get_miss", elapsed, BENCH_ITERATIONS);
    }
}

fn outputJson() void {
    std.debug.print("{{\n  \"implementation\": \"pingora-zig\",\n  \"timestamp\": \"{d}\",\n  \"iterations\": {d},\n  \"results\": [\n", .{ std.time.timestamp(), BENCH_ITERATIONS });

    for (results.items, 0..) |result, i| {
        std.debug.print("    {{\n      \"category\": \"{s}\",\n      \"name\": \"{s}\",\n      \"iterations\": {d},\n      \"total_ns\": {d},\n      \"per_op_ns\": {d},\n      \"ops_per_sec\": {d}\n    }}", .{
            result.category,
            result.name,
            result.iterations,
            result.total_ns,
            result.per_op_ns,
            result.ops_per_sec,
        });
        if (i < results.items.len - 1) {
            std.debug.print(",\n", .{});
        } else {
            std.debug.print("\n", .{});
        }
    }

    std.debug.print("  ]\n}}\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize results storage
    results_allocator = allocator;
    defer results.deinit(allocator);

    // Parse command line arguments
    var args = std.process.args();
    _ = args.skip(); // Skip program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
        }
    }

    if (!json_output) {
        std.debug.print("\n", .{});
        std.debug.print("╔══════════════════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║                      pingora-zig Benchmarks                          ║\n", .{});
        std.debug.print("║                    Iterations: {d:<10}                            ║\n", .{BENCH_ITERATIONS});
        std.debug.print("╚══════════════════════════════════════════════════════════════════════╝\n", .{});
    }

    // Run all benchmarks
    try benchmarkLru(allocator);
    try benchmarkTinyUfo(allocator);
    try benchmarkKetama(allocator);
    try benchmarkLinkedList(allocator);
    try benchmarkCache(allocator);
    try benchmarkLoadBalancer(allocator);
    try benchmarkHttpHeaders(allocator);
    try benchmarkHttpParsing(allocator);
    try benchmarkConnectionPool(allocator);
    try benchmarkTimeout(allocator);
    try benchmarkCompression(allocator);
    try benchmarkWebSocket(allocator);
    try benchmarkHttp2(allocator);
    try benchmarkQpack(allocator);
    try benchmarkMemoryCache(allocator);

    if (json_output) {
        outputJson();
    } else {
        std.debug.print("\n=== Benchmark Complete ===\n", .{});
        std.debug.print("Total benchmarks run: {d}\n\n", .{results.items.len});
    }
}
