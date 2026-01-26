# Quick Start Guide

Get started with Pingora-Zig in 5 minutes.

## Prerequisites

- **Zig 0.13.0+** - [Install Zig](https://ziglang.org/download/)
- **zlib** - Required for compression support
- **OpenSSL** (optional) - For TLS support
- **quiche** (optional) - For QUIC/HTTP3 support

## Installation

### As a Zig Package

Add Pingora-Zig to your `build.zig.zon`:

```zig
.{
    .name = "my_project",
    .version = "0.1.0",
    .dependencies = .{
        .pingora = .{
            .path = "path/to/pingora-zig",
        },
    },
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}
```

Then in your `build.zig`:

```zig
const pingora = b.dependency("pingora", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("pingora", pingora.module("pingora"));

// Link required libraries
exe.linkSystemLibrary("z");
exe.linkLibC();

// Optional: Link OpenSSL for TLS
exe.linkSystemLibrary("ssl");
exe.linkSystemLibrary("crypto");
```

### Building from Source

```bash
git clone <repository>
cd pingora-zig

# Run tests to verify installation
zig build test

# Build the library
zig build

# Build and run examples
zig build examples
```

## Basic Examples

### 1. HTTP Request Parsing

Parse HTTP requests without any network I/O:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    const raw_request =
        "GET /api/users HTTP/1.1\r\n" ++
        "Host: api.example.com\r\n" ++
        "User-Agent: pingora-zig/0.1\r\n" ++
        "Accept: application/json\r\n" ++
        "\r\n";

    var headers_buf: [64]pingora.HeaderRef = undefined;
    if (try pingora.parseRequestFull(raw_request, &headers_buf)) |parsed| {
        std.debug.print("Method: {s}\n", .{parsed.method});
        std.debug.print("Path: {s}\n", .{parsed.path});
        std.debug.print("Version: {s}\n", .{parsed.version});

        for (parsed.headers) |header| {
            std.debug.print("{s}: {s}\n", .{ header.name, header.value });
        }
    }
}
```

### 2. Load Balancer Setup

Create a load balancer with multiple backends:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create load balancer with different algorithms
    // Options: .round_robin, .weighted_round_robin, .least_connections, .consistent_hash
    var lb = pingora.LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    // Add backend servers with weights
    try lb.addBackend("192.168.1.10", 8080, 1); // weight=1
    try lb.addBackend("192.168.1.11", 8080, 2); // weight=2 (gets 2x traffic)
    try lb.addBackend("192.168.1.12", 8080, 1); // weight=1

    // Select backends for requests
    for (0..5) |_| {
        if (lb.select(null)) |peer| {
            std.debug.print("Selected: {s}:{d}\n", .{ peer.address, peer.port });
        }
    }
}
```

### 3. In-Memory Cache with TTL

Cache data with automatic expiration:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create cache with 1000 entry capacity
    var cache = pingora.MemoryCache([]const u8).init(allocator, .{
        .max_size = 1000,
        .default_ttl_ms = 60_000, // 60 seconds
    });
    defer cache.deinit();

    // Store values
    try cache.put("user:123", "John Doe", null); // uses default TTL
    try cache.put("session:abc", "token_xyz", 300_000); // 5 minute TTL

    // Retrieve values
    if (cache.get("user:123")) |value| {
        std.debug.print("Found: {s}\n", .{value});
    }

    // Check cache status
    const status = cache.getStatus("user:123");
    std.debug.print("Status: {s}\n", .{@tagName(status)});
}
```

### 4. Rate Limiting

Implement sliding window rate limiting:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    // Create rate estimator
    // Window: 1 second, Max requests: 100
    var estimator = pingora.Estimator.init(1_000_000_000, 100);

    // Simulate requests
    for (0..150) |i| {
        const allowed = estimator.observe(1);
        if (!allowed) {
            std.debug.print("Request {d}: RATE LIMITED\n", .{i});
        } else {
            std.debug.print("Request {d}: allowed\n", .{i});
        }
    }

    // Get current rate
    const current_rate = estimator.rate();
    std.debug.print("Current rate: {d}\n", .{current_rate});
}
```

### 5. LRU Cache

Weighted LRU cache for connection pooling or response caching:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create LRU with max weight of 1000
    var lru = pingora.Lru([]const u8, []const u8).init(allocator, 1000);
    defer lru.deinit();

    // Insert items with weights
    try lru.insert("key1", "value1", 100); // weight=100
    try lru.insert("key2", "value2", 200); // weight=200
    try lru.insert("key3", "value3", 150); // weight=150

    // Lookup (moves item to front)
    if (lru.get("key1")) |value| {
        std.debug.print("Found: {s}\n", .{value});
    }

    // Peek without affecting order
    if (lru.peek("key2")) |value| {
        std.debug.print("Peeked: {s}\n", .{value});
    }
}
```

### 6. Consistent Hashing (Ketama)

Consistent hash ring for sticky load balancing:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create hash ring
    var ring = try pingora.Continuum.init(allocator);
    defer ring.deinit();

    // Add nodes with weights
    try ring.addNode("server1.example.com", 100);
    try ring.addNode("server2.example.com", 100);
    try ring.addNode("server3.example.com", 100);

    // Build the ring
    try ring.build();

    // Hash keys to nodes (same key always maps to same node)
    const keys = [_][]const u8{ "user:123", "user:456", "session:abc" };
    for (keys) |key| {
        if (ring.getNode(key)) |node| {
            std.debug.print("{s} -> {s}\n", .{ key, node });
        }
    }
}
```

### 7. Prometheus Metrics

Collect and export Prometheus-compatible metrics:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create metrics registry
    var registry = pingora.prometheus.Registry.init(allocator);
    defer registry.deinit();

    // Create a counter
    var requests = pingora.prometheus.Counter.init("http_requests_total", "Total HTTP requests");
    try registry.register(&requests);

    // Create a gauge
    var connections = pingora.prometheus.Gauge.init("active_connections", "Active connections");
    try registry.register(&connections);

    // Create a histogram
    var latency = pingora.prometheus.Histogram.init(
        "request_latency_seconds",
        "Request latency",
        &[_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0 },
    );
    try registry.register(&latency);

    // Record metrics
    requests.inc();
    connections.set(42);
    latency.observe(0.025);

    // Export to Prometheus text format
    var buffer: [4096]u8 = undefined;
    const output = try registry.encode(&buffer);
    std.debug.print("{s}\n", .{output});
}
```

### 8. Distributed Tracing

W3C Trace Context compatible tracing:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    // Generate trace and span IDs
    const trace_id = pingora.tracing.TraceId.generate();
    const span_id = pingora.tracing.SpanId.generate();

    // Create trace context
    var ctx = pingora.tracing.TraceContext{
        .trace_id = trace_id,
        .span_id = span_id,
        .parent_span_id = null,
        .flags = .{ .sampled = true },
    };

    // Format as traceparent header
    var buf: [64]u8 = undefined;
    const traceparent = ctx.toTraceparent(&buf);
    std.debug.print("traceparent: {s}\n", .{traceparent});

    // Parse incoming traceparent header
    const incoming = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    if (pingora.tracing.TraceContext.fromTraceparent(incoming)) |parsed| {
        var trace_hex: [32]u8 = undefined;
        std.debug.print("Trace ID: {s}\n", .{parsed.trace_id.toHex(&trace_hex)});
    }
}
```

### 9. HTTP/2 HPACK Header Compression

Compress headers using HPACK (RFC 7541):

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create HPACK encoder
    var encoder = pingora.http2.HpackEncoder.init(allocator, .{});
    defer encoder.deinit();

    // Encode headers
    const headers = [_]pingora.http2.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/api/users" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = "accept", .value = "application/json" },
    };

    const encoded = try encoder.encode(&headers);
    defer allocator.free(encoded);

    std.debug.print("Encoded {d} headers into {d} bytes\n", .{ headers.len, encoded.len });

    // Create HPACK decoder
    var decoder = pingora.http2.HpackDecoder.init(allocator, .{});
    defer decoder.deinit();

    // Decode headers
    const decoded = try decoder.decode(encoded);
    defer allocator.free(decoded);

    for (decoded) |h| {
        std.debug.print("{s}: {s}\n", .{ h.name, h.value });
    }
}
```

### 10. Compression

Compress and decompress HTTP response bodies:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse Accept-Encoding header
    const accept_encoding = "gzip, deflate, br, zstd";
    if (pingora.CompressionAlgorithm.fromAcceptEncoding(accept_encoding)) |algo| {
        std.debug.print("Best algorithm: {s}\n", .{algo.toContentEncoding()});
    }

    // Create compression context
    var ctx = try pingora.ResponseCompressionCtx.init(allocator, .gzip, .default);
    defer ctx.deinit();

    // Compress data
    const input = "Hello, World! This is some text to compress.";
    const compressed = try ctx.compress(input);
    defer allocator.free(compressed);

    std.debug.print("Original: {d} bytes, Compressed: {d} bytes\n", .{ input.len, compressed.len });

    // Get compression stats
    const stats = ctx.getStats();
    std.debug.print("Compression ratio: {d:.2}\n", .{stats.compressionRatio()});
}
```

## Running the Examples

The repository includes complete working examples:

```bash
# Build all examples
zig build examples

# Run specific examples
zig build run-example-simple-proxy
zig build run-example-load-balancing
zig build run-example-caching
```

## Next Steps

- Read the [User Guide](user_guide/index.md) for detailed documentation
- Explore the [source code](../src/) for implementation details
- Check the [integration tests](../src/integration_tests.zig) for more usage patterns
- Review the [examples](../examples/) directory for complete applications

## Getting Help

- Open an issue on GitHub for bugs or feature requests
- Check existing tests for usage patterns
- Review the original [Pingora documentation](https://github.com/cloudflare/pingora/tree/main/docs) for concepts
