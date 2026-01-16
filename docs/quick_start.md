# Quick Start Guide

Get started with Pingora-Zig in 5 minutes.

## Prerequisites

- **Zig 0.13.0+** - [Install Zig](https://ziglang.org/download/)
- **OpenSSL** (optional) - For TLS support
- **zlib** - For WebSocket compression

## Installation

### As a Zig Package

Add Pingora-Zig to your `build.zig.zon`:

```zig
.{
    .name = .my_project,
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
```

### Building from Source

```bash
git clone <repository>
cd pingora-zig

# Run tests to verify installation
zig build test

# Build the library
zig build
```

## Basic Examples

### 1. Simple HTTP Client

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create HTTP client
    var client = pingora.HttpClient.init(allocator, .{});
    defer client.deinit();

    // Build request
    var request = pingora.RequestHeader.init(allocator);
    defer request.deinit();
    try request.setMethod(.GET);
    try request.setUri("/");
    try request.headers.append("Host", "example.com");

    // Connect and send
    try client.connect("93.184.216.34", 80);
    const response = try client.sendRequest(&request, null);
    defer response.deinit();

    std.debug.print("Status: {d}\n", .{response.status.code});
}
```

### 2. HTTP Request Parsing

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

    const result = try pingora.parseRequestFull(raw_request);

    std.debug.print("Method: {s}\n", .{result.method});
    std.debug.print("Path: {s}\n", .{result.path});
    std.debug.print("Version: {s}\n", .{result.version});

    for (result.headers) |header| {
        std.debug.print("{s}: {s}\n", .{ header.name, header.value });
    }
}
```

### 3. Load Balancer Setup

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create load balancer with round-robin
    var lb = pingora.LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    // Add backend servers
    try lb.addBackend("192.168.1.10", 8080, 1); // weight=1
    try lb.addBackend("192.168.1.11", 8080, 2); // weight=2
    try lb.addBackend("192.168.1.12", 8080, 1); // weight=1

    // Select a backend for each request
    if (lb.select(null)) |peer| {
        std.debug.print("Selected: {s}:{d}\n", .{ peer.address, peer.port });
    }
}
```

### 4. HTTP Response Caching

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create cache with 1000 entry capacity
    var cache = try pingora.HttpCache.init(allocator, .{
        .max_entries = 1000,
        .default_ttl_seconds = 300, // 5 minutes
    });
    defer cache.deinit();

    // Cache a response
    const key = pingora.CacheKey.fromUri("/api/data");
    try cache.store(key, response_header, response_body);

    // Lookup cached response
    if (try cache.lookup(key)) |cached| {
        std.debug.print("Cache hit! Status: {d}\n", .{cached.status});
    }
}
```

### 5. WebSocket Client

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create WebSocket client
    var client = pingora.websocket.WebSocketClient.init(allocator);
    defer client.deinit();

    // Create handshake request
    const handshake = client.createHandshake("example.com", "/ws");

    // Build handshake HTTP request
    const request = try handshake.build(allocator);
    defer allocator.free(request);

    // After receiving handshake response and validating...
    // Enable per-message deflate compression (optional)
    try client.enablePerMessageDeflate(.{});

    // Send a text message
    const frame = try client.sendText("Hello, WebSocket!");
    defer allocator.free(frame);

    // Process incoming frames
    if (try client.processFrame(incoming_data)) |msg| {
        defer msg.deinit();
        std.debug.print("Received: {s}\n", .{msg.data});
    }
}
```

### 6. HTTP/2 Frame Handling

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create HPACK encoder/decoder
    var encoder = pingora.http2.HpackEncoder.init(allocator);
    defer encoder.deinit();

    var decoder = pingora.http2.HpackDecoder.init(allocator);
    defer decoder.deinit();

    // Encode headers
    var headers = [_]pingora.http2.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/api" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const encoded = try encoder.encode(&headers);
    defer allocator.free(encoded);

    // Build HEADERS frame
    const frame = try pingora.http2.FrameBuilder.buildHeadersFrame(
        allocator,
        1, // stream ID
        encoded,
        .{ .end_headers = true, .end_stream = true },
    );
    defer allocator.free(frame);
}
```

## Proxy Framework

For building complete HTTP proxies, implement the `ProxyHttp` interface:

```zig
const std = @import("std");
const pingora = @import("pingora");

const MyProxy = struct {
    allocator: std.mem.Allocator,

    // Called to select upstream peer
    pub fn upstreamPeerFn(self: *MyProxy, session: *pingora.Session) !?*pingora.Peer {
        _ = self;
        // Select based on request path, headers, etc.
        const req = session.reqHeader() orelse return null;
        const path = req.uri.path;

        if (std.mem.startsWith(u8, path, "/api")) {
            return &self.api_backend;
        }
        return &self.default_backend;
    }

    // Called before sending request to upstream
    pub fn upstreamRequestFilterFn(
        self: *MyProxy,
        session: *pingora.Session,
        request: *pingora.RequestHeader,
    ) !pingora.FilterResult {
        _ = self;
        _ = session;
        // Add custom headers
        try request.headers.append("X-Forwarded-By", "pingora-zig");
        return .continue_processing;
    }

    // Called after receiving response from upstream
    pub fn responseFilterFn(
        self: *MyProxy,
        session: *pingora.Session,
        response: *pingora.ResponseHeader,
    ) !pingora.FilterResult {
        _ = self;
        _ = session;
        // Add security headers
        try response.headers.append("X-Content-Type-Options", "nosniff");
        return .continue_processing;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var my_proxy = MyProxy{ .allocator = allocator };

    // Create proxy with your implementation
    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = 8080,
        .max_connections = 10000,
    });
    defer proxy.deinit();

    // Configure proxy handlers
    proxy.setHandler(pingora.proxyHttpFrom(&my_proxy));

    // Start serving
    try proxy.serve();
}
```

## Configuration Options

### HTTP Client Config

```zig
const config = pingora.HttpClientConfig{
    .connect_timeout_ms = 5000,      // Connection timeout
    .read_timeout_ms = 30000,        // Read timeout
    .write_timeout_ms = 30000,       // Write timeout
    .max_idle_connections = 100,     // Pool size per host
    .enable_keepalive = true,        // HTTP keep-alive
};
```

### Load Balancer Algorithms

```zig
// Round-robin (default)
var lb = pingora.LoadBalancer.init(allocator, .round_robin);

// Weighted round-robin
var lb = pingora.LoadBalancer.init(allocator, .weighted_round_robin);

// Least connections
var lb = pingora.LoadBalancer.init(allocator, .least_connections);

// Consistent hashing (for session affinity)
var lb = pingora.LoadBalancer.init(allocator, .consistent_hash);
```

### Cache Configuration

```zig
const config = pingora.HttpCacheConfig{
    .max_entries = 10000,            // Maximum cached responses
    .max_memory_bytes = 100_000_000, // 100MB memory limit
    .default_ttl_seconds = 300,      // Default TTL
    .respect_cache_control = true,   // Honor Cache-Control headers
};
```

## Running Tests

```bash
# All tests
zig build test

# TLS/OpenSSL tests
zig build test-tls

# Verbose output
zig build test -- --verbose
```

## Next Steps

- Read the [User Guide](user_guide/index.md) for detailed documentation
- Explore the [source code](../src/) for implementation details
- Check the [integration tests](../src/integration_tests.zig) for more examples

## Getting Help

- Open an issue on GitHub for bugs or feature requests
- Check existing tests for usage patterns
- Review the original [Pingora documentation](https://github.com/cloudflare/pingora/tree/main/docs) for concepts
