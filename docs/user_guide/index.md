# Pingora-Zig User Guide

Welcome to the Pingora-Zig user guide. This documentation covers all aspects of building HTTP proxies with Pingora-Zig.

## Table of Contents

### Getting Started
- [Configuration](conf.md) - How to configure your proxy
- [Start/Stop](start_stop.md) - Service lifecycle management
- [Daemon Mode](daemon.md) - Running as a background service

### Core Concepts
- [Request/Response Context](ctx.md) - Working with session context
- [Proxy Phases](phase.md) - Understanding the proxy lifecycle
- [Phase Chart](phase_chart.md) - Visual guide to request flow
- [Peer Selection](peer.md) - Upstream peer management

### Traffic Management
- [Request/Response Modification](modify_filter.md) - Filtering and transforming traffic
- [Connection Pooling](pooling.md) - Efficient connection reuse
- [Failover](failover.md) - Handling upstream failures
- [Rate Limiting](rate_limiter.md) - Traffic rate control

### Operations
- [Error Handling](errors.md) - Managing errors gracefully
- [Error Logging](error_log.md) - Logging configuration
- [Panic Handling](panic.md) - Crash recovery
- [Graceful Shutdown](graceful.md) - Zero-downtime restarts
- [Systemd Integration](systemd.md) - Linux service management
- [Prometheus Metrics](prom.md) - Observability and monitoring

### Advanced Topics
- [Internals](internals.md) - Deep dive into architecture

## Architecture Overview

Pingora-Zig follows a layered architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application Code                        │
├─────────────────────────────────────────────────────────────────┤
│  Level 5: proxy         │ HTTP proxy framework                  │
├─────────────────────────────────────────────────────────────────┤
│  Level 4: cache         │ HTTP caching layer                    │
│           http2         │ HTTP/2 protocol                       │
│           websocket     │ WebSocket protocol                    │
├─────────────────────────────────────────────────────────────────┤
│  Level 3: http_server   │ HTTP/1.1 server                       │
│           http_client   │ HTTP/1.1 client                       │
│           load_balancer │ Load balancing algorithms             │
│           upstream      │ Peer management                       │
├─────────────────────────────────────────────────────────────────┤
│  Level 2: tls/openssl   │ TLS support                           │
│           runtime       │ Task scheduling                       │
├─────────────────────────────────────────────────────────────────┤
│  Level 1: http          │ HTTP types                            │
│           http_parser   │ HTTP parsing                          │
│           pool          │ Connection pooling                    │
├─────────────────────────────────────────────────────────────────┤
│  Level 0: error         │ Error handling                        │
│           lru/tinyufo   │ Cache algorithms                      │
│           ketama        │ Consistent hashing                    │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Principles

### 1. Pure Zig Implementation

Pingora-Zig is implemented in pure Zig with minimal C dependencies:
- **OpenSSL** - For production TLS (cryptographic correctness is critical)
- **zlib** - For WebSocket per-message deflate compression

All data structures, HTTP parsing, caching algorithms, and load balancing logic are implemented in Zig.

### 2. Explicit Memory Management

All allocations use explicit allocators:

```zig
pub fn init(allocator: std.mem.Allocator) Self {
    return .{ .allocator = allocator };
}
```

This ensures:
- Clear memory ownership
- No hidden allocations
- Easy memory leak detection with `testing.allocator`

### 3. Error Handling

Zig error unions are used throughout:

```zig
pub fn connect(addr: Address) !Connection {
    return self.inner.connect(addr) catch |err| {
        return error.ConnectionFailed;
    };
}
```

### 4. Interface Pattern

For extensibility, Pingora-Zig uses tagged unions and function pointers:

```zig
pub const Algorithm = union(enum) {
    round_robin: RoundRobin,
    weighted: WeightedRoundRobin,
    least_conn: LeastConnections,
    consistent_hash: ConsistentHash,
};
```

## Quick Example

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a reverse proxy to a backend
    var proxy = try pingora.ReverseProxy.init(allocator, .{
        .listen_port = 8080,
        .upstream_host = "backend.example.com",
        .upstream_port = 80,
    });
    defer proxy.deinit();

    try proxy.serve();
}
```

## Next Steps

1. Read [Configuration](conf.md) to understand configuration options
2. Explore [Proxy Phases](phase.md) to understand the request lifecycle
3. Check [Quick Start](../quick_start.md) for more examples
