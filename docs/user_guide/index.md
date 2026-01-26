# Pingora-Zig User Guide

Welcome to the Pingora-Zig user guide. This documentation covers all aspects of building HTTP proxies with Pingora-Zig.

## Table of Contents

### Getting Started
- [Configuration](conf.md) - Server and proxy configuration
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

### Protocol Support
- [HTTP/2](http2.md) - HTTP/2 protocol support
- [HTTP/3 & QUIC](http3.md) - QUIC-based HTTP/3
- [WebSocket](websocket.md) - WebSocket protocol
- [Compression](compression.md) - Response compression

### Observability
- [Prometheus Metrics](prom.md) - Monitoring and metrics
- [Distributed Tracing](tracing.md) - W3C Trace Context support

### Operations
- [Error Handling](errors.md) - Managing errors gracefully
- [Error Logging](error_log.md) - Logging configuration
- [Panic Handling](panic.md) - Crash recovery
- [Graceful Shutdown](graceful.md) - Zero-downtime restarts
- [Systemd Integration](systemd.md) - Linux service management

### Advanced Topics
- [Internals](internals.md) - Architecture deep dive

## Architecture Overview

Pingora-Zig follows a layered architecture where each level depends only on lower levels:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application Code                        │
├─────────────────────────────────────────────────────────────────┤
│  Level 5: proxy, server    │ Proxy framework, multi-service     │
├─────────────────────────────────────────────────────────────────┤
│  Level 4: cache, http2     │ Caching, HTTP/2                    │
│           http3, websocket │ HTTP/3, WebSocket                  │
│           compression      │ Gzip, Deflate, Zstd, Brotli        │
├─────────────────────────────────────────────────────────────────┤
│  Level 3: http_client      │ HTTP client/server                 │
│           http_server      │ Load balancing                     │
│           load_balancer    │ Upstream management                │
│           quic             │ QUIC transport                     │
├─────────────────────────────────────────────────────────────────┤
│  Level 2: tls, openssl     │ TLS support                        │
│           runtime          │ Task scheduling                    │
│           async_io         │ Event loops                        │
├─────────────────────────────────────────────────────────────────┤
│  Level 1: http             │ HTTP types                         │
│           http_parser      │ HTTP parsing                       │
│           pool, limits     │ Pooling, rate limiting             │
├─────────────────────────────────────────────────────────────────┤
│  Level 0: error            │ Error handling                     │
│           lru, tinyufo     │ Cache algorithms                   │
│           ketama           │ Consistent hashing                 │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Principles

### 1. Pure Zig Implementation

Pingora-Zig is implemented in pure Zig with minimal C dependencies:
- **zlib** - For compression (gzip, deflate)
- **OpenSSL** - For production TLS (optional)
- **quiche** - For QUIC/HTTP3 support (optional)
- **Brotli** - For Brotli compression (optional)

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
    const stream = try std.net.tcpConnectToAddress(addr);
    return Connection{ .stream = stream };
}
```

### 4. Interface Pattern

For extensibility, Pingora-Zig uses tagged unions and function pointers:

```zig
pub const Algorithm = enum {
    round_robin,
    weighted_round_robin,
    least_connections,
    consistent_hash,
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

    // Create a load balancer
    var lb = pingora.LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    // Add backend servers
    try lb.addBackend("backend1.example.com", 8080, 1);
    try lb.addBackend("backend2.example.com", 8080, 2);

    // Select a backend
    if (lb.select(null)) |peer| {
        std.debug.print("Selected: {s}:{d}\n", .{ peer.address, peer.port });
    }
}
```

## Module Quick Reference

| Use Case | Module | Key Types |
|----------|--------|-----------|
| HTTP Parsing | `http_parser` | `parseRequest`, `parseResponse` |
| Load Balancing | `load_balancer` | `LoadBalancer`, `Algorithm` |
| Caching | `cache`, `memory_cache` | `HttpCache`, `MemoryCache` |
| Rate Limiting | `limits` | `Estimator`, `Rate` |
| Connection Pool | `pool` | `ConnectionPool` |
| HTTP/2 | `http2` | `HpackEncoder`, `HpackDecoder` |
| HTTP/3 | `http3` | `FrameParser`, `QpackEncoder` |
| WebSocket | `websocket` | `WebSocketClient`, `Frame` |
| Compression | `compression` | `Algorithm`, `ResponseCompressionCtx` |
| Metrics | `prometheus` | `Counter`, `Gauge`, `Histogram` |
| Tracing | `tracing` | `TraceContext`, `TraceId`, `SpanId` |
| TLS | `tls`, `openssl` | `TlsConfig`, `SslContext` |

## Next Steps

1. Read [Configuration](conf.md) to understand configuration options
2. Explore [Proxy Phases](phase.md) to understand the request lifecycle
3. Check [Quick Start](../quick_start.md) for more examples
4. Review the [examples](../../examples/) directory for complete applications
