# Pingora-Zig

A high-performance HTTP proxy framework written in pure Zig, inspired by Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

![Pingora-Zig](docs/assets/zingora.png)

## Features

### Protocol Support
- **HTTP/1.1** - Full request/response parsing, connection pooling, keep-alive
- **HTTP/2** - Frame parsing, HPACK compression (RFC 7541), stream multiplexing, flow control
- **HTTP/3** - QUIC-based HTTP (RFC 9114) with QPACK header compression (RFC 9204)
- **WebSocket** - RFC 6455 compliant with per-message deflate compression (RFC 7692)
- **QUIC** - UDP-based transport with 0-RTT connection establishment (RFC 9000)
- **gRPC-Web** - Bridge for gRPC-Web to gRPC backend communication

### Security & Encryption
- **TLS/SSL** - OpenSSL integration with session resumption, ALPN, SNI
- **Compression** - Gzip, Deflate, Zstd, and Brotli support with content negotiation

### Load Balancing & Traffic Management
- **Load Balancing** - Round-robin, weighted round-robin, least connections, consistent hashing (Ketama)
- **Connection Pooling** - Efficient connection reuse with health tracking
- **Rate Limiting** - Sliding window estimator for traffic control
- **Failover** - Automatic backend failover with health checks

### Caching
- **HTTP Cache** - Response caching with TTL, Cache-Control support
- **LRU Eviction** - Weighted LRU cache implementation
- **TinyUFO** - Advanced TinyLFU + S3-FIFO cache eviction algorithm

### Observability
- **Prometheus Metrics** - Counters, gauges, histograms with text format export
- **Distributed Tracing** - W3C Trace Context support with span-based tracing
- **Request Digests** - Timing, socket, SSL, and proxy diagnostics

### Server Framework
- **Multi-Service Server** - Run multiple services in a single process
- **Graceful Shutdown** - Zero-downtime restarts
- **Daemon Mode** - Background service with PID file management
- **Systemd Integration** - Linux service management support

## Quick Start

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a load balancer with round-robin
    var lb = pingora.LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    // Add backend servers
    try lb.addBackend("192.168.1.10", 8080, 1);
    try lb.addBackend("192.168.1.11", 8080, 2); // weight=2
    try lb.addBackend("192.168.1.12", 8080, 1);

    // Select a backend for each request
    if (lb.select(null)) |peer| {
        std.debug.print("Selected: {s}:{d}\n", .{ peer.address, peer.port });
    }
}
```

## Requirements

- **Zig**: 0.13.0 or later
- **zlib**: Required for compression support
- **OpenSSL** (optional): For TLS support (enabled by default)
- **quiche** (optional): For QUIC/HTTP3 support
- **Brotli** (optional): For Brotli compression

## Building

```bash
# Build the library
zig build

# Run unit tests
zig build test

# Run TLS/OpenSSL tests
zig build test-tls

# Run QUIC/HTTP3 tests (requires quiche)
zig build test-quiche -Dquiche=true

# Run benchmarks
zig build bench

# Build all examples
zig build examples

# Build specific example
zig build example-simple-proxy
zig build example-load-balancing
zig build example-caching

# Run an example
zig build run-example-simple-proxy
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `-Dopenssl=true/false` | `true` | Enable/disable OpenSSL TLS support |
| `-Dquiche=true/false` | `false` | Enable/disable QUIC/HTTP3 support |
| `-Dbrotli=true/false` | `false` | Enable/disable Brotli compression |

## Module Overview

| Level | Module | Description |
|-------|--------|-------------|
| 5 | `proxy` | HTTP proxy framework with filter chain |
| 5 | `server` | Multi-service server with daemonization |
| 4 | `cache` | HTTP response caching layer |
| 4 | `http2` | HTTP/2 protocol (RFC 7540, RFC 7541) |
| 4 | `http3` | HTTP/3 protocol (RFC 9114, RFC 9204) |
| 4 | `websocket` | WebSocket protocol (RFC 6455, RFC 7692) |
| 4 | `compression` | Gzip, Deflate, Zstd, Brotli compression |
| 3 | `http_client` | HTTP/1.1 client implementation |
| 3 | `http_server` | HTTP/1.1 server implementation |
| 3 | `load_balancer` | Load balancing algorithms |
| 3 | `upstream` | Peer management and health checks |
| 3 | `protocols` | TCP/UDP networking abstractions |
| 3 | `quic` | QUIC transport protocol (RFC 9000) |
| 2 | `tls`, `openssl` | TLS support with OpenSSL |
| 2 | `header_serde` | Header serialization to wire format |
| 2 | `runtime` | Task scheduling and async primitives |
| 2 | `async_io` | Event loop (io_uring, kqueue, epoll) |
| 1 | `http` | HTTP types (Method, Headers, Request/Response) |
| 1 | `http_parser` | HTTP/1.1 request/response parsing |
| 1 | `limits` | Rate limiting with sliding window |
| 1 | `memory_cache` | In-memory cache with TTL |
| 1 | `pool` | Generic connection pooling |
| 0 | `error` | Error types and handling |
| 0 | `lru`, `tinyufo` | Cache eviction algorithms |
| 0 | `ketama` | Consistent hash ring |
| 0 | `timeout` | Timer wheel utilities |
| 0 | `linked_list` | Intrusive doubly-linked list |
| 0 | `digest` | Request/connection diagnostics |
| 0 | `allocators` | Slab allocator, request arena |
| - | `prometheus` | Prometheus metrics collection |
| - | `tracing` | Distributed tracing (W3C Trace Context) |
| - | `grpc_web` | gRPC-Web bridge |
| - | `subrequest` | Internal subrequest support |
| - | `range` | HTTP Range request handling |

## Documentation

- **[Quick Start Guide](docs/quick_start.md)** - Get up and running in 5 minutes
- **[Documentation Index](docs/README.md)** - Complete documentation
- **[User Guide](docs/user_guide/index.md)** - Detailed usage guide

## Examples

The `examples/` directory contains working examples:

| Example | Description |
|---------|-------------|
| [`simple_reverse_proxy.zig`](examples/simple_reverse_proxy.zig) | Basic reverse proxy to a single backend |
| [`load_balancing_proxy.zig`](examples/load_balancing_proxy.zig) | Load balancer with multiple backends |
| [`caching_proxy.zig`](examples/caching_proxy.zig) | Caching proxy with TTL and hit/miss tracking |

## Design Principles

1. **Pure Zig First** - Use Zig standard library for everything possible
2. **Minimal C Dependencies** - Only OpenSSL (TLS), zlib (compression), quiche (QUIC)
3. **Explicit Over Implicit** - Allocators passed explicitly, no hidden state
4. **Zero-Copy Where Possible** - Parsing returns slices into input buffers
5. **Compile-Time Safety** - Leverage Zig's comptime for type safety

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application Code                        │
├─────────────────────────────────────────────────────────────────┤
│  Level 5: proxy, server    │ Proxy framework, multi-service     │
├─────────────────────────────────────────────────────────────────┤
│  Level 4: cache, http2     │ Caching, HTTP/2, HTTP/3            │
│           http3, websocket │ WebSocket, compression             │
├─────────────────────────────────────────────────────────────────┤
│  Level 3: http_client      │ HTTP client/server                 │
│           http_server      │ Load balancing, QUIC               │
│           load_balancer    │ Upstream management                │
├─────────────────────────────────────────────────────────────────┤
│  Level 2: tls, runtime     │ TLS, async I/O                     │
│           async_io         │ Event loops                        │
├─────────────────────────────────────────────────────────────────┤
│  Level 1: http, http_parser│ HTTP primitives                    │
│           pool, limits     │ Pooling, rate limiting             │
├─────────────────────────────────────────────────────────────────┤
│  Level 0: error, lru       │ Foundation utilities               │
│           ketama, timeout  │ Data structures                    │
└─────────────────────────────────────────────────────────────────┘
```

## License

Server Side Public License - See [LICENSE](LICENSE) for details.

## Credits

This project is inspired by and ported from [Cloudflare's Pingora](https://github.com/cloudflare/pingora), a Rust-based HTTP proxy framework.
