# Pingora-Zig

A high-performance HTTP proxy framework written in pure Zig, inspired by Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

![Pingora-Zig](docs/assets/zingora.png)

## Features

- **Pure Zig Implementation** - Minimal C dependencies (only OpenSSL for TLS, zlib for compression)
- **HTTP/1.1 Support** - Full request/response parsing, connection pooling, keep-alive
- **HTTP/2 Support** - Frame parsing, HPACK compression (RFC 7541), stream multiplexing, flow control
- **WebSocket Support** - RFC 6455 compliant with per-message deflate compression (RFC 7692)
- **TLS/SSL** - OpenSSL integration with session resumption, ALPN, SNI
- **Load Balancing** - Round-robin, weighted round-robin, least connections, consistent hashing (Ketama)
- **Caching** - HTTP response caching with TTL, LRU eviction, TinyUFO algorithm
- **Connection Pooling** - Efficient connection reuse with health tracking
- **Rate Limiting** - Sliding window estimator for traffic control

## Quick Start

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
    try lb.addBackend("192.168.1.10", 8080, 1);
    try lb.addBackend("192.168.1.11", 8080, 1);

    // Select a backend
    if (lb.select(null)) |peer| {
        std.debug.print("Selected: {s}:{d}\n", .{ peer.address, peer.port });
    }
}
```

## Requirements

- **Zig**: 0.13.0 or later
- **OpenSSL**: For TLS support (optional, enabled by default)
- **zlib**: For WebSocket per-message deflate compression

## Building

```bash
# Build the library
zig build

# Run all tests
zig build test

# Run TLS tests (requires OpenSSL)
zig build test-tls

# Run benchmarks
zig build bench
```

## Module Overview

| Level | Module | Description |
|-------|--------|-------------|
| 5 | `proxy` | HTTP proxy framework |
| 4 | `cache` | HTTP response caching |
| 4 | `http2` | HTTP/2 protocol (RFC 7540, RFC 7541) |
| 4 | `websocket` | WebSocket protocol (RFC 6455, RFC 7692) |
| 3 | `http_client` | HTTP/1.1 client |
| 3 | `http_server` | HTTP/1.1 server |
| 3 | `load_balancer` | Load balancing algorithms |
| 3 | `upstream` | Peer management and health checks |
| 3 | `protocols` | TCP/UDP networking |
| 2 | `tls`, `openssl` | TLS support |
| 2 | `header_serde` | Header serialization |
| 2 | `runtime` | Task scheduling |
| 1 | `http` | HTTP types (Method, Headers, etc.) |
| 1 | `http_parser` | HTTP/1.1 parsing |
| 1 | `limits` | Rate limiting |
| 1 | `memory_cache` | In-memory cache with TTL |
| 1 | `pool` | Connection pooling |
| 0 | `error` | Error handling |
| 0 | `lru`, `tinyufo` | Cache eviction algorithms |
| 0 | `ketama` | Consistent hashing |
| 0 | `timeout` | Timer utilities |
| 0 | `linked_list` | Intrusive linked list |

## Documentation

- **[Quick Start Guide](docs/quick_start.md)** - Get up and running in 5 minutes
- **[Documentation Index](docs/README.md)** - Complete documentation
- **[User Guide](docs/user_guide/index.md)** - Detailed usage guide

## Current Progress

- ✅ Level 0: All foundation modules
- ✅ Level 1: All HTTP primitives
- ✅ Level 2: All infrastructure modules
- ✅ Level 3: All networking modules
- ✅ Level 4: HTTP cache module
- ✅ Level 5: Proxy framework
- ✅ Real upstream connectivity
- ✅ Comprehensive integration tests (425+ tests)
- ✅ HTTP/2 frame types (RFC 7540)
- ✅ HPACK header compression (RFC 7541) with Huffman encoding/decoding
- ✅ HTTP/2 stream multiplexing and flow control
- ✅ WebSocket support (RFC 6455)
- ✅ WebSocket per-message deflate compression (RFC 7692)
- ✅ OpenSSL session resumption APIs

## Design Principles

1. **Pure Zig First** - Use Zig standard library for everything possible
2. **Minimal C Dependencies** - Only OpenSSL (TLS) and zlib (compression)
3. **Explicit Over Implicit** - Allocators passed explicitly, no hidden state
4. **Zero-Copy Where Possible** - Parsing returns slices into input buffers

## License

 - Server Side Public License, See [LICENSE](LICENSE) for details.

## Credits

This project is inspired by and ported from [Cloudflare's Pingora](https://github.com/cloudflare/pingora), a Rust-based HTTP proxy framework.
