# Pingora-Zig Documentation

![Pingora banner image](assets/zingora.png)

A high-performance HTTP proxy framework written in pure Zig, inspired by Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

## Overview

Pingora-Zig provides a complete toolkit for building fast, reliable HTTP proxies and load balancers. It features:

- **Pure Zig Implementation** - No Rust dependencies, minimal C dependencies
- **Multi-Protocol Support** - HTTP/1.1, HTTP/2, HTTP/3, WebSocket, QUIC
- **TLS/SSL** - OpenSSL integration with session resumption, ALPN, SNI
- **Load Balancing** - Round-robin, weighted, least connections, consistent hashing
- **Caching** - HTTP response caching with TTL, LRU/TinyUFO eviction
- **Compression** - Gzip, Deflate, Zstd, Brotli with content negotiation
- **Observability** - Prometheus metrics, distributed tracing, request digests
- **Production Ready** - Graceful shutdown, daemon mode, systemd integration

## Quick Navigation

### Getting Started
| Document | Description |
|----------|-------------|
| [Quick Start Guide](quick_start.md) | Get up and running in 5 minutes |
| [User Guide Index](user_guide/index.md) | Complete user documentation |

### Core Concepts
| Document | Description |
|----------|-------------|
| [Configuration](user_guide/conf.md) | Server and proxy configuration |
| [Request Context](user_guide/ctx.md) | Working with request/response context |
| [Proxy Phases](user_guide/phase.md) | Understanding the proxy lifecycle |
| [Phase Chart](user_guide/phase_chart.md) | Visual guide to request flow |

### Traffic Management
| Document | Description |
|----------|-------------|
| [Peer Selection](user_guide/peer.md) | Upstream peer management |
| [Connection Pooling](user_guide/pooling.md) | Efficient connection reuse |
| [Failover](user_guide/failover.md) | Handling upstream failures |
| [Rate Limiting](user_guide/rate_limiter.md) | Traffic rate control |
| [Modify/Filter](user_guide/modify_filter.md) | Request/response transformation |

### Operations
| Document | Description |
|----------|-------------|
| [Error Handling](user_guide/errors.md) | Managing errors gracefully |
| [Error Logging](user_guide/error_log.md) | Logging configuration |
| [Panic Handling](user_guide/panic.md) | Crash recovery |
| [Graceful Shutdown](user_guide/graceful.md) | Zero-downtime restarts |
| [Start/Stop](user_guide/start_stop.md) | Service lifecycle |
| [Daemon Mode](user_guide/daemon.md) | Background service |
| [Systemd](user_guide/systemd.md) | Linux service management |
| [Prometheus Metrics](user_guide/prom.md) | Monitoring and observability |

### Advanced Topics
| Document | Description |
|----------|-------------|
| [Internals](user_guide/internals.md) | Architecture deep dive |

## Module Reference

### Level 0: Foundation (No Dependencies)

| Module | Description |
|--------|-------------|
| `error` | Error types and result handling |
| `timeout` | Timer wheel for fast timeout management |
| `lru` | Weighted LRU cache implementation |
| `tinyufo` | TinyLFU + S3-FIFO cache eviction |
| `ketama` | Consistent hash ring for load balancing |
| `linked_list` | Intrusive doubly-linked list |
| `digest` | Request/connection diagnostics |
| `allocators` | Slab allocator, request arena, pooled buffers |

### Level 1: HTTP Primitives

| Module | Description |
|--------|-------------|
| `http` | HTTP types (Method, Version, Headers, Request/Response) |
| `http_parser` | HTTP/1.1 request/response parsing |
| `http_utils` | Utility functions (date caching, error responses) |
| `limits` | Rate limiting with sliding window estimator |
| `memory_cache` | In-memory cache with TTL support |
| `pool` | Generic connection pooling |

### Level 2: Infrastructure

| Module | Description |
|--------|-------------|
| `header_serde` | Header serialization to wire format |
| `runtime` | Task queue and async primitives |
| `async_io` | Event loop (io_uring, kqueue, epoll) |
| `tls` | TLS types and configuration |
| `openssl` | OpenSSL bindings for TLS |

### Level 3: Networking

| Module | Description |
|--------|-------------|
| `protocols` | TCP/UDP networking abstractions |
| `http_client` | HTTP/1.1 client implementation |
| `http_server` | HTTP/1.1 server implementation |
| `upstream` | Upstream peer management and health checks |
| `load_balancer` | Load balancing algorithms |
| `quic` | QUIC transport protocol (RFC 9000) |
| `connector` | Connection establishment utilities |
| `listener` | Server listener management |

### Level 4: Application Layer

| Module | Description |
|--------|-------------|
| `cache` | HTTP response caching layer |
| `http2` | HTTP/2 protocol (frames, HPACK, streams) |
| `http3` | HTTP/3 protocol (RFC 9114, QPACK) |
| `websocket` | WebSocket protocol (RFC 6455, RFC 7692) |
| `compression` | Gzip, Deflate, Zstd, Brotli compression |
| `http_modules` | HTTP module framework |

### Level 5: Proxy Framework

| Module | Description |
|--------|-------------|
| `proxy` | Complete HTTP proxy framework |
| `server` | Multi-service server with daemonization |
| `background` | Background task processing |
| `read_through` | Read-through cache pattern |

### Cross-Cutting Modules

| Module | Description |
|--------|-------------|
| `prometheus` | Prometheus metrics collection |
| `tracing` | W3C Trace Context distributed tracing |
| `grpc_web` | gRPC-Web to gRPC bridge |
| `subrequest` | Internal subrequest support |
| `range` | HTTP Range request handling |
| `peer` | Extended peer configuration |
| `connect` | HTTP CONNECT tunnel support |

## Requirements

- **Zig**: 0.13.0 or later
- **zlib**: Required for compression
- **OpenSSL** (optional): For TLS support
- **quiche** (optional): For QUIC/HTTP3 support
- **Brotli** (optional): For Brotli compression

## Building

```bash
# Build the library
zig build

# Run unit tests
zig build test

# Run TLS tests (requires OpenSSL)
zig build test-tls

# Run QUIC/HTTP3 tests (requires quiche)
zig build test-quiche -Dquiche=true

# Run benchmarks
zig build bench

# Build examples
zig build examples
```

### Build Options

```bash
# Disable OpenSSL (TLS support)
zig build -Dopenssl=false

# Enable QUIC/HTTP3 support
zig build -Dquiche=true

# Enable Brotli compression
zig build -Dbrotli=true
```

## Examples

The repository includes working examples in the `examples/` directory:

| Example | Command | Description |
|---------|---------|-------------|
| Simple Proxy | `zig build run-example-simple-proxy` | Basic reverse proxy |
| Load Balancing | `zig build run-example-load-balancing` | Multi-backend load balancer |
| Caching Proxy | `zig build run-example-caching` | Response caching proxy |

## License

Server Side Public License - See [LICENSE](../LICENSE) for details.

## Credits

This project is inspired by and ported from [Cloudflare's Pingora](https://github.com/cloudflare/pingora), a Rust-based HTTP proxy framework.
