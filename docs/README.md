# Pingora-Zig Documentation
![Pingora banner image](./docs/assets/zingora.png)
A high-performance HTTP proxy framework written in pure Zig, inspired by Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

## Overview

Pingora-Zig provides a complete toolkit for building fast, reliable HTTP proxies and load balancers. It features:

- **Pure Zig Implementation** - No Rust dependencies, minimal C dependencies (only OpenSSL for TLS and zlib for compression)
- **HTTP/1.1 Support** - Full request/response parsing, connection pooling, keep-alive
- **HTTP/2 Support** - Frame parsing, HPACK compression, stream multiplexing, flow control
- **WebSocket Support** - RFC 6455 compliant with per-message deflate compression (RFC 7692)
- **TLS/SSL** - OpenSSL integration with session resumption, ALPN, SNI
- **Load Balancing** - Round-robin, weighted round-robin, least connections, consistent hashing
- **Caching** - HTTP response caching with TTL, LRU eviction, TinyUFO algorithm
- **Connection Pooling** - Efficient connection reuse with health tracking

## Documentation Structure

### Getting Started

- **[Quick Start Guide](quick_start.md)** - Get up and running in 5 minutes

### User Guide

- **[Index](user_guide/index.md)** - Overview of the user guide
- **[Configuration](user_guide/conf.md)** - Configuring your proxy
- **[Request/Response Context](user_guide/ctx.md)** - Working with request context
- **[Proxy Phases](user_guide/phase.md)** - Understanding the proxy lifecycle
- **[Phase Chart](user_guide/phase_chart.md)** - Visual guide to proxy phases
- **[Peer Selection](user_guide/peer.md)** - Upstream peer management
- **[Connection Pooling](user_guide/pooling.md)** - Connection pool configuration
- **[Failover](user_guide/failover.md)** - Handling upstream failures
- **[Request/Response Modification](user_guide/modify_filter.md)** - Filtering and transforming traffic
- **[Rate Limiting](user_guide/rate_limiter.md)** - Traffic rate control
- **[Error Handling](user_guide/errors.md)** - Managing errors gracefully
- **[Error Logging](user_guide/error_log.md)** - Logging configuration
- **[Panic Handling](user_guide/panic.md)** - Crash recovery
- **[Graceful Shutdown](user_guide/graceful.md)** - Zero-downtime restarts
- **[Start/Stop](user_guide/start_stop.md)** - Service lifecycle management
- **[Daemon Mode](user_guide/daemon.md)** - Running as a background service
- **[Systemd Integration](user_guide/systemd.md)** - Linux service management
- **[Prometheus Metrics](user_guide/prom.md)** - Observability and monitoring
- **[Internals](user_guide/internals.md)** - Deep dive into architecture

## Module Overview

### Level 0: Foundation (No Dependencies)

| Module | Description |
|--------|-------------|
| `error` | Error types and result handling |
| `timeout` | Timer wheel for fast timeout management |
| `lru` | Weighted LRU cache implementation |
| `tinyufo` | TinyLFU + S3-FIFO cache eviction |
| `ketama` | Consistent hash ring for load balancing |
| `linked_list` | Intrusive doubly-linked list |

### Level 1: HTTP Primitives

| Module | Description |
|--------|-------------|
| `http` | HTTP types (Method, Version, Headers, Request/Response) |
| `http_parser` | HTTP/1.1 request/response parsing |
| `limits` | Rate limiting with sliding window estimator |
| `memory_cache` | In-memory cache with TTL support |
| `pool` | Generic connection pooling |

### Level 2: Infrastructure

| Module | Description |
|--------|-------------|
| `header_serde` | Header serialization to wire format |
| `runtime` | Task queue and async primitives |
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

### Level 4: Application Layer

| Module | Description |
|--------|-------------|
| `cache` | HTTP response caching layer |
| `http2` | HTTP/2 protocol (frames, HPACK, streams) |
| `websocket` | WebSocket protocol (RFC 6455, RFC 7692) |

### Level 5: Proxy Framework

| Module | Description |
|--------|-------------|
| `proxy` | Complete HTTP proxy framework |

## Requirements

- **Zig**: 0.13.0 or later
- **OpenSSL**: For TLS support (optional, enabled by default)
- **zlib**: For WebSocket per-message deflate compression

## Building

```bash
# Build the library
cd pingora-zig && zig build

# Run all tests
cd pingora-zig && zig build test

# Run TLS tests (requires OpenSSL)
cd pingora-zig && zig build test-tls

# Run benchmarks
cd pingora-zig && zig build bench
```

## License

Apache-2.0 - See [LICENSE](../LICENSE) for details.

## Credits

This project is inspired by and ported from [Cloudflare's Pingora](https://github.com/cloudflare/pingora), a Rust-based HTTP proxy framework.
