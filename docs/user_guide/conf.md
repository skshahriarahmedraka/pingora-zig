# Configuration

This guide covers configuration options for Pingora-Zig proxies.

## Proxy Configuration

### HttpProxyConfig

The main proxy configuration struct:

```zig
const pingora = @import("pingora");

const config = pingora.HttpProxyConfig{
    // Network settings
    .listen_port = 8080,              // Port to listen on
    .listen_address = "0.0.0.0",      // Bind address
    .max_connections = 10000,         // Maximum concurrent connections

    // Timeouts (in milliseconds)
    .connect_timeout_ms = 5000,       // Upstream connect timeout
    .read_timeout_ms = 30000,         // Read timeout
    .write_timeout_ms = 30000,        // Write timeout
    .idle_timeout_ms = 60000,         // Keep-alive idle timeout

    // Buffer sizes
    .read_buffer_size = 8192,         // Read buffer size
    .write_buffer_size = 8192,        // Write buffer size

    // Features
    .enable_keepalive = true,         // HTTP keep-alive
    .enable_caching = false,          // Response caching
    .max_retries = 3,                 // Upstream retry count
};
```

## HTTP Client Configuration

### HttpClientConfig

Configuration for the HTTP client used for upstream connections:

```zig
const client_config = pingora.HttpClientConfig{
    // Connection settings
    .connect_timeout_ms = 5000,
    .read_timeout_ms = 30000,
    .write_timeout_ms = 30000,

    // Connection pooling
    .max_idle_connections = 100,      // Per-host pool size
    .max_idle_time_ms = 90000,        // Max idle time before close
    .enable_keepalive = true,

    // HTTP settings
    .max_header_size = 8192,          // Maximum header size
    .max_body_size = 10_000_000,      // Maximum body size (10MB)
};
```

## HTTP Server Configuration

### HttpServerConfig

Configuration for the downstream HTTP server:

```zig
const server_config = pingora.HttpServerConfig{
    .listen_port = 8080,
    .listen_address = "0.0.0.0",
    .max_connections = 10000,

    // Request limits
    .max_request_line_size = 8192,
    .max_header_size = 8192,
    .max_headers_count = 100,

    // Timeouts
    .read_timeout_ms = 30000,
    .write_timeout_ms = 30000,
    .keepalive_timeout_ms = 60000,
};
```

## Cache Configuration

### HttpCacheConfig

Configuration for HTTP response caching:

```zig
const cache_config = pingora.HttpCacheConfig{
    // Capacity limits
    .max_entries = 10000,             // Maximum cached responses
    .max_memory_bytes = 100_000_000,  // 100MB memory limit

    // TTL settings
    .default_ttl_seconds = 300,       // Default TTL (5 minutes)
    .max_ttl_seconds = 86400,         // Maximum TTL (24 hours)
    .min_ttl_seconds = 1,             // Minimum TTL

    // Behavior
    .respect_cache_control = true,    // Honor Cache-Control headers
    .respect_vary = true,             // Honor Vary headers
    .cache_private = false,           // Cache private responses

    // Eviction
    .eviction_policy = .lru,          // LRU or TinyUFO
};
```

## Load Balancer Configuration

### Algorithm Selection

```zig
// Round-robin (default, simple rotation)
var lb = pingora.LoadBalancer.init(allocator, .round_robin);

// Weighted round-robin (respects backend weights)
var lb = pingora.LoadBalancer.init(allocator, .weighted_round_robin);

// Least connections (routes to least busy backend)
var lb = pingora.LoadBalancer.init(allocator, .least_connections);

// Consistent hashing (session affinity)
var lb = pingora.LoadBalancer.init(allocator, .consistent_hash);
```

### Health Check Configuration

```zig
const health_config = pingora.HealthCheckConfig{
    .interval_ms = 5000,              // Check every 5 seconds
    .timeout_ms = 2000,               // Health check timeout
    .unhealthy_threshold = 3,         // Failures before marking unhealthy
    .healthy_threshold = 2,           // Successes before marking healthy

    // HTTP health check
    .http_path = "/health",           // Health check endpoint
    .expected_status = 200,           // Expected status code
};
```

## TLS Configuration

### Server TLS

```zig
const tls_config = pingora.TlsServerConfig{
    .cert_path = "/etc/ssl/cert.pem",
    .key_path = "/etc/ssl/key.pem",

    // Protocol versions
    .min_version = .tls_1_2,
    .max_version = .tls_1_3,

    // Cipher configuration
    .cipher_list = "ECDHE+AESGCM:DHE+AESGCM",

    // Features
    .enable_session_tickets = true,
    .session_timeout_seconds = 300,

    // ALPN for HTTP/2
    .alpn_protocols = &[_][]const u8{ "h2", "http/1.1" },
};
```

### Client TLS

```zig
const client_tls = pingora.TlsClientConfig{
    // Verification
    .verify_peer = true,
    .ca_path = "/etc/ssl/certs",

    // SNI
    .server_name = "backend.example.com",

    // Session resumption
    .enable_session_cache = true,
};
```

## Rate Limiter Configuration

```zig
const rate_config = pingora.RateLimiterConfig{
    .requests_per_second = 100,       // Rate limit
    .burst_size = 50,                 // Burst allowance
    .window_size_ms = 1000,           // Sliding window size
};
```

## Connection Pool Configuration

```zig
const pool_config = pingora.PoolConfig{
    .max_size = 100,                  // Maximum connections per host
    .min_size = 10,                   // Minimum connections to keep
    .max_idle_time_ms = 90000,        // Max idle time
    .connection_timeout_ms = 5000,    // Connection timeout
    .health_check_interval_ms = 30000, // Health check frequency
};
```

## Environment Variables

Pingora-Zig can be configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PINGORA_LISTEN_PORT` | Listen port | 8080 |
| `PINGORA_LOG_LEVEL` | Log level (debug/info/warn/error) | info |
| `PINGORA_WORKERS` | Number of worker threads | CPU count |
| `PINGORA_MAX_CONNECTIONS` | Max connections | 10000 |

## Configuration Best Practices

1. **Timeouts**: Set appropriate timeouts based on your upstream latency
2. **Connection Pools**: Size pools based on expected traffic patterns
3. **Buffer Sizes**: Tune based on typical request/response sizes
4. **Health Checks**: Use aggressive health checks for quick failover
5. **Rate Limiting**: Protect backends from traffic spikes

## Example: Full Configuration

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = 8080,
        .max_connections = 10000,
        .connect_timeout_ms = 5000,
        .read_timeout_ms = 30000,
        .enable_keepalive = true,
        .enable_caching = true,
        .max_retries = 3,
    });
    defer proxy.deinit();

    // Configure cache
    try proxy.configureCache(.{
        .max_entries = 10000,
        .default_ttl_seconds = 300,
    });

    // Configure load balancer
    try proxy.configureLoadBalancer(.weighted_round_robin);
    try proxy.addBackend("192.168.1.10", 8080, 2);
    try proxy.addBackend("192.168.1.11", 8080, 1);

    try proxy.serve();
}
```
