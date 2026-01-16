# Connection Pooling

Connection pooling reuses TCP connections to upstream servers, reducing latency and resource usage.

## Overview

Without pooling:
```
Request 1: Connect → Send → Receive → Close
Request 2: Connect → Send → Receive → Close  (new connection)
Request 3: Connect → Send → Receive → Close  (new connection)
```

With pooling:
```
Request 1: Connect → Send → Receive → Return to pool
Request 2: Get from pool → Send → Receive → Return to pool  (reused!)
Request 3: Get from pool → Send → Receive → Return to pool  (reused!)
```

## Connection Pool Structure

```zig
pub const ConnectionPool = struct {
    allocator: Allocator,
    
    /// Pool configuration
    config: PoolConfig,
    
    /// Connections by host:port key
    pools: std.StringHashMap(HostPool),
    
    /// Statistics
    stats: PoolStats,
};

pub const PoolConfig = struct {
    /// Maximum connections per host
    max_size: u32 = 100,
    
    /// Minimum connections to keep warm
    min_size: u32 = 0,
    
    /// Maximum idle time before closing (ms)
    max_idle_time_ms: u64 = 90000,
    
    /// Connection timeout (ms)
    connection_timeout_ms: u64 = 5000,
    
    /// Health check interval (ms)
    health_check_interval_ms: u64 = 30000,
};
```

## Basic Usage

```zig
const pingora = @import("pingora");

var pool = pingora.ConnectionPool.init(allocator, .{
    .max_size = 100,
    .max_idle_time_ms = 90000,
});
defer pool.deinit();

// Get a connection
const conn = try pool.acquire("192.168.1.10", 8080);

// Use the connection
try conn.write(request_data);
const response = try conn.read();

// Return to pool (or close on error)
pool.release(conn);
```

## Pool Configuration

### High-Traffic Configuration

```zig
const config = pingora.PoolConfig{
    .max_size = 500,              // Large pool
    .min_size = 50,               // Keep connections warm
    .max_idle_time_ms = 120000,   // 2 minute idle timeout
    .connection_timeout_ms = 3000, // Fast timeout
};
```

### Low-Latency Configuration

```zig
const config = pingora.PoolConfig{
    .max_size = 200,
    .min_size = 20,               // Pre-warm connections
    .max_idle_time_ms = 60000,    // 1 minute idle
    .connection_timeout_ms = 1000, // Very fast timeout
    .health_check_interval_ms = 10000, // Frequent health checks
};
```

### Resource-Constrained Configuration

```zig
const config = pingora.PoolConfig{
    .max_size = 20,               // Small pool
    .min_size = 0,                // No pre-warming
    .max_idle_time_ms = 30000,    // 30 second idle
    .connection_timeout_ms = 10000, // Longer timeout
};
```

## Connection Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    CONNECTION LIFECYCLE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. ACQUIRE                                                 │
│     ├── Check pool for idle connection                      │
│     ├── If found and healthy → return connection            │
│     ├── If found but unhealthy → close, try next            │
│     └── If none available → create new connection           │
│                                                             │
│  2. USE                                                     │
│     ├── Send request                                        │
│     ├── Receive response                                    │
│     └── Track usage statistics                              │
│                                                             │
│  3. RELEASE                                                 │
│     ├── If connection healthy → return to pool              │
│     ├── If connection error → close connection              │
│     └── If pool full → close connection                     │
│                                                             │
│  4. EVICTION                                                │
│     ├── Periodic cleanup of idle connections                │
│     ├── Close connections exceeding max_idle_time           │
│     └── Maintain min_size warm connections                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Pool Statistics

```zig
pub const PoolStats = struct {
    /// Total connections created
    connections_created: u64,
    
    /// Total connections closed
    connections_closed: u64,
    
    /// Pool hits (reused connections)
    pool_hits: u64,
    
    /// Pool misses (new connections)
    pool_misses: u64,
    
    /// Current idle connections
    idle_connections: u32,
    
    /// Current active connections
    active_connections: u32,
};

// Access statistics
const stats = pool.getStats();
const hit_rate = @as(f64, stats.pool_hits) / 
                 @as(f64, stats.pool_hits + stats.pool_misses);
std.debug.print("Pool hit rate: {d:.2}%\n", .{hit_rate * 100});
```

## Connection Health

### Checking Connection Health

```zig
fn isConnectionHealthy(conn: *Connection) bool {
    // Check if connection is still open
    if (conn.isClosed()) return false;
    
    // Check if connection has pending data (unexpected)
    if (conn.hasPendingData()) return false;
    
    // Check idle time
    const idle_time = std.time.milliTimestamp() - conn.last_used;
    if (idle_time > config.max_idle_time_ms) return false;
    
    return true;
}
```

### Connection Validation

```zig
// Validate before use
const conn = try pool.acquire("host", 8080);
if (!conn.validate()) {
    pool.discard(conn);
    // Get a new connection
    conn = try pool.acquireNew("host", 8080);
}
```

## Per-Host Pools

Each upstream host has its own pool:

```zig
// Separate pools for each backend
pool.acquire("backend1.example.com", 8080); // Pool A
pool.acquire("backend2.example.com", 8080); // Pool B
pool.acquire("backend1.example.com", 8080); // Pool A (same as first)
```

## TLS Connection Pooling

TLS connections can also be pooled:

```zig
var tls_pool = pingora.ConnectionPool.init(allocator, .{
    .max_size = 50,
    .max_idle_time_ms = 60000,
});

// TLS connections preserve session state
const conn = try tls_pool.acquireTls("secure.example.com", 443, .{
    .verify_cert = true,
    .sni = "secure.example.com",
});

// Session resumption reduces handshake overhead
```

## HTTP Keep-Alive Integration

Connection pooling works with HTTP keep-alive:

```zig
fn handleResponse(conn: *Connection, response: *Response) !void {
    // Check if connection can be reused
    const keep_alive = response.isKeepAlive();
    
    if (keep_alive) {
        // Return to pool for reuse
        pool.release(conn);
    } else {
        // Server requested close
        pool.discard(conn);
    }
}
```

## Best Practices

### 1. Size Pools Appropriately

```zig
// Calculate based on expected traffic
// max_size = peak_requests_per_second * avg_response_time_seconds
const max_size: u32 = 1000 * 0.1; // 100 connections for 1000 RPS, 100ms latency
```

### 2. Handle Pool Exhaustion

```zig
const conn = pool.acquire("host", 8080) catch |err| {
    if (err == error.PoolExhausted) {
        // Wait and retry, or fail gracefully
        std.time.sleep(10 * std.time.ns_per_ms);
        return pool.acquire("host", 8080);
    }
    return err;
};
```

### 3. Monitor Pool Health

```zig
fn monitorPool(pool: *ConnectionPool) void {
    const stats = pool.getStats();
    
    // Alert on low hit rate
    const hit_rate = stats.pool_hits / (stats.pool_hits + stats.pool_misses);
    if (hit_rate < 0.8) {
        log.warn("Low pool hit rate: {d}%", .{hit_rate * 100});
    }
    
    // Alert on pool saturation
    if (stats.active_connections > pool.config.max_size * 0.9) {
        log.warn("Pool near capacity: {d}/{d}", .{
            stats.active_connections,
            pool.config.max_size,
        });
    }
}
```

### 4. Clean Up Properly

```zig
// Always release or discard connections
const conn = try pool.acquire("host", 8080);
errdefer pool.discard(conn);

try sendRequest(conn);
const response = try receiveResponse(conn);

if (response.isKeepAlive()) {
    pool.release(conn);
} else {
    pool.discard(conn);
}
```
