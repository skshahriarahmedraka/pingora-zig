# Peer Selection

Peers represent upstream backend servers. This guide covers peer management and selection strategies.

## Peer Structure

```zig
pub const Peer = struct {
    /// Peer address (IP or hostname)
    address: []const u8,

    /// Port number
    port: u16,

    /// Weight for load balancing (higher = more traffic)
    weight: u32,

    /// Current health status
    health_status: HealthStatus,

    /// Connection statistics
    stats: PeerStats,

    /// Custom peer options
    options: PeerOptions,
};

pub const HealthStatus = enum {
    healthy,
    unhealthy,
    unknown,
};

pub const PeerStats = struct {
    /// Total requests sent to this peer
    total_requests: u64,

    /// Failed requests
    failed_requests: u64,

    /// Current active connections
    active_connections: u32,

    /// Average response time (ms)
    avg_response_time_ms: u32,

    /// Last health check time
    last_health_check: i64,
};
```

## Creating Peers

### Basic Peer

```zig
var peer = pingora.Peer{
    .address = "192.168.1.10",
    .port = 8080,
    .weight = 1,
    .health_status = .healthy,
    .stats = .{},
    .options = .{},
};
```

### Peer with Options

```zig
var peer = pingora.Peer{
    .address = "backend.example.com",
    .port = 443,
    .weight = 2,
    .health_status = .healthy,
    .stats = .{},
    .options = .{
        .tls = true,
        .sni = "backend.example.com",
        .verify_cert = true,
        .connect_timeout_ms = 5000,
        .read_timeout_ms = 30000,
    },
};
```

## Upstream Groups

Group peers for load balancing:

```zig
var group = pingora.UpstreamGroup.init(allocator);
defer group.deinit();

// Add peers
try group.addPeer(.{
    .address = "192.168.1.10",
    .port = 8080,
    .weight = 2,
});
try group.addPeer(.{
    .address = "192.168.1.11",
    .port = 8080,
    .weight = 1,
});
try group.addPeer(.{
    .address = "192.168.1.12",
    .port = 8080,
    .weight = 1,
});

// Select a peer
if (group.selectHealthy()) |peer| {
    // Use peer
}
```

## Load Balancing Algorithms

### Round Robin

Distributes requests evenly across all healthy peers:

```zig
var lb = pingora.LoadBalancer.init(allocator, .round_robin);
defer lb.deinit();

try lb.addBackend("192.168.1.10", 8080, 1);
try lb.addBackend("192.168.1.11", 8080, 1);
try lb.addBackend("192.168.1.12", 8080, 1);

// Requests cycle through: 10 → 11 → 12 → 10 → 11 → ...
const peer1 = lb.select(null); // .10
const peer2 = lb.select(null); // .11
const peer3 = lb.select(null); // .12
const peer4 = lb.select(null); // .10
```

### Weighted Round Robin

Respects peer weights:

```zig
var lb = pingora.LoadBalancer.init(allocator, .weighted_round_robin);

try lb.addBackend("192.168.1.10", 8080, 3); // 3x traffic
try lb.addBackend("192.168.1.11", 8080, 1); // 1x traffic

// Distribution: 10, 10, 10, 11, 10, 10, 10, 11, ...
```

### Least Connections

Routes to the peer with fewest active connections:

```zig
var lb = pingora.LoadBalancer.init(allocator, .least_connections);

try lb.addBackend("192.168.1.10", 8080, 1);
try lb.addBackend("192.168.1.11", 8080, 1);

// Always selects the peer with lowest active_connections
```

### Consistent Hashing

Routes based on a key (for session affinity):

```zig
var lb = pingora.LoadBalancer.init(allocator, .consistent_hash);

try lb.addBackend("192.168.1.10", 8080, 100); // 100 virtual nodes
try lb.addBackend("192.168.1.11", 8080, 100);
try lb.addBackend("192.168.1.12", 8080, 100);

// Same key always routes to same peer (unless peer fails)
const peer1 = lb.select("user-123"); // .10
const peer2 = lb.select("user-123"); // .10 (same)
const peer3 = lb.select("user-456"); // .11 (different key)
```

## Custom Peer Selection

Implement custom selection logic in `upstream_peer`:

```zig
fn upstreamPeer(self: *MyProxy, session: *pingora.Session) !?*pingora.Peer {
    const req = session.reqHeader() orelse return null;

    // Route based on path
    if (std.mem.startsWith(u8, req.uri.path, "/api")) {
        return self.lb.select(null);
    }

    // Route based on header
    if (req.headers.get("X-Backend")) |backend| {
        return self.getPeerByName(backend);
    }

    // Route based on user
    if (getUserId(session)) |user_id| {
        // Consistent hashing for session affinity
        return self.lb.select(user_id);
    }

    return self.default_peer;
}
```

## Health Checking

### Passive Health Checks

Peers are marked unhealthy based on connection failures:

```zig
fn failToConnect(
    self: *MyProxy,
    session: *pingora.Session,
    peer: *pingora.Peer,
    err: anyerror,
) !bool {
    peer.stats.failed_requests += 1;

    // Mark unhealthy after 3 consecutive failures
    if (peer.stats.consecutive_failures >= 3) {
        peer.health_status = .unhealthy;
    }

    // Retry with different peer
    return true;
}
```

### Active Health Checks

Configure periodic health checks:

```zig
const health_config = pingora.HealthCheckConfig{
    .interval_ms = 5000,           // Check every 5 seconds
    .timeout_ms = 2000,            // 2 second timeout
    .unhealthy_threshold = 3,      // 3 failures → unhealthy
    .healthy_threshold = 2,        // 2 successes → healthy

    // HTTP health check
    .check_type = .http,
    .http_path = "/health",
    .expected_status = 200,
};

try group.enableHealthChecks(health_config);
```

### Custom Health Check

```zig
fn customHealthCheck(peer: *pingora.Peer) !bool {
    // Connect to peer
    var client = try pingora.HttpClient.connect(peer.address, peer.port);
    defer client.close();

    // Send health check request
    var req = pingora.RequestHeader.init(allocator);
    defer req.deinit();
    try req.setMethod(.GET);
    try req.setUri("/health");

    const resp = try client.sendRequest(&req, null);
    defer resp.deinit();

    // Check response
    if (resp.status.code == 200) {
        peer.health_status = .healthy;
        return true;
    }

    peer.health_status = .unhealthy;
    return false;
}
```

## Peer Statistics

Track peer performance:

```zig
fn updatePeerStats(peer: *pingora.Peer, response_time_ms: u32, success: bool) void {
    peer.stats.total_requests += 1;

    if (success) {
        peer.stats.consecutive_failures = 0;

        // Update average response time (exponential moving average)
        const alpha = 0.1;
        peer.stats.avg_response_time_ms = @intFromFloat(
            alpha * @as(f64, response_time_ms) +
            (1.0 - alpha) * @as(f64, peer.stats.avg_response_time_ms)
        );
    } else {
        peer.stats.failed_requests += 1;
        peer.stats.consecutive_failures += 1;
    }
}
```

## Best Practices

1. **Use appropriate algorithms**: Round-robin for stateless, consistent hashing for stateful
2. **Configure health checks**: Detect and route around failures quickly
3. **Set appropriate weights**: Distribute load based on server capacity
4. **Monitor statistics**: Track peer performance for capacity planning
5. **Handle failures gracefully**: Always have fallback logic
6. **Use connection pooling**: Reuse connections to reduce latency
