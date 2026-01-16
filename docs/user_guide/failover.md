# Failover

Failover ensures high availability by automatically routing around failed backends.

## Failover Types

### Connection Failover

When a connection to an upstream fails:

```zig
fn failToConnect(
    self: *MyProxy,
    session: *pingora.Session,
    peer: *pingora.Peer,
    err: anyerror,
) !bool {
    // Log the failure
    self.logger.warn("Connection to {s}:{d} failed: {s}", .{
        peer.address,
        peer.port,
        @errorName(err),
    });

    // Update peer health
    peer.stats.failed_requests += 1;
    if (peer.stats.consecutive_failures >= 3) {
        peer.health_status = .unhealthy;
    }

    // Return true to retry with another peer
    return session.retry_count < self.config.max_retries;
}
```

### Request Failover

When a request fails after connection:

```zig
fn errorWhileProxying(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
) !u16 {
    switch (err) {
        error.UpstreamTimeout => {
            // Retry on timeout
            if (session.retry_count < 2) {
                session.retry_count += 1;
                return try self.retryRequest(session);
            }
            return 504; // Gateway Timeout
        },
        error.UpstreamConnectionReset => {
            // Retry on connection reset
            if (session.retry_count < 3) {
                return try self.retryRequest(session);
            }
            return 502; // Bad Gateway
        },
        else => return 500,
    }
}
```

## Retry Configuration

```zig
pub const RetryConfig = struct {
    /// Maximum retry attempts
    max_retries: u32 = 3,

    /// Delay between retries (ms)
    retry_delay_ms: u64 = 100,

    /// Exponential backoff multiplier
    backoff_multiplier: f64 = 2.0,

    /// Maximum backoff delay (ms)
    max_backoff_ms: u64 = 5000,

    /// Errors that trigger retry
    retriable_errors: []const anyerror = &[_]anyerror{
        error.ConnectionRefused,
        error.ConnectionReset,
        error.Timeout,
        error.BrokenPipe,
    },

    /// HTTP status codes that trigger retry
    retriable_status_codes: []const u16 = &[_]u16{ 502, 503, 504 },
};
```

## Implementing Failover

### Basic Failover

```zig
fn handleRequest(self: *MyProxy, session: *pingora.Session) !void {
    var last_error: ?anyerror = null;

    while (session.retry_count <= self.config.max_retries) {
        // Select peer (avoid previously failed peer)
        const peer = try self.selectPeer(session, last_error != null);

        // Try to proxy the request
        self.proxyRequest(session, peer) catch |err| {
            last_error = err;
            session.retry_count += 1;

            // Mark peer as potentially unhealthy
            peer.stats.failed_requests += 1;

            // Exponential backoff
            const delay = self.calculateBackoff(session.retry_count);
            std.time.sleep(delay * std.time.ns_per_ms);

            continue;
        };

        // Success!
        return;
    }

    // All retries exhausted
    return error.MaxRetriesExceeded;
}
```

### Peer Selection with Failover

```zig
fn selectPeer(
    self: *MyProxy,
    session: *pingora.Session,
    exclude_last: bool,
) !*pingora.Peer {
    const last_peer = session.upstream_peer;

    // Get all healthy peers
    var candidates = std.ArrayList(*pingora.Peer).init(self.allocator);
    defer candidates.deinit();

    for (self.peers) |peer| {
        if (peer.health_status != .unhealthy) {
            if (!exclude_last or peer != last_peer) {
                try candidates.append(peer);
            }
        }
    }

    if (candidates.items.len == 0) {
        return error.NoPeerAvailable;
    }

    // Select using load balancer
    return self.lb.selectFrom(candidates.items);
}
```

## Circuit Breaker Pattern

Prevent cascading failures:

```zig
pub const CircuitBreaker = struct {
    state: State,
    failure_count: u32,
    success_count: u32,
    last_failure_time: i64,

    pub const State = enum {
        closed,      // Normal operation
        open,        // Failing, reject requests
        half_open,   // Testing if recovered
    };

    pub fn allowRequest(self: *CircuitBreaker) bool {
        switch (self.state) {
            .closed => return true,
            .open => {
                // Check if timeout expired
                const now = std.time.milliTimestamp();
                if (now - self.last_failure_time > 30000) {
                    self.state = .half_open;
                    return true;
                }
                return false;
            },
            .half_open => return true,
        }
    }

    pub fn recordSuccess(self: *CircuitBreaker) void {
        switch (self.state) {
            .half_open => {
                self.success_count += 1;
                if (self.success_count >= 3) {
                    self.state = .closed;
                    self.failure_count = 0;
                }
            },
            else => {},
        }
    }

    pub fn recordFailure(self: *CircuitBreaker) void {
        self.failure_count += 1;
        self.last_failure_time = std.time.milliTimestamp();

        switch (self.state) {
            .closed => {
                if (self.failure_count >= 5) {
                    self.state = .open;
                }
            },
            .half_open => {
                self.state = .open;
                self.success_count = 0;
            },
            else => {},
        }
    }
};
```

### Using Circuit Breaker

```zig
fn proxyWithCircuitBreaker(
    self: *MyProxy,
    session: *pingora.Session,
    peer: *pingora.Peer,
) !void {
    const breaker = self.getCircuitBreaker(peer);

    if (!breaker.allowRequest()) {
        // Circuit open, try another peer
        return error.CircuitOpen;
    }

    self.proxyRequest(session, peer) catch |err| {
        breaker.recordFailure();
        return err;
    };

    breaker.recordSuccess();
}
```

## Failover Strategies

### Active-Passive

Primary backend with standby:

```zig
fn selectPeer(self: *MyProxy) !*pingora.Peer {
    // Try primary first
    if (self.primary.health_status == .healthy) {
        return self.primary;
    }

    // Failover to secondary
    if (self.secondary.health_status == .healthy) {
        self.logger.warn("Failing over to secondary", .{});
        return self.secondary;
    }

    return error.NoPeerAvailable;
}
```

### Active-Active

Distribute across multiple backends:

```zig
fn selectPeer(self: *MyProxy, hash_key: ?[]const u8) !*pingora.Peer {
    // Use consistent hashing for distribution
    if (hash_key) |key| {
        const peer = self.lb.selectConsistent(key);
        if (peer.health_status == .healthy) {
            return peer;
        }
        // Fall through to round-robin on failure
    }

    // Round-robin among healthy peers
    return self.lb.selectHealthy() orelse error.NoPeerAvailable;
}
```

### Geographic Failover

Route based on region:

```zig
fn selectPeer(self: *MyProxy, session: *pingora.Session) !*pingora.Peer {
    const region = self.detectRegion(session);

    // Try local region first
    if (self.getRegionalPeers(region)) |peers| {
        if (selectHealthy(peers)) |peer| {
            return peer;
        }
    }

    // Failover to other regions
    for (self.all_regions) |r| {
        if (r != region) {
            if (self.getRegionalPeers(r)) |peers| {
                if (selectHealthy(peers)) |peer| {
                    self.logger.warn("Regional failover from {s} to {s}", .{
                        region, r,
                    });
                    return peer;
                }
            }
        }
    }

    return error.NoPeerAvailable;
}
```

## Best Practices

1. **Set appropriate retry limits**: Too many retries can cascade failures
2. **Use exponential backoff**: Prevent overwhelming recovering backends
3. **Implement circuit breakers**: Protect against sustained failures
4. **Monitor failover events**: Track for capacity planning
5. **Test failover regularly**: Ensure it works when needed
6. **Consider idempotency**: Only retry safe requests automatically
