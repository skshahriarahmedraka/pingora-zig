# Rate Limiting

Rate limiting protects backends from traffic spikes and ensures fair resource allocation.

## Rate Limiter Types

### Sliding Window Estimator

Accurate rate estimation with low memory:

```zig
const pingora = @import("pingora");

var estimator = pingora.Estimator.init(allocator, .{
    .window_size_ms = 1000,    // 1 second window
    .slots = 10,               // 10 slots for granularity
});
defer estimator.deinit();

// Record requests
estimator.observe("client-ip-123", 1);

// Get current rate
const rate = estimator.rate("client-ip-123");
std.debug.print("Current rate: {d} req/s\n", .{rate});
```

### Token Bucket

Classic rate limiting with burst support:

```zig
pub const TokenBucket = struct {
    capacity: u32,           // Maximum tokens
    tokens: u32,             // Current tokens
    refill_rate: u32,        // Tokens per second
    last_refill: i64,        // Last refill timestamp

    pub fn init(capacity: u32, refill_rate: u32) TokenBucket {
        return .{
            .capacity = capacity,
            .tokens = capacity,
            .refill_rate = refill_rate,
            .last_refill = std.time.milliTimestamp(),
        };
    }

    pub fn tryAcquire(self: *TokenBucket, tokens: u32) bool {
        self.refill();
        if (self.tokens >= tokens) {
            self.tokens -= tokens;
            return true;
        }
        return false;
    }

    fn refill(self: *TokenBucket) void {
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.last_refill;
        const new_tokens = @divFloor(elapsed_ms * self.refill_rate, 1000);

        self.tokens = @min(self.capacity, self.tokens + @intCast(new_tokens));
        self.last_refill = now;
    }
};
```

### Rate Type

Simple rate tracking:

```zig
var rate = pingora.Rate.init(allocator, 60000); // 1 minute window
defer rate.deinit();

// Increment counter
rate.inc("user-123");

// Get rate
const requests_per_minute = rate.rate("user-123");
```

## Inflight Request Limiting

Limit concurrent requests:

```zig
var inflight = pingora.Inflight.init(allocator);
defer inflight.deinit();

// Try to start a request
if (!inflight.acquire("user-123", 10)) { // max 10 concurrent
    return error.TooManyRequests;
}

// Process request...
defer inflight.release("user-123");
```

## Implementation Examples

### Per-IP Rate Limiting

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const client_ip = session.client_ip;

    // Check rate
    const rate = self.rate_limiter.rate(client_ip);
    if (rate > self.config.requests_per_second) {
        return .{ .reject = .{
            .status = 429,
            .reason = "Too Many Requests",
        }};
    }

    // Record this request
    self.rate_limiter.observe(client_ip, 1);

    return .continue_processing;
}
```

### Per-User Rate Limiting

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Get user from auth header
    const user_id = self.extractUserId(req) orelse {
        // No auth, use IP-based limiting
        return self.ipRateLimit(session);
    };

    // Check user-specific limits
    const limit = self.getUserLimit(user_id);
    const rate = self.rate_limiter.rate(user_id);

    if (rate > limit) {
        // Add Retry-After header
        return .{ .respond = .{
            .status = 429,
            .headers = try self.rateLimitHeaders(limit, rate),
            .body = "{\"error\":\"rate_limit_exceeded\"}",
        }};
    }

    self.rate_limiter.observe(user_id, 1);
    return .continue_processing;
}
```

### Per-Endpoint Rate Limiting

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Different limits per endpoint
    const limit = self.getEndpointLimit(req.uri.path);

    // Create composite key
    var key_buf: [256]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{
        session.client_ip,
        req.uri.path,
    }) catch return .continue_processing;

    const rate = self.rate_limiter.rate(key);
    if (rate > limit) {
        return .{ .reject = .{
            .status = 429,
            .reason = "Too Many Requests",
        }};
    }

    self.rate_limiter.observe(key, 1);
    return .continue_processing;
}

fn getEndpointLimit(self: *MyProxy, path: []const u8) u32 {
    if (std.mem.startsWith(u8, path, "/api/search")) {
        return 10;  // 10 req/s for search
    } else if (std.mem.startsWith(u8, path, "/api/upload")) {
        return 2;   // 2 req/s for upload
    }
    return 100;     // 100 req/s default
}
```

### Tiered Rate Limiting

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Get user tier
    const tier = self.getUserTier(req);

    const limits = switch (tier) {
        .free => .{ .per_second = 1, .per_minute = 30, .per_hour = 500 },
        .basic => .{ .per_second = 10, .per_minute = 300, .per_hour = 5000 },
        .premium => .{ .per_second = 100, .per_minute = 3000, .per_hour = 50000 },
        .enterprise => .{ .per_second = 1000, .per_minute = 30000, .per_hour = 500000 },
    };

    const user_id = self.getUserId(req);

    // Check all tiers
    if (self.second_limiter.rate(user_id) > limits.per_second or
        self.minute_limiter.rate(user_id) > limits.per_minute or
        self.hour_limiter.rate(user_id) > limits.per_hour)
    {
        return .{ .reject = .{
            .status = 429,
            .reason = "Too Many Requests",
        }};
    }

    // Record in all windows
    self.second_limiter.observe(user_id, 1);
    self.minute_limiter.observe(user_id, 1);
    self.hour_limiter.observe(user_id, 1);

    return .continue_processing;
}
```

## Rate Limit Headers

Standard rate limit headers:

```zig
fn addRateLimitHeaders(
    response: *pingora.ResponseHeader,
    limit: u32,
    remaining: u32,
    reset_time: i64,
) !void {
    var buf: [32]u8 = undefined;

    // X-RateLimit-Limit
    const limit_str = try std.fmt.bufPrint(&buf, "{d}", .{limit});
    try response.headers.append("X-RateLimit-Limit", limit_str);

    // X-RateLimit-Remaining
    const remaining_str = try std.fmt.bufPrint(&buf, "{d}", .{remaining});
    try response.headers.append("X-RateLimit-Remaining", remaining_str);

    // X-RateLimit-Reset
    const reset_str = try std.fmt.bufPrint(&buf, "{d}", .{reset_time});
    try response.headers.append("X-RateLimit-Reset", reset_str);
}
```

## Distributed Rate Limiting

For multi-instance deployments:

```zig
pub const DistributedRateLimiter = struct {
    local: pingora.Estimator,
    sync_interval_ms: u64,

    // Sync with central store (Redis, etc.)
    pub fn sync(self: *DistributedRateLimiter, key: []const u8) !u64 {
        // Get local count
        const local_count = self.local.count(key);

        // Sync to central store and get global count
        const global_count = try self.centralStore.incrementAndGet(key, local_count);

        // Reset local counter
        self.local.reset(key);

        return global_count;
    }
};
```

## Configuration

```zig
pub const RateLimiterConfig = struct {
    /// Requests per second limit
    requests_per_second: u32 = 100,

    /// Burst size (token bucket capacity)
    burst_size: u32 = 50,

    /// Window size for sliding window (ms)
    window_size_ms: u64 = 1000,

    /// Number of slots in sliding window
    slots: u32 = 10,

    /// Response status code when rate limited
    limit_status: u16 = 429,

    /// Include Retry-After header
    include_retry_after: bool = true,
};
```

## Best Practices

1. **Choose appropriate algorithms**: Token bucket for burstiness, sliding window for accuracy
2. **Set reasonable limits**: Too strict loses users, too loose doesn't protect
3. **Implement graceful degradation**: Return cached/stale data when rate limited
4. **Add rate limit headers**: Help clients understand limits
5. **Log rate limit events**: Track abuse patterns
6. **Consider distributed limiting**: For multi-instance deployments
7. **Exempt internal services**: Allow higher limits for trusted sources
8. **Test under load**: Verify limits work as expected
