# Request/Response Context

The session context holds all state for a single HTTP request as it flows through the proxy.

## Session Structure

```zig
pub const Session = struct {
    /// The allocator for this session
    allocator: Allocator,

    /// The downstream (client) request
    downstream_request: ?http.RequestHeader,

    /// The downstream response to send
    downstream_response: ?http.ResponseHeader,

    /// Request body (if buffered)
    request_body: ?[]const u8,

    /// Response body (if buffered)
    response_body: ?[]u8,

    /// The selected upstream peer
    upstream_peer: ?*upstream.Peer,

    /// Cache lookup result
    cache_result: ?cache.CacheLookupResult,

    /// Whether to cache this response
    cache_enabled: bool,

    /// Timing information
    timing: SessionTiming,

    /// Whether the request has been sent to upstream
    request_sent: bool,

    /// Whether the response has been received from upstream
    response_received: bool,

    /// Number of retry attempts
    retry_count: u32,

    /// Custom user context (opaque pointer)
    user_ctx: ?*anyopaque,
};
```

## Accessing Request Data

### Get Request Header

```zig
fn handleRequest(session: *pingora.Session) !void {
    // Get immutable request header
    if (session.reqHeader()) |req| {
        const method = req.method;
        const path = req.uri.path;
        const host = req.headers.get("Host");

        std.debug.print("Request: {s} {s}\n", .{ method.asStr(), path });
    }
}
```

### Get Mutable Request Header

```zig
fn modifyRequest(session: *pingora.Session) !void {
    // Get mutable request header for modification
    if (session.reqHeaderMut()) |req| {
        try req.headers.append("X-Request-Id", generateRequestId());
        try req.headers.remove("X-Internal-Header");
    }
}
```

### Access Request Body

```zig
fn processRequestBody(session: *pingora.Session) !void {
    if (session.request_body) |body| {
        // Process the request body
        const parsed = try json.parse(body);
        // ...
    }
}
```

## Accessing Response Data

### Get Response Header

```zig
fn handleResponse(session: *pingora.Session) !void {
    if (session.respHeader()) |resp| {
        const status = resp.status.code;
        const content_type = resp.headers.get("Content-Type");

        if (status >= 500) {
            // Log server errors
            logError(session);
        }
    }
}
```

### Modify Response

```zig
fn modifyResponse(session: *pingora.Session) !void {
    if (session.respHeaderMut()) |resp| {
        // Add security headers
        try resp.headers.append("X-Content-Type-Options", "nosniff");
        try resp.headers.append("X-Frame-Options", "DENY");

        // Remove internal headers
        try resp.headers.remove("X-Internal-Debug");
    }
}
```

## Timing Information

The session tracks timing for observability:

```zig
pub const SessionTiming = struct {
    /// When the request was received
    request_start: i64,

    /// When upstream connection was established
    upstream_connect: ?i64,

    /// When request was sent to upstream
    upstream_request_sent: ?i64,

    /// When response headers were received
    upstream_response_start: ?i64,

    /// When response was fully received
    upstream_response_end: ?i64,

    /// When response was sent to client
    response_sent: ?i64,
};
```

### Using Timing Data

```zig
fn logTiming(session: *pingora.Session) void {
    const timing = session.timing;

    if (timing.upstream_response_end) |end| {
        if (timing.upstream_connect) |start| {
            const upstream_latency = end - start;
            std.debug.print("Upstream latency: {d}ms\n", .{upstream_latency});
        }
    }

    if (timing.response_sent) |sent| {
        const total_time = sent - timing.request_start;
        std.debug.print("Total request time: {d}ms\n", .{total_time});
    }
}
```

## Custom User Context

Store custom data in the session:

```zig
const MyContext = struct {
    user_id: []const u8,
    request_id: []const u8,
    auth_level: u8,
};

fn setUserContext(session: *pingora.Session, ctx: *MyContext) void {
    session.user_ctx = @ptrCast(ctx);
}

fn getUserContext(session: *pingora.Session) ?*MyContext {
    if (session.user_ctx) |ptr| {
        return @ptrCast(@alignCast(ptr));
    }
    return null;
}
```

## Cache Context

### Check Cache Status

```zig
fn handleCacheResult(session: *pingora.Session) !void {
    if (session.cache_result) |result| {
        switch (result.status) {
            .hit => {
                // Serve from cache
                std.debug.print("Cache hit!\n", .{});
            },
            .miss => {
                // Enable caching for this response
                session.cache_enabled = true;
            },
            .stale => {
                // Serve stale while revalidating
                session.cache_enabled = true;
            },
            .bypass => {
                // Don't cache
                session.cache_enabled = false;
            },
        }
    }
}
```

## Upstream Context

### Access Selected Peer

```zig
fn logUpstream(session: *pingora.Session) void {
    if (session.upstream_peer) |peer| {
        std.debug.print("Upstream: {s}:{d}\n", .{
            peer.address,
            peer.port,
        });
        std.debug.print("Peer health: {s}\n", .{
            @tagName(peer.health_status),
        });
    }
}
```

### Track Retries

```zig
fn handleRetry(session: *pingora.Session) !void {
    session.retry_count += 1;

    if (session.retry_count > 3) {
        return error.MaxRetriesExceeded;
    }

    // Select a different upstream
    session.upstream_peer = try selectAlternatePeer(session);
}
```

## Session Lifecycle

```
1. Session created
   └── downstream_request populated

2. Request filter phase
   └── Modify request headers/body

3. Cache lookup
   └── cache_result populated

4. Upstream selection
   └── upstream_peer populated

5. Upstream request
   └── request_sent = true
   └── timing updated

6. Upstream response
   └── response_received = true
   └── downstream_response populated

7. Response filter phase
   └── Modify response headers/body

8. Send response
   └── timing.response_sent updated

9. Session cleanup
   └── deinit() called
```

## Best Practices

1. **Always check for null**: Request/response headers may not be populated at all phases
2. **Use timing data**: Track latency for observability
3. **Clean up user context**: Free any allocated user context in cleanup
4. **Don't store references**: Session data may be invalidated between phases
5. **Use retry_count**: Track retries to avoid infinite loops
