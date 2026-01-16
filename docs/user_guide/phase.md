# Proxy Phases

Pingora-Zig processes requests through a series of phases, each providing hooks for custom logic.

## Phase Overview

```
Client Request
      │
      ▼
┌─────────────────┐
│ request_filter  │ ──► Inspect/modify/reject request
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  cache_lookup   │ ──► Check cache for response
└────────┬────────┘
         │
    ┌────┴────┐
    │ HIT?    │
    └────┬────┘
    YES  │  NO
    ┌────┘  └────┐
    │            │
    ▼            ▼
┌────────┐  ┌─────────────────┐
│ return │  │ upstream_peer   │ ──► Select backend server
│ cached │  └────────┬────────┘
└────────┘           │
                     ▼
            ┌─────────────────┐
            │upstream_request │ ──► Modify request to upstream
            │    _filter      │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │ send to         │
            │ upstream        │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │response_filter  │ ──► Inspect/modify response
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │ cache_store     │ ──► Store response in cache
            └────────┬────────┘
                     │
      ◄──────────────┘
      │
      ▼
┌─────────────────┐
│ logging         │ ──► Log request/response
└────────┬────────┘
         │
         ▼
   Send to Client
```

## Phase Callbacks

### 1. request_filter

Called immediately after receiving the client request. Use this to:
- Validate requests
- Add/remove/modify headers
- Reject malicious requests
- Set up request context

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Reject requests without Host header
    if (req.headers.get("Host") == null) {
        return .{ .reject = .{
            .status = 400,
            .reason = "Missing Host header",
        }};
    }

    // Add request ID
    if (session.reqHeaderMut()) |r| {
        try r.headers.append("X-Request-Id", generateUuid());
    }

    return .continue_processing;
}
```

### 2. upstream_peer

Called to select the upstream server. Use this to:
- Implement custom load balancing
- Route based on request attributes
- Handle service discovery

```zig
fn upstreamPeer(
    self: *MyProxy,
    session: *pingora.Session,
) !?*pingora.Peer {
    const req = session.reqHeader() orelse return null;
    const path = req.uri.path;

    // Route based on path
    if (std.mem.startsWith(u8, path, "/api/v2")) {
        return self.api_v2_backend;
    } else if (std.mem.startsWith(u8, path, "/api")) {
        return self.api_v1_backend;
    } else if (std.mem.startsWith(u8, path, "/static")) {
        return self.static_backend;
    }

    return self.default_backend;
}
```

### 3. upstream_request_filter

Called before sending the request to upstream. Use this to:
- Add authentication headers
- Modify the request for the backend
- Add tracing headers

```zig
fn upstreamRequestFilter(
    self: *MyProxy,
    session: *pingora.Session,
    upstream_request: *pingora.RequestHeader,
) !pingora.FilterResult {
    // Add internal headers for backend
    try upstream_request.headers.append("X-Real-IP", session.client_ip);
    try upstream_request.headers.append("X-Forwarded-Proto", "https");

    // Add authentication
    if (self.getBackendToken()) |token| {
        try upstream_request.headers.append("Authorization", token);
    }

    return .continue_processing;
}
```

### 4. response_filter

Called after receiving the response from upstream. Use this to:
- Add security headers
- Modify response headers
- Transform response body
- Decide whether to cache

```zig
fn responseFilter(
    self: *MyProxy,
    session: *pingora.Session,
    response: *pingora.ResponseHeader,
) !pingora.FilterResult {
    // Add security headers
    try response.headers.append("X-Content-Type-Options", "nosniff");
    try response.headers.append("X-Frame-Options", "DENY");
    try response.headers.append("Strict-Transport-Security", "max-age=31536000");

    // Remove internal headers
    try response.headers.remove("X-Internal-Debug");
    try response.headers.remove("X-Backend-Server");

    // Disable caching for errors
    if (response.status.code >= 500) {
        session.cache_enabled = false;
    }

    return .continue_processing;
}
```

### 5. logging

Called after the response is sent. Use this to:
- Log requests
- Update metrics
- Clean up resources

```zig
fn logging(
    self: *MyProxy,
    session: *pingora.Session,
    error_info: ?*pingora.Error,
) void {
    const timing = session.timing;
    const req = session.reqHeader();
    const resp = session.respHeader();

    // Calculate latency
    const latency = if (timing.response_sent) |sent|
        sent - timing.request_start
    else
        0;

    // Log the request
    self.logger.log(.info, "{s} {s} {d} {d}ms", .{
        if (req) |r| r.method.asStr() else "???",
        if (req) |r| r.uri.path else "???",
        if (resp) |r| r.status.code else 0,
        latency,
    });

    // Update metrics
    self.metrics.requests_total.inc();
    self.metrics.latency_histogram.observe(latency);

    if (error_info) |err| {
        self.metrics.errors_total.inc();
        self.logger.log(.err, "Request error: {s}", .{err.message});
    }
}
```

## Filter Results

Each filter can return a `FilterResult`:

```zig
pub const FilterResult = union(enum) {
    /// Continue to the next phase
    continue_processing,

    /// Reject the request with a status code
    reject: struct {
        status: u16,
        reason: []const u8,
    },

    /// Return a custom response immediately
    respond: struct {
        status: u16,
        headers: *pingora.Headers,
        body: ?[]const u8,
    },

    /// Retry with a different upstream
    retry,

    /// Skip remaining filters in this phase
    skip_remaining,
};
```

## Error Handling in Phases

Errors during any phase trigger error handling:

```zig
fn failToConnect(
    self: *MyProxy,
    session: *pingora.Session,
    peer: *pingora.Peer,
    err: anyerror,
) !bool {
    // Log the failure
    self.logger.log(.warn, "Failed to connect to {s}:{d}: {s}", .{
        peer.address,
        peer.port,
        @errorName(err),
    });

    // Mark peer unhealthy
    peer.health_status = .unhealthy;

    // Return true to retry with another peer
    return session.retry_count < 3;
}

fn errorWhileProxying(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
) !u16 {
    // Return appropriate status code
    return switch (err) {
        error.UpstreamTimeout => 504, // Gateway Timeout
        error.UpstreamConnectionFailed => 502, // Bad Gateway
        error.RequestFiltered => 403, // Forbidden
        else => 500, // Internal Server Error
    };
}
```

## Phase Ordering

Phases are executed in strict order:

1. **request_filter** - First chance to inspect/modify request
2. **cache_lookup** - Check if response is cached (if caching enabled)
3. **upstream_peer** - Select upstream (skipped on cache hit)
4. **upstream_request_filter** - Modify upstream request
5. **connected_to_upstream** - Called after successful connection
6. **response_filter** - Modify response from upstream
7. **cache_store** - Store response in cache (if cacheable)
8. **logging** - Final logging phase

## Best Practices

1. **Keep filters fast**: Filters run synchronously for each request
2. **Handle errors gracefully**: Always handle potential failures
3. **Use appropriate phases**: Don't do heavy work in early phases
4. **Log appropriately**: Use the logging phase for request logging
5. **Clean up resources**: Free any allocated resources in logging phase
