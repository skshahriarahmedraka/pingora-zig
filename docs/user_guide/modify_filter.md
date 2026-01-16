# Request/Response Modification

This guide covers filtering and transforming HTTP traffic.

## Request Modification

### Adding Headers

```zig
fn upstreamRequestFilter(
    self: *MyProxy,
    session: *pingora.Session,
    request: *pingora.RequestHeader,
) !pingora.FilterResult {
    // Add tracing headers
    try request.headers.append("X-Request-Id", session.request_id);
    try request.headers.append("X-Forwarded-For", session.client_ip);
    try request.headers.append("X-Forwarded-Proto", "https");

    // Add timestamp
    var buf: [32]u8 = undefined;
    const timestamp = std.fmt.bufPrint(&buf, "{d}", .{
        std.time.milliTimestamp(),
    }) catch unreachable;
    try request.headers.append("X-Request-Time", timestamp);

    return .continue_processing;
}
```

### Removing Headers

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    if (session.reqHeaderMut()) |req| {
        // Remove sensitive headers
        try req.headers.remove("Authorization");
        try req.headers.remove("Cookie");
        try req.headers.remove("X-Internal-Token");

        // Remove hop-by-hop headers
        try req.headers.remove("Connection");
        try req.headers.remove("Keep-Alive");
        try req.headers.remove("Proxy-Authorization");
        try req.headers.remove("TE");
        try req.headers.remove("Trailer");
        try req.headers.remove("Transfer-Encoding");
        try req.headers.remove("Upgrade");
    }
    return .continue_processing;
}
```

### Modifying Headers

```zig
fn upstreamRequestFilter(
    self: *MyProxy,
    session: *pingora.Session,
    request: *pingora.RequestHeader,
) !pingora.FilterResult {
    // Rewrite Host header
    try request.headers.insert("Host", "internal-api.local");

    // Modify User-Agent
    if (request.headers.get("User-Agent")) |ua| {
        var new_ua = try std.fmt.allocPrint(
            self.allocator,
            "{s} (via pingora-zig)",
            .{ua},
        );
        try request.headers.insert("User-Agent", new_ua);
    }

    return .continue_processing;
}
```

### Modifying URI

```zig
fn upstreamRequestFilter(
    self: *MyProxy,
    session: *pingora.Session,
    request: *pingora.RequestHeader,
) !pingora.FilterResult {
    // Rewrite path
    const original_path = request.uri.path;

    if (std.mem.startsWith(u8, original_path, "/api/v1")) {
        // Rewrite /api/v1/* to /v1/*
        const new_path = original_path[4..]; // Remove "/api"
        request.uri.path = new_path;
    }

    // Add query parameter
    if (request.uri.query) |query| {
        const new_query = try std.fmt.allocPrint(
            self.allocator,
            "{s}&internal=true",
            .{query},
        );
        request.uri.query = new_query;
    } else {
        request.uri.query = "internal=true";
    }

    return .continue_processing;
}
```

## Response Modification

### Adding Security Headers

```zig
fn responseFilter(
    self: *MyProxy,
    session: *pingora.Session,
    response: *pingora.ResponseHeader,
) !pingora.FilterResult {
    // Security headers
    try response.headers.append("X-Content-Type-Options", "nosniff");
    try response.headers.append("X-Frame-Options", "DENY");
    try response.headers.append("X-XSS-Protection", "1; mode=block");
    try response.headers.append("Referrer-Policy", "strict-origin-when-cross-origin");

    // HSTS
    try response.headers.append(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
    );

    // CSP
    try response.headers.append(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'",
    );

    return .continue_processing;
}
```

### Removing Internal Headers

```zig
fn responseFilter(
    self: *MyProxy,
    session: *pingora.Session,
    response: *pingora.ResponseHeader,
) !pingora.FilterResult {
    // Remove internal/debug headers
    try response.headers.remove("X-Internal-Request-Id");
    try response.headers.remove("X-Backend-Server");
    try response.headers.remove("X-Debug-Info");
    try response.headers.remove("Server");

    // Add generic server header
    try response.headers.append("Server", "pingora-zig");

    return .continue_processing;
}
```

### Modifying Cache Headers

```zig
fn responseFilter(
    self: *MyProxy,
    session: *pingora.Session,
    response: *pingora.ResponseHeader,
) !pingora.FilterResult {
    const req = session.reqHeader();

    // Adjust caching based on content type
    if (response.headers.get("Content-Type")) |ct| {
        if (std.mem.startsWith(u8, ct, "image/") or
            std.mem.startsWith(u8, ct, "font/"))
        {
            // Long cache for static assets
            try response.headers.insert(
                "Cache-Control",
                "public, max-age=31536000, immutable",
            );
        } else if (std.mem.startsWith(u8, ct, "text/html")) {
            // Short cache for HTML
            try response.headers.insert(
                "Cache-Control",
                "public, max-age=300, must-revalidate",
            );
        }
    }

    // Disable caching for authenticated requests
    if (req) |r| {
        if (r.headers.get("Authorization") != null) {
            try response.headers.insert("Cache-Control", "private, no-store");
        }
    }

    return .continue_processing;
}
```

## Request Body Modification

```zig
fn requestBodyFilter(
    self: *MyProxy,
    session: *pingora.Session,
    body: []const u8,
) ![]const u8 {
    // Parse JSON body
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        self.allocator,
        body,
        .{},
    );
    defer parsed.deinit();

    // Modify the JSON
    var root = parsed.value.object;
    try root.put("modified_by", .{ .string = "proxy" });
    try root.put("timestamp", .{ .integer = std.time.timestamp() });

    // Serialize back
    return try std.json.stringifyAlloc(self.allocator, root, .{});
}
```

## Response Body Modification

```zig
fn responseBodyFilter(
    self: *MyProxy,
    session: *pingora.Session,
    body: []const u8,
) ![]const u8 {
    const content_type = session.respHeader().?.headers.get("Content-Type");

    // Only modify HTML
    if (content_type) |ct| {
        if (!std.mem.startsWith(u8, ct, "text/html")) {
            return body;
        }
    }

    // Inject script before </body>
    const script = "<script src=\"/analytics.js\"></script>";
    const insert_pos = std.mem.lastIndexOf(u8, body, "</body>") orelse body.len;

    var result = try self.allocator.alloc(u8, body.len + script.len);
    @memcpy(result[0..insert_pos], body[0..insert_pos]);
    @memcpy(result[insert_pos..][0..script.len], script);
    @memcpy(result[insert_pos + script.len ..], body[insert_pos..]);

    return result;
}
```

## Rejecting Requests

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Block by User-Agent
    if (req.headers.get("User-Agent")) |ua| {
        if (std.mem.indexOf(u8, ua, "BadBot") != null) {
            return .{ .reject = .{
                .status = 403,
                .reason = "Forbidden",
            }};
        }
    }

    // Block by path
    if (std.mem.startsWith(u8, req.uri.path, "/admin")) {
        if (!self.isAuthorized(session)) {
            return .{ .reject = .{
                .status = 401,
                .reason = "Unauthorized",
            }};
        }
    }

    // Block large requests
    if (req.headers.get("Content-Length")) |cl| {
        const size = std.fmt.parseInt(u64, cl, 10) catch 0;
        if (size > 10_000_000) { // 10MB
            return .{ .reject = .{
                .status = 413,
                .reason = "Request Entity Too Large",
            }};
        }
    }

    return .continue_processing;
}
```

## Returning Custom Responses

```zig
fn requestFilter(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    // Handle health check directly
    if (std.mem.eql(u8, req.uri.path, "/health")) {
        var headers = pingora.Headers.init(self.allocator);
        try headers.append("Content-Type", "application/json");

        return .{ .respond = .{
            .status = 200,
            .headers = &headers,
            .body = "{\"status\":\"ok\"}",
        }};
    }

    // Handle maintenance mode
    if (self.maintenance_mode) {
        var headers = pingora.Headers.init(self.allocator);
        try headers.append("Content-Type", "text/html");
        try headers.append("Retry-After", "3600");

        return .{ .respond = .{
            .status = 503,
            .headers = &headers,
            .body = "<html><body><h1>Maintenance</h1></body></html>",
        }};
    }

    return .continue_processing;
}
```

## Best Practices

1. **Preserve important headers**: Don't remove headers needed by backends
2. **Handle encoding correctly**: Be careful with Content-Encoding when modifying bodies
3. **Update Content-Length**: When modifying body, update the Content-Length header
4. **Log modifications**: Track what was modified for debugging
5. **Consider performance**: Body modification requires buffering the entire response
6. **Test thoroughly**: Header/body modifications can break applications
