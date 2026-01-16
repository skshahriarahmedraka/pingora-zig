# Error Handling

Proper error handling ensures reliable proxy operation.

## Error Types

### Proxy Errors

```zig
pub const ProxyError = error{
    /// Failed to connect to upstream
    UpstreamConnectionFailed,
    /// Upstream peer selection failed
    NoPeerAvailable,
    /// Request was filtered/rejected
    RequestFiltered,
    /// Response was filtered/rejected
    ResponseFiltered,
    /// Upstream request timed out
    UpstreamTimeout,
    /// Upstream returned an error
    UpstreamError,
    /// Max retries exceeded
    MaxRetriesExceeded,
    /// Invalid request
    InvalidRequest,
    /// Invalid response from upstream
    InvalidUpstreamResponse,
    /// Session error
    SessionError,
    /// Cache error
    CacheError,
    /// Internal proxy error
    InternalError,
    /// Allocation failed
    OutOfMemory,
};
```

### HTTP Parser Errors

```zig
pub const ParseError = error{
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    InvalidStatusCode,
    InvalidHeader,
    HeaderTooLarge,
    BodyTooLarge,
    IncompleteData,
    MalformedChunk,
};
```

### Connection Errors

```zig
pub const ConnectionError = error{
    ConnectionRefused,
    ConnectionReset,
    ConnectionClosed,
    Timeout,
    TlsHandshakeFailed,
    DnsResolutionFailed,
    AddressInUse,
    NetworkUnreachable,
};
```

## Error Handling Callbacks

### failToConnect

Called when connection to upstream fails:

```zig
fn failToConnect(
    self: *MyProxy,
    session: *pingora.Session,
    peer: *pingora.Peer,
    err: anyerror,
) !bool {
    // Log the error
    self.logger.err("Failed to connect to {s}:{d}: {s}", .{
        peer.address,
        peer.port,
        @errorName(err),
    });

    // Update metrics
    self.metrics.connection_failures.inc();

    // Update peer health
    peer.stats.failed_requests += 1;
    peer.stats.consecutive_failures += 1;

    if (peer.stats.consecutive_failures >= 3) {
        peer.health_status = .unhealthy;
        self.logger.warn("Marked {s}:{d} as unhealthy", .{
            peer.address,
            peer.port,
        });
    }

    // Decide whether to retry
    const should_retry = switch (err) {
        error.ConnectionRefused,
        error.Timeout,
        error.NetworkUnreachable => session.retry_count < 3,
        error.TlsHandshakeFailed => false, // Don't retry TLS errors
        else => session.retry_count < 2,
    };

    return should_retry;
}
```

### errorWhileProxying

Called when error occurs during request/response:

```zig
fn errorWhileProxying(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
) !u16 {
    // Log with context
    self.logger.err("Error proxying request: {s}", .{@errorName(err)});

    if (session.upstream_peer) |peer| {
        self.logger.err("  Upstream: {s}:{d}", .{peer.address, peer.port});
    }

    if (session.reqHeader()) |req| {
        self.logger.err("  Request: {s} {s}", .{
            req.method.asStr(),
            req.uri.path,
        });
    }

    // Update metrics
    self.metrics.proxy_errors.inc();

    // Map error to status code
    return switch (err) {
        error.UpstreamTimeout => 504,
        error.UpstreamConnectionFailed => 502,
        error.NoPeerAvailable => 503,
        error.RequestFiltered => 403,
        error.InvalidRequest => 400,
        error.InvalidUpstreamResponse => 502,
        error.MaxRetriesExceeded => 502,
        else => 500,
    };
}
```

## Error Responses

### Custom Error Pages

```zig
fn generateErrorResponse(
    self: *MyProxy,
    session: *pingora.Session,
    status: u16,
    err: anyerror,
) !void {
    var response = pingora.ResponseHeader.init(self.allocator);
    defer response.deinit();

    response.setStatus(status);
    try response.headers.append("Content-Type", "application/json");

    const body = try std.json.stringifyAlloc(self.allocator, .{
        .error = @errorName(err),
        .status = status,
        .message = self.getErrorMessage(status),
        .request_id = session.request_id,
        .timestamp = std.time.timestamp(),
    }, .{});
    defer self.allocator.free(body);

    session.downstream_response = response;
    session.response_body = body;
}

fn getErrorMessage(self: *MyProxy, status: u16) []const u8 {
    return switch (status) {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "Unknown Error",
    };
}
```

### HTML Error Pages

```zig
fn generateHtmlErrorPage(status: u16, message: []const u8) []const u8 {
    return std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>{d} {s}</title></head>
        \\<body>
        \\<h1>{d} {s}</h1>
        \\<p>The requested resource could not be served.</p>
        \\<hr>
        \\<p><em>pingora-zig</em></p>
        \\</body>
        \\</html>
    , .{ status, message, status, message }) catch "";
}
```

## Error Recovery

### Retry Logic

```zig
fn handleRequestWithRetry(
    self: *MyProxy,
    session: *pingora.Session,
) !void {
    var last_error: ?anyerror = null;

    while (session.retry_count <= self.config.max_retries) : (session.retry_count += 1) {
        // Try to proxy
        self.proxyRequest(session) catch |err| {
            last_error = err;

            // Check if retriable
            if (!self.isRetriableError(err)) {
                return err;
            }

            // Exponential backoff
            const delay = self.calculateBackoff(session.retry_count);
            std.time.sleep(delay);

            // Select different peer
            session.upstream_peer = try self.selectAlternatePeer(session);
            continue;
        };

        // Success
        return;
    }

    // All retries exhausted
    return last_error orelse error.MaxRetriesExceeded;
}

fn isRetriableError(self: *MyProxy, err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionReset,
        error.Timeout,
        error.NetworkUnreachable,
        error.BrokenPipe => true,
        else => false,
    };
}
```

### Graceful Degradation

```zig
fn handleCacheError(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
) !void {
    // Log but don't fail the request
    self.logger.warn("Cache error: {s}, continuing without cache", .{
        @errorName(err),
    });

    // Disable caching for this request
    session.cache_enabled = false;

    // Continue with upstream request
}
```

## Error Logging

```zig
fn logError(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
    context: []const u8,
) void {
    const req = session.reqHeader();

    self.logger.err(
        \\Error in {s}:
        \\  Error: {s}
        \\  Request: {s} {s}
        \\  Client: {s}
        \\  Upstream: {s}
        \\  Retry count: {d}
        \\  Duration: {d}ms
    , .{
        context,
        @errorName(err),
        if (req) |r| r.method.asStr() else "?",
        if (req) |r| r.uri.path else "?",
        session.client_ip,
        if (session.upstream_peer) |p| p.address else "none",
        session.retry_count,
        session.getDuration(),
    });
}
```

## Best Practices

1. **Always handle errors**: Never ignore errors in production
2. **Log with context**: Include request/session info in error logs
3. **Map to appropriate status codes**: Return meaningful HTTP status codes
4. **Implement retries carefully**: Avoid retry storms
5. **Monitor error rates**: Alert on elevated error rates
6. **Provide useful error responses**: Help clients understand what went wrong
7. **Fail fast when appropriate**: Don't retry unrecoverable errors
8. **Clean up resources**: Ensure cleanup on error paths (use `errdefer`)
