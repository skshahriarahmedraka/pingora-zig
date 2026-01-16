# Graceful Shutdown

Graceful shutdown allows the proxy to stop accepting new connections while completing in-flight requests.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    GRACEFUL SHUTDOWN                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Receive shutdown signal (SIGTERM/SIGINT)                │
│  2. Stop accepting new connections                          │
│  3. Wait for in-flight requests to complete                 │
│  4. Close idle connections                                  │
│  5. Drain connection pools                                  │
│  6. Exit cleanly                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Implementation

### Signal Handling

```zig
const std = @import("std");

pub const ShutdownHandler = struct {
    shutdown_requested: std.atomic.Value(bool),
    in_flight_requests: std.atomic.Value(u32),

    pub fn init() ShutdownHandler {
        return .{
            .shutdown_requested = std.atomic.Value(bool).init(false),
            .in_flight_requests = std.atomic.Value(u32).init(0),
        };
    }

    pub fn requestShutdown(self: *ShutdownHandler) void {
        self.shutdown_requested.store(true, .seq_cst);
    }

    pub fn isShuttingDown(self: *ShutdownHandler) bool {
        return self.shutdown_requested.load(.seq_cst);
    }

    pub fn incrementInFlight(self: *ShutdownHandler) void {
        _ = self.in_flight_requests.fetchAdd(1, .seq_cst);
    }

    pub fn decrementInFlight(self: *ShutdownHandler) void {
        _ = self.in_flight_requests.fetchSub(1, .seq_cst);
    }

    pub fn waitForDrain(self: *ShutdownHandler, timeout_ms: u64) bool {
        const start = std.time.milliTimestamp();
        while (self.in_flight_requests.load(.seq_cst) > 0) {
            if (std.time.milliTimestamp() - start > timeout_ms) {
                return false; // Timeout
            }
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        return true;
    }
};
```

### Signal Registration

```zig
var shutdown_handler: ShutdownHandler = undefined;

fn setupSignalHandlers() !void {
    // Handle SIGTERM and SIGINT
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };

    try std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
    try std.posix.sigaction(std.posix.SIG.INT, &handler, null);
}

fn signalHandler(sig: i32) callconv(.C) void {
    _ = sig;
    shutdown_handler.requestShutdown();
}
```

### Graceful Server Shutdown

```zig
pub fn serve(self: *HttpProxy) !void {
    try setupSignalHandlers();

    while (!shutdown_handler.isShuttingDown()) {
        // Accept new connection with timeout
        const conn = self.listener.accept(100) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };

        // Handle in new thread/task
        shutdown_handler.incrementInFlight();
        try self.runtime.spawn(handleConnection, .{ self, conn });
    }

    // Graceful shutdown
    self.logger.info("Shutting down gracefully...", .{});

    // Wait for in-flight requests (with timeout)
    if (!shutdown_handler.waitForDrain(30000)) {
        self.logger.warn("Timeout waiting for requests to drain", .{});
    }

    // Close listener
    self.listener.close();

    // Drain connection pools
    self.pool.drainAll();

    self.logger.info("Shutdown complete", .{});
}

fn handleConnection(self: *HttpProxy, conn: *Connection) void {
    defer shutdown_handler.decrementInFlight();
    defer conn.close();

    // Process requests on this connection
    while (!shutdown_handler.isShuttingDown()) {
        self.handleRequest(conn) catch |err| {
            if (err == error.ConnectionClosed) break;
            self.logger.err("Request error: {s}", .{@errorName(err)});
        };

        // Check for keep-alive
        if (!conn.isKeepAlive()) break;
    }
}
```

## Graceful Restart (Zero-Downtime)

### Socket Handoff

```zig
pub fn gracefulRestart(self: *HttpProxy) !void {
    // Fork new process
    const pid = try std.posix.fork();

    if (pid == 0) {
        // Child process - new server
        // Inherit listening socket via environment or file descriptor
        try self.reinitializeWithSocket(self.listener.fd);
    } else {
        // Parent process - old server
        // Stop accepting, drain, exit
        shutdown_handler.requestShutdown();
        _ = shutdown_handler.waitForDrain(30000);
        std.posix.exit(0);
    }
}
```

### File Descriptor Passing

```zig
fn passListenerToNewProcess(listener_fd: std.posix.fd_t) !void {
    // Set environment variable with FD number
    var buf: [16]u8 = undefined;
    const fd_str = std.fmt.bufPrint(&buf, "{d}", .{listener_fd}) catch unreachable;

    try std.posix.setenv("PINGORA_LISTENER_FD", fd_str);

    // Execute new binary
    const argv = [_][]const u8{ "./pingora-proxy", "--upgrade" };
    return std.posix.execve(&argv, std.os.environ);
}

fn inheritListener() !std.posix.fd_t {
    const fd_str = std.posix.getenv("PINGORA_LISTENER_FD") orelse {
        return error.NoInheritedSocket;
    };

    return std.fmt.parseInt(std.posix.fd_t, fd_str, 10) catch {
        return error.InvalidSocketFd;
    };
}
```

## Health Check During Shutdown

```zig
fn healthCheckHandler(self: *HttpProxy, session: *Session) !FilterResult {
    if (shutdown_handler.isShuttingDown()) {
        // Return 503 during shutdown so load balancer routes away
        return .{ .respond = .{
            .status = 503,
            .headers = null,
            .body = "{\"status\":\"shutting_down\"}",
        }};
    }

    return .{ .respond = .{
        .status = 200,
        .headers = null,
        .body = "{\"status\":\"healthy\"}",
    }};
}
```

## Configuration

```zig
pub const GracefulConfig = struct {
    /// Maximum time to wait for requests to drain (ms)
    drain_timeout_ms: u64 = 30000,

    /// Grace period before forced shutdown (ms)
    shutdown_grace_period_ms: u64 = 5000,

    /// Enable zero-downtime restart
    enable_zero_downtime: bool = false,

    /// Path for socket handoff
    socket_path: ?[]const u8 = null,
};
```

## Kubernetes Integration

### Preemptive Health Degradation

```zig
fn handlePreStop(self: *HttpProxy) void {
    // Mark as unhealthy immediately
    self.healthy = false;

    // Wait for load balancer to notice
    std.time.sleep(5 * std.time.ns_per_s);

    // Now begin actual shutdown
    shutdown_handler.requestShutdown();
}
```

### Liveness vs Readiness

```zig
fn livenessHandler(self: *HttpProxy) !FilterResult {
    // Always return healthy unless critically failed
    return .{ .respond = .{
        .status = 200,
        .body = "{\"status\":\"alive\"}",
    }};
}

fn readinessHandler(self: *HttpProxy) !FilterResult {
    if (shutdown_handler.isShuttingDown() or !self.healthy) {
        return .{ .respond = .{
            .status = 503,
            .body = "{\"status\":\"not_ready\"}",
        }};
    }
    return .{ .respond = .{
        .status = 200,
        .body = "{\"status\":\"ready\"}",
    }};
}
```

## Best Practices

1. **Set appropriate timeouts**: Don't wait forever for requests to drain
2. **Log shutdown progress**: Track what's happening during shutdown
3. **Return 503 on health checks**: Help load balancers route away
4. **Handle SIGTERM properly**: Kubernetes sends SIGTERM before SIGKILL
5. **Test shutdown regularly**: Verify graceful shutdown works
6. **Consider preStop hooks**: Give load balancers time to update
7. **Clean up resources**: Close files, flush buffers, etc.
