# Start/Stop

Managing the proxy service lifecycle.

## Starting the Proxy

### Basic Startup

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize proxy
    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = 8080,
        .max_connections = 10000,
    });
    defer proxy.deinit();

    // Configure
    try proxy.addBackend("192.168.1.10", 8080, 1);

    // Start serving
    std.debug.print("Starting proxy on port 8080...\n", .{});
    try proxy.serve();
}
```

### With Configuration File

```zig
pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Load configuration
    const config = try loadConfig("config.json");

    // Initialize with config
    var proxy = try pingora.HttpProxy.init(allocator, config.proxy);
    defer proxy.deinit();

    // Add backends from config
    for (config.backends) |backend| {
        try proxy.addBackend(backend.address, backend.port, backend.weight);
    }

    try proxy.serve();
}

fn loadConfig(path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);

    return try std.json.parseFromSlice(Config, allocator, content, .{});
}
```

### Command Line Arguments

```zig
pub fn main() !void {
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    var port: u16 = 8080;
    var config_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |p| {
                port = try std.fmt.parseInt(u16, p, 10);
            }
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            config_path = args.next();
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = port,
    });
    defer proxy.deinit();

    try proxy.serve();
}

fn printUsage() void {
    std.debug.print(
        \\Usage: pingora-proxy [OPTIONS]
        \\
        \\Options:
        \\  -p, --port PORT     Listen port (default: 8080)
        \\  -c, --config FILE   Configuration file path
        \\  -h, --help          Show this help
        \\
    , .{});
}
```

## Stopping the Proxy

### Signal Handling

```zig
var running = std.atomic.Value(bool).init(true);

pub fn main() !void {
    // Setup signal handlers
    try setupSignalHandlers();

    var proxy = try pingora.HttpProxy.init(allocator, config);
    defer proxy.deinit();

    // Run until signal received
    while (running.load(.seq_cst)) {
        proxy.tick() catch |err| {
            std.debug.print("Error: {s}\n", .{@errorName(err)});
        };
    }

    std.debug.print("Shutting down...\n", .{});
}

fn setupSignalHandlers() !void {
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
    running.store(false, .seq_cst);
}
```

### Graceful Shutdown

```zig
fn shutdown(proxy: *pingora.HttpProxy) void {
    std.debug.print("Initiating graceful shutdown...\n", .{});

    // Stop accepting new connections
    proxy.stopAccepting();

    // Wait for in-flight requests
    const timeout_ms: u64 = 30000;
    const start = std.time.milliTimestamp();

    while (proxy.getActiveConnections() > 0) {
        if (std.time.milliTimestamp() - start > timeout_ms) {
            std.debug.print("Timeout waiting for connections to drain\n", .{});
            break;
        }
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    // Close remaining connections
    proxy.closeAllConnections();

    // Cleanup
    proxy.deinit();

    std.debug.print("Shutdown complete\n", .{});
}
```

## Lifecycle Hooks

```zig
pub const LifecycleHooks = struct {
    /// Called before starting to accept connections
    onStart: ?*const fn (*HttpProxy) void = null,

    /// Called after stopping to accept connections
    onStop: ?*const fn (*HttpProxy) void = null,

    /// Called before each request
    onRequestStart: ?*const fn (*Session) void = null,

    /// Called after each request completes
    onRequestEnd: ?*const fn (*Session) void = null,
};

// Usage
var proxy = try pingora.HttpProxy.init(allocator, .{
    .listen_port = 8080,
    .hooks = .{
        .onStart = onProxyStart,
        .onStop = onProxyStop,
    },
});

fn onProxyStart(proxy: *pingora.HttpProxy) void {
    std.debug.print("Proxy started on port {d}\n", .{proxy.config.listen_port});
    // Initialize metrics, open log files, etc.
}

fn onProxyStop(proxy: *pingora.HttpProxy) void {
    std.debug.print("Proxy stopping...\n", .{});
    // Flush metrics, close log files, etc.
}
```

## Health Checks

### Startup Health Check

```zig
fn waitForHealthy(proxy: *pingora.HttpProxy, timeout_ms: u64) !void {
    const start = std.time.milliTimestamp();

    while (true) {
        if (proxy.isHealthy()) {
            return;
        }

        if (std.time.milliTimestamp() - start > timeout_ms) {
            return error.StartupTimeout;
        }

        std.time.sleep(100 * std.time.ns_per_ms);
    }
}

pub fn main() !void {
    var proxy = try pingora.HttpProxy.init(allocator, config);

    // Start in background
    const serve_thread = try std.Thread.spawn(.{}, proxy.serve, .{});

    // Wait for healthy
    waitForHealthy(&proxy, 10000) catch |err| {
        std.debug.print("Failed to start: {s}\n", .{@errorName(err)});
        proxy.shutdown();
        return err;
    };

    std.debug.print("Proxy is healthy and accepting connections\n", .{});

    serve_thread.join();
}
```

### Readiness Endpoint

```zig
fn readinessHandler(proxy: *pingora.HttpProxy, session: *Session) !FilterResult {
    // Check all dependencies
    const checks = .{
        .backends_available = proxy.hasHealthyBackends(),
        .pool_healthy = proxy.pool.isHealthy(),
        .cache_healthy = proxy.cache.isHealthy(),
    };

    const all_healthy = checks.backends_available and
        checks.pool_healthy and
        checks.cache_healthy;

    const body = try std.json.stringifyAlloc(allocator, .{
        .ready = all_healthy,
        .checks = checks,
    }, .{});

    return .{ .respond = .{
        .status = if (all_healthy) 200 else 503,
        .body = body,
    }};
}
```

## Process Management

### PID File

```zig
fn writePidFile(path: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    const pid = std.os.linux.getpid();
    try file.writer().print("{d}\n", .{pid});
}

fn removePidFile(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

pub fn main() !void {
    const pid_path = "/var/run/pingora.pid";

    try writePidFile(pid_path);
    defer removePidFile(pid_path);

    var proxy = try pingora.HttpProxy.init(allocator, config);
    defer proxy.deinit();

    try proxy.serve();
}
```

### Status Check Script

```bash
#!/bin/bash
# check_status.sh

PID_FILE="/var/run/pingora.pid"
HEALTH_URL="http://localhost:8080/health"

if [ ! -f "$PID_FILE" ]; then
    echo "Proxy not running (no PID file)"
    exit 1
fi

PID=$(cat "$PID_FILE")
if ! kill -0 "$PID" 2>/dev/null; then
    echo "Proxy not running (stale PID file)"
    exit 1
fi

# Check health endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL")
if [ "$HTTP_CODE" = "200" ]; then
    echo "Proxy running and healthy (PID: $PID)"
    exit 0
else
    echo "Proxy running but unhealthy (PID: $PID, HTTP: $HTTP_CODE)"
    exit 1
fi
```

## Best Practices

1. **Use graceful shutdown**: Allow in-flight requests to complete
2. **Handle signals properly**: Respond to SIGTERM and SIGINT
3. **Write PID files**: Enable external process management
4. **Implement health checks**: Allow orchestrators to monitor state
5. **Log lifecycle events**: Track startups, shutdowns, restarts
6. **Set appropriate timeouts**: Don't wait forever during shutdown
7. **Clean up resources**: Close files, connections, free memory
8. **Test shutdown paths**: Verify graceful shutdown works correctly
