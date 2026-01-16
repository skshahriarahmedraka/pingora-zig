# Error Logging

Comprehensive logging for debugging and monitoring.

## Log Levels

```zig
pub const LogLevel = enum {
    debug,   // Detailed debugging information
    info,    // General operational information
    warn,    // Warning conditions
    err,     // Error conditions
    fatal,   // Critical errors that require shutdown
};
```

## Basic Logging

```zig
const std = @import("std");

pub const Logger = struct {
    level: LogLevel,
    writer: std.fs.File.Writer,

    pub fn init(level: LogLevel) Logger {
        return .{
            .level = level,
            .writer = std.io.getStdErr().writer(),
        };
    }

    pub fn log(
        self: *Logger,
        level: LogLevel,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) {
            return;
        }

        const timestamp = std.time.timestamp();
        self.writer.print("[{d}] [{s}] " ++ fmt ++ "\n", .{
            timestamp,
            @tagName(level),
        } ++ args) catch {};
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn warn(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }
};
```

## Structured Logging

```zig
pub const StructuredLogger = struct {
    allocator: Allocator,
    writer: std.fs.File.Writer,

    pub fn logJson(self: *StructuredLogger, event: anytype) void {
        const json = std.json.stringifyAlloc(
            self.allocator,
            event,
            .{},
        ) catch return;
        defer self.allocator.free(json);

        self.writer.print("{s}\n", .{json}) catch {};
    }
};

// Usage
logger.logJson(.{
    .timestamp = std.time.timestamp(),
    .level = "error",
    .event = "upstream_connection_failed",
    .upstream = peer.address,
    .port = peer.port,
    .error = @errorName(err),
    .retry_count = session.retry_count,
});
```

## Request Logging

### Access Log Format

```zig
fn logAccess(self: *MyProxy, session: *pingora.Session) void {
    const req = session.reqHeader();
    const resp = session.respHeader();
    const timing = session.timing;

    // Combined log format (like nginx)
    self.access_log.print(
        "{s} - - [{s}] \"{s} {s} {s}\" {d} {d} \"{s}\" \"{s}\" {d}ms\n",
        .{
            session.client_ip,
            formatTimestamp(timing.request_start),
            if (req) |r| r.method.asStr() else "-",
            if (req) |r| r.uri.path else "-",
            if (req) |r| r.version.asStr() else "-",
            if (resp) |r| r.status.code else 0,
            session.response_body_size,
            if (req) |r| r.headers.get("Referer") orelse "-" else "-",
            if (req) |r| r.headers.get("User-Agent") orelse "-" else "-",
            timing.getDuration(),
        },
    ) catch {};
}
```

### JSON Access Log

```zig
fn logAccessJson(self: *MyProxy, session: *pingora.Session) void {
    const req = session.reqHeader();
    const resp = session.respHeader();

    self.logger.logJson(.{
        .@"type" = "access",
        .timestamp = std.time.timestamp(),
        .client_ip = session.client_ip,
        .method = if (req) |r| r.method.asStr() else null,
        .path = if (req) |r| r.uri.path else null,
        .status = if (resp) |r| r.status.code else null,
        .response_size = session.response_body_size,
        .duration_ms = session.timing.getDuration(),
        .upstream = if (session.upstream_peer) |p| p.address else null,
        .cache_status = @tagName(session.cache_status),
        .request_id = session.request_id,
    });
}
```

## Error Logging

### Detailed Error Logs

```zig
fn logError(
    self: *MyProxy,
    session: *pingora.Session,
    err: anyerror,
    phase: []const u8,
) void {
    self.error_log.logJson(.{
        .@"type" = "error",
        .timestamp = std.time.timestamp(),
        .phase = phase,
        .error = @errorName(err),
        .request = if (session.reqHeader()) |r| .{
            .method = r.method.asStr(),
            .path = r.uri.path,
            .host = r.headers.get("Host"),
        } else null,
        .client = .{
            .ip = session.client_ip,
            .port = session.client_port,
        },
        .upstream = if (session.upstream_peer) |p| .{
            .address = p.address,
            .port = p.port,
            .health = @tagName(p.health_status),
        } else null,
        .session = .{
            .retry_count = session.retry_count,
            .duration_ms = session.timing.getDuration(),
        },
    });
}
```

### Stack Traces

```zig
fn logErrorWithTrace(
    self: *MyProxy,
    err: anyerror,
    trace: ?*std.builtin.StackTrace,
) void {
    self.logger.err("Error: {s}", .{@errorName(err)});

    if (trace) |t| {
        var buf: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        std.debug.writeStackTrace(t, fbs.writer());
        self.logger.err("Stack trace:\n{s}", .{fbs.getWritten()});
    }
}
```

## Log Rotation

```zig
pub const RotatingLogger = struct {
    base_path: []const u8,
    max_size: u64,
    max_files: u32,
    current_file: std.fs.File,
    current_size: u64,

    pub fn write(self: *RotatingLogger, data: []const u8) !void {
        if (self.current_size + data.len > self.max_size) {
            try self.rotate();
        }

        try self.current_file.writeAll(data);
        self.current_size += data.len;
    }

    fn rotate(self: *RotatingLogger) !void {
        self.current_file.close();

        // Rename existing files
        var i: u32 = self.max_files - 1;
        while (i > 0) : (i -= 1) {
            const old_name = try std.fmt.allocPrint(
                self.allocator,
                "{s}.{d}",
                .{ self.base_path, i - 1 },
            );
            const new_name = try std.fmt.allocPrint(
                self.allocator,
                "{s}.{d}",
                .{ self.base_path, i },
            );
            std.fs.renameAbsolute(old_name, new_name) catch {};
        }

        // Rename current to .0
        std.fs.renameAbsolute(
            self.base_path,
            try std.fmt.allocPrint(self.allocator, "{s}.0", .{self.base_path}),
        ) catch {};

        // Open new file
        self.current_file = try std.fs.createFileAbsolute(self.base_path, .{});
        self.current_size = 0;
    }
};
```

## Log Configuration

```zig
pub const LogConfig = struct {
    /// Minimum log level
    level: LogLevel = .info,

    /// Access log path (null for stdout)
    access_log_path: ?[]const u8 = null,

    /// Error log path (null for stderr)
    error_log_path: ?[]const u8 = null,

    /// Log format
    format: LogFormat = .combined,

    /// Enable JSON logging
    json: bool = false,

    /// Maximum log file size (bytes)
    max_size: u64 = 100 * 1024 * 1024, // 100MB

    /// Maximum log files to keep
    max_files: u32 = 10,

    /// Include request body in logs
    log_request_body: bool = false,

    /// Include response body in logs
    log_response_body: bool = false,
};
```

## Async Logging

For high-performance logging:

```zig
pub const AsyncLogger = struct {
    queue: std.ArrayList(LogEntry),
    mutex: std.Thread.Mutex,
    writer_thread: std.Thread,
    running: bool,

    pub fn log(self: *AsyncLogger, entry: LogEntry) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.queue.append(entry) catch return;
    }

    fn writerLoop(self: *AsyncLogger) void {
        while (self.running) {
            self.mutex.lock();
            const entries = self.queue.toOwnedSlice();
            self.mutex.unlock();

            for (entries) |entry| {
                self.writeEntry(entry);
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
};
```

## Best Practices

1. **Use appropriate log levels**: Debug for development, Info for production
2. **Include context**: Request ID, client IP, upstream info
3. **Use structured logging**: JSON for machine parsing
4. **Rotate logs**: Prevent disk space issues
5. **Log sampling**: Sample high-volume logs in production
6. **Secure sensitive data**: Don't log passwords, tokens, etc.
7. **Monitor log volume**: Alert on unusual log patterns
8. **Async logging**: Avoid blocking request processing
