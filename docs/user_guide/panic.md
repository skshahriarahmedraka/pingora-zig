# Panic Handling

Handling panics and crashes gracefully to maintain service availability.

## Zig Panic Behavior

In Zig, panics indicate programming errors (not recoverable errors):

```zig
// These cause panics:
unreachable;
@panic("explicit panic");
var x: u8 = 300;  // Integer overflow in debug mode
slice[100];       // Out of bounds access
```

## Panic Handler

Custom panic handler for logging:

```zig
const std = @import("std");

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    // Log panic information
    const stderr = std.io.getStdErr().writer();
    stderr.print("\n!!! PANIC !!!\n", .{}) catch {};
    stderr.print("Message: {s}\n", .{msg}) catch {};

    // Print stack trace
    if (error_return_trace) |trace| {
        stderr.print("\nStack trace:\n", .{}) catch {};
        std.debug.dumpStackTrace(trace.*);
    }

    if (ret_addr) |addr| {
        stderr.print("\nReturn address: 0x{x}\n", .{addr}) catch {};
    }

    // Attempt to write crash dump
    writeCrashDump(msg, error_return_trace) catch {};

    // Exit
    std.posix.abort();
}

fn writeCrashDump(
    msg: []const u8,
    trace: ?*std.builtin.StackTrace,
) !void {
    const file = try std.fs.cwd().createFile(
        "crash_dump.txt",
        .{ .truncate = true },
    );
    defer file.close();

    const writer = file.writer();
    try writer.print("Crash at: {d}\n", .{std.time.timestamp()});
    try writer.print("Message: {s}\n", .{msg});

    if (trace) |t| {
        try writer.print("\nStack trace:\n", .{});
        try std.debug.writeStackTrace(t.*, writer);
    }
}
```

## Request Isolation

Isolate request handling to prevent cascading failures:

```zig
fn handleRequestSafely(self: *HttpProxy, conn: *Connection) void {
    // Each request is handled independently
    self.handleRequest(conn) catch |err| {
        // Log error but don't crash the server
        self.logger.err("Request failed: {s}", .{@errorName(err)});

        // Send error response
        self.sendErrorResponse(conn, 500) catch {};
    };
}
```

## Thread Isolation

Use separate threads to isolate crashes:

```zig
pub const WorkerPool = struct {
    workers: []std.Thread,
    supervisor: std.Thread,

    pub fn spawnWorker(self: *WorkerPool, task: anytype) !void {
        const thread = try std.Thread.spawn(.{}, workerWrapper, .{task});
        // Supervisor monitors workers
    }

    fn workerWrapper(task: anytype) void {
        // Catch panics at thread boundary
        @setCold(true);

        task() catch |err| {
            std.debug.print("Worker error: {s}\n", .{@errorName(err)});
        };
    }

    fn supervisorLoop(self: *WorkerPool) void {
        while (true) {
            // Monitor worker health
            for (self.workers) |*worker| {
                if (!worker.isAlive()) {
                    // Restart crashed worker
                    self.restartWorker(worker) catch {};
                }
            }
            std.time.sleep(1 * std.time.ns_per_s);
        }
    }
};
```

## Defensive Programming

### Bounds Checking

```zig
fn safeSlice(data: []const u8, start: usize, end: usize) ?[]const u8 {
    if (start > data.len or end > data.len or start > end) {
        return null;
    }
    return data[start..end];
}
```

### Null Checks

```zig
fn processRequest(session: *Session) !void {
    // Always check optional values
    const req = session.reqHeader() orelse {
        return error.NoRequest;
    };

    const host = req.headers.get("Host") orelse {
        return error.MissingHost;
    };

    // Safe to use host now
}
```

### Integer Overflow Protection

```zig
fn safeAdd(a: u32, b: u32) ?u32 {
    return std.math.add(u32, a, b) catch null;
}

fn safeMultiply(a: u32, b: u32) ?u32 {
    return std.math.mul(u32, a, b) catch null;
}
```

## Recovery Strategies

### Watchdog Process

```zig
pub fn runWithWatchdog(main_fn: fn () void) !void {
    while (true) {
        const pid = try std.posix.fork();

        if (pid == 0) {
            // Child - run main
            main_fn();
            std.posix.exit(0);
        } else {
            // Parent - watchdog
            const status = std.posix.waitpid(pid, 0);

            if (status.signal) |sig| {
                std.debug.print("Child crashed with signal {d}, restarting...\n", .{sig});
                std.time.sleep(1 * std.time.ns_per_s);
            } else if (status.exit_code != 0) {
                std.debug.print("Child exited with code {d}, restarting...\n", .{status.exit_code});
                std.time.sleep(1 * std.time.ns_per_s);
            } else {
                // Clean exit
                break;
            }
        }
    }
}
```

### Circuit Breaker for Panics

```zig
pub const PanicCircuitBreaker = struct {
    panic_count: u32 = 0,
    last_panic_time: i64 = 0,
    open: bool = false,

    pub fn recordPanic(self: *PanicCircuitBreaker) void {
        const now = std.time.timestamp();

        // Reset if enough time has passed
        if (now - self.last_panic_time > 60) {
            self.panic_count = 0;
        }

        self.panic_count += 1;
        self.last_panic_time = now;

        // Open circuit after too many panics
        if (self.panic_count >= 5) {
            self.open = true;
        }
    }

    pub fn allowRequest(self: *PanicCircuitBreaker) bool {
        if (!self.open) return true;

        // Check if we can close the circuit
        const now = std.time.timestamp();
        if (now - self.last_panic_time > 30) {
            self.open = false;
            self.panic_count = 0;
            return true;
        }

        return false;
    }
};
```

## Crash Reporting

```zig
pub const CrashReporter = struct {
    pub fn report(
        msg: []const u8,
        trace: ?*std.builtin.StackTrace,
    ) void {
        // Collect system info
        const info = .{
            .timestamp = std.time.timestamp(),
            .message = msg,
            .zig_version = @import("builtin").zig_version_string,
            .os = @tagName(@import("builtin").os.tag),
            .arch = @tagName(@import("builtin").cpu.arch),
        };

        // Write to file
        writeToFile(info, trace) catch {};

        // Send to monitoring (if configured)
        sendToMonitoring(info, trace) catch {};
    }
};
```

## Best Practices

1. **Use error handling, not panics**: Panics are for bugs, not expected errors
2. **Isolate request handling**: One bad request shouldn't crash the server
3. **Log crashes thoroughly**: Include stack traces and context
4. **Implement watchdog**: Auto-restart on crashes
5. **Use defensive programming**: Check bounds, nulls, overflows
6. **Test crash recovery**: Verify the system recovers correctly
7. **Monitor panic rates**: Alert on elevated panic counts
8. **Keep crash dumps**: Useful for post-mortem debugging
