# Daemon Mode

Running Pingora-Zig as a background daemon process.

## Daemonization

### Basic Daemon

```zig
const std = @import("std");

pub fn daemonize() !void {
    // First fork
    const pid1 = try std.posix.fork();
    if (pid1 > 0) {
        // Parent exits
        std.posix.exit(0);
    }

    // Create new session
    _ = try std.posix.setsid();

    // Second fork (prevent acquiring a controlling terminal)
    const pid2 = try std.posix.fork();
    if (pid2 > 0) {
        std.posix.exit(0);
    }

    // Change working directory
    try std.posix.chdir("/");

    // Close standard file descriptors
    std.posix.close(0); // stdin
    std.posix.close(1); // stdout
    std.posix.close(2); // stderr

    // Redirect to /dev/null
    _ = try std.posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    _ = try std.posix.dup(0); // stdout
    _ = try std.posix.dup(0); // stderr
}

pub fn main() !void {
    var args = std.process.args();
    _ = args.skip();

    var daemon_mode = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
            daemon_mode = true;
        }
    }

    if (daemon_mode) {
        try daemonize();
    }

    // Continue with normal startup
    var proxy = try pingora.HttpProxy.init(allocator, config);
    defer proxy.deinit();

    try proxy.serve();
}
```

## PID File Management

```zig
pub const PidFile = struct {
    path: []const u8,
    fd: ?std.posix.fd_t = null,

    pub fn acquire(self: *PidFile) !void {
        // Open with exclusive lock
        self.fd = try std.posix.open(
            self.path,
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );

        // Try to lock
        std.posix.flock(self.fd.?, .{ .TYPE = .EX, .NONBLOCK = true }) catch {
            std.posix.close(self.fd.?);
            self.fd = null;
            return error.AlreadyRunning;
        };

        // Write PID
        const pid = std.os.linux.getpid();
        var buf: [16]u8 = undefined;
        const len = std.fmt.formatIntBuf(&buf, pid, 10, .lower, .{});
        _ = try std.posix.write(self.fd.?, buf[0..len]);
    }

    pub fn release(self: *PidFile) void {
        if (self.fd) |fd| {
            std.posix.close(fd);
            std.fs.cwd().deleteFile(self.path) catch {};
        }
    }
};

// Usage
var pid_file = PidFile{ .path = "/var/run/pingora.pid" };
pid_file.acquire() catch |err| {
    if (err == error.AlreadyRunning) {
        std.debug.print("Another instance is already running\n", .{});
        return;
    }
    return err;
};
defer pid_file.release();
```

## Logging in Daemon Mode

```zig
pub const DaemonLogger = struct {
    log_file: std.fs.File,

    pub fn init(path: []const u8) !DaemonLogger {
        const file = try std.fs.cwd().createFile(path, .{
            .truncate = false,
        });
        // Seek to end for append
        try file.seekFromEnd(0);

        return .{ .log_file = file };
    }

    pub fn log(self: *DaemonLogger, comptime fmt: []const u8, args: anytype) void {
        const writer = self.log_file.writer();
        const timestamp = std.time.timestamp();
        writer.print("[{d}] " ++ fmt ++ "\n", .{timestamp} ++ args) catch {};
    }

    pub fn deinit(self: *DaemonLogger) void {
        self.log_file.close();
    }
};

// In daemon mode, redirect logs to file
var logger: DaemonLogger = undefined;
if (daemon_mode) {
    logger = try DaemonLogger.init("/var/log/pingora/pingora.log");
} else {
    // Use stderr in foreground mode
}
```

## Signal Handling for Daemons

```zig
var should_reload = std.atomic.Value(bool).init(false);
var should_stop = std.atomic.Value(bool).init(false);

fn setupDaemonSignals() !void {
    // SIGTERM - graceful shutdown
    try std.posix.sigaction(std.posix.SIG.TERM, &.{
        .handler = .{ .handler = handleTerm },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);

    // SIGHUP - reload configuration
    try std.posix.sigaction(std.posix.SIG.HUP, &.{
        .handler = .{ .handler = handleHup },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);

    // Ignore SIGPIPE
    try std.posix.sigaction(std.posix.SIG.PIPE, &.{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);
}

fn handleTerm(sig: i32) callconv(.C) void {
    _ = sig;
    should_stop.store(true, .seq_cst);
}

fn handleHup(sig: i32) callconv(.C) void {
    _ = sig;
    should_reload.store(true, .seq_cst);
}
```

## Configuration Reload

```zig
fn mainLoop(proxy: *pingora.HttpProxy) !void {
    while (!should_stop.load(.seq_cst)) {
        // Check for reload signal
        if (should_reload.swap(false, .seq_cst)) {
            reloadConfig(proxy) catch |err| {
                logger.log("Config reload failed: {s}", .{@errorName(err)});
            };
        }

        // Process requests
        proxy.tick() catch |err| {
            logger.log("Error: {s}", .{@errorName(err)});
        };
    }
}

fn reloadConfig(proxy: *pingora.HttpProxy) !void {
    logger.log("Reloading configuration...", .{});

    // Load new config
    const new_config = try loadConfig("/etc/pingora/config.json");

    // Apply non-disruptive changes
    try proxy.updateBackends(new_config.backends);
    try proxy.updateRateLimits(new_config.rate_limits);

    logger.log("Configuration reloaded successfully", .{});
}
```

## User/Group Switching

```zig
fn dropPrivileges(user: []const u8, group: []const u8) !void {
    // Get group ID
    const grp = try std.c.getgrnam(group);
    if (grp == null) return error.GroupNotFound;

    // Get user ID
    const pwd = try std.c.getpwnam(user);
    if (pwd == null) return error.UserNotFound;

    // Set supplementary groups
    try std.posix.setgroups(&[_]std.posix.gid_t{grp.?.gr_gid});

    // Set GID first (must be done before setuid)
    try std.posix.setgid(grp.?.gr_gid);

    // Set UID
    try std.posix.setuid(pwd.?.pw_uid);

    // Verify we can't regain privileges
    if (std.posix.setuid(0)) |_| {
        return error.PrivilegeDropFailed;
    } else |_| {
        // Expected to fail - good
    }
}

pub fn main() !void {
    // Bind to privileged port as root
    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = 80,
    });

    // Drop privileges after binding
    try dropPrivileges("pingora", "pingora");

    try proxy.serve();
}
```

## Resource Limits

```zig
fn setResourceLimits() !void {
    // Increase file descriptor limit
    try std.posix.setrlimit(.NOFILE, .{
        .cur = 65535,
        .max = 65535,
    });

    // Set core dump size (0 to disable, or specific size)
    try std.posix.setrlimit(.CORE, .{
        .cur = 0,
        .max = 0,
    });
}
```

## Complete Daemon Example

```zig
const std = @import("std");
const pingora = @import("pingora");

const Config = struct {
    listen_port: u16 = 8080,
    pid_file: []const u8 = "/var/run/pingora.pid",
    log_file: []const u8 = "/var/log/pingora/pingora.log",
    user: []const u8 = "pingora",
    group: []const u8 = "pingora",
    daemon: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Parse command line
    const config = try parseArgs();

    // Daemonize if requested
    if (config.daemon) {
        try daemonize();
    }

    // Setup logging
    var logger = try DaemonLogger.init(config.log_file);
    defer logger.deinit();

    // Acquire PID file
    var pid_file = PidFile{ .path = config.pid_file };
    try pid_file.acquire();
    defer pid_file.release();

    // Setup signals
    try setupDaemonSignals();

    // Initialize proxy
    var proxy = try pingora.HttpProxy.init(allocator, .{
        .listen_port = config.listen_port,
    });
    defer proxy.deinit();

    // Drop privileges (if running as root)
    if (std.os.linux.getuid() == 0) {
        try dropPrivileges(config.user, config.group);
    }

    logger.log("Pingora daemon started on port {d}", .{config.listen_port});

    // Main loop
    try mainLoop(&proxy, &logger);

    logger.log("Pingora daemon stopped", .{});
}
```

## Best Practices

1. **Double fork**: Properly detach from terminal
2. **Close file descriptors**: Prevent leaking parent's FDs
3. **Write PID file**: Enable process management
4. **Handle signals**: TERM for shutdown, HUP for reload
5. **Log to files**: stdout/stderr not available in daemon mode
6. **Drop privileges**: Don't run as root after binding ports
7. **Set resource limits**: Prevent resource exhaustion
8. **Lock PID file**: Prevent multiple instances
