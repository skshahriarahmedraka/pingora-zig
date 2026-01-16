# Systemd Integration

Running Pingora-Zig as a systemd service on Linux.

## Basic Service Unit

Create `/etc/systemd/system/pingora.service`:

```ini
[Unit]
Description=Pingora-Zig HTTP Proxy
Documentation=https://github.com/your-repo/pingora-zig
After=network.target

[Service]
Type=simple
User=pingora
Group=pingora
ExecStart=/usr/local/bin/pingora-proxy --config /etc/pingora/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/pingora /var/run/pingora

# Resource limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## Socket Activation

For zero-downtime restarts:

### Socket Unit

Create `/etc/systemd/system/pingora.socket`:

```ini
[Unit]
Description=Pingora-Zig HTTP Proxy Socket

[Socket]
ListenStream=80
ListenStream=443
NoDelay=true
ReusePort=true

[Install]
WantedBy=sockets.target
```

### Socket-Activated Service

```ini
[Unit]
Description=Pingora-Zig HTTP Proxy
Requires=pingora.socket
After=pingora.socket

[Service]
Type=simple
User=pingora
Group=pingora
ExecStart=/usr/local/bin/pingora-proxy --socket-activated
NonBlocking=true
```

### Zig Code for Socket Activation

```zig
fn getSystemdSockets() ![]std.posix.fd_t {
    // Check if socket activated
    const listen_pid = std.posix.getenv("LISTEN_PID") orelse return error.NotSocketActivated;
    const listen_fds = std.posix.getenv("LISTEN_FDS") orelse return error.NotSocketActivated;

    const pid = try std.fmt.parseInt(i32, listen_pid, 10);
    if (pid != std.os.linux.getpid()) {
        return error.PidMismatch;
    }

    const num_fds = try std.fmt.parseInt(usize, listen_fds, 10);
    var fds = try allocator.alloc(std.posix.fd_t, num_fds);

    // Systemd passes FDs starting at 3
    const SD_LISTEN_FDS_START = 3;
    for (0..num_fds) |i| {
        fds[i] = @intCast(SD_LISTEN_FDS_START + i);
    }

    return fds;
}
```

## Watchdog Integration

### Service with Watchdog

```ini
[Service]
Type=notify
WatchdogSec=30
ExecStart=/usr/local/bin/pingora-proxy --config /etc/pingora/config.json
```

### Zig Watchdog Code

```zig
const std = @import("std");

pub const SystemdNotify = struct {
    socket_path: []const u8,

    pub fn init() ?SystemdNotify {
        const path = std.posix.getenv("NOTIFY_SOCKET") orelse return null;
        return .{ .socket_path = path };
    }

    pub fn ready(self: *SystemdNotify) void {
        self.send("READY=1");
    }

    pub fn watchdog(self: *SystemdNotify) void {
        self.send("WATCHDOG=1");
    }

    pub fn stopping(self: *SystemdNotify) void {
        self.send("STOPPING=1");
    }

    pub fn status(self: *SystemdNotify, msg: []const u8) void {
        var buf: [256]u8 = undefined;
        const status_msg = std.fmt.bufPrint(&buf, "STATUS={s}", .{msg}) catch return;
        self.send(status_msg);
    }

    fn send(self: *SystemdNotify, msg: []const u8) void {
        const sock = std.posix.socket(.UN, .DGRAM, 0) catch return;
        defer std.posix.close(sock);

        var addr: std.posix.sockaddr.un = .{ .path = undefined };
        @memcpy(addr.path[0..self.socket_path.len], self.socket_path);

        _ = std.posix.sendto(sock, msg, 0, &addr, @sizeOf(@TypeOf(addr))) catch {};
    }
};

// Usage
pub fn main() !void {
    var sd = SystemdNotify.init();

    // Initialize proxy
    var proxy = try pingora.HttpProxy.init(allocator, config);

    // Notify systemd we're ready
    if (sd) |*s| {
        s.ready();
        s.status("Accepting connections");
    }

    // Main loop with watchdog
    while (running.load(.seq_cst)) {
        proxy.tick() catch {};

        // Pet the watchdog
        if (sd) |*s| {
            s.watchdog();
        }
    }

    // Notify stopping
    if (sd) |*s| {
        s.stopping();
    }
}
```

## Service Management Commands

```bash
# Enable service to start on boot
sudo systemctl enable pingora

# Start the service
sudo systemctl start pingora

# Check status
sudo systemctl status pingora

# View logs
sudo journalctl -u pingora -f

# Reload configuration (sends SIGHUP)
sudo systemctl reload pingora

# Restart service
sudo systemctl restart pingora

# Stop service
sudo systemctl stop pingora
```

## Log Integration with Journald

### Direct Journal Logging

```zig
const std = @import("std");

pub fn logToJournal(
    priority: u3,
    comptime fmt: []const u8,
    args: anytype,
) void {
    // Format message
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;

    // Use sd_journal_send or write to /dev/log
    const syslog_sock = std.posix.socket(.UN, .DGRAM, 0) catch return;
    defer std.posix.close(syslog_sock);

    var addr: std.posix.sockaddr.un = .{ .path = undefined };
    const path = "/dev/log";
    @memcpy(addr.path[0..path.len], path);

    // Syslog format: <priority>message
    var syslog_buf: [4128]u8 = undefined;
    const syslog_msg = std.fmt.bufPrint(&syslog_buf, "<{d}>{s}", .{
        priority,
        msg,
    }) catch return;

    _ = std.posix.sendto(syslog_sock, syslog_msg, 0, &addr, @sizeOf(@TypeOf(addr))) catch {};
}
```

### Structured Logging

```zig
// journald supports structured fields
fn logStructured(fields: anytype) void {
    // Each field as KEY=VALUE, separated by newlines
    // MESSAGE= is the main message
}
```

## Environment Configuration

Create `/etc/pingora/pingora.env`:

```bash
# Environment variables for Pingora
PINGORA_LOG_LEVEL=info
PINGORA_WORKERS=4
```

Service unit:

```ini
[Service]
EnvironmentFile=/etc/pingora/pingora.env
```

## Security Hardening

```ini
[Service]
# Run as non-root user
User=pingora
Group=pingora

# Prevent privilege escalation
NoNewPrivileges=true

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/pingora
ReadWritePaths=/var/log/pingora /var/run/pingora

# Network restrictions (allow only needed ports)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Memory protection
MemoryDenyWriteExecute=true
```

## Resource Control

```ini
[Service]
# CPU limits
CPUQuota=200%

# Memory limits
MemoryMax=2G
MemoryHigh=1.5G

# IO limits
IOWeight=100

# File descriptor limits
LimitNOFILE=65535
```

## Best Practices

1. **Use Type=notify**: Better lifecycle tracking with watchdog
2. **Enable socket activation**: Zero-downtime upgrades
3. **Set resource limits**: Prevent runaway processes
4. **Harden security**: Use systemd's security features
5. **Log to journald**: Centralized logging with structured data
6. **Use environment files**: Separate config from service definition
7. **Test restart behavior**: Verify Restart= settings work correctly
8. **Monitor with watchdog**: Detect and recover from hangs
