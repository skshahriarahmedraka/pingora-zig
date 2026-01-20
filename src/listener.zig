//! pingora-zig: Listener Features
//!
//! Advanced listener support including Unix sockets, connection filtering,
//! TLS settings per listener, and multi-listener services.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const posix = std.posix;
const tls = @import("tls.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Listener Types
// ============================================================================

/// Type of listener
pub const ListenerType = enum {
    /// TCP/IP socket
    tcp,
    /// Unix domain socket
    unix,
    /// Abstract Unix socket (Linux only)
    unix_abstract,
};

/// Listener address - either TCP or Unix socket
pub const ListenerAddress = union(ListenerType) {
    /// TCP address (host:port)
    tcp: TcpAddress,
    /// Unix socket path
    unix: UnixAddress,
    /// Abstract Unix socket (Linux)
    unix_abstract: []const u8,

    pub const TcpAddress = struct {
        host: []const u8,
        port: u16,
    };

    pub const UnixAddress = struct {
        path: []const u8,
        /// File mode for the socket (Unix only)
        mode: ?u32 = null,
    };

    /// Format as string for display
    pub fn format(self: ListenerAddress, buf: []u8) ![]u8 {
        return switch (self) {
            .tcp => |addr| std.fmt.bufPrint(buf, "{s}:{d}", .{ addr.host, addr.port }) catch error.BufferTooSmall,
            .unix => |addr| std.fmt.bufPrint(buf, "unix:{s}", .{addr.path}) catch error.BufferTooSmall,
            .unix_abstract => |name| std.fmt.bufPrint(buf, "unix-abstract:{s}", .{name}) catch error.BufferTooSmall,
        };
    }
};

// ============================================================================
// Connection Filter
// ============================================================================

/// Result of connection filter
pub const FilterResult = enum {
    /// Accept the connection
    accept,
    /// Reject the connection (close immediately)
    reject,
    /// Reject with a specific response (for HTTP)
    reject_with_response,
};

/// Connection filter decision with optional response
pub const FilterDecision = struct {
    result: FilterResult,
    /// Response to send before closing (for reject_with_response)
    response: ?[]const u8 = null,
    /// Reason for rejection (for logging)
    reason: ?[]const u8 = null,
};

/// Information about an incoming connection for filtering
pub const ConnectionInfo = struct {
    /// Remote address
    remote_addr: ?net.Address,
    /// Local address
    local_addr: ?net.Address,
    /// Listener that accepted this connection
    listener_id: u64,
    /// Time connection was accepted
    accepted_at: i64,
    /// TLS SNI hostname (if TLS and available)
    sni_hostname: ?[]const u8,
};

/// Connection filter function type
pub const ConnectionFilterFn = *const fn (*const ConnectionInfo) FilterDecision;

/// Connection filter configuration
pub const ConnectionFilter = struct {
    /// Filter function
    filter_fn: ConnectionFilterFn,
    /// Whether to log rejections
    log_rejections: bool = true,
    /// Maximum connections per IP (0 = unlimited)
    max_connections_per_ip: u32 = 0,
    /// Allowlist of IP addresses/ranges (empty = allow all)
    allowlist: []const []const u8 = &[_][]const u8{},
    /// Blocklist of IP addresses/ranges
    blocklist: []const []const u8 = &[_][]const u8{},

    const Self = @This();

    /// Create a simple filter that accepts all connections
    pub fn acceptAll() Self {
        return .{
            .filter_fn = struct {
                fn accept(_: *const ConnectionInfo) FilterDecision {
                    return .{ .result = .accept };
                }
            }.accept,
        };
    }

    /// Create a filter based on blocklist
    pub fn fromBlocklist(blocklist: []const []const u8) Self {
        return .{
            .filter_fn = struct {
                fn filter(_: *const ConnectionInfo) FilterDecision {
                    // Basic implementation - in production you'd check the blocklist
                    return .{ .result = .accept };
                }
            }.filter,
            .blocklist = blocklist,
        };
    }

    /// Check if an IP is in the blocklist
    pub fn isBlocked(self: *const Self, ip: []const u8) bool {
        for (self.blocklist) |blocked| {
            if (std.mem.eql(u8, blocked, ip)) {
                return true;
            }
        }
        return false;
    }

    /// Check if an IP is in the allowlist (empty allowlist = allow all)
    pub fn isAllowed(self: *const Self, ip: []const u8) bool {
        if (self.allowlist.len == 0) return true;
        for (self.allowlist) |allowed| {
            if (std.mem.eql(u8, allowed, ip)) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// TLS Settings
// ============================================================================

/// TLS configuration for a listener
pub const TlsSettings = struct {
    /// Certificate file path
    cert_path: []const u8,
    /// Private key file path
    key_path: []const u8,
    /// CA certificate path (for client verification)
    ca_path: ?[]const u8 = null,
    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,
    /// Maximum TLS version
    max_version: TlsVersion = .tls_1_3,
    /// Cipher suites (null = use defaults)
    cipher_suites: ?[]const u8 = null,
    /// ALPN protocols to advertise
    alpn_protocols: []const []const u8 = &[_][]const u8{ "h2", "http/1.1" },
    /// Whether to require client certificate
    require_client_cert: bool = false,
    /// Session ticket key (for session resumption)
    session_ticket_key: ?[48]u8 = null,
    /// Enable OCSP stapling
    ocsp_stapling: bool = false,
    /// OCSP response file path
    ocsp_response_path: ?[]const u8 = null,

    pub const TlsVersion = enum {
        tls_1_0,
        tls_1_1,
        tls_1_2,
        tls_1_3,

        pub fn toString(self: TlsVersion) []const u8 {
            return switch (self) {
                .tls_1_0 => "TLSv1.0",
                .tls_1_1 => "TLSv1.1",
                .tls_1_2 => "TLSv1.2",
                .tls_1_3 => "TLSv1.3",
            };
        }
    };
};

// ============================================================================
// Listener Configuration
// ============================================================================

/// Full listener configuration
pub const ListenerConfig = struct {
    /// Listener address
    address: ListenerAddress,
    /// TLS settings (null = plain TCP)
    tls: ?TlsSettings = null,
    /// Connection filter
    filter: ?ConnectionFilter = null,
    /// TCP backlog size
    backlog: u31 = 1024,
    /// Enable SO_REUSEADDR
    reuse_addr: bool = true,
    /// Enable SO_REUSEPORT
    reuse_port: bool = true,
    /// TCP keepalive settings
    keepalive: ?KeepaliveSettings = null,
    /// TCP_NODELAY (disable Nagle's algorithm)
    tcp_nodelay: bool = true,
    /// Receive buffer size (0 = system default)
    recv_buffer_size: u32 = 0,
    /// Send buffer size (0 = system default)
    send_buffer_size: u32 = 0,

    pub const KeepaliveSettings = struct {
        /// Enable keepalive
        enabled: bool = true,
        /// Time before first probe (seconds)
        idle_time: u32 = 60,
        /// Interval between probes (seconds)
        interval: u32 = 10,
        /// Number of probes before giving up
        count: u32 = 6,
    };

    /// Check if this is a TLS listener
    pub fn isTls(self: *const ListenerConfig) bool {
        return self.tls != null;
    }

    /// Check if this is a Unix socket listener
    pub fn isUnix(self: *const ListenerConfig) bool {
        return self.address == .unix or self.address == .unix_abstract;
    }
};

// ============================================================================
// Listener State
// ============================================================================

/// Listener state
pub const ListenerState = enum {
    /// Not yet started
    stopped,
    /// Starting up
    starting,
    /// Running and accepting connections
    running,
    /// Paused (not accepting new connections)
    paused,
    /// Shutting down
    stopping,
    /// Error state
    errored,
};

/// Listener statistics
pub const ListenerStats = struct {
    /// Total connections accepted
    connections_accepted: u64 = 0,
    /// Connections currently active
    active_connections: u64 = 0,
    /// Connections rejected by filter
    connections_rejected: u64 = 0,
    /// Total bytes received
    bytes_received: u64 = 0,
    /// Total bytes sent
    bytes_sent: u64 = 0,
    /// TLS handshake failures
    tls_handshake_failures: u64 = 0,
    /// Start time
    started_at: i64 = 0,

    pub fn uptime(self: *const ListenerStats) i64 {
        if (self.started_at == 0) return 0;
        return std.time.timestamp() - self.started_at;
    }
};

// ============================================================================
// Listener
// ============================================================================

/// A network listener that accepts connections
pub const Listener = struct {
    /// Unique listener ID
    id: u64,
    /// Configuration
    config: ListenerConfig,
    /// Current state
    state: std.atomic.Value(u8),
    /// Statistics
    stats: ListenerStats,
    /// Socket file descriptor (if bound)
    socket: ?posix.socket_t,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ListenerConfig) Self {
        return .{
            .id = generateId(),
            .config = config,
            .state = std.atomic.Value(u8).init(@intFromEnum(ListenerState.stopped)),
            .stats = .{},
            .socket = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop() catch {};
    }

    /// Get current state
    pub fn getState(self: *const Self) ListenerState {
        return @enumFromInt(self.state.load(.seq_cst));
    }

    /// Set state
    fn setState(self: *Self, new_state: ListenerState) void {
        self.state.store(@intFromEnum(new_state), .seq_cst);
    }

    /// Bind and start listening
    pub fn start(self: *Self) !void {
        if (self.getState() != .stopped) {
            return error.InvalidState;
        }

        self.setState(.starting);
        errdefer self.setState(.errored);

        switch (self.config.address) {
            .tcp => |addr| try self.bindTcp(addr),
            .unix => |addr| try self.bindUnix(addr),
            .unix_abstract => |name| try self.bindUnixAbstract(name),
        }

        self.stats.started_at = std.time.timestamp();
        self.setState(.running);
    }

    /// Stop listening
    pub fn stop(self: *Self) !void {
        const current_state = self.getState();
        if (current_state == .stopped) return;

        self.setState(.stopping);

        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }

        // Clean up Unix socket file
        if (self.config.address == .unix) {
            const path = self.config.address.unix.path;
            std.fs.cwd().deleteFile(path) catch {};
        }

        self.setState(.stopped);
    }

    /// Pause accepting new connections
    pub fn pause(self: *Self) void {
        if (self.getState() == .running) {
            self.setState(.paused);
        }
    }

    /// Resume accepting connections
    pub fn resume_(self: *Self) void {
        if (self.getState() == .paused) {
            self.setState(.running);
        }
    }

    /// Accept a connection
    pub fn accept(self: *Self) !AcceptedConnection {
        if (self.getState() != .running) {
            return error.NotRunning;
        }

        const sock = self.socket orelse return error.NotBound;

        var client_addr: net.Address = undefined;
        var addr_len: posix.socklen_t = @sizeOf(net.Address);

        const client_sock = posix.accept(sock, &client_addr.any, &addr_len, 0) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                else => error.AcceptFailed,
            };
        };

        self.stats.connections_accepted += 1;
        self.stats.active_connections += 1;

        const conn_info = ConnectionInfo{
            .remote_addr = client_addr,
            .local_addr = null,
            .listener_id = self.id,
            .accepted_at = std.time.timestamp(),
            .sni_hostname = null,
        };

        // Apply connection filter if configured
        if (self.config.filter) |filter| {
            const decision = filter.filter_fn(&conn_info);
            if (decision.result != .accept) {
                posix.close(client_sock);
                self.stats.connections_rejected += 1;
                self.stats.active_connections -= 1;
                return error.ConnectionFiltered;
            }
        }

        return AcceptedConnection{
            .socket = client_sock,
            .remote_addr = client_addr,
            .listener_id = self.id,
            .accepted_at = conn_info.accepted_at,
        };
    }

    /// Bind to TCP address
    fn bindTcp(self: *Self, addr: ListenerAddress.TcpAddress) !void {
        const address = net.Address.parseIp(addr.host, addr.port) catch {
            // Try resolving as hostname
            return error.InvalidAddress;
        };

        const sock = try posix.socket(address.any.family, posix.SOCK.STREAM, 0);
        errdefer posix.close(sock);

        // Set socket options
        if (self.config.reuse_addr) {
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        }

        if (self.config.reuse_port) {
            posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1))) catch {};
        }

        if (self.config.tcp_nodelay) {
            try posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
        }

        try posix.bind(sock, &address.any, address.getOsSockLen());
        try posix.listen(sock, self.config.backlog);

        self.socket = sock;
    }

    /// Bind to Unix socket
    fn bindUnix(self: *Self, addr: ListenerAddress.UnixAddress) !void {
        if (builtin.os.tag == .windows) {
            return error.UnsupportedPlatform;
        }

        // Remove existing socket file
        std.fs.cwd().deleteFile(addr.path) catch {};

        const sock = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
        errdefer posix.close(sock);

        var sockaddr: posix.sockaddr.un = .{
            .family = posix.AF.UNIX,
            .path = undefined,
        };

        if (addr.path.len >= sockaddr.path.len) {
            return error.PathTooLong;
        }

        @memcpy(sockaddr.path[0..addr.path.len], addr.path);
        sockaddr.path[addr.path.len] = 0;

        try posix.bind(sock, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.un));
        try posix.listen(sock, self.config.backlog);

        // Set file mode if specified
        if (addr.mode) |mode| {
            std.fs.cwd().updateFile(addr.path, .{ .mode = @intCast(mode) }) catch {};
        }

        self.socket = sock;
    }

    /// Bind to abstract Unix socket (Linux only)
    fn bindUnixAbstract(self: *Self, name: []const u8) !void {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        const sock = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
        errdefer posix.close(sock);

        var sockaddr: posix.sockaddr.un = .{
            .family = posix.AF.UNIX,
            .path = undefined,
        };

        // Abstract socket: path starts with null byte
        sockaddr.path[0] = 0;
        if (name.len >= sockaddr.path.len - 1) {
            return error.PathTooLong;
        }
        @memcpy(sockaddr.path[1..][0..name.len], name);

        const addr_len: posix.socklen_t = @intCast(@sizeOf(posix.sa_family_t) + 1 + name.len);
        try posix.bind(sock, @ptrCast(&sockaddr), addr_len);
        try posix.listen(sock, self.config.backlog);

        self.socket = sock;
    }

    /// Record connection closed
    pub fn connectionClosed(self: *Self) void {
        if (self.stats.active_connections > 0) {
            self.stats.active_connections -= 1;
        }
    }

    /// Get statistics
    pub fn getStats(self: *const Self) ListenerStats {
        return self.stats;
    }

    fn generateId() u64 {
        const ts: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())) & 0xFFFFFFFFFFFF);
        return ts ^ (@as(u64, std.crypto.random.int(u16)) << 48);
    }
};

/// An accepted connection
pub const AcceptedConnection = struct {
    /// Client socket
    socket: posix.socket_t,
    /// Remote address
    remote_addr: net.Address,
    /// Listener ID that accepted this connection
    listener_id: u64,
    /// Timestamp when accepted
    accepted_at: i64,

    /// Close the connection
    pub fn close(self: *AcceptedConnection) void {
        posix.close(self.socket);
    }
};

// ============================================================================
// Multi-Listener Service
// ============================================================================

/// Manages multiple listeners as a single service
pub const MultiListenerService = struct {
    /// Service name
    name: []const u8,
    /// Listeners
    listeners: std.ArrayListUnmanaged(*Listener),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, name: []const u8) Self {
        return .{
            .name = name,
            .listeners = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.listeners.items) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
        }
        self.listeners.deinit(self.allocator);
    }

    /// Add a listener to the service
    pub fn addListener(self: *Self, config: ListenerConfig) !*Listener {
        const listener = try self.allocator.create(Listener);
        listener.* = Listener.init(self.allocator, config);
        try self.listeners.append(self.allocator, listener);
        return listener;
    }

    /// Start all listeners
    pub fn startAll(self: *Self) !void {
        for (self.listeners.items) |listener| {
            try listener.start();
        }
    }

    /// Stop all listeners
    pub fn stopAll(self: *Self) void {
        for (self.listeners.items) |listener| {
            listener.stop() catch {};
        }
    }

    /// Get total statistics across all listeners
    pub fn getTotalStats(self: *const Self) ListenerStats {
        var total = ListenerStats{};

        for (self.listeners.items) |listener| {
            const stats = listener.getStats();
            total.connections_accepted += stats.connections_accepted;
            total.active_connections += stats.active_connections;
            total.connections_rejected += stats.connections_rejected;
            total.bytes_received += stats.bytes_received;
            total.bytes_sent += stats.bytes_sent;
            total.tls_handshake_failures += stats.tls_handshake_failures;
        }

        return total;
    }

    /// Get listener by ID
    pub fn getListener(self: *Self, id: u64) ?*Listener {
        for (self.listeners.items) |listener| {
            if (listener.id == id) {
                return listener;
            }
        }
        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ListenerAddress format" {
    var buf: [64]u8 = undefined;

    const tcp_addr = ListenerAddress{ .tcp = .{ .host = "127.0.0.1", .port = 8080 } };
    const tcp_str = try tcp_addr.format(&buf);
    try testing.expectEqualStrings("127.0.0.1:8080", tcp_str);

    const unix_addr = ListenerAddress{ .unix = .{ .path = "/tmp/test.sock" } };
    const unix_str = try unix_addr.format(&buf);
    try testing.expectEqualStrings("unix:/tmp/test.sock", unix_str);
}

test "ConnectionFilter acceptAll" {
    const filter = ConnectionFilter.acceptAll();
    const info = ConnectionInfo{
        .remote_addr = null,
        .local_addr = null,
        .listener_id = 1,
        .accepted_at = 0,
        .sni_hostname = null,
    };
    const decision = filter.filter_fn(&info);
    try testing.expectEqual(FilterResult.accept, decision.result);
}

test "ConnectionFilter isBlocked" {
    const blocklist = [_][]const u8{ "192.168.1.1", "10.0.0.1" };
    const filter = ConnectionFilter{
        .filter_fn = ConnectionFilter.acceptAll().filter_fn,
        .blocklist = &blocklist,
    };

    try testing.expect(filter.isBlocked("192.168.1.1"));
    try testing.expect(filter.isBlocked("10.0.0.1"));
    try testing.expect(!filter.isBlocked("172.16.0.1"));
}

test "ConnectionFilter isAllowed" {
    const allowlist = [_][]const u8{ "192.168.1.1", "10.0.0.1" };
    const filter = ConnectionFilter{
        .filter_fn = ConnectionFilter.acceptAll().filter_fn,
        .allowlist = &allowlist,
    };

    try testing.expect(filter.isAllowed("192.168.1.1"));
    try testing.expect(filter.isAllowed("10.0.0.1"));
    try testing.expect(!filter.isAllowed("172.16.0.1"));

    // Empty allowlist allows all
    const empty_filter = ConnectionFilter.acceptAll();
    try testing.expect(empty_filter.isAllowed("anything"));
}

test "TlsSettings defaults" {
    const settings = TlsSettings{
        .cert_path = "/path/to/cert.pem",
        .key_path = "/path/to/key.pem",
    };

    try testing.expectEqual(TlsSettings.TlsVersion.tls_1_2, settings.min_version);
    try testing.expectEqual(TlsSettings.TlsVersion.tls_1_3, settings.max_version);
    try testing.expect(!settings.require_client_cert);
}

test "TlsVersion toString" {
    try testing.expectEqualStrings("TLSv1.2", TlsSettings.TlsVersion.tls_1_2.toString());
    try testing.expectEqualStrings("TLSv1.3", TlsSettings.TlsVersion.tls_1_3.toString());
}

test "ListenerConfig isTls and isUnix" {
    const tcp_config = ListenerConfig{
        .address = .{ .tcp = .{ .host = "0.0.0.0", .port = 80 } },
    };
    try testing.expect(!tcp_config.isTls());
    try testing.expect(!tcp_config.isUnix());

    const tls_config = ListenerConfig{
        .address = .{ .tcp = .{ .host = "0.0.0.0", .port = 443 } },
        .tls = .{
            .cert_path = "/cert.pem",
            .key_path = "/key.pem",
        },
    };
    try testing.expect(tls_config.isTls());
    try testing.expect(!tls_config.isUnix());

    const unix_config = ListenerConfig{
        .address = .{ .unix = .{ .path = "/tmp/test.sock" } },
    };
    try testing.expect(!unix_config.isTls());
    try testing.expect(unix_config.isUnix());
}

test "Listener init and state" {
    var listener = Listener.init(testing.allocator, .{
        .address = .{ .tcp = .{ .host = "127.0.0.1", .port = 0 } },
    });
    defer listener.deinit();

    try testing.expectEqual(ListenerState.stopped, listener.getState());
    try testing.expect(listener.id != 0);
}

test "ListenerStats uptime" {
    var stats = ListenerStats{};
    try testing.expectEqual(@as(i64, 0), stats.uptime());

    stats.started_at = std.time.timestamp() - 10;
    try testing.expect(stats.uptime() >= 10);
}

test "MultiListenerService" {
    var service = MultiListenerService.init(testing.allocator, "test");
    defer service.deinit();

    _ = try service.addListener(.{
        .address = .{ .tcp = .{ .host = "127.0.0.1", .port = 0 } },
    });

    _ = try service.addListener(.{
        .address = .{ .tcp = .{ .host = "127.0.0.1", .port = 0 } },
    });

    try testing.expectEqual(@as(usize, 2), service.listeners.items.len);

    const stats = service.getTotalStats();
    try testing.expectEqual(@as(u64, 0), stats.connections_accepted);
}

test "KeepaliveSettings defaults" {
    const keepalive = ListenerConfig.KeepaliveSettings{};
    try testing.expect(keepalive.enabled);
    try testing.expectEqual(@as(u32, 60), keepalive.idle_time);
    try testing.expectEqual(@as(u32, 10), keepalive.interval);
    try testing.expectEqual(@as(u32, 6), keepalive.count);
}
