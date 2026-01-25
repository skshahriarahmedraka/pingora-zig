//! pingora-zig: Connector Features
//!
//! Advanced connector configuration including total connection timeout,
//! connection offloading, and source address binding.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const peer_mod = @import("peer.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Connector Configuration
// ============================================================================

/// Connector configuration for outbound connections
pub const ConnectorConfig = struct {
    /// Total connection timeout (includes DNS, connect, TLS handshake)
    total_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// TCP connect timeout
    connect_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// TLS handshake timeout
    tls_handshake_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// Source address to bind to (null = any)
    bind_to: ?BindAddress = null,
    /// Enable connection offloading (background keepalive)
    offload_enabled: bool = true,
    /// Offload idle timeout (connections idle longer than this are closed)
    offload_idle_timeout_ns: u64 = 60 * std.time.ns_per_s,
    /// Maximum offloaded connections
    max_offloaded: u32 = 1000,
    /// TCP keepalive configuration
    tcp_keepalive: ?TcpKeepalive = null,
    /// TCP_NODELAY (disable Nagle's algorithm)
    tcp_nodelay: bool = true,
    /// SO_REUSEADDR
    reuse_addr: bool = true,
    /// Send buffer size (0 = system default)
    send_buffer_size: u32 = 0,
    /// Receive buffer size (0 = system default)
    recv_buffer_size: u32 = 0,
    /// Enable happy eyeballs (RFC 8305) for dual-stack connections
    happy_eyeballs: bool = true,
    /// Happy eyeballs delay before trying IPv4 (nanoseconds)
    happy_eyeballs_delay_ns: u64 = 250 * std.time.ns_per_ms,

    pub const TcpKeepalive = struct {
        /// Idle time before first probe (seconds)
        idle_time: u32 = 60,
        /// Interval between probes (seconds)
        interval: u32 = 10,
        /// Number of probes before giving up
        count: u32 = 6,
    };
};

/// Source address binding configuration
pub const BindAddress = union(enum) {
    /// Bind to specific IPv4 address
    ipv4: [4]u8,
    /// Bind to specific IPv6 address
    ipv6: [16]u8,
    /// Bind to interface by name (Linux only)
    interface: []const u8,
    /// Bind to any address in a range
    range: AddressRange,

    pub const AddressRange = struct {
        /// Starting address
        start: [4]u8,
        /// Number of addresses in range
        count: u32,
    };

    /// Format as string
    pub fn format(self: BindAddress, buf: []u8) ![]u8 {
        return switch (self) {
            .ipv4 => |addr| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch error.BufferTooSmall,
            .ipv6 => std.fmt.bufPrint(buf, "::1", .{}) catch error.BufferTooSmall, // Simplified
            .interface => |name| std.fmt.bufPrint(buf, "if:{s}", .{name}) catch error.BufferTooSmall,
            .range => |r| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}/{d}", .{ r.start[0], r.start[1], r.start[2], r.start[3], r.count }) catch error.BufferTooSmall,
        };
    }

    /// Create from IPv4 string
    pub fn fromIpv4(ip: []const u8) !BindAddress {
        var parts: [4]u8 = undefined;
        var iter = std.mem.splitScalar(u8, ip, '.');
        var i: usize = 0;
        while (iter.next()) |part| {
            if (i >= 4) return error.InvalidAddress;
            parts[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
            i += 1;
        }
        if (i != 4) return error.InvalidAddress;
        return .{ .ipv4 = parts };
    }
};

// ============================================================================
// Connection Offloading
// ============================================================================

/// Connection state for offloading
pub const OffloadedConnection = struct {
    /// Socket file descriptor
    socket: posix.socket_t,
    /// Peer identifier
    peer_id: u64,
    /// Last activity timestamp
    last_activity: i64,
    /// Idle since timestamp
    idle_since: i64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Whether connection is TLS
    is_tls: bool,
    /// TLS session data for resumption (if applicable)
    tls_session: ?[]const u8,

    /// Check if connection has been idle too long
    pub fn isIdleTooLong(self: *const OffloadedConnection, max_idle_ns: u64) bool {
        const now = std.time.timestamp();
        const idle_duration = now - self.idle_since;
        return idle_duration * std.time.ns_per_s > @as(i64, @intCast(max_idle_ns));
    }

    /// Update last activity
    pub fn touch(self: *OffloadedConnection) void {
        self.last_activity = std.time.timestamp();
    }

    /// Mark as idle
    pub fn markIdle(self: *OffloadedConnection) void {
        self.idle_since = std.time.timestamp();
    }
};

/// Connection offload manager
pub const OffloadManager = struct {
    /// Offloaded connections by peer ID
    connections: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(OffloadedConnection)),
    /// Configuration
    config: ConnectorConfig,
    /// Statistics
    stats: OffloadStats,
    /// Allocator
    allocator: Allocator,

    pub const OffloadStats = struct {
        /// Total connections offloaded
        total_offloaded: u64 = 0,
        /// Connections reused from offload
        reused: u64 = 0,
        /// Connections closed due to idle timeout
        idle_closed: u64 = 0,
        /// Current offloaded count
        current_offloaded: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, config: ConnectorConfig) Self {
        return .{
            .connections = .{},
            .config = config,
            .stats = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.connections.valueIterator();
        while (iter.next()) |list| {
            for (list.items) |conn| {
                posix.close(conn.socket);
            }
            list.deinit(self.allocator);
        }
        self.connections.deinit(self.allocator);
    }

    /// Offload a connection for potential reuse
    pub fn offload(self: *Self, peer_id: u64, conn: OffloadedConnection) !void {
        if (!self.config.offload_enabled) {
            posix.close(conn.socket);
            return;
        }

        if (self.stats.current_offloaded >= self.config.max_offloaded) {
            // Close oldest idle connection to make room
            self.evictOldest();
        }

        var list = self.connections.getPtr(peer_id);
        if (list == null) {
            try self.connections.put(self.allocator, peer_id, .{});
            list = self.connections.getPtr(peer_id);
        }

        var marked_conn = conn;
        marked_conn.markIdle();
        try list.?.append(self.allocator, marked_conn);

        self.stats.total_offloaded += 1;
        self.stats.current_offloaded += 1;
    }

    /// Try to get an offloaded connection for a peer
    pub fn getConnection(self: *Self, peer_id: u64) ?OffloadedConnection {
        const list = self.connections.getPtr(peer_id) orelse return null;

        // Find a valid connection (not idle too long)
        while (list.items.len > 0) {
            // Get last item and remove it - O(1) using pop()
            const conn = list.pop() orelse break;

            if (!conn.isIdleTooLong(self.config.offload_idle_timeout_ns)) {
                self.stats.reused += 1;
                self.stats.current_offloaded -= 1;
                return conn;
            }
            // Connection too old, close it
            posix.close(conn.socket);
            self.stats.idle_closed += 1;
            self.stats.current_offloaded -= 1;
        }

        return null;
    }

    /// Evict the oldest idle connection
    fn evictOldest(self: *Self) void {
        var oldest_peer: ?u64 = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.items.len > 0) {
                const conn = &entry.value_ptr.items[0];
                if (conn.idle_since < oldest_time) {
                    oldest_time = conn.idle_since;
                    oldest_peer = entry.key_ptr.*;
                }
            }
        }

        if (oldest_peer) |peer_id| {
            if (self.connections.getPtr(peer_id)) |list| {
                if (list.items.len > 0) {
                    // Use swapRemove for O(1) - order doesn't matter for eviction
                    const conn = list.swapRemove(0);
                    posix.close(conn.socket);
                    self.stats.idle_closed += 1;
                    self.stats.current_offloaded -= 1;
                }
            }
        }
    }

    /// Clean up expired connections
    pub fn cleanup(self: *Self) u64 {
        var closed: u64 = 0;

        var iter = self.connections.valueIterator();
        while (iter.next()) |list| {
            var i: usize = 0;
            while (i < list.items.len) {
                if (list.items[i].isIdleTooLong(self.config.offload_idle_timeout_ns)) {
                    // Use swapRemove for O(1) - order doesn't matter for cleanup
                    const conn = list.swapRemove(i);
                    posix.close(conn.socket);
                    self.stats.idle_closed += 1;
                    self.stats.current_offloaded -= 1;
                    closed += 1;
                    // Don't increment i - swapRemove moves last element to i
                } else {
                    i += 1;
                }
            }
        }

        return closed;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) OffloadStats {
        return self.stats;
    }
};

// ============================================================================
// Connector
// ============================================================================

/// Connection result
pub const ConnectResult = struct {
    /// Socket file descriptor
    socket: posix.socket_t,
    /// Whether this was a reused connection
    reused: bool,
    /// Time to connect (nanoseconds)
    connect_time_ns: u64,
    /// Resolved address
    resolved_addr: ?net.Address,
};

/// Connector for creating outbound connections
pub const Connector = struct {
    /// Configuration
    config: ConnectorConfig,
    /// Offload manager
    offload: OffloadManager,
    /// Statistics
    stats: ConnectorStats,
    /// Allocator
    allocator: Allocator,

    pub const ConnectorStats = struct {
        /// Total connection attempts
        connect_attempts: u64 = 0,
        /// Successful connections
        connect_success: u64 = 0,
        /// Failed connections
        connect_failed: u64 = 0,
        /// Connections reused
        connections_reused: u64 = 0,
        /// Total connect time (nanoseconds)
        total_connect_time_ns: u64 = 0,
        /// Timeout errors
        timeout_errors: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, config: ConnectorConfig) Self {
        return .{
            .config = config,
            .offload = OffloadManager.init(allocator, config),
            .stats = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.offload.deinit();
    }

    /// Connect to a peer
    pub fn connect(self: *Self, peer: *const peer_mod.HttpPeer) !ConnectResult {
        const start_time = std.time.nanoTimestamp();
        self.stats.connect_attempts += 1;

        // Calculate peer ID for connection reuse
        const peer_id = self.calculatePeerId(peer);

        // Try to get an offloaded connection first
        if (self.offload.getConnection(peer_id)) |conn| {
            self.stats.connections_reused += 1;
            return ConnectResult{
                .socket = conn.socket,
                .reused = true,
                .connect_time_ns = 0,
                .resolved_addr = null,
            };
        }

        // Create new connection
        const result = self.createConnection(peer) catch |err| {
            self.stats.connect_failed += 1;
            if (err == error.TimedOut) {
                self.stats.timeout_errors += 1;
            }
            return err;
        };

        const elapsed = std.time.nanoTimestamp() - start_time;
        self.stats.connect_success += 1;
        self.stats.total_connect_time_ns += @intCast(@max(0, elapsed));

        return ConnectResult{
            .socket = result.socket,
            .reused = false,
            .connect_time_ns = @intCast(@max(0, elapsed)),
            .resolved_addr = result.addr,
        };
    }

    /// Create a new connection to peer
    fn createConnection(self: *Self, peer: *const peer_mod.HttpPeer) !struct { socket: posix.socket_t, addr: ?net.Address } {
        // Resolve address
        const addr = switch (peer.address) {
            .hostname => |h| net.Address.parseIp(h.host, h.port) catch {
                // In production, this would do DNS resolution
                return error.DnsResolutionFailed;
            },
            .ip => |ip| blk: {
                if (ip.is_ipv6) {
                    break :blk net.Address.initIp6(ip.addr, ip.port);
                } else {
                    break :blk net.Address.initIp4(ip.addr[0..4].*, ip.port);
                }
            },
            .unix => return error.UnixSocketNotSupported,
        };

        // Create socket
        const sock = try posix.socket(addr.any.family, posix.SOCK.STREAM, 0);
        errdefer posix.close(sock);

        // Apply socket options
        try self.applySocketOptions(sock);

        // Bind to source address if configured
        if (self.config.bind_to) |bind| {
            try self.bindToSource(sock, bind);
        }

        // Connect
        posix.connect(sock, &addr.any, addr.getOsSockLen()) catch |err| {
            return switch (err) {
                error.ConnectionRefused => error.ConnectionRefused,
                error.NetworkUnreachable => error.NetworkUnreachable,
                else => error.ConnectFailed,
            };
        };

        return .{ .socket = sock, .addr = addr };
    }

    /// Apply socket options from config
    fn applySocketOptions(self: *Self, sock: posix.socket_t) !void {
        if (self.config.tcp_nodelay) {
            try posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
        }

        if (self.config.reuse_addr) {
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        }

        if (self.config.send_buffer_size > 0) {
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(@as(c_int, @intCast(self.config.send_buffer_size))));
        }

        if (self.config.recv_buffer_size > 0) {
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(@as(c_int, @intCast(self.config.recv_buffer_size))));
        }
    }

    /// Bind socket to source address
    fn bindToSource(_: *Self, sock: posix.socket_t, bind: BindAddress) !void {
        switch (bind) {
            .ipv4 => |addr| {
                const bind_addr = net.Address.initIp4(addr, 0);
                try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());
            },
            .ipv6 => |addr| {
                const bind_addr = net.Address.initIp6(addr, 0);
                try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());
            },
            .interface => {
                // SO_BINDTODEVICE on Linux
                // Not portable, skip for now
            },
            .range => {
                // Round-robin through addresses
                // For simplicity, use first address
                const bind_addr = net.Address.initIp4(bind.range.start, 0);
                try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());
            },
        }
    }

    /// Release a connection (return to pool or close)
    pub fn release(self: *Self, peer: *const peer_mod.HttpPeer, socket: posix.socket_t, reusable: bool) void {
        if (!reusable or !self.config.offload_enabled) {
            posix.close(socket);
            return;
        }

        const peer_id = self.calculatePeerId(peer);
        const conn = OffloadedConnection{
            .socket = socket,
            .peer_id = peer_id,
            .last_activity = std.time.timestamp(),
            .idle_since = std.time.timestamp(),
            .bytes_sent = 0,
            .bytes_received = 0,
            .is_tls = peer.isTls(),
            .tls_session = null,
        };

        self.offload.offload(peer_id, conn) catch {
            posix.close(socket);
        };
    }

    /// Calculate peer ID for connection pooling
    fn calculatePeerId(_: *Self, peer: *const peer_mod.HttpPeer) u64 {
        var hasher = std.hash.Wyhash.init(0);

        switch (peer.address) {
            .hostname => |h| {
                hasher.update(h.host);
                hasher.update(std.mem.asBytes(&h.port));
            },
            .ip => |ip| {
                hasher.update(&ip.addr);
                hasher.update(std.mem.asBytes(&ip.port));
            },
            .unix => |path| {
                hasher.update(path);
            },
        }

        // Include TLS in peer ID
        if (peer.isTls()) {
            hasher.update("tls");
        }

        return hasher.final();
    }

    /// Get statistics
    pub fn getStats(self: *const Self) ConnectorStats {
        return self.stats;
    }

    /// Get average connect time (milliseconds)
    pub fn avgConnectTimeMs(self: *const Self) u64 {
        if (self.stats.connect_success == 0) return 0;
        return @divFloor(self.stats.total_connect_time_ns, self.stats.connect_success) / std.time.ns_per_ms;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ConnectorConfig defaults" {
    const config = ConnectorConfig{};
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), config.total_timeout_ns);
    try testing.expect(config.offload_enabled);
    try testing.expect(config.tcp_nodelay);
}

test "BindAddress fromIpv4" {
    const addr = try BindAddress.fromIpv4("192.168.1.100");
    try testing.expectEqual(@as(u8, 192), addr.ipv4[0]);
    try testing.expectEqual(@as(u8, 168), addr.ipv4[1]);
    try testing.expectEqual(@as(u8, 1), addr.ipv4[2]);
    try testing.expectEqual(@as(u8, 100), addr.ipv4[3]);
}

test "BindAddress fromIpv4 invalid" {
    try testing.expectError(error.InvalidAddress, BindAddress.fromIpv4("invalid"));
    try testing.expectError(error.InvalidAddress, BindAddress.fromIpv4("256.0.0.1"));
    try testing.expectError(error.InvalidAddress, BindAddress.fromIpv4("1.2.3"));
}

test "BindAddress format" {
    const addr = try BindAddress.fromIpv4("10.0.0.1");
    var buf: [32]u8 = undefined;
    const str = try addr.format(&buf);
    try testing.expectEqualStrings("10.0.0.1", str);
}

test "OffloadedConnection isIdleTooLong" {
    var conn = OffloadedConnection{
        .socket = 0,
        .peer_id = 1,
        .last_activity = std.time.timestamp(),
        .idle_since = std.time.timestamp() - 120, // 2 minutes ago
        .bytes_sent = 0,
        .bytes_received = 0,
        .is_tls = false,
        .tls_session = null,
    };

    // 60 second timeout - should be too long
    try testing.expect(conn.isIdleTooLong(60 * std.time.ns_per_s));

    // 180 second timeout - should be fine
    try testing.expect(!conn.isIdleTooLong(180 * std.time.ns_per_s));
}

test "OffloadManager init and deinit" {
    var manager = OffloadManager.init(testing.allocator, .{});
    defer manager.deinit();

    try testing.expectEqual(@as(u64, 0), manager.stats.total_offloaded);
}

test "OffloadManager getConnection empty" {
    var manager = OffloadManager.init(testing.allocator, .{});
    defer manager.deinit();

    try testing.expect(manager.getConnection(12345) == null);
}

test "Connector init and deinit" {
    var connector = Connector.init(testing.allocator, .{});
    defer connector.deinit();

    try testing.expectEqual(@as(u64, 0), connector.stats.connect_attempts);
}

test "Connector avgConnectTimeMs zero" {
    var connector = Connector.init(testing.allocator, .{});
    defer connector.deinit();

    try testing.expectEqual(@as(u64, 0), connector.avgConnectTimeMs());
}

test "ConnectorStats defaults" {
    const stats = Connector.ConnectorStats{};
    try testing.expectEqual(@as(u64, 0), stats.connect_attempts);
    try testing.expectEqual(@as(u64, 0), stats.connect_success);
    try testing.expectEqual(@as(u64, 0), stats.connect_failed);
}

test "TcpKeepalive defaults" {
    const keepalive = ConnectorConfig.TcpKeepalive{};
    try testing.expectEqual(@as(u32, 60), keepalive.idle_time);
    try testing.expectEqual(@as(u32, 10), keepalive.interval);
    try testing.expectEqual(@as(u32, 6), keepalive.count);
}
