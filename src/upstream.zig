//! Upstream Peer Management
//!
//! This module provides types and utilities for managing upstream backend servers.
//! It includes peer health tracking, weight management, and connection metadata.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-core/src/upstreams

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const protocols = @import("protocols.zig");
const pool = @import("pool.zig");

// ============================================================================
// Peer Health Status
// ============================================================================

/// Health status of a peer
pub const HealthStatus = enum {
    /// Peer is healthy and accepting connections
    healthy,
    /// Peer is unhealthy and should not receive new connections
    unhealthy,
    /// Peer health is unknown (not yet checked)
    unknown,
    /// Peer is in maintenance mode
    maintenance,

    pub fn isAvailable(self: HealthStatus) bool {
        return self == .healthy or self == .unknown;
    }
};

// ============================================================================
// Peer Statistics
// ============================================================================

/// Statistics for a single peer
pub const PeerStats = struct {
    /// Total number of connections made
    total_connections: u64,
    /// Currently active connections
    active_connections: u32,
    /// Number of successful requests
    successful_requests: u64,
    /// Number of failed requests
    failed_requests: u64,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Average response time in milliseconds
    avg_response_time_ms: f64,
    /// Last response time in milliseconds
    last_response_time_ms: u64,
    /// Last successful connection timestamp
    last_success: ?i128,
    /// Last failed connection timestamp
    last_failure: ?i128,

    const Self = @This();

    pub fn init() Self {
        return .{
            .total_connections = 0,
            .active_connections = 0,
            .successful_requests = 0,
            .failed_requests = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
            .avg_response_time_ms = 0,
            .last_response_time_ms = 0,
            .last_success = null,
            .last_failure = null,
        };
    }

    /// Record a successful request
    pub fn recordSuccess(self: *Self, response_time_ms: u64, bytes_sent: u64, bytes_recv: u64) void {
        self.successful_requests += 1;
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_recv;
        self.last_response_time_ms = response_time_ms;
        self.last_success = std.time.nanoTimestamp();

        // Update running average
        const total = self.successful_requests + self.failed_requests;
        if (total > 0) {
            self.avg_response_time_ms = (self.avg_response_time_ms * @as(f64, @floatFromInt(total - 1)) +
                @as(f64, @floatFromInt(response_time_ms))) / @as(f64, @floatFromInt(total));
        }
    }

    /// Record a failed request
    pub fn recordFailure(self: *Self) void {
        self.failed_requests += 1;
        self.last_failure = std.time.nanoTimestamp();
    }

    /// Record connection start
    pub fn connectionStarted(self: *Self) void {
        self.total_connections += 1;
        self.active_connections += 1;
    }

    /// Record connection end
    pub fn connectionEnded(self: *Self) void {
        if (self.active_connections > 0) {
            self.active_connections -= 1;
        }
    }

    /// Get success rate (0.0 - 1.0)
    pub fn getSuccessRate(self: *const Self) f64 {
        const total = self.successful_requests + self.failed_requests;
        if (total == 0) return 1.0;
        return @as(f64, @floatFromInt(self.successful_requests)) / @as(f64, @floatFromInt(total));
    }
};

// ============================================================================
// Upstream Peer
// ============================================================================

/// Configuration options for a peer
pub const PeerOptions = struct {
    /// Connection weight (for weighted load balancing)
    weight: u32 = 1,
    /// Maximum number of concurrent connections
    max_connections: u32 = 0, // 0 = unlimited
    /// Fail timeout in seconds (how long to consider a peer unhealthy after failure)
    fail_timeout_secs: u32 = 10,
    /// Maximum number of failures before marking unhealthy
    max_fails: u32 = 1,
    /// Whether to use TLS
    use_tls: bool = false,
    /// TLS server name (SNI)
    tls_sni: ?[]const u8 = null,
};

/// An upstream peer (backend server)
pub const Peer = struct {
    /// Network address
    address: net.Address,
    /// Optional hostname (for DNS-based discovery)
    hostname: ?[]const u8,
    /// Peer options
    options: PeerOptions,
    /// Health status
    health: HealthStatus,
    /// Statistics
    stats: PeerStats,
    /// Number of consecutive failures
    consecutive_failures: u32,
    /// When the peer was last marked unhealthy
    unhealthy_since: ?i128,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new peer
    pub fn init(allocator: Allocator, address: net.Address, options: PeerOptions) Self {
        return .{
            .address = address,
            .hostname = null,
            .options = options,
            .health = .unknown,
            .stats = PeerStats.init(),
            .consecutive_failures = 0,
            .unhealthy_since = null,
            .allocator = allocator,
        };
    }

    /// Create a new peer with hostname
    pub fn initWithHostname(allocator: Allocator, address: net.Address, hostname: []const u8, options: PeerOptions) !Self {
        var peer = init(allocator, address, options);
        peer.hostname = try allocator.dupe(u8, hostname);
        return peer;
    }

    /// Free resources
    pub fn deinit(self: *Self) void {
        if (self.hostname) |h| {
            self.allocator.free(h);
        }
    }

    /// Check if the peer is available for new connections
    pub fn isAvailable(self: *const Self) bool {
        if (!self.health.isAvailable()) return false;

        // Check max connections limit
        if (self.options.max_connections > 0 and
            self.stats.active_connections >= self.options.max_connections)
        {
            return false;
        }

        return true;
    }

    /// Mark the peer as healthy
    pub fn markHealthy(self: *Self) void {
        self.health = .healthy;
        self.consecutive_failures = 0;
        self.unhealthy_since = null;
    }

    /// Mark the peer as unhealthy
    pub fn markUnhealthy(self: *Self) void {
        self.health = .unhealthy;
        self.unhealthy_since = std.time.nanoTimestamp();
    }

    /// Record a connection failure
    pub fn recordFailure(self: *Self) void {
        self.stats.recordFailure();
        self.consecutive_failures += 1;

        if (self.consecutive_failures >= self.options.max_fails) {
            self.markUnhealthy();
        }
    }

    /// Record a successful connection
    pub fn recordSuccess(self: *Self, response_time_ms: u64, bytes_sent: u64, bytes_recv: u64) void {
        self.stats.recordSuccess(response_time_ms, bytes_sent, bytes_recv);
        self.consecutive_failures = 0;

        if (self.health == .unhealthy) {
            // Check if fail timeout has passed
            if (self.unhealthy_since) |since| {
                const elapsed_ns = std.time.nanoTimestamp() - since;
                const elapsed_secs = @divFloor(elapsed_ns, std.time.ns_per_s);
                if (elapsed_secs >= self.options.fail_timeout_secs) {
                    self.markHealthy();
                }
            }
        } else if (self.health == .unknown) {
            self.markHealthy();
        }
    }

    /// Get the port
    pub fn getPort(self: *const Self) u16 {
        return self.address.getPort();
    }

    /// Get effective weight (considering health)
    pub fn getEffectiveWeight(self: *const Self) u32 {
        if (!self.isAvailable()) return 0;
        return self.options.weight;
    }
};

// ============================================================================
// Upstream Group
// ============================================================================

/// A group of upstream peers (backend server pool)
pub const UpstreamGroup = struct {
    /// Name of this upstream group
    name: []const u8,
    /// List of peers
    peers: std.ArrayListUnmanaged(*Peer),
    /// Connection pool for this group
    connection_pool: pool.ConnectionPool(u64, *protocols.TcpStream),
    /// Total weight of healthy peers
    total_weight: u32,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new upstream group
    pub fn init(allocator: Allocator, name: []const u8) !Self {
        return .{
            .name = try allocator.dupe(u8, name),
            .peers = .{},
            .connection_pool = pool.ConnectionPool(u64, *protocols.TcpStream).init(allocator, 100),
            .total_weight = 0,
            .allocator = allocator,
        };
    }

    /// Free resources
    pub fn deinit(self: *Self) void {
        for (self.peers.items) |peer| {
            peer.deinit();
            self.allocator.destroy(peer);
        }
        self.peers.deinit(self.allocator);
        self.connection_pool.deinit();
        self.allocator.free(self.name);
    }

    /// Add a peer to the group
    pub fn addPeer(self: *Self, address: net.Address, options: PeerOptions) !*Peer {
        const peer = try self.allocator.create(Peer);
        peer.* = Peer.init(self.allocator, address, options);
        try self.peers.append(self.allocator, peer);
        self.updateTotalWeight();
        return peer;
    }

    /// Add a peer with hostname
    pub fn addPeerWithHostname(self: *Self, address: net.Address, hostname: []const u8, options: PeerOptions) !*Peer {
        const peer = try self.allocator.create(Peer);
        peer.* = try Peer.initWithHostname(self.allocator, address, hostname, options);
        try self.peers.append(self.allocator, peer);
        self.updateTotalWeight();
        return peer;
    }

    /// Remove a peer from the group
    pub fn removePeer(self: *Self, peer: *Peer) bool {
        for (self.peers.items, 0..) |p, i| {
            if (p == peer) {
                p.deinit();
                self.allocator.destroy(p);
                _ = self.peers.orderedRemove(i);
                self.updateTotalWeight();
                return true;
            }
        }
        return false;
    }

    /// Get the number of peers
    pub fn peerCount(self: *const Self) usize {
        return self.peers.items.len;
    }

    /// Get the number of healthy peers
    pub fn healthyPeerCount(self: *const Self) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.isAvailable()) count += 1;
        }
        return count;
    }

    /// Update total weight of healthy peers
    fn updateTotalWeight(self: *Self) void {
        self.total_weight = 0;
        for (self.peers.items) |peer| {
            self.total_weight += peer.getEffectiveWeight();
        }
    }

    /// Get all available peers
    pub fn getAvailablePeers(self: *Self, out: []*Peer) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.isAvailable() and count < out.len) {
                out[count] = peer;
                count += 1;
            }
        }
        return count;
    }

    /// Mark all peers as healthy (for recovery)
    pub fn markAllHealthy(self: *Self) void {
        for (self.peers.items) |peer| {
            peer.markHealthy();
        }
        self.updateTotalWeight();
    }
};

// ============================================================================
// Health Check Configuration
// ============================================================================

/// Configuration for health checks
pub const HealthCheckConfig = struct {
    /// Interval between health checks in milliseconds
    interval_ms: u32 = 5000,
    /// Timeout for health check in milliseconds
    timeout_ms: u32 = 2000,
    /// Number of successful checks to mark healthy
    healthy_threshold: u32 = 2,
    /// Number of failed checks to mark unhealthy
    unhealthy_threshold: u32 = 3,
    /// HTTP path for HTTP health checks
    http_path: []const u8 = "/health",
    /// Expected HTTP status codes (empty = any 2xx)
    expected_status: []const u16 = &[_]u16{},
};

// ============================================================================
// Tests
// ============================================================================

test "HealthStatus isAvailable" {
    try testing.expect(HealthStatus.healthy.isAvailable());
    try testing.expect(HealthStatus.unknown.isAvailable());
    try testing.expect(!HealthStatus.unhealthy.isAvailable());
    try testing.expect(!HealthStatus.maintenance.isAvailable());
}

test "PeerStats init" {
    const stats = PeerStats.init();
    try testing.expectEqual(stats.total_connections, 0);
    try testing.expectEqual(stats.active_connections, 0);
    try testing.expectEqual(stats.successful_requests, 0);
}

test "PeerStats recordSuccess" {
    var stats = PeerStats.init();

    stats.recordSuccess(100, 1000, 2000);
    try testing.expectEqual(stats.successful_requests, 1);
    try testing.expectEqual(stats.bytes_sent, 1000);
    try testing.expectEqual(stats.bytes_received, 2000);
    try testing.expectEqual(stats.last_response_time_ms, 100);
    try testing.expect(stats.last_success != null);
}

test "PeerStats recordFailure" {
    var stats = PeerStats.init();

    stats.recordFailure();
    try testing.expectEqual(stats.failed_requests, 1);
    try testing.expect(stats.last_failure != null);
}

test "PeerStats getSuccessRate" {
    var stats = PeerStats.init();

    // No requests = 100% success
    try testing.expectEqual(stats.getSuccessRate(), 1.0);

    stats.recordSuccess(100, 0, 0);
    stats.recordSuccess(100, 0, 0);
    stats.recordFailure();

    // 2 successes, 1 failure = 66.67%
    try testing.expect(stats.getSuccessRate() > 0.66);
    try testing.expect(stats.getSuccessRate() < 0.67);
}

test "PeerStats connectionStarted and ended" {
    var stats = PeerStats.init();

    stats.connectionStarted();
    try testing.expectEqual(stats.total_connections, 1);
    try testing.expectEqual(stats.active_connections, 1);

    stats.connectionStarted();
    try testing.expectEqual(stats.active_connections, 2);

    stats.connectionEnded();
    try testing.expectEqual(stats.active_connections, 1);
}

test "Peer init" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = Peer.init(testing.allocator, addr, .{});
    defer peer.deinit();

    try testing.expectEqual(peer.health, .unknown);
    try testing.expectEqual(peer.getPort(), 8080);
    try testing.expect(peer.isAvailable());
}

test "Peer markHealthy and markUnhealthy" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = Peer.init(testing.allocator, addr, .{});
    defer peer.deinit();

    peer.markHealthy();
    try testing.expectEqual(peer.health, .healthy);
    try testing.expect(peer.isAvailable());

    peer.markUnhealthy();
    try testing.expectEqual(peer.health, .unhealthy);
    try testing.expect(!peer.isAvailable());
}

test "Peer recordFailure triggers unhealthy" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = Peer.init(testing.allocator, addr, .{ .max_fails = 3 });
    defer peer.deinit();

    peer.markHealthy();

    peer.recordFailure();
    try testing.expectEqual(peer.health, .healthy); // Still healthy

    peer.recordFailure();
    try testing.expectEqual(peer.health, .healthy); // Still healthy

    peer.recordFailure();
    try testing.expectEqual(peer.health, .unhealthy); // Now unhealthy
}

test "Peer max_connections limit" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = Peer.init(testing.allocator, addr, .{ .max_connections = 2 });
    defer peer.deinit();

    peer.markHealthy();
    try testing.expect(peer.isAvailable());

    peer.stats.connectionStarted();
    try testing.expect(peer.isAvailable());

    peer.stats.connectionStarted();
    try testing.expect(!peer.isAvailable()); // At max connections
}

test "Peer getEffectiveWeight" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = Peer.init(testing.allocator, addr, .{ .weight = 10 });
    defer peer.deinit();

    peer.markHealthy();
    try testing.expectEqual(peer.getEffectiveWeight(), 10);

    peer.markUnhealthy();
    try testing.expectEqual(peer.getEffectiveWeight(), 0);
}

test "UpstreamGroup init and deinit" {
    var group = try UpstreamGroup.init(testing.allocator, "backend");
    defer group.deinit();

    try testing.expectEqualStrings("backend", group.name);
    try testing.expectEqual(group.peerCount(), 0);
}

test "UpstreamGroup addPeer" {
    var group = try UpstreamGroup.init(testing.allocator, "backend");
    defer group.deinit();

    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    _ = try group.addPeer(addr, .{ .weight = 5 });

    try testing.expectEqual(group.peerCount(), 1);
}

test "UpstreamGroup multiple peers" {
    var group = try UpstreamGroup.init(testing.allocator, "backend");
    defer group.deinit();

    const addr1 = try protocols.parseAddress("127.0.0.1", 8081);
    const addr2 = try protocols.parseAddress("127.0.0.1", 8082);
    const addr3 = try protocols.parseAddress("127.0.0.1", 8083);

    _ = try group.addPeer(addr1, .{});
    _ = try group.addPeer(addr2, .{});
    _ = try group.addPeer(addr3, .{});

    try testing.expectEqual(group.peerCount(), 3);
    try testing.expectEqual(group.healthyPeerCount(), 3); // All unknown = available
}

test "UpstreamGroup removePeer" {
    var group = try UpstreamGroup.init(testing.allocator, "backend");
    defer group.deinit();

    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    const peer = try group.addPeer(addr, .{});

    try testing.expectEqual(group.peerCount(), 1);

    const removed = group.removePeer(peer);
    try testing.expect(removed);
    try testing.expectEqual(group.peerCount(), 0);
}

test "HealthCheckConfig defaults" {
    const config = HealthCheckConfig{};
    try testing.expectEqual(config.interval_ms, 5000);
    try testing.expectEqual(config.timeout_ms, 2000);
    try testing.expectEqualStrings("/health", config.http_path);
}
