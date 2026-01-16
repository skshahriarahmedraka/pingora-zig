//! Load Balancing Algorithms
//!
//! This module provides various load balancing algorithms for distributing
//! requests across upstream peers. Includes round-robin, weighted round-robin,
//! least connections, random, and consistent hashing.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-load-balancing

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const upstream = @import("upstream.zig");
const ketama = @import("ketama.zig");

// ============================================================================
// Load Balancer Selection
// ============================================================================

/// Selection result from load balancer
pub const Selection = struct {
    /// Selected peer
    peer: *upstream.Peer,
    /// Index of the peer in the group
    index: usize,
};

// ============================================================================
// Load Balancer Types
// ============================================================================

/// Available load balancing algorithms
pub const Algorithm = enum {
    /// Round-robin selection
    round_robin,
    /// Weighted round-robin selection
    weighted_round_robin,
    /// Select peer with least active connections
    least_connections,
    /// Random selection
    random,
    /// Consistent hashing based on a key
    consistent_hash,
    /// IP hash (based on client IP)
    ip_hash,
};

// ============================================================================
// Round Robin
// ============================================================================

/// Simple round-robin load balancer
pub const RoundRobin = struct {
    current: usize,

    const Self = @This();

    pub fn init() Self {
        return .{ .current = 0 };
    }

    /// Select the next available peer
    pub fn select(self: *Self, group: *upstream.UpstreamGroup) ?Selection {
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        // Find next available peer
        var attempts: usize = 0;
        while (attempts < peers.len) {
            const index = self.current % peers.len;
            self.current = (self.current + 1) % peers.len;

            const peer = peers[index];
            if (peer.isAvailable()) {
                return Selection{ .peer = peer, .index = index };
            }
            attempts += 1;
        }

        return null;
    }

    /// Reset the counter
    pub fn reset(self: *Self) void {
        self.current = 0;
    }
};

// ============================================================================
// Weighted Round Robin
// ============================================================================

/// Weighted round-robin load balancer (smooth weighted round-robin)
pub const WeightedRoundRobin = struct {
    current_weights: []i32,
    allocator: Allocator,
    initialized: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .current_weights = &[_]i32{},
            .allocator = allocator,
            .initialized = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.current_weights.len > 0) {
            self.allocator.free(self.current_weights);
        }
    }

    /// Initialize weights for a group
    pub fn initForGroup(self: *Self, group: *upstream.UpstreamGroup) !void {
        if (self.current_weights.len > 0) {
            self.allocator.free(self.current_weights);
        }

        const peers = group.peers.items;
        self.current_weights = try self.allocator.alloc(i32, peers.len);
        @memset(self.current_weights, 0);
        self.initialized = true;
    }

    /// Select the next peer using smooth weighted round-robin
    pub fn select(self: *Self, group: *upstream.UpstreamGroup) !?Selection {
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        // Initialize if needed
        if (!self.initialized or self.current_weights.len != peers.len) {
            try self.initForGroup(group);
        }

        var total_weight: i32 = 0;
        var best_index: ?usize = null;
        var best_weight: i32 = std.math.minInt(i32);

        // Add effective weights and find best
        for (peers, 0..) |peer, i| {
            const effective_weight: i32 = @intCast(peer.getEffectiveWeight());
            if (effective_weight == 0) continue;

            self.current_weights[i] += effective_weight;
            total_weight += effective_weight;

            if (self.current_weights[i] > best_weight) {
                best_weight = self.current_weights[i];
                best_index = i;
            }
        }

        if (best_index) |idx| {
            self.current_weights[idx] -= total_weight;
            return Selection{ .peer = peers[idx], .index = idx };
        }

        return null;
    }
};

// ============================================================================
// Least Connections
// ============================================================================

/// Least connections load balancer
pub const LeastConnections = struct {
    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    /// Select the peer with the least active connections
    pub fn select(self: *Self, group: *upstream.UpstreamGroup) ?Selection {
        _ = self;
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        var best_peer: ?*upstream.Peer = null;
        var best_index: usize = 0;
        var min_connections: u32 = std.math.maxInt(u32);

        for (peers, 0..) |peer, i| {
            if (!peer.isAvailable()) continue;

            const connections = peer.stats.active_connections;
            if (connections < min_connections) {
                min_connections = connections;
                best_peer = peer;
                best_index = i;
            }
        }

        if (best_peer) |peer| {
            return Selection{ .peer = peer, .index = best_index };
        }

        return null;
    }

    /// Select with weighted least connections
    pub fn selectWeighted(self: *Self, group: *upstream.UpstreamGroup) ?Selection {
        _ = self;
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        var best_peer: ?*upstream.Peer = null;
        var best_index: usize = 0;
        var best_ratio: f64 = std.math.floatMax(f64);

        for (peers, 0..) |peer, i| {
            if (!peer.isAvailable()) continue;

            const weight = peer.getEffectiveWeight();
            if (weight == 0) continue;

            // Calculate connections/weight ratio (lower is better)
            const ratio = @as(f64, @floatFromInt(peer.stats.active_connections)) /
                @as(f64, @floatFromInt(weight));

            if (ratio < best_ratio) {
                best_ratio = ratio;
                best_peer = peer;
                best_index = i;
            }
        }

        if (best_peer) |peer| {
            return Selection{ .peer = peer, .index = best_index };
        }

        return null;
    }
};

// ============================================================================
// Random
// ============================================================================

/// Random load balancer
pub const Random = struct {
    rng: std.Random,

    const Self = @This();

    pub fn init() Self {
        return .{
            .rng = std.crypto.random,
        };
    }

    /// Select a random available peer
    pub fn select(self: *Self, group: *upstream.UpstreamGroup) ?Selection {
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        // Count available peers
        var available: usize = 0;
        for (peers) |peer| {
            if (peer.isAvailable()) available += 1;
        }

        if (available == 0) return null;

        // Select random available peer
        const target = self.rng.intRangeLessThan(usize, 0, available);
        var current: usize = 0;

        for (peers, 0..) |peer, i| {
            if (peer.isAvailable()) {
                if (current == target) {
                    return Selection{ .peer = peer, .index = i };
                }
                current += 1;
            }
        }

        return null;
    }

    /// Select with weighted random
    pub fn selectWeighted(self: *Self, group: *upstream.UpstreamGroup) ?Selection {
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        var total_weight: u32 = 0;
        for (peers) |peer| {
            total_weight += peer.getEffectiveWeight();
        }

        if (total_weight == 0) return null;

        var target = self.rng.intRangeLessThan(u32, 0, total_weight);

        for (peers, 0..) |peer, i| {
            const weight = peer.getEffectiveWeight();
            if (target < weight) {
                return Selection{ .peer = peer, .index = i };
            }
            target -= weight;
        }

        return null;
    }
};

// ============================================================================
// IP Hash
// ============================================================================

/// IP-based hash load balancer
pub const IpHash = struct {
    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    /// Select peer based on client IP hash
    pub fn select(self: *Self, group: *upstream.UpstreamGroup, client_ip: []const u8) ?Selection {
        _ = self;
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        // Hash the client IP
        const hash = std.hash.Wyhash.hash(0, client_ip);

        // Find available peers
        var available_count: usize = 0;
        for (peers) |peer| {
            if (peer.isAvailable()) available_count += 1;
        }

        if (available_count == 0) return null;

        // Select based on hash
        var target = hash % available_count;
        for (peers, 0..) |peer, i| {
            if (peer.isAvailable()) {
                if (target == 0) {
                    return Selection{ .peer = peer, .index = i };
                }
                target -= 1;
            }
        }

        return null;
    }
};

// ============================================================================
// Consistent Hash
// ============================================================================

/// Consistent hash load balancer using ketama
pub const ConsistentHash = struct {
    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    /// Select peer based on consistent hashing of a key
    pub fn select(self: *Self, group: *upstream.UpstreamGroup, key: []const u8) ?Selection {
        _ = self;
        const peers = group.peers.items;
        if (peers.len == 0) return null;

        // Use ketama-style hashing
        const hash = std.hash.Wyhash.hash(0, key);

        // Find available peers
        var available_count: usize = 0;
        var total_weight: u32 = 0;
        for (peers) |peer| {
            if (peer.isAvailable()) {
                available_count += 1;
                total_weight += peer.getEffectiveWeight();
            }
        }

        if (available_count == 0) return null;

        // For weighted selection, use the hash to pick a point in the weight space
        var point = hash % @as(u64, total_weight);

        for (peers, 0..) |peer, i| {
            if (peer.isAvailable()) {
                const weight = peer.getEffectiveWeight();
                if (point < weight) {
                    return Selection{ .peer = peer, .index = i };
                }
                point -= weight;
            }
        }

        // Fallback to first available
        for (peers, 0..) |peer, i| {
            if (peer.isAvailable()) {
                return Selection{ .peer = peer, .index = i };
            }
        }

        return null;
    }
};

// ============================================================================
// Generic Load Balancer
// ============================================================================

/// Generic load balancer that can use different algorithms
pub const LoadBalancer = struct {
    algorithm: Algorithm,
    round_robin: RoundRobin,
    weighted_round_robin: WeightedRoundRobin,
    least_connections: LeastConnections,
    random: Random,
    ip_hash: IpHash,
    consistent_hash: ConsistentHash,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, algorithm: Algorithm) Self {
        return .{
            .algorithm = algorithm,
            .round_robin = RoundRobin.init(),
            .weighted_round_robin = WeightedRoundRobin.init(allocator),
            .least_connections = LeastConnections.init(),
            .random = Random.init(),
            .ip_hash = IpHash.init(),
            .consistent_hash = ConsistentHash.init(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.weighted_round_robin.deinit();
    }

    /// Select a peer using the configured algorithm
    pub fn select(self: *Self, group: *upstream.UpstreamGroup) !?Selection {
        return switch (self.algorithm) {
            .round_robin => self.round_robin.select(group),
            .weighted_round_robin => try self.weighted_round_robin.select(group),
            .least_connections => self.least_connections.select(group),
            .random => self.random.select(group),
            .consistent_hash, .ip_hash => null, // Need key/IP
        };
    }

    /// Select a peer using consistent hashing with a key
    pub fn selectWithKey(self: *Self, group: *upstream.UpstreamGroup, key: []const u8) ?Selection {
        return switch (self.algorithm) {
            .consistent_hash => self.consistent_hash.select(group, key),
            .ip_hash => self.ip_hash.select(group, key),
            else => null,
        };
    }

    /// Set the algorithm
    pub fn setAlgorithm(self: *Self, algorithm: Algorithm) void {
        self.algorithm = algorithm;
    }
};

// ============================================================================
// Tests
// ============================================================================

fn createTestGroup(allocator: Allocator) !*upstream.UpstreamGroup {
    const group = try allocator.create(upstream.UpstreamGroup);
    group.* = try upstream.UpstreamGroup.init(allocator, "test");

    const addr1 = try @import("protocols.zig").parseAddress("127.0.0.1", 8081);
    const addr2 = try @import("protocols.zig").parseAddress("127.0.0.1", 8082);
    const addr3 = try @import("protocols.zig").parseAddress("127.0.0.1", 8083);

    const p1 = try group.addPeer(addr1, .{ .weight = 1 });
    const p2 = try group.addPeer(addr2, .{ .weight = 2 });
    const p3 = try group.addPeer(addr3, .{ .weight = 3 });

    p1.markHealthy();
    p2.markHealthy();
    p3.markHealthy();

    return group;
}

test "RoundRobin basic" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var rr = RoundRobin.init();

    const s1 = rr.select(group);
    try testing.expect(s1 != null);
    try testing.expectEqual(s1.?.index, 0);

    const s2 = rr.select(group);
    try testing.expect(s2 != null);
    try testing.expectEqual(s2.?.index, 1);

    const s3 = rr.select(group);
    try testing.expect(s3 != null);
    try testing.expectEqual(s3.?.index, 2);

    // Wraps around
    const s4 = rr.select(group);
    try testing.expect(s4 != null);
    try testing.expectEqual(s4.?.index, 0);
}

test "RoundRobin skips unhealthy" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    group.peers.items[1].markUnhealthy();

    var rr = RoundRobin.init();

    const s1 = rr.select(group);
    try testing.expectEqual(s1.?.index, 0);

    const s2 = rr.select(group);
    try testing.expectEqual(s2.?.index, 2); // Skips unhealthy peer at index 1
}

test "LeastConnections basic" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    // Add some connections
    group.peers.items[0].stats.active_connections = 5;
    group.peers.items[1].stats.active_connections = 2;
    group.peers.items[2].stats.active_connections = 8;

    var lc = LeastConnections.init();
    const selection = lc.select(group);

    try testing.expect(selection != null);
    try testing.expectEqual(selection.?.index, 1); // Peer with least connections
}

test "Random select" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var rnd = Random.init();

    // Should always return a valid selection
    for (0..10) |_| {
        const selection = rnd.select(group);
        try testing.expect(selection != null);
    }
}

test "IpHash consistent for same IP" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var ih = IpHash.init();

    const s1 = ih.select(group, "192.168.1.100");
    const s2 = ih.select(group, "192.168.1.100");
    const s3 = ih.select(group, "192.168.1.100");

    try testing.expect(s1 != null);
    try testing.expect(s2 != null);
    try testing.expect(s3 != null);

    // Same IP should always map to same peer
    try testing.expectEqual(s1.?.index, s2.?.index);
    try testing.expectEqual(s2.?.index, s3.?.index);
}

test "ConsistentHash consistent for same key" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var ch = ConsistentHash.init();

    const s1 = ch.select(group, "user:12345");
    const s2 = ch.select(group, "user:12345");

    try testing.expect(s1 != null);
    try testing.expect(s2 != null);
    try testing.expectEqual(s1.?.index, s2.?.index);

    // Different key may (likely) map to different peer
    const s3 = ch.select(group, "user:99999");
    try testing.expect(s3 != null);
}

test "LoadBalancer with different algorithms" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var lb = LoadBalancer.init(testing.allocator, .round_robin);
    defer lb.deinit();

    const s1 = try lb.select(group);
    try testing.expect(s1 != null);

    lb.setAlgorithm(.least_connections);
    const s2 = try lb.select(group);
    try testing.expect(s2 != null);

    lb.setAlgorithm(.random);
    const s3 = try lb.select(group);
    try testing.expect(s3 != null);
}

test "LoadBalancer selectWithKey" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var lb = LoadBalancer.init(testing.allocator, .consistent_hash);
    defer lb.deinit();

    const s1 = lb.selectWithKey(group, "session:abc");
    try testing.expect(s1 != null);

    lb.setAlgorithm(.ip_hash);
    const s2 = lb.selectWithKey(group, "10.0.0.1");
    try testing.expect(s2 != null);
}

test "WeightedRoundRobin respects weights" {
    const group = try createTestGroup(testing.allocator);
    defer {
        group.deinit();
        testing.allocator.destroy(group);
    }

    var wrr = WeightedRoundRobin.init(testing.allocator);
    defer wrr.deinit();

    // Count selections over many iterations
    var counts = [_]usize{ 0, 0, 0 };

    for (0..60) |_| {
        if (try wrr.select(group)) |s| {
            counts[s.index] += 1;
        }
    }

    // With weights 1, 2, 3 (total 6), expect roughly:
    // peer 0: 10 (1/6)
    // peer 1: 20 (2/6)
    // peer 2: 30 (3/6)
    try testing.expect(counts[0] < counts[1]);
    try testing.expect(counts[1] < counts[2]);
}

test "Empty group returns null" {
    var group = try upstream.UpstreamGroup.init(testing.allocator, "empty");
    defer group.deinit();

    var rr = RoundRobin.init();
    try testing.expect(rr.select(&group) == null);

    var lc = LeastConnections.init();
    try testing.expect(lc.select(&group) == null);

    var rnd = Random.init();
    try testing.expect(rnd.select(&group) == null);
}
