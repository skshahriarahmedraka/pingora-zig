//! Load Balancing Algorithms
//!
//! This module provides various load balancing algorithms for distributing
//! requests across upstream peers. Includes round-robin, weighted round-robin,
//! least connections, random, and consistent hashing.
//!
//! Also includes:
//! - Service Discovery: Static, DNS-based, and health-aware discovery
//! - Health Checks: TCP and HTTP health checking with configurable thresholds
//! - Backend Selection: Weighted selection with unique iteration support
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-load-balancing

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const upstream = @import("upstream.zig");
const ketama = @import("ketama.zig");
const protocols = @import("protocols.zig");
const http = @import("http.zig");

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
// Backend - Represents a single upstream server
// ============================================================================

/// A backend server that can be discovered and health-checked
pub const Backend = struct {
    /// Address of the backend (IP:port)
    address: std.net.Address,
    /// Weight for weighted load balancing (default: 1)
    weight: u32,
    /// Whether this backend is healthy
    healthy: bool,
    /// Number of consecutive health check successes
    consecutive_successes: u32,
    /// Number of consecutive health check failures
    consecutive_failures: u32,
    /// Optional hostname for HTTP health checks
    hostname: ?[]const u8,
    /// Custom extensions/metadata
    extensions: ?*anyopaque,

    const Self = @This();

    /// Create a new backend from an address string (e.g., "127.0.0.1:8080")
    pub fn new(addr_str: []const u8, port: u16) !Self {
        const address = try protocols.parseAddress(addr_str, port);
        return .{
            .address = address,
            .weight = 1,
            .healthy = true,
            .consecutive_successes = 0,
            .consecutive_failures = 0,
            .hostname = null,
            .extensions = null,
        };
    }

    /// Create a new backend with a specific weight
    pub fn newWeighted(addr_str: []const u8, port: u16, weight: u32) !Self {
        var backend = try new(addr_str, port);
        backend.weight = weight;
        return backend;
    }

    /// Create from an existing address
    pub fn fromAddress(address: std.net.Address, weight: u32) Self {
        return .{
            .address = address,
            .weight = weight,
            .healthy = true,
            .consecutive_successes = 0,
            .consecutive_failures = 0,
            .hostname = null,
            .extensions = null,
        };
    }

    /// Compute a hash key for this backend (for deduplication)
    pub fn hashKey(self: *const Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        // Hash address bytes
        const addr_bytes = std.mem.asBytes(&self.address);
        hasher.update(addr_bytes);
        return hasher.final();
    }

    /// Check if this backend equals another
    pub fn eql(self: *const Self, other: *const Self) bool {
        return self.hashKey() == other.hashKey();
    }

    /// Mark this backend as healthy after a successful check
    pub fn markHealthy(self: *Self, threshold: u32) bool {
        self.consecutive_failures = 0;
        self.consecutive_successes += 1;
        if (!self.healthy and self.consecutive_successes >= threshold) {
            self.healthy = true;
            return true; // Health changed
        }
        return false;
    }

    /// Mark this backend as unhealthy after a failed check
    pub fn markUnhealthy(self: *Self, threshold: u32) bool {
        self.consecutive_successes = 0;
        self.consecutive_failures += 1;
        if (self.healthy and self.consecutive_failures >= threshold) {
            self.healthy = false;
            return true; // Health changed
        }
        return false;
    }
};

// ============================================================================
// Service Discovery - Interface for discovering backends
// ============================================================================

/// Result of a discovery operation
pub const DiscoveryResult = struct {
    /// Discovered backends
    backends: std.ArrayListUnmanaged(Backend),
    /// Health status overrides (backend hash -> enabled)
    health_overrides: std.AutoHashMap(u64, bool),
    /// Allocator for cleanup
    allocator: Allocator,

    pub fn init(allocator: Allocator) DiscoveryResult {
        return .{
            .backends = .{},
            .health_overrides = std.AutoHashMap(u64, bool).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DiscoveryResult) void {
        self.backends.deinit(self.allocator);
        self.health_overrides.deinit();
    }
};

/// Service discovery interface using tagged union
pub const ServiceDiscovery = union(enum) {
    /// Static list of backends
    static: StaticDiscovery,
    /// DNS-based discovery
    dns: DnsDiscovery,
    /// Custom discovery with function pointer
    custom: CustomDiscovery,

    const Self = @This();

    /// Discover backends
    pub fn discover(self: *Self, allocator: Allocator) !DiscoveryResult {
        return switch (self.*) {
            .static => |*s| s.discover(allocator),
            .dns => |*d| d.discover(allocator),
            .custom => |*c| c.discover(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            .static => |*s| s.deinit(),
            .dns => |*d| d.deinit(),
            .custom => {},
        }
    }
};

/// Static service discovery - hardcoded list of backends
pub const StaticDiscovery = struct {
    backends: std.ArrayListUnmanaged(Backend),
    allocator: Allocator,
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Create a new static discovery with no backends
    pub fn init(allocator: Allocator) Self {
        return .{
            .backends = .{},
            .allocator = allocator,
            .mutex = .{},
        };
    }

    /// Create from an array of address strings
    pub fn fromAddresses(allocator: Allocator, addresses: []const struct { addr: []const u8, port: u16 }) !Self {
        var self = init(allocator);
        errdefer self.deinit();

        for (addresses) |addr_info| {
            const backend = try Backend.new(addr_info.addr, addr_info.port);
            try self.backends.append(self.allocator, backend);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.backends.deinit(self.allocator);
    }

    /// Add a backend
    pub fn add(self: *Self, backend: Backend) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.backends.append(self.allocator, backend);
    }

    /// Remove a backend
    pub fn remove(self: *Self, backend: *const Backend) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const hash = backend.hashKey();
        for (self.backends.items, 0..) |*b, i| {
            if (b.hashKey() == hash) {
                _ = self.backends.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Get all backends
    pub fn get(self: *Self) []Backend {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.backends.items;
    }

    /// Discover backends (returns a copy)
    pub fn discover(self: *Self, allocator: Allocator) !DiscoveryResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = DiscoveryResult.init(allocator);
        errdefer result.deinit();

        for (self.backends.items) |backend| {
            try result.backends.append(allocator, backend);
        }

        return result;
    }
};

/// DNS-based service discovery
pub const DnsDiscovery = struct {
    /// Hostname to resolve
    hostname: []const u8,
    /// Port to use for discovered backends
    port: u16,
    /// Default weight for discovered backends
    default_weight: u32,
    /// Allocator
    allocator: Allocator,
    /// Owned hostname copy
    hostname_owned: bool,

    const Self = @This();

    /// Create a new DNS discovery
    pub fn init(allocator: Allocator, hostname: []const u8, port: u16) !Self {
        const hostname_copy = try allocator.dupe(u8, hostname);
        return .{
            .hostname = hostname_copy,
            .port = port,
            .default_weight = 1,
            .allocator = allocator,
            .hostname_owned = true,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.hostname_owned) {
            self.allocator.free(self.hostname);
        }
    }

    /// Discover backends via DNS resolution
    pub fn discover(self: *Self, allocator: Allocator) !DiscoveryResult {
        var result = DiscoveryResult.init(allocator);
        errdefer result.deinit();

        // Use std.net.getAddressList for DNS resolution
        const list = std.net.getAddressList(allocator, self.hostname, self.port) catch {
            // DNS resolution failed - return empty result
            return result;
        };
        defer list.deinit();

        for (list.addrs) |addr| {
            const backend = Backend.fromAddress(addr, self.default_weight);
            try result.backends.append(allocator, backend);
        }

        return result;
    }
};

/// Custom service discovery with function pointer
pub const CustomDiscovery = struct {
    context: *anyopaque,
    discoverFn: *const fn (*anyopaque, Allocator) anyerror!DiscoveryResult,

    const Self = @This();

    pub fn discover(self: *Self, allocator: Allocator) !DiscoveryResult {
        return self.discoverFn(self.context, allocator);
    }
};

// ============================================================================
// Health Check System
// ============================================================================

/// Health check result
pub const HealthCheckResult = enum {
    healthy,
    unhealthy,
    timeout,
};

/// Health check configuration
pub const HealthCheckConfig = struct {
    /// Number of consecutive successes to mark healthy
    consecutive_success: u32 = 1,
    /// Number of consecutive failures to mark unhealthy
    consecutive_failure: u32 = 1,
    /// Connection timeout in milliseconds
    connection_timeout_ms: u64 = 1000,
    /// Read timeout in milliseconds (for HTTP checks)
    read_timeout_ms: u64 = 1000,
    /// Check interval in milliseconds
    interval_ms: u64 = 5000,
};

/// Health check interface using tagged union
pub const HealthCheck = union(enum) {
    /// TCP health check - just try to connect
    tcp: TcpHealthCheck,
    /// HTTP health check - send HTTP request
    http_check: HttpHealthCheck,
    /// Custom health check with function pointer
    custom: CustomHealthCheck,

    const Self = @This();

    /// Perform a health check on a backend
    pub fn check(self: *Self, backend: *const Backend) HealthCheckResult {
        return switch (self.*) {
            .tcp => |*t| t.check(backend),
            .http_check => |*h| h.check(backend),
            .custom => |*c| c.check(backend),
        };
    }

    /// Get the health threshold for success/failure
    pub fn healthThreshold(self: *const Self, success: bool) u32 {
        return switch (self.*) {
            .tcp => |t| if (success) t.config.consecutive_success else t.config.consecutive_failure,
            .http_check => |h| if (success) h.config.consecutive_success else h.config.consecutive_failure,
            .custom => |c| if (success) c.consecutive_success else c.consecutive_failure,
        };
    }

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            .tcp => {},
            .http_check => |*h| h.deinit(),
            .custom => {},
        }
    }
};

/// TCP health check - verifies TCP connection can be established
pub const TcpHealthCheck = struct {
    config: HealthCheckConfig,

    const Self = @This();

    pub fn init(config: HealthCheckConfig) Self {
        return .{ .config = config };
    }

    pub fn initDefault() Self {
        return init(.{});
    }

    /// Check if we can establish a TCP connection
    pub fn check(self: *Self, backend: *const Backend) HealthCheckResult {
        _ = self;
        // Try to connect
        const stream = std.net.tcpConnectToAddress(backend.address) catch {
            return .unhealthy;
        };
        stream.close();
        return .healthy;
    }
};

/// HTTP health check - sends HTTP request and validates response
pub const HttpHealthCheck = struct {
    config: HealthCheckConfig,
    /// HTTP method to use
    method: http.Method,
    /// Path to request
    path: []const u8,
    /// Host header value
    host: []const u8,
    /// Expected status code (0 = any 2xx)
    expected_status: u16,
    /// Optional port override
    port_override: ?u16,
    /// Allocator
    allocator: Allocator,
    /// Whether path/host are owned
    owned: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, host: []const u8, config: HealthCheckConfig) !Self {
        const host_copy = try allocator.dupe(u8, host);
        const path_copy = try allocator.dupe(u8, "/");
        return .{
            .config = config,
            .method = .GET,
            .path = path_copy,
            .host = host_copy,
            .expected_status = 0, // Any 2xx
            .port_override = null,
            .allocator = allocator,
            .owned = true,
        };
    }

    pub fn initDefault(allocator: Allocator, host: []const u8) !Self {
        return init(allocator, host, .{});
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            self.allocator.free(self.path);
            self.allocator.free(self.host);
        }
    }

    /// Set the path to request
    pub fn setPath(self: *Self, path: []const u8) !void {
        if (self.owned) {
            self.allocator.free(self.path);
        }
        self.path = try self.allocator.dupe(u8, path);
        self.owned = true;
    }

    /// Check backend health via HTTP
    pub fn check(self: *Self, backend: *const Backend) HealthCheckResult {
        // Determine port
        const port = self.port_override orelse backend.address.getPort();

        // Try to connect
        const stream = std.net.tcpConnectToAddress(backend.address) catch {
            return .unhealthy;
        };
        defer stream.close();

        // Build HTTP request
        var buf: [1024]u8 = undefined;
        const request = std.fmt.bufPrint(&buf, "{s} {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n", .{
            @tagName(self.method),
            self.path,
            self.host,
            port,
        }) catch {
            return .unhealthy;
        };

        // Send request
        _ = stream.write(request) catch {
            return .unhealthy;
        };

        // Read response (just the status line)
        var response_buf: [256]u8 = undefined;
        const bytes_read = stream.read(&response_buf) catch {
            return .unhealthy;
        };

        if (bytes_read < 12) return .unhealthy;

        // Parse status code from "HTTP/1.1 200 OK"
        const response = response_buf[0..bytes_read];
        if (!std.mem.startsWith(u8, response, "HTTP/1.")) {
            return .unhealthy;
        }

        // Find status code
        var it = std.mem.splitScalar(u8, response, ' ');
        _ = it.next(); // Skip "HTTP/1.x"
        const status_str = it.next() orelse return .unhealthy;
        const status = std.fmt.parseInt(u16, status_str, 10) catch return .unhealthy;

        // Validate status
        if (self.expected_status == 0) {
            // Any 2xx is OK
            if (status >= 200 and status < 300) {
                return .healthy;
            }
        } else if (status == self.expected_status) {
            return .healthy;
        }

        return .unhealthy;
    }
};

/// Custom health check with function pointer
pub const CustomHealthCheck = struct {
    context: *anyopaque,
    checkFn: *const fn (*anyopaque, *const Backend) HealthCheckResult,
    consecutive_success: u32,
    consecutive_failure: u32,

    const Self = @This();

    pub fn check(self: *Self, backend: *const Backend) HealthCheckResult {
        return self.checkFn(self.context, backend);
    }
};

/// Health check callback for observing health changes
pub const HealthObserveCallback = *const fn (backend: *const Backend, healthy: bool) void;

/// Background health checker that monitors backends
pub const BackgroundHealthChecker = struct {
    /// Backends being monitored
    backends: std.ArrayListUnmanaged(*Backend),
    /// Health check to use
    health_check: *HealthCheck,
    /// Check interval in nanoseconds
    interval_ns: u64,
    /// Whether the checker is running
    running: std.atomic.Value(bool),
    /// Optional callback for health changes
    callback: ?HealthObserveCallback,
    /// Allocator
    allocator: Allocator,
    /// Background thread
    thread: ?std.Thread,

    const Self = @This();

    pub fn init(allocator: Allocator, health_check: *HealthCheck, interval_ms: u64) Self {
        return .{
            .backends = .{},
            .health_check = health_check,
            .interval_ns = interval_ms * std.time.ns_per_ms,
            .running = std.atomic.Value(bool).init(false),
            .callback = null,
            .allocator = allocator,
            .thread = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.backends.deinit(self.allocator);
    }

    /// Add a backend to monitor
    pub fn addBackend(self: *Self, backend: *Backend) !void {
        try self.backends.append(self.allocator, backend);
    }

    /// Remove a backend from monitoring
    pub fn removeBackend(self: *Self, backend: *const Backend) bool {
        const hash = backend.hashKey();
        for (self.backends.items, 0..) |b, i| {
            if (b.hashKey() == hash) {
                _ = self.backends.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Set the health change callback
    pub fn setCallback(self: *Self, callback: HealthObserveCallback) void {
        self.callback = callback;
    }

    /// Start background health checking
    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, runLoop, .{self});
    }

    /// Stop background health checking
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Run a single check iteration on all backends
    pub fn runOnce(self: *Self) void {
        for (self.backends.items) |backend| {
            const result = self.health_check.check(backend);
            const success_threshold = self.health_check.healthThreshold(true);
            const failure_threshold = self.health_check.healthThreshold(false);

            const health_changed = switch (result) {
                .healthy => backend.markHealthy(success_threshold),
                .unhealthy, .timeout => backend.markUnhealthy(failure_threshold),
            };

            if (health_changed) {
                if (self.callback) |cb| {
                    cb(backend, backend.healthy);
                }
            }
        }
    }

    fn runLoop(self: *Self) void {
        while (self.running.load(.acquire)) {
            self.runOnce();
            std.time.sleep(self.interval_ns);
        }
    }
};

// ============================================================================
// Unique Iterator - Filters duplicate backends during iteration
// ============================================================================

/// An iterator that yields unique backends, useful for retry logic
pub fn UniqueIterator(comptime Iter: type) type {
    return struct {
        inner: Iter,
        seen: std.AutoHashMap(u64, void),
        max_iterations: usize,
        steps: usize,
        allocator: Allocator,

        const Self = @This();

        pub fn init(allocator: Allocator, inner: Iter, max_iterations: usize) Self {
            return .{
                .inner = inner,
                .seen = std.AutoHashMap(u64, void).init(allocator),
                .max_iterations = max_iterations,
                .steps = 0,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.seen.deinit();
        }

        /// Get the next unique backend
        pub fn next(self: *Self) ?*Backend {
            while (self.steps < self.max_iterations) {
                const item = self.inner.next() orelse return null;
                self.steps += 1;

                const hash = item.hashKey();
                if (!self.seen.contains(hash)) {
                    self.seen.put(hash, {}) catch return null;
                    return item;
                }
            }
            return null;
        }
    };
}

// ============================================================================
// Backend Set - Manages a collection of backends with health state
// ============================================================================

/// A set of backends with discovery and health checking
pub const BackendSet = struct {
    /// All known backends
    backends: std.ArrayListUnmanaged(Backend),
    /// Service discovery (optional)
    discovery: ?ServiceDiscovery,
    /// Health checker (optional)
    health_checker: ?BackgroundHealthChecker,
    /// Allocator
    allocator: Allocator,
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .backends = .{},
            .discovery = null,
            .health_checker = null,
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.health_checker) |*hc| {
            hc.deinit();
        }
        if (self.discovery) |*d| {
            d.deinit();
        }
        self.backends.deinit(self.allocator);
    }

    /// Set the service discovery
    pub fn setDiscovery(self: *Self, discovery: ServiceDiscovery) void {
        self.discovery = discovery;
    }

    /// Set up health checking
    pub fn setupHealthCheck(self: *Self, health_check: *HealthCheck, interval_ms: u64) void {
        self.health_checker = BackgroundHealthChecker.init(self.allocator, health_check, interval_ms);
    }

    /// Add a backend manually
    pub fn addBackend(self: *Self, backend: Backend) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.backends.append(self.allocator, backend);

        if (self.health_checker) |*hc| {
            const last_idx = self.backends.items.len - 1;
            try hc.addBackend(&self.backends.items[last_idx]);
        }
    }

    /// Refresh backends from discovery
    pub fn refresh(self: *Self) !void {
        if (self.discovery) |*d| {
            var result = try d.discover(self.allocator);
            defer result.deinit();

            self.mutex.lock();
            defer self.mutex.unlock();

            // Replace backends
            self.backends.clearRetainingCapacity();
            for (result.backends.items) |backend| {
                try self.backends.append(self.allocator, backend);
            }

            // Apply health overrides
            for (self.backends.items) |*backend| {
                if (result.health_overrides.get(backend.hashKey())) |enabled| {
                    backend.healthy = enabled;
                }
            }

            // Update health checker
            if (self.health_checker) |*hc| {
                hc.backends.clearRetainingCapacity();
                for (self.backends.items) |*backend| {
                    try hc.addBackend(backend);
                }
            }
        }
    }

    /// Get healthy backends
    pub fn getHealthy(self: *Self) []Backend {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.backends.items) |backend| {
            if (backend.healthy) count += 1;
        }

        return self.backends.items;
    }

    /// Get all backends
    pub fn getAll(self: *Self) []Backend {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.backends.items;
    }

    /// Start health checking
    pub fn startHealthChecking(self: *Self) !void {
        if (self.health_checker) |*hc| {
            try hc.start();
        }
    }

    /// Stop health checking
    pub fn stopHealthChecking(self: *Self) void {
        if (self.health_checker) |*hc| {
            hc.stop();
        }
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

// ============================================================================
// Service Discovery Tests
// ============================================================================

test "Backend creation and hashing" {
    const b1 = try Backend.new("127.0.0.1", 8080);
    const b2 = try Backend.new("127.0.0.1", 8080);
    const b3 = try Backend.new("127.0.0.1", 8081);

    // Same address should have same hash
    try testing.expectEqual(b1.hashKey(), b2.hashKey());

    // Different port should have different hash
    try testing.expect(b1.hashKey() != b3.hashKey());
}

test "Backend health state transitions" {
    var backend = try Backend.new("127.0.0.1", 8080);

    // Initially healthy
    try testing.expect(backend.healthy);

    // Single failure doesn't change state with threshold 2
    const changed1 = backend.markUnhealthy(2);
    try testing.expect(!changed1);
    try testing.expect(backend.healthy);
    try testing.expectEqual(@as(u32, 1), backend.consecutive_failures);

    // Second failure changes state
    const changed2 = backend.markUnhealthy(2);
    try testing.expect(changed2);
    try testing.expect(!backend.healthy);

    // Single success doesn't change state with threshold 2
    const changed3 = backend.markHealthy(2);
    try testing.expect(!changed3);
    try testing.expect(!backend.healthy);
    try testing.expectEqual(@as(u32, 1), backend.consecutive_successes);

    // Second success changes state
    const changed4 = backend.markHealthy(2);
    try testing.expect(changed4);
    try testing.expect(backend.healthy);
}

test "StaticDiscovery basic operations" {
    var discovery = StaticDiscovery.init(testing.allocator);
    defer discovery.deinit();

    // Add backends
    const b1 = try Backend.new("127.0.0.1", 8080);
    const b2 = try Backend.new("127.0.0.1", 8081);
    try discovery.add(b1);
    try discovery.add(b2);

    // Discover should return all backends
    var result = try discovery.discover(testing.allocator);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 2), result.backends.items.len);
}

test "StaticDiscovery remove" {
    var discovery = StaticDiscovery.init(testing.allocator);
    defer discovery.deinit();

    const b1 = try Backend.new("127.0.0.1", 8080);
    const b2 = try Backend.new("127.0.0.1", 8081);
    try discovery.add(b1);
    try discovery.add(b2);

    // Remove first backend
    const removed = discovery.remove(&b1);
    try testing.expect(removed);

    var result = try discovery.discover(testing.allocator);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.backends.items.len);
}

test "ServiceDiscovery union" {
    var static = StaticDiscovery.init(testing.allocator);
    const b1 = try Backend.new("127.0.0.1", 8080);
    try static.add(b1);

    var discovery = ServiceDiscovery{ .static = static };
    defer discovery.deinit();

    var result = try discovery.discover(testing.allocator);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.backends.items.len);
}

// ============================================================================
// Health Check Tests
// ============================================================================

test "HealthCheckConfig defaults" {
    const config = HealthCheckConfig{};
    try testing.expectEqual(@as(u32, 1), config.consecutive_success);
    try testing.expectEqual(@as(u32, 1), config.consecutive_failure);
    try testing.expectEqual(@as(u64, 1000), config.connection_timeout_ms);
}

test "TcpHealthCheck creation" {
    const tcp_check = TcpHealthCheck.initDefault();
    try testing.expectEqual(@as(u32, 1), tcp_check.config.consecutive_success);
}

test "HttpHealthCheck creation" {
    var http_check = try HttpHealthCheck.initDefault(testing.allocator, "example.com");
    defer http_check.deinit();

    try testing.expectEqualStrings("/", http_check.path);
    try testing.expectEqualStrings("example.com", http_check.host);
    try testing.expectEqual(http.Method.GET, http_check.method);
}

test "HttpHealthCheck setPath" {
    var http_check = try HttpHealthCheck.initDefault(testing.allocator, "example.com");
    defer http_check.deinit();

    try http_check.setPath("/health");
    try testing.expectEqualStrings("/health", http_check.path);
}

test "HealthCheck union" {
    var hc = HealthCheck{ .tcp = TcpHealthCheck.initDefault() };
    defer hc.deinit();

    try testing.expectEqual(@as(u32, 1), hc.healthThreshold(true));
    try testing.expectEqual(@as(u32, 1), hc.healthThreshold(false));
}

// ============================================================================
// BackendSet Tests
// ============================================================================

test "BackendSet basic operations" {
    var backend_set = BackendSet.init(testing.allocator);
    defer backend_set.deinit();

    const b1 = try Backend.new("127.0.0.1", 8080);
    const b2 = try Backend.new("127.0.0.1", 8081);

    try backend_set.addBackend(b1);
    try backend_set.addBackend(b2);

    const all = backend_set.getAll();
    try testing.expectEqual(@as(usize, 2), all.len);
}

test "BackendSet with static discovery" {
    var backend_set = BackendSet.init(testing.allocator);
    defer backend_set.deinit();

    var static = StaticDiscovery.init(testing.allocator);
    const b1 = try Backend.new("127.0.0.1", 8080);
    try static.add(b1);

    backend_set.setDiscovery(.{ .static = static });

    try backend_set.refresh();

    const all = backend_set.getAll();
    try testing.expectEqual(@as(usize, 1), all.len);
}

// ============================================================================
// DnsDiscovery Tests
// ============================================================================

test "DnsDiscovery creation" {
    var dns = try DnsDiscovery.init(testing.allocator, "localhost", 8080);
    defer dns.deinit();

    try testing.expectEqualStrings("localhost", dns.hostname);
    try testing.expectEqual(@as(u16, 8080), dns.port);
}

test "DnsDiscovery discover localhost" {
    var dns = try DnsDiscovery.init(testing.allocator, "localhost", 8080);
    defer dns.deinit();

    var result = try dns.discover(testing.allocator);
    defer result.deinit();

    // localhost should resolve to at least one address
    try testing.expect(result.backends.items.len >= 1);
}
