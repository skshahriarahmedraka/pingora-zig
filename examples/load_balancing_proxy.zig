//! Load Balancing Proxy Example
//!
//! This example demonstrates a load balancing proxy that distributes
//! requests across multiple backend servers using different algorithms.
//!
//! Features:
//! - Round-robin load balancing
//! - Weighted round-robin
//! - Health checking
//! - Connection tracking

const std = @import("std");
const pingora = @import("pingora");

const http_parser = pingora.http_parser;
const ketama = pingora.ketama;

/// Backend server configuration
pub const Backend = struct {
    address: []const u8,
    port: u16,
    weight: u32 = 1,
    healthy: bool = true,
    active_connections: u32 = 0,
    total_requests: u64 = 0,
    failed_requests: u64 = 0,
};

/// Load balancing algorithms
pub const Algorithm = enum {
    round_robin,
    weighted_round_robin,
    least_connections,
    consistent_hash,
};

/// Load Balancer implementation
pub const LoadBalancer = struct {
    allocator: std.mem.Allocator,
    backends: std.ArrayListUnmanaged(Backend),
    algorithm: Algorithm,
    current_index: usize,
    weighted_index: usize,
    weighted_count: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, algorithm: Algorithm) Self {
        return .{
            .allocator = allocator,
            .backends = .{},
            .algorithm = algorithm,
            .current_index = 0,
            .weighted_index = 0,
            .weighted_count = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backends.deinit(self.allocator);
    }

    /// Add a backend server
    pub fn addBackend(self: *Self, address: []const u8, port: u16, weight: u32) !void {
        try self.backends.append(self.allocator, .{
            .address = address,
            .port = port,
            .weight = weight,
            .healthy = true,
            .active_connections = 0,
            .total_requests = 0,
            .failed_requests = 0,
        });
    }

    /// Select a backend based on the configured algorithm
    pub fn select(self: *Self, key: ?[]const u8) ?*Backend {
        const healthy_backends = self.getHealthyBackends();
        if (healthy_backends.len == 0) return null;

        return switch (self.algorithm) {
            .round_robin => self.selectRoundRobin(healthy_backends),
            .weighted_round_robin => self.selectWeightedRoundRobin(healthy_backends),
            .least_connections => self.selectLeastConnections(healthy_backends),
            .consistent_hash => self.selectConsistentHash(healthy_backends, key),
        };
    }

    fn getHealthyBackends(self: *Self) []Backend {
        var count: usize = 0;
        for (self.backends.items) |backend| {
            if (backend.healthy) count += 1;
        }
        return self.backends.items[0..count];
    }

    fn selectRoundRobin(self: *Self, backends: []Backend) ?*Backend {
        if (backends.len == 0) return null;

        var idx = self.current_index;
        var attempts: usize = 0;

        while (attempts < self.backends.items.len) {
            if (self.backends.items[idx].healthy) {
                self.current_index = (idx + 1) % self.backends.items.len;
                return &self.backends.items[idx];
            }
            idx = (idx + 1) % self.backends.items.len;
            attempts += 1;
        }

        return null;
    }

    fn selectWeightedRoundRobin(self: *Self, backends: []Backend) ?*Backend {
        _ = backends;
        if (self.backends.items.len == 0) return null;

        var total_weight: u32 = 0;
        for (self.backends.items) |b| {
            if (b.healthy) total_weight += b.weight;
        }
        if (total_weight == 0) return null;

        // Find backend for current weighted position
        var accumulated: u32 = 0;
        for (self.backends.items, 0..) |*backend, i| {
            if (!backend.healthy) continue;
            accumulated += backend.weight;
            if (self.weighted_count < accumulated) {
                self.weighted_count += 1;
                if (self.weighted_count >= total_weight) {
                    self.weighted_count = 0;
                }
                return &self.backends.items[i];
            }
        }

        return &self.backends.items[0];
    }

    fn selectLeastConnections(self: *Self, backends: []Backend) ?*Backend {
        _ = backends;
        var min_connections: u32 = std.math.maxInt(u32);
        var selected: ?*Backend = null;

        for (self.backends.items, 0..) |*backend, i| {
            if (!backend.healthy) continue;
            if (backend.active_connections < min_connections) {
                min_connections = backend.active_connections;
                selected = &self.backends.items[i];
            }
        }

        return selected;
    }

    fn selectConsistentHash(self: *Self, backends: []Backend, key: ?[]const u8) ?*Backend {
        _ = backends;
        const hash_key = key orelse "default";

        // Simple hash-based selection
        var hash: u32 = 0;
        for (hash_key) |c| {
            hash = hash *% 31 +% c;
        }

        var healthy_count: usize = 0;
        for (self.backends.items) |b| {
            if (b.healthy) healthy_count += 1;
        }
        if (healthy_count == 0) return null;

        const idx = hash % @as(u32, @intCast(healthy_count));
        var count: u32 = 0;
        for (self.backends.items, 0..) |*backend, i| {
            if (backend.healthy) {
                if (count == idx) return &self.backends.items[i];
                count += 1;
            }
        }

        return null;
    }

    /// Mark a backend as unhealthy
    pub fn markUnhealthy(self: *Self, backend: *Backend) void {
        _ = self;
        backend.healthy = false;
        backend.failed_requests += 1;
    }

    /// Mark a backend as healthy
    pub fn markHealthy(self: *Self, backend: *Backend) void {
        _ = self;
        backend.healthy = true;
    }

    /// Record request start
    pub fn onRequestStart(self: *Self, backend: *Backend) void {
        _ = self;
        backend.active_connections += 1;
        backend.total_requests += 1;
    }

    /// Record request end
    pub fn onRequestEnd(self: *Self, backend: *Backend, success: bool) void {
        _ = self;
        if (backend.active_connections > 0) {
            backend.active_connections -= 1;
        }
        if (!success) {
            backend.failed_requests += 1;
        }
    }

    /// Get statistics
    pub fn getStats(self: *Self) Stats {
        var total_requests: u64 = 0;
        var total_failed: u64 = 0;
        var healthy_count: u32 = 0;

        for (self.backends.items) |backend| {
            total_requests += backend.total_requests;
            total_failed += backend.failed_requests;
            if (backend.healthy) healthy_count += 1;
        }

        return .{
            .total_backends = @intCast(self.backends.items.len),
            .healthy_backends = healthy_count,
            .total_requests = total_requests,
            .failed_requests = total_failed,
        };
    }

    pub const Stats = struct {
        total_backends: u32,
        healthy_backends: u32,
        total_requests: u64,
        failed_requests: u64,
    };
};

/// Load Balancing Proxy
pub const LoadBalancingProxy = struct {
    allocator: std.mem.Allocator,
    lb: LoadBalancer,
    listen_port: u16,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, listen_port: u16, algorithm: Algorithm) Self {
        return .{
            .allocator = allocator,
            .lb = LoadBalancer.init(allocator, algorithm),
            .listen_port = listen_port,
        };
    }

    pub fn deinit(self: *Self) void {
        self.lb.deinit();
    }

    pub fn addBackend(self: *Self, address: []const u8, port: u16, weight: u32) !void {
        try self.lb.addBackend(address, port, weight);
    }

    /// Select backend and proxy request
    pub fn proxyRequest(self: *Self, request: []const u8) ![]u8 {
        // Parse request to get hash key (e.g., from URL or header)
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        const parsed = try http_parser.parseRequestFull(request, &headers_buf);
        
        // Use path as hash key for consistent hashing
        const hash_key = if (parsed) |p| p.path else null;

        // Select backend
        const backend = self.lb.select(hash_key) orelse {
            return error.NoHealthyBackend;
        };

        self.lb.onRequestStart(backend);
        errdefer self.lb.onRequestEnd(backend, false);

        // Forward request to backend
        const response = self.sendToBackend(backend, request) catch |err| {
            self.lb.markUnhealthy(backend);
            self.lb.onRequestEnd(backend, false);
            return err;
        };

        self.lb.onRequestEnd(backend, true);
        return response;
    }

    fn sendToBackend(self: *Self, backend: *Backend, request: []const u8) ![]u8 {
        const address = std.net.Address.parseIp4(backend.address, backend.port) catch {
            return error.InvalidBackendAddress;
        };

        const stream = std.net.tcpConnectToAddress(address) catch {
            return error.BackendConnectionFailed;
        };
        defer stream.close();

        _ = stream.write(request) catch {
            return error.BackendWriteFailed;
        };

        var response: std.ArrayListUnmanaged(u8) = .{};
        errdefer response.deinit(self.allocator);

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stream.read(&buf) catch break;
            if (n == 0) break;
            try response.appendSlice(self.allocator, buf[0..n]);

            // Simple check for complete response
            if (std.mem.indexOf(u8, response.items, "\r\n\r\n") != null) {
                if (response.items.len > 1000 or n < buf.len) break;
            }
        }

        return response.toOwnedSlice(self.allocator);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create load balancing proxy with round-robin
    var proxy = LoadBalancingProxy.init(allocator, 8080, .round_robin);
    defer proxy.deinit();

    // Add backend servers
    try proxy.addBackend("127.0.0.1", 8001, 1);
    try proxy.addBackend("127.0.0.1", 8002, 2); // Higher weight
    try proxy.addBackend("127.0.0.1", 8003, 1);

    std.debug.print(
        \\
        \\=== Load Balancing Proxy ===
        \\Listening on: http://localhost:{d}
        \\Algorithm: round_robin
        \\Backends:
        \\  - 127.0.0.1:8001 (weight: 1)
        \\  - 127.0.0.1:8002 (weight: 2)
        \\  - 127.0.0.1:8003 (weight: 1)
        \\
        \\Press Ctrl+C to stop.
        \\
    , .{proxy.listen_port});

    // Create TCP listener
    const address = try std.net.Address.parseIp4("127.0.0.1", proxy.listen_port);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    // Accept connections
    while (true) {
        var conn = server.accept() catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
            continue;
        };

        handleConnection(allocator, &proxy, &conn) catch |err| {
            std.debug.print("Connection error: {}\n", .{err});
        };
        conn.stream.close();
    }
}

fn handleConnection(
    allocator: std.mem.Allocator,
    proxy: *LoadBalancingProxy,
    conn: *std.net.Server.Connection,
) !void {
    var buf: [8192]u8 = undefined;
    const n = try conn.stream.read(&buf);
    if (n == 0) return;

    const request = buf[0..n];

    const response = proxy.proxyRequest(request) catch |err| {
        std.debug.print("Proxy error: {}\n", .{err});
        const error_response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\n\r\nService Unavailable";
        _ = try conn.stream.write(error_response);
        return;
    };
    defer allocator.free(response);

    _ = try conn.stream.write(response);

    // Print stats periodically
    const stats = proxy.lb.getStats();
    std.debug.print("Stats: {d}/{d} healthy, {d} total requests, {d} failed\n", .{
        stats.healthy_backends,
        stats.total_backends,
        stats.total_requests,
        stats.failed_requests,
    });
}

test "LoadBalancer round robin" {
    const allocator = std.testing.allocator;
    var lb = LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    try lb.addBackend("127.0.0.1", 8001, 1);
    try lb.addBackend("127.0.0.1", 8002, 1);

    const b1 = lb.select(null);
    try std.testing.expect(b1 != null);

    const b2 = lb.select(null);
    try std.testing.expect(b2 != null);
}

test "LoadBalancer least connections" {
    const allocator = std.testing.allocator;
    var lb = LoadBalancer.init(allocator, .least_connections);
    defer lb.deinit();

    try lb.addBackend("127.0.0.1", 8001, 1);
    try lb.addBackend("127.0.0.1", 8002, 1);

    const backend = lb.select(null);
    try std.testing.expect(backend != null);
}
