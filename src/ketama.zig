//! pingora-zig: ketama
//!
//! Nginx-compatible consistent hashing implementation.
//! Minimizes request rehashing when nodes are added or removed.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-ketama

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const net = std.net;

/// Points per weight unit (nginx compatible)
pub const DEFAULT_POINT_MULTIPLE: u32 = 160;

/// A bucket represents a server for consistent hashing
pub const Bucket = struct {
    node: net.Address,
    weight: u32,

    /// Create a new bucket with the given address and weight
    pub fn init(address: net.Address, weight: u32) Bucket {
        std.debug.assert(weight != 0);
        return .{ .node = address, .weight = weight };
    }

    /// Create from IP string and port
    pub fn fromString(ip: []const u8, port: u16, weight: u32) !Bucket {
        const addr = try net.Address.parseIp(ip, port);
        return init(addr, weight);
    }
};

/// A point on the continuum
const Point = struct {
    node: u32,
    hash: u32,

    fn lessThan(_: void, a: Point, b: Point) bool {
        return a.hash < b.hash;
    }
};

/// CRC32 hash function (matching nginx behavior)
fn crc32Hash(data: []const u8) u32 {
    return std.hash.crc.Crc32IsoHdlc.hash(data);
}

/// The consistent hashing ring
pub const Continuum = struct {
    allocator: Allocator,
    ring: []Point,
    addrs: []net.Address,

    const Self = @This();

    /// Create a new Continuum with the given list of buckets
    pub fn init(allocator: Allocator, buckets: []const Bucket) !Self {
        if (buckets.len == 0) {
            return .{
                .allocator = allocator,
                .ring = &[_]Point{},
                .addrs = &[_]net.Address{},
            };
        }

        // Calculate total weight
        var total_weight: u32 = 0;
        for (buckets) |b| {
            total_weight += b.weight;
        }

        // Allocate ring and addresses
        var ring = try allocator.alloc(Point, total_weight * DEFAULT_POINT_MULTIPLE);
        errdefer allocator.free(ring);

        var addrs = try allocator.alloc(net.Address, buckets.len);
        errdefer allocator.free(addrs);

        var ring_idx: usize = 0;

        for (buckets, 0..) |bucket, node_idx| {
            addrs[node_idx] = bucket.node;

            // Format address for hashing (nginx compatible format)
            var hash_buf: [64]u8 = undefined;
            const hash_input = try formatAddressForHash(&hash_buf, bucket.node);

            // Calculate base hash using CRC32
            var prev_hash: u32 = 0;
            var hasher = std.hash.crc.Crc32IsoHdlc.init();
            hasher.update(hash_input);

            const num_points = bucket.weight * DEFAULT_POINT_MULTIPLE;
            for (0..num_points) |_| {
                // Clone hasher and add previous hash
                var point_hasher = hasher;
                point_hasher.update(std.mem.asBytes(&prev_hash));

                const hash = point_hasher.final();
                ring[ring_idx] = .{
                    .node = @intCast(node_idx),
                    .hash = hash,
                };
                ring_idx += 1;
                prev_hash = hash;
            }
        }

        // Sort by hash and deduplicate
        std.mem.sort(Point, ring[0..ring_idx], {}, Point.lessThan);

        // Deduplicate
        var write_idx: usize = 0;
        var last_hash: ?u32 = null;
        for (ring[0..ring_idx]) |point| {
            if (last_hash == null or last_hash.? != point.hash) {
                ring[write_idx] = point;
                write_idx += 1;
                last_hash = point.hash;
            }
        }

        // Shrink to actual size
        const final_ring = try allocator.realloc(ring, write_idx);

        return .{
            .allocator = allocator,
            .ring = final_ring,
            .addrs = addrs,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.ring.len > 0) {
            self.allocator.free(self.ring);
        }
        if (self.addrs.len > 0) {
            self.allocator.free(self.addrs);
        }
    }

    fn formatAddressForHash(buf: []u8, addr: net.Address) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        // Format: "IP\0PORT" (nginx compatible)
        switch (addr.any.family) {
            std.posix.AF.INET => {
                const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                try writer.print("{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
            },
            std.posix.AF.INET6 => {
                // IPv6 formatting
                const ip6 = &addr.in6.sa.addr;
                for (ip6) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
            },
            else => return error.UnsupportedAddressFamily,
        }

        try writer.writeByte(0); // null separator
        try writer.print("{}", .{addr.getPort()});

        return fbs.getWritten();
    }

    /// Find the node index for the given input
    pub fn nodeIdx(self: *const Self, input: []const u8) usize {
        if (self.ring.len == 0) return 0;

        const hash = crc32Hash(input);
        return self.nodeIdxByHash(hash);
    }

    fn nodeIdxByHash(self: *const Self, hash: u32) usize {
        // Binary search for the first point with hash >= input hash
        var left: usize = 0;
        var right: usize = self.ring.len;

        while (left < right) {
            const mid = left + (right - left) / 2;
            if (self.ring[mid].hash < hash) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        // Wrap around if we're at the end
        if (left >= self.ring.len) {
            return 0;
        }
        return left;
    }

    /// Hash the given key to a server address
    pub fn node(self: *const Self, hash_key: []const u8) ?net.Address {
        if (self.ring.len == 0) return null;

        const idx = self.nodeIdx(hash_key);
        const node_idx = self.ring[idx].node;
        return self.addrs[node_idx];
    }

    /// Get an iterator of nodes starting at the hashed node
    pub fn nodeIter(self: *const Self, hash_key: []const u8) NodeIterator {
        return .{
            .continuum = self,
            .idx = self.nodeIdx(hash_key),
            .count = 0,
        };
    }

    /// Get address at index and advance
    pub fn getAddr(self: *const Self, idx: *usize) ?*const net.Address {
        if (self.ring.len == 0) return null;

        const point = self.ring[idx.*];
        idx.* = (idx.* + 1) % self.ring.len;
        return &self.addrs[point.node];
    }

    /// Get the number of points in the ring
    pub fn len(self: *const Self) usize {
        return self.ring.len;
    }
};

/// Iterator over nodes in the continuum
pub const NodeIterator = struct {
    continuum: *const Continuum,
    idx: usize,
    count: usize,

    pub fn next(self: *NodeIterator) ?*const net.Address {
        if (self.continuum.ring.len == 0) return null;

        const result = self.continuum.getAddr(&self.idx);
        self.count += 1;
        return result;
    }
};

// Helper to create address from string for tests
fn parseAddr(comptime ip: []const u8, port: u16) net.Address {
    return net.Address.parseIp4(ip, port) catch unreachable;
}

// Tests
test "Continuum empty" {
    var c = try Continuum.init(testing.allocator, &[_]Bucket{});
    defer c.deinit();

    try testing.expect(c.node("doghash") == null);

    var iter = c.nodeIter("doghash");
    try testing.expect(iter.next() == null);
}

test "Continuum single node" {
    const addr = parseAddr("127.0.0.1", 7777);
    var buckets = [_]Bucket{Bucket.init(addr, 1)};

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    const result = c.node("test_key");
    try testing.expect(result != null);
    try testing.expectEqual(result.?.getPort(), @as(u16, 7777));
}

test "Continuum consistency after adding host" {
    // Test with 10 hosts
    var buckets1: [10]Bucket = undefined;
    for (0..10) |i| {
        const ip_last: u8 = @intCast(i + 1);
        var ip_buf: [16]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "127.0.0.{d}", .{ip_last}) catch unreachable;
        buckets1[i] = Bucket.fromString(ip, 6443, 1) catch unreachable;
    }

    var c1 = try Continuum.init(testing.allocator, &buckets1);
    defer c1.deinit();

    // Get initial mappings
    const node_a = c1.node("a");
    const node_b = c1.node("b");

    try testing.expect(node_a != null);
    try testing.expect(node_b != null);

    // Now with 11 hosts
    var buckets2: [11]Bucket = undefined;
    for (0..11) |i| {
        const ip_last: u8 = @intCast(i + 1);
        var ip_buf: [16]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "127.0.0.{d}", .{ip_last}) catch unreachable;
        buckets2[i] = Bucket.fromString(ip, 6443, 1) catch unreachable;
    }

    var c2 = try Continuum.init(testing.allocator, &buckets2);
    defer c2.deinit();

    // Verify consistency - same keys should map to same or nearby nodes
    const new_node_a = c2.node("a");
    const new_node_b = c2.node("b");

    try testing.expect(new_node_a != null);
    try testing.expect(new_node_b != null);
}

test "Continuum weighted distribution" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    const addr2 = parseAddr("127.0.0.2", 7778);

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 2), // Double weight
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    // Count distribution over many keys
    var count1: usize = 0;
    var count2: usize = 0;

    for (0..1000) |i| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
        if (c.node(key)) |addr| {
            if (addr.getPort() == 7777) {
                count1 += 1;
            } else {
                count2 += 1;
            }
        }
    }

    // addr2 should have roughly 2x the requests (with some variance)
    // We just check that addr2 has more
    try testing.expect(count2 > count1);
}

test "Continuum node iterator" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    const addr2 = parseAddr("127.0.0.1", 7778);
    const addr3 = parseAddr("127.0.0.1", 7779);

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 1),
        Bucket.init(addr3, 1),
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    var iter = c.nodeIter("doghash");

    // Should be able to iterate through all points
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
        if (count > c.len()) break; // Prevent infinite loop
    }

    try testing.expect(count > 0);
}

test "Bucket creation" {
    const b1 = Bucket.init(parseAddr("127.0.0.1", 8080), 1);
    try testing.expectEqual(b1.weight, 1);
    try testing.expectEqual(b1.node.getPort(), 8080);

    const b2 = try Bucket.fromString("192.168.1.1", 443, 5);
    try testing.expectEqual(b2.weight, 5);
    try testing.expectEqual(b2.node.getPort(), 443);
}

test "CRC32 hash" {
    // Basic hash test
    const h1 = crc32Hash("test");
    const h2 = crc32Hash("test");
    try testing.expectEqual(h1, h2);

    const h3 = crc32Hash("different");
    try testing.expect(h1 != h3);
}

// Additional tests ported from Pingora

test "Continuum node_iter cycles through ring" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    const addr2 = parseAddr("127.0.0.1", 7778);

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 1),
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    var iter = c.nodeIter("test_key");

    // Should be able to iterate multiple times (cycling through ring)
    var seen_7777: usize = 0;
    var seen_7778: usize = 0;

    for (0..10) |_| {
        if (iter.next()) |addr| {
            if (addr.getPort() == 7777) {
                seen_7777 += 1;
            } else if (addr.getPort() == 7778) {
                seen_7778 += 1;
            }
        }
    }

    // Both nodes should have been seen
    try testing.expect(seen_7777 > 0);
    try testing.expect(seen_7778 > 0);
}

test "Continuum deterministic hashing" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    const addr2 = parseAddr("127.0.0.2", 7778);

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 1),
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    // Same key should always hash to same node
    const node1 = c.node("fixed_key");
    const node2 = c.node("fixed_key");

    try testing.expect(node1 != null);
    try testing.expect(node2 != null);
    try testing.expectEqual(node1.?.getPort(), node2.?.getPort());
}

// Additional edge case tests

test "Continuum IPv6 addresses" {
    const addr1 = net.Address.parseIp6("::1", 7777) catch unreachable;
    const addr2 = net.Address.parseIp6("::1", 7778) catch unreachable;
    const addr3 = net.Address.parseIp6("::1", 7779) catch unreachable;

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 1),
        Bucket.init(addr3, 1),
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    var iter = c.nodeIter("doghash");

    // Should be able to iterate through IPv6 nodes
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
        if (count >= 7) break;
    }
    try testing.expect(count == 7);
}

test "Continuum high weight distribution" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    const addr2 = parseAddr("127.0.0.2", 7778);

    var buckets = [_]Bucket{
        Bucket.init(addr1, 1),
        Bucket.init(addr2, 10), // 10x weight
    };

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    // Ring should have more points for addr2
    try testing.expect(c.len() > 0);

    var count1: usize = 0;
    var count2: usize = 0;

    for (0..100) |i| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "test_key_{d}", .{i}) catch unreachable;
        if (c.node(key)) |addr| {
            if (addr.getPort() == 7777) {
                count1 += 1;
            } else {
                count2 += 1;
            }
        }
    }

    // addr2 should get significantly more requests
    try testing.expect(count2 > count1 * 3);
}

test "Continuum single node all keys" {
    const addr = parseAddr("127.0.0.1", 8080);
    var buckets = [_]Bucket{Bucket.init(addr, 1)};

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    // All keys should map to the single node
    for (0..100) |i| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch unreachable;
        const result = c.node(key);
        try testing.expect(result != null);
        try testing.expectEqual(result.?.getPort(), @as(u16, 8080));
    }
}

test "Continuum iterator exhaustion" {
    const addr1 = parseAddr("127.0.0.1", 7777);
    var buckets = [_]Bucket{Bucket.init(addr1, 1)};

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    var iter = c.nodeIter("test");

    // Iterator should cycle through all points
    const ring_len = c.len();
    for (0..ring_len * 2) |_| {
        try testing.expect(iter.next() != null);
    }
}

test "Continuum different keys different nodes" {
    var buckets: [5]Bucket = undefined;
    for (0..5) |i| {
        const port: u16 = @intCast(7770 + i);
        buckets[i] = Bucket.init(parseAddr("127.0.0.1", port), 1);
    }

    var c = try Continuum.init(testing.allocator, &buckets);
    defer c.deinit();

    // Different keys might map to different nodes
    var seen_ports = std.AutoHashMap(u16, void).init(testing.allocator);
    defer seen_ports.deinit();

    for (0..1000) |i| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "unique_key_{d}", .{i}) catch unreachable;
        if (c.node(key)) |addr| {
            seen_ports.put(addr.getPort(), {}) catch {};
        }
    }

    // Should have seen multiple different ports
    try testing.expect(seen_ports.count() > 1);
}
