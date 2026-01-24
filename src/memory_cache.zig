//! pingora-memory-cache: In-memory cache with TTL support
//!
//! A high-performance in-memory cache built on top of TinyUFO.
//! Supports TTL (time-to-live) for cache entries.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-memory-cache

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const tinyufo = @import("tinyufo.zig");

// ============================================================================
// CacheStatus - Result status for cache operations
// ============================================================================

/// The status of a cache lookup
pub const CacheStatus = union(enum) {
    /// The key was found and is valid
    hit,
    /// The key was not found
    miss,
    /// The key was found but is expired
    expired,
    /// The key was found but is stale (contains stale duration in nanoseconds)
    stale: i128,

    pub fn isHit(self: CacheStatus) bool {
        return self == .hit;
    }

    pub fn isMiss(self: CacheStatus) bool {
        return self == .miss;
    }

    pub fn isExpired(self: CacheStatus) bool {
        return self == .expired;
    }

    pub fn isStale(self: CacheStatus) bool {
        return switch (self) {
            .stale => true,
            else => false,
        };
    }
};

// ============================================================================
// Node - Cache entry with TTL support
// ============================================================================

/// A cache node that wraps a value with optional expiration
pub fn Node(comptime T: type) type {
    return struct {
        value: T,
        /// Expiration time in nanoseconds since epoch, null means no expiration
        expire_at: ?i128,

        const Self = @This();

        pub fn init(value: T, ttl_ns: ?u64) Self {
            const expire_at = if (ttl_ns) |ttl| blk: {
                const now = std.time.nanoTimestamp();
                break :blk now + @as(i128, ttl);
            } else null;

            return .{
                .value = value,
                .expire_at = expire_at,
            };
        }

        /// Check if this node has expired
        pub fn isExpired(self: *const Self) bool {
            if (self.expire_at) |expire| {
                return std.time.nanoTimestamp() >= expire;
            }
            return false;
        }

        /// Get how long this node has been stale (if stale)
        /// Returns null if not stale, otherwise returns stale duration in nanoseconds
        pub fn staleDuration(self: *const Self) ?i128 {
            if (self.expire_at) |expire| {
                const now = std.time.nanoTimestamp();
                if (now >= expire) {
                    return now - expire;
                }
            }
            return null;
        }
    };
}

// ============================================================================
// MemoryCache - Main cache implementation
// ============================================================================

/// A high-performance in-memory cache with TTL support.
/// Uses TinyUFO as the underlying eviction algorithm.
pub fn MemoryCache(comptime K: type, comptime V: type) type {
    return struct {
        store: tinyufo.TinyUfo(u64, CacheNode),
        allocator: Allocator,

        const Self = @This();
        const CacheNode = Node(V);

        /// Create a new MemoryCache with the given capacity (number of items).
        pub fn init(allocator: Allocator, capacity: usize) !Self {
            return .{
                .store = try tinyufo.TinyUfo(u64, CacheNode).init(allocator, capacity, capacity),
                .allocator = allocator,
            };
        }

        /// Free all resources
        pub fn deinit(self: *Self) void {
            self.store.deinit();
        }

        /// Hash a key to u64 - inlined for performance
        inline fn hashKey(key: K) u64 {
            // Use direct hash for primitive types, autoHash for complex types
            if (@sizeOf(K) <= 8 and @typeInfo(K) != .pointer) {
                return std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
            } else {
                var hasher = std.hash.Wyhash.init(0);
                std.hash.autoHash(&hasher, key);
                return hasher.final();
            }
        }

        /// Fetch a key and return its value along with a CacheStatus.
        /// Returns (value, status) where value is null if not found or expired.
        pub fn get(self: *Self, key: K) struct { ?V, CacheStatus } {
            const hashed_key = hashKey(key);

            if (self.store.get(&hashed_key)) |node| {
                if (!node.isExpired()) {
                    return .{ node.value, .hit };
                } else {
                    return .{ null, .expired };
                }
            }
            return .{ null, .miss };
        }

        /// Similar to get(), but also returns the value even if expired.
        /// When expired, the stale duration is included in the status.
        pub fn getStale(self: *Self, key: K) struct { ?V, CacheStatus } {
            const hashed_key = hashKey(key);

            if (self.store.get(&hashed_key)) |node| {
                if (node.staleDuration()) |stale_ns| {
                    return .{ node.value, CacheStatus{ .stale = stale_ns } };
                } else {
                    return .{ node.value, .hit };
                }
            }
            return .{ null, .miss };
        }

        /// Insert a key and value pair with an optional TTL into the cache.
        /// TTL is in nanoseconds. An item with zero TTL will not be inserted.
        pub fn put(self: *Self, key: K, value: V, ttl_ns: ?u64) !void {
            if (ttl_ns) |ttl| {
                if (ttl == 0) {
                    return;
                }
            }

            const hashed_key = hashKey(key);
            const node = CacheNode.init(value, ttl_ns);
            // Weight is always 1 for now
            var evicted = try self.store.put(hashed_key, node, 1);
            evicted.deinit(self.allocator);
        }

        /// Force insert a key and value, bypassing admission policy.
        pub fn forcePut(self: *Self, key: K, value: V, ttl_ns: ?u64) !void {
            if (ttl_ns) |ttl| {
                if (ttl == 0) {
                    return;
                }
            }

            const hashed_key = hashKey(key);
            const node = CacheNode.init(value, ttl_ns);
            var evicted = try self.store.forcePut(hashed_key, node, 1);
            evicted.deinit(self.allocator);
        }

        /// Remove a key from the cache if it exists.
        pub fn remove(self: *Self, key: K) ?V {
            const hashed_key = hashKey(key);
            if (self.store.remove(&hashed_key)) |node| {
                return node.value;
            }
            return null;
        }

        /// Check if a key exists in the cache (even if expired).
        pub fn contains(self: *Self, key: K) bool {
            const hashed_key = hashKey(key);
            return self.store.get(&hashed_key) != null;
        }

        /// Put with TTL in milliseconds (convenience function)
        pub fn putMs(self: *Self, key: K, value: V, ttl_ms: ?u64) !void {
            const ttl_ns = if (ttl_ms) |ms| ms * std.time.ns_per_ms else null;
            try self.put(key, value, ttl_ns);
        }

        /// Put with TTL in seconds (convenience function)
        pub fn putSecs(self: *Self, key: K, value: V, ttl_secs: ?u64) !void {
            const ttl_ns = if (ttl_secs) |secs| secs * std.time.ns_per_s else null;
            try self.put(key, value, ttl_ns);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "CacheStatus variants" {
    const hit: CacheStatus = .hit;
    const miss: CacheStatus = .miss;
    const expired: CacheStatus = .expired;
    const stale: CacheStatus = .{ .stale = 1000 };

    try testing.expect(hit.isHit());
    try testing.expect(!hit.isMiss());

    try testing.expect(miss.isMiss());
    try testing.expect(!miss.isHit());

    try testing.expect(expired.isExpired());
    try testing.expect(!expired.isHit());

    try testing.expect(stale.isStale());
    try testing.expect(!stale.isHit());
}

test "Node expiration" {
    const TestNode = Node(i32);

    // Node without TTL never expires
    const no_ttl = TestNode.init(42, null);
    try testing.expect(!no_ttl.isExpired());
    try testing.expect(no_ttl.staleDuration() == null);

    // Node with very long TTL should not be expired
    const long_ttl = TestNode.init(42, std.time.ns_per_hour);
    try testing.expect(!long_ttl.isExpired());
}

test "MemoryCache basic operations" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    // Miss on empty cache
    const result1 = cache.get(1);
    try testing.expect(result1[0] == null);
    try testing.expect(result1[1].isMiss());

    // Put and get
    try cache.put(1, 100, null);
    const result2 = cache.get(1);
    try testing.expectEqual(result2[0].?, 100);
    try testing.expect(result2[1].isHit());

    // Remove
    const removed = cache.remove(1);
    try testing.expectEqual(removed.?, 100);

    // Miss after remove
    const result3 = cache.get(1);
    try testing.expect(result3[0] == null);
    try testing.expect(result3[1].isMiss());
}

test "MemoryCache put and get multiple" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    try cache.put(1, 2, null);
    try cache.put(3, 4, null);
    try cache.put(5, 6, null);

    const r1 = cache.get(1);
    try testing.expectEqual(r1[0].?, 2);
    try testing.expect(r1[1].isHit());

    const r3 = cache.get(3);
    try testing.expectEqual(r3[0].?, 4);
    try testing.expect(r3[1].isHit());

    const r5 = cache.get(5);
    try testing.expectEqual(r5[0].?, 6);
    try testing.expect(r5[1].isHit());
}

test "MemoryCache remove operations" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    try cache.put(1, 2, null);
    try cache.put(3, 4, null);
    try cache.put(5, 6, null);

    // Verify initial state
    try testing.expectEqual(cache.get(1)[0].?, 2);

    // Remove specific keys
    _ = cache.remove(1);
    _ = cache.remove(3);

    // Verify removals
    try testing.expect(cache.get(1)[0] == null);
    try testing.expect(cache.get(1)[1].isMiss());

    try testing.expect(cache.get(3)[0] == null);
    try testing.expect(cache.get(3)[1].isMiss());

    // Key 5 should still exist
    try testing.expectEqual(cache.get(5)[0].?, 6);
    try testing.expect(cache.get(5)[1].isHit());
}

test "MemoryCache contains" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    try testing.expect(!cache.contains(1));

    try cache.put(1, 100, null);
    try testing.expect(cache.contains(1));

    _ = cache.remove(1);
    try testing.expect(!cache.contains(1));
}

test "MemoryCache zero TTL not inserted" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    // Zero TTL should not insert
    try cache.put(1, 100, 0);

    try testing.expect(cache.get(1)[0] == null);
    try testing.expect(cache.get(1)[1].isMiss());
}

test "MemoryCache forcePut" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    try cache.forcePut(1, 100, null);

    const result = cache.get(1);
    try testing.expectEqual(result[0].?, 100);
    try testing.expect(result[1].isHit());
}

test "MemoryCache putMs convenience" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    // Put with 1 hour TTL in milliseconds
    try cache.putMs(1, 100, 3600000);

    const result = cache.get(1);
    try testing.expectEqual(result[0].?, 100);
    try testing.expect(result[1].isHit());
}

test "MemoryCache putSecs convenience" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    // Put with 1 hour TTL in seconds
    try cache.putSecs(1, 100, 3600);

    const result = cache.get(1);
    try testing.expectEqual(result[0].?, 100);
    try testing.expect(result[1].isHit());
}

test "MemoryCache update existing key" {
    var cache = try MemoryCache(i32, i32).init(testing.allocator, 10);
    defer cache.deinit();

    try cache.put(1, 100, null);
    try testing.expectEqual(cache.get(1)[0].?, 100);

    // Update the value
    try cache.put(1, 200, null);
    try testing.expectEqual(cache.get(1)[0].?, 200);
}

test "MemoryCache with string keys" {
    var cache = try MemoryCache(u64, []const u8).init(testing.allocator, 10);
    defer cache.deinit();

    try cache.put(std.hash.Wyhash.hash(0, "key1"), "value1", null);
    try cache.put(std.hash.Wyhash.hash(0, "key2"), "value2", null);

    const r1 = cache.get(std.hash.Wyhash.hash(0, "key1"));
    try testing.expectEqualStrings("value1", r1[0].?);
}
