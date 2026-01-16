//! pingora-pool: Generic connection pooling
//!
//! The pool is optimized for high concurrency, high RPS use cases.
//! This implementation provides a synchronous connection pool that can
//! manage reusable connections.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-pool

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const lru = @import("lru.zig");

// ============================================================================
// ConnectionMeta - Metadata for a pooled connection
// ============================================================================

/// Metadata associated with a pooled connection
pub const ConnectionMeta = struct {
    /// Unique identifier for this connection
    id: u64,
    /// When this connection was created (nanoseconds since epoch)
    created_at: i128,
    /// When this connection was last used (nanoseconds since epoch)
    last_used_at: i128,
    /// Number of times this connection has been reused
    reuse_count: u32,

    const Self = @This();

    pub fn init(id: u64) Self {
        const now = std.time.nanoTimestamp();
        return .{
            .id = id,
            .created_at = now,
            .last_used_at = now,
            .reuse_count = 0,
        };
    }

    /// Mark this connection as used
    pub fn markUsed(self: *Self) void {
        self.last_used_at = std.time.nanoTimestamp();
        self.reuse_count += 1;
    }

    /// Get the age of this connection in nanoseconds
    pub fn age(self: *const Self) i128 {
        return std.time.nanoTimestamp() - self.created_at;
    }

    /// Get the idle time of this connection in nanoseconds
    pub fn idleTime(self: *const Self) i128 {
        return std.time.nanoTimestamp() - self.last_used_at;
    }
};

// ============================================================================
// PoolNode - A node in the connection pool
// ============================================================================

/// A wrapper around a pooled connection
pub fn PoolNode(comptime T: type) type {
    return struct {
        connection: T,
        meta: ConnectionMeta,
        closed: bool,

        const Self = @This();

        pub fn init(connection: T, id: u64) Self {
            return .{
                .connection = connection,
                .meta = ConnectionMeta.init(id),
                .closed = false,
            };
        }

        /// Mark this connection as closed
        pub fn close(self: *Self) void {
            self.closed = true;
        }

        /// Check if this connection is closed
        pub fn isClosed(self: *const Self) bool {
            return self.closed;
        }

        /// Get a reference to the connection
        pub fn get(self: *Self) *T {
            self.meta.markUsed();
            return &self.connection;
        }
    };
}

// ============================================================================
// ConnectionPool - Main pool implementation
// ============================================================================

/// A generic connection pool that manages reusable connections.
/// Connections are grouped by a key and managed with LRU eviction.
pub fn ConnectionPool(comptime K: type, comptime T: type) type {
    return struct {
        /// Pool storage: key -> list of connections
        pools: std.AutoHashMapUnmanaged(u64, ConnectionList),
        /// Total capacity across all groups
        capacity: usize,
        /// Current total count
        total_count: usize,
        /// Maximum idle time before a connection is considered stale (nanoseconds)
        max_idle_ns: i128,
        /// Maximum connection age (nanoseconds)
        max_age_ns: ?i128,
        /// Next connection ID
        next_id: u64,
        /// Mutex for thread safety
        mutex: std.Thread.Mutex,
        /// Allocator
        allocator: Allocator,

        const Self = @This();
        const Node = PoolNode(T);
        const ConnectionList = std.ArrayListUnmanaged(Node);

        /// Create a new connection pool with the given capacity.
        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .pools = .{},
                .capacity = capacity,
                .total_count = 0,
                .max_idle_ns = 60 * std.time.ns_per_s, // 60 seconds default
                .max_age_ns = null,
                .next_id = 0,
                .mutex = .{},
                .allocator = allocator,
            };
        }

        /// Free all resources
        pub fn deinit(self: *Self) void {
            var it = self.pools.valueIterator();
            while (it.next()) |list| {
                list.deinit(self.allocator);
            }
            self.pools.deinit(self.allocator);
        }

        /// Set the maximum idle time for connections (in nanoseconds)
        pub fn setMaxIdleTime(self: *Self, max_idle_ns: i128) void {
            self.max_idle_ns = max_idle_ns;
        }

        /// Set the maximum age for connections (in nanoseconds)
        pub fn setMaxAge(self: *Self, max_age_ns: ?i128) void {
            self.max_age_ns = max_age_ns;
        }

        /// Hash a key
        fn hashKey(key: K) u64 {
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, key);
            return hasher.final();
        }

        /// Put a connection back into the pool.
        /// Returns true if the connection was accepted, false if rejected (pool full or connection stale).
        pub fn put(self: *Self, key: K, connection: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check capacity
            if (self.total_count >= self.capacity) {
                // Try to evict a stale connection first
                if (!self.evictOneStale()) {
                    return false;
                }
            }

            const hashed_key = hashKey(key);
            const id = self.next_id;
            self.next_id += 1;

            const node = Node.init(connection, id);

            if (self.pools.getPtr(hashed_key)) |list| {
                list.append(self.allocator, node) catch return false;
            } else {
                var new_list: ConnectionList = .{};
                new_list.append(self.allocator, node) catch return false;
                self.pools.put(self.allocator, hashed_key, new_list) catch {
                    new_list.deinit(self.allocator);
                    return false;
                };
            }

            self.total_count += 1;
            return true;
        }

        /// Get a connection from the pool for the given key.
        /// Returns the connection and its metadata, or null if none available.
        pub fn get(self: *Self, key: K) ?struct { T, ConnectionMeta } {
            self.mutex.lock();
            defer self.mutex.unlock();

            const hashed_key = hashKey(key);

            if (self.pools.getPtr(hashed_key)) |list| {
                // Find a valid connection (not stale, not too old)
                var i: usize = list.items.len;
                while (i > 0) {
                    i -= 1;
                    var node = &list.items[i];

                    if (node.isClosed()) {
                        _ = list.orderedRemove(i);
                        self.total_count -|= 1;
                        continue;
                    }

                    // Check idle time
                    if (node.meta.idleTime() > self.max_idle_ns) {
                        _ = list.orderedRemove(i);
                        self.total_count -|= 1;
                        continue;
                    }

                    // Check max age
                    if (self.max_age_ns) |max_age| {
                        if (node.meta.age() > max_age) {
                            _ = list.orderedRemove(i);
                            self.total_count -|= 1;
                            continue;
                        }
                    }

                    // Found a valid connection
                    const result = list.orderedRemove(i);
                    self.total_count -|= 1;
                    return .{ result.connection, result.meta };
                }
            }

            return null;
        }

        /// Remove all connections for a given key
        pub fn removeAll(self: *Self, key: K) usize {
            self.mutex.lock();
            defer self.mutex.unlock();

            const hashed_key = hashKey(key);

            if (self.pools.fetchRemove(hashed_key)) |entry| {
                const removed_count = entry.value.items.len;
                self.total_count -|= removed_count;
                var list = entry.value;
                list.deinit(self.allocator);
                return removed_count;
            }

            return 0;
        }

        /// Evict one stale connection from any group
        fn evictOneStale(self: *Self) bool {
            var it = self.pools.iterator();
            while (it.next()) |entry| {
                var list = entry.value_ptr;
                var i: usize = 0;
                while (i < list.items.len) {
                    const node = &list.items[i];
                    if (node.meta.idleTime() > self.max_idle_ns or node.isClosed()) {
                        _ = list.orderedRemove(i);
                        self.total_count -|= 1;
                        return true;
                    }
                    i += 1;
                }
            }
            return false;
        }

        /// Get the total number of pooled connections
        pub fn count(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.total_count;
        }

        /// Get the number of connections for a specific key
        pub fn countFor(self: *Self, key: K) usize {
            self.mutex.lock();
            defer self.mutex.unlock();

            const hashed_key = hashKey(key);
            if (self.pools.get(hashed_key)) |list| {
                return list.items.len;
            }
            return 0;
        }

        /// Drain all connections from the pool
        pub fn drain(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var it = self.pools.valueIterator();
            while (it.next()) |list| {
                list.deinit(self.allocator);
            }
            self.pools.clearRetainingCapacity();
            self.total_count = 0;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "ConnectionMeta initialization" {
    const meta = ConnectionMeta.init(1);
    try testing.expectEqual(meta.id, 1);
    try testing.expectEqual(meta.reuse_count, 0);
    try testing.expect(meta.age() >= 0);
}

test "ConnectionMeta markUsed" {
    var meta = ConnectionMeta.init(1);
    const initial_reuse = meta.reuse_count;

    meta.markUsed();
    try testing.expectEqual(meta.reuse_count, initial_reuse + 1);

    meta.markUsed();
    try testing.expectEqual(meta.reuse_count, initial_reuse + 2);
}

test "PoolNode basic operations" {
    const TestNode = PoolNode(i32);
    var node = TestNode.init(42, 1);

    try testing.expect(!node.isClosed());
    try testing.expectEqual(node.get().*, 42);

    node.close();
    try testing.expect(node.isClosed());
}

test "ConnectionPool put and get" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    // Put a connection
    try testing.expect(pool.put(1, 100));
    try testing.expectEqual(pool.count(), 1);

    // Get the connection back
    const result = pool.get(1);
    try testing.expect(result != null);
    try testing.expectEqual(result.?[0], 100);
    try testing.expectEqual(pool.count(), 0);

    // No more connections for this key
    try testing.expect(pool.get(1) == null);
}

test "ConnectionPool multiple connections per key" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(1, 200));
    try testing.expect(pool.put(1, 300));

    try testing.expectEqual(pool.count(), 3);
    try testing.expectEqual(pool.countFor(1), 3);

    // Get connections (LIFO order due to orderedRemove from end)
    const r1 = pool.get(1);
    try testing.expectEqual(r1.?[0], 300);

    const r2 = pool.get(1);
    try testing.expectEqual(r2.?[0], 200);

    const r3 = pool.get(1);
    try testing.expectEqual(r3.?[0], 100);

    try testing.expect(pool.get(1) == null);
}

test "ConnectionPool multiple keys" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(2, 200));
    try testing.expect(pool.put(3, 300));

    try testing.expectEqual(pool.count(), 3);

    const r1 = pool.get(1);
    try testing.expectEqual(r1.?[0], 100);

    const r2 = pool.get(2);
    try testing.expectEqual(r2.?[0], 200);

    const r3 = pool.get(3);
    try testing.expectEqual(r3.?[0], 300);
}

test "ConnectionPool capacity limit" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 2);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(2, 200));

    // Pool is full, should reject new connections
    try testing.expect(!pool.put(3, 300));

    try testing.expectEqual(pool.count(), 2);
}

test "ConnectionPool removeAll" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(1, 200));
    try testing.expect(pool.put(2, 300));

    const removed = pool.removeAll(1);
    try testing.expectEqual(removed, 2);
    try testing.expectEqual(pool.count(), 1);

    // Key 1 should have no connections
    try testing.expect(pool.get(1) == null);

    // Key 2 should still have its connection
    try testing.expectEqual(pool.get(2).?[0], 300);
}

test "ConnectionPool drain" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(2, 200));
    try testing.expect(pool.put(3, 300));

    pool.drain();

    try testing.expectEqual(pool.count(), 0);
    try testing.expect(pool.get(1) == null);
    try testing.expect(pool.get(2) == null);
    try testing.expect(pool.get(3) == null);
}

test "ConnectionPool connection metadata" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 10);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));

    const result = pool.get(1);
    try testing.expect(result != null);

    const meta = result.?[1];
    try testing.expect(meta.id >= 0);
    try testing.expect(meta.created_at > 0);
    try testing.expectEqual(meta.reuse_count, 0);
}

test "ConnectionPool with string keys" {
    var pool = ConnectionPool(u64, i32).init(testing.allocator, 10);
    defer pool.deinit();

    const key1 = std.hash.Wyhash.hash(0, "server1:8080");
    const key2 = std.hash.Wyhash.hash(0, "server2:8080");

    try testing.expect(pool.put(key1, 100));
    try testing.expect(pool.put(key2, 200));

    try testing.expectEqual(pool.get(key1).?[0], 100);
    try testing.expectEqual(pool.get(key2).?[0], 200);
}
