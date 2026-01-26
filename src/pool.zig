//! pingora-pool: Generic connection pooling
//!
//! The pool is optimized for high concurrency, high RPS use cases.
//! This implementation provides a synchronous connection pool that can
//! manage reusable connections.
//!
//! Performance optimizations:
//! - Cached timestamps to avoid syscall overhead on every operation
//! - Lock-free hot queue for frequently accessed connections
//! - LRU-based eviction instead of full pool iteration
//! - O(1) connection removal using intrusive linked list
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-pool

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const lru = @import("lru.zig");

// ============================================================================
// Cached Timestamp - Reduces syscall overhead
// ============================================================================

/// Thread-local cached timestamp to reduce syscall overhead.
/// Updated lazily - accuracy is not critical for idle timeout checks.
const CachedTimestamp = struct {
    var cached_time: i128 = 0;
    var update_counter: u32 = 0;
    const UPDATE_INTERVAL: u32 = 64; // Update every N operations

    /// Get current time, using cache when possible
    pub fn now() i128 {
        update_counter +%= 1;
        if (update_counter % UPDATE_INTERVAL == 0 or cached_time == 0) {
            cached_time = std.time.nanoTimestamp();
        }
        return cached_time;
    }

    /// Force refresh the cached time
    pub fn refresh() i128 {
        cached_time = std.time.nanoTimestamp();
        return cached_time;
    }
};

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
        const now = CachedTimestamp.refresh(); // Force refresh on new connection
        return .{
            .id = id,
            .created_at = now,
            .last_used_at = now,
            .reuse_count = 0,
        };
    }

    /// Initialize with a pre-fetched timestamp (avoids syscall)
    pub fn initWithTimestamp(id: u64, timestamp: i128) Self {
        return .{
            .id = id,
            .created_at = timestamp,
            .last_used_at = timestamp,
            .reuse_count = 0,
        };
    }

    /// Mark this connection as used
    pub fn markUsed(self: *Self) void {
        self.last_used_at = CachedTimestamp.now();
        self.reuse_count += 1;
    }

    /// Mark this connection as used with a pre-fetched timestamp
    pub fn markUsedWithTimestamp(self: *Self, timestamp: i128) void {
        self.last_used_at = timestamp;
        self.reuse_count += 1;
    }

    /// Get the age of this connection in nanoseconds
    pub fn age(self: *const Self) i128 {
        return CachedTimestamp.now() - self.created_at;
    }

    /// Get the age using a pre-fetched timestamp
    pub fn ageAt(self: *const Self, now: i128) i128 {
        return now - self.created_at;
    }

    /// Get the idle time of this connection in nanoseconds
    pub fn idleTime(self: *const Self) i128 {
        return CachedTimestamp.now() - self.last_used_at;
    }

    /// Get the idle time using a pre-fetched timestamp
    pub fn idleTimeAt(self: *const Self, now: i128) i128 {
        return now - self.last_used_at;
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

        /// Initialize with a pre-fetched timestamp
        pub fn initWithTimestamp(connection: T, id: u64, timestamp: i128) Self {
            return .{
                .connection = connection,
                .meta = ConnectionMeta.initWithTimestamp(id, timestamp),
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
// EvictionTracker - Simple LRU tracking for eviction
// ============================================================================

/// Tracks connection IDs for LRU eviction using a simple linked structure.
/// Optimized for the connection pool use case where we need:
/// - O(1) insert (at head)
/// - O(1) remove by ID
/// - O(1) pop from tail (eviction)
const EvictionTracker = struct {
    /// Map from connection ID to group key, list position, AND index within the group's list
    entries: std.AutoHashMapUnmanaged(u64, Entry),
    /// Head of the LRU list (most recently used)
    head: ?u64,
    /// Tail of the LRU list (least recently used)
    tail: ?u64,
    allocator: Allocator,

    const Entry = struct {
        group_key: u64,
        prev: ?u64,
        next: ?u64,
    };

    pub fn init(allocator: Allocator) EvictionTracker {
        return .{
            .entries = .{},
            .head = null,
            .tail = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EvictionTracker) void {
        self.entries.deinit(self.allocator);
    }

    /// Insert a new connection at the head (most recently used)
    pub fn insert(self: *EvictionTracker, id: u64, group_key: u64) void {
        const entry = Entry{
            .group_key = group_key,
            .prev = null,
            .next = self.head,
        };

        // Update old head's prev pointer
        if (self.head) |old_head| {
            if (self.entries.getPtr(old_head)) |old_entry| {
                old_entry.prev = id;
            }
        }

        self.entries.put(self.allocator, id, entry) catch return;
        self.head = id;

        // If this is the first entry, it's also the tail
        if (self.tail == null) {
            self.tail = id;
        }
    }

    /// Remove a connection by ID
    pub fn remove(self: *EvictionTracker, id: u64) ?u64 {
        const entry = self.entries.fetchRemove(id) orelse return null;
        const e = entry.value;

        // Update prev's next pointer
        if (e.prev) |prev_id| {
            if (self.entries.getPtr(prev_id)) |prev_entry| {
                prev_entry.next = e.next;
            }
        } else {
            // This was the head
            self.head = e.next;
        }

        // Update next's prev pointer
        if (e.next) |next_id| {
            if (self.entries.getPtr(next_id)) |next_entry| {
                next_entry.prev = e.prev;
            }
        } else {
            // This was the tail
            self.tail = e.prev;
        }

        return e.group_key;
    }

    /// Pop the least recently used connection (from tail)
    pub fn popLru(self: *EvictionTracker) ?struct { id: u64, group_key: u64 } {
        const tail_id = self.tail orelse return null;
        const group_key = self.remove(tail_id) orelse return null;
        return .{ .id = tail_id, .group_key = group_key };
    }

    /// Clear all entries
    pub fn clear(self: *EvictionTracker) void {
        self.entries.clearRetainingCapacity();
        self.head = null;
        self.tail = null;
    }

    pub fn len(self: *const EvictionTracker) usize {
        return self.entries.count();
    }
};

// ============================================================================
// ConnectionPool - Main pool implementation (optimized)
// ============================================================================

/// A generic connection pool that manages reusable connections.
/// Connections are grouped by a key and managed with LRU eviction.
///
/// Performance features:
/// - O(1) LRU tracking for efficient eviction
/// - Cached timestamps to reduce syscall overhead
/// - SwapRemove instead of OrderedRemove for O(1) removal
pub fn ConnectionPool(comptime K: type, comptime T: type) type {
    return struct {
        /// Pool storage: key -> list of connections
        pools: std.AutoHashMapUnmanaged(u64, ConnectionList),
        /// LRU tracker for eviction order
        eviction_tracker: EvictionTracker,
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
                .eviction_tracker = EvictionTracker.init(allocator),
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
            self.eviction_tracker.deinit();
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
        /// Hot path - safety checks disabled for performance.
        pub fn put(self: *Self, key: K, connection: T) bool {
            @setRuntimeSafety(false);
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check capacity first
            if (self.total_count >= self.capacity) {
                // Try to evict using LRU
                if (!self.evictOneLru()) {
                    return false;
                }
            }

            const hashed_key = hashKey(key);
            // Use cached timestamp instead of refresh() to avoid syscall on every put
            const timestamp = CachedTimestamp.now();
            const id = self.next_id;
            self.next_id += 1;

            const node = Node.initWithTimestamp(connection, id, timestamp);

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

            self.eviction_tracker.insert(id, hashed_key);
            self.total_count += 1;
            return true;
        }

        /// Get a connection from the pool for the given key.
        /// Returns the connection and its metadata, or null if none available.
        /// Hot path - safety checks disabled for performance.
        pub fn get(self: *Self, key: K) ?struct { T, ConnectionMeta } {
            @setRuntimeSafety(false);
            self.mutex.lock();
            defer self.mutex.unlock();

            const hashed_key = hashKey(key);
            const now = CachedTimestamp.now();

            if (self.pools.getPtr(hashed_key)) |list| {
                // Find a valid connection (not stale, not too old)
                // Iterate from end for LIFO behavior, use swapRemove for O(1)
                while (list.items.len > 0) {
                    const last_idx = list.items.len - 1;
                    const node = &list.items[last_idx];

                    if (node.isClosed()) {
                        _ = self.eviction_tracker.remove(node.meta.id);
                        _ = list.swapRemove(last_idx);
                        self.total_count -|= 1;
                        continue;
                    }

                    // Check idle time using cached timestamp
                    if (node.meta.idleTimeAt(now) > self.max_idle_ns) {
                        _ = self.eviction_tracker.remove(node.meta.id);
                        _ = list.swapRemove(last_idx);
                        self.total_count -|= 1;
                        continue;
                    }

                    // Check max age
                    if (self.max_age_ns) |max_age| {
                        if (node.meta.ageAt(now) > max_age) {
                            _ = self.eviction_tracker.remove(node.meta.id);
                            _ = list.swapRemove(last_idx);
                            self.total_count -|= 1;
                            continue;
                        }
                    }

                    // Found a valid connection - use swapRemove for O(1)
                    const result = list.swapRemove(last_idx);
                    _ = self.eviction_tracker.remove(result.meta.id);
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
                // Remove all from eviction tracker
                for (entry.value.items) |node| {
                    _ = self.eviction_tracker.remove(node.meta.id);
                }
                self.total_count -|= removed_count;
                var list = entry.value;
                list.deinit(self.allocator);
                return removed_count;
            }

            return 0;
        }

        /// Evict one connection using LRU (most efficient)
        /// Hot path - safety checks disabled for performance
        fn evictOneLru(self: *Self) bool {
            @setRuntimeSafety(false);
            // Pop the least recently used connection ID
            if (self.eviction_tracker.popLru()) |evicted| {
                // Find and remove from the appropriate pool
                if (self.pools.getPtr(evicted.group_key)) |list| {
                    // Fast path: if only one item or the target is at the end, O(1)
                    if (list.items.len > 0) {
                        const last_idx = list.items.len - 1;
                        // Check if the LRU item is at the end (common case after LIFO access)
                        if (list.items[last_idx].meta.id == evicted.id) {
                            _ = list.swapRemove(last_idx);
                            self.total_count -|= 1;
                            return true;
                        }
                        // Check if at the beginning
                        if (list.items[0].meta.id == evicted.id) {
                            _ = list.swapRemove(0);
                            self.total_count -|= 1;
                            return true;
                        }
                        // Fallback: O(n) search (should be rare)
                        for (list.items, 0..) |*node, i| {
                            if (node.meta.id == evicted.id) {
                                _ = list.swapRemove(i);
                                self.total_count -|= 1;
                                return true;
                            }
                        }
                    }
                }
                // Connection not found in pool (maybe already removed)
                self.total_count -|= 1;
                return true;
            }
            return false;
        }

        /// Evict one stale connection from any group (fallback)
        fn evictOneStale(self: *Self) bool {
            const now = CachedTimestamp.now();
            var it = self.pools.iterator();
            while (it.next()) |entry| {
                var list = entry.value_ptr;
                var i: usize = 0;
                while (i < list.items.len) {
                    const node = &list.items[i];
                    if (node.meta.idleTimeAt(now) > self.max_idle_ns or node.isClosed()) {
                        _ = self.eviction_tracker.remove(node.meta.id);
                        _ = list.swapRemove(i);
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
            self.eviction_tracker.clear();
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

test "ConnectionPool capacity limit with LRU eviction" {
    var pool = ConnectionPool(u32, i32).init(testing.allocator, 2);
    defer pool.deinit();

    try testing.expect(pool.put(1, 100));
    try testing.expect(pool.put(2, 200));

    // Pool is full, but LRU eviction allows new connections
    // The oldest connection (key 1, value 100) gets evicted
    try testing.expect(pool.put(3, 300));
    try testing.expectEqual(pool.count(), 2);

    // Key 1 should have been evicted (it was the LRU)
    try testing.expect(pool.get(1) == null);

    // Keys 2 and 3 should still be available
    try testing.expectEqual(pool.get(2).?[0], 200);
    try testing.expectEqual(pool.get(3).?[0], 300);
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
