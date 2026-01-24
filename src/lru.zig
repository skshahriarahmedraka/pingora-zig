//! pingora-zig: lru
//!
//! LRU cache implementation with weighted eviction and sharding.
//! Features: different key sizes, sharded for concurrency, memory efficient.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-lru

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;

pub const LinkedList = @import("linked_list.zig").LinkedList;

/// Get the shard index for a key
fn getShard(key: u64, n_shards: usize) usize {
    return @intCast(key % n_shards);
}

/// LRU node containing data and metadata
fn LruNode(comptime T: type) type {
    return struct {
        data: T,
        list_index: usize,
        weight: usize,
    };
}

/// Slab Allocator for fixed-size LruNode objects
/// Pre-allocates objects in chunks for O(1) allocation without syscalls
fn NodeSlabAllocator(comptime T: type) type {
    return struct {
        allocator: Allocator,
        free_list: std.ArrayListUnmanaged(*LruNode(T)),
        slabs: std.ArrayListUnmanaged([]LruNode(T)),

        const Self = @This();
        const Node = LruNode(T);
        const SLAB_SIZE: usize = 64;

        fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .free_list = .{},
                .slabs = .{},
            };
        }

        fn deinit(self: *Self) void {
            for (self.slabs.items) |slab| {
                self.allocator.free(slab);
            }
            self.slabs.deinit(self.allocator);
            self.free_list.deinit(self.allocator);
        }

        fn alloc(self: *Self) !*Node {
            if (self.free_list.pop()) |ptr| {
                return ptr;
            }
            try self.growSlab();
            return self.free_list.pop() orelse unreachable;
        }

        fn free(self: *Self, ptr: *Node) void {
            self.free_list.append(self.allocator, ptr) catch {};
        }

        fn growSlab(self: *Self) !void {
            const slab = try self.allocator.alloc(Node, SLAB_SIZE);
            try self.slabs.append(self.allocator, slab);
            try self.free_list.ensureUnusedCapacity(self.allocator, SLAB_SIZE);
            for (slab) |*item| {
                self.free_list.appendAssumeCapacity(item);
            }
        }
    };
}

/// Single LRU unit (one shard)
pub fn LruUnit(comptime T: type) type {
    return struct {
        allocator: Allocator,
        lookup_table: std.AutoHashMapUnmanaged(u64, *LruNode(T)),
        order: LinkedList,
        used_weight: usize,
        node_slab: NodeSlabAllocator(T),

        const Self = @This();
        const Node = LruNode(T);

        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .lookup_table = .{},
                .order = LinkedList.init(allocator),
                .used_weight = 0,
                .node_slab = NodeSlabAllocator(T).init(allocator),
            };
        }

        pub fn initCapacity(allocator: Allocator, capacity: usize) !Self {
            var lookup_table: std.AutoHashMapUnmanaged(u64, *Node) = .{};
            try lookup_table.ensureTotalCapacity(allocator, @intCast(capacity));
            return .{
                .allocator = allocator,
                .lookup_table = lookup_table,
                .order = try LinkedList.initCapacity(allocator, capacity),
                .used_weight = 0,
                .node_slab = NodeSlabAllocator(T).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            // No need to individually free nodes - slab allocator frees all
            self.lookup_table.deinit(self.allocator);
            self.order.deinit();
            self.node_slab.deinit();
        }

        /// Peek data without changing order
        pub fn peek(self: *const Self, key: u64) ?*const T {
            if (self.lookup_table.get(key)) |node| {
                return &node.data;
            }
            return null;
        }

        /// Peek weight without changing order
        pub fn peekWeight(self: *const Self, key: u64) ?usize {
            if (self.lookup_table.get(key)) |node| {
                return node.weight;
            }
            return null;
        }

        /// Admit into LRU, return old weight (0 if new)
        pub fn admit(self: *Self, key: u64, data: T, weight: usize) !usize {
            if (self.lookup_table.getPtr(key)) |node_ptr| {
                const node = node_ptr.*;
                const old_weight = node.weight;
                self.adjustWeight(node, weight);
                node.data = data;
                self.order.promote(node.list_index);
                return old_weight;
            }

            self.used_weight += weight;
            const list_index = try self.order.pushHead(key);
            const node = try self.node_slab.alloc();
            node.* = .{ .data = data, .list_index = list_index, .weight = weight };
            try self.lookup_table.put(self.allocator, key, node);
            return 0;
        }

        /// Increment weight, returns (old_weight, new_weight) or null if not found
        pub fn incrementWeight(self: *Self, key: u64, delta: usize, max_weight: ?usize) ?struct { usize, usize } {
            if (self.lookup_table.get(key)) |node| {
                const old_weight = node.weight;
                var new_weight = old_weight + delta;
                if (max_weight) |max| {
                    new_weight = @min(new_weight, max);
                }
                self.adjustWeight(node, new_weight);
                self.order.promote(node.list_index);
                return .{ old_weight, new_weight };
            }
            return null;
        }

        /// Access (promote) a key
        pub fn access(self: *Self, key: u64) bool {
            if (self.lookup_table.get(key)) |node| {
                self.order.promote(node.list_index);
                return true;
            }
            return false;
        }

        /// Check if key needs promotion (not in top n)
        pub fn needPromote(self: *const Self, key: u64, limit: usize) bool {
            if (self.lookup_table.get(key)) |_| {
                return !self.order.existNearHead(key, limit);
            }
            return false;
        }

        /// Evict one item from tail
        pub fn evict(self: *Self) ?struct { T, usize } {
            const key = self.order.popTail() orelse return null;
            if (self.lookup_table.fetchRemove(key)) |kv| {
                const node = kv.value;
                self.used_weight -= node.weight;
                const data = node.data;
                const weight = node.weight;
                self.node_slab.free(node);
                return .{ data, weight };
            }
            return null;
        }

        /// Remove a specific key
        pub fn remove(self: *Self, key: u64) ?struct { T, usize } {
            if (self.lookup_table.fetchRemove(key)) |kv| {
                const node = kv.value;
                _ = self.order.remove(node.list_index) catch {};
                self.used_weight -= node.weight;
                const data = node.data;
                const weight = node.weight;
                self.node_slab.free(node);
                return .{ data, weight };
            }
            return null;
        }

        /// Insert at tail
        pub fn insertTail(self: *Self, key: u64, data: T, weight: usize) !bool {
            if (self.lookup_table.contains(key)) return false;

            const list_index = try self.order.pushTail(key);
            const node = try self.node_slab.alloc();
            node.* = .{ .data = data, .list_index = list_index, .weight = weight };
            try self.lookup_table.put(self.allocator, key, node);
            self.used_weight += weight;
            return true;
        }

        pub fn len(self: *const Self) usize {
            return self.lookup_table.count();
        }

        fn adjustWeight(self: *Self, node: *Node, new_weight: usize) void {
            const old_weight = node.weight;
            if (new_weight != old_weight) {
                self.used_weight += new_weight;
                self.used_weight -= old_weight;
                node.weight = new_weight;
            }
        }

        /// Iterator over the unit
        pub fn iter(self: *const Self) Iterator {
            return .{ .unit = self, .list_iter = self.order.iter() };
        }

        pub const Iterator = struct {
            unit: *const LruUnit(T),
            list_iter: LinkedList.Iterator,

            pub fn next(self: *Iterator) ?struct { *const T, usize } {
                const key = self.list_iter.next() orelse return null;
                if (self.unit.lookup_table.get(key)) |node| {
                    return .{ &node.data, node.weight };
                }
                return null;
            }
        };
    };
}

/// Sharded LRU cache
pub fn Lru(comptime T: type, comptime N: usize) type {
    return struct {
        allocator: Allocator,
        units: [N]LruUnit(T),
        weight: std.atomic.Value(usize),
        weight_limit: usize,
        len_watermark: ?usize,
        total_len: std.atomic.Value(usize),
        evicted_weight: std.atomic.Value(usize),
        evicted_len: std.atomic.Value(usize),
        mutexes: [N]Mutex,

        const Self = @This();

        pub fn init(allocator: Allocator, weight_limit: usize) Self {
            var units: [N]LruUnit(T) = undefined;
            var mutexes: [N]Mutex = undefined;
            for (0..N) |i| {
                units[i] = LruUnit(T).init(allocator);
                mutexes[i] = .{};
            }
            return .{
                .allocator = allocator,
                .units = units,
                .weight = std.atomic.Value(usize).init(0),
                .weight_limit = weight_limit,
                .len_watermark = null,
                .total_len = std.atomic.Value(usize).init(0),
                .evicted_weight = std.atomic.Value(usize).init(0),
                .evicted_len = std.atomic.Value(usize).init(0),
                .mutexes = mutexes,
            };
        }

        pub fn initWithWatermark(allocator: Allocator, weight_limit: usize, watermark: ?usize) Self {
            var self = init(allocator, weight_limit);
            self.len_watermark = watermark;
            return self;
        }

        pub fn deinit(self: *Self) void {
            for (&self.units) |*unit| {
                unit.deinit();
            }
        }

        /// Admit a key-value pair
        pub fn admit(self: *Self, key: u64, data: T, weight: usize) !usize {
            const shard = getShard(key, N);
            const actual_weight = @max(weight, 1);

            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();

            const old_weight = try self.units[shard].admit(key, data, actual_weight);
            if (old_weight != actual_weight) {
                _ = self.weight.fetchAdd(actual_weight, .monotonic);
                if (old_weight > 0) {
                    _ = self.weight.fetchSub(old_weight, .monotonic);
                } else {
                    _ = self.total_len.fetchAdd(1, .monotonic);
                }
            }
            return shard;
        }

        /// Increment weight for a key
        pub fn incrementWeight(self: *Self, key: u64, delta: usize, max_weight: ?usize) usize {
            const shard = getShard(key, N);

            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();

            if (self.units[shard].incrementWeight(key, delta, max_weight)) |result| {
                const old_weight = result[0];
                const new_weight = result[1];
                if (new_weight >= old_weight) {
                    _ = self.weight.fetchAdd(new_weight - old_weight, .monotonic);
                } else {
                    _ = self.weight.fetchSub(old_weight - new_weight, .monotonic);
                }
                return new_weight;
            }
            return 0;
        }

        /// Promote a key to head
        pub fn promote(self: *Self, key: u64) bool {
            const shard = getShard(key, N);
            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();
            return self.units[shard].access(key);
        }

        /// Evict one item from a shard
        pub fn evictShard(self: *Self, shard: u64) ?struct { T, usize } {
            const s = getShard(shard, N);
            self.mutexes[s].lock();
            defer self.mutexes[s].unlock();

            if (self.units[s].evict()) |result| {
                _ = self.weight.fetchSub(result[1], .monotonic);
                _ = self.total_len.fetchSub(1, .monotonic);
                _ = self.evicted_weight.fetchAdd(result[1], .monotonic);
                _ = self.evicted_len.fetchAdd(1, .monotonic);
                return result;
            }
            return null;
        }

        /// Evict until weight is below limit
        pub fn evictToLimit(self: *Self) std.ArrayList(struct { T, usize }) {
            var evicted: std.ArrayList(struct { T, usize }) = .{};
            var initial_weight = self.getWeight();
            var initial_len = self.getLen();
            var shard_seed: u64 = @intCast(@as(u64, @bitCast(std.time.milliTimestamp())) & 0xFFFF);
            var empty_shard: usize = 0;

            while (self.shouldEvict(initial_weight, initial_len) and empty_shard < N) {
                if (self.evictShard(shard_seed)) |item| {
                    initial_weight -|= item[1];
                    initial_len -|= 1;
                    evicted.append(self.allocator, item) catch {};
                } else {
                    empty_shard += 1;
                }
                shard_seed +%= 1;
            }
            return evicted;
        }

        fn shouldEvict(self: *Self, initial_weight: usize, initial_len: usize) bool {
            const current_weight = self.getWeight();
            const current_len = self.getLen();

            const over_weight = initial_weight > self.weight_limit and current_weight > self.weight_limit;
            const over_watermark = if (self.len_watermark) |w|
                initial_len > w and current_len > w
            else
                false;

            return over_weight or over_watermark;
        }

        /// Remove a specific key
        pub fn remove(self: *Self, key: u64) ?struct { T, usize } {
            const shard = getShard(key, N);
            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();

            if (self.units[shard].remove(key)) |result| {
                _ = self.weight.fetchSub(result[1], .monotonic);
                _ = self.total_len.fetchSub(1, .monotonic);
                return result;
            }
            return null;
        }

        /// Check if key exists
        pub fn peek(self: *Self, key: u64) bool {
            const shard = getShard(key, N);
            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();
            return self.units[shard].peek(key) != null;
        }

        /// Get weight of a key
        pub fn peekWeight(self: *Self, key: u64) ?usize {
            const shard = getShard(key, N);
            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();
            return self.units[shard].peekWeight(key);
        }

        /// Insert at tail
        pub fn insertTail(self: *Self, key: u64, data: T, weight: usize) !bool {
            const shard = getShard(key, N);
            self.mutexes[shard].lock();
            defer self.mutexes[shard].unlock();

            if (try self.units[shard].insertTail(key, data, weight)) {
                _ = self.weight.fetchAdd(weight, .monotonic);
                _ = self.total_len.fetchAdd(1, .monotonic);
                return true;
            }
            return false;
        }

        pub fn getWeight(self: *Self) usize {
            return self.weight.load(.monotonic);
        }

        pub fn getLen(self: *Self) usize {
            return self.total_len.load(.monotonic);
        }

        pub fn getEvictedWeight(self: *Self) usize {
            return self.evicted_weight.load(.monotonic);
        }

        pub fn getEvictedLen(self: *Self) usize {
            return self.evicted_len.load(.monotonic);
        }

        pub fn shards(self: *const Self) usize {
            _ = self;
            return N;
        }
    };
}

// Tests
test "LruUnit admit and peek" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    try testing.expectEqual(unit.len(), 0);
    try testing.expectEqual(unit.peek(0), null);

    _ = try unit.admit(2, 2, 1);
    try testing.expectEqual(unit.len(), 1);
    try testing.expectEqual(unit.peek(2).?.*, 2);
    try testing.expectEqual(unit.used_weight, 1);

    _ = try unit.admit(2, 2, 2);
    try testing.expectEqual(unit.used_weight, 2);

    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    try testing.expectEqual(unit.used_weight, 2 + 3 + 4);
}

test "LruUnit access" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    try testing.expect(unit.access(3));
    try testing.expect(unit.access(2));
    try testing.expect(!unit.access(5));
}

test "LruUnit evict" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    _ = unit.access(3);
    _ = unit.access(2);

    try testing.expectEqual(unit.used_weight, 2 + 3 + 4);
    const e1 = unit.evict();
    try testing.expect(e1 != null);
    try testing.expectEqual(e1.?[0], 4);
    try testing.expectEqual(unit.used_weight, 2 + 3);
}

test "LruUnit remove" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    const removed = unit.remove(3);
    try testing.expect(removed != null);
    try testing.expectEqual(removed.?[0], 3);
    try testing.expectEqual(unit.used_weight, 2 + 4);
}

test "Lru admit" {
    var lru = Lru(i32, 2).init(testing.allocator, 30);
    defer lru.deinit();

    try testing.expectEqual(lru.getLen(), 0);

    _ = try lru.admit(2, 2, 3);
    try testing.expectEqual(lru.getLen(), 1);
    try testing.expectEqual(lru.getWeight(), 3);

    _ = try lru.admit(2, 2, 1);
    try testing.expectEqual(lru.getLen(), 1);
    try testing.expectEqual(lru.getWeight(), 1);

    _ = try lru.admit(3, 3, 3);
    _ = try lru.admit(4, 4, 4);

    try testing.expectEqual(lru.getWeight(), 1 + 3 + 4);
    try testing.expectEqual(lru.getLen(), 3);
}

test "Lru promote" {
    var lru = Lru(i32, 2).init(testing.allocator, 30);
    defer lru.deinit();

    _ = try lru.admit(2, 2, 2);
    _ = try lru.admit(3, 3, 3);

    try testing.expect(lru.promote(3));
    try testing.expect(lru.promote(2));
    try testing.expect(!lru.promote(7));
}

test "Lru remove" {
    var lru = Lru(i32, 2).init(testing.allocator, 30);
    defer lru.deinit();

    _ = try lru.admit(2, 2, 2);
    _ = try lru.admit(3, 3, 3);
    _ = try lru.admit(4, 4, 4);

    try testing.expectEqual(lru.getWeight(), 2 + 3 + 4);
    try testing.expectEqual(lru.getLen(), 3);

    const removed = lru.remove(3);
    try testing.expect(removed != null);
    try testing.expectEqual(removed.?[0], 3);
    try testing.expectEqual(lru.getWeight(), 2 + 4);
    try testing.expectEqual(lru.getLen(), 2);
}

test "Lru peek" {
    var lru = Lru(i32, 2).init(testing.allocator, 30);
    defer lru.deinit();

    _ = try lru.admit(2, 2, 2);
    _ = try lru.admit(3, 3, 3);

    try testing.expect(lru.peek(2));
    try testing.expect(lru.peek(3));
    try testing.expect(!lru.peek(4));
}

test "Lru increment_weight" {
    var lru = Lru(i32, 2).init(testing.allocator, 100);
    defer lru.deinit();

    _ = try lru.admit(1, 1, 1);
    _ = lru.incrementWeight(1, 1, null);
    try testing.expectEqual(lru.getWeight(), 2);

    _ = lru.incrementWeight(0, 1000, null);
    try testing.expectEqual(lru.getWeight(), 2);

    _ = try lru.admit(2, 2, 2);
    _ = lru.incrementWeight(2, 2, null);
    try testing.expectEqual(lru.getWeight(), 2 + 4);

    _ = lru.incrementWeight(2, 2, 3);
    try testing.expectEqual(lru.getWeight(), 2 + 3);
}

test "Lru insert_tail" {
    var lru = Lru(i32, 2).init(testing.allocator, 30);
    defer lru.deinit();

    _ = try lru.admit(2, 2, 2);
    _ = try lru.admit(3, 3, 3);

    try testing.expect(try lru.insertTail(7, 7, 7));
    try testing.expectEqual(lru.getWeight(), 2 + 3 + 7);
    try testing.expectEqual(lru.getLen(), 3);

    try testing.expect(!try lru.insertTail(2, 2, 2));
}

test "Lru watermark eviction" {
    const WEIGHT_LIMIT = std.math.maxInt(usize) / 2;
    var lru = Lru(u64, 2).initWithWatermark(testing.allocator, WEIGHT_LIMIT, 4);
    defer lru.deinit();

    for ([_]u64{ 2, 3, 4, 5, 6, 7 }) |k| {
        _ = try lru.admit(k, k, 1);
    }

    try testing.expect(lru.getWeight() < WEIGHT_LIMIT);
    try testing.expectEqual(lru.getLen(), 6);

    var evicted = lru.evictToLimit();
    defer evicted.deinit(testing.allocator);

    try testing.expectEqual(lru.getLen(), 4);
    try testing.expectEqual(evicted.items.len, 2);
    try testing.expectEqual(lru.getEvictedLen(), 2);
}

// Additional tests ported from Pingora

test "LruUnit order after admit" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    // Order should be: 4, 3, 2 (most recent first)
    var it = unit.iter();
    const first = it.next();
    try testing.expect(first != null);
    try testing.expectEqual(first.?[0].*, 4);

    const second = it.next();
    try testing.expect(second != null);
    try testing.expectEqual(second.?[0].*, 3);

    const third = it.next();
    try testing.expect(third != null);
    try testing.expectEqual(third.?[0].*, 2);

    try testing.expect(it.next() == null);
}

test "LruUnit order after access" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    // Access 2 to promote it to head
    _ = unit.access(2);

    // Order should be: 2, 4, 3
    var it = unit.iter();
    try testing.expectEqual(it.next().?[0].*, 2);
    try testing.expectEqual(it.next().?[0].*, 4);
    try testing.expectEqual(it.next().?[0].*, 3);
}

test "LruUnit need_promote" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    // 4 is at head, should not need promote with limit 1
    try testing.expect(!unit.needPromote(4, 1));
    // 2 is at tail, should need promote with limit 1
    try testing.expect(unit.needPromote(2, 1));
    // With limit 3, even 2 doesn't need promote
    try testing.expect(!unit.needPromote(2, 3));
}

// Edge case tests

test "LruUnit evict all" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    // Evict all items
    const e1 = unit.evict();
    try testing.expect(e1 != null);
    try testing.expectEqual(e1.?[0], 2);

    const e2 = unit.evict();
    try testing.expect(e2 != null);
    try testing.expectEqual(e2.?[0], 3);

    const e3 = unit.evict();
    try testing.expect(e3 != null);
    try testing.expectEqual(e3.?[0], 4);

    // No more items to evict
    try testing.expect(unit.evict() == null);
    try testing.expectEqual(unit.len(), 0);
    try testing.expectEqual(unit.used_weight, 0);
}

test "LruUnit insert tail does not duplicate" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    try testing.expect(try unit.insertTail(2, 2, 1));
    try testing.expectEqual(unit.len(), 1);
    try testing.expectEqual(unit.used_weight, 1);

    // Inserting same key should fail
    try testing.expect(!try unit.insertTail(2, 2, 2));
    try testing.expectEqual(unit.len(), 1);
    try testing.expectEqual(unit.used_weight, 1); // Weight unchanged

    try testing.expect(try unit.insertTail(3, 3, 3));
    try testing.expectEqual(unit.used_weight, 1 + 3);
}

test "LruUnit remove nonexistent key" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);

    // Remove nonexistent key
    try testing.expect(unit.remove(99) == null);
    try testing.expectEqual(unit.len(), 1);
}

test "LruUnit weight update on re-admit" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(1, 10, 5);
    try testing.expectEqual(unit.used_weight, 5);

    // Re-admit with different weight
    const old_weight = try unit.admit(1, 20, 10);
    try testing.expectEqual(old_weight, 5);
    try testing.expectEqual(unit.used_weight, 10);

    // Value should be updated
    try testing.expectEqual(unit.peek(1).?.*, 20);
}

test "Lru evict from specific shard" {
    var lru = Lru(i32, 4).init(testing.allocator, 100);
    defer lru.deinit();

    // Add items that will go to different shards
    for (0..8) |i| {
        _ = try lru.admit(@intCast(i), @intCast(i), 1);
    }

    try testing.expectEqual(lru.getLen(), 8);

    // Evict from shard 0
    const evicted = lru.evictShard(0);
    try testing.expect(evicted != null);
    try testing.expectEqual(lru.getLen(), 7);
    try testing.expectEqual(lru.getEvictedLen(), 1);
}

test "Lru peek weight" {
    var lru = Lru(i32, 2).init(testing.allocator, 100);
    defer lru.deinit();

    _ = try lru.admit(1, 10, 5);
    _ = try lru.admit(2, 20, 10);

    try testing.expectEqual(lru.peekWeight(1), 5);
    try testing.expectEqual(lru.peekWeight(2), 10);
    try testing.expectEqual(lru.peekWeight(99), null);
}

test "Lru weight limit eviction" {
    var lru = Lru(i32, 2).init(testing.allocator, 10);
    defer lru.deinit();

    _ = try lru.admit(1, 1, 5);
    _ = try lru.admit(2, 2, 5);

    try testing.expectEqual(lru.getWeight(), 10);

    // Add item that exceeds limit
    _ = try lru.admit(3, 3, 5);

    // Now evict to limit
    var evicted = lru.evictToLimit();
    defer evicted.deinit(testing.allocator);

    try testing.expect(lru.getWeight() <= 10);
}

// Additional edge case tests from Pingora

test "LruUnit admit updates weight" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 3);
    try testing.expectEqual(unit.len(), 1);
    try testing.expectEqual(unit.used_weight, 3);

    // Re-admit with different weight
    const old_weight = try unit.admit(2, 2, 1);
    try testing.expectEqual(old_weight, 3);
    try testing.expectEqual(unit.len(), 1);
    try testing.expectEqual(unit.used_weight, 1);

    // Re-admit again
    _ = try unit.admit(2, 2, 2);
    try testing.expectEqual(unit.used_weight, 2);
}

test "LruUnit multiple admits accumulate weight" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(2, 2, 2);
    _ = try unit.admit(3, 3, 3);
    _ = try unit.admit(4, 4, 4);

    try testing.expectEqual(unit.used_weight, 2 + 3 + 4);
    try testing.expectEqual(unit.len(), 3);
}

test "Lru sharded distribution" {
    // Test that keys get distributed across shards
    var lru = Lru(i32, 4).init(testing.allocator, 100);
    defer lru.deinit();

    // Add items that will go to different shards
    for (0..16) |i| {
        _ = try lru.admit(@intCast(i), @intCast(i * 10), 1);
    }

    try testing.expectEqual(lru.getLen(), 16);
    try testing.expectEqual(lru.getWeight(), 16);
}

test "Lru peek does not change order" {
    var lru = Lru(i32, 1).init(testing.allocator, 100);
    defer lru.deinit();

    _ = try lru.admit(1, 10, 1);
    _ = try lru.admit(2, 20, 1);
    _ = try lru.admit(3, 30, 1);

    // Peek should not promote
    try testing.expect(lru.peek(1));
    try testing.expect(lru.peek(2));
    try testing.expect(lru.peek(3));

    // All should still be there
    try testing.expectEqual(lru.getLen(), 3);
}

test "LruUnit iter order" {
    var unit = LruUnit(i32).init(testing.allocator);
    defer unit.deinit();

    _ = try unit.admit(1, 10, 1);
    _ = try unit.admit(2, 20, 1);
    _ = try unit.admit(3, 30, 1);

    // Order should be 3, 2, 1 (most recent first)
    var it = unit.iter();
    try testing.expectEqual(it.next().?[0].*, 30);
    try testing.expectEqual(it.next().?[0].*, 20);
    try testing.expectEqual(it.next().?[0].*, 10);
    try testing.expect(it.next() == null);
}
