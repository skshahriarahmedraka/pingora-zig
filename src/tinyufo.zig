//! pingora-zig: tinyufo
//!
//! In-memory cache with TinyLFU admission policy and S3-FIFO eviction policy.
//! Lock-free implementation for high concurrent read/write performance.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/tinyufo

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const RwLock = std.Thread.RwLock;

const SMALL: bool = false;
const MAIN: bool = true;
const USES_CAP: u8 = 3;
const SMALL_QUEUE_PERCENTAGE: f32 = 0.1;

pub const Weight = u16;
pub const Key = u64;

/// Key-value pair returned from cache eviction
pub fn KV(comptime T: type) type {
    return struct {
        key: Key,
        data: T,
        weight: Weight,
    };
}

/// Location indicator (small or main queue)
const Location = struct {
    value: std.atomic.Value(bool),

    fn initSmall() Location {
        return .{ .value = std.atomic.Value(bool).init(SMALL) };
    }

    fn isMain(self: *const Location) bool {
        return self.value.load(.monotonic);
    }

    fn moveToMain(self: *Location) void {
        self.value.store(MAIN, .monotonic);
    }
};

/// Use counter with cap
const Uses = struct {
    value: std.atomic.Value(u8),

    fn init() Uses {
        return .{ .value = std.atomic.Value(u8).init(0) };
    }

    fn uses(self: *const Uses) u8 {
        return self.value.load(.monotonic);
    }

    fn incUses(self: *Uses) u8 {
        while (true) {
            const current = self.uses();
            if (current >= USES_CAP) return current;

            if (self.value.cmpxchgWeak(current, current + 1, .acquire, .monotonic)) |new| {
                if (new >= USES_CAP) return new;
            } else {
                return current + 1;
            }
        }
    }

    fn decrUses(self: *Uses) u8 {
        while (true) {
            const current = self.uses();
            if (current == 0) return 0;

            if (self.value.cmpxchgWeak(current, current - 1, .acquire, .monotonic)) |new| {
                if (new == 0) return 0;
            } else {
                return current;
            }
        }
    }
};

/// Bucket containing data and metadata
fn Bucket(comptime T: type) type {
    return struct {
        uses: Uses,
        queue: Location,
        weight: Weight,
        data: T,
    };
}

/// Slab Allocator for fixed-size objects
/// Pre-allocates objects in chunks for O(1) allocation without syscalls
fn SlabAllocator(comptime T: type) type {
    return struct {
        allocator: Allocator,
        free_list: std.ArrayListUnmanaged(*T),
        slabs: std.ArrayListUnmanaged([]T),
        slab_size: usize,

        const Self = @This();
        const DEFAULT_SLAB_SIZE: usize = 64;

        fn init(allocator: Allocator, slab_size: ?usize) Self {
            return .{
                .allocator = allocator,
                .free_list = .{},
                .slabs = .{},
                .slab_size = slab_size orelse DEFAULT_SLAB_SIZE,
            };
        }

        fn deinit(self: *Self) void {
            // Free all slabs
            for (self.slabs.items) |slab| {
                self.allocator.free(slab);
            }
            self.slabs.deinit(self.allocator);
            self.free_list.deinit(self.allocator);
        }

        fn alloc(self: *Self) !*T {
            // Try to get from free list first
            if (self.free_list.pop()) |ptr| {
                return ptr;
            }

            // Allocate new slab
            try self.growSlab();
            return self.free_list.pop() orelse unreachable;
        }

        fn free(self: *Self, ptr: *T) void {
            // Add back to free list
            self.free_list.append(self.allocator, ptr) catch {
                // If we can't add to free list, just leak it
                // This should be rare
            };
        }

        fn growSlab(self: *Self) !void {
            const slab = try self.allocator.alloc(T, self.slab_size);
            try self.slabs.append(self.allocator, slab);

            // Add all items in slab to free list
            try self.free_list.ensureUnusedCapacity(self.allocator, self.slab_size);
            for (slab) |*item| {
                self.free_list.appendAssumeCapacity(item);
            }
        }
    };
}

/// Count-Min Sketch for frequency estimation
/// Optimized with single hash + mixing for better cache locality and fewer operations
const CountMinSketch = struct {
    allocator: Allocator,
    counters: [][]u8,
    width: usize,
    width_mask: usize, // For fast modulo when width is power of 2

    fn init(allocator: Allocator, estimated_size: usize) !CountMinSketch {
        // Round up to power of 2 for fast modulo
        const width = blk: {
            var w = @max(estimated_size, 16);
            w |= w >> 1;
            w |= w >> 2;
            w |= w >> 4;
            w |= w >> 8;
            w |= w >> 16;
            break :blk w + 1;
        };
        const depth: usize = 4;

        var counters = try allocator.alloc([]u8, depth);
        errdefer allocator.free(counters);

        for (0..depth) |i| {
            counters[i] = try allocator.alloc(u8, width);
            @memset(counters[i], 0);
        }

        return .{
            .allocator = allocator,
            .counters = counters,
            .width = width,
            .width_mask = width - 1,
        };
    }

    fn deinit(self: *CountMinSketch) void {
        for (self.counters) |row| {
            self.allocator.free(row);
        }
        self.allocator.free(self.counters);
    }

    /// Compute 4 hash indices from a single base hash using fast mixing
    /// This is much faster than calling Wyhash 4 times
    inline fn hashIndices(self: *const CountMinSketch, key: Key) [4]usize {
        // Single high-quality hash
        const h = std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
        
        // Split into two 32-bit values and derive 4 indices using cheap mixing
        const h1: u64 = h;
        const h2: u64 = h >> 32;
        
        return .{
            @intCast(h1 & self.width_mask),
            @intCast(h2 & self.width_mask),
            @intCast((h1 +% h2) & self.width_mask),
            @intCast((h1 +% h2 *% 2) & self.width_mask),
        };
    }

    fn increment(self: *CountMinSketch, key: Key) u8 {
        const indices = self.hashIndices(key);
        var min_count: u8 = 255;
        
        inline for (0..4) |i| {
            const idx = indices[i];
            if (self.counters[i][idx] < 255) {
                self.counters[i][idx] += 1;
            }
            min_count = @min(min_count, self.counters[i][idx]);
        }
        return min_count;
    }

    fn get(self: *const CountMinSketch, key: Key) u8 {
        const indices = self.hashIndices(key);
        var min_count: u8 = 255;
        
        inline for (0..4) |i| {
            min_count = @min(min_count, self.counters[i][indices[i]]);
        }
        return min_count;
    }
};

/// High-performance FIFO Queue using Ring Buffer
/// O(1) push and pop operations instead of O(n) with ArrayList
fn RingBuffer(comptime T: type) type {
    return struct {
        allocator: Allocator,
        buffer: []T,
        head: usize, // Index of first element (for pop)
        tail: usize, // Index of next write position (for push)
        count: usize, // Number of elements
        mutex: Mutex,

        const Self = @This();
        const INITIAL_CAPACITY: usize = 64;

        fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .buffer = &[_]T{},
                .head = 0,
                .tail = 0,
                .count = 0,
                .mutex = .{},
            };
        }

        fn deinit(self: *Self) void {
            if (self.buffer.len > 0) {
                self.allocator.free(self.buffer);
            }
        }

        fn push(self: *Self, item: T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Ensure capacity
            if (self.count >= self.buffer.len) {
                self.grow() catch return;
            }

            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % self.buffer.len;
            self.count += 1;
        }

        fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.count == 0) return null;

            const item = self.buffer[self.head];
            self.head = (self.head + 1) % self.buffer.len;
            self.count -= 1;
            return item;
        }

        fn grow(self: *Self) !void {
            const new_capacity = if (self.buffer.len == 0)
                INITIAL_CAPACITY
            else
                self.buffer.len * 2;

            const new_buffer = try self.allocator.alloc(T, new_capacity);

            // Copy existing elements in order
            if (self.count > 0) {
                if (self.head < self.tail) {
                    // Elements are contiguous
                    @memcpy(new_buffer[0..self.count], self.buffer[self.head..self.tail]);
                } else {
                    // Elements wrap around
                    const first_part = self.buffer.len - self.head;
                    @memcpy(new_buffer[0..first_part], self.buffer[self.head..]);
                    @memcpy(new_buffer[first_part..self.count], self.buffer[0..self.tail]);
                }
            }

            if (self.buffer.len > 0) {
                self.allocator.free(self.buffer);
            }

            self.buffer = new_buffer;
            self.head = 0;
            self.tail = self.count;
        }

        /// Get current length (for testing)
        fn len(self: *const Self) usize {
            return self.count;
        }
    };
}

/// FIFO Queue using Ring Buffer (high-performance replacement for ArrayList-based queue)
fn FifoQueue(comptime T: type) type {
    _ = T;
    return RingBuffer(Key);
}

/// TinyUFO cache implementation
/// Optimized with RwLock for concurrent read access
pub fn TinyUfo(comptime K: type, comptime T: type) type {
    return struct {
        allocator: Allocator,
        buckets: std.AutoHashMapUnmanaged(Key, *Bucket(T)),
        buckets_rwlock: RwLock, // RwLock allows concurrent reads
        bucket_slab: SlabAllocator(Bucket(T)),

        small_queue: FifoQueue(T),
        small_weight: std.atomic.Value(usize),

        main_queue: FifoQueue(T),
        main_weight: std.atomic.Value(usize),

        total_weight_limit: usize,
        estimator: CountMinSketch,

        const Self = @This();

        pub fn init(allocator: Allocator, total_weight_limit: usize, estimated_size: usize) !Self {
            return .{
                .allocator = allocator,
                .buckets = .{},
                .buckets_rwlock = .{},
                .bucket_slab = SlabAllocator(Bucket(T)).init(allocator, null),
                .small_queue = FifoQueue(T).init(allocator),
                .small_weight = std.atomic.Value(usize).init(0),
                .main_queue = FifoQueue(T).init(allocator),
                .main_weight = std.atomic.Value(usize).init(0),
                .total_weight_limit = total_weight_limit,
                .estimator = try CountMinSketch.init(allocator, estimated_size),
            };
        }

        pub fn deinit(self: *Self) void {
            // No need to individually free buckets - slab allocator frees all
            self.buckets.deinit(self.allocator);
            self.bucket_slab.deinit();
            self.small_queue.deinit();
            self.main_queue.deinit();
            self.estimator.deinit();
        }

        /// Compute hash key - inlined for performance
        inline fn hashKey(key: *const K) Key {
            // Use direct hash for better performance
            return std.hash.Wyhash.hash(0, std.mem.asBytes(key));
        }

        /// Get a value from the cache
        /// Uses read lock for concurrent access - multiple readers can access simultaneously
        pub fn get(self: *Self, key: *const K) ?T {
            const hashed = hashKey(key);

            // Use read lock - allows concurrent reads
            self.buckets_rwlock.lockShared();
            defer self.buckets_rwlock.unlockShared();

            if (self.buckets.get(hashed)) |bucket| {
                // incUses is atomic, safe under read lock
                _ = bucket.uses.incUses();
                return bucket.data;
            }
            return null;
        }

        /// Put a value into the cache, returns evicted items
        pub fn put(self: *Self, key: K, data: T, weight: Weight) !std.ArrayListUnmanaged(KV(T)) {
            const hashed = hashKey(&key);
            return self.admit(hashed, data, weight, false);
        }

        /// Force put (ignores TinyLFU check)
        pub fn forcePut(self: *Self, key: K, data: T, weight: Weight) !std.ArrayListUnmanaged(KV(T)) {
            const hashed = hashKey(&key);
            return self.admit(hashed, data, weight, true);
        }

        /// Remove a key from the cache
        pub fn remove(self: *Self, key: *const K) ?T {
            const hashed = hashKey(key);

            self.buckets_rwlock.lock();
            defer self.buckets_rwlock.unlock();

            if (self.buckets.fetchRemove(hashed)) |kv| {
                const bucket = kv.value;
                const data = bucket.data;
                const w = bucket.weight;

                if (bucket.queue.isMain()) {
                    _ = self.main_weight.fetchSub(w, .seq_cst);
                } else {
                    _ = self.small_weight.fetchSub(w, .seq_cst);
                }

                self.bucket_slab.free(bucket);
                return data;
            }
            return null;
        }

        fn admit(self: *Self, key: Key, data: T, weight: Weight, ignore_lfu: bool) !std.ArrayListUnmanaged(KV(T)) {
            const new_freq = self.estimator.increment(key);
            std.debug.assert(weight > 0);

            self.buckets_rwlock.lock();

            // Check if key already exists
            if (self.buckets.get(key)) |bucket| {
                _ = bucket.uses.incUses();
                bucket.data = data;

                const old_weight = bucket.weight;
                if (old_weight != weight) {
                    if (bucket.queue.isMain()) {
                        if (old_weight > weight) {
                            _ = self.main_weight.fetchSub(old_weight - weight, .seq_cst);
                        } else {
                            _ = self.main_weight.fetchAdd(weight - old_weight, .seq_cst);
                        }
                    } else {
                        if (old_weight > weight) {
                            _ = self.small_weight.fetchSub(old_weight - weight, .seq_cst);
                        } else {
                            _ = self.small_weight.fetchAdd(weight - old_weight, .seq_cst);
                        }
                    }
                    bucket.weight = weight;
                }
                self.buckets_rwlock.unlock();
                return self.evictToLimit(0);
            }

            self.buckets_rwlock.unlock();

            // Evict to make room
            var evicted = try self.evictToLimit(weight);

            // TinyLFU admission check
            var final_key = key;
            var final_data = data;
            var final_weight = weight;

            if (!ignore_lfu and evicted.items.len == 1) {
                const evicted_first = &evicted.items[0];
                const evicted_freq = self.estimator.get(evicted_first.key);
                if (evicted_freq > new_freq) {
                    // Put back evicted, reject new
                    final_key = evicted_first.key;
                    final_data = evicted_first.data;
                    final_weight = evicted_first.weight;
                    evicted.items[0] = .{ .key = key, .data = data, .weight = weight };
                }
            }

            // Create new bucket using slab allocator
            const bucket = try self.bucket_slab.alloc();
            bucket.* = .{
                .queue = Location.initSmall(),
                .weight = final_weight,
                .uses = Uses.init(),
                .data = final_data,
            };

            self.buckets_rwlock.lock();
            defer self.buckets_rwlock.unlock();

            if (self.buckets.get(final_key) == null) {
                try self.buckets.put(self.allocator, final_key, bucket);
                self.small_queue.push(final_key);
                _ = self.small_weight.fetchAdd(final_weight, .seq_cst);
            } else {
                self.bucket_slab.free(bucket);
            }

            return evicted;
        }

        fn smallWeightLimit(self: *const Self) usize {
            return @as(usize, @intFromFloat(@floor(@as(f32, @floatFromInt(self.total_weight_limit)) * SMALL_QUEUE_PERCENTAGE))) + 1;
        }

        fn evictToLimit(self: *Self, extra_weight: Weight) !std.ArrayListUnmanaged(KV(T)) {
            var evicted = std.ArrayListUnmanaged(KV(T)){};

            while (self.total_weight_limit < self.small_weight.load(.seq_cst) + self.main_weight.load(.seq_cst) + extra_weight) {
                if (self.evictOne()) |item| {
                    try evicted.append(self.allocator, item);
                } else {
                    break;
                }
            }

            return evicted;
        }

        fn evictOne(self: *Self) ?KV(T) {
            const evict_small = self.smallWeightLimit() <= self.small_weight.load(.seq_cst);

            if (evict_small) {
                if (self.evictOneFromSmall()) |item| {
                    return item;
                }
            }
            return self.evictOneFromMain();
        }

        fn evictOneFromSmall(self: *Self) ?KV(T) {
            while (true) {
                const to_evict = self.small_queue.pop() orelse return null;

                self.buckets_rwlock.lock();
                defer self.buckets_rwlock.unlock();

                if (self.buckets.get(to_evict)) |bucket| {
                    const w = bucket.weight;
                    _ = self.small_weight.fetchSub(w, .seq_cst);

                    if (bucket.uses.uses() > 1) {
                        // Move to main
                        bucket.queue.moveToMain();
                        self.main_queue.push(to_evict);
                        _ = self.main_weight.fetchAdd(w, .seq_cst);
                    } else {
                        // Evict
                        const data = bucket.data;
                        _ = self.buckets.remove(to_evict);
                        self.bucket_slab.free(bucket);
                        return .{ .key = to_evict, .data = data, .weight = w };
                    }
                }
            }
        }

        fn evictOneFromMain(self: *Self) ?KV(T) {
            while (true) {
                const to_evict = self.main_queue.pop() orelse return null;

                self.buckets_rwlock.lock();
                defer self.buckets_rwlock.unlock();

                if (self.buckets.get(to_evict)) |bucket| {
                    if (bucket.uses.decrUses() > 0) {
                        // Put back
                        self.main_queue.push(to_evict);
                    } else {
                        // Evict
                        const w = bucket.weight;
                        _ = self.main_weight.fetchSub(w, .seq_cst);
                        const data = bucket.data;
                        _ = self.buckets.remove(to_evict);
                        self.bucket_slab.free(bucket);
                        return .{ .key = to_evict, .data = data, .weight = w };
                    }
                }
            }
        }

        /// Check which queue a key is in (for testing)
        /// Uses read lock since it only reads data
        pub fn peekQueue(self: *Self, key: K) ?bool {
            const hashed = hashKey(&key);
            self.buckets_rwlock.lockShared();
            defer self.buckets_rwlock.unlockShared();

            if (self.buckets.get(hashed)) |bucket| {
                return bucket.queue.isMain();
            }
            return null;
        }
    };
}

// Tests
test "Uses counter" {
    var uses = Uses.init();
    try testing.expectEqual(uses.uses(), 0);

    _ = uses.incUses();
    try testing.expectEqual(uses.uses(), 1);

    for (0..USES_CAP) |_| {
        _ = uses.incUses();
    }
    try testing.expectEqual(uses.uses(), USES_CAP);

    for (0..USES_CAP + 2) |_| {
        _ = uses.decrUses();
    }
    try testing.expectEqual(uses.uses(), 0);
}

test "TinyUfo basic operations" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var evicted = try cache.put(1, 1, 1);
    evicted.deinit(testing.allocator);

    try testing.expectEqual(cache.get(&@as(i32, 1)), 1);
    try testing.expectEqual(cache.get(&@as(i32, 2)), null);
}

test "TinyUfo evict from small" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);
    var e2 = try cache.put(2, 2, 2);
    e2.deinit(testing.allocator);
    var e3 = try cache.put(3, 3, 2);
    e3.deinit(testing.allocator);

    try testing.expectEqual(cache.peekQueue(1), SMALL);
    try testing.expectEqual(cache.peekQueue(2), SMALL);
    try testing.expectEqual(cache.peekQueue(3), SMALL);

    var evicted = try cache.put(4, 4, 3);
    defer evicted.deinit(testing.allocator);

    try testing.expectEqual(evicted.items.len, 2);
}

test "TinyUfo evict from small to main" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);
    var e2 = try cache.put(2, 2, 2);
    e2.deinit(testing.allocator);
    var e3 = try cache.put(3, 3, 2);
    e3.deinit(testing.allocator);

    // Access 1 multiple times to promote it
    _ = cache.get(&@as(i32, 1));
    _ = cache.get(&@as(i32, 1));

    try testing.expectEqual(cache.peekQueue(1), SMALL);

    var evicted = try cache.put(4, 4, 2);
    defer evicted.deinit(testing.allocator);

    try testing.expectEqual(evicted.items.len, 1);
    // 1 should have moved to main
    try testing.expectEqual(cache.peekQueue(1), MAIN);
}

test "TinyUfo remove" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);
    var e2 = try cache.put(2, 2, 2);
    e2.deinit(testing.allocator);
    var e3 = try cache.put(3, 3, 2);
    e3.deinit(testing.allocator);

    try testing.expectEqual(cache.remove(&@as(i32, 1)), 1);
    try testing.expectEqual(cache.remove(&@as(i32, 3)), 3);
    try testing.expectEqual(cache.get(&@as(i32, 1)), null);
    try testing.expectEqual(cache.get(&@as(i32, 3)), null);
}

test "CountMinSketch" {
    var cms = try CountMinSketch.init(testing.allocator, 100);
    defer cms.deinit();

    try testing.expectEqual(cms.get(42), 0);

    _ = cms.increment(42);
    try testing.expectEqual(cms.get(42), 1);

    for (0..10) |_| {
        _ = cms.increment(42);
    }
    try testing.expectEqual(cms.get(42), 11);
}

// Additional tests ported from Pingora

test "TinyUfo evict reentry to main" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);
    var e2 = try cache.put(2, 2, 2);
    e2.deinit(testing.allocator);
    var e3 = try cache.put(3, 3, 2);
    e3.deinit(testing.allocator);

    // Access 1 multiple times to give it higher uses count
    _ = cache.get(&@as(i32, 1));
    _ = cache.get(&@as(i32, 1));
    _ = cache.get(&@as(i32, 1));

    // Now evict - 1 should move to main, not be evicted
    var evicted = try cache.put(4, 4, 2);
    defer evicted.deinit(testing.allocator);

    // 1 should be in main queue now
    try testing.expectEqual(cache.peekQueue(1), MAIN);
}

test "TinyUfo force put bypasses TinyLFU" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 5, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);

    // Force put should always succeed regardless of frequency
    var evicted = try cache.forcePut(2, 2, 1);
    defer evicted.deinit(testing.allocator);

    try testing.expect(cache.get(&@as(i32, 2)) != null);
}

test "TinyUfo update existing key" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 10, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 100, 1);
    e1.deinit(testing.allocator);

    try testing.expectEqual(cache.get(&@as(i32, 1)), 100);

    // Update the value
    var e2 = try cache.put(1, 200, 1);
    e2.deinit(testing.allocator);

    try testing.expectEqual(cache.get(&@as(i32, 1)), 200);
}

// Additional edge case tests

test "Uses counter cap behavior" {
    var uses = Uses.init();

    // Increment beyond cap
    for (0..10) |_| {
        _ = uses.incUses();
    }
    // Should be capped at USES_CAP
    try testing.expectEqual(uses.uses(), USES_CAP);

    // Decrement to 0
    for (0..10) |_| {
        _ = uses.decrUses();
    }
    // Should be 0, not negative
    try testing.expectEqual(uses.uses(), 0);
}

test "TinyUfo empty cache get" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 10, 5);
    defer cache.deinit();

    // Get from empty cache
    try testing.expectEqual(cache.get(&@as(i32, 1)), null);
    try testing.expectEqual(cache.get(&@as(i32, 999)), null);
}

test "TinyUfo remove nonexistent" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 10, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);

    // Remove key that doesn't exist
    try testing.expectEqual(cache.remove(&@as(i32, 999)), null);
    // Original key still exists
    try testing.expectEqual(cache.get(&@as(i32, 1)), 1);
}

test "TinyUfo weight update on existing key" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 10, 5);
    defer cache.deinit();

    var e1 = try cache.put(1, 100, 2);
    e1.deinit(testing.allocator);

    // Update with different weight
    var e2 = try cache.put(1, 200, 5);
    e2.deinit(testing.allocator);

    try testing.expectEqual(cache.get(&@as(i32, 1)), 200);
}

test "TinyUfo evict from main queue" {
    var cache = try TinyUfo(i32, i32).init(testing.allocator, 10, 5);
    defer cache.deinit();

    // Add items and access them multiple times to increase uses
    var e1 = try cache.put(1, 1, 1);
    e1.deinit(testing.allocator);
    _ = cache.get(&@as(i32, 1));
    _ = cache.get(&@as(i32, 1));
    _ = cache.get(&@as(i32, 1));

    var e2 = try cache.put(2, 2, 1);
    e2.deinit(testing.allocator);
    _ = cache.get(&@as(i32, 2));
    _ = cache.get(&@as(i32, 2));
    _ = cache.get(&@as(i32, 2));

    // Fill the cache to trigger eviction from small queue
    var e3 = try cache.put(3, 3, 4);
    e3.deinit(testing.allocator);

    var e4 = try cache.put(4, 4, 4);
    e4.deinit(testing.allocator);

    // At this point, items with high use count should move to main
    // Items 1 and 2 had multiple accesses so they should be promoted
    // Check if at least one of them is in main or got evicted
    const q1 = cache.peekQueue(1);
    const q2 = cache.peekQueue(2);

    // At least one should still exist
    try testing.expect(q1 != null or q2 != null);
}

test "CountMinSketch frequency estimation" {
    var cms = try CountMinSketch.init(testing.allocator, 100);
    defer cms.deinit();

    // Increment key 42 many times
    for (0..50) |_| {
        _ = cms.increment(42);
    }

    // Increment key 99 a few times
    for (0..5) |_| {
        _ = cms.increment(99);
    }

    // 42 should have higher count than 99
    try testing.expect(cms.get(42) > cms.get(99));
}

test "CountMinSketch different keys" {
    var cms = try CountMinSketch.init(testing.allocator, 100);
    defer cms.deinit();

    _ = cms.increment(1);
    _ = cms.increment(2);
    _ = cms.increment(3);

    try testing.expectEqual(cms.get(1), 1);
    try testing.expectEqual(cms.get(2), 1);
    try testing.expectEqual(cms.get(3), 1);
    try testing.expectEqual(cms.get(4), 0); // Never incremented
}

// ============================================================================
// RingBuffer Tests - High-performance FIFO queue
// ============================================================================

test "RingBuffer basic push and pop" {
    var rb = RingBuffer(u64).init(testing.allocator);
    defer rb.deinit();

    rb.push(1);
    rb.push(2);
    rb.push(3);

    try testing.expectEqual(rb.len(), 3);
    try testing.expectEqual(rb.pop(), 1);
    try testing.expectEqual(rb.pop(), 2);
    try testing.expectEqual(rb.pop(), 3);
    try testing.expectEqual(rb.pop(), null);
    try testing.expectEqual(rb.len(), 0);
}

test "RingBuffer wrap around" {
    var rb = RingBuffer(u64).init(testing.allocator);
    defer rb.deinit();

    // Fill initial capacity and more to trigger wrap-around behavior
    for (0..100) |i| {
        rb.push(i);
    }

    // Pop half
    for (0..50) |i| {
        try testing.expectEqual(rb.pop(), i);
    }

    // Push more (these should wrap around)
    for (100..150) |i| {
        rb.push(i);
    }

    // Verify FIFO order maintained
    for (50..150) |i| {
        try testing.expectEqual(rb.pop(), i);
    }

    try testing.expectEqual(rb.pop(), null);
}

test "RingBuffer grow with wrap around" {
    var rb = RingBuffer(u64).init(testing.allocator);
    defer rb.deinit();

    // Push and pop to create wrap-around state
    for (0..64) |i| {
        rb.push(i);
    }
    for (0..32) |_| {
        _ = rb.pop();
    }
    // Now head is at 32, tail at 0, elements 32..63 remain

    // Push more to trigger grow while in wrapped state
    for (64..128) |i| {
        rb.push(i);
    }

    // Verify all elements in order
    for (32..128) |i| {
        try testing.expectEqual(rb.pop(), i);
    }
}

test "RingBuffer empty pop" {
    var rb = RingBuffer(u64).init(testing.allocator);
    defer rb.deinit();

    try testing.expectEqual(rb.pop(), null);
    try testing.expectEqual(rb.len(), 0);
}

test "RingBuffer single element" {
    var rb = RingBuffer(u64).init(testing.allocator);
    defer rb.deinit();

    rb.push(42);
    try testing.expectEqual(rb.len(), 1);
    try testing.expectEqual(rb.pop(), 42);
    try testing.expectEqual(rb.len(), 0);
    try testing.expectEqual(rb.pop(), null);
}
