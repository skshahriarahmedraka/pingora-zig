//! pingora-limits: Rate limiting and event count estimation
//!
//! This module contains:
//! - `Estimator`: A lock-free Count-Min Sketch for frequency estimation
//! - `Inflight`: Tracks the frequency of actions that are actively occurring
//! - `Rate`: Estimates the occurrence of events over a period of time
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-limits

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Hash function using SipHash (similar to ahash in Rust)
fn hash(key: anytype) u64 {
    var hasher = std.hash.Wyhash.init(0);
    std.hash.autoHash(&hasher, key);
    return hasher.final();
}

/// Hash a byte slice
fn hashBytes(key: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(key);
    return hasher.final();
}

// ============================================================================
// Estimator: Count-Min Sketch
// ============================================================================

/// An implementation of a lock-free count-min sketch estimator.
/// See: https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch
///
/// This data structure is useful for estimating the frequency of items in a stream
/// with a fixed amount of memory. It may over-count but never under-counts.
pub const Estimator = struct {
    /// The 2D array of atomic counters [slots][hashes]
    estimator: [][]std.atomic.Value(isize),
    allocator: Allocator,
    slots: usize,
    hashes: usize,

    const Self = @This();

    /// Create a new `Estimator` with the given number of hashes and slots.
    ///
    /// The accuracy of the estimation is determined by the number of hashes and slots:
    /// - More hashes = lower false positive rate but slower
    /// - More slots = lower collision rate but more memory
    ///
    /// Recommended starting point: 8 hashes, 2048 slots
    pub fn init(allocator: Allocator, hashes: usize, slots: usize) !Self {
        const estimator = try allocator.alloc([]std.atomic.Value(isize), slots);
        errdefer allocator.free(estimator);

        for (estimator) |*slot| {
            slot.* = try allocator.alloc(std.atomic.Value(isize), hashes);
            for (slot.*) |*counter| {
                counter.* = std.atomic.Value(isize).init(0);
            }
        }

        return .{
            .estimator = estimator,
            .allocator = allocator,
            .slots = slots,
            .hashes = hashes,
        };
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        for (self.estimator) |slot| {
            self.allocator.free(slot);
        }
        self.allocator.free(self.estimator);
    }

    /// Increment the count for the given key by delta.
    /// Returns the estimated count after increment.
    pub fn incr(self: *Self, key: anytype, delta: isize) isize {
        return self.incrBytes(std.mem.asBytes(&key), delta);
    }

    /// Increment the count for the given key (as bytes) by delta.
    /// Returns the estimated count after increment.
    pub fn incrBytes(self: *Self, key: []const u8, delta: isize) isize {
        var min: isize = std.math.maxInt(isize);
        const key_hash = hashBytes(key);

        for (0..self.hashes) |i| {
            const slot_idx = self.slotIndex(key_hash, i);
            const counter = &self.estimator[slot_idx][i];
            const new_val = counter.fetchAdd(delta, .monotonic) + delta;
            min = @min(min, new_val);
        }

        return min;
    }

    /// Decrement the count for the given key by delta.
    pub fn decr(self: *Self, key: anytype, delta: isize) void {
        self.decrBytes(std.mem.asBytes(&key), delta);
    }

    /// Decrement the count for the given key (as bytes) by delta.
    pub fn decrBytes(self: *Self, key: []const u8, delta: isize) void {
        const key_hash = hashBytes(key);

        for (0..self.hashes) |i| {
            const slot_idx = self.slotIndex(key_hash, i);
            const counter = &self.estimator[slot_idx][i];
            _ = counter.fetchSub(delta, .monotonic);
        }
    }

    /// Get the estimated count for the given key.
    /// This returns the minimum value across all hash positions.
    pub fn get(self: *Self, key: anytype) isize {
        return self.getBytes(std.mem.asBytes(&key));
    }

    /// Get the estimated count for the given key (as bytes).
    pub fn getBytes(self: *Self, key: []const u8) isize {
        var min: isize = std.math.maxInt(isize);
        const key_hash = hashBytes(key);

        for (0..self.hashes) |i| {
            const slot_idx = self.slotIndex(key_hash, i);
            const val = self.estimator[slot_idx][i].load(.monotonic);
            min = @min(min, val);
        }

        return min;
    }

    /// Reset all values inside this Estimator to zero.
    pub fn reset(self: *Self) void {
        for (self.estimator) |slot| {
            for (slot) |*counter| {
                counter.store(0, .monotonic);
            }
        }
    }

    /// Calculate the slot index for a given hash and hash index
    fn slotIndex(self: *Self, key_hash: u64, hash_idx: usize) usize {
        // Use different bits of the hash for each hash function
        const rotated = std.math.rotr(u64, key_hash, @as(u6, @truncate(hash_idx * 8)));
        return @intCast(rotated % self.slots);
    }
};

// ============================================================================
// Inflight: Track in-progress actions
// ============================================================================

/// An `Inflight` type tracks the frequency of actions that are actively occurring.
/// When the Guard is dropped/deinitialized, the count will automatically decrease.
pub const Inflight = struct {
    estimator: *Estimator,
    allocator: Allocator,
    owned_estimator: bool,

    const Self = @This();

    /// Create a new `Inflight` tracker with default estimator settings (8 hashes, 8 slots).
    pub fn init(allocator: Allocator) !Self {
        const estimator = try allocator.create(Estimator);
        estimator.* = try Estimator.init(allocator, 8, 8);
        return .{
            .estimator = estimator,
            .allocator = allocator,
            .owned_estimator = true,
        };
    }

    /// Create a new `Inflight` tracker with custom estimator settings.
    pub fn initWithSize(allocator: Allocator, hashes: usize, slots: usize) !Self {
        const estimator = try allocator.create(Estimator);
        estimator.* = try Estimator.init(allocator, hashes, slots);
        return .{
            .estimator = estimator,
            .allocator = allocator,
            .owned_estimator = true,
        };
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        if (self.owned_estimator) {
            self.estimator.deinit();
            self.allocator.destroy(self.estimator);
        }
    }

    /// Increment the count for the given key by the value.
    /// Returns a Guard that will decrement the count when deinitialized,
    /// and the estimated count after increment.
    pub fn incr(self: *Self, key: anytype, value: isize) struct { Guard, isize } {
        return self.incrBytes(std.mem.asBytes(&key), value);
    }

    /// Increment the count for the given key (as bytes) by the value.
    pub fn incrBytes(self: *Self, key: []const u8, value: isize) struct { Guard, isize } {
        const new_val = self.estimator.incrBytes(key, value);
        const guard = Guard{
            .estimator = self.estimator,
            .key = key,
            .value = value,
        };
        return .{ guard, new_val };
    }

    /// A guard that decrements the inflight count when dropped.
    pub const Guard = struct {
        estimator: *Estimator,
        key: []const u8,
        value: isize,

        /// Get the current estimated count for this key.
        pub fn get(self: *const Guard) isize {
            return self.estimator.getBytes(self.key);
        }

        /// Release this guard without decrementing the count.
        /// Use this if you want to transfer ownership elsewhere.
        pub fn release(self: *Guard) void {
            self.value = 0;
        }

        /// Decrement the count (called automatically on scope exit).
        pub fn deinit(self: *Guard) void {
            if (self.value != 0) {
                self.estimator.decrBytes(self.key, self.value);
            }
        }
    };
};

// ============================================================================
// Rate: Estimate event occurrence over time
// ============================================================================

/// Input struct for custom rate calculation functions.
pub const RateComponents = struct {
    /// Count from the current (in-progress) interval
    curr_interval_count: isize,
    /// Count from the previous (completed) interval
    prev_interval_count: isize,
    /// The configured duration of a single interval in ms
    interval_ms: u64,
    /// How far into the current interval we are (0.0 - 1.0)
    elapsed_fraction: f64,
};

/// Rate calculation function type
pub const RateCalcFn = *const fn (RateComponents) f64;

/// Default rate calculation: returns the previous interval count as-is.
pub fn defaultRateCalc(components: RateComponents) f64 {
    return @floatFromInt(components.prev_interval_count);
}

/// Proportional rate estimate: interpolates between current and previous intervals.
pub fn proportionalRateCalc(components: RateComponents) f64 {
    const curr: f64 = @floatFromInt(components.curr_interval_count);
    const prev: f64 = @floatFromInt(components.prev_interval_count);
    const frac = components.elapsed_fraction;

    // Interpolate: use fraction of previous + extrapolated current
    return prev * (1.0 - frac) + curr;
}

/// A `Rate` type estimates the occurrence of events over a period of time.
/// It uses a sliding window approach with two intervals.
pub const Rate = struct {
    /// The underlying estimator for counting
    estimator: [2]*Estimator,
    /// Index of the current interval (0 or 1)
    current_interval: std.atomic.Value(u8),
    /// Timestamp when the current interval started (in ms)
    interval_start_ms: std.atomic.Value(u64),
    /// Duration of each interval in milliseconds
    reset_interval_ms: u64,
    /// Lock for reset operation
    resetting: std.atomic.Value(bool),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new Rate tracker with the given interval duration.
    pub fn init(allocator: Allocator, interval: u64) !Self {
        const est0 = try allocator.create(Estimator);
        errdefer allocator.destroy(est0);
        est0.* = try Estimator.init(allocator, 8, 128);
        errdefer est0.deinit();

        const est1 = try allocator.create(Estimator);
        errdefer allocator.destroy(est1);
        est1.* = try Estimator.init(allocator, 8, 128);

        const now_ms = @as(u64, @intCast(@divFloor(std.time.milliTimestamp(), 1)));

        return .{
            .estimator = .{ est0, est1 },
            .current_interval = std.atomic.Value(u8).init(0),
            .interval_start_ms = std.atomic.Value(u64).init(now_ms),
            .reset_interval_ms = interval,
            .resetting = std.atomic.Value(bool).init(false),
            .allocator = allocator,
        };
    }

    /// Create a new Rate tracker with custom estimator settings.
    pub fn initWithEstimatorSize(allocator: Allocator, interval: u64, hashes: usize, slots: usize) !Self {
        const est0 = try allocator.create(Estimator);
        errdefer allocator.destroy(est0);
        est0.* = try Estimator.init(allocator, hashes, slots);
        errdefer est0.deinit();

        const est1 = try allocator.create(Estimator);
        errdefer allocator.destroy(est1);
        est1.* = try Estimator.init(allocator, hashes, slots);

        const now_ms = @as(u64, @intCast(@divFloor(std.time.milliTimestamp(), 1)));

        return .{
            .estimator = .{ est0, est1 },
            .current_interval = std.atomic.Value(u8).init(0),
            .interval_start_ms = std.atomic.Value(u64).init(now_ms),
            .reset_interval_ms = interval,
            .resetting = std.atomic.Value(bool).init(false),
            .allocator = allocator,
        };
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        self.estimator[0].deinit();
        self.allocator.destroy(self.estimator[0]);
        self.estimator[1].deinit();
        self.allocator.destroy(self.estimator[1]);
    }

    /// Observe a new event for the given key (adds 1 to the count).
    pub fn observe(self: *Self, key: anytype, value: isize) isize {
        return self.observeBytes(std.mem.asBytes(&key), value);
    }

    /// Observe a new event for the given key (as bytes).
    pub fn observeBytes(self: *Self, key: []const u8, value: isize) isize {
        _ = self.maybeReset();
        const idx = self.current_interval.load(.seq_cst);
        return self.estimator[idx].incrBytes(key, value);
    }

    /// Get the rate for the given key using the default calculation.
    pub fn rate(self: *Self, key: anytype) f64 {
        return self.rateWith(key, defaultRateCalc);
    }

    /// Get the rate for the given key (as bytes) using the default calculation.
    pub fn rateBytes(self: *Self, key: []const u8) f64 {
        return self.rateBytesWithFn(key, defaultRateCalc);
    }

    /// Get the rate for the given key using a custom calculation function.
    pub fn rateWith(self: *Self, key: anytype, rate_calc_fn: RateCalcFn) f64 {
        return self.rateBytesWithFn(std.mem.asBytes(&key), rate_calc_fn);
    }

    /// Get the rate for the given key (as bytes) using a custom calculation function.
    pub fn rateBytesWithFn(self: *Self, key: []const u8, rate_calc_fn: RateCalcFn) f64 {
        const past_ms = self.maybeReset();

        const curr_idx = self.current_interval.load(.seq_cst);
        const prev_idx = 1 - curr_idx;

        // If we've missed 2 or more intervals, no valid data
        if (past_ms >= self.reset_interval_ms * 2) {
            return rate_calc_fn(.{
                .curr_interval_count = 0,
                .prev_interval_count = 0,
                .interval_ms = self.reset_interval_ms,
                .elapsed_fraction = 0,
            });
        }

        const curr_samples = self.estimator[curr_idx].getBytes(key);
        const prev_samples = self.estimator[prev_idx].getBytes(key);

        const elapsed_fraction = @as(f64, @floatFromInt(past_ms)) /
            @as(f64, @floatFromInt(self.reset_interval_ms));

        return rate_calc_fn(.{
            .curr_interval_count = curr_samples,
            .prev_interval_count = prev_samples,
            .interval_ms = self.reset_interval_ms,
            .elapsed_fraction = @min(1.0, elapsed_fraction),
        });
    }

    /// Check if we need to reset and switch intervals.
    /// Returns the time elapsed since interval start in ms.
    fn maybeReset(self: *Self) u64 {
        const now_ms = @as(u64, @intCast(@max(0, std.time.milliTimestamp())));
        const start_ms = self.interval_start_ms.load(.seq_cst);
        const past_ms = now_ms -| start_ms;

        if (past_ms < self.reset_interval_ms) {
            return past_ms;
        }

        // Try to acquire the reset lock
        if (self.resetting.cmpxchgStrong(false, true, .seq_cst, .seq_cst)) |_| {
            // Another thread is resetting, just return
            return past_ms;
        }

        defer self.resetting.store(false, .seq_cst);

        // Double-check after acquiring lock
        const start_ms_2 = self.interval_start_ms.load(.seq_cst);
        const past_ms_2 = now_ms -| start_ms_2;

        if (past_ms_2 < self.reset_interval_ms) {
            return past_ms_2;
        }

        // Switch intervals
        const curr_idx = self.current_interval.load(.seq_cst);
        const new_idx: u8 = 1 - curr_idx;

        // Reset the interval we're about to switch to
        self.estimator[new_idx].reset();

        // Switch to new interval
        self.current_interval.store(new_idx, .seq_cst);

        // Update start time
        const new_start = start_ms_2 + self.reset_interval_ms;
        self.interval_start_ms.store(new_start, .seq_cst);

        return now_ms -| new_start;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Estimator incr" {
    var est = try Estimator.init(testing.allocator, 8, 8);
    defer est.deinit();

    const v1 = est.incrBytes("a", 1);
    try testing.expectEqual(v1, 1);
    const v2 = est.incrBytes("b", 1);
    try testing.expectEqual(v2, 1);
    const v3 = est.incrBytes("a", 2);
    try testing.expectEqual(v3, 3);
    const v4 = est.incrBytes("b", 2);
    try testing.expectEqual(v4, 3);
}

test "Estimator get" {
    var est = try Estimator.init(testing.allocator, 8, 8);
    defer est.deinit();

    _ = est.incrBytes("a", 1);
    _ = est.incrBytes("a", 2);
    _ = est.incrBytes("b", 1);
    _ = est.incrBytes("b", 2);

    try testing.expectEqual(est.getBytes("a"), 3);
    try testing.expectEqual(est.getBytes("b"), 3);
}

test "Estimator reset" {
    var est = try Estimator.init(testing.allocator, 8, 8);
    defer est.deinit();

    _ = est.incrBytes("a", 1);
    _ = est.incrBytes("a", 2);
    _ = est.incrBytes("b", 1);
    _ = est.incrBytes("b", 2);
    est.decrBytes("b", 1);

    est.reset();

    try testing.expectEqual(est.getBytes("a"), 0);
    try testing.expectEqual(est.getBytes("b"), 0);
}

test "Estimator decr" {
    var est = try Estimator.init(testing.allocator, 8, 8);
    defer est.deinit();

    _ = est.incrBytes("a", 5);
    try testing.expectEqual(est.getBytes("a"), 5);

    est.decrBytes("a", 2);
    try testing.expectEqual(est.getBytes("a"), 3);

    est.decrBytes("a", 3);
    try testing.expectEqual(est.getBytes("a"), 0);
}

test "Estimator different keys" {
    var est = try Estimator.init(testing.allocator, 8, 64);
    defer est.deinit();

    _ = est.incrBytes("key1", 10);
    _ = est.incrBytes("key2", 20);
    _ = est.incrBytes("key3", 30);

    try testing.expectEqual(est.getBytes("key1"), 10);
    try testing.expectEqual(est.getBytes("key2"), 20);
    try testing.expectEqual(est.getBytes("key3"), 30);
    try testing.expectEqual(est.getBytes("key4"), 0); // Never incremented
}

test "Inflight count" {
    var inflight = try Inflight.init(testing.allocator);
    defer inflight.deinit();

    const result1 = inflight.incrBytes("a", 1);
    var g1 = result1[0];
    const v1 = result1[1];
    try testing.expectEqual(v1, 1);

    const result2 = inflight.incrBytes("a", 2);
    var g2 = result2[0];
    const v2 = result2[1];
    try testing.expectEqual(v2, 3);

    // Drop g1
    g1.deinit();

    // g2 should now see count of 2
    try testing.expectEqual(g2.get(), 2);

    // Drop g2
    g2.deinit();

    // New increment should start from 1
    const result3 = inflight.incrBytes("a", 1);
    var g3 = result3[0];
    defer g3.deinit();
    const v3 = result3[1];
    try testing.expectEqual(v3, 1);
}

test "Inflight multiple keys" {
    var inflight = try Inflight.init(testing.allocator);
    defer inflight.deinit();

    const result_a = inflight.incrBytes("a", 5);
    var guard_a = result_a[0];
    defer guard_a.deinit();

    const result_b = inflight.incrBytes("b", 10);
    var guard_b = result_b[0];
    defer guard_b.deinit();

    try testing.expectEqual(guard_a.get(), 5);
    try testing.expectEqual(guard_b.get(), 10);
}

test "Inflight guard release" {
    var inflight = try Inflight.init(testing.allocator);
    defer inflight.deinit();

    const result = inflight.incrBytes("a", 5);
    var guard = result[0];

    // Release the guard - it won't decrement on deinit
    guard.release();
    guard.deinit();

    // The count should still be 5
    try testing.expectEqual(inflight.estimator.getBytes("a"), 5);
}

test "Rate observe and rate" {
    var r = try Rate.init(testing.allocator, 1000); // 1 second interval
    defer r.deinit();

    _ = r.observeBytes("key", 1);
    _ = r.observeBytes("key", 1);
    _ = r.observeBytes("key", 1);

    // Rate should be 0 since we haven't completed an interval yet
    // (default rate calc returns previous interval count)
    const rate_val = r.rateBytes("key");
    try testing.expectEqual(rate_val, 0);
}

test "Rate proportional calculation" {
    // Test the proportional rate calculation function
    const components = RateComponents{
        .curr_interval_count = 10,
        .prev_interval_count = 20,
        .interval_ms = 1000,
        .elapsed_fraction = 0.5,
    };

    const result = proportionalRateCalc(components);
    // 20 * 0.5 + 10 = 20
    try testing.expectEqual(result, 20.0);
}

test "Rate components at start of interval" {
    const components = RateComponents{
        .curr_interval_count = 0,
        .prev_interval_count = 100,
        .interval_ms = 1000,
        .elapsed_fraction = 0.0,
    };

    const result = proportionalRateCalc(components);
    // 100 * 1.0 + 0 = 100
    try testing.expectEqual(result, 100.0);
}

test "Rate components at end of interval" {
    const components = RateComponents{
        .curr_interval_count = 50,
        .prev_interval_count = 100,
        .interval_ms = 1000,
        .elapsed_fraction = 1.0,
    };

    const result = proportionalRateCalc(components);
    // 100 * 0.0 + 50 = 50
    try testing.expectEqual(result, 50.0);
}

test "Rate multiple keys" {
    var r = try Rate.init(testing.allocator, 1000);
    defer r.deinit();

    _ = r.observeBytes("key1", 5);
    _ = r.observeBytes("key2", 10);
    _ = r.observeBytes("key1", 5);

    // Both should have rate 0 (no completed interval)
    try testing.expectEqual(r.rateBytes("key1"), 0);
    try testing.expectEqual(r.rateBytes("key2"), 0);
}

test "Estimator large values" {
    var est = try Estimator.init(testing.allocator, 4, 16);
    defer est.deinit();

    _ = est.incrBytes("big", 1000000);
    try testing.expectEqual(est.getBytes("big"), 1000000);

    est.decrBytes("big", 500000);
    try testing.expectEqual(est.getBytes("big"), 500000);
}

test "Estimator concurrent safety simulation" {
    var est = try Estimator.init(testing.allocator, 8, 64);
    defer est.deinit();

    // Simulate concurrent increments
    for (0..1000) |_| {
        _ = est.incrBytes("concurrent_key", 1);
    }

    try testing.expectEqual(est.getBytes("concurrent_key"), 1000);
}

// ============================================================================
// Leaky Bucket Rate Limiter
// ============================================================================

/// A leaky bucket rate limiter.
/// 
/// The bucket fills with tokens at a constant rate and empties as requests arrive.
/// This provides smooth rate limiting without bursting.
pub const LeakyBucket = struct {
    /// Maximum capacity of the bucket
    capacity: f64,
    /// Rate at which the bucket leaks (tokens per second)
    leak_rate: f64,
    /// Current water level (tokens in bucket)
    level: std.atomic.Value(u64),
    /// Last update timestamp (nanoseconds)
    last_update_ns: std.atomic.Value(i64),
    /// Lock for updates
    updating: std.atomic.Value(bool),

    const Self = @This();

    /// Create a new leaky bucket.
    /// - capacity: Maximum burst size (tokens)
    /// - rate_per_second: Steady-state rate limit
    pub fn init(capacity: f64, rate_per_second: f64) Self {
        return .{
            .capacity = capacity,
            .leak_rate = rate_per_second,
            .level = std.atomic.Value(u64).init(0),
            .last_update_ns = std.atomic.Value(i64).init(@intCast(std.time.nanoTimestamp())),
            .updating = std.atomic.Value(bool).init(false),
        };
    }

    /// Try to acquire tokens from the bucket.
    /// Returns true if allowed, false if rate limited.
    pub fn acquire(self: *Self, tokens: f64) bool {
        return self.acquireAt(tokens, @intCast(std.time.nanoTimestamp()));
    }

    /// Try to acquire tokens at a specific timestamp (for testing).
    pub fn acquireAt(self: *Self, tokens: f64, now_ns: i64) bool {
        // Try to acquire lock
        if (self.updating.cmpxchgStrong(false, true, .seq_cst, .seq_cst)) |_| {
            // Another thread is updating, try again later
            return false;
        }
        defer self.updating.store(false, .seq_cst);

        // Calculate leaked amount since last update
        const last_ns = self.last_update_ns.load(.seq_cst);
        const elapsed_ns = now_ns - last_ns;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

        // Current level (using u64 bits to store f64)
        const current_bits = self.level.load(.seq_cst);
        var current_level: f64 = @bitCast(current_bits);

        // Leak water from bucket
        const leaked = elapsed_secs * self.leak_rate;
        current_level = @max(0, current_level - leaked);

        // Try to add tokens
        const new_level = current_level + tokens;
        if (new_level > self.capacity) {
            // Bucket would overflow - rate limited
            return false;
        }

        // Update level and timestamp
        self.level.store(@bitCast(new_level), .seq_cst);
        self.last_update_ns.store(now_ns, .seq_cst);

        return true;
    }

    /// Get current fill level (0.0 to 1.0)
    pub fn fillLevel(self: *Self) f64 {
        const now_ns = std.time.nanoTimestamp();
        const last_ns = self.last_update_ns.load(.seq_cst);
        const elapsed_ns = now_ns - last_ns;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

        const current_bits = self.level.load(.seq_cst);
        var current_level: f64 = @bitCast(current_bits);

        const leaked = elapsed_secs * self.leak_rate;
        current_level = @max(0, current_level - leaked);

        return current_level / self.capacity;
    }

    /// Reset the bucket to empty
    pub fn reset(self: *Self) void {
        self.level.store(@bitCast(@as(f64, 0)), .seq_cst);
        self.last_update_ns.store(@intCast(std.time.nanoTimestamp()), .seq_cst);
    }
};

// ============================================================================
// Token Bucket Rate Limiter
// ============================================================================

/// A token bucket rate limiter.
///
/// Tokens are added at a constant rate up to a maximum capacity.
/// Requests consume tokens; if not enough tokens, request is denied.
/// Unlike leaky bucket, this allows controlled bursting.
pub const TokenBucket = struct {
    /// Maximum tokens the bucket can hold
    capacity: f64,
    /// Rate at which tokens are added (tokens per second)
    refill_rate: f64,
    /// Current number of tokens
    tokens: std.atomic.Value(u64),
    /// Last refill timestamp (nanoseconds)
    last_refill_ns: std.atomic.Value(i64),
    /// Lock for updates
    updating: std.atomic.Value(bool),

    const Self = @This();

    /// Create a new token bucket.
    /// - capacity: Maximum burst size
    /// - refill_rate: Tokens added per second
    pub fn init(capacity: f64, refill_rate: f64) Self {
        return .{
            .capacity = capacity,
            .refill_rate = refill_rate,
            .tokens = std.atomic.Value(u64).init(@bitCast(capacity)), // Start full
            .last_refill_ns = std.atomic.Value(i64).init(@intCast(std.time.nanoTimestamp())),
            .updating = std.atomic.Value(bool).init(false),
        };
    }

    /// Create a token bucket that starts empty.
    pub fn initEmpty(capacity: f64, refill_rate: f64) Self {
        return .{
            .capacity = capacity,
            .refill_rate = refill_rate,
            .tokens = std.atomic.Value(u64).init(@bitCast(@as(f64, 0))),
            .last_refill_ns = std.atomic.Value(i64).init(@intCast(std.time.nanoTimestamp())),
            .updating = std.atomic.Value(bool).init(false),
        };
    }

    /// Try to consume tokens from the bucket.
    /// Returns true if tokens were consumed, false if not enough tokens.
    pub fn consume(self: *Self, tokens: f64) bool {
        return self.consumeAt(tokens, @intCast(std.time.nanoTimestamp()));
    }

    /// Try to consume tokens at a specific timestamp (for testing).
    pub fn consumeAt(self: *Self, tokens_needed: f64, now_ns: i64) bool {
        // Try to acquire lock
        if (self.updating.cmpxchgStrong(false, true, .seq_cst, .seq_cst)) |_| {
            return false;
        }
        defer self.updating.store(false, .seq_cst);

        // Refill tokens based on elapsed time
        const last_ns = self.last_refill_ns.load(.seq_cst);
        const elapsed_ns = now_ns - last_ns;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

        const current_bits = self.tokens.load(.seq_cst);
        var current_tokens: f64 = @bitCast(current_bits);

        // Add tokens based on elapsed time
        const refilled = elapsed_secs * self.refill_rate;
        current_tokens = @min(self.capacity, current_tokens + refilled);

        // Check if we have enough tokens
        if (current_tokens < tokens_needed) {
            return false;
        }

        // Consume tokens
        current_tokens -= tokens_needed;
        self.tokens.store(@bitCast(current_tokens), .seq_cst);
        self.last_refill_ns.store(now_ns, .seq_cst);

        return true;
    }

    /// Get current token count
    pub fn availableTokens(self: *Self) f64 {
        const now_ns = std.time.nanoTimestamp();
        const last_ns = self.last_refill_ns.load(.seq_cst);
        const elapsed_ns = now_ns - last_ns;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

        const current_bits = self.tokens.load(.seq_cst);
        var current_tokens: f64 = @bitCast(current_bits);

        const refilled = elapsed_secs * self.refill_rate;
        current_tokens = @min(self.capacity, current_tokens + refilled);

        return current_tokens;
    }

    /// Time until n tokens are available (in seconds)
    pub fn timeUntilAvailable(self: *Self, tokens_needed: f64) f64 {
        const available = self.availableTokens();
        if (available >= tokens_needed) return 0;

        const deficit = tokens_needed - available;
        return deficit / self.refill_rate;
    }

    /// Reset bucket to full capacity
    pub fn reset(self: *Self) void {
        self.tokens.store(@bitCast(self.capacity), .seq_cst);
        self.last_refill_ns.store(@intCast(std.time.nanoTimestamp()), .seq_cst);
    }
};

// ============================================================================
// Sliding Window Rate Limiter
// ============================================================================

/// A sliding window rate limiter using multiple time slots.
///
/// More accurate than fixed windows, less bursty at window boundaries.
pub const SlidingWindowLimiter = struct {
    /// Counters for each slot
    slots: []std.atomic.Value(u64),
    /// Number of slots
    num_slots: usize,
    /// Duration of the entire window (nanoseconds)
    window_ns: u64,
    /// Duration of each slot (nanoseconds)
    slot_ns: u64,
    /// Maximum requests per window
    max_requests: u64,
    /// Current slot index
    current_slot: std.atomic.Value(usize),
    /// Timestamp of current slot start
    slot_start_ns: std.atomic.Value(i64),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new sliding window limiter.
    /// - window_seconds: Total window duration
    /// - num_slots: Number of slots (more = more accurate, more memory)
    /// - max_requests: Maximum requests allowed per window
    pub fn init(allocator: Allocator, window_seconds: u64, num_slots: usize, max_requests: u64) !Self {
        const slots = try allocator.alloc(std.atomic.Value(u64), num_slots);
        for (slots) |*slot| {
            slot.* = std.atomic.Value(u64).init(0);
        }

        const window_ns = window_seconds * std.time.ns_per_s;
        const slot_ns = window_ns / num_slots;

        return .{
            .slots = slots,
            .num_slots = num_slots,
            .window_ns = window_ns,
            .slot_ns = slot_ns,
            .max_requests = max_requests,
            .current_slot = std.atomic.Value(usize).init(0),
            .slot_start_ns = std.atomic.Value(i64).init(@intCast(std.time.nanoTimestamp())),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.slots);
    }

    /// Try to record a request. Returns true if allowed, false if rate limited.
    pub fn allow(self: *Self) bool {
        return self.allowN(1);
    }

    /// Try to record N requests.
    pub fn allowN(self: *Self, n: u64) bool {
        self.advanceSlots();

        // Count total requests in window
        var total: u64 = 0;
        for (self.slots) |*slot| {
            total += slot.load(.seq_cst);
        }

        if (total + n > self.max_requests) {
            return false;
        }

        // Record the request
        const slot_idx = self.current_slot.load(.seq_cst);
        _ = self.slots[slot_idx].fetchAdd(n, .seq_cst);

        return true;
    }

    /// Get current request count in window
    pub fn currentCount(self: *Self) u64 {
        self.advanceSlots();

        var total: u64 = 0;
        for (self.slots) |*slot| {
            total += slot.load(.seq_cst);
        }
        return total;
    }

    /// Get remaining requests allowed
    pub fn remaining(self: *Self) u64 {
        const current = self.currentCount();
        if (current >= self.max_requests) return 0;
        return self.max_requests - current;
    }

    /// Advance slots if needed based on elapsed time
    fn advanceSlots(self: *Self) void {
        const now_ns = std.time.nanoTimestamp();
        const start_ns = self.slot_start_ns.load(.seq_cst);
        const elapsed_ns: u64 = @intCast(@max(0, now_ns - start_ns));

        // How many slots have passed?
        const slots_passed = elapsed_ns / self.slot_ns;
        if (slots_passed == 0) return;

        const current_idx = self.current_slot.load(.seq_cst);

        // Clear passed slots
        const to_clear = @min(slots_passed, self.num_slots);
        for (0..to_clear) |i| {
            const idx = (current_idx + 1 + i) % self.num_slots;
            self.slots[idx].store(0, .seq_cst);
        }

        // Update current slot
        const new_idx = (current_idx + slots_passed) % self.num_slots;
        self.current_slot.store(new_idx, .seq_cst);

        // Update slot start time
        const new_start = start_ns + @as(i64, @intCast(slots_passed * self.slot_ns));
        self.slot_start_ns.store(new_start, .seq_cst);
    }

    /// Reset all counters
    pub fn reset(self: *Self) void {
        for (self.slots) |*slot| {
            slot.store(0, .seq_cst);
        }
        self.current_slot.store(0, .seq_cst);
        self.slot_start_ns.store(@intCast(std.time.nanoTimestamp()), .seq_cst);
    }
};

// ============================================================================
// Distributed Rate Limiter (for multi-key scenarios)
// ============================================================================

/// A rate limiter that tracks rates per key using a hash map.
pub const KeyedRateLimiter = struct {
    /// Token buckets per key
    buckets: std.StringHashMapUnmanaged(TokenBucket),
    /// Default capacity for new buckets
    default_capacity: f64,
    /// Default refill rate for new buckets
    default_refill_rate: f64,
    /// Maximum number of keys to track
    max_keys: usize,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new keyed rate limiter.
    pub fn init(allocator: Allocator, default_capacity: f64, default_refill_rate: f64, max_keys: usize) Self {
        return .{
            .buckets = .{},
            .default_capacity = default_capacity,
            .default_refill_rate = default_refill_rate,
            .max_keys = max_keys,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buckets.deinit(self.allocator);
    }

    /// Check if a request for the given key is allowed.
    pub fn allow(self: *Self, key: []const u8) !bool {
        return self.allowN(key, 1);
    }

    /// Check if N requests for the given key are allowed.
    pub fn allowN(self: *Self, key: []const u8, n: f64) !bool {
        // Get or create bucket for key
        if (self.buckets.getPtr(key)) |bucket| {
            return bucket.consume(n);
        }

        // Create new bucket if under limit
        if (self.buckets.count() >= self.max_keys) {
            return false; // Too many keys
        }

        var bucket = TokenBucket.init(self.default_capacity, self.default_refill_rate);
        const allowed = bucket.consume(n);
        try self.buckets.put(self.allocator, key, bucket);
        return allowed;
    }

    /// Get remaining tokens for a key
    pub fn remaining(self: *Self, key: []const u8) f64 {
        if (self.buckets.getPtr(key)) |bucket| {
            return bucket.availableTokens();
        }
        return self.default_capacity;
    }

    /// Remove a key from tracking
    pub fn remove(self: *Self, key: []const u8) void {
        _ = self.buckets.remove(key);
    }

    /// Clear all tracked keys
    pub fn clear(self: *Self) void {
        self.buckets.clearRetainingCapacity();
    }
};

// ============================================================================
// Additional Rate Calculation Functions
// ============================================================================

/// Exponentially weighted moving average rate calculation.
/// Gives more weight to recent observations.
pub fn ewmaRateCalc(components: RateComponents) f64 {
    const alpha = 0.3; // Smoothing factor
    const curr: f64 = @floatFromInt(components.curr_interval_count);
    const prev: f64 = @floatFromInt(components.prev_interval_count);

    // Extrapolate current interval if not complete
    const extrapolated_curr = if (components.elapsed_fraction > 0)
        curr / components.elapsed_fraction
    else
        0;

    return alpha * extrapolated_curr + (1.0 - alpha) * prev;
}

/// Peak rate calculation - returns the maximum of current and previous.
pub fn peakRateCalc(components: RateComponents) f64 {
    const curr: f64 = @floatFromInt(components.curr_interval_count);
    const prev: f64 = @floatFromInt(components.prev_interval_count);

    // Extrapolate current
    const extrapolated = if (components.elapsed_fraction > 0.1)
        curr / components.elapsed_fraction
    else
        curr;

    return @max(extrapolated, prev);
}

/// Minimum rate calculation - conservative estimate.
pub fn minRateCalc(components: RateComponents) f64 {
    const curr: f64 = @floatFromInt(components.curr_interval_count);
    const prev: f64 = @floatFromInt(components.prev_interval_count);

    return @min(curr, prev);
}

// ============================================================================
// Rate Limiter Result
// ============================================================================

/// Result from a rate limit check
pub const RateLimitResult = struct {
    /// Whether the request is allowed
    allowed: bool,
    /// Current request count/tokens
    current: f64,
    /// Maximum allowed
    limit: f64,
    /// Time until reset (seconds), 0 if allowed
    retry_after_secs: f64,
    /// Remaining capacity
    remaining: f64,

    pub fn allow() RateLimitResult {
        return .{
            .allowed = true,
            .current = 0,
            .limit = 0,
            .retry_after_secs = 0,
            .remaining = 0,
        };
    }

    pub fn deny(current: f64, limit: f64, retry_after: f64) RateLimitResult {
        return .{
            .allowed = false,
            .current = current,
            .limit = limit,
            .retry_after_secs = retry_after,
            .remaining = 0,
        };
    }
};

// ============================================================================
// Additional Tests
// ============================================================================

test "LeakyBucket basic" {
    var bucket = LeakyBucket.init(10.0, 1.0); // 10 capacity, 1 per second leak

    // Should allow requests up to capacity
    try testing.expect(bucket.acquire(5.0));
    try testing.expect(bucket.acquire(5.0));

    // Should deny when full
    try testing.expect(!bucket.acquire(1.0));
}

test "LeakyBucket reset" {
    var bucket = LeakyBucket.init(10.0, 1.0);

    _ = bucket.acquire(10.0);
    try testing.expect(!bucket.acquire(1.0));

    bucket.reset();
    try testing.expect(bucket.acquire(5.0));
}

test "TokenBucket basic" {
    var bucket = TokenBucket.init(10.0, 1.0); // 10 capacity, 1 per second refill

    // Should have full capacity initially
    try testing.expect(bucket.consume(5.0));
    try testing.expect(bucket.consume(5.0));

    // Should be empty now
    try testing.expect(!bucket.consume(1.0));
}

test "TokenBucket initEmpty" {
    var bucket = TokenBucket.initEmpty(10.0, 100.0); // Empty, fast refill

    // Should be empty initially
    const available = bucket.availableTokens();
    try testing.expect(available < 10.0); // Some time may have passed
}

test "TokenBucket timeUntilAvailable" {
    var bucket = TokenBucket.initEmpty(10.0, 10.0); // 10 tokens/sec

    // Need 5 tokens, should take about 0.5 seconds
    const time_needed = bucket.timeUntilAvailable(5.0);
    try testing.expect(time_needed <= 0.6); // Allow some margin
}

test "SlidingWindowLimiter basic" {
    var limiter = try SlidingWindowLimiter.init(testing.allocator, 1, 10, 100);
    defer limiter.deinit();

    // Should allow up to max_requests
    for (0..100) |_| {
        try testing.expect(limiter.allow());
    }

    // Should deny after limit
    try testing.expect(!limiter.allow());
}

test "SlidingWindowLimiter remaining" {
    var limiter = try SlidingWindowLimiter.init(testing.allocator, 1, 10, 100);
    defer limiter.deinit();

    try testing.expectEqual(@as(u64, 100), limiter.remaining());

    _ = limiter.allow();
    try testing.expectEqual(@as(u64, 99), limiter.remaining());
}

test "SlidingWindowLimiter reset" {
    var limiter = try SlidingWindowLimiter.init(testing.allocator, 1, 10, 100);
    defer limiter.deinit();

    for (0..50) |_| {
        _ = limiter.allow();
    }

    limiter.reset();
    try testing.expectEqual(@as(u64, 100), limiter.remaining());
}

test "KeyedRateLimiter basic" {
    var limiter = KeyedRateLimiter.init(testing.allocator, 10.0, 1.0, 100);
    defer limiter.deinit();

    // First request should be allowed
    try testing.expect(try limiter.allow("user1"));
    try testing.expect(try limiter.allow("user2"));
}

test "KeyedRateLimiter per-key limits" {
    var limiter = KeyedRateLimiter.init(testing.allocator, 5.0, 1.0, 100);
    defer limiter.deinit();

    // Exhaust user1's limit
    for (0..5) |_| {
        _ = try limiter.allow("user1");
    }

    // user1 should be denied
    try testing.expect(!try limiter.allow("user1"));

    // user2 should still be allowed
    try testing.expect(try limiter.allow("user2"));
}

test "ewmaRateCalc" {
    const components = RateComponents{
        .curr_interval_count = 100,
        .prev_interval_count = 80,
        .interval_ms = 1000,
        .elapsed_fraction = 0.5,
    };

    const result = ewmaRateCalc(components);
    // alpha=0.3: 0.3 * (100/0.5) + 0.7 * 80 = 0.3 * 200 + 56 = 60 + 56 = 116
    try testing.expect(result > 100 and result < 150);
}

test "peakRateCalc" {
    const components = RateComponents{
        .curr_interval_count = 50,
        .prev_interval_count = 100,
        .interval_ms = 1000,
        .elapsed_fraction = 0.5,
    };

    const result = peakRateCalc(components);
    // max(50/0.5, 100) = max(100, 100) = 100
    try testing.expectEqual(@as(f64, 100), result);
}

test "minRateCalc" {
    const components = RateComponents{
        .curr_interval_count = 50,
        .prev_interval_count = 100,
        .interval_ms = 1000,
        .elapsed_fraction = 0.5,
    };

    const result = minRateCalc(components);
    try testing.expectEqual(@as(f64, 50), result);
}

test "RateLimitResult" {
    const allowed = RateLimitResult.allow();
    try testing.expect(allowed.allowed);

    const denied = RateLimitResult.deny(100, 50, 10);
    try testing.expect(!denied.allowed);
    try testing.expectEqual(@as(f64, 100), denied.current);
    try testing.expectEqual(@as(f64, 50), denied.limit);
    try testing.expectEqual(@as(f64, 10), denied.retry_after_secs);
}
