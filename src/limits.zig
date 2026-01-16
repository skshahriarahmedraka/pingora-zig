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
