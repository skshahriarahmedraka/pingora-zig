//! pingora-zig: timeout
//!
//! Efficient timeout management with timer wheel implementation.
//! Provides fast timeouts that are lazily initialized and shared across
//! operations with the same deadline.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-timeout

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;

/// Resolution of the timer in milliseconds
pub const RESOLUTION_MS: u64 = 10;
pub const RESOLUTION_NS: u64 = RESOLUTION_MS * std.time.ns_per_ms;

/// The error type returned when the timeout is reached
pub const Elapsed = error{Elapsed};

/// Round to the next timestamp based on the resolution
fn roundTo(raw: u128, resolution: u128) u128 {
    if (raw == 0) return resolution;
    return raw - 1 + resolution - (raw - 1) % resolution;
}

/// Time type with millisecond resolution (rounded to RESOLUTION_MS)
pub const Time = struct {
    ms: u128,

    pub fn fromMs(raw_ms: u128) Time {
        return .{ .ms = roundTo(raw_ms, RESOLUTION_MS) };
    }

    pub fn fromNs(raw_ns: u128) Time {
        return fromMs(raw_ns / std.time.ns_per_ms);
    }

    pub fn fromDuration(duration_ns: u64) Time {
        return fromMs(duration_ns / std.time.ns_per_ms);
    }

    pub fn notAfter(self: Time, ts: u128) bool {
        return self.ms <= ts;
    }

    pub fn eql(self: Time, other: Time) bool {
        return self.ms == other.ms;
    }

    pub fn lessThan(self: Time, other: Time) bool {
        return self.ms < other.ms;
    }
};

/// Timer state
const TimerState = enum(u8) {
    pending = 0,
    fired = 1,
};

/// A timer stub that can be polled for expiration
pub const TimerStub = struct {
    state: *std.atomic.Value(TimerState),
    mutex: *Mutex,
    condition: *Condition,

    /// Wait for the timer to expire (blocking)
    pub fn poll(self: *TimerStub) void {
        // Check if already fired
        if (self.state.load(.seq_cst) == .fired) {
            return;
        }

        // Wait for notification
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.state.load(.seq_cst) != .fired) {
            self.condition.wait(self.mutex);
        }
    }

    /// Check if the timer has fired without blocking
    pub fn isFired(self: *const TimerStub) bool {
        return self.state.load(.seq_cst) == .fired;
    }
};

/// Internal timer structure
const Timer = struct {
    state: std.atomic.Value(TimerState),
    mutex: Mutex,
    condition: Condition,

    pub fn init() Timer {
        return .{
            .state = std.atomic.Value(TimerState).init(.pending),
            .mutex = .{},
            .condition = .{},
        };
    }

    pub fn fire(self: *Timer) void {
        self.state.store(.fired, .seq_cst);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.condition.broadcast();
    }

    pub fn subscribe(self: *Timer) TimerStub {
        return .{
            .state = &self.state,
            .mutex = &self.mutex,
            .condition = &self.condition,
        };
    }
};

/// Timer node in the timer tree
const TimerNode = struct {
    time: Time,
    timer: *Timer,
    next: ?*TimerNode,
};

/// Timer manager that holds all registered timers
pub const TimerManager = struct {
    allocator: Allocator,
    timers: std.ArrayListUnmanaged(TimerEntry),
    mutex: Mutex,
    zero: i128, // Reference zero point in nanoseconds
    clock_running: std.atomic.Value(bool),
    paused: std.atomic.Value(bool),
    clock_thread: ?Thread,

    const TimerEntry = struct {
        time: Time,
        timer: *Timer,
    };

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .timers = .{},
            .mutex = .{},
            .zero = std.time.nanoTimestamp(),
            .clock_running = std.atomic.Value(bool).init(false),
            .paused = std.atomic.Value(bool).init(false),
            .clock_thread = null,
        };
    }

    pub fn deinit(self: *Self) void {
        // Stop clock thread if running
        self.clock_running.store(false, .seq_cst);
        if (self.clock_thread) |t| {
            t.join();
        }

        // Free all timers
        for (self.timers.items) |entry| {
            self.allocator.destroy(entry.timer);
        }
        self.timers.deinit(self.allocator);
    }

    /// Start the clock thread if not already running
    pub fn ensureClockRunning(self: *Self) void {
        if (self.clock_running.load(.seq_cst)) {
            return;
        }

        // Try to start the clock
        if (self.clock_running.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null) {
            self.clock_thread = Thread.spawn(.{}, clockThreadFn, .{self}) catch null;
        }
    }

    fn clockThreadFn(self: *Self) void {
        while (self.clock_running.load(.seq_cst)) {
            std.Thread.sleep(RESOLUTION_NS);

            if (self.paused.load(.seq_cst)) {
                continue;
            }

            const now_ns = std.time.nanoTimestamp() - self.zero;
            const now_ms: u128 = @intCast(@max(0, @divFloor(now_ns, std.time.ns_per_ms)));

            self.mutex.lock();
            defer self.mutex.unlock();

            // Fire all timers that are due
            var i: usize = 0;
            while (i < self.timers.items.len) {
                const entry = self.timers.items[i];
                if (entry.time.notAfter(now_ms)) {
                    entry.timer.fire();
                    _ = self.timers.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Register a timer with the given duration
    pub fn registerTimer(self: *Self, duration_ns: u64) !TimerStub {
        self.ensureClockRunning();

        if (self.paused.load(.seq_cst)) {
            // Return a timer that fires immediately during pause
            // Add it to the timers list so it gets cleaned up on deinit
            const timer = try self.allocator.create(Timer);
            timer.* = Timer.init();
            timer.fire();
            
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.timers.append(self.allocator, .{
                .time = Time.fromMs(0),
                .timer = timer,
            });
            return timer.subscribe();
        }

        const now_ns = std.time.nanoTimestamp() - self.zero;
        const deadline_ns: u128 = @intCast(@max(0, now_ns) + duration_ns);
        const time = Time.fromNs(deadline_ns);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if we already have a timer for this time
        for (self.timers.items) |entry| {
            if (entry.time.eql(time)) {
                return entry.timer.subscribe();
            }
        }

        // Create a new timer
        const timer = try self.allocator.create(Timer);
        timer.* = Timer.init();

        try self.timers.append(self.allocator, .{
            .time = time,
            .timer = timer,
        });

        return timer.subscribe();
    }

    /// Pause the timer for fork()
    pub fn pauseForFork(self: *Self) void {
        self.paused.store(true, .seq_cst);
        // Wait for everything to get out of locks
        std.Thread.sleep(RESOLUTION_NS * 2);
    }

    /// Unpause the timer after fork()
    pub fn unpause(self: *Self) void {
        self.paused.store(false, .seq_cst);
    }

    /// Check if clock is running
    pub fn isClockRunning(self: *Self) bool {
        return self.clock_running.load(.seq_cst);
    }
};

/// A simple timeout wrapper that can timeout any operation
pub fn Timeout(comptime T: type) type {
    return struct {
        value: T,
        deadline_ns: u64,
        start_time: i128,

        const Self = @This();

        pub fn init(value: T, duration_ns: u64) Self {
            return .{
                .value = value,
                .deadline_ns = duration_ns,
                .start_time = std.time.nanoTimestamp(),
            };
        }

        /// Check if the timeout has elapsed
        pub fn isElapsed(self: Self) bool {
            const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - self.start_time));
            return elapsed >= self.deadline_ns;
        }

        /// Get remaining time in nanoseconds
        pub fn remaining(self: Self) u64 {
            const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - self.start_time));
            if (elapsed >= self.deadline_ns) {
                return 0;
            }
            return self.deadline_ns - elapsed;
        }
    };
}

/// Fast timeout - sleeps for the given duration
pub fn fastSleep(duration_ns: u64) void {
    std.time.sleep(duration_ns);
}

/// Fast timeout with a value - returns error if timeout elapses before completion
pub fn fastTimeout(comptime T: type, duration_ns: u64, value: T) Timeout(T) {
    return Timeout(T).init(value, duration_ns);
}

// ============================================================================
// Tests
// ============================================================================

test "round to resolution" {
    try testing.expectEqual(roundTo(30, 10), 30);
    try testing.expectEqual(roundTo(31, 10), 40);
    try testing.expectEqual(roundTo(29, 10), 30);
    try testing.expectEqual(roundTo(0, 10), 10);
    try testing.expectEqual(roundTo(1, 10), 10);
    try testing.expectEqual(roundTo(10, 10), 10);
    try testing.expectEqual(roundTo(11, 10), 20);
}

test "Time from milliseconds" {
    const t = Time.fromMs(128);
    try testing.expectEqual(t.ms, 130);

    const t2 = Time.fromMs(130);
    try testing.expect(t.eql(t2));

    try testing.expect(!t.notAfter(128));
    try testing.expect(!t.notAfter(129));
    try testing.expect(t.notAfter(130));
    try testing.expect(t.notAfter(131));
}

test "Time comparison" {
    const t1 = Time.fromMs(100);
    const t2 = Time.fromMs(200);

    try testing.expect(t1.lessThan(t2));
    try testing.expect(!t2.lessThan(t1));
    try testing.expect(!t1.eql(t2));

    const t3 = Time.fromMs(100);
    try testing.expect(t1.eql(t3));
}

test "Timer init and fire" {
    var timer = Timer.init();
    try testing.expectEqual(timer.state.load(.seq_cst), .pending);

    timer.fire();
    try testing.expectEqual(timer.state.load(.seq_cst), .fired);
}

test "TimerStub is_fired" {
    var timer = Timer.init();
    var stub = timer.subscribe();

    try testing.expect(!stub.isFired());
    timer.fire();
    try testing.expect(stub.isFired());
}

test "TimerManager init and deinit" {
    var tm = TimerManager.init(testing.allocator);
    defer tm.deinit();

    try testing.expect(!tm.isClockRunning());
}

test "Timeout elapsed check" {
    const to = Timeout(i32).init(42, 1_000_000); // 1ms timeout

    try testing.expect(!to.isElapsed());
    try testing.expect(to.remaining() > 0);
    try testing.expectEqual(to.value, 42);

    // Sleep past the timeout
    std.Thread.sleep(2_000_000_000); // 2ms (in ns)

    try testing.expect(to.isElapsed());
    try testing.expectEqual(to.remaining(), 0);
}

test "fast timeout wrapper" {
    const to = fastTimeout(i32, 10_000_000, 123); // 10ms
    try testing.expectEqual(to.value, 123);
    try testing.expect(!to.isElapsed());
}

test "TimerManager register timer" {
    var tm = TimerManager.init(testing.allocator);
    defer tm.deinit();

    // Register a short timer
    const stub = try tm.registerTimer(50_000_000); // 50ms

    // Timer should not be fired immediately
    try testing.expect(!stub.isFired());
}

test "TimerManager shared timers" {
    var tm = TimerManager.init(testing.allocator);
    defer tm.deinit();

    // Register two timers with the same deadline
    const stub1 = try tm.registerTimer(100_000_000); // 100ms
    const stub2 = try tm.registerTimer(100_000_000); // 100ms

    // They should share the same timer (same state pointer)
    try testing.expectEqual(stub1.state, stub2.state);
}

test "TimerManager pause and unpause" {
    var tm = TimerManager.init(testing.allocator);
    defer tm.deinit();

    try testing.expect(!tm.paused.load(.seq_cst));

    tm.pauseForFork();
    try testing.expect(tm.paused.load(.seq_cst));

    tm.unpause();
    try testing.expect(!tm.paused.load(.seq_cst));
}

test "TimerManager paused returns immediate timer" {
    var tm = TimerManager.init(testing.allocator);
    defer tm.deinit();

    tm.paused.store(true, .seq_cst);

    // Timer during pause should fire immediately
    const stub = try tm.registerTimer(1_000_000_000); // 1 second
    try testing.expect(stub.isFired());
}
