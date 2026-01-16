//! Pingora Runtime
//!
//! This module provides runtime primitives for concurrent task execution.
//! Unlike the original Pingora which uses tokio for async I/O, this implementation
//! provides simpler synchronous primitives suitable for Zig.
//!
//! Features:
//! - Task abstraction for deferred execution
//! - Thread-safe task queue
//! - Runtime configuration
//!
//! Note: Zig's async/await was removed in 0.11 and is being redesigned.
//! This module provides basic building blocks that can be extended.
//!
//! Ported from concepts in: https://github.com/cloudflare/pingora/tree/main/pingora-runtime

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const testing = std.testing;

// ============================================================================
// Runtime Configuration
// ============================================================================

/// Configuration for the runtime
pub const RuntimeConfig = struct {
    /// Number of worker threads
    threads: usize = 4,
    /// Name prefix for worker threads
    name: []const u8 = "pingora-worker",
    /// Stack size for worker threads (0 = default)
    stack_size: usize = 0,
};

// ============================================================================
// Task - A unit of work
// ============================================================================

/// A task that can be executed
pub const Task = struct {
    /// The function to execute
    func: *const fn (*anyopaque) void,
    /// Context/argument for the function
    context: *anyopaque,

    /// Execute the task
    pub fn execute(self: *const Task) void {
        self.func(self.context);
    }
};

// ============================================================================
// TaskQueue - Thread-safe queue for tasks
// ============================================================================

/// Thread-safe task queue (non-blocking)
pub const TaskQueue = struct {
    tasks: std.ArrayListUnmanaged(Task),
    mutex: Thread.Mutex,
    closed: bool,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .tasks = .{},
            .mutex = .{},
            .closed = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tasks.deinit(self.allocator);
    }

    /// Push a task to the queue
    pub fn push(self: *Self, task: Task) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return error.QueueClosed;

        try self.tasks.append(self.allocator, task);
    }

    /// Try to pop a task from the queue (non-blocking)
    /// Returns null if queue is empty or closed
    pub fn tryPop(self: *Self) ?Task {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tasks.items.len == 0 or self.closed) {
            return null;
        }

        return self.tasks.orderedRemove(0);
    }

    /// Close the queue
    pub fn close(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
    }

    /// Check if the queue is closed
    pub fn isClosed(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }

    /// Get the number of pending tasks
    pub fn len(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.tasks.items.len;
    }

    /// Check if empty
    pub fn isEmpty(self: *Self) bool {
        return self.len() == 0;
    }

    /// Drain all tasks and execute them
    pub fn drainAndExecute(self: *Self) usize {
        var count: usize = 0;
        while (self.tryPop()) |task| {
            task.execute();
            count += 1;
        }
        return count;
    }
};

// ============================================================================
// Runtime - High-level runtime interface
// ============================================================================

/// The main runtime configuration and task management
pub const Runtime = struct {
    config: RuntimeConfig,
    queue: TaskQueue,
    allocator: Allocator,

    const Self = @This();

    /// Create a new runtime with default configuration
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Create a new runtime with custom configuration
    pub fn initWithConfig(allocator: Allocator, config: RuntimeConfig) Self {
        return .{
            .config = config,
            .queue = TaskQueue.init(allocator),
            .allocator = allocator,
        };
    }

    /// Shutdown the runtime
    pub fn deinit(self: *Self) void {
        self.queue.close();
        self.queue.deinit();
    }

    /// Submit a task to the runtime
    pub fn submit(self: *Self, task: Task) !void {
        try self.queue.push(task);
    }

    /// Get the number of worker threads (from config)
    pub fn numWorkers(self: *const Self) usize {
        return self.config.threads;
    }

    /// Get the number of pending tasks
    pub fn pendingTasks(self: *Self) usize {
        return self.queue.len();
    }

    /// Run all pending tasks synchronously
    pub fn runPending(self: *Self) usize {
        return self.queue.drainAndExecute();
    }

    /// Check if there are pending tasks
    pub fn hasPendingTasks(self: *Self) bool {
        return !self.queue.isEmpty();
    }
};

// ============================================================================
// Handle - Reference to a runtime for spawning tasks
// ============================================================================

/// A handle to the runtime that can be used to spawn tasks
pub const Handle = struct {
    runtime: *Runtime,

    const Self = @This();

    pub fn submit(self: *const Self, task: Task) !void {
        try self.runtime.submit(task);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TaskQueue push and tryPop" {
    var queue = TaskQueue.init(testing.allocator);
    defer queue.deinit();

    var counter: i32 = 0;
    const task = Task{
        .func = struct {
            fn inc(ctx: *anyopaque) void {
                const c: *i32 = @ptrCast(@alignCast(ctx));
                c.* += 1;
            }
        }.inc,
        .context = @ptrCast(&counter),
    };

    try queue.push(task);
    try testing.expectEqual(queue.len(), 1);

    const popped = queue.tryPop();
    try testing.expect(popped != null);
    popped.?.execute();

    try testing.expectEqual(counter, 1);
}

test "TaskQueue close" {
    var queue = TaskQueue.init(testing.allocator);
    defer queue.deinit();

    queue.close();
    try testing.expect(queue.isClosed());

    // tryPop on closed queue returns null
    try testing.expect(queue.tryPop() == null);
}

test "Runtime init and deinit" {
    var rt = Runtime.init(testing.allocator);
    defer rt.deinit();

    try testing.expectEqual(rt.numWorkers(), 4);
}

test "Runtime with custom config" {
    var rt = Runtime.initWithConfig(testing.allocator, .{
        .threads = 2,
        .name = "custom-worker",
    });
    defer rt.deinit();

    try testing.expectEqual(rt.numWorkers(), 2);
}

test "TaskQueue multiple tasks" {
    var queue = TaskQueue.init(testing.allocator);
    defer queue.deinit();

    var counter: i32 = 0;
    const task = Task{
        .func = struct {
            fn inc(ctx: *anyopaque) void {
                const c: *i32 = @ptrCast(@alignCast(ctx));
                c.* += 1;
            }
        }.inc,
        .context = @ptrCast(&counter),
    };

    // Push multiple tasks
    for (0..5) |_| {
        try queue.push(task);
    }

    try testing.expectEqual(queue.len(), 5);

    // Drain and execute all
    const executed = queue.drainAndExecute();
    try testing.expectEqual(executed, 5);
    try testing.expectEqual(counter, 5);
}

test "Task execute" {
    var value: i32 = 10;

    const task = Task{
        .func = struct {
            fn double(ctx: *anyopaque) void {
                const v: *i32 = @ptrCast(@alignCast(ctx));
                v.* *= 2;
            }
        }.double,
        .context = @ptrCast(&value),
    };

    task.execute();
    try testing.expectEqual(value, 20);

    task.execute();
    try testing.expectEqual(value, 40);
}

test "Runtime submit and run" {
    var rt = Runtime.init(testing.allocator);
    defer rt.deinit();

    var counter: i32 = 0;
    const task = Task{
        .func = struct {
            fn inc(ctx: *anyopaque) void {
                const c: *i32 = @ptrCast(@alignCast(ctx));
                c.* += 1;
            }
        }.inc,
        .context = @ptrCast(&counter),
    };

    try rt.submit(task);
    try rt.submit(task);
    try rt.submit(task);

    try testing.expectEqual(rt.pendingTasks(), 3);
    try testing.expect(rt.hasPendingTasks());

    const executed = rt.runPending();
    try testing.expectEqual(executed, 3);
    try testing.expectEqual(counter, 3);
    try testing.expect(!rt.hasPendingTasks());
}

test "TaskQueue isEmpty" {
    var queue = TaskQueue.init(testing.allocator);
    defer queue.deinit();

    try testing.expect(queue.isEmpty());

    var dummy: i32 = 0;
    try queue.push(.{
        .func = struct {
            fn noop(_: *anyopaque) void {}
        }.noop,
        .context = @ptrCast(&dummy),
    });

    try testing.expect(!queue.isEmpty());
}
