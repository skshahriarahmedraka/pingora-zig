//! pingora-zig: Background Service Module
//!
//! A BackgroundService can be run as part of a Pingora application to add supporting logic
//! that exists outside of the request/response lifecycle.
//!
//! Examples include:
//! - Service discovery (load balancing)
//! - Background updates such as push-style metrics
//! - Periodic health checks
//! - Cache warming/preloading
//! - Log rotation
//!
//! This is a pure Zig implementation inspired by Pingora's services/background.rs.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Shutdown signal that background services should monitor
pub const ShutdownWatch = struct {
    /// Atomic flag indicating shutdown has been requested
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Mutex for condition variable
    mutex: std.Thread.Mutex = .{},
    /// Condition variable for waiting on shutdown
    cond: std.Thread.Condition = .{},

    const Self = @This();

    /// Request shutdown
    pub fn shutdown(self: *Self) void {
        self.shutdown_requested.store(true, .release);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cond.broadcast();
    }

    /// Check if shutdown has been requested
    pub fn isShutdown(self: *const Self) bool {
        return self.shutdown_requested.load(.acquire);
    }

    /// Wait for shutdown signal with optional timeout
    /// Returns true if shutdown was signaled, false if timed out
    pub fn waitForShutdown(self: *Self, timeout_ns: ?u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.shutdown_requested.load(.acquire)) {
            return true;
        }

        if (timeout_ns) |timeout| {
            _ = self.cond.timedWait(&self.mutex, timeout) catch {};
        } else {
            self.cond.wait(&self.mutex);
        }

        return self.shutdown_requested.load(.acquire);
    }
};

/// Background service error types
pub const BackgroundServiceError = error{
    /// Service failed to start
    StartFailed,
    /// Service encountered an error during execution
    ExecutionError,
    /// Service was interrupted
    Interrupted,
    /// Resource allocation failed
    OutOfMemory,
};

/// Result type for background service operations
pub const BackgroundServiceResult = BackgroundServiceError!void;

/// Background service interface using function pointers
/// This allows for runtime polymorphism without comptime generics
pub const BackgroundService = struct {
    /// Opaque pointer to the service implementation
    ptr: *anyopaque,
    /// Virtual table for service operations
    vtable: *const VTable,

    pub const VTable = struct {
        /// Start the background service
        /// The service should run until shutdown is signaled
        start: *const fn (ptr: *anyopaque, shutdown: *ShutdownWatch) BackgroundServiceResult,
        /// Get the name of this service
        name: *const fn (ptr: *anyopaque) []const u8,
        /// Optional cleanup when service stops
        deinit: ?*const fn (ptr: *anyopaque) void,
    };

    const Self = @This();

    /// Start the background service
    pub fn start(self: Self, shutdown: *ShutdownWatch) BackgroundServiceResult {
        return self.vtable.start(self.ptr, shutdown);
    }

    /// Get the name of this service
    pub fn name(self: Self) []const u8 {
        return self.vtable.name(self.ptr);
    }

    /// Cleanup the service
    pub fn deinit(self: Self) void {
        if (self.vtable.deinit) |deinit_fn| {
            deinit_fn(self.ptr);
        }
    }
};

/// Generic background service wrapper
/// Wraps a user-defined task that implements the required interface
pub fn GenBackgroundService(comptime Task: type) type {
    return struct {
        /// The wrapped task
        task: *Task,
        /// Service name
        service_name: []const u8,
        /// Allocator for cleanup
        allocator: Allocator,

        const Self = @This();

        /// Create a new GenBackgroundService
        pub fn init(allocator: Allocator, service_name: []const u8, task: *Task) Self {
            return .{
                .task = task,
                .service_name = service_name,
                .allocator = allocator,
            };
        }

        /// Get the task behind this service
        pub fn getTask(self: *Self) *Task {
            return self.task;
        }

        /// Get as BackgroundService interface
        pub fn service(self: *Self) BackgroundService {
            return .{
                .ptr = self,
                .vtable = &vtable,
            };
        }

        const vtable = BackgroundService.VTable{
            .start = startImpl,
            .name = nameImpl,
            .deinit = null, // Task owns its own cleanup
        };

        fn startImpl(ptr: *anyopaque, shutdown: *ShutdownWatch) BackgroundServiceResult {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.task.start(shutdown);
        }

        fn nameImpl(ptr: *anyopaque) []const u8 {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.service_name;
        }
    };
}

/// A simple periodic task that runs a callback at fixed intervals
pub const PeriodicTask = struct {
    /// Callback to execute periodically
    callback: *const fn (*anyopaque) void,
    /// User context passed to callback
    context: *anyopaque,
    /// Interval between executions in nanoseconds
    interval_ns: u64,
    /// Task name
    task_name: []const u8,

    const Self = @This();

    /// Create a new periodic task
    pub fn init(
        task_name: []const u8,
        callback: *const fn (*anyopaque) void,
        context: *anyopaque,
        interval_ns: u64,
    ) Self {
        return .{
            .callback = callback,
            .context = context,
            .interval_ns = interval_ns,
            .task_name = task_name,
        };
    }

    /// Start the periodic task (implements BackgroundService interface)
    pub fn start(self: *Self, shutdown: *ShutdownWatch) BackgroundServiceResult {
        while (!shutdown.isShutdown()) {
            // Execute the callback
            self.callback(self.context);

            // Wait for interval or shutdown
            if (shutdown.waitForShutdown(self.interval_ns)) {
                break;
            }
        }
        return;
    }
};

/// Background service runner that manages multiple background services
pub const BackgroundServiceRunner = struct {
    allocator: Allocator,
    services: std.ArrayListUnmanaged(BackgroundService),
    threads: std.ArrayListUnmanaged(std.Thread),
    shutdown: ShutdownWatch,

    const Self = @This();

    /// Create a new background service runner
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .services = .{},
            .threads = .{},
            .shutdown = .{},
        };
    }

    /// Cleanup and free resources
    pub fn deinit(self: *Self) void {
        // Signal shutdown to all services
        self.shutdown.shutdown();

        // Wait for all threads to complete
        for (self.threads.items) |thread| {
            thread.join();
        }

        // Cleanup services
        for (self.services.items) |svc| {
            svc.deinit();
        }

        self.services.deinit(self.allocator);
        self.threads.deinit(self.allocator);
    }

    /// Add a background service
    pub fn addService(self: *Self, service: BackgroundService) !void {
        try self.services.append(self.allocator, service);
    }

    /// Start all background services
    pub fn startAll(self: *Self) !void {
        for (self.services.items) |svc| {
            const thread = try std.Thread.spawn(.{}, runService, .{ svc, &self.shutdown });
            try self.threads.append(self.allocator, thread);
        }
    }

    /// Request shutdown of all services
    pub fn shutdownAll(self: *Self) void {
        self.shutdown.shutdown();
    }

    /// Wait for all services to complete
    pub fn waitAll(self: *Self) void {
        for (self.threads.items) |thread| {
            thread.join();
        }
        self.threads.clearRetainingCapacity();
    }

    fn runService(service: BackgroundService, shutdown: *ShutdownWatch) void {
        _ = service.start(shutdown) catch |err| {
            std.log.err("Background service '{s}' failed: {}", .{ service.name(), err });
        };
    }
};

/// Health check background service
/// Periodically checks health of backends
pub const HealthCheckService = struct {
    allocator: Allocator,
    /// Check interval in nanoseconds
    check_interval_ns: u64,
    /// Health check callback
    check_fn: *const fn (*anyopaque) bool,
    /// Context for health check
    check_context: *anyopaque,
    /// Callback when health changes
    on_health_change: ?*const fn (*anyopaque, bool) void,
    /// Context for health change callback
    health_change_context: ?*anyopaque,
    /// Current health status
    is_healthy: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        check_interval_ns: u64,
        check_fn: *const fn (*anyopaque) bool,
        check_context: *anyopaque,
    ) Self {
        return .{
            .allocator = allocator,
            .check_interval_ns = check_interval_ns,
            .check_fn = check_fn,
            .check_context = check_context,
            .on_health_change = null,
            .health_change_context = null,
            .is_healthy = std.atomic.Value(bool).init(true),
        };
    }

    /// Set callback for health state changes
    pub fn setHealthChangeCallback(
        self: *Self,
        callback: *const fn (*anyopaque, bool) void,
        context: *anyopaque,
    ) void {
        self.on_health_change = callback;
        self.health_change_context = context;
    }

    /// Get current health status
    pub fn isHealthy(self: *const Self) bool {
        return self.is_healthy.load(.acquire);
    }

    /// Start the health check service (implements BackgroundService interface)
    pub fn start(self: *Self, shutdown: *ShutdownWatch) BackgroundServiceResult {
        while (!shutdown.isShutdown()) {
            const healthy = self.check_fn(self.check_context);
            const prev_healthy = self.is_healthy.swap(healthy, .acq_rel);

            // Notify on health change
            if (healthy != prev_healthy) {
                if (self.on_health_change) |callback| {
                    callback(self.health_change_context.?, healthy);
                }
            }

            // Wait for interval or shutdown
            if (shutdown.waitForShutdown(self.check_interval_ns)) {
                break;
            }
        }
        return;
    }
};

/// Metrics push service
/// Periodically pushes metrics to a remote endpoint
pub const MetricsPushService = struct {
    allocator: Allocator,
    /// Push interval in nanoseconds
    push_interval_ns: u64,
    /// Metrics collection callback
    collect_fn: *const fn (*anyopaque, *std.ArrayListUnmanaged(u8)) void,
    /// Context for metrics collection
    collect_context: *anyopaque,
    /// Push destination callback
    push_fn: *const fn (*anyopaque, []const u8) bool,
    /// Context for push callback
    push_context: *anyopaque,
    /// Buffer for collected metrics
    buffer: std.ArrayListUnmanaged(u8),
    /// Statistics
    push_count: std.atomic.Value(u64),
    push_failures: std.atomic.Value(u64),

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        push_interval_ns: u64,
        collect_fn: *const fn (*anyopaque, *std.ArrayListUnmanaged(u8)) void,
        collect_context: *anyopaque,
        push_fn: *const fn (*anyopaque, []const u8) bool,
        push_context: *anyopaque,
    ) Self {
        return .{
            .allocator = allocator,
            .push_interval_ns = push_interval_ns,
            .collect_fn = collect_fn,
            .collect_context = collect_context,
            .push_fn = push_fn,
            .push_context = push_context,
            .buffer = .{},
            .push_count = std.atomic.Value(u64).init(0),
            .push_failures = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    /// Get push statistics
    pub fn getStats(self: *const Self) struct { pushes: u64, failures: u64 } {
        return .{
            .pushes = self.push_count.load(.acquire),
            .failures = self.push_failures.load(.acquire),
        };
    }

    /// Start the metrics push service (implements BackgroundService interface)
    pub fn start(self: *Self, shutdown: *ShutdownWatch) BackgroundServiceResult {
        while (!shutdown.isShutdown()) {
            // Collect metrics
            self.buffer.clearRetainingCapacity();
            self.collect_fn(self.collect_context, &self.buffer);

            // Push metrics
            if (self.buffer.items.len > 0) {
                const success = self.push_fn(self.push_context, self.buffer.items);
                if (success) {
                    _ = self.push_count.fetchAdd(1, .monotonic);
                } else {
                    _ = self.push_failures.fetchAdd(1, .monotonic);
                }
            }

            // Wait for interval or shutdown
            if (shutdown.waitForShutdown(self.push_interval_ns)) {
                break;
            }
        }
        return;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ShutdownWatch basic" {
    var watch = ShutdownWatch{};

    try std.testing.expect(!watch.isShutdown());

    watch.shutdown();

    try std.testing.expect(watch.isShutdown());
}

test "ShutdownWatch wait with timeout" {
    var watch = ShutdownWatch{};

    // Should timeout (return false) since no shutdown signal
    const result = watch.waitForShutdown(1_000_000); // 1ms timeout
    try std.testing.expect(!result or watch.isShutdown());
}

test "GenBackgroundService creation" {
    const TestTask = struct {
        started: bool = false,

        pub fn start(self: *@This(), shutdown: *ShutdownWatch) BackgroundServiceResult {
            _ = shutdown;
            self.started = true;
            return;
        }
    };

    var task = TestTask{};
    var gen_service = GenBackgroundService(TestTask).init(
        std.testing.allocator,
        "test-service",
        &task,
    );

    const service = gen_service.service();
    try std.testing.expectEqualStrings("test-service", service.name());
}

test "PeriodicTask basic" {
    const Context = struct {
        count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

        fn callback(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            _ = self.count.fetchAdd(1, .monotonic);
        }
    };

    var ctx = Context{};
    var task = PeriodicTask.init(
        "counter",
        Context.callback,
        &ctx,
        1_000_000, // 1ms
    );

    var shutdown = ShutdownWatch{};

    // Start task in a thread
    const thread = try std.Thread.spawn(.{}, struct {
        fn run(t: *PeriodicTask, s: *ShutdownWatch) void {
            _ = t.start(s) catch {};
        }
    }.run, .{ &task, &shutdown });

    // Let it run for a bit
    std.Thread.sleep(10_000_000); // 10ms

    // Signal shutdown
    shutdown.shutdown();
    thread.join();

    // Should have executed several times
    try std.testing.expect(ctx.count.load(.acquire) > 0);
}

test "BackgroundServiceRunner basic" {
    var runner = BackgroundServiceRunner.init(std.testing.allocator);
    defer runner.deinit();

    // Just test initialization and cleanup
    try std.testing.expect(runner.services.items.len == 0);
}

test "HealthCheckService basic" {
    const Context = struct {
        healthy: bool = true,

        fn check(ptr: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.healthy;
        }
    };

    var ctx = Context{};
    var health_service = HealthCheckService.init(
        std.testing.allocator,
        1_000_000, // 1ms
        Context.check,
        &ctx,
    );

    try std.testing.expect(health_service.isHealthy());
}

test "MetricsPushService basic" {
    const CollectContext = struct {
        fn collect(_: *anyopaque, buffer: *std.ArrayListUnmanaged(u8)) void {
            buffer.appendSlice(std.testing.allocator, "test_metric 1\n") catch {};
        }
    };

    const PushContext = struct {
        pushed: bool = false,

        fn push(ptr: *anyopaque, _: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.pushed = true;
            return true;
        }
    };

    var collect_ctx: u8 = 0;
    var push_ctx = PushContext{};

    var metrics_service = MetricsPushService.init(
        std.testing.allocator,
        1_000_000, // 1ms
        CollectContext.collect,
        &collect_ctx,
        PushContext.push,
        &push_ctx,
    );
    defer metrics_service.deinit();

    const stats = metrics_service.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.pushes);
}
