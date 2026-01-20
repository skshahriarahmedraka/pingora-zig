//! pingora-zig: Subrequest Support
//!
//! Create and manage subrequests from existing sessions.
//! Enables internal requests, request splitting, and request chaining.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const http = @import("http.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Subrequest Types
// ============================================================================

/// Subrequest execution mode
pub const ExecutionMode = enum {
    /// Execute in-memory without network I/O
    in_memory,
    /// Execute as internal request through the proxy
    internal,
    /// Execute as external request to upstream
    external,
};

/// Subrequest state
pub const SubrequestState = enum {
    /// Created but not started
    created,
    /// Currently executing
    executing,
    /// Completed successfully
    completed,
    /// Failed with error
    failed,
    /// Cancelled
    cancelled,
};

/// Subrequest priority
pub const Priority = enum(u8) {
    /// Lowest priority
    low = 0,
    /// Normal priority (default)
    normal = 50,
    /// High priority
    high = 100,
    /// Critical - execute immediately
    critical = 255,
};

// ============================================================================
// Subrequest
// ============================================================================

/// A subrequest created from a parent request
pub const Subrequest = struct {
    /// Unique identifier
    id: u64,
    /// Parent request ID (null if no parent)
    parent_id: ?u64,
    /// Request headers
    request: http.RequestHeader,
    /// Request body (optional)
    body: ?[]const u8,
    /// Execution mode
    mode: ExecutionMode,
    /// Current state
    state: SubrequestState,
    /// Priority
    priority: Priority,
    /// Response (populated after completion)
    response: ?SubrequestResponse,
    /// Error message if failed
    error_message: ?[]const u8,
    /// Creation timestamp
    created_at: i64,
    /// Completion timestamp
    completed_at: ?i64,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new subrequest
    pub fn init(
        allocator: Allocator,
        method: http.Method,
        uri: []const u8,
        parent_id: ?u64,
    ) !Self {
        const request = try http.RequestHeader.build(allocator, method, uri, null);

        return .{
            .id = generateId(),
            .parent_id = parent_id,
            .request = request,
            .body = null,
            .mode = .internal,
            .state = .created,
            .priority = .normal,
            .response = null,
            .error_message = null,
            .created_at = std.time.timestamp(),
            .completed_at = null,
            .allocator = allocator,
        };
    }

    /// Create from an existing request (clone)
    pub fn fromRequest(
        allocator: Allocator,
        source: *const http.RequestHeader,
        parent_id: ?u64,
    ) !Self {
        var request = try http.RequestHeader.build(
            allocator,
            source.method,
            source.uri.raw,
            null,
        );

        // Copy headers
        for (source.headers.headers.items) |header| {
            try request.appendHeader(header.name.bytes, header.value);
        }

        return .{
            .id = generateId(),
            .parent_id = parent_id,
            .request = request,
            .body = null,
            .mode = .internal,
            .state = .created,
            .priority = .normal,
            .response = null,
            .error_message = null,
            .created_at = std.time.timestamp(),
            .completed_at = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.request.deinit();
        if (self.body) |b| {
            self.allocator.free(b);
        }
        if (self.response) |*r| {
            r.deinit();
        }
        if (self.error_message) |msg| {
            self.allocator.free(msg);
        }
    }

    /// Set request body
    pub fn setBody(self: *Self, body: []const u8) !void {
        if (self.body) |old| {
            self.allocator.free(old);
        }
        self.body = try self.allocator.dupe(u8, body);
    }

    /// Set execution mode
    pub fn setMode(self: *Self, mode: ExecutionMode) void {
        self.mode = mode;
    }

    /// Set priority
    pub fn setPriority(self: *Self, priority: Priority) void {
        self.priority = priority;
    }

    /// Add a header to the request
    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.request.appendHeader(name, value);
    }

    /// Mark subrequest as completed with response
    pub fn complete(self: *Self, response: SubrequestResponse) void {
        self.response = response;
        self.state = .completed;
        self.completed_at = std.time.timestamp();
    }

    /// Mark subrequest as failed
    pub fn fail(self: *Self, message: []const u8) !void {
        self.error_message = try self.allocator.dupe(u8, message);
        self.state = .failed;
        self.completed_at = std.time.timestamp();
    }

    /// Cancel the subrequest
    pub fn cancel(self: *Self) void {
        self.state = .cancelled;
        self.completed_at = std.time.timestamp();
    }

    /// Check if subrequest is finished (completed, failed, or cancelled)
    pub fn isFinished(self: *const Self) bool {
        return self.state == .completed or self.state == .failed or self.state == .cancelled;
    }

    /// Get execution duration in milliseconds (null if not finished)
    pub fn durationMs(self: *const Self) ?i64 {
        if (self.completed_at) |completed| {
            return (completed - self.created_at) * 1000;
        }
        return null;
    }

    fn generateId() u64 {
        const ts: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())) & 0xFFFFFFFFFFFF);
        return ts ^ (@as(u64, std.crypto.random.int(u16)) << 48);
    }
};

/// Response from a subrequest
pub const SubrequestResponse = struct {
    /// HTTP status code
    status_code: u16,
    /// Response headers
    headers: std.StringHashMapUnmanaged([]const u8),
    /// Response body
    body: ?[]u8,
    /// Allocator
    allocator: Allocator,

    pub fn init(allocator: Allocator, status_code: u16) SubrequestResponse {
        return .{
            .status_code = status_code,
            .headers = .{},
            .body = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SubrequestResponse) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit(self.allocator);
        if (self.body) |b| {
            self.allocator.free(b);
        }
    }

    /// Add a header
    pub fn addHeader(self: *SubrequestResponse, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.headers.put(self.allocator, name_copy, value_copy);
    }

    /// Set response body
    pub fn setBody(self: *SubrequestResponse, body: []const u8) !void {
        if (self.body) |old| {
            self.allocator.free(old);
        }
        self.body = try self.allocator.dupe(u8, body);
    }

    /// Check if response indicates success (2xx)
    pub fn isSuccess(self: *const SubrequestResponse) bool {
        return self.status_code >= 200 and self.status_code < 300;
    }
};

// ============================================================================
// Subrequest Handle
// ============================================================================

/// Handle for managing subrequest lifecycle
pub const SubrequestHandle = struct {
    /// The subrequest
    subrequest: *Subrequest,
    /// Whether this handle owns the subrequest
    owned: bool,
    /// Callback for when subrequest completes
    on_complete: ?*const fn (*Subrequest) void,
    /// Callback for when subrequest fails
    on_error: ?*const fn (*Subrequest, []const u8) void,

    const Self = @This();

    pub fn init(subrequest: *Subrequest, owned: bool) Self {
        return .{
            .subrequest = subrequest,
            .owned = owned,
            .on_complete = null,
            .on_error = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            self.subrequest.deinit();
            self.subrequest.allocator.destroy(self.subrequest);
        }
    }

    /// Set completion callback
    pub fn onComplete(self: *Self, callback: *const fn (*Subrequest) void) *Self {
        self.on_complete = callback;
        return self;
    }

    /// Set error callback
    pub fn onError(self: *Self, callback: *const fn (*Subrequest, []const u8) void) *Self {
        self.on_error = callback;
        return self;
    }

    /// Get the subrequest ID
    pub fn id(self: *const Self) u64 {
        return self.subrequest.id;
    }

    /// Check if subrequest is finished
    pub fn isFinished(self: *const Self) bool {
        return self.subrequest.isFinished();
    }

    /// Get the response (null if not completed)
    pub fn getResponse(self: *const Self) ?*const SubrequestResponse {
        if (self.subrequest.response) |*r| {
            return r;
        }
        return null;
    }

    /// Wait for subrequest to complete (blocking)
    pub fn wait(self: *Self, timeout_ms: ?u64) bool {
        const start = std.time.milliTimestamp();
        const deadline = if (timeout_ms) |t| start + @as(i64, @intCast(t)) else null;

        while (!self.isFinished()) {
            if (deadline) |d| {
                if (std.time.milliTimestamp() >= d) {
                    return false; // Timeout
                }
            }
            std.Thread.sleep(1_000_000); // 1ms
        }
        return true;
    }
};

// ============================================================================
// Subrequest Manager
// ============================================================================

/// Configuration for subrequest manager
pub const SubrequestManagerConfig = struct {
    /// Maximum concurrent subrequests
    max_concurrent: usize = 100,
    /// Maximum subrequests per parent request
    max_per_parent: usize = 10,
    /// Default timeout for subrequests (nanoseconds)
    default_timeout_ns: u64 = 30 * std.time.ns_per_s,
};

/// Manages subrequests for a proxy
pub const SubrequestManager = struct {
    /// Configuration
    config: SubrequestManagerConfig,
    /// Active subrequests
    active: std.AutoHashMapUnmanaged(u64, *Subrequest),
    /// Pending subrequests (waiting to execute)
    pending: std.ArrayListUnmanaged(*Subrequest),
    /// Statistics
    stats: Stats,
    /// Allocator
    allocator: Allocator,

    pub const Stats = struct {
        total_created: u64 = 0,
        total_completed: u64 = 0,
        total_failed: u64 = 0,
        total_cancelled: u64 = 0,
        current_active: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, config: SubrequestManagerConfig) Self {
        return .{
            .config = config,
            .active = .{},
            .pending = .{},
            .stats = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up active subrequests
        var iter = self.active.valueIterator();
        while (iter.next()) |sr| {
            sr.*.deinit();
            self.allocator.destroy(sr.*);
        }
        self.active.deinit(self.allocator);

        // Clean up pending subrequests
        for (self.pending.items) |sr| {
            sr.deinit();
            self.allocator.destroy(sr);
        }
        self.pending.deinit(self.allocator);
    }

    /// Create a new subrequest
    pub fn create(
        self: *Self,
        method: http.Method,
        uri: []const u8,
        parent_id: ?u64,
    ) !SubrequestHandle {
        // Check limits
        if (self.active.count() >= self.config.max_concurrent) {
            return error.TooManyConcurrentSubrequests;
        }

        if (parent_id) |pid| {
            const count = self.countByParent(pid);
            if (count >= self.config.max_per_parent) {
                return error.TooManySubrequestsPerParent;
            }
        }

        // Create subrequest
        const sr = try self.allocator.create(Subrequest);
        sr.* = try Subrequest.init(self.allocator, method, uri, parent_id);

        // Track it
        try self.active.put(self.allocator, sr.id, sr);
        self.stats.total_created += 1;
        self.stats.current_active += 1;

        return SubrequestHandle.init(sr, false);
    }

    /// Create a subrequest from an existing request
    pub fn createFromRequest(
        self: *Self,
        source: *const http.RequestHeader,
        parent_id: ?u64,
    ) !SubrequestHandle {
        // Check limits
        if (self.active.count() >= self.config.max_concurrent) {
            return error.TooManyConcurrentSubrequests;
        }

        // Create subrequest
        const sr = try self.allocator.create(Subrequest);
        sr.* = try Subrequest.fromRequest(self.allocator, source, parent_id);

        // Track it
        try self.active.put(self.allocator, sr.id, sr);
        self.stats.total_created += 1;
        self.stats.current_active += 1;

        return SubrequestHandle.init(sr, false);
    }

    /// Count subrequests by parent ID
    fn countByParent(self: *Self, parent_id: u64) usize {
        var count: usize = 0;
        var iter = self.active.valueIterator();
        while (iter.next()) |sr| {
            if (sr.*.parent_id) |pid| {
                if (pid == parent_id) {
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Complete a subrequest with a response
    pub fn complete(self: *Self, id: u64, response: SubrequestResponse) void {
        if (self.active.fetchRemove(id)) |kv| {
            const sr = kv.value;
            sr.complete(response);
            self.stats.total_completed += 1;
            self.stats.current_active -= 1;
            // Clean up the subrequest
            sr.deinit();
            self.allocator.destroy(sr);
        }
    }

    /// Fail a subrequest
    pub fn fail(self: *Self, id: u64, message: []const u8) void {
        if (self.active.fetchRemove(id)) |kv| {
            const sr = kv.value;
            sr.fail(message) catch {};
            self.stats.total_failed += 1;
            self.stats.current_active -= 1;
            // Clean up the subrequest
            sr.deinit();
            self.allocator.destroy(sr);
        }
    }

    /// Cancel a subrequest
    pub fn cancel(self: *Self, id: u64) void {
        if (self.active.fetchRemove(id)) |kv| {
            const sr = kv.value;
            sr.cancel();
            self.stats.total_cancelled += 1;
            self.stats.current_active -= 1;
            // Clean up the subrequest
            sr.deinit();
            self.allocator.destroy(sr);
        }
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }
};

// ============================================================================
// In-Memory Subrequest Handler
// ============================================================================

/// Handler for in-memory subrequests
pub const InMemoryHandler = struct {
    /// Registered handlers by path prefix
    handlers: std.StringHashMapUnmanaged(HandlerFn),
    /// Allocator
    allocator: Allocator,

    pub const HandlerFn = *const fn (*const Subrequest, Allocator) anyerror!SubrequestResponse;

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .handlers = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    /// Register a handler for a path prefix
    pub fn register(self: *Self, path_prefix: []const u8, handler: HandlerFn) !void {
        try self.handlers.put(self.allocator, path_prefix, handler);
    }

    /// Execute a subrequest in-memory
    pub fn execute(self: *Self, subrequest: *Subrequest) !void {
        subrequest.state = .executing;

        // Find matching handler
        const path = subrequest.request.uri.path;
        var best_match: ?HandlerFn = null;
        var best_len: usize = 0;

        var iter = self.handlers.iterator();
        while (iter.next()) |entry| {
            if (std.mem.startsWith(u8, path, entry.key_ptr.*)) {
                if (entry.key_ptr.len > best_len) {
                    best_len = entry.key_ptr.len;
                    best_match = entry.value_ptr.*;
                }
            }
        }

        if (best_match) |handler| {
            const response = handler(subrequest, self.allocator) catch |err| {
                try subrequest.fail(@errorName(err));
                return;
            };
            subrequest.complete(response);
        } else {
            // No handler found - return 404
            var response = SubrequestResponse.init(self.allocator, 404);
            try response.setBody("Not Found");
            subrequest.complete(response);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Subrequest init" {
    var sr = try Subrequest.init(testing.allocator, .GET, "/api/test", null);
    defer sr.deinit();

    try testing.expect(sr.id != 0);
    try testing.expect(sr.parent_id == null);
    try testing.expectEqual(SubrequestState.created, sr.state);
    try testing.expectEqual(ExecutionMode.internal, sr.mode);
    try testing.expect(!sr.isFinished());
}

test "Subrequest with parent" {
    var sr = try Subrequest.init(testing.allocator, .POST, "/api/data", 12345);
    defer sr.deinit();

    try testing.expectEqual(@as(u64, 12345), sr.parent_id.?);
}

test "Subrequest setBody" {
    var sr = try Subrequest.init(testing.allocator, .POST, "/api/data", null);
    defer sr.deinit();

    try sr.setBody("Hello, World!");
    try testing.expectEqualStrings("Hello, World!", sr.body.?);
}

test "Subrequest complete" {
    var sr = try Subrequest.init(testing.allocator, .GET, "/api/test", null);
    defer sr.deinit();

    var response = SubrequestResponse.init(testing.allocator, 200);
    try response.setBody("OK");

    sr.complete(response);

    try testing.expectEqual(SubrequestState.completed, sr.state);
    try testing.expect(sr.isFinished());
    try testing.expect(sr.response != null);
    try testing.expectEqual(@as(u16, 200), sr.response.?.status_code);
}

test "Subrequest fail" {
    var sr = try Subrequest.init(testing.allocator, .GET, "/api/test", null);
    defer sr.deinit();

    try sr.fail("Connection timeout");

    try testing.expectEqual(SubrequestState.failed, sr.state);
    try testing.expect(sr.isFinished());
    try testing.expectEqualStrings("Connection timeout", sr.error_message.?);
}

test "Subrequest cancel" {
    var sr = try Subrequest.init(testing.allocator, .GET, "/api/test", null);
    defer sr.deinit();

    sr.cancel();

    try testing.expectEqual(SubrequestState.cancelled, sr.state);
    try testing.expect(sr.isFinished());
}

test "SubrequestResponse" {
    var response = SubrequestResponse.init(testing.allocator, 200);
    defer response.deinit();

    try response.addHeader("Content-Type", "application/json");
    try response.setBody("{\"status\": \"ok\"}");

    try testing.expect(response.isSuccess());
    try testing.expectEqualStrings("{\"status\": \"ok\"}", response.body.?);
}

test "SubrequestResponse failure" {
    var response = SubrequestResponse.init(testing.allocator, 500);
    defer response.deinit();

    try testing.expect(!response.isSuccess());
}

test "SubrequestHandle" {
    var sr = try Subrequest.init(testing.allocator, .GET, "/test", null);
    var handle = SubrequestHandle.init(&sr, false);
    defer sr.deinit();

    try testing.expect(!handle.isFinished());
    try testing.expect(handle.getResponse() == null);
}

test "SubrequestManager create" {
    var manager = SubrequestManager.init(testing.allocator, .{});
    defer manager.deinit();

    const handle = try manager.create(.GET, "/api/test", null);
    _ = handle;

    try testing.expectEqual(@as(u64, 1), manager.stats.total_created);
    try testing.expectEqual(@as(u64, 1), manager.stats.current_active);
}

test "SubrequestManager limits" {
    var manager = SubrequestManager.init(testing.allocator, .{
        .max_concurrent = 2,
    });
    defer manager.deinit();

    _ = try manager.create(.GET, "/test1", null);
    _ = try manager.create(.GET, "/test2", null);

    // Third should fail
    try testing.expectError(error.TooManyConcurrentSubrequests, manager.create(.GET, "/test3", null));
}

test "SubrequestManager complete" {
    var manager = SubrequestManager.init(testing.allocator, .{});
    defer manager.deinit();

    const handle = try manager.create(.GET, "/test", null);
    const id = handle.id();

    const response = SubrequestResponse.init(testing.allocator, 200);
    manager.complete(id, response);

    try testing.expectEqual(@as(u64, 1), manager.stats.total_completed);
    try testing.expectEqual(@as(u64, 0), manager.stats.current_active);
}

test "InMemoryHandler" {
    var handler = InMemoryHandler.init(testing.allocator);
    defer handler.deinit();

    // Register a handler
    try handler.register("/api/", struct {
        fn handle(_: *const Subrequest, allocator: Allocator) !SubrequestResponse {
            var response = SubrequestResponse.init(allocator, 200);
            try response.setBody("API Response");
            return response;
        }
    }.handle);

    // Execute subrequest
    var sr = try Subrequest.init(testing.allocator, .GET, "/api/users", null);
    defer sr.deinit();
    sr.mode = .in_memory;

    try handler.execute(&sr);

    try testing.expectEqual(SubrequestState.completed, sr.state);
    try testing.expectEqual(@as(u16, 200), sr.response.?.status_code);
}

test "InMemoryHandler 404" {
    var handler = InMemoryHandler.init(testing.allocator);
    defer handler.deinit();

    // Execute subrequest with no matching handler
    var sr = try Subrequest.init(testing.allocator, .GET, "/unknown/path", null);
    defer sr.deinit();

    try handler.execute(&sr);

    try testing.expectEqual(SubrequestState.completed, sr.state);
    try testing.expectEqual(@as(u16, 404), sr.response.?.status_code);
}

test "Subrequest fromRequest" {
    var original = try http.RequestHeader.build(testing.allocator, .GET, "/original/path", null);
    defer original.deinit();
    try original.appendHeader("X-Custom", "value");

    var sr = try Subrequest.fromRequest(testing.allocator, &original, 999);
    defer sr.deinit();

    try testing.expectEqual(@as(u64, 999), sr.parent_id.?);
    try testing.expectEqual(http.Method.GET, sr.request.method);
}
