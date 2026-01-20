//! pingora-zig: HTTP Modules Framework
//!
//! A plugin system for request/response filters that allows modular
//! processing of HTTP traffic. Inspired by Pingora's module system.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const http = @import("http.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Module Context - Per-request module state
// ============================================================================

/// Per-request context for modules
/// Each module can store its own state in the context
pub const ModuleContext = struct {
    /// Module-specific data storage (keyed by module ID)
    data: std.StringHashMap(*anyopaque),
    /// Allocator for this context
    allocator: Allocator,
    /// Request start time
    request_start_ns: i128,
    /// Request ID (for tracing)
    request_id: u64,
    /// Whether the request should be aborted
    abort: bool,
    /// Abort reason if aborted
    abort_reason: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .data = std.StringHashMap(*anyopaque).init(allocator),
            .allocator = allocator,
            .request_start_ns = std.time.nanoTimestamp(),
            .request_id = generateRequestId(),
            .abort = false,
            .abort_reason = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.data.deinit();
        if (self.abort_reason) |reason| {
            self.allocator.free(reason);
        }
    }

    /// Store module-specific data
    pub fn set(self: *Self, module_id: []const u8, data: *anyopaque) !void {
        try self.data.put(module_id, data);
    }

    /// Retrieve module-specific data
    pub fn get(self: *Self, module_id: []const u8, comptime T: type) ?*T {
        if (self.data.get(module_id)) |ptr| {
            return @ptrCast(@alignCast(ptr));
        }
        return null;
    }

    /// Mark request for abort with reason
    pub fn abortRequest(self: *Self, reason: []const u8) !void {
        self.abort = true;
        self.abort_reason = try self.allocator.dupe(u8, reason);
    }

    /// Get elapsed time since request start
    pub fn elapsedNs(self: *const Self) i128 {
        return std.time.nanoTimestamp() - self.request_start_ns;
    }

    fn generateRequestId() u64 {
        const ts_i128 = std.time.nanoTimestamp();
        const ts: u64 = @truncate(@as(u128, @bitCast(ts_i128)) & 0xFFFFFFFFFFFF);
        return ts ^ (@as(u64, std.crypto.random.int(u16)) << 48);
    }
};

// ============================================================================
// Module Phase - When modules are invoked
// ============================================================================

/// Phases in the request/response lifecycle
pub const ModulePhase = enum {
    /// Before request is processed
    request_filter,
    /// After upstream selection, before connecting
    upstream_request_filter,
    /// When response headers are received from upstream
    response_header_filter,
    /// When response body chunks are received
    response_body_filter,
    /// After response is complete
    logging,
    /// On error conditions
    error_handler,
};

// ============================================================================
// Module Actions - Control flow from modules
// ============================================================================

/// Actions that modules can return to control request flow
pub const ModuleAction = union(enum) {
    /// Continue to next module/phase
    continue_processing,
    /// Skip remaining modules in this phase
    skip_phase,
    /// Return early with a response (short-circuit)
    early_response: http.ResponseHeader,
    /// Abort the request with an error
    abort: AbortInfo,
    /// Redirect to a different URL
    redirect: RedirectInfo,

    pub const AbortInfo = struct {
        status_code: u16,
        reason: []const u8,
    };

    pub const RedirectInfo = struct {
        location: []const u8,
        status_code: u16, // 301, 302, 307, 308
    };
};

// ============================================================================
// HTTP Module Trait
// ============================================================================

/// Function types for module callbacks
pub const RequestFilterFn = *const fn (*ModuleContext, *http.RequestHeader) anyerror!ModuleAction;
pub const ResponseHeaderFilterFn = *const fn (*ModuleContext, *http.RequestHeader, *http.ResponseHeader) anyerror!ModuleAction;
pub const ResponseBodyFilterFn = *const fn (*ModuleContext, []const u8, bool) anyerror!BodyFilterResult;
pub const LoggingFn = *const fn (*ModuleContext, *const http.RequestHeader, *const http.ResponseHeader) anyerror!void;
pub const ErrorHandlerFn = *const fn (*ModuleContext, anyerror) anyerror!?http.ResponseHeader;

/// Result from body filter
pub const BodyFilterResult = struct {
    /// Modified body data (null to keep original)
    data: ?[]const u8,
    /// Whether to continue processing
    action: ModuleAction,
};

/// HTTP Module interface
///
/// Modules can implement any subset of the filter functions.
/// Unimplemented filters default to pass-through behavior.
pub const HttpModule = struct {
    /// Unique module identifier
    id: []const u8,
    /// Human-readable name
    name: []const u8,
    /// Module priority (lower = runs first)
    priority: u32,
    /// Whether module is enabled
    enabled: bool,

    // Filter function pointers (null = not implemented)
    request_filter: ?RequestFilterFn,
    upstream_request_filter: ?RequestFilterFn,
    response_header_filter: ?ResponseHeaderFilterFn,
    response_body_filter: ?ResponseBodyFilterFn,
    logging: ?LoggingFn,
    error_handler: ?ErrorHandlerFn,

    /// Module initialization function (called once at startup)
    init_fn: ?*const fn (Allocator) anyerror!*anyopaque,
    /// Module cleanup function
    deinit_fn: ?*const fn (*anyopaque) void,
    /// Module state (set after init)
    state: ?*anyopaque,

    const Self = @This();

    pub fn create(
        id: []const u8,
        name: []const u8,
        priority: u32,
    ) Self {
        return .{
            .id = id,
            .name = name,
            .priority = priority,
            .enabled = true,
            .request_filter = null,
            .upstream_request_filter = null,
            .response_header_filter = null,
            .response_body_filter = null,
            .logging = null,
            .error_handler = null,
            .init_fn = null,
            .deinit_fn = null,
            .state = null,
        };
    }

    /// Builder pattern methods
    pub fn withRequestFilter(self: Self, f: RequestFilterFn) Self {
        var m = self;
        m.request_filter = f;
        return m;
    }

    pub fn withUpstreamRequestFilter(self: Self, f: RequestFilterFn) Self {
        var m = self;
        m.upstream_request_filter = f;
        return m;
    }

    pub fn withResponseHeaderFilter(self: Self, f: ResponseHeaderFilterFn) Self {
        var m = self;
        m.response_header_filter = f;
        return m;
    }

    pub fn withResponseBodyFilter(self: Self, f: ResponseBodyFilterFn) Self {
        var m = self;
        m.response_body_filter = f;
        return m;
    }

    pub fn withLogging(self: Self, f: LoggingFn) Self {
        var m = self;
        m.logging = f;
        return m;
    }

    pub fn withErrorHandler(self: Self, f: ErrorHandlerFn) Self {
        var m = self;
        m.error_handler = f;
        return m;
    }

    pub fn withInit(self: Self, init_f: *const fn (Allocator) anyerror!*anyopaque, deinit_f: *const fn (*anyopaque) void) Self {
        var m = self;
        m.init_fn = init_f;
        m.deinit_fn = deinit_f;
        return m;
    }
};

// ============================================================================
// Module Builder - Factory Pattern
// ============================================================================

/// Builder for creating HTTP modules
pub const HttpModuleBuilder = struct {
    module: HttpModule,

    const Self = @This();

    pub fn init(id: []const u8, name: []const u8) Self {
        return .{
            .module = HttpModule.create(id, name, 100),
        };
    }

    pub fn priority(self: *Self, p: u32) *Self {
        self.module.priority = p;
        return self;
    }

    pub fn requestFilter(self: *Self, f: RequestFilterFn) *Self {
        self.module.request_filter = f;
        return self;
    }

    pub fn upstreamRequestFilter(self: *Self, f: RequestFilterFn) *Self {
        self.module.upstream_request_filter = f;
        return self;
    }

    pub fn responseHeaderFilter(self: *Self, f: ResponseHeaderFilterFn) *Self {
        self.module.response_header_filter = f;
        return self;
    }

    pub fn responseBodyFilter(self: *Self, f: ResponseBodyFilterFn) *Self {
        self.module.response_body_filter = f;
        return self;
    }

    pub fn logging(self: *Self, f: LoggingFn) *Self {
        self.module.logging = f;
        return self;
    }

    pub fn errorHandler(self: *Self, f: ErrorHandlerFn) *Self {
        self.module.error_handler = f;
        return self;
    }

    pub fn build(self: *Self) HttpModule {
        return self.module;
    }
};

// ============================================================================
// Module Chain - Manages multiple modules
// ============================================================================

/// Chain of HTTP modules that processes requests
pub const ModuleChain = struct {
    modules: std.ArrayListUnmanaged(HttpModule),
    allocator: Allocator,
    sorted: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .modules = .{},
            .allocator = allocator,
            .sorted = false,
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up module states
        for (self.modules.items) |*module| {
            if (module.state) |state| {
                if (module.deinit_fn) |deinit_f| {
                    deinit_f(state);
                }
            }
        }
        self.modules.deinit(self.allocator);
    }

    /// Add a module to the chain
    pub fn addModule(self: *Self, module: HttpModule) !void {
        try self.modules.append(self.allocator, module);
        self.sorted = false;
    }

    /// Initialize all modules
    pub fn initModules(self: *Self) !void {
        for (self.modules.items) |*module| {
            if (module.init_fn) |init_f| {
                module.state = try init_f(self.allocator);
            }
        }
    }

    /// Sort modules by priority (call before processing)
    fn ensureSorted(self: *Self) void {
        if (self.sorted) return;

        std.mem.sort(HttpModule, self.modules.items, {}, struct {
            fn lessThan(_: void, a: HttpModule, b: HttpModule) bool {
                return a.priority < b.priority;
            }
        }.lessThan);

        self.sorted = true;
    }

    /// Run request filters on all modules
    pub fn runRequestFilters(
        self: *Self,
        ctx: *ModuleContext,
        req: *http.RequestHeader,
    ) !ModuleAction {
        self.ensureSorted();

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.request_filter) |filter| {
                const action = try filter(ctx, req);
                switch (action) {
                    .continue_processing => continue,
                    .skip_phase => return .continue_processing,
                    else => return action,
                }
            }
        }

        return .continue_processing;
    }

    /// Run upstream request filters
    pub fn runUpstreamRequestFilters(
        self: *Self,
        ctx: *ModuleContext,
        req: *http.RequestHeader,
    ) !ModuleAction {
        self.ensureSorted();

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.upstream_request_filter) |filter| {
                const action = try filter(ctx, req);
                switch (action) {
                    .continue_processing => continue,
                    .skip_phase => return .continue_processing,
                    else => return action,
                }
            }
        }

        return .continue_processing;
    }

    /// Run response header filters
    pub fn runResponseHeaderFilters(
        self: *Self,
        ctx: *ModuleContext,
        req: *http.RequestHeader,
        resp: *http.ResponseHeader,
    ) !ModuleAction {
        self.ensureSorted();

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.response_header_filter) |filter| {
                const action = try filter(ctx, req, resp);
                switch (action) {
                    .continue_processing => continue,
                    .skip_phase => return .continue_processing,
                    else => return action,
                }
            }
        }

        return .continue_processing;
    }

    /// Run response body filters
    pub fn runResponseBodyFilters(
        self: *Self,
        ctx: *ModuleContext,
        body: []const u8,
        is_final: bool,
    ) !BodyFilterResult {
        self.ensureSorted();

        var current_body = body;

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.response_body_filter) |filter| {
                const result = try filter(ctx, current_body, is_final);
                if (result.data) |new_data| {
                    current_body = new_data;
                }
                switch (result.action) {
                    .continue_processing => continue,
                    else => return .{
                        .data = if (current_body.ptr != body.ptr) current_body else null,
                        .action = result.action,
                    },
                }
            }
        }

        return .{
            .data = if (current_body.ptr != body.ptr) current_body else null,
            .action = .continue_processing,
        };
    }

    /// Run logging on all modules
    pub fn runLogging(
        self: *Self,
        ctx: *ModuleContext,
        req: *const http.RequestHeader,
        resp: *const http.ResponseHeader,
    ) !void {
        self.ensureSorted();

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.logging) |log_fn| {
                try log_fn(ctx, req, resp);
            }
        }
    }

    /// Run error handlers
    pub fn runErrorHandlers(
        self: *Self,
        ctx: *ModuleContext,
        err: anyerror,
    ) !?http.ResponseHeader {
        self.ensureSorted();

        for (self.modules.items) |module| {
            if (!module.enabled) continue;
            if (module.error_handler) |handler| {
                if (try handler(ctx, err)) |resp| {
                    return resp;
                }
            }
        }

        return null;
    }
};

// ============================================================================
// Built-in Modules
// ============================================================================

/// Request logging module
pub const RequestLoggingModule = struct {
    pub fn create() HttpModule {
        return HttpModule.create("request_logging", "Request Logging", 1000)
            .withLogging(logRequest);
    }

    fn logRequest(ctx: *ModuleContext, req: *const http.RequestHeader, resp: *const http.ResponseHeader) !void {
        const elapsed_ms = @divFloor(ctx.elapsedNs(), std.time.ns_per_ms);
        _ = req;
        _ = resp;
        _ = elapsed_ms;
        // In a real implementation, this would log to a file or logging system
        // std.log.info("{d} {s} {s} {d} {d}ms", .{
        //     ctx.request_id, req.method.asString(), req.uri, resp.status.code, elapsed_ms
        // });
    }
};

/// Request ID module - adds X-Request-ID header
pub const RequestIdModule = struct {
    pub fn create() HttpModule {
        return HttpModule.create("request_id", "Request ID", 10)
            .withRequestFilter(addRequestId)
            .withResponseHeaderFilter(addResponseRequestId);
    }

    fn addRequestId(ctx: *ModuleContext, req: *http.RequestHeader) !ModuleAction {
        // Add request ID to request if not present
        if (req.headers.get("x-request-id") == null) {
            var buf: [32]u8 = undefined;
            const id_str = std.fmt.bufPrint(&buf, "{x}", .{ctx.request_id}) catch return .continue_processing;
            try req.appendHeader("X-Request-ID", id_str);
        }
        return .continue_processing;
    }

    fn addResponseRequestId(ctx: *ModuleContext, req: *http.RequestHeader, resp: *http.ResponseHeader) !ModuleAction {
        _ = req;
        var buf: [32]u8 = undefined;
        const id_str = std.fmt.bufPrint(&buf, "{x}", .{ctx.request_id}) catch return .continue_processing;
        try resp.appendHeader("X-Request-ID", id_str);
        return .continue_processing;
    }
};

/// Security headers module
pub const SecurityHeadersModule = struct {
    pub fn create() HttpModule {
        return HttpModule.create("security_headers", "Security Headers", 50)
            .withResponseHeaderFilter(addSecurityHeaders);
    }

    fn addSecurityHeaders(_: *ModuleContext, _: *http.RequestHeader, resp: *http.ResponseHeader) !ModuleAction {
        // Add security headers if not present
        if (resp.headers.get("x-content-type-options") == null) {
            try resp.appendHeader("X-Content-Type-Options", "nosniff");
        }
        if (resp.headers.get("x-frame-options") == null) {
            try resp.appendHeader("X-Frame-Options", "SAMEORIGIN");
        }
        if (resp.headers.get("x-xss-protection") == null) {
            try resp.appendHeader("X-XSS-Protection", "1; mode=block");
        }
        return .continue_processing;
    }
};

/// CORS module
pub const CorsModule = struct {
    pub const Config = struct {
        allowed_origins: []const []const u8 = &[_][]const u8{"*"},
        allowed_methods: []const u8 = "GET, POST, PUT, DELETE, OPTIONS",
        allowed_headers: []const u8 = "Content-Type, Authorization",
        max_age: u32 = 86400,
    };

    pub fn create() HttpModule {
        return HttpModule.create("cors", "CORS", 20)
            .withRequestFilter(handlePreflight)
            .withResponseHeaderFilter(addCorsHeaders);
    }

    fn handlePreflight(_: *ModuleContext, req: *http.RequestHeader) !ModuleAction {
        if (req.method == .OPTIONS) {
            // Return early for preflight
            var resp = http.ResponseHeader.init(std.heap.page_allocator, 204);
            try resp.appendHeader("Access-Control-Allow-Origin", "*");
            try resp.appendHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            try resp.appendHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
            try resp.appendHeader("Access-Control-Max-Age", "86400");
            return .{ .early_response = resp };
        }
        return .continue_processing;
    }

    fn addCorsHeaders(_: *ModuleContext, _: *http.RequestHeader, resp: *http.ResponseHeader) !ModuleAction {
        if (resp.headers.get("access-control-allow-origin") == null) {
            try resp.appendHeader("Access-Control-Allow-Origin", "*");
        }
        return .continue_processing;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ModuleContext basic operations" {
    var ctx = ModuleContext.init(testing.allocator);
    defer ctx.deinit();

    try testing.expect(ctx.request_id != 0);
    try testing.expect(!ctx.abort);

    // Test abort
    try ctx.abortRequest("test abort");
    try testing.expect(ctx.abort);
    try testing.expectEqualStrings("test abort", ctx.abort_reason.?);
}

test "HttpModule builder pattern" {
    const filter = struct {
        fn dummy(_: *ModuleContext, _: *http.RequestHeader) anyerror!ModuleAction {
            return .continue_processing;
        }
    }.dummy;

    const module = HttpModule.create("test", "Test Module", 100)
        .withRequestFilter(filter);

    try testing.expectEqualStrings("test", module.id);
    try testing.expectEqualStrings("Test Module", module.name);
    try testing.expectEqual(@as(u32, 100), module.priority);
    try testing.expect(module.request_filter != null);
}

test "HttpModuleBuilder" {
    var builder = HttpModuleBuilder.init("test", "Test");
    const module = builder
        .priority(50)
        .build();

    try testing.expectEqualStrings("test", module.id);
    try testing.expectEqual(@as(u32, 50), module.priority);
}

test "ModuleChain add and sort" {
    var chain = ModuleChain.init(testing.allocator);
    defer chain.deinit();

    // Add modules in reverse priority order
    try chain.addModule(HttpModule.create("low", "Low Priority", 100));
    try chain.addModule(HttpModule.create("high", "High Priority", 10));
    try chain.addModule(HttpModule.create("mid", "Mid Priority", 50));

    chain.ensureSorted();

    // Should be sorted by priority
    try testing.expectEqualStrings("high", chain.modules.items[0].id);
    try testing.expectEqualStrings("mid", chain.modules.items[1].id);
    try testing.expectEqualStrings("low", chain.modules.items[2].id);
}

test "ModuleChain runRequestFilters" {
    var chain = ModuleChain.init(testing.allocator);
    defer chain.deinit();

    const filter = struct {
        fn pass(_: *ModuleContext, req: *http.RequestHeader) anyerror!ModuleAction {
            try req.appendHeader("X-Filtered", "true");
            return .continue_processing;
        }
    }.pass;

    try chain.addModule(HttpModule.create("test", "Test", 100).withRequestFilter(filter));

    var ctx = ModuleContext.init(testing.allocator);
    defer ctx.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();

    const action = try chain.runRequestFilters(&ctx, &req);
    try testing.expect(action == .continue_processing);
    try testing.expect(req.headers.get("X-Filtered") != null);
}

test "ModuleChain early response" {
    var chain = ModuleChain.init(testing.allocator);
    defer chain.deinit();

    const filter = struct {
        fn block(_: *ModuleContext, _: *http.RequestHeader) anyerror!ModuleAction {
            const resp = http.ResponseHeader.init(std.heap.page_allocator, 403);
            return .{ .early_response = resp };
        }
    }.block;

    try chain.addModule(HttpModule.create("block", "Blocker", 100).withRequestFilter(filter));

    var ctx = ModuleContext.init(testing.allocator);
    defer ctx.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();

    const action = try chain.runRequestFilters(&ctx, &req);
    switch (action) {
        .early_response => |resp| {
            try testing.expectEqual(@as(u16, 403), resp.status.code);
        },
        else => try testing.expect(false),
    }
}

test "RequestIdModule" {
    var chain = ModuleChain.init(testing.allocator);
    defer chain.deinit();

    try chain.addModule(RequestIdModule.create());

    var ctx = ModuleContext.init(testing.allocator);
    defer ctx.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();

    _ = try chain.runRequestFilters(&ctx, &req);

    // Request should have X-Request-ID header
    try testing.expect(req.headers.get("X-Request-ID") != null);
}

test "SecurityHeadersModule" {
    var chain = ModuleChain.init(testing.allocator);
    defer chain.deinit();

    try chain.addModule(SecurityHeadersModule.create());

    var ctx = ModuleContext.init(testing.allocator);
    defer ctx.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();

    var resp = http.ResponseHeader.init(testing.allocator, 200);
    defer resp.deinit();

    _ = try chain.runResponseHeaderFilters(&ctx, &req, &resp);

    // Response should have security headers
    try testing.expect(resp.headers.get("X-Content-Type-Options") != null);
    try testing.expect(resp.headers.get("X-Frame-Options") != null);
    try testing.expect(resp.headers.get("X-XSS-Protection") != null);
}
