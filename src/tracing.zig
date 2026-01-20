//! pingora-zig: Tracing & Observability
//!
//! Distributed tracing support with span-based tracing, cache hit/miss tagging,
//! and subrequest tagging for comprehensive observability.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// Trace Context (W3C Trace Context format)
// ============================================================================

/// W3C Trace Context trace ID (16 bytes / 128 bits)
pub const TraceId = struct {
    bytes: [16]u8,

    pub fn generate() TraceId {
        var id: TraceId = undefined;
        std.crypto.random.bytes(&id.bytes);
        return id;
    }

    pub fn fromHex(hex: []const u8) !TraceId {
        if (hex.len != 32) return error.InvalidTraceId;
        var id: TraceId = undefined;
        _ = std.fmt.hexToBytes(&id.bytes, hex) catch return error.InvalidTraceId;
        return id;
    }

    pub fn toHex(self: *const TraceId, buf: *[32]u8) []const u8 {
        const charset = "0123456789abcdef";
        for (self.bytes, 0..) |byte, i| {
            buf[i * 2] = charset[byte >> 4];
            buf[i * 2 + 1] = charset[byte & 0x0f];
        }
        return buf;
    }

    pub fn isZero(self: *const TraceId) bool {
        for (self.bytes) |b| {
            if (b != 0) return false;
        }
        return true;
    }
};

/// W3C Trace Context span ID (8 bytes / 64 bits)
pub const SpanId = struct {
    bytes: [8]u8,

    pub fn generate() SpanId {
        var id: SpanId = undefined;
        std.crypto.random.bytes(&id.bytes);
        return id;
    }

    pub fn fromHex(hex: []const u8) !SpanId {
        if (hex.len != 16) return error.InvalidSpanId;
        var id: SpanId = undefined;
        _ = std.fmt.hexToBytes(&id.bytes, hex) catch return error.InvalidSpanId;
        return id;
    }

    pub fn toHex(self: *const SpanId, buf: *[16]u8) []const u8 {
        const charset = "0123456789abcdef";
        for (self.bytes, 0..) |byte, i| {
            buf[i * 2] = charset[byte >> 4];
            buf[i * 2 + 1] = charset[byte & 0x0f];
        }
        return buf;
    }

    pub fn isZero(self: *const SpanId) bool {
        for (self.bytes) |b| {
            if (b != 0) return false;
        }
        return true;
    }
};

/// Trace flags
pub const TraceFlags = packed struct {
    sampled: bool = false,
    _reserved: u7 = 0,

    pub fn toByte(self: TraceFlags) u8 {
        return @bitCast(self);
    }

    pub fn fromByte(byte: u8) TraceFlags {
        return @bitCast(byte);
    }
};

/// W3C Trace Context propagation header
pub const TraceContext = struct {
    /// Trace ID
    trace_id: TraceId,
    /// Parent span ID
    parent_span_id: SpanId,
    /// Trace flags
    flags: TraceFlags,
    /// Trace state (vendor-specific data)
    trace_state: ?[]const u8,

    /// Parse from traceparent header
    /// Format: 00-<trace_id>-<parent_id>-<flags>
    pub fn parseTraceparent(header: []const u8) !TraceContext {
        if (header.len < 55) return error.InvalidTraceparent;

        // Version check (must be 00)
        if (!std.mem.eql(u8, header[0..2], "00")) return error.UnsupportedVersion;
        if (header[2] != '-') return error.InvalidTraceparent;

        // Parse trace ID
        const trace_id = try TraceId.fromHex(header[3..35]);
        if (header[35] != '-') return error.InvalidTraceparent;

        // Parse parent span ID
        const parent_span_id = try SpanId.fromHex(header[36..52]);
        if (header[52] != '-') return error.InvalidTraceparent;

        // Parse flags
        const flags_byte = std.fmt.parseInt(u8, header[53..55], 16) catch return error.InvalidTraceparent;
        const flags = TraceFlags.fromByte(flags_byte);

        return .{
            .trace_id = trace_id,
            .parent_span_id = parent_span_id,
            .flags = flags,
            .trace_state = null,
        };
    }

    /// Format as traceparent header
    pub fn formatTraceparent(self: *const TraceContext, buf: []u8) ![]u8 {
        if (buf.len < 55) return error.BufferTooSmall;

        var trace_id_hex: [32]u8 = undefined;
        var span_id_hex: [16]u8 = undefined;

        _ = self.trace_id.toHex(&trace_id_hex);
        _ = self.parent_span_id.toHex(&span_id_hex);

        return std.fmt.bufPrint(buf, "00-{s}-{s}-{x:0>2}", .{
            trace_id_hex,
            span_id_hex,
            self.flags.toByte(),
        }) catch error.BufferTooSmall;
    }

    /// Create a new trace context (start of new trace)
    pub fn new() TraceContext {
        return .{
            .trace_id = TraceId.generate(),
            .parent_span_id = SpanId.generate(),
            .flags = .{ .sampled = true },
            .trace_state = null,
        };
    }

    /// Create child context (for creating child spans)
    pub fn child(self: *const TraceContext) TraceContext {
        return .{
            .trace_id = self.trace_id,
            .parent_span_id = SpanId.generate(),
            .flags = self.flags,
            .trace_state = self.trace_state,
        };
    }
};

// ============================================================================
// Span
// ============================================================================

/// Span kind
pub const SpanKind = enum {
    /// Internal operation
    internal,
    /// Server-side handling of request
    server,
    /// Client-side request to another service
    client,
    /// Producer (e.g., message queue producer)
    producer,
    /// Consumer (e.g., message queue consumer)
    consumer,
};

/// Span status
pub const SpanStatus = enum {
    /// Not set
    unset,
    /// Success
    ok,
    /// Error occurred
    err,
};

/// Span attribute value
pub const AttributeValue = union(enum) {
    string: []const u8,
    int: i64,
    float: f64,
    bool_val: bool,
    string_array: []const []const u8,
    int_array: []const i64,

    pub fn format(self: AttributeValue, buf: []u8) ![]u8 {
        return switch (self) {
            .string => |s| std.fmt.bufPrint(buf, "\"{s}\"", .{s}) catch error.BufferTooSmall,
            .int => |i| std.fmt.bufPrint(buf, "{d}", .{i}) catch error.BufferTooSmall,
            .float => |f| std.fmt.bufPrint(buf, "{d}", .{f}) catch error.BufferTooSmall,
            .bool_val => |b| std.fmt.bufPrint(buf, "{}", .{b}) catch error.BufferTooSmall,
            else => std.fmt.bufPrint(buf, "[array]", .{}) catch error.BufferTooSmall,
        };
    }
};

/// Span event (point-in-time occurrence)
pub const SpanEvent = struct {
    /// Event name
    name: []const u8,
    /// Timestamp (nanoseconds since epoch)
    timestamp_ns: i128,
    /// Event attributes
    attributes: std.StringHashMapUnmanaged(AttributeValue),
};

/// A trace span representing a unit of work
pub const Span = struct {
    /// Span name
    name: []const u8,
    /// Trace context
    context: TraceContext,
    /// Span ID
    span_id: SpanId,
    /// Parent span ID (if any)
    parent_span_id: ?SpanId,
    /// Span kind
    kind: SpanKind,
    /// Start time (nanoseconds since epoch)
    start_time_ns: i128,
    /// End time (nanoseconds since epoch, 0 if not ended)
    end_time_ns: i128,
    /// Status
    status: SpanStatus,
    /// Status message (if error)
    status_message: ?[]const u8,
    /// Attributes
    attributes: std.StringHashMapUnmanaged(AttributeValue),
    /// Events
    events: std.ArrayListUnmanaged(SpanEvent),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, name: []const u8, context: TraceContext, kind: SpanKind) Self {
        return .{
            .name = name,
            .context = context,
            .span_id = SpanId.generate(),
            .parent_span_id = context.parent_span_id,
            .kind = kind,
            .start_time_ns = std.time.nanoTimestamp(),
            .end_time_ns = 0,
            .status = .unset,
            .status_message = null,
            .attributes = .{},
            .events = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.attributes.deinit(self.allocator);
        for (self.events.items) |*event| {
            event.attributes.deinit(self.allocator);
        }
        self.events.deinit(self.allocator);
    }

    /// Set an attribute
    pub fn setAttribute(self: *Self, key: []const u8, value: AttributeValue) !void {
        try self.attributes.put(self.allocator, key, value);
    }

    /// Set string attribute
    pub fn setStringAttribute(self: *Self, key: []const u8, value: []const u8) !void {
        try self.setAttribute(key, .{ .string = value });
    }

    /// Set int attribute
    pub fn setIntAttribute(self: *Self, key: []const u8, value: i64) !void {
        try self.setAttribute(key, .{ .int = value });
    }

    /// Set bool attribute
    pub fn setBoolAttribute(self: *Self, key: []const u8, value: bool) !void {
        try self.setAttribute(key, .{ .bool_val = value });
    }

    /// Add an event
    pub fn addEvent(self: *Self, name: []const u8) !void {
        const event = SpanEvent{
            .name = name,
            .timestamp_ns = std.time.nanoTimestamp(),
            .attributes = .{},
        };
        try self.events.append(self.allocator, event);
    }

    /// Set status to OK
    pub fn setOk(self: *Self) void {
        self.status = .ok;
    }

    /// Set status to error
    pub fn setError(self: *Self, message: ?[]const u8) void {
        self.status = .err;
        self.status_message = message;
    }

    /// End the span
    pub fn end(self: *Self) void {
        if (self.end_time_ns == 0) {
            self.end_time_ns = std.time.nanoTimestamp();
        }
    }

    /// Get duration in nanoseconds
    pub fn durationNs(self: *const Self) i128 {
        const end_time = if (self.end_time_ns != 0) self.end_time_ns else std.time.nanoTimestamp();
        return end_time - self.start_time_ns;
    }

    /// Get duration in milliseconds
    pub fn durationMs(self: *const Self) i64 {
        return @intCast(@divFloor(self.durationNs(), std.time.ns_per_ms));
    }

    /// Check if span has ended
    pub fn hasEnded(self: *const Self) bool {
        return self.end_time_ns != 0;
    }
};

// ============================================================================
// Cache Tracing Tags
// ============================================================================

/// Cache operation result for tracing
pub const CacheResult = enum {
    hit,
    miss,
    stale,
    bypass,
    expired,
    error_result,

    pub fn toString(self: CacheResult) []const u8 {
        return switch (self) {
            .hit => "HIT",
            .miss => "MISS",
            .stale => "STALE",
            .bypass => "BYPASS",
            .expired => "EXPIRED",
            .error_result => "ERROR",
        };
    }
};

/// Add cache-related attributes to a span
pub fn tagCacheResult(span: *Span, result: CacheResult) !void {
    try span.setStringAttribute("cache.result", result.toString());
    try span.setBoolAttribute("cache.hit", result == .hit);
}

/// Add cache key attribute
pub fn tagCacheKey(span: *Span, key: []const u8) !void {
    try span.setStringAttribute("cache.key", key);
}

/// Add cache TTL attribute
pub fn tagCacheTtl(span: *Span, ttl_seconds: i64) !void {
    try span.setIntAttribute("cache.ttl_seconds", ttl_seconds);
}

// ============================================================================
// HTTP Tracing Tags
// ============================================================================

/// Add HTTP request attributes to a span
pub fn tagHttpRequest(span: *Span, method: []const u8, url: []const u8, host: ?[]const u8) !void {
    try span.setStringAttribute("http.method", method);
    try span.setStringAttribute("http.url", url);
    if (host) |h| {
        try span.setStringAttribute("http.host", h);
    }
}

/// Add HTTP response attributes to a span
pub fn tagHttpResponse(span: *Span, status_code: u16, content_length: ?i64) !void {
    try span.setIntAttribute("http.status_code", status_code);
    if (content_length) |len| {
        try span.setIntAttribute("http.response_content_length", len);
    }
}

/// Add HTTP error attributes
pub fn tagHttpError(span: *Span, error_type: []const u8, message: ?[]const u8) !void {
    try span.setStringAttribute("error.type", error_type);
    if (message) |m| {
        try span.setStringAttribute("error.message", m);
    }
    span.setError(message);
}

// ============================================================================
// Subrequest Tracing Tags
// ============================================================================

/// Add subrequest attributes to a span
pub fn tagSubrequest(span: *Span, subrequest_id: u64, parent_request_id: ?u64) !void {
    try span.setIntAttribute("subrequest.id", @intCast(subrequest_id));
    if (parent_request_id) |pid| {
        try span.setIntAttribute("subrequest.parent_id", @intCast(pid));
    }
    try span.setBoolAttribute("subrequest", true);
}

// ============================================================================
// Tracer
// ============================================================================

/// Tracer configuration
pub const TracerConfig = struct {
    /// Service name
    service_name: []const u8,
    /// Sample rate (0.0 to 1.0)
    sample_rate: f64 = 1.0,
    /// Maximum attributes per span
    max_attributes: u32 = 128,
    /// Maximum events per span
    max_events: u32 = 128,
    /// Whether to propagate trace context
    propagate: bool = true,
};

/// Span exporter interface
pub const SpanExporter = struct {
    ctx: *anyopaque,
    exportFn: *const fn (*anyopaque, []const *const Span) anyerror!void,

    pub fn exportSpans(self: *SpanExporter, spans: []const *const Span) !void {
        try self.exportFn(self.ctx, spans);
    }
};

/// Tracer for creating and managing spans
pub const Tracer = struct {
    config: TracerConfig,
    /// Active spans (for finding parent spans)
    active_spans: std.ArrayListUnmanaged(*Span),
    /// Completed spans waiting for export
    completed_spans: std.ArrayListUnmanaged(*Span),
    /// Exporter (optional)
    exporter: ?SpanExporter,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: TracerConfig) Self {
        return .{
            .config = config,
            .active_spans = .{},
            .completed_spans = .{},
            .exporter = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.active_spans.items) |span| {
            span.deinit();
            self.allocator.destroy(span);
        }
        self.active_spans.deinit(self.allocator);

        for (self.completed_spans.items) |span| {
            span.deinit();
            self.allocator.destroy(span);
        }
        self.completed_spans.deinit(self.allocator);
    }

    /// Set the span exporter
    pub fn setExporter(self: *Self, exporter: SpanExporter) void {
        self.exporter = exporter;
    }

    /// Start a new span
    pub fn startSpan(self: *Self, name: []const u8, parent_context: ?TraceContext, kind: SpanKind) !*Span {
        const context = if (parent_context) |ctx|
            ctx.child()
        else
            TraceContext.new();

        const span = try self.allocator.create(Span);
        span.* = Span.init(self.allocator, name, context, kind);

        // Add service name attribute
        try span.setStringAttribute("service.name", self.config.service_name);

        try self.active_spans.append(self.allocator, span);
        return span;
    }

    /// End a span and queue for export
    pub fn endSpan(self: *Self, span: *Span) !void {
        span.end();

        // Remove from active spans
        for (self.active_spans.items, 0..) |s, i| {
            if (s == span) {
                _ = self.active_spans.orderedRemove(i);
                break;
            }
        }

        // Add to completed spans
        try self.completed_spans.append(self.allocator, span);

        // Export if exporter is set and we have enough spans
        if (self.exporter != null and self.completed_spans.items.len >= 10) {
            try self.flush();
        }
    }

    /// Flush completed spans to exporter
    pub fn flush(self: *Self) !void {
        if (self.exporter) |*exporter| {
            const spans_to_export = self.completed_spans.items;
            const span_ptrs = try self.allocator.alloc(*const Span, spans_to_export.len);
            defer self.allocator.free(span_ptrs);

            for (spans_to_export, 0..) |span, i| {
                span_ptrs[i] = span;
            }

            try exporter.exportSpans(span_ptrs);

            // Clean up exported spans
            for (self.completed_spans.items) |span| {
                span.deinit();
                self.allocator.destroy(span);
            }
            self.completed_spans.clearRetainingCapacity();
        }
    }

    /// Check if tracing should be sampled
    pub fn shouldSample(self: *const Self) bool {
        if (self.config.sample_rate >= 1.0) return true;
        if (self.config.sample_rate <= 0.0) return false;

        const rand = std.crypto.random.float(f64);
        return rand < self.config.sample_rate;
    }
};

// ============================================================================
// Console Exporter (for debugging)
// ============================================================================

/// Simple console exporter for debugging
pub const ConsoleExporter = struct {
    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn toSpanExporter(self: *Self) SpanExporter {
        return .{
            .ctx = self,
            .exportFn = exportImpl,
        };
    }

    fn exportImpl(_: *anyopaque, spans: []const *const Span) anyerror!void {
        for (spans) |span| {
            var trace_buf: [32]u8 = undefined;
            var span_buf: [16]u8 = undefined;

            const trace_hex = span.context.trace_id.toHex(&trace_buf);
            const span_hex = span.span_id.toHex(&span_buf);

            std.debug.print("[SPAN] {s} trace={s} span={s} duration={d}ms status={s}\n", .{
                span.name,
                trace_hex,
                span_hex,
                span.durationMs(),
                @tagName(span.status),
            });
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TraceId generate and hex" {
    const id = TraceId.generate();
    try testing.expect(!id.isZero());

    var buf: [32]u8 = undefined;
    const hex = id.toHex(&buf);
    try testing.expectEqual(@as(usize, 32), hex.len);
}

test "TraceId fromHex" {
    const hex = "0af7651916cd43dd8448eb211c80319c";
    const id = try TraceId.fromHex(hex);

    var buf: [32]u8 = undefined;
    const result = id.toHex(&buf);
    try testing.expectEqualStrings(hex, result);
}

test "SpanId generate and hex" {
    const id = SpanId.generate();
    try testing.expect(!id.isZero());

    var buf: [16]u8 = undefined;
    const hex = id.toHex(&buf);
    try testing.expectEqual(@as(usize, 16), hex.len);
}

test "TraceFlags" {
    const flags = TraceFlags{ .sampled = true };
    try testing.expectEqual(@as(u8, 1), flags.toByte());

    const parsed = TraceFlags.fromByte(1);
    try testing.expect(parsed.sampled);
}

test "TraceContext parseTraceparent" {
    const header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    const ctx = try TraceContext.parseTraceparent(header);

    try testing.expect(ctx.flags.sampled);
}

test "TraceContext formatTraceparent" {
    const ctx = TraceContext.new();
    var buf: [64]u8 = undefined;
    const header = try ctx.formatTraceparent(&buf);

    try testing.expect(std.mem.startsWith(u8, header, "00-"));
    try testing.expectEqual(@as(usize, 55), header.len);
}

test "TraceContext child" {
    const parent = TraceContext.new();
    const child_ctx = parent.child();

    // Same trace ID
    try testing.expectEqualSlices(u8, &parent.trace_id.bytes, &child_ctx.trace_id.bytes);
    // Different span ID
    try testing.expect(!std.mem.eql(u8, &parent.parent_span_id.bytes, &child_ctx.parent_span_id.bytes));
}

test "Span basic" {
    const ctx = TraceContext.new();
    var span = Span.init(testing.allocator, "test-span", ctx, .server);
    defer span.deinit();

    try testing.expectEqualStrings("test-span", span.name);
    try testing.expectEqual(SpanKind.server, span.kind);
    try testing.expect(!span.hasEnded());

    span.end();
    try testing.expect(span.hasEnded());
    try testing.expect(span.durationNs() >= 0);
}

test "Span attributes" {
    const ctx = TraceContext.new();
    var span = Span.init(testing.allocator, "test", ctx, .internal);
    defer span.deinit();

    try span.setStringAttribute("http.method", "GET");
    try span.setIntAttribute("http.status_code", 200);
    try span.setBoolAttribute("cache.hit", true);

    try testing.expect(span.attributes.get("http.method") != null);
    try testing.expect(span.attributes.get("http.status_code") != null);
    try testing.expect(span.attributes.get("cache.hit") != null);
}

test "Span events" {
    const ctx = TraceContext.new();
    var span = Span.init(testing.allocator, "test", ctx, .internal);
    defer span.deinit();

    try span.addEvent("request_received");
    try span.addEvent("response_sent");

    try testing.expectEqual(@as(usize, 2), span.events.items.len);
}

test "Span status" {
    const ctx = TraceContext.new();
    var span = Span.init(testing.allocator, "test", ctx, .internal);
    defer span.deinit();

    try testing.expectEqual(SpanStatus.unset, span.status);

    span.setOk();
    try testing.expectEqual(SpanStatus.ok, span.status);

    span.setError("Connection failed");
    try testing.expectEqual(SpanStatus.err, span.status);
    try testing.expectEqualStrings("Connection failed", span.status_message.?);
}

test "CacheResult toString" {
    try testing.expectEqualStrings("HIT", CacheResult.hit.toString());
    try testing.expectEqualStrings("MISS", CacheResult.miss.toString());
    try testing.expectEqualStrings("STALE", CacheResult.stale.toString());
}

test "tagCacheResult" {
    const ctx = TraceContext.new();
    var span = Span.init(testing.allocator, "test", ctx, .internal);
    defer span.deinit();

    try tagCacheResult(&span, .hit);

    try testing.expect(span.attributes.get("cache.result") != null);
    try testing.expect(span.attributes.get("cache.hit") != null);
}

test "Tracer startSpan and endSpan" {
    var tracer = Tracer.init(testing.allocator, .{ .service_name = "test-service" });
    defer tracer.deinit();

    const span = try tracer.startSpan("test-operation", null, .server);
    try testing.expectEqual(@as(usize, 1), tracer.active_spans.items.len);

    try tracer.endSpan(span);
    try testing.expectEqual(@as(usize, 0), tracer.active_spans.items.len);
    try testing.expectEqual(@as(usize, 1), tracer.completed_spans.items.len);
}

test "Tracer shouldSample" {
    const tracer1 = Tracer.init(testing.allocator, .{ .service_name = "test", .sample_rate = 1.0 });
    try testing.expect(tracer1.shouldSample());

    const tracer2 = Tracer.init(testing.allocator, .{ .service_name = "test", .sample_rate = 0.0 });
    try testing.expect(!tracer2.shouldSample());
}

test "ConsoleExporter" {
    var exporter = ConsoleExporter.init();
    _ = exporter.toSpanExporter();
}
