# Distributed Tracing

Pingora-Zig provides W3C Trace Context compatible distributed tracing for observability across services.

## Overview

Distributed tracing helps you:
- Track requests across multiple services
- Identify performance bottlenecks
- Debug distributed systems
- Understand request flow

## W3C Trace Context

Pingora-Zig implements the W3C Trace Context standard for trace propagation.

### Trace ID

A 128-bit (16 byte) identifier for the entire trace:

```zig
const pingora = @import("pingora");

// Generate a new trace ID
const trace_id = pingora.tracing.TraceId.generate();

// Parse from hex string
const parsed = try pingora.tracing.TraceId.fromHex("0af7651916cd43dd8448eb211c80319c");

// Convert to hex string
var buf: [32]u8 = undefined;
const hex = trace_id.toHex(&buf);
```

### Span ID

A 64-bit (8 byte) identifier for a single span:

```zig
const pingora = @import("pingora");

// Generate a new span ID
const span_id = pingora.tracing.SpanId.generate();

// Parse from hex string
const parsed = try pingora.tracing.SpanId.fromHex("b7ad6b7169203331");

// Convert to hex string
var buf: [16]u8 = undefined;
const hex = span_id.toHex(&buf);
```

### Trace Flags

```zig
const pingora = @import("pingora");

const flags = pingora.tracing.TraceFlags{
    .sampled = true,  // Whether this trace should be recorded
};

// Convert to/from byte
const byte = flags.toByte();  // 0x01 if sampled
const parsed = pingora.tracing.TraceFlags.fromByte(0x01);
```

## Trace Context

### Creating a Context

```zig
const pingora = @import("pingora");

pub fn createTraceContext() pingora.tracing.TraceContext {
    return .{
        .trace_id = pingora.tracing.TraceId.generate(),
        .span_id = pingora.tracing.SpanId.generate(),
        .parent_span_id = null,
        .flags = .{ .sampled = true },
    };
}
```

### Traceparent Header

The `traceparent` header format: `{version}-{trace-id}-{span-id}-{flags}`

```zig
const pingora = @import("pingora");

// Format as traceparent header
var buf: [64]u8 = undefined;
const traceparent = ctx.toTraceparent(&buf);
// Result: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

// Parse traceparent header
const incoming = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
if (pingora.tracing.TraceContext.fromTraceparent(incoming)) |parsed| {
    // Use parsed context
}
```

### Tracestate Header

The `tracestate` header carries vendor-specific trace data:

```zig
const pingora = @import("pingora");

// Parse tracestate
const tracestate = "vendor1=value1,vendor2=value2";
var state = try pingora.tracing.TraceState.parse(allocator, tracestate);
defer state.deinit();

// Get vendor value
if (state.get("vendor1")) |value| {
    std.debug.print("vendor1: {s}\n", .{value});
}

// Add vendor value
try state.put("myvendor", "myvalue");

// Format for header
const header = try state.format(allocator);
defer allocator.free(header);
```

## Span Management

### Creating Spans

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn createSpan(parent: ?pingora.tracing.TraceContext) pingora.tracing.Span {
    const trace_id = if (parent) |p| p.trace_id else pingora.tracing.TraceId.generate();
    const parent_span_id = if (parent) |p| p.span_id else null;

    return .{
        .trace_id = trace_id,
        .span_id = pingora.tracing.SpanId.generate(),
        .parent_span_id = parent_span_id,
        .name = "http_request",
        .start_time = std.time.nanoTimestamp(),
        .end_time = null,
        .status = .unset,
        .attributes = .{},
    };
}
```

### Span Attributes

```zig
const pingora = @import("pingora");

pub fn addSpanAttributes(span: *pingora.tracing.Span) !void {
    // HTTP semantic conventions
    try span.setAttribute("http.method", "GET");
    try span.setAttribute("http.url", "/api/users");
    try span.setAttribute("http.status_code", "200");
    try span.setAttribute("http.host", "api.example.com");
    
    // Custom attributes
    try span.setAttribute("user.id", "12345");
    try span.setAttribute("cache.hit", "true");
}
```

### Span Status

```zig
const pingora = @import("pingora");

const SpanStatus = enum {
    unset,
    ok,
    error_status,
};

pub fn setSpanStatus(span: *pingora.tracing.Span, status_code: u16) void {
    if (status_code >= 400) {
        span.status = .error_status;
    } else {
        span.status = .ok;
    }
}
```

## Tracer

### Configuration

```zig
const pingora = @import("pingora");

const TracerConfig = struct {
    /// Service name
    service_name: []const u8 = "pingora-proxy",
    
    /// Sampling rate (0.0 - 1.0)
    sample_rate: f64 = 1.0,
    
    /// Maximum spans per trace
    max_spans: usize = 1000,
    
    /// Export batch size
    batch_size: usize = 100,
    
    /// Export interval in milliseconds
    export_interval_ms: u64 = 5000,
};
```

### Sampling

```zig
const pingora = @import("pingora");

pub fn shouldSample(tracer: *pingora.tracing.Tracer, trace_id: pingora.tracing.TraceId) bool {
    // Deterministic sampling based on trace ID
    return tracer.shouldSample(trace_id);
}

// Always sample (rate = 1.0)
// Never sample (rate = 0.0)
// 10% sampling (rate = 0.1)
```

## Proxy Integration

### Extracting Context from Request

```zig
const pingora = @import("pingora");

pub fn extractTraceContext(headers: *const pingora.Headers) ?pingora.tracing.TraceContext {
    const traceparent = headers.get("traceparent") orelse return null;
    return pingora.tracing.TraceContext.fromTraceparent(traceparent);
}
```

### Injecting Context into Request

```zig
const pingora = @import("pingora");

pub fn injectTraceContext(
    headers: *pingora.Headers,
    ctx: pingora.tracing.TraceContext,
) !void {
    var buf: [64]u8 = undefined;
    const traceparent = ctx.toTraceparent(&buf);
    try headers.put("traceparent", traceparent);
}
```

### Full Request Tracing

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn traceRequest(
    allocator: std.mem.Allocator,
    request: *pingora.RequestHeader,
    response: *pingora.ResponseHeader,
) !void {
    // Extract or create trace context
    var ctx = extractTraceContext(&request.headers) orelse 
        pingora.tracing.TraceContext{
            .trace_id = pingora.tracing.TraceId.generate(),
            .span_id = pingora.tracing.SpanId.generate(),
            .parent_span_id = null,
            .flags = .{ .sampled = true },
        };

    // Create child span for this request
    const child_ctx = pingora.tracing.TraceContext{
        .trace_id = ctx.trace_id,
        .span_id = pingora.tracing.SpanId.generate(),
        .parent_span_id = ctx.span_id,
        .flags = ctx.flags,
    };

    // Inject into upstream request
    try injectTraceContext(&request.headers, child_ctx);

    // Add trace ID to response for debugging
    var trace_buf: [32]u8 = undefined;
    try response.headers.put("X-Trace-ID", ctx.trace_id.toHex(&trace_buf));
}
```

## Cache Tagging

Tag spans with cache information:

```zig
const pingora = @import("pingora");

pub fn tagCacheResult(span: *pingora.tracing.Span, hit: bool) !void {
    try span.setAttribute("cache.hit", if (hit) "true" else "false");
    
    if (hit) {
        try span.setAttribute("cache.status", "HIT");
    } else {
        try span.setAttribute("cache.status", "MISS");
    }
}
```

## Subrequest Tagging

Tag spans for subrequests:

```zig
const pingora = @import("pingora");

pub fn tagSubrequest(span: *pingora.tracing.Span, subrequest_type: []const u8) !void {
    try span.setAttribute("subrequest.type", subrequest_type);
    try span.setAttribute("span.kind", "client");
}
```

## Best Practices

1. **Propagate context** - Always forward traceparent/tracestate headers
2. **Use semantic conventions** - Follow OpenTelemetry naming conventions
3. **Sample appropriately** - 100% sampling may be too expensive in production
4. **Add useful attributes** - Include information that helps debugging
5. **Handle missing context** - Create new traces for requests without context
6. **Keep spans lightweight** - Don't add excessive attributes

## See Also

- [Prometheus Metrics](prom.md) - Metrics collection
- [Error Logging](error_log.md) - Logging configuration
- [Proxy Phases](phase.md) - Request lifecycle
