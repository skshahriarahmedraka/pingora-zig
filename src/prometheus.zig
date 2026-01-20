//! pingora-zig: Prometheus Metrics Module
//!
//! Provides Prometheus-compatible metrics collection and export.
//! Supports counters, gauges, histograms, and text format encoding.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// Metric Types
// ============================================================================

/// Type of metric
pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,

    pub fn asStr(self: MetricType) []const u8 {
        return switch (self) {
            .counter => "counter",
            .gauge => "gauge",
            .histogram => "histogram",
            .summary => "summary",
        };
    }
};

/// A label key-value pair
pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// Labels for a metric (up to 8 labels supported)
pub const Labels = struct {
    items: [8]Label = undefined,
    len: usize = 0,

    pub fn init() Labels {
        return .{};
    }

    pub fn add(self: *Labels, name: []const u8, value: []const u8) *Labels {
        if (self.len < 8) {
            self.items[self.len] = .{ .name = name, .value = value };
            self.len += 1;
        }
        return self;
    }

    pub fn format(self: *const Labels, writer: anytype) !void {
        if (self.len == 0) return;

        try writer.writeByte('{');
        for (self.items[0..self.len], 0..) |label, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{s}=\"{s}\"", .{ label.name, label.value });
        }
        try writer.writeByte('}');
    }

    /// Generate a key for this label set
    pub fn key(self: *const Labels, allocator: Allocator) ![]u8 {
        var result: std.ArrayListUnmanaged(u8) = .{};
        errdefer result.deinit(allocator);

        for (self.items[0..self.len], 0..) |label, i| {
            if (i > 0) try result.append(allocator, ',');
            try result.appendSlice(allocator, label.name);
            try result.append(allocator, '=');
            try result.appendSlice(allocator, label.value);
        }
        return result.toOwnedSlice(allocator);
    }
};

// ============================================================================
// Counter
// ============================================================================

/// A monotonically increasing counter
pub const Counter = struct {
    name: []const u8,
    help: []const u8,
    value: std.atomic.Value(u64),

    const Self = @This();

    pub fn init(name: []const u8, help: []const u8) Self {
        return .{
            .name = name,
            .help = help,
            .value = std.atomic.Value(u64).init(0),
        };
    }

    /// Increment the counter by 1
    pub fn inc(self: *Self) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    /// Increment the counter by n
    pub fn add(self: *Self, n: u64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }

    /// Get the current value
    pub fn get(self: *const Self) u64 {
        return self.value.load(.monotonic);
    }

    /// Reset the counter to 0
    pub fn reset(self: *Self) void {
        self.value.store(0, .monotonic);
    }
};

// ============================================================================
// Gauge
// ============================================================================

/// A gauge that can increase and decrease
pub const Gauge = struct {
    name: []const u8,
    help: []const u8,
    value: std.atomic.Value(i64),

    const Self = @This();

    pub fn init(name: []const u8, help: []const u8) Self {
        return .{
            .name = name,
            .help = help,
            .value = std.atomic.Value(i64).init(0),
        };
    }

    /// Set the gauge to a specific value
    pub fn set(self: *Self, v: i64) void {
        self.value.store(v, .monotonic);
    }

    /// Increment the gauge by 1
    pub fn inc(self: *Self) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    /// Decrement the gauge by 1
    pub fn dec(self: *Self) void {
        _ = self.value.fetchSub(1, .monotonic);
    }

    /// Add to the gauge
    pub fn add(self: *Self, n: i64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }

    /// Subtract from the gauge
    pub fn sub(self: *Self, n: i64) void {
        _ = self.value.fetchSub(n, .monotonic);
    }

    /// Get the current value
    pub fn get(self: *const Self) i64 {
        return self.value.load(.monotonic);
    }

    /// Set gauge to current time in seconds since epoch
    pub fn setToCurrentTime(self: *Self) void {
        const now = std.time.timestamp();
        self.set(now);
    }
};

// ============================================================================
// Histogram
// ============================================================================

/// Default histogram buckets (in seconds, suitable for HTTP latencies)
pub const DEFAULT_BUCKETS = [_]f64{
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
};

/// A histogram for observing value distributions
pub const Histogram = struct {
    name: []const u8,
    help: []const u8,
    buckets: []const f64,
    bucket_counts: []std.atomic.Value(u64),
    sum: std.atomic.Value(u64), // stored as bits of f64
    count: std.atomic.Value(u64),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, name: []const u8, help: []const u8, buckets: []const f64) !Self {
        const bucket_counts = try allocator.alloc(std.atomic.Value(u64), buckets.len);
        for (bucket_counts) |*bc| {
            bc.* = std.atomic.Value(u64).init(0);
        }

        return .{
            .name = name,
            .help = help,
            .buckets = buckets,
            .bucket_counts = bucket_counts,
            .sum = std.atomic.Value(u64).init(@bitCast(@as(f64, 0.0))),
            .count = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
    }

    pub fn initDefault(allocator: Allocator, name: []const u8, help: []const u8) !Self {
        return init(allocator, name, help, &DEFAULT_BUCKETS);
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bucket_counts);
    }

    /// Observe a value
    pub fn observe(self: *Self, value: f64) void {
        // Update bucket counts
        for (self.buckets, 0..) |bound, i| {
            if (value <= bound) {
                _ = self.bucket_counts[i].fetchAdd(1, .monotonic);
            }
        }

        // Update sum (using CAS for f64)
        var old_bits = self.sum.load(.monotonic);
        while (true) {
            const old_sum: f64 = @bitCast(old_bits);
            const new_sum = old_sum + value;
            const new_bits: u64 = @bitCast(new_sum);

            const result = self.sum.cmpxchgWeak(old_bits, new_bits, .monotonic, .monotonic);
            if (result) |bits| {
                old_bits = bits;
            } else {
                break;
            }
        }

        // Update count
        _ = self.count.fetchAdd(1, .monotonic);
    }

    /// Observe a duration in nanoseconds (converts to seconds)
    pub fn observeNs(self: *Self, ns: u64) void {
        const seconds = @as(f64, @floatFromInt(ns)) / 1_000_000_000.0;
        self.observe(seconds);
    }

    /// Get the sum
    pub fn getSum(self: *const Self) f64 {
        return @bitCast(self.sum.load(.monotonic));
    }

    /// Get the count
    pub fn getCount(self: *const Self) u64 {
        return self.count.load(.monotonic);
    }

    /// Get bucket count at index
    pub fn getBucketCount(self: *const Self, index: usize) u64 {
        if (index >= self.bucket_counts.len) return 0;
        return self.bucket_counts[index].load(.monotonic);
    }
};

// ============================================================================
// Text Encoder
// ============================================================================

/// Prometheus text format encoder
pub const TextEncoder = struct {
    /// MIME type for Prometheus text format
    pub const CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

    /// Encode a single counter to a buffer
    pub fn encodeCounter(allocator: Allocator, counter: *const Counter, labels: ?*const Labels) ![]u8 {
        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        try writer.print("# HELP {s} {s}\n", .{ counter.name, counter.help });
        try writer.print("# TYPE {s} counter\n", .{counter.name});
        try writer.print("{s}", .{counter.name});
        if (labels) |l| try l.format(writer);
        try writer.print(" {d}\n", .{counter.get()});

        const written = stream.getWritten();
        const result = try allocator.alloc(u8, written.len);
        @memcpy(result, written);
        return result;
    }

    /// Encode a single gauge to a buffer
    pub fn encodeGauge(allocator: Allocator, gauge: *const Gauge, labels: ?*const Labels) ![]u8 {
        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        try writer.print("# HELP {s} {s}\n", .{ gauge.name, gauge.help });
        try writer.print("# TYPE {s} gauge\n", .{gauge.name});
        try writer.print("{s}", .{gauge.name});
        if (labels) |l| try l.format(writer);
        try writer.print(" {d}\n", .{gauge.get()});

        const written = stream.getWritten();
        const result = try allocator.alloc(u8, written.len);
        @memcpy(result, written);
        return result;
    }

    /// Encode a single histogram to a buffer
    pub fn encodeHistogram(allocator: Allocator, histogram: *const Histogram, labels: ?*const Labels) ![]u8 {
        var buf: [8192]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        try writer.print("# HELP {s} {s}\n", .{ histogram.name, histogram.help });
        try writer.print("# TYPE {s} histogram\n", .{histogram.name});

        // Write buckets
        var cumulative: u64 = 0;
        for (histogram.buckets, 0..) |bound, i| {
            cumulative += histogram.getBucketCount(i);
            try writer.print("{s}_bucket{{le=\"{d}\"", .{ histogram.name, bound });
            if (labels) |l| {
                if (l.len > 0) {
                    try writer.writeByte(',');
                    for (l.items[0..l.len], 0..) |label, j| {
                        if (j > 0) try writer.writeByte(',');
                        try writer.print("{s}=\"{s}\"", .{ label.name, label.value });
                    }
                }
            }
            try writer.print("}} {d}\n", .{cumulative});
        }

        // +Inf bucket
        try writer.print("{s}_bucket{{le=\"+Inf\"", .{histogram.name});
        if (labels) |l| {
            if (l.len > 0) {
                try writer.writeByte(',');
                for (l.items[0..l.len], 0..) |label, j| {
                    if (j > 0) try writer.writeByte(',');
                    try writer.print("{s}=\"{s}\"", .{ label.name, label.value });
                }
            }
        }
        try writer.print("}} {d}\n", .{histogram.getCount()});

        // Sum
        try writer.print("{s}_sum", .{histogram.name});
        if (labels) |l| try l.format(writer);
        try writer.print(" {d}\n", .{histogram.getSum()});

        // Count
        try writer.print("{s}_count", .{histogram.name});
        if (labels) |l| try l.format(writer);
        try writer.print(" {d}\n", .{histogram.getCount()});

        const written = stream.getWritten();
        const result = try allocator.alloc(u8, written.len);
        @memcpy(result, written);
        return result;
    }
};

// ============================================================================
// Common Proxy Metrics
// ============================================================================

/// Pre-defined metrics for HTTP proxy monitoring
pub const ProxyMetrics = struct {
    /// Total requests received
    requests_total: Counter,
    /// Currently active connections
    active_connections: Gauge,
    /// Request duration histogram
    request_duration_seconds: Histogram,
    /// Upstream connection errors
    upstream_errors_total: Counter,
    /// Cache hits
    cache_hits_total: Counter,
    /// Cache misses
    cache_misses_total: Counter,
    /// Bytes sent to clients
    bytes_sent_total: Counter,
    /// Bytes received from clients
    bytes_received_total: Counter,

    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        return .{
            .requests_total = Counter.init("pingora_requests_total", "Total number of requests"),
            .active_connections = Gauge.init("pingora_active_connections", "Number of active connections"),
            .request_duration_seconds = try Histogram.initDefault(
                allocator,
                "pingora_request_duration_seconds",
                "Request duration in seconds",
            ),
            .upstream_errors_total = Counter.init("pingora_upstream_errors_total", "Total upstream errors"),
            .cache_hits_total = Counter.init("pingora_cache_hits_total", "Total cache hits"),
            .cache_misses_total = Counter.init("pingora_cache_misses_total", "Total cache misses"),
            .bytes_sent_total = Counter.init("pingora_bytes_sent_total", "Total bytes sent to clients"),
            .bytes_received_total = Counter.init("pingora_bytes_received_total", "Total bytes received from clients"),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.request_duration_seconds.deinit();
    }

    /// Record a request
    pub fn recordRequest(self: *Self) void {
        self.requests_total.inc();
    }

    /// Record request completion with duration
    pub fn recordRequestComplete(self: *Self, duration_ns: u64) void {
        self.request_duration_seconds.observeNs(duration_ns);
    }

    /// Record connection open
    pub fn connectionOpened(self: *Self) void {
        self.active_connections.inc();
    }

    /// Record connection close
    pub fn connectionClosed(self: *Self) void {
        self.active_connections.dec();
    }

    /// Record cache hit
    pub fn recordCacheHit(self: *Self) void {
        self.cache_hits_total.inc();
    }

    /// Record cache miss
    pub fn recordCacheMiss(self: *Self) void {
        self.cache_misses_total.inc();
    }

    /// Record upstream error
    pub fn recordUpstreamError(self: *Self) void {
        self.upstream_errors_total.inc();
    }

    /// Record bytes sent
    pub fn recordBytesSent(self: *Self, bytes: u64) void {
        self.bytes_sent_total.add(bytes);
    }

    /// Record bytes received
    pub fn recordBytesReceived(self: *Self, bytes: u64) void {
        self.bytes_received_total.add(bytes);
    }

    /// Encode all metrics
    pub fn encode(self: *Self, allocator: Allocator) ![]u8 {
        var result: std.ArrayListUnmanaged(u8) = .{};
        errdefer result.deinit(allocator);

        // Encode each metric
        const counters = [_]*const Counter{
            &self.requests_total,
            &self.upstream_errors_total,
            &self.cache_hits_total,
            &self.cache_misses_total,
            &self.bytes_sent_total,
            &self.bytes_received_total,
        };

        for (counters) |c| {
            const encoded = try TextEncoder.encodeCounter(allocator, c, null);
            defer allocator.free(encoded);
            try result.appendSlice(allocator, encoded);
            try result.append(allocator, '\n');
        }

        // Gauge
        {
            const encoded = try TextEncoder.encodeGauge(allocator, &self.active_connections, null);
            defer allocator.free(encoded);
            try result.appendSlice(allocator, encoded);
            try result.append(allocator, '\n');
        }

        // Histogram
        {
            const encoded = try TextEncoder.encodeHistogram(allocator, &self.request_duration_seconds, null);
            defer allocator.free(encoded);
            try result.appendSlice(allocator, encoded);
        }

        return result.toOwnedSlice(allocator);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Counter basic operations" {
    var counter = Counter.init("test_counter", "A test counter");

    try testing.expectEqual(@as(u64, 0), counter.get());

    counter.inc();
    try testing.expectEqual(@as(u64, 1), counter.get());

    counter.add(5);
    try testing.expectEqual(@as(u64, 6), counter.get());

    counter.reset();
    try testing.expectEqual(@as(u64, 0), counter.get());
}

test "Gauge basic operations" {
    var gauge = Gauge.init("test_gauge", "A test gauge");

    try testing.expectEqual(@as(i64, 0), gauge.get());

    gauge.set(100);
    try testing.expectEqual(@as(i64, 100), gauge.get());

    gauge.inc();
    try testing.expectEqual(@as(i64, 101), gauge.get());

    gauge.dec();
    try testing.expectEqual(@as(i64, 100), gauge.get());

    gauge.add(50);
    try testing.expectEqual(@as(i64, 150), gauge.get());

    gauge.sub(25);
    try testing.expectEqual(@as(i64, 125), gauge.get());
}

test "Histogram basic operations" {
    var histogram = try Histogram.initDefault(testing.allocator, "test_histogram", "A test histogram");
    defer histogram.deinit();

    try testing.expectEqual(@as(u64, 0), histogram.getCount());
    try testing.expectEqual(@as(f64, 0.0), histogram.getSum());

    histogram.observe(0.05);
    try testing.expectEqual(@as(u64, 1), histogram.getCount());

    histogram.observe(0.5);
    histogram.observe(1.5);
    try testing.expectEqual(@as(u64, 3), histogram.getCount());

    // Check bucket counts
    // 0.05 should be in buckets >= 0.05
    // 0.5 should be in buckets >= 0.5
    // 1.5 should be in buckets >= 2.5
    try testing.expect(histogram.getBucketCount(3) >= 1); // 0.05 bucket
}

test "Histogram observeNs" {
    var histogram = try Histogram.initDefault(testing.allocator, "test_histogram_ns", "Test histogram with ns");
    defer histogram.deinit();

    histogram.observeNs(50_000_000); // 50ms
    try testing.expectEqual(@as(u64, 1), histogram.getCount());

    const sum = histogram.getSum();
    try testing.expect(sum > 0.04 and sum < 0.06);
}

test "Labels format" {
    var labels = Labels.init();
    _ = labels.add("method", "GET").add("path", "/api");

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try labels.format(stream.writer());

    const result = stream.getWritten();
    try testing.expectEqualStrings("{method=\"GET\",path=\"/api\"}", result);
}

test "TextEncoder encodeCounter" {
    var counter = Counter.init("test_requests", "Test request count");
    counter.add(42);

    const output = try TextEncoder.encodeCounter(testing.allocator, &counter, null);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "# HELP test_requests") != null);
    try testing.expect(std.mem.indexOf(u8, output, "# TYPE test_requests counter") != null);
    try testing.expect(std.mem.indexOf(u8, output, "test_requests 42") != null);
}

test "TextEncoder encodeCounter with labels" {
    var counter = Counter.init("http_requests", "HTTP requests");
    counter.add(10);

    var labels = Labels.init();
    _ = labels.add("method", "POST").add("status", "200");

    const output = try TextEncoder.encodeCounter(testing.allocator, &counter, &labels);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "http_requests{method=\"POST\",status=\"200\"} 10") != null);
}

test "TextEncoder encodeHistogram" {
    var histogram = try Histogram.initDefault(testing.allocator, "request_latency", "Request latency");
    defer histogram.deinit();

    histogram.observe(0.05);
    histogram.observe(0.25);
    histogram.observe(0.75);

    const output = try TextEncoder.encodeHistogram(testing.allocator, &histogram, null);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "# TYPE request_latency histogram") != null);
    try testing.expect(std.mem.indexOf(u8, output, "request_latency_bucket{le=\"+Inf\"} 3") != null);
    try testing.expect(std.mem.indexOf(u8, output, "request_latency_count 3") != null);
}

test "ProxyMetrics" {
    var metrics = try ProxyMetrics.init(testing.allocator);
    defer metrics.deinit();

    metrics.recordRequest();
    metrics.recordRequest();
    metrics.connectionOpened();
    metrics.connectionOpened();
    metrics.connectionClosed();
    metrics.recordCacheHit();
    metrics.recordCacheMiss();
    metrics.recordCacheMiss();
    metrics.recordRequestComplete(100_000_000); // 100ms
    metrics.recordBytesSent(1024);
    metrics.recordBytesReceived(512);

    try testing.expectEqual(@as(u64, 2), metrics.requests_total.get());
    try testing.expectEqual(@as(i64, 1), metrics.active_connections.get());
    try testing.expectEqual(@as(u64, 1), metrics.cache_hits_total.get());
    try testing.expectEqual(@as(u64, 2), metrics.cache_misses_total.get());
    try testing.expectEqual(@as(u64, 1024), metrics.bytes_sent_total.get());
    try testing.expectEqual(@as(u64, 512), metrics.bytes_received_total.get());

    // Test encoding
    const output = try metrics.encode(testing.allocator);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "pingora_requests_total 2") != null);
    try testing.expect(std.mem.indexOf(u8, output, "pingora_active_connections 1") != null);
}

test "MetricType asStr" {
    try testing.expectEqualStrings("counter", MetricType.counter.asStr());
    try testing.expectEqualStrings("gauge", MetricType.gauge.asStr());
    try testing.expectEqualStrings("histogram", MetricType.histogram.asStr());
    try testing.expectEqualStrings("summary", MetricType.summary.asStr());
}
