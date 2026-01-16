# Prometheus Metrics

Exposing metrics for monitoring with Prometheus.

## Metrics Types

### Counter

Monotonically increasing value:

```zig
pub const Counter = struct {
    value: std.atomic.Value(u64),

    pub fn init() Counter {
        return .{ .value = std.atomic.Value(u64).init(0) };
    }

    pub fn inc(self: *Counter) void {
        _ = self.value.fetchAdd(1, .seq_cst);
    }

    pub fn add(self: *Counter, n: u64) void {
        _ = self.value.fetchAdd(n, .seq_cst);
    }

    pub fn get(self: *Counter) u64 {
        return self.value.load(.seq_cst);
    }
};
```

### Gauge

Value that can go up and down:

```zig
pub const Gauge = struct {
    value: std.atomic.Value(i64),

    pub fn init() Gauge {
        return .{ .value = std.atomic.Value(i64).init(0) };
    }

    pub fn set(self: *Gauge, v: i64) void {
        self.value.store(v, .seq_cst);
    }

    pub fn inc(self: *Gauge) void {
        _ = self.value.fetchAdd(1, .seq_cst);
    }

    pub fn dec(self: *Gauge) void {
        _ = self.value.fetchSub(1, .seq_cst);
    }

    pub fn get(self: *Gauge) i64 {
        return self.value.load(.seq_cst);
    }
};
```

### Histogram

Distribution of values:

```zig
pub const Histogram = struct {
    buckets: []Bucket,
    sum: std.atomic.Value(f64),
    count: std.atomic.Value(u64),

    pub const Bucket = struct {
        upper_bound: f64,
        count: std.atomic.Value(u64),
    };

    pub fn observe(self: *Histogram, value: f64) void {
        for (self.buckets) |*bucket| {
            if (value <= bucket.upper_bound) {
                _ = bucket.count.fetchAdd(1, .seq_cst);
            }
        }
        _ = self.count.fetchAdd(1, .seq_cst);
        // Note: atomic f64 add is more complex in practice
    }
};
```

## Proxy Metrics

```zig
pub const ProxyMetrics = struct {
    // Request counters
    requests_total: Counter,
    requests_by_method: std.StringHashMap(Counter),
    requests_by_status: std.AutoHashMap(u16, Counter),

    // Latency histograms
    request_duration_seconds: Histogram,
    upstream_connect_duration_seconds: Histogram,
    upstream_request_duration_seconds: Histogram,

    // Connection gauges
    active_connections: Gauge,
    idle_connections: Gauge,

    // Error counters
    errors_total: Counter,
    upstream_errors_total: Counter,
    timeout_errors_total: Counter,

    // Cache metrics
    cache_hits_total: Counter,
    cache_misses_total: Counter,
    cache_size_bytes: Gauge,

    // Upstream metrics
    upstream_requests_total: Counter,
    upstream_healthy_backends: Gauge,
};
```

## Recording Metrics

```zig
fn recordRequestMetrics(
    metrics: *ProxyMetrics,
    session: *pingora.Session,
) void {
    // Increment request counter
    metrics.requests_total.inc();

    // Record by method
    if (session.reqHeader()) |req| {
        const method = req.method.asStr();
        if (metrics.requests_by_method.getPtr(method)) |counter| {
            counter.inc();
        }
    }

    // Record by status
    if (session.respHeader()) |resp| {
        const status = resp.status.code;
        if (metrics.requests_by_status.getPtr(status)) |counter| {
            counter.inc();
        }
    }

    // Record latency
    const duration_ms = session.timing.getDuration();
    const duration_s = @as(f64, @floatFromInt(duration_ms)) / 1000.0;
    metrics.request_duration_seconds.observe(duration_s);

    // Record cache status
    if (session.cache_result) |result| {
        switch (result.status) {
            .hit => metrics.cache_hits_total.inc(),
            .miss => metrics.cache_misses_total.inc(),
            else => {},
        }
    }
}
```

## Prometheus Exposition Format

```zig
pub fn writePrometheusMetrics(
    writer: anytype,
    metrics: *ProxyMetrics,
) !void {
    // Counter
    try writer.print(
        \\# HELP pingora_requests_total Total number of HTTP requests
        \\# TYPE pingora_requests_total counter
        \\pingora_requests_total {d}
        \\
    , .{metrics.requests_total.get()});

    // Gauge
    try writer.print(
        \\# HELP pingora_active_connections Current number of active connections
        \\# TYPE pingora_active_connections gauge
        \\pingora_active_connections {d}
        \\
    , .{metrics.active_connections.get()});

    // Histogram
    try writer.print(
        \\# HELP pingora_request_duration_seconds Request duration in seconds
        \\# TYPE pingora_request_duration_seconds histogram
        \\
    , .{});

    for (metrics.request_duration_seconds.buckets) |bucket| {
        try writer.print(
            \\pingora_request_duration_seconds_bucket{{le="{d}"}} {d}
            \\
        , .{ bucket.upper_bound, bucket.count.load(.seq_cst) });
    }

    try writer.print(
        \\pingora_request_duration_seconds_bucket{{le="+Inf"}} {d}
        \\pingora_request_duration_seconds_sum {d}
        \\pingora_request_duration_seconds_count {d}
        \\
    , .{
        metrics.request_duration_seconds.count.load(.seq_cst),
        metrics.request_duration_seconds.sum.load(.seq_cst),
        metrics.request_duration_seconds.count.load(.seq_cst),
    });
}
```

## Metrics Endpoint Handler

```zig
fn metricsHandler(
    self: *MyProxy,
    session: *pingora.Session,
) !pingora.FilterResult {
    const req = session.reqHeader() orelse return .continue_processing;

    if (!std.mem.eql(u8, req.uri.path, "/metrics")) {
        return .continue_processing;
    }

    // Generate metrics
    var buf = std.ArrayList(u8).init(self.allocator);
    defer buf.deinit();

    try writePrometheusMetrics(buf.writer(), &self.metrics);

    var headers = pingora.Headers.init(self.allocator);
    try headers.append("Content-Type", "text/plain; version=0.0.4");

    return .{ .respond = .{
        .status = 200,
        .headers = &headers,
        .body = buf.items,
    }};
}
```

## Labels

Adding labels to metrics:

```zig
pub const LabeledCounter = struct {
    counters: std.StringHashMap(Counter),
    allocator: Allocator,

    pub fn inc(self: *LabeledCounter, labels: []const u8) void {
        const counter = self.counters.getPtr(labels) orelse {
            self.counters.put(labels, Counter.init()) catch return;
            return self.inc(labels);
        };
        counter.inc();
    }

    pub fn write(self: *LabeledCounter, writer: anytype, name: []const u8) !void {
        var iter = self.counters.iterator();
        while (iter.next()) |entry| {
            try writer.print("{s}{{{s}}} {d}\n", .{
                name,
                entry.key_ptr.*,
                entry.value_ptr.get(),
            });
        }
    }
};

// Usage
metrics.requests_by_endpoint.inc("method=\"GET\",path=\"/api\"");
```

## Example Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'pingora'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
```

## Grafana Dashboard Queries

```promql
# Request rate
rate(pingora_requests_total[5m])

# Error rate
rate(pingora_errors_total[5m]) / rate(pingora_requests_total[5m])

# P99 latency
histogram_quantile(0.99, rate(pingora_request_duration_seconds_bucket[5m]))

# Active connections
pingora_active_connections

# Cache hit rate
rate(pingora_cache_hits_total[5m]) / (rate(pingora_cache_hits_total[5m]) + rate(pingora_cache_misses_total[5m]))

# Upstream health
pingora_upstream_healthy_backends
```

## Best Practices

1. **Use consistent naming**: Follow Prometheus naming conventions
2. **Add HELP and TYPE**: Required for proper metric discovery
3. **Use labels sparingly**: High cardinality labels cause memory issues
4. **Expose standard metrics**: requests, errors, latency, connections
5. **Include cache metrics**: Hit rate, size, evictions
6. **Monitor upstreams**: Health, latency, errors per backend
7. **Set up alerts**: Define SLOs and alert on violations
8. **Use histograms for latency**: Enable percentile calculations
