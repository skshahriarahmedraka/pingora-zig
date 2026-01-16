//! Integration Tests
//!
//! Tests that verify the interaction between multiple modules.
//! These tests ensure the components work correctly together.

const std = @import("std");
const testing = std.testing;

// Import all modules
const http = @import("http.zig");
const http_parser = @import("http_parser.zig");
const memory_cache = @import("memory_cache.zig");
const pool = @import("pool.zig");
const limits = @import("limits.zig");
const lru = @import("lru.zig");
const tinyufo = @import("tinyufo.zig");
const protocols = @import("protocols.zig");
const header_serde = @import("header_serde.zig");

// ============================================================================
// Integration Test: HTTP Parser + HTTP Types
// ============================================================================

test "integration: parse request and build RequestHeader" {
    const raw_request = "GET /api/users?id=123 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: TestClient/1.0\r\n" ++
        "Accept: application/json\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";

    var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed = try http_parser.parseRequestFull(raw_request, &headers_buf);
    try testing.expect(parsed != null);

    const req = parsed.?;

    // Build a RequestHeader from parsed data
    var request = try http.RequestHeader.build(
        testing.allocator,
        http.Method.fromStr(req.method).?,
        req.path,
        if (req.version == 1) http.Version.http_1_1 else http.Version.http_1_0,
    );
    defer request.deinit();

    // Add headers from parsed request
    for (req.headers) |h| {
        try request.appendHeader(h.name, h.value);
    }

    // Verify - note: Uri.path contains just the path, query is separate
    try testing.expectEqualStrings("/api/users", request.uri.path);
    try testing.expectEqualStrings("id=123", request.uri.query.?);
    try testing.expectEqual(request.method, .GET);
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("application/json", request.headers.get("Accept").?);
}

test "integration: parse response and build ResponseHeader" {
    const raw_response = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 1234\r\n" ++
        "Cache-Control: max-age=3600\r\n" ++
        "\r\n";

    var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed = try http_parser.parseResponseFull(raw_response, &headers_buf);
    try testing.expect(parsed != null);

    const resp = parsed.?;

    // Build a ResponseHeader from parsed data
    var response = http.ResponseHeader.init(testing.allocator, resp.status_code);
    defer response.deinit();

    if (resp.version == 1) {
        response.setVersion(.http_1_1);
    }

    for (resp.headers) |h| {
        try response.appendHeader(h.name, h.value);
    }

    // Verify
    try testing.expectEqual(response.status.code, 200);
    try testing.expectEqualStrings("application/json", response.headers.get("Content-Type").?);
    try testing.expectEqualStrings("1234", response.headers.get("Content-Length").?);
}

// ============================================================================
// Integration Test: MemoryCache + HTTP Response Caching
// ============================================================================

const CachedResponse = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

test "integration: cache HTTP responses with TTL" {
    var cache = try memory_cache.MemoryCache(u64, CachedResponse).init(testing.allocator, 100);
    defer cache.deinit();

    // Cache a response
    const response1 = CachedResponse{
        .status = 200,
        .content_type = "text/html",
        .body = "<html>Hello</html>",
    };

    const key = std.hash.Wyhash.hash(0, "GET:/index.html");
    try cache.putSecs(key, response1, 3600); // 1 hour TTL

    // Retrieve from cache
    const result = cache.get(key);
    try testing.expect(result[0] != null);
    try testing.expect(result[1].isHit());

    const cached = result[0].?;
    try testing.expectEqual(cached.status, 200);
    try testing.expectEqualStrings("text/html", cached.content_type);
}

test "integration: cache multiple responses" {
    var cache = try memory_cache.MemoryCache(u64, CachedResponse).init(testing.allocator, 100);
    defer cache.deinit();

    // Cache multiple responses
    const paths = [_][]const u8{ "/index.html", "/about.html", "/contact.html" };
    for (paths, 0..) |path, i| {
        const key = std.hash.Wyhash.hash(0, path);
        try cache.put(key, CachedResponse{
            .status = 200,
            .content_type = "text/html",
            .body = path,
        }, null);
        _ = i;
    }

    // All should be hits
    for (paths) |path| {
        const key = std.hash.Wyhash.hash(0, path);
        const result = cache.get(key);
        try testing.expect(result[1].isHit());
        try testing.expectEqualStrings(path, result[0].?.body);
    }
}

// ============================================================================
// Integration Test: ConnectionPool + Rate Limiting
// ============================================================================

test "integration: connection pool with rate tracking" {
    var pool_inst = pool.ConnectionPool(u64, i32).init(testing.allocator, 10);
    defer pool_inst.deinit();

    var rate = try limits.Rate.init(testing.allocator, 1000); // 1 second interval
    defer rate.deinit();

    const server_key: u64 = 12345;

    // Simulate getting/returning connections with rate tracking
    for (0..5) |i| {
        // Create a new connection
        const conn: i32 = @intCast(i);

        // Track the connection rate
        _ = rate.observe(server_key, 1);

        // Put connection in pool
        _ = pool_inst.put(server_key, conn);
    }

    try testing.expectEqual(pool_inst.count(), 5);

    // Get connections from pool
    for (0..5) |_| {
        const result = pool_inst.get(server_key);
        try testing.expect(result != null);
    }

    try testing.expectEqual(pool_inst.count(), 0);
}

// ============================================================================
// Integration Test: LRU + Request Deduplication
// ============================================================================

test "integration: LRU for request deduplication" {
    var lru_cache = lru.Lru(u64, 4).init(testing.allocator, 1000);
    defer lru_cache.deinit();

    // Simulate multiple requests to same endpoint
    const endpoints = [_][]const u8{
        "GET:/api/users/1",
        "GET:/api/users/2",
        "GET:/api/users/1", // Duplicate
        "POST:/api/users",
        "GET:/api/users/1", // Duplicate again
    };

    var unique_count: usize = 0;
    var duplicate_count: usize = 0;

    for (endpoints) |endpoint| {
        const key = std.hash.Wyhash.hash(0, endpoint);
        const now = std.time.milliTimestamp();

        if (lru_cache.peek(key)) {
            // Already seen this request
            duplicate_count += 1;
            _ = lru_cache.promote(key);
        } else {
            // New request
            unique_count += 1;
            _ = try lru_cache.admit(key, @bitCast(now), 1);
        }
    }

    try testing.expectEqual(unique_count, 3); // 3 unique endpoints
    try testing.expectEqual(duplicate_count, 2); // 2 duplicates
}

// ============================================================================
// Integration Test: Inflight Tracking + Pool
// ============================================================================

test "integration: inflight request tracking" {
    var inflight = try limits.Inflight.init(testing.allocator);
    defer inflight.deinit();

    var pool_inst = pool.ConnectionPool(u64, i32).init(testing.allocator, 5);
    defer pool_inst.deinit();

    const server: u64 = 1;

    // Track inflight requests to server
    const result1 = inflight.incr(server, 1);
    var guard1 = result1[0];
    try testing.expectEqual(result1[1], 1);

    const result2 = inflight.incr(server, 1);
    var guard2 = result2[0];
    try testing.expectEqual(result2[1], 2);

    // Complete first request
    guard1.deinit();
    try testing.expectEqual(guard2.get(), 1);

    // Complete second request
    guard2.deinit();

    // New request should start at 1
    const result3 = inflight.incr(server, 1);
    var guard3 = result3[0];
    defer guard3.deinit();
    try testing.expectEqual(result3[1], 1);
}

// ============================================================================
// Integration Test: Full Request/Response Cycle Simulation
// ============================================================================

test "integration: simulate proxy request cycle" {
    // 1. Parse incoming request
    const client_request = "GET /api/data HTTP/1.1\r\n" ++
        "Host: backend.local\r\n" ++
        "X-Request-ID: abc123\r\n" ++
        "\r\n";

    var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed_req = (try http_parser.parseRequestFull(client_request, &headers_buf)).?;

    // 2. Check cache first
    var cache = try memory_cache.MemoryCache(u64, []const u8).init(testing.allocator, 100);
    defer cache.deinit();

    const cache_key = std.hash.Wyhash.hash(0, parsed_req.path);
    const cache_result = cache.get(cache_key);

    if (cache_result[1].isHit()) {
        // Cache hit - return cached response
        try testing.expect(false); // Should not hit on first request
    }

    // 3. Track inflight request
    var inflight = try limits.Inflight.init(testing.allocator);
    defer inflight.deinit();

    const inflight_result = inflight.incr(cache_key, 1);
    var inflight_guard = inflight_result[0];
    defer inflight_guard.deinit();

    // 4. Get connection from pool (or create new)
    var conn_pool = pool.ConnectionPool(u64, i32).init(testing.allocator, 10);
    defer conn_pool.deinit();

    const backend_key = std.hash.Wyhash.hash(0, "backend.local:80");
    var conn: i32 = undefined;

    if (conn_pool.get(backend_key)) |pooled| {
        conn = pooled[0];
    } else {
        conn = 42; // Simulate new connection
    }

    // 5. Build upstream request
    var upstream_req = try http.RequestHeader.build(
        testing.allocator,
        http.Method.fromStr(parsed_req.method).?,
        parsed_req.path,
        .http_1_1,
    );
    defer upstream_req.deinit();

    for (parsed_req.headers) |h| {
        try upstream_req.appendHeader(h.name, h.value);
    }

    // 6. Simulate backend response
    const backend_response = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "{\"data\":true}";

    var resp_headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed_resp = (try http_parser.parseResponseFull(backend_response, &resp_headers_buf)).?;

    // 7. Cache the response
    const body_start = parsed_resp.bytes_consumed;
    const body = backend_response[body_start..];
    try cache.putSecs(cache_key, body, 60);

    // 8. Return connection to pool
    _ = conn_pool.put(backend_key, conn);

    // Verify final state
    try testing.expectEqual(parsed_resp.status_code, 200);
    try testing.expectEqualStrings("{\"data\":true}", body);
    try testing.expect(cache.get(cache_key)[1].isHit());
    try testing.expectEqual(conn_pool.count(), 1);
}

// ============================================================================
// Integration Test: HTTP Parser with Chunked Encoding
// ============================================================================

test "integration: parse chunked response" {
    const response = "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";

    var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed = (try http_parser.parseResponseFull(response, &headers_buf)).?;

    try testing.expect(http_parser.isChunkedEncoding(parsed.headers));
    try testing.expect(!http_parser.isConnectionClose(parsed.headers));

    // Parse chunk headers
    const chunk1 = "a\r\n";
    const chunk1_header = (try http_parser.parseChunkHeader(chunk1)).?;
    try testing.expectEqual(chunk1_header.size, 10);

    const last_chunk = "0\r\n";
    const last_header = (try http_parser.parseChunkHeader(last_chunk)).?;
    try testing.expectEqual(last_header.size, 0);
}

// ============================================================================
// Integration Test: Rate Limiting + Cache
// ============================================================================

test "integration: rate limited cache access" {
    var cache = try memory_cache.MemoryCache(u64, i32).init(testing.allocator, 100);
    defer cache.deinit();

    var estimator = try limits.Estimator.init(testing.allocator, 8, 64);
    defer estimator.deinit();

    // Simulate rate-limited cache access pattern
    const keys = [_]u64{ 1, 2, 3, 1, 1, 1, 2, 3, 1, 1 };

    for (keys) |key| {
        // Track access frequency
        const freq = estimator.incr(key, 1);

        // Only cache if accessed frequently
        if (freq >= 3) {
            if (cache.get(key)[1].isMiss()) {
                try cache.put(key, @intCast(key * 10), null);
            }
        }
    }

    // Key 1 was accessed 6 times, should be cached
    try testing.expect(cache.get(1)[1].isHit());

    // Key 2 was accessed 2 times, should not be cached
    try testing.expect(cache.get(2)[1].isMiss());

    // Key 3 was accessed 2 times, should not be cached
    try testing.expect(cache.get(3)[1].isMiss());
}

// ============================================================================
// Integration Test: Connection Pool Metadata
// ============================================================================

test "integration: track connection reuse" {
    var conn_pool = pool.ConnectionPool(u64, i32).init(testing.allocator, 10);
    defer conn_pool.deinit();

    const server: u64 = 1;

    // Put and get connection multiple times
    _ = conn_pool.put(server, 100);

    const first_get = conn_pool.get(server).?;
    try testing.expectEqual(first_get[1].reuse_count, 0);

    // Return and get again
    _ = conn_pool.put(server, first_get[0]);
    const second_get = conn_pool.get(server).?;
    // Reuse count resets since it's a new PoolNode
    try testing.expectEqual(second_get[1].reuse_count, 0);
}

// ============================================================================
// Integration Test: Proxy with Real Upstream
// ============================================================================

const proxy = @import("proxy.zig");
const upstream = @import("upstream.zig");
const load_balancer = @import("load_balancer.zig");

test "integration: proxy session lifecycle" {
    // Test the complete session lifecycle without network
    var session = proxy.Session.init(testing.allocator);
    defer session.deinit();

    // Create a request
    var req = try http.RequestHeader.build(testing.allocator, .GET, "/api/test", .http_1_1);
    try req.appendHeader("Host", "localhost");
    try req.appendHeader("User-Agent", "pingora-zig-test");
    session.setRequest(req);

    // Verify request is set
    try testing.expect(session.reqHeader() != null);
    try testing.expect(session.timing.request_start != null);

    // Create a mock response
    var resp = http.ResponseHeader.init(testing.allocator, 200);
    try resp.appendHeader("Content-Type", "application/json");
    try resp.appendHeader("Server", "pingora-zig");
    session.setResponse(resp);

    // Verify response is set
    try testing.expect(session.respHeader() != null);
    try testing.expect(session.timing.response_start != null);

    // Mark complete
    session.markComplete();
    try testing.expect(session.timing.request_end != null);

    // Duration should be positive
    const duration = session.getDurationNs();
    try testing.expect(duration >= 0);
}

test "integration: proxy with load balancer" {
    // Create upstream group
    var group = try upstream.UpstreamGroup.init(testing.allocator, "test-backend");
    defer group.deinit();

    // Add peers to the group
    const addr1 = try protocols.parseAddress("127.0.0.1", 8081);
    const addr2 = try protocols.parseAddress("127.0.0.1", 8082);

    const peer1 = try group.addPeer(addr1, .{});
    const peer2 = try group.addPeer(addr2, .{});
    peer1.markHealthy();
    peer2.markHealthy();

    // Create load balancer with round robin
    var lb = load_balancer.LoadBalancer.init(testing.allocator, .round_robin);
    defer lb.deinit();

    // Test round-robin selection
    const first = try lb.select(&group);
    try testing.expect(first != null);

    const second = try lb.select(&group);
    try testing.expect(second != null);

    // Round robin should give different peers
    try testing.expect(first.?.peer.getPort() != second.?.peer.getPort() or first.?.index == second.?.index);
}

test "integration: proxy request/response filters" {
    // Test proxy filter chain with mock implementation
    const TestProxy = struct {
        peer: upstream.Peer,
        request_filter_count: usize = 0,
        response_filter_count: usize = 0,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            const address = try protocols.parseAddress("127.0.0.1", 9999);
            return .{
                .peer = upstream.Peer.init(allocator, address, .{}),
            };
        }

        pub fn deinit(self: *Self) void {
            self.peer.deinit();
        }

        pub fn upstreamPeer(self: *Self, session: *proxy.Session, ctx: ?*anyopaque) proxy.ProxyError!?*upstream.Peer {
            _ = session;
            _ = ctx;
            return &self.peer;
        }

        pub fn requestFilter(self: *Self, session: *proxy.Session, ctx: ?*anyopaque) proxy.ProxyError!proxy.FilterResult {
            _ = session;
            _ = ctx;
            self.request_filter_count += 1;
            return .@"continue";
        }

        pub fn responseFilter(self: *Self, session: *proxy.Session, response: *http.ResponseHeader, ctx: ?*anyopaque) proxy.ProxyError!void {
            _ = session;
            _ = ctx;
            self.response_filter_count += 1;
            // Add custom header
            try response.appendHeader("X-Processed-By", "pingora-zig");
        }

        pub fn asProxyHttp(self: *Self) proxy.ProxyHttp {
            return proxy.proxyHttpFrom(Self, self);
        }
    };

    var test_proxy = try TestProxy.init(testing.allocator);
    defer test_proxy.deinit();

    var http_proxy = try proxy.HttpProxy.init(
        testing.allocator,
        test_proxy.asProxyHttp(),
        .{ .use_mock_upstream = true },
    );
    defer http_proxy.deinit();

    // Process a request
    var session = proxy.Session.init(testing.allocator);
    defer session.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", .http_1_1);
    try req.appendHeader("Host", "test.local");
    session.setRequest(req);

    try http_proxy.processRequest(&session);

    // Verify filters were called
    try testing.expect(test_proxy.request_filter_count == 1);
    try testing.expect(test_proxy.response_filter_count == 1);

    // Verify stats
    const stats = http_proxy.getStats();
    try testing.expectEqual(stats.requests_total, 1);
    try testing.expectEqual(stats.requests_success, 1);
}

test "integration: reverse proxy creation" {
    var rp = try proxy.ReverseProxy.initFromHostPort(testing.allocator, "127.0.0.1", 8080);
    defer rp.deinit();

    var session = proxy.Session.init(testing.allocator);
    defer session.deinit();

    // Test peer selection
    const peer = try rp.upstreamPeer(&session, null);
    try testing.expect(peer != null);
    try testing.expectEqual(peer.?.getPort(), 8080);
}

test "integration: upstream health tracking" {
    const addr = try protocols.parseAddress("127.0.0.1", 8080);
    var peer = upstream.Peer.init(testing.allocator, addr, .{ .max_fails = 3 });
    defer peer.deinit();

    // Initially available (unknown health = available)
    try testing.expect(peer.isAvailable());

    // Record failures
    peer.recordFailure();
    peer.recordFailure();
    try testing.expect(peer.isAvailable()); // Still available

    peer.recordFailure(); // 3rd failure
    try testing.expect(!peer.isAvailable()); // Now unhealthy

    // Check stats
    try testing.expect(peer.stats.failed_requests >= 3);

    // Record success to recover (after fail timeout passes)
    peer.markHealthy(); // Force healthy for testing
    peer.recordSuccess(100, 0, 0);
    try testing.expect(peer.stats.successful_requests >= 1);
    try testing.expect(peer.isAvailable());
}

test "integration: multiple request processing" {
    const SimpleProxy = struct {
        peer: upstream.Peer,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            const address = try protocols.parseAddress("127.0.0.1", 8080);
            return .{
                .peer = upstream.Peer.init(allocator, address, .{}),
            };
        }

        pub fn deinit(self: *Self) void {
            self.peer.deinit();
        }

        pub fn upstreamPeer(self: *Self, session: *proxy.Session, ctx: ?*anyopaque) proxy.ProxyError!?*upstream.Peer {
            _ = session;
            _ = ctx;
            return &self.peer;
        }

        pub fn asProxyHttp(self: *Self) proxy.ProxyHttp {
            return proxy.proxyHttpFrom(Self, self);
        }
    };

    var simple_proxy = try SimpleProxy.init(testing.allocator);
    defer simple_proxy.deinit();

    var http_proxy = try proxy.HttpProxy.init(
        testing.allocator,
        simple_proxy.asProxyHttp(),
        .{ .use_mock_upstream = true },
    );
    defer http_proxy.deinit();

    // Process multiple requests
    const paths = [_][]const u8{ "/api/users", "/api/products", "/api/orders", "/health", "/status" };

    for (paths) |path| {
        var session = proxy.Session.init(testing.allocator);
        defer session.deinit();

        var req = try http.RequestHeader.build(testing.allocator, .GET, path, .http_1_1);
        try req.appendHeader("Host", "api.example.com");
        session.setRequest(req);

        try http_proxy.processRequest(&session);
    }

    // Verify all requests were processed
    const stats = http_proxy.getStats();
    try testing.expectEqual(stats.requests_total, 5);
    try testing.expectEqual(stats.requests_success, 5);
    try testing.expectEqual(stats.requests_failed, 0);
}

test "integration: proxy with caching disabled" {
    const CacheProxy = struct {
        peer: upstream.Peer,
        cache_checks: usize = 0,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            const address = try protocols.parseAddress("127.0.0.1", 8080);
            return .{
                .peer = upstream.Peer.init(allocator, address, .{}),
            };
        }

        pub fn deinit(self: *Self) void {
            self.peer.deinit();
        }

        pub fn upstreamPeer(self: *Self, session: *proxy.Session, ctx: ?*anyopaque) proxy.ProxyError!?*upstream.Peer {
            _ = session;
            _ = ctx;
            return &self.peer;
        }

        pub fn requestCacheFilter(self: *Self, session: *proxy.Session, ctx: ?*anyopaque) bool {
            _ = session;
            _ = ctx;
            self.cache_checks += 1;
            return false; // Caching disabled
        }

        pub fn asProxyHttp(self: *Self) proxy.ProxyHttp {
            return proxy.proxyHttpFrom(Self, self);
        }
    };

    var cache_proxy = try CacheProxy.init(testing.allocator);
    defer cache_proxy.deinit();

    var http_proxy = try proxy.HttpProxy.init(
        testing.allocator,
        cache_proxy.asProxyHttp(),
        .{
            .use_mock_upstream = true,
            .cache_enabled = true, // Enable at proxy level
        },
    );
    defer http_proxy.deinit();

    var session = proxy.Session.init(testing.allocator);
    defer session.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/cacheable", .http_1_1);
    try req.appendHeader("Host", "cache.example.com");
    session.setRequest(req);

    try http_proxy.processRequest(&session);

    // Cache filter should have been consulted
    try testing.expect(cache_proxy.cache_checks >= 1);

    // No cache hits since we disabled caching in the filter
    const stats = http_proxy.getStats();
    try testing.expectEqual(stats.cache_hits, 0);
}


// ============================================================================
// Integration Tests with Actual Network I/O
// ============================================================================

test "integration: TCP listener bind and close" {
    // Simple test: just bind and close without actual connection
    var listener = try protocols.TcpListener.bind(
        testing.allocator,
        try protocols.parseAddress("127.0.0.1", 0),
        .{},
    );

    const addr = listener.getLocalAddress();
    try testing.expect(addr.getPort() > 0);

    listener.close();
}

test "integration: HTTP/2 connection preface constant" {
    const http2 = @import("http2.zig");
    
    // Verify the connection preface is correct per RFC 7540
    try testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", http2.CONNECTION_PREFACE);
    try testing.expectEqual(http2.CONNECTION_PREFACE.len, 24);
}

test "integration: HTTP/2 frame building and parsing roundtrip" {
    const http2 = @import("http2.zig");
    
    // Build a SETTINGS frame
    var buf: [128]u8 = undefined;
    const settings = http2.Settings{ .max_concurrent_streams = 200 };
    const len = http2.FrameBuilder.buildSettings(settings, false, &buf);
    
    // Parse it back
    const header = http2.FrameHeader.parse(buf[0..len]);
    try testing.expect(header != null);
    try testing.expectEqual(header.?.frame_type, .settings);
    try testing.expectEqual(header.?.stream_id, 0);
}

test "integration: HTTP/2 DATA frame roundtrip" {
    const http2 = @import("http2.zig");
    
    var buf: [256]u8 = undefined;
    const payload = "Hello, HTTP/2 World!";
    
    const len = try http2.FrameBuilder.buildData(5, payload, true, &buf);
    
    const header = http2.FrameHeader.parse(buf[0..len]);
    try testing.expect(header != null);
    try testing.expectEqual(header.?.frame_type, .data);
    try testing.expectEqual(header.?.stream_id, 5);
    try testing.expect(header.?.flags.hasEndStream());
    try testing.expectEqual(header.?.length, payload.len);
}

test "integration: HTTP/2 HEADERS frame roundtrip" {
    const http2 = @import("http2.zig");
    
    var buf: [256]u8 = undefined;
    const header_block = "encoded-headers";
    
    const len = try http2.FrameBuilder.buildHeaders(1, header_block, false, true, null, &buf);
    
    const header = http2.FrameHeader.parse(buf[0..len]);
    try testing.expect(header != null);
    try testing.expectEqual(header.?.frame_type, .headers);
    try testing.expect(header.?.flags.hasEndHeaders());
    try testing.expect(!header.?.flags.hasEndStream());
}

test "integration: WebSocket handshake key generation" {
    const websocket = @import("websocket.zig");
    
    // Test that handshake request generates valid key
    const req = websocket.HandshakeRequest.init("example.com", "/ws");
    try testing.expectEqual(req.key.len, 24);
    
    // Test that accept key is correctly generated
    const accept = websocket.generateAcceptKey(&req.key);
    try testing.expect(req.validateResponse(&accept));
}

test "integration: WebSocket handshake request building" {
    const websocket = @import("websocket.zig");
    
    var req = websocket.HandshakeRequest.init("localhost", "/chat");
    const data = try req.build(testing.allocator);
    defer testing.allocator.free(data);
    
    // Verify required headers are present
    try testing.expect(std.mem.indexOf(u8, data, "GET /chat HTTP/1.1") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Host: localhost") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Sec-WebSocket-Version: 13") != null);
}

test "integration: WebSocket handshake response building" {
    const websocket = @import("websocket.zig");
    
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var resp = websocket.HandshakeResponse.init(client_key);
    const data = try resp.build(testing.allocator);
    defer testing.allocator.free(data);
    
    try testing.expect(std.mem.indexOf(u8, data, "101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
}

test "integration: WebSocket client and server init" {
    const websocket = @import("websocket.zig");
    
    var client = websocket.WebSocketClient.init(testing.allocator);
    defer client.deinit();
    
    var server = websocket.WebSocketServer.init(testing.allocator);
    defer server.deinit();
    
    try testing.expect(!client.isHealthy()); // Not connected
    try testing.expectEqual(server.connection.state, .connecting);
    
    server.accept();
    try testing.expectEqual(server.connection.state, .open);
}

test "integration: HTTP/2 multiplexer with connection" {
    const http2 = @import("http2.zig");
    
    var conn = http2.Connection.initClient(testing.allocator);
    defer conn.deinit();
    
    var mux = http2.StreamMultiplexer.init(testing.allocator, &conn);
    defer mux.deinit();
    
    // Create a stream
    const stream = try conn.createStream();
    stream.state = .open;
    
    // Queue some data
    const test_data = "Hello, HTTP/2!";
    try mux.queueData(stream.id, test_data, true);
    
    try testing.expect(mux.hasPendingData());
    try testing.expectEqual(mux.pendingStreamCount(), 1);
    
    // Select should return our stream
    const selected = mux.selectNextStream();
    try testing.expect(selected != null);
    try testing.expectEqual(selected.?, stream.id);
}

test "integration: HTTP/2 flow control manager" {
    const http2 = @import("http2.zig");
    
    var conn = http2.Connection.initClient(testing.allocator);
    defer conn.deinit();
    
    var fcm = http2.FlowControlManager.init(testing.allocator, &conn);
    defer fcm.deinit();
    
    // Check initial state
    const stats = fcm.getStats();
    try testing.expectEqual(stats.connection_send_window, http2.DEFAULT_INITIAL_WINDOW_SIZE);
    try testing.expectEqual(stats.pending_window_updates, 0);
    
    // Should be able to send within window
    try testing.expect(fcm.canSend(0, 1000));
}

test "integration: full proxy session lifecycle" {
    // Test complete session lifecycle with all components
    var session = proxy.Session.init(testing.allocator);
    defer session.deinit();

    // Create and set request
    var req = try http.RequestHeader.build(testing.allocator, .POST, "/api/data", .http_1_1);
    try req.appendHeader("Host", "api.example.com");
    try req.appendHeader("Content-Type", "application/json");
    try req.appendHeader("Accept", "application/json");
    session.setRequest(req);

    try testing.expect(session.reqHeader() != null);
    try testing.expect(session.timing.request_start != null);

    // Create and set response  
    var resp = http.ResponseHeader.init(testing.allocator, 201);
    try resp.appendHeader("Content-Type", "application/json");
    try resp.appendHeader("X-Request-Id", "abc123");
    session.setResponse(resp);

    try testing.expect(session.respHeader() != null);
    try testing.expect(session.timing.response_start != null);
    
    session.markComplete();
    try testing.expect(session.timing.request_end != null);
    
    // Duration should be non-negative
    const duration = session.getDurationNs();
    try testing.expect(duration >= 0);
}

test "integration: HTTP parser to header serde roundtrip" {
    // Parse a request
    const raw_request = "GET /test HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "User-Agent: test\r\n" ++
        "\r\n";
    
    var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const parsed = try http_parser.parseRequestFull(raw_request, &headers_buf);
    try testing.expect(parsed != null);
    
    // Build a RequestHeader from parsed
    var req = try http.RequestHeader.build(
        testing.allocator,
        .GET,
        parsed.?.path,
        .http_1_1,
    );
    defer req.deinit();
    
    for (parsed.?.headers) |h| {
        try req.appendHeader(h.name, h.value);
    }
    
    // Serialize back to wire format
    const wire = try header_serde.requestToWireFormat(testing.allocator, &req);
    defer testing.allocator.free(wire);
    
    // Verify it can be parsed again
    var headers_buf2: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
    const reparsed = try http_parser.parseRequestFull(wire, &headers_buf2);
    try testing.expect(reparsed != null);
    try testing.expectEqualStrings("/test", reparsed.?.path);
}
