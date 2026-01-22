//! Caching Proxy Example
//!
//! This example demonstrates a caching reverse proxy that stores
//! responses in memory to reduce backend load.

const std = @import("std");
const pingora = @import("pingora");

const http_parser = pingora.http_parser;
const lru = pingora.lru;

/// Cache entry
pub const CacheEntry = struct {
    response: []u8,
    created_at: i64,
    ttl_seconds: u32,
    
    pub fn isExpired(self: CacheEntry) bool {
        const now = std.time.timestamp();
        return now > self.created_at + self.ttl_seconds;
    }
};

/// Simple HTTP cache
pub const HttpCache = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(CacheEntry),
    max_entries: usize,
    default_ttl: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_entries: usize, default_ttl: u32) Self {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .max_entries = max_entries,
            .default_ttl = default_ttl,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.response);
        }
        self.entries.deinit();
    }

    pub fn get(self: *Self, key: []const u8) ?[]const u8 {
        if (self.entries.get(key)) |entry| {
            if (!entry.isExpired()) {
                return entry.response;
            }
            // Remove expired entry
            self.remove(key);
        }
        return null;
    }

    pub fn put(self: *Self, key: []const u8, response: []const u8, ttl: ?u32) !void {
        // Evict if at capacity
        if (self.entries.count() >= self.max_entries) {
            self.evictOne();
        }

        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        const response_copy = try self.allocator.dupe(u8, response);
        errdefer self.allocator.free(response_copy);

        try self.entries.put(key_copy, .{
            .response = response_copy,
            .created_at = std.time.timestamp(),
            .ttl_seconds = ttl orelse self.default_ttl,
        });
    }

    pub fn remove(self: *Self, key: []const u8) void {
        if (self.entries.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.response);
        }
    }

    fn evictOne(self: *Self) void {
        var iter = self.entries.iterator();
        if (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.response);
            self.entries.removeByPtr(entry.key_ptr);
        }
    }
};

/// Caching Proxy
pub const CachingProxy = struct {
    allocator: std.mem.Allocator,
    cache: HttpCache,
    upstream_host: []const u8,
    upstream_port: u16,
    listen_port: u16,
    cache_hits: u64,
    cache_misses: u64,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        upstream_host: []const u8,
        upstream_port: u16,
    ) Self {
        return .{
            .allocator = allocator,
            .cache = HttpCache.init(allocator, 1000, 300),
            .upstream_host = upstream_host,
            .upstream_port = upstream_port,
            .listen_port = listen_port,
            .cache_hits = 0,
            .cache_misses = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
    }

    pub fn proxyRequest(self: *Self, request: []const u8) ![]u8 {
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        const parsed = try http_parser.parseRequestFull(request, &headers_buf);
        if (parsed == null) return error.InvalidRequest;

        // Only cache GET requests
        const is_get = std.mem.eql(u8, parsed.?.method, "GET");
        const cache_key = parsed.?.path;

        // Check cache
        if (is_get) {
            if (self.cache.get(cache_key)) |cached| {
                self.cache_hits += 1;
                return try self.allocator.dupe(u8, cached);
            }
        }
        self.cache_misses += 1;

        // Fetch from upstream
        const response = try self.fetchFromUpstream(request);

        // Cache successful GET responses
        if (is_get and self.isCacheable(response)) {
            self.cache.put(cache_key, response, null) catch {};
        }

        return response;
    }

    fn isCacheable(self: *Self, response: []const u8) bool {
        _ = self;
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        if (http_parser.parseResponseFull(response, &headers_buf)) |maybe_parsed| {
            if (maybe_parsed) |parsed| {
                // Only cache 200 OK
                if (parsed.status_code != 200) return false;
                // Check Cache-Control
                for (parsed.headers) |h| {
                    if (std.ascii.eqlIgnoreCase(h.name, "Cache-Control")) {
                        if (std.mem.indexOf(u8, h.value, "no-store") != null) return false;
                        if (std.mem.indexOf(u8, h.value, "private") != null) return false;
                    }
                }
                return true;
            }
        } else |_| {}
        return false;
    }

    fn fetchFromUpstream(self: *Self, request: []const u8) ![]u8 {
        const address = std.net.Address.parseIp4(self.upstream_host, self.upstream_port) catch {
            return error.InvalidUpstreamAddress;
        };

        const stream = std.net.tcpConnectToAddress(address) catch {
            return error.UpstreamConnectionFailed;
        };
        defer stream.close();

        _ = stream.write(request) catch return error.UpstreamWriteFailed;

        var response: std.ArrayListUnmanaged(u8) = .{};
        errdefer response.deinit(self.allocator);

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stream.read(&buf) catch break;
            if (n == 0) break;
            try response.appendSlice(self.allocator, buf[0..n]);
            if (std.mem.indexOf(u8, response.items, "\r\n\r\n") != null) {
                if (response.items.len > 1000 or n < buf.len) break;
            }
        }

        return response.toOwnedSlice(self.allocator);
    }

    pub fn getStats(self: *Self) Stats {
        const total = self.cache_hits + self.cache_misses;
        return .{
            .cache_hits = self.cache_hits,
            .cache_misses = self.cache_misses,
            .hit_rate = if (total > 0) @as(f64, @floatFromInt(self.cache_hits)) / @as(f64, @floatFromInt(total)) * 100.0 else 0.0,
            .cached_entries = self.cache.entries.count(),
        };
    }

    pub const Stats = struct {
        cache_hits: u64,
        cache_misses: u64,
        hit_rate: f64,
        cached_entries: usize,
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var proxy = CachingProxy.init(allocator, 8080, "127.0.0.1", 8000);
    defer proxy.deinit();

    std.debug.print(
        \\
        \\=== Caching Proxy ===
        \\Listening on: http://localhost:{d}
        \\Upstream: http://{s}:{d}
        \\Cache: 1000 entries, 300s TTL
        \\
    , .{ proxy.listen_port, proxy.upstream_host, proxy.upstream_port });

    const address = try std.net.Address.parseIp4("127.0.0.1", proxy.listen_port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    while (true) {
        var conn = server.accept() catch continue;
        handleConnection(allocator, &proxy, &conn) catch {};
        conn.stream.close();
    }
}

fn handleConnection(allocator: std.mem.Allocator, proxy: *CachingProxy, conn: *std.net.Server.Connection) !void {
    var buf: [8192]u8 = undefined;
    const n = try conn.stream.read(&buf);
    if (n == 0) return;

    const response = proxy.proxyRequest(buf[0..n]) catch {
        _ = try conn.stream.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway");
        return;
    };
    defer allocator.free(response);

    _ = try conn.stream.write(response);

    const stats = proxy.getStats();
    std.debug.print("Cache: {d} hits, {d} misses, {d:.1}% hit rate\n", .{ stats.cache_hits, stats.cache_misses, stats.hit_rate });
}

test "HttpCache basic" {
    const allocator = std.testing.allocator;
    var cache = HttpCache.init(allocator, 10, 60);
    defer cache.deinit();

    try cache.put("/test", "response data", null);
    const result = cache.get("/test");
    try std.testing.expect(result != null);
}
