//! pingora-cache: HTTP caching layer
//!
//! A high-performance HTTP cache implementation that handles:
//! - Cache-Control header parsing and enforcement
//! - Cache key generation from requests
//! - Response caching with TTL support
//! - Conditional requests (ETag, If-Modified-Since)
//! - Cache validation and revalidation
//!
//! This is a pure Zig implementation. No C dependencies.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-cache

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const http = @import("http.zig");
const memory_cache = @import("memory_cache.zig");
const lru = @import("lru.zig");

// ============================================================================
// Cache-Control Directives
// ============================================================================

/// Parsed Cache-Control header directives
pub const CacheControl = struct {
    /// Response may be stored by any cache
    public: bool = false,
    /// Response is intended for single user, must not be stored by shared cache
    private: bool = false,
    /// Response must not be stored
    no_store: bool = false,
    /// Response must be revalidated before use
    no_cache: bool = false,
    /// Cache must not transform the response
    no_transform: bool = false,
    /// Response must be revalidated once stale
    must_revalidate: bool = false,
    /// Like must-revalidate, but only for shared caches
    proxy_revalidate: bool = false,
    /// Maximum age in seconds the response is fresh
    max_age: ?u64 = null,
    /// Maximum age for shared caches
    s_maxage: ?u64 = null,
    /// Maximum staleness client will accept
    max_stale: ?u64 = null,
    /// Minimum freshness client requires
    min_fresh: ?u64 = null,
    /// Response can be served stale while revalidating
    stale_while_revalidate: ?u64 = null,
    /// Response can be served stale if error occurs
    stale_if_error: ?u64 = null,
    /// Caches must not use response without revalidation
    immutable: bool = false,
    /// Only serve from cache, don't fetch from origin
    only_if_cached: bool = false,

    const Self = @This();

    /// Parse Cache-Control header value
    pub fn parse(value: []const u8) Self {
        var result = Self{};
        var iter = std.mem.splitSequence(u8, value, ",");

        while (iter.next()) |directive_raw| {
            const directive = std.mem.trim(u8, directive_raw, " \t");
            if (directive.len == 0) continue;

            // Check for directives with values (directive=value)
            if (std.mem.indexOf(u8, directive, "=")) |eq_pos| {
                const name = std.mem.trim(u8, directive[0..eq_pos], " \t");
                const val_str = std.mem.trim(u8, directive[eq_pos + 1 ..], " \t\"");

                if (std.ascii.eqlIgnoreCase(name, "max-age")) {
                    result.max_age = std.fmt.parseInt(u64, val_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(name, "s-maxage")) {
                    result.s_maxage = std.fmt.parseInt(u64, val_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(name, "max-stale")) {
                    result.max_stale = std.fmt.parseInt(u64, val_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(name, "min-fresh")) {
                    result.min_fresh = std.fmt.parseInt(u64, val_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(name, "stale-while-revalidate")) {
                    result.stale_while_revalidate = std.fmt.parseInt(u64, val_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(name, "stale-if-error")) {
                    result.stale_if_error = std.fmt.parseInt(u64, val_str, 10) catch null;
                }
            } else {
                // Boolean directives
                if (std.ascii.eqlIgnoreCase(directive, "public")) {
                    result.public = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "private")) {
                    result.private = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "no-store")) {
                    result.no_store = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "no-cache")) {
                    result.no_cache = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "no-transform")) {
                    result.no_transform = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "must-revalidate")) {
                    result.must_revalidate = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "proxy-revalidate")) {
                    result.proxy_revalidate = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "immutable")) {
                    result.immutable = true;
                } else if (std.ascii.eqlIgnoreCase(directive, "only-if-cached")) {
                    result.only_if_cached = true;
                }
            }
        }

        return result;
    }

    /// Check if response is cacheable based on directives
    pub fn isCacheable(self: *const Self) bool {
        // no-store means never cache
        if (self.no_store) return false;
        // private means don't cache in shared cache
        if (self.private) return false;
        // Must have some indication of freshness to cache
        return self.max_age != null or self.s_maxage != null or self.public;
    }

    /// Get the TTL in seconds for caching
    pub fn getTtlSeconds(self: *const Self) ?u64 {
        // s-maxage takes precedence for shared caches
        if (self.s_maxage) |s| return s;
        return self.max_age;
    }

    /// Format Cache-Control header value
    pub fn format(self: *const Self, allocator: Allocator) ![]u8 {
        var parts = std.ArrayList([]const u8).init(allocator);
        defer parts.deinit();

        if (self.public) try parts.append("public");
        if (self.private) try parts.append("private");
        if (self.no_store) try parts.append("no-store");
        if (self.no_cache) try parts.append("no-cache");
        if (self.no_transform) try parts.append("no-transform");
        if (self.must_revalidate) try parts.append("must-revalidate");
        if (self.proxy_revalidate) try parts.append("proxy-revalidate");
        if (self.immutable) try parts.append("immutable");
        if (self.only_if_cached) try parts.append("only-if-cached");

        // Calculate total size needed
        var total_len: usize = 0;
        for (parts.items) |part| {
            if (total_len > 0) total_len += 2; // ", "
            total_len += part.len;
        }

        // Add space for numeric directives
        var numeric_parts = std.ArrayList([]u8).init(allocator);
        defer {
            for (numeric_parts.items) |p| allocator.free(p);
            numeric_parts.deinit();
        }

        if (self.max_age) |v| {
            const s = try std.fmt.allocPrint(allocator, "max-age={d}", .{v});
            try numeric_parts.append(s);
        }
        if (self.s_maxage) |v| {
            const s = try std.fmt.allocPrint(allocator, "s-maxage={d}", .{v});
            try numeric_parts.append(s);
        }

        for (numeric_parts.items) |np| {
            if (total_len > 0) total_len += 2;
            total_len += np.len;
        }

        // Build result
        var result = try allocator.alloc(u8, total_len);
        var pos: usize = 0;

        for (parts.items, 0..) |part, i| {
            if (i > 0) {
                @memcpy(result[pos .. pos + 2], ", ");
                pos += 2;
            }
            @memcpy(result[pos .. pos + part.len], part);
            pos += part.len;
        }

        const base_parts_count = parts.items.len;
        for (numeric_parts.items, 0..) |np, i| {
            if (base_parts_count > 0 or i > 0) {
                @memcpy(result[pos .. pos + 2], ", ");
                pos += 2;
            }
            @memcpy(result[pos .. pos + np.len], np);
            pos += np.len;
        }

        return result;
    }
};

// ============================================================================
// Cache Key
// ============================================================================

/// A cache key uniquely identifies a cached response
pub const CacheKey = struct {
    /// The full key string
    key: []const u8,
    /// Whether we own the memory
    owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    /// Generate a cache key from a request
    pub fn fromRequest(allocator: Allocator, req: *const http.RequestHeader) !Self {
        // Default key: METHOD:HOST:PATH?QUERY
        const method = req.method.asStr();
        const host = req.headers.get("host") orelse "localhost";
        const path_query = req.uri.pathAndQuery();

        const key = try std.fmt.allocPrint(allocator, "{s}:{s}:{s}", .{ method, host, path_query });

        return .{
            .key = key,
            .owned = true,
            .allocator = allocator,
        };
    }

    /// Create from a raw string (borrowed)
    pub fn fromSlice(key: []const u8) Self {
        return .{
            .key = key,
            .owned = false,
            .allocator = null,
        };
    }

    /// Create from a raw string (owned copy)
    pub fn fromSliceOwned(allocator: Allocator, key: []const u8) !Self {
        return .{
            .key = try allocator.dupe(u8, key),
            .owned = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.key);
            }
        }
    }

    /// Get the key as a slice
    pub fn asSlice(self: *const Self) []const u8 {
        return self.key;
    }

    /// Hash the key for use in hash maps
    pub fn hash(self: *const Self) u64 {
        return std.hash.Wyhash.hash(0, self.key);
    }
};

// ============================================================================
// Cached Response
// ============================================================================

/// Metadata about a cached response
pub const CacheMeta = struct {
    /// When the response was cached (nanoseconds since epoch)
    cached_at: i128,
    /// When the response expires (nanoseconds since epoch), null means no expiry
    expires_at: ?i128,
    /// The ETag if present
    etag: ?[]const u8,
    /// Last-Modified timestamp if present
    last_modified: ?[]const u8,
    /// Original status code
    status: u16,
    /// Content-Type
    content_type: ?[]const u8,
    /// Content-Length
    content_length: ?usize,
    /// Whether response can be served stale
    stale_while_revalidate: ?u64,
    /// Whether response can be served stale on error
    stale_if_error: ?u64,

    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .cached_at = std.time.nanoTimestamp(),
            .expires_at = null,
            .etag = null,
            .last_modified = null,
            .status = 200,
            .content_type = null,
            .content_length = null,
            .stale_while_revalidate = null,
            .stale_if_error = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.etag) |e| self.allocator.free(e);
        if (self.last_modified) |lm| self.allocator.free(lm);
        if (self.content_type) |ct| self.allocator.free(ct);
    }

    /// Create metadata from a response header
    pub fn fromResponse(allocator: Allocator, resp: *const http.ResponseHeader, cc: *const CacheControl) !Self {
        var meta = Self.init(allocator);
        errdefer meta.deinit();

        meta.status = resp.status.code;

        // Set expiration based on Cache-Control
        if (cc.getTtlSeconds()) |ttl| {
            meta.expires_at = meta.cached_at + @as(i128, ttl) * std.time.ns_per_s;
        }

        meta.stale_while_revalidate = cc.stale_while_revalidate;
        meta.stale_if_error = cc.stale_if_error;

        // Copy ETag
        if (resp.headers.get("etag")) |etag| {
            meta.etag = try allocator.dupe(u8, etag);
        }

        // Copy Last-Modified
        if (resp.headers.get("last-modified")) |lm| {
            meta.last_modified = try allocator.dupe(u8, lm);
        }

        // Copy Content-Type
        if (resp.headers.get("content-type")) |ct| {
            meta.content_type = try allocator.dupe(u8, ct);
        }

        // Parse Content-Length
        if (resp.headers.get("content-length")) |cl| {
            meta.content_length = std.fmt.parseInt(usize, cl, 10) catch null;
        }

        return meta;
    }

    /// Check if the cached response is fresh
    pub fn isFresh(self: *const Self) bool {
        if (self.expires_at) |exp| {
            return std.time.nanoTimestamp() < exp;
        }
        // No expiry means always fresh (immutable)
        return true;
    }

    /// Check if response is stale but can be served while revalidating
    pub fn canServeStaleWhileRevalidating(self: *const Self) bool {
        if (!self.isFresh()) {
            if (self.stale_while_revalidate) |swr| {
                if (self.expires_at) |exp| {
                    const stale_deadline = exp + @as(i128, swr) * std.time.ns_per_s;
                    return std.time.nanoTimestamp() < stale_deadline;
                }
            }
        }
        return false;
    }

    /// Check if response can be served stale on error
    pub fn canServeStaleOnError(self: *const Self) bool {
        if (self.stale_if_error) |sie| {
            if (self.expires_at) |exp| {
                const stale_deadline = exp + @as(i128, sie) * std.time.ns_per_s;
                return std.time.nanoTimestamp() < stale_deadline;
            }
            // No expiry with stale-if-error means can always serve on error
            return true;
        }
        return false;
    }

    /// Get the age of the cached response in seconds
    pub fn getAgeSeconds(self: *const Self) u64 {
        const now = std.time.nanoTimestamp();
        const age_ns = now - self.cached_at;
        if (age_ns < 0) return 0;
        return @intCast(@divFloor(age_ns, std.time.ns_per_s));
    }
};

/// A cached HTTP response
pub const CachedResponse = struct {
    /// Cache metadata
    meta: CacheMeta,
    /// Response headers (serialized)
    headers: []const u8,
    /// Response body
    body: []const u8,

    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, meta: CacheMeta, headers: []const u8, body: []const u8) !Self {
        return .{
            .meta = meta,
            .headers = try allocator.dupe(u8, headers),
            .body = try allocator.dupe(u8, body),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.meta.deinit();
        self.allocator.free(self.headers);
        self.allocator.free(self.body);
    }

    /// Get total size in bytes
    pub fn size(self: *const Self) usize {
        return self.headers.len + self.body.len;
    }
};

// ============================================================================
// Cache Lookup Result
// ============================================================================

/// Result of a cache lookup
pub const CacheLookupResult = union(enum) {
    /// Cache hit with fresh response
    hit,
    /// Cache hit but response is stale (needs revalidation)
    stale,
    /// Cache miss
    miss,
    /// Response should not be served from cache (no-cache, etc.)
    bypass,

    pub fn isHit(self: CacheLookupResult) bool {
        return self == .hit;
    }

    pub fn isMiss(self: CacheLookupResult) bool {
        return self == .miss;
    }

    pub fn isStale(self: CacheLookupResult) bool {
        return self == .stale;
    }
};

// ============================================================================
// HTTP Cache
// ============================================================================

/// Configuration for the HTTP cache
pub const HttpCacheConfig = struct {
    /// Maximum number of entries
    max_entries: usize = 10000,
    /// Maximum total size in bytes (0 = unlimited)
    max_size_bytes: usize = 0,
    /// Default TTL if response doesn't specify (in seconds)
    default_ttl_seconds: u64 = 300,
    /// Whether to respect Cache-Control: private
    respect_private: bool = true,
    /// Whether to respect Cache-Control: no-store
    respect_no_store: bool = true,
    /// Whether to cache responses without explicit caching headers
    cache_without_headers: bool = false,
};

/// HTTP Cache implementation
pub const HttpCache = struct {
    /// The underlying cache storage
    cache_store: CacheStore,
    /// Cache configuration
    config: HttpCacheConfig,
    /// Allocator
    allocator: Allocator,
    /// Statistics
    stats: CacheStats,

    const Self = @This();
    const CacheStore = memory_cache.MemoryCache(u64, CachedResponse);

    /// Cache statistics
    pub const CacheStats = struct {
        hits: u64 = 0,
        misses: u64 = 0,
        stale_hits: u64 = 0,
        bypasses: u64 = 0,
        stores: u64 = 0,
        evictions: u64 = 0,

        pub fn hitRate(self: *const CacheStats) f64 {
            const total = self.hits + self.misses + self.stale_hits + self.bypasses;
            if (total == 0) return 0.0;
            return @as(f64, @floatFromInt(self.hits + self.stale_hits)) / @as(f64, @floatFromInt(total));
        }
    };

    /// Create a new HTTP cache
    pub fn init(allocator: Allocator, config: HttpCacheConfig) !Self {
        return .{
            .cache_store = try CacheStore.init(allocator, config.max_entries),
            .config = config,
            .allocator = allocator,
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.cache_store.deinit();
    }

    /// Check if a request is cacheable
    pub fn isRequestCacheable(self: *const Self, req: *const http.RequestHeader) bool {
        // Only GET and HEAD are cacheable
        if (req.method != .GET and req.method != .HEAD) {
            return false;
        }

        // Check request Cache-Control
        if (req.headers.get("cache-control")) |cc_str| {
            const cc = CacheControl.parse(cc_str);
            if (cc.no_store and self.config.respect_no_store) return false;
        }

        // Check Authorization header (typically not cacheable)
        if (req.headers.get("authorization") != null) {
            return false;
        }

        return true;
    }

    /// Check if a response is cacheable
    pub fn isResponseCacheable(self: *const Self, resp: *const http.ResponseHeader) bool {
        // Only cache successful responses and 304
        const code = resp.status.code;
        if (!(code == 200 or code == 203 or code == 204 or code == 206 or
            code == 300 or code == 301 or code == 304 or code == 404 or code == 410))
        {
            return false;
        }

        // Check Cache-Control
        if (resp.headers.get("cache-control")) |cc_str| {
            const cc = CacheControl.parse(cc_str);

            if (cc.no_store and self.config.respect_no_store) return false;
            if (cc.private and self.config.respect_private) return false;

            // Has explicit caching directives
            if (cc.max_age != null or cc.s_maxage != null or cc.public) {
                return true;
            }
        }

        // Check Expires header
        if (resp.headers.get("expires") != null) {
            return true;
        }

        // No explicit caching headers
        return self.config.cache_without_headers;
    }

    /// Look up a cached response
    pub fn lookup(self: *Self, req: *const http.RequestHeader) !CacheLookupResult {
        // Check if request is cacheable
        if (!self.isRequestCacheable(req)) {
            self.stats.bypasses += 1;
            return .bypass;
        }

        // Check request Cache-Control for no-cache
        if (req.headers.get("cache-control")) |cc_str| {
            const cc = CacheControl.parse(cc_str);
            if (cc.no_cache) {
                self.stats.bypasses += 1;
                return .bypass;
            }
        }

        // Generate cache key
        var key = try CacheKey.fromRequest(self.allocator, req);
        defer key.deinit();

        const result = self.cache_store.get(key.hash());

        if (result[0]) |cached| {
            switch (result[1]) {
                .hit => {
                    if (cached.meta.isFresh()) {
                        self.stats.hits += 1;
                        return .hit;
                    } else if (cached.meta.canServeStaleWhileRevalidating()) {
                        self.stats.stale_hits += 1;
                        return .stale;
                    } else {
                        self.stats.misses += 1;
                        return .miss;
                    }
                },
                .expired => {
                    if (cached.meta.canServeStaleWhileRevalidating()) {
                        self.stats.stale_hits += 1;
                        return .stale;
                    }
                    self.stats.misses += 1;
                    return .miss;
                },
                else => {
                    self.stats.misses += 1;
                    return .miss;
                },
            }
        }

        self.stats.misses += 1;
        return .miss;
    }

    /// Store a response in the cache
    pub fn store(
        self: *Self,
        req: *const http.RequestHeader,
        resp: *const http.ResponseHeader,
        body: []const u8,
    ) !bool {
        // Check if response is cacheable
        if (!self.isResponseCacheable(resp)) {
            return false;
        }

        // Parse Cache-Control
        var cc = CacheControl{};
        if (resp.headers.get("cache-control")) |cc_str| {
            cc = CacheControl.parse(cc_str);
        } else if (self.config.cache_without_headers) {
            // Use default TTL
            cc.max_age = self.config.default_ttl_seconds;
        } else {
            return false;
        }

        // Generate cache key
        var key = try CacheKey.fromRequest(self.allocator, req);
        defer key.deinit();

        // Create cache metadata
        var meta = try CacheMeta.fromResponse(self.allocator, resp, &cc);
        errdefer meta.deinit();

        // Serialize headers
        var header_buf: std.ArrayListUnmanaged(u8) = .{};
        defer header_buf.deinit(self.allocator);
        try resp.writeHttp1(header_buf.writer(self.allocator));

        // Create cached response
        const cached = try CachedResponse.init(self.allocator, meta, header_buf.items, body);

        // Calculate TTL in nanoseconds
        const ttl_ns: ?u64 = if (cc.getTtlSeconds()) |ttl|
            ttl * std.time.ns_per_s
        else
            null;

        // Store in cache
        _ = try self.cache_store.put(key.hash(), cached, ttl_ns);
        self.stats.stores += 1;

        return true;
    }

    /// Invalidate a cache entry
    pub fn invalidate(self: *Self, req: *const http.RequestHeader) !bool {
        var key = try CacheKey.fromRequest(self.allocator, req);
        defer key.deinit();

        return self.cache_store.remove(key.hash());
    }

    /// Purge all entries from the cache
    pub fn purge(self: *Self) void {
        self.cache_store.deinit();
        self.cache_store = CacheStore.init(self.allocator, self.config.max_entries) catch return;
        self.stats = .{};
    }

    /// Get cache statistics
    pub fn getStats(self: *const Self) CacheStats {
        return self.stats;
    }
};

// ============================================================================
// Conditional Request Helpers
// ============================================================================

/// Check if a conditional request matches the cached response
pub fn checkConditional(req: *const http.RequestHeader, cached: *const CachedResponse) ConditionalResult {
    // Check If-None-Match (ETag)
    if (req.headers.get("if-none-match")) |inm| {
        if (cached.meta.etag) |etag| {
            if (etagMatches(inm, etag)) {
                return .not_modified;
            }
        }
        return .modified;
    }

    // Check If-Modified-Since
    if (req.headers.get("if-modified-since")) |ims| {
        if (cached.meta.last_modified) |lm| {
            // Simple string comparison (both should be in HTTP-date format)
            if (std.mem.eql(u8, ims, lm)) {
                return .not_modified;
            }
        }
    }

    return .no_condition;
}

/// Result of conditional request check
pub const ConditionalResult = enum {
    /// No conditional headers present
    no_condition,
    /// Resource has not been modified (304)
    not_modified,
    /// Resource has been modified
    modified,
};

/// Check if an ETag matches (handles weak ETags and *)
fn etagMatches(if_none_match: []const u8, etag: []const u8) bool {
    // Handle * (matches any)
    if (std.mem.eql(u8, if_none_match, "*")) {
        return true;
    }

    // Parse multiple ETags in If-None-Match
    var iter = std.mem.splitSequence(u8, if_none_match, ",");
    while (iter.next()) |tag_raw| {
        const tag = std.mem.trim(u8, tag_raw, " \t");

        // Compare (weak comparison - ignore W/ prefix)
        const tag_value = if (std.mem.startsWith(u8, tag, "W/"))
            tag[2..]
        else
            tag;

        const etag_value = if (std.mem.startsWith(u8, etag, "W/"))
            etag[2..]
        else
            etag;

        if (std.mem.eql(u8, tag_value, etag_value)) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Vary Header Support
// ============================================================================

/// Generate a vary-aware cache key
pub fn generateVaryKey(
    allocator: Allocator,
    req: *const http.RequestHeader,
    vary_headers: []const []const u8,
) !CacheKey {
    var parts: std.ArrayListUnmanaged(u8) = .{};
    defer parts.deinit(allocator);

    // Start with basic key components
    try parts.appendSlice(allocator, req.method.asStr());
    try parts.append(allocator, ':');

    if (req.headers.get("host")) |host| {
        try parts.appendSlice(allocator, host);
    } else {
        try parts.appendSlice(allocator, "localhost");
    }

    try parts.append(allocator, ':');
    try parts.appendSlice(allocator, req.uri.pathAndQuery());

    // Add vary header values
    for (vary_headers) |header_name| {
        try parts.append(allocator, ':');
        try parts.appendSlice(allocator, header_name);
        try parts.append(allocator, '=');
        if (req.headers.get(header_name)) |value| {
            try parts.appendSlice(allocator, value);
        }
    }

    const key = try allocator.dupe(u8, parts.items);
    return .{
        .key = key,
        .owned = true,
        .allocator = allocator,
    };
}

/// Parse Vary header value into list of header names
pub fn parseVaryHeader(allocator: Allocator, vary: []const u8) ![][]const u8 {
    var headers: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer headers.deinit(allocator);

    var iter = std.mem.splitSequence(u8, vary, ",");
    while (iter.next()) |header_raw| {
        const header = std.mem.trim(u8, header_raw, " \t");
        if (header.len > 0) {
            try headers.append(allocator, header);
        }
    }

    return headers.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "CacheControl parse basic directives" {
    const cc = CacheControl.parse("public, max-age=3600");
    try testing.expect(cc.public);
    try testing.expect(!cc.private);
    try testing.expectEqual(cc.max_age, 3600);
}

test "CacheControl parse no-store" {
    const cc = CacheControl.parse("no-store, no-cache");
    try testing.expect(cc.no_store);
    try testing.expect(cc.no_cache);
    try testing.expect(!cc.isCacheable());
}

test "CacheControl parse s-maxage" {
    const cc = CacheControl.parse("public, max-age=3600, s-maxage=7200");
    try testing.expectEqual(cc.max_age, 3600);
    try testing.expectEqual(cc.s_maxage, 7200);
    try testing.expectEqual(cc.getTtlSeconds(), 7200); // s-maxage takes precedence
}

test "CacheControl parse stale directives" {
    const cc = CacheControl.parse("max-age=300, stale-while-revalidate=60, stale-if-error=86400");
    try testing.expectEqual(cc.max_age, 300);
    try testing.expectEqual(cc.stale_while_revalidate, 60);
    try testing.expectEqual(cc.stale_if_error, 86400);
}

test "CacheControl isCacheable" {
    // Cacheable
    try testing.expect(CacheControl.parse("public, max-age=300").isCacheable());
    try testing.expect(CacheControl.parse("max-age=300").isCacheable());

    // Not cacheable
    try testing.expect(!CacheControl.parse("no-store").isCacheable());
    try testing.expect(!CacheControl.parse("private, max-age=300").isCacheable());
}

test "CacheKey fromRequest" {
    var req = try http.RequestHeader.build(testing.allocator, .GET, "/api/users?page=1", null);
    defer req.deinit();
    try req.appendHeader("Host", "example.com");

    var key = try CacheKey.fromRequest(testing.allocator, &req);
    defer key.deinit();

    try testing.expect(std.mem.indexOf(u8, key.asSlice(), "GET") != null);
    try testing.expect(std.mem.indexOf(u8, key.asSlice(), "example.com") != null);
    try testing.expect(std.mem.indexOf(u8, key.asSlice(), "/api/users") != null);
}

test "CacheMeta freshness" {
    var meta = CacheMeta.init(testing.allocator);
    defer meta.deinit();

    // No expiry = always fresh
    try testing.expect(meta.isFresh());

    // Set expiry in the past
    meta.expires_at = std.time.nanoTimestamp() - std.time.ns_per_s;
    try testing.expect(!meta.isFresh());

    // Set expiry in the future
    meta.expires_at = std.time.nanoTimestamp() + 10 * std.time.ns_per_s;
    try testing.expect(meta.isFresh());
}

test "HttpCache basic operations" {
    // Use a simple arena allocator for this test since the cache 
    // stores values that have internal allocations
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = try HttpCache.init(alloc, .{});
    defer cache.deinit();

    // Create a request
    var req = try http.RequestHeader.build(alloc, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("Host", "example.com");

    // Create a response
    var resp = http.ResponseHeader.init(alloc, 200);
    defer resp.deinit();
    try resp.appendHeader("Cache-Control", "public, max-age=3600");
    try resp.appendHeader("Content-Type", "text/html");

    // Initially should be a miss
    const result1 = try cache.lookup(&req);
    try testing.expect(result1.isMiss());

    // Store the response
    const stored = try cache.store(&req, &resp, "<html>test</html>");
    try testing.expect(stored);

    // Now should be a hit
    const result2 = try cache.lookup(&req);
    try testing.expect(result2.isHit());

    // Check stats
    const stats = cache.getStats();
    try testing.expectEqual(stats.misses, 1);
    try testing.expectEqual(stats.hits, 1);
    try testing.expectEqual(stats.stores, 1);
}

test "HttpCache respects no-store" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = try HttpCache.init(alloc, .{});
    defer cache.deinit();

    var req = try http.RequestHeader.build(alloc, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("Host", "example.com");

    var resp = http.ResponseHeader.init(alloc, 200);
    defer resp.deinit();
    try resp.appendHeader("Cache-Control", "no-store");

    // Should not store
    const stored = try cache.store(&req, &resp, "body");
    try testing.expect(!stored);
}

test "HttpCache POST not cacheable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = try HttpCache.init(alloc, .{});
    defer cache.deinit();

    var req = try http.RequestHeader.build(alloc, .POST, "/test", null);
    defer req.deinit();

    try testing.expect(!cache.isRequestCacheable(&req));
}

test "etagMatches" {
    // Exact match
    try testing.expect(etagMatches("\"abc123\"", "\"abc123\""));

    // Wildcard
    try testing.expect(etagMatches("*", "\"anything\""));

    // Weak comparison
    try testing.expect(etagMatches("W/\"abc\"", "\"abc\""));
    try testing.expect(etagMatches("\"abc\"", "W/\"abc\""));

    // Multiple ETags
    try testing.expect(etagMatches("\"foo\", \"bar\", \"abc\"", "\"bar\""));

    // No match
    try testing.expect(!etagMatches("\"foo\"", "\"bar\""));
}

test "checkConditional with ETag" {
    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("If-None-Match", "\"abc123\"");

    var meta = CacheMeta.init(testing.allocator);
    meta.etag = "\"abc123\"";
    defer {
        meta.etag = null; // Don't free static string
        meta.deinit();
    }

    var cached = CachedResponse{
        .meta = meta,
        .headers = "",
        .body = "",
        .allocator = testing.allocator,
    };

    const result = checkConditional(&req, &cached);
    try testing.expectEqual(result, .not_modified);
}

test "parseVaryHeader" {
    const vary = "Accept-Encoding, Accept-Language, Cookie";
    const headers = try parseVaryHeader(testing.allocator, vary);
    defer testing.allocator.free(headers);

    try testing.expectEqual(headers.len, 3);
    try testing.expectEqualStrings("Accept-Encoding", headers[0]);
    try testing.expectEqualStrings("Accept-Language", headers[1]);
    try testing.expectEqualStrings("Cookie", headers[2]);
}

test "generateVaryKey" {
    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("Host", "example.com");
    try req.appendHeader("Accept-Encoding", "gzip");

    const vary_headers = [_][]const u8{"Accept-Encoding"};
    var key = try generateVaryKey(testing.allocator, &req, &vary_headers);
    defer key.deinit();

    try testing.expect(std.mem.indexOf(u8, key.asSlice(), "Accept-Encoding=gzip") != null);
}

// ============================================================================
// Cache Lock System - Prevents Thundering Herd
// ============================================================================

/// Status which the read locks could possibly see
pub const LockStatus = enum(u8) {
    /// Waiting for the writer to populate the asset
    waiting = 0,
    /// The writer finishes, readers can start
    done = 1,
    /// The writer encountered error, such as network issue. A new writer will be elected.
    transient_error = 2,
    /// The writer observed that no cache lock is needed (e.g., uncacheable), readers should start
    /// to fetch independently without a new writer
    give_up = 3,
    /// The write lock is dropped without being unlocked
    dangling = 4,
    /// Reader has held onto cache locks for too long, give up
    wait_timeout = 5,
    /// The lock is held for too long by the writer
    age_timeout = 6,

    pub fn asStr(self: LockStatus) []const u8 {
        return switch (self) {
            .waiting => "waiting",
            .done => "done",
            .transient_error => "transient_error",
            .give_up => "give_up",
            .dangling => "dangling",
            .wait_timeout => "wait_timeout",
            .age_timeout => "age_timeout",
        };
    }
};

/// Core lock state shared between writer and readers
pub const LockCore = struct {
    /// When the lock was created (nanoseconds since epoch)
    lock_start: i128,
    /// Age timeout in nanoseconds
    age_timeout_ns: u64,
    /// Current lock status (atomic)
    lock_status: std.atomic.Value(u8),
    /// Number of permits available (atomic) - 0 means locked
    permits: std.atomic.Value(u32),
    /// Whether this lock is for a stale writer (revalidation)
    stale_writer: bool,
    /// Reference count for shared ownership
    ref_count: std.atomic.Value(u32),
    /// Allocator for cleanup
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, timeout_ns: u64, stale_writer: bool) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .lock_start = std.time.nanoTimestamp(),
            .age_timeout_ns = timeout_ns,
            .lock_status = std.atomic.Value(u8).init(@intFromEnum(LockStatus.waiting)),
            .permits = std.atomic.Value(u32).init(0),
            .stale_writer = stale_writer,
            .ref_count = std.atomic.Value(u32).init(1),
            .allocator = allocator,
        };
        return self;
    }

    pub fn ref(self: *Self) *Self {
        _ = self.ref_count.fetchAdd(1, .monotonic);
        return self;
    }

    pub fn unref(self: *Self) void {
        // Use acq_rel ordering to ensure proper synchronization before deallocation
        if (self.ref_count.fetchSub(1, .acq_rel) == 1) {
            self.allocator.destroy(self);
        }
    }

    pub fn locked(self: *const Self) bool {
        return self.permits.load(.acquire) == 0;
    }

    pub fn unlock(self: *Self, reason: LockStatus) void {
        std.debug.assert(reason != .wait_timeout); // WaitTimeout is not stored in LockCore
        self.lock_status.store(@intFromEnum(reason), .seq_cst);
        // Release permits to wake up readers (any positive number works)
        self.permits.store(10, .release);
    }

    pub fn lockStatus(self: *const Self) LockStatus {
        return @enumFromInt(self.lock_status.load(.seq_cst));
    }

    pub fn isStaleWriter(self: *const Self) bool {
        return self.stale_writer;
    }

    /// Check if the lock has expired based on age timeout
    pub fn expired(self: *const Self) bool {
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.lock_start;
        if (elapsed < 0) return false;
        return @as(u64, @intCast(elapsed)) >= self.age_timeout_ns;
    }
};

/// ReadLock: the requests who get it need to wait until it is released
pub const ReadLock = struct {
    core: *LockCore,

    const Self = @This();

    pub fn init(core: *LockCore) Self {
        return .{ .core = core.ref() };
    }

    pub fn deinit(self: *Self) void {
        self.core.unref();
    }

    /// Wait for the writer to release the lock (blocking with timeout)
    pub fn wait(self: *Self) void {
        if (!self.locked()) {
            return;
        }

        // Check if already expired
        if (self.core.expired()) {
            self.core.lock_status.store(@intFromEnum(LockStatus.age_timeout), .seq_cst);
            return;
        }

        // Calculate remaining time
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.core.lock_start;
        if (elapsed < 0) return;

        const elapsed_u64: u64 = @intCast(elapsed);
        if (elapsed_u64 >= self.core.age_timeout_ns) {
            self.core.lock_status.store(@intFromEnum(LockStatus.age_timeout), .seq_cst);
            return;
        }

        const remaining_ns = self.core.age_timeout_ns - elapsed_u64;
        const sleep_interval_ns: u64 = 1_000_000; // 1ms

        // Poll until unlocked or timeout
        var waited_ns: u64 = 0;
        while (waited_ns < remaining_ns) {
            if (self.core.permits.load(.acquire) > 0) {
                return; // Lock released
            }
            std.time.sleep(sleep_interval_ns);
            waited_ns += sleep_interval_ns;
        }

        // Timed out
        self.core.lock_status.store(@intFromEnum(LockStatus.age_timeout), .seq_cst);
    }

    /// Test if it is still locked
    pub fn locked(self: *const Self) bool {
        return self.core.locked();
    }

    /// Whether the lock is expired
    pub fn expired(self: *const Self) bool {
        return self.core.expired();
    }

    /// The current status of the lock
    pub fn lockStatus(self: *const Self) LockStatus {
        const status = self.core.lockStatus();
        if (status == .waiting and self.expired()) {
            return .age_timeout;
        }
        return status;
    }
};

/// WritePermit: the holder must populate the cache and then release it
pub const WritePermit = struct {
    core: *LockCore,
    finished: bool,

    const Self = @This();

    pub fn init(core: *LockCore) Self {
        return .{
            .core = core.ref(),
            .finished = false,
        };
    }

    pub fn deinit(self: *Self) void {
        // Writer exited without properly unlocking - let others compete again
        if (!self.finished) {
            self.unlock(.dangling);
        }
        self.core.unref();
    }

    /// Was this lock for a stale cache fetch writer?
    pub fn staleWriter(self: *const Self) bool {
        return self.core.isStaleWriter();
    }

    pub fn unlock(self: *Self, reason: LockStatus) void {
        self.finished = true;
        self.core.unlock(reason);
    }

    pub fn lockStatus(self: *const Self) LockStatus {
        return self.core.lockStatus();
    }
};

/// A struct representing locked cache access
pub const Locked = union(enum) {
    /// The writer is allowed to fetch the asset
    write: WritePermit,
    /// The reader waits for the writer to fetch the asset
    read: ReadLock,

    pub fn isWrite(self: Locked) bool {
        return self == .write;
    }

    pub fn deinit(self: *Locked) void {
        switch (self.*) {
            .write => |*w| w.deinit(),
            .read => |*r| r.deinit(),
        }
    }
};

/// Internal lock stub stored in the lock table
const LockStub = struct {
    core: *LockCore,

    pub fn readLock(self: *const LockStub) ReadLock {
        return ReadLock.init(self.core);
    }

    pub fn deinit(self: *LockStub) void {
        self.core.unref();
    }
};

/// The global cache locking manager - prevents thundering herd on cache misses
pub const CacheLock = struct {
    /// Lock table mapping cache key hashes to lock stubs
    lock_table: std.AutoHashMap(u128, LockStub),
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex,
    /// Age timeout for locks (nanoseconds)
    age_timeout_ns: u64,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new CacheLock with the given age timeout in seconds
    pub fn init(allocator: Allocator, age_timeout_seconds: u64) Self {
        return .{
            .lock_table = std.AutoHashMap(u128, LockStub).init(allocator),
            .mutex = .{},
            .age_timeout_ns = age_timeout_seconds * std.time.ns_per_s,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.lock_table.valueIterator();
        while (iter.next()) |stub| {
            var s = stub.*;
            s.deinit();
        }
        self.lock_table.deinit();
    }

    /// Try to lock a cache fetch
    ///
    /// If `stale_writer` is true, this fetch is to revalidate an asset already in cache.
    /// Users should call after a cache miss before fetching the asset.
    /// The returned Locked will tell the caller either to fetch (write) or wait (read).
    pub fn lock(self: *Self, key: *const CacheKey, stale_writer: bool) !Locked {
        const hash = keyToU128(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if there's an existing lock
        if (self.lock_table.get(hash)) |stub| {
            const status = stub.core.lockStatus();
            // If the lock is dangling or timed out, allow replacing it
            if (status != .dangling and status != .age_timeout) {
                return .{ .read = stub.readLock() };
            }
            // Fall through to create new lock
        }

        // Create a new lock - this request becomes the writer
        // LockCore.init returns with ref_count=1
        const core = try LockCore.init(self.allocator, self.age_timeout_ns, stale_writer);
        errdefer core.unref();

        // Stub gets a reference (ref_count=2)
        const stub = LockStub{ .core = core.ref() };

        // Remove old entry if exists and insert new one
        if (self.lock_table.fetchRemove(hash)) |old| {
            var old_stub = old.value;
            old_stub.deinit();
        }
        try self.lock_table.put(hash, stub);

        // WritePermit.init calls core.ref() internally (ref_count=3)
        // We need to transfer ownership of the original ref to the WritePermit
        // So we don't call ref() again - just pass the core directly
        // The WritePermit now owns the original reference
        return .{ .write = .{ .core = core, .finished = false } };
    }

    /// Release a lock for the given key
    pub fn release(self: *Self, key: *const CacheKey, permit: *WritePermit, reason: LockStatus) void {
        const hash = keyToU128(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (permit.core.lockStatus() == .age_timeout) {
            // If lock age timed out, readers can replace the lock
            // Keep the lock status as timeout when unlocking
            permit.unlock(.age_timeout);
        } else if (self.lock_table.fetchRemove(hash)) |removed| {
            var stub = removed.value;
            permit.unlock(reason);
            stub.deinit();
        }
    }

    /// Convert a CacheKey to u128 hash for the lock table
    fn keyToU128(key: *const CacheKey) u128 {
        const h64 = std.hash.Wyhash.hash(0, key.key);
        const h64_2 = std.hash.Wyhash.hash(h64, key.key);
        return (@as(u128, h64) << 64) | @as(u128, h64_2);
    }
};

// ============================================================================
// Cache Lock Tests
// ============================================================================

test "LockStatus conversion" {
    try testing.expectEqual(LockStatus.waiting, @as(LockStatus, @enumFromInt(0)));
    try testing.expectEqual(LockStatus.done, @as(LockStatus, @enumFromInt(1)));
    try testing.expectEqualStrings("waiting", LockStatus.waiting.asStr());
    try testing.expectEqualStrings("done", LockStatus.done.asStr());
}

test "CacheLock basic lock/release" {
    var cache_lock = CacheLock.init(testing.allocator, 1000);
    defer cache_lock.deinit();

    var key1 = CacheKey.fromSlice("test:key:1");

    // First lock should be write permit
    var locked1 = try cache_lock.lock(&key1, false);
    try testing.expect(locked1.isWrite());

    // Second lock on same key should be read lock
    var locked2 = try cache_lock.lock(&key1, false);
    try testing.expect(!locked2.isWrite());
    locked2.deinit();

    // Release the write lock
    cache_lock.release(&key1, &locked1.write, .done);
    locked1.deinit();

    // Now should get write permit again
    var locked3 = try cache_lock.lock(&key1, false);
    try testing.expect(locked3.isWrite());
    cache_lock.release(&key1, &locked3.write, .done);
    locked3.deinit();
}

test "CacheLock different keys" {
    var cache_lock = CacheLock.init(testing.allocator, 1000);
    defer cache_lock.deinit();

    var key1 = CacheKey.fromSlice("test:key:1");
    var key2 = CacheKey.fromSlice("test:key:2");

    // Different keys should both get write permits
    var locked1 = try cache_lock.lock(&key1, false);
    try testing.expect(locked1.isWrite());

    var locked2 = try cache_lock.lock(&key2, false);
    try testing.expect(locked2.isWrite());

    cache_lock.release(&key1, &locked1.write, .done);
    cache_lock.release(&key2, &locked2.write, .done);
    locked1.deinit();
    locked2.deinit();
}

test "CacheLock stale writer flag" {
    var cache_lock = CacheLock.init(testing.allocator, 1000);
    defer cache_lock.deinit();

    var key = CacheKey.fromSlice("test:key");

    var locked = try cache_lock.lock(&key, true);
    try testing.expect(locked.isWrite());
    try testing.expect(locked.write.staleWriter());

    cache_lock.release(&key, &locked.write, .done);
    locked.deinit();
}

test "ReadLock status" {
    var cache_lock = CacheLock.init(testing.allocator, 1000);
    defer cache_lock.deinit();

    var key = CacheKey.fromSlice("test:key");

    var write_locked = try cache_lock.lock(&key, false);
    var read_locked = try cache_lock.lock(&key, false);

    try testing.expect(read_locked.read.locked());
    try testing.expectEqual(LockStatus.waiting, read_locked.read.lockStatus());

    // Unlock the write permit
    cache_lock.release(&key, &write_locked.write, .done);

    // Read lock should now see done status
    try testing.expect(!read_locked.read.locked());
    try testing.expectEqual(LockStatus.done, read_locked.read.lockStatus());

    write_locked.deinit();
    read_locked.deinit();
}

test "WritePermit dangling on drop without unlock" {
    var cache_lock = CacheLock.init(testing.allocator, 1000);
    defer cache_lock.deinit();

    var key = CacheKey.fromSlice("test:key");

    // Get write permit but don't release properly
    {
        var locked = try cache_lock.lock(&key, false);
        // locked goes out of scope without calling release
        // This should set status to dangling
        locked.deinit();
    }

    // New request should be able to get write permit (dangling lock replaced)
    var locked2 = try cache_lock.lock(&key, false);
    try testing.expect(locked2.isWrite());
    cache_lock.release(&key, &locked2.write, .done);
    locked2.deinit();
}

// ============================================================================
// Cache Predictor - Remembers Uncacheable Assets
// ============================================================================

/// Reasons why a response was not cached
pub const NoCacheReason = union(enum) {
    /// Caching was never enabled for this request
    never_enabled,
    /// Storage backend error
    storage_error,
    /// Internal error during caching
    internal_error,
    /// Caching was deferred
    deferred,
    /// Cache lock was given up
    cache_lock_give_up,
    /// Cache lock timed out
    cache_lock_timeout,
    /// Request was declined and sent to upstream
    declined_to_upstream,
    /// Upstream returned an error
    upstream_error,
    /// Origin explicitly said not to cache (Cache-Control: no-store, private, etc.)
    origin_not_cache,
    /// Response was too large to cache
    response_too_large,
    /// Predicted response would be too large
    predicted_response_too_large,
    /// Custom reason with a description
    custom: []const u8,

    pub fn shouldRemember(self: NoCacheReason) bool {
        // Only remember certain reasons that indicate the asset is truly uncacheable
        return switch (self) {
            // These are transient errors - don't remember
            .never_enabled,
            .storage_error,
            .internal_error,
            .deferred,
            .cache_lock_give_up,
            .cache_lock_timeout,
            .declined_to_upstream,
            .upstream_error,
            .predicted_response_too_large,
            => false,
            // These indicate the origin doesn't want caching - remember these
            .origin_not_cache,
            .response_too_large,
            .custom,
            => true,
        };
    }

    pub fn asStr(self: NoCacheReason) []const u8 {
        return switch (self) {
            .never_enabled => "never_enabled",
            .storage_error => "storage_error",
            .internal_error => "internal_error",
            .deferred => "deferred",
            .cache_lock_give_up => "cache_lock_give_up",
            .cache_lock_timeout => "cache_lock_timeout",
            .declined_to_upstream => "declined_to_upstream",
            .upstream_error => "upstream_error",
            .origin_not_cache => "origin_not_cache",
            .response_too_large => "response_too_large",
            .predicted_response_too_large => "predicted_response_too_large",
            .custom => |reason| reason,
        };
    }
};

/// Custom reason predicate function type
pub const CustomReasonPredicate = *const fn ([]const u8) bool;

/// Cacheability Predictor
///
/// Remembers previously uncacheable assets.
/// Allows bypassing cache / cache lock early based on historical precedent.
///
/// NOTE: to simply avoid caching requests with certain characteristics,
/// add checks in request_cache_filter to avoid enabling cache in the first place.
/// The predictor's bypass mechanism handles cases where the request _looks_ cacheable
/// but its previous responses suggest otherwise.
pub const CachePredictor = struct {
    /// LRU cache of uncacheable key hashes (using hash map + linked list for LRU behavior)
    uncacheable_keys: std.AutoHashMap(u128, void),
    /// Order of keys for LRU eviction (oldest first)
    key_order: std.ArrayListUnmanaged(u128),
    /// Maximum capacity
    capacity: usize,
    /// Optional predicate to skip certain custom reasons
    skip_custom_reasons_fn: ?CustomReasonPredicate,
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    /// Create a new CachePredictor with the given capacity
    ///
    /// - `capacity`: number of uncacheable keys to remember
    /// - `skip_custom_reasons_fn`: optional predicate that returns true if a custom
    ///   reason should be skipped (not remembered as uncacheable)
    pub fn init(
        allocator: Allocator,
        capacity: usize,
        skip_custom_reasons_fn: ?CustomReasonPredicate,
    ) !Self {
        return .{
            .uncacheable_keys = std.AutoHashMap(u128, void).init(allocator),
            .key_order = .{},
            .capacity = capacity,
            .skip_custom_reasons_fn = skip_custom_reasons_fn,
            .mutex = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.uncacheable_keys.deinit();
        self.key_order.deinit(self.allocator);
    }

    /// Return true if likely cacheable, false if likely not.
    /// Based on historical data about previous requests to this key.
    pub fn cacheablePrediction(self: *Self, key: *const CacheKey) bool {
        const hash = keyToU128(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        // If key is in uncacheable list, predict not cacheable
        return !self.uncacheable_keys.contains(hash);
    }

    /// Mark a key as cacheable (remove from uncacheable list).
    /// Returns false if the key was already marked cacheable (not in list).
    pub fn markCacheable(self: *Self, key: *const CacheKey) bool {
        const hash = keyToU128(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if in uncacheable list
        if (!self.uncacheable_keys.contains(hash)) {
            // Not in uncacheable list, nothing to do
            return true;
        }

        // Remove from uncacheable list
        _ = self.uncacheable_keys.remove(hash);
        // Remove from order list
        for (self.key_order.items, 0..) |k, i| {
            if (k == hash) {
                _ = self.key_order.orderedRemove(i);
                break;
            }
        }
        return false;
    }

    /// Mark a key as uncacheable.
    /// May skip marking on certain NoCacheReasons.
    /// Returns null if we skipped marking uncacheable.
    /// Returns false if the key was already marked uncacheable.
    /// Returns true if newly marked uncacheable.
    pub fn markUncacheable(self: *Self, key: *const CacheKey, reason: NoCacheReason) ?bool {
        // Check if we should remember this reason
        if (!reason.shouldRemember()) {
            return null;
        }

        // Check custom reason predicate
        if (reason == .custom) {
            if (self.skip_custom_reasons_fn) |predicate| {
                if (predicate(reason.custom)) {
                    return null; // Skip this custom reason
                }
            }
        }

        const hash = keyToU128(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already in uncacheable list
        if (self.uncacheable_keys.contains(hash)) {
            // Already marked uncacheable, but update LRU position (move to end)
            for (self.key_order.items, 0..) |k, i| {
                if (k == hash) {
                    _ = self.key_order.orderedRemove(i);
                    break;
                }
            }
            self.key_order.append(self.allocator, hash) catch return false;
            return false;
        }

        // Evict oldest if at capacity
        if (self.key_order.items.len >= self.capacity) {
            if (self.key_order.items.len > 0) {
                const oldest = self.key_order.orderedRemove(0);
                _ = self.uncacheable_keys.remove(oldest);
            }
        }

        // Add to uncacheable list
        self.uncacheable_keys.put(hash, {}) catch return null;
        self.key_order.append(self.allocator, hash) catch {
            _ = self.uncacheable_keys.remove(hash);
            return null;
        };
        return true;
    }

    /// Convert a CacheKey to u128 hash
    fn keyToU128(key: *const CacheKey) u128 {
        const h64 = std.hash.Wyhash.hash(0, key.key);
        const h64_2 = std.hash.Wyhash.hash(h64, key.key);
        return (@as(u128, h64) << 64) | @as(u128, h64_2);
    }
};

// ============================================================================
// Cache Predictor Tests
// ============================================================================

test "NoCacheReason shouldRemember" {
    // Transient errors should not be remembered
    const internal_error: NoCacheReason = .internal_error;
    const storage_error: NoCacheReason = .storage_error;
    const cache_lock_timeout: NoCacheReason = .cache_lock_timeout;
    try testing.expect(!internal_error.shouldRemember());
    try testing.expect(!storage_error.shouldRemember());
    try testing.expect(!cache_lock_timeout.shouldRemember());

    // Origin decisions should be remembered
    const origin_not_cache: NoCacheReason = .origin_not_cache;
    const response_too_large: NoCacheReason = .response_too_large;
    const custom: NoCacheReason = .{ .custom = "test" };
    try testing.expect(origin_not_cache.shouldRemember());
    try testing.expect(response_too_large.shouldRemember());
    try testing.expect(custom.shouldRemember());
}

test "CachePredictor basic cacheability" {
    var predictor = try CachePredictor.init(testing.allocator, 10, null);
    defer predictor.deinit();

    var key = CacheKey.fromSlice("a:b:c");

    // Cacheable if no history
    try testing.expect(predictor.cacheablePrediction(&key));

    // Don't remember internal / storage errors
    _ = predictor.markUncacheable(&key, .internal_error);
    try testing.expect(predictor.cacheablePrediction(&key));
    _ = predictor.markUncacheable(&key, .storage_error);
    try testing.expect(predictor.cacheablePrediction(&key));

    // Origin explicitly said uncacheable
    _ = predictor.markUncacheable(&key, .origin_not_cache);
    try testing.expect(!predictor.cacheablePrediction(&key));

    // Mark cacheable again
    _ = predictor.markCacheable(&key);
    try testing.expect(predictor.cacheablePrediction(&key));
}

test "CachePredictor custom skip predicate" {
    const skipFn = struct {
        fn predicate(reason: []const u8) bool {
            return std.mem.eql(u8, reason, "Skipping");
        }
    }.predicate;

    var predictor = try CachePredictor.init(testing.allocator, 10, skipFn);
    defer predictor.deinit();

    var key1 = CacheKey.fromSlice("a:b:c");

    // Cacheable if no history
    try testing.expect(predictor.cacheablePrediction(&key1));

    // Custom predicate still uses default skip reasons
    _ = predictor.markUncacheable(&key1, .internal_error);
    try testing.expect(predictor.cacheablePrediction(&key1));

    // Other custom reasons can still be marked uncacheable
    _ = predictor.markUncacheable(&key1, .{ .custom = "DontCacheMe" });
    try testing.expect(!predictor.cacheablePrediction(&key1));

    var key2 = CacheKey.fromSlice("a:c:d");
    try testing.expect(predictor.cacheablePrediction(&key2));

    // Specific custom reason is skipped
    _ = predictor.markUncacheable(&key2, .{ .custom = "Skipping" });
    try testing.expect(predictor.cacheablePrediction(&key2));
}

test "CachePredictor LRU eviction" {
    var predictor = try CachePredictor.init(testing.allocator, 3, null);
    defer predictor.deinit();

    var key1 = CacheKey.fromSlice("a:b:c");
    _ = predictor.markUncacheable(&key1, .origin_not_cache);
    try testing.expect(!predictor.cacheablePrediction(&key1));

    var key2 = CacheKey.fromSlice("a:bc:c");
    _ = predictor.markUncacheable(&key2, .origin_not_cache);
    try testing.expect(!predictor.cacheablePrediction(&key2));

    var key3 = CacheKey.fromSlice("a:cd:c");
    _ = predictor.markUncacheable(&key3, .origin_not_cache);
    try testing.expect(!predictor.cacheablePrediction(&key3));

    // Promote / reinsert key1
    _ = predictor.markUncacheable(&key1, .origin_not_cache);

    var key4 = CacheKey.fromSlice("a:de:c");
    _ = predictor.markUncacheable(&key4, .origin_not_cache);
    try testing.expect(!predictor.cacheablePrediction(&key4));

    // key1 was recently used, should still be there
    try testing.expect(!predictor.cacheablePrediction(&key1));
    // key2 was evicted (LRU)
    try testing.expect(predictor.cacheablePrediction(&key2));
    // key3 and key4 should still be there
    try testing.expect(!predictor.cacheablePrediction(&key3));
    try testing.expect(!predictor.cacheablePrediction(&key4));
}


// ============================================================================
// Cache Storage Backend - Pluggable Storage Interface
// ============================================================================

/// Types of cache purge operations
pub const PurgeType = enum {
    /// Exact key match - purge a single entry
    exact,
    /// File/prefix match - purge all entries matching a prefix
    file,
    /// Scan and purge - purge entries matching a predicate
    scan,
};

/// Result of a cache lookup operation
pub const LookupResult = union(enum) {
    /// Cache hit - entry found and valid
    hit: CacheHit,
    /// Cache miss - entry not found
    miss,
    /// Entry found but stale (needs revalidation)
    stale: CacheHit,
    /// Error during lookup
    err: StorageError,
};

/// Represents a cache hit with metadata and data access
pub const CacheHit = struct {
    /// Cache key that was hit
    key: CacheKey,
    /// Metadata about the cached response
    meta: CacheMeta,
    /// Handle to read the cached body
    body_reader: ?*BodyReader,

    pub fn deinit(self: *CacheHit, allocator: Allocator) void {
        if (self.body_reader) |reader| {
            reader.close();
            allocator.destroy(reader);
        }
    }
};

/// Reader interface for cached body data
pub const BodyReader = struct {
    /// Context pointer for the storage implementation
    ctx: *anyopaque,
    /// Read function pointer
    readFn: *const fn (*anyopaque, []u8) anyerror!usize,
    /// Close function pointer
    closeFn: *const fn (*anyopaque) void,
    /// Total size of the body (if known)
    total_size: ?usize,
    /// Current read position
    position: usize,

    const Self = @This();

    /// Read data from the cached body
    pub fn read(self: *Self, buffer: []u8) !usize {
        const bytes_read = try self.readFn(self.ctx, buffer);
        self.position += bytes_read;
        return bytes_read;
    }

    /// Check if all data has been read
    pub fn isComplete(self: *const Self) bool {
        if (self.total_size) |size| {
            return self.position >= size;
        }
        return false;
    }

    /// Close the reader and release resources
    pub fn close(self: *Self) void {
        self.closeFn(self.ctx);
    }
};

/// Writer interface for storing body data
pub const BodyWriter = struct {
    /// Context pointer for the storage implementation
    ctx: *anyopaque,
    /// Write function pointer
    writeFn: *const fn (*anyopaque, []const u8) anyerror!usize,
    /// Finish function pointer (commits the write)
    finishFn: *const fn (*anyopaque) anyerror!void,
    /// Abort function pointer (cancels the write)
    abortFn: *const fn (*anyopaque) void,
    /// Total bytes written
    bytes_written: usize,

    const Self = @This();

    /// Write data to the cache
    pub fn write(self: *Self, data: []const u8) !usize {
        const bytes_written = try self.writeFn(self.ctx, data);
        self.bytes_written += bytes_written;
        return bytes_written;
    }

    /// Finish the write operation and commit to storage
    pub fn finish(self: *Self) !void {
        try self.finishFn(self.ctx);
    }

    /// Abort the write operation and discard data
    pub fn abort(self: *Self) void {
        self.abortFn(self.ctx);
    }
};

/// Write ID for tracking in-progress writes
pub const WriteId = struct {
    /// Unique identifier for this write operation
    id: u64,
    /// Timestamp when write started
    started_at: i64,

    pub fn init() WriteId {
        return .{
            .id = @intCast(@as(u64, @bitCast(std.time.nanoTimestamp())) & 0xFFFFFFFF),
            .started_at = std.time.timestamp(),
        };
    }
};

/// Storage errors
pub const StorageError = error{
    /// Key not found in storage
    NotFound,
    /// Storage is full
    StorageFull,
    /// Write operation failed
    WriteFailed,
    /// Read operation failed
    ReadFailed,
    /// Invalid key format
    InvalidKey,
    /// Storage backend error
    BackendError,
    /// Entry is locked by another operation
    EntryLocked,
    /// Operation timed out
    Timeout,
    /// Entry too large for storage
    EntryTooLarge,
    /// Purge operation failed
    PurgeFailed,
};

/// Storage trait - Pluggable cache storage interface
///
/// Implementations can store cache entries in memory, on disk,
/// or in distributed storage systems.
pub const Storage = union(enum) {
    /// In-memory storage implementation
    memory: *MemoryStorage,
    /// Custom storage implementation via function pointers
    custom: CustomStorage,

    const Self = @This();

    /// Look up a cache entry by key
    pub fn lookup(self: *Self, key: *const CacheKey) LookupResult {
        return switch (self.*) {
            .memory => |mem| mem.lookup(key),
            .custom => |*cust| cust.lookupFn(cust.ctx, key),
        };
    }

    /// Get the body data for a cache hit
    pub fn getBody(self: *Self, key: *const CacheKey, allocator: Allocator) !?*BodyReader {
        return switch (self.*) {
            .memory => |mem| mem.getBody(key, allocator),
            .custom => |*cust| cust.getBodyFn(cust.ctx, key, allocator),
        };
    }

    /// Put a new entry into the cache
    pub fn put(self: *Self, key: *const CacheKey, meta: *const CacheMeta, allocator: Allocator) !*BodyWriter {
        return switch (self.*) {
            .memory => |mem| mem.put(key, meta, allocator),
            .custom => |*cust| cust.putFn(cust.ctx, key, meta, allocator),
        };
    }

    /// Purge entries from the cache
    pub fn purge(self: *Self, key: *const CacheKey, purge_type: PurgeType) !usize {
        return switch (self.*) {
            .memory => |mem| mem.purge(key, purge_type),
            .custom => |*cust| cust.purgeFn(cust.ctx, key, purge_type),
        };
    }

    /// Check if an entry exists without retrieving it
    pub fn exists(self: *Self, key: *const CacheKey) bool {
        return switch (self.*) {
            .memory => |mem| mem.exists(key),
            .custom => |*cust| cust.existsFn(cust.ctx, key),
        };
    }

    /// Get storage statistics
    pub fn stats(self: *Self) StorageStats {
        return switch (self.*) {
            .memory => |mem| mem.stats(),
            .custom => |*cust| cust.statsFn(cust.ctx),
        };
    }
};

/// Custom storage implementation via function pointers
pub const CustomStorage = struct {
    ctx: *anyopaque,
    lookupFn: *const fn (*anyopaque, *const CacheKey) LookupResult,
    getBodyFn: *const fn (*anyopaque, *const CacheKey, Allocator) anyerror!?*BodyReader,
    putFn: *const fn (*anyopaque, *const CacheKey, *const CacheMeta, Allocator) anyerror!*BodyWriter,
    purgeFn: *const fn (*anyopaque, *const CacheKey, PurgeType) anyerror!usize,
    existsFn: *const fn (*anyopaque, *const CacheKey) bool,
    statsFn: *const fn (*anyopaque) StorageStats,
};

/// Storage statistics
pub const StorageStats = struct {
    /// Total number of entries
    entry_count: usize,
    /// Total bytes used
    bytes_used: usize,
    /// Maximum capacity in bytes
    max_capacity: usize,
    /// Number of cache hits
    hits: u64,
    /// Number of cache misses
    misses: u64,
    /// Number of evictions
    evictions: u64,

    pub fn hitRate(self: StorageStats) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }

    pub fn usagePercent(self: StorageStats) f64 {
        if (self.max_capacity == 0) return 0.0;
        return @as(f64, @floatFromInt(self.bytes_used)) / @as(f64, @floatFromInt(self.max_capacity)) * 100.0;
    }
};

/// In-memory cache entry
const MemoryCacheEntry = struct {
    meta: CacheMeta,
    body: []u8,
    created_at: i64,
    last_accessed: i64,
    access_count: u64,

    pub fn size(self: *const MemoryCacheEntry) usize {
        return self.body.len + @sizeOf(CacheMeta) + @sizeOf(MemoryCacheEntry);
    }
};

/// Memory body reader context
const MemoryReaderCtx = struct {
    data: []const u8,
    position: usize,

    pub fn read(ctx_ptr: *anyopaque, buffer: []u8) anyerror!usize {
        const ctx: *MemoryReaderCtx = @ptrCast(@alignCast(ctx_ptr));
        const remaining = ctx.data.len - ctx.position;
        if (remaining == 0) return 0;

        const to_read = @min(buffer.len, remaining);
        @memcpy(buffer[0..to_read], ctx.data[ctx.position..][0..to_read]);
        ctx.position += to_read;
        return to_read;
    }

    pub fn close(_: *anyopaque) void {
        // Memory reader doesn't need cleanup
    }
};

/// Memory body writer context
const MemoryWriterCtx = struct {
    storage: *MemoryStorage,
    key_hash: u128,
    meta: CacheMeta,
    buffer: std.ArrayListUnmanaged(u8),
    committed: bool,
    allocator: Allocator,

    pub fn write(ctx_ptr: *anyopaque, data: []const u8) anyerror!usize {
        const ctx: *MemoryWriterCtx = @ptrCast(@alignCast(ctx_ptr));
        try ctx.buffer.appendSlice(ctx.allocator, data);
        return data.len;
    }

    pub fn finish(ctx_ptr: *anyopaque) anyerror!void {
        const ctx: *MemoryWriterCtx = @ptrCast(@alignCast(ctx_ptr));
        if (ctx.committed) return;

        const body = try ctx.buffer.toOwnedSlice(ctx.allocator);
        errdefer ctx.allocator.free(body);

        const entry = MemoryCacheEntry{
            .meta = ctx.meta,
            .body = body,
            .created_at = std.time.timestamp(),
            .last_accessed = std.time.timestamp(),
            .access_count = 0,
        };

        ctx.storage.mutex.lock();
        defer ctx.storage.mutex.unlock();

        // Remove old entry if exists
        if (ctx.storage.entries.fetchRemove(ctx.key_hash)) |old| {
            ctx.storage.bytes_used -= old.value.size();
            ctx.allocator.free(old.value.body);
        }

        ctx.storage.entries.put(ctx.key_hash, entry) catch {
            ctx.allocator.free(body);
            return StorageError.WriteFailed;
        };
        ctx.storage.bytes_used += entry.size();
        ctx.committed = true;
    }

    pub fn abort(ctx_ptr: *anyopaque) void {
        const ctx: *MemoryWriterCtx = @ptrCast(@alignCast(ctx_ptr));
        ctx.buffer.deinit(ctx.allocator);
        ctx.committed = true; // Prevent double-free
    }
};

/// In-memory storage implementation
pub const MemoryStorage = struct {
    /// Hash map of cache entries
    entries: std.AutoHashMap(u128, MemoryCacheEntry),
    /// Maximum capacity in bytes
    max_capacity: usize,
    /// Current bytes used
    bytes_used: usize,
    /// Statistics
    hits: u64,
    misses: u64,
    evictions: u64,
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_capacity: usize) Self {
        return .{
            .entries = std.AutoHashMap(u128, MemoryCacheEntry).init(allocator),
            .max_capacity = max_capacity,
            .bytes_used = 0,
            .hits = 0,
            .misses = 0,
            .evictions = 0,
            .mutex = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.body);
        }
        self.entries.deinit();
    }

    /// Convert CacheKey to u128 hash
    fn keyHash(key: *const CacheKey) u128 {
        const h64 = std.hash.Wyhash.hash(0, key.key);
        const h64_2 = std.hash.Wyhash.hash(h64, key.key);
        return (@as(u128, h64) << 64) | @as(u128, h64_2);
    }

    pub fn lookup(self: *Self, key: *const CacheKey) LookupResult {
        const hash = keyHash(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.getPtr(hash)) |entry| {
            self.hits += 1;
            entry.last_accessed = std.time.timestamp();
            entry.access_count += 1;

            // Check if entry is stale
            if (!entry.meta.isFresh()) {
                return .{ .stale = .{
                    .key = key.*,
                    .meta = entry.meta,
                    .body_reader = null,
                } };
            }

            return .{ .hit = .{
                .key = key.*,
                .meta = entry.meta,
                .body_reader = null,
            } };
        }

        self.misses += 1;
        return .miss;
    }

    pub fn getBody(self: *Self, key: *const CacheKey, allocator: Allocator) !?*BodyReader {
        const hash = keyHash(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.get(hash)) |entry| {
            const ctx = try allocator.create(MemoryReaderCtx);
            ctx.* = .{
                .data = entry.body,
                .position = 0,
            };

            const reader = try allocator.create(BodyReader);
            reader.* = .{
                .ctx = ctx,
                .readFn = MemoryReaderCtx.read,
                .closeFn = MemoryReaderCtx.close,
                .total_size = entry.body.len,
                .position = 0,
            };
            return reader;
        }

        return null;
    }

    pub fn put(self: *Self, key: *const CacheKey, meta: *const CacheMeta, allocator: Allocator) !*BodyWriter {
        const hash = keyHash(key);

        const ctx = try allocator.create(MemoryWriterCtx);
        ctx.* = .{
            .storage = self,
            .key_hash = hash,
            .meta = meta.*,
            .buffer = .{},
            .committed = false,
            .allocator = allocator,
        };

        const writer = try allocator.create(BodyWriter);
        writer.* = .{
            .ctx = ctx,
            .writeFn = MemoryWriterCtx.write,
            .finishFn = MemoryWriterCtx.finish,
            .abortFn = MemoryWriterCtx.abort,
            .bytes_written = 0,
        };
        return writer;
    }

    pub fn purge(self: *Self, key: *const CacheKey, purge_type: PurgeType) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var purged: usize = 0;

        switch (purge_type) {
            .exact => {
                const hash = keyHash(key);
                if (self.entries.fetchRemove(hash)) |removed| {
                    self.bytes_used -= removed.value.size();
                    self.allocator.free(removed.value.body);
                    purged = 1;
                }
            },
            .file, .scan => {
                // For memory storage, file and scan purge are not efficient
                // In a real implementation, you'd maintain indexes for these operations
                // For now, just purge the exact key
                const hash = keyHash(key);
                if (self.entries.fetchRemove(hash)) |removed| {
                    self.bytes_used -= removed.value.size();
                    self.allocator.free(removed.value.body);
                    purged = 1;
                }
            },
        }

        return purged;
    }

    pub fn exists(self: *Self, key: *const CacheKey) bool {
        const hash = keyHash(key);

        self.mutex.lock();
        defer self.mutex.unlock();

        return self.entries.contains(hash);
    }

    pub fn stats(self: *Self) StorageStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        return .{
            .entry_count = self.entries.count(),
            .bytes_used = self.bytes_used,
            .max_capacity = self.max_capacity,
            .hits = self.hits,
            .misses = self.misses,
            .evictions = self.evictions,
        };
    }

    /// Evict entries to make room for new data
    pub fn evictToFit(self: *Self, needed_bytes: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.bytes_used + needed_bytes > self.max_capacity and self.entries.count() > 0) {
            // Find the oldest entry (simple LRU)
            var oldest_hash: ?u128 = null;
            var oldest_time: i64 = std.math.maxInt(i64);

            var iter = self.entries.iterator();
            while (iter.next()) |kv| {
                if (kv.value_ptr.last_accessed < oldest_time) {
                    oldest_time = kv.value_ptr.last_accessed;
                    oldest_hash = kv.key_ptr.*;
                }
            }

            if (oldest_hash) |hash| {
                if (self.entries.fetchRemove(hash)) |removed| {
                    self.bytes_used -= removed.value.size();
                    self.allocator.free(removed.value.body);
                    self.evictions += 1;
                }
            } else {
                break;
            }
        }
    }
};

// ============================================================================
// Storage Backend Tests
// ============================================================================

test "MemoryStorage basic put/lookup" {
    var storage = MemoryStorage.init(testing.allocator, 1024 * 1024);
    defer storage.deinit();

    var key = CacheKey.fromSlice("test:storage:1");
    var meta = CacheMeta.init(testing.allocator);
    meta.expires_at = std.time.nanoTimestamp() + 3600 * std.time.ns_per_s;
    meta.stale_while_revalidate = 60;
    meta.stale_if_error = 300;

    // Put entry
    const writer = try storage.put(&key, &meta, testing.allocator);
    _ = try writer.write("Hello, World!");
    try writer.finish();
    testing.allocator.destroy(@as(*MemoryWriterCtx, @ptrCast(@alignCast(writer.ctx))));
    testing.allocator.destroy(writer);

    // Lookup entry
    const result = storage.lookup(&key);
    try testing.expect(result == .hit);

    // Get body
    const reader = try storage.getBody(&key, testing.allocator);
    try testing.expect(reader != null);

    if (reader) |r| {
        var buf: [64]u8 = undefined;
        const n = try r.read(&buf);
        try testing.expectEqualStrings("Hello, World!", buf[0..n]);
        r.close();
        testing.allocator.destroy(@as(*MemoryReaderCtx, @ptrCast(@alignCast(r.ctx))));
        testing.allocator.destroy(r);
    }
}

test "MemoryStorage miss" {
    var storage = MemoryStorage.init(testing.allocator, 1024 * 1024);
    defer storage.deinit();

    var key = CacheKey.fromSlice("nonexistent:key");
    const result = storage.lookup(&key);
    try testing.expect(result == .miss);
}

test "MemoryStorage purge exact" {
    var storage = MemoryStorage.init(testing.allocator, 1024 * 1024);
    defer storage.deinit();

    var key = CacheKey.fromSlice("test:purge:1");
    var meta = CacheMeta.init(testing.allocator);
    meta.expires_at = std.time.nanoTimestamp() + 3600 * std.time.ns_per_s;
    meta.stale_while_revalidate = 60;
    meta.stale_if_error = 300;

    // Put entry
    const writer = try storage.put(&key, &meta, testing.allocator);
    _ = try writer.write("Data");
    try writer.finish();
    testing.allocator.destroy(@as(*MemoryWriterCtx, @ptrCast(@alignCast(writer.ctx))));
    testing.allocator.destroy(writer);

    // Verify exists
    try testing.expect(storage.exists(&key));

    // Purge
    const purged = try storage.purge(&key, .exact);
    try testing.expectEqual(@as(usize, 1), purged);

    // Verify gone
    try testing.expect(!storage.exists(&key));
}

test "MemoryStorage stats" {
    var storage = MemoryStorage.init(testing.allocator, 1024 * 1024);
    defer storage.deinit();

    var key1 = CacheKey.fromSlice("test:stats:1");
    var key2 = CacheKey.fromSlice("test:stats:2");
    var meta = CacheMeta.init(testing.allocator);
    meta.expires_at = std.time.nanoTimestamp() + 3600 * std.time.ns_per_s;
    meta.stale_while_revalidate = 60;
    meta.stale_if_error = 300;

    // Put entry
    const writer1 = try storage.put(&key1, &meta, testing.allocator);
    _ = try writer1.write("Data1");
    try writer1.finish();
    testing.allocator.destroy(@as(*MemoryWriterCtx, @ptrCast(@alignCast(writer1.ctx))));
    testing.allocator.destroy(writer1);

    // Lookup (hit)
    _ = storage.lookup(&key1);
    // Lookup (miss)
    _ = storage.lookup(&key2);

    const s = storage.stats();
    try testing.expectEqual(@as(usize, 1), s.entry_count);
    try testing.expectEqual(@as(u64, 1), s.hits);
    try testing.expectEqual(@as(u64, 1), s.misses);
    try testing.expect(s.hitRate() == 0.5);
}

test "Storage trait with MemoryStorage" {
    var mem_storage = MemoryStorage.init(testing.allocator, 1024 * 1024);
    defer mem_storage.deinit();

    var storage = Storage{ .memory = &mem_storage };

    var key = CacheKey.fromSlice("test:trait:1");
    var meta = CacheMeta.init(testing.allocator);
    meta.expires_at = std.time.nanoTimestamp() + 3600 * std.time.ns_per_s;
    meta.stale_while_revalidate = 60;
    meta.stale_if_error = 300;

    // Put via trait
    const writer = try storage.put(&key, &meta, testing.allocator);
    _ = try writer.write("Trait test");
    try writer.finish();
    testing.allocator.destroy(@as(*MemoryWriterCtx, @ptrCast(@alignCast(writer.ctx))));
    testing.allocator.destroy(writer);

    // Lookup via trait
    const result = storage.lookup(&key);
    try testing.expect(result == .hit);

    // Exists via trait
    try testing.expect(storage.exists(&key));

    // Stats via trait
    const s = storage.stats();
    try testing.expectEqual(@as(usize, 1), s.entry_count);
}

// ============================================================================
// Cache Eviction Policies - Pluggable Eviction Interface
// ============================================================================

/// Eviction policy types
pub const EvictionPolicy = enum {
    /// Least Recently Used
    lru,
    /// Least Frequently Used
    lfu,
    /// First In First Out
    fifo,
    /// Size-aware LRU (evicts largest items first when sizes are similar)
    size_aware_lru,
    /// Time-based (evicts items closest to expiration)
    ttl_based,
};

/// Information about a cache entry for eviction decisions
pub const EvictionCandidate = struct {
    /// Hash of the cache key
    key_hash: u128,
    /// Size of the entry in bytes
    size: usize,
    /// Last access time (timestamp)
    last_accessed: i64,
    /// Access count
    access_count: u64,
    /// Time to live remaining (nanoseconds), null if no expiry
    ttl_remaining: ?i128,
    /// Creation time
    created_at: i64,
};

/// Result of an eviction operation
pub const EvictionResult = struct {
    /// Number of entries evicted
    entries_evicted: usize,
    /// Total bytes freed
    bytes_freed: usize,
};

/// Eviction Manager trait - Pluggable eviction interface
///
/// Implementations decide which entries to evict when the cache is full.
pub const EvictionManager = union(enum) {
    /// LRU eviction
    lru: *LruEviction,
    /// Size-aware LRU eviction
    size_aware: *SizeAwareLruEviction,
    /// Simple LRU eviction (lightweight)
    simple_lru: *SimpleLruEviction,
    /// Custom eviction via function pointers
    custom: CustomEviction,

    const Self = @This();

    /// Select entries to evict to free at least `bytes_needed` bytes
    pub fn selectForEviction(
        self: *Self,
        candidates: []const EvictionCandidate,
        bytes_needed: usize,
    ) []const u128 {
        return switch (self.*) {
            .lru => |mgr| mgr.selectForEviction(candidates, bytes_needed),
            .size_aware => |mgr| mgr.selectForEviction(candidates, bytes_needed),
            .simple_lru => |mgr| mgr.selectForEviction(candidates, bytes_needed),
            .custom => |*cust| cust.selectFn(cust.ctx, candidates, bytes_needed),
        };
    }

    /// Notify the manager that an entry was accessed
    pub fn recordAccess(self: *Self, key_hash: u128) void {
        switch (self.*) {
            .lru => |mgr| mgr.recordAccess(key_hash),
            .size_aware => |mgr| mgr.recordAccess(key_hash),
            .simple_lru => |mgr| mgr.recordAccess(key_hash),
            .custom => |*cust| if (cust.recordAccessFn) |f| f(cust.ctx, key_hash),
        }
    }

    /// Notify the manager that an entry was added
    pub fn recordAdd(self: *Self, key_hash: u128, size: usize) void {
        switch (self.*) {
            .lru => |mgr| mgr.recordAdd(key_hash, size),
            .size_aware => |mgr| mgr.recordAdd(key_hash, size),
            .simple_lru => |mgr| mgr.recordAdd(key_hash, size),
            .custom => |*cust| if (cust.recordAddFn) |f| f(cust.ctx, key_hash, size),
        }
    }

    /// Notify the manager that an entry was removed
    pub fn recordRemove(self: *Self, key_hash: u128) void {
        switch (self.*) {
            .lru => |mgr| mgr.recordRemove(key_hash),
            .size_aware => |mgr| mgr.recordRemove(key_hash),
            .simple_lru => |mgr| mgr.recordRemove(key_hash),
            .custom => |*cust| if (cust.recordRemoveFn) |f| f(cust.ctx, key_hash),
        }
    }

    /// Save eviction state to bytes (for persistence)
    pub fn save(self: *Self, allocator: Allocator) ![]u8 {
        return switch (self.*) {
            .lru => |mgr| mgr.save(allocator),
            .size_aware => |mgr| mgr.save(allocator),
            .simple_lru => |mgr| mgr.save(allocator),
            .custom => |*cust| if (cust.saveFn) |f| f(cust.ctx, allocator) else &[_]u8{},
        };
    }

    /// Load eviction state from bytes
    pub fn load(self: *Self, data: []const u8) !void {
        switch (self.*) {
            .lru => |mgr| try mgr.load(data),
            .size_aware => |mgr| try mgr.load(data),
            .simple_lru => |mgr| try mgr.load(data),
            .custom => |*cust| if (cust.loadFn) |f| try f(cust.ctx, data),
        }
    }
};

/// Custom eviction implementation via function pointers
pub const CustomEviction = struct {
    ctx: *anyopaque,
    selectFn: *const fn (*anyopaque, []const EvictionCandidate, usize) []const u128,
    recordAccessFn: ?*const fn (*anyopaque, u128) void,
    recordAddFn: ?*const fn (*anyopaque, u128, usize) void,
    recordRemoveFn: ?*const fn (*anyopaque, u128) void,
    saveFn: ?*const fn (*anyopaque, Allocator) anyerror![]u8,
    loadFn: ?*const fn (*anyopaque, []const u8) anyerror!void,
};

/// LRU Eviction Manager
///
/// Evicts the least recently used entries first.
pub const LruEviction = struct {
    /// Access order (most recent at end)
    access_order: std.ArrayListUnmanaged(u128),
    /// Entry sizes
    sizes: std.AutoHashMap(u128, usize),
    /// Selection buffer for results
    selection_buffer: std.ArrayListUnmanaged(u128),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .access_order = .{},
            .sizes = std.AutoHashMap(u128, usize).init(allocator),
            .selection_buffer = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.access_order.deinit(self.allocator);
        self.sizes.deinit();
        self.selection_buffer.deinit(self.allocator);
    }

    pub fn selectForEviction(
        self: *Self,
        candidates: []const EvictionCandidate,
        bytes_needed: usize,
    ) []const u128 {
        _ = candidates; // We use our own order

        self.selection_buffer.clearRetainingCapacity();
        var bytes_freed: usize = 0;

        // Evict from oldest to newest
        for (self.access_order.items) |key_hash| {
            if (bytes_freed >= bytes_needed) break;

            if (self.sizes.get(key_hash)) |size| {
                self.selection_buffer.append(self.allocator, key_hash) catch break;
                bytes_freed += size;
            }
        }

        return self.selection_buffer.items;
    }

    pub fn recordAccess(self: *Self, key_hash: u128) void {
        // Move to end of access order
        for (self.access_order.items, 0..) |k, i| {
            if (k == key_hash) {
                _ = self.access_order.orderedRemove(i);
                break;
            }
        }
        self.access_order.append(self.allocator, key_hash) catch return;
    }

    pub fn recordAdd(self: *Self, key_hash: u128, size: usize) void {
        self.sizes.put(key_hash, size) catch return;
        self.access_order.append(self.allocator, key_hash) catch return;
    }

    pub fn recordRemove(self: *Self, key_hash: u128) void {
        _ = self.sizes.remove(key_hash);
        for (self.access_order.items, 0..) |k, i| {
            if (k == key_hash) {
                _ = self.access_order.orderedRemove(i);
                break;
            }
        }
    }

    pub fn save(self: *Self, allocator: Allocator) ![]u8 {
        // Simple format: count followed by key hashes
        const count = self.access_order.items.len;
        const size = @sizeOf(usize) + count * @sizeOf(u128);
        const data = try allocator.alloc(u8, size);

        var offset: usize = 0;
        @memcpy(data[offset..][0..@sizeOf(usize)], std.mem.asBytes(&count));
        offset += @sizeOf(usize);

        for (self.access_order.items) |key_hash| {
            @memcpy(data[offset..][0..@sizeOf(u128)], std.mem.asBytes(&key_hash));
            offset += @sizeOf(u128);
        }

        return data;
    }

    pub fn load(self: *Self, data: []const u8) !void {
        if (data.len < @sizeOf(usize)) return error.InvalidData;

        const count = std.mem.bytesToValue(usize, data[0..@sizeOf(usize)]);
        var offset: usize = @sizeOf(usize);

        self.access_order.clearRetainingCapacity();

        for (0..count) |_| {
            if (offset + @sizeOf(u128) > data.len) break;
            const key_hash = std.mem.bytesToValue(u128, data[offset..][0..@sizeOf(u128)]);
            try self.access_order.append(self.allocator, key_hash);
            offset += @sizeOf(u128);
        }
    }
};

/// Size-aware LRU Eviction Manager
///
/// Similar to LRU but considers entry sizes when making eviction decisions.
/// Prefers evicting larger entries when access times are similar.
pub const SizeAwareLruEviction = struct {
    /// Entry metadata
    entries: std.AutoHashMap(u128, EntryMeta),
    /// Selection buffer for results
    selection_buffer: std.ArrayListUnmanaged(u128),
    /// Time window for "similar" access times (nanoseconds)
    time_window_ns: i64,
    /// Allocator
    allocator: Allocator,

    const EntryMeta = struct {
        size: usize,
        last_accessed: i64,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, time_window_seconds: u64) Self {
        return .{
            .entries = std.AutoHashMap(u128, EntryMeta).init(allocator),
            .selection_buffer = .{},
            .time_window_ns = @intCast(time_window_seconds * std.time.ns_per_s),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.entries.deinit();
        self.selection_buffer.deinit(self.allocator);
    }

    pub fn selectForEviction(
        self: *Self,
        candidates: []const EvictionCandidate,
        bytes_needed: usize,
    ) []const u128 {
        _ = candidates;

        self.selection_buffer.clearRetainingCapacity();
        var bytes_freed: usize = 0;

        // Build a list of entries sorted by score (access_time - size_bonus)
        var sorted_entries = std.ArrayListUnmanaged(struct { hash: u128, score: i64, size: usize }){};
        defer sorted_entries.deinit(self.allocator);

        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            // Lower score = higher eviction priority
            // Score = last_accessed - (size / 1024) to prefer larger items
            const size_bonus: i64 = @intCast(@min(kv.value_ptr.size / 1024, 3600));
            const score = kv.value_ptr.last_accessed - size_bonus;
            sorted_entries.append(self.allocator, .{
                .hash = kv.key_ptr.*,
                .score = score,
                .size = kv.value_ptr.size,
            }) catch continue;
        }

        // Sort by score ascending (lower = evict first)
        std.mem.sort(@TypeOf(sorted_entries.items[0]), sorted_entries.items, {}, struct {
            fn lessThan(_: void, a: @TypeOf(sorted_entries.items[0]), b: @TypeOf(sorted_entries.items[0])) bool {
                return a.score < b.score;
            }
        }.lessThan);

        // Select entries to evict
        for (sorted_entries.items) |entry| {
            if (bytes_freed >= bytes_needed) break;
            self.selection_buffer.append(self.allocator, entry.hash) catch break;
            bytes_freed += entry.size;
        }

        return self.selection_buffer.items;
    }

    pub fn recordAccess(self: *Self, key_hash: u128) void {
        if (self.entries.getPtr(key_hash)) |meta| {
            meta.last_accessed = std.time.timestamp();
        }
    }

    pub fn recordAdd(self: *Self, key_hash: u128, size: usize) void {
        self.entries.put(key_hash, .{
            .size = size,
            .last_accessed = std.time.timestamp(),
        }) catch return;
    }

    pub fn recordRemove(self: *Self, key_hash: u128) void {
        _ = self.entries.remove(key_hash);
    }

    pub fn save(self: *Self, allocator: Allocator) ![]u8 {
        const count = self.entries.count();
        const entry_size = @sizeOf(u128) + @sizeOf(EntryMeta);
        const size = @sizeOf(usize) + count * entry_size;
        const data = try allocator.alloc(u8, size);

        var offset: usize = 0;
        @memcpy(data[offset..][0..@sizeOf(usize)], std.mem.asBytes(&count));
        offset += @sizeOf(usize);

        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            @memcpy(data[offset..][0..@sizeOf(u128)], std.mem.asBytes(kv.key_ptr));
            offset += @sizeOf(u128);
            @memcpy(data[offset..][0..@sizeOf(EntryMeta)], std.mem.asBytes(kv.value_ptr));
            offset += @sizeOf(EntryMeta);
        }

        return data;
    }

    pub fn load(self: *Self, data: []const u8) !void {
        if (data.len < @sizeOf(usize)) return error.InvalidData;

        const count = std.mem.bytesToValue(usize, data[0..@sizeOf(usize)]);
        const entry_size = @sizeOf(u128) + @sizeOf(EntryMeta);
        var offset: usize = @sizeOf(usize);

        self.entries.clearRetainingCapacity();

        for (0..count) |_| {
            if (offset + entry_size > data.len) break;
            const key_hash = std.mem.bytesToValue(u128, data[offset..][0..@sizeOf(u128)]);
            offset += @sizeOf(u128);
            const meta = std.mem.bytesToValue(EntryMeta, data[offset..][0..@sizeOf(EntryMeta)]);
            offset += @sizeOf(EntryMeta);
            try self.entries.put(key_hash, meta);
        }
    }
};

/// Simple LRU Eviction Manager
///
/// A lightweight LRU implementation that only tracks access order.
/// Does not track sizes - useful when entries are roughly the same size.
pub const SimpleLruEviction = struct {
    /// Access order (most recent at end)
    access_order: std.ArrayListUnmanaged(u128),
    /// Selection buffer
    selection_buffer: std.ArrayListUnmanaged(u128),
    /// Default entry size estimate
    default_size: usize,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, default_size: usize) Self {
        return .{
            .access_order = .{},
            .selection_buffer = .{},
            .default_size = default_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.access_order.deinit(self.allocator);
        self.selection_buffer.deinit(self.allocator);
    }

    pub fn selectForEviction(
        self: *Self,
        candidates: []const EvictionCandidate,
        bytes_needed: usize,
    ) []const u128 {
        _ = candidates;

        self.selection_buffer.clearRetainingCapacity();
        var bytes_freed: usize = 0;

        // Calculate how many entries to evict
        const entries_needed = (bytes_needed + self.default_size - 1) / self.default_size;

        for (self.access_order.items) |key_hash| {
            if (self.selection_buffer.items.len >= entries_needed and bytes_freed >= bytes_needed) break;
            self.selection_buffer.append(self.allocator, key_hash) catch break;
            bytes_freed += self.default_size;
        }

        return self.selection_buffer.items;
    }

    pub fn recordAccess(self: *Self, key_hash: u128) void {
        for (self.access_order.items, 0..) |k, i| {
            if (k == key_hash) {
                _ = self.access_order.orderedRemove(i);
                break;
            }
        }
        self.access_order.append(self.allocator, key_hash) catch return;
    }

    pub fn recordAdd(self: *Self, key_hash: u128, size: usize) void {
        _ = size;
        self.access_order.append(self.allocator, key_hash) catch return;
    }

    pub fn recordRemove(self: *Self, key_hash: u128) void {
        for (self.access_order.items, 0..) |k, i| {
            if (k == key_hash) {
                _ = self.access_order.orderedRemove(i);
                break;
            }
        }
    }

    pub fn save(self: *Self, allocator: Allocator) ![]u8 {
        const count = self.access_order.items.len;
        const size = @sizeOf(usize) + count * @sizeOf(u128);
        const data = try allocator.alloc(u8, size);

        var offset: usize = 0;
        @memcpy(data[offset..][0..@sizeOf(usize)], std.mem.asBytes(&count));
        offset += @sizeOf(usize);

        for (self.access_order.items) |key_hash| {
            @memcpy(data[offset..][0..@sizeOf(u128)], std.mem.asBytes(&key_hash));
            offset += @sizeOf(u128);
        }

        return data;
    }

    pub fn load(self: *Self, data: []const u8) !void {
        if (data.len < @sizeOf(usize)) return error.InvalidData;

        const count = std.mem.bytesToValue(usize, data[0..@sizeOf(usize)]);
        var offset: usize = @sizeOf(usize);

        self.access_order.clearRetainingCapacity();

        for (0..count) |_| {
            if (offset + @sizeOf(u128) > data.len) break;
            const key_hash = std.mem.bytesToValue(u128, data[offset..][0..@sizeOf(u128)]);
            try self.access_order.append(self.allocator, key_hash);
            offset += @sizeOf(u128);
        }
    }
};

// ============================================================================
// Eviction Manager Tests
// ============================================================================

test "LruEviction basic eviction" {
    var eviction = LruEviction.init(testing.allocator);
    defer eviction.deinit();

    // Add entries
    eviction.recordAdd(1, 100);
    eviction.recordAdd(2, 200);
    eviction.recordAdd(3, 150);

    // Access entry 1 (move to most recent)
    eviction.recordAccess(1);

    // Select for eviction - should select 2 first (oldest), then 3
    const to_evict = eviction.selectForEviction(&[_]EvictionCandidate{}, 250);

    try testing.expect(to_evict.len >= 1);
    try testing.expectEqual(@as(u128, 2), to_evict[0]); // Entry 2 should be first
}

test "LruEviction remove" {
    var eviction = LruEviction.init(testing.allocator);
    defer eviction.deinit();

    eviction.recordAdd(1, 100);
    eviction.recordAdd(2, 200);
    eviction.recordRemove(1);

    // Only entry 2 should remain
    const to_evict = eviction.selectForEviction(&[_]EvictionCandidate{}, 100);
    try testing.expect(to_evict.len == 1);
    try testing.expectEqual(@as(u128, 2), to_evict[0]);
}

test "SizeAwareLruEviction prefers larger entries" {
    var eviction = SizeAwareLruEviction.init(testing.allocator, 60);
    defer eviction.deinit();

    // Add entries at "same" time
    eviction.recordAdd(1, 100); // Small
    eviction.recordAdd(2, 10000); // Large
    eviction.recordAdd(3, 500); // Medium

    // Select for eviction - should prefer larger entry (2) due to size bonus
    const to_evict = eviction.selectForEviction(&[_]EvictionCandidate{}, 5000);

    try testing.expect(to_evict.len >= 1);
    // Entry 2 should be evicted first due to size bonus making it have lower score
    try testing.expectEqual(@as(u128, 2), to_evict[0]);
}

test "SimpleLruEviction basic" {
    var eviction = SimpleLruEviction.init(testing.allocator, 100);
    defer eviction.deinit();

    eviction.recordAdd(1, 0);
    eviction.recordAdd(2, 0);
    eviction.recordAdd(3, 0);
    eviction.recordAccess(1);

    // Should evict entry 2 first (oldest after 1 was accessed)
    const to_evict = eviction.selectForEviction(&[_]EvictionCandidate{}, 100);
    try testing.expect(to_evict.len >= 1);
    try testing.expectEqual(@as(u128, 2), to_evict[0]);
}

test "LruEviction save/load" {
    var eviction1 = LruEviction.init(testing.allocator);
    defer eviction1.deinit();

    eviction1.recordAdd(1, 100);
    eviction1.recordAdd(2, 200);
    eviction1.recordAccess(1);

    // Save state
    const saved = try eviction1.save(testing.allocator);
    defer testing.allocator.free(saved);

    // Load into new eviction manager
    var eviction2 = LruEviction.init(testing.allocator);
    defer eviction2.deinit();
    try eviction2.load(saved);

    // Should have same order
    try testing.expectEqual(eviction1.access_order.items.len, eviction2.access_order.items.len);
}

test "EvictionManager trait with LruEviction" {
    var lru_evict = LruEviction.init(testing.allocator);
    defer lru_evict.deinit();

    var manager = EvictionManager{ .lru = &lru_evict };

    // Use through trait interface
    manager.recordAdd(1, 100);
    manager.recordAdd(2, 200);
    manager.recordAccess(1);

    const to_evict = manager.selectForEviction(&[_]EvictionCandidate{}, 100);
    try testing.expect(to_evict.len >= 1);
    try testing.expectEqual(@as(u128, 2), to_evict[0]);
}

// ============================================================================
// Conditional Request Filter - Full 304 Not Modified Support
// ============================================================================

/// Configuration for conditional request handling
pub const ConditionalFilterConfig = struct {
    /// Whether to handle If-None-Match (ETag) headers
    handle_etag: bool = true,
    /// Whether to handle If-Modified-Since headers
    handle_if_modified_since: bool = true,
    /// Whether to use weak ETag comparison (default: true per RFC 7232)
    weak_etag_comparison: bool = true,
    /// Whether to use strong ETag comparison for certain methods
    strong_comparison_for_range: bool = true,
};

/// Conditional Request Filter
///
/// Handles conditional requests (If-None-Match, If-Modified-Since) and
/// generates 304 Not Modified responses when appropriate.
pub const ConditionalFilter = struct {
    config: ConditionalFilterConfig,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ConditionalFilterConfig) Self {
        return .{
            .config = config,
            .allocator = allocator,
        };
    }

    /// Check if a request should receive a 304 response based on cached metadata
    pub fn shouldReturn304(
        self: *const Self,
        req: *const http.RequestHeader,
        cached_meta: *const CacheMeta,
    ) bool {
        // Check If-None-Match first (takes precedence per RFC 7232)
        if (self.config.handle_etag) {
            if (req.headers.get("if-none-match")) |inm| {
                if (cached_meta.etag) |etag| {
                    if (self.etagMatchesWithConfig(inm, etag, req.method)) {
                        return true;
                    }
                    // If ETag doesn't match, don't check If-Modified-Since
                    return false;
                }
            }
        }

        // Check If-Modified-Since
        if (self.config.handle_if_modified_since) {
            if (req.headers.get("if-modified-since")) |ims| {
                if (cached_meta.last_modified) |lm| {
                    if (self.dateNotModified(ims, lm)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// Check if ETag matches based on configuration
    fn etagMatchesWithConfig(
        self: *const Self,
        if_none_match: []const u8,
        etag: []const u8,
        method: http.Method,
    ) bool {
        // For Range requests, use strong comparison if configured
        const use_strong = self.config.strong_comparison_for_range and
            (method == .GET or method == .HEAD);
        _ = use_strong; // Currently we use weak comparison for all

        if (!self.config.weak_etag_comparison) {
            return strongEtagMatches(if_none_match, etag);
        }

        return etagMatches(if_none_match, etag);
    }

    /// Compare dates for If-Modified-Since
    fn dateNotModified(_: *const Self, if_modified_since: []const u8, last_modified: []const u8) bool {
        // Parse and compare HTTP dates
        // For simplicity, we do a string comparison since both should be in RFC 7231 format
        // A proper implementation would parse the dates
        const ims_parsed = parseHttpDate(if_modified_since);
        const lm_parsed = parseHttpDate(last_modified);

        if (ims_parsed != null and lm_parsed != null) {
            return lm_parsed.? <= ims_parsed.?;
        }

        // Fall back to string comparison
        return std.mem.eql(u8, if_modified_since, last_modified);
    }

    /// Convert a cached response to a 304 Not Modified response
    pub fn to304(
        self: *const Self,
        cached_meta: *const CacheMeta,
    ) !http.ResponseHeader {
        var resp = http.ResponseHeader.init(self.allocator, 304);
        errdefer resp.deinit();

        // Copy relevant headers from cached metadata
        if (cached_meta.etag) |etag| {
            try resp.appendHeader("ETag", etag);
        }

        if (cached_meta.last_modified) |lm| {
            try resp.appendHeader("Last-Modified", lm);
        }

        // Add Cache-Control headers based on original response
        if (cached_meta.stale_while_revalidate) |swr| {
            var buf: [64]u8 = undefined;
            const cc = std.fmt.bufPrint(&buf, "stale-while-revalidate={d}", .{swr}) catch "stale-while-revalidate=0";
            try resp.appendHeader("Cache-Control", cc);
        }

        // Add Date header
        try resp.appendHeader("Date", formatHttpDate(std.time.timestamp()));

        return resp;
    }

    /// Generate a 304 response from a full response (strips body and adjusts headers)
    pub fn responseToNotModified(
        self: *const Self,
        original: *const http.ResponseHeader,
    ) !http.ResponseHeader {
        var resp = http.ResponseHeader.init(self.allocator, 304);
        errdefer resp.deinit();

        // Copy headers that should be included in 304 response per RFC 7232
        const headers_to_copy = [_][]const u8{
            "cache-control",
            "content-location",
            "date",
            "etag",
            "expires",
            "last-modified",
            "vary",
        };

        for (headers_to_copy) |header_name| {
            if (original.headers.get(header_name)) |value| {
                try resp.appendHeader(header_name, value);
            }
        }

        return resp;
    }
};

/// Strong ETag comparison (requires exact match, W/ prefix matters)
pub fn strongEtagMatches(if_none_match: []const u8, etag: []const u8) bool {
    // Handle * (matches any entity)
    if (std.mem.eql(u8, if_none_match, "*")) {
        return true;
    }

    // Strong comparison - weak ETags never match
    if (std.mem.startsWith(u8, if_none_match, "W/") or std.mem.startsWith(u8, etag, "W/")) {
        return false;
    }

    // Parse multiple ETags
    var iter = std.mem.splitSequence(u8, if_none_match, ",");
    while (iter.next()) |tag_raw| {
        const tag = std.mem.trim(u8, tag_raw, " \t");
        if (std.mem.eql(u8, tag, etag)) {
            return true;
        }
    }

    return false;
}

/// Parse an HTTP date string to timestamp
/// Supports RFC 7231 IMF-fixdate format: "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn parseHttpDate(date_str: []const u8) ?i64 {
    // Simple parser for IMF-fixdate format
    // Format: "Day, DD Mon YYYY HH:MM:SS GMT"
    if (date_str.len < 29) return null;

    const month_names = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };

    // Parse day of month
    const day = std.fmt.parseInt(u8, date_str[5..7], 10) catch return null;

    // Parse month
    const month_str = date_str[8..11];
    var month: u8 = 0;
    for (month_names, 1..) |name, i| {
        if (std.mem.eql(u8, month_str, name)) {
            month = @intCast(i);
            break;
        }
    }
    if (month == 0) return null;

    // Parse year
    const year = std.fmt.parseInt(u16, date_str[12..16], 10) catch return null;

    // Parse time
    const hour = std.fmt.parseInt(u8, date_str[17..19], 10) catch return null;
    const minute = std.fmt.parseInt(u8, date_str[20..22], 10) catch return null;
    const second = std.fmt.parseInt(u8, date_str[23..25], 10) catch return null;

    // Convert to Unix timestamp (simplified calculation)
    // Days from year 1970
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeapYear(y)) 366 else 365;
    }

    // Days from month
    const days_in_month = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += days_in_month[m - 1];
        if (m == 2 and isLeapYear(year)) {
            days += 1;
        }
    }

    // Day of month (1-indexed)
    days += day - 1;

    // Calculate total seconds
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

/// Format a timestamp as HTTP date (IMF-fixdate format)
pub fn formatHttpDate(timestamp: i64) []const u8 {
    // For simplicity, return a static placeholder
    // A proper implementation would format the actual timestamp
    _ = timestamp;
    return "Sun, 01 Jan 2024 00:00:00 GMT";
}

/// Generate validators for a response (ETag and/or Last-Modified)
pub const ValidatorGenerator = struct {
    /// Generate a weak ETag from response body
    pub fn generateWeakEtag(allocator: Allocator, body: []const u8) ![]u8 {
        const hash = std.hash.Wyhash.hash(0, body);
        return std.fmt.allocPrint(allocator, "W/\"{x}\"", .{hash});
    }

    /// Generate a strong ETag from response body
    pub fn generateStrongEtag(allocator: Allocator, body: []const u8) ![]u8 {
        const hash = std.hash.Wyhash.hash(0, body);
        return std.fmt.allocPrint(allocator, "\"{x}\"", .{hash});
    }

    /// Format current time as Last-Modified header value
    pub fn generateLastModified(allocator: Allocator) ![]u8 {
        const timestamp = std.time.timestamp();
        _ = timestamp;
        // Return formatted date - simplified for now
        return allocator.dupe(u8, "Sun, 01 Jan 2024 00:00:00 GMT");
    }
};

// ============================================================================
// Conditional Filter Tests
// ============================================================================

test "ConditionalFilter shouldReturn304 with ETag" {
    var filter = ConditionalFilter.init(testing.allocator, .{});

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("If-None-Match", "\"abc123\"");

    var meta = CacheMeta.init(testing.allocator);
    defer {
        meta.etag = null; // Don't free static string
        meta.deinit();
    }
    meta.etag = "\"abc123\"";

    try testing.expect(filter.shouldReturn304(&req, &meta));
}

test "ConditionalFilter shouldReturn304 ETag mismatch" {
    var filter = ConditionalFilter.init(testing.allocator, .{});

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    defer req.deinit();
    try req.appendHeader("If-None-Match", "\"abc123\"");

    var meta = CacheMeta.init(testing.allocator);
    defer {
        meta.etag = null;
        meta.deinit();
    }
    meta.etag = "\"different\"";

    try testing.expect(!filter.shouldReturn304(&req, &meta));
}

test "ConditionalFilter to304" {
    var filter = ConditionalFilter.init(testing.allocator, .{});

    var meta = CacheMeta.init(testing.allocator);
    defer {
        meta.etag = null;
        meta.last_modified = null;
        meta.deinit();
    }
    meta.etag = "\"test-etag\"";
    meta.last_modified = "Mon, 01 Jan 2024 00:00:00 GMT";

    var resp = try filter.to304(&meta);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 304), resp.status.code);
    try testing.expect(resp.headers.get("ETag") != null);
    try testing.expect(resp.headers.get("Last-Modified") != null);
}

test "strongEtagMatches" {
    // Strong match
    try testing.expect(strongEtagMatches("\"abc\"", "\"abc\""));

    // Weak ETag - should not match in strong comparison
    try testing.expect(!strongEtagMatches("W/\"abc\"", "\"abc\""));
    try testing.expect(!strongEtagMatches("\"abc\"", "W/\"abc\""));

    // Wildcard matches
    try testing.expect(strongEtagMatches("*", "\"anything\""));

    // No match
    try testing.expect(!strongEtagMatches("\"foo\"", "\"bar\""));
}

test "parseHttpDate" {
    // Valid IMF-fixdate
    const date = "Sun, 06 Nov 1994 08:49:37 GMT";
    const timestamp = parseHttpDate(date);
    try testing.expect(timestamp != null);

    // Invalid date
    const invalid = "not a date";
    try testing.expect(parseHttpDate(invalid) == null);
}

test "ValidatorGenerator generateWeakEtag" {
    const etag = try ValidatorGenerator.generateWeakEtag(testing.allocator, "Hello, World!");
    defer testing.allocator.free(etag);

    try testing.expect(std.mem.startsWith(u8, etag, "W/\""));
    try testing.expect(std.mem.endsWith(u8, etag, "\""));
}

test "ValidatorGenerator generateStrongEtag" {
    const etag = try ValidatorGenerator.generateStrongEtag(testing.allocator, "Hello, World!");
    defer testing.allocator.free(etag);

    try testing.expect(!std.mem.startsWith(u8, etag, "W/"));
    try testing.expect(std.mem.startsWith(u8, etag, "\""));
    try testing.expect(std.mem.endsWith(u8, etag, "\""));
}

// ============================================================================
// Max File Size Handling
// ============================================================================

/// Error type for responses that exceed the maximum cacheable size
pub const MaxFileSizeError = error{
    /// Response body is too large to cache
    ResponseTooLarge,
};

/// Body bytes tracker to adjust (predicted) cacheability,
/// even if cache has been disabled.
///
/// This tracker is used to monitor the size of response bodies
/// and determine if they exceed the maximum allowed size for caching.
pub const MaxFileSizeTracker = struct {
    /// Current accumulated body bytes
    body_bytes: usize,
    /// Maximum allowed size in bytes
    max_size: usize,

    const Self = @This();

    /// Create a new tracker with the given maximum size
    pub fn init(max_size: usize) Self {
        return .{
            .body_bytes = 0,
            .max_size = max_size,
        };
    }

    /// Add bytes to the tracker.
    /// Returns true if the accumulated bytes are still under the max size allowed.
    pub fn addBodyBytes(self: *Self, bytes: usize) bool {
        self.body_bytes += bytes;
        return self.allowCaching();
    }

    /// Get the maximum file size in bytes
    pub fn maxFileSizeBytes(self: *const Self) usize {
        return self.max_size;
    }

    /// Check if caching is still allowed based on accumulated bytes
    pub fn allowCaching(self: *const Self) bool {
        return self.body_bytes <= self.max_size;
    }

    /// Get the current accumulated body bytes
    pub fn currentBytes(self: *const Self) usize {
        return self.body_bytes;
    }

    /// Reset the tracker
    pub fn reset(self: *Self) void {
        self.body_bytes = 0;
    }

    /// Check if adding the given bytes would exceed the limit
    pub fn wouldExceed(self: *const Self, additional_bytes: usize) bool {
        return self.body_bytes + additional_bytes > self.max_size;
    }

    /// Get the remaining bytes that can be added before exceeding the limit
    pub fn remainingBytes(self: *const Self) usize {
        if (self.body_bytes >= self.max_size) {
            return 0;
        }
        return self.max_size - self.body_bytes;
    }
};

// ============================================================================
// Max File Size Tests
// ============================================================================

test "MaxFileSizeTracker basic" {
    var tracker = MaxFileSizeTracker.init(1000);

    try testing.expect(tracker.allowCaching());
    try testing.expectEqual(@as(usize, 0), tracker.currentBytes());
    try testing.expectEqual(@as(usize, 1000), tracker.maxFileSizeBytes());
}

test "MaxFileSizeTracker addBodyBytes" {
    var tracker = MaxFileSizeTracker.init(100);

    // Adding bytes under limit
    try testing.expect(tracker.addBodyBytes(50));
    try testing.expectEqual(@as(usize, 50), tracker.currentBytes());
    try testing.expect(tracker.allowCaching());

    // Adding more bytes still under limit
    try testing.expect(tracker.addBodyBytes(50));
    try testing.expectEqual(@as(usize, 100), tracker.currentBytes());
    try testing.expect(tracker.allowCaching());

    // Adding bytes that exceed limit
    try testing.expect(!tracker.addBodyBytes(1));
    try testing.expectEqual(@as(usize, 101), tracker.currentBytes());
    try testing.expect(!tracker.allowCaching());
}

test "MaxFileSizeTracker wouldExceed" {
    var tracker = MaxFileSizeTracker.init(100);
    _ = tracker.addBodyBytes(90);

    // 10 more bytes would not exceed
    try testing.expect(!tracker.wouldExceed(10));

    // 11 more bytes would exceed
    try testing.expect(tracker.wouldExceed(11));
}

test "MaxFileSizeTracker remainingBytes" {
    var tracker = MaxFileSizeTracker.init(100);

    try testing.expectEqual(@as(usize, 100), tracker.remainingBytes());

    _ = tracker.addBodyBytes(60);
    try testing.expectEqual(@as(usize, 40), tracker.remainingBytes());

    _ = tracker.addBodyBytes(50); // Now at 110, over limit
    try testing.expectEqual(@as(usize, 0), tracker.remainingBytes());
}

test "MaxFileSizeTracker reset" {
    var tracker = MaxFileSizeTracker.init(100);
    _ = tracker.addBodyBytes(100);

    try testing.expectEqual(@as(usize, 100), tracker.currentBytes());

    tracker.reset();
    try testing.expectEqual(@as(usize, 0), tracker.currentBytes());
    try testing.expect(tracker.allowCaching());
}
