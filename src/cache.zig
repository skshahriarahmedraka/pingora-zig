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
        const core = try LockCore.init(self.allocator, self.age_timeout_ns, stale_writer);
        errdefer core.unref();

        const stub = LockStub{ .core = core.ref() };

        // Remove old entry if exists and insert new one
        if (self.lock_table.fetchRemove(hash)) |old| {
            var old_stub = old.value;
            old_stub.deinit();
        }
        try self.lock_table.put(hash, stub);

        return .{ .write = WritePermit.init(core) };
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

