//! pingora-proxy: HTTP Proxy Framework
//!
//! A programmable HTTP proxy built on top of pingora-zig core components.
//!
//! # Features
//! - HTTP/1.1 for both downstream and upstream
//! - Connection pooling
//! - Request/Response scanning, modification or rejection
//! - Dynamic upstream selection
//! - Configurable retry and failover
//! - Fully programmable and customizable at any stage of an HTTP request
//! - Caching support via the cache module
//!
//! # How to use
//!
//! Users define their proxy by implementing the `ProxyHttp` interface, which contains
//! callbacks to be invoked at each stage of an HTTP request.
//!
//! This is a pure Zig implementation. No C dependencies.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-proxy

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// Import dependencies from lower levels
const http = @import("http.zig");
const http_client = @import("http_client.zig");
const http_server = @import("http_server.zig");
const upstream = @import("upstream.zig");
const load_balancer = @import("load_balancer.zig");
const cache = @import("cache.zig");
const protocols = @import("protocols.zig");
const err = @import("error.zig");

// ============================================================================
// Proxy Errors
// ============================================================================

pub const ProxyError = error{
    /// Failed to connect to upstream
    UpstreamConnectionFailed,
    /// Upstream peer selection failed
    NoPeerAvailable,
    /// Request was filtered/rejected
    RequestFiltered,
    /// Response was filtered/rejected
    ResponseFiltered,
    /// Upstream request timed out
    UpstreamTimeout,
    /// Upstream returned an error
    UpstreamError,
    /// Max retries exceeded
    MaxRetriesExceeded,
    /// Invalid request
    InvalidRequest,
    /// Invalid response from upstream
    InvalidUpstreamResponse,
    /// Session error
    SessionError,
    /// Cache error
    CacheError,
    /// Internal proxy error
    InternalError,
    /// Allocation failed
    OutOfMemory,
};

// ============================================================================
// Session - Per-request state
// ============================================================================

/// Per-request session state
///
/// This holds all the state for a single HTTP request being proxied,
/// including the downstream connection, request/response data, and timing info.
pub const Session = struct {
    /// The allocator for this session
    allocator: Allocator,
    /// The downstream (client) request
    downstream_request: ?http.RequestHeader,
    /// The downstream response to send
    downstream_response: ?http.ResponseHeader,
    /// Request body (if buffered)
    request_body: ?[]const u8,
    /// Response body (if buffered)
    response_body: ?[]u8,
    /// The selected upstream peer
    upstream_peer: ?*upstream.Peer,
    /// Cache lookup result
    cache_result: ?cache.CacheLookupResult,
    /// Whether to cache this response
    cache_enabled: bool,
    /// Timing information
    timing: SessionTiming,
    /// Whether the request has been sent to upstream
    request_sent: bool,
    /// Whether the response has been received from upstream
    response_received: bool,
    /// Number of retry attempts
    retry_count: u32,
    /// Custom user context (opaque pointer)
    user_ctx: ?*anyopaque,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .downstream_request = null,
            .downstream_response = null,
            .request_body = null,
            .response_body = null,
            .upstream_peer = null,
            .cache_result = null,
            .cache_enabled = false,
            .timing = SessionTiming.init(),
            .request_sent = false,
            .response_received = false,
            .retry_count = 0,
            .user_ctx = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.downstream_request) |*req| {
            req.deinit();
        }
        if (self.downstream_response) |*resp| {
            resp.deinit();
        }
        if (self.request_body) |body| {
            self.allocator.free(body);
        }
        if (self.response_body) |body| {
            self.allocator.free(body);
        }
    }

    /// Get the request header
    pub fn reqHeader(self: *const Self) ?*const http.RequestHeader {
        if (self.downstream_request) |*req| {
            return req;
        }
        return null;
    }

    /// Get mutable request header
    pub fn reqHeaderMut(self: *Self) ?*http.RequestHeader {
        if (self.downstream_request) |*req| {
            return req;
        }
        return null;
    }

    /// Get the response header
    pub fn respHeader(self: *const Self) ?*const http.ResponseHeader {
        if (self.downstream_response) |*resp| {
            return resp;
        }
        return null;
    }

    /// Get mutable response header
    pub fn respHeaderMut(self: *Self) ?*http.ResponseHeader {
        if (self.downstream_response) |*resp| {
            return resp;
        }
        return null;
    }

    /// Set the request from parsed data
    pub fn setRequest(self: *Self, req: http.RequestHeader) void {
        if (self.downstream_request) |*old| {
            old.deinit();
        }
        self.downstream_request = req;
        self.timing.request_start = std.time.nanoTimestamp();
    }

    /// Set the response
    pub fn setResponse(self: *Self, resp: http.ResponseHeader) void {
        if (self.downstream_response) |*old| {
            old.deinit();
        }
        self.downstream_response = resp;
        self.timing.response_start = std.time.nanoTimestamp();
    }

    /// Mark request as complete
    pub fn markComplete(self: *Self) void {
        self.timing.request_end = std.time.nanoTimestamp();
    }

    /// Get total request duration in nanoseconds
    pub fn getDurationNs(self: *const Self) i128 {
        if (self.timing.request_end) |end| {
            if (self.timing.request_start) |start| {
                return end - start;
            }
        }
        return 0;
    }
};

/// Timing information for a session
pub const SessionTiming = struct {
    /// When the request started
    request_start: ?i128,
    /// When we started connecting to upstream
    upstream_connect_start: ?i128,
    /// When upstream connection was established
    upstream_connect_end: ?i128,
    /// When we started receiving the response
    response_start: ?i128,
    /// When the request completed
    request_end: ?i128,

    pub fn init() SessionTiming {
        return .{
            .request_start = null,
            .upstream_connect_start = null,
            .upstream_connect_end = null,
            .response_start = null,
            .request_end = null,
        };
    }

    /// Get upstream connection time in nanoseconds
    pub fn getUpstreamConnectTimeNs(self: *const SessionTiming) ?i128 {
        if (self.upstream_connect_end) |end| {
            if (self.upstream_connect_start) |start| {
                return end - start;
            }
        }
        return null;
    }
};

// ============================================================================
// ProxyHttp Interface
// ============================================================================

/// Filter result indicating what action to take
pub const FilterResult = enum {
    /// Continue processing
    @"continue",
    /// Response has been sent, finish the request
    done,
    /// Retry the request
    retry,
};

/// Result returned by fail_to_proxy callback
pub const FailToProxy = struct {
    /// HTTP error code sent to downstream (0 means no response sent)
    error_code: u16,
    /// Whether the downstream connection can be reused
    can_reuse_downstream: bool,
};

/// Response cacheability result
pub const RespCacheable = union(enum) {
    /// Response is cacheable with the given TTL in seconds
    cacheable: CacheableMeta,
    /// Response is not cacheable
    uncacheable: NoCacheReason,
};

/// Metadata for cacheable responses
pub const CacheableMeta = struct {
    /// Time-to-live in seconds
    ttl_seconds: u64 = 3600,
    /// Whether the response can be stored in shared caches
    shared: bool = true,
    /// Whether to store despite Set-Cookie header
    store_with_set_cookie: bool = false,
};

/// Reasons why a response is not cacheable
pub const NoCacheReason = enum {
    /// Response status code is not cacheable
    response_status,
    /// Cache-Control: no-store
    no_store,
    /// Cache-Control: private
    private,
    /// Response has Set-Cookie header
    set_cookie,
    /// Response varies on uncacheable headers
    vary,
    /// User-defined reason
    custom,
    /// Method is not cacheable (only GET/HEAD)
    method_not_cacheable,
    /// Response is too large
    response_too_large,
    /// No explicit caching headers
    no_cache_headers,
    /// Origin server error
    origin_error,
    /// Internal error during caching
    internal_error,
    /// Default - caching disabled
    default,
};

/// Purge operation status
pub const PurgeStatus = enum {
    /// Purge succeeded
    success,
    /// Item was not found in cache
    not_found,
    /// Purge failed
    failed,
    /// Partial purge (some items purged)
    partial,
};

/// The interface to control the HTTP proxy
///
/// This uses Zig's interface pattern with function pointers.
/// Users implement this interface to customize proxy behavior at each stage.
pub const ProxyHttp = struct {
    /// Opaque pointer to user implementation
    ptr: *anyopaque,
    /// Virtual function table
    vtable: *const VTable,

    pub const VTable = struct {
        /// Create a new per-request context
        newCtx: *const fn (ptr: *anyopaque, allocator: Allocator) ?*anyopaque,

        /// Destroy the per-request context
        freeCtx: *const fn (ptr: *anyopaque, ctx: *anyopaque) void,

        /// Select the upstream peer for this request
        /// This is the only required callback.
        upstreamPeer: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer,

        /// Handle the incoming request before any downstream module
        /// This runs before request_filter and allows finer control over module behavior
        earlyRequestFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!void,

        /// Handle the incoming request (before upstream)
        /// Return true if response was sent and request should end
        requestFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!FilterResult,

        /// Filter request body chunks as they arrive
        /// body is the current chunk (not the entire body)
        requestBodyFilter: *const fn (ptr: *anyopaque, session: *Session, body: ?[]const u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void,

        /// Modify the request before sending to upstream
        upstreamRequestFilter: *const fn (ptr: *anyopaque, session: *Session, upstream_request: *http.RequestHeader, ctx: ?*anyopaque) ProxyError!void,

        /// Modify the response from upstream before sending downstream
        upstreamResponseFilter: *const fn (ptr: *anyopaque, session: *Session, upstream_response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void,

        /// Filter response body chunks from upstream
        /// body is the current chunk (not the entire body)
        responseBodyFilter: *const fn (ptr: *anyopaque, session: *Session, body: ?[]u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void,

        /// Final modification of response before sending to client
        responseFilter: *const fn (ptr: *anyopaque, session: *Session, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void,

        /// Called when request completes (for logging, metrics, etc.)
        loggingFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) void,

        /// Called on error
        errorFilter: *const fn (ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) void,

        /// Check if request should use cache
        requestCacheFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) bool,

        /// Generate custom cache key for this request
        /// Called only when cache is enabled
        cacheKeyCallback: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ?cache.CacheKey,

        /// Called on cache miss, before fetching from upstream
        cacheMissFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) void,

        /// Called on cache hit, allows force invalidation
        /// Returns true to force revalidation
        cacheHitFilter: *const fn (ptr: *anyopaque, session: *Session, is_fresh: bool, ctx: ?*anyopaque) bool,

        /// Decide if response is cacheable
        responseCacheFilter: *const fn (ptr: *anyopaque, session: *Session, response: *const http.ResponseHeader, ctx: ?*anyopaque) RespCacheable,

        /// Decide if request should continue to upstream after cache miss
        /// Returns true if request should continue, false if response was written
        proxyUpstreamFilter: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!bool,

        /// Determine if upstream should be retried on error
        shouldRetry: *const fn (ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) bool,

        /// Called when connection to upstream fails
        /// Allows marking error as retryable or selecting different peer
        failToConnect: *const fn (ptr: *anyopaque, session: *Session, peer: *upstream.Peer, err_val: ProxyError, ctx: ?*anyopaque) ProxyError,

        /// Called when proxy encounters a fatal error
        /// Write error response to downstream and return status
        failToProxy: *const fn (ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) FailToProxy,

        /// Check if request is a cache purge request
        isPurge: *const fn (ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) bool,

        /// Modify the purge response before sending to downstream
        purgeResponseFilter: *const fn (ptr: *anyopaque, session: *Session, status: PurgeStatus, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void,
    };

    /// Create a new per-request context
    pub fn newCtx(self: ProxyHttp, allocator: Allocator) ?*anyopaque {
        return self.vtable.newCtx(self.ptr, allocator);
    }

    /// Free the per-request context
    pub fn freeCtx(self: ProxyHttp, ctx: *anyopaque) void {
        self.vtable.freeCtx(self.ptr, ctx);
    }

    /// Select upstream peer
    pub fn upstreamPeer(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer {
        return self.vtable.upstreamPeer(self.ptr, session, ctx);
    }

    /// Early request filter (before any modules)
    pub fn earlyRequestFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.earlyRequestFilter(self.ptr, session, ctx);
    }

    /// Request filter
    pub fn requestFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) ProxyError!FilterResult {
        return self.vtable.requestFilter(self.ptr, session, ctx);
    }

    /// Request body filter
    pub fn requestBodyFilter(self: ProxyHttp, session: *Session, body: ?[]const u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.requestBodyFilter(self.ptr, session, body, end_of_stream, ctx);
    }

    /// Upstream request filter
    pub fn upstreamRequestFilter(self: ProxyHttp, session: *Session, upstream_request: *http.RequestHeader, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.upstreamRequestFilter(self.ptr, session, upstream_request, ctx);
    }

    /// Upstream response filter
    pub fn upstreamResponseFilter(self: ProxyHttp, session: *Session, upstream_response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.upstreamResponseFilter(self.ptr, session, upstream_response, ctx);
    }

    /// Response body filter
    pub fn responseBodyFilter(self: ProxyHttp, session: *Session, body: ?[]u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.responseBodyFilter(self.ptr, session, body, end_of_stream, ctx);
    }

    /// Response filter
    pub fn responseFilter(self: ProxyHttp, session: *Session, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.responseFilter(self.ptr, session, response, ctx);
    }

    /// Logging filter
    pub fn loggingFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) void {
        self.vtable.loggingFilter(self.ptr, session, ctx);
    }

    /// Error filter
    pub fn errorFilter(self: ProxyHttp, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) void {
        self.vtable.errorFilter(self.ptr, session, err_val, ctx);
    }

    /// Request cache filter
    pub fn requestCacheFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) bool {
        return self.vtable.requestCacheFilter(self.ptr, session, ctx);
    }

    /// Cache key callback - generate custom cache key
    pub fn cacheKeyCallback(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) ?cache.CacheKey {
        return self.vtable.cacheKeyCallback(self.ptr, session, ctx);
    }

    /// Cache miss filter
    pub fn cacheMissFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) void {
        self.vtable.cacheMissFilter(self.ptr, session, ctx);
    }

    /// Cache hit filter - returns true to force revalidation
    pub fn cacheHitFilter(self: ProxyHttp, session: *Session, is_fresh: bool, ctx: ?*anyopaque) bool {
        return self.vtable.cacheHitFilter(self.ptr, session, is_fresh, ctx);
    }

    /// Response cache filter - decide if response is cacheable
    pub fn responseCacheFilter(self: ProxyHttp, session: *Session, response: *const http.ResponseHeader, ctx: ?*anyopaque) RespCacheable {
        return self.vtable.responseCacheFilter(self.ptr, session, response, ctx);
    }

    /// Proxy upstream filter - decide if request should go to upstream
    pub fn proxyUpstreamFilter(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) ProxyError!bool {
        return self.vtable.proxyUpstreamFilter(self.ptr, session, ctx);
    }

    /// Should retry
    pub fn shouldRetry(self: ProxyHttp, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) bool {
        return self.vtable.shouldRetry(self.ptr, session, err_val, ctx);
    }

    /// Fail to connect - called when upstream connection fails
    pub fn failToConnect(self: ProxyHttp, session: *Session, peer: *upstream.Peer, err_val: ProxyError, ctx: ?*anyopaque) ProxyError {
        return self.vtable.failToConnect(self.ptr, session, peer, err_val, ctx);
    }

    /// Fail to proxy - called on fatal errors
    pub fn failToProxy(self: ProxyHttp, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) FailToProxy {
        return self.vtable.failToProxy(self.ptr, session, err_val, ctx);
    }

    /// Check if request is a purge request
    pub fn isPurge(self: ProxyHttp, session: *Session, ctx: ?*anyopaque) bool {
        return self.vtable.isPurge(self.ptr, session, ctx);
    }

    /// Purge response filter
    pub fn purgeResponseFilter(self: ProxyHttp, session: *Session, status: PurgeStatus, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
        return self.vtable.purgeResponseFilter(self.ptr, session, status, response, ctx);
    }
};

// ============================================================================
// Default ProxyHttp Implementation Helper
// ============================================================================

/// Helper to create a ProxyHttp from a user type
/// The user type T must have an `upstreamPeer` method at minimum.
pub fn proxyHttpFrom(comptime T: type, impl: *T) ProxyHttp {
    const gen = struct {
        fn newCtx(ptr: *anyopaque, allocator: Allocator) ?*anyopaque {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "newCtx")) {
                return self.newCtx(allocator);
            }
            return null;
        }

        fn freeCtx(ptr: *anyopaque, ctx: *anyopaque) void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "freeCtx")) {
                self.freeCtx(ctx);
            }
        }

        fn upstreamPeer(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer {
            const self: *T = @ptrCast(@alignCast(ptr));
            return self.upstreamPeer(session, ctx);
        }

        fn earlyRequestFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "earlyRequestFilter")) {
                return self.earlyRequestFilter(session, ctx);
            }
        }

        fn requestFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!FilterResult {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "requestFilter")) {
                return self.requestFilter(session, ctx);
            }
            return .@"continue";
        }

        fn requestBodyFilter(ptr: *anyopaque, session: *Session, body: ?[]const u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "requestBodyFilter")) {
                return self.requestBodyFilter(session, body, end_of_stream, ctx);
            }
        }

        fn upstreamRequestFilter(ptr: *anyopaque, session: *Session, upstream_request: *http.RequestHeader, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "upstreamRequestFilter")) {
                return self.upstreamRequestFilter(session, upstream_request, ctx);
            }
        }

        fn upstreamResponseFilter(ptr: *anyopaque, session: *Session, upstream_response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "upstreamResponseFilter")) {
                return self.upstreamResponseFilter(session, upstream_response, ctx);
            }
        }

        fn responseBodyFilter(ptr: *anyopaque, session: *Session, body: ?[]u8, end_of_stream: bool, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "responseBodyFilter")) {
                return self.responseBodyFilter(session, body, end_of_stream, ctx);
            }
        }

        fn responseFilter(ptr: *anyopaque, session: *Session, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "responseFilter")) {
                return self.responseFilter(session, response, ctx);
            }
        }

        fn loggingFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "loggingFilter")) {
                self.loggingFilter(session, ctx);
            }
        }

        fn errorFilter(ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "errorFilter")) {
                self.errorFilter(session, err_val, ctx);
            }
        }

        fn requestCacheFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) bool {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "requestCacheFilter")) {
                return self.requestCacheFilter(session, ctx);
            }
            return false; // caching disabled by default
        }

        fn cacheKeyCallback(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ?cache.CacheKey {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "cacheKeyCallback")) {
                return self.cacheKeyCallback(session, ctx);
            }
            // Default: generate key from request
            if (session.reqHeader()) |req| {
                return cache.CacheKey.fromRequest(session.allocator, req) catch null;
            }
            return null;
        }

        fn cacheMissFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) void {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "cacheMissFilter")) {
                self.cacheMissFilter(session, ctx);
            }
            // Default: do nothing
        }

        fn cacheHitFilter(ptr: *anyopaque, session: *Session, is_fresh: bool, ctx: ?*anyopaque) bool {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "cacheHitFilter")) {
                return self.cacheHitFilter(session, is_fresh, ctx);
            }
            // Default: don't force revalidation
            return false;
        }

        fn responseCacheFilter(ptr: *anyopaque, session: *Session, response: *const http.ResponseHeader, ctx: ?*anyopaque) RespCacheable {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "responseCacheFilter")) {
                return self.responseCacheFilter(session, response, ctx);
            }
            // Default: not cacheable
            return .{ .uncacheable = .default };
        }

        fn proxyUpstreamFilter(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) ProxyError!bool {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "proxyUpstreamFilter")) {
                return self.proxyUpstreamFilter(session, ctx);
            }
            // Default: continue to upstream
            return true;
        }

        fn shouldRetry(ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) bool {
            const self: *T = @ptrCast(@alignCast(ptr));
            if (@hasDecl(T, "shouldRetry")) {
                return self.shouldRetry(session, err_val, ctx);
            }
            // Default: retry on connection errors
            return err_val == ProxyError.UpstreamConnectionFailed;
        }

        const failToConnect = if (@hasDecl(T, "failToConnect"))
            struct {
                fn f(ptr: *anyopaque, session: *Session, peer: *upstream.Peer, err_val: ProxyError, ctx: ?*anyopaque) ProxyError {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    return self.failToConnect(session, peer, err_val, ctx);
                }
            }.f
        else
            struct {
                fn f(_: *anyopaque, _: *Session, _: *upstream.Peer, err_val: ProxyError, _: ?*anyopaque) ProxyError {
                    return err_val;
                }
            }.f;

        const failToProxy = if (@hasDecl(T, "failToProxy"))
            struct {
                fn f(ptr: *anyopaque, session: *Session, err_val: ProxyError, ctx: ?*anyopaque) FailToProxy {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    return self.failToProxy(session, err_val, ctx);
                }
            }.f
        else
            struct {
                fn f(_: *anyopaque, _: *Session, err_val: ProxyError, _: ?*anyopaque) FailToProxy {
                    const code: u16 = switch (err_val) {
                        ProxyError.UpstreamConnectionFailed, ProxyError.UpstreamError, ProxyError.UpstreamTimeout => 502,
                        ProxyError.NoPeerAvailable => 503,
                        ProxyError.InvalidRequest => 400,
                        ProxyError.RequestFiltered => 403,
                        else => 500,
                    };
                    return .{
                        .error_code = code,
                        .can_reuse_downstream = false,
                    };
                }
            }.f;

        const isPurge = if (@hasDecl(T, "isPurge"))
            struct {
                fn f(ptr: *anyopaque, session: *Session, ctx: ?*anyopaque) bool {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    return self.isPurge(session, ctx);
                }
            }.f
        else
            struct {
                fn f(_: *anyopaque, _: *Session, _: ?*anyopaque) bool {
                    return false;
                }
            }.f;

        const purgeResponseFilter = if (@hasDecl(T, "purgeResponseFilter"))
            struct {
                fn f(ptr: *anyopaque, session: *Session, status: PurgeStatus, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    return self.purgeResponseFilter(session, status, response, ctx);
                }
            }.f
        else
            struct {
                fn f(_: *anyopaque, _: *Session, _: PurgeStatus, _: *http.ResponseHeader, _: ?*anyopaque) ProxyError!void {}
            }.f;

        const vtable = ProxyHttp.VTable{
            .newCtx = newCtx,
            .freeCtx = freeCtx,
            .upstreamPeer = upstreamPeer,
            .earlyRequestFilter = earlyRequestFilter,
            .requestFilter = requestFilter,
            .requestBodyFilter = requestBodyFilter,
            .upstreamRequestFilter = upstreamRequestFilter,
            .upstreamResponseFilter = upstreamResponseFilter,
            .responseBodyFilter = responseBodyFilter,
            .responseFilter = responseFilter,
            .loggingFilter = loggingFilter,
            .errorFilter = errorFilter,
            .requestCacheFilter = requestCacheFilter,
            .cacheKeyCallback = cacheKeyCallback,
            .cacheMissFilter = cacheMissFilter,
            .cacheHitFilter = cacheHitFilter,
            .responseCacheFilter = responseCacheFilter,
            .proxyUpstreamFilter = proxyUpstreamFilter,
            .shouldRetry = shouldRetry,
            .failToConnect = failToConnect,
            .failToProxy = failToProxy,
            .isPurge = isPurge,
            .purgeResponseFilter = purgeResponseFilter,
        };
    };

    return .{
        .ptr = impl,
        .vtable = &gen.vtable,
    };
}

// ============================================================================
// HttpProxy Configuration
// ============================================================================

/// Configuration for the HTTP proxy
pub const HttpProxyConfig = struct {
    /// Maximum number of retry attempts
    max_retries: u32 = 3,
    /// Connection timeout in milliseconds
    connect_timeout_ms: u64 = 5000,
    /// Read timeout in milliseconds
    read_timeout_ms: u64 = 30000,
    /// Write timeout in milliseconds
    write_timeout_ms: u64 = 30000,
    /// Whether to enable HTTP keep-alive to upstream
    upstream_keepalive: bool = true,
    /// Maximum idle connections per upstream
    max_idle_per_upstream: usize = 10,
    /// Whether to buffer the full request body
    buffer_request_body: bool = false,
    /// Whether to buffer the full response body
    buffer_response_body: bool = false,
    /// Enable caching
    cache_enabled: bool = false,
    /// Cache configuration (if caching is enabled)
    cache_config: cache.HttpCacheConfig = .{},
    /// Use mock upstream for testing (bypasses real network I/O)
    use_mock_upstream: bool = false,
};

// ============================================================================
// HttpProxy - Main Proxy Implementation
// ============================================================================

/// The main HTTP proxy struct
///
/// This coordinates all proxy operations: accepting connections,
/// processing requests through filters, forwarding to upstreams,
/// and sending responses back to clients.
pub const HttpProxy = struct {
    /// Allocator
    allocator: Allocator,
    /// The user's proxy implementation
    proxy_impl: ProxyHttp,
    /// Configuration
    config: HttpProxyConfig,
    /// HTTP cache (if enabled)
    http_cache: ?*cache.HttpCache,
    /// Statistics
    stats: ProxyStats,

    const Self = @This();

    /// Proxy statistics
    pub const ProxyStats = struct {
        /// Total requests processed
        requests_total: u64 = 0,
        /// Successful requests
        requests_success: u64 = 0,
        /// Failed requests
        requests_failed: u64 = 0,
        /// Cache hits
        cache_hits: u64 = 0,
        /// Cache misses
        cache_misses: u64 = 0,
        /// Total bytes received from clients
        bytes_received: u64 = 0,
        /// Total bytes sent to clients
        bytes_sent: u64 = 0,
        /// Total upstream connections made
        upstream_connections: u64 = 0,
        /// Total retry attempts
        retries: u64 = 0,
    };

    /// Create a new HTTP proxy
    pub fn init(allocator: Allocator, proxy_impl: ProxyHttp, config: HttpProxyConfig) !Self {
        var http_cache_ptr: ?*cache.HttpCache = null;

        if (config.cache_enabled) {
            const cache_ptr = try allocator.create(cache.HttpCache);
            cache_ptr.* = try cache.HttpCache.init(allocator, config.cache_config);
            http_cache_ptr = cache_ptr;
        }

        return .{
            .allocator = allocator,
            .proxy_impl = proxy_impl,
            .config = config,
            .http_cache = http_cache_ptr,
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.http_cache) |cache_ptr| {
            cache_ptr.deinit();
            self.allocator.destroy(cache_ptr);
        }
    }

    /// Process a single HTTP request through the proxy pipeline
    ///
    /// This is the main entry point for proxying a request.
    /// It runs through all the proxy phases:
    /// 1. Request filter
    /// 2. Cache lookup (if enabled)
    /// 3. Upstream peer selection
    /// 4. Upstream request filter
    /// 5. Send request to upstream
    /// 6. Receive response from upstream
    /// 7. Upstream response filter
    /// 8. Cache store (if enabled)
    /// 9. Response filter
    /// 10. Send response to client
    /// 11. Logging filter
    pub fn processRequest(self: *Self, session: *Session) !void {
        self.stats.requests_total += 1;

        // Create user context for this request
        const ctx = self.proxy_impl.newCtx(self.allocator);
        defer if (ctx) |c| self.proxy_impl.freeCtx(c);

        session.user_ctx = ctx;

        // Run the proxy pipeline with retry support
        var last_error: ?ProxyError = null;
        var attempt: u32 = 0;

        while (attempt <= self.config.max_retries) : (attempt += 1) {
            session.retry_count = attempt;

            const result = self.runProxyPipeline(session, ctx);

            if (result) |_| {
                // Success
                self.stats.requests_success += 1;
                session.markComplete();
                self.proxy_impl.loggingFilter(session, ctx);
                return;
            } else |proxy_err| {
                last_error = proxy_err;

                // Check if we should retry
                if (attempt < self.config.max_retries and self.proxy_impl.shouldRetry(session, proxy_err, ctx)) {
                    self.stats.retries += 1;
                    session.request_sent = false;
                    session.response_received = false;
                    continue;
                }

                // No more retries - report error
                break;
            }
        }

        // All retries exhausted or non-retryable error
        self.stats.requests_failed += 1;
        if (last_error) |proxy_err| {
            self.proxy_impl.errorFilter(session, proxy_err, ctx);
        }
        session.markComplete();
        self.proxy_impl.loggingFilter(session, ctx);

        if (last_error) |proxy_err| {
            return proxy_err;
        }
    }

    /// Run the main proxy pipeline (single attempt)
    fn runProxyPipeline(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!void {
        // Phase 1: Request filter
        const filter_result = try self.proxy_impl.requestFilter(session, ctx);
        switch (filter_result) {
            .done => return, // Response already sent
            .retry => return ProxyError.InternalError, // Will trigger retry
            .@"continue" => {},
        }

        // Phase 2: Cache lookup (if enabled)
        if (self.config.cache_enabled and self.proxy_impl.requestCacheFilter(session, ctx)) {
            if (self.http_cache) |http_cache| {
                if (session.reqHeader()) |req| {
                    const cache_result = http_cache.lookup(req) catch .miss;
                    session.cache_result = cache_result;
                    session.cache_enabled = true;

                    switch (cache_result) {
                        .hit => {
                            self.stats.cache_hits += 1;
                            // Serve from cache - create response from cached data
                            try self.serveCachedResponse(session, ctx);
                            return;
                        },
                        .stale => {
                            self.stats.cache_hits += 1;
                            // Stale-while-revalidate: serve stale content immediately,
                            // then trigger background revalidation.
                            // Per RFC 5861, we serve the stale response to the client
                            // while asynchronously revalidating in the background.
                            try self.serveStaleAndRevalidate(session, ctx);
                            return;
                        },
                        .miss, .bypass => {
                            self.stats.cache_misses += 1;
                        },
                    }
                }
            }
        }

        // Phase 3: Select upstream peer
        const peer = try self.proxy_impl.upstreamPeer(session, ctx);
        if (peer == null) {
            return ProxyError.NoPeerAvailable;
        }
        session.upstream_peer = peer;

        // Phase 4: Prepare upstream request
        var upstream_request = try self.prepareUpstreamRequest(session);
        defer upstream_request.deinit();

        // Phase 5: Upstream request filter
        try self.proxy_impl.upstreamRequestFilter(session, &upstream_request, ctx);

        // Phase 6: Send request to upstream and get response
        session.timing.upstream_connect_start = std.time.nanoTimestamp();

        var upstream_response = if (self.config.use_mock_upstream)
            try self.sendUpstreamRequestMock(session, &upstream_request)
        else
            try self.sendUpstreamRequest(session, &upstream_request);
        defer upstream_response.deinit();

        session.timing.upstream_connect_end = std.time.nanoTimestamp();
        session.request_sent = true;
        session.response_received = true;
        self.stats.upstream_connections += 1;

        // Phase 7: Upstream response filter
        try self.proxy_impl.upstreamResponseFilter(session, &upstream_response, ctx);

        // Phase 8: Cache store (if enabled and response is cacheable)
        if (session.cache_enabled) {
            if (self.http_cache) |http_cache| {
                if (session.reqHeader()) |req| {
                    const body = session.response_body orelse "";
                    _ = http_cache.store(req, &upstream_response, body) catch false;
                }
            }
        }

        // Phase 9: Response filter
        try self.proxy_impl.responseFilter(session, &upstream_response, ctx);

        // Phase 10: Set the response for the session
        // Clone the response since upstream_response will be deinitialized
        var response_copy = http.ResponseHeader.init(self.allocator, upstream_response.status.code);
        errdefer response_copy.deinit();

        // Copy headers
        for (upstream_response.headers.iterator()) |header| {
            response_copy.appendHeader(header.name.asSlice(), header.value) catch return ProxyError.OutOfMemory;
        }

        session.setResponse(response_copy);
    }

    /// Prepare the upstream request from the downstream request
    fn prepareUpstreamRequest(self: *Self, session: *Session) ProxyError!http.RequestHeader {
        const req = session.reqHeader() orelse return ProxyError.InvalidRequest;

        // Clone the request for upstream
        var upstream_req = http.RequestHeader.build(
            self.allocator,
            req.method,
            req.uri.raw,
            if (req.version == .http_1_0) .http_1_0 else .http_1_1,
        ) catch return ProxyError.OutOfMemory;
        errdefer upstream_req.deinit();

        // Copy relevant headers
        for (req.headers.iterator()) |header| {
            // Skip hop-by-hop headers
            if (isHopByHopHeader(header.name.asSlice())) continue;

            upstream_req.appendHeader(header.name.asSlice(), header.value) catch return ProxyError.OutOfMemory;
        }

        return upstream_req;
    }

    /// Send request to upstream and get response
    ///
    /// This function establishes a connection to the upstream peer,
    /// sends the HTTP request, and receives the response.
    fn sendUpstreamRequest(self: *Self, session: *Session, upstream_request: *http.RequestHeader) ProxyError!http.ResponseHeader {
        const peer = session.upstream_peer orelse return ProxyError.NoPeerAvailable;

        // Connect to upstream using http_client
        var http_session = http_client.HttpSession.connect(
            self.allocator,
            peer.address,
            .{
                .connect_timeout_ms = @intCast(self.config.connect_timeout_ms),
                .read_timeout_ms = @intCast(self.config.read_timeout_ms),
                .write_timeout_ms = @intCast(self.config.write_timeout_ms),
                .keep_alive = self.config.upstream_keepalive,
            },
        ) catch {
            return ProxyError.UpstreamConnectionFailed;
        };
        defer http_session.close();

        // Send the request
        http_session.sendRequest(upstream_request, session.request_body) catch {
            return ProxyError.UpstreamError;
        };

        // Read the response
        var client_response = http_session.readResponse() catch {
            return ProxyError.InvalidUpstreamResponse;
        };
        defer client_response.deinit();

        // Convert HttpResponse to ResponseHeader
        var response = http.ResponseHeader.init(session.allocator, client_response.status_code);
        errdefer response.deinit();

        // Copy headers from client response
        var it = client_response.headers.iterator();
        while (it.next()) |entry| {
            response.appendHeader(entry.key_ptr.*, entry.value_ptr.*) catch return ProxyError.OutOfMemory;
        }

        // Store response body in session if buffering is enabled
        if (self.config.buffer_response_body) {
            if (client_response.body) |body| {
                session.response_body = self.allocator.dupe(u8, body) catch return ProxyError.OutOfMemory;
            }
        }

        return response;
    }

    /// Send request to upstream with mock response (for testing)
    /// This is useful when running tests without actual network connectivity.
    pub fn sendUpstreamRequestMock(self: *Self, session: *Session, upstream_request: *http.RequestHeader) ProxyError!http.ResponseHeader {
        _ = self;
        _ = upstream_request;
        const peer = session.upstream_peer orelse return ProxyError.NoPeerAvailable;
        _ = peer;

        var response = http.ResponseHeader.init(session.allocator, 200);
        response.appendHeader("Content-Type", "text/plain") catch return ProxyError.OutOfMemory;
        response.appendHeader("Server", "pingora-zig") catch return ProxyError.OutOfMemory;

        return response;
    }

    /// Serve a cached response
    fn serveCachedResponse(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!void {
        // Create response from cache
        // The cache module stores the response headers and body

        var response = http.ResponseHeader.init(self.allocator, 200);
        errdefer response.deinit();

        response.appendHeader("X-Cache", "HIT") catch return ProxyError.OutOfMemory;

        // Run response filter
        try self.proxy_impl.responseFilter(session, &response, ctx);

        session.setResponse(response);
    }

    /// Serve stale cached response and trigger background revalidation (RFC 5861)
    ///
    /// This implements stale-while-revalidate behavior:
    /// 1. Immediately serve the stale cached response to the client
    /// 2. Trigger a background revalidation to refresh the cache
    ///
    /// Note: In this synchronous implementation, we serve the stale response first,
    /// then perform revalidation inline. In a production async runtime, the
    /// revalidation would happen in a separate task/coroutine.
    fn serveStaleAndRevalidate(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!void {
        // Step 1: Serve the stale response immediately
        var response = http.ResponseHeader.init(self.allocator, 200);
        errdefer response.deinit();

        // Mark as stale hit for observability
        response.appendHeader("X-Cache", "HIT") catch return ProxyError.OutOfMemory;
        response.appendHeader("X-Cache-Status", "stale") catch return ProxyError.OutOfMemory;

        // Add Warning header per RFC 7234 Section 5.5.1
        // Warning: 110 - "Response is Stale"
        response.appendHeader("Warning", "110 - \"Response is Stale\"") catch return ProxyError.OutOfMemory;

        // Run response filter on the stale response
        try self.proxy_impl.responseFilter(session, &response, ctx);

        // Set the stale response for the client
        session.setResponse(response);

        // Step 2: Trigger background revalidation
        // In a blocking I/O model, we perform this after serving the response.
        // The client gets the stale response immediately, and we update the cache
        // for subsequent requests.
        self.triggerBackgroundRevalidation(session, ctx);
    }

    /// Trigger background cache revalidation
    ///
    /// This fetches fresh content from upstream and updates the cache.
    /// In a synchronous model, this runs after the stale response is served.
    /// Errors during revalidation are logged but don't affect the client response.
    fn triggerBackgroundRevalidation(self: *Self, session: *Session, ctx: ?*anyopaque) void {
        // Select upstream peer for revalidation
        const peer = self.proxy_impl.upstreamPeer(session, ctx) catch return;
        if (peer == null) return;

        // Store original peer and set for revalidation request
        const original_peer = session.upstream_peer;
        session.upstream_peer = peer;
        defer session.upstream_peer = original_peer;

        // Prepare upstream request for revalidation
        var upstream_request = self.prepareUpstreamRequest(session) catch return;
        defer upstream_request.deinit();

        // Add conditional request headers if we have validators
        // This allows the origin to return 304 Not Modified if content hasn't changed
        if (self.http_cache) |http_cache| {
            if (session.reqHeader()) |req| {
                var key = cache.CacheKey.fromRequest(self.allocator, req) catch return;
                defer key.deinit();

                // Try to get cached entry to extract ETag/Last-Modified
                // Note: We already know the entry exists since we got a stale result
                const lookup_result = http_cache.cache_store.get(key.hash());
                if (lookup_result[0]) |cached| {
                    // Add If-None-Match header with ETag
                    if (cached.meta.etag) |etag| {
                        upstream_request.appendHeader("If-None-Match", etag) catch {};
                    }
                    // Add If-Modified-Since header
                    if (cached.meta.last_modified) |lm| {
                        upstream_request.appendHeader("If-Modified-Since", lm) catch {};
                    }
                }
            }
        }

        // Send revalidation request to upstream
        var upstream_response = if (self.config.use_mock_upstream)
            self.sendUpstreamRequestMock(session, &upstream_request) catch return
        else
            self.sendUpstreamRequest(session, &upstream_request) catch return;
        defer upstream_response.deinit();

        // Check if we got 304 Not Modified
        if (upstream_response.status.code == 304) {
            // Content hasn't changed, just update the cache metadata (freshness)
            // The existing cached body is still valid
            if (self.http_cache) |http_cache| {
                if (session.reqHeader()) |req| {
                    // Re-store with updated freshness (the store will update timestamps)
                    const body = session.response_body orelse "";
                    _ = http_cache.store(req, &upstream_response, body) catch {};
                }
            }
            return;
        }

        // Got a new response (200 or other), update the cache
        if (upstream_response.status.code >= 200 and upstream_response.status.code < 400) {
            if (self.http_cache) |http_cache| {
                if (session.reqHeader()) |req| {
                    const body = session.response_body orelse "";
                    _ = http_cache.store(req, &upstream_response, body) catch {};
                }
            }
        }
        // If upstream returns an error, we keep the stale content (stale-if-error behavior)
    }

    /// Get proxy statistics
    pub fn getStats(self: *const Self) ProxyStats {
        return self.stats;
    }

    /// Reset statistics
    pub fn resetStats(self: *Self) void {
        self.stats = .{};
    }
};

/// Check if a header is a hop-by-hop header that shouldn't be forwarded
fn isHopByHopHeader(name: []const u8) bool {
    const hop_headers = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    };

    for (hop_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Simple Load Balancer Proxy Implementation
// ============================================================================

/// A simple load balancer proxy implementation using round-robin selection
pub const LoadBalancerProxy = struct {
    lb: *load_balancer.LoadBalancer,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, lb: *load_balancer.LoadBalancer) Self {
        return .{
            .lb = lb,
            .allocator = allocator,
        };
    }

    /// Select an upstream peer using the load balancer
    pub fn upstreamPeer(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer {
        _ = ctx;

        // Use request path as the key for consistent hashing
        const key: ?[]const u8 = if (session.reqHeader()) |req|
            req.uri.pathAndQuery()
        else
            null;

        return self.lb.select(key);
    }

    /// Add custom headers to upstream request
    pub fn upstreamRequestFilter(self: *Self, session: *Session, upstream_request: *http.RequestHeader, ctx: ?*anyopaque) ProxyError!void {
        _ = self;
        _ = session;
        _ = ctx;

        // Add X-Forwarded headers
        upstream_request.appendHeader("X-Forwarded-Proto", "http") catch return ProxyError.OutOfMemory;
    }

    /// Get as ProxyHttp interface
    pub fn asProxyHttp(self: *Self) ProxyHttp {
        return proxyHttpFrom(Self, self);
    }
};

// ============================================================================
// Reverse Proxy Implementation
// ============================================================================

/// A simple reverse proxy to a single upstream
pub const ReverseProxy = struct {
    upstream_peer: upstream.Peer,
    allocator: Allocator,

    const Self = @This();

    /// Create a reverse proxy to the given address
    pub fn init(allocator: Allocator, address: std.net.Address) Self {
        return .{
            .upstream_peer = upstream.Peer.init(allocator, address, .{}),
            .allocator = allocator,
        };
    }

    /// Create a reverse proxy from host and port
    pub fn initFromHostPort(allocator: Allocator, host: []const u8, port: u16) !Self {
        const address = try protocols.parseAddress(host, port);
        return init(allocator, address);
    }

    pub fn deinit(self: *Self) void {
        self.upstream_peer.deinit();
    }

    pub fn upstreamPeer(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer {
        _ = session;
        _ = ctx;
        return &self.upstream_peer;
    }

    pub fn asProxyHttp(self: *Self) ProxyHttp {
        return proxyHttpFrom(Self, self);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Session init and deinit" {
    var session = Session.init(testing.allocator);
    defer session.deinit();

    try testing.expect(session.downstream_request == null);
    try testing.expect(session.downstream_response == null);
    try testing.expect(session.upstream_peer == null);
    try testing.expect(session.retry_count == 0);
}

test "Session timing" {
    var session = Session.init(testing.allocator);
    defer session.deinit();

    // Initially no timing
    try testing.expect(session.timing.request_start == null);

    // Create and set a request
    const req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    session.setRequest(req);

    try testing.expect(session.timing.request_start != null);
    try testing.expect(session.reqHeader() != null);
}

test "Session request/response" {
    var session = Session.init(testing.allocator);
    defer session.deinit();

    // Set request
    var req = try http.RequestHeader.build(testing.allocator, .GET, "/api/users", null);
    try req.appendHeader("Host", "example.com");
    session.setRequest(req);

    // Verify request
    const req_header = session.reqHeader().?;
    try testing.expectEqual(req_header.method, .GET);

    // Set response
    var resp = http.ResponseHeader.init(testing.allocator, 200);
    try resp.appendHeader("Content-Type", "application/json");
    session.setResponse(resp);

    // Verify response
    const resp_header = session.respHeader().?;
    try testing.expectEqual(resp_header.status.code, 200);
}

test "FilterResult enum" {
    const result: FilterResult = .@"continue";
    try testing.expect(result == .@"continue");

    const done: FilterResult = .done;
    try testing.expect(done == .done);
}

test "isHopByHopHeader" {
    try testing.expect(isHopByHopHeader("Connection"));
    try testing.expect(isHopByHopHeader("connection"));
    try testing.expect(isHopByHopHeader("Keep-Alive"));
    try testing.expect(isHopByHopHeader("Transfer-Encoding"));

    try testing.expect(!isHopByHopHeader("Content-Type"));
    try testing.expect(!isHopByHopHeader("Host"));
    try testing.expect(!isHopByHopHeader("Accept"));
}

test "HttpProxyConfig defaults" {
    const config = HttpProxyConfig{};

    try testing.expectEqual(config.max_retries, 3);
    try testing.expectEqual(config.connect_timeout_ms, 5000);
    try testing.expect(config.upstream_keepalive);
    try testing.expect(!config.cache_enabled);
}

test "ProxyStats initialization" {
    const stats = HttpProxy.ProxyStats{};

    try testing.expectEqual(stats.requests_total, 0);
    try testing.expectEqual(stats.requests_success, 0);
    try testing.expectEqual(stats.cache_hits, 0);
}

// Test proxy with a mock implementation
const MockProxy = struct {
    peer: upstream.Peer,
    request_filter_called: bool = false,
    upstream_request_filter_called: bool = false,
    response_filter_called: bool = false,
    logging_filter_called: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        const address = try protocols.parseAddress("127.0.0.1", 8080);
        return .{
            .peer = upstream.Peer.init(allocator, address, .{}),
        };
    }

    pub fn deinit(self: *Self) void {
        self.peer.deinit();
    }

    pub fn upstreamPeer(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!?*upstream.Peer {
        _ = session;
        _ = ctx;
        return &self.peer;
    }

    pub fn requestFilter(self: *Self, session: *Session, ctx: ?*anyopaque) ProxyError!FilterResult {
        _ = session;
        _ = ctx;
        self.request_filter_called = true;
        return .@"continue";
    }

    pub fn upstreamRequestFilter(self: *Self, session: *Session, upstream_request: *http.RequestHeader, ctx: ?*anyopaque) ProxyError!void {
        _ = session;
        _ = upstream_request;
        _ = ctx;
        self.upstream_request_filter_called = true;
    }

    pub fn responseFilter(self: *Self, session: *Session, response: *http.ResponseHeader, ctx: ?*anyopaque) ProxyError!void {
        _ = session;
        _ = response;
        _ = ctx;
        self.response_filter_called = true;
    }

    pub fn loggingFilter(self: *Self, session: *Session, ctx: ?*anyopaque) void {
        _ = session;
        _ = ctx;
        self.logging_filter_called = true;
    }

    pub fn asProxyHttp(self: *Self) ProxyHttp {
        return proxyHttpFrom(Self, self);
    }
};

test "HttpProxy basic request processing" {
    var mock = try MockProxy.init(testing.allocator);
    defer mock.deinit();

    var proxy = try HttpProxy.init(testing.allocator, mock.asProxyHttp(), .{ .use_mock_upstream = true });
    defer proxy.deinit();

    // Create a session with a request
    var session = Session.init(testing.allocator);
    defer session.deinit();

    var req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
    try req.appendHeader("Host", "example.com");
    session.setRequest(req);

    // Process the request
    try proxy.processRequest(&session);

    // Verify filters were called
    try testing.expect(mock.request_filter_called);
    try testing.expect(mock.upstream_request_filter_called);
    try testing.expect(mock.response_filter_called);
    try testing.expect(mock.logging_filter_called);

    // Verify stats
    const stats = proxy.getStats();
    try testing.expectEqual(stats.requests_total, 1);
    try testing.expectEqual(stats.requests_success, 1);
    try testing.expectEqual(stats.upstream_connections, 1);
}

test "HttpProxy statistics" {
    var mock = try MockProxy.init(testing.allocator);
    defer mock.deinit();

    var proxy = try HttpProxy.init(testing.allocator, mock.asProxyHttp(), .{ .use_mock_upstream = true });
    defer proxy.deinit();

    // Process multiple requests
    for (0..3) |_| {
        var session = Session.init(testing.allocator);
        defer session.deinit();

        const req = try http.RequestHeader.build(testing.allocator, .GET, "/test", null);
        session.setRequest(req);

        try proxy.processRequest(&session);
    }

    const stats = proxy.getStats();
    try testing.expectEqual(stats.requests_total, 3);
    try testing.expectEqual(stats.requests_success, 3);

    // Reset stats
    proxy.resetStats();
    const new_stats = proxy.getStats();
    try testing.expectEqual(new_stats.requests_total, 0);
}

test "ReverseProxy creation" {
    var rp = try ReverseProxy.initFromHostPort(testing.allocator, "127.0.0.1", 8080);
    defer rp.deinit();

    // Test peer selection
    var session = Session.init(testing.allocator);
    defer session.deinit();

    const peer = try rp.upstreamPeer(&session, null);
    try testing.expect(peer != null);
    try testing.expectEqual(peer.?.getPort(), 8080);
}

test "proxyHttpFrom creates valid interface" {
    var mock = try MockProxy.init(testing.allocator);
    defer mock.deinit();

    const proxy_http = mock.asProxyHttp();

    // Verify interface works by calling a method
    var session = Session.init(testing.allocator);
    defer session.deinit();

    const peer = try proxy_http.upstreamPeer(&session, null);
    try testing.expect(peer != null);
}

