//! pingora-http: HTTP header objects that preserve header cases
//!
//! Although HTTP header names are supposed to be case-insensitive for compatibility,
//! proxies ideally shouldn't alter the HTTP traffic, especially the headers they
//! don't need to read.
//!
//! This module provides structs and methods to preserve the headers in order to
//! build a transparent proxy.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-http

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// HTTP Version
// ============================================================================

/// HTTP protocol version
pub const Version = enum {
    http_0_9,
    http_1_0,
    http_1_1,
    http_2,
    http_3,

    pub fn asStr(self: Version) []const u8 {
        return switch (self) {
            .http_0_9 => "HTTP/0.9",
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2 => "HTTP/2.0",
            .http_3 => "HTTP/3.0",
        };
    }

    pub fn fromStr(s: []const u8) ?Version {
        if (std.mem.eql(u8, s, "HTTP/0.9")) return .http_0_9;
        if (std.mem.eql(u8, s, "HTTP/1.0")) return .http_1_0;
        if (std.mem.eql(u8, s, "HTTP/1.1")) return .http_1_1;
        if (std.mem.eql(u8, s, "HTTP/2.0") or std.mem.eql(u8, s, "HTTP/2")) return .http_2;
        if (std.mem.eql(u8, s, "HTTP/3.0") or std.mem.eql(u8, s, "HTTP/3")) return .http_3;
        return null;
    }
};

// ============================================================================
// HTTP Method
// ============================================================================

/// HTTP request method
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,

    pub fn asStr(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .HEAD => "HEAD",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .CONNECT => "CONNECT",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .PATCH => "PATCH",
        };
    }

    pub fn fromStr(s: []const u8) ?Method {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "CONNECT")) return .CONNECT;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, s, "TRACE")) return .TRACE;
        if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
        return null;
    }
};

// ============================================================================
// HTTP Status Code
// ============================================================================

/// HTTP status code
pub const StatusCode = struct {
    code: u16,

    pub fn init(code: u16) StatusCode {
        return .{ .code = code };
    }

    pub fn canonicalReason(self: StatusCode) ?[]const u8 {
        return switch (self.code) {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            423 => "Locked",
            424 => "Failed Dependency",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            else => null,
        };
    }

    pub fn isInformational(self: StatusCode) bool {
        return self.code >= 100 and self.code < 200;
    }

    pub fn isSuccess(self: StatusCode) bool {
        return self.code >= 200 and self.code < 300;
    }

    pub fn isRedirection(self: StatusCode) bool {
        return self.code >= 300 and self.code < 400;
    }

    pub fn isClientError(self: StatusCode) bool {
        return self.code >= 400 and self.code < 500;
    }

    pub fn isServerError(self: StatusCode) bool {
        return self.code >= 500 and self.code < 600;
    }
};

// Common status codes
pub const STATUS_OK = StatusCode.init(200);
pub const STATUS_NOT_FOUND = StatusCode.init(404);
pub const STATUS_BAD_REQUEST = StatusCode.init(400);
pub const STATUS_INTERNAL_SERVER_ERROR = StatusCode.init(500);


// ============================================================================
// Standard Header Names
// ============================================================================

/// Standard HTTP header names
pub const HeaderName = enum {
    accept,
    accept_charset,
    accept_encoding,
    accept_language,
    accept_ranges,
    access_control_allow_credentials,
    access_control_allow_headers,
    access_control_allow_methods,
    access_control_allow_origin,
    access_control_expose_headers,
    access_control_max_age,
    access_control_request_headers,
    access_control_request_method,
    age,
    allow,
    authorization,
    cache_control,
    connection,
    content_disposition,
    content_encoding,
    content_language,
    content_length,
    content_location,
    content_range,
    content_security_policy,
    content_type,
    cookie,
    date,
    etag,
    expect,
    expires,
    forwarded,
    from,
    host,
    if_match,
    if_modified_since,
    if_none_match,
    if_range,
    if_unmodified_since,
    last_modified,
    link,
    location,
    max_forwards,
    origin,
    pragma,
    proxy_authenticate,
    proxy_authorization,
    range,
    referer,
    refresh,
    retry_after,
    sec_websocket_accept,
    sec_websocket_key,
    sec_websocket_protocol,
    sec_websocket_version,
    server,
    set_cookie,
    strict_transport_security,
    te,
    trailer,
    transfer_encoding,
    upgrade,
    user_agent,
    vary,
    via,
    warning,
    www_authenticate,
    x_content_type_options,
    x_frame_options,
    x_xss_protection,

    pub fn asStr(self: HeaderName) []const u8 {
        return switch (self) {
            .accept => "accept",
            .accept_charset => "accept-charset",
            .accept_encoding => "accept-encoding",
            .accept_language => "accept-language",
            .accept_ranges => "accept-ranges",
            .access_control_allow_credentials => "access-control-allow-credentials",
            .access_control_allow_headers => "access-control-allow-headers",
            .access_control_allow_methods => "access-control-allow-methods",
            .access_control_allow_origin => "access-control-allow-origin",
            .access_control_expose_headers => "access-control-expose-headers",
            .access_control_max_age => "access-control-max-age",
            .access_control_request_headers => "access-control-request-headers",
            .access_control_request_method => "access-control-request-method",
            .age => "age",
            .allow => "allow",
            .authorization => "authorization",
            .cache_control => "cache-control",
            .connection => "connection",
            .content_disposition => "content-disposition",
            .content_encoding => "content-encoding",
            .content_language => "content-language",
            .content_length => "content-length",
            .content_location => "content-location",
            .content_range => "content-range",
            .content_security_policy => "content-security-policy",
            .content_type => "content-type",
            .cookie => "cookie",
            .date => "date",
            .etag => "etag",
            .expect => "expect",
            .expires => "expires",
            .forwarded => "forwarded",
            .from => "from",
            .host => "host",
            .if_match => "if-match",
            .if_modified_since => "if-modified-since",
            .if_none_match => "if-none-match",
            .if_range => "if-range",
            .if_unmodified_since => "if-unmodified-since",
            .last_modified => "last-modified",
            .link => "link",
            .location => "location",
            .max_forwards => "max-forwards",
            .origin => "origin",
            .pragma => "pragma",
            .proxy_authenticate => "proxy-authenticate",
            .proxy_authorization => "proxy-authorization",
            .range => "range",
            .referer => "referer",
            .refresh => "refresh",
            .retry_after => "retry-after",
            .sec_websocket_accept => "sec-websocket-accept",
            .sec_websocket_key => "sec-websocket-key",
            .sec_websocket_protocol => "sec-websocket-protocol",
            .sec_websocket_version => "sec-websocket-version",
            .server => "server",
            .set_cookie => "set-cookie",
            .strict_transport_security => "strict-transport-security",
            .te => "te",
            .trailer => "trailer",
            .transfer_encoding => "transfer-encoding",
            .upgrade => "upgrade",
            .user_agent => "user-agent",
            .vary => "vary",
            .via => "via",
            .warning => "warning",
            .www_authenticate => "www-authenticate",
            .x_content_type_options => "x-content-type-options",
            .x_frame_options => "x-frame-options",
            .x_xss_protection => "x-xss-protection",
        };
    }

    /// Get the title case representation of this header
    pub fn titleCase(self: HeaderName) []const u8 {
        return switch (self) {
            .accept => "Accept",
            .accept_charset => "Accept-Charset",
            .accept_encoding => "Accept-Encoding",
            .accept_language => "Accept-Language",
            .cache_control => "Cache-Control",
            .connection => "Connection",
            .content_encoding => "Content-Encoding",
            .content_length => "Content-Length",
            .content_type => "Content-Type",
            .cookie => "Cookie",
            .date => "Date",
            .host => "Host",
            .server => "Server",
            .set_cookie => "Set-Cookie",
            .transfer_encoding => "Transfer-Encoding",
            .user_agent => "User-Agent",
            else => self.asStr(),
        };
    }
};


// ============================================================================
// CaseHeaderName - Preserves original case of header name
// ============================================================================

/// A header name that preserves the original case.
/// HTTP headers are case-insensitive, but we preserve case for transparency.
pub const CaseHeaderName = struct {
    /// The original bytes of the header name (with original case)
    bytes: []const u8,
    /// Whether we own the memory
    owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    /// Create from a slice (borrowed, not owned)
    pub fn fromSlice(name: []const u8) Self {
        return .{
            .bytes = name,
            .owned = false,
            .allocator = null,
        };
    }

    /// Create from a slice (owned copy)
    pub fn fromSliceOwned(allocator: Allocator, name: []const u8) !Self {
        const copy = try allocator.dupe(u8, name);
        return .{
            .bytes = copy,
            .owned = true,
            .allocator = allocator,
        };
    }

    /// Create from a standard header name
    pub fn fromHeaderName(name: HeaderName) Self {
        return .{
            .bytes = name.titleCase(),
            .owned = false,
            .allocator = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.bytes);
            }
        }
    }

    pub fn asSlice(self: *const Self) []const u8 {
        return self.bytes;
    }

    /// Compare case-insensitively with another header name
    pub fn eqlIgnoreCase(self: *const Self, other: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.bytes, other);
    }
};

// ============================================================================
// Header - Single header key-value pair
// ============================================================================

/// A single HTTP header with case-preserved name
pub const Header = struct {
    name: CaseHeaderName,
    value: []const u8,
    value_owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    pub fn init(name: CaseHeaderName, value: []const u8) Self {
        return .{
            .name = name,
            .value = value,
            .value_owned = false,
            .allocator = null,
        };
    }

    pub fn initOwned(allocator: Allocator, name: []const u8, value: []const u8) !Self {
        var case_name = try CaseHeaderName.fromSliceOwned(allocator, name);
        errdefer case_name.deinit();

        const value_copy = try allocator.dupe(u8, value);

        return .{
            .name = case_name,
            .value = value_copy,
            .value_owned = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.name.deinit();
        if (self.value_owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.value);
            }
        }
    }
};

// ============================================================================
// Headers - Collection of HTTP headers
// ============================================================================

/// A collection of HTTP headers that preserves case and order
pub const Headers = struct {
    headers: std.ArrayListUnmanaged(Header),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .headers = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.headers.items) |*header| {
            header.deinit();
        }
        self.headers.deinit(self.allocator);
    }

    /// Get the number of headers
    pub fn len(self: *const Self) usize {
        return self.headers.items.len;
    }

    /// Append a header (does not check for duplicates)
    pub fn append(self: *Self, name: []const u8, value: []const u8) !void {
        const header = try Header.initOwned(self.allocator, name, value);
        try self.headers.append(self.allocator, header);
    }

    /// Append a header with a standard header name
    pub fn appendStd(self: *Self, name: HeaderName, value: []const u8) !void {
        const case_name = CaseHeaderName.fromHeaderName(name);
        const value_copy = try self.allocator.dupe(u8, value);
        const header = Header{
            .name = case_name,
            .value = value_copy,
            .value_owned = true,
            .allocator = self.allocator,
        };
        try self.headers.append(self.allocator, header);
    }

    /// Insert or replace a header (replaces first occurrence, removes others)
    pub fn insert(self: *Self, name: []const u8, value: []const u8) !void {
        var found = false;
        var i: usize = 0;
        while (i < self.headers.items.len) {
            if (self.headers.items[i].name.eqlIgnoreCase(name)) {
                if (!found) {
                    // Update first occurrence
                    var old = self.headers.items[i];
                    old.deinit();
                    self.headers.items[i] = try Header.initOwned(self.allocator, name, value);
                    found = true;
                    i += 1;
                } else {
                    // Remove subsequent occurrences
                    var removed = self.headers.orderedRemove(i);
                    removed.deinit();
                }
            } else {
                i += 1;
            }
        }

        if (!found) {
            try self.append(name, value);
        }
    }

    /// Get the first value for a header name (case-insensitive)
    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| {
            if (header.name.eqlIgnoreCase(name)) {
                return header.value;
            }
        }
        return null;
    }

    /// Get the first value for a standard header name
    pub fn getStd(self: *const Self, name: HeaderName) ?[]const u8 {
        return self.get(name.asStr());
    }

    /// Get all values for a header name (case-insensitive)
    pub fn getAll(self: *const Self, allocator: Allocator, name: []const u8) ![][]const u8 {
        var list: std.ArrayListUnmanaged([]const u8) = .{};
        defer list.deinit(allocator);

        for (self.headers.items) |header| {
            if (header.name.eqlIgnoreCase(name)) {
                try list.append(allocator, header.value);
            }
        }

        return try list.toOwnedSlice(allocator);
    }

    /// Remove all headers with the given name (case-insensitive)
    pub fn remove(self: *Self, name: []const u8) usize {
        var removed_count: usize = 0;
        var i: usize = 0;
        while (i < self.headers.items.len) {
            if (self.headers.items[i].name.eqlIgnoreCase(name)) {
                var removed = self.headers.orderedRemove(i);
                removed.deinit();
                removed_count += 1;
            } else {
                i += 1;
            }
        }
        return removed_count;
    }

    /// Check if a header exists
    pub fn contains(self: *const Self, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Iterate over all headers
    pub fn iterator(self: *const Self) []const Header {
        return self.headers.items;
    }

    /// Write headers to a buffer in HTTP/1.1 format
    pub fn writeHttp1(self: *const Self, writer: anytype) !void {
        for (self.headers.items) |header| {
            try writer.writeAll(header.name.asSlice());
            try writer.writeAll(": ");
            try writer.writeAll(header.value);
            try writer.writeAll("\r\n");
        }
    }
};


// ============================================================================
// URI - Request URI
// ============================================================================

/// Zero-copy parsed URI components - avoids memory allocation by storing slices into original string
/// This is the high-performance variant for cases where the original string outlives the URI
pub const ZeroCopyUri = struct {
    raw: []const u8,
    scheme: ?[]const u8,
    authority: ?[]const u8,
    path: []const u8,
    query: ?[]const u8,

    const Self = @This();

    /// Parse a URI without any memory allocation - zero-copy
    /// The caller must ensure `raw` outlives the returned ZeroCopyUri
    pub fn parse(raw: []const u8) Self {
        var scheme: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var path: []const u8 = raw;
        var query: ?[]const u8 = null;

        var remaining = raw;

        // Check for scheme (e.g., "http://")
        if (std.mem.indexOf(u8, remaining, "://")) |scheme_end| {
            scheme = remaining[0..scheme_end];
            remaining = remaining[scheme_end + 3 ..];

            // Find authority (host:port)
            if (std.mem.indexOfScalar(u8, remaining, '/')) |path_start| {
                authority = remaining[0..path_start];
                remaining = remaining[path_start..];
            } else {
                authority = remaining;
                // No path after authority - use "/" as default
                path = "/";
                // No query possible without path
                return .{
                    .raw = raw,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path,
                    .query = null,
                };
            }
        }

        // Separate path and query
        if (std.mem.indexOfScalar(u8, remaining, '?')) |query_start| {
            path = remaining[0..query_start];
            query = remaining[query_start + 1 ..];
        } else {
            path = remaining;
        }

        return .{
            .raw = raw,
            .scheme = scheme,
            .authority = authority,
            .path = path,
            .query = query,
        };
    }

    /// No-op deinit for API compatibility - zero-copy means no cleanup needed
    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Get path and query string combined
    pub fn pathAndQuery(self: *const Self) []const u8 {
        if (self.query) |_| {
            // Return from path start to end of query
            const path_ptr = @intFromPtr(self.path.ptr);
            const raw_ptr = @intFromPtr(self.raw.ptr);
            const path_offset = path_ptr - raw_ptr;
            return self.raw[path_offset..];
        }
        return self.path;
    }

    /// Extract the host (without port) from the authority - zero-copy
    pub fn host(self: *const Self) ?[]const u8 {
        const auth = self.authority orelse return null;
        // Check for IPv6 address format [host]:port
        if (std.mem.indexOfScalar(u8, auth, '[')) |bracket_start| {
            if (std.mem.indexOfScalar(u8, auth, ']')) |bracket_end| {
                // IPv6: return content between brackets
                return auth[bracket_start + 1 .. bracket_end];
            }
        }
        // Regular host:port or just host
        if (std.mem.lastIndexOfScalar(u8, auth, ':')) |colon_pos| {
            return auth[0..colon_pos];
        }
        return auth;
    }

    /// Extract the port from the authority, or return default based on scheme
    pub fn port(self: *const Self) u16 {
        if (self.authority) |auth| {
            // Check for IPv6 address format [host]:port
            if (std.mem.indexOfScalar(u8, auth, ']')) |bracket_end| {
                // Port comes after ]:
                if (bracket_end + 1 < auth.len and auth[bracket_end + 1] == ':') {
                    const port_str = auth[bracket_end + 2 ..];
                    return std.fmt.parseInt(u16, port_str, 10) catch self.defaultPort();
                }
                return self.defaultPort();
            }
            // Regular host:port
            if (std.mem.lastIndexOfScalar(u8, auth, ':')) |colon_pos| {
                const port_str = auth[colon_pos + 1 ..];
                return std.fmt.parseInt(u16, port_str, 10) catch self.defaultPort();
            }
        }
        return self.defaultPort();
    }

    /// Get the default port based on the scheme
    fn defaultPort(self: *const Self) u16 {
        if (self.scheme) |s| {
            if (std.mem.eql(u8, s, "https")) return 443;
            if (std.mem.eql(u8, s, "http")) return 80;
            if (std.mem.eql(u8, s, "ws")) return 80;
            if (std.mem.eql(u8, s, "wss")) return 443;
        }
        return 80;
    }

    /// Convert to owned Uri (allocates memory)
    pub fn toOwned(self: *const Self, allocator: Allocator) !Uri {
        return Uri.parse(allocator, self.raw);
    }
};

/// Parsed URI components (allocating version)
pub const Uri = struct {
    raw: []const u8,
    scheme: ?[]const u8,
    authority: ?[]const u8,
    path: []const u8,
    query: ?[]const u8,
    owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    /// Parse a URI with memory allocation (copies the input string)
    pub fn parse(allocator: Allocator, raw: []const u8) !Self {
        const raw_copy = try allocator.dupe(u8, raw);
        errdefer allocator.free(raw_copy);

        // Use zero-copy parser on the copied data
        const zc = ZeroCopyUri.parse(raw_copy);

        // The zc slices already point into raw_copy, so use them directly
        // Exception: path "/" literal for authority-only URIs
        return .{
            .raw = raw_copy,
            .scheme = zc.scheme,
            .authority = zc.authority,
            .path = zc.path,
            .query = zc.query,
            .owned = true,
            .allocator = allocator,
        };
    }

    /// Create a Uri from a zero-copy parse result (takes ownership of raw string)
    pub fn fromZeroCopy(allocator: Allocator, raw: []const u8) !Self {
        const raw_copy = try allocator.dupe(u8, raw);
        const zc = ZeroCopyUri.parse(raw_copy);

        // The zc slices already point into raw_copy, so use them directly
        return .{
            .raw = raw_copy,
            .scheme = zc.scheme,
            .authority = zc.authority,
            .path = zc.path,
            .query = zc.query,
            .owned = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.raw);
            }
        }
    }

    pub fn pathAndQuery(self: *const Self) []const u8 {
        if (self.query) |_| {
            // Return from path start to end of query
            const path_ptr = @intFromPtr(self.path.ptr);
            const raw_ptr = @intFromPtr(self.raw.ptr);
            const path_offset = path_ptr - raw_ptr;
            return self.raw[path_offset..];
        }
        return self.path;
    }

    /// Extract the host (without port) from the authority
    pub fn host(self: *const Self) ?[]const u8 {
        const auth = self.authority orelse return null;
        // Check for IPv6 address format [host]:port
        if (std.mem.indexOfScalar(u8, auth, '[')) |bracket_start| {
            if (std.mem.indexOfScalar(u8, auth, ']')) |bracket_end| {
                // IPv6: return content between brackets
                return auth[bracket_start + 1 .. bracket_end];
            }
        }
        // Regular host:port or just host
        if (std.mem.lastIndexOfScalar(u8, auth, ':')) |colon_pos| {
            return auth[0..colon_pos];
        }
        return auth;
    }

    /// Extract the port from the authority, or return default based on scheme
    pub fn port(self: *const Self) u16 {
        if (self.authority) |auth| {
            // Check for IPv6 address format [host]:port
            if (std.mem.indexOfScalar(u8, auth, ']')) |bracket_end| {
                // Port comes after ]:
                if (bracket_end + 1 < auth.len and auth[bracket_end + 1] == ':') {
                    const port_str = auth[bracket_end + 2 ..];
                    return std.fmt.parseInt(u16, port_str, 10) catch self.defaultPort();
                }
                return self.defaultPort();
            }
            // Regular host:port
            if (std.mem.lastIndexOfScalar(u8, auth, ':')) |colon_pos| {
                const port_str = auth[colon_pos + 1 ..];
                return std.fmt.parseInt(u16, port_str, 10) catch self.defaultPort();
            }
        }
        return self.defaultPort();
    }

    /// Get the default port based on the scheme
    fn defaultPort(self: *const Self) u16 {
        if (self.scheme) |s| {
            if (std.mem.eql(u8, s, "https")) return 443;
            if (std.mem.eql(u8, s, "http")) return 80;
            if (std.mem.eql(u8, s, "ws")) return 80;
            if (std.mem.eql(u8, s, "wss")) return 443;
        }
        return 80;
    }
};

// ============================================================================
// RequestHeader
// ============================================================================

/// HTTP request header
pub const RequestHeader = struct {
    method: Method,
    uri: Uri,
    version: Version,
    headers: Headers,
    send_end_stream: bool,
    allocator: Allocator,

    const Self = @This();

    /// Build a new request header
    pub fn build(allocator: Allocator, method: Method, uri_str: []const u8, version: ?Version) !Self {
        const uri = try Uri.parse(allocator, uri_str);
        return .{
            .method = method,
            .uri = uri,
            .version = version orelse .http_1_1,
            .headers = Headers.init(allocator),
            .send_end_stream = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.uri.deinit();
        self.headers.deinit();
    }

    /// Append a header
    pub fn appendHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.append(name, value);
    }

    /// Insert or replace a header
    pub fn insertHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.insert(name, value);
    }

    /// Remove a header
    pub fn removeHeader(self: *Self, name: []const u8) usize {
        return self.headers.remove(name);
    }

    /// Set the HTTP version
    pub fn setVersion(self: *Self, version: Version) void {
        self.version = version;
    }

    /// Set the URI
    pub fn setUri(self: *Self, uri_str: []const u8) !void {
        self.uri.deinit();
        self.uri = try Uri.parse(self.allocator, uri_str);
    }

    /// Get the raw path
    pub fn rawPath(self: *const Self) []const u8 {
        return self.uri.path;
    }

    /// Set whether we send END_STREAM on H2 request HEADERS if body is empty
    pub fn setSendEndStream(self: *Self, send_end_stream: bool) void {
        self.send_end_stream = send_end_stream;
    }

    /// Returns if we support sending END_STREAM on H2 request HEADERS
    pub fn sendEndStream(self: *const Self) ?bool {
        if (self.version != .http_2) {
            return null;
        }
        return self.send_end_stream;
    }

    /// Write the request line and headers to a buffer
    pub fn writeHttp1(self: *const Self, writer: anytype) !void {
        // Request line: METHOD PATH VERSION
        try writer.writeAll(self.method.asStr());
        try writer.writeAll(" ");
        try writer.writeAll(self.uri.pathAndQuery());
        try writer.writeAll(" ");
        try writer.writeAll(self.version.asStr());
        try writer.writeAll("\r\n");

        // Headers
        try self.headers.writeHttp1(writer);
        try writer.writeAll("\r\n");
    }
};

// ============================================================================
// ResponseHeader
// ============================================================================

/// HTTP response header
pub const ResponseHeader = struct {
    status: StatusCode,
    version: Version,
    headers: Headers,
    reason_phrase: ?[]const u8,
    reason_owned: bool,
    allocator: Allocator,

    const Self = @This();

    /// Create a new response header with optional status code
    pub fn init(allocator: Allocator, status: ?u16) Self {
        return .{
            .status = StatusCode.init(status orelse 200),
            .version = .http_1_1,
            .headers = Headers.init(allocator),
            .reason_phrase = null,
            .reason_owned = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        if (self.reason_owned) {
            if (self.reason_phrase) |phrase| {
                self.allocator.free(phrase);
            }
        }
    }

    /// Append a header
    pub fn appendHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.append(name, value);
    }

    /// Insert or replace a header
    pub fn insertHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.insert(name, value);
    }

    /// Set the status code
    pub fn setStatus(self: *Self, status: u16) void {
        self.status = StatusCode.init(status);
    }

    /// Set the HTTP version
    pub fn setVersion(self: *Self, version: Version) void {
        self.version = version;
    }

    /// Set a custom reason phrase
    pub fn setReasonPhrase(self: *Self, phrase: ?[]const u8) !void {
        // Clean up old phrase if owned
        if (self.reason_owned) {
            if (self.reason_phrase) |old| {
                self.allocator.free(old);
            }
        }

        if (phrase) |p| {
            // Check if it's the canonical reason
            if (self.status.canonicalReason()) |canonical| {
                if (std.mem.eql(u8, p, canonical)) {
                    self.reason_phrase = null;
                    self.reason_owned = false;
                    return;
                }
            }
            self.reason_phrase = try self.allocator.dupe(u8, p);
            self.reason_owned = true;
        } else {
            self.reason_phrase = null;
            self.reason_owned = false;
        }
    }

    /// Get the reason phrase
    pub fn getReasonPhrase(self: *const Self) ?[]const u8 {
        if (self.reason_phrase) |phrase| {
            return phrase;
        }
        return self.status.canonicalReason();
    }

    /// Set the Content-Length header
    pub fn setContentLength(self: *Self, len: usize) !void {
        var buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&buf, "{d}", .{len}) catch unreachable;
        try self.insertHeader("Content-Length", len_str);
    }

    /// Write the status line and headers to a buffer
    pub fn writeHttp1(self: *const Self, writer: anytype) !void {
        // Status line: VERSION STATUS REASON
        try writer.writeAll(self.version.asStr());
        try writer.writeAll(" ");
        var status_buf: [3]u8 = undefined;
        _ = std.fmt.bufPrint(&status_buf, "{d}", .{self.status.code}) catch unreachable;
        try writer.writeAll(&status_buf);
        try writer.writeAll(" ");
        if (self.getReasonPhrase()) |reason| {
            try writer.writeAll(reason);
        }
        try writer.writeAll("\r\n");

        // Headers
        try self.headers.writeHttp1(writer);
        try writer.writeAll("\r\n");
    }
};


// ============================================================================
// Tests
// ============================================================================

test "Version asStr and fromStr" {
    try testing.expectEqualStrings("HTTP/1.1", Version.http_1_1.asStr());
    try testing.expectEqualStrings("HTTP/2.0", Version.http_2.asStr());

    try testing.expectEqual(Version.fromStr("HTTP/1.1"), .http_1_1);
    try testing.expectEqual(Version.fromStr("HTTP/2.0"), .http_2);
    try testing.expectEqual(Version.fromStr("invalid"), null);
}

test "Method asStr and fromStr" {
    try testing.expectEqualStrings("GET", Method.GET.asStr());
    try testing.expectEqualStrings("POST", Method.POST.asStr());

    try testing.expectEqual(Method.fromStr("GET"), .GET);
    try testing.expectEqual(Method.fromStr("POST"), .POST);
    try testing.expectEqual(Method.fromStr("INVALID"), null);
}

test "StatusCode canonicalReason" {
    const ok = StatusCode.init(200);
    try testing.expectEqualStrings("OK", ok.canonicalReason().?);

    const not_found = StatusCode.init(404);
    try testing.expectEqualStrings("Not Found", not_found.canonicalReason().?);

    const custom = StatusCode.init(999);
    try testing.expect(custom.canonicalReason() == null);
}

test "StatusCode categories" {
    try testing.expect(StatusCode.init(100).isInformational());
    try testing.expect(StatusCode.init(200).isSuccess());
    try testing.expect(StatusCode.init(301).isRedirection());
    try testing.expect(StatusCode.init(404).isClientError());
    try testing.expect(StatusCode.init(500).isServerError());
}

test "CaseHeaderName preserves case" {
    const name = CaseHeaderName.fromSlice("Content-Type");
    try testing.expectEqualStrings("Content-Type", name.asSlice());

    // Case-insensitive comparison
    try testing.expect(name.eqlIgnoreCase("content-type"));
    try testing.expect(name.eqlIgnoreCase("CONTENT-TYPE"));
}

test "CaseHeaderName from standard header" {
    const name = CaseHeaderName.fromHeaderName(.content_type);
    try testing.expectEqualStrings("Content-Type", name.asSlice());
}

test "Headers append and get" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("Content-Type", "application/json");
    try headers.append("X-Custom", "value1");

    try testing.expectEqualStrings("application/json", headers.get("content-type").?);
    try testing.expectEqualStrings("value1", headers.get("X-CUSTOM").?);
    try testing.expect(headers.get("nonexistent") == null);
}

test "Headers insert replaces" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("Content-Type", "text/plain");
    try headers.insert("Content-Type", "application/json");

    try testing.expectEqualStrings("application/json", headers.get("content-type").?);
    try testing.expectEqual(headers.len(), 1);
}

test "Headers remove" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("X-Custom", "value1");
    try headers.append("X-Custom", "value2");
    try headers.append("Other", "value");

    const removed = headers.remove("x-custom");
    try testing.expectEqual(removed, 2);
    try testing.expectEqual(headers.len(), 1);
}

test "Headers getAll" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "a=1");
    try headers.append("Set-Cookie", "b=2");
    try headers.append("Other", "value");

    const cookies = try headers.getAll(testing.allocator, "set-cookie");
    defer testing.allocator.free(cookies);

    try testing.expectEqual(cookies.len, 2);
    try testing.expectEqualStrings("a=1", cookies[0]);
    try testing.expectEqualStrings("b=2", cookies[1]);
}

test "Headers writeHttp1" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("Content-Type", "text/html");
    try headers.append("Content-Length", "100");

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try headers.writeHttp1(stream.writer());

    const written = stream.getWritten();
    try testing.expect(std.mem.indexOf(u8, written, "Content-Type: text/html\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, written, "Content-Length: 100\r\n") != null);
}

test "Uri parse simple path" {
    var uri = try Uri.parse(testing.allocator, "/path/to/resource");
    defer uri.deinit();

    try testing.expect(uri.scheme == null);
    try testing.expect(uri.authority == null);
    try testing.expectEqualStrings("/path/to/resource", uri.path);
    try testing.expect(uri.query == null);
}

test "Uri parse with query" {
    var uri = try Uri.parse(testing.allocator, "/search?q=test&page=1");
    defer uri.deinit();

    try testing.expectEqualStrings("/search", uri.path);
    try testing.expectEqualStrings("q=test&page=1", uri.query.?);
}

test "Uri parse full url" {
    var uri = try Uri.parse(testing.allocator, "http://example.com/path?query=1");
    defer uri.deinit();

    try testing.expectEqualStrings("http", uri.scheme.?);
    try testing.expectEqualStrings("example.com", uri.authority.?);
    try testing.expectEqualStrings("/path", uri.path);
    try testing.expectEqualStrings("query=1", uri.query.?);
}

test "RequestHeader build and write" {
    var req = try RequestHeader.build(testing.allocator, .GET, "/index.html", null);
    defer req.deinit();

    try req.appendHeader("Host", "example.com");
    try req.appendHeader("User-Agent", "test");

    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try req.writeHttp1(stream.writer());

    const written = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, written, "GET /index.html HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, written, "Host: example.com\r\n") != null);
}

test "RequestHeader setVersion" {
    var req = try RequestHeader.build(testing.allocator, .GET, "/", null);
    defer req.deinit();

    try testing.expectEqual(req.version, .http_1_1);

    req.setVersion(.http_2);
    try testing.expectEqual(req.version, .http_2);
}

test "RequestHeader sendEndStream for H2" {
    var req = try RequestHeader.build(testing.allocator, .GET, "/", .http_2);
    defer req.deinit();

    // Default is true for H2
    try testing.expect(req.sendEndStream().?);

    req.setSendEndStream(false);
    try testing.expect(!req.sendEndStream().?);
}

test "RequestHeader sendEndStream for H1" {
    var req = try RequestHeader.build(testing.allocator, .GET, "/", .http_1_1);
    defer req.deinit();

    // Should be null for non-H2
    try testing.expect(req.sendEndStream() == null);
}

test "ResponseHeader init and status" {
    var resp = ResponseHeader.init(testing.allocator, null);
    defer resp.deinit();

    try testing.expectEqual(resp.status.code, 200);

    resp.setStatus(404);
    try testing.expectEqual(resp.status.code, 404);
}

test "ResponseHeader setContentLength" {
    var resp = ResponseHeader.init(testing.allocator, null);
    defer resp.deinit();

    try resp.setContentLength(1234);
    try testing.expectEqualStrings("1234", resp.headers.get("Content-Length").?);
}

test "ResponseHeader reasonPhrase" {
    var resp = ResponseHeader.init(testing.allocator, 200);
    defer resp.deinit();

    // Default reason
    try testing.expectEqualStrings("OK", resp.getReasonPhrase().?);

    // Custom reason
    try resp.setReasonPhrase("All Good");
    try testing.expectEqualStrings("All Good", resp.getReasonPhrase().?);

    // Reset to default
    try resp.setReasonPhrase(null);
    try testing.expectEqualStrings("OK", resp.getReasonPhrase().?);
}

test "ResponseHeader writeHttp1" {
    var resp = ResponseHeader.init(testing.allocator, 200);
    defer resp.deinit();

    try resp.appendHeader("Content-Type", "text/html");
    try resp.setContentLength(100);

    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try resp.writeHttp1(stream.writer());

    const written = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, written, "Content-Type: text/html\r\n") != null);
}

test "HeaderName titleCase" {
    try testing.expectEqualStrings("Content-Type", HeaderName.content_type.titleCase());
    try testing.expectEqualStrings("User-Agent", HeaderName.user_agent.titleCase());
    try testing.expectEqualStrings("Set-Cookie", HeaderName.set_cookie.titleCase());
}

test "Headers appendStd" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.appendStd(.content_type, "application/json");
    try testing.expectEqualStrings("application/json", headers.getStd(.content_type).?);
}

// Additional edge case tests from Pingora

test "Headers case preservation" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    // Test that original case is preserved
    try headers.append("FoO", "Bar");
    try headers.append("fOO", "bar");
    try headers.append("BAZ", "baR");

    // Case-insensitive lookup should work
    try testing.expectEqualStrings("Bar", headers.get("foo").?);

    // All values should be retrievable
    const all_foo = try headers.getAll(testing.allocator, "foo");
    defer testing.allocator.free(all_foo);
    try testing.expectEqual(all_foo.len, 2);
}

test "Headers insert replaces all occurrences" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("X-Custom", "value1");
    try headers.append("X-Custom", "value2");
    try headers.append("X-Custom", "value3");

    try testing.expectEqual(headers.len(), 3);

    // Insert should replace first and remove others
    try headers.insert("x-custom", "new-value");

    try testing.expectEqual(headers.len(), 1);
    try testing.expectEqualStrings("new-value", headers.get("X-Custom").?);
}

test "RequestHeader with query string" {
    var req = try RequestHeader.build(testing.allocator, .GET, "/search?q=test&page=1", null);
    defer req.deinit();

    try testing.expectEqualStrings("/search", req.uri.path);
    try testing.expectEqualStrings("q=test&page=1", req.uri.query.?);
}

test "ResponseHeader custom reason phrase" {
    var resp = ResponseHeader.init(testing.allocator, 200);
    defer resp.deinit();

    try resp.setReasonPhrase("All Good");
    try testing.expectEqualStrings("All Good", resp.getReasonPhrase().?);

    // Setting canonical reason should clear custom
    try resp.setReasonPhrase("OK");
    try testing.expect(resp.reason_phrase == null);
    try testing.expectEqualStrings("OK", resp.getReasonPhrase().?);
}

test "StatusCode edge cases" {
    // Test boundary status codes
    try testing.expect(StatusCode.init(99).canonicalReason() == null);
    try testing.expect(StatusCode.init(100).isInformational());
    try testing.expect(StatusCode.init(199).isInformational());
    try testing.expect(StatusCode.init(200).isSuccess());
    try testing.expect(StatusCode.init(299).isSuccess());
    try testing.expect(StatusCode.init(300).isRedirection());
    try testing.expect(StatusCode.init(399).isRedirection());
    try testing.expect(StatusCode.init(400).isClientError());
    try testing.expect(StatusCode.init(499).isClientError());
    try testing.expect(StatusCode.init(500).isServerError());
    try testing.expect(StatusCode.init(599).isServerError());
}

test "Headers empty value" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.append("X-Empty", "");
    try testing.expectEqualStrings("", headers.get("X-Empty").?);
}

test "Uri pathAndQuery reconstruction" {
    var uri = try Uri.parse(testing.allocator, "/path?a=1&b=2");
    defer uri.deinit();

    const pq = uri.pathAndQuery();
    try testing.expectEqualStrings("/path?a=1&b=2", pq);
}

test "Uri port parsing with explicit port" {
    var uri = try Uri.parse(testing.allocator, "http://example.com:8080/path");
    defer uri.deinit();

    try testing.expectEqualStrings("example.com", uri.host().?);
    try testing.expectEqual(@as(u16, 8080), uri.port());
}

test "Uri port parsing with default http port" {
    var uri = try Uri.parse(testing.allocator, "http://example.com/path");
    defer uri.deinit();

    try testing.expectEqualStrings("example.com", uri.host().?);
    try testing.expectEqual(@as(u16, 80), uri.port());
}

test "Uri port parsing with default https port" {
    var uri = try Uri.parse(testing.allocator, "https://secure.example.com/path");
    defer uri.deinit();

    try testing.expectEqualStrings("secure.example.com", uri.host().?);
    try testing.expectEqual(@as(u16, 443), uri.port());
}

test "Uri port parsing with IPv6 address" {
    var uri = try Uri.parse(testing.allocator, "http://[::1]:9000/path");
    defer uri.deinit();

    try testing.expectEqualStrings("::1", uri.host().?);
    try testing.expectEqual(@as(u16, 9000), uri.port());
}

test "Uri port parsing with IPv6 no port" {
    var uri = try Uri.parse(testing.allocator, "http://[2001:db8::1]/path");
    defer uri.deinit();

    try testing.expectEqualStrings("2001:db8::1", uri.host().?);
    try testing.expectEqual(@as(u16, 80), uri.port());
}

test "Uri host and port for websocket" {
    var uri = try Uri.parse(testing.allocator, "wss://ws.example.com/socket");
    defer uri.deinit();

    try testing.expectEqualStrings("ws.example.com", uri.host().?);
    try testing.expectEqual(@as(u16, 443), uri.port());
}

// ============================================================================
// ZeroCopyUri Tests - Zero-allocation URI parsing
// ============================================================================

test "ZeroCopyUri parse simple path - zero allocation" {
    const raw = "/path/to/resource";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit(); // No-op but API compatible

    try testing.expect(uri.scheme == null);
    try testing.expect(uri.authority == null);
    try testing.expectEqualStrings("/path/to/resource", uri.path);
    try testing.expect(uri.query == null);
    // Verify zero-copy: pointers should be into original string
    try testing.expect(uri.path.ptr == raw.ptr);
}

test "ZeroCopyUri parse with query - zero allocation" {
    const raw = "/search?q=test&page=1";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    try testing.expectEqualStrings("/search", uri.path);
    try testing.expectEqualStrings("q=test&page=1", uri.query.?);
    // Verify zero-copy
    try testing.expect(uri.path.ptr == raw.ptr);
}

test "ZeroCopyUri parse full url - zero allocation" {
    const raw = "http://example.com/path?query=1";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    try testing.expectEqualStrings("http", uri.scheme.?);
    try testing.expectEqualStrings("example.com", uri.authority.?);
    try testing.expectEqualStrings("/path", uri.path);
    try testing.expectEqualStrings("query=1", uri.query.?);
}

test "ZeroCopyUri pathAndQuery" {
    const raw = "/path?a=1&b=2";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    const pq = uri.pathAndQuery();
    try testing.expectEqualStrings("/path?a=1&b=2", pq);
}

test "ZeroCopyUri host extraction" {
    const raw = "http://example.com:8080/path";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    try testing.expectEqualStrings("example.com", uri.host().?);
    try testing.expectEqual(@as(u16, 8080), uri.port());
}

test "ZeroCopyUri IPv6 host and port" {
    const raw = "http://[::1]:9000/path";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    try testing.expectEqualStrings("::1", uri.host().?);
    try testing.expectEqual(@as(u16, 9000), uri.port());
}

test "ZeroCopyUri default port by scheme" {
    const https_raw = "https://secure.example.com/path";
    var https_uri = ZeroCopyUri.parse(https_raw);
    defer https_uri.deinit();
    try testing.expectEqual(@as(u16, 443), https_uri.port());

    const http_raw = "http://example.com/path";
    var http_uri = ZeroCopyUri.parse(http_raw);
    defer http_uri.deinit();
    try testing.expectEqual(@as(u16, 80), http_uri.port());

    const wss_raw = "wss://ws.example.com/socket";
    var wss_uri = ZeroCopyUri.parse(wss_raw);
    defer wss_uri.deinit();
    try testing.expectEqual(@as(u16, 443), wss_uri.port());
}

test "ZeroCopyUri authority only (no path)" {
    const raw = "http://example.com";
    var uri = ZeroCopyUri.parse(raw);
    defer uri.deinit();

    try testing.expectEqualStrings("http", uri.scheme.?);
    try testing.expectEqualStrings("example.com", uri.authority.?);
    try testing.expectEqualStrings("/", uri.path);
    try testing.expect(uri.query == null);
}

test "ZeroCopyUri toOwned conversion" {
    const raw = "http://example.com/path?query=1";
    var zc_uri = ZeroCopyUri.parse(raw);
    defer zc_uri.deinit();

    var owned_uri = try zc_uri.toOwned(testing.allocator);
    defer owned_uri.deinit();

    try testing.expectEqualStrings("http", owned_uri.scheme.?);
    try testing.expectEqualStrings("example.com", owned_uri.authority.?);
    try testing.expectEqualStrings("/path", owned_uri.path);
    try testing.expectEqualStrings("query=1", owned_uri.query.?);
}

