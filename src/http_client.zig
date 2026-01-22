//! HTTP/1.1 Client
//!
//! This module provides an HTTP/1.1 client for making requests to upstream servers.
//! It supports connection reuse (keep-alive), chunked transfer encoding, and
//! integrates with the connection pool for efficient connection management.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-core/src/protocols/http/v1

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const http = @import("http.zig");
const http_parser = @import("http_parser.zig");
const protocols = @import("protocols.zig");
const pool = @import("pool.zig");

// ============================================================================
// HTTP Client Configuration
// ============================================================================

/// Configuration for the HTTP client
pub const HttpClientConfig = struct {
    /// Connection timeout in milliseconds
    connect_timeout_ms: u32 = 30000,
    /// Read timeout in milliseconds
    read_timeout_ms: u32 = 60000,
    /// Write timeout in milliseconds
    write_timeout_ms: u32 = 30000,
    /// Maximum response header size
    max_header_size: usize = 64 * 1024,
    /// Whether to use HTTP keep-alive
    keep_alive: bool = true,
    /// User-Agent header value
    user_agent: ?[]const u8 = null,
    /// TCP options
    tcp_options: protocols.TcpOptions = .{},
};

// ============================================================================
// HTTP Client Error
// ============================================================================

pub const HttpClientError = error{
    ConnectionFailed,
    RequestFailed,
    ResponseParseError,
    Timeout,
    InvalidResponse,
    TooManyRedirects,
    ConnectionClosed,
    OutOfMemory,
    HeaderTooLarge,
};

// ============================================================================
// HTTP Response (Client-side)
// ============================================================================

/// A complete HTTP response received from a server
pub const HttpResponse = struct {
    /// Response status code
    status_code: u16,
    /// HTTP version
    version: http.Version,
    /// Reason phrase
    reason: []const u8,
    /// Response headers
    headers: std.StringHashMapUnmanaged([]const u8),
    /// Response body (if any)
    body: ?[]const u8,
    /// Whether the connection can be reused
    keep_alive: bool,
    /// Allocator used for this response
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .status_code = 0,
            .version = .http_1_1,
            .reason = "",
            .headers = .{},
            .body = null,
            .keep_alive = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free header storage
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit(self.allocator);

        // Free body
        if (self.body) |body| {
            self.allocator.free(body);
        }
    }

    /// Get a header value (case-insensitive)
    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        // StringHashMap is case-sensitive, so we need to lowercase
        var lower_buf: [256]u8 = undefined;
        const lower_name = std.ascii.lowerString(&lower_buf, name);
        return self.headers.get(lower_name[0..name.len]);
    }

    /// Get Content-Length if present
    pub fn getContentLength(self: *const Self) ?usize {
        if (self.getHeader("content-length")) |cl| {
            return std.fmt.parseInt(usize, cl, 10) catch null;
        }
        return null;
    }

    /// Check if response is chunked
    pub fn isChunked(self: *const Self) bool {
        if (self.getHeader("transfer-encoding")) |te| {
            return std.mem.indexOf(u8, te, "chunked") != null;
        }
        return false;
    }
};

// ============================================================================
// HTTP Session (Single connection)
// ============================================================================

/// An HTTP session representing a single connection to a server
pub const HttpSession = struct {
    stream: protocols.TcpStream,
    config: HttpClientConfig,
    read_buffer: []u8,
    read_pos: usize,
    read_len: usize,
    allocator: Allocator,
    requests_sent: usize,

    const Self = @This();
    const READ_BUFFER_SIZE = 8192;

    /// Create a new HTTP session by connecting to a server
    pub fn connect(allocator: Allocator, address: net.Address, config: HttpClientConfig) !Self {
        var stream = try protocols.TcpStream.connect(address, config.tcp_options);
        errdefer stream.close();

        const read_buffer = try allocator.alloc(u8, READ_BUFFER_SIZE);

        return .{
            .stream = stream,
            .config = config,
            .read_buffer = read_buffer,
            .read_pos = 0,
            .read_len = 0,
            .allocator = allocator,
            .requests_sent = 0,
        };
    }

    /// Create a new HTTP session by connecting to host:port
    pub fn connectHost(allocator: Allocator, host: []const u8, port: u16, config: HttpClientConfig) !Self {
        const address = try protocols.parseAddress(host, port);
        return connect(allocator, address, config);
    }

    /// Close the session
    pub fn close(self: *Self) void {
        self.stream.close();
        self.allocator.free(self.read_buffer);
    }

    /// Send an HTTP request
    pub fn sendRequest(self: *Self, request: *const http.RequestHeader, body: ?[]const u8) !void {
        // Write request line
        try self.stream.writeAll(request.method.asStr());
        try self.stream.writeAll(" ");
        try self.stream.writeAll(request.uri.pathAndQuery());
        try self.stream.writeAll(" ");
        try self.stream.writeAll(request.version.asStr());
        try self.stream.writeAll("\r\n");

        // Write headers
        for (request.headers.headers.items) |h| {
            try self.stream.writeAll(h.name.bytes);
            try self.stream.writeAll(": ");
            try self.stream.writeAll(h.value);
            try self.stream.writeAll("\r\n");
        }

        // Add Content-Length if body present and header not set
        if (body) |b| {
            if (request.headers.get("content-length") == null) {
                var len_buf: [20]u8 = undefined;
                const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{b.len}) catch unreachable;
                try self.stream.writeAll("Content-Length: ");
                try self.stream.writeAll(len_str);
                try self.stream.writeAll("\r\n");
            }
        }

        // End of headers
        try self.stream.writeAll("\r\n");

        // Write body if present
        if (body) |b| {
            try self.stream.writeAll(b);
        }

        self.requests_sent += 1;
    }

    /// Read HTTP response
    pub fn readResponse(self: *Self) !HttpResponse {
        var response = HttpResponse.init(self.allocator);
        errdefer response.deinit();

        // Read and parse headers
        var header_buf: [64 * 1024]u8 = undefined;
        var header_len: usize = 0;

        while (header_len < header_buf.len) {
            // Read more data
            const bytes_read = try self.readSome();
            if (bytes_read == 0) {
                return HttpClientError.ConnectionClosed;
            }

            // Copy to header buffer
            const copy_len = @min(self.read_len - self.read_pos, header_buf.len - header_len);
            @memcpy(header_buf[header_len..][0..copy_len], self.read_buffer[self.read_pos..][0..copy_len]);
            header_len += copy_len;

            // Try to parse response
            var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
            const parse_result = http_parser.parseResponseFull(header_buf[0..header_len], &headers_buf);
            if (parse_result) |parsed_opt| {
                if (parsed_opt) |parsed| {
                    response.status_code = parsed.status_code;
                    response.version = if (parsed.version == 1) .http_1_1 else .http_1_0;
                    response.reason = try self.allocator.dupe(u8, parsed.reason);

                    // Copy headers
                    for (parsed.headers) |h| {
                        // Lowercase header name for consistent lookup
                        var lower_name: [256]u8 = undefined;
                        const ln = std.ascii.lowerString(&lower_name, h.name);
                        const name = try self.allocator.dupe(u8, ln[0..h.name.len]);
                        const value = try self.allocator.dupe(u8, h.value);
                        try response.headers.put(self.allocator, name, value);
                    }

                    // Check keep-alive
                    response.keep_alive = !http_parser.isConnectionClose(parsed.headers);
                    if (response.version == .http_1_0) {
                        response.keep_alive = http_parser.isKeepAlive(parsed.headers);
                    }

                    // Consume parsed bytes
                    self.read_pos += parsed.bytes_consumed;

                    // Read body if present
                    if (http_parser.findContentLength(parsed.headers)) |content_length| {
                        if (content_length > 0) {
                            response.body = try self.readExactBody(content_length);
                        }
                    } else if (http_parser.isChunkedEncoding(parsed.headers)) {
                        response.body = try self.readChunkedBody();
                    }

                    return response;
                }
                // parsed_opt is null - incomplete, continue reading
            } else |err| {
                return err;
            }
        }

        return HttpClientError.HeaderTooLarge;
    }

    /// Read some data into buffer
    fn readSome(self: *Self) !usize {
        if (self.read_pos >= self.read_len) {
            self.read_pos = 0;
            self.read_len = 0;
        }

        if (self.read_len < self.read_buffer.len) {
            const n = try self.stream.read(self.read_buffer[self.read_len..]);
            self.read_len += n;
            return n;
        }

        return 0;
    }

    /// Read exact number of bytes for body
    fn readExactBody(self: *Self, length: usize) ![]u8 {
        var body = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(body);

        var total_read: usize = 0;

        // First, copy any buffered data
        const buffered = self.read_len - self.read_pos;
        if (buffered > 0) {
            const copy_len = @min(buffered, length);
            @memcpy(body[0..copy_len], self.read_buffer[self.read_pos..][0..copy_len]);
            self.read_pos += copy_len;
            total_read = copy_len;
        }

        // Read rest directly
        while (total_read < length) {
            const n = try self.stream.read(body[total_read..]);
            if (n == 0) {
                return HttpClientError.ConnectionClosed;
            }
            total_read += n;
        }

        return body;
    }

    /// Read chunked body
    fn readChunkedBody(self: *Self) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .{};
        errdefer body.deinit(self.allocator);

        while (true) {
            // Read chunk size line
            var chunk_header: [64]u8 = undefined;
            var chunk_header_len: usize = 0;

            while (chunk_header_len < chunk_header.len) {
                if (self.read_pos >= self.read_len) {
                    _ = try self.readSome();
                }

                if (self.read_pos < self.read_len) {
                    const c = self.read_buffer[self.read_pos];
                    chunk_header[chunk_header_len] = c;
                    chunk_header_len += 1;
                    self.read_pos += 1;

                    // Check for end of line
                    if (chunk_header_len >= 2 and
                        chunk_header[chunk_header_len - 2] == '\r' and
                        chunk_header[chunk_header_len - 1] == '\n')
                    {
                        break;
                    }
                }
            }

            // Parse chunk size
            const parsed = try http_parser.parseChunkHeader(chunk_header[0..chunk_header_len]);
            if (parsed) |chunk| {
                if (chunk.size == 0) {
                    // Last chunk - read trailing CRLF
                    const trailing = try self.readExactBody(2);
                    self.allocator.free(trailing);
                    break;
                }

                // Read chunk data
                const chunk_data = try self.readExactBody(chunk.size);
                defer self.allocator.free(chunk_data);
                try body.appendSlice(self.allocator, chunk_data);

                // Read trailing CRLF
                const crlf = try self.readExactBody(2);
                self.allocator.free(crlf);
            } else {
                return HttpClientError.ResponseParseError;
            }
        }

        return try body.toOwnedSlice(self.allocator);
    }

    /// Get connection info
    pub fn getConnectionInfo(self: *const Self) protocols.ConnectionInfo {
        return protocols.ConnectionInfo.fromTcpStream(&self.stream);
    }
};

// ============================================================================
// Simple HTTP Client (with connection pooling)
// ============================================================================

/// A simple HTTP client that manages connections
pub const HttpClient = struct {
    config: HttpClientConfig,
    connection_pool: pool.ConnectionPool(u64, *HttpSession),
    allocator: Allocator,

    const Self = @This();

    /// Create a new HTTP client
    pub fn init(allocator: Allocator, config: HttpClientConfig) Self {
        return .{
            .config = config,
            .connection_pool = pool.ConnectionPool(u64, *HttpSession).init(allocator, 100),
            .allocator = allocator,
        };
    }

    /// Close the client and all pooled connections
    pub fn deinit(self: *Self) void {
        self.connection_pool.drain();
        self.connection_pool.deinit();
    }

    /// Make a GET request
    pub fn get(self: *Self, url: []const u8) !HttpResponse {
        return self.request(.GET, url, null, null);
    }

    /// Make a POST request
    pub fn post(self: *Self, url: []const u8, body: ?[]const u8, content_type: ?[]const u8) !HttpResponse {
        return self.request(.POST, url, body, content_type);
    }

    /// Make a generic request
    pub fn request(
        self: *Self,
        method: http.Method,
        url: []const u8,
        body: ?[]const u8,
        content_type: ?[]const u8,
    ) !HttpResponse {
        // Parse URL to extract host and path
        var uri = try http.Uri.parse(self.allocator, url);
        defer uri.deinit();

        const host = uri.host() orelse return HttpClientError.InvalidResponse;
        const port: u16 = uri.port();

        // Build request
        var req = try http.RequestHeader.build(self.allocator, method, uri.pathAndQuery(), .http_1_1);
        defer req.deinit();

        try req.appendHeader("Host", host);
        if (self.config.user_agent) |ua| {
            try req.appendHeader("User-Agent", ua);
        }
        if (content_type) |ct| {
            try req.appendHeader("Content-Type", ct);
        }
        if (self.config.keep_alive) {
            try req.appendHeader("Connection", "keep-alive");
        }

        // Get or create session
        const pool_key = std.hash.Wyhash.hash(0, host);
        var session: *HttpSession = undefined;
        var reused = false;

        if (self.connection_pool.get(pool_key)) |pooled| {
            session = pooled[0];
            reused = true;
        } else {
            const new_session = try self.allocator.create(HttpSession);
            new_session.* = try HttpSession.connectHost(self.allocator, host, port, self.config);
            session = new_session;
        }

        errdefer if (!reused) {
            session.close();
            self.allocator.destroy(session);
        };

        // Send request and read response
        try session.sendRequest(&req, body);
        const response = try session.readResponse();

        // Return connection to pool if keep-alive
        if (response.keep_alive and self.config.keep_alive) {
            _ = self.connection_pool.put(pool_key, session);
        } else {
            session.close();
            self.allocator.destroy(session);
        }

        return response;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HttpClientConfig defaults" {
    const config = HttpClientConfig{};
    try testing.expectEqual(config.connect_timeout_ms, 30000);
    try testing.expectEqual(config.read_timeout_ms, 60000);
    try testing.expect(config.keep_alive);
}

test "HttpResponse init and deinit" {
    var response = HttpResponse.init(testing.allocator);
    defer response.deinit();

    try testing.expectEqual(response.status_code, 0);
    try testing.expect(response.keep_alive);
}

test "HttpResponse getContentLength" {
    var response = HttpResponse.init(testing.allocator);
    defer response.deinit();

    const name = try testing.allocator.dupe(u8, "content-length");
    const value = try testing.allocator.dupe(u8, "1234");
    try response.headers.put(testing.allocator, name, value);

    try testing.expectEqual(response.getContentLength(), 1234);
}

test "HttpResponse isChunked" {
    var response = HttpResponse.init(testing.allocator);
    defer response.deinit();

    try testing.expect(!response.isChunked());

    const name = try testing.allocator.dupe(u8, "transfer-encoding");
    const value = try testing.allocator.dupe(u8, "chunked");
    try response.headers.put(testing.allocator, name, value);

    try testing.expect(response.isChunked());
}

test "HttpClient init and deinit" {
    var client = HttpClient.init(testing.allocator, .{});
    defer client.deinit();

    try testing.expect(client.config.keep_alive);
}

test "HttpClientConfig with custom values" {
    const config = HttpClientConfig{
        .connect_timeout_ms = 5000,
        .read_timeout_ms = 10000,
        .keep_alive = false,
        .user_agent = "Test/1.0",
    };

    try testing.expectEqual(config.connect_timeout_ms, 5000);
    try testing.expect(!config.keep_alive);
    try testing.expectEqualStrings("Test/1.0", config.user_agent.?);
}
