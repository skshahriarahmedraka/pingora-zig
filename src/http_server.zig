//! HTTP/1.1 Server
//!
//! This module provides an HTTP/1.1 server for handling incoming requests.
//! It supports keep-alive connections, chunked transfer encoding, and
//! provides hooks for request handling.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-core/src/protocols/http/v1

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const http = @import("http.zig");
const http_parser = @import("http_parser.zig");
const protocols = @import("protocols.zig");

// ============================================================================
// HTTP Server Configuration
// ============================================================================

/// Configuration for the HTTP server
pub const HttpServerConfig = struct {
    /// Read timeout in milliseconds
    read_timeout_ms: u32 = 60000,
    /// Write timeout in milliseconds
    write_timeout_ms: u32 = 30000,
    /// Maximum request header size
    max_header_size: usize = 64 * 1024,
    /// Maximum request body size (0 = unlimited)
    max_body_size: usize = 10 * 1024 * 1024, // 10MB default
    /// Whether to enable HTTP keep-alive
    keep_alive: bool = true,
    /// Maximum requests per connection (0 = unlimited)
    max_requests_per_conn: usize = 1000,
    /// Server name for Server header
    server_name: ?[]const u8 = "pingora-zig",
    /// TCP options
    tcp_options: protocols.TcpOptions = .{},
};

// ============================================================================
// HTTP Server Error
// ============================================================================

pub const HttpServerError = error{
    ConnectionClosed,
    RequestParseError,
    RequestTooLarge,
    HeaderTooLarge,
    BodyTooLarge,
    Timeout,
    InvalidRequest,
    OutOfMemory,
};

// ============================================================================
// HTTP Request (Server-side)
// ============================================================================

/// An incoming HTTP request
pub const HttpRequest = struct {
    /// Request method
    method: http.Method,
    /// Request path
    path: []const u8,
    /// Query string (if any)
    query: ?[]const u8,
    /// HTTP version
    version: http.Version,
    /// Request headers
    headers: std.StringHashMapUnmanaged([]const u8),
    /// Request body (if any)
    body: ?[]const u8,
    /// Raw path (original)
    raw_path: []const u8,
    /// Allocator used
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .method = .GET,
            .path = "/",
            .query = null,
            .version = .http_1_1,
            .headers = .{},
            .body = null,
            .raw_path = "/",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit(self.allocator);

        if (self.body) |body| {
            self.allocator.free(body);
        }
    }

    /// Get a header value (case-insensitive)
    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
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

    /// Check if request is chunked
    pub fn isChunked(self: *const Self) bool {
        if (self.getHeader("transfer-encoding")) |te| {
            return std.mem.indexOf(u8, te, "chunked") != null;
        }
        return false;
    }

    /// Check if keep-alive is requested
    pub fn isKeepAlive(self: *const Self) bool {
        if (self.getHeader("connection")) |conn| {
            if (std.ascii.indexOfIgnoreCase(conn, "close")) |_| {
                return false;
            }
            if (std.ascii.indexOfIgnoreCase(conn, "keep-alive")) |_| {
                return true;
            }
        }
        // HTTP/1.1 defaults to keep-alive
        return self.version == .http_1_1;
    }

    /// Get the Host header
    pub fn getHost(self: *const Self) ?[]const u8 {
        return self.getHeader("host");
    }
};

// ============================================================================
// HTTP Server Session (Single connection)
// ============================================================================

/// An HTTP server session representing a single client connection
pub const HttpServerSession = struct {
    stream: protocols.TcpStream,
    config: HttpServerConfig,
    read_buffer: []u8,
    read_pos: usize,
    read_len: usize,
    allocator: Allocator,
    requests_handled: usize,
    keep_alive: bool,

    const Self = @This();
    const READ_BUFFER_SIZE = 8192;

    /// Create a new server session from an accepted connection
    pub fn init(allocator: Allocator, stream: protocols.TcpStream, config: HttpServerConfig) !Self {
        const read_buffer = try allocator.alloc(u8, READ_BUFFER_SIZE);

        return .{
            .stream = stream,
            .config = config,
            .read_buffer = read_buffer,
            .read_pos = 0,
            .read_len = 0,
            .allocator = allocator,
            .requests_handled = 0,
            .keep_alive = config.keep_alive,
        };
    }

    /// Close the session
    pub fn close(self: *Self) void {
        self.stream.close();
        self.allocator.free(self.read_buffer);
    }

    /// Check if session should continue (keep-alive)
    pub fn shouldContinue(self: *const Self) bool {
        if (!self.keep_alive) return false;
        if (self.config.max_requests_per_conn > 0 and
            self.requests_handled >= self.config.max_requests_per_conn)
        {
            return false;
        }
        return true;
    }

    /// Read the next HTTP request
    pub fn readRequest(self: *Self) !HttpRequest {
        var request = HttpRequest.init(self.allocator);
        errdefer request.deinit();

        // Read and parse headers
        var header_buf: [64 * 1024]u8 = undefined;
        var header_len: usize = 0;

        while (header_len < header_buf.len) {
            const bytes_read = try self.readSome();
            if (bytes_read == 0 and header_len == 0) {
                return HttpServerError.ConnectionClosed;
            }
            if (bytes_read == 0) {
                return HttpServerError.RequestParseError;
            }

            const copy_len = @min(self.read_len - self.read_pos, header_buf.len - header_len);
            @memcpy(header_buf[header_len..][0..copy_len], self.read_buffer[self.read_pos..][0..copy_len]);
            header_len += copy_len;

            var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
            if (http_parser.parseRequestFull(header_buf[0..header_len], &headers_buf)) |parsed| {
                // Parse method
                request.method = http.Method.fromStr(parsed.method) orelse .GET;
                request.raw_path = try self.allocator.dupe(u8, parsed.path);
                request.version = if (parsed.version == 1) .http_1_1 else .http_1_0;

                // Parse path and query
                if (std.mem.indexOf(u8, parsed.path, "?")) |query_start| {
                    request.path = request.raw_path[0..query_start];
                    request.query = request.raw_path[query_start + 1 ..];
                } else {
                    request.path = request.raw_path;
                }

                // Copy headers
                for (parsed.headers) |h| {
                    var lower_name: [256]u8 = undefined;
                    const ln = std.ascii.lowerString(&lower_name, h.name);
                    const name = try self.allocator.dupe(u8, ln[0..h.name.len]);
                    const value = try self.allocator.dupe(u8, h.value);
                    try request.headers.put(self.allocator, name, value);
                }

                // Update keep-alive state
                self.keep_alive = request.isKeepAlive() and self.config.keep_alive;

                // Consume parsed bytes
                self.read_pos += parsed.bytes_consumed;

                // Read body if present
                if (http_parser.findContentLength(parsed.headers)) |content_length| {
                    if (self.config.max_body_size > 0 and content_length > self.config.max_body_size) {
                        return HttpServerError.BodyTooLarge;
                    }
                    if (content_length > 0) {
                        request.body = try self.readExactBody(content_length);
                    }
                } else if (http_parser.isChunkedEncoding(parsed.headers)) {
                    request.body = try self.readChunkedBody();
                }

                self.requests_handled += 1;
                return request;
            } else |err| {
                return err;
            }
        }

        return HttpServerError.HeaderTooLarge;
    }

    /// Send an HTTP response
    pub fn sendResponse(self: *Self, status: u16, headers: ?*const http.Headers, body: ?[]const u8) !void {
        // Status line
        try self.stream.writeAll("HTTP/1.1 ");
        var status_buf: [3]u8 = undefined;
        _ = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch unreachable;
        try self.stream.writeAll(&status_buf);
        try self.stream.writeAll(" ");

        const reason = http.StatusCode.init(status).canonicalReason() orelse "Unknown";
        try self.stream.writeAll(reason);
        try self.stream.writeAll("\r\n");

        // Server header
        if (self.config.server_name) |name| {
            try self.stream.writeAll("Server: ");
            try self.stream.writeAll(name);
            try self.stream.writeAll("\r\n");
        }

        // Connection header
        if (self.keep_alive) {
            try self.stream.writeAll("Connection: keep-alive\r\n");
        } else {
            try self.stream.writeAll("Connection: close\r\n");
        }

        // Custom headers
        if (headers) |h| {
            for (h.headers.items) |header| {
                try self.stream.writeAll(header.name.bytes);
                try self.stream.writeAll(": ");
                try self.stream.writeAll(header.value);
                try self.stream.writeAll("\r\n");
            }
        }

        // Content-Length
        if (body) |b| {
            var len_buf: [20]u8 = undefined;
            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{b.len}) catch unreachable;
            try self.stream.writeAll("Content-Length: ");
            try self.stream.writeAll(len_str);
            try self.stream.writeAll("\r\n");
        } else {
            try self.stream.writeAll("Content-Length: 0\r\n");
        }

        // End of headers
        try self.stream.writeAll("\r\n");

        // Body
        if (body) |b| {
            try self.stream.writeAll(b);
        }
    }

    /// Send a simple response with body
    pub fn sendSimpleResponse(self: *Self, status: u16, content_type: []const u8, body: []const u8) !void {
        var headers = http.Headers.init(self.allocator);
        defer headers.deinit();

        try headers.append("Content-Type", content_type);
        try self.sendResponse(status, &headers, body);
    }

    /// Send a redirect response
    pub fn sendRedirect(self: *Self, status: u16, location: []const u8) !void {
        var headers = http.Headers.init(self.allocator);
        defer headers.deinit();

        try headers.append("Location", location);
        try self.sendResponse(status, &headers, null);
    }

    /// Send an error response
    pub fn sendError(self: *Self, status: u16, message: []const u8) !void {
        try self.sendSimpleResponse(status, "text/plain", message);
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

        const buffered = self.read_len - self.read_pos;
        if (buffered > 0) {
            const copy_len = @min(buffered, length);
            @memcpy(body[0..copy_len], self.read_buffer[self.read_pos..][0..copy_len]);
            self.read_pos += copy_len;
            total_read = copy_len;
        }

        while (total_read < length) {
            const n = try self.stream.read(body[total_read..]);
            if (n == 0) {
                return HttpServerError.ConnectionClosed;
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

                    if (chunk_header_len >= 2 and
                        chunk_header[chunk_header_len - 2] == '\r' and
                        chunk_header[chunk_header_len - 1] == '\n')
                    {
                        break;
                    }
                }
            }

            const parsed = try http_parser.parseChunkHeader(chunk_header[0..chunk_header_len]);
            if (parsed) |chunk| {
                if (chunk.size == 0) {
                    _ = try self.readExactBody(2);
                    break;
                }

                const chunk_data = try self.readExactBody(chunk.size);
                defer self.allocator.free(chunk_data);
                try body.appendSlice(self.allocator, chunk_data);

                _ = try self.readExactBody(2);
            } else {
                return HttpServerError.RequestParseError;
            }
        }

        return body.toOwnedSlice(self.allocator);
    }

    /// Get connection info
    pub fn getConnectionInfo(self: *const Self) protocols.ConnectionInfo {
        return protocols.ConnectionInfo.fromTcpStream(&self.stream);
    }

    /// Get peer address
    pub fn getPeerAddress(self: *const Self) net.Address {
        return self.stream.getPeerAddress();
    }
};

// ============================================================================
// Request Handler Type
// ============================================================================

/// Function type for handling requests
pub const RequestHandler = *const fn (*HttpServerSession, *HttpRequest) anyerror!void;

// ============================================================================
// Simple HTTP Server
// ============================================================================

/// A simple HTTP server that accepts connections and handles requests
pub const HttpServer = struct {
    listener: protocols.TcpListener,
    config: HttpServerConfig,
    allocator: Allocator,

    const Self = @This();

    /// Create a new HTTP server bound to an address
    pub fn bind(allocator: Allocator, address: net.Address, config: HttpServerConfig) !Self {
        const listener = try protocols.TcpListener.bind(allocator, address, config.tcp_options);

        return .{
            .listener = listener,
            .config = config,
            .allocator = allocator,
        };
    }

    /// Create a new HTTP server bound to host:port
    pub fn bindHostPort(allocator: Allocator, host: []const u8, port: u16, config: HttpServerConfig) !Self {
        const address = try protocols.parseAddress(host, port);
        return bind(allocator, address, config);
    }

    /// Close the server
    pub fn close(self: *Self) void {
        self.listener.close();
    }

    /// Accept and handle a single connection
    pub fn acceptAndHandle(self: *Self, handler: RequestHandler) !void {
        const stream = try self.listener.accept();
        var session = try HttpServerSession.init(self.allocator, stream, self.config);
        defer session.close();

        while (session.shouldContinue()) {
            var request = session.readRequest() catch |err| {
                if (err == HttpServerError.ConnectionClosed) break;
                try session.sendError(400, "Bad Request");
                break;
            };
            defer request.deinit();

            handler(&session, &request) catch |err| {
                std.debug.print("Handler error: {}\n", .{err});
                session.sendError(500, "Internal Server Error") catch {};
                break;
            };
        }
    }

    /// Get the local address the server is bound to
    pub fn getLocalAddress(self: *const Self) net.Address {
        return self.listener.getLocalAddress();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HttpServerConfig defaults" {
    const config = HttpServerConfig{};
    try testing.expectEqual(config.read_timeout_ms, 60000);
    try testing.expect(config.keep_alive);
    try testing.expectEqual(config.max_requests_per_conn, 1000);
}

test "HttpRequest init and deinit" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    try testing.expectEqual(request.method, .GET);
    try testing.expectEqualStrings("/", request.path);
}

test "HttpRequest getContentLength" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    const name = try testing.allocator.dupe(u8, "content-length");
    const value = try testing.allocator.dupe(u8, "1234");
    try request.headers.put(testing.allocator, name, value);

    try testing.expectEqual(request.getContentLength(), 1234);
}

test "HttpRequest isChunked" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    try testing.expect(!request.isChunked());

    const name = try testing.allocator.dupe(u8, "transfer-encoding");
    const value = try testing.allocator.dupe(u8, "chunked");
    try request.headers.put(testing.allocator, name, value);

    try testing.expect(request.isChunked());
}

test "HttpRequest isKeepAlive defaults" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    // HTTP/1.1 defaults to keep-alive
    request.version = .http_1_1;
    try testing.expect(request.isKeepAlive());

    // HTTP/1.0 defaults to close
    request.version = .http_1_0;
    try testing.expect(!request.isKeepAlive());
}

test "HttpRequest isKeepAlive with header" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    request.version = .http_1_1;

    const name = try testing.allocator.dupe(u8, "connection");
    const value = try testing.allocator.dupe(u8, "close");
    try request.headers.put(testing.allocator, name, value);

    try testing.expect(!request.isKeepAlive());
}

test "HttpServerConfig with custom values" {
    const config = HttpServerConfig{
        .read_timeout_ms = 5000,
        .keep_alive = false,
        .server_name = "CustomServer/1.0",
        .max_body_size = 1024,
    };

    try testing.expectEqual(config.read_timeout_ms, 5000);
    try testing.expect(!config.keep_alive);
    try testing.expectEqualStrings("CustomServer/1.0", config.server_name.?);
}

test "HttpRequest getHost" {
    var request = HttpRequest.init(testing.allocator);
    defer request.deinit();

    try testing.expect(request.getHost() == null);

    const name = try testing.allocator.dupe(u8, "host");
    const value = try testing.allocator.dupe(u8, "example.com");
    try request.headers.put(testing.allocator, name, value);

    try testing.expectEqualStrings("example.com", request.getHost().?);
}
