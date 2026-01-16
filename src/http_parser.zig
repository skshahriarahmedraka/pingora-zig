//! HTTP/1.1 Parser
//!
//! A zero-copy HTTP/1.1 parser that parses requests and responses from byte buffers.
//! Similar to the `httparse` crate used by Pingora.
//!
//! Features:
//! - Zero-copy parsing - returns slices into the original buffer
//! - Incremental parsing - can handle partial data
//! - Supports both requests and responses
//!
//! Ported from concepts in: https://github.com/cloudflare/pingora/tree/main/pingora-core

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const http = @import("http.zig");

/// Maximum number of headers to parse
pub const MAX_HEADERS: usize = 100;

/// Maximum header size (64KB)
pub const MAX_HEADER_SIZE: usize = 64 * 1024;

// ============================================================================
// Parse Status
// ============================================================================

/// Result of a parse operation
pub const ParseStatus = union(enum) {
    /// Parsing is complete, contains the number of bytes consumed
    complete: usize,
    /// Need more data to complete parsing
    partial,
};

/// Parse error types
pub const ParseError = error{
    /// Invalid HTTP token (method, header name, etc.)
    InvalidToken,
    /// Invalid HTTP version
    InvalidVersion,
    /// Invalid status code
    InvalidStatus,
    /// Invalid header name
    InvalidHeaderName,
    /// Invalid header value
    InvalidHeaderValue,
    /// Too many headers
    TooManyHeaders,
    /// Header too large
    HeaderTooLarge,
    /// Invalid request line
    InvalidRequestLine,
    /// Invalid status line
    InvalidStatusLine,
    /// Invalid chunk size
    InvalidChunkSize,
    /// Unexpected end of input
    UnexpectedEof,
};

// ============================================================================
// Header Reference (zero-copy)
// ============================================================================

/// A parsed header with references into the original buffer
pub const HeaderRef = struct {
    /// Header name as a slice into the buffer
    name: []const u8,
    /// Header value as a slice into the buffer
    value: []const u8,
};

// ============================================================================
// Request Parser
// ============================================================================

/// Parsed HTTP request (zero-copy references into buffer)
pub const ParsedRequest = struct {
    /// HTTP method
    method: []const u8,
    /// Request path/URI
    path: []const u8,
    /// HTTP version (0 for 1.0, 1 for 1.1)
    version: u8,
    /// Parsed headers
    headers: []HeaderRef,
    /// Number of bytes consumed
    bytes_consumed: usize,
};

/// Parse an HTTP/1.x request from a buffer
/// Returns ParseStatus.partial if more data is needed
pub fn parseRequest(buf: []const u8, headers_buf: []HeaderRef) ParseError!ParseStatus {
    if (buf.len == 0) return .partial;

    // Find end of request line
    const request_line_end = findLineEnd(buf) orelse return .partial;

    // Parse request line: METHOD PATH VERSION\r\n
    const request_line = buf[0..request_line_end];
    _ = try parseRequestLine(request_line); // Validate request line

    // Parse headers
    var pos = request_line_end + 2; // skip \r\n
    var header_count: usize = 0;

    while (pos < buf.len) {
        // Check for end of headers (\r\n)
        if (buf.len >= pos + 2 and buf[pos] == '\r' and buf[pos + 1] == '\n') {
            // End of headers
            return .{ .complete = pos + 2 };
        }

        // Find end of this header line
        const line_end = findLineEnd(buf[pos..]) orelse return .partial;

        // Parse header
        const header_line = buf[pos .. pos + line_end];
        const header = try parseHeaderLine(header_line);

        if (header_count >= headers_buf.len) {
            return ParseError.TooManyHeaders;
        }
        headers_buf[header_count] = header;
        header_count += 1;

        pos += line_end + 2; // skip \r\n
    }

    return .partial;
}

/// Parse request into a ParsedRequest struct
pub fn parseRequestFull(buf: []const u8, headers_buf: []HeaderRef) ParseError!?ParsedRequest {
    if (buf.len == 0) return null;

    // Find end of request line
    const request_line_end = findLineEnd(buf) orelse return null;

    // Parse request line
    const request_line = buf[0..request_line_end];
    const parsed_line = try parseRequestLine(request_line);

    // Parse headers
    var pos = request_line_end + 2;
    var header_count: usize = 0;

    while (pos < buf.len) {
        if (buf.len >= pos + 2 and buf[pos] == '\r' and buf[pos + 1] == '\n') {
            return ParsedRequest{
                .method = parsed_line.method,
                .path = parsed_line.path,
                .version = parsed_line.version,
                .headers = headers_buf[0..header_count],
                .bytes_consumed = pos + 2,
            };
        }

        const line_end = findLineEnd(buf[pos..]) orelse return null;
        const header_line = buf[pos .. pos + line_end];
        const header = try parseHeaderLine(header_line);

        if (header_count >= headers_buf.len) {
            return ParseError.TooManyHeaders;
        }
        headers_buf[header_count] = header;
        header_count += 1;

        pos += line_end + 2;
    }

    return null;
}

// ============================================================================
// Response Parser
// ============================================================================

/// Parsed HTTP response (zero-copy references into buffer)
pub const ParsedResponse = struct {
    /// HTTP version (0 for 1.0, 1 for 1.1)
    version: u8,
    /// Status code
    status_code: u16,
    /// Reason phrase
    reason: []const u8,
    /// Parsed headers
    headers: []HeaderRef,
    /// Number of bytes consumed
    bytes_consumed: usize,
};

/// Parse an HTTP/1.x response from a buffer
pub fn parseResponse(buf: []const u8, headers_buf: []HeaderRef) ParseError!ParseStatus {
    if (buf.len == 0) return .partial;

    // Find end of status line
    const status_line_end = findLineEnd(buf) orelse return .partial;

    // Parse status line: VERSION STATUS REASON\r\n
    const status_line = buf[0..status_line_end];
    _ = try parseStatusLine(status_line);

    // Parse headers
    var pos = status_line_end + 2;
    var header_count: usize = 0;

    while (pos < buf.len) {
        if (buf.len >= pos + 2 and buf[pos] == '\r' and buf[pos + 1] == '\n') {
            return .{ .complete = pos + 2 };
        }

        const line_end = findLineEnd(buf[pos..]) orelse return .partial;
        const header_line = buf[pos .. pos + line_end];
        const header = try parseHeaderLine(header_line);

        if (header_count >= headers_buf.len) {
            return ParseError.TooManyHeaders;
        }
        headers_buf[header_count] = header;
        header_count += 1;

        pos += line_end + 2;
    }

    return .partial;
}

/// Parse response into a ParsedResponse struct
pub fn parseResponseFull(buf: []const u8, headers_buf: []HeaderRef) ParseError!?ParsedResponse {
    if (buf.len == 0) return null;

    const status_line_end = findLineEnd(buf) orelse return null;
    const status_line = buf[0..status_line_end];
    const parsed_status = try parseStatusLine(status_line);

    var pos = status_line_end + 2;
    var header_count: usize = 0;

    while (pos < buf.len) {
        if (buf.len >= pos + 2 and buf[pos] == '\r' and buf[pos + 1] == '\n') {
            return ParsedResponse{
                .version = parsed_status.version,
                .status_code = parsed_status.status_code,
                .reason = parsed_status.reason,
                .headers = headers_buf[0..header_count],
                .bytes_consumed = pos + 2,
            };
        }

        const line_end = findLineEnd(buf[pos..]) orelse return null;
        const header_line = buf[pos .. pos + line_end];
        const header = try parseHeaderLine(header_line);

        if (header_count >= headers_buf.len) {
            return ParseError.TooManyHeaders;
        }
        headers_buf[header_count] = header;
        header_count += 1;

        pos += line_end + 2;
    }

    return null;
}

// ============================================================================
// Chunked Transfer Encoding Parser
// ============================================================================

/// Result of parsing a chunk header
pub const ChunkHeader = struct {
    /// Size of the chunk (0 indicates last chunk)
    size: usize,
    /// Bytes consumed (chunk header line including \r\n)
    bytes_consumed: usize,
};

/// Parse a chunk header (size in hex followed by optional extensions)
pub fn parseChunkHeader(buf: []const u8) ParseError!?ChunkHeader {
    const line_end = findLineEnd(buf) orelse return null;
    const line = buf[0..line_end];

    // Find size (before any extension separator ';')
    var size_end: usize = 0;
    for (line, 0..) |c, i| {
        if (c == ';' or c == ' ') break;
        size_end = i + 1;
    }

    if (size_end == 0) return ParseError.InvalidChunkSize;

    const size_str = line[0..size_end];
    const size = std.fmt.parseInt(usize, size_str, 16) catch return ParseError.InvalidChunkSize;

    return ChunkHeader{
        .size = size,
        .bytes_consumed = line_end + 2,
    };
}

// ============================================================================
// Internal Parsing Helpers
// ============================================================================

const RequestLine = struct {
    method: []const u8,
    path: []const u8,
    version: u8,
};

fn parseRequestLine(line: []const u8) ParseError!RequestLine {
    // Find method (first space)
    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse return ParseError.InvalidRequestLine;
    if (method_end == 0) return ParseError.InvalidToken;

    const method = line[0..method_end];
    var rest = line[method_end + 1 ..];

    // Validate method (only alphanumeric)
    for (method) |c| {
        if (!std.ascii.isAlphanumeric(c)) return ParseError.InvalidToken;
    }

    // Find path (second space, searching from end for VERSION)
    const path_end = std.mem.lastIndexOfScalar(u8, rest, ' ') orelse return ParseError.InvalidRequestLine;
    if (path_end == 0) return ParseError.InvalidRequestLine;

    const path = rest[0..path_end];
    const version_str = rest[path_end + 1 ..];

    // Parse version
    const version = try parseVersion(version_str);

    return RequestLine{
        .method = method,
        .path = path,
        .version = version,
    };
}

const StatusLine = struct {
    version: u8,
    status_code: u16,
    reason: []const u8,
};

fn parseStatusLine(line: []const u8) ParseError!StatusLine {
    // Find version (first space)
    const version_end = std.mem.indexOfScalar(u8, line, ' ') orelse return ParseError.InvalidStatusLine;
    const version_str = line[0..version_end];
    const version = try parseVersion(version_str);

    var rest = line[version_end + 1 ..];

    // Find status code (next space)
    const status_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    if (status_end < 3) return ParseError.InvalidStatus;

    const status_str = rest[0..status_end];
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch return ParseError.InvalidStatus;

    if (status_code < 100 or status_code > 999) return ParseError.InvalidStatus;

    const reason = if (status_end < rest.len) rest[status_end + 1 ..] else "";

    return StatusLine{
        .version = version,
        .status_code = status_code,
        .reason = reason,
    };
}

fn parseHeaderLine(line: []const u8) ParseError!HeaderRef {
    // Find colon separator
    const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse return ParseError.InvalidHeaderName;

    if (colon_pos == 0) return ParseError.InvalidHeaderName;

    const name = line[0..colon_pos];

    // Validate header name (token characters)
    for (name) |c| {
        if (!isTokenChar(c)) return ParseError.InvalidHeaderName;
    }

    // Value is everything after colon, trimmed of leading/trailing whitespace
    var value = line[colon_pos + 1 ..];
    value = std.mem.trim(u8, value, " \t");

    return HeaderRef{
        .name = name,
        .value = value,
    };
}

fn parseVersion(version_str: []const u8) ParseError!u8 {
    if (std.mem.eql(u8, version_str, "HTTP/1.0")) return 0;
    if (std.mem.eql(u8, version_str, "HTTP/1.1")) return 1;
    if (std.mem.eql(u8, version_str, "HTTP/2.0") or std.mem.eql(u8, version_str, "HTTP/2")) return 2;
    return ParseError.InvalidVersion;
}

fn findLineEnd(buf: []const u8) ?usize {
    // Look for \r\n
    var i: usize = 0;
    while (i + 1 < buf.len) : (i += 1) {
        if (buf[i] == '\r' and buf[i + 1] == '\n') {
            return i;
        }
    }
    return null;
}

fn isTokenChar(c: u8) bool {
    // HTTP token characters (RFC 7230)
    return switch (c) {
        '!' => true,
        '#' => true,
        '$' => true,
        '%' => true,
        '&' => true,
        '\'' => true,
        '*' => true,
        '+' => true,
        '-' => true,
        '.' => true,
        '^' => true,
        '_' => true,
        '`' => true,
        '|' => true,
        '~' => true,
        '0'...'9' => true,
        'A'...'Z' => true,
        'a'...'z' => true,
        else => false,
    };
}

// ============================================================================
// Content-Length and Transfer-Encoding helpers
// ============================================================================

/// Find Content-Length header value from parsed headers
pub fn findContentLength(headers: []const HeaderRef) ?usize {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            return std.fmt.parseInt(usize, h.value, 10) catch null;
        }
    }
    return null;
}

/// Check if Transfer-Encoding: chunked is present
pub fn isChunkedEncoding(headers: []const HeaderRef) bool {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) {
            // Check if "chunked" is in the value (could be a list)
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |part| {
                const trimmed = std.mem.trim(u8, part, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "chunked")) {
                    return true;
                }
            }
        }
    }
    return false;
}

/// Check if Connection: close is present
pub fn isConnectionClose(headers: []const HeaderRef) bool {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |part| {
                const trimmed = std.mem.trim(u8, part, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "close")) {
                    return true;
                }
            }
        }
    }
    return false;
}

/// Check if Connection: keep-alive is present
pub fn isKeepAlive(headers: []const HeaderRef) bool {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |part| {
                const trimmed = std.mem.trim(u8, part, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "keep-alive")) {
                    return true;
                }
            }
        }
    }
    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "parseRequest simple GET" {
    const request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = try parseRequest(request, &headers);
    try testing.expect(result == .complete);
    try testing.expectEqual(result.complete, request.len);
}

test "parseRequest partial" {
    const partial = "GET /index.html HTTP/1.1\r\nHost: exam";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = try parseRequest(partial, &headers);
    try testing.expect(result == .partial);
}

test "parseRequestFull simple GET" {
    const request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);

    const req = parsed.?;
    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/index.html", req.path);
    try testing.expectEqual(req.version, 1); // HTTP/1.1
    try testing.expectEqual(req.headers.len, 2);
    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
}

test "parseRequestFull POST with path" {
    const request = "POST /api/users?id=123 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);

    const req = parsed.?;
    try testing.expectEqualStrings("POST", req.method);
    try testing.expectEqualStrings("/api/users?id=123", req.path);
}

test "parseRequestFull HTTP/1.0" {
    const request = "GET / HTTP/1.0\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqual(parsed.?.version, 0);
}

test "parseRequest invalid method" {
    const request = "G@T / HTTP/1.1\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = parseRequestFull(request, &headers);
    try testing.expectError(ParseError.InvalidToken, result);
}

test "parseRequest invalid version" {
    const request = "GET / HTTP/9.9\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = parseRequestFull(request, &headers);
    try testing.expectError(ParseError.InvalidVersion, result);
}

test "parseResponse simple 200" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = try parseResponse(response, &headers);
    try testing.expect(result == .complete);
}

test "parseResponseFull 200 OK" {
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseResponseFull(response, &headers);
    try testing.expect(parsed != null);

    const resp = parsed.?;
    try testing.expectEqual(resp.version, 1);
    try testing.expectEqual(resp.status_code, 200);
    try testing.expectEqualStrings("OK", resp.reason);
    try testing.expectEqual(resp.headers.len, 2);
}

test "parseResponseFull 404 Not Found" {
    const response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseResponseFull(response, &headers);
    try testing.expect(parsed != null);

    try testing.expectEqual(parsed.?.status_code, 404);
    try testing.expectEqualStrings("Not Found", parsed.?.reason);
}

test "parseResponseFull no reason phrase" {
    const response = "HTTP/1.1 204\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseResponseFull(response, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqual(parsed.?.status_code, 204);
    try testing.expectEqualStrings("", parsed.?.reason);
}

test "parseChunkHeader" {
    const chunk = "1a\r\n";
    const header = try parseChunkHeader(chunk);

    try testing.expect(header != null);
    try testing.expectEqual(header.?.size, 0x1a);
    try testing.expectEqual(header.?.bytes_consumed, 4);
}

test "parseChunkHeader with extension" {
    const chunk = "ff;ext=value\r\n";
    const header = try parseChunkHeader(chunk);

    try testing.expect(header != null);
    try testing.expectEqual(header.?.size, 0xff);
}

test "parseChunkHeader zero (last chunk)" {
    const chunk = "0\r\n";
    const header = try parseChunkHeader(chunk);

    try testing.expect(header != null);
    try testing.expectEqual(header.?.size, 0);
}

test "findContentLength" {
    var headers = [_]HeaderRef{
        .{ .name = "Content-Type", .value = "text/html" },
        .{ .name = "Content-Length", .value = "1234" },
    };

    try testing.expectEqual(findContentLength(&headers), 1234);
}

test "findContentLength missing" {
    var headers = [_]HeaderRef{
        .{ .name = "Content-Type", .value = "text/html" },
    };

    try testing.expect(findContentLength(&headers) == null);
}

test "isChunkedEncoding" {
    var headers = [_]HeaderRef{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    };

    try testing.expect(isChunkedEncoding(&headers));
}

test "isChunkedEncoding in list" {
    var headers = [_]HeaderRef{
        .{ .name = "Transfer-Encoding", .value = "gzip, chunked" },
    };

    try testing.expect(isChunkedEncoding(&headers));
}

test "isChunkedEncoding not present" {
    var headers = [_]HeaderRef{
        .{ .name = "Transfer-Encoding", .value = "gzip" },
    };

    try testing.expect(!isChunkedEncoding(&headers));
}

test "isConnectionClose" {
    var headers = [_]HeaderRef{
        .{ .name = "Connection", .value = "close" },
    };

    try testing.expect(isConnectionClose(&headers));
}

test "isKeepAlive" {
    var headers = [_]HeaderRef{
        .{ .name = "Connection", .value = "keep-alive" },
    };

    try testing.expect(isKeepAlive(&headers));
}

test "parseRequest multiple headers" {
    const request = "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: Mozilla/5.0\r\n" ++
        "Accept: text/html\r\n" ++
        "Accept-Language: en-US\r\n" ++
        "Accept-Encoding: gzip, deflate\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqual(parsed.?.headers.len, 6);
}

test "parseRequest header with whitespace" {
    const request = "GET / HTTP/1.1\r\nX-Custom:   spaced value   \r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqualStrings("spaced value", parsed.?.headers[0].value);
}

test "parseResponse partial data" {
    const partial = "HTTP/1.1 200 OK\r\nContent-Length";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const result = try parseResponse(partial, &headers);
    try testing.expect(result == .partial);
}

test "bytes consumed correctly" {
    const full = "GET / HTTP/1.1\r\nHost: test\r\n\r\nBODY DATA HERE";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(full, &headers);
    try testing.expect(parsed != null);

    // Body should start after headers
    const body_start = parsed.?.bytes_consumed;
    try testing.expectEqualStrings("BODY DATA HERE", full[body_start..]);
}

// Additional tests from Pingora

test "check duplicate content-length" {
    var headers = [_]HeaderRef{
        .{ .name = "Content-Length", .value = "100" },
    };
    // Single content-length is fine
    try testing.expectEqual(findContentLength(&headers), 100);

    var dup_headers = [_]HeaderRef{
        .{ .name = "Content-Length", .value = "100" },
        .{ .name = "Content-Length", .value = "200" },
    };
    // First one wins in our implementation
    try testing.expectEqual(findContentLength(&dup_headers), 100);
}

test "is upgrade response detection" {
    // HTTP/1.1 101 with upgrade header
    const upgrade_headers = [_]HeaderRef{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "upgrade" },
    };
    
    // Check connection header contains upgrade
    var has_upgrade = false;
    for (upgrade_headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
            if (std.mem.indexOf(u8, h.value, "upgrade") != null) {
                has_upgrade = true;
            }
        }
    }
    try testing.expect(has_upgrade);
}

test "transfer encoding with content-length" {
    // When both Transfer-Encoding and Content-Length present
    var headers = [_]HeaderRef{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Content-Length", .value = "100" },
    };
    
    // Chunked takes precedence
    try testing.expect(isChunkedEncoding(&headers));
    // But content-length is still readable
    try testing.expectEqual(findContentLength(&headers), 100);
}

test "parse response with no reason phrase" {
    const response = "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseResponseFull(response, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqual(parsed.?.status_code, 200);
    try testing.expectEqualStrings("", parsed.?.reason);
}

test "parse request with absolute URI" {
    const request = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers: [MAX_HEADERS]HeaderRef = undefined;

    const parsed = try parseRequestFull(request, &headers);
    try testing.expect(parsed != null);
    try testing.expectEqualStrings("http://example.com/path", parsed.?.path);
}

test "chunk header with large size" {
    const chunk = "ffffffff\r\n";
    const header = try parseChunkHeader(chunk);
    
    try testing.expect(header != null);
    try testing.expectEqual(header.?.size, 0xffffffff);
}

test "multiple connection header values" {
    var headers = [_]HeaderRef{
        .{ .name = "Connection", .value = "keep-alive, upgrade" },
    };
    
    try testing.expect(isKeepAlive(&headers));
}

test "case insensitive header matching" {
    var headers = [_]HeaderRef{
        .{ .name = "CONTENT-LENGTH", .value = "100" },
        .{ .name = "transfer-ENCODING", .value = "CHUNKED" },
    };
    
    try testing.expectEqual(findContentLength(&headers), 100);
    try testing.expect(isChunkedEncoding(&headers));
}
