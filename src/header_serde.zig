//! Header Serialization/Deserialization
//!
//! This module provides efficient serialization and deserialization of HTTP headers.
//! It can serialize headers to a compact binary format and deserialize them back.
//!
//! The format is designed to be:
//! - Compact (smaller than HTTP/1.1 wire format)
//! - Fast to serialize/deserialize
//! - Zero-copy where possible
//!
//! Note: This is a simplified version. The original Pingora uses zstd compression
//! with trained dictionaries for even better compression ratios.
//!
//! Ported from concepts in: https://github.com/cloudflare/pingora/tree/main/pingora-header-serde

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const http = @import("http.zig");

// ============================================================================
// Wire Format Constants
// ============================================================================

/// Magic bytes to identify serialized headers
const MAGIC: [4]u8 = .{ 'P', 'H', 'D', 'R' }; // Pingora HeaDeR

/// Version of the serialization format
const FORMAT_VERSION: u8 = 1;

/// Maximum header name length
const MAX_NAME_LEN: u16 = 256;

/// Maximum header value length
const MAX_VALUE_LEN: u16 = 8192;

// ============================================================================
// Serialization Error
// ============================================================================

pub const SerdeError = error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidFormat,
    HeaderTooLarge,
    BufferTooSmall,
    OutOfMemory,
    InvalidUtf8,
};

// ============================================================================
// HeaderSerde - Main serializer/deserializer
// ============================================================================

/// HTTP Header Serializer/Deserializer
///
/// Provides efficient binary serialization of HTTP response headers.
pub const HeaderSerde = struct {
    allocator: Allocator,
    /// Whether to use compression (placeholder for future zstd support)
    use_compression: bool,

    const Self = @This();

    /// Create a new HeaderSerde instance
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .use_compression = false,
        };
    }

    /// Serialize a ResponseHeader to a byte buffer
    /// Returns owned slice that must be freed by caller
    pub fn serialize(self: *const Self, header: *const http.ResponseHeader) SerdeError![]u8 {
        // Calculate required size
        var size: usize = 0;
        size += MAGIC.len; // Magic
        size += 1; // Version
        size += 2; // Status code
        size += 1; // Version enum
        size += 2; // Header count

        // Headers: each is [name_len:2][value_len:2][name][value]
        for (header.headers.headers.items) |h| {
            size += 2 + 2 + h.name.bytes.len + h.value.len;
        }

        // Allocate buffer
        const buf = self.allocator.alloc(u8, size) catch return SerdeError.OutOfMemory;
        errdefer self.allocator.free(buf);

        // Write magic
        var pos: usize = 0;
        @memcpy(buf[pos .. pos + MAGIC.len], &MAGIC);
        pos += MAGIC.len;

        // Write version
        buf[pos] = FORMAT_VERSION;
        pos += 1;

        // Write status code (big-endian)
        std.mem.writeInt(u16, buf[pos..][0..2], header.status.code, .big);
        pos += 2;

        // Write HTTP version
        buf[pos] = switch (header.version) {
            .http_0_9 => 0,
            .http_1_0 => 1,
            .http_1_1 => 2,
            .http_2 => 3,
            .http_3 => 4,
        };
        pos += 1;

        // Write header count
        const header_count: u16 = @intCast(header.headers.headers.items.len);
        std.mem.writeInt(u16, buf[pos..][0..2], header_count, .big);
        pos += 2;

        // Write headers
        for (header.headers.headers.items) |h| {
            const name_len: u16 = @intCast(h.name.bytes.len);
            const value_len: u16 = @intCast(h.value.len);

            std.mem.writeInt(u16, buf[pos..][0..2], name_len, .big);
            pos += 2;
            std.mem.writeInt(u16, buf[pos..][0..2], value_len, .big);
            pos += 2;

            @memcpy(buf[pos .. pos + name_len], h.name.bytes);
            pos += name_len;
            @memcpy(buf[pos .. pos + value_len], h.value);
            pos += value_len;
        }

        _ = self.use_compression; // Future: apply compression here

        return buf;
    }

    /// Deserialize a byte buffer back to a ResponseHeader
    pub fn deserialize(self: *const Self, data: []const u8) SerdeError!http.ResponseHeader {
        if (data.len < MAGIC.len + 1 + 2 + 1 + 2) {
            return SerdeError.InvalidFormat;
        }

        var pos: usize = 0;

        // Check magic
        if (!std.mem.eql(u8, data[pos .. pos + MAGIC.len], &MAGIC)) {
            return SerdeError.InvalidMagic;
        }
        pos += MAGIC.len;

        // Check version
        const version = data[pos];
        pos += 1;
        if (version != FORMAT_VERSION) {
            return SerdeError.UnsupportedVersion;
        }

        // Read status code
        const status_code = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;

        // Read HTTP version
        const http_version: http.Version = switch (data[pos]) {
            0 => .http_0_9,
            1 => .http_1_0,
            2 => .http_1_1,
            3 => .http_2,
            4 => .http_3,
            else => return SerdeError.InvalidFormat,
        };
        pos += 1;

        // Read header count
        const header_count = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;

        // Create response header
        var response = http.ResponseHeader.init(self.allocator, status_code);
        response.setVersion(http_version);

        // Read headers
        for (0..header_count) |_| {
            if (pos + 4 > data.len) return SerdeError.InvalidFormat;

            const name_len = std.mem.readInt(u16, data[pos..][0..2], .big);
            pos += 2;
            const value_len = std.mem.readInt(u16, data[pos..][0..2], .big);
            pos += 2;

            if (pos + name_len + value_len > data.len) return SerdeError.InvalidFormat;

            const name = data[pos .. pos + name_len];
            pos += name_len;
            const value = data[pos .. pos + value_len];
            pos += value_len;

            response.appendHeader(name, value) catch return SerdeError.OutOfMemory;
        }

        return response;
    }

    /// Free resources (no-op for this implementation)
    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

// ============================================================================
// Wire Format Helpers
// ============================================================================

/// Convert a ResponseHeader to HTTP/1.1 wire format
pub fn toWireFormat(allocator: Allocator, header: *const http.ResponseHeader) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    const writer = buf.writer(allocator);

    // Status line
    try writer.writeAll(header.version.asStr());
    try writer.writeByte(' ');

    var status_buf: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&status_buf, "{d}", .{header.status.code}) catch unreachable;
    try writer.writeAll(&status_buf);
    try writer.writeByte(' ');

    if (header.getReasonPhrase()) |reason| {
        try writer.writeAll(reason);
    }
    try writer.writeAll("\r\n");

    // Headers
    for (header.headers.headers.items) |h| {
        try writer.writeAll(h.name.bytes);
        try writer.writeAll(": ");
        try writer.writeAll(h.value);
        try writer.writeAll("\r\n");
    }

    // End of headers
    try writer.writeAll("\r\n");

    return buf.toOwnedSlice(allocator);
}

/// Convert a RequestHeader to HTTP/1.1 wire format
pub fn requestToWireFormat(allocator: Allocator, header: *const http.RequestHeader) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    const writer = buf.writer(allocator);

    // Request line
    try writer.writeAll(header.method.asStr());
    try writer.writeByte(' ');
    try writer.writeAll(header.uri.pathAndQuery());
    try writer.writeByte(' ');
    try writer.writeAll(header.version.asStr());
    try writer.writeAll("\r\n");

    // Headers
    for (header.headers.headers.items) |h| {
        try writer.writeAll(h.name.bytes);
        try writer.writeAll(": ");
        try writer.writeAll(h.value);
        try writer.writeAll("\r\n");
    }

    // End of headers
    try writer.writeAll("\r\n");

    return buf.toOwnedSlice(allocator);
}

/// Estimate the wire format size without allocating
pub fn estimateWireSize(header: *const http.ResponseHeader) usize {
    var size: usize = 0;

    // Status line: "HTTP/1.1 XXX Reason\r\n"
    size += header.version.asStr().len + 1 + 3 + 1;
    if (header.getReasonPhrase()) |reason| {
        size += reason.len;
    }
    size += 2; // \r\n

    // Headers
    for (header.headers.headers.items) |h| {
        size += h.name.bytes.len + 2 + h.value.len + 2; // "Name: Value\r\n"
    }

    size += 2; // Final \r\n

    return size;
}

// ============================================================================
// Tests
// ============================================================================

test "HeaderSerde serialize and deserialize" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    // Create a response header
    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    try header.appendHeader("Content-Type", "application/json");
    try header.appendHeader("Content-Length", "1234");
    try header.appendHeader("Cache-Control", "max-age=3600");

    // Serialize
    const data = try serde.serialize(&header);
    defer testing.allocator.free(data);

    // Deserialize
    var restored = try serde.deserialize(data);
    defer restored.deinit();

    // Verify
    try testing.expectEqual(restored.status.code, 200);
    try testing.expectEqual(restored.version, .http_1_1);
    try testing.expectEqual(restored.headers.len(), 3);
    try testing.expectEqualStrings("application/json", restored.headers.get("Content-Type").?);
    try testing.expectEqualStrings("1234", restored.headers.get("Content-Length").?);
}

test "HeaderSerde empty headers" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    var header = http.ResponseHeader.init(testing.allocator, 204);
    defer header.deinit();

    const data = try serde.serialize(&header);
    defer testing.allocator.free(data);

    var restored = try serde.deserialize(data);
    defer restored.deinit();

    try testing.expectEqual(restored.status.code, 204);
    try testing.expectEqual(restored.headers.len(), 0);
}

test "HeaderSerde different status codes" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    const codes = [_]u16{ 200, 201, 301, 400, 404, 500, 503 };

    for (codes) |code| {
        var header = http.ResponseHeader.init(testing.allocator, code);
        defer header.deinit();

        const data = try serde.serialize(&header);
        defer testing.allocator.free(data);

        var restored = try serde.deserialize(data);
        defer restored.deinit();

        try testing.expectEqual(restored.status.code, code);
    }
}

test "HeaderSerde different versions" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    const versions = [_]http.Version{ .http_1_0, .http_1_1, .http_2, .http_3 };

    for (versions) |ver| {
        var header = http.ResponseHeader.init(testing.allocator, 200);
        defer header.deinit();
        header.setVersion(ver);

        const data = try serde.serialize(&header);
        defer testing.allocator.free(data);

        var restored = try serde.deserialize(data);
        defer restored.deinit();

        try testing.expectEqual(restored.version, ver);
    }
}

test "HeaderSerde invalid magic" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    const bad_data = [_]u8{ 'B', 'A', 'D', '!', 1, 0, 200, 2, 0, 0 };
    const result = serde.deserialize(&bad_data);
    try testing.expectError(SerdeError.InvalidMagic, result);
}

test "HeaderSerde unsupported version" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    var bad_data = MAGIC ++ [_]u8{ 99, 0, 200, 2, 0, 0 };
    const result = serde.deserialize(&bad_data);
    try testing.expectError(SerdeError.UnsupportedVersion, result);
}

test "toWireFormat basic" {
    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    try header.appendHeader("Content-Type", "text/html");

    const wire = try toWireFormat(testing.allocator, &header);
    defer testing.allocator.free(wire);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/html\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n"));
}

test "toWireFormat empty response" {
    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    const wire = try toWireFormat(testing.allocator, &header);
    defer testing.allocator.free(wire);

    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", wire);
}

test "requestToWireFormat" {
    var header = try http.RequestHeader.build(testing.allocator, .GET, "/path?query=1", .http_1_1);
    defer header.deinit();

    try header.appendHeader("Host", "example.com");

    const wire = try requestToWireFormat(testing.allocator, &header);
    defer testing.allocator.free(wire);

    try testing.expect(std.mem.startsWith(u8, wire, "GET /path?query=1 HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Host: example.com\r\n") != null);
}

test "estimateWireSize" {
    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    try header.appendHeader("Content-Type", "text/html");

    const estimated = estimateWireSize(&header);
    const actual = try toWireFormat(testing.allocator, &header);
    defer testing.allocator.free(actual);

    // Estimated size should be close to actual
    try testing.expect(estimated >= actual.len - 5);
    try testing.expect(estimated <= actual.len + 5);
}

test "HeaderSerde roundtrip with many headers" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    // Add many headers
    try header.appendHeader("Content-Type", "application/json");
    try header.appendHeader("Content-Length", "12345");
    try header.appendHeader("Cache-Control", "max-age=3600, public");
    try header.appendHeader("ETag", "\"abc123\"");
    try header.appendHeader("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT");
    try header.appendHeader("X-Custom-Header", "custom-value");
    try header.appendHeader("Set-Cookie", "session=abc123; Path=/; HttpOnly");

    const data = try serde.serialize(&header);
    defer testing.allocator.free(data);

    var restored = try serde.deserialize(data);
    defer restored.deinit();

    try testing.expectEqual(restored.headers.len(), 7);
    try testing.expectEqualStrings("\"abc123\"", restored.headers.get("ETag").?);
}

test "serialized size vs wire format" {
    var serde = HeaderSerde.init(testing.allocator);
    defer serde.deinit();

    var header = http.ResponseHeader.init(testing.allocator, 200);
    defer header.deinit();

    try header.appendHeader("Content-Type", "application/json");
    try header.appendHeader("Content-Length", "1234");
    try header.appendHeader("Cache-Control", "max-age=3600");

    const serialized = try serde.serialize(&header);
    defer testing.allocator.free(serialized);

    const wire = try toWireFormat(testing.allocator, &header);
    defer testing.allocator.free(wire);

    // Serialized format should be more compact than wire format
    // (In production with zstd, it would be ~1/3 the size)
    try testing.expect(serialized.len < wire.len);
}
