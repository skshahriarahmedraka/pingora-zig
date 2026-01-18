//! HTTP/3 Protocol Implementation (RFC 9114)
//!
//! HTTP/3 is the third major version of HTTP, built on top of QUIC.
//! It provides the same semantics as HTTP/1.1 and HTTP/2 but with:
//! - Improved performance through QUIC's multiplexing
//! - No head-of-line blocking at the transport layer
//! - Faster connection establishment (0-RTT)
//!
//! This module implements:
//! - HTTP/3 frame types (RFC 9114 Section 7)
//! - QPACK header compression (RFC 9204)
//! - HTTP/3 stream management

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const quic = @import("quic.zig");

// ============================================================================
// HTTP/3 Error Codes (RFC 9114 Section 8.1)
// ============================================================================

/// HTTP/3 error codes
pub const ErrorCode = enum(u64) {
    /// No error
    h3_no_error = 0x100,
    /// General protocol error
    h3_general_protocol_error = 0x101,
    /// Internal error
    h3_internal_error = 0x102,
    /// Stream creation error
    h3_stream_creation_error = 0x103,
    /// Closed critical stream
    h3_closed_critical_stream = 0x104,
    /// Frame unexpected
    h3_frame_unexpected = 0x105,
    /// Frame error
    h3_frame_error = 0x106,
    /// Excessive load
    h3_excessive_load = 0x107,
    /// ID error
    h3_id_error = 0x108,
    /// Settings error
    h3_settings_error = 0x109,
    /// Missing settings
    h3_missing_settings = 0x10a,
    /// Request rejected
    h3_request_rejected = 0x10b,
    /// Request cancelled
    h3_request_cancelled = 0x10c,
    /// Request incomplete
    h3_request_incomplete = 0x10d,
    /// Message error
    h3_message_error = 0x10e,
    /// Connect error
    h3_connect_error = 0x10f,
    /// Version fallback
    h3_version_fallback = 0x110,

    // QPACK errors (RFC 9204)
    /// QPACK decompression failed
    qpack_decompression_failed = 0x200,
    /// QPACK encoder stream error
    qpack_encoder_stream_error = 0x201,
    /// QPACK decoder stream error
    qpack_decoder_stream_error = 0x202,

    pub fn isQpackError(self: ErrorCode) bool {
        const code = @intFromEnum(self);
        return code >= 0x200 and code <= 0x2ff;
    }
};

// ============================================================================
// HTTP/3 Frame Types (RFC 9114 Section 7.2)
// ============================================================================

/// HTTP/3 frame types
pub const FrameType = enum(u64) {
    /// DATA frame - carries request/response body
    data = 0x00,
    /// HEADERS frame - carries HTTP headers (QPACK encoded)
    headers = 0x01,
    /// CANCEL_PUSH frame - cancels server push
    cancel_push = 0x03,
    /// SETTINGS frame - connection settings
    settings = 0x04,
    /// PUSH_PROMISE frame - server push promise
    push_promise = 0x05,
    /// GOAWAY frame - graceful shutdown
    goaway = 0x07,
    /// MAX_PUSH_ID frame - maximum push ID
    max_push_id = 0x0d,

    /// Reserved frame types for grease
    pub fn isReserved(frame_type: u64) bool {
        // Reserved: 0x1f * N + 0x21 for any N >= 0
        return (frame_type -% 0x21) % 0x1f == 0;
    }

    pub fn fromInt(value: u64) ?FrameType {
        return std.meta.intToEnum(FrameType, value) catch null;
    }
};

/// HTTP/3 frame header
pub const FrameHeader = struct {
    frame_type: u64,
    length: u64,

    const Self = @This();

    /// Parse a frame header from bytes
    pub fn parse(data: []const u8) ?struct { header: Self, consumed: usize } {
        var offset: usize = 0;

        // Parse type (variable-length integer)
        const type_result = decodeVarInt(data[offset..]) orelse return null;
        offset += type_result.len;

        // Parse length (variable-length integer)
        if (offset >= data.len) return null;
        const len_result = decodeVarInt(data[offset..]) orelse return null;
        offset += len_result.len;

        return .{
            .header = .{
                .frame_type = type_result.value,
                .length = len_result.value,
            },
            .consumed = offset,
        };
    }

    /// Serialize frame header to bytes
    pub fn serialize(self: Self, buf: []u8) usize {
        var offset: usize = 0;
        offset += encodeVarInt(self.frame_type, buf[offset..]);
        offset += encodeVarInt(self.length, buf[offset..]);
        return offset;
    }

    /// Get the frame type as enum (if known)
    pub fn getType(self: Self) ?FrameType {
        return FrameType.fromInt(self.frame_type);
    }
};

// ============================================================================
// HTTP/3 Settings (RFC 9114 Section 7.2.4)
// ============================================================================

/// HTTP/3 setting identifiers
pub const SettingId = enum(u64) {
    /// QPACK max table capacity
    qpack_max_table_capacity = 0x01,
    /// Max field section size
    max_field_section_size = 0x06,
    /// QPACK blocked streams
    qpack_blocked_streams = 0x07,
    /// Enable connect protocol
    enable_connect_protocol = 0x08,

    pub fn fromInt(value: u64) ?SettingId {
        return std.meta.intToEnum(SettingId, value) catch null;
    }
};

/// HTTP/3 settings
pub const Settings = struct {
    /// Maximum dynamic table capacity for QPACK
    qpack_max_table_capacity: u64 = 0,
    /// Maximum size of a field section
    max_field_section_size: u64 = 16384,
    /// Maximum number of blocked streams for QPACK
    qpack_blocked_streams: u64 = 0,
    /// Enable extended CONNECT protocol
    enable_connect_protocol: bool = false,

    const Self = @This();

    pub fn default() Self {
        return .{};
    }

    /// Encode settings to bytes
    pub fn encode(self: Self, buf: []u8) usize {
        var offset: usize = 0;

        // QPACK max table capacity
        if (self.qpack_max_table_capacity > 0) {
            offset += encodeVarInt(@intFromEnum(SettingId.qpack_max_table_capacity), buf[offset..]);
            offset += encodeVarInt(self.qpack_max_table_capacity, buf[offset..]);
        }

        // Max field section size
        offset += encodeVarInt(@intFromEnum(SettingId.max_field_section_size), buf[offset..]);
        offset += encodeVarInt(self.max_field_section_size, buf[offset..]);

        // QPACK blocked streams
        if (self.qpack_blocked_streams > 0) {
            offset += encodeVarInt(@intFromEnum(SettingId.qpack_blocked_streams), buf[offset..]);
            offset += encodeVarInt(self.qpack_blocked_streams, buf[offset..]);
        }

        // Enable connect protocol
        if (self.enable_connect_protocol) {
            offset += encodeVarInt(@intFromEnum(SettingId.enable_connect_protocol), buf[offset..]);
            offset += encodeVarInt(1, buf[offset..]);
        }

        return offset;
    }

    /// Decode settings from bytes
    pub fn decode(data: []const u8) !Self {
        var settings = Self.default();
        var offset: usize = 0;

        while (offset < data.len) {
            const id_result = decodeVarInt(data[offset..]) orelse break;
            offset += id_result.len;

            if (offset >= data.len) break;
            const value_result = decodeVarInt(data[offset..]) orelse break;
            offset += value_result.len;

            if (SettingId.fromInt(id_result.value)) |id| {
                switch (id) {
                    .qpack_max_table_capacity => settings.qpack_max_table_capacity = value_result.value,
                    .max_field_section_size => settings.max_field_section_size = value_result.value,
                    .qpack_blocked_streams => settings.qpack_blocked_streams = value_result.value,
                    .enable_connect_protocol => settings.enable_connect_protocol = value_result.value != 0,
                }
            }
            // Unknown settings are ignored per spec
        }

        return settings;
    }
};

// ============================================================================
// HTTP/3 Stream Types (RFC 9114 Section 6)
// ============================================================================

/// HTTP/3 unidirectional stream types
pub const UniStreamType = enum(u64) {
    /// Control stream
    control = 0x00,
    /// Push stream
    push = 0x01,
    /// QPACK encoder stream
    qpack_encoder = 0x02,
    /// QPACK decoder stream
    qpack_decoder = 0x03,

    pub fn fromInt(value: u64) ?UniStreamType {
        return std.meta.intToEnum(UniStreamType, value) catch null;
    }
};

// ============================================================================
// Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================================

/// Decode a variable-length integer
pub fn decodeVarInt(data: []const u8) ?struct { value: u64, len: usize } {
    if (data.len == 0) return null;

    const prefix = data[0] >> 6;
    const len: usize = @as(usize, 1) << @as(u6, @truncate(prefix));

    if (data.len < len) return null;

    var value: u64 = data[0] & 0x3f;
    for (data[1..len]) |b| {
        value = (value << 8) | b;
    }

    return .{ .value = value, .len = len };
}

/// Encode a variable-length integer
pub fn encodeVarInt(value: u64, buf: []u8) usize {
    if (value <= 63) {
        buf[0] = @truncate(value);
        return 1;
    } else if (value <= 16383) {
        buf[0] = @truncate((value >> 8) | 0x40);
        buf[1] = @truncate(value);
        return 2;
    } else if (value <= 1073741823) {
        buf[0] = @truncate((value >> 24) | 0x80);
        buf[1] = @truncate(value >> 16);
        buf[2] = @truncate(value >> 8);
        buf[3] = @truncate(value);
        return 4;
    } else {
        buf[0] = @truncate((value >> 56) | 0xc0);
        buf[1] = @truncate(value >> 48);
        buf[2] = @truncate(value >> 40);
        buf[3] = @truncate(value >> 32);
        buf[4] = @truncate(value >> 24);
        buf[5] = @truncate(value >> 16);
        buf[6] = @truncate(value >> 8);
        buf[7] = @truncate(value);
        return 8;
    }
}

/// Get the encoded length of a variable-length integer
pub fn varIntLen(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

// ============================================================================
// Frame Builders
// ============================================================================

pub const FrameBuilder = struct {
    /// Build a DATA frame
    pub fn buildData(payload: []const u8, buf: []u8) !usize {
        const header_len = varIntLen(@intFromEnum(FrameType.data)) + varIntLen(payload.len);
        if (buf.len < header_len + payload.len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.data), buf[offset..]);
        offset += encodeVarInt(payload.len, buf[offset..]);
        @memcpy(buf[offset..][0..payload.len], payload);
        return offset + payload.len;
    }

    /// Build a HEADERS frame
    pub fn buildHeaders(encoded_headers: []const u8, buf: []u8) !usize {
        const header_len = varIntLen(@intFromEnum(FrameType.headers)) + varIntLen(encoded_headers.len);
        if (buf.len < header_len + encoded_headers.len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.headers), buf[offset..]);
        offset += encodeVarInt(encoded_headers.len, buf[offset..]);
        @memcpy(buf[offset..][0..encoded_headers.len], encoded_headers);
        return offset + encoded_headers.len;
    }

    /// Build a SETTINGS frame
    pub fn buildSettings(settings: Settings, buf: []u8) !usize {
        var settings_buf: [128]u8 = undefined;
        const settings_len = settings.encode(&settings_buf);

        const header_len = varIntLen(@intFromEnum(FrameType.settings)) + varIntLen(settings_len);
        if (buf.len < header_len + settings_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.settings), buf[offset..]);
        offset += encodeVarInt(settings_len, buf[offset..]);
        @memcpy(buf[offset..][0..settings_len], settings_buf[0..settings_len]);
        return offset + settings_len;
    }

    /// Build a GOAWAY frame
    pub fn buildGoaway(stream_id: u64, buf: []u8) !usize {
        const payload_len = varIntLen(stream_id);
        const header_len = varIntLen(@intFromEnum(FrameType.goaway)) + varIntLen(payload_len);
        if (buf.len < header_len + payload_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.goaway), buf[offset..]);
        offset += encodeVarInt(payload_len, buf[offset..]);
        offset += encodeVarInt(stream_id, buf[offset..]);
        return offset;
    }

    /// Build a CANCEL_PUSH frame
    pub fn buildCancelPush(push_id: u64, buf: []u8) !usize {
        const payload_len = varIntLen(push_id);
        const header_len = varIntLen(@intFromEnum(FrameType.cancel_push)) + varIntLen(payload_len);
        if (buf.len < header_len + payload_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.cancel_push), buf[offset..]);
        offset += encodeVarInt(payload_len, buf[offset..]);
        offset += encodeVarInt(push_id, buf[offset..]);
        return offset;
    }

    /// Build a MAX_PUSH_ID frame
    pub fn buildMaxPushId(push_id: u64, buf: []u8) !usize {
        const payload_len = varIntLen(push_id);
        const header_len = varIntLen(@intFromEnum(FrameType.max_push_id)) + varIntLen(payload_len);
        if (buf.len < header_len + payload_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.max_push_id), buf[offset..]);
        offset += encodeVarInt(payload_len, buf[offset..]);
        offset += encodeVarInt(push_id, buf[offset..]);
        return offset;
    }

    /// Build a PUSH_PROMISE frame (server only)
    pub fn buildPushPromise(push_id: u64, encoded_headers: []const u8, buf: []u8) !usize {
        const push_id_len = varIntLen(push_id);
        const payload_len = push_id_len + encoded_headers.len;
        const header_len = varIntLen(@intFromEnum(FrameType.push_promise)) + varIntLen(payload_len);
        if (buf.len < header_len + payload_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(FrameType.push_promise), buf[offset..]);
        offset += encodeVarInt(payload_len, buf[offset..]);
        offset += encodeVarInt(push_id, buf[offset..]);
        @memcpy(buf[offset..][0..encoded_headers.len], encoded_headers);
        return offset + encoded_headers.len;
    }

    /// Build a GREASE frame (for protocol extensibility testing)
    pub fn buildGrease(buf: []u8) !usize {
        // GREASE frame type: 0x1f * N + 0x21
        const grease_type: u64 = 0x21; // First GREASE type
        const payload = [_]u8{}; // Empty payload

        const header_len = varIntLen(grease_type) + varIntLen(payload.len);
        if (buf.len < header_len) return error.BufferTooSmall;

        var offset: usize = 0;
        offset += encodeVarInt(grease_type, buf[offset..]);
        offset += encodeVarInt(payload.len, buf[offset..]);
        return offset;
    }

    /// Build a stream type indicator for unidirectional streams
    pub fn buildStreamType(stream_type: UniStreamType, buf: []u8) usize {
        return encodeVarInt(@intFromEnum(stream_type), buf);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "variable-length integer encoding/decoding" {
    var buf: [8]u8 = undefined;

    // 1-byte encoding (0-63)
    const len1 = encodeVarInt(37, &buf);
    try testing.expectEqual(len1, 1);
    const dec1 = decodeVarInt(&buf).?;
    try testing.expectEqual(dec1.value, 37);
    try testing.expectEqual(dec1.len, 1);

    // 2-byte encoding (64-16383)
    const len2 = encodeVarInt(15293, &buf);
    try testing.expectEqual(len2, 2);
    const dec2 = decodeVarInt(&buf).?;
    try testing.expectEqual(dec2.value, 15293);
    try testing.expectEqual(dec2.len, 2);

    // 4-byte encoding (16384-1073741823)
    const len4 = encodeVarInt(494878333, &buf);
    try testing.expectEqual(len4, 4);
    const dec4 = decodeVarInt(&buf).?;
    try testing.expectEqual(dec4.value, 494878333);
    try testing.expectEqual(dec4.len, 4);
}

test "FrameHeader parse and serialize" {
    var buf: [16]u8 = undefined;

    const header = FrameHeader{
        .frame_type = @intFromEnum(FrameType.headers),
        .length = 100,
    };

    const len = header.serialize(&buf);
    const parsed = FrameHeader.parse(buf[0..len]).?;

    try testing.expectEqual(parsed.header.frame_type, @intFromEnum(FrameType.headers));
    try testing.expectEqual(parsed.header.length, 100);
}

test "Settings encode and decode" {
    var buf: [64]u8 = undefined;

    const settings = Settings{
        .qpack_max_table_capacity = 4096,
        .max_field_section_size = 8192,
        .qpack_blocked_streams = 100,
        .enable_connect_protocol = true,
    };

    const len = settings.encode(&buf);
    const decoded = try Settings.decode(buf[0..len]);

    try testing.expectEqual(decoded.qpack_max_table_capacity, 4096);
    try testing.expectEqual(decoded.max_field_section_size, 8192);
    try testing.expectEqual(decoded.qpack_blocked_streams, 100);
    try testing.expect(decoded.enable_connect_protocol);
}

test "FrameBuilder buildData" {
    var buf: [64]u8 = undefined;
    const payload = "Hello, HTTP/3!";

    _ = try FrameBuilder.buildData(payload, &buf);
    const parsed = FrameHeader.parse(&buf).?;

    try testing.expectEqual(parsed.header.frame_type, @intFromEnum(FrameType.data));
    try testing.expectEqual(parsed.header.length, payload.len);
}

test "FrameBuilder buildGoaway" {
    var buf: [16]u8 = undefined;

    const len = try FrameBuilder.buildGoaway(100, &buf);
    const parsed = FrameHeader.parse(&buf).?;

    try testing.expectEqual(parsed.header.frame_type, @intFromEnum(FrameType.goaway));
    try testing.expect(len > 0);
}

test "FrameType reserved detection" {
    // Reserved frame types: 0x21, 0x40, 0x5f, ...
    try testing.expect(FrameType.isReserved(0x21));
    try testing.expect(FrameType.isReserved(0x40));
    try testing.expect(!FrameType.isReserved(0x00)); // DATA
    try testing.expect(!FrameType.isReserved(0x01)); // HEADERS
}

test "ErrorCode QPACK detection" {
    try testing.expect(ErrorCode.qpack_decompression_failed.isQpackError());
    try testing.expect(ErrorCode.qpack_encoder_stream_error.isQpackError());
    try testing.expect(!ErrorCode.h3_no_error.isQpackError());
}

// ============================================================================
// QPACK Header Compression (RFC 9204)
// ============================================================================

/// Header field type
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK static table (RFC 9204 Appendix A) - partial
pub const QpackStaticTable = struct {
    pub const Entry = struct { name: []const u8, value: []const u8 };
    
    /// Static table entries (first 20 for brevity)
    pub const entries = [_]Entry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "age", .value = "0" },
        .{ .name = "content-disposition", .value = "" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "cookie", .value = "" },
        .{ .name = "date", .value = "" },
        .{ .name = "etag", .value = "" },
        .{ .name = "if-modified-since", .value = "" },
        .{ .name = "if-none-match", .value = "" },
        .{ .name = "last-modified", .value = "" },
        .{ .name = "link", .value = "" },
        .{ .name = "location", .value = "" },
        .{ .name = "referer", .value = "" },
        .{ .name = "set-cookie", .value = "" },
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":method", .value = "DELETE" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":method", .value = "PUT" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "204" },
        .{ .name = ":status", .value = "206" },
        .{ .name = ":status", .value = "304" },
        .{ .name = ":status", .value = "400" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "500" },
    };

    pub fn get(index: usize) ?Entry {
        if (index >= entries.len) return null;
        return entries[index];
    }

    pub fn findIndex(name: []const u8, value: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i;
            }
        }
        return null;
    }

    pub fn findNameIndex(name: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i;
            }
        }
        return null;
    }
};

/// QPACK encoder (simplified - static refs only)
pub const QpackEncoder = struct {
    max_table_capacity: usize,

    const Self = @This();

    pub fn init(max_table_capacity: usize) Self {
        return .{ .max_table_capacity = max_table_capacity };
    }

    /// Encode a header field
    pub fn encodeField(name: []const u8, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;

        // Try static table indexed
        if (QpackStaticTable.findIndex(name, value)) |index| {
            if (index < 64) {
                buf[offset] = 0xc0 | @as(u8, @truncate(index));
                offset += 1;
                return offset;
            }
        }

        // Try static table name reference
        if (QpackStaticTable.findNameIndex(name)) |name_idx| {
            if (name_idx < 16) {
                buf[offset] = 0x50 | @as(u8, @truncate(name_idx));
                offset += 1;
                offset += encodeLiteralString(value, buf[offset..]);
                return offset;
            }
        }

        // Literal name and value
        buf[offset] = 0x20;
        offset += 1;
        offset += encodeLiteralString(name, buf[offset..]);
        offset += encodeLiteralString(value, buf[offset..]);
        return offset;
    }

    fn encodeLiteralString(str: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        if (str.len < 127) {
            buf[offset] = @truncate(str.len);
            offset += 1;
        } else {
            buf[offset] = 127;
            offset += 1;
            var remaining = str.len - 127;
            while (remaining >= 128) {
                buf[offset] = @truncate((remaining & 0x7f) | 0x80);
                offset += 1;
                remaining >>= 7;
            }
            buf[offset] = @truncate(remaining);
            offset += 1;
        }
        @memcpy(buf[offset..][0..str.len], str);
        return offset + str.len;
    }

    /// Encode request headers
    pub fn encodeRequest(
        self: Self,
        method: []const u8,
        scheme: []const u8,
        authority: []const u8,
        path: []const u8,
        headers: []const HeaderField,
        buf: []u8,
    ) usize {
        _ = self;
        var offset: usize = 0;

        // Required insert count and delta base
        buf[offset] = 0;
        offset += 1;
        buf[offset] = 0;
        offset += 1;

        // Pseudo-headers
        offset += encodeField(":method", method, buf[offset..]);
        offset += encodeField(":scheme", scheme, buf[offset..]);
        offset += encodeField(":authority", authority, buf[offset..]);
        offset += encodeField(":path", path, buf[offset..]);

        // Regular headers
        for (headers) |h| {
            offset += encodeField(h.name, h.value, buf[offset..]);
        }

        return offset;
    }
};

// ============================================================================
// HTTP/3 Connection State Machine
// ============================================================================

/// HTTP/3 connection role
pub const ConnectionRole = enum {
    client,
    server,
};

/// HTTP/3 connection state
pub const ConnectionState = enum {
    /// Initial state - waiting for settings
    idle,
    /// Settings exchanged, ready for requests
    ready,
    /// GOAWAY sent/received, graceful shutdown in progress
    closing,
    /// Connection closed
    closed,
};

/// HTTP/3 stream state
pub const StreamState = enum {
    /// Stream created but no frames sent/received
    idle,
    /// Request/response headers sent/received
    open,
    /// All data sent (FIN sent)
    half_closed_local,
    /// All data received (FIN received)
    half_closed_remote,
    /// Stream fully closed
    closed,
    /// Stream was reset
    reset,
};

/// HTTP/3 stream information
pub const Stream = struct {
    id: u64,
    state: StreamState,
    stream_type: StreamType,
    /// Bytes sent on this stream
    bytes_sent: u64,
    /// Bytes received on this stream
    bytes_received: u64,
    /// Whether we've received headers
    headers_received: bool,
    /// Whether we've sent headers
    headers_sent: bool,

    const Self = @This();

    pub fn init(id: u64, stream_type: StreamType) Self {
        return .{
            .id = id,
            .state = .idle,
            .stream_type = stream_type,
            .bytes_sent = 0,
            .bytes_received = 0,
            .headers_received = false,
            .headers_sent = false,
        };
    }

    pub fn canSend(self: *const Self) bool {
        return self.state == .idle or self.state == .open or self.state == .half_closed_remote;
    }

    pub fn canReceive(self: *const Self) bool {
        return self.state == .idle or self.state == .open or self.state == .half_closed_local;
    }
};

/// HTTP/3 stream type classification
pub const StreamType = enum {
    /// Request stream (client-initiated bidirectional)
    request,
    /// Push stream (server-initiated)
    push,
    /// Control stream
    control,
    /// QPACK encoder stream
    qpack_encoder,
    /// QPACK decoder stream
    qpack_decoder,
    /// Unknown/reserved stream type
    unknown,

    pub fn fromUniStreamType(uni_type: UniStreamType) StreamType {
        return switch (uni_type) {
            .control => .control,
            .push => .push,
            .qpack_encoder => .qpack_encoder,
            .qpack_decoder => .qpack_decoder,
        };
    }
};

/// HTTP/3 Connection
pub const Connection = struct {
    allocator: Allocator,
    role: ConnectionRole,
    state: ConnectionState,
    /// Local settings
    local_settings: Settings,
    /// Peer settings (received)
    peer_settings: ?Settings,
    /// Active streams
    streams: std.AutoHashMap(u64, Stream),
    /// Next stream ID for client-initiated streams
    next_stream_id: u64,
    /// Control stream ID (local)
    local_control_stream_id: ?u64,
    /// Control stream ID (peer)
    peer_control_stream_id: ?u64,
    /// QPACK encoder stream ID (local)
    local_qpack_encoder_stream_id: ?u64,
    /// QPACK decoder stream ID (local)
    local_qpack_decoder_stream_id: ?u64,
    /// Peer QPACK encoder stream ID
    peer_qpack_encoder_stream_id: ?u64,
    /// Peer QPACK decoder stream ID
    peer_qpack_decoder_stream_id: ?u64,
    /// Last received GOAWAY stream ID
    goaway_received: ?u64,
    /// Last sent GOAWAY stream ID
    goaway_sent: ?u64,
    /// Maximum push ID we can use (client sets this)
    max_push_id: u64,
    /// Next push ID for server push
    next_push_id: u64,
    /// Active push promises (push_id -> stream_id mapping)
    push_promises: std.AutoHashMap(u64, u64),
    /// Cancelled push IDs
    cancelled_pushes: std.AutoHashMap(u64, void),
    /// QPACK encoder
    qpack_encoder: QpackEncoder,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Number of requests processed
    requests_count: u64,

    const Self = @This();

    /// Initialize a new HTTP/3 connection
    pub fn init(allocator: Allocator, role: ConnectionRole, settings: Settings) Self {
        return .{
            .allocator = allocator,
            .role = role,
            .state = .idle,
            .local_settings = settings,
            .peer_settings = null,
            .streams = std.AutoHashMap(u64, Stream).init(allocator),
            .next_stream_id = if (role == .client) 0 else 1,
            .local_control_stream_id = null,
            .peer_control_stream_id = null,
            .local_qpack_encoder_stream_id = null,
            .local_qpack_decoder_stream_id = null,
            .peer_qpack_encoder_stream_id = null,
            .peer_qpack_decoder_stream_id = null,
            .goaway_received = null,
            .goaway_sent = null,
            .max_push_id = 0,
            .next_push_id = 0,
            .push_promises = std.AutoHashMap(u64, u64).init(allocator),
            .cancelled_pushes = std.AutoHashMap(u64, void).init(allocator),
            .qpack_encoder = QpackEncoder.init(settings.qpack_max_table_capacity),
            .bytes_sent = 0,
            .bytes_received = 0,
            .requests_count = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.streams.deinit();
        self.push_promises.deinit();
        self.cancelled_pushes.deinit();
    }

    /// Create the initial control streams (must be called after QUIC connection is established)
    pub fn initializeControlStreams(self: *Self) !struct { control: u64, encoder: u64, decoder: u64 } {
        // Allocate unidirectional stream IDs
        // Client uses 2, 6, 10, ... for unidirectional
        // Server uses 3, 7, 11, ... for unidirectional
        const base: u64 = if (self.role == .client) 2 else 3;

        self.local_control_stream_id = base;
        self.local_qpack_encoder_stream_id = base + 4;
        self.local_qpack_decoder_stream_id = base + 8;

        // Register the streams
        try self.streams.put(self.local_control_stream_id.?, Stream.init(self.local_control_stream_id.?, .control));
        try self.streams.put(self.local_qpack_encoder_stream_id.?, Stream.init(self.local_qpack_encoder_stream_id.?, .qpack_encoder));
        try self.streams.put(self.local_qpack_decoder_stream_id.?, Stream.init(self.local_qpack_decoder_stream_id.?, .qpack_decoder));

        return .{
            .control = self.local_control_stream_id.?,
            .encoder = self.local_qpack_encoder_stream_id.?,
            .decoder = self.local_qpack_decoder_stream_id.?,
        };
    }

    /// Build the initial SETTINGS frame payload for the control stream
    pub fn buildSettingsFrame(self: *Self, buf: []u8) !usize {
        // First byte is the stream type for unidirectional streams
        var offset: usize = 0;
        offset += encodeVarInt(@intFromEnum(UniStreamType.control), buf[offset..]);

        // Then the SETTINGS frame
        offset += try FrameBuilder.buildSettings(self.local_settings, buf[offset..]);

        return offset;
    }

    /// Process a received SETTINGS frame
    pub fn processSettings(self: *Self, data: []const u8) !void {
        self.peer_settings = try Settings.decode(data);
        if (self.state == .idle) {
            self.state = .ready;
        }
    }

    /// Process a received GOAWAY frame
    pub fn processGoaway(self: *Self, stream_id: u64) void {
        self.goaway_received = stream_id;
        self.state = .closing;
    }

    /// Create a new request stream (client only)
    pub fn createRequestStream(self: *Self) !u64 {
        if (self.role != .client) {
            return error.InvalidRole;
        }
        if (self.state != .ready) {
            return error.NotReady;
        }
        if (self.goaway_received != null) {
            return error.GoawayReceived;
        }

        // Client bidirectional streams: 0, 4, 8, ...
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4;

        try self.streams.put(stream_id, Stream.init(stream_id, .request));
        return stream_id;
    }

    /// Build a request on a stream
    pub fn buildRequest(
        self: *Self,
        stream_id: u64,
        method: []const u8,
        scheme: []const u8,
        authority: []const u8,
        path: []const u8,
        headers: []const HeaderField,
        buf: []u8,
    ) !usize {
        if (self.streams.get(stream_id)) |*stream| {
            _ = stream;
            var qpack_buf: [4096]u8 = undefined;
            const qpack_len = self.qpack_encoder.encodeRequest(method, scheme, authority, path, headers, &qpack_buf);

            return try FrameBuilder.buildHeaders(qpack_buf[0..qpack_len], buf);
        }
        return error.StreamNotFound;
    }

    /// Build a response on a stream (server only)
    pub fn buildResponse(
        self: *Self,
        stream_id: u64,
        status: []const u8,
        headers: []const HeaderField,
        buf: []u8,
    ) !usize {
        if (self.role != .server) {
            return error.InvalidRole;
        }

        if (self.streams.get(stream_id)) |*stream| {
            _ = stream;
            var qpack_buf: [4096]u8 = undefined;
            var offset: usize = 0;

            // Required insert count and delta base
            qpack_buf[offset] = 0;
            offset += 1;
            qpack_buf[offset] = 0;
            offset += 1;

            // Encode :status pseudo-header
            offset += QpackEncoder.encodeField(":status", status, qpack_buf[offset..]);

            // Encode other headers
            for (headers) |h| {
                offset += QpackEncoder.encodeField(h.name, h.value, qpack_buf[offset..]);
            }

            return try FrameBuilder.buildHeaders(qpack_buf[0..offset], buf);
        }
        return error.StreamNotFound;
    }

    /// Build a DATA frame
    pub fn buildData(self: *Self, stream_id: u64, payload: []const u8, buf: []u8) !usize {
        if (self.streams.get(stream_id)) |*stream| {
            _ = stream;
            return try FrameBuilder.buildData(payload, buf);
        }
        return error.StreamNotFound;
    }

    /// Send a GOAWAY frame
    pub fn sendGoaway(self: *Self, stream_id: u64, buf: []u8) !usize {
        self.goaway_sent = stream_id;
        self.state = .closing;
        return try FrameBuilder.buildGoaway(stream_id, buf);
    }

    /// Get a stream by ID
    pub fn getStream(self: *Self, stream_id: u64) ?*Stream {
        return self.streams.getPtr(stream_id);
    }

    /// Check if we can create new streams
    pub fn canCreateStreams(self: *Self) bool {
        return self.state == .ready and self.goaway_received == null;
    }

    /// Get connection statistics
    pub fn getStats(self: *Self) ConnectionStats {
        var total_streams: usize = 0;
        var active_streams: usize = 0;
        var stream_bytes_sent: u64 = 0;
        var stream_bytes_received: u64 = 0;

        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            total_streams += 1;
            if (entry.value_ptr.state == .open or
                entry.value_ptr.state == .half_closed_local or
                entry.value_ptr.state == .half_closed_remote)
            {
                active_streams += 1;
            }
            stream_bytes_sent += entry.value_ptr.bytes_sent;
            stream_bytes_received += entry.value_ptr.bytes_received;
        }

        return .{
            .total_streams = total_streams,
            .active_streams = active_streams,
            .bytes_sent = self.bytes_sent,
            .bytes_received = self.bytes_received,
            .state = self.state,
        };
    }

    // ========================================================================
    // Server Push (RFC 9114 Section 4.6)
    // ========================================================================

    /// Set the maximum push ID (client only)
    pub fn setMaxPushId(self: *Self, push_id: u64, buf: []u8) !usize {
        if (self.role != .client) {
            return error.InvalidRole;
        }
        self.max_push_id = push_id;
        return try FrameBuilder.buildMaxPushId(push_id, buf);
    }

    /// Process a received MAX_PUSH_ID frame (server only)
    pub fn processMaxPushId(self: *Self, push_id: u64) !void {
        if (self.role != .server) {
            return error.InvalidRole;
        }
        if (push_id < self.max_push_id) {
            return error.InvalidPushId; // Can't decrease max push ID
        }
        self.max_push_id = push_id;
    }

    /// Create a push promise (server only)
    pub fn createPushPromise(
        self: *Self,
        request_stream_id: u64,
        method: []const u8,
        scheme: []const u8,
        authority: []const u8,
        path: []const u8,
        headers: []const HeaderField,
        buf: []u8,
    ) !struct { push_id: u64, len: usize } {
        if (self.role != .server) {
            return error.InvalidRole;
        }
        if (self.next_push_id > self.max_push_id) {
            return error.PushIdExhausted;
        }

        const push_id = self.next_push_id;
        self.next_push_id += 1;

        // Build QPACK encoded headers for the promised request
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = self.qpack_encoder.encodeRequest(method, scheme, authority, path, headers, &qpack_buf);

        const len = try FrameBuilder.buildPushPromise(push_id, qpack_buf[0..qpack_len], buf);

        // Track the push promise
        try self.push_promises.put(push_id, request_stream_id);

        return .{ .push_id = push_id, .len = len };
    }

    /// Cancel a push (client only)
    pub fn cancelPush(self: *Self, push_id: u64, buf: []u8) !usize {
        if (self.role != .client) {
            return error.InvalidRole;
        }
        try self.cancelled_pushes.put(push_id, {});
        return try FrameBuilder.buildCancelPush(push_id, buf);
    }

    /// Process a received CANCEL_PUSH frame (server only)
    pub fn processCancelPush(self: *Self, push_id: u64) !void {
        if (self.role != .server) {
            return error.InvalidRole;
        }
        _ = self.push_promises.remove(push_id);
        try self.cancelled_pushes.put(push_id, {});
    }

    /// Check if a push was cancelled
    pub fn isPushCancelled(self: *Self, push_id: u64) bool {
        return self.cancelled_pushes.contains(push_id);
    }

    // ========================================================================
    // Peer Unidirectional Stream Handling
    // ========================================================================

    /// Register a peer's unidirectional stream
    pub fn registerPeerUniStream(self: *Self, stream_id: u64, stream_type: UniStreamType) !void {
        switch (stream_type) {
            .control => {
                if (self.peer_control_stream_id != null) {
                    return error.DuplicateControlStream;
                }
                self.peer_control_stream_id = stream_id;
            },
            .qpack_encoder => {
                if (self.peer_qpack_encoder_stream_id != null) {
                    return error.DuplicateQpackStream;
                }
                self.peer_qpack_encoder_stream_id = stream_id;
            },
            .qpack_decoder => {
                if (self.peer_qpack_decoder_stream_id != null) {
                    return error.DuplicateQpackStream;
                }
                self.peer_qpack_decoder_stream_id = stream_id;
            },
            .push => {
                // Push streams are handled separately
            },
        }
        try self.streams.put(stream_id, Stream.init(stream_id, StreamType.fromUniStreamType(stream_type)));
    }

    // ========================================================================
    // Stream State Management
    // ========================================================================

    /// Close a stream locally (send FIN)
    pub fn closeStreamLocal(self: *Self, stream_id: u64) !void {
        if (self.streams.getPtr(stream_id)) |stream| {
            switch (stream.state) {
                .idle, .open => stream.state = .half_closed_local,
                .half_closed_remote => stream.state = .closed,
                else => return error.InvalidStreamState,
            }
        } else {
            return error.StreamNotFound;
        }
    }

    /// Mark stream as closed by remote (received FIN)
    pub fn closeStreamRemote(self: *Self, stream_id: u64) !void {
        if (self.streams.getPtr(stream_id)) |stream| {
            switch (stream.state) {
                .idle, .open => stream.state = .half_closed_remote,
                .half_closed_local => stream.state = .closed,
                else => return error.InvalidStreamState,
            }
        } else {
            return error.StreamNotFound;
        }
    }

    /// Reset a stream
    pub fn resetStream(self: *Self, stream_id: u64) !void {
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.state = .reset;
        } else {
            return error.StreamNotFound;
        }
    }

    /// Remove a closed stream from tracking
    pub fn removeStream(self: *Self, stream_id: u64) bool {
        return self.streams.remove(stream_id);
    }

    /// Get number of active request streams
    pub fn activeRequestStreams(self: *Self) usize {
        var count: usize = 0;
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.stream_type == .request and
                (entry.value_ptr.state == .open or
                entry.value_ptr.state == .half_closed_local or
                entry.value_ptr.state == .half_closed_remote))
            {
                count += 1;
            }
        }
        return count;
    }

    // ========================================================================
    // Frame Processing
    // ========================================================================

    /// Process a received frame on a stream
    pub fn processFrame(self: *Self, stream_id: u64, frame_type: FrameType, payload: []const u8) !void {
        switch (frame_type) {
            .data => {
                if (self.streams.getPtr(stream_id)) |stream| {
                    stream.bytes_received += payload.len;
                    self.bytes_received += payload.len;
                }
            },
            .headers => {
                if (self.streams.getPtr(stream_id)) |stream| {
                    stream.headers_received = true;
                    stream.bytes_received += payload.len;
                    self.bytes_received += payload.len;
                    if (stream.state == .idle) {
                        stream.state = .open;
                    }
                }
            },
            .settings => {
                try self.processSettings(payload);
            },
            .goaway => {
                if (FrameParser.parseGoaway(payload)) |goaway_id| {
                    self.processGoaway(goaway_id);
                }
            },
            .cancel_push => {
                if (FrameParser.parseCancelPush(payload)) |push_id| {
                    try self.processCancelPush(push_id);
                }
            },
            .max_push_id => {
                if (FrameParser.parseMaxPushId(payload)) |push_id| {
                    try self.processMaxPushId(push_id);
                }
            },
            .push_promise => {
                // Client receives push promises
                self.bytes_received += payload.len;
            },
        }
    }

    /// Update bytes sent tracking
    pub fn recordBytesSent(self: *Self, stream_id: u64, bytes: u64) void {
        self.bytes_sent += bytes;
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.bytes_sent += bytes;
        }
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    total_streams: usize,
    active_streams: usize,
    bytes_sent: u64,
    bytes_received: u64,
    state: ConnectionState,
};

// ============================================================================
// Frame Parser
// ============================================================================

/// Parse an HTTP/3 frame from a buffer
pub const FrameParser = struct {
    /// Parse result
    pub const ParseResult = struct {
        frame_type: FrameType,
        payload: []const u8,
        consumed: usize,
    };

    /// Parse a frame from the buffer
    pub fn parse(data: []const u8) ?ParseResult {
        const header_result = FrameHeader.parse(data) orelse return null;
        const header = header_result.header;
        const header_len = header_result.consumed;

        // Check if we have enough data for the payload
        if (data.len < header_len + header.length) {
            return null; // Need more data
        }

        const frame_type = FrameType.fromInt(header.frame_type) orelse {
            // Unknown frame type - skip it per spec
            return .{
                .frame_type = .data, // Placeholder
                .payload = data[header_len .. header_len + header.length],
                .consumed = header_len + header.length,
            };
        };

        return .{
            .frame_type = frame_type,
            .payload = data[header_len .. header_len + header.length],
            .consumed = header_len + header.length,
        };
    }

    /// Parse a DATA frame payload (just returns the data)
    pub fn parseData(payload: []const u8) []const u8 {
        return payload;
    }

    /// Parse a GOAWAY frame payload
    pub fn parseGoaway(payload: []const u8) ?u64 {
        const result = decodeVarInt(payload) orelse return null;
        return result.value;
    }

    /// Parse a MAX_PUSH_ID frame payload
    pub fn parseMaxPushId(payload: []const u8) ?u64 {
        const result = decodeVarInt(payload) orelse return null;
        return result.value;
    }

    /// Parse a CANCEL_PUSH frame payload
    pub fn parseCancelPush(payload: []const u8) ?u64 {
        const result = decodeVarInt(payload) orelse return null;
        return result.value;
    }
};

// ============================================================================
// Additional Tests
// ============================================================================

test "QpackStaticTable lookup" {
    const get_idx = QpackStaticTable.findIndex(":method", "GET");
    try testing.expect(get_idx != null);
    try testing.expectEqual(get_idx.?, 17);

    const name_idx = QpackStaticTable.findNameIndex(":method");
    try testing.expect(name_idx != null);
}

test "QpackEncoder encodeRequest" {
    const encoder = QpackEncoder.init(4096);
    var buf: [512]u8 = undefined;

    const headers = [_]HeaderField{
        .{ .name = "user-agent", .value = "pingora-zig" },
    };

    const len = encoder.encodeRequest("GET", "https", "example.com", "/", &headers, &buf);
    try testing.expect(len > 4); // At least prefix + some headers
}

test "HTTP/3 Connection initialization" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    try testing.expectEqual(conn.state, .idle);
    try testing.expectEqual(conn.role, .client);
    try testing.expectEqual(conn.next_stream_id, 0);
}

test "HTTP/3 Connection control streams" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    const streams = try conn.initializeControlStreams();
    try testing.expectEqual(streams.control, 2);
    try testing.expectEqual(streams.encoder, 6);
    try testing.expectEqual(streams.decoder, 10);
}

test "HTTP/3 Connection request stream creation" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    // Initialize control streams first
    _ = try conn.initializeControlStreams();

    // Simulate receiving peer settings
    conn.state = .ready;

    // Create request streams
    const stream1 = try conn.createRequestStream();
    const stream2 = try conn.createRequestStream();

    try testing.expectEqual(stream1, 0);
    try testing.expectEqual(stream2, 4);
}

test "HTTP/3 Stream state" {
    var stream = Stream.init(0, .request);

    try testing.expect(stream.canSend());
    try testing.expect(stream.canReceive());

    stream.state = .half_closed_local;
    try testing.expect(stream.canSend() == false);
    try testing.expect(stream.canReceive());

    stream.state = .half_closed_remote;
    try testing.expect(stream.canSend());
    try testing.expect(stream.canReceive() == false);
}

test "FrameParser parse DATA frame" {
    var buf: [32]u8 = undefined;
    const payload = "Hello";
    const len = try FrameBuilder.buildData(payload, &buf);

    const result = FrameParser.parse(buf[0..len]);
    try testing.expect(result != null);
    try testing.expectEqual(result.?.frame_type, .data);
    try testing.expectEqualStrings(result.?.payload, payload);
}

test "FrameParser parse GOAWAY frame" {
    var buf: [16]u8 = undefined;
    const len = try FrameBuilder.buildGoaway(100, &buf);

    const result = FrameParser.parse(buf[0..len]);
    try testing.expect(result != null);
    try testing.expectEqual(result.?.frame_type, .goaway);

    const stream_id = FrameParser.parseGoaway(result.?.payload);
    try testing.expectEqual(stream_id, 100);
}

test "ConnectionStats" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    _ = try conn.initializeControlStreams();
    conn.state = .ready;

    const stats = conn.getStats();
    try testing.expectEqual(stats.total_streams, 3); // control, encoder, decoder
    try testing.expectEqual(stats.state, .ready);
}

test "FrameBuilder buildPushPromise" {
    var buf: [128]u8 = undefined;
    const headers = "encoded_headers_data";

    const len = try FrameBuilder.buildPushPromise(42, headers, &buf);
    try testing.expect(len > 0);

    // Parse the frame header
    const parsed = FrameHeader.parse(&buf);
    try testing.expect(parsed != null);
    try testing.expectEqual(parsed.?.header.frame_type, @intFromEnum(FrameType.push_promise));
}

test "FrameBuilder buildGrease" {
    var buf: [16]u8 = undefined;
    const len = try FrameBuilder.buildGrease(&buf);
    try testing.expect(len >= 2); // At least frame type + length
}

test "FrameBuilder buildStreamType" {
    var buf: [8]u8 = undefined;

    const len1 = FrameBuilder.buildStreamType(.control, &buf);
    try testing.expectEqual(len1, 1);
    try testing.expectEqual(buf[0], 0x00);

    const len2 = FrameBuilder.buildStreamType(.qpack_encoder, &buf);
    try testing.expectEqual(len2, 1);
    try testing.expectEqual(buf[0], 0x02);
}

test "Connection stream state transitions" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    _ = try conn.initializeControlStreams();
    conn.state = .ready;

    // Create a request stream
    const stream_id = try conn.createRequestStream();

    // Stream should start in idle state
    const stream = conn.getStream(stream_id);
    try testing.expect(stream != null);
    try testing.expectEqual(stream.?.state, .idle);

    // Close local side
    try conn.closeStreamLocal(stream_id);
    try testing.expectEqual(conn.getStream(stream_id).?.state, .half_closed_local);

    // Close remote side
    try conn.closeStreamRemote(stream_id);
    try testing.expectEqual(conn.getStream(stream_id).?.state, .closed);
}

test "Connection activeRequestStreams" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    _ = try conn.initializeControlStreams();
    conn.state = .ready;

    // Initially no request streams
    try testing.expectEqual(conn.activeRequestStreams(), 0);

    // Create some request streams
    const s1 = try conn.createRequestStream();
    _ = try conn.createRequestStream();

    // They start as idle, so not counted as active yet
    try testing.expectEqual(conn.activeRequestStreams(), 0);

    // Mark one as open
    conn.getStream(s1).?.state = .open;
    try testing.expectEqual(conn.activeRequestStreams(), 1);
}

test "Connection registerPeerUniStream" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .server, Settings.default());
    defer conn.deinit();

    // Register peer control stream
    try conn.registerPeerUniStream(2, .control);
    try testing.expectEqual(conn.peer_control_stream_id, 2);

    // Duplicate should fail
    const result = conn.registerPeerUniStream(6, .control);
    try testing.expectError(error.DuplicateControlStream, result);

    // Register QPACK streams
    try conn.registerPeerUniStream(6, .qpack_encoder);
    try testing.expectEqual(conn.peer_qpack_encoder_stream_id, 6);
}

test "Connection bytes tracking" {
    const allocator = testing.allocator;
    var conn = Connection.init(allocator, .client, Settings.default());
    defer conn.deinit();

    _ = try conn.initializeControlStreams();
    conn.state = .ready;

    const stream_id = try conn.createRequestStream();

    // Record bytes sent
    conn.recordBytesSent(stream_id, 100);
    conn.recordBytesSent(stream_id, 50);

    try testing.expectEqual(conn.bytes_sent, 150);
    try testing.expectEqual(conn.getStream(stream_id).?.bytes_sent, 150);
}
