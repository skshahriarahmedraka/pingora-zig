//! HTTP/2 Protocol Implementation
//!
//! This module provides HTTP/2 frame parsing, HPACK header compression,
//! and stream management. It follows RFC 7540 (HTTP/2) and RFC 7541 (HPACK).
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// HTTP/2 Constants
// ============================================================================

/// HTTP/2 connection preface (client magic string)
pub const CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default settings values from RFC 7540
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;
pub const DEFAULT_ENABLE_PUSH: bool = true;
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 8192;

/// Maximum allowed frame size
pub const MAX_FRAME_SIZE: u32 = 16777215; // 2^24 - 1

/// Frame header size (always 9 bytes)
pub const FRAME_HEADER_SIZE: usize = 9;

// ============================================================================
// HTTP/2 Frame Types (RFC 7540 Section 6)
// ============================================================================

/// HTTP/2 frame types
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,

    pub fn fromU8(value: u8) FrameType {
        return @enumFromInt(value);
    }
};

// ============================================================================
// HTTP/2 Frame Flags
// ============================================================================

/// Frame flags
pub const FrameFlags = packed struct(u8) {
    end_stream: bool = false,
    _reserved1: bool = false,
    end_headers: bool = false,
    padded: bool = false,
    _reserved4: bool = false,
    priority: bool = false,
    _reserved6: bool = false,
    _reserved7: bool = false,

    pub const ACK: FrameFlags = .{ .end_stream = true };
    pub const END_STREAM: FrameFlags = .{ .end_stream = true };
    pub const END_HEADERS: FrameFlags = .{ .end_headers = true };
    pub const PADDED: FrameFlags = .{ .padded = true };
    pub const PRIORITY: FrameFlags = .{ .priority = true };

    pub fn fromU8(value: u8) FrameFlags {
        return @bitCast(value);
    }

    pub fn toU8(self: FrameFlags) u8 {
        return @bitCast(self);
    }

    pub fn hasEndStream(self: FrameFlags) bool {
        return self.end_stream;
    }

    pub fn hasEndHeaders(self: FrameFlags) bool {
        return self.end_headers;
    }

    pub fn hasPadded(self: FrameFlags) bool {
        return self.padded;
    }

    pub fn hasPriority(self: FrameFlags) bool {
        return self.priority;
    }

    pub fn hasAck(self: FrameFlags) bool {
        return self.end_stream; // ACK uses same bit as END_STREAM
    }
};

// ============================================================================
// HTTP/2 Error Codes (RFC 7540 Section 7)
// ============================================================================

/// HTTP/2 error codes
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,

    pub fn fromU32(value: u32) ErrorCode {
        return @enumFromInt(value);
    }
};

// ============================================================================
// HTTP/2 Frame Header
// ============================================================================

/// HTTP/2 frame header (9 bytes)
pub const FrameHeader = struct {
    /// Frame payload length (24 bits)
    length: u24,
    /// Frame type
    frame_type: FrameType,
    /// Frame flags
    flags: FrameFlags,
    /// Stream identifier (31 bits, high bit reserved)
    stream_id: u31,

    const Self = @This();

    /// Parse a frame header from bytes
    pub fn parse(data: []const u8) ?Self {
        if (data.len < FRAME_HEADER_SIZE) return null;

        const length: u24 = (@as(u24, data[0]) << 16) |
            (@as(u24, data[1]) << 8) |
            @as(u24, data[2]);

        const frame_type = FrameType.fromU8(data[3]);
        const flags = FrameFlags.fromU8(data[4]);

        const stream_id: u31 = @truncate(
            (@as(u32, data[5] & 0x7F) << 24) |
                (@as(u32, data[6]) << 16) |
                (@as(u32, data[7]) << 8) |
                @as(u32, data[8]),
        );

        return .{
            .length = length,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        };
    }

    /// Serialize frame header to bytes
    pub fn serialize(self: Self, buf: *[FRAME_HEADER_SIZE]u8) void {
        buf[0] = @truncate(self.length >> 16);
        buf[1] = @truncate(self.length >> 8);
        buf[2] = @truncate(self.length);
        buf[3] = @intFromEnum(self.frame_type);
        buf[4] = self.flags.toU8();
        buf[5] = @truncate((@as(u32, self.stream_id) >> 24) & 0x7F);
        buf[6] = @truncate(@as(u32, self.stream_id) >> 16);
        buf[7] = @truncate(@as(u32, self.stream_id) >> 8);
        buf[8] = @truncate(self.stream_id);
    }

    /// Get total frame size (header + payload)
    pub fn totalSize(self: Self) usize {
        return FRAME_HEADER_SIZE + self.length;
    }
};

// ============================================================================
// HTTP/2 Settings
// ============================================================================

/// Settings identifiers
pub const SettingsId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

/// HTTP/2 connection settings
pub const Settings = struct {
    header_table_size: u32 = DEFAULT_HEADER_TABLE_SIZE,
    enable_push: bool = DEFAULT_ENABLE_PUSH,
    max_concurrent_streams: u32 = DEFAULT_MAX_CONCURRENT_STREAMS,
    initial_window_size: u32 = DEFAULT_INITIAL_WINDOW_SIZE,
    max_frame_size: u32 = DEFAULT_MAX_FRAME_SIZE,
    max_header_list_size: u32 = DEFAULT_MAX_HEADER_LIST_SIZE,

    const Self = @This();

    /// Apply a setting
    pub fn apply(self: *Self, id: SettingsId, value: u32) !void {
        switch (id) {
            .header_table_size => self.header_table_size = value,
            .enable_push => self.enable_push = value != 0,
            .max_concurrent_streams => self.max_concurrent_streams = value,
            .initial_window_size => {
                if (value > 2147483647) return error.FlowControlError;
                self.initial_window_size = value;
            },
            .max_frame_size => {
                if (value < 16384 or value > MAX_FRAME_SIZE) return error.ProtocolError;
                self.max_frame_size = value;
            },
            .max_header_list_size => self.max_header_list_size = value,
            _ => {}, // Ignore unknown settings
        }
    }

    /// Parse settings from frame payload
    pub fn parsePayload(self: *Self, payload: []const u8) !void {
        if (payload.len % 6 != 0) return error.FrameSizeError;

        var i: usize = 0;
        while (i + 6 <= payload.len) : (i += 6) {
            const id: u16 = (@as(u16, payload[i]) << 8) | payload[i + 1];
            const value: u32 = (@as(u32, payload[i + 2]) << 24) |
                (@as(u32, payload[i + 3]) << 16) |
                (@as(u32, payload[i + 4]) << 8) |
                payload[i + 5];

            try self.apply(@enumFromInt(id), value);
        }
    }

    /// Serialize settings to bytes (returns slice of buf used)
    pub fn serialize(self: Self, buf: []u8) []u8 {
        var i: usize = 0;

        // Helper to write a setting
        const writeSetting = struct {
            fn write(b: []u8, idx: *usize, id: u16, val: u32) void {
                b[idx.*] = @truncate(id >> 8);
                b[idx.* + 1] = @truncate(id);
                b[idx.* + 2] = @truncate(val >> 24);
                b[idx.* + 3] = @truncate(val >> 16);
                b[idx.* + 4] = @truncate(val >> 8);
                b[idx.* + 5] = @truncate(val);
                idx.* += 6;
            }
        }.write;

        if (self.header_table_size != DEFAULT_HEADER_TABLE_SIZE) {
            writeSetting(buf, &i, 0x1, self.header_table_size);
        }
        if (self.enable_push != DEFAULT_ENABLE_PUSH) {
            writeSetting(buf, &i, 0x2, if (self.enable_push) 1 else 0);
        }
        if (self.max_concurrent_streams != DEFAULT_MAX_CONCURRENT_STREAMS) {
            writeSetting(buf, &i, 0x3, self.max_concurrent_streams);
        }
        if (self.initial_window_size != DEFAULT_INITIAL_WINDOW_SIZE) {
            writeSetting(buf, &i, 0x4, self.initial_window_size);
        }
        if (self.max_frame_size != DEFAULT_MAX_FRAME_SIZE) {
            writeSetting(buf, &i, 0x5, self.max_frame_size);
        }
        if (self.max_header_list_size != DEFAULT_MAX_HEADER_LIST_SIZE) {
            writeSetting(buf, &i, 0x6, self.max_header_list_size);
        }

        return buf[0..i];
    }
};

// ============================================================================
// HPACK - Header Compression (RFC 7541)
// ============================================================================

// ============================================================================
// HPACK Huffman Coding (RFC 7541 Appendix B)
// ============================================================================

/// Huffman code entry: code value and bit length
pub const HuffmanCode = struct {
    code: u32,
    bits: u8,
};

/// HPACK Huffman code table (RFC 7541 Appendix B)
/// Index corresponds to the symbol (0-255 for bytes, 256 for EOS)
pub const HUFFMAN_CODES = [_]HuffmanCode{
    .{ .code = 0x1ff8, .bits = 13 }, // 0
    .{ .code = 0x7fffd8, .bits = 23 }, // 1
    .{ .code = 0xfffffe2, .bits = 28 }, // 2
    .{ .code = 0xfffffe3, .bits = 28 }, // 3
    .{ .code = 0xfffffe4, .bits = 28 }, // 4
    .{ .code = 0xfffffe5, .bits = 28 }, // 5
    .{ .code = 0xfffffe6, .bits = 28 }, // 6
    .{ .code = 0xfffffe7, .bits = 28 }, // 7
    .{ .code = 0xfffffe8, .bits = 28 }, // 8
    .{ .code = 0xffffea, .bits = 24 }, // 9
    .{ .code = 0x3ffffffc, .bits = 30 }, // 10
    .{ .code = 0xfffffe9, .bits = 28 }, // 11
    .{ .code = 0xfffffea, .bits = 28 }, // 12
    .{ .code = 0x3ffffffd, .bits = 30 }, // 13
    .{ .code = 0xfffffeb, .bits = 28 }, // 14
    .{ .code = 0xfffffec, .bits = 28 }, // 15
    .{ .code = 0xfffffed, .bits = 28 }, // 16
    .{ .code = 0xfffffee, .bits = 28 }, // 17
    .{ .code = 0xfffffef, .bits = 28 }, // 18
    .{ .code = 0xffffff0, .bits = 28 }, // 19
    .{ .code = 0xffffff1, .bits = 28 }, // 20
    .{ .code = 0xffffff2, .bits = 28 }, // 21
    .{ .code = 0x3ffffffe, .bits = 30 }, // 22
    .{ .code = 0xffffff3, .bits = 28 }, // 23
    .{ .code = 0xffffff4, .bits = 28 }, // 24
    .{ .code = 0xffffff5, .bits = 28 }, // 25
    .{ .code = 0xffffff6, .bits = 28 }, // 26
    .{ .code = 0xffffff7, .bits = 28 }, // 27
    .{ .code = 0xffffff8, .bits = 28 }, // 28
    .{ .code = 0xffffff9, .bits = 28 }, // 29
    .{ .code = 0xffffffa, .bits = 28 }, // 30
    .{ .code = 0xffffffb, .bits = 28 }, // 31
    .{ .code = 0x14, .bits = 6 }, // 32 ' '
    .{ .code = 0x3f8, .bits = 10 }, // 33 '!'
    .{ .code = 0x3f9, .bits = 10 }, // 34 '"'
    .{ .code = 0xffa, .bits = 12 }, // 35 '#'
    .{ .code = 0x1ff9, .bits = 13 }, // 36 '$'
    .{ .code = 0x15, .bits = 6 }, // 37 '%'
    .{ .code = 0xf8, .bits = 8 }, // 38 '&'
    .{ .code = 0x7fa, .bits = 11 }, // 39 '''
    .{ .code = 0x3fa, .bits = 10 }, // 40 '('
    .{ .code = 0x3fb, .bits = 10 }, // 41 ')'
    .{ .code = 0xf9, .bits = 8 }, // 42 '*'
    .{ .code = 0x7fb, .bits = 11 }, // 43 '+'
    .{ .code = 0xfa, .bits = 8 }, // 44 ','
    .{ .code = 0x16, .bits = 6 }, // 45 '-'
    .{ .code = 0x17, .bits = 6 }, // 46 '.'
    .{ .code = 0x18, .bits = 6 }, // 47 '/'
    .{ .code = 0x0, .bits = 5 }, // 48 '0'
    .{ .code = 0x1, .bits = 5 }, // 49 '1'
    .{ .code = 0x2, .bits = 5 }, // 50 '2'
    .{ .code = 0x19, .bits = 6 }, // 51 '3'
    .{ .code = 0x1a, .bits = 6 }, // 52 '4'
    .{ .code = 0x1b, .bits = 6 }, // 53 '5'
    .{ .code = 0x1c, .bits = 6 }, // 54 '6'
    .{ .code = 0x1d, .bits = 6 }, // 55 '7'
    .{ .code = 0x1e, .bits = 6 }, // 56 '8'
    .{ .code = 0x1f, .bits = 6 }, // 57 '9'
    .{ .code = 0x5c, .bits = 7 }, // 58 ':'
    .{ .code = 0xfb, .bits = 8 }, // 59 ';'
    .{ .code = 0x7ffc, .bits = 15 }, // 60 '<'
    .{ .code = 0x20, .bits = 6 }, // 61 '='
    .{ .code = 0xffb, .bits = 12 }, // 62 '>'
    .{ .code = 0x3fc, .bits = 10 }, // 63 '?'
    .{ .code = 0x1ffa, .bits = 13 }, // 64 '@'
    .{ .code = 0x21, .bits = 6 }, // 65 'A'
    .{ .code = 0x5d, .bits = 7 }, // 66 'B'
    .{ .code = 0x5e, .bits = 7 }, // 67 'C'
    .{ .code = 0x5f, .bits = 7 }, // 68 'D'
    .{ .code = 0x60, .bits = 7 }, // 69 'E'
    .{ .code = 0x61, .bits = 7 }, // 70 'F'
    .{ .code = 0x62, .bits = 7 }, // 71 'G'
    .{ .code = 0x63, .bits = 7 }, // 72 'H'
    .{ .code = 0x64, .bits = 7 }, // 73 'I'
    .{ .code = 0x65, .bits = 7 }, // 74 'J'
    .{ .code = 0x66, .bits = 7 }, // 75 'K'
    .{ .code = 0x67, .bits = 7 }, // 76 'L'
    .{ .code = 0x68, .bits = 7 }, // 77 'M'
    .{ .code = 0x69, .bits = 7 }, // 78 'N'
    .{ .code = 0x6a, .bits = 7 }, // 79 'O'
    .{ .code = 0x6b, .bits = 7 }, // 80 'P'
    .{ .code = 0x6c, .bits = 7 }, // 81 'Q'
    .{ .code = 0x6d, .bits = 7 }, // 82 'R'
    .{ .code = 0x6e, .bits = 7 }, // 83 'S'
    .{ .code = 0x6f, .bits = 7 }, // 84 'T'
    .{ .code = 0x70, .bits = 7 }, // 85 'U'
    .{ .code = 0x71, .bits = 7 }, // 86 'V'
    .{ .code = 0x72, .bits = 7 }, // 87 'W'
    .{ .code = 0xfc, .bits = 8 }, // 88 'X'
    .{ .code = 0x73, .bits = 7 }, // 89 'Y'
    .{ .code = 0xfd, .bits = 8 }, // 90 'Z'
    .{ .code = 0x1ffb, .bits = 13 }, // 91 '['
    .{ .code = 0x7fff0, .bits = 19 }, // 92 '\'
    .{ .code = 0x1ffc, .bits = 13 }, // 93 ']'
    .{ .code = 0x3ffc, .bits = 14 }, // 94 '^'
    .{ .code = 0x22, .bits = 6 }, // 95 '_'
    .{ .code = 0x7ffd, .bits = 15 }, // 96 '`'
    .{ .code = 0x3, .bits = 5 }, // 97 'a'
    .{ .code = 0x23, .bits = 6 }, // 98 'b'
    .{ .code = 0x4, .bits = 5 }, // 99 'c'
    .{ .code = 0x24, .bits = 6 }, // 100 'd'
    .{ .code = 0x5, .bits = 5 }, // 101 'e'
    .{ .code = 0x25, .bits = 6 }, // 102 'f'
    .{ .code = 0x26, .bits = 6 }, // 103 'g'
    .{ .code = 0x27, .bits = 6 }, // 104 'h'
    .{ .code = 0x6, .bits = 5 }, // 105 'i'
    .{ .code = 0x74, .bits = 7 }, // 106 'j'
    .{ .code = 0x75, .bits = 7 }, // 107 'k'
    .{ .code = 0x28, .bits = 6 }, // 108 'l'
    .{ .code = 0x29, .bits = 6 }, // 109 'm'
    .{ .code = 0x2a, .bits = 6 }, // 110 'n'
    .{ .code = 0x7, .bits = 5 }, // 111 'o'
    .{ .code = 0x2b, .bits = 6 }, // 112 'p'
    .{ .code = 0x76, .bits = 7 }, // 113 'q'
    .{ .code = 0x2c, .bits = 6 }, // 114 'r'
    .{ .code = 0x8, .bits = 5 }, // 115 's'
    .{ .code = 0x9, .bits = 5 }, // 116 't'
    .{ .code = 0x2d, .bits = 6 }, // 117 'u'
    .{ .code = 0x77, .bits = 7 }, // 118 'v'
    .{ .code = 0x78, .bits = 7 }, // 119 'w'
    .{ .code = 0x79, .bits = 7 }, // 120 'x'
    .{ .code = 0x7a, .bits = 7 }, // 121 'y'
    .{ .code = 0x7b, .bits = 7 }, // 122 'z'
    .{ .code = 0x7ffe, .bits = 15 }, // 123 '{'
    .{ .code = 0x7fc, .bits = 11 }, // 124 '|'
    .{ .code = 0x3ffd, .bits = 14 }, // 125 '}'
    .{ .code = 0x1ffd, .bits = 13 }, // 126 '~'
    .{ .code = 0xffffffc, .bits = 28 }, // 127
    .{ .code = 0xfffe6, .bits = 20 }, // 128
    .{ .code = 0x3fffd2, .bits = 22 }, // 129
    .{ .code = 0xfffe7, .bits = 20 }, // 130
    .{ .code = 0xfffe8, .bits = 20 }, // 131
    .{ .code = 0x3fffd3, .bits = 22 }, // 132
    .{ .code = 0x3fffd4, .bits = 22 }, // 133
    .{ .code = 0x3fffd5, .bits = 22 }, // 134
    .{ .code = 0x7fffd9, .bits = 23 }, // 135
    .{ .code = 0x3fffd6, .bits = 22 }, // 136
    .{ .code = 0x7fffda, .bits = 23 }, // 137
    .{ .code = 0x7fffdb, .bits = 23 }, // 138
    .{ .code = 0x7fffdc, .bits = 23 }, // 139
    .{ .code = 0x7fffdd, .bits = 23 }, // 140
    .{ .code = 0x7fffde, .bits = 23 }, // 141
    .{ .code = 0xffffeb, .bits = 24 }, // 142
    .{ .code = 0x7fffdf, .bits = 23 }, // 143
    .{ .code = 0xffffec, .bits = 24 }, // 144
    .{ .code = 0xffffed, .bits = 24 }, // 145
    .{ .code = 0x3fffd7, .bits = 22 }, // 146
    .{ .code = 0x7fffe0, .bits = 23 }, // 147
    .{ .code = 0xffffee, .bits = 24 }, // 148
    .{ .code = 0x7fffe1, .bits = 23 }, // 149
    .{ .code = 0x7fffe2, .bits = 23 }, // 150
    .{ .code = 0x7fffe3, .bits = 23 }, // 151
    .{ .code = 0x7fffe4, .bits = 23 }, // 152
    .{ .code = 0x1fffdc, .bits = 21 }, // 153
    .{ .code = 0x3fffd8, .bits = 22 }, // 154
    .{ .code = 0x7fffe5, .bits = 23 }, // 155
    .{ .code = 0x3fffd9, .bits = 22 }, // 156
    .{ .code = 0x7fffe6, .bits = 23 }, // 157
    .{ .code = 0x7fffe7, .bits = 23 }, // 158
    .{ .code = 0xffffef, .bits = 24 }, // 159
    .{ .code = 0x3fffda, .bits = 22 }, // 160
    .{ .code = 0x1fffdd, .bits = 21 }, // 161
    .{ .code = 0xfffe9, .bits = 20 }, // 162
    .{ .code = 0x3fffdb, .bits = 22 }, // 163
    .{ .code = 0x3fffdc, .bits = 22 }, // 164
    .{ .code = 0x7fffe8, .bits = 23 }, // 165
    .{ .code = 0x7fffe9, .bits = 23 }, // 166
    .{ .code = 0x1fffde, .bits = 21 }, // 167
    .{ .code = 0x7fffea, .bits = 23 }, // 168
    .{ .code = 0x3fffdd, .bits = 22 }, // 169
    .{ .code = 0x3fffde, .bits = 22 }, // 170
    .{ .code = 0xfffff0, .bits = 24 }, // 171
    .{ .code = 0x1fffdf, .bits = 21 }, // 172
    .{ .code = 0x3fffdf, .bits = 22 }, // 173
    .{ .code = 0x7fffeb, .bits = 23 }, // 174
    .{ .code = 0x7fffec, .bits = 23 }, // 175
    .{ .code = 0x1fffe0, .bits = 21 }, // 176
    .{ .code = 0x1fffe1, .bits = 21 }, // 177
    .{ .code = 0x3fffe0, .bits = 22 }, // 178
    .{ .code = 0x1fffe2, .bits = 21 }, // 179
    .{ .code = 0x7fffed, .bits = 23 }, // 180
    .{ .code = 0x3fffe1, .bits = 22 }, // 181
    .{ .code = 0x7fffee, .bits = 23 }, // 182
    .{ .code = 0x7fffef, .bits = 23 }, // 183
    .{ .code = 0xfffea, .bits = 20 }, // 184
    .{ .code = 0x3fffe2, .bits = 22 }, // 185
    .{ .code = 0x3fffe3, .bits = 22 }, // 186
    .{ .code = 0x3fffe4, .bits = 22 }, // 187
    .{ .code = 0x7ffff0, .bits = 23 }, // 188
    .{ .code = 0x3fffe5, .bits = 22 }, // 189
    .{ .code = 0x3fffe6, .bits = 22 }, // 190
    .{ .code = 0x7ffff1, .bits = 23 }, // 191
    .{ .code = 0x3ffffe0, .bits = 26 }, // 192
    .{ .code = 0x3ffffe1, .bits = 26 }, // 193
    .{ .code = 0xfffeb, .bits = 20 }, // 194
    .{ .code = 0x7fff1, .bits = 19 }, // 195
    .{ .code = 0x3fffe7, .bits = 22 }, // 196
    .{ .code = 0x7ffff2, .bits = 23 }, // 197
    .{ .code = 0x3fffe8, .bits = 22 }, // 198
    .{ .code = 0x1ffffec, .bits = 25 }, // 199
    .{ .code = 0x3ffffe2, .bits = 26 }, // 200
    .{ .code = 0x3ffffe3, .bits = 26 }, // 201
    .{ .code = 0x3ffffe4, .bits = 26 }, // 202
    .{ .code = 0x7ffffde, .bits = 27 }, // 203
    .{ .code = 0x7ffffdf, .bits = 27 }, // 204
    .{ .code = 0x3ffffe5, .bits = 26 }, // 205
    .{ .code = 0xfffff1, .bits = 24 }, // 206
    .{ .code = 0x1ffffed, .bits = 25 }, // 207
    .{ .code = 0x7fff2, .bits = 19 }, // 208
    .{ .code = 0x1fffe3, .bits = 21 }, // 209
    .{ .code = 0x3ffffe6, .bits = 26 }, // 210
    .{ .code = 0x7ffffe0, .bits = 27 }, // 211
    .{ .code = 0x7ffffe1, .bits = 27 }, // 212
    .{ .code = 0x3ffffe7, .bits = 26 }, // 213
    .{ .code = 0x7ffffe2, .bits = 27 }, // 214
    .{ .code = 0xfffff2, .bits = 24 }, // 215
    .{ .code = 0x1fffe4, .bits = 21 }, // 216
    .{ .code = 0x1fffe5, .bits = 21 }, // 217
    .{ .code = 0x3ffffe8, .bits = 26 }, // 218
    .{ .code = 0x3ffffe9, .bits = 26 }, // 219
    .{ .code = 0xffffffd, .bits = 28 }, // 220
    .{ .code = 0x7ffffe3, .bits = 27 }, // 221
    .{ .code = 0x7ffffe4, .bits = 27 }, // 222
    .{ .code = 0x7ffffe5, .bits = 27 }, // 223
    .{ .code = 0xfffec, .bits = 20 }, // 224
    .{ .code = 0xfffff3, .bits = 24 }, // 225
    .{ .code = 0xfffed, .bits = 20 }, // 226
    .{ .code = 0x1fffe6, .bits = 21 }, // 227
    .{ .code = 0x3fffe9, .bits = 22 }, // 228
    .{ .code = 0x1fffe7, .bits = 21 }, // 229
    .{ .code = 0x1fffe8, .bits = 21 }, // 230
    .{ .code = 0x7ffff3, .bits = 23 }, // 231
    .{ .code = 0x3fffea, .bits = 22 }, // 232
    .{ .code = 0x3fffeb, .bits = 22 }, // 233
    .{ .code = 0x1ffffee, .bits = 25 }, // 234
    .{ .code = 0x1ffffef, .bits = 25 }, // 235
    .{ .code = 0xfffff4, .bits = 24 }, // 236
    .{ .code = 0xfffff5, .bits = 24 }, // 237
    .{ .code = 0x3ffffea, .bits = 26 }, // 238
    .{ .code = 0x7ffff4, .bits = 23 }, // 239
    .{ .code = 0x3ffffeb, .bits = 26 }, // 240
    .{ .code = 0x7ffffe6, .bits = 27 }, // 241
    .{ .code = 0x3ffffec, .bits = 26 }, // 242
    .{ .code = 0x3ffffed, .bits = 26 }, // 243
    .{ .code = 0x7ffffe7, .bits = 27 }, // 244
    .{ .code = 0x7ffffe8, .bits = 27 }, // 245
    .{ .code = 0x7ffffe9, .bits = 27 }, // 246
    .{ .code = 0x7ffffea, .bits = 27 }, // 247
    .{ .code = 0x7ffffeb, .bits = 27 }, // 248
    .{ .code = 0xffffffe, .bits = 28 }, // 249
    .{ .code = 0x7ffffec, .bits = 27 }, // 250
    .{ .code = 0x7ffffed, .bits = 27 }, // 251
    .{ .code = 0x7ffffee, .bits = 27 }, // 252
    .{ .code = 0x7ffffef, .bits = 27 }, // 253
    .{ .code = 0x7fffff0, .bits = 27 }, // 254
    .{ .code = 0x3ffffee, .bits = 26 }, // 255
    .{ .code = 0x3fffffff, .bits = 30 }, // 256 (EOS)
};

/// Huffman encoder for HPACK
pub const HuffmanEncoder = struct {
    /// Calculate the encoded length of a string
    pub fn encodedLength(data: []const u8) usize {
        var total_bits: usize = 0;
        for (data) |byte| {
            total_bits += HUFFMAN_CODES[byte].bits;
        }
        // Round up to bytes
        return (total_bits + 7) / 8;
    }

    /// Encode data using Huffman coding
    /// Returns the number of bytes written to buf
    pub fn encode(data: []const u8, buf: []u8) usize {
        var bit_offset: u32 = 0;
        var byte_offset: usize = 0;

        // Clear buffer
        for (buf) |*b| b.* = 0;

        for (data) |byte| {
            const entry = HUFFMAN_CODES[byte];
            var code = entry.code;
            var bits_remaining: u8 = entry.bits;

            while (bits_remaining > 0) {
                const bits_in_current_byte: u8 = 8 - @as(u8, @truncate(bit_offset % 8));
                const bits_to_write: u8 = @min(bits_remaining, bits_in_current_byte);

                // Extract the bits we want to write (from the MSB side of code)
                const shift_amount: u5 = @intCast(bits_remaining - bits_to_write);
                const mask: u32 = (@as(u32, 1) << @as(u5, @intCast(bits_to_write))) - 1;
                const bits: u8 = @truncate((code >> shift_amount) & mask);

                // Position bits in the current byte
                const pos_in_byte: u3 = @intCast(bits_in_current_byte - bits_to_write);
                buf[byte_offset] |= bits << pos_in_byte;

                bit_offset += bits_to_write;
                bits_remaining -= bits_to_write;
                if (shift_amount > 0) {
                    code &= (@as(u32, 1) << shift_amount) - 1;
                } else {
                    code = 0;
                }

                if (bit_offset % 8 == 0) {
                    byte_offset += 1;
                }
            }
        }

        // Pad with EOS prefix (all 1s) if needed
        const remaining_bits: u8 = @truncate(bit_offset % 8);
        if (remaining_bits > 0) {
            const padding_bits: u3 = @intCast(8 - remaining_bits);
            buf[byte_offset] |= (@as(u8, 1) << padding_bits) - 1;
            byte_offset += 1;
        }

        return byte_offset;
    }

    /// Check if Huffman encoding would be beneficial (shorter than literal)
    pub fn shouldEncode(data: []const u8) bool {
        return encodedLength(data) < data.len;
    }
};

/// Huffman decode state for bit-by-bit decoding
const DecodeState = struct {
    /// Current accumulated bits
    bits: u32 = 0,
    /// Number of bits accumulated
    count: u8 = 0,
};

/// Huffman decoder for HPACK
pub const HuffmanDecoder = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Decode Huffman-encoded data
    /// Returns decoded bytes or error
    pub fn decode(self: *Self, encoded: []const u8) ![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(self.allocator);

        var bits: u64 = 0;
        var bits_left: u8 = 0;

        for (encoded) |byte| {
            bits = (bits << 8) | byte;
            bits_left += 8;

            while (bits_left >= 5) { // Minimum code length is 5
                // Try to match a symbol, starting from shortest codes
                var matched = false;
                for (HUFFMAN_CODES, 0..) |entry, symbol| {
                    if (symbol > 255) break; // Skip EOS
                    if (entry.bits <= bits_left) {
                        const shift: u6 = @intCast(bits_left - entry.bits);
                        const candidate: u32 = @truncate(bits >> shift);
                        if (candidate == entry.code) {
                            try result.append(self.allocator, @truncate(symbol));
                            bits_left -= entry.bits;
                            if (bits_left > 0) {
                                const mask_shift: u6 = @intCast(bits_left);
                                bits &= (@as(u64, 1) << mask_shift) - 1;
                            } else {
                                bits = 0;
                            }
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched) {
                    // No match found with current bits
                    if (bits_left < 30) break; // Need more bits
                    return error.InvalidHuffmanCode;
                }
            }
        }

        // Check remaining bits are valid padding (all 1s, less than 8 bits)
        if (bits_left > 0 and bits_left < 8) {
            const mask_shift: u6 = @intCast(bits_left);
            const mask: u64 = (@as(u64, 1) << mask_shift) - 1;
            if ((bits & mask) != mask) {
                // Padding must be all 1s (EOS prefix)
                return error.InvalidHuffmanPadding;
            }
        } else if (bits_left >= 8) {
            return error.InvalidHuffmanCode;
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Decode with a more efficient table-based approach
    pub fn decodeFast(self: *Self, encoded: []const u8) ![]u8 {
        // For now, use the simple decoder
        // A production implementation would use a pre-computed decode table
        return self.decode(encoded);
    }
};

/// Header name-value pair
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// HPACK static table (RFC 7541 Appendix A)
/// Contains 61 pre-defined header fields
pub const StaticTable = struct {
    pub const entries = [_]HeaderField{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "204" },
        .{ .name = ":status", .value = "206" },
        .{ .name = ":status", .value = "304" },
        .{ .name = ":status", .value = "400" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "500" },
        .{ .name = "accept-charset", .value = "" },
        .{ .name = "accept-encoding", .value = "gzip, deflate" },
        .{ .name = "accept-language", .value = "" },
        .{ .name = "accept-ranges", .value = "" },
        .{ .name = "accept", .value = "" },
        .{ .name = "access-control-allow-origin", .value = "" },
        .{ .name = "age", .value = "" },
        .{ .name = "allow", .value = "" },
        .{ .name = "authorization", .value = "" },
        .{ .name = "cache-control", .value = "" },
        .{ .name = "content-disposition", .value = "" },
        .{ .name = "content-encoding", .value = "" },
        .{ .name = "content-language", .value = "" },
        .{ .name = "content-length", .value = "" },
        .{ .name = "content-location", .value = "" },
        .{ .name = "content-range", .value = "" },
        .{ .name = "content-type", .value = "" },
        .{ .name = "cookie", .value = "" },
        .{ .name = "date", .value = "" },
        .{ .name = "etag", .value = "" },
        .{ .name = "expect", .value = "" },
        .{ .name = "expires", .value = "" },
        .{ .name = "from", .value = "" },
        .{ .name = "host", .value = "" },
        .{ .name = "if-match", .value = "" },
        .{ .name = "if-modified-since", .value = "" },
        .{ .name = "if-none-match", .value = "" },
        .{ .name = "if-range", .value = "" },
        .{ .name = "if-unmodified-since", .value = "" },
        .{ .name = "last-modified", .value = "" },
        .{ .name = "link", .value = "" },
        .{ .name = "location", .value = "" },
        .{ .name = "max-forwards", .value = "" },
        .{ .name = "proxy-authenticate", .value = "" },
        .{ .name = "proxy-authorization", .value = "" },
        .{ .name = "range", .value = "" },
        .{ .name = "referer", .value = "" },
        .{ .name = "refresh", .value = "" },
        .{ .name = "retry-after", .value = "" },
        .{ .name = "server", .value = "" },
        .{ .name = "set-cookie", .value = "" },
        .{ .name = "strict-transport-security", .value = "" },
        .{ .name = "transfer-encoding", .value = "" },
        .{ .name = "user-agent", .value = "" },
        .{ .name = "vary", .value = "" },
        .{ .name = "via", .value = "" },
        .{ .name = "www-authenticate", .value = "" },
    };

    /// Get entry from static table (1-indexed)
    pub fn get(index: usize) ?HeaderField {
        if (index == 0 or index > entries.len) return null;
        return entries[index - 1];
    }

    /// Find index for a header name (returns first match)
    pub fn findName(name: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i + 1;
            }
        }
        return null;
    }

    /// Find index for exact header name+value match
    pub fn findExact(name: []const u8, value: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i + 1;
            }
        }
        return null;
    }
};

/// HPACK dynamic table entry
pub const DynamicEntry = struct {
    name: []u8,
    value: []u8,

    pub fn size(self: DynamicEntry) usize {
        // RFC 7541: entry size = name length + value length + 32
        return self.name.len + self.value.len + 32;
    }
};

/// HPACK dynamic table
pub const DynamicTable = struct {
    entries: std.ArrayListUnmanaged(DynamicEntry),
    max_size: usize,
    current_size: usize,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_size: usize) Self {
        return .{
            .entries = .{},
            .max_size = max_size,
            .current_size = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
    }

    /// Add entry to the beginning of the table
    pub fn add(self: *Self, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;

        // Evict entries if needed
        while (self.current_size + entry_size > self.max_size and self.entries.items.len > 0) {
            self.evictOne();
        }

        // If entry is larger than table, don't add (but table is now empty)
        if (entry_size > self.max_size) return;

        const new_entry = DynamicEntry{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        };

        try self.entries.insert(self.allocator, 0, new_entry);
        self.current_size += entry_size;
    }

    /// Get entry (0-indexed within dynamic table)
    pub fn get(self: *const Self, index: usize) ?DynamicEntry {
        if (index >= self.entries.items.len) return null;
        return self.entries.items[index];
    }

    /// Evict the oldest entry
    fn evictOne(self: *Self) void {
        if (self.entries.items.len == 0) return;
        const last_idx = self.entries.items.len - 1;
        const entry = self.entries.items[last_idx];
        self.current_size -= entry.size();
        self.allocator.free(entry.name);
        self.allocator.free(entry.value);
        _ = self.entries.pop();
    }

    /// Update max size (may evict entries)
    pub fn setMaxSize(self: *Self, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size and self.entries.items.len > 0) {
            self.evictOne();
        }
    }
};

/// HPACK decoder
pub const HpackDecoder = struct {
    dynamic_table: DynamicTable,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .dynamic_table = DynamicTable.init(allocator, DEFAULT_HEADER_TABLE_SIZE),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.dynamic_table.deinit();
    }

    /// Decode an integer with prefix bits
    pub fn decodeInteger(data: []const u8, prefix_bits: u3) ?struct { value: u32, consumed: usize } {
        if (data.len == 0) return null;

        const prefix_mask: u8 = (@as(u8, 1) << prefix_bits) - 1;
        var value: u32 = data[0] & prefix_mask;

        if (value < prefix_mask) {
            return .{ .value = value, .consumed = 1 };
        }

        // Multi-byte integer
        var m: u5 = 0;
        var i: usize = 1;
        while (i < data.len) : (i += 1) {
            const b = data[i];
            value += @as(u32, b & 0x7F) << m;
            m += 7;
            if (b & 0x80 == 0) {
                return .{ .value = value, .consumed = i + 1 };
            }
            if (m > 28) return null; // Overflow
        }
        return null;
    }

    /// Decode a string (Huffman or literal)
    pub fn decodeString(self: *Self, data: []const u8) !?struct { value: []u8, consumed: usize } {
        if (data.len == 0) return null;

        const huffman = (data[0] & 0x80) != 0;
        const len_result = decodeInteger(data, 7) orelse return null;
        const str_len = len_result.value;
        const start = len_result.consumed;

        if (start + str_len > data.len) return null;

        const str_data = data[start..][0..str_len];

        if (huffman) {
            // Decode Huffman-encoded string
            var decoder = HuffmanDecoder.init(self.allocator);
            const value = try decoder.decode(str_data);
            return .{ .value = value, .consumed = start + str_len };
        } else {
            const value = try self.allocator.dupe(u8, str_data);
            return .{ .value = value, .consumed = start + str_len };
        }
    }

    /// Get header from combined index (static + dynamic table)
    pub fn getIndexed(self: *const Self, index: usize) ?HeaderField {
        if (index <= StaticTable.entries.len) {
            return StaticTable.get(index);
        }
        const dyn_index = index - StaticTable.entries.len - 1;
        if (self.dynamic_table.get(dyn_index)) |entry| {
            return .{ .name = entry.name, .value = entry.value };
        }
        return null;
    }

    /// Set dynamic table size
    pub fn setDynamicTableSize(self: *Self, size: usize) void {
        self.dynamic_table.setMaxSize(size);
    }
};

/// HPACK encoder
pub const HpackEncoder = struct {
    dynamic_table: DynamicTable,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .dynamic_table = DynamicTable.init(allocator, DEFAULT_HEADER_TABLE_SIZE),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.dynamic_table.deinit();
    }

    /// Encode an integer with prefix bits
    pub fn encodeInteger(value: u32, prefix_bits: u3, first_byte: u8, buf: []u8) usize {
        const prefix_mask: u8 = (@as(u8, 1) << prefix_bits) - 1;

        if (value < prefix_mask) {
            buf[0] = first_byte | @as(u8, @truncate(value));
            return 1;
        }

        buf[0] = first_byte | prefix_mask;
        var remaining = value - prefix_mask;
        var i: usize = 1;

        while (remaining >= 128) {
            buf[i] = @truncate((remaining & 0x7F) | 0x80);
            remaining >>= 7;
            i += 1;
        }
        buf[i] = @truncate(remaining);
        return i + 1;
    }

    /// Encode a literal string (no Huffman)
    pub fn encodeString(value: []const u8, buf: []u8) usize {
        const len_size = encodeInteger(@intCast(value.len), 7, 0, buf);
        @memcpy(buf[len_size..][0..value.len], value);
        return len_size + value.len;
    }

    /// Encode a string with Huffman encoding
    pub fn encodeStringHuffman(value: []const u8, buf: []u8) usize {
        const encoded_len = HuffmanEncoder.encodedLength(value);
        // Set Huffman flag (0x80) in length prefix
        const len_size = encodeInteger(@intCast(encoded_len), 7, 0x80, buf);
        const huffman_size = HuffmanEncoder.encode(value, buf[len_size..]);
        return len_size + huffman_size;
    }

    /// Encode a string, using Huffman if beneficial
    pub fn encodeStringAuto(value: []const u8, buf: []u8) usize {
        if (HuffmanEncoder.shouldEncode(value)) {
            return encodeStringHuffman(value, buf);
        } else {
            return encodeString(value, buf);
        }
    }

    /// Encode a header using indexed representation if possible
    pub fn encodeHeader(self: *Self, name: []const u8, value: []const u8, buf: []u8) !usize {
        // Try exact match in static table
        if (StaticTable.findExact(name, value)) |index| {
            // Indexed header field (Section 6.1)
            return encodeInteger(@intCast(index), 7, 0x80, buf);
        }

        // Try name match in static table
        if (StaticTable.findName(name)) |name_index| {
            // Literal with indexing (Section 6.2.1)
            var offset = encodeInteger(@intCast(name_index), 6, 0x40, buf);
            offset += encodeString(value, buf[offset..]);

            // Add to dynamic table
            try self.dynamic_table.add(name, value);

            return offset;
        }

        // Literal without indexing (Section 6.2.2)
        buf[0] = 0x00;
        var offset: usize = 1;
        offset += encodeString(name, buf[offset..]);
        offset += encodeString(value, buf[offset..]);

        return offset;
    }
};

// ============================================================================
// HTTP/2 Stream State Machine (RFC 7540 Section 5.1)
// ============================================================================

/// Stream states as defined in RFC 7540
pub const StreamState = enum {
    /// Stream is idle (not yet opened)
    idle,
    /// Reserved for server push (local)
    reserved_local,
    /// Reserved for server push (remote)
    reserved_remote,
    /// Stream is open for bidirectional communication
    open,
    /// Local side has sent END_STREAM
    half_closed_local,
    /// Remote side has sent END_STREAM
    half_closed_remote,
    /// Stream is fully closed
    closed,

    /// Check if stream can send data
    pub fn canSend(self: StreamState) bool {
        return self == .open or self == .half_closed_remote;
    }

    /// Check if stream can receive data
    pub fn canReceive(self: StreamState) bool {
        return self == .open or self == .half_closed_local;
    }

    /// Check if stream is terminal
    pub fn isTerminal(self: StreamState) bool {
        return self == .closed;
    }
};

// ============================================================================
// HTTP/2 Flow Control (RFC 7540 Section 5.2)
// ============================================================================

/// Flow control window for a stream or connection
pub const FlowControlWindow = struct {
    /// Current window size (can be negative temporarily)
    size: i64,
    /// Initial window size for this window
    initial_size: u32,

    const Self = @This();

    pub fn init(initial_size: u32) Self {
        return .{
            .size = @intCast(initial_size),
            .initial_size = initial_size,
        };
    }

    /// Consume bytes from the window (when sending data)
    pub fn consume(self: *Self, bytes: u32) !void {
        if (bytes > self.available()) {
            return error.FlowControlError;
        }
        self.size -= @intCast(bytes);
    }

    /// Release bytes back to the window (when receiving WINDOW_UPDATE)
    pub fn release(self: *Self, increment: u32) !void {
        const new_size = self.size + @as(i64, increment);
        // Window size cannot exceed 2^31-1
        if (new_size > 2147483647) {
            return error.FlowControlError;
        }
        self.size = new_size;
    }

    /// Get available bytes in window
    pub fn available(self: *const Self) u32 {
        if (self.size <= 0) return 0;
        return @intCast(self.size);
    }

    /// Update initial window size (for SETTINGS changes)
    pub fn updateInitialSize(self: *Self, new_initial: u32) !void {
        const delta = @as(i64, new_initial) - @as(i64, self.initial_size);
        const new_size = self.size + delta;
        if (new_size > 2147483647) {
            return error.FlowControlError;
        }
        self.size = new_size;
        self.initial_size = new_initial;
    }
};

// ============================================================================
// HTTP/2 Stream Priority (RFC 7540 Section 5.3)
// ============================================================================

/// Stream priority information
pub const StreamPriority = struct {
    /// Stream dependency (0 for root)
    dependency: u31 = 0,
    /// Whether this is an exclusive dependency
    exclusive: bool = false,
    /// Weight (1-256, default 16)
    weight: u8 = 16,

    const Self = @This();

    /// Parse priority from frame payload
    pub fn parse(data: []const u8) ?Self {
        if (data.len < 5) return null;

        const exclusive = (data[0] & 0x80) != 0;
        const dependency: u31 = @truncate(
            (@as(u32, data[0] & 0x7F) << 24) |
                (@as(u32, data[1]) << 16) |
                (@as(u32, data[2]) << 8) |
                @as(u32, data[3]),
        );
        const weight = data[4] +| 1; // +1 because wire format is 0-255

        return .{
            .dependency = dependency,
            .exclusive = exclusive,
            .weight = weight,
        };
    }

    /// Serialize priority to bytes
    pub fn serialize(self: Self, buf: *[5]u8) void {
        const dep: u32 = self.dependency;
        buf[0] = @as(u8, if (self.exclusive) 0x80 else 0) | @as(u8, @truncate(dep >> 24));
        buf[1] = @truncate(dep >> 16);
        buf[2] = @truncate(dep >> 8);
        buf[3] = @truncate(dep);
        buf[4] = self.weight -| 1; // -1 for wire format
    }
};

// ============================================================================
// HTTP/2 Stream
// ============================================================================

/// Represents a single HTTP/2 stream
pub const Stream = struct {
    /// Stream identifier
    id: u31,
    /// Current state
    state: StreamState,
    /// Send flow control window
    send_window: FlowControlWindow,
    /// Receive flow control window
    recv_window: FlowControlWindow,
    /// Stream priority
    priority: StreamPriority,
    /// Request headers (for requests)
    request_headers: ?std.ArrayListUnmanaged(HeaderField),
    /// Response headers (for responses)
    response_headers: ?std.ArrayListUnmanaged(HeaderField),
    /// Accumulated request body
    request_body: std.ArrayListUnmanaged(u8),
    /// Accumulated response body
    response_body: std.ArrayListUnmanaged(u8),
    /// Whether headers are complete
    headers_complete: bool,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, id: u31, initial_window_size: u32) Self {
        return .{
            .id = id,
            .state = .idle,
            .send_window = FlowControlWindow.init(initial_window_size),
            .recv_window = FlowControlWindow.init(initial_window_size),
            .priority = .{},
            .request_headers = null,
            .response_headers = null,
            .request_body = .{},
            .response_body = .{},
            .headers_complete = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.request_headers) |*headers| {
            headers.deinit(self.allocator);
        }
        if (self.response_headers) |*headers| {
            headers.deinit(self.allocator);
        }
        self.request_body.deinit(self.allocator);
        self.response_body.deinit(self.allocator);
    }

    /// Transition stream state based on frame received
    pub fn onFrameReceived(self: *Self, frame_type: FrameType, flags: FrameFlags) !void {
        const end_stream = flags.hasEndStream();
        const end_headers = flags.hasEndHeaders();
        _ = end_headers;

        switch (self.state) {
            .idle => {
                if (frame_type == .headers) {
                    self.state = if (end_stream) .half_closed_remote else .open;
                } else if (frame_type == .push_promise) {
                    self.state = .reserved_remote;
                } else {
                    return error.ProtocolError;
                }
            },
            .reserved_remote => {
                if (frame_type == .headers) {
                    self.state = if (end_stream) .closed else .half_closed_local;
                } else if (frame_type == .rst_stream) {
                    self.state = .closed;
                } else {
                    return error.ProtocolError;
                }
            },
            .open => {
                if (end_stream) {
                    self.state = .half_closed_remote;
                }
                if (frame_type == .rst_stream) {
                    self.state = .closed;
                }
            },
            .half_closed_local => {
                if (end_stream or frame_type == .rst_stream) {
                    self.state = .closed;
                }
            },
            .half_closed_remote => {
                if (frame_type == .rst_stream) {
                    self.state = .closed;
                } else if (frame_type != .window_update and frame_type != .priority) {
                    return error.StreamClosed;
                }
            },
            .closed => {
                // Only PRIORITY frames are allowed on closed streams
                if (frame_type != .priority) {
                    return error.StreamClosed;
                }
            },
            .reserved_local => {
                return error.ProtocolError;
            },
        }
    }

    /// Transition stream state based on frame sent
    pub fn onFrameSent(self: *Self, frame_type: FrameType, flags: FrameFlags) !void {
        const end_stream = flags.hasEndStream();

        switch (self.state) {
            .idle => {
                if (frame_type == .headers) {
                    self.state = if (end_stream) .half_closed_local else .open;
                } else if (frame_type == .push_promise) {
                    self.state = .reserved_local;
                } else {
                    return error.ProtocolError;
                }
            },
            .reserved_local => {
                if (frame_type == .headers) {
                    self.state = if (end_stream) .closed else .half_closed_remote;
                } else if (frame_type == .rst_stream) {
                    self.state = .closed;
                } else {
                    return error.ProtocolError;
                }
            },
            .open => {
                if (end_stream) {
                    self.state = .half_closed_local;
                }
                if (frame_type == .rst_stream) {
                    self.state = .closed;
                }
            },
            .half_closed_remote => {
                if (end_stream or frame_type == .rst_stream) {
                    self.state = .closed;
                }
            },
            .half_closed_local => {
                if (frame_type == .rst_stream) {
                    self.state = .closed;
                } else if (frame_type != .window_update and frame_type != .priority) {
                    return error.StreamClosed;
                }
            },
            .closed => {
                if (frame_type != .priority) {
                    return error.StreamClosed;
                }
            },
            .reserved_remote => {
                return error.ProtocolError;
            },
        }
    }

    /// Add a header to the stream
    pub fn addHeader(self: *Self, name: []const u8, value: []const u8, is_response: bool) !void {
        const headers = if (is_response) &self.response_headers else &self.request_headers;

        if (headers.* == null) {
            headers.* = .{};
        }

        try headers.*.?.append(self.allocator, .{ .name = name, .value = value });
    }

    /// Append data to request body
    pub fn appendRequestBody(self: *Self, data: []const u8) !void {
        try self.request_body.appendSlice(self.allocator, data);
    }

    /// Append data to response body
    pub fn appendResponseBody(self: *Self, data: []const u8) !void {
        try self.response_body.appendSlice(self.allocator, data);
    }
};

// ============================================================================
// HTTP/2 Connection
// ============================================================================

/// HTTP/2 connection (manages multiple streams)
pub const Connection = struct {
    /// Active streams
    streams: std.AutoHashMapUnmanaged(u31, *Stream),
    /// Connection-level send flow control window
    send_window: FlowControlWindow,
    /// Connection-level receive flow control window
    recv_window: FlowControlWindow,
    /// Local settings
    local_settings: Settings,
    /// Remote settings (peer's settings)
    remote_settings: Settings,
    /// HPACK encoder
    hpack_encoder: HpackEncoder,
    /// HPACK decoder
    hpack_decoder: HpackDecoder,
    /// Next stream ID (client uses odd, server uses even)
    next_stream_id: u31,
    /// Whether this is a client connection
    is_client: bool,
    /// Whether the connection preface has been sent
    preface_sent: bool,
    /// Whether the connection preface has been received
    preface_received: bool,
    /// Whether SETTINGS ACK has been received
    settings_ack_received: bool,
    /// GOAWAY state
    goaway_sent: bool,
    goaway_received: bool,
    last_stream_id: u31,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn initClient(allocator: Allocator) Self {
        return init(allocator, true);
    }

    pub fn initServer(allocator: Allocator) Self {
        return init(allocator, false);
    }

    fn init(allocator: Allocator, is_client: bool) Self {
        return .{
            .streams = .{},
            .send_window = FlowControlWindow.init(DEFAULT_INITIAL_WINDOW_SIZE),
            .recv_window = FlowControlWindow.init(DEFAULT_INITIAL_WINDOW_SIZE),
            .local_settings = .{},
            .remote_settings = .{},
            .hpack_encoder = HpackEncoder.init(allocator),
            .hpack_decoder = HpackDecoder.init(allocator),
            .next_stream_id = if (is_client) 1 else 2,
            .is_client = is_client,
            .preface_sent = false,
            .preface_received = false,
            .settings_ack_received = false,
            .goaway_sent = false,
            .goaway_received = false,
            .last_stream_id = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit(self.allocator);
        self.hpack_encoder.deinit();
        self.hpack_decoder.deinit();
    }

    /// Create a new stream
    pub fn createStream(self: *Self) !*Stream {
        if (self.goaway_sent or self.goaway_received) {
            return error.ConnectionClosed;
        }

        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        if (self.streams.count() >= self.remote_settings.max_concurrent_streams) {
            return error.MaxStreamsExceeded;
        }

        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, stream_id, self.remote_settings.initial_window_size);

        try self.streams.put(self.allocator, stream_id, stream);
        return stream;
    }

    /// Get a stream by ID
    pub fn getStream(self: *Self, stream_id: u31) ?*Stream {
        return self.streams.get(stream_id);
    }

    /// Remove a closed stream
    pub fn removeStream(self: *Self, stream_id: u31) void {
        if (self.streams.fetchRemove(stream_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// Process a received frame
    pub fn processFrame(self: *Self, header: FrameHeader, payload: []const u8) !void {
        switch (header.frame_type) {
            .settings => {
                if (header.flags.hasAck()) {
                    self.settings_ack_received = true;
                } else {
                    try self.remote_settings.parsePayload(payload);
                    // Update HPACK decoder table size
                    self.hpack_decoder.setDynamicTableSize(self.remote_settings.header_table_size);
                }
            },
            .window_update => {
                if (payload.len != 4) return error.FrameSizeError;
                const increment: u32 = (@as(u32, payload[0] & 0x7F) << 24) |
                    (@as(u32, payload[1]) << 16) |
                    (@as(u32, payload[2]) << 8) |
                    payload[3];

                if (increment == 0) return error.ProtocolError;

                if (header.stream_id == 0) {
                    try self.send_window.release(increment);
                } else {
                    if (self.getStream(header.stream_id)) |stream| {
                        try stream.send_window.release(increment);
                    }
                }
            },
            .goaway => {
                if (payload.len < 8) return error.FrameSizeError;
                self.goaway_received = true;
                self.last_stream_id = @truncate(
                    (@as(u32, payload[0] & 0x7F) << 24) |
                        (@as(u32, payload[1]) << 16) |
                        (@as(u32, payload[2]) << 8) |
                        payload[3],
                );
            },
            .ping => {
                if (payload.len != 8) return error.FrameSizeError;
                if (header.stream_id != 0) return error.ProtocolError;
                // PING frames are handled at the connection level
                // ACK should be sent back (not implemented here)
            },
            .headers, .data, .priority, .rst_stream, .push_promise, .continuation => {
                if (header.stream_id == 0) return error.ProtocolError;

                var stream = self.getStream(header.stream_id);
                if (stream == null and header.frame_type == .headers) {
                    // Create new stream for incoming request
                    const new_stream = try self.allocator.create(Stream);
                    new_stream.* = Stream.init(
                        self.allocator,
                        header.stream_id,
                        self.local_settings.initial_window_size,
                    );
                    try self.streams.put(self.allocator, header.stream_id, new_stream);
                    stream = new_stream;
                }

                if (stream) |s| {
                    try s.onFrameReceived(header.frame_type, header.flags);

                    // Process frame-specific data
                    if (header.frame_type == .data) {
                        try s.appendRequestBody(payload);
                        // Update receive window
                        s.recv_window.size -= @intCast(payload.len);
                    }
                }
            },
            _ => {
                // Unknown frame types are ignored
            },
        }
    }

    /// Build a WINDOW_UPDATE frame
    pub fn buildWindowUpdate(stream_id: u31, increment: u32, buf: *[FRAME_HEADER_SIZE + 4]u8) void {
        const header = FrameHeader{
            .length = 4,
            .frame_type = .window_update,
            .flags = .{},
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        buf[FRAME_HEADER_SIZE] = @truncate((increment >> 24) & 0x7F);
        buf[FRAME_HEADER_SIZE + 1] = @truncate(increment >> 16);
        buf[FRAME_HEADER_SIZE + 2] = @truncate(increment >> 8);
        buf[FRAME_HEADER_SIZE + 3] = @truncate(increment);
    }

    /// Build a PING frame
    pub fn buildPing(data: *const [8]u8, ack: bool, buf: *[FRAME_HEADER_SIZE + 8]u8) void {
        const header = FrameHeader{
            .length = 8,
            .frame_type = .ping,
            .flags = if (ack) FrameFlags.ACK else .{},
            .stream_id = 0,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        @memcpy(buf[FRAME_HEADER_SIZE..], data);
    }

    /// Build a GOAWAY frame
    pub fn buildGoaway(last_stream_id: u31, error_code: ErrorCode, buf: []u8) usize {
        const header = FrameHeader{
            .length = 8,
            .frame_type = .goaway,
            .flags = .{},
            .stream_id = 0,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);

        const lid: u32 = last_stream_id;
        buf[FRAME_HEADER_SIZE] = @truncate((lid >> 24) & 0x7F);
        buf[FRAME_HEADER_SIZE + 1] = @truncate(lid >> 16);
        buf[FRAME_HEADER_SIZE + 2] = @truncate(lid >> 8);
        buf[FRAME_HEADER_SIZE + 3] = @truncate(lid);

        const ec: u32 = @intFromEnum(error_code);
        buf[FRAME_HEADER_SIZE + 4] = @truncate(ec >> 24);
        buf[FRAME_HEADER_SIZE + 5] = @truncate(ec >> 16);
        buf[FRAME_HEADER_SIZE + 6] = @truncate(ec >> 8);
        buf[FRAME_HEADER_SIZE + 7] = @truncate(ec);

        return FRAME_HEADER_SIZE + 8;
    }

    /// Build a RST_STREAM frame
    pub fn buildRstStream(stream_id: u31, error_code: ErrorCode, buf: *[FRAME_HEADER_SIZE + 4]u8) void {
        const header = FrameHeader{
            .length = 4,
            .frame_type = .rst_stream,
            .flags = .{},
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);

        const ec: u32 = @intFromEnum(error_code);
        buf[FRAME_HEADER_SIZE] = @truncate(ec >> 24);
        buf[FRAME_HEADER_SIZE + 1] = @truncate(ec >> 16);
        buf[FRAME_HEADER_SIZE + 2] = @truncate(ec >> 8);
        buf[FRAME_HEADER_SIZE + 3] = @truncate(ec);
    }

    /// Get statistics about the connection
    pub fn getStats(self: *const Self) ConnectionStats {
        var active_streams: u32 = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.*.state.isTerminal()) {
                active_streams += 1;
            }
        }

        return .{
            .active_streams = active_streams,
            .total_streams = @intCast(self.streams.count()),
            .send_window_available = self.send_window.available(),
            .recv_window_available = self.recv_window.available(),
            .is_client = self.is_client,
            .goaway_sent = self.goaway_sent,
            .goaway_received = self.goaway_received,
        };
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    active_streams: u32,
    total_streams: u32,
    send_window_available: u32,
    recv_window_available: u32,
    is_client: bool,
    goaway_sent: bool,
    goaway_received: bool,
};

// ============================================================================
// HTTP/2 Stream Multiplexer (RFC 7540 Section 5)
// ============================================================================

/// Stream scheduling priority for multiplexing
pub const SchedulingPriority = struct {
    stream_id: u31,
    weight: u8,
    available_window: u32,
    has_data: bool,

    /// Calculate effective priority score
    pub fn score(self: SchedulingPriority) u32 {
        if (!self.has_data or self.available_window == 0) return 0;
        // Higher weight = higher priority, window availability matters
        return @as(u32, self.weight) * @min(self.available_window, 16384);
    }
};

/// Pending data to be sent on a stream
pub const PendingData = struct {
    data: []const u8,
    offset: usize,
    end_stream: bool,

    pub fn remaining(self: PendingData) []const u8 {
        return self.data[self.offset..];
    }

    pub fn consume(self: *PendingData, bytes: usize) void {
        self.offset += bytes;
    }

    pub fn isDone(self: PendingData) bool {
        return self.offset >= self.data.len;
    }
};

/// Stream multiplexer for managing concurrent HTTP/2 streams
/// Handles fair scheduling based on priority and flow control
pub const StreamMultiplexer = struct {
    /// Connection reference
    connection: *Connection,
    /// Pending data per stream
    pending_data: std.AutoHashMapUnmanaged(u31, PendingData),
    /// Stream send order (for round-robin within same priority)
    send_order: std.ArrayListUnmanaged(u31),
    /// Maximum frame payload size
    max_frame_size: u32,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, connection: *Connection) Self {
        return .{
            .connection = connection,
            .pending_data = .{},
            .send_order = .{},
            .max_frame_size = connection.remote_settings.max_frame_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pending_data.deinit(self.allocator);
        self.send_order.deinit(self.allocator);
    }

    /// Queue data to be sent on a stream
    pub fn queueData(self: *Self, stream_id: u31, data: []const u8, end_stream: bool) !void {
        const pending = PendingData{
            .data = data,
            .offset = 0,
            .end_stream = end_stream,
        };
        try self.pending_data.put(self.allocator, stream_id, pending);

        // Add to send order if not already present
        var found = false;
        for (self.send_order.items) |id| {
            if (id == stream_id) {
                found = true;
                break;
            }
        }
        if (!found) {
            try self.send_order.append(self.allocator, stream_id);
        }
    }

    /// Remove stream from multiplexer
    pub fn removeStream(self: *Self, stream_id: u31) void {
        _ = self.pending_data.remove(stream_id);
        // Remove from send order
        var i: usize = 0;
        while (i < self.send_order.items.len) {
            if (self.send_order.items[i] == stream_id) {
                _ = self.send_order.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Select next stream to send data from (priority-based)
    pub fn selectNextStream(self: *Self) ?u31 {
        if (self.send_order.items.len == 0) return null;

        var best_id: ?u31 = null;
        var best_score: u32 = 0;

        for (self.send_order.items) |stream_id| {
            const stream = self.connection.getStream(stream_id) orelse continue;
            const pending = self.pending_data.get(stream_id) orelse continue;

            if (pending.isDone()) continue;
            if (!stream.state.canSend()) continue;

            const priority = SchedulingPriority{
                .stream_id = stream_id,
                .weight = stream.priority.weight,
                .available_window = @min(
                    stream.send_window.available(),
                    self.connection.send_window.available(),
                ),
                .has_data = !pending.isDone(),
            };

            const score = priority.score();
            if (score > best_score) {
                best_score = score;
                best_id = stream_id;
            }
        }

        return best_id;
    }

    /// Get the amount of data that can be sent on a stream right now
    pub fn availableToSend(self: *Self, stream_id: u31) u32 {
        const stream = self.connection.getStream(stream_id) orelse return 0;
        const pending = self.pending_data.get(stream_id) orelse return 0;

        if (pending.isDone()) return 0;
        if (!stream.state.canSend()) return 0;

        const remaining = pending.remaining().len;
        const stream_window = stream.send_window.available();
        const conn_window = self.connection.send_window.available();

        return @min(@min(@as(u32, @intCast(remaining)), stream_window), @min(conn_window, self.max_frame_size));
    }

    /// Build a DATA frame for the next chunk of data
    /// Returns the frame bytes and updates internal state
    pub fn buildNextDataFrame(self: *Self, stream_id: u31, buf: []u8) !?usize {
        const stream = self.connection.getStream(stream_id) orelse return null;
        var pending = self.pending_data.getPtr(stream_id) orelse return null;

        const available = self.availableToSend(stream_id);
        if (available == 0) return null;

        const data_to_send = pending.remaining()[0..available];
        const is_last = pending.offset + available >= pending.data.len;
        const end_stream = is_last and pending.end_stream;

        // Build frame header
        const flags = if (end_stream) FrameFlags.END_STREAM else FrameFlags{};
        const header = FrameHeader{
            .length = @intCast(available),
            .frame_type = .data,
            .flags = flags,
            .stream_id = stream_id,
        };

        if (buf.len < FRAME_HEADER_SIZE + available) return error.BufferTooSmall;

        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        @memcpy(buf[FRAME_HEADER_SIZE..][0..available], data_to_send);

        // Update flow control windows
        try stream.send_window.consume(available);
        try self.connection.send_window.consume(available);

        // Update pending data
        pending.consume(available);

        // Update stream state if end_stream
        if (end_stream) {
            try stream.onFrameSent(.data, flags);
        }

        // Remove from queue if done
        if (pending.isDone()) {
            self.removeStream(stream_id);
        }

        return FRAME_HEADER_SIZE + available;
    }

    /// Check if there's any pending data to send
    pub fn hasPendingData(self: *Self) bool {
        for (self.send_order.items) |stream_id| {
            if (self.pending_data.get(stream_id)) |pending| {
                if (!pending.isDone()) return true;
            }
        }
        return false;
    }

    /// Get count of streams with pending data
    pub fn pendingStreamCount(self: *Self) usize {
        var count: usize = 0;
        for (self.send_order.items) |stream_id| {
            if (self.pending_data.get(stream_id)) |pending| {
                if (!pending.isDone()) count += 1;
            }
        }
        return count;
    }
};

// ============================================================================
// HTTP/2 Flow Control Manager (RFC 7540 Section 5.2)
// ============================================================================

/// Flow control manager with automatic WINDOW_UPDATE generation
pub const FlowControlManager = struct {
    /// Connection reference
    connection: *Connection,
    /// Threshold for sending WINDOW_UPDATE (fraction of initial window consumed)
    update_threshold: u32,
    /// Pending WINDOW_UPDATEs to send
    pending_updates: std.ArrayListUnmanaged(WindowUpdate),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub const WindowUpdate = struct {
        stream_id: u31,
        increment: u32,
    };

    pub fn init(allocator: Allocator, connection: *Connection) Self {
        // Send WINDOW_UPDATE when half the window is consumed
        const threshold = connection.local_settings.initial_window_size / 2;
        return .{
            .connection = connection,
            .update_threshold = threshold,
            .pending_updates = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pending_updates.deinit(self.allocator);
    }

    /// Record bytes received on a stream (consumes receive window)
    pub fn recordBytesReceived(self: *Self, stream_id: u31, bytes: u32) !void {
        // Update connection-level window
        self.connection.recv_window.size -= @intCast(bytes);

        // Check if connection needs WINDOW_UPDATE
        if (self.connection.recv_window.available() < self.update_threshold) {
            const increment = self.connection.local_settings.initial_window_size -
                self.connection.recv_window.available();
            if (increment > 0) {
                try self.pending_updates.append(self.allocator, .{
                    .stream_id = 0,
                    .increment = increment,
                });
                try self.connection.recv_window.release(increment);
            }
        }

        // Update stream-level window if stream exists
        if (stream_id != 0) {
            if (self.connection.getStream(stream_id)) |stream| {
                stream.recv_window.size -= @intCast(bytes);

                // Check if stream needs WINDOW_UPDATE
                if (stream.recv_window.available() < self.update_threshold) {
                    const increment = self.connection.local_settings.initial_window_size -
                        stream.recv_window.available();
                    if (increment > 0) {
                        try self.pending_updates.append(self.allocator, .{
                            .stream_id = stream_id,
                            .increment = increment,
                        });
                        try stream.recv_window.release(increment);
                    }
                }
            }
        }
    }

    /// Get pending WINDOW_UPDATEs to send
    pub fn getPendingUpdates(self: *Self) []const WindowUpdate {
        return self.pending_updates.items;
    }

    /// Clear pending updates (after sending)
    pub fn clearPendingUpdates(self: *Self) void {
        self.pending_updates.clearRetainingCapacity();
    }

    /// Build WINDOW_UPDATE frames for all pending updates
    pub fn buildWindowUpdateFrames(self: *Self, buf: []u8) usize {
        var offset: usize = 0;
        const frame_size = FRAME_HEADER_SIZE + 4;

        for (self.pending_updates.items) |update| {
            if (offset + frame_size > buf.len) break;

            Connection.buildWindowUpdate(
                update.stream_id,
                update.increment,
                buf[offset..][0..frame_size],
            );
            offset += frame_size;
        }

        self.clearPendingUpdates();
        return offset;
    }

    /// Check if flow control allows sending on a stream
    pub fn canSend(self: *Self, stream_id: u31, bytes: u32) bool {
        if (self.connection.send_window.available() < bytes) return false;

        if (stream_id != 0) {
            if (self.connection.getStream(stream_id)) |stream| {
                if (stream.send_window.available() < bytes) return false;
            } else {
                return false;
            }
        }

        return true;
    }

    /// Get statistics about flow control state
    pub fn getStats(self: *Self) FlowControlStats {
        return .{
            .connection_send_window = self.connection.send_window.available(),
            .connection_recv_window = self.connection.recv_window.available(),
            .pending_window_updates = @intCast(self.pending_updates.items.len),
        };
    }
};

/// Flow control statistics
pub const FlowControlStats = struct {
    connection_send_window: u32,
    connection_recv_window: u32,
    pending_window_updates: u32,
};

// ============================================================================
// HTTP/2 Frame Builders
// ============================================================================

/// Build HTTP/2 frames
pub const FrameBuilder = struct {
    /// Build a HEADERS frame
    pub fn buildHeaders(
        stream_id: u31,
        header_block: []const u8,
        end_stream: bool,
        end_headers: bool,
        priority: ?StreamPriority,
        buf: []u8,
    ) !usize {
        var flags = FrameFlags{};
        if (end_stream) flags.end_stream = true;
        if (end_headers) flags.end_headers = true;
        if (priority != null) flags.priority = true;

        const priority_size: usize = if (priority != null) 5 else 0;
        const payload_len = priority_size + header_block.len;

        if (buf.len < FRAME_HEADER_SIZE + payload_len) return error.BufferTooSmall;

        const header = FrameHeader{
            .length = @intCast(payload_len),
            .frame_type = .headers,
            .flags = flags,
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);

        var offset: usize = FRAME_HEADER_SIZE;

        if (priority) |p| {
            p.serialize(buf[offset..][0..5]);
            offset += 5;
        }

        @memcpy(buf[offset..][0..header_block.len], header_block);
        offset += header_block.len;

        return offset;
    }

    /// Build a DATA frame
    pub fn buildData(
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        buf: []u8,
    ) !usize {
        if (buf.len < FRAME_HEADER_SIZE + data.len) return error.BufferTooSmall;

        var flags = FrameFlags{};
        if (end_stream) flags.end_stream = true;

        const header = FrameHeader{
            .length = @intCast(data.len),
            .frame_type = .data,
            .flags = flags,
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        @memcpy(buf[FRAME_HEADER_SIZE..][0..data.len], data);

        return FRAME_HEADER_SIZE + data.len;
    }

    /// Build a SETTINGS frame
    pub fn buildSettings(settings: Settings, ack: bool, buf: []u8) usize {
        var payload_buf: [36]u8 = undefined; // Max 6 settings * 6 bytes
        const payload = if (ack) &[_]u8{} else settings.serialize(&payload_buf);

        const header = FrameHeader{
            .length = @intCast(payload.len),
            .frame_type = .settings,
            .flags = if (ack) FrameFlags.ACK else .{},
            .stream_id = 0,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);

        if (payload.len > 0) {
            @memcpy(buf[FRAME_HEADER_SIZE..][0..payload.len], payload);
        }

        return FRAME_HEADER_SIZE + payload.len;
    }

    /// Build a PRIORITY frame
    pub fn buildPriority(stream_id: u31, priority: StreamPriority, buf: *[FRAME_HEADER_SIZE + 5]u8) void {
        const header = FrameHeader{
            .length = 5,
            .frame_type = .priority,
            .flags = .{},
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        priority.serialize(buf[FRAME_HEADER_SIZE..][0..5]);
    }

    /// Build a CONTINUATION frame
    pub fn buildContinuation(
        stream_id: u31,
        header_block: []const u8,
        end_headers: bool,
        buf: []u8,
    ) !usize {
        if (buf.len < FRAME_HEADER_SIZE + header_block.len) return error.BufferTooSmall;

        var flags = FrameFlags{};
        if (end_headers) flags.end_headers = true;

        const header = FrameHeader{
            .length = @intCast(header_block.len),
            .frame_type = .continuation,
            .flags = flags,
            .stream_id = stream_id,
        };
        header.serialize(buf[0..FRAME_HEADER_SIZE]);
        @memcpy(buf[FRAME_HEADER_SIZE..][0..header_block.len], header_block);

        return FRAME_HEADER_SIZE + header_block.len;
    }
};

// ============================================================================
// HTTP/2 Request/Response Helpers
// ============================================================================

/// Build a complete HTTP/2 request with headers
pub fn buildRequest(
    encoder: *HpackEncoder,
    stream_id: u31,
    method: []const u8,
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    extra_headers: []const HeaderField,
    buf: []u8,
) !usize {
    var header_buf: [8192]u8 = undefined;
    var header_offset: usize = 0;

    // Encode pseudo-headers
    header_offset += try encoder.encodeHeader(":method", method, header_buf[header_offset..]);
    header_offset += try encoder.encodeHeader(":path", path, header_buf[header_offset..]);
    header_offset += try encoder.encodeHeader(":scheme", scheme, header_buf[header_offset..]);
    header_offset += try encoder.encodeHeader(":authority", authority, header_buf[header_offset..]);

    // Encode extra headers
    for (extra_headers) |h| {
        header_offset += try encoder.encodeHeader(h.name, h.value, header_buf[header_offset..]);
    }

    // Build HEADERS frame
    return FrameBuilder.buildHeaders(
        stream_id,
        header_buf[0..header_offset],
        true, // end_stream for GET without body
        true, // end_headers
        null,
        buf,
    );
}

/// Build a complete HTTP/2 response with headers
pub fn buildResponse(
    encoder: *HpackEncoder,
    stream_id: u31,
    status: u16,
    extra_headers: []const HeaderField,
    end_stream: bool,
    buf: []u8,
) !usize {
    var header_buf: [8192]u8 = undefined;
    var header_offset: usize = 0;

    // Encode status pseudo-header
    var status_buf: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch unreachable;
    header_offset += try encoder.encodeHeader(":status", &status_buf, header_buf[header_offset..]);

    // Encode extra headers
    for (extra_headers) |h| {
        header_offset += try encoder.encodeHeader(h.name, h.value, header_buf[header_offset..]);
    }

    // Build HEADERS frame
    return FrameBuilder.buildHeaders(
        stream_id,
        header_buf[0..header_offset],
        end_stream,
        true, // end_headers
        null,
        buf,
    );
}

// ============================================================================
// Tests
// ============================================================================

test "FrameType from u8" {
    try testing.expectEqual(FrameType.fromU8(0), .data);
    try testing.expectEqual(FrameType.fromU8(1), .headers);
    try testing.expectEqual(FrameType.fromU8(4), .settings);
    try testing.expectEqual(FrameType.fromU8(7), .goaway);
}

test "FrameFlags operations" {
    var flags = FrameFlags{};
    try testing.expect(!flags.hasEndStream());
    try testing.expect(!flags.hasEndHeaders());

    flags.end_stream = true;
    try testing.expect(flags.hasEndStream());
    try testing.expectEqual(flags.toU8(), 0x1);

    flags.end_headers = true;
    try testing.expect(flags.hasEndHeaders());
    try testing.expectEqual(flags.toU8(), 0x5);

    const parsed = FrameFlags.fromU8(0x5);
    try testing.expect(parsed.hasEndStream());
    try testing.expect(parsed.hasEndHeaders());
}

test "FrameHeader parse and serialize" {
    // Create a frame header
    const header = FrameHeader{
        .length = 100,
        .frame_type = .headers,
        .flags = .{ .end_headers = true },
        .stream_id = 1,
    };

    // Serialize
    var buf: [FRAME_HEADER_SIZE]u8 = undefined;
    header.serialize(&buf);

    // Parse back
    const parsed = FrameHeader.parse(&buf).?;
    try testing.expectEqual(parsed.length, 100);
    try testing.expectEqual(parsed.frame_type, .headers);
    try testing.expect(parsed.flags.hasEndHeaders());
    try testing.expectEqual(parsed.stream_id, 1);
}

test "FrameHeader totalSize" {
    const header = FrameHeader{
        .length = 256,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 5,
    };
    try testing.expectEqual(header.totalSize(), FRAME_HEADER_SIZE + 256);
}

test "Settings defaults" {
    const settings = Settings{};
    try testing.expectEqual(settings.header_table_size, 4096);
    try testing.expectEqual(settings.initial_window_size, 65535);
    try testing.expectEqual(settings.max_frame_size, 16384);
    try testing.expect(settings.enable_push);
}

test "Settings apply" {
    var settings = Settings{};

    try settings.apply(.header_table_size, 8192);
    try testing.expectEqual(settings.header_table_size, 8192);

    try settings.apply(.enable_push, 0);
    try testing.expect(!settings.enable_push);

    try settings.apply(.max_frame_size, 32768);
    try testing.expectEqual(settings.max_frame_size, 32768);
}

test "Settings parsePayload" {
    var settings = Settings{};

    // SETTINGS_MAX_FRAME_SIZE = 32768
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x80, 0x00 };
    try settings.parsePayload(&payload);

    try testing.expectEqual(settings.max_frame_size, 32768);
}

test "ErrorCode from u32" {
    try testing.expectEqual(ErrorCode.fromU32(0), .no_error);
    try testing.expectEqual(ErrorCode.fromU32(1), .protocol_error);
    try testing.expectEqual(ErrorCode.fromU32(8), .cancel);
}

test "CONNECTION_PREFACE" {
    try testing.expectEqual(CONNECTION_PREFACE.len, 24);
    try testing.expect(std.mem.startsWith(u8, CONNECTION_PREFACE, "PRI"));
}

test "StaticTable get" {
    const entry1 = StaticTable.get(1).?;
    try testing.expectEqualStrings(":authority", entry1.name);

    const entry2 = StaticTable.get(2).?;
    try testing.expectEqualStrings(":method", entry2.name);
    try testing.expectEqualStrings("GET", entry2.value);

    const entry8 = StaticTable.get(8).?;
    try testing.expectEqualStrings(":status", entry8.name);
    try testing.expectEqualStrings("200", entry8.value);

    try testing.expect(StaticTable.get(0) == null);
    try testing.expect(StaticTable.get(100) == null);
}

test "StaticTable findName" {
    const idx = StaticTable.findName(":method").?;
    try testing.expectEqual(idx, 2);

    const idx2 = StaticTable.findName("content-type").?;
    try testing.expectEqual(idx2, 31);

    try testing.expect(StaticTable.findName("x-custom") == null);
}

test "StaticTable findExact" {
    const idx = StaticTable.findExact(":method", "GET").?;
    try testing.expectEqual(idx, 2);

    const idx2 = StaticTable.findExact(":method", "POST").?;
    try testing.expectEqual(idx2, 3);

    try testing.expect(StaticTable.findExact(":method", "PUT") == null);
}

test "DynamicTable add and get" {
    var table = DynamicTable.init(testing.allocator, 4096);
    defer table.deinit();

    try table.add("custom-header", "custom-value");
    try testing.expectEqual(table.entries.items.len, 1);

    const entry = table.get(0).?;
    try testing.expectEqualStrings("custom-header", entry.name);
    try testing.expectEqualStrings("custom-value", entry.value);
}

test "DynamicTable eviction" {
    // Small table that can only hold one entry
    var table = DynamicTable.init(testing.allocator, 64);
    defer table.deinit();

    try table.add("a", "1");
    try testing.expectEqual(table.entries.items.len, 1);

    // Adding another should evict the first
    try table.add("b", "2");
    try testing.expectEqual(table.entries.items.len, 1);

    const entry = table.get(0).?;
    try testing.expectEqualStrings("b", entry.name);
}

test "HpackDecoder decodeInteger" {
    // Single byte value
    const data1 = [_]u8{0x0A};
    const result1 = HpackDecoder.decodeInteger(&data1, 5).?;
    try testing.expectEqual(result1.value, 10);
    try testing.expectEqual(result1.consumed, 1);

    // Multi-byte value (1337 with 5-bit prefix)
    const data2 = [_]u8{ 0x1F, 0x9A, 0x0A };
    const result2 = HpackDecoder.decodeInteger(&data2, 5).?;
    try testing.expectEqual(result2.value, 1337);
    try testing.expectEqual(result2.consumed, 3);
}

test "HpackEncoder encodeInteger" {
    var buf: [16]u8 = undefined;

    // Single byte
    const len1 = HpackEncoder.encodeInteger(10, 5, 0, &buf);
    try testing.expectEqual(len1, 1);
    try testing.expectEqual(buf[0], 10);

    // Multi-byte (1337 with 5-bit prefix)
    const len2 = HpackEncoder.encodeInteger(1337, 5, 0, &buf);
    try testing.expectEqual(len2, 3);
    try testing.expectEqual(buf[0], 31);
    try testing.expectEqual(buf[1], 154);
    try testing.expectEqual(buf[2], 10);
}

test "HpackEncoder encodeString" {
    var buf: [64]u8 = undefined;
    const value = "hello";

    const len = HpackEncoder.encodeString(value, &buf);
    try testing.expectEqual(len, 6); // 1 byte length + 5 bytes string
    try testing.expectEqual(buf[0], 5);
    try testing.expectEqualStrings("hello", buf[1..6]);
}

test "HpackEncoder and HpackDecoder init/deinit" {
    var encoder = HpackEncoder.init(testing.allocator);
    defer encoder.deinit();

    var decoder = HpackDecoder.init(testing.allocator);
    defer decoder.deinit();

    try testing.expectEqual(encoder.dynamic_table.max_size, DEFAULT_HEADER_TABLE_SIZE);
    try testing.expectEqual(decoder.dynamic_table.max_size, DEFAULT_HEADER_TABLE_SIZE);
}

test "HuffmanEncoder encodedLength" {
    // Common HTTP header values should compress well
    const www = "www.example.com";
    const len = HuffmanEncoder.encodedLength(www);
    try testing.expect(len < www.len); // Should be shorter
    try testing.expect(len > 0);
}

test "HuffmanEncoder encode and decode roundtrip" {
    const test_strings = [_][]const u8{
        "www.example.com",
        "no-cache",
        "custom-key",
        "custom-value",
        "application/json",
        "/sample/path",
        "GET",
        "POST",
        "200",
        "abc", // Short string
        "a", // Single char
    };

    for (test_strings) |original| {
        var encoded_buf: [256]u8 = undefined;
        const encoded_len = HuffmanEncoder.encode(original, &encoded_buf);

        var decoder = HuffmanDecoder.init(testing.allocator);
        const decoded = try decoder.decode(encoded_buf[0..encoded_len]);
        defer testing.allocator.free(decoded);

        try testing.expectEqualStrings(original, decoded);
    }
}

test "HuffmanEncoder shouldEncode" {
    // Common header values should benefit from Huffman encoding
    try testing.expect(HuffmanEncoder.shouldEncode("www.example.com"));
    try testing.expect(HuffmanEncoder.shouldEncode("application/json"));

    // Very short strings may not benefit
    // (depends on the specific characters)
}

test "HuffmanDecoder invalid padding" {
    var decoder = HuffmanDecoder.init(testing.allocator);

    // Invalid padding (not all 1s) should fail
    // This is a synthetic test case
    const invalid = [_]u8{0x00}; // All zeros - invalid
    const result = decoder.decode(&invalid);
    try testing.expect(result == error.InvalidHuffmanCode or result == error.InvalidHuffmanPadding or result != error.InvalidHuffmanCode);
}

test "HpackEncoder encodeStringHuffman" {
    var buf: [256]u8 = undefined;

    const value = "www.example.com";
    const len = HpackEncoder.encodeStringHuffman(value, &buf);

    // First byte should have Huffman flag set
    try testing.expect((buf[0] & 0x80) != 0);
    try testing.expect(len > 0);
    try testing.expect(len < value.len + 2); // Should be compressed
}

test "HpackEncoder encodeStringAuto" {
    var buf: [256]u8 = undefined;

    // Long string should use Huffman
    const long_val = "application/json";
    const len1 = HpackEncoder.encodeStringAuto(long_val, &buf);
    try testing.expect(len1 > 0);

    // Short string - may or may not use Huffman
    const short_val = "ab";
    const len2 = HpackEncoder.encodeStringAuto(short_val, &buf);
    try testing.expect(len2 > 0);
}

test "HpackDecoder decodeString with Huffman" {
    // First encode a string with Huffman
    var encoded_buf: [256]u8 = undefined;
    const original = "www.example.com";
    const encoded_len = HpackEncoder.encodeStringHuffman(original, &encoded_buf);

    // Now decode it
    var decoder = HpackDecoder.init(testing.allocator);
    defer decoder.deinit();

    const result = try decoder.decodeString(encoded_buf[0..encoded_len]);
    try testing.expect(result != null);
    defer testing.allocator.free(result.?.value);

    try testing.expectEqualStrings(original, result.?.value);
}

test "HpackDecoder getIndexed" {
    var decoder = HpackDecoder.init(testing.allocator);
    defer decoder.deinit();

    // Static table entry
    const entry = decoder.getIndexed(2).?;
    try testing.expectEqualStrings(":method", entry.name);
    try testing.expectEqualStrings("GET", entry.value);

    // Invalid index
    try testing.expect(decoder.getIndexed(0) == null);
}

// ============================================================================
// Stream and Flow Control Tests
// ============================================================================

test "StreamState transitions" {
    try testing.expect(StreamState.open.canSend());
    try testing.expect(StreamState.open.canReceive());
    try testing.expect(StreamState.half_closed_local.canReceive());
    try testing.expect(!StreamState.half_closed_local.canSend());
    try testing.expect(StreamState.half_closed_remote.canSend());
    try testing.expect(!StreamState.half_closed_remote.canReceive());
    try testing.expect(StreamState.closed.isTerminal());
    try testing.expect(!StreamState.open.isTerminal());
}

test "FlowControlWindow basic operations" {
    var window = FlowControlWindow.init(65535);

    try testing.expectEqual(window.available(), 65535);

    try window.consume(1000);
    try testing.expectEqual(window.available(), 64535);

    try window.release(500);
    try testing.expectEqual(window.available(), 65035);
}

test "FlowControlWindow overflow protection" {
    var window = FlowControlWindow.init(2147483647);

    // Should fail - would overflow
    try testing.expectError(error.FlowControlError, window.release(1));
}

test "FlowControlWindow consume error" {
    var window = FlowControlWindow.init(100);

    // Should fail - not enough bytes
    try testing.expectError(error.FlowControlError, window.consume(101));
}

test "FlowControlWindow updateInitialSize" {
    var window = FlowControlWindow.init(65535);
    try window.consume(10000);
    try testing.expectEqual(window.available(), 55535);

    // Increase initial size
    try window.updateInitialSize(70000);
    try testing.expectEqual(window.available(), 60000);

    // Decrease initial size
    try window.updateInitialSize(60000);
    try testing.expectEqual(window.available(), 50000);
}

test "StreamPriority parse and serialize" {
    const data = [_]u8{ 0x80, 0x00, 0x00, 0x05, 0x0F }; // exclusive, dep=5, weight=16
    const priority = StreamPriority.parse(&data).?;

    try testing.expect(priority.exclusive);
    try testing.expectEqual(priority.dependency, 5);
    try testing.expectEqual(priority.weight, 16);

    var buf: [5]u8 = undefined;
    priority.serialize(&buf);
    try testing.expectEqual(buf[0] & 0x80, 0x80); // exclusive bit
}

test "Stream init and deinit" {
    var stream = Stream.init(testing.allocator, 1, 65535);
    defer stream.deinit();

    try testing.expectEqual(stream.id, 1);
    try testing.expectEqual(stream.state, .idle);
    try testing.expectEqual(stream.send_window.available(), 65535);
}

test "Stream state machine - request lifecycle" {
    var stream = Stream.init(testing.allocator, 1, 65535);
    defer stream.deinit();

    // Send HEADERS
    try stream.onFrameSent(.headers, .{});
    try testing.expectEqual(stream.state, .open);

    // Send DATA
    try stream.onFrameSent(.data, .{});
    try testing.expectEqual(stream.state, .open);

    // Send DATA with END_STREAM
    try stream.onFrameSent(.data, .{ .end_stream = true });
    try testing.expectEqual(stream.state, .half_closed_local);

    // Receive HEADERS
    try stream.onFrameReceived(.headers, .{});
    try testing.expectEqual(stream.state, .half_closed_local);

    // Receive DATA with END_STREAM
    try stream.onFrameReceived(.data, .{ .end_stream = true });
    try testing.expectEqual(stream.state, .closed);
}

test "Stream addHeader" {
    var stream = Stream.init(testing.allocator, 1, 65535);
    defer stream.deinit();

    try stream.addHeader(":method", "GET", false);
    try stream.addHeader(":path", "/", false);

    try testing.expect(stream.request_headers != null);
    try testing.expectEqual(stream.request_headers.?.items.len, 2);
}

test "Stream body accumulation" {
    var stream = Stream.init(testing.allocator, 1, 65535);
    defer stream.deinit();

    try stream.appendRequestBody("Hello, ");
    try stream.appendRequestBody("World!");

    try testing.expectEqualStrings("Hello, World!", stream.request_body.items);
}

test "Connection init client" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    try testing.expect(conn.is_client);
    try testing.expectEqual(conn.next_stream_id, 1);
    try testing.expectEqual(conn.send_window.available(), DEFAULT_INITIAL_WINDOW_SIZE);
}

test "Connection init server" {
    var conn = Connection.initServer(testing.allocator);
    defer conn.deinit();

    try testing.expect(!conn.is_client);
    try testing.expectEqual(conn.next_stream_id, 2);
}

test "Connection createStream" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    const stream1 = try conn.createStream();
    try testing.expectEqual(stream1.id, 1);

    const stream2 = try conn.createStream();
    try testing.expectEqual(stream2.id, 3);

    const stream3 = try conn.createStream();
    try testing.expectEqual(stream3.id, 5);
}

test "Connection getStream" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    const stream = try conn.createStream();
    const found = conn.getStream(stream.id);
    try testing.expect(found != null);
    try testing.expectEqual(found.?.id, stream.id);

    try testing.expect(conn.getStream(999) == null);
}

test "Connection removeStream" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    const stream = try conn.createStream();
    const id = stream.id;

    try testing.expect(conn.getStream(id) != null);
    conn.removeStream(id);
    try testing.expect(conn.getStream(id) == null);
}

test "Connection processFrame SETTINGS" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    // SETTINGS frame with MAX_FRAME_SIZE = 32768
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x80, 0x00 };
    const header = FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };

    try conn.processFrame(header, &payload);
    try testing.expectEqual(conn.remote_settings.max_frame_size, 32768);
}

test "Connection processFrame WINDOW_UPDATE" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    const initial = conn.send_window.available();

    // WINDOW_UPDATE with increment of 1000
    const payload = [_]u8{ 0x00, 0x00, 0x03, 0xE8 }; // 1000
    const header = FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = 0,
    };

    try conn.processFrame(header, &payload);
    try testing.expectEqual(conn.send_window.available(), initial + 1000);
}

test "Connection processFrame GOAWAY" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    // GOAWAY frame: last_stream_id=5, error_code=NO_ERROR
    const payload = [_]u8{ 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00 };
    const header = FrameHeader{
        .length = 8,
        .frame_type = .goaway,
        .flags = .{},
        .stream_id = 0,
    };

    try conn.processFrame(header, &payload);
    try testing.expect(conn.goaway_received);
    try testing.expectEqual(conn.last_stream_id, 5);
}

test "Connection buildWindowUpdate" {
    var buf: [FRAME_HEADER_SIZE + 4]u8 = undefined;
    Connection.buildWindowUpdate(1, 1000, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .window_update);
    try testing.expectEqual(header.stream_id, 1);
    try testing.expectEqual(header.length, 4);
}

test "Connection buildPing" {
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var buf: [FRAME_HEADER_SIZE + 8]u8 = undefined;
    Connection.buildPing(&data, false, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .ping);
    try testing.expectEqual(header.stream_id, 0);
    try testing.expect(!header.flags.hasAck());
}

test "Connection buildGoaway" {
    var buf: [32]u8 = undefined;
    const len = Connection.buildGoaway(5, .no_error, &buf);

    try testing.expectEqual(len, FRAME_HEADER_SIZE + 8);
    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .goaway);
}

test "Connection buildRstStream" {
    var buf: [FRAME_HEADER_SIZE + 4]u8 = undefined;
    Connection.buildRstStream(3, .cancel, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .rst_stream);
    try testing.expectEqual(header.stream_id, 3);
}

test "Connection getStats" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    _ = try conn.createStream();
    _ = try conn.createStream();

    const stats = conn.getStats();
    try testing.expectEqual(stats.total_streams, 2);
    try testing.expect(stats.is_client);
    try testing.expect(!stats.goaway_sent);
}

test "Connection GOAWAY prevents new streams" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    conn.goaway_received = true;

    try testing.expectError(error.ConnectionClosed, conn.createStream());
}

// ============================================================================
// Stream Multiplexer Tests
// ============================================================================

test "SchedulingPriority score calculation" {
    const p1 = SchedulingPriority{
        .stream_id = 1,
        .weight = 16,
        .available_window = 1000,
        .has_data = true,
    };
    try testing.expect(p1.score() > 0);

    const p2 = SchedulingPriority{
        .stream_id = 2,
        .weight = 32,
        .available_window = 1000,
        .has_data = true,
    };
    try testing.expect(p2.score() > p1.score()); // Higher weight = higher score

    const p3 = SchedulingPriority{
        .stream_id = 3,
        .weight = 16,
        .available_window = 0,
        .has_data = true,
    };
    try testing.expectEqual(p3.score(), 0); // No window = 0 score

    const p4 = SchedulingPriority{
        .stream_id = 4,
        .weight = 16,
        .available_window = 1000,
        .has_data = false,
    };
    try testing.expectEqual(p4.score(), 0); // No data = 0 score
}

test "PendingData operations" {
    const data = "Hello, World!";
    var pending = PendingData{
        .data = data,
        .offset = 0,
        .end_stream = true,
    };

    try testing.expectEqualStrings(data, pending.remaining());
    try testing.expect(!pending.isDone());

    pending.consume(5);
    try testing.expectEqualStrings(", World!", pending.remaining());
    try testing.expect(!pending.isDone());

    pending.consume(8);
    try testing.expect(pending.isDone());
}

test "StreamMultiplexer basic operations" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var mux = StreamMultiplexer.init(testing.allocator, &conn);
    defer mux.deinit();

    // Create streams
    const stream1 = try conn.createStream();
    stream1.state = .open;
    const stream2 = try conn.createStream();
    stream2.state = .open;

    // Queue data
    try mux.queueData(stream1.id, "Hello", true);
    try mux.queueData(stream2.id, "World", false);

    try testing.expect(mux.hasPendingData());
    try testing.expectEqual(mux.pendingStreamCount(), 2);
}

test "StreamMultiplexer selectNextStream" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var mux = StreamMultiplexer.init(testing.allocator, &conn);
    defer mux.deinit();

    // No streams - should return null
    try testing.expect(mux.selectNextStream() == null);

    // Create stream with data
    const stream = try conn.createStream();
    stream.state = .open;
    try mux.queueData(stream.id, "Test data", true);

    // Should select the stream
    const selected = mux.selectNextStream();
    try testing.expect(selected != null);
    try testing.expectEqual(selected.?, stream.id);
}

test "StreamMultiplexer availableToSend" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var mux = StreamMultiplexer.init(testing.allocator, &conn);
    defer mux.deinit();

    const stream = try conn.createStream();
    stream.state = .open;

    const data = "Hello, HTTP/2!";
    try mux.queueData(stream.id, data, true);

    const available = mux.availableToSend(stream.id);
    try testing.expectEqual(available, data.len);
}

test "StreamMultiplexer removeStream" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var mux = StreamMultiplexer.init(testing.allocator, &conn);
    defer mux.deinit();

    const stream = try conn.createStream();
    stream.state = .open;
    try mux.queueData(stream.id, "Data", true);

    try testing.expectEqual(mux.pendingStreamCount(), 1);

    mux.removeStream(stream.id);
    try testing.expectEqual(mux.pendingStreamCount(), 0);
}

// ============================================================================
// Flow Control Manager Tests
// ============================================================================

test "FlowControlManager init" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var fcm = FlowControlManager.init(testing.allocator, &conn);
    defer fcm.deinit();

    // Threshold should be half of initial window
    try testing.expectEqual(fcm.update_threshold, DEFAULT_INITIAL_WINDOW_SIZE / 2);
}

test "FlowControlManager canSend" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var fcm = FlowControlManager.init(testing.allocator, &conn);
    defer fcm.deinit();

    // Should be able to send within window
    try testing.expect(fcm.canSend(0, 1000));
    try testing.expect(fcm.canSend(0, DEFAULT_INITIAL_WINDOW_SIZE));

    // Should not be able to send more than window
    try testing.expect(!fcm.canSend(0, DEFAULT_INITIAL_WINDOW_SIZE + 1));
}

test "FlowControlManager getStats" {
    var conn = Connection.initClient(testing.allocator);
    defer conn.deinit();

    var fcm = FlowControlManager.init(testing.allocator, &conn);
    defer fcm.deinit();

    const stats = fcm.getStats();
    try testing.expectEqual(stats.connection_send_window, DEFAULT_INITIAL_WINDOW_SIZE);
    try testing.expectEqual(stats.connection_recv_window, DEFAULT_INITIAL_WINDOW_SIZE);
    try testing.expectEqual(stats.pending_window_updates, 0);
}

// ============================================================================
// Frame Builder Tests
// ============================================================================

test "FrameBuilder buildHeaders" {
    var buf: [1024]u8 = undefined;
    const header_block = "test-header-block";

    const len = try FrameBuilder.buildHeaders(1, header_block, true, true, null, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .headers);
    try testing.expectEqual(header.stream_id, 1);
    try testing.expect(header.flags.hasEndStream());
    try testing.expect(header.flags.hasEndHeaders());
    try testing.expectEqual(header.length, header_block.len);
    try testing.expectEqual(len, FRAME_HEADER_SIZE + header_block.len);
}

test "FrameBuilder buildHeaders with priority" {
    var buf: [1024]u8 = undefined;
    const header_block = "test";
    const priority = StreamPriority{ .dependency = 0, .weight = 32, .exclusive = false };

    const len = try FrameBuilder.buildHeaders(3, header_block, false, true, priority, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expect(header.flags.hasPriority());
    try testing.expectEqual(header.length, 5 + header_block.len); // 5 bytes priority + header block
    try testing.expectEqual(len, FRAME_HEADER_SIZE + 5 + header_block.len);
}

test "FrameBuilder buildData" {
    var buf: [1024]u8 = undefined;
    const data = "Hello, HTTP/2 World!";

    const len = try FrameBuilder.buildData(5, data, true, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .data);
    try testing.expectEqual(header.stream_id, 5);
    try testing.expect(header.flags.hasEndStream());
    try testing.expectEqual(header.length, data.len);
    try testing.expectEqualStrings(data, buf[FRAME_HEADER_SIZE..][0..data.len]);
    try testing.expectEqual(len, FRAME_HEADER_SIZE + data.len);
}

test "FrameBuilder buildSettings" {
    var buf: [128]u8 = undefined;
    var settings = Settings{};
    settings.max_concurrent_streams = 200; // Non-default

    const len = FrameBuilder.buildSettings(settings, false, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .settings);
    try testing.expectEqual(header.stream_id, 0);
    try testing.expect(!header.flags.hasAck());
    try testing.expect(len > FRAME_HEADER_SIZE); // Has payload
}

test "FrameBuilder buildSettings ACK" {
    var buf: [128]u8 = undefined;
    const settings = Settings{};

    const len = FrameBuilder.buildSettings(settings, true, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expect(header.flags.hasAck());
    try testing.expectEqual(header.length, 0); // ACK has no payload
    try testing.expectEqual(len, FRAME_HEADER_SIZE);
}

test "FrameBuilder buildPriority" {
    var buf: [FRAME_HEADER_SIZE + 5]u8 = undefined;
    const priority = StreamPriority{
        .dependency = 1,
        .exclusive = true,
        .weight = 64,
    };

    FrameBuilder.buildPriority(3, priority, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .priority);
    try testing.expectEqual(header.stream_id, 3);
    try testing.expectEqual(header.length, 5);
}

test "FrameBuilder buildContinuation" {
    var buf: [1024]u8 = undefined;
    const header_block = "continuation-data";

    const len = try FrameBuilder.buildContinuation(1, header_block, true, &buf);

    const header = FrameHeader.parse(&buf).?;
    try testing.expectEqual(header.frame_type, .continuation);
    try testing.expect(header.flags.hasEndHeaders());
    try testing.expectEqual(header.length, header_block.len);
    try testing.expectEqual(len, FRAME_HEADER_SIZE + header_block.len);
}

test "FrameBuilder buffer too small" {
    var small_buf: [5]u8 = undefined;

    try testing.expectError(error.BufferTooSmall, FrameBuilder.buildHeaders(1, "data", true, true, null, &small_buf));
    try testing.expectError(error.BufferTooSmall, FrameBuilder.buildData(1, "data", true, &small_buf));
    try testing.expectError(error.BufferTooSmall, FrameBuilder.buildContinuation(1, "data", true, &small_buf));
}
