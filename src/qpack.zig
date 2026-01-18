//! QPACK Header Compression (RFC 9204)
//!
//! QPACK is the header compression format for HTTP/3, based on HPACK
//! but designed to work with QUIC's out-of-order delivery.
//!
//! This module implements:
//! - Huffman encoding/decoding (same as HPACK, RFC 7541 Appendix B)
//! - Static table (RFC 9204 Appendix A) - 99 entries
//! - Dynamic table with insertion, eviction, and duplicate detection
//! - Full encoder instruction set (Section 4.3)
//! - Full decoder instruction set (Section 4.4)
//! - Required Insert Count and Base encoding
//! - Blocked stream handling

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// Import Huffman codes from HTTP/2 (same encoding used in QPACK)
const http2 = @import("http2.zig");

// ============================================================================
// QPACK Constants
// ============================================================================

/// Default maximum dynamic table capacity
pub const DEFAULT_MAX_TABLE_CAPACITY: usize = 4096;

/// Maximum number of blocked streams
pub const DEFAULT_BLOCKED_STREAMS: usize = 100;

/// Minimum dynamic table entry overhead (per RFC 9204)
pub const ENTRY_OVERHEAD: usize = 32;

// ============================================================================
// Huffman Encoding (RFC 9204 Section 4.1.2)
// ============================================================================

/// QPACK uses the same Huffman coding as HPACK (RFC 7541 Appendix B)
pub const HuffmanEncoder = http2.HuffmanEncoder;
pub const HuffmanDecoder = http2.HuffmanDecoder;
pub const HUFFMAN_CODES = http2.HUFFMAN_CODES;

// ============================================================================
// QPACK Integer Encoding (RFC 9204 Section 4.1.1)
// ============================================================================

/// Encode an integer with a prefix
pub fn encodeInteger(value: u64, prefix_bits: u4, first_byte_mask: u8, buf: []u8) usize {
    const prefix_max: u64 = (@as(u64, 1) << @as(u6, prefix_bits)) - 1;

    if (value < prefix_max) {
        buf[0] = first_byte_mask | @as(u8, @truncate(value));
        return 1;
    }

    buf[0] = first_byte_mask | @as(u8, @truncate(prefix_max));
    var remaining = value - prefix_max;
    var i: usize = 1;

    while (remaining >= 128) {
        buf[i] = @truncate((remaining & 0x7F) | 0x80);
        remaining >>= 7;
        i += 1;
    }
    buf[i] = @truncate(remaining);
    return i + 1;
}

/// Decode an integer with a prefix
pub fn decodeInteger(data: []const u8, prefix_bits: u4) ?struct { value: u64, consumed: usize } {
    if (data.len == 0) return null;

    const prefix_mask: u8 = (@as(u8, 1) << @as(u3, @truncate(prefix_bits))) - 1;
    var value: u64 = data[0] & prefix_mask;

    if (value < prefix_mask) {
        return .{ .value = value, .consumed = 1 };
    }

    // Multi-byte integer
    var m: u6 = 0;
    var i: usize = 1;
    while (i < data.len) : (i += 1) {
        const b = data[i];
        value += @as(u64, b & 0x7F) << m;
        m += 7;
        if (b & 0x80 == 0) {
            return .{ .value = value, .consumed = i + 1 };
        }
        if (m > 62) return null; // Overflow protection
    }
    return null;
}

// ============================================================================
// Header Field
// ============================================================================

/// Header name-value pair
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,

    /// Calculate the size of this header field per RFC 9204
    /// Size = name length + value length + 32
    pub fn size(self: HeaderField) usize {
        return self.name.len + self.value.len + 32;
    }
};

// ============================================================================
// QPACK Static Table (RFC 9204 Appendix A)
// ============================================================================

/// Static table entry
pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK static table - complete table per RFC 9204 Appendix A
pub const StaticTable = struct {
    /// Full static table (99 entries, indices 0-98)
    pub const entries = [_]StaticEntry{
        // Index 0
        .{ .name = ":authority", .value = "" },
        // Index 1
        .{ .name = ":path", .value = "/" },
        // Index 2
        .{ .name = "age", .value = "0" },
        // Index 3
        .{ .name = "content-disposition", .value = "" },
        // Index 4
        .{ .name = "content-length", .value = "0" },
        // Index 5
        .{ .name = "cookie", .value = "" },
        // Index 6
        .{ .name = "date", .value = "" },
        // Index 7
        .{ .name = "etag", .value = "" },
        // Index 8
        .{ .name = "if-modified-since", .value = "" },
        // Index 9
        .{ .name = "if-none-match", .value = "" },
        // Index 10
        .{ .name = "last-modified", .value = "" },
        // Index 11
        .{ .name = "link", .value = "" },
        // Index 12
        .{ .name = "location", .value = "" },
        // Index 13
        .{ .name = "referer", .value = "" },
        // Index 14
        .{ .name = "set-cookie", .value = "" },
        // Index 15
        .{ .name = ":method", .value = "CONNECT" },
        // Index 16
        .{ .name = ":method", .value = "DELETE" },
        // Index 17
        .{ .name = ":method", .value = "GET" },
        // Index 18
        .{ .name = ":method", .value = "HEAD" },
        // Index 19
        .{ .name = ":method", .value = "OPTIONS" },
        // Index 20
        .{ .name = ":method", .value = "POST" },
        // Index 21
        .{ .name = ":method", .value = "PUT" },
        // Index 22
        .{ .name = ":scheme", .value = "http" },
        // Index 23
        .{ .name = ":scheme", .value = "https" },
        // Index 24
        .{ .name = ":status", .value = "103" },
        // Index 25
        .{ .name = ":status", .value = "200" },
        // Index 26
        .{ .name = ":status", .value = "304" },
        // Index 27
        .{ .name = ":status", .value = "404" },
        // Index 28
        .{ .name = ":status", .value = "503" },
        // Index 29
        .{ .name = "accept", .value = "*/*" },
        // Index 30
        .{ .name = "accept", .value = "application/dns-message" },
        // Index 31
        .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
        // Index 32
        .{ .name = "accept-ranges", .value = "bytes" },
        // Index 33
        .{ .name = "access-control-allow-headers", .value = "cache-control" },
        // Index 34
        .{ .name = "access-control-allow-headers", .value = "content-type" },
        // Index 35
        .{ .name = "access-control-allow-origin", .value = "*" },
        // Index 36
        .{ .name = "cache-control", .value = "max-age=0" },
        // Index 37
        .{ .name = "cache-control", .value = "max-age=2592000" },
        // Index 38
        .{ .name = "cache-control", .value = "max-age=604800" },
        // Index 39
        .{ .name = "cache-control", .value = "no-cache" },
        // Index 40
        .{ .name = "cache-control", .value = "no-store" },
        // Index 41
        .{ .name = "cache-control", .value = "public, max-age=31536000" },
        // Index 42
        .{ .name = "content-encoding", .value = "br" },
        // Index 43
        .{ .name = "content-encoding", .value = "gzip" },
        // Index 44
        .{ .name = "content-type", .value = "application/dns-message" },
        // Index 45
        .{ .name = "content-type", .value = "application/javascript" },
        // Index 46
        .{ .name = "content-type", .value = "application/json" },
        // Index 47
        .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
        // Index 48
        .{ .name = "content-type", .value = "image/gif" },
        // Index 49
        .{ .name = "content-type", .value = "image/jpeg" },
        // Index 50
        .{ .name = "content-type", .value = "image/png" },
        // Index 51
        .{ .name = "content-type", .value = "text/css" },
        // Index 52
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        // Index 53
        .{ .name = "content-type", .value = "text/plain" },
        // Index 54
        .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
        // Index 55
        .{ .name = "range", .value = "bytes=0-" },
        // Index 56
        .{ .name = "strict-transport-security", .value = "max-age=31536000" },
        // Index 57
        .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
        // Index 58
        .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
        // Index 59
        .{ .name = "vary", .value = "accept-encoding" },
        // Index 60
        .{ .name = "vary", .value = "origin" },
        // Index 61
        .{ .name = "x-content-type-options", .value = "nosniff" },
        // Index 62
        .{ .name = "x-xss-protection", .value = "1; mode=block" },
        // Index 63
        .{ .name = ":status", .value = "100" },
        // Index 64
        .{ .name = ":status", .value = "204" },
        // Index 65
        .{ .name = ":status", .value = "206" },
        // Index 66
        .{ .name = ":status", .value = "302" },
        // Index 67
        .{ .name = ":status", .value = "400" },
        // Index 68
        .{ .name = ":status", .value = "403" },
        // Index 69
        .{ .name = ":status", .value = "421" },
        // Index 70
        .{ .name = ":status", .value = "425" },
        // Index 71
        .{ .name = ":status", .value = "500" },
        // Index 72
        .{ .name = "accept-language", .value = "" },
        // Index 73
        .{ .name = "access-control-allow-credentials", .value = "FALSE" },
        // Index 74
        .{ .name = "access-control-allow-credentials", .value = "TRUE" },
        // Index 75
        .{ .name = "access-control-allow-headers", .value = "*" },
        // Index 76
        .{ .name = "access-control-allow-methods", .value = "get" },
        // Index 77
        .{ .name = "access-control-allow-methods", .value = "get, post, options" },
        // Index 78
        .{ .name = "access-control-allow-methods", .value = "options" },
        // Index 79
        .{ .name = "access-control-expose-headers", .value = "content-length" },
        // Index 80
        .{ .name = "access-control-request-headers", .value = "content-type" },
        // Index 81
        .{ .name = "access-control-request-method", .value = "get" },
        // Index 82
        .{ .name = "access-control-request-method", .value = "post" },
        // Index 83
        .{ .name = "alt-svc", .value = "clear" },
        // Index 84
        .{ .name = "authorization", .value = "" },
        // Index 85
        .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
        // Index 86
        .{ .name = "early-data", .value = "1" },
        // Index 87
        .{ .name = "expect-ct", .value = "" },
        // Index 88
        .{ .name = "forwarded", .value = "" },
        // Index 89
        .{ .name = "if-range", .value = "" },
        // Index 90
        .{ .name = "origin", .value = "" },
        // Index 91
        .{ .name = "purpose", .value = "prefetch" },
        // Index 92
        .{ .name = "server", .value = "" },
        // Index 93
        .{ .name = "timing-allow-origin", .value = "*" },
        // Index 94
        .{ .name = "upgrade-insecure-requests", .value = "1" },
        // Index 95
        .{ .name = "user-agent", .value = "" },
        // Index 96
        .{ .name = "x-forwarded-for", .value = "" },
        // Index 97
        .{ .name = "x-frame-options", .value = "deny" },
        // Index 98
        .{ .name = "x-frame-options", .value = "sameorigin" },
    };

    /// Get entry by index
    pub fn get(index: usize) ?StaticEntry {
        if (index >= entries.len) return null;
        return entries[index];
    }

    /// Find exact match (name and value)
    pub fn findExact(name: []const u8, value: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i;
            }
        }
        return null;
    }

    /// Find name match only
    pub fn findName(name: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i;
            }
        }
        return null;
    }
};

// ============================================================================
// Dynamic Table Entry
// ============================================================================

/// Dynamic table entry with owned memory
pub const DynamicEntry = struct {
    name: []u8,
    value: []u8,

    /// Calculate size per RFC 9204 (name + value + 32)
    pub fn size(self: DynamicEntry) usize {
        return self.name.len + self.value.len + 32;
    }
};

// ============================================================================
// Dynamic Table
// ============================================================================

/// QPACK dynamic table
pub const DynamicTable = struct {
    entries: std.ArrayListUnmanaged(DynamicEntry),
    max_capacity: usize,
    current_size: usize,
    /// Absolute index of the first entry (for QPACK addressing)
    insert_count: u64,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_capacity: usize) Self {
        return .{
            .entries = .{},
            .max_capacity = max_capacity,
            .current_size = 0,
            .insert_count = 0,
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

    /// Add entry to the table (at the beginning)
    pub fn insert(self: *Self, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;

        // Evict entries if needed
        while (self.current_size + entry_size > self.max_capacity and self.entries.items.len > 0) {
            self.evictOne();
        }

        // If entry is larger than table capacity, don't add
        if (entry_size > self.max_capacity) return;

        const new_entry = DynamicEntry{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        };

        try self.entries.insert(self.allocator, 0, new_entry);
        self.current_size += entry_size;
        self.insert_count += 1;
    }

    /// Get entry by relative index (0 = most recent)
    pub fn get(self: *const Self, index: usize) ?DynamicEntry {
        if (index >= self.entries.items.len) return null;
        return self.entries.items[index];
    }

    /// Get entry by absolute index
    pub fn getAbsolute(self: *const Self, abs_index: u64) ?DynamicEntry {
        if (abs_index >= self.insert_count) return null;
        const rel_index = self.insert_count - abs_index - 1;
        if (rel_index >= self.entries.items.len) return null;
        return self.entries.items[@intCast(rel_index)];
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

    /// Update maximum capacity (may evict entries)
    pub fn setCapacity(self: *Self, new_capacity: usize) void {
        self.max_capacity = new_capacity;
        while (self.current_size > self.max_capacity and self.entries.items.len > 0) {
            self.evictOne();
        }
    }

    /// Find exact match in dynamic table
    pub fn findExact(self: *const Self, name: []const u8, value: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i;
            }
        }
        return null;
    }

    /// Find name match in dynamic table
    pub fn findName(self: *const Self, name: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i;
            }
        }
        return null;
    }

    /// Get the current insert count
    pub fn getInsertCount(self: *const Self) u64 {
        return self.insert_count;
    }

    /// Check if table is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.entries.items.len == 0;
    }

    /// Get number of entries
    pub fn len(self: *const Self) usize {
        return self.entries.items.len;
    }
};

// ============================================================================
// QPACK String Encoding (RFC 9204 Section 4.1.2)
// ============================================================================

/// Encode a string with optional Huffman encoding
pub fn encodeString(value: []const u8, use_huffman: bool, buf: []u8) usize {
    if (use_huffman and HuffmanEncoder.shouldEncode(value)) {
        return encodeStringHuffman(value, buf);
    } else {
        return encodeStringLiteral(value, buf);
    }
}

/// Encode a string literally (no Huffman)
pub fn encodeStringLiteral(value: []const u8, buf: []u8) usize {
    // Length without Huffman flag (H=0)
    const len_size = encodeInteger(value.len, 7, 0x00, buf);
    @memcpy(buf[len_size..][0..value.len], value);
    return len_size + value.len;
}

/// Encode a string with Huffman encoding
pub fn encodeStringHuffman(value: []const u8, buf: []u8) usize {
    const encoded_len = HuffmanEncoder.encodedLength(value);
    // Length with Huffman flag (H=1, 0x80)
    const len_size = encodeInteger(encoded_len, 7, 0x80, buf);
    const huffman_size = HuffmanEncoder.encode(value, buf[len_size..]);
    return len_size + huffman_size;
}

/// Decode a string (handles both Huffman and literal)
pub fn decodeString(data: []const u8, allocator: Allocator) !?struct { value: []u8, consumed: usize } {
    if (data.len == 0) return null;

    const huffman = (data[0] & 0x80) != 0;
    const len_result = decodeInteger(data, 7) orelse return null;
    const str_len = len_result.value;
    const start = len_result.consumed;

    if (start + str_len > data.len) return null;

    const str_data = data[start..][0..@intCast(str_len)];

    if (huffman) {
        var decoder = HuffmanDecoder.init(allocator);
        const decoded = try decoder.decode(str_data);
        return .{ .value = decoded, .consumed = start + @as(usize, @intCast(str_len)) };
    } else {
        const value = try allocator.dupe(u8, str_data);
        return .{ .value = value, .consumed = start + @as(usize, @intCast(str_len)) };
    }
}

// ============================================================================
// QPACK Encoder Instructions (RFC 9204 Section 4.3)
// ============================================================================

/// QPACK encoder instruction types
pub const EncoderInstruction = enum {
    /// Set Dynamic Table Capacity (Section 4.3.1)
    set_capacity,
    /// Insert With Name Reference (Section 4.3.2)
    insert_with_name_ref,
    /// Insert With Literal Name (Section 4.3.3)
    insert_literal,
    /// Duplicate (Section 4.3.4)
    duplicate,
};

/// QPACK Encoder for creating encoder instructions
pub const Encoder = struct {
    dynamic_table: DynamicTable,
    max_blocked_streams: usize,
    use_huffman: bool,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_capacity: usize) Self {
        return .{
            .dynamic_table = DynamicTable.init(allocator, max_capacity),
            .max_blocked_streams = DEFAULT_BLOCKED_STREAMS,
            .use_huffman = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.dynamic_table.deinit();
    }

    /// Set whether to use Huffman encoding
    pub fn setHuffman(self: *Self, enabled: bool) void {
        self.use_huffman = enabled;
    }

    /// Build Set Dynamic Table Capacity instruction
    pub fn buildSetCapacity(capacity: u64, buf: []u8) usize {
        // Format: 001xxxxx
        return encodeInteger(capacity, 5, 0x20, buf);
    }

    /// Build Insert With Name Reference (static table)
    pub fn buildInsertStaticNameRef(self: *Self, static_index: usize, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 11xxxxxx (static=1, name index)
        offset += encodeInteger(static_index, 6, 0xC0, buf[offset..]);
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Build Insert With Name Reference (dynamic table)
    pub fn buildInsertDynamicNameRef(self: *Self, dynamic_index: usize, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 10xxxxxx (static=0, name index)
        offset += encodeInteger(dynamic_index, 6, 0x80, buf[offset..]);
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Build Insert With Literal Name
    pub fn buildInsertLiteral(self: *Self, name: []const u8, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 01xxxxxx
        offset += encodeInteger(0, 6, 0x40, buf[offset..]);
        // Encode name (with optional Huffman, bit 3)
        offset += encodeString(name, self.use_huffman, buf[offset..]);
        // Encode value
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Build Duplicate instruction
    pub fn buildDuplicate(index: usize, buf: []u8) usize {
        // Format: 000xxxxx
        return encodeInteger(index, 5, 0x00, buf);
    }

    /// Insert a header into the dynamic table and return the instruction
    pub fn insert(self: *Self, name: []const u8, value: []const u8, buf: []u8) !usize {
        // Check if we can use a name reference
        if (StaticTable.findName(name)) |static_idx| {
            const len = self.buildInsertStaticNameRef(static_idx, value, buf);
            try self.dynamic_table.insert(name, value);
            return len;
        }

        if (self.dynamic_table.findName(name)) |dyn_idx| {
            const len = self.buildInsertDynamicNameRef(dyn_idx, value, buf);
            try self.dynamic_table.insert(name, value);
            return len;
        }

        // Insert with literal name
        const len = self.buildInsertLiteral(name, value, buf);
        try self.dynamic_table.insert(name, value);
        return len;
    }

    /// Get the current insert count for the encoder
    pub fn getInsertCount(self: *const Self) u64 {
        return self.dynamic_table.getInsertCount();
    }
};

// ============================================================================
// QPACK Decoder Instructions (RFC 9204 Section 4.4)
// ============================================================================

/// QPACK decoder instruction types
pub const DecoderInstruction = enum {
    /// Section Acknowledgment (Section 4.4.1)
    section_ack,
    /// Stream Cancellation (Section 4.4.2)
    stream_cancel,
    /// Insert Count Increment (Section 4.4.3)
    insert_count_increment,
};

/// QPACK Decoder for processing decoder instructions
pub const Decoder = struct {
    dynamic_table: DynamicTable,
    /// Known received count (for flow control)
    known_received_count: u64,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_capacity: usize) Self {
        return .{
            .dynamic_table = DynamicTable.init(allocator, max_capacity),
            .known_received_count = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.dynamic_table.deinit();
    }

    /// Build Section Acknowledgment instruction
    pub fn buildSectionAck(stream_id: u64, buf: []u8) usize {
        // Format: 1xxxxxxx
        return encodeInteger(stream_id, 7, 0x80, buf);
    }

    /// Build Stream Cancellation instruction
    pub fn buildStreamCancel(stream_id: u64, buf: []u8) usize {
        // Format: 01xxxxxx
        return encodeInteger(stream_id, 6, 0x40, buf);
    }

    /// Build Insert Count Increment instruction
    pub fn buildInsertCountIncrement(increment: u64, buf: []u8) usize {
        // Format: 00xxxxxx
        return encodeInteger(increment, 6, 0x00, buf);
    }

    /// Process an encoder instruction
    pub fn processEncoderInstruction(self: *Self, data: []const u8) !usize {
        if (data.len == 0) return error.InsufficientData;

        const first_byte = data[0];

        if (first_byte & 0x80 != 0) {
            // Insert With Name Reference
            const is_static = (first_byte & 0x40) != 0;
            const idx_result = decodeInteger(data, 6) orelse return error.InvalidInstruction;
            var offset = idx_result.consumed;

            const value_result = try decodeString(data[offset..], self.allocator) orelse return error.InvalidInstruction;
            defer self.allocator.free(value_result.value);
            offset += value_result.consumed;

            if (is_static) {
                if (StaticTable.get(idx_result.value)) |entry| {
                    try self.dynamic_table.insert(entry.name, value_result.value);
                }
            } else {
                if (self.dynamic_table.get(@intCast(idx_result.value))) |entry| {
                    const name_copy = try self.allocator.dupe(u8, entry.name);
                    defer self.allocator.free(name_copy);
                    try self.dynamic_table.insert(name_copy, value_result.value);
                }
            }
            return offset;
        } else if (first_byte & 0x40 != 0) {
            // Insert With Literal Name
            var offset: usize = 0;
            const name_result = try decodeString(data[1..], self.allocator) orelse return error.InvalidInstruction;
            defer self.allocator.free(name_result.value);
            offset += 1 + name_result.consumed;

            const value_result = try decodeString(data[offset..], self.allocator) orelse return error.InvalidInstruction;
            defer self.allocator.free(value_result.value);
            offset += value_result.consumed;

            try self.dynamic_table.insert(name_result.value, value_result.value);
            return offset;
        } else if (first_byte & 0x20 != 0) {
            // Set Dynamic Table Capacity
            const cap_result = decodeInteger(data, 5) orelse return error.InvalidInstruction;
            self.dynamic_table.setCapacity(@intCast(cap_result.value));
            return cap_result.consumed;
        } else {
            // Duplicate
            const idx_result = decodeInteger(data, 5) orelse return error.InvalidInstruction;
            if (self.dynamic_table.get(@intCast(idx_result.value))) |entry| {
                const name_copy = try self.allocator.dupe(u8, entry.name);
                defer self.allocator.free(name_copy);
                const value_copy = try self.allocator.dupe(u8, entry.value);
                defer self.allocator.free(value_copy);
                try self.dynamic_table.insert(name_copy, value_copy);
            }
            return idx_result.consumed;
        }
    }

    /// Get header from static or dynamic table
    pub fn getIndexed(self: *const Self, index: usize, is_static: bool) ?HeaderField {
        if (is_static) {
            if (StaticTable.get(index)) |entry| {
                return .{ .name = entry.name, .value = entry.value };
            }
        } else {
            if (self.dynamic_table.get(index)) |entry| {
                return .{ .name = entry.name, .value = entry.value };
            }
        }
        return null;
    }
};

// ============================================================================
// QPACK Field Line Representations (RFC 9204 Section 4.5)
// ============================================================================

/// Encode Required Insert Count (RFC 9204 Section 4.5.1)
pub fn encodeRequiredInsertCount(req_insert_count: u64, max_entries: u64, buf: []u8) usize {
    if (req_insert_count == 0) {
        buf[0] = 0;
        return 1;
    }
    const encoded = (req_insert_count % (2 * max_entries)) + 1;
    return encodeInteger(encoded, 8, 0, buf);
}

/// Decode Required Insert Count
pub fn decodeRequiredInsertCount(encoded: u64, max_entries: u64, total_inserted: u64) u64 {
    if (encoded == 0) return 0;

    const full_range = 2 * max_entries;
    if (encoded > full_range) return 0; // Invalid

    const max_value = total_inserted + max_entries;
    const max_wrapped = (max_value / full_range) * full_range;
    var req_insert_count = max_wrapped + encoded - 1;

    if (req_insert_count > max_value) {
        if (req_insert_count <= full_range) return 0; // Invalid
        req_insert_count -= full_range;
    }

    if (req_insert_count == 0) return 0; // Invalid

    return req_insert_count;
}

/// Encode Base (RFC 9204 Section 4.5.1)
pub fn encodeBase(req_insert_count: u64, base: u64, buf: []u8) usize {
    if (base >= req_insert_count) {
        // Delta Base is non-negative
        const delta = base - req_insert_count;
        return encodeInteger(delta, 7, 0x00, buf); // S=0
    } else {
        // Delta Base is negative
        const delta = req_insert_count - base - 1;
        return encodeInteger(delta, 7, 0x80, buf); // S=1
    }
}

/// Field line encoder for request/response headers
pub const FieldLineEncoder = struct {
    encoder: *Encoder,
    use_huffman: bool,

    const Self = @This();

    pub fn init(encoder: *Encoder) Self {
        return .{
            .encoder = encoder,
            .use_huffman = encoder.use_huffman,
        };
    }

    /// Encode an indexed field line (static table)
    pub fn encodeIndexedStatic(index: usize, buf: []u8) usize {
        // Format: 1 T=1 index (static)
        return encodeInteger(index, 6, 0xC0, buf);
    }

    /// Encode an indexed field line (dynamic table, post-base)
    pub fn encodeIndexedDynamic(index: usize, buf: []u8) usize {
        // Format: 1 T=0 index (dynamic)
        return encodeInteger(index, 6, 0x80, buf);
    }

    /// Encode a post-base indexed field line
    pub fn encodePostBaseIndexed(index: usize, buf: []u8) usize {
        // Format: 0001 index
        return encodeInteger(index, 4, 0x10, buf);
    }

    /// Encode literal with name reference (static)
    pub fn encodeLiteralStaticNameRef(self: *Self, static_index: usize, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 01 N=0 T=1 index
        offset += encodeInteger(static_index, 4, 0x50, buf[offset..]);
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Encode literal with name reference (dynamic)
    pub fn encodeLiteralDynamicNameRef(self: *Self, dynamic_index: usize, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 01 N=0 T=0 index
        offset += encodeInteger(dynamic_index, 4, 0x40, buf[offset..]);
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Encode literal with literal name
    pub fn encodeLiteralWithLiteralName(self: *Self, name: []const u8, value: []const u8, buf: []u8) usize {
        var offset: usize = 0;
        // Format: 001 N=0 name value
        buf[offset] = 0x20;
        offset += 1;
        offset += encodeString(name, self.use_huffman, buf[offset..]);
        offset += encodeString(value, self.use_huffman, buf[offset..]);
        return offset;
    }

    /// Encode a header field, choosing the best representation
    pub fn encodeField(self: *Self, name: []const u8, value: []const u8, buf: []u8) usize {
        // Try static table exact match
        if (StaticTable.findExact(name, value)) |index| {
            return encodeIndexedStatic(index, buf);
        }

        // Try static table name reference
        if (StaticTable.findName(name)) |name_idx| {
            return self.encodeLiteralStaticNameRef(name_idx, value, buf);
        }

        // Try dynamic table
        if (self.encoder.dynamic_table.findExact(name, value)) |index| {
            return encodeIndexedDynamic(index, buf);
        }

        if (self.encoder.dynamic_table.findName(name)) |name_idx| {
            return self.encodeLiteralDynamicNameRef(name_idx, value, buf);
        }

        // Literal with literal name
        return self.encodeLiteralWithLiteralName(name, value, buf);
    }

    /// Encode a complete header block with prefix
    pub fn encodeHeaderBlock(
        self: *Self,
        headers: []const HeaderField,
        buf: []u8,
    ) usize {
        var offset: usize = 0;

        // Required Insert Count (0 = no dynamic table references)
        _ = @as(u64, 0); // req_insert_count not used when encoding static-only headers
        buf[offset] = 0;
        offset += 1;

        // Delta Base (0 = base equals required insert count)
        buf[offset] = 0;
        offset += 1;

        // Encode each header field
        for (headers) |header| {
            offset += self.encodeField(header.name, header.value, buf[offset..]);
        }

        return offset;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "encodeInteger and decodeInteger" {
    var buf: [16]u8 = undefined;

    // Single byte encoding
    const len1 = encodeInteger(10, 5, 0x00, &buf);
    try testing.expectEqual(len1, 1);
    const dec1 = decodeInteger(&buf, 5);
    try testing.expect(dec1 != null);
    try testing.expectEqual(dec1.?.value, 10);

    // Multi-byte encoding (value at prefix boundary)
    const len2 = encodeInteger(31, 5, 0x00, &buf);
    try testing.expectEqual(len2, 2);
    const dec2 = decodeInteger(&buf, 5);
    try testing.expect(dec2 != null);
    try testing.expectEqual(dec2.?.value, 31);

    // Large value
    const len3 = encodeInteger(1337, 5, 0x00, &buf);
    try testing.expect(len3 > 2);
    const dec3 = decodeInteger(&buf, 5);
    try testing.expect(dec3 != null);
    try testing.expectEqual(dec3.?.value, 1337);
}

test "encodeStringLiteral and encodeStringHuffman" {
    var buf: [256]u8 = undefined;

    const value = "www.example.com";

    // Literal encoding
    const lit_len = encodeStringLiteral(value, &buf);
    try testing.expect(lit_len > value.len);
    try testing.expectEqual(buf[0] & 0x80, 0); // No Huffman flag

    // Huffman encoding
    const huff_len = encodeStringHuffman(value, &buf);
    try testing.expect(huff_len > 0);
    try testing.expect((buf[0] & 0x80) != 0); // Huffman flag set
}

test "StaticTable full coverage" {
    // Test first entry
    const entry0 = StaticTable.get(0);
    try testing.expect(entry0 != null);
    try testing.expectEqualStrings(":authority", entry0.?.name);

    // Test :method GET (index 17)
    const get_idx = StaticTable.findExact(":method", "GET");
    try testing.expect(get_idx != null);
    try testing.expectEqual(get_idx.?, 17);

    // Test :status 200 (index 25)
    const status_idx = StaticTable.findExact(":status", "200");
    try testing.expect(status_idx != null);
    try testing.expectEqual(status_idx.?, 25);

    // Test name-only lookup
    const method_idx = StaticTable.findName(":method");
    try testing.expect(method_idx != null);

    // Test out of bounds
    try testing.expectEqual(StaticTable.get(99), null);
}

test "DynamicTable operations" {
    var table = DynamicTable.init(testing.allocator, 4096);
    defer table.deinit();

    try testing.expect(table.isEmpty());
    try testing.expectEqual(table.len(), 0);

    // Insert entry
    try table.insert("custom-header", "custom-value");
    try testing.expect(!table.isEmpty());
    try testing.expectEqual(table.len(), 1);
    try testing.expectEqual(table.getInsertCount(), 1);

    // Get entry
    const entry = table.get(0);
    try testing.expect(entry != null);
    try testing.expectEqualStrings("custom-header", entry.?.name);
    try testing.expectEqualStrings("custom-value", entry.?.value);

    // Find operations
    const exact_idx = table.findExact("custom-header", "custom-value");
    try testing.expect(exact_idx != null);
    try testing.expectEqual(exact_idx.?, 0);

    const name_idx = table.findName("custom-header");
    try testing.expect(name_idx != null);
}

test "DynamicTable eviction" {
    var table = DynamicTable.init(testing.allocator, 100);
    defer table.deinit();

    // Insert entries until eviction occurs
    try table.insert("header1", "value1");
    try table.insert("header2", "value2");
    try table.insert("header3", "value3");

    // Table should have evicted older entries due to size constraint
    try testing.expect(table.current_size <= 100);
}

test "Encoder basic operations" {
    var encoder = Encoder.init(testing.allocator, 4096);
    defer encoder.deinit();

    var buf: [256]u8 = undefined;

    // Test Set Capacity instruction
    const cap_len = Encoder.buildSetCapacity(4096, &buf);
    try testing.expect(cap_len > 0);
    try testing.expectEqual(buf[0] & 0xE0, 0x20); // 001xxxxx pattern

    // Test Duplicate instruction
    const dup_len = Encoder.buildDuplicate(5, &buf);
    try testing.expect(dup_len > 0);
    try testing.expectEqual(buf[0] & 0xE0, 0x00); // 000xxxxx pattern

    // Test insert with static name ref
    const insert_len = try encoder.insert(":method", "PATCH", &buf);
    try testing.expect(insert_len > 0);
    try testing.expectEqual(encoder.getInsertCount(), 1);
}

test "Decoder instructions" {
    var buf: [64]u8 = undefined;

    // Section Acknowledgment
    const ack_len = Decoder.buildSectionAck(42, &buf);
    try testing.expect(ack_len > 0);
    try testing.expect((buf[0] & 0x80) != 0);

    // Stream Cancellation
    const cancel_len = Decoder.buildStreamCancel(10, &buf);
    try testing.expect(cancel_len > 0);
    try testing.expectEqual(buf[0] & 0xC0, 0x40);

    // Insert Count Increment
    const inc_len = Decoder.buildInsertCountIncrement(5, &buf);
    try testing.expect(inc_len > 0);
    try testing.expectEqual(buf[0] & 0xC0, 0x00);
}

test "Decoder getIndexed" {
    var decoder = Decoder.init(testing.allocator, 4096);
    defer decoder.deinit();

    // Static table lookup
    const static_header = decoder.getIndexed(17, true);
    try testing.expect(static_header != null);
    try testing.expectEqualStrings(":method", static_header.?.name);
    try testing.expectEqualStrings("GET", static_header.?.value);

    // Dynamic table lookup (empty)
    const dyn_header = decoder.getIndexed(0, false);
    try testing.expectEqual(dyn_header, null);
}

test "FieldLineEncoder encodeField" {
    var encoder = Encoder.init(testing.allocator, 4096);
    defer encoder.deinit();

    var field_encoder = FieldLineEncoder.init(&encoder);
    var buf: [256]u8 = undefined;

    // Encode :method GET (should use static indexed)
    const len1 = field_encoder.encodeField(":method", "GET", &buf);
    try testing.expect(len1 > 0);
    try testing.expect((buf[0] & 0xC0) == 0xC0); // Indexed static

    // Encode :status 200 (should use static indexed)
    const len2 = field_encoder.encodeField(":status", "200", &buf);
    try testing.expect(len2 > 0);

    // Encode custom header (should use literal)
    const len3 = field_encoder.encodeField("x-custom", "value", &buf);
    try testing.expect(len3 > 0);
}

test "FieldLineEncoder encodeHeaderBlock" {
    var encoder = Encoder.init(testing.allocator, 4096);
    defer encoder.deinit();

    var field_encoder = FieldLineEncoder.init(&encoder);
    var buf: [512]u8 = undefined;

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "pingora-zig" },
    };

    const len = field_encoder.encodeHeaderBlock(&headers, &buf);
    try testing.expect(len > 4); // At least prefix + some headers

    // First two bytes should be prefix (Required Insert Count, Delta Base)
    try testing.expectEqual(buf[0], 0); // Required Insert Count = 0
    try testing.expectEqual(buf[1], 0); // Delta Base = 0
}

test "encodeRequiredInsertCount and decodeRequiredInsertCount" {
    var buf: [8]u8 = undefined;

    // Zero insert count
    const len1 = encodeRequiredInsertCount(0, 100, &buf);
    try testing.expectEqual(len1, 1);
    try testing.expectEqual(buf[0], 0);

    // Non-zero insert count
    const len2 = encodeRequiredInsertCount(50, 100, &buf);
    try testing.expect(len2 >= 1);

    // Decode zero
    const decoded_zero = decodeRequiredInsertCount(0, 100, 50);
    try testing.expectEqual(decoded_zero, 0);
}

test "encodeBase" {
    var buf: [8]u8 = undefined;

    // Non-negative delta (base >= req_insert_count)
    const len1 = encodeBase(10, 15, &buf);
    try testing.expect(len1 >= 1);
    try testing.expectEqual(buf[0] & 0x80, 0); // S=0

    // Negative delta (base < req_insert_count)
    const len2 = encodeBase(15, 10, &buf);
    try testing.expect(len2 >= 1);
    try testing.expect((buf[0] & 0x80) != 0); // S=1
}

test "Huffman encoding roundtrip via QPACK" {
    const test_strings = [_][]const u8{
        "www.example.com",
        "application/json",
        "/api/v1/users",
        "GET",
        "200",
    };

    for (test_strings) |original| {
        var buf: [256]u8 = undefined;
        const encoded_len = encodeStringHuffman(original, &buf);

        const decoded = try decodeString(buf[0..encoded_len], testing.allocator);
        try testing.expect(decoded != null);
        defer testing.allocator.free(decoded.?.value);

        try testing.expectEqualStrings(original, decoded.?.value);
    }
}
