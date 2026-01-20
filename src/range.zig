//! pingora-zig: Range Request Support
//!
//! HTTP Range request handling (RFC 7233).
//! Supports byte ranges, multipart ranges, and 206 Partial Content responses.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const http = @import("http.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Range Types
// ============================================================================

/// A single byte range
pub const ByteRange = struct {
    /// Start byte position (inclusive)
    start: ?u64,
    /// End byte position (inclusive)
    end: ?u64,

    const Self = @This();

    /// Create a range from start to end (inclusive)
    pub fn fromStartEnd(start: u64, end: u64) Self {
        return .{ .start = start, .end = end };
    }

    /// Create a range from start to end of content
    pub fn fromStart(start: u64) Self {
        return .{ .start = start, .end = null };
    }

    /// Create a suffix range (last N bytes)
    pub fn suffix(length: u64) Self {
        return .{ .start = null, .end = length };
    }

    /// Check if this is a suffix range
    pub fn isSuffix(self: *const Self) bool {
        return self.start == null and self.end != null;
    }

    /// Resolve the range against a known content length
    /// Returns null if the range is not satisfiable
    pub fn resolve(self: *const Self, content_length: u64) ?ResolvedRange {
        if (content_length == 0) return null;

        if (self.isSuffix()) {
            // Suffix range: last N bytes
            const suffix_len = self.end.?;
            if (suffix_len == 0) return null;
            if (suffix_len >= content_length) {
                return .{ .start = 0, .end = content_length - 1, .length = content_length };
            }
            const start = content_length - suffix_len;
            return .{ .start = start, .end = content_length - 1, .length = suffix_len };
        }

        const start = self.start orelse return null;
        if (start >= content_length) return null;

        const end = if (self.end) |e|
            @min(e, content_length - 1)
        else
            content_length - 1;

        if (start > end) return null;

        return .{
            .start = start,
            .end = end,
            .length = end - start + 1,
        };
    }

    /// Format as Range header value component
    pub fn format(self: *const Self, buf: []u8) ![]u8 {
        if (self.isSuffix()) {
            return std.fmt.bufPrint(buf, "-{d}", .{self.end.?}) catch error.BufferTooSmall;
        } else if (self.end) |end| {
            return std.fmt.bufPrint(buf, "{d}-{d}", .{ self.start.?, end }) catch error.BufferTooSmall;
        } else {
            return std.fmt.bufPrint(buf, "{d}-", .{self.start.?}) catch error.BufferTooSmall;
        }
    }
};

/// A resolved byte range with concrete positions
pub const ResolvedRange = struct {
    /// Start byte position (inclusive)
    start: u64,
    /// End byte position (inclusive)
    end: u64,
    /// Length of the range
    length: u64,

    /// Format as Content-Range header value
    pub fn formatContentRange(self: *const ResolvedRange, content_length: u64, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "bytes {d}-{d}/{d}", .{ self.start, self.end, content_length }) catch error.BufferTooSmall;
    }
};

/// Parsed Range header
pub const RangeHeader = struct {
    /// Unit (usually "bytes")
    unit: []const u8,
    /// List of ranges
    ranges: []ByteRange,
    /// Whether this owns the ranges slice
    owned: bool,
    /// Allocator
    allocator: ?Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.ranges);
            }
        }
    }

    /// Check if this is a single range request
    pub fn isSingleRange(self: *const Self) bool {
        return self.ranges.len == 1;
    }

    /// Check if this is a multipart range request
    pub fn isMultipart(self: *const Self) bool {
        return self.ranges.len > 1;
    }

    /// Get the first range (convenience method)
    pub fn firstRange(self: *const Self) ?ByteRange {
        if (self.ranges.len > 0) {
            return self.ranges[0];
        }
        return null;
    }
};

// ============================================================================
// Range Parser
// ============================================================================

/// Parse errors
pub const ParseError = error{
    InvalidFormat,
    InvalidUnit,
    InvalidRange,
    EmptyRanges,
    OutOfMemory,
    BufferTooSmall,
};

/// Parse a Range header value
/// Format: "bytes=0-499", "bytes=0-499, 500-999", "bytes=-500", "bytes=500-"
pub fn parseRangeHeader(allocator: Allocator, header_value: []const u8) ParseError!RangeHeader {
    // Find the '=' separator
    const eq_pos = std.mem.indexOf(u8, header_value, "=") orelse return ParseError.InvalidFormat;

    const unit = std.mem.trim(u8, header_value[0..eq_pos], " \t");
    const ranges_str = std.mem.trim(u8, header_value[eq_pos + 1 ..], " \t");

    if (ranges_str.len == 0) return ParseError.EmptyRanges;

    // Count ranges first
    var count: usize = 1;
    for (ranges_str) |c| {
        if (c == ',') count += 1;
    }

    // Allocate ranges
    var ranges = allocator.alloc(ByteRange, count) catch return ParseError.OutOfMemory;
    errdefer allocator.free(ranges);

    // Parse each range
    var range_iter = std.mem.splitScalar(u8, ranges_str, ',');
    var idx: usize = 0;

    while (range_iter.next()) |range_str| {
        const trimmed = std.mem.trim(u8, range_str, " \t");
        if (trimmed.len == 0) continue;

        ranges[idx] = parseByteRange(trimmed) catch return ParseError.InvalidRange;
        idx += 1;
    }

    if (idx == 0) return ParseError.EmptyRanges;

    return RangeHeader{
        .unit = unit,
        .ranges = ranges[0..idx],
        .owned = true,
        .allocator = allocator,
    };
}

/// Parse a single byte range spec
fn parseByteRange(spec: []const u8) !ByteRange {
    const dash_pos = std.mem.indexOf(u8, spec, "-") orelse return error.InvalidRange;

    const start_str = spec[0..dash_pos];
    const end_str = spec[dash_pos + 1 ..];

    // Suffix range: "-500"
    if (start_str.len == 0) {
        if (end_str.len == 0) return error.InvalidRange;
        const suffix_len = std.fmt.parseInt(u64, end_str, 10) catch return error.InvalidRange;
        return ByteRange.suffix(suffix_len);
    }

    const start = std.fmt.parseInt(u64, start_str, 10) catch return error.InvalidRange;

    // Open-ended range: "500-"
    if (end_str.len == 0) {
        return ByteRange.fromStart(start);
    }

    // Full range: "0-499"
    const end = std.fmt.parseInt(u64, end_str, 10) catch return error.InvalidRange;
    if (end < start) return error.InvalidRange;

    return ByteRange.fromStartEnd(start, end);
}

// ============================================================================
// Range Body Filter
// ============================================================================

/// Filter for extracting range from response body
pub const RangeBodyFilter = struct {
    /// Resolved range to extract
    range: ResolvedRange,
    /// Total content length
    content_length: u64,
    /// Current position in the original content
    position: u64,
    /// Bytes written so far
    bytes_written: u64,
    /// Whether filtering is complete
    complete: bool,

    const Self = @This();

    pub fn init(range: ResolvedRange, content_length: u64) Self {
        return .{
            .range = range,
            .content_length = content_length,
            .position = 0,
            .bytes_written = 0,
            .complete = false,
        };
    }

    /// Filter a chunk of data, returning the portion that falls within the range
    pub fn filter(self: *Self, data: []const u8) ?[]const u8 {
        if (self.complete) return null;

        const chunk_start = self.position;
        const chunk_end = self.position + data.len;
        self.position = chunk_end;

        // Check if chunk is entirely before the range
        if (chunk_end <= self.range.start) {
            return null;
        }

        // Check if chunk is entirely after the range
        if (chunk_start > self.range.end) {
            self.complete = true;
            return null;
        }

        // Calculate overlap
        const overlap_start = @max(chunk_start, self.range.start);
        const overlap_end = @min(chunk_end - 1, self.range.end);
        const local_start = overlap_start - chunk_start;
        const local_end = overlap_end - chunk_start + 1;

        const result = data[local_start..local_end];
        self.bytes_written += result.len;

        // Check if we've completed the range
        if (overlap_end >= self.range.end) {
            self.complete = true;
        }

        return result;
    }

    /// Check if the filter is complete
    pub fn isComplete(self: *const Self) bool {
        return self.complete;
    }

    /// Get remaining bytes needed
    pub fn remaining(self: *const Self) u64 {
        return self.range.length - self.bytes_written;
    }
};

// ============================================================================
// Multipart Range Response Builder
// ============================================================================

/// Boundary generator for multipart responses
pub fn generateBoundary() [32]u8 {
    var buf: [32]u8 = undefined;
    const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (&buf) |*c| {
        // chars has 62 characters, so use modulo to ensure valid index
        c.* = chars[std.crypto.random.int(u8) % 62];
    }

    return buf;
}

/// Builder for multipart/byteranges response
pub const MultipartRangeBuilder = struct {
    /// Boundary string
    boundary: []const u8,
    /// Content type of the original resource
    content_type: []const u8,
    /// Total content length
    content_length: u64,
    /// Output buffer
    buffer: std.ArrayListUnmanaged(u8),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, boundary: []const u8, content_type: []const u8, content_length: u64) Self {
        return .{
            .boundary = boundary,
            .content_type = content_type,
            .content_length = content_length,
            .buffer = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    /// Add a range part
    pub fn addPart(self: *Self, range: ResolvedRange, data: []const u8) !void {
        // Boundary
        try self.buffer.appendSlice(self.allocator, "--");
        try self.buffer.appendSlice(self.allocator, self.boundary);
        try self.buffer.appendSlice(self.allocator, "\r\n");

        // Content-Type header
        try self.buffer.appendSlice(self.allocator, "Content-Type: ");
        try self.buffer.appendSlice(self.allocator, self.content_type);
        try self.buffer.appendSlice(self.allocator, "\r\n");

        // Content-Range header
        try self.buffer.appendSlice(self.allocator, "Content-Range: bytes ");
        var range_buf: [64]u8 = undefined;
        const range_str = try range.formatContentRange(self.content_length, &range_buf);
        // Remove "bytes " prefix since we already added it
        const start_idx = std.mem.indexOf(u8, range_str, " ").? + 1;
        try self.buffer.appendSlice(self.allocator, range_str[start_idx..]);
        try self.buffer.appendSlice(self.allocator, "\r\n");

        // Empty line before body
        try self.buffer.appendSlice(self.allocator, "\r\n");

        // Body
        try self.buffer.appendSlice(self.allocator, data);
        try self.buffer.appendSlice(self.allocator, "\r\n");
    }

    /// Finish the multipart response
    pub fn finish(self: *Self) ![]u8 {
        // Final boundary
        try self.buffer.appendSlice(self.allocator, "--");
        try self.buffer.appendSlice(self.allocator, self.boundary);
        try self.buffer.appendSlice(self.allocator, "--\r\n");

        return self.buffer.toOwnedSlice(self.allocator);
    }

    /// Get the Content-Type header value for the multipart response
    pub fn contentType(self: *const Self, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "multipart/byteranges; boundary={s}", .{self.boundary}) catch error.BufferTooSmall;
    }
};

// ============================================================================
// Range Response Helper
// ============================================================================

/// Helper for generating range responses
pub const RangeResponse = struct {
    /// Check if a request has a Range header
    pub fn hasRangeHeader(req: *const http.RequestHeader) bool {
        return req.headers.get("Range") != null;
    }

    /// Check if the response supports range requests
    pub fn acceptsRanges(resp: *const http.ResponseHeader) bool {
        if (resp.headers.get("Accept-Ranges")) |ar| {
            return !std.mem.eql(u8, ar, "none");
        }
        return true; // Default to accepting ranges
    }

    /// Build a 206 Partial Content response for a single range
    pub fn build206Response(
        allocator: Allocator,
        range: ResolvedRange,
        content_length: u64,
        content_type: ?[]const u8,
    ) !http.ResponseHeader {
        var resp = http.ResponseHeader.init(allocator, 206);
        errdefer resp.deinit();

        // Content-Range header
        var range_buf: [64]u8 = undefined;
        const range_str = try range.formatContentRange(content_length, &range_buf);
        try resp.appendHeader("Content-Range", range_str);

        // Content-Length for the range
        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{range.length}) catch return error.BufferTooSmall;
        try resp.appendHeader("Content-Length", len_str);

        // Content-Type if provided
        if (content_type) |ct| {
            try resp.appendHeader("Content-Type", ct);
        }

        // Accept-Ranges
        try resp.appendHeader("Accept-Ranges", "bytes");

        return resp;
    }

    /// Build a 416 Range Not Satisfiable response
    pub fn build416Response(allocator: Allocator, content_length: u64) !http.ResponseHeader {
        var resp = http.ResponseHeader.init(allocator, 416);
        errdefer resp.deinit();

        // Content-Range header with unsatisfiable indicator
        var range_buf: [64]u8 = undefined;
        const range_str = std.fmt.bufPrint(&range_buf, "bytes */{d}", .{content_length}) catch return error.BufferTooSmall;
        try resp.appendHeader("Content-Range", range_str);

        return resp;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ByteRange fromStartEnd" {
    const range = ByteRange.fromStartEnd(0, 499);
    try testing.expectEqual(@as(u64, 0), range.start.?);
    try testing.expectEqual(@as(u64, 499), range.end.?);
    try testing.expect(!range.isSuffix());
}

test "ByteRange fromStart" {
    const range = ByteRange.fromStart(500);
    try testing.expectEqual(@as(u64, 500), range.start.?);
    try testing.expect(range.end == null);
    try testing.expect(!range.isSuffix());
}

test "ByteRange suffix" {
    const range = ByteRange.suffix(100);
    try testing.expect(range.start == null);
    try testing.expectEqual(@as(u64, 100), range.end.?);
    try testing.expect(range.isSuffix());
}

test "ByteRange resolve normal" {
    const range = ByteRange.fromStartEnd(0, 499);
    const resolved = range.resolve(1000);

    try testing.expect(resolved != null);
    try testing.expectEqual(@as(u64, 0), resolved.?.start);
    try testing.expectEqual(@as(u64, 499), resolved.?.end);
    try testing.expectEqual(@as(u64, 500), resolved.?.length);
}

test "ByteRange resolve suffix" {
    const range = ByteRange.suffix(100);
    const resolved = range.resolve(1000);

    try testing.expect(resolved != null);
    try testing.expectEqual(@as(u64, 900), resolved.?.start);
    try testing.expectEqual(@as(u64, 999), resolved.?.end);
    try testing.expectEqual(@as(u64, 100), resolved.?.length);
}

test "ByteRange resolve open-ended" {
    const range = ByteRange.fromStart(500);
    const resolved = range.resolve(1000);

    try testing.expect(resolved != null);
    try testing.expectEqual(@as(u64, 500), resolved.?.start);
    try testing.expectEqual(@as(u64, 999), resolved.?.end);
    try testing.expectEqual(@as(u64, 500), resolved.?.length);
}

test "ByteRange resolve clamp end" {
    const range = ByteRange.fromStartEnd(0, 9999);
    const resolved = range.resolve(1000);

    try testing.expect(resolved != null);
    try testing.expectEqual(@as(u64, 0), resolved.?.start);
    try testing.expectEqual(@as(u64, 999), resolved.?.end);
    try testing.expectEqual(@as(u64, 1000), resolved.?.length);
}

test "ByteRange resolve unsatisfiable" {
    const range = ByteRange.fromStartEnd(1000, 2000);
    const resolved = range.resolve(500);

    try testing.expect(resolved == null);
}

test "parseRangeHeader single range" {
    var header = try parseRangeHeader(testing.allocator, "bytes=0-499");
    defer header.deinit();

    try testing.expectEqualStrings("bytes", header.unit);
    try testing.expect(header.isSingleRange());
    try testing.expectEqual(@as(u64, 0), header.ranges[0].start.?);
    try testing.expectEqual(@as(u64, 499), header.ranges[0].end.?);
}

test "parseRangeHeader multiple ranges" {
    var header = try parseRangeHeader(testing.allocator, "bytes=0-499, 500-999");
    defer header.deinit();

    try testing.expect(header.isMultipart());
    try testing.expectEqual(@as(usize, 2), header.ranges.len);
}

test "parseRangeHeader suffix range" {
    var header = try parseRangeHeader(testing.allocator, "bytes=-500");
    defer header.deinit();

    try testing.expect(header.ranges[0].isSuffix());
    try testing.expectEqual(@as(u64, 500), header.ranges[0].end.?);
}

test "parseRangeHeader open-ended" {
    var header = try parseRangeHeader(testing.allocator, "bytes=500-");
    defer header.deinit();

    try testing.expectEqual(@as(u64, 500), header.ranges[0].start.?);
    try testing.expect(header.ranges[0].end == null);
}

test "RangeBodyFilter single chunk" {
    const range = ResolvedRange{ .start = 10, .end = 19, .length = 10 };
    var filter = RangeBodyFilter.init(range, 100);

    // Full chunk covering the range
    const data = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const result = filter.filter(data);

    try testing.expect(result != null);
    try testing.expectEqualStrings("ABCDEFGHIJ", result.?);
    try testing.expect(filter.isComplete());
}

test "RangeBodyFilter multiple chunks" {
    const range = ResolvedRange{ .start = 5, .end = 14, .length = 10 };
    var filter = RangeBodyFilter.init(range, 100);

    // First chunk: 0-9
    const chunk1 = "0123456789";
    const result1 = filter.filter(chunk1);
    try testing.expect(result1 != null);
    try testing.expectEqualStrings("56789", result1.?);
    try testing.expect(!filter.isComplete());

    // Second chunk: 10-19
    const chunk2 = "ABCDEFGHIJ";
    const result2 = filter.filter(chunk2);
    try testing.expect(result2 != null);
    try testing.expectEqualStrings("ABCDE", result2.?);
    try testing.expect(filter.isComplete());
}

test "RangeBodyFilter skip before range" {
    const range = ResolvedRange{ .start = 20, .end = 29, .length = 10 };
    var filter = RangeBodyFilter.init(range, 100);

    // Chunk before range
    const chunk = "0123456789";
    const result = filter.filter(chunk);
    try testing.expect(result == null);
    try testing.expect(!filter.isComplete());
}

test "ResolvedRange formatContentRange" {
    const range = ResolvedRange{ .start = 0, .end = 499, .length = 500 };
    var buf: [64]u8 = undefined;
    const result = try range.formatContentRange(1000, &buf);

    try testing.expectEqualStrings("bytes 0-499/1000", result);
}

test "MultipartRangeBuilder" {
    var builder = MultipartRangeBuilder.init(testing.allocator, "boundary123", "text/plain", 1000);
    defer builder.deinit();

    const range1 = ResolvedRange{ .start = 0, .end = 9, .length = 10 };
    try builder.addPart(range1, "0123456789");

    const range2 = ResolvedRange{ .start = 100, .end = 109, .length = 10 };
    try builder.addPart(range2, "ABCDEFGHIJ");

    const body = try builder.finish();
    defer testing.allocator.free(body);

    try testing.expect(std.mem.indexOf(u8, body, "--boundary123") != null);
    try testing.expect(std.mem.indexOf(u8, body, "0123456789") != null);
    try testing.expect(std.mem.indexOf(u8, body, "ABCDEFGHIJ") != null);
    try testing.expect(std.mem.indexOf(u8, body, "--boundary123--") != null);
}

test "RangeResponse build206Response" {
    const range = ResolvedRange{ .start = 0, .end = 499, .length = 500 };
    var resp = try RangeResponse.build206Response(testing.allocator, range, 1000, "text/plain");
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 206), resp.status.code);
    try testing.expect(resp.headers.get("Content-Range") != null);
    try testing.expect(resp.headers.get("Accept-Ranges") != null);
}

test "RangeResponse build416Response" {
    var resp = try RangeResponse.build416Response(testing.allocator, 1000);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 416), resp.status.code);
    try testing.expect(resp.headers.get("Content-Range") != null);
}

test "generateBoundary" {
    const boundary = generateBoundary();
    try testing.expectEqual(@as(usize, 32), boundary.len);
}
