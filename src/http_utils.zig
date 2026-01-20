//! pingora-zig: HTTP Utilities Module
//!
//! Various HTTP utility types and functions including:
//! - FixedBuffer: A buffer with size limit for HTTP bodies
//! - CachedDate: Thread-local cached HTTP Date header generation
//! - Error Response generation utilities
//!
//! This is a pure Zig implementation inspired by Pingora's protocols/http/*.rs

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");

// ============================================================================
// FixedBuffer: Size-limited buffer for HTTP bodies
// ============================================================================

/// A buffer with size limit. When the total amount of data written to the buffer
/// is below the limit, all the data will be held in the buffer. Otherwise, the
/// buffer will report to be truncated.
///
/// Useful for buffering response bodies up to a maximum size before deciding
/// whether to cache them or stream them directly.
pub const FixedBuffer = struct {
    buffer: std.ArrayListUnmanaged(u8),
    allocator: Allocator,
    capacity: usize,
    truncated: bool,

    const Self = @This();

    /// Create a new FixedBuffer with the specified capacity
    pub fn init(allocator: Allocator, capacity: usize) Self {
        return .{
            .buffer = .{},
            .allocator = allocator,
            .capacity = capacity,
            .truncated = false,
        };
    }

    /// Free resources
    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    /// Write data to the buffer. If the buffer would exceed capacity,
    /// mark it as truncated instead of storing the data.
    pub fn write(self: *Self, data: []const u8) void {
        if (!self.truncated and (self.buffer.items.len + data.len <= self.capacity)) {
            self.buffer.appendSlice(self.allocator, data) catch {
                self.truncated = true;
            };
        } else {
            self.truncated = true;
        }
    }

    /// Clear the buffer and reset truncated state
    pub fn clear(self: *Self) void {
        self.truncated = false;
        self.buffer.clearRetainingCapacity();
    }

    /// Check if the buffer is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.buffer.items.len == 0;
    }

    /// Check if the buffer was truncated
    pub fn isTruncated(self: *const Self) bool {
        return self.truncated;
    }

    /// Get the buffer contents if not empty
    pub fn getBuffer(self: *const Self) ?[]const u8 {
        if (!self.isEmpty()) {
            return self.buffer.items;
        }
        return null;
    }

    /// Get the current length of buffered data
    pub fn len(self: *const Self) usize {
        return self.buffer.items.len;
    }

    /// Get remaining capacity
    pub fn remaining(self: *const Self) usize {
        if (self.truncated) return 0;
        return self.capacity - self.buffer.items.len;
    }
};

// ============================================================================
// CachedDate: HTTP Date header caching
// ============================================================================

/// Days of the week abbreviations for HTTP date format
const DAYS = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/// Months abbreviations for HTTP date format
const MONTHS = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// Cached HTTP Date header value.
/// HTTP Date headers only need second precision, so we can cache the formatted
/// string and only regenerate it when the second changes.
pub const CachedDate = struct {
    /// The formatted HTTP date string
    date_string: [29]u8,
    /// Length of the date string (always 29 for HTTP date format)
    date_len: usize,
    /// The epoch second when this was generated
    cached_epoch_sec: i64,

    const Self = @This();

    /// Create a new CachedDate with the current time
    pub fn init() Self {
        var self = Self{
            .date_string = undefined,
            .date_len = 0,
            .cached_epoch_sec = 0,
        };
        self.update();
        return self;
    }

    /// Update the cached date if the second has changed
    pub fn update(self: *Self) void {
        const now_sec = std.time.timestamp();
        if (now_sec != self.cached_epoch_sec) {
            self.cached_epoch_sec = now_sec;
            self.formatDate(now_sec);
        }
    }

    /// Get the cached date string, updating if necessary
    pub fn get(self: *Self) []const u8 {
        self.update();
        return self.date_string[0..self.date_len];
    }

    /// Format an epoch timestamp as an HTTP date
    /// Format: "Sun, 06 Nov 1994 08:49:37 GMT"
    fn formatDate(self: *Self, epoch_sec: i64) void {
        const epoch_day = @divFloor(epoch_sec, 86400);
        const day_sec = @mod(epoch_sec, 86400);

        // Calculate day of week (Jan 1, 1970 was Thursday = 4)
        const day_of_week: usize = @intCast(@mod(epoch_day + 4, 7));

        // Calculate hours, minutes, seconds
        const hour: u8 = @intCast(@divFloor(day_sec, 3600));
        const min: u8 = @intCast(@mod(@divFloor(day_sec, 60), 60));
        const sec: u8 = @intCast(@mod(day_sec, 60));

        // Calculate year, month, day using a simplified algorithm
        var days_remaining: i64 = epoch_day;
        var year: i32 = 1970;

        // Advance by years
        while (true) {
            const days_in_year: i64 = if (isLeapYear(year)) 366 else 365;
            if (days_remaining < days_in_year) break;
            days_remaining -= days_in_year;
            year += 1;
        }

        // Advance by months
        const leap = isLeapYear(year);
        const days_in_months = if (leap)
            [_]i64{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        else
            [_]i64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        var month: usize = 0;
        while (month < 12 and days_remaining >= days_in_months[month]) {
            days_remaining -= days_in_months[month];
            month += 1;
        }

        const day: u8 = @intCast(days_remaining + 1);

        // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
        var stream = std.io.fixedBufferStream(&self.date_string);
        const writer = stream.writer();

        writer.print("{s}, {:0>2} {s} {} {:0>2}:{:0>2}:{:0>2} GMT", .{
            DAYS[day_of_week],
            day,
            MONTHS[month],
            year,
            hour,
            min,
            sec,
        }) catch {};

        self.date_len = stream.pos;
    }

    fn isLeapYear(year: i32) bool {
        return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
    }
};

/// Thread-local cached date header
threadlocal var cached_date: ?CachedDate = null;

/// Get a cached HTTP Date header value.
/// This uses thread-local storage to cache the formatted date string.
pub fn getCachedDate() []const u8 {
    if (cached_date == null) {
        cached_date = CachedDate.init();
    }
    return cached_date.?.get();
}

// ============================================================================
// Error Response Generation
// ============================================================================

/// Server name header value
pub const SERVER_NAME: []const u8 = "pingora-zig";

/// Generate an error response with the given status code.
/// The response has a zero Content-Length and Cache-Control: private, no-store.
pub fn genErrorResponse(allocator: Allocator, code: u16) !http.ResponseHeader {
    var resp = http.ResponseHeader.init(allocator, code);
    errdefer resp.deinit();
    resp.version = .http_1_1;

    try resp.headers.append("Server", SERVER_NAME);
    try resp.headers.append("Date", getCachedDate());
    try resp.headers.append("Content-Length", "0");
    try resp.headers.append("Cache-Control", "private, no-store");

    return resp;
}

/// Pre-defined error response status codes
pub const ErrorResponseCode = enum(u16) {
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    im_a_teapot = 418,
    misdirected_request = 421,
    unprocessable_entity = 422,
    too_early = 425,
    upgrade_required = 426,
    precondition_required = 428,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    unavailable_for_legal_reasons = 451,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    not_extended = 510,
    network_authentication_required = 511,

    pub fn toU16(self: ErrorResponseCode) u16 {
        return @intFromEnum(self);
    }

    /// Get a human-readable reason phrase
    pub fn reasonPhrase(self: ErrorResponseCode) []const u8 {
        return switch (self) {
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .im_a_teapot => "I'm a teapot",
            .misdirected_request => "Misdirected Request",
            .unprocessable_entity => "Unprocessable Entity",
            .too_early => "Too Early",
            .upgrade_required => "Upgrade Required",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .unavailable_for_legal_reasons => "Unavailable For Legal Reasons",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            .variant_also_negotiates => "Variant Also Negotiates",
            .insufficient_storage => "Insufficient Storage",
            .loop_detected => "Loop Detected",
            .not_extended => "Not Extended",
            .network_authentication_required => "Network Authentication Required",
        };
    }
};

/// Generate an error response with body containing the reason phrase
pub fn genErrorResponseWithBody(allocator: Allocator, code: ErrorResponseCode) !struct {
    header: http.ResponseHeader,
    body: []const u8,
} {
    const body = code.reasonPhrase();

    var resp = http.ResponseHeader.init(allocator, code.toU16());
    errdefer resp.deinit();
    resp.version = .http_1_1;

    try resp.headers.append("Server", SERVER_NAME);
    try resp.headers.append("Date", getCachedDate());
    try resp.headers.append("Content-Type", "text/plain; charset=utf-8");

    var len_buf: [20]u8 = undefined;
    const len_str = std.fmt.bufPrint(&len_buf, "{}", .{body.len}) catch "0";
    try resp.headers.append("Content-Length", len_str);
    try resp.headers.append("Cache-Control", "private, no-store");

    return .{
        .header = resp,
        .body = body,
    };
}

/// Generate a simple HTML error page
pub fn genHtmlErrorPage(allocator: Allocator, code: ErrorResponseCode) ![]u8 {
    const reason = code.reasonPhrase();
    const code_num = code.toU16();

    return std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>{d} {s}</title></head>
        \\<body>
        \\<center><h1>{d} {s}</h1></center>
        \\<hr><center>{s}</center>
        \\</body>
        \\</html>
    , .{ code_num, reason, code_num, reason, SERVER_NAME });
}

// ============================================================================
// Tests
// ============================================================================

test "FixedBuffer basic operations" {
    var buf = FixedBuffer.init(std.testing.allocator, 100);
    defer buf.deinit();

    try std.testing.expect(buf.isEmpty());
    try std.testing.expect(!buf.isTruncated());

    buf.write("Hello");
    try std.testing.expect(!buf.isEmpty());
    try std.testing.expectEqual(@as(usize, 5), buf.len());
    try std.testing.expectEqualStrings("Hello", buf.getBuffer().?);

    buf.write(" World");
    try std.testing.expectEqual(@as(usize, 11), buf.len());
    try std.testing.expectEqualStrings("Hello World", buf.getBuffer().?);
}

test "FixedBuffer truncation" {
    var buf = FixedBuffer.init(std.testing.allocator, 10);
    defer buf.deinit();

    buf.write("12345");
    try std.testing.expect(!buf.isTruncated());
    try std.testing.expectEqual(@as(usize, 5), buf.remaining());

    buf.write("67890");
    try std.testing.expect(!buf.isTruncated());
    try std.testing.expectEqual(@as(usize, 0), buf.remaining());

    // This should cause truncation
    buf.write("X");
    try std.testing.expect(buf.isTruncated());
    // Data should still be 10 bytes (not appended)
    try std.testing.expectEqual(@as(usize, 10), buf.len());
}

test "FixedBuffer clear" {
    var buf = FixedBuffer.init(std.testing.allocator, 10);
    defer buf.deinit();

    buf.write("12345678901"); // Causes truncation
    try std.testing.expect(buf.isTruncated());

    buf.clear();
    try std.testing.expect(buf.isEmpty());
    try std.testing.expect(!buf.isTruncated());
}

test "CachedDate format" {
    var date = CachedDate.init();
    const date_str = date.get();

    // Should be 29 characters: "Sun, 06 Nov 1994 08:49:37 GMT"
    try std.testing.expectEqual(@as(usize, 29), date_str.len);

    // Should end with GMT
    try std.testing.expect(std.mem.endsWith(u8, date_str, "GMT"));

    // Should contain a comma
    try std.testing.expect(std.mem.indexOf(u8, date_str, ",") != null);
}

test "getCachedDate thread-local" {
    const date1 = getCachedDate();
    const date2 = getCachedDate();

    // Should be the same (cached)
    try std.testing.expectEqualStrings(date1, date2);
    try std.testing.expectEqual(@as(usize, 29), date1.len);
}

test "genErrorResponse" {
    var resp = try genErrorResponse(std.testing.allocator, 502);
    defer resp.deinit();

    try std.testing.expectEqual(http.StatusCode.init(502), resp.status);
    try std.testing.expect(resp.headers.get("Server") != null);
    try std.testing.expect(resp.headers.get("Date") != null);
    try std.testing.expectEqualStrings("0", resp.headers.get("Content-Length").?);
    try std.testing.expectEqualStrings("private, no-store", resp.headers.get("Cache-Control").?);
}

test "ErrorResponseCode reason phrases" {
    try std.testing.expectEqualStrings("Bad Gateway", ErrorResponseCode.bad_gateway.reasonPhrase());
    try std.testing.expectEqualStrings("Not Found", ErrorResponseCode.not_found.reasonPhrase());
    try std.testing.expectEqualStrings("Internal Server Error", ErrorResponseCode.internal_server_error.reasonPhrase());
    try std.testing.expectEqual(@as(u16, 502), ErrorResponseCode.bad_gateway.toU16());
}

test "genErrorResponseWithBody" {
    var result = try genErrorResponseWithBody(std.testing.allocator, .not_found);
    defer result.header.deinit();

    try std.testing.expectEqual(http.StatusCode.init(404), result.header.status);
    try std.testing.expectEqualStrings("Not Found", result.body);
}

test "genHtmlErrorPage" {
    const html = try genHtmlErrorPage(std.testing.allocator, .bad_gateway);
    defer std.testing.allocator.free(html);

    try std.testing.expect(std.mem.indexOf(u8, html, "502") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "Bad Gateway") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, SERVER_NAME) != null);
}
