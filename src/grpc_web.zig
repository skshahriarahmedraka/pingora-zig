//! pingora-zig: gRPC-Web Bridge
//!
//! Protocol bridging between gRPC and gRPC-Web (RFC 8441).
//! Handles trailer conversion, content-type mapping, and message framing.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const http = @import("http.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// gRPC-Web Content Types
// ============================================================================

/// gRPC content types
pub const ContentType = enum {
    /// Standard gRPC over HTTP/2: application/grpc
    grpc,
    /// gRPC-Web binary format: application/grpc-web
    grpc_web,
    /// gRPC-Web text format (base64): application/grpc-web-text
    grpc_web_text,
    /// gRPC-Web binary with protobuf: application/grpc-web+proto
    grpc_web_proto,
    /// gRPC-Web text with protobuf: application/grpc-web-text+proto
    grpc_web_text_proto,
    /// Unknown content type
    unknown,

    const Self = @This();

    /// Parse content type from header value
    pub fn fromString(value: []const u8) Self {
        // Trim any parameters (e.g., charset)
        const base = if (std.mem.indexOf(u8, value, ";")) |idx|
            std.mem.trim(u8, value[0..idx], " \t")
        else
            std.mem.trim(u8, value, " \t");

        if (std.mem.eql(u8, base, "application/grpc")) return .grpc;
        if (std.mem.eql(u8, base, "application/grpc-web")) return .grpc_web;
        if (std.mem.eql(u8, base, "application/grpc-web-text")) return .grpc_web_text;
        if (std.mem.eql(u8, base, "application/grpc-web+proto")) return .grpc_web_proto;
        if (std.mem.eql(u8, base, "application/grpc-web-text+proto")) return .grpc_web_text_proto;

        // Check for prefix matches
        if (std.mem.startsWith(u8, base, "application/grpc-web-text")) return .grpc_web_text;
        if (std.mem.startsWith(u8, base, "application/grpc-web")) return .grpc_web;
        if (std.mem.startsWith(u8, base, "application/grpc")) return .grpc;

        return .unknown;
    }

    /// Convert to string representation
    pub fn toString(self: Self) []const u8 {
        return switch (self) {
            .grpc => "application/grpc",
            .grpc_web => "application/grpc-web",
            .grpc_web_text => "application/grpc-web-text",
            .grpc_web_proto => "application/grpc-web+proto",
            .grpc_web_text_proto => "application/grpc-web-text+proto",
            .unknown => "application/octet-stream",
        };
    }

    /// Check if this is a gRPC-Web content type
    pub fn isGrpcWeb(self: Self) bool {
        return switch (self) {
            .grpc_web, .grpc_web_text, .grpc_web_proto, .grpc_web_text_proto => true,
            else => false,
        };
    }

    /// Check if this is a text (base64) format
    pub fn isTextFormat(self: Self) bool {
        return self == .grpc_web_text or self == .grpc_web_text_proto;
    }

    /// Get the corresponding gRPC-Web content type for a gRPC type
    pub fn toGrpcWeb(self: Self) Self {
        return switch (self) {
            .grpc => .grpc_web,
            else => self,
        };
    }

    /// Get the corresponding gRPC content type for a gRPC-Web type
    pub fn toGrpc(self: Self) Self {
        return switch (self) {
            .grpc_web, .grpc_web_text, .grpc_web_proto, .grpc_web_text_proto => .grpc,
            else => self,
        };
    }
};

// ============================================================================
// gRPC Message Framing
// ============================================================================

/// gRPC message frame flags
pub const FrameFlags = packed struct {
    /// Compression flag (bit 0)
    compressed: bool = false,
    /// Reserved bits (1-6)
    reserved: u6 = 0,
    /// Trailer flag for gRPC-Web (bit 7)
    trailer: bool = false,

    pub fn toByte(self: FrameFlags) u8 {
        return @bitCast(self);
    }

    pub fn fromByte(byte: u8) FrameFlags {
        return @bitCast(byte);
    }
};

/// gRPC message frame header (5 bytes)
pub const FrameHeader = struct {
    /// Frame flags
    flags: FrameFlags,
    /// Message length (big-endian u32)
    length: u32,

    const HEADER_SIZE = 5;

    /// Parse frame header from bytes
    pub fn parse(data: []const u8) ?FrameHeader {
        if (data.len < HEADER_SIZE) return null;

        const flags = FrameFlags.fromByte(data[0]);
        const length = std.mem.readInt(u32, data[1..5], .big);

        return .{
            .flags = flags,
            .length = length,
        };
    }

    /// Serialize frame header to bytes
    pub fn serialize(self: FrameHeader, buf: *[HEADER_SIZE]u8) void {
        buf[0] = self.flags.toByte();
        std.mem.writeInt(u32, buf[1..5], self.length, .big);
    }

    /// Check if this is a trailer frame
    pub fn isTrailer(self: FrameHeader) bool {
        return self.flags.trailer;
    }

    /// Check if message is compressed
    pub fn isCompressed(self: FrameHeader) bool {
        return self.flags.compressed;
    }
};

/// gRPC message with frame header
pub const GrpcMessage = struct {
    /// Frame header
    header: FrameHeader,
    /// Message payload
    payload: []const u8,

    /// Total size including header
    pub fn totalSize(self: GrpcMessage) usize {
        return FrameHeader.HEADER_SIZE + self.payload.len;
    }
};

// ============================================================================
// gRPC-Web Bridge
// ============================================================================

/// gRPC-Web bridge configuration
pub const BridgeConfig = struct {
    /// Maximum message size (default 4MB)
    max_message_size: usize = 4 * 1024 * 1024,
    /// Whether to allow unary requests only
    unary_only: bool = false,
    /// Timeout for requests (nanoseconds, 0 = no timeout)
    timeout_ns: u64 = 0,
};

/// gRPC-Web bridge for converting between gRPC and gRPC-Web protocols
pub const GrpcWebBridge = struct {
    config: BridgeConfig,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: BridgeConfig) Self {
        return .{
            .config = config,
            .allocator = allocator,
        };
    }

    /// Convert gRPC-Web request to gRPC request
    pub fn requestToGrpc(
        self: *Self,
        req: *http.RequestHeader,
        body: []const u8,
    ) !ConvertedRequest {
        const content_type = if (req.headers.get("content-type")) |ct|
            ContentType.fromString(ct)
        else
            ContentType.unknown;

        if (!content_type.isGrpcWeb()) {
            return error.NotGrpcWeb;
        }

        // Decode body if text format (base64)
        var decoded_body: []u8 = undefined;
        var owned_body = false;

        if (content_type.isTextFormat()) {
            const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(body) catch return error.InvalidBase64;
            decoded_body = try self.allocator.alloc(u8, decoded_len);
            owned_body = true;
            _ = std.base64.standard.Decoder.decode(decoded_body, body) catch {
                self.allocator.free(decoded_body);
                return error.InvalidBase64;
            };
        } else {
            decoded_body = @constCast(body);
        }

        // Update content type to gRPC
        // Note: In a real implementation, we'd modify the request headers

        return .{
            .body = decoded_body,
            .owned = owned_body,
            .original_content_type = content_type,
            .allocator = self.allocator,
        };
    }

    /// Convert gRPC response to gRPC-Web response
    pub fn responseToGrpcWeb(
        self: *Self,
        resp: *http.ResponseHeader,
        body: []const u8,
        trailers: ?[]const Trailer,
        use_text_format: bool,
    ) !ConvertedResponse {
        _ = resp;

        // Calculate total size: body + trailer frame
        var total_size = body.len;
        var trailer_data: ?[]u8 = null;

        if (trailers) |ts| {
            // Build trailer frame
            trailer_data = try self.buildTrailerFrame(ts);
            total_size += trailer_data.?.len;
        }

        // Combine body and trailers
        var combined = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(combined);

        @memcpy(combined[0..body.len], body);
        if (trailer_data) |td| {
            @memcpy(combined[body.len..], td);
            self.allocator.free(td);
        }

        // Encode to base64 if text format
        if (use_text_format) {
            const encoded_len = std.base64.standard.Encoder.calcSize(combined.len);
            const encoded = try self.allocator.alloc(u8, encoded_len);
            _ = std.base64.standard.Encoder.encode(encoded, combined);
            self.allocator.free(combined);
            combined = encoded;
        }

        return .{
            .body = combined,
            .content_type = if (use_text_format) ContentType.grpc_web_text else ContentType.grpc_web,
            .allocator = self.allocator,
        };
    }

    /// Build a trailer frame from trailers
    fn buildTrailerFrame(self: *Self, trailers: []const Trailer) ![]u8 {
        // Calculate trailer data size
        var data_size: usize = 0;
        for (trailers) |t| {
            // Format: "name: value\r\n"
            data_size += t.name.len + 2 + t.value.len + 2;
        }

        // Allocate for header + data
        const total_size = FrameHeader.HEADER_SIZE + data_size;
        var buf = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(buf);

        // Write frame header
        const header = FrameHeader{
            .flags = .{ .trailer = true },
            .length = @intCast(data_size),
        };
        header.serialize(buf[0..FrameHeader.HEADER_SIZE]);

        // Write trailer data
        var offset: usize = FrameHeader.HEADER_SIZE;
        for (trailers) |t| {
            @memcpy(buf[offset..][0..t.name.len], t.name);
            offset += t.name.len;
            buf[offset] = ':';
            buf[offset + 1] = ' ';
            offset += 2;
            @memcpy(buf[offset..][0..t.value.len], t.value);
            offset += t.value.len;
            buf[offset] = '\r';
            buf[offset + 1] = '\n';
            offset += 2;
        }

        return buf;
    }

    /// Parse trailers from a gRPC-Web trailer frame
    pub fn parseTrailerFrame(self: *Self, data: []const u8) ![]Trailer {
        const header = FrameHeader.parse(data) orelse return error.InvalidFrame;

        if (!header.isTrailer()) {
            return error.NotTrailerFrame;
        }

        if (data.len < FrameHeader.HEADER_SIZE + header.length) {
            return error.IncompleteFrame;
        }

        const trailer_data = data[FrameHeader.HEADER_SIZE..][0..header.length];
        return self.parseTrailers(trailer_data);
    }

    /// Parse trailer key-value pairs
    fn parseTrailers(self: *Self, data: []const u8) ![]Trailer {
        var trailers = std.ArrayListUnmanaged(Trailer){};
        errdefer trailers.deinit(self.allocator);

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            if (std.mem.indexOf(u8, line, ": ")) |sep| {
                try trailers.append(self.allocator, .{
                    .name = line[0..sep],
                    .value = line[sep + 2 ..],
                });
            } else if (std.mem.indexOf(u8, line, ":")) |sep| {
                try trailers.append(self.allocator, .{
                    .name = line[0..sep],
                    .value = if (sep + 1 < line.len) line[sep + 1 ..] else "",
                });
            }
        }

        return trailers.toOwnedSlice(self.allocator);
    }

    /// Extract messages from a gRPC stream
    pub fn extractMessages(self: *Self, data: []const u8) MessageIterator {
        return MessageIterator.init(self, data);
    }

    /// Frame a message for gRPC
    pub fn frameMessage(self: *Self, payload: []const u8, compressed: bool) ![]u8 {
        if (payload.len > self.config.max_message_size) {
            return error.MessageTooLarge;
        }

        const total_size = FrameHeader.HEADER_SIZE + payload.len;
        var buf = try self.allocator.alloc(u8, total_size);

        const header = FrameHeader{
            .flags = .{ .compressed = compressed },
            .length = @intCast(payload.len),
        };
        header.serialize(buf[0..FrameHeader.HEADER_SIZE]);
        @memcpy(buf[FrameHeader.HEADER_SIZE..], payload);

        return buf;
    }
};

/// Converted request result
pub const ConvertedRequest = struct {
    body: []u8,
    owned: bool,
    original_content_type: ContentType,
    allocator: Allocator,

    pub fn deinit(self: *ConvertedRequest) void {
        if (self.owned) {
            self.allocator.free(self.body);
        }
    }
};

/// Converted response result
pub const ConvertedResponse = struct {
    body: []u8,
    content_type: ContentType,
    allocator: Allocator,

    pub fn deinit(self: *ConvertedResponse) void {
        self.allocator.free(self.body);
    }
};

/// gRPC trailer
pub const Trailer = struct {
    name: []const u8,
    value: []const u8,
};

/// Iterator for extracting messages from gRPC stream
pub const MessageIterator = struct {
    bridge: *GrpcWebBridge,
    data: []const u8,
    offset: usize,

    pub fn init(bridge: *GrpcWebBridge, data: []const u8) MessageIterator {
        return .{
            .bridge = bridge,
            .data = data,
            .offset = 0,
        };
    }

    pub fn next(self: *MessageIterator) ?GrpcMessage {
        if (self.offset >= self.data.len) return null;

        const remaining = self.data[self.offset..];
        const header = FrameHeader.parse(remaining) orelse return null;

        const total_frame_size = FrameHeader.HEADER_SIZE + header.length;
        if (remaining.len < total_frame_size) return null;

        const payload = remaining[FrameHeader.HEADER_SIZE..][0..header.length];
        self.offset += total_frame_size;

        return GrpcMessage{
            .header = header,
            .payload = payload,
        };
    }

    pub fn reset(self: *MessageIterator) void {
        self.offset = 0;
    }
};

// ============================================================================
// gRPC Status Codes
// ============================================================================

/// gRPC status codes
pub const StatusCode = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,

    pub fn toString(self: StatusCode) []const u8 {
        return switch (self) {
            .ok => "OK",
            .cancelled => "CANCELLED",
            .unknown => "UNKNOWN",
            .invalid_argument => "INVALID_ARGUMENT",
            .deadline_exceeded => "DEADLINE_EXCEEDED",
            .not_found => "NOT_FOUND",
            .already_exists => "ALREADY_EXISTS",
            .permission_denied => "PERMISSION_DENIED",
            .resource_exhausted => "RESOURCE_EXHAUSTED",
            .failed_precondition => "FAILED_PRECONDITION",
            .aborted => "ABORTED",
            .out_of_range => "OUT_OF_RANGE",
            .unimplemented => "UNIMPLEMENTED",
            .internal => "INTERNAL",
            .unavailable => "UNAVAILABLE",
            .data_loss => "DATA_LOSS",
            .unauthenticated => "UNAUTHENTICATED",
        };
    }

    pub fn fromInt(code: u8) StatusCode {
        return std.meta.intToEnum(StatusCode, code) catch .unknown;
    }
};

/// gRPC status with message
pub const Status = struct {
    code: StatusCode,
    message: ?[]const u8,

    pub fn ok() Status {
        return .{ .code = .ok, .message = null };
    }

    pub fn err(code: StatusCode, message: ?[]const u8) Status {
        return .{ .code = code, .message = message };
    }

    /// Format as trailers
    pub fn toTrailers(self: Status, allocator: Allocator) ![]Trailer {
        var trailers = std.ArrayListUnmanaged(Trailer){};
        errdefer trailers.deinit(allocator);

        // grpc-status
        var status_buf: [4]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{@intFromEnum(self.code)}) catch "0";
        try trailers.append(allocator, .{ .name = "grpc-status", .value = status_str });

        // grpc-message (if present)
        if (self.message) |msg| {
            try trailers.append(allocator, .{ .name = "grpc-message", .value = msg });
        }

        return trailers.toOwnedSlice(allocator);
    }

    /// Parse from trailers
    pub fn fromTrailers(trailers: []const Trailer) Status {
        var code: StatusCode = .ok;
        var message: ?[]const u8 = null;

        for (trailers) |t| {
            if (std.mem.eql(u8, t.name, "grpc-status")) {
                const parsed = std.fmt.parseInt(u8, t.value, 10) catch 2;
                code = StatusCode.fromInt(parsed);
            } else if (std.mem.eql(u8, t.name, "grpc-message")) {
                message = t.value;
            }
        }

        return .{ .code = code, .message = message };
    }
};

// ============================================================================
// gRPC-Web HTTP Module
// ============================================================================

/// gRPC-Web module for the HTTP modules framework
pub const GrpcWebModule = struct {
    const http_modules = @import("http_modules.zig");

    pub fn create() http_modules.HttpModule {
        return http_modules.HttpModule.create("grpc_web", "gRPC-Web Bridge", 30)
            .withRequestFilter(handleRequest)
            .withResponseHeaderFilter(handleResponseHeaders);
    }

    fn handleRequest(ctx: *http_modules.ModuleContext, req: *http.RequestHeader) anyerror!http_modules.ModuleAction {
        // Check if this is a gRPC-Web request
        if (req.headers.get("content-type")) |ct| {
            const content_type = ContentType.fromString(ct);
            if (content_type.isGrpcWeb()) {
                // Store original content type in context
                try ctx.set("grpc_web_original_ct", @ptrCast(@constCast(ct.ptr)));

                // Convert content type for upstream
                try req.setHeader("content-type", "application/grpc");
            }
        }
        return .continue_processing;
    }

    fn handleResponseHeaders(_: *http_modules.ModuleContext, _: *http.RequestHeader, resp: *http.ResponseHeader) anyerror!http_modules.ModuleAction {
        // Check if response is gRPC and convert to gRPC-Web
        if (resp.headers.get("content-type")) |ct| {
            const content_type = ContentType.fromString(ct);
            if (content_type == .grpc) {
                try resp.setHeader("content-type", ContentType.grpc_web.toString());
            }
        }
        return .continue_processing;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ContentType parsing" {
    try testing.expectEqual(ContentType.grpc, ContentType.fromString("application/grpc"));
    try testing.expectEqual(ContentType.grpc_web, ContentType.fromString("application/grpc-web"));
    try testing.expectEqual(ContentType.grpc_web_text, ContentType.fromString("application/grpc-web-text"));
    try testing.expectEqual(ContentType.grpc_web_proto, ContentType.fromString("application/grpc-web+proto"));

    // With parameters
    try testing.expectEqual(ContentType.grpc, ContentType.fromString("application/grpc; charset=utf-8"));
    try testing.expectEqual(ContentType.grpc_web, ContentType.fromString("application/grpc-web; mode=binary"));
}

test "ContentType properties" {
    try testing.expect(ContentType.grpc_web.isGrpcWeb());
    try testing.expect(ContentType.grpc_web_text.isGrpcWeb());
    try testing.expect(!ContentType.grpc.isGrpcWeb());

    try testing.expect(ContentType.grpc_web_text.isTextFormat());
    try testing.expect(!ContentType.grpc_web.isTextFormat());
}

test "ContentType conversion" {
    try testing.expectEqual(ContentType.grpc_web, ContentType.grpc.toGrpcWeb());
    try testing.expectEqual(ContentType.grpc, ContentType.grpc_web.toGrpc());
    try testing.expectEqual(ContentType.grpc, ContentType.grpc_web_text.toGrpc());
}

test "FrameFlags" {
    const flags1 = FrameFlags{};
    try testing.expectEqual(@as(u8, 0), flags1.toByte());

    const flags2 = FrameFlags{ .compressed = true };
    try testing.expectEqual(@as(u8, 1), flags2.toByte());

    const flags3 = FrameFlags{ .trailer = true };
    try testing.expectEqual(@as(u8, 128), flags3.toByte());

    const flags4 = FrameFlags{ .compressed = true, .trailer = true };
    try testing.expectEqual(@as(u8, 129), flags4.toByte());

    // Round trip
    const parsed = FrameFlags.fromByte(129);
    try testing.expect(parsed.compressed);
    try testing.expect(parsed.trailer);
}

test "FrameHeader parse and serialize" {
    var buf: [5]u8 = undefined;
    const header = FrameHeader{
        .flags = .{ .compressed = false },
        .length = 1000,
    };
    header.serialize(&buf);

    const parsed = FrameHeader.parse(&buf);
    try testing.expect(parsed != null);
    try testing.expectEqual(@as(u32, 1000), parsed.?.length);
    try testing.expect(!parsed.?.isCompressed());
    try testing.expect(!parsed.?.isTrailer());
}

test "FrameHeader trailer frame" {
    var buf: [5]u8 = undefined;
    const header = FrameHeader{
        .flags = .{ .trailer = true },
        .length = 50,
    };
    header.serialize(&buf);

    const parsed = FrameHeader.parse(&buf);
    try testing.expect(parsed != null);
    try testing.expect(parsed.?.isTrailer());
}

test "GrpcWebBridge frame message" {
    var bridge = GrpcWebBridge.init(testing.allocator, .{});

    const payload = "Hello, gRPC!";
    const framed = try bridge.frameMessage(payload, false);
    defer testing.allocator.free(framed);

    try testing.expectEqual(@as(usize, 5 + payload.len), framed.len);

    // Parse it back
    const header = FrameHeader.parse(framed);
    try testing.expect(header != null);
    try testing.expectEqual(@as(u32, payload.len), header.?.length);
    try testing.expect(!header.?.isCompressed());
}

test "GrpcWebBridge message too large" {
    var bridge = GrpcWebBridge.init(testing.allocator, .{ .max_message_size = 10 });

    const payload = "This is a message that is too large";
    try testing.expectError(error.MessageTooLarge, bridge.frameMessage(payload, false));
}

test "MessageIterator" {
    var bridge = GrpcWebBridge.init(testing.allocator, .{});

    // Create two messages
    const msg1 = try bridge.frameMessage("Hello", false);
    defer testing.allocator.free(msg1);
    const msg2 = try bridge.frameMessage("World", false);
    defer testing.allocator.free(msg2);

    // Combine them
    const combined = try testing.allocator.alloc(u8, msg1.len + msg2.len);
    defer testing.allocator.free(combined);
    @memcpy(combined[0..msg1.len], msg1);
    @memcpy(combined[msg1.len..], msg2);

    // Iterate
    var iter = bridge.extractMessages(combined);

    const first = iter.next();
    try testing.expect(first != null);
    try testing.expectEqualStrings("Hello", first.?.payload);

    const second = iter.next();
    try testing.expect(second != null);
    try testing.expectEqualStrings("World", second.?.payload);

    const third = iter.next();
    try testing.expect(third == null);
}

test "StatusCode" {
    try testing.expectEqualStrings("OK", StatusCode.ok.toString());
    try testing.expectEqualStrings("INTERNAL", StatusCode.internal.toString());
    try testing.expectEqual(StatusCode.not_found, StatusCode.fromInt(5));
    try testing.expectEqual(StatusCode.unknown, StatusCode.fromInt(255));
}

test "Status toTrailers" {
    const status = Status.err(.not_found, "Resource not found");
    const trailers = try status.toTrailers(testing.allocator);
    defer testing.allocator.free(trailers);

    try testing.expectEqual(@as(usize, 2), trailers.len);
    try testing.expectEqualStrings("grpc-status", trailers[0].name);
    try testing.expectEqualStrings("grpc-message", trailers[1].name);
}

test "Status fromTrailers" {
    const trailers = [_]Trailer{
        .{ .name = "grpc-status", .value = "5" },
        .{ .name = "grpc-message", .value = "Not found" },
    };

    const status = Status.fromTrailers(&trailers);
    try testing.expectEqual(StatusCode.not_found, status.code);
    try testing.expectEqualStrings("Not found", status.message.?);
}

test "Status ok" {
    const status = Status.ok();
    try testing.expectEqual(StatusCode.ok, status.code);
    try testing.expect(status.message == null);
}
