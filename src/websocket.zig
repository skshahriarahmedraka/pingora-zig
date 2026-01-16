//! WebSocket Protocol Implementation (RFC 6455)
//!
//! This module provides WebSocket frame parsing, building, and connection
//! management. It supports both client and server modes.
//!
//! Per-message deflate compression (RFC 7692) uses zlib C library.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const http = @import("http.zig");

// ============================================================================
// Zlib C Bindings for Per-Message Deflate (RFC 7692)
// ============================================================================

const c = @cImport({
    @cInclude("zlib.h");
});

/// Zlib return codes
const Z_OK = 0;
const Z_STREAM_END = 1;
const Z_NEED_DICT = 2;
const Z_BUF_ERROR = -5;
const Z_FINISH = 4;
const Z_SYNC_FLUSH = 2;
const Z_NO_FLUSH = 0;

/// Default compression level
const Z_DEFAULT_COMPRESSION = -1;

/// Deflate method
const Z_DEFLATED = 8;

/// Maximum window bits for raw deflate (negative for raw, no zlib header)
const MAX_WBITS = 15;

// ============================================================================
// WebSocket Constants
// ============================================================================

/// WebSocket GUID for handshake (RFC 6455)
pub const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Maximum frame payload size (for safety)
pub const MAX_PAYLOAD_SIZE: u64 = 16 * 1024 * 1024; // 16 MB

/// Maximum control frame payload (RFC 6455)
pub const MAX_CONTROL_PAYLOAD: usize = 125;

// ============================================================================
// WebSocket Opcodes (RFC 6455 Section 5.2)
// ============================================================================

/// WebSocket frame opcodes
pub const Opcode = enum(u4) {
    /// Continuation frame
    continuation = 0x0,
    /// Text frame (UTF-8)
    text = 0x1,
    /// Binary frame
    binary = 0x2,
    // 0x3-0x7 reserved for non-control frames
    /// Connection close
    close = 0x8,
    /// Ping
    ping = 0x9,
    /// Pong
    pong = 0xA,
    // 0xB-0xF reserved for control frames
    _,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn isData(self: Opcode) bool {
        return @intFromEnum(self) <= 0x2;
    }
};

// ============================================================================
// WebSocket Close Codes (RFC 6455 Section 7.4.1)
// ============================================================================

/// WebSocket close status codes
pub const CloseCode = enum(u16) {
    /// Normal closure
    normal = 1000,
    /// Going away (server shutdown, browser navigating away)
    going_away = 1001,
    /// Protocol error
    protocol_error = 1002,
    /// Unsupported data type
    unsupported_data = 1003,
    /// Reserved (not used)
    reserved = 1004,
    /// No status code present (internal use)
    no_status = 1005,
    /// Abnormal closure (internal use)
    abnormal = 1006,
    /// Invalid payload data (e.g., non-UTF8 in text frame)
    invalid_payload = 1007,
    /// Policy violation
    policy_violation = 1008,
    /// Message too big
    message_too_big = 1009,
    /// Missing extension
    missing_extension = 1010,
    /// Internal server error
    internal_error = 1011,
    /// TLS handshake failure (internal use)
    tls_handshake = 1015,
    _,

    pub fn isValid(code: u16) bool {
        // Valid ranges: 1000-1011, 3000-3999, 4000-4999
        if (code >= 1000 and code <= 1011) return true;
        if (code >= 3000 and code <= 4999) return true;
        return false;
    }
};

// ============================================================================
// WebSocket Frame Header
// ============================================================================

/// Parsed WebSocket frame header
pub const FrameHeader = struct {
    /// Final fragment flag
    fin: bool,
    /// RSV1 flag (used by extensions)
    rsv1: bool,
    /// RSV2 flag (used by extensions)
    rsv2: bool,
    /// RSV3 flag (used by extensions)
    rsv3: bool,
    /// Frame opcode
    opcode: Opcode,
    /// Whether payload is masked
    masked: bool,
    /// Payload length
    payload_len: u64,
    /// Masking key (if masked)
    mask_key: ?[4]u8,
    /// Total header size in bytes
    header_size: usize,

    const Self = @This();

    /// Parse a frame header from bytes
    /// Returns null if not enough data
    pub fn parse(data: []const u8) ?Self {
        if (data.len < 2) return null;

        const byte0 = data[0];
        const byte1 = data[1];

        const fin = (byte0 & 0x80) != 0;
        const rsv1 = (byte0 & 0x40) != 0;
        const rsv2 = (byte0 & 0x20) != 0;
        const rsv3 = (byte0 & 0x10) != 0;
        const opcode: Opcode = @enumFromInt(@as(u4, @truncate(byte0 & 0x0F)));

        const masked = (byte1 & 0x80) != 0;
        var payload_len: u64 = byte1 & 0x7F;

        var offset: usize = 2;

        // Extended payload length
        if (payload_len == 126) {
            if (data.len < 4) return null;
            payload_len = (@as(u64, data[2]) << 8) | @as(u64, data[3]);
            offset = 4;
        } else if (payload_len == 127) {
            if (data.len < 10) return null;
            payload_len = (@as(u64, data[2]) << 56) |
                (@as(u64, data[3]) << 48) |
                (@as(u64, data[4]) << 40) |
                (@as(u64, data[5]) << 32) |
                (@as(u64, data[6]) << 24) |
                (@as(u64, data[7]) << 16) |
                (@as(u64, data[8]) << 8) |
                @as(u64, data[9]);
            offset = 10;
        }

        // Masking key
        var mask_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < offset + 4) return null;
            mask_key = data[offset..][0..4].*;
            offset += 4;
        }

        return .{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .payload_len = payload_len,
            .mask_key = mask_key,
            .header_size = offset,
        };
    }

    /// Calculate header size for a given payload length and mask
    pub fn calcSize(payload_len: u64, masked: bool) usize {
        var size: usize = 2;
        if (payload_len > 65535) {
            size += 8;
        } else if (payload_len > 125) {
            size += 2;
        }
        if (masked) {
            size += 4;
        }
        return size;
    }

    /// Total frame size (header + payload)
    pub fn totalSize(self: Self) u64 {
        return self.header_size + self.payload_len;
    }
};

// ============================================================================
// WebSocket Frame Builder
// ============================================================================

/// Build a WebSocket frame
pub const FrameBuilder = struct {
    /// Build a frame header into a buffer
    /// Returns the number of bytes written
    pub fn buildHeader(
        buf: []u8,
        opcode: Opcode,
        payload_len: u64,
        fin: bool,
        mask_key: ?[4]u8,
    ) usize {
        return buildHeaderExt(buf, opcode, payload_len, fin, false, mask_key);
    }

    /// Build a frame header with RSV1 support (used by permessage-deflate)
    pub fn buildHeaderExt(
        buf: []u8,
        opcode: Opcode,
        payload_len: u64,
        fin: bool,
        rsv1: bool,
        mask_key: ?[4]u8,
    ) usize {
        var offset: usize = 0;

        // Byte 0: FIN + RSV + opcode
        buf[0] = (if (fin) @as(u8, 0x80) else 0) |
            (if (rsv1) @as(u8, 0x40) else 0) |
            @as(u8, @intFromEnum(opcode));
        offset += 1;

        // Byte 1+: MASK + payload length
        const masked: u8 = if (mask_key != null) 0x80 else 0;

        if (payload_len <= 125) {
            buf[1] = masked | @as(u8, @truncate(payload_len));
            offset += 1;
        } else if (payload_len <= 65535) {
            buf[1] = masked | 126;
            buf[2] = @truncate(payload_len >> 8);
            buf[3] = @truncate(payload_len);
            offset += 3;
        } else {
            buf[1] = masked | 127;
            buf[2] = @truncate(payload_len >> 56);
            buf[3] = @truncate(payload_len >> 48);
            buf[4] = @truncate(payload_len >> 40);
            buf[5] = @truncate(payload_len >> 32);
            buf[6] = @truncate(payload_len >> 24);
            buf[7] = @truncate(payload_len >> 16);
            buf[8] = @truncate(payload_len >> 8);
            buf[9] = @truncate(payload_len);
            offset += 9;
        }

        // Masking key
        if (mask_key) |key| {
            buf[offset] = key[0];
            buf[offset + 1] = key[1];
            buf[offset + 2] = key[2];
            buf[offset + 3] = key[3];
            offset += 4;
        }

        return offset;
    }

    /// Build a complete text frame
    pub fn buildTextFrame(allocator: Allocator, data: []const u8, mask_key: ?[4]u8) ![]u8 {
        return buildFrame(allocator, .text, data, true, mask_key);
    }

    /// Build a complete binary frame
    pub fn buildBinaryFrame(allocator: Allocator, data: []const u8, mask_key: ?[4]u8) ![]u8 {
        return buildFrame(allocator, .binary, data, true, mask_key);
    }

    /// Build a ping frame
    pub fn buildPingFrame(allocator: Allocator, data: []const u8, mask_key: ?[4]u8) ![]u8 {
        if (data.len > MAX_CONTROL_PAYLOAD) return error.PayloadTooLarge;
        return buildFrame(allocator, .ping, data, true, mask_key);
    }

    /// Build a pong frame
    pub fn buildPongFrame(allocator: Allocator, data: []const u8, mask_key: ?[4]u8) ![]u8 {
        if (data.len > MAX_CONTROL_PAYLOAD) return error.PayloadTooLarge;
        return buildFrame(allocator, .pong, data, true, mask_key);
    }

    /// Build a close frame
    pub fn buildCloseFrame(allocator: Allocator, code: ?CloseCode, reason: ?[]const u8, mask_key: ?[4]u8) ![]u8 {
        var payload_buf: [MAX_CONTROL_PAYLOAD]u8 = undefined;
        var payload_len: usize = 0;

        if (code) |close_code| {
            const code_val: u16 = @intFromEnum(close_code);
            payload_buf[0] = @truncate(code_val >> 8);
            payload_buf[1] = @truncate(code_val);
            payload_len = 2;

            if (reason) |r| {
                const reason_len = @min(r.len, MAX_CONTROL_PAYLOAD - 2);
                @memcpy(payload_buf[2..][0..reason_len], r[0..reason_len]);
                payload_len += reason_len;
            }
        }

        return buildFrame(allocator, .close, payload_buf[0..payload_len], true, mask_key);
    }

    /// Build a generic frame
    pub fn buildFrame(allocator: Allocator, opcode: Opcode, data: []const u8, fin: bool, mask_key: ?[4]u8) ![]u8 {
        return buildFrameExt(allocator, opcode, data, fin, false, mask_key);
    }

    /// Build a generic frame with RSV1 support (used by permessage-deflate)
    pub fn buildFrameExt(allocator: Allocator, opcode: Opcode, data: []const u8, fin: bool, rsv1: bool, mask_key: ?[4]u8) ![]u8 {
        const header_size = FrameHeader.calcSize(data.len, mask_key != null);
        const frame = try allocator.alloc(u8, header_size + data.len);
        errdefer allocator.free(frame);

        _ = buildHeaderExt(frame, opcode, data.len, fin, rsv1, mask_key);

        // Copy and optionally mask payload
        if (mask_key) |key| {
            for (data, 0..) |byte, i| {
                frame[header_size + i] = byte ^ key[i % 4];
            }
        } else {
            @memcpy(frame[header_size..], data);
        }

        return frame;
    }
};

// ============================================================================
// WebSocket Masking
// ============================================================================

/// Apply or remove XOR mask to data (in-place)
pub fn applyMask(data: []u8, mask_key: [4]u8) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= mask_key[i % 4];
    }
}

/// Generate a random masking key
pub fn generateMaskKey() [4]u8 {
    var key: [4]u8 = undefined;
    std.crypto.random.bytes(&key);
    return key;
}

// ============================================================================
// WebSocket Handshake
// ============================================================================

/// Generate a Sec-WebSocket-Accept header value
pub fn generateAcceptKey(client_key: []const u8) [28]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(client_key);
    hasher.update(WS_GUID);
    const hash = hasher.finalResult();

    var encoded: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &hash);
    return encoded;
}

/// Validate a Sec-WebSocket-Accept value
pub fn validateAcceptKey(client_key: []const u8, accept_key: []const u8) bool {
    const expected = generateAcceptKey(client_key);
    return std.mem.eql(u8, &expected, accept_key);
}

/// Generate a random Sec-WebSocket-Key (for clients)
pub fn generateClientKey() [24]u8 {
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    var encoded: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &random_bytes);
    return encoded;
}

// ============================================================================
// WebSocket Connection State
// ============================================================================

/// WebSocket connection state
pub const ConnectionState = enum {
    /// Connection is being established
    connecting,
    /// Connection is open and ready
    open,
    /// Close handshake in progress
    closing,
    /// Connection is closed
    closed,
};

/// WebSocket connection
pub const Connection = struct {
    /// Current state
    state: ConnectionState,
    /// Whether this is a client (clients must mask)
    is_client: bool,
    /// Allocator
    allocator: Allocator,
    /// Accumulated message fragments
    fragment_buffer: std.ArrayListUnmanaged(u8),
    /// Opcode of fragmented message
    fragment_opcode: ?Opcode,
    /// Close code received
    close_code: ?CloseCode,
    /// Close reason received
    close_reason: ?[]u8,

    const Self = @This();

    pub fn init(allocator: Allocator, is_client: bool) Self {
        return .{
            .state = .connecting,
            .is_client = is_client,
            .allocator = allocator,
            .fragment_buffer = .{},
            .fragment_opcode = null,
            .close_code = null,
            .close_reason = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.fragment_buffer.deinit(self.allocator);
        if (self.close_reason) |reason| {
            self.allocator.free(reason);
        }
    }

    /// Mark connection as open (after successful handshake)
    pub fn markOpen(self: *Self) void {
        self.state = .open;
    }

    /// Check if connection can send data
    pub fn canSend(self: *const Self) bool {
        return self.state == .open or self.state == .closing;
    }

    /// Check if connection can receive data
    pub fn canReceive(self: *const Self) bool {
        return self.state == .open or self.state == .closing;
    }

    /// Process a received frame header
    pub fn processFrameHeader(self: *Self, header: FrameHeader) !void {
        // Validate frame
        if (header.rsv1 or header.rsv2 or header.rsv3) {
            // RSV bits must be 0 unless extension is negotiated
            return error.ProtocolError;
        }

        // Control frames must not be fragmented
        if (header.opcode.isControl() and !header.fin) {
            return error.ProtocolError;
        }

        // Control frames must be <= 125 bytes
        if (header.opcode.isControl() and header.payload_len > MAX_CONTROL_PAYLOAD) {
            return error.ProtocolError;
        }

        // Client frames must be masked, server frames must not
        if (self.is_client) {
            if (header.masked) return error.ProtocolError;
        } else {
            if (!header.masked) return error.ProtocolError;
        }

        // Handle close frame
        if (header.opcode == .close) {
            if (self.state == .open) {
                self.state = .closing;
            }
        }
    }

    /// Add fragment to buffer
    pub fn addFragment(self: *Self, opcode: Opcode, data: []const u8, fin: bool) !void {
        if (self.fragment_opcode == null) {
            // Start of new message
            if (opcode == .continuation) {
                return error.ProtocolError;
            }
            self.fragment_opcode = opcode;
        } else {
            // Continuation
            if (opcode != .continuation) {
                return error.ProtocolError;
            }
        }

        try self.fragment_buffer.appendSlice(self.allocator, data);

        if (fin) {
            // Message complete - would normally deliver here
            self.fragment_opcode = null;
        }
    }

    /// Get and clear the fragment buffer (returns owned slice)
    pub fn takeFragmentBuffer(self: *Self) ![]u8 {
        const result = try self.fragment_buffer.toOwnedSlice(self.allocator);
        self.fragment_opcode = null;
        return result;
    }

    /// Build a text message frame
    pub fn buildTextMessage(self: *Self, data: []const u8) ![]u8 {
        const mask = if (self.is_client) generateMaskKey() else null;
        return FrameBuilder.buildTextFrame(self.allocator, data, mask);
    }

    /// Build a binary message frame
    pub fn buildBinaryMessage(self: *Self, data: []const u8) ![]u8 {
        const mask = if (self.is_client) generateMaskKey() else null;
        return FrameBuilder.buildBinaryFrame(self.allocator, data, mask);
    }

    /// Build a ping frame
    pub fn buildPing(self: *Self, data: []const u8) ![]u8 {
        const mask = if (self.is_client) generateMaskKey() else null;
        return FrameBuilder.buildPingFrame(self.allocator, data, mask);
    }

    /// Build a pong frame
    pub fn buildPong(self: *Self, data: []const u8) ![]u8 {
        const mask = if (self.is_client) generateMaskKey() else null;
        return FrameBuilder.buildPongFrame(self.allocator, data, mask);
    }

    /// Build a close frame and transition to closing
    pub fn buildClose(self: *Self, code: ?CloseCode, reason: ?[]const u8) ![]u8 {
        if (self.state == .open) {
            self.state = .closing;
        }
        const mask = if (self.is_client) generateMaskKey() else null;
        return FrameBuilder.buildCloseFrame(self.allocator, code, reason, mask);
    }

    /// Parse close frame payload
    pub fn parseClosePayload(self: *Self, payload: []const u8) !void {
        if (payload.len >= 2) {
            const code: u16 = (@as(u16, payload[0]) << 8) | payload[1];
            self.close_code = @enumFromInt(code);

            if (payload.len > 2) {
                self.close_reason = try self.allocator.dupe(u8, payload[2..]);
            }
        }
    }

    /// Mark connection as closed
    pub fn markClosed(self: *Self) void {
        self.state = .closed;
    }
};

// ============================================================================
// WebSocket Message
// ============================================================================

/// A complete WebSocket message
pub const Message = struct {
    /// Message type
    opcode: Opcode,
    /// Message data
    data: []u8,
    /// Allocator used for data
    allocator: Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    /// Check if this is a text message
    pub fn isText(self: *const Self) bool {
        return self.opcode == .text;
    }

    /// Check if this is a binary message
    pub fn isBinary(self: *const Self) bool {
        return self.opcode == .binary;
    }

    /// Get text data (only valid for text messages)
    pub fn getText(self: *const Self) []const u8 {
        return self.data;
    }
};

// ============================================================================
// WebSocket Handshake (RFC 6455 Section 4)
// ============================================================================

/// WebSocket handshake request builder (for clients)
pub const HandshakeRequest = struct {
    /// Host header value
    host: []const u8,
    /// Request path
    path: []const u8,
    /// Origin header (optional)
    origin: ?[]const u8,
    /// Requested protocols (Sec-WebSocket-Protocol)
    protocols: []const []const u8,
    /// Requested extensions (Sec-WebSocket-Extensions)
    extensions: []const []const u8,
    /// The generated client key
    key: [24]u8,

    const Self = @This();

    pub fn init(host: []const u8, path: []const u8) Self {
        return .{
            .host = host,
            .path = path,
            .origin = null,
            .protocols = &.{},
            .extensions = &.{},
            .key = generateClientKey(),
        };
    }

    /// Build the HTTP upgrade request
    pub fn build(self: Self, allocator: Allocator) ![]u8 {
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);

        try writer.print("GET {s} HTTP/1.1\r\n", .{self.path});
        try writer.print("Host: {s}\r\n", .{self.host});
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Key: {s}\r\n", .{self.key});
        try writer.writeAll("Sec-WebSocket-Version: 13\r\n");

        if (self.origin) |origin| {
            try writer.print("Origin: {s}\r\n", .{origin});
        }

        if (self.protocols.len > 0) {
            try writer.writeAll("Sec-WebSocket-Protocol: ");
            for (self.protocols, 0..) |proto, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll(proto);
            }
            try writer.writeAll("\r\n");
        }

        if (self.extensions.len > 0) {
            try writer.writeAll("Sec-WebSocket-Extensions: ");
            for (self.extensions, 0..) |ext, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll(ext);
            }
            try writer.writeAll("\r\n");
        }

        try writer.writeAll("\r\n");

        return list.toOwnedSlice(allocator);
    }

    /// Validate the server's handshake response
    pub fn validateResponse(self: Self, accept_key: []const u8) bool {
        return validateAcceptKey(&self.key, accept_key);
    }
};

/// WebSocket handshake response builder (for servers)
pub const HandshakeResponse = struct {
    /// Selected protocol (if any)
    protocol: ?[]const u8,
    /// Selected extensions (if any)
    extensions: []const []const u8,
    /// The accept key to send
    accept_key: [28]u8,

    const Self = @This();

    pub fn init(client_key: []const u8) Self {
        return .{
            .protocol = null,
            .extensions = &.{},
            .accept_key = generateAcceptKey(client_key),
        };
    }

    /// Build the HTTP upgrade response
    pub fn build(self: Self, allocator: Allocator) ![]u8 {
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);

        try writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Accept: {s}\r\n", .{self.accept_key});

        if (self.protocol) |proto| {
            try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{proto});
        }

        if (self.extensions.len > 0) {
            try writer.writeAll("Sec-WebSocket-Extensions: ");
            for (self.extensions, 0..) |ext, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll(ext);
            }
            try writer.writeAll("\r\n");
        }

        try writer.writeAll("\r\n");

        return list.toOwnedSlice(allocator);
    }
};

// ============================================================================
// WebSocket Message Reassembler
// ============================================================================

/// Reassembles fragmented WebSocket messages
pub const MessageReassembler = struct {
    /// Buffer for accumulating fragments
    buffer: std.ArrayListUnmanaged(u8),
    /// Opcode of the message being reassembled
    opcode: ?Opcode,
    /// Whether the current message is compressed (RSV1 on first data frame)
    compressed: bool,
    /// Maximum message size allowed
    max_message_size: usize,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_message_size: usize) Self {
        return .{
            .buffer = .{},
            .opcode = null,
            .compressed = false,
            .max_message_size = max_message_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    /// Process a frame and return a complete message if ready.
    /// If `permessage_deflate` is non-null and RSV1 is set on the first data frame,
    /// the reassembled message will be transparently decompressed.
    pub fn processFrame(self: *Self, header: FrameHeader, payload: []const u8, permessage_deflate: ?*PerMessageDeflate) !?Message {
        // Control frames don't participate in fragmentation
        if (header.opcode.isControl()) {
            const data = try self.allocator.dupe(u8, payload);
            return Message{
                .opcode = header.opcode,
                .data = data,
                .allocator = self.allocator,
            };
        }

        // RSV1 is only valid on the first frame of a (possibly fragmented) data message.
        if (header.opcode == .continuation and header.rsv1) {
            return error.ProtocolError;
        }

        // Check for protocol errors
        if (header.opcode == .continuation) {
            if (self.opcode == null) {
                return error.ProtocolError; // Continuation without start
            }
        } else {
            if (self.opcode != null) {
                return error.ProtocolError; // New message while reassembling
            }
            self.opcode = header.opcode;
            self.compressed = header.rsv1;
        }

        // Check message size limit
        if (self.buffer.items.len + payload.len > self.max_message_size) {
            return error.MessageTooLarge;
        }

        // Add payload to buffer
        try self.buffer.appendSlice(self.allocator, payload);

        // If FIN, return complete message
        if (header.fin) {
            const data_raw = try self.buffer.toOwnedSlice(self.allocator);
            errdefer self.allocator.free(data_raw);

            const opcode = self.opcode.?;
            const was_compressed = self.compressed;
            self.opcode = null;
            self.compressed = false;

            if (was_compressed) {
                const inflater = permessage_deflate orelse return error.ProtocolError;
                const decompressed = try inflater.decompressMessage(data_raw);
                self.allocator.free(data_raw);
                return Message{
                    .opcode = opcode,
                    .data = decompressed,
                    .allocator = self.allocator,
                };
            }

            return Message{
                .opcode = opcode,
                .data = data_raw,
                .allocator = self.allocator,
            };
        }

        return null; // More fragments expected
    }

    /// Reset the reassembler state
    pub fn reset(self: *Self) void {
        self.buffer.clearRetainingCapacity();
        self.opcode = null;
        self.compressed = false;
    }

    /// Check if currently reassembling a message
    pub fn isReassembling(self: *const Self) bool {
        return self.opcode != null;
    }
};

// ============================================================================
// WebSocket Ping/Pong Handler
// ============================================================================

/// Handles WebSocket ping/pong for connection keepalive
pub const PingPongHandler = struct {
    /// Pending pong data (if waiting for pong)
    pending_pong: ?[]u8,
    /// Time when ping was sent
    ping_sent_time: ?i64,
    /// Ping timeout in milliseconds
    ping_timeout_ms: i64,
    /// Last pong received time
    last_pong_time: ?i64,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, ping_timeout_ms: i64) Self {
        return .{
            .pending_pong = null,
            .ping_sent_time = null,
            .ping_timeout_ms = ping_timeout_ms,
            .last_pong_time = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.pending_pong) |pong| {
            self.allocator.free(pong);
        }
    }

    /// Create a ping frame with random data
    pub fn createPing(self: *Self) ![MAX_CONTROL_PAYLOAD]u8 {
        var data: [MAX_CONTROL_PAYLOAD]u8 = undefined;
        // Use first 8 bytes for random data
        std.crypto.random.bytes(data[0..8]);

        // Store expected pong data
        if (self.pending_pong) |old| {
            self.allocator.free(old);
        }
        self.pending_pong = try self.allocator.dupe(u8, data[0..8]);
        self.ping_sent_time = std.time.milliTimestamp();

        return data;
    }

    /// Check if a pong matches the expected data
    pub fn validatePong(self: *Self, pong_data: []const u8) bool {
        if (self.pending_pong) |expected| {
            if (std.mem.eql(u8, expected, pong_data)) {
                self.allocator.free(expected);
                self.pending_pong = null;
                self.last_pong_time = std.time.milliTimestamp();
                return true;
            }
        }
        return false;
    }

    /// Check if ping has timed out
    pub fn hasTimedOut(self: *const Self) bool {
        if (self.ping_sent_time) |sent| {
            const now = std.time.milliTimestamp();
            return (now - sent) > self.ping_timeout_ms;
        }
        return false;
    }

    /// Get round-trip time of last successful ping/pong
    pub fn getRtt(self: *const Self) ?i64 {
        if (self.ping_sent_time != null and self.last_pong_time != null) {
            return self.last_pong_time.? - self.ping_sent_time.?;
        }
        return null;
    }
};

// ============================================================================
// WebSocket Extension Support (RFC 7692 - Per-Message Compression)
// ============================================================================

/// Per-message deflate extension parameters
pub const PerMessageDeflateParams = struct {
    /// Server's maximum window bits (8-15)
    server_max_window_bits: u4 = 15,
    /// Client's maximum window bits (8-15)
    client_max_window_bits: u4 = 15,
    /// Server takes over context
    server_no_context_takeover: bool = false,
    /// Client takes over context
    client_no_context_takeover: bool = false,

    const Self = @This();

    /// Parse extension parameters from header value
    pub fn parse(value: []const u8) Self {
        var params = Self{};

        var it = std.mem.splitScalar(u8, value, ';');
        while (it.next()) |param| {
            const trimmed = std.mem.trim(u8, param, " ");
            if (std.mem.startsWith(u8, trimmed, "server_max_window_bits=")) {
                const bits_str = trimmed["server_max_window_bits=".len..];
                params.server_max_window_bits = std.fmt.parseInt(u4, bits_str, 10) catch 15;
            } else if (std.mem.startsWith(u8, trimmed, "client_max_window_bits=")) {
                const bits_str = trimmed["client_max_window_bits=".len..];
                params.client_max_window_bits = std.fmt.parseInt(u4, bits_str, 10) catch 15;
            } else if (std.mem.eql(u8, trimmed, "server_no_context_takeover")) {
                params.server_no_context_takeover = true;
            } else if (std.mem.eql(u8, trimmed, "client_no_context_takeover")) {
                params.client_no_context_takeover = true;
            }
        }

        return params;
    }

    /// Serialize parameters for header
    pub fn serialize(self: Self, allocator: Allocator) ![]u8 {
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);
        try writer.writeAll("permessage-deflate");

        if (self.server_max_window_bits != 15) {
            try writer.print("; server_max_window_bits={d}", .{self.server_max_window_bits});
        }
        if (self.client_max_window_bits != 15) {
            try writer.print("; client_max_window_bits={d}", .{self.client_max_window_bits});
        }
        if (self.server_no_context_takeover) {
            try writer.writeAll("; server_no_context_takeover");
        }
        if (self.client_no_context_takeover) {
            try writer.writeAll("; client_no_context_takeover");
        }

        return list.toOwnedSlice(allocator);
    }
};

/// RFC 7692 per-message deflate implementation.
///
/// We use raw DEFLATE streams (no zlib header) and follow RFC 7692's special
/// tail handling: compressed messages are produced with Z_SYNC_FLUSH and the
/// last 4 bytes 0x00 0x00 0xff 0xff are removed; on decompression those bytes
/// are appended back before inflating.
pub const PerMessageDeflate = struct {
    allocator: Allocator,
    params: PerMessageDeflateParams,

    // z_stream must be kept across messages when context takeover is enabled.
    deflate_stream: c.z_stream,
    inflate_stream: c.z_stream,
    deflate_inited: bool,
    inflate_inited: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, params: PerMessageDeflateParams) !Self {
        return .{
            .allocator = allocator,
            .params = params,
            .deflate_stream = std.mem.zeroes(c.z_stream),
            .inflate_stream = std.mem.zeroes(c.z_stream),
            .deflate_inited = false,
            .inflate_inited = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.deflate_inited) {
            _ = c.deflateEnd(&self.deflate_stream);
            self.deflate_inited = false;
        }
        if (self.inflate_inited) {
            _ = c.inflateEnd(&self.inflate_stream);
            self.inflate_inited = false;
        }
    }

    fn ensureDeflateInit(self: *Self) !void {
        if (self.deflate_inited) return;
        // Negative window bits => raw deflate.
        const wbits: c_int = -@as(c_int, @intCast(@min(MAX_WBITS, @as(u8, self.params.client_max_window_bits))));
        // memLevel 8, strategy default.
        const rc = c.deflateInit2_(&self.deflate_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits, 8, 0, c.zlibVersion(), @sizeOf(c.z_stream));
        if (rc != Z_OK) return error.OutOfMemory;
        self.deflate_inited = true;
    }

    fn ensureInflateInit(self: *Self) !void {
        if (self.inflate_inited) return;
        const wbits: c_int = -@as(c_int, @intCast(@min(MAX_WBITS, @as(u8, self.params.server_max_window_bits))));
        const rc = c.inflateInit2_(&self.inflate_stream, wbits, c.zlibVersion(), @sizeOf(c.z_stream));
        if (rc != Z_OK) return error.OutOfMemory;
        self.inflate_inited = true;
    }

    fn maybeResetDeflate(self: *Self) void {
        if (self.params.client_no_context_takeover and self.deflate_inited) {
            _ = c.deflateReset(&self.deflate_stream);
        }
    }

    fn maybeResetInflate(self: *Self) void {
        if (self.params.server_no_context_takeover and self.inflate_inited) {
            _ = c.inflateReset(&self.inflate_stream);
        }
    }

    /// Compress a message payload (caller sets RSV1 on the first data frame).
    pub fn compressMessage(self: *Self, payload: []const u8) ![]u8 {
        try self.ensureDeflateInit();

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        // Conservative initial capacity (deflate can expand a little).
        try out.ensureTotalCapacity(self.allocator, payload.len + 64);

        // Prepare input
        self.deflate_stream.next_in = @constCast(payload.ptr);
        self.deflate_stream.avail_in = @intCast(payload.len);

        // Use Z_SYNC_FLUSH and then remove trailing 0x00 0x00 0xff 0xff
        while (true) {
            const start_len = out.items.len;
            try out.ensureTotalCapacity(self.allocator, out.items.len + 4096);
            const chunk = out.unusedCapacitySlice();

            self.deflate_stream.next_out = chunk.ptr;
            self.deflate_stream.avail_out = @intCast(chunk.len);

            const rc = c.deflate(&self.deflate_stream, Z_SYNC_FLUSH);
            const produced: usize = chunk.len - @as(usize, @intCast(self.deflate_stream.avail_out));
            out.items.len = start_len + produced;

            if (rc == Z_OK) {
                if (self.deflate_stream.avail_in == 0 and self.deflate_stream.avail_out != 0) break;
                continue;
            }
            if (rc == Z_BUF_ERROR and self.deflate_stream.avail_in == 0) break;
            return error.OutOfMemory;
        }

        // RFC 7692: remove last 4 bytes 0x00 0x00 0xff 0xff.
        if (out.items.len >= 4) {
            const tail = out.items[out.items.len - 4 .. out.items.len];
            if (std.mem.eql(u8, tail, &[_]u8{ 0x00, 0x00, 0xff, 0xff })) {
                out.items.len -= 4;
            }
        }

        self.maybeResetDeflate();
        return out.toOwnedSlice(self.allocator);
    }

    /// Decompress a message payload (concatenated fragments). Returns owned slice.
    pub fn decompressMessage(self: *Self, payload: []const u8) ![]u8 {
        try self.ensureInflateInit();

        // Append RFC 7692 tail
        var input = std.ArrayListUnmanaged(u8){};
        defer input.deinit(self.allocator);
        try input.appendSlice(self.allocator, payload);
        try input.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00, 0xff, 0xff });

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        self.inflate_stream.next_in = input.items.ptr;
        self.inflate_stream.avail_in = @intCast(input.items.len);

        while (true) {
            const start_len = out.items.len;
            try out.ensureTotalCapacity(self.allocator, out.items.len + 4096);
            const chunk = out.unusedCapacitySlice();

            self.inflate_stream.next_out = chunk.ptr;
            self.inflate_stream.avail_out = @intCast(chunk.len);

            const rc = c.inflate(&self.inflate_stream, Z_NO_FLUSH);
            const produced: usize = chunk.len - @as(usize, @intCast(self.inflate_stream.avail_out));
            out.items.len = start_len + produced;

            if (rc == Z_STREAM_END) break;
            if (rc == Z_OK) {
                if (self.inflate_stream.avail_in == 0 and self.inflate_stream.avail_out != 0) break;
                continue;
            }
            if (rc == Z_BUF_ERROR and self.inflate_stream.avail_in == 0) break;
            if (rc == Z_NEED_DICT) return error.ProtocolError;
            return error.ProtocolError;
        }

        self.maybeResetInflate();
        return out.toOwnedSlice(self.allocator);
    }
};

/// WebSocket extension negotiation
pub const ExtensionNegotiator = struct {
    /// Supported extensions
    supported: std.ArrayListUnmanaged([]const u8),
    /// Negotiated extensions
    negotiated: std.ArrayListUnmanaged([]const u8),
    /// Per-message deflate params (if negotiated)
    deflate_params: ?PerMessageDeflateParams,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .supported = .{},
            .negotiated = .{},
            .deflate_params = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.supported.deinit(self.allocator);
        self.negotiated.deinit(self.allocator);
    }

    /// Add a supported extension
    pub fn addSupported(self: *Self, extension: []const u8) !void {
        try self.supported.append(self.allocator, extension);
    }

    /// Process offered extensions and select those we support
    pub fn negotiate(self: *Self, offered: []const u8) !void {
        var it = std.mem.splitScalar(u8, offered, ',');
        while (it.next()) |ext| {
            const trimmed = std.mem.trim(u8, ext, " ");

            // Extract extension name (before any parameters)
            var name_end: usize = 0;
            for (trimmed, 0..) |ch, i| {
                if (ch == ';' or ch == ' ') {
                    name_end = i;
                    break;
                }
                name_end = i + 1;
            }
            const name = trimmed[0..name_end];

            // Check if we support this extension
            for (self.supported.items) |supported| {
                if (std.mem.eql(u8, supported, name)) {
                    try self.negotiated.append(self.allocator, supported);

                    // Parse parameters for known extensions
                    if (std.mem.eql(u8, name, "permessage-deflate")) {
                        self.deflate_params = PerMessageDeflateParams.parse(trimmed);
                    }
                    break;
                }
            }
        }
    }

    /// Check if an extension was negotiated
    pub fn hasExtension(self: *const Self, name: []const u8) bool {
        for (self.negotiated.items) |ext| {
            if (std.mem.eql(u8, ext, name)) return true;
        }
        return false;
    }

    /// Check if compression is enabled
    pub fn isCompressionEnabled(self: *const Self) bool {
        return self.deflate_params != null;
    }
};

// ============================================================================
// Enhanced WebSocket Client
// ============================================================================

/// Full-featured WebSocket client
pub const WebSocketClient = struct {
    /// Connection state
    connection: Connection,
    /// Message reassembler
    reassembler: MessageReassembler,
    /// Ping/pong handler
    ping_handler: PingPongHandler,
    /// Extension negotiator
    extensions: ExtensionNegotiator,
    /// Per-message deflate state (when negotiated)
    permessage_deflate: ?*PerMessageDeflate,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .connection = Connection.init(allocator, true), // Client mode
            .reassembler = MessageReassembler.init(allocator, MAX_PAYLOAD_SIZE),
            .ping_handler = PingPongHandler.init(allocator, 30000), // 30 second timeout
            .extensions = ExtensionNegotiator.init(allocator),
            .permessage_deflate = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.connection.deinit();
        self.reassembler.deinit();
        self.ping_handler.deinit();
        self.extensions.deinit();
        if (self.permessage_deflate) |pmd| {
            pmd.*.deinit();
            self.allocator.destroy(pmd);
        }
    }

    /// Enable per-message deflate (typically after successful handshake negotiation).
    pub fn enablePerMessageDeflate(self: *Self, params: PerMessageDeflateParams) !void {
        // If re-enabled, free old state first.
        if (self.permessage_deflate) |old| {
            old.*.deinit();
            self.allocator.destroy(old);
            self.permessage_deflate = null;
        }

        self.extensions.deflate_params = params;
        const pmd_ptr = try self.allocator.create(PerMessageDeflate);
        pmd_ptr.* = try PerMessageDeflate.init(self.allocator, params);
        self.permessage_deflate = pmd_ptr;
    }

    /// Create a handshake request
    pub fn createHandshake(self: *Self, host: []const u8, path: []const u8) HandshakeRequest {
        _ = self;
        return HandshakeRequest.init(host, path);
    }

    /// Process a received frame
    pub fn processFrame(self: *Self, data: []const u8) !?Message {
        const header = FrameHeader.parse(data) orelse return error.InvalidFrame;

        // Validate frame
        try self.connection.processFrameHeader(header);

        // Get payload
        if (data.len < header.header_size + header.payload_len) {
            return error.IncompleteFrame;
        }

        const payload = try self.allocator.alloc(u8, @intCast(header.payload_len));
        defer self.allocator.free(payload);
        @memcpy(payload, data[header.header_size..][0..@intCast(header.payload_len)]);

        // Unmask if needed
        if (header.mask_key) |key| {
            applyMask(payload, key);
        }

        // Handle control frames
        switch (header.opcode) {
            .ping => {
                // Auto-respond with pong (caller should send this)
                return Message{
                    .opcode = .ping,
                    .data = try self.allocator.dupe(u8, payload),
                    .allocator = self.allocator,
                };
            },
            .pong => {
                _ = self.ping_handler.validatePong(payload);
                return null; // Pong handled internally
            },
            .close => {
                try self.connection.parseClosePayload(payload);
                self.connection.state = .closing;
                return Message{
                    .opcode = .close,
                    .data = try self.allocator.dupe(u8, payload),
                    .allocator = self.allocator,
                };
            },
            else => {
                // Data frame - reassemble (and decompress if needed)
                const pmd_ptr: ?*PerMessageDeflate = if (self.permessage_deflate) |*pmd| pmd else null;
                return self.reassembler.processFrame(header, payload, pmd_ptr);
            },
        }
    }

    /// Send a text message
    pub fn sendText(self: *Self, text: []const u8) ![]u8 {
        if (self.extensions.isCompressionEnabled()) {
            const pmd = self.permessage_deflate orelse return error.ProtocolError;
            const compressed = try pmd.compressMessage(text);
            defer self.allocator.free(compressed);

            // Client must mask.
            const mask = generateMaskKey();
            return FrameBuilder.buildFrameExt(self.allocator, .text, compressed, true, true, mask);
        }
        return self.connection.buildTextMessage(text);
    }

    /// Send a binary message
    pub fn sendBinary(self: *Self, data: []const u8) ![]u8 {
        if (self.extensions.isCompressionEnabled()) {
            const pmd = self.permessage_deflate orelse return error.ProtocolError;
            const compressed = try pmd.compressMessage(data);
            defer self.allocator.free(compressed);

            // Client must mask.
            const mask = generateMaskKey();
            return FrameBuilder.buildFrameExt(self.allocator, .binary, compressed, true, true, mask);
        }
        return self.connection.buildBinaryMessage(data);
    }

    /// Send a ping
    pub fn sendPing(self: *Self) ![]u8 {
        const ping_data = try self.ping_handler.createPing();
        return self.connection.buildPing(ping_data[0..8]);
    }

    /// Send a close frame
    pub fn sendClose(self: *Self, code: ?CloseCode, reason: ?[]const u8) ![]u8 {
        return self.connection.buildClose(code, reason);
    }

    /// Check connection health
    pub fn isHealthy(self: *const Self) bool {
        return self.connection.state == .open and !self.ping_handler.hasTimedOut();
    }
};

// ============================================================================
// Enhanced WebSocket Server
// ============================================================================

/// Full-featured WebSocket server connection handler
pub const WebSocketServer = struct {
    /// Connection state
    connection: Connection,
    /// Message reassembler
    reassembler: MessageReassembler,
    /// Extension negotiator
    extensions: ExtensionNegotiator,
    /// Per-message deflate state (when negotiated)
    permessage_deflate: ?*PerMessageDeflate,
    /// Subprotocol (if negotiated)
    subprotocol: ?[]const u8,
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .connection = Connection.init(allocator, false), // Server mode
            .reassembler = MessageReassembler.init(allocator, MAX_PAYLOAD_SIZE),
            .extensions = ExtensionNegotiator.init(allocator),
            .permessage_deflate = null,
            .subprotocol = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.connection.deinit();
        self.reassembler.deinit();
        self.extensions.deinit();
        if (self.permessage_deflate) |pmd| {
            pmd.deinit();
            self.allocator.destroy(pmd);
        }
    }

    /// Create a handshake response
    pub fn createHandshakeResponse(self: *Self, client_key: []const u8) HandshakeResponse {
        _ = self;
        return HandshakeResponse.init(client_key);
    }

    /// Enable per-message deflate (typically after successful handshake negotiation).
    pub fn enablePerMessageDeflate(self: *Self, params: PerMessageDeflateParams) !void {
        // If re-enabled, free old state first.
        if (self.permessage_deflate) |old| {
            old.*.deinit();
            self.allocator.destroy(old);
            self.permessage_deflate = null;
        }

        self.extensions.deflate_params = params;
        const pmd_ptr = try self.allocator.create(PerMessageDeflate);
        pmd_ptr.* = try PerMessageDeflate.init(self.allocator, params);
        self.permessage_deflate = pmd_ptr;
    }

    /// Accept the connection (after sending handshake response)
    pub fn accept(self: *Self) void {
        self.connection.markOpen();
    }

    /// Process a received frame
    pub fn processFrame(self: *Self, data: []const u8) !?Message {
        const header = FrameHeader.parse(data) orelse return error.InvalidFrame;

        // Validate frame
        // Allow RSV1 only when permessage-deflate is negotiated.
        if (header.rsv2 or header.rsv3) return error.ProtocolError;
        if (header.rsv1 and !self.extensions.isCompressionEnabled()) return error.ProtocolError;

        // Reuse Connection's masking + control-frame checks, but ignore RSV bits there.
        const header_no_rsv = FrameHeader{
            .fin = header.fin,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = header.opcode,
            .masked = header.masked,
            .payload_len = header.payload_len,
            .mask_key = header.mask_key,
            .header_size = header.header_size,
        };
        try self.connection.processFrameHeader(header_no_rsv);

        // Get payload
        if (data.len < header.header_size + header.payload_len) {
            return error.IncompleteFrame;
        }

        const payload = try self.allocator.alloc(u8, @intCast(header.payload_len));
        defer self.allocator.free(payload);
        @memcpy(payload, data[header.header_size..][0..@intCast(header.payload_len)]);

        // Unmask (clients must mask)
        if (header.mask_key) |key| {
            applyMask(payload, key);
        }

        // Handle based on opcode
        switch (header.opcode) {
            .ping => {
                return Message{
                    .opcode = .ping,
                    .data = try self.allocator.dupe(u8, payload),
                    .allocator = self.allocator,
                };
            },
            .pong => {
                return null; // Ignore pongs
            },
            .close => {
                try self.connection.parseClosePayload(payload);
                self.connection.state = .closing;
                return Message{
                    .opcode = .close,
                    .data = try self.allocator.dupe(u8, payload),
                    .allocator = self.allocator,
                };
            },
            else => {
                return self.reassembler.processFrame(header, payload, self.permessage_deflate);
            },
        }
    }

    /// Send a text message
    pub fn sendText(self: *Self, text: []const u8) ![]u8 {
        return self.connection.buildTextMessage(text);
    }

    /// Send a binary message
    pub fn sendBinary(self: *Self, data: []const u8) ![]u8 {
        return self.connection.buildBinaryMessage(data);
    }

    /// Send a pong (in response to ping)
    pub fn sendPong(self: *Self, ping_data: []const u8) ![]u8 {
        return self.connection.buildPong(ping_data);
    }

    /// Send a close frame
    pub fn sendClose(self: *Self, code: ?CloseCode, reason: ?[]const u8) ![]u8 {
        return self.connection.buildClose(code, reason);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Opcode properties" {
    try testing.expect(Opcode.text.isData());
    try testing.expect(Opcode.binary.isData());
    try testing.expect(Opcode.continuation.isData());
    try testing.expect(!Opcode.ping.isData());

    try testing.expect(Opcode.close.isControl());
    try testing.expect(Opcode.ping.isControl());
    try testing.expect(Opcode.pong.isControl());
    try testing.expect(!Opcode.text.isControl());
}

test "CloseCode validation" {
    try testing.expect(CloseCode.isValid(1000));
    try testing.expect(CloseCode.isValid(1001));
    try testing.expect(CloseCode.isValid(3000));
    try testing.expect(CloseCode.isValid(4000));
    try testing.expect(!CloseCode.isValid(999));
    try testing.expect(!CloseCode.isValid(1012));
    try testing.expect(!CloseCode.isValid(2999));
}

test "FrameHeader parse - small payload" {
    // Text frame, FIN, no mask, 5 bytes payload
    const data = [_]u8{ 0x81, 0x05 };
    const header = FrameHeader.parse(&data).?;

    try testing.expect(header.fin);
    try testing.expectEqual(header.opcode, .text);
    try testing.expect(!header.masked);
    try testing.expectEqual(header.payload_len, 5);
    try testing.expectEqual(header.header_size, 2);
}

test "FrameHeader parse - medium payload" {
    // Binary frame, FIN, no mask, 1000 bytes payload
    const data = [_]u8{ 0x82, 0x7E, 0x03, 0xE8 };
    const header = FrameHeader.parse(&data).?;

    try testing.expect(header.fin);
    try testing.expectEqual(header.opcode, .binary);
    try testing.expectEqual(header.payload_len, 1000);
    try testing.expectEqual(header.header_size, 4);
}

test "FrameHeader parse - masked" {
    // Text frame, FIN, masked, 5 bytes payload
    const data = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d };
    const header = FrameHeader.parse(&data).?;

    try testing.expect(header.masked);
    try testing.expectEqual(header.mask_key.?, [_]u8{ 0x37, 0xfa, 0x21, 0x3d });
    try testing.expectEqual(header.header_size, 6);
}

test "FrameHeader calcSize" {
    try testing.expectEqual(FrameHeader.calcSize(10, false), 2);
    try testing.expectEqual(FrameHeader.calcSize(10, true), 6);
    try testing.expectEqual(FrameHeader.calcSize(200, false), 4);
    try testing.expectEqual(FrameHeader.calcSize(70000, false), 10);
}

test "FrameBuilder buildHeader" {
    var buf: [14]u8 = undefined;

    // Small frame
    const len1 = FrameBuilder.buildHeader(&buf, .text, 5, true, null);
    try testing.expectEqual(len1, 2);
    try testing.expectEqual(buf[0], 0x81);
    try testing.expectEqual(buf[1], 0x05);

    // Medium frame
    const len2 = FrameBuilder.buildHeader(&buf, .binary, 1000, true, null);
    try testing.expectEqual(len2, 4);
    try testing.expectEqual(buf[1], 126);
}

test "applyMask" {
    var data = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    const mask = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };

    applyMask(&data, mask);
    // Data is now masked

    applyMask(&data, mask);
    // Data is restored
    try testing.expectEqualStrings("Hello", &data);
}

test "generateAcceptKey" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = generateAcceptKey(client_key);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "validateAcceptKey" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    try testing.expect(validateAcceptKey(client_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    try testing.expect(!validateAcceptKey(client_key, "invalid"));
}

test "Connection init" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    try testing.expectEqual(conn.state, .connecting);
    try testing.expect(conn.is_client);
}

test "Connection state transitions" {
    var conn = Connection.init(testing.allocator, false);
    defer conn.deinit();

    try testing.expect(!conn.canSend());
    conn.markOpen();
    try testing.expect(conn.canSend());
    try testing.expect(conn.canReceive());

    conn.state = .closing;
    try testing.expect(conn.canSend());

    conn.markClosed();
    try testing.expect(!conn.canSend());
}

test "Connection processFrameHeader validation" {
    var server_conn = Connection.init(testing.allocator, false);
    defer server_conn.deinit();
    server_conn.markOpen();

    // Server should reject unmasked frames
    const unmasked_header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = null,
        .header_size = 2,
    };
    try testing.expectError(error.ProtocolError, server_conn.processFrameHeader(unmasked_header));
}

test "Connection fragment handling" {
    var conn = Connection.init(testing.allocator, false);
    defer conn.deinit();
    conn.markOpen();

    // First fragment
    try conn.addFragment(.text, "Hello", false);
    try testing.expectEqual(conn.fragment_opcode.?, .text);

    // Continuation
    try conn.addFragment(.continuation, " World", true);

    const buffer = try conn.takeFragmentBuffer();
    defer conn.allocator.free(buffer);
    try testing.expectEqualStrings("Hello World", buffer);
}

test "FrameBuilder buildTextFrame" {
    const frame = try FrameBuilder.buildTextFrame(testing.allocator, "Hello", null);
    defer testing.allocator.free(frame);

    const header = FrameHeader.parse(frame).?;
    try testing.expectEqual(header.opcode, .text);
    try testing.expect(header.fin);
    try testing.expectEqual(header.payload_len, 5);
    try testing.expectEqualStrings("Hello", frame[header.header_size..]);
}

test "FrameBuilder buildCloseFrame" {
    const frame = try FrameBuilder.buildCloseFrame(testing.allocator, .normal, "goodbye", null);
    defer testing.allocator.free(frame);

    const header = FrameHeader.parse(frame).?;
    try testing.expectEqual(header.opcode, .close);
    try testing.expectEqual(header.payload_len, 9); // 2 bytes code + 7 bytes reason
}

test "Connection buildTextMessage client" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();
    conn.markOpen();

    const frame = try conn.buildTextMessage("Hello");
    defer conn.allocator.free(frame);

    const header = FrameHeader.parse(frame).?;
    try testing.expect(header.masked); // Client must mask
}

test "Connection buildTextMessage server" {
    var conn = Connection.init(testing.allocator, false);
    defer conn.deinit();
    conn.markOpen();

    const frame = try conn.buildTextMessage("Hello");
    defer conn.allocator.free(frame);

    const header = FrameHeader.parse(frame).?;
    try testing.expect(!header.masked); // Server must not mask
}

// ============================================================================
// Enhanced WebSocket Tests
// ============================================================================

test "HandshakeRequest build" {
    var req = HandshakeRequest.init("example.com", "/ws");
    const data = try req.build(testing.allocator);
    defer testing.allocator.free(data);

    try testing.expect(std.mem.indexOf(u8, data, "GET /ws HTTP/1.1") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Host: example.com") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Connection: Upgrade") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Sec-WebSocket-Key:") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Sec-WebSocket-Version: 13") != null);
}

test "HandshakeRequest validateResponse" {
    const req = HandshakeRequest.init("example.com", "/ws");
    const accept = generateAcceptKey(&req.key);
    try testing.expect(req.validateResponse(&accept));
    try testing.expect(!req.validateResponse("invalid-key"));
}

test "HandshakeResponse build" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var resp = HandshakeResponse.init(client_key);
    const data = try resp.build(testing.allocator);
    defer testing.allocator.free(data);

    try testing.expect(std.mem.indexOf(u8, data, "HTTP/1.1 101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Connection: Upgrade") != null);
    try testing.expect(std.mem.indexOf(u8, data, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
}

test "MessageReassembler single frame" {
    var reassembler = MessageReassembler.init(testing.allocator, 1024);
    defer reassembler.deinit();

    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = null,
        .header_size = 2,
    };

    var msg = (try reassembler.processFrame(header, "Hello", null)).?;
    defer msg.deinit();

    try testing.expectEqualStrings("Hello", msg.data);
    try testing.expectEqual(msg.opcode, .text);
}

test "MessageReassembler fragmented message" {
    var reassembler = MessageReassembler.init(testing.allocator, 1024);
    defer reassembler.deinit();

    // First fragment
    const header1 = FrameHeader{
        .fin = false,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = null,
        .header_size = 2,
    };
    const result1 = try reassembler.processFrame(header1, "Hello", null);
    try testing.expect(result1 == null);
    try testing.expect(reassembler.isReassembling());

    // Continuation
    const header2 = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .continuation,
        .masked = false,
        .payload_len = 6,
        .mask_key = null,
        .header_size = 2,
    };
    var msg = (try reassembler.processFrame(header2, " World", null)).?;
    defer msg.deinit();

    try testing.expectEqualStrings("Hello World", msg.data);
    try testing.expect(!reassembler.isReassembling());
}

test "MessageReassembler message too large" {
    var reassembler = MessageReassembler.init(testing.allocator, 10); // Small limit
    defer reassembler.deinit();

    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 20,
        .mask_key = null,
        .header_size = 2,
    };

    try testing.expectError(error.MessageTooLarge, reassembler.processFrame(header, "This is way too long", null));
}

test "PingPongHandler timeout" {
    var handler = PingPongHandler.init(testing.allocator, 100); // 100ms timeout
    defer handler.deinit();

    try testing.expect(!handler.hasTimedOut());

    _ = try handler.createPing();
    // Immediately after creating ping, should not be timed out
    try testing.expect(!handler.hasTimedOut());
}

test "PingPongHandler validate pong" {
    var handler = PingPongHandler.init(testing.allocator, 30000);
    defer handler.deinit();

    const ping_data = try handler.createPing();
    try testing.expect(handler.pending_pong != null);

    // Valid pong
    try testing.expect(handler.validatePong(ping_data[0..8]));
    try testing.expect(handler.pending_pong == null);

    // Invalid pong (no pending)
    try testing.expect(!handler.validatePong("invalid"));
}

test "PerMessageDeflateParams parse" {
    const params = PerMessageDeflateParams.parse("permessage-deflate; server_max_window_bits=12; client_no_context_takeover");

    try testing.expectEqual(params.server_max_window_bits, 12);
    try testing.expectEqual(params.client_max_window_bits, 15); // Default
    try testing.expect(!params.server_no_context_takeover);
    try testing.expect(params.client_no_context_takeover);
}

test "PerMessageDeflateParams serialize" {
    var params = PerMessageDeflateParams{};
    params.server_max_window_bits = 10;
    params.server_no_context_takeover = true;

    const result = try params.serialize(testing.allocator);
    defer testing.allocator.free(result);

    try testing.expect(std.mem.indexOf(u8, result, "permessage-deflate") != null);
    try testing.expect(std.mem.indexOf(u8, result, "server_max_window_bits=10") != null);
    try testing.expect(std.mem.indexOf(u8, result, "server_no_context_takeover") != null);
}

test "ExtensionNegotiator negotiate" {
    var negotiator = ExtensionNegotiator.init(testing.allocator);
    defer negotiator.deinit();

    try negotiator.addSupported("permessage-deflate");

    try negotiator.negotiate("permessage-deflate; server_max_window_bits=12, x-unknown-ext");

    try testing.expect(negotiator.hasExtension("permessage-deflate"));
    try testing.expect(!negotiator.hasExtension("x-unknown-ext"));
    try testing.expect(negotiator.isCompressionEnabled());
    try testing.expectEqual(negotiator.deflate_params.?.server_max_window_bits, 12);
}

test "PerMessageDeflate compress/decompress roundtrip" {
    const params = PerMessageDeflateParams{};
    var pmd = try PerMessageDeflate.init(testing.allocator, params);
    defer pmd.deinit();

    const input = "Hello permessage-deflate! Hello permessage-deflate! Hello permessage-deflate!";
    const compressed = try pmd.compressMessage(input);
    defer testing.allocator.free(compressed);

    // compressed can be smaller or larger depending on input, but must be non-empty
    try testing.expect(compressed.len > 0);

    const decompressed = try pmd.decompressMessage(compressed);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualStrings(input, decompressed);
}

test "WebSocketServer processFrame decompresses RSV1 message" {
    var server = WebSocketServer.init(testing.allocator);
    defer server.deinit();
    server.accept();

    // Enable permessage-deflate
    try server.enablePerMessageDeflate(PerMessageDeflateParams{});

    // Build a compressed binary frame with RSV1 set.
    var pmd = try PerMessageDeflate.init(testing.allocator, PerMessageDeflateParams{});
    defer pmd.deinit();

    const payload = "Compressed payload over WebSocket";
    const compressed = try pmd.compressMessage(payload);
    defer testing.allocator.free(compressed);

    // Client-to-server frames must be masked.
    const mask = generateMaskKey();
    const frame = try FrameBuilder.buildFrameExt(testing.allocator, .binary, compressed, true, true, mask);
    defer testing.allocator.free(frame);

    // Server should return a fully decompressed message.
    var msg = (try server.processFrame(frame)).?;
    defer msg.deinit();

    try testing.expectEqual(msg.opcode, .binary);
    try testing.expectEqualStrings(payload, msg.data);
}

test "WebSocketClient sendText sets RSV1 when compression enabled" {
    var client = WebSocketClient.init(testing.allocator);
    defer client.deinit();

    try client.enablePerMessageDeflate(PerMessageDeflateParams{});

    const frame = try client.sendText("hello");
    defer testing.allocator.free(frame);

    const header = FrameHeader.parse(frame).?;
    try testing.expect(header.rsv1);
    try testing.expectEqual(header.opcode, .text);
}

test "WebSocketClient init and deinit" {
    var client = WebSocketClient.init(testing.allocator);
    defer client.deinit();

    try testing.expect(!client.isHealthy()); // Not open yet
}

test "WebSocketClient createHandshake" {
    var client = WebSocketClient.init(testing.allocator);
    defer client.deinit();

    const handshake = client.createHandshake("example.com", "/ws");
    try testing.expectEqualStrings("example.com", handshake.host);
    try testing.expectEqualStrings("/ws", handshake.path);
}

test "WebSocketServer init and deinit" {
    var server = WebSocketServer.init(testing.allocator);
    defer server.deinit();

    try testing.expectEqual(server.connection.state, .connecting);
}

test "WebSocketServer accept" {
    var server = WebSocketServer.init(testing.allocator);
    defer server.deinit();

    server.accept();
    try testing.expectEqual(server.connection.state, .open);
}

test "WebSocketServer createHandshakeResponse" {
    var server = WebSocketServer.init(testing.allocator);
    defer server.deinit();

    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const response = server.createHandshakeResponse(client_key);

    // Should generate correct accept key
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &response.accept_key);
}
