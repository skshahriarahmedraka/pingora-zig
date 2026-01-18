//! QUIC Protocol Implementation (RFC 9000)
//!
//! This module provides QUIC transport protocol support using the quiche library
//! from Cloudflare. QUIC is a UDP-based transport protocol that provides:
//! - Encrypted connections by default (TLS 1.3)
//! - Multiplexed streams without head-of-line blocking
//! - Connection migration
//! - Low-latency connection establishment
//!
//! Reference: https://github.com/cloudflare/quiche

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// ============================================================================
// QUIC Error Types (RFC 9000 Section 20)
// ============================================================================

/// QUIC Transport Error Codes
pub const TransportError = enum(u64) {
    /// No error
    no_error = 0x00,
    /// Implementation error
    internal_error = 0x01,
    /// Server is refusing connection
    connection_refused = 0x02,
    /// Flow control error
    flow_control_error = 0x03,
    /// Stream limit exceeded
    stream_limit_error = 0x04,
    /// Stream state error
    stream_state_error = 0x05,
    /// Final size error
    final_size_error = 0x06,
    /// Frame encoding error
    frame_encoding_error = 0x07,
    /// Transport parameter error
    transport_parameter_error = 0x08,
    /// Connection ID limit exceeded
    connection_id_limit_error = 0x09,
    /// Protocol violation
    protocol_violation = 0x0a,
    /// Invalid token
    invalid_token = 0x0b,
    /// Application error
    application_error = 0x0c,
    /// Crypto buffer exceeded
    crypto_buffer_exceeded = 0x0d,
    /// Key update error
    key_update_error = 0x0e,
    /// AEAD limit reached
    aead_limit_reached = 0x0f,
    /// No viable path
    no_viable_path = 0x10,
    /// Crypto error (0x100-0x1ff reserved for TLS alerts)
    crypto_error = 0x100,

    pub fn fromCode(code: u64) ?TransportError {
        return std.meta.intToEnum(TransportError, code) catch null;
    }

    pub fn toCode(self: TransportError) u64 {
        return @intFromEnum(self);
    }
};

/// QUIC Error union for all error types
pub const QuicError = error{
    /// Configuration error
    InvalidConfig,
    /// Connection error
    ConnectionError,
    /// Stream error
    StreamError,
    /// Crypto/TLS error
    CryptoError,
    /// Buffer too small
    BufferTooSmall,
    /// Operation would block
    WouldBlock,
    /// Done (no more data)
    Done,
    /// Invalid state
    InvalidState,
    /// Flow control limit
    FlowControl,
    /// Stream limit exceeded
    StreamLimit,
    /// Final size mismatch
    FinalSize,
    /// Invalid stream ID
    InvalidStreamId,
    /// Invalid packet
    InvalidPacket,
    /// Unknown version
    UnknownVersion,
    /// Out of memory
    OutOfMemory,
};

// ============================================================================
// QUIC Version
// ============================================================================

/// QUIC protocol versions
pub const Version = enum(u32) {
    /// QUIC v1 (RFC 9000)
    v1 = 0x00000001,
    /// QUIC v2 (RFC 9369)
    v2 = 0x6b3343cf,
    /// Version negotiation
    negotiation = 0x00000000,

    pub fn isSupported(version: u32) bool {
        return version == @intFromEnum(Version.v1) or
            version == @intFromEnum(Version.v2);
    }
};

// ============================================================================
// Connection ID
// ============================================================================

/// Maximum connection ID length (RFC 9000)
pub const MAX_CONN_ID_LEN = 20;

/// QUIC Connection ID
pub const ConnectionId = struct {
    data: [MAX_CONN_ID_LEN]u8,
    len: u8,

    const Self = @This();

    pub fn init(data: []const u8) !Self {
        if (data.len > MAX_CONN_ID_LEN) {
            return error.InvalidConfig;
        }
        var cid = Self{
            .data = undefined,
            .len = @intCast(data.len),
        };
        @memcpy(cid.data[0..data.len], data);
        return cid;
    }

    pub fn generate(allocator: Allocator, len: u8) !Self {
        _ = allocator;
        if (len > MAX_CONN_ID_LEN) {
            return error.InvalidConfig;
        }
        var cid = Self{
            .data = undefined,
            .len = len,
        };
        std.crypto.random.bytes(cid.data[0..len]);
        return cid;
    }

    pub fn slice(self: *const Self) []const u8 {
        return self.data[0..self.len];
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

// ============================================================================
// Stream Types
// ============================================================================

/// Stream ID type (62-bit)
pub const StreamId = u62;

/// Stream type (derived from stream ID bits)
pub const StreamType = enum(u2) {
    client_bidirectional = 0b00,
    server_bidirectional = 0b01,
    client_unidirectional = 0b10,
    server_unidirectional = 0b11,

    pub fn fromStreamId(id: StreamId) StreamType {
        return @enumFromInt(@as(u2, @truncate(id)));
    }

    pub fn isBidirectional(self: StreamType) bool {
        return self == .client_bidirectional or self == .server_bidirectional;
    }

    pub fn isUnidirectional(self: StreamType) bool {
        return !self.isBidirectional();
    }

    pub fn isClientInitiated(self: StreamType) bool {
        return self == .client_bidirectional or self == .client_unidirectional;
    }

    pub fn isServerInitiated(self: StreamType) bool {
        return !self.isClientInitiated();
    }
};

// ============================================================================
// Transport Parameters (RFC 9000 Section 18)
// ============================================================================

/// QUIC Transport Parameters
pub const TransportParams = struct {
    /// Maximum idle timeout (milliseconds)
    max_idle_timeout: u64 = 30000,
    /// Maximum UDP payload size
    max_udp_payload_size: u64 = 65527,
    /// Initial max data (connection-level flow control)
    initial_max_data: u64 = 10 * 1024 * 1024, // 10 MB
    /// Initial max stream data (bidi local)
    initial_max_stream_data_bidi_local: u64 = 1 * 1024 * 1024, // 1 MB
    /// Initial max stream data (bidi remote)
    initial_max_stream_data_bidi_remote: u64 = 1 * 1024 * 1024, // 1 MB
    /// Initial max stream data (unidirectional)
    initial_max_stream_data_uni: u64 = 1 * 1024 * 1024, // 1 MB
    /// Initial max streams (bidirectional)
    initial_max_streams_bidi: u64 = 100,
    /// Initial max streams (unidirectional)
    initial_max_streams_uni: u64 = 100,
    /// ACK delay exponent
    ack_delay_exponent: u64 = 3,
    /// Max ACK delay (milliseconds)
    max_ack_delay: u64 = 25,
    /// Disable active migration
    disable_active_migration: bool = false,
    /// Active connection ID limit
    active_connection_id_limit: u64 = 2,

    const Self = @This();

    pub fn default() Self {
        return .{};
    }

    pub fn forServer() Self {
        return .{
            .max_idle_timeout = 60000,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 100,
        };
    }

    pub fn forClient() Self {
        return .{
            .max_idle_timeout = 30000,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 100,
        };
    }
};

// ============================================================================
// Packet Types (RFC 9000 Section 17)
// ============================================================================

/// QUIC packet types
pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,

    pub fn isLongHeader(self: PacketType) bool {
        _ = self;
        return true; // All these are long header packets
    }
};

/// Short header packet (1-RTT)
pub const ShortHeaderPacket = struct {
    dcid: ConnectionId,
    packet_number: u32,
    payload: []const u8,
};

/// Long header packet
pub const LongHeaderPacket = struct {
    packet_type: PacketType,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: ?[]const u8,
    packet_number: u32,
    payload: []const u8,
};

// ============================================================================
// QUIC Configuration
// ============================================================================

/// QUIC configuration options
pub const Config = struct {
    /// Transport parameters
    transport_params: TransportParams = .{},
    /// TLS certificate path (for server)
    cert_path: ?[]const u8 = null,
    /// TLS private key path (for server)
    key_path: ?[]const u8 = null,
    /// ALPN protocols
    alpn: []const []const u8 = &[_][]const u8{"h3"},
    /// Enable 0-RTT
    enable_early_data: bool = false,
    /// Verify peer certificate
    verify_peer: bool = true,
    /// Connection timeout (milliseconds)
    connection_timeout: u64 = 5000,
    /// Enable DATAGRAM extension
    enable_dgram: bool = false,
    /// DATAGRAM receive queue length
    dgram_recv_queue_len: usize = 0,
    /// DATAGRAM send queue length
    dgram_send_queue_len: usize = 0,

    const Self = @This();

    pub fn default() Self {
        return .{};
    }

    pub fn forHttp3Client() Self {
        return .{
            .alpn = &[_][]const u8{"h3"},
            .verify_peer = true,
            .enable_early_data = true,
        };
    }

    pub fn forHttp3Server() Self {
        return .{
            .alpn = &[_][]const u8{"h3"},
            .transport_params = TransportParams.forServer(),
        };
    }
};

// ============================================================================
// Connection State
// ============================================================================

/// QUIC connection state
pub const ConnectionState = enum {
    /// Initial state
    idle,
    /// Handshake in progress
    handshaking,
    /// Connection established
    established,
    /// Connection closing
    closing,
    /// Connection draining
    draining,
    /// Connection closed
    closed,

    pub fn isActive(self: ConnectionState) bool {
        return self == .handshaking or self == .established;
    }

    pub fn canSend(self: ConnectionState) bool {
        return self == .handshaking or self == .established or self == .closing;
    }
};

// ============================================================================
// Stream State
// ============================================================================

/// QUIC stream state
pub const StreamState = enum {
    /// Stream ready (not yet opened)
    ready,
    /// Stream open for sending/receiving
    open,
    /// Send side closed (FIN sent)
    half_closed_local,
    /// Receive side closed (FIN received)
    half_closed_remote,
    /// Both sides closed
    closed,
    /// Stream reset
    reset,

    pub fn canSend(self: StreamState) bool {
        return self == .open or self == .half_closed_remote;
    }

    pub fn canRecv(self: StreamState) bool {
        return self == .open or self == .half_closed_local;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ConnectionId generation and comparison" {
    const cid1 = try ConnectionId.generate(testing.allocator, 16);
    const cid2 = try ConnectionId.generate(testing.allocator, 16);

    try testing.expect(!cid1.eql(&cid2));
    try testing.expect(cid1.eql(&cid1));
    try testing.expectEqual(cid1.len, 16);
}

test "ConnectionId from slice" {
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const cid = try ConnectionId.init(&data);

    try testing.expectEqual(cid.len, 8);
    try testing.expectEqualSlices(u8, &data, cid.slice());
}

test "StreamType from StreamId" {
    // Client-initiated bidirectional: 0, 4, 8, ...
    try testing.expectEqual(StreamType.fromStreamId(0), .client_bidirectional);
    try testing.expectEqual(StreamType.fromStreamId(4), .client_bidirectional);

    // Server-initiated bidirectional: 1, 5, 9, ...
    try testing.expectEqual(StreamType.fromStreamId(1), .server_bidirectional);
    try testing.expectEqual(StreamType.fromStreamId(5), .server_bidirectional);

    // Client-initiated unidirectional: 2, 6, 10, ...
    try testing.expectEqual(StreamType.fromStreamId(2), .client_unidirectional);
    try testing.expectEqual(StreamType.fromStreamId(6), .client_unidirectional);

    // Server-initiated unidirectional: 3, 7, 11, ...
    try testing.expectEqual(StreamType.fromStreamId(3), .server_unidirectional);
    try testing.expectEqual(StreamType.fromStreamId(7), .server_unidirectional);
}

test "TransportParams defaults" {
    const params = TransportParams.default();
    try testing.expectEqual(params.max_idle_timeout, 30000);
    try testing.expectEqual(params.initial_max_streams_bidi, 100);
}

test "Version supported check" {
    try testing.expect(Version.isSupported(0x00000001)); // v1
    try testing.expect(Version.isSupported(0x6b3343cf)); // v2
    try testing.expect(!Version.isSupported(0x12345678)); // unknown
}

test "ConnectionState transitions" {
    try testing.expect(ConnectionState.idle.isActive() == false);
    try testing.expect(ConnectionState.handshaking.isActive() == true);
    try testing.expect(ConnectionState.established.isActive() == true);
    try testing.expect(ConnectionState.closing.canSend() == true);
    try testing.expect(ConnectionState.closed.canSend() == false);
}

test "StreamState send/recv capabilities" {
    try testing.expect(StreamState.open.canSend());
    try testing.expect(StreamState.open.canRecv());
    try testing.expect(StreamState.half_closed_local.canRecv());
    try testing.expect(!StreamState.half_closed_local.canSend());
    try testing.expect(StreamState.half_closed_remote.canSend());
    try testing.expect(!StreamState.half_closed_remote.canRecv());
}
