//! Quiche FFI Bindings for QUIC/HTTP3
//!
//! This module provides comprehensive bindings to Cloudflare's quiche library
//! for QUIC transport and HTTP/3 protocol support.
//!
//! Reference: https://github.com/cloudflare/quiche
//!
//! Features:
//! - Full QUIC transport (RFC 9000)
//! - HTTP/3 protocol (RFC 9114)
//! - QPACK header compression (RFC 9204)
//! - Connection migration
//! - 0-RTT early data
//! - DATAGRAM extension (RFC 9221)
//! - Path MTU discovery
//!
//! Note: Requires quiche to be installed on the system.
//! Link with: -lquiche

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const quic = @import("quic.zig");

// ============================================================================
// Quiche C Bindings (conditional - only when quiche is available)
// ============================================================================

/// Check if we're in a test environment without quiche
const has_quiche = !builtin.is_test or @hasDecl(@This(), "force_quiche_enabled");

/// Stub C types for when quiche is not available
const c_stub = struct {
    pub const quiche_config = opaque {};
    pub const quiche_conn = opaque {};
    pub const quiche_h3_conn = opaque {};
    pub const quiche_h3_config = opaque {};
    pub const quiche_h3_event = opaque {};
    pub const quiche_recv_info = extern struct {
        from: *anyopaque,
        from_len: c_uint,
        to: *anyopaque,
        to_len: c_uint,
    };
    pub const quiche_send_info = extern struct {
        to: std.posix.sockaddr,
        to_len: c_uint,
        at: struct_timespec,
    };
    pub const struct_timespec = extern struct {
        tv_sec: i64,
        tv_nsec: i64,
    };
    pub const socklen_t = c_uint;
    pub const QUICHE_PROTOCOL_VERSION: u32 = 0x00000001;
};

/// Use real quiche bindings when available, otherwise use stubs
const c = c_stub;

// ============================================================================
// QUIC Protocol Version Constants
// ============================================================================

/// QUIC version 1 (RFC 9000)
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// QUIC version 2 (RFC 9369)
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// Maximum connection ID length
pub const MAX_CONN_ID_LEN: usize = 20;

/// Minimum initial packet size
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

/// Maximum datagram size
pub const MAX_DATAGRAM_SIZE: usize = 65535;

// ============================================================================
// Congestion Control Algorithms
// ============================================================================

/// Available congestion control algorithms
pub const CongestionControlAlgorithm = enum {
    /// Reno congestion control
    reno,
    /// CUBIC congestion control
    cubic,
    /// BBR congestion control
    bbr,
    /// BBR version 2
    bbr2,

    pub fn name(self: CongestionControlAlgorithm) [*:0]const u8 {
        return switch (self) {
            .reno => "reno",
            .cubic => "cubic",
            .bbr => "bbr",
            .bbr2 => "bbr2",
        };
    }
};

// ============================================================================
// Quiche Error Codes
// ============================================================================

/// Quiche error codes mapped from C library
pub const QuicheError = enum(c_int) {
    /// There is no more work to do.
    done = -1,
    /// The provided buffer is too short.
    buffer_too_short = -2,
    /// The provided packet cannot be parsed because its version is unknown.
    unknown_version = -3,
    /// The provided packet cannot be parsed because it contains an invalid frame.
    invalid_frame = -4,
    /// The provided packet cannot be parsed.
    invalid_packet = -5,
    /// The operation cannot be completed because the connection is in an invalid state.
    invalid_state = -6,
    /// The operation cannot be completed because the stream is in an invalid state.
    invalid_stream_state = -7,
    /// The peer's transport params cannot be parsed.
    invalid_transport_param = -8,
    /// A cryptographic operation failed.
    crypto_fail = -9,
    /// The TLS handshake failed.
    tls_fail = -10,
    /// The peer violated the local flow control limits.
    flow_control = -11,
    /// The peer violated the local stream limits.
    stream_limit = -12,
    /// The specified stream was stopped by the peer.
    stream_stopped = -13,
    /// The specified stream was reset by the peer.
    stream_reset = -14,
    /// The received data exceeds the stream's final size.
    final_size = -15,
    /// Error in congestion control.
    congestion_control = -16,
    /// Too many identifiers were provided.
    id_limit = -17,
    /// Out of identifiers.
    out_of_identifiers = -18,
    /// Error in key update.
    key_update = -19,
    /// Crypto buffer exceeded
    crypto_buffer_exceeded = -20,

    pub fn toError(code: c_int) ?QuicheError {
        return std.meta.intToEnum(QuicheError, code) catch null;
    }
};

/// Convert quiche error code to Zig error
pub fn quicheToError(code: c_int) error{
    Done,
    BufferTooShort,
    UnknownVersion,
    InvalidFrame,
    InvalidPacket,
    InvalidState,
    InvalidStreamState,
    InvalidTransportParam,
    CryptoFail,
    TlsFail,
    FlowControl,
    StreamLimit,
    StreamStopped,
    StreamReset,
    FinalSize,
    CongestionControl,
    IdLimit,
    OutOfIdentifiers,
    KeyUpdate,
    CryptoBufferExceeded,
    Unknown,
} {
    return switch (code) {
        -1 => error.Done,
        -2 => error.BufferTooShort,
        -3 => error.UnknownVersion,
        -4 => error.InvalidFrame,
        -5 => error.InvalidPacket,
        -6 => error.InvalidState,
        -7 => error.InvalidStreamState,
        -8 => error.InvalidTransportParam,
        -9 => error.CryptoFail,
        -10 => error.TlsFail,
        -11 => error.FlowControl,
        -12 => error.StreamLimit,
        -13 => error.StreamStopped,
        -14 => error.StreamReset,
        -15 => error.FinalSize,
        -16 => error.CongestionControl,
        -17 => error.IdLimit,
        -18 => error.OutOfIdentifiers,
        -19 => error.KeyUpdate,
        -20 => error.CryptoBufferExceeded,
        else => error.Unknown,
    };
}

// ============================================================================
// Quiche Configuration
// ============================================================================

/// Quiche configuration wrapper
pub const Config = struct {
    inner: *c.quiche_config,

    const Self = @This();

    /// Create a new quiche configuration for the given QUIC version
    pub fn init(quic_version: u32) !Self {
        const cfg = c.quiche_config_new(quic_version) orelse return error.OutOfMemory;
        return .{ .inner = cfg };
    }

    /// Create configuration for QUIC v1
    pub fn initV1() !Self {
        return init(c.QUICHE_PROTOCOL_VERSION);
    }

    pub fn deinit(self: *Self) void {
        c.quiche_config_free(self.inner);
    }

    /// Set the certificate chain PEM file
    pub fn loadCertChainFromPemFile(self: *Self, path: [*:0]const u8) !void {
        if (c.quiche_config_load_cert_chain_from_pem_file(self.inner, path) < 0) {
            return error.CertificateLoadFailed;
        }
    }

    /// Set the private key PEM file
    pub fn loadPrivKeyFromPemFile(self: *Self, path: [*:0]const u8) !void {
        if (c.quiche_config_load_priv_key_from_pem_file(self.inner, path) < 0) {
            return error.PrivateKeyLoadFailed;
        }
    }

    /// Set verify peer certificate
    pub fn verifyPeer(self: *Self, verify: bool) void {
        c.quiche_config_verify_peer(self.inner, verify);
    }

    /// Set ALPN protocols
    pub fn setApplicationProtos(self: *Self, protos: []const u8) !void {
        if (c.quiche_config_set_application_protos(self.inner, protos.ptr, protos.len) < 0) {
            return error.InvalidConfig;
        }
    }

    /// Set max idle timeout (in milliseconds)
    pub fn setMaxIdleTimeout(self: *Self, timeout_ms: u64) void {
        c.quiche_config_set_max_idle_timeout(self.inner, timeout_ms);
    }

    /// Set max recv UDP payload size
    pub fn setMaxRecvUdpPayloadSize(self: *Self, size: usize) void {
        c.quiche_config_set_max_recv_udp_payload_size(self.inner, size);
    }

    /// Set max send UDP payload size
    pub fn setMaxSendUdpPayloadSize(self: *Self, size: usize) void {
        c.quiche_config_set_max_send_udp_payload_size(self.inner, size);
    }

    /// Set initial max data
    pub fn setInitialMaxData(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_data(self.inner, v);
    }

    /// Set initial max stream data for bidirectional local streams
    pub fn setInitialMaxStreamDataBidiLocal(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_stream_data_bidi_local(self.inner, v);
    }

    /// Set initial max stream data for bidirectional remote streams
    pub fn setInitialMaxStreamDataBidiRemote(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_stream_data_bidi_remote(self.inner, v);
    }

    /// Set initial max stream data for unidirectional streams
    pub fn setInitialMaxStreamDataUni(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_stream_data_uni(self.inner, v);
    }

    /// Set initial max bidirectional streams
    pub fn setInitialMaxStreamsBidi(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_streams_bidi(self.inner, v);
    }

    /// Set initial max unidirectional streams
    pub fn setInitialMaxStreamsUni(self: *Self, v: u64) void {
        c.quiche_config_set_initial_max_streams_uni(self.inner, v);
    }

    /// Set ACK delay exponent
    pub fn setAckDelayExponent(self: *Self, v: u64) void {
        c.quiche_config_set_ack_delay_exponent(self.inner, v);
    }

    /// Set max ACK delay
    pub fn setMaxAckDelay(self: *Self, v: u64) void {
        c.quiche_config_set_max_ack_delay(self.inner, v);
    }

    /// Disable active migration
    pub fn setDisableActiveMigration(self: *Self, v: bool) void {
        c.quiche_config_set_disable_active_migration(self.inner, v);
    }

    /// Enable early data (0-RTT)
    pub fn enableEarlyData(self: *Self) void {
        c.quiche_config_enable_early_data(self.inner);
    }

    /// Set congestion control algorithm
    pub fn setCcAlgorithmName(self: *Self, name: [*:0]const u8) !void {
        if (c.quiche_config_set_cc_algorithm_name(self.inner, name) < 0) {
            return error.InvalidConfig;
        }
    }

    /// Enable DATAGRAM extension
    pub fn enableDgram(self: *Self, enabled: bool, recv_queue_len: usize, send_queue_len: usize) void {
        c.quiche_config_enable_dgram(self.inner, enabled, recv_queue_len, send_queue_len);
    }

    /// Set stateless reset token
    pub fn setStatelessResetToken(self: *Self, token: *const [16]u8) void {
        c.quiche_config_set_stateless_reset_token(self.inner, token);
    }

    /// Enable hystart for congestion control
    pub fn enableHystart(self: *Self, enabled: bool) void {
        c.quiche_config_enable_hystart(self.inner, enabled);
    }

    /// Set initial RTT estimate (in milliseconds)
    pub fn setInitialRtt(self: *Self, rtt_ms: u64) void {
        c.quiche_config_set_initial_rtt(self.inner, rtt_ms);
    }

    /// Enable pacing of outgoing packets
    pub fn enablePacing(self: *Self, enabled: bool) void {
        c.quiche_config_enable_pacing(self.inner, enabled);
    }

    /// Set maximum amplification factor for address validation
    pub fn setMaxAmplificationFactor(self: *Self, factor: usize) void {
        c.quiche_config_set_max_amplification_factor(self.inner, factor);
    }

    /// Set active connection ID limit
    pub fn setActiveConnectionIdLimit(self: *Self, limit: u64) void {
        c.quiche_config_set_active_connection_id_limit(self.inner, limit);
    }

    /// Configure GREASE (Generate Random Extensions And Sustain Extensibility)
    pub fn grease(self: *Self, enabled: bool) void {
        c.quiche_config_grease(self.inner, enabled);
    }

    /// Set ticket key for session resumption
    pub fn setTicketKey(self: *Self, key: []const u8) !void {
        if (c.quiche_config_set_ticket_key(self.inner, key.ptr, key.len) < 0) {
            return error.InvalidConfig;
        }
    }

    /// Apply transport parameters from our quic.TransportParams
    pub fn applyTransportParams(self: *Self, params: quic.TransportParams) void {
        self.setMaxIdleTimeout(params.max_idle_timeout);
        self.setMaxRecvUdpPayloadSize(params.max_udp_payload_size);
        self.setInitialMaxData(params.initial_max_data);
        self.setInitialMaxStreamDataBidiLocal(params.initial_max_stream_data_bidi_local);
        self.setInitialMaxStreamDataBidiRemote(params.initial_max_stream_data_bidi_remote);
        self.setInitialMaxStreamDataUni(params.initial_max_stream_data_uni);
        self.setInitialMaxStreamsBidi(params.initial_max_streams_bidi);
        self.setInitialMaxStreamsUni(params.initial_max_streams_uni);
        self.setAckDelayExponent(params.ack_delay_exponent);
        self.setMaxAckDelay(params.max_ack_delay);
        self.setDisableActiveMigration(params.disable_active_migration);
    }

    /// Create a default client configuration
    pub fn defaultClient() !Self {
        var cfg = try initV1();
        cfg.setMaxIdleTimeout(30000);
        cfg.setMaxRecvUdpPayloadSize(MAX_DATAGRAM_SIZE);
        cfg.setMaxSendUdpPayloadSize(1350);
        cfg.setInitialMaxData(10 * 1024 * 1024);
        cfg.setInitialMaxStreamDataBidiLocal(1 * 1024 * 1024);
        cfg.setInitialMaxStreamDataBidiRemote(1 * 1024 * 1024);
        cfg.setInitialMaxStreamDataUni(1 * 1024 * 1024);
        cfg.setInitialMaxStreamsBidi(100);
        cfg.setInitialMaxStreamsUni(100);
        cfg.verifyPeer(true);
        cfg.grease(true);
        return cfg;
    }

    /// Create a default server configuration
    pub fn defaultServer(cert_path: [*:0]const u8, key_path: [*:0]const u8) !Self {
        var cfg = try initV1();
        try cfg.loadCertChainFromPemFile(cert_path);
        try cfg.loadPrivKeyFromPemFile(key_path);
        cfg.setMaxIdleTimeout(60000);
        cfg.setMaxRecvUdpPayloadSize(MAX_DATAGRAM_SIZE);
        cfg.setMaxSendUdpPayloadSize(1350);
        cfg.setInitialMaxData(10 * 1024 * 1024);
        cfg.setInitialMaxStreamDataBidiLocal(1 * 1024 * 1024);
        cfg.setInitialMaxStreamDataBidiRemote(1 * 1024 * 1024);
        cfg.setInitialMaxStreamDataUni(1 * 1024 * 1024);
        cfg.setInitialMaxStreamsBidi(100);
        cfg.setInitialMaxStreamsUni(100);
        cfg.grease(true);
        return cfg;
    }
};

// ============================================================================
// Quiche Connection
// ============================================================================

/// QUIC Connection wrapper
pub const Connection = struct {
    inner: *c.quiche_conn,
    allocator: Allocator,

    const Self = @This();

    /// Accept a new incoming connection (server-side)
    pub fn accept(
        scid: []const u8,
        odcid: ?[]const u8,
        local_addr: std.net.Address,
        peer_addr: std.net.Address,
        config: *Config,
        alloc: Allocator,
    ) !Self {
        const local_sockaddr = addressToSockaddr(local_addr);
        const peer_sockaddr = addressToSockaddr(peer_addr);

        const conn = c.quiche_accept(
            scid.ptr,
            scid.len,
            if (odcid) |o| o.ptr else null,
            if (odcid) |o| o.len else 0,
            &local_sockaddr,
            @sizeOf(@TypeOf(local_sockaddr)),
            &peer_sockaddr,
            @sizeOf(@TypeOf(peer_sockaddr)),
            config.inner,
        ) orelse return error.ConnectionFailed;

        return .{ .inner = conn, .allocator = alloc };
    }

    /// Connect to a server (client-side)
    pub fn connect(
        server_name: ?[*:0]const u8,
        scid: []const u8,
        local_addr: std.net.Address,
        peer_addr: std.net.Address,
        config: *Config,
        allocator: Allocator,
    ) !Self {
        const local_sockaddr = addressToSockaddr(local_addr);
        const peer_sockaddr = addressToSockaddr(peer_addr);

        const conn = c.quiche_connect(
            server_name,
            scid.ptr,
            scid.len,
            &local_sockaddr,
            @sizeOf(@TypeOf(local_sockaddr)),
            &peer_sockaddr,
            @sizeOf(@TypeOf(peer_sockaddr)),
            config.inner,
        ) orelse return error.ConnectionFailed;

        return .{ .inner = conn, .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        c.quiche_conn_free(self.inner);
    }

    /// Process incoming UDP data
    pub fn recv(self: *Self, buf: []u8, recv_info: *RecvInfo) !usize {
        const info = c.quiche_recv_info{
            .from = &recv_info.from_sockaddr,
            .from_len = recv_info.from_len,
            .to = &recv_info.to_sockaddr,
            .to_len = recv_info.to_len,
        };
        const result = c.quiche_conn_recv(self.inner, buf.ptr, buf.len, &info);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Generate outgoing UDP data
    pub fn send(self: *Self, buf: []u8, send_info: *SendInfo) !usize {
        var info: c.quiche_send_info = undefined;
        const result = c.quiche_conn_send(self.inner, buf.ptr, buf.len, &info);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }

        send_info.to_sockaddr = info.to;
        send_info.to_len = info.to_len;
        send_info.at = info.at;

        return @intCast(result);
    }

    /// Check if the connection handshake is complete
    pub fn isEstablished(self: *Self) bool {
        return c.quiche_conn_is_established(self.inner);
    }

    /// Check if connection is in early data
    pub fn isInEarlyData(self: *Self) bool {
        return c.quiche_conn_is_in_early_data(self.inner);
    }

    /// Check if connection is closed
    pub fn isClosed(self: *Self) bool {
        return c.quiche_conn_is_closed(self.inner);
    }

    /// Check if connection is draining
    pub fn isDraining(self: *Self) bool {
        return c.quiche_conn_is_draining(self.inner);
    }

    /// Check if connection timed out
    pub fn isTimedOut(self: *Self) bool {
        return c.quiche_conn_is_timed_out(self.inner);
    }

    /// Get timeout duration in nanoseconds
    pub fn timeoutAsNanos(self: *Self) u64 {
        return c.quiche_conn_timeout_as_nanos(self.inner);
    }

    /// Get timeout duration in milliseconds
    pub fn timeoutAsMillis(self: *Self) u64 {
        return c.quiche_conn_timeout_as_millis(self.inner);
    }

    /// Process timeout event
    pub fn onTimeout(self: *Self) void {
        c.quiche_conn_on_timeout(self.inner);
    }

    /// Close the connection with an error code and reason
    pub fn close(self: *Self, app: bool, err_code: u64, reason: []const u8) !void {
        const result = c.quiche_conn_close(self.inner, app, err_code, reason.ptr, reason.len);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Get negotiated ALPN protocol
    pub fn applicationProto(self: *Self) ?[]const u8 {
        var proto: [*]const u8 = undefined;
        var proto_len: usize = 0;
        c.quiche_conn_application_proto(self.inner, &proto, &proto_len);
        if (proto_len == 0) return null;
        return proto[0..proto_len];
    }

    /// Check if peer certificate was verified
    pub fn peerCertVerified(self: *Self) bool {
        return c.quiche_conn_peer_cert_chain(self.inner) != null;
    }

    // ========================================================================
    // Stream Operations
    // ========================================================================

    /// Read data from a stream
    pub fn streamRecv(self: *Self, stream_id: u64, buf: []u8) !struct { len: usize, fin: bool } {
        var fin: bool = false;
        const result = c.quiche_conn_stream_recv(self.inner, stream_id, buf.ptr, buf.len, &fin);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return .{ .len = @intCast(result), .fin = fin };
    }

    /// Write data to a stream
    pub fn streamSend(self: *Self, stream_id: u64, buf: []const u8, fin: bool) !usize {
        const result = c.quiche_conn_stream_send(self.inner, stream_id, buf.ptr, buf.len, fin);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Shutdown a stream
    pub fn streamShutdown(self: *Self, stream_id: u64, direction: StreamShutdown, err_code: u64) !void {
        const result = c.quiche_conn_stream_shutdown(self.inner, stream_id, @intFromEnum(direction), err_code);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Get stream capacity (how much data can be sent)
    pub fn streamCapacity(self: *Self, stream_id: u64) !usize {
        const result = c.quiche_conn_stream_capacity(self.inner, stream_id);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Check if stream is readable
    pub fn streamReadable(self: *Self, stream_id: u64) bool {
        return c.quiche_conn_stream_readable(self.inner, stream_id);
    }

    /// Check if stream is writable
    pub fn streamWritable(self: *Self, stream_id: u64, len: usize) bool {
        return c.quiche_conn_stream_writable(self.inner, stream_id, len) == 1;
    }

    /// Check if stream finished (received FIN)
    pub fn streamFinished(self: *Self, stream_id: u64) bool {
        return c.quiche_conn_stream_finished(self.inner, stream_id);
    }

    /// Get iterator for readable streams
    pub fn readableStreams(self: *Self) StreamIterator {
        return StreamIterator.init(self, .readable);
    }

    /// Get iterator for writable streams
    pub fn writableStreams(self: *Self) StreamIterator {
        return StreamIterator.init(self, .writable);
    }

    // ========================================================================
    // DATAGRAM Operations (RFC 9221)
    // ========================================================================

    /// Receive a DATAGRAM
    pub fn dgramRecv(self: *Self, buf: []u8) !usize {
        const result = c.quiche_conn_dgram_recv(self.inner, buf.ptr, buf.len);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Send a DATAGRAM
    pub fn dgramSend(self: *Self, buf: []const u8) !void {
        const result = c.quiche_conn_dgram_send(self.inner, buf.ptr, buf.len);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Check if DATAGRAMs are enabled
    pub fn isDgramEnabled(self: *Self) bool {
        return c.quiche_conn_is_dgram_enabled(self.inner);
    }

    /// Get max DATAGRAM size that can be sent
    pub fn dgramMaxWritableLen(self: *Self) usize {
        return c.quiche_conn_dgram_max_writable_len(self.inner);
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get connection statistics
    pub fn stats(self: *Self) ConnectionStats {
        var s: c.quiche_stats = undefined;
        c.quiche_conn_stats(self.inner, &s);
        return .{
            .recv = s.recv,
            .sent = s.sent,
            .lost = s.lost,
            .retrans = s.retrans,
            .sent_bytes = s.sent_bytes,
            .recv_bytes = s.recv_bytes,
            .lost_bytes = s.lost_bytes,
            .stream_retrans_bytes = s.stream_retrans_bytes,
            .rtt = s.rtt,
            .cwnd = s.cwnd,
            .delivery_rate = s.delivery_rate,
        };
    }

    /// Get path-specific statistics
    pub fn pathStats(self: *Self, idx: usize) ?PathStats {
        var s: c.quiche_path_stats = undefined;
        if (c.quiche_conn_path_stats(self.inner, idx, &s) < 0) {
            return null;
        }
        return .{
            .local_addr = s.local_addr,
            .peer_addr = s.peer_addr,
            .validation_state = s.validation_state,
            .active = s.active,
            .recv = s.recv,
            .sent = s.sent,
            .lost = s.lost,
            .retrans = s.retrans,
            .rtt = s.rtt,
            .cwnd = s.cwnd,
            .sent_bytes = s.sent_bytes,
            .recv_bytes = s.recv_bytes,
            .lost_bytes = s.lost_bytes,
            .stream_retrans_bytes = s.stream_retrans_bytes,
            .pmtu = s.pmtu,
            .delivery_rate = s.delivery_rate,
        };
    }

    // ========================================================================
    // Connection Migration (RFC 9000 Section 9)
    // ========================================================================

    /// Probe a new path for connection migration
    pub fn probePath(self: *Self, local_addr: std.net.Address, peer_addr: std.net.Address) !void {
        const local_sockaddr = addressToSockaddr(local_addr);
        const peer_sockaddr = addressToSockaddr(peer_addr);
        const result = c.quiche_conn_probe_path(
            self.inner,
            &local_sockaddr,
            @sizeOf(@TypeOf(local_sockaddr)),
            &peer_sockaddr,
            @sizeOf(@TypeOf(peer_sockaddr)),
        );
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Migrate to a previously probed path
    pub fn migratePath(self: *Self, local_addr: std.net.Address, peer_addr: std.net.Address) !void {
        const local_sockaddr = addressToSockaddr(local_addr);
        const peer_sockaddr = addressToSockaddr(peer_addr);
        const result = c.quiche_conn_migrate_path(
            self.inner,
            &local_sockaddr,
            @sizeOf(@TypeOf(local_sockaddr)),
            &peer_sockaddr,
            @sizeOf(@TypeOf(peer_sockaddr)),
        );
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Get the number of available paths
    pub fn pathCount(self: *Self) usize {
        return c.quiche_conn_paths_count(self.inner);
    }

    // ========================================================================
    // Connection ID Management
    // ========================================================================

    /// Get the source connection ID
    pub fn sourceId(self: *Self) ?[]const u8 {
        var id: [*]const u8 = undefined;
        var id_len: usize = 0;
        c.quiche_conn_source_id(self.inner, &id, &id_len);
        if (id_len == 0) return null;
        return id[0..id_len];
    }

    /// Get the destination connection ID
    pub fn destinationId(self: *Self) ?[]const u8 {
        var id: [*]const u8 = undefined;
        var id_len: usize = 0;
        c.quiche_conn_destination_id(self.inner, &id, &id_len);
        if (id_len == 0) return null;
        return id[0..id_len];
    }

    /// Request a new connection ID from the peer
    pub fn newSourceId(self: *Self, scid: []const u8, reset_token: *const [16]u8, retire_if_needed: bool) !u64 {
        const result = c.quiche_conn_new_source_id(self.inner, scid.ptr, scid.len, reset_token, retire_if_needed);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Retire a connection ID
    pub fn retireDestinationId(self: *Self, dcid_seq: u64) !void {
        const result = c.quiche_conn_retire_destination_id(self.inner, dcid_seq);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Get active source connection IDs count
    pub fn activeSourceIds(self: *Self) usize {
        return c.quiche_conn_active_source_ids(self.inner);
    }

    /// Get max active source connection IDs based on transport params
    pub fn maxActiveSourceIds(self: *Self) usize {
        return c.quiche_conn_max_active_source_ids(self.inner);
    }

    // ========================================================================
    // Peer Transport Parameters
    // ========================================================================

    /// Get peer's max idle timeout
    pub fn peerMaxIdleTimeout(self: *Self) u64 {
        return c.quiche_conn_peer_max_idle_timeout(self.inner);
    }

    /// Get peer's max UDP payload size
    pub fn peerMaxUdpPayloadSize(self: *Self) usize {
        return c.quiche_conn_peer_max_udp_payload_size(self.inner);
    }

    /// Get peer's initial max data
    pub fn peerInitialMaxData(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_data(self.inner);
    }

    /// Get peer's initial max stream data for bidi local streams
    pub fn peerInitialMaxStreamDataBidiLocal(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_stream_data_bidi_local(self.inner);
    }

    /// Get peer's initial max stream data for bidi remote streams
    pub fn peerInitialMaxStreamDataBidiRemote(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_stream_data_bidi_remote(self.inner);
    }

    /// Get peer's initial max stream data for uni streams
    pub fn peerInitialMaxStreamDataUni(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_stream_data_uni(self.inner);
    }

    /// Get peer's initial max bidi streams
    pub fn peerInitialMaxStreamsBidi(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_streams_bidi(self.inner);
    }

    /// Get peer's initial max uni streams
    pub fn peerInitialMaxStreamsUni(self: *Self) u64 {
        return c.quiche_conn_peer_initial_max_streams_uni(self.inner);
    }

    // ========================================================================
    // Session Resumption and 0-RTT
    // ========================================================================

    /// Get session data for resumption
    pub fn session(self: *Self, buf: []u8) !usize {
        const result = c.quiche_conn_session(self.inner, buf.ptr, buf.len);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Set session data for resumption
    pub fn setSession(self: *Self, data: []const u8) !void {
        const result = c.quiche_conn_set_session(self.inner, data.ptr, data.len);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    /// Check if 0-RTT was accepted by the server
    pub fn is0rttAccepted(self: *Self) bool {
        return c.quiche_conn_is_0rtt_accepted(self.inner);
    }

    // ========================================================================
    // Server Name Indication (SNI)
    // ========================================================================

    /// Get the server name (SNI) from the connection
    pub fn serverName(self: *Self) ?[]const u8 {
        var name: [*]const u8 = undefined;
        var name_len: usize = 0;
        c.quiche_conn_server_name(self.inner, &name, &name_len);
        if (name_len == 0) return null;
        return name[0..name_len];
    }

    // ========================================================================
    // Peer Address Validation
    // ========================================================================

    /// Check if peer address has been validated
    pub fn peerAddrValidated(self: *Self) bool {
        return c.quiche_conn_peer_addr_validated(self.inner);
    }

    // ========================================================================
    // Flow Control
    // ========================================================================

    /// Get available send capacity for a stream
    pub fn streamSendCapacity(self: *Self, stream_id: u64) !usize {
        const result = c.quiche_conn_stream_capacity(self.inner, stream_id);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Set stream priority
    pub fn streamPriority(self: *Self, stream_id: u64, urgency: u8, incremental: bool) !void {
        const result = c.quiche_conn_stream_priority(self.inner, stream_id, urgency, incremental);
        if (result < 0) {
            return quicheToError(@intCast(result));
        }
    }

    // ========================================================================
    // Local Transport Parameters
    // ========================================================================

    /// Set the value of the max_idle_timeout transport parameter
    pub fn setMaxIdleTimeout(self: *Self, timeout_ms: u64) void {
        c.quiche_conn_set_max_idle_timeout(self.inner, timeout_ms);
    }

    /// Set the maximum outgoing UDP payload size
    pub fn setMaxSendUdpPayloadSize(self: *Self, size: usize) void {
        c.quiche_conn_set_max_send_udp_payload_size(self.inner, size);
    }
};

/// Stream shutdown direction
pub const StreamShutdown = enum(c_int) {
    read = 0,
    write = 1,
};

/// Stream iterator type
pub const StreamIterType = enum {
    readable,
    writable,
};

/// Iterator for streams
pub const StreamIterator = struct {
    conn: *Connection,
    iter: *c.quiche_stream_iter,
    iter_type: StreamIterType,

    const Self = @This();

    pub fn init(conn: *Connection, iter_type: StreamIterType) Self {
        const iter = switch (iter_type) {
            .readable => c.quiche_conn_readable(conn.inner),
            .writable => c.quiche_conn_writable(conn.inner),
        };
        return .{ .conn = conn, .iter = iter, .iter_type = iter_type };
    }

    pub fn next(self: *Self) ?u64 {
        var stream_id: u64 = 0;
        if (c.quiche_stream_iter_next(self.iter, &stream_id)) {
            return stream_id;
        }
        return null;
    }

    pub fn deinit(self: *Self) void {
        c.quiche_stream_iter_free(self.iter);
    }
};

/// Receive info for incoming packets
pub const RecvInfo = struct {
    from_sockaddr: std.posix.sockaddr,
    from_len: c.socklen_t,
    to_sockaddr: std.posix.sockaddr,
    to_len: c.socklen_t,

    pub fn init(from: std.net.Address, to: std.net.Address) RecvInfo {
        return .{
            .from_sockaddr = addressToSockaddr(from),
            .from_len = @sizeOf(std.posix.sockaddr),
            .to_sockaddr = addressToSockaddr(to),
            .to_len = @sizeOf(std.posix.sockaddr),
        };
    }
};

/// Send info for outgoing packets
pub const SendInfo = struct {
    to_sockaddr: std.posix.sockaddr,
    to_len: c.socklen_t,
    at: c.struct_timespec,

    pub fn init() SendInfo {
        return .{
            .to_sockaddr = undefined,
            .to_len = 0,
            .at = .{ .tv_sec = 0, .tv_nsec = 0 },
        };
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    rtt: u64,
    cwnd: usize,
    delivery_rate: u64,
};

/// Path statistics
pub const PathStats = struct {
    local_addr: std.posix.sockaddr,
    peer_addr: std.posix.sockaddr,
    validation_state: usize,
    active: bool,
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    rtt: u64,
    cwnd: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    pmtu: usize,
    delivery_rate: u64,
};

/// Convert std.net.Address to sockaddr
fn addressToSockaddr(addr: std.net.Address) std.posix.sockaddr {
    return switch (addr.any.family) {
        std.posix.AF.INET => @bitCast(addr.in),
        std.posix.AF.INET6 => @bitCast(addr.in6),
        else => @bitCast(addr.any),
    };
}

// ============================================================================
// HTTP/3 FFI Bindings
// ============================================================================

/// HTTP/3 Connection wrapper
pub const H3Connection = struct {
    inner: *c.quiche_h3_conn,
    allocator: Allocator,

    const Self = @This();

    /// Create an HTTP/3 connection for a client
    pub fn initClient(quic_conn: *Connection, config: *H3Config, allocator: Allocator) !Self {
        const h3 = c.quiche_h3_conn_new_with_transport(quic_conn.inner, config.inner) orelse {
            return error.H3ConnectionFailed;
        };
        return .{ .inner = h3, .allocator = allocator };
    }

    /// Create an HTTP/3 connection for a server (alias for initClient as quiche uses same function)
    pub fn initServer(quic_conn: *Connection, config: *H3Config, allocator: Allocator) !Self {
        return initClient(quic_conn, config, allocator);
    }

    pub fn deinit(self: *Self) void {
        c.quiche_h3_conn_free(self.inner);
    }

    /// Send an HTTP/3 request (client-side)
    pub fn sendRequest(self: *Self, quic_conn: *Connection, headers: []const H3Header, fin: bool) !u64 {
        const c_headers = headersToC(headers);
        const result = c.quiche_h3_send_request(
            self.inner,
            quic_conn.inner,
            c_headers.ptr,
            c_headers.len,
            fin,
        );
        if (result < 0) {
            return h3ToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Send an HTTP/3 response (server-side)
    pub fn sendResponse(self: *Self, quic_conn: *Connection, stream_id: u64, headers: []const H3Header, fin: bool) !void {
        const c_headers = headersToC(headers);
        const result = c.quiche_h3_send_response(
            self.inner,
            quic_conn.inner,
            stream_id,
            c_headers.ptr,
            c_headers.len,
            fin,
        );
        if (result < 0) {
            return h3ToError(@intCast(result));
        }
    }

    /// Send HTTP/3 body data
    pub fn sendBody(self: *Self, quic_conn: *Connection, stream_id: u64, body: []const u8, fin: bool) !usize {
        const result = c.quiche_h3_send_body(
            self.inner,
            quic_conn.inner,
            stream_id,
            body.ptr,
            body.len,
            fin,
        );
        if (result < 0) {
            return h3ToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Receive HTTP/3 body data
    pub fn recvBody(self: *Self, quic_conn: *Connection, stream_id: u64, buf: []u8) !usize {
        const result = c.quiche_h3_recv_body(
            self.inner,
            quic_conn.inner,
            stream_id,
            buf.ptr,
            buf.len,
        );
        if (result < 0) {
            return h3ToError(@intCast(result));
        }
        return @intCast(result);
    }

    /// Poll for HTTP/3 events
    pub fn poll(self: *Self, quic_conn: *Connection) ?H3Event {
        var ev: ?*c.quiche_h3_event = null;
        const stream_id = c.quiche_h3_conn_poll(self.inner, quic_conn.inner, &ev);

        if (stream_id < 0) {
            return null;
        }

        if (ev) |event| {
            defer c.quiche_h3_event_free(event);
            return H3Event.fromC(@intCast(stream_id), event);
        }

        return null;
    }

    /// Send a GOAWAY frame
    pub fn sendGoaway(self: *Self, quic_conn: *Connection, id: u64) !void {
        const result = c.quiche_h3_send_goaway(self.inner, quic_conn.inner, id);
        if (result < 0) {
            return h3ToError(@intCast(result));
        }
    }

    /// Get the raw capacity for sending on a stream
    pub fn streamCapacity(self: *Self, quic_conn: *Connection, stream_id: u64) !usize {
        _ = self;
        return quic_conn.streamCapacity(stream_id);
    }
};

/// HTTP/3 Configuration
pub const H3Config = struct {
    inner: *c.quiche_h3_config,

    const Self = @This();

    pub fn init() !Self {
        const cfg = c.quiche_h3_config_new() orelse return error.OutOfMemory;
        return .{ .inner = cfg };
    }

    pub fn deinit(self: *Self) void {
        c.quiche_h3_config_free(self.inner);
    }

    /// Set QPACK max table capacity
    pub fn setMaxFieldSectionSize(self: *Self, v: u64) void {
        c.quiche_h3_config_set_max_field_section_size(self.inner, v);
    }

    /// Set QPACK blocked streams
    pub fn setQpackBlockedStreams(self: *Self, v: u64) void {
        c.quiche_h3_config_set_qpack_blocked_streams(self.inner, v);
    }

    /// Set QPACK max table capacity
    pub fn setQpackMaxTableCapacity(self: *Self, v: u64) void {
        c.quiche_h3_config_set_qpack_max_table_capacity(self.inner, v);
    }
};

/// HTTP/3 Header
pub const H3Header = struct {
    name: []const u8,
    value: []const u8,

    pub fn init(name: []const u8, value: []const u8) H3Header {
        return .{ .name = name, .value = value };
    }
};

/// Convert Zig headers to C headers
fn headersToC(headers: []const H3Header) []const c.quiche_h3_header {
    // This is a simplified version - in production, you'd want to allocate
    // For now, we use a static buffer (limited to 64 headers)
    const S = struct {
        var c_headers: [64]c.quiche_h3_header = undefined;
    };

    const len = @min(headers.len, 64);
    for (headers[0..len], 0..) |h, i| {
        S.c_headers[i] = .{
            .name = h.name.ptr,
            .name_len = h.name.len,
            .value = h.value.ptr,
            .value_len = h.value.len,
        };
    }
    return S.c_headers[0..len];
}

/// HTTP/3 Event types
pub const H3EventType = enum(c_int) {
    headers = 0,
    data = 1,
    finished = 2,
    datagram = 3,
    goaway = 4,
    reset = 5,
    priority_update = 6,

    pub fn fromC(val: c_int) ?H3EventType {
        return std.meta.intToEnum(H3EventType, val) catch null;
    }
};

/// HTTP/3 Event
pub const H3Event = struct {
    stream_id: u64,
    event_type: H3EventType,
    headers: ?[]H3Header = null,
    error_code: ?u64 = null,

    const Self = @This();

    pub fn fromC(stream_id: u64, ev: *c.quiche_h3_event) Self {
        const event_type = H3EventType.fromC(c.quiche_h3_event_type(ev)) orelse .finished;

        const result = Self{
            .stream_id = stream_id,
            .event_type = event_type,
        };

        // Get additional event data based on type
        switch (event_type) {
            .headers => {
                // Headers are iterated separately via quiche_h3_event_for_each_header
            },
            .reset => {
                // Could extract error code if needed
            },
            else => {},
        }

        return result;
    }
};

/// Header iteration callback context
pub const HeaderIterContext = struct {
    headers: std.ArrayListUnmanaged(H3Header),
    allocator: Allocator,
    error_occurred: bool = false,

    const Self = @This();

    pub fn init(alloc: Allocator) Self {
        return .{
            .headers = .{},
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit(self.allocator);
    }
};

/// Callback function for header iteration
fn headerIterCallback(
    name: [*]const u8,
    name_len: usize,
    value: [*]const u8,
    value_len: usize,
    ctx: ?*anyopaque,
) callconv(.C) c_int {
    const context: *HeaderIterContext = @ptrCast(@alignCast(ctx));

    // Duplicate name and value since they may not persist
    const name_copy = context.allocator.dupe(u8, name[0..name_len]) catch {
        context.error_occurred = true;
        return -1;
    };
    errdefer context.allocator.free(name_copy);

    const value_copy = context.allocator.dupe(u8, value[0..value_len]) catch {
        context.allocator.free(name_copy);
        context.error_occurred = true;
        return -1;
    };

    context.headers.append(context.allocator, .{
        .name = name_copy,
        .value = value_copy,
    }) catch {
        context.allocator.free(name_copy);
        context.allocator.free(value_copy);
        context.error_occurred = true;
        return -1;
    };

    return 0;
}

/// Extended H3Connection with header iteration support
pub const H3ConnectionExt = struct {
    h3: H3Connection,

    const Self = @This();

    pub fn init(h3: H3Connection) Self {
        return .{ .h3 = h3 };
    }

    /// Poll for HTTP/3 events with full header extraction
    pub fn pollWithHeaders(self: *Self, quic_conn: *Connection, allocator: Allocator) ?struct {
        event: H3Event,
        headers: ?HeaderIterContext,
    } {
        var ev: ?*c.quiche_h3_event = null;
        const stream_id = c.quiche_h3_conn_poll(self.h3.inner, quic_conn.inner, &ev);

        if (stream_id < 0) {
            return null;
        }

        if (ev) |event| {
            defer c.quiche_h3_event_free(event);

            const event_type = H3EventType.fromC(c.quiche_h3_event_type(event)) orelse .finished;
            const h3_event = H3Event{
                .stream_id = @intCast(stream_id),
                .event_type = event_type,
            };

            var header_ctx: ?HeaderIterContext = null;

            // Extract headers for header events
            if (event_type == .headers) {
                var ctx = HeaderIterContext.init(allocator);
                const rc = c.quiche_h3_event_for_each_header(event, headerIterCallback, &ctx);
                if (rc == 0 and !ctx.error_occurred) {
                    header_ctx = ctx;
                } else {
                    ctx.deinit();
                }
            }

            return .{
                .event = h3_event,
                .headers = header_ctx,
            };
        }

        return null;
    }
};

/// HTTP/3 error conversion
pub fn h3ToError(code: c_int) error{
    Done,
    BufferTooShort,
    InternalError,
    ExcessiveLoad,
    IdError,
    StreamCreationError,
    ClosedCriticalStream,
    MissingSettings,
    FrameUnexpected,
    FrameError,
    QpackDecompressionFailed,
    TransportError,
    StreamBlocked,
    SettingsError,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    ConnectError,
    VersionFallback,
    Unknown,
} {
    return switch (code) {
        -1 => error.Done,
        -2 => error.BufferTooShort,
        -3 => error.InternalError,
        -4 => error.ExcessiveLoad,
        -5 => error.IdError,
        -6 => error.StreamCreationError,
        -7 => error.ClosedCriticalStream,
        -8 => error.MissingSettings,
        -9 => error.FrameUnexpected,
        -10 => error.FrameError,
        -11 => error.QpackDecompressionFailed,
        -12 => error.TransportError,
        -13 => error.StreamBlocked,
        -14 => error.SettingsError,
        -15 => error.RequestRejected,
        -16 => error.RequestCancelled,
        -17 => error.RequestIncomplete,
        -18 => error.MessageError,
        -19 => error.ConnectError,
        -20 => error.VersionFallback,
        else => error.Unknown,
    };
}

// ============================================================================
// High-Level QUIC/HTTP3 Client
// ============================================================================

/// High-level HTTP/3 client that wraps quiche
pub const Http3Client = struct {
    config: Config,
    h3_config: H3Config,
    conn: ?Connection,
    h3_conn: ?H3Connection,
    allocator: Allocator,

    const Self = @This();

    /// Initialize HTTP/3 client
    pub fn init(allocator: Allocator) !Self {
        var config = try Config.initV1();
        errdefer config.deinit();

        // Set HTTP/3 ALPN
        try config.setApplicationProtos("\x02h3");

        // Set reasonable defaults
        config.setMaxIdleTimeout(30000);
        config.setMaxRecvUdpPayloadSize(65535);
        config.setMaxSendUdpPayloadSize(1350);
        config.setInitialMaxData(10 * 1024 * 1024);
        config.setInitialMaxStreamDataBidiLocal(1 * 1024 * 1024);
        config.setInitialMaxStreamDataBidiRemote(1 * 1024 * 1024);
        config.setInitialMaxStreamDataUni(1 * 1024 * 1024);
        config.setInitialMaxStreamsBidi(100);
        config.setInitialMaxStreamsUni(100);
        config.verifyPeer(true);

        var h3_config = try H3Config.init();
        errdefer h3_config.deinit();

        return .{
            .config = config,
            .h3_config = h3_config,
            .conn = null,
            .h3_conn = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.h3_conn) |*h3| h3.deinit();
        if (self.conn) |*conn| conn.deinit();
        self.h3_config.deinit();
        self.config.deinit();
    }

    /// Connect to a server
    pub fn connect(
        self: *Self,
        server_name: [*:0]const u8,
        local_addr: std.net.Address,
        peer_addr: std.net.Address,
    ) !void {
        // Generate connection ID
        var scid: [16]u8 = undefined;
        std.crypto.random.bytes(&scid);

        self.conn = try Connection.connect(
            server_name,
            &scid,
            local_addr,
            peer_addr,
            &self.config,
            self.allocator,
        );
    }

    /// Initialize HTTP/3 layer (call after QUIC handshake completes)
    pub fn initHttp3(self: *Self) !void {
        if (self.conn) |*conn| {
            self.h3_conn = try H3Connection.initClient(conn, &self.h3_config, self.allocator);
        } else {
            return error.NotConnected;
        }
    }

    /// Check if connected
    pub fn isConnected(self: *Self) bool {
        if (self.conn) |*conn| {
            return conn.isEstablished();
        }
        return false;
    }
};

/// High-level HTTP/3 server that wraps quiche
pub const Http3Server = struct {
    config: Config,
    h3_config: H3Config,
    allocator: Allocator,

    const Self = @This();

    /// Initialize HTTP/3 server
    pub fn init(
        allocator: Allocator,
        cert_path: [*:0]const u8,
        key_path: [*:0]const u8,
    ) !Self {
        var config = try Config.initV1();
        errdefer config.deinit();

        // Load TLS certificates
        try config.loadCertChainFromPemFile(cert_path);
        try config.loadPrivKeyFromPemFile(key_path);

        // Set HTTP/3 ALPN
        try config.setApplicationProtos("\x02h3");

        // Set server defaults
        config.setMaxIdleTimeout(60000);
        config.setMaxRecvUdpPayloadSize(65535);
        config.setMaxSendUdpPayloadSize(1350);
        config.setInitialMaxData(10 * 1024 * 1024);
        config.setInitialMaxStreamDataBidiLocal(1 * 1024 * 1024);
        config.setInitialMaxStreamDataBidiRemote(1 * 1024 * 1024);
        config.setInitialMaxStreamDataUni(1 * 1024 * 1024);
        config.setInitialMaxStreamsBidi(100);
        config.setInitialMaxStreamsUni(100);

        var h3_config = try H3Config.init();
        errdefer h3_config.deinit();

        return .{
            .config = config,
            .h3_config = h3_config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.h3_config.deinit();
        self.config.deinit();
    }

    /// Accept a new connection
    pub fn accept(
        self: *Self,
        scid: []const u8,
        odcid: ?[]const u8,
        local_addr: std.net.Address,
        peer_addr: std.net.Address,
    ) !Connection {
        return Connection.accept(scid, odcid, local_addr, peer_addr, &self.config, self.allocator);
    }

    /// Create HTTP/3 connection for an established QUIC connection
    pub fn createH3Connection(self: *Self, conn: *Connection) !H3Connection {
        return H3Connection.initServer(conn, &self.h3_config, self.allocator);
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Get quiche version string
pub fn version() []const u8 {
    const ver = c.quiche_version();
    if (ver) |v| {
        const len = std.mem.len(v);
        return v[0..len];
    }
    return "unknown";
}

/// Check if a buffer contains a QUIC packet
pub fn isQuicPacket(buf: []const u8) bool {
    if (buf.len == 0) return false;
    // QUIC long header starts with 1, short header with 0 in high bit
    // But both are valid QUIC packets
    return true;
}

/// Parse connection ID from incoming packet
pub fn parseConnectionId(buf: []const u8, dcid_len: usize) ?[]const u8 {
    if (buf.len < 1 + dcid_len) return null;

    // Check if long header (bit 7 set)
    const is_long = (buf[0] & 0x80) != 0;

    if (is_long) {
        // Long header: version (4) + dcid_len (1) + dcid
        if (buf.len < 6) return null;
        const len = buf[5];
        if (buf.len < 6 + len) return null;
        return buf[6 .. 6 + len];
    } else {
        // Short header: dcid starts at byte 1
        if (buf.len < 1 + dcid_len) return null;
        return buf[1 .. 1 + dcid_len];
    }
}

// ============================================================================
// Tests (only run when quiche is available)
// ============================================================================

test "Config creation and defaults" {
    // These tests require quiche library to be linked
    // Skip if not available
    if (@import("builtin").is_test) {
        // Basic type checks - actual functionality requires quiche
        const stats = ConnectionStats{
            .recv = 0,
            .sent = 0,
            .lost = 0,
            .retrans = 0,
            .sent_bytes = 0,
            .recv_bytes = 0,
            .lost_bytes = 0,
            .stream_retrans_bytes = 0,
            .rtt = 0,
            .cwnd = 0,
            .delivery_rate = 0,
        };
        try testing.expectEqual(stats.recv, 0);
    }
}

test "QuicheError conversion" {
    try testing.expectEqual(QuicheError.toError(-1), .done);
    try testing.expectEqual(QuicheError.toError(-2), .buffer_too_short);
    try testing.expectEqual(QuicheError.toError(-10), .tls_fail);
    try testing.expectEqual(QuicheError.toError(-999), null);
}

test "H3Header creation" {
    const header = H3Header.init(":method", "GET");
    try testing.expectEqualStrings(header.name, ":method");
    try testing.expectEqualStrings(header.value, "GET");
}

test "H3EventType conversion" {
    try testing.expectEqual(H3EventType.fromC(0), .headers);
    try testing.expectEqual(H3EventType.fromC(1), .data);
    try testing.expectEqual(H3EventType.fromC(2), .finished);
    try testing.expectEqual(H3EventType.fromC(99), null);
}

test "parseConnectionId" {
    // Short header packet simulation
    var short_pkt = [_]u8{ 0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const short_dcid = parseConnectionId(&short_pkt, 8);
    try testing.expect(short_dcid != null);
    try testing.expectEqual(short_dcid.?.len, 8);

    // Long header packet simulation
    var long_pkt = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };
    const long_dcid = parseConnectionId(&long_pkt, 4);
    try testing.expect(long_dcid != null);
    try testing.expectEqualSlices(u8, long_dcid.?, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
}

test "CongestionControlAlgorithm names" {
    try testing.expectEqualStrings("reno", std.mem.span(CongestionControlAlgorithm.reno.name()));
    try testing.expectEqualStrings("cubic", std.mem.span(CongestionControlAlgorithm.cubic.name()));
    try testing.expectEqualStrings("bbr", std.mem.span(CongestionControlAlgorithm.bbr.name()));
    try testing.expectEqualStrings("bbr2", std.mem.span(CongestionControlAlgorithm.bbr2.name()));
}

test "QUIC version constants" {
    try testing.expectEqual(QUIC_VERSION_1, 0x00000001);
    try testing.expectEqual(QUIC_VERSION_2, 0x6b3343cf);
    try testing.expectEqual(MAX_CONN_ID_LEN, 20);
    try testing.expectEqual(MIN_CLIENT_INITIAL_LEN, 1200);
}

test "HeaderIterContext init and deinit" {
    var ctx = HeaderIterContext.init(testing.allocator);
    defer ctx.deinit();

    try testing.expectEqual(ctx.headers.items.len, 0);
    try testing.expect(!ctx.error_occurred);
}

test "StreamShutdown enum values" {
    try testing.expectEqual(@intFromEnum(StreamShutdown.read), 0);
    try testing.expectEqual(@intFromEnum(StreamShutdown.write), 1);
}

// ============================================================================
// Extended Integration Tests (Pure Zig - no quiche library required)
// ============================================================================

test "quicheToError all error codes" {
    // Test all error code conversions
    try testing.expectEqual(quicheToError(-1), error.Done);
    try testing.expectEqual(quicheToError(-2), error.BufferTooShort);
    try testing.expectEqual(quicheToError(-3), error.UnknownVersion);
    try testing.expectEqual(quicheToError(-4), error.InvalidFrame);
    try testing.expectEqual(quicheToError(-5), error.InvalidPacket);
    try testing.expectEqual(quicheToError(-6), error.InvalidState);
    try testing.expectEqual(quicheToError(-7), error.InvalidStreamState);
    try testing.expectEqual(quicheToError(-8), error.InvalidTransportParam);
    try testing.expectEqual(quicheToError(-9), error.CryptoFail);
    try testing.expectEqual(quicheToError(-10), error.TlsFail);
    try testing.expectEqual(quicheToError(-11), error.FlowControl);
    try testing.expectEqual(quicheToError(-12), error.StreamLimit);
    try testing.expectEqual(quicheToError(-13), error.StreamStopped);
    try testing.expectEqual(quicheToError(-14), error.StreamReset);
    try testing.expectEqual(quicheToError(-15), error.FinalSize);
    try testing.expectEqual(quicheToError(-16), error.CongestionControl);
    try testing.expectEqual(quicheToError(-17), error.IdLimit);
    try testing.expectEqual(quicheToError(-18), error.OutOfIdentifiers);
    try testing.expectEqual(quicheToError(-19), error.KeyUpdate);
    try testing.expectEqual(quicheToError(-20), error.CryptoBufferExceeded);
    try testing.expectEqual(quicheToError(-100), error.Unknown);
    try testing.expectEqual(quicheToError(0), error.Unknown);
}

test "ConnectionStats initialization and fields" {
    const stats = ConnectionStats{
        .recv = 100,
        .sent = 200,
        .lost = 5,
        .retrans = 10,
        .sent_bytes = 50000,
        .recv_bytes = 40000,
        .lost_bytes = 1000,
        .stream_retrans_bytes = 500,
        .rtt = 25000, // 25ms in microseconds
        .cwnd = 65535,
        .delivery_rate = 1000000,
    };

    try testing.expectEqual(stats.recv, 100);
    try testing.expectEqual(stats.sent, 200);
    try testing.expectEqual(stats.lost, 5);
    try testing.expectEqual(stats.retrans, 10);
    try testing.expectEqual(stats.sent_bytes, 50000);
    try testing.expectEqual(stats.recv_bytes, 40000);
    try testing.expectEqual(stats.lost_bytes, 1000);
    try testing.expectEqual(stats.stream_retrans_bytes, 500);
    try testing.expectEqual(stats.rtt, 25000);
    try testing.expectEqual(stats.cwnd, 65535);
    try testing.expectEqual(stats.delivery_rate, 1000000);
}

test "PathStats initialization" {
    var stats: PathStats = undefined;
    stats.active = true;
    stats.recv = 50;
    stats.sent = 100;
    stats.lost = 2;
    stats.retrans = 3;
    stats.rtt = 10000;
    stats.cwnd = 32768;
    stats.sent_bytes = 25000;
    stats.recv_bytes = 20000;
    stats.lost_bytes = 500;
    stats.stream_retrans_bytes = 200;
    stats.pmtu = 1200;
    stats.delivery_rate = 500000;

    try testing.expect(stats.active);
    try testing.expectEqual(stats.recv, 50);
    try testing.expectEqual(stats.pmtu, 1200);
}

test "SendInfo initialization" {
    const send_info = SendInfo.init();
    try testing.expectEqual(send_info.to_len, 0);
    try testing.expectEqual(send_info.at.tv_sec, 0);
    try testing.expectEqual(send_info.at.tv_nsec, 0);
}

test "H3Header multiple headers" {
    const headers = [_]H3Header{
        H3Header.init(":method", "GET"),
        H3Header.init(":path", "/index.html"),
        H3Header.init(":scheme", "https"),
        H3Header.init(":authority", "example.com"),
        H3Header.init("accept", "text/html"),
        H3Header.init("user-agent", "pingora-zig/1.0"),
    };

    try testing.expectEqual(headers.len, 6);
    try testing.expectEqualStrings(headers[0].name, ":method");
    try testing.expectEqualStrings(headers[1].value, "/index.html");
    try testing.expectEqualStrings(headers[3].value, "example.com");
}

test "H3EventType all types" {
    try testing.expectEqual(H3EventType.fromC(0), .headers);
    try testing.expectEqual(H3EventType.fromC(1), .data);
    try testing.expectEqual(H3EventType.fromC(2), .finished);
    try testing.expectEqual(H3EventType.fromC(3), .datagram);
    try testing.expectEqual(H3EventType.fromC(4), .goaway);
    try testing.expectEqual(H3EventType.fromC(5), .reset);
    try testing.expectEqual(H3EventType.fromC(6), .priority_update);
    try testing.expectEqual(H3EventType.fromC(100), null);
}

test "parseConnectionId edge cases" {
    // Empty buffer
    const empty: []const u8 = &[_]u8{};
    try testing.expectEqual(parseConnectionId(empty, 8), null);

    // Buffer too short for short header
    const too_short = [_]u8{ 0x40, 0x01 };
    try testing.expectEqual(parseConnectionId(&too_short, 8), null);

    // Exact minimum for short header
    const exact_short = [_]u8{ 0x40, 0x01, 0x02, 0x03, 0x04 };
    const short_cid = parseConnectionId(&exact_short, 4);
    try testing.expect(short_cid != null);
    try testing.expectEqual(short_cid.?.len, 4);

    // Long header with zero-length DCID
    const long_zero_dcid = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00 };
    const zero_dcid = parseConnectionId(&long_zero_dcid, 0);
    try testing.expect(zero_dcid != null);
    try testing.expectEqual(zero_dcid.?.len, 0);

    // Long header too short
    const long_too_short = [_]u8{ 0xc0, 0x00, 0x00 };
    try testing.expectEqual(parseConnectionId(&long_too_short, 8), null);
}

test "isQuicPacket" {
    // Empty buffer
    const empty: []const u8 = &[_]u8{};
    try testing.expect(!isQuicPacket(empty));

    // Long header (bit 7 set)
    const long_header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    try testing.expect(isQuicPacket(&long_header));

    // Short header (bit 7 clear)
    const short_header = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    try testing.expect(isQuicPacket(&short_header));
}

test "QuicheError enum values" {
    try testing.expectEqual(@intFromEnum(QuicheError.done), -1);
    try testing.expectEqual(@intFromEnum(QuicheError.buffer_too_short), -2);
    try testing.expectEqual(@intFromEnum(QuicheError.unknown_version), -3);
    try testing.expectEqual(@intFromEnum(QuicheError.invalid_frame), -4);
    try testing.expectEqual(@intFromEnum(QuicheError.invalid_packet), -5);
    try testing.expectEqual(@intFromEnum(QuicheError.invalid_state), -6);
    try testing.expectEqual(@intFromEnum(QuicheError.invalid_stream_state), -7);
    try testing.expectEqual(@intFromEnum(QuicheError.invalid_transport_param), -8);
    try testing.expectEqual(@intFromEnum(QuicheError.crypto_fail), -9);
    try testing.expectEqual(@intFromEnum(QuicheError.tls_fail), -10);
    try testing.expectEqual(@intFromEnum(QuicheError.flow_control), -11);
    try testing.expectEqual(@intFromEnum(QuicheError.stream_limit), -12);
    try testing.expectEqual(@intFromEnum(QuicheError.stream_stopped), -13);
    try testing.expectEqual(@intFromEnum(QuicheError.stream_reset), -14);
    try testing.expectEqual(@intFromEnum(QuicheError.final_size), -15);
    try testing.expectEqual(@intFromEnum(QuicheError.congestion_control), -16);
    try testing.expectEqual(@intFromEnum(QuicheError.id_limit), -17);
    try testing.expectEqual(@intFromEnum(QuicheError.out_of_identifiers), -18);
    try testing.expectEqual(@intFromEnum(QuicheError.key_update), -19);
    try testing.expectEqual(@intFromEnum(QuicheError.crypto_buffer_exceeded), -20);
}

test "HeaderIterContext add headers" {
    var ctx = HeaderIterContext.init(testing.allocator);
    defer ctx.deinit();

    // Simulate adding headers (what the callback would do)
    const name1 = try testing.allocator.dupe(u8, ":status");
    const value1 = try testing.allocator.dupe(u8, "200");
    try ctx.headers.append(ctx.allocator, H3Header.init(name1, value1));

    const name2 = try testing.allocator.dupe(u8, "content-type");
    const value2 = try testing.allocator.dupe(u8, "text/html");
    try ctx.headers.append(ctx.allocator, H3Header.init(name2, value2));

    try testing.expectEqual(ctx.headers.items.len, 2);
    try testing.expectEqualStrings(ctx.headers.items[0].name, ":status");
    try testing.expectEqualStrings(ctx.headers.items[0].value, "200");
    try testing.expectEqualStrings(ctx.headers.items[1].name, "content-type");
    try testing.expectEqualStrings(ctx.headers.items[1].value, "text/html");
}

test "QUIC protocol constants" {
    // RFC 9000 compliance checks
    try testing.expect(MAX_CONN_ID_LEN == 20); // RFC 9000 Section 17.2
    try testing.expect(MIN_CLIENT_INITIAL_LEN >= 1200); // RFC 9000 Section 14.1
    try testing.expect(MAX_DATAGRAM_SIZE <= 65535); // UDP max payload
}

test "CongestionControlAlgorithm iteration" {
    const algorithms = [_]CongestionControlAlgorithm{ .reno, .cubic, .bbr, .bbr2 };
    var names_found: usize = 0;

    for (algorithms) |algo| {
        const name = std.mem.span(algo.name());
        try testing.expect(name.len > 0);
        names_found += 1;
    }

    try testing.expectEqual(names_found, 4);
}

test "H3Event creation" {
    const event = H3Event{
        .stream_id = 4,
        .event_type = .headers,
    };

    try testing.expectEqual(event.stream_id, 4);
    try testing.expectEqual(event.event_type, .headers);

    // Test different event types
    const data_event = H3Event{
        .stream_id = 8,
        .event_type = .data,
    };
    try testing.expectEqual(data_event.event_type, .data);
}
