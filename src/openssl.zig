//! OpenSSL Bindings for TLS
//!
//! This module provides bindings to OpenSSL for TLS handshake and encryption.
//! It wraps the OpenSSL C API for use in Zig.
//!
//! Note: Requires OpenSSL to be installed on the system.
//! Link with: -lssl -lcrypto
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-openssl

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const tls = @import("tls.zig");
const protocols = @import("protocols.zig");

// ============================================================================
// OpenSSL C Bindings
// ============================================================================

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/hmac.h");
    @cInclude("openssl/crypto.h");
});

// ============================================================================
// OpenSSL Error Handling
// ============================================================================

pub const SslError = error{
    InitFailed,
    ContextCreationFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    ShutdownFailed,
    WantRead,
    WantWrite,
    ZeroReturn,
    Syscall,
    UnknownError,
    VerificationFailed,
    OutOfMemory,

    /// Session was not available (e.g. before handshake)
    SessionUnavailable,

    /// Peer certificate was not available (e.g. not provided by peer)
    PeerCertificateUnavailable,

    /// OCSP response was not available / not supported
    OcspUnavailable,

    /// OpenSSL rejected a callback registration / configuration
    CallbackRegistrationFailed,
};

/// Get the last OpenSSL error as a string
pub fn getLastError() []const u8 {
    const err = c.ERR_get_error();
    if (err == 0) return "No error";

    var buf: [256]u8 = undefined;
    c.ERR_error_string_n(err, &buf, buf.len);

    // Find null terminator
    for (buf, 0..) |char, i| {
        if (char == 0) return buf[0..i];
    }
    return &buf;
}

/// Clear all pending OpenSSL errors
pub fn clearErrors() void {
    c.ERR_clear_error();
}

// ============================================================================
// SSL Method Types
// ============================================================================

pub const SslMethod = enum {
    /// TLS client method (auto-negotiate version)
    tls_client,
    /// TLS server method (auto-negotiate version)
    tls_server,
    /// TLS 1.2 only
    tls_1_2,
    /// TLS 1.3 only
    tls_1_3,

    fn toOpenSSL(self: SslMethod) ?*c.SSL_METHOD {
        return switch (self) {
            .tls_client => c.TLS_client_method(),
            .tls_server => c.TLS_server_method(),
            .tls_1_2 => c.TLSv1_2_method(),
            .tls_1_3 => c.TLS_method(), // Use TLS_method and set min version
        };
    }
};

// ============================================================================
// SSL Context
// ============================================================================

/// SSL Context - holds certificates and configuration
pub const SslContext = struct {
    ctx: *c.SSL_CTX,
    allocator: Allocator,
    /// Optional callback storage owned by this context.
    ///
    /// We keep this to ensure any allocated callback context is freed when the
    /// SSL_CTX is freed.
    callback_ctx: ?*CallbackCtx = null,

    const Self = @This();

    // ------------------------------------------------------------------------
    // Callback types (Pingora-like hooks)
    // ------------------------------------------------------------------------

    /// OpenSSL session ticket key callback.
    /// See: SSL_CTX_set_tlsext_ticket_key_cb
    pub const TicketKeyCb = *const fn (
        ssl: ?*c.SSL,
        key_name: [*c]u8,
        iv: [*c]u8,
        evp_ctx: ?*c.EVP_CIPHER_CTX,
        hmac_ctx: ?*c.HMAC_CTX,
        enc: c_int,
    ) callconv(.C) c_int;

    /// OpenSSL OCSP status callback.
    /// See: SSL_CTX_set_tlsext_status_cb
    pub const OcspStatusCb = *const fn (ssl: ?*c.SSL, arg: ?*anyopaque) callconv(.C) c_int;

    const CallbackCtx = struct {
        ticket_cb: ?TicketKeyCb = null,
        ticket_arg: ?*anyopaque = null,
    };

    var ex_data_index: std.atomic.Value(c_int) = .init(-1);

    fn ensureExDataIndex() void {
        const existing = ex_data_index.load(.acquire);
        if (existing >= 0) return;

        // We use an SSL_CTX ex_data slot to store a pointer to CallbackCtx.
        const created: c_int = c.SSL_CTX_get_ex_new_index(0, null, null, null, null);
        if (created < 0) {
            // Leave as -1
            return;
        }

        // Best-effort publish (if another thread wins, keep their value).
        _ = ex_data_index.compareExchangeStrong(-1, created, .acq_rel, .acquire);
    }

    fn setCallbackCtx(self: *Self, ptr: *CallbackCtx) SslError!void {
        ensureExDataIndex();
        const idx = ex_data_index.load(.acquire);
        if (idx < 0) return SslError.CallbackRegistrationFailed;
        if (c.SSL_CTX_set_ex_data(self.ctx, idx, ptr) != 1) {
            return SslError.CallbackRegistrationFailed;
        }
    }

    fn getCallbackCtx(self: *Self) ?*CallbackCtx {
        ensureExDataIndex();
        const idx = ex_data_index.load(.acquire);
        if (idx < 0) return null;
        return @ptrCast(@alignCast(c.SSL_CTX_get_ex_data(self.ctx, idx)));
    }

    fn ticketKeyTrampoline(
        ssl: ?*c.SSL,
        key_name: [*c]u8,
        iv: [*c]u8,
        evp_ctx: ?*c.EVP_CIPHER_CTX,
        hmac_ctx: ?*c.HMAC_CTX,
        enc: c_int,
    ) callconv(.C) c_int {
        const s = ssl orelse return -1;
        const ctx = c.SSL_get_SSL_CTX(s) orelse return -1;
        ensureExDataIndex();
        const idx = ex_data_index.load(.acquire);
        if (idx < 0) return -1;
        const cb_ctx: ?*CallbackCtx = @ptrCast(@alignCast(c.SSL_CTX_get_ex_data(ctx, idx)));
        if (cb_ctx) |p| {
            if (p.ticket_cb) |cb| {
                _ = p; // keep p alive
                return cb(ssl, key_name, iv, evp_ctx, hmac_ctx, enc);
            }
        }
        return -1;
    }

    /// Create a new SSL context for client connections
    pub fn initClient(allocator: Allocator) SslError!Self {
        // Initialize OpenSSL
        _ = c.OPENSSL_init_ssl(0, null);

        const method = c.TLS_client_method() orelse return SslError.InitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.ContextCreationFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
            .callback_ctx = null,
        };
    }

    /// Create a new SSL context for server connections
    pub fn initServer(allocator: Allocator) SslError!Self {
        _ = c.OPENSSL_init_ssl(0, null);

        const method = c.TLS_server_method() orelse return SslError.InitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.ContextCreationFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
            .callback_ctx = null,
        };
    }

    /// Free the SSL context
    pub fn deinit(self: *Self) void {
        // Best-effort cleanup of any allocated callback context.
        if (self.callback_ctx) |p| {
            // Clear ex_data to avoid dangling pointer during SSL_CTX_free.
            if (self.getCallbackCtx() != null) {
                ensureExDataIndex();
                const idx = ex_data_index.load(.acquire);
                if (idx >= 0) {
                    _ = c.SSL_CTX_set_ex_data(self.ctx, idx, null);
                }
            }
            self.allocator.destroy(p);
            self.callback_ctx = null;
        }
        c.SSL_CTX_free(self.ctx);
    }

    /// Load certificate from file (PEM format)
    pub fn loadCertificateFile(self: *Self, path: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_use_certificate_file(self.ctx, path, c.SSL_FILETYPE_PEM) != 1) {
            return SslError.CertificateLoadFailed;
        }
    }

    /// Load certificate chain from file (PEM format)
    pub fn loadCertificateChainFile(self: *Self, path: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_use_certificate_chain_file(self.ctx, path) != 1) {
            return SslError.CertificateLoadFailed;
        }
    }

    /// Load private key from file (PEM format)
    pub fn loadPrivateKeyFile(self: *Self, path: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_use_PrivateKey_file(self.ctx, path, c.SSL_FILETYPE_PEM) != 1) {
            return SslError.PrivateKeyLoadFailed;
        }
    }

    /// Load certificate from memory (DER format)
    pub fn loadCertificateDer(self: *Self, der: []const u8) SslError!void {
        if (c.SSL_CTX_use_certificate_ASN1(self.ctx, @intCast(der.len), der.ptr) != 1) {
            return SslError.CertificateLoadFailed;
        }
    }

    /// Set minimum TLS version
    pub fn setMinVersion(self: *Self, version: tls.TlsVersion) void {
        const v: c_int = switch (version) {
            .tls_1_0 => c.TLS1_VERSION,
            .tls_1_1 => c.TLS1_1_VERSION,
            .tls_1_2 => c.TLS1_2_VERSION,
            .tls_1_3 => c.TLS1_3_VERSION,
        };
        _ = c.SSL_CTX_set_min_proto_version(self.ctx, v);
    }

    /// Set maximum TLS version
    pub fn setMaxVersion(self: *Self, version: tls.TlsVersion) void {
        const v: c_int = switch (version) {
            .tls_1_0 => c.TLS1_VERSION,
            .tls_1_1 => c.TLS1_1_VERSION,
            .tls_1_2 => c.TLS1_2_VERSION,
            .tls_1_3 => c.TLS1_3_VERSION,
        };
        _ = c.SSL_CTX_set_max_proto_version(self.ctx, v);
    }

    /// Set ALPN protocols (for HTTP/2 negotiation)
    pub fn setAlpnProtocols(self: *Self, protocols_wire: []const u8) SslError!void {
        if (c.SSL_CTX_set_alpn_protos(self.ctx, protocols_wire.ptr, @intCast(protocols_wire.len)) != 0) {
            return SslError.InitFailed;
        }
    }

    /// Enable/disable certificate verification (client-side)
    pub fn setVerifyMode(self: *Self, verify: bool) void {
        const mode: c_int = if (verify) c.SSL_VERIFY_PEER else c.SSL_VERIFY_NONE;
        c.SSL_CTX_set_verify(self.ctx, mode, null);
    }

    /// Configure server-side client certificate authentication.
    ///
    /// If `required` is true, handshake fails if the client does not provide a cert.
    pub fn requireClientCertificate(self: *Self, required: bool) void {
        var mode: c_int = c.SSL_VERIFY_PEER;
        if (required) mode |= c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        c.SSL_CTX_set_verify(self.ctx, mode, null);
    }

    /// Set maximum verification depth.
    pub fn setVerifyDepth(self: *Self, depth: u32) void {
        c.SSL_CTX_set_verify_depth(self.ctx, @intCast(depth));
    }

    /// Register a session ticket key callback (server-side).
    ///
    /// This is the OpenSSL hook used to encrypt/decrypt session tickets.
    pub fn setSessionTicketKeyCallback(self: *Self, cb: TicketKeyCb, arg: ?*anyopaque) SslError!void {
        // Store callback context in SSL_CTX ex_data.
        // Allocate at most once per context to avoid leaks on repeated calls.
        const ctx_ptr: *CallbackCtx = self.callback_ctx orelse blk: {
            const p = try self.allocator.create(CallbackCtx);
            errdefer self.allocator.destroy(p);
            self.callback_ctx = p;
            break :blk p;
        };

        ctx_ptr.* = .{ .ticket_cb = cb, .ticket_arg = arg };
        try self.setCallbackCtx(ctx_ptr);

        c.SSL_CTX_set_tlsext_ticket_key_cb(self.ctx, ticketKeyTrampoline);
    }

    /// Register an OCSP status callback (server-side).
    ///
    /// This enables OCSP stapling: OpenSSL will invoke `cb` to fetch/set the OCSP response.
    pub fn setOcspStatusCallback(self: *Self, cb: OcspStatusCb, arg: ?*anyopaque) void {
        c.SSL_CTX_set_tlsext_status_cb(self.ctx, cb);
        c.SSL_CTX_set_tlsext_status_arg(self.ctx, arg);
    }

    /// Load CA certificates from file
    pub fn loadCaFile(self: *Self, path: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_load_verify_locations(self.ctx, path, null) != 1) {
            return SslError.CertificateLoadFailed;
        }
    }

    /// Set cipher list
    pub fn setCipherList(self: *Self, ciphers: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_set_cipher_list(self.ctx, ciphers) != 1) {
            return SslError.InitFailed;
        }
    }

    /// Set ciphersuites (TLS 1.3)
    pub fn setCipherSuites(self: *Self, ciphersuites: [*:0]const u8) SslError!void {
        if (c.SSL_CTX_set_ciphersuites(self.ctx, ciphersuites) != 1) {
            return SslError.InitFailed;
        }
    }

    /// Create a new SSL connection from this context
    pub fn createSsl(self: *Self) SslError!SslConnection {
        const ssl = c.SSL_new(self.ctx) orelse return SslError.InitFailed;
        return SslConnection{
            .ssl = ssl,
            .allocator = self.allocator,
        };
    }
};

// ============================================================================
// SSL Connection
// ============================================================================

/// SSL Connection - represents a TLS connection
/// SSL_SESSION wrapper with reference counting.
pub const SslSession = struct {
    session: *c.SSL_SESSION,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        c.SSL_SESSION_free(self.session);
    }
};

pub const SslConnection = struct {
    ssl: *c.SSL,
    allocator: Allocator,
    handshake_complete: bool = false,

    const Self = @This();

    /// Free the SSL connection
    pub fn deinit(self: *Self) void {
        c.SSL_free(self.ssl);
    }

    /// Set the file descriptor for the connection
    pub fn setFd(self: *Self, fd: c_int) SslError!void {
        if (c.SSL_set_fd(self.ssl, fd) != 1) {
            return SslError.InitFailed;
        }
    }

    /// Set the server name for SNI
    pub fn setServerName(self: *Self, hostname: [*:0]const u8) SslError!void {
        if (c.SSL_set_tlsext_host_name(self.ssl, hostname) != 1) {
            return SslError.InitFailed;
        }
    }

    /// Perform the TLS handshake (client side)
    pub fn connect(self: *Self) SslError!void {
        clearErrors();
        const ret = c.SSL_connect(self.ssl);
        if (ret == 1) {
            self.handshake_complete = true;
            return;
        }
        return self.handleError(ret);
    }

    /// Perform the TLS handshake (server side)
    pub fn accept(self: *Self) SslError!void {
        clearErrors();
        const ret = c.SSL_accept(self.ssl);
        if (ret == 1) {
            self.handshake_complete = true;
            return;
        }
        return self.handleError(ret);
    }

    /// Read decrypted data
    pub fn read(self: *Self, buf: []u8) SslError!usize {
        clearErrors();
        const ret = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (ret > 0) {
            return @intCast(ret);
        }
        if (ret == 0) {
            return SslError.ZeroReturn;
        }
        return self.handleError(ret);
    }

    /// Write data to be encrypted
    pub fn write(self: *Self, data: []const u8) SslError!usize {
        clearErrors();
        const ret = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (ret > 0) {
            return @intCast(ret);
        }
        return self.handleError(ret);
    }

    /// Shutdown the TLS connection
    pub fn shutdown(self: *Self) SslError!void {
        clearErrors();
        const ret = c.SSL_shutdown(self.ssl);
        if (ret >= 0) return;
        return self.handleError(ret);
    }

    /// Get the negotiated TLS version
    pub fn getVersion(self: *Self) ?tls.TlsVersion {
        const v = c.SSL_version(self.ssl);
        return switch (v) {
            c.TLS1_VERSION => .tls_1_0,
            c.TLS1_1_VERSION => .tls_1_1,
            c.TLS1_2_VERSION => .tls_1_2,
            c.TLS1_3_VERSION => .tls_1_3,
            else => null,
        };
    }

    /// Get the negotiated cipher suite
    pub fn getCipherName(self: *Self) ?[]const u8 {
        const cipher = c.SSL_get_current_cipher(self.ssl) orelse return null;
        const name = c.SSL_CIPHER_get_name(cipher);
        if (name == null) return null;

        // Convert C string to Zig slice
        const ptr: [*:0]const u8 = @ptrCast(name);
        return std.mem.span(ptr);
    }

    /// Get the negotiated ALPN protocol
    pub fn getAlpnProtocol(self: *Self) ?[]const u8 {
        var data: [*c]const u8 = undefined;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(self.ssl, &data, &len);
        if (len == 0 or data == null) return null;
        return data[0..len];
    }

    /// Get the peer certificate.
    ///
    /// Note: OpenSSL returns a *new reference* (caller must free with `X509_free`).
    pub fn getPeerCertificate(self: *Self) ?*c.X509 {
        return c.SSL_get_peer_certificate(self.ssl);
    }

    /// Get the peer certificate encoded as DER.
    ///
    /// Allocates a new buffer owned by the caller.
    pub fn getPeerCertificateDer(self: *Self, allocator: Allocator) SslError![]u8 {
        if (!@hasDecl(c, "i2d_X509")) return SslError.InitFailed;
        const cert = self.getPeerCertificate() orelse return SslError.PeerCertificateUnavailable;
        defer c.X509_free(cert);

        // i2d_X509 advances the pointer, so we need a temp pointer variable.
        const len_i: c_int = c.i2d_X509(cert, null);
        if (len_i <= 0) return SslError.InitFailed;
        const len: usize = @intCast(len_i);

        var out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var p: [*c]u8 = out.ptr;
        const written: c_int = c.i2d_X509(cert, &p);
        if (written != len_i) return SslError.InitFailed;
        return out;
    }

    /// Set an OCSP stapling response for this connection.
    ///
    /// Ownership: OpenSSL takes ownership of the provided buffer and will free it.
    /// This function therefore allocates with `OPENSSL_malloc`.
    pub fn setOcspResponse(self: *Self, resp: []const u8) SslError!void {
        if (!@hasDecl(c, "SSL_set_tlsext_status_ocsp_resp")) return SslError.OcspUnavailable;
        if (!@hasDecl(c, "OPENSSL_malloc")) return SslError.OcspUnavailable;

        const mem = c.OPENSSL_malloc(resp.len) orelse return SslError.OutOfMemory;
        const mem_u8: [*]u8 = @ptrCast(mem);
        @memcpy(mem_u8[0..resp.len], resp);

        // If OpenSSL rejects, it won't take ownership; free to avoid leak.
        if (c.SSL_set_tlsext_status_ocsp_resp(self.ssl, @ptrCast(mem), @intCast(resp.len)) != 1) {
            c.OPENSSL_free(mem);
            return SslError.OcspUnavailable;
        }
    }

    /// Get the current OCSP stapling response (borrowed slice).
    ///
    /// The returned slice is owned by OpenSSL and valid for the lifetime of the SSL object.
    pub fn getOcspResponse(self: *Self) ?[]const u8 {
        if (!@hasDecl(c, "SSL_get0_tlsext_status_ocsp_resp")) return null;
        var p: [*c]const u8 = null;
        const len_i: c_int = c.SSL_get0_tlsext_status_ocsp_resp(self.ssl, &p);
        if (len_i <= 0 or p == null) return null;
        return p[0..@intCast(len_i)];
    }

    /// Verify the peer certificate
    pub fn verifyPeerCertificate(self: *Self) SslError!void {
        const result = c.SSL_get_verify_result(self.ssl);
        if (result != c.X509_V_OK) {
            return SslError.VerificationFailed;
        }
    }

    /// Check if handshake is complete
    pub fn isHandshakeComplete(self: *Self) bool {
        return self.handshake_complete;
    }

    /// Get the SNI server name (server side)
    pub fn getServerName(self: *Self) ?[]const u8 {
        const name = c.SSL_get_servername(self.ssl, c.TLSEXT_NAMETYPE_host_name);
        if (name == null) return null;
        const ptr: [*:0]const u8 = @ptrCast(name);
        return std.mem.span(ptr);
    }

    /// Returns true if session resumption was used for this connection.
    ///
    /// Meaningful only after handshake; before handshake returns false.
    pub fn isSessionReused(self: *Self) bool {
        return c.SSL_session_reused(self.ssl) == 1;
    }

    /// Get the negotiated session (increments refcount).
    ///
    /// Requires handshake; otherwise returns `SslError.SessionUnavailable`.
    pub fn get1Session(self: *Self) SslError!SslSession {
        if (!self.handshake_complete) return SslError.SessionUnavailable;
        const sess = c.SSL_get1_session(self.ssl) orelse return SslError.SessionUnavailable;
        return .{ .session = sess };
    }

    /// Set a session for possible resumption on the next handshake.
    pub fn setSession(self: *Self, session: *c.SSL_SESSION) SslError!void {
        if (c.SSL_set_session(self.ssl, session) != 1) {
            return SslError.InitFailed;
        }
    }

    fn handleError(self: *Self, ret: c_int) SslError {
        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => SslError.WantRead,
            c.SSL_ERROR_WANT_WRITE => SslError.WantWrite,
            c.SSL_ERROR_ZERO_RETURN => SslError.ZeroReturn,
            c.SSL_ERROR_SYSCALL => SslError.Syscall,
            c.SSL_ERROR_SSL => SslError.HandshakeFailed,
            else => SslError.UnknownError,
        };
    }
};

// ============================================================================
// TLS Stream - High-level wrapper
// ============================================================================

/// A TLS-wrapped stream
pub const TlsStream = struct {
    ssl: SslConnection,
    tcp: protocols.TcpStream,
    allocator: Allocator,

    const Self = @This();

    /// Create a TLS client stream by connecting to a server
    pub fn connectClient(
        allocator: Allocator,
        address: std.net.Address,
        ctx: *SslContext,
        hostname: ?[*:0]const u8,
    ) !Self {
        // Connect TCP
        var tcp = try protocols.TcpStream.connect(address, .{});
        errdefer tcp.close();

        // Create SSL
        var ssl = try ctx.createSsl();
        errdefer ssl.deinit();

        // Set SNI
        if (hostname) |h| {
            try ssl.setServerName(h);
        }

        // Set file descriptor
        try ssl.setFd(@intCast(tcp.getFd()));

        // Perform handshake
        try ssl.connect();

        return .{
            .ssl = ssl,
            .tcp = tcp,
            .allocator = allocator,
        };
    }

    /// Wrap an existing TCP stream with TLS (server side)
    pub fn acceptServer(
        allocator: Allocator,
        tcp: protocols.TcpStream,
        ctx: *SslContext,
    ) !Self {
        var ssl = try ctx.createSsl();
        errdefer ssl.deinit();

        try ssl.setFd(@intCast(tcp.getFd()));
        try ssl.accept();

        return .{
            .ssl = ssl,
            .tcp = tcp,
            .allocator = allocator,
        };
    }

    /// Read decrypted data
    pub fn read(self: *Self, buf: []u8) !usize {
        return self.ssl.read(buf);
    }

    /// Write data to be encrypted
    pub fn write(self: *Self, data: []const u8) !usize {
        return self.ssl.write(data);
    }

    /// Write all data
    pub fn writeAll(self: *Self, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            written += try self.write(data[written..]);
        }
    }

    /// Close the TLS connection
    pub fn close(self: *Self) void {
        self.ssl.shutdown() catch {};
        self.ssl.deinit();
        self.tcp.close();
    }

    /// Get TLS connection info
    pub fn getTlsInfo(self: *Self) tls.TlsInfo {
        const version = self.ssl.getVersion() orelse .tls_1_2;
        const cipher = self.ssl.getCipherName() orelse "UNKNOWN";

        return tls.TlsInfo{
            .version = version,
            .cipher_suite = cipher,
            .alpn_protocol = self.ssl.getAlpnProtocol(),
            .server_name = self.ssl.getServerName(),
            .client_cert_provided = self.ssl.getPeerCertificate() != null,
            .session_resumed = self.ssl.isSessionReused(),
        };
    }
};

// ============================================================================
// ALPN Wire Format Helpers
// ============================================================================

/// Build ALPN wire format from protocol list
/// Format: [len1][proto1][len2][proto2]...
pub fn buildAlpnWireFormat(allocator: Allocator, protocols_list: []const []const u8) ![]u8 {
    var total_len: usize = 0;
    for (protocols_list) |proto| {
        total_len += 1 + proto.len; // length byte + protocol
    }

    const buf = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    for (protocols_list) |proto| {
        buf[pos] = @intCast(proto.len);
        pos += 1;
        @memcpy(buf[pos..][0..proto.len], proto);
        pos += proto.len;
    }

    return buf;
}

// ============================================================================
// Tests (compile-time only when OpenSSL is available)
// ============================================================================

test "SslError type" {
    const err: SslError = SslError.HandshakeFailed;
    try testing.expect(err == SslError.HandshakeFailed);
}

test "SslMethod enum" {
    const method = SslMethod.tls_client;
    try testing.expect(method == .tls_client);
}

test "buildAlpnWireFormat" {
    const protos = [_][]const u8{ "h2", "http/1.1" };
    const wire = try buildAlpnWireFormat(testing.allocator, &protos);
    defer testing.allocator.free(wire);

    // Format: [2]h2[8]http/1.1
    try testing.expectEqual(wire.len, 12);
    try testing.expectEqual(wire[0], 2); // "h2" length
    try testing.expectEqualStrings("h2", wire[1..3]);
    try testing.expectEqual(wire[3], 8); // "http/1.1" length
    try testing.expectEqualStrings("http/1.1", wire[4..12]);
}

test "SslConnection session APIs pre-handshake" {
    var ctx = try SslContext.initClient(testing.allocator);
    defer ctx.deinit();

    var ssl = try ctx.createSsl();
    defer ssl.deinit();

    try testing.expect(!ssl.isSessionReused());
    try testing.expectError(SslError.SessionUnavailable, ssl.get1Session());
}

test "SslContext TLS enhancement hooks" {
    // Ticket callback trampoline + OCSP callback registration should be callable.
    var server_ctx = try SslContext.initServer(testing.allocator);
    defer server_ctx.deinit();

    const dummy_ticket_cb: SslContext.TicketKeyCb = struct {
        fn cb(
            ssl: ?*c.SSL,
            key_name: [*c]u8,
            iv: [*c]u8,
            evp_ctx: ?*c.EVP_CIPHER_CTX,
            hmac_ctx: ?*c.HMAC_CTX,
            enc: c_int,
        ) callconv(.C) c_int {
            _ = ssl;
            _ = key_name;
            _ = iv;
            _ = evp_ctx;
            _ = hmac_ctx;
            _ = enc;
            return 0;
        }
    }.cb;

    const dummy_ticket_cb_2: SslContext.TicketKeyCb = struct {
        fn cb(
            ssl: ?*c.SSL,
            key_name: [*c]u8,
            iv: [*c]u8,
            evp_ctx: ?*c.EVP_CIPHER_CTX,
            hmac_ctx: ?*c.HMAC_CTX,
            enc: c_int,
        ) callconv(.C) c_int {
            _ = ssl;
            _ = key_name;
            _ = iv;
            _ = evp_ctx;
            _ = hmac_ctx;
            _ = enc;
            return 1;
        }
    }.cb;

    // Calling setter repeatedly should not leak (we keep one CallbackCtx allocation).
    try server_ctx.setSessionTicketKeyCallback(dummy_ticket_cb, null);
    try server_ctx.setSessionTicketKeyCallback(dummy_ticket_cb_2, null);

    const dummy_ocsp_cb: SslContext.OcspStatusCb = struct {
        fn cb(ssl: ?*c.SSL, arg: ?*anyopaque) callconv(.C) c_int {
            _ = ssl;
            _ = arg;
            return 0;
        }
    }.cb;

    server_ctx.setOcspStatusCallback(dummy_ocsp_cb, null);

    // mTLS helpers should be callable.
    server_ctx.requireClientCertificate(true);
    server_ctx.setVerifyDepth(5);
}

test "SslConnection OCSP response helpers" {
    var server_ctx = try SslContext.initServer(testing.allocator);
    defer server_ctx.deinit();

    var ssl = try server_ctx.createSsl();
    defer ssl.deinit();

    const resp = "dummy-ocsp";
    // If OpenSSL build doesn't support the API, expect OcspUnavailable.
    ssl.setOcspResponse(resp) catch |err| switch (err) {
        SslError.OcspUnavailable => return,
        else => return err,
    };

    const got = ssl.getOcspResponse() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(resp, got);
}

test "TlsVersion in tls module" {
    try testing.expectEqual(tls.TlsVersion.tls_1_2.asStr(), "TLSv1.2");
    try testing.expectEqual(tls.TlsVersion.tls_1_3.asStr(), "TLSv1.3");
}
