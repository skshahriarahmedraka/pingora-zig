//! TLS Types and Abstractions
//!
//! This module provides TLS-related types and abstractions for secure connections.
//! It defines interfaces that can be implemented with various TLS backends
//! (OpenSSL, BoringSSL, rustls-equivalent, etc.)
//!
//! Note: This is an abstraction layer. Actual TLS implementation would require
//! linking to a TLS library (e.g., OpenSSL via Zig's C interop).
//!
//! Ported from concepts in:
//! - https://github.com/cloudflare/pingora/tree/main/pingora-openssl
//! - https://github.com/cloudflare/pingora/tree/main/pingora-rustls

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// TLS Version
// ============================================================================

/// TLS protocol version
pub const TlsVersion = enum(u16) {
    tls_1_0 = 0x0301,
    tls_1_1 = 0x0302,
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,

    pub fn asStr(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_0 => "TLSv1.0",
            .tls_1_1 => "TLSv1.1",
            .tls_1_2 => "TLSv1.2",
            .tls_1_3 => "TLSv1.3",
        };
    }

    pub fn fromU16(value: u16) ?TlsVersion {
        return switch (value) {
            0x0301 => .tls_1_0,
            0x0302 => .tls_1_1,
            0x0303 => .tls_1_2,
            0x0304 => .tls_1_3,
            else => null,
        };
    }
};

// ============================================================================
// Certificate Types
// ============================================================================

/// X.509 certificate in DER format
pub const Certificate = struct {
    /// DER-encoded certificate data
    der: []const u8,
    /// Whether we own the memory
    owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    /// Create from DER data (borrowed)
    pub fn fromDer(der: []const u8) Self {
        return .{
            .der = der,
            .owned = false,
            .allocator = null,
        };
    }

    /// Create from DER data (owned copy)
    pub fn fromDerOwned(allocator: Allocator, der: []const u8) !Self {
        const copy = try allocator.dupe(u8, der);
        return .{
            .der = copy,
            .owned = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.der);
            }
        }
    }

    /// Get the DER-encoded data
    pub fn asDer(self: *const Self) []const u8 {
        return self.der;
    }
};

/// Private key types
pub const PrivateKeyType = enum {
    rsa,
    ecdsa,
    ed25519,
    unknown,
};

/// Private key in DER format
pub const PrivateKey = struct {
    /// DER-encoded private key data
    der: []const u8,
    /// Type of the private key
    key_type: PrivateKeyType,
    /// Whether we own the memory
    owned: bool,
    allocator: ?Allocator,

    const Self = @This();

    /// Create from DER data (borrowed)
    pub fn fromDer(der: []const u8, key_type: PrivateKeyType) Self {
        return .{
            .der = der,
            .key_type = key_type,
            .owned = false,
            .allocator = null,
        };
    }

    /// Create from DER data (owned copy)
    pub fn fromDerOwned(allocator: Allocator, der: []const u8, key_type: PrivateKeyType) !Self {
        const copy = try allocator.dupe(u8, der);
        return .{
            .der = copy,
            .key_type = key_type,
            .owned = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                alloc.free(self.der);
            }
        }
    }
};

// ============================================================================
// TLS Configuration
// ============================================================================

/// Server Name Indication (SNI) callback result
pub const SniResult = enum {
    /// Use the default certificate
    use_default,
    /// Certificate was set for this SNI
    certificate_set,
    /// No certificate available for this SNI
    not_found,
    /// Error occurred
    err,
};

/// TLS configuration for server-side connections
pub const TlsServerConfig = struct {
    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,
    /// Maximum TLS version
    max_version: TlsVersion = .tls_1_3,
    /// Certificate chain
    certificates: []const Certificate = &[_]Certificate{},
    /// Private key
    private_key: ?PrivateKey = null,
    /// ALPN protocols (e.g., "h2", "http/1.1")
    alpn_protocols: []const []const u8 = &[_][]const u8{},
    /// Whether to require client certificates
    require_client_cert: bool = false,
    /// Session ticket key (for TLS session resumption)
    session_ticket_key: ?[48]u8 = null,

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn setMinVersion(self: *Self, version: TlsVersion) *Self {
        self.min_version = version;
        return self;
    }

    pub fn setMaxVersion(self: *Self, version: TlsVersion) *Self {
        self.max_version = version;
        return self;
    }

    pub fn setAlpnProtocols(self: *Self, protocols: []const []const u8) *Self {
        self.alpn_protocols = protocols;
        return self;
    }

    pub fn setRequireClientCert(self: *Self, require: bool) *Self {
        self.require_client_cert = require;
        return self;
    }
};

/// TLS configuration for client-side connections
pub const TlsClientConfig = struct {
    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,
    /// Maximum TLS version
    max_version: TlsVersion = .tls_1_3,
    /// Server name for SNI
    server_name: ?[]const u8 = null,
    /// ALPN protocols (e.g., "h2", "http/1.1")
    alpn_protocols: []const []const u8 = &[_][]const u8{},
    /// Whether to verify server certificate
    verify_server_cert: bool = true,
    /// CA certificates for verification
    ca_certificates: []const Certificate = &[_]Certificate{},

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn setServerName(self: *Self, name: []const u8) *Self {
        self.server_name = name;
        return self;
    }

    pub fn setAlpnProtocols(self: *Self, protocols: []const []const u8) *Self {
        self.alpn_protocols = protocols;
        return self;
    }

    pub fn setVerifyServerCert(self: *Self, verify: bool) *Self {
        self.verify_server_cert = verify;
        return self;
    }
};

// ============================================================================
// TLS Connection State
// ============================================================================

/// State of a TLS connection
pub const TlsState = enum {
    /// Not yet started
    initial,
    /// Handshake in progress
    handshaking,
    /// Handshake complete, connection established
    established,
    /// Connection is closing
    closing,
    /// Connection closed
    closed,
    /// Error state
    err,
};

/// Information about an established TLS connection
pub const TlsInfo = struct {
    /// Negotiated TLS version
    version: TlsVersion,
    /// Negotiated cipher suite name
    cipher_suite: []const u8,
    /// Negotiated ALPN protocol (if any)
    alpn_protocol: ?[]const u8,
    /// Server name from SNI (if any)
    server_name: ?[]const u8,
    /// Whether client certificate was provided
    client_cert_provided: bool,
    /// Whether session was resumed
    session_resumed: bool,

    const Self = @This();

    pub fn init(version: TlsVersion, cipher_suite: []const u8) Self {
        return .{
            .version = version,
            .cipher_suite = cipher_suite,
            .alpn_protocol = null,
            .server_name = null,
            .client_cert_provided = false,
            .session_resumed = false,
        };
    }
};

// ============================================================================
// TLS Errors
// ============================================================================

/// TLS-related errors
pub const TlsError = error{
    /// Handshake failed
    HandshakeFailed,
    /// Certificate verification failed
    CertificateVerificationFailed,
    /// Certificate expired
    CertificateExpired,
    /// Certificate not yet valid
    CertificateNotYetValid,
    /// Unknown CA
    UnknownCa,
    /// Invalid certificate
    InvalidCertificate,
    /// Invalid private key
    InvalidPrivateKey,
    /// Protocol version not supported
    UnsupportedVersion,
    /// No common cipher suite
    NoCipherSuiteMatch,
    /// ALPN negotiation failed
    AlpnNegotiationFailed,
    /// Connection closed unexpectedly
    ConnectionClosed,
    /// Would block (for non-blocking I/O)
    WouldBlock,
    /// Generic TLS error
    TlsError,
    /// I/O error
    IoError,
    /// Out of memory
    OutOfMemory,
};

// ============================================================================
// PEM Parsing Helpers
// ============================================================================

/// PEM block type
pub const PemType = enum {
    certificate,
    private_key,
    rsa_private_key,
    ec_private_key,
    public_key,
    unknown,
};

/// A parsed PEM block
pub const PemBlock = struct {
    pem_type: PemType,
    der_data: []const u8,
    label: []const u8,
};

/// Parse PEM data and extract DER blocks
/// Note: This is a simplified parser. Production code should use a proper PEM parser.
pub fn parsePem(allocator: Allocator, pem_data: []const u8) ![]PemBlock {
    var blocks: std.ArrayListUnmanaged(PemBlock) = .{};
    errdefer blocks.deinit(allocator);

    const BEGIN_MARKER = "-----BEGIN ";
    const END_MARKER = "-----END ";

    var pos: usize = 0;
    while (pos < pem_data.len) {
        // Find begin marker
        const begin_start = std.mem.indexOf(u8, pem_data[pos..], BEGIN_MARKER) orelse break;
        const abs_begin = pos + begin_start;

        // Find the label end
        const label_start = abs_begin + BEGIN_MARKER.len;
        const label_end = std.mem.indexOf(u8, pem_data[label_start..], "-----") orelse break;
        const label = pem_data[label_start .. label_start + label_end];

        // Find the data start (after the header line)
        const header_end = std.mem.indexOf(u8, pem_data[abs_begin..], "\n") orelse break;
        const data_start = abs_begin + header_end + 1;

        // Find end marker
        const end_marker_full = END_MARKER;
        const end_start = std.mem.indexOf(u8, pem_data[data_start..], end_marker_full) orelse break;
        const data_end = data_start + end_start;

        // Determine PEM type
        const pem_type: PemType = if (std.mem.eql(u8, label, "CERTIFICATE"))
            .certificate
        else if (std.mem.eql(u8, label, "PRIVATE KEY"))
            .private_key
        else if (std.mem.eql(u8, label, "RSA PRIVATE KEY"))
            .rsa_private_key
        else if (std.mem.eql(u8, label, "EC PRIVATE KEY"))
            .ec_private_key
        else if (std.mem.eql(u8, label, "PUBLIC KEY"))
            .public_key
        else
            .unknown;

        // The data between markers is base64-encoded DER
        // Note: actual implementation would decode base64 here
        const base64_data = std.mem.trim(u8, pem_data[data_start..data_end], " \t\r\n");

        try blocks.append(allocator, .{
            .pem_type = pem_type,
            .der_data = base64_data, // In real impl, this would be decoded
            .label = label,
        });

        // Move past this block
        pos = data_end + END_MARKER.len;
    }

    return blocks.toOwnedSlice(allocator);
}

/// Free PEM blocks allocated by parsePem
pub fn freePemBlocks(allocator: Allocator, blocks: []PemBlock) void {
    allocator.free(blocks);
}

// ============================================================================
// ALPN Protocol Constants
// ============================================================================

/// Common ALPN protocol identifiers
pub const ALPN = struct {
    pub const HTTP_1_1 = "http/1.1";
    pub const HTTP_2 = "h2";
    pub const HTTP_3 = "h3";
};

// ============================================================================
// Tests
// ============================================================================

test "TlsVersion conversion" {
    try testing.expectEqualStrings("TLSv1.2", TlsVersion.tls_1_2.asStr());
    try testing.expectEqualStrings("TLSv1.3", TlsVersion.tls_1_3.asStr());

    try testing.expectEqual(TlsVersion.fromU16(0x0303), .tls_1_2);
    try testing.expectEqual(TlsVersion.fromU16(0x0304), .tls_1_3);
    try testing.expect(TlsVersion.fromU16(0x0000) == null);
}

test "Certificate creation" {
    const der_data = [_]u8{ 0x30, 0x82, 0x01, 0x22 }; // Fake DER data

    var cert = Certificate.fromDer(&der_data);
    try testing.expectEqual(cert.asDer().len, 4);
    try testing.expect(!cert.owned);

    var owned_cert = try Certificate.fromDerOwned(testing.allocator, &der_data);
    defer owned_cert.deinit();
    try testing.expectEqual(owned_cert.asDer().len, 4);
    try testing.expect(owned_cert.owned);
}

test "PrivateKey creation" {
    const key_data = [_]u8{ 0x30, 0x82, 0x01 };

    const key = PrivateKey.fromDer(&key_data, .rsa);
    try testing.expectEqual(key.key_type, .rsa);
    try testing.expect(!key.owned);

    var owned_key = try PrivateKey.fromDerOwned(testing.allocator, &key_data, .ecdsa);
    defer owned_key.deinit();
    try testing.expectEqual(owned_key.key_type, .ecdsa);
    try testing.expect(owned_key.owned);
}

test "TlsServerConfig builder" {
    var config = TlsServerConfig.init();
    _ = config.setMinVersion(.tls_1_2)
        .setMaxVersion(.tls_1_3)
        .setRequireClientCert(true);

    try testing.expectEqual(config.min_version, .tls_1_2);
    try testing.expectEqual(config.max_version, .tls_1_3);
    try testing.expect(config.require_client_cert);
}

test "TlsClientConfig builder" {
    var config = TlsClientConfig.init();
    _ = config.setServerName("example.com")
        .setVerifyServerCert(true);

    try testing.expectEqualStrings("example.com", config.server_name.?);
    try testing.expect(config.verify_server_cert);
}

test "TlsInfo initialization" {
    const info = TlsInfo.init(.tls_1_3, "TLS_AES_256_GCM_SHA384");

    try testing.expectEqual(info.version, .tls_1_3);
    try testing.expectEqualStrings("TLS_AES_256_GCM_SHA384", info.cipher_suite);
    try testing.expect(info.alpn_protocol == null);
    try testing.expect(!info.session_resumed);
}

test "TlsState enum" {
    const state: TlsState = .handshaking;
    try testing.expect(state == .handshaking);
}

test "PemType enum" {
    try testing.expect(PemType.certificate != PemType.private_key);
}

test "ALPN constants" {
    try testing.expectEqualStrings("h2", ALPN.HTTP_2);
    try testing.expectEqualStrings("http/1.1", ALPN.HTTP_1_1);
}

test "parsePem simple" {
    const pem =
        \\-----BEGIN CERTIFICATE-----
        \\dGVzdCBkYXRh
        \\-----END CERTIFICATE-----
    ;

    const blocks = try parsePem(testing.allocator, pem);
    defer freePemBlocks(testing.allocator, blocks);

    try testing.expectEqual(blocks.len, 1);
    try testing.expectEqual(blocks[0].pem_type, .certificate);
    try testing.expectEqualStrings("CERTIFICATE", blocks[0].label);
}

test "parsePem multiple blocks" {
    const pem =
        \\-----BEGIN CERTIFICATE-----
        \\Y2VydDE=
        \\-----END CERTIFICATE-----
        \\-----BEGIN PRIVATE KEY-----
        \\a2V5MQ==
        \\-----END PRIVATE KEY-----
    ;

    const blocks = try parsePem(testing.allocator, pem);
    defer freePemBlocks(testing.allocator, blocks);

    try testing.expectEqual(blocks.len, 2);
    try testing.expectEqual(blocks[0].pem_type, .certificate);
    try testing.expectEqual(blocks[1].pem_type, .private_key);
}

test "parsePem empty" {
    const pem = "";

    const blocks = try parsePem(testing.allocator, pem);
    defer freePemBlocks(testing.allocator, blocks);

    try testing.expectEqual(blocks.len, 0);
}
