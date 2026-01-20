//! pingora-zig: Peer Features
//!
//! HTTP peer configuration with full TLS options including ALPN negotiation,
//! custom CA certificates, client certificates, SNI override, and PROXY protocol support.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const net = std.net;
const tls = @import("tls.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Peer Address Types
// ============================================================================

/// Peer address - can be IP, hostname, or Unix socket
pub const PeerAddress = union(enum) {
    /// IP address with port
    ip: IpAddress,
    /// Hostname with port (requires DNS resolution)
    hostname: HostnameAddress,
    /// Unix domain socket
    unix: []const u8,

    pub const IpAddress = struct {
        addr: [16]u8, // IPv4 or IPv6
        port: u16,
        is_ipv6: bool,
    };

    pub const HostnameAddress = struct {
        host: []const u8,
        port: u16,
    };

    /// Parse from string (host:port or unix:/path)
    pub fn parse(allocator: Allocator, addr_str: []const u8) !PeerAddress {
        if (std.mem.startsWith(u8, addr_str, "unix:")) {
            return .{ .unix = addr_str[5..] };
        }

        // Find the last colon for port separation
        const last_colon = std.mem.lastIndexOf(u8, addr_str, ":") orelse return error.InvalidAddress;
        const host = addr_str[0..last_colon];
        const port_str = addr_str[last_colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

        // Try parsing as IP address
        if (net.Address.parseIp4(host, port)) |_| {
            var ip_addr: [16]u8 = undefined;
            @memset(&ip_addr, 0);
            @memcpy(ip_addr[0..host.len], host);
            return .{ .ip = .{ .addr = ip_addr, .port = port, .is_ipv6 = false } };
        } else |_| {}

        // Treat as hostname
        const host_copy = try allocator.dupe(u8, host);
        return .{ .hostname = .{ .host = host_copy, .port = port } };
    }

    /// Format as string
    pub fn format(self: PeerAddress, buf: []u8) ![]u8 {
        return switch (self) {
            .ip => |addr| {
                if (addr.is_ipv6) {
                    return std.fmt.bufPrint(buf, "[{s}]:{d}", .{ addr.addr, addr.port }) catch error.BufferTooSmall;
                }
                return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                    addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3], addr.port,
                }) catch error.BufferTooSmall;
            },
            .hostname => |addr| std.fmt.bufPrint(buf, "{s}:{d}", .{ addr.host, addr.port }) catch error.BufferTooSmall,
            .unix => |path| std.fmt.bufPrint(buf, "unix:{s}", .{path}) catch error.BufferTooSmall,
        };
    }
};

// ============================================================================
// ALPN Protocol Negotiation
// ============================================================================

/// ALPN (Application-Layer Protocol Negotiation) configuration
pub const AlpnConfig = struct {
    /// Protocols to advertise, in order of preference
    protocols: []const []const u8,
    /// Whether to require ALPN negotiation
    required: bool = false,
    /// Fallback protocol if negotiation fails (when not required)
    fallback: ?[]const u8 = null,

    /// Common ALPN configurations
    pub const http11_only = AlpnConfig{ .protocols = &[_][]const u8{"http/1.1"} };
    pub const http2_only = AlpnConfig{ .protocols = &[_][]const u8{"h2"} };
    pub const http2_with_fallback = AlpnConfig{
        .protocols = &[_][]const u8{ "h2", "http/1.1" },
        .fallback = "http/1.1",
    };
    pub const grpc = AlpnConfig{ .protocols = &[_][]const u8{"h2"}, .required = true };

    /// Check if a protocol was negotiated
    pub fn isNegotiated(self: *const AlpnConfig, negotiated: ?[]const u8) bool {
        if (negotiated) |proto| {
            for (self.protocols) |p| {
                if (std.mem.eql(u8, p, proto)) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Get the effective protocol after negotiation
    pub fn getEffectiveProtocol(self: *const AlpnConfig, negotiated: ?[]const u8) ?[]const u8 {
        if (negotiated) |proto| {
            for (self.protocols) |p| {
                if (std.mem.eql(u8, p, proto)) {
                    return proto;
                }
            }
        }
        return self.fallback;
    }
};

// ============================================================================
// TLS Peer Configuration
// ============================================================================

/// TLS configuration for a peer connection
pub const PeerTlsConfig = struct {
    /// Enable TLS
    enabled: bool = false,
    /// SNI hostname (defaults to peer hostname)
    sni: ?[]const u8 = null,
    /// Custom CA certificate path (for self-signed certs)
    ca_path: ?[]const u8 = null,
    /// Custom CA certificate data (PEM format)
    ca_data: ?[]const u8 = null,
    /// Client certificate path
    client_cert_path: ?[]const u8 = null,
    /// Client private key path
    client_key_path: ?[]const u8 = null,
    /// Client certificate data (PEM format)
    client_cert_data: ?[]const u8 = null,
    /// Client key data (PEM format)
    client_key_data: ?[]const u8 = null,
    /// Skip server certificate verification (DANGEROUS - use only for testing)
    skip_verify: bool = false,
    /// ALPN configuration
    alpn: ?AlpnConfig = null,
    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,
    /// Maximum TLS version
    max_version: TlsVersion = .tls_1_3,
    /// Cipher suites (null = use defaults)
    cipher_suites: ?[]const u8 = null,
    /// Enable session resumption
    session_resumption: bool = true,
    /// Session cache key (for sharing sessions across peers)
    session_cache_key: ?[]const u8 = null,

    pub const TlsVersion = enum {
        tls_1_0,
        tls_1_1,
        tls_1_2,
        tls_1_3,
    };

    /// Get SNI hostname (uses peer hostname if not explicitly set)
    pub fn getSni(self: *const PeerTlsConfig, peer_hostname: ?[]const u8) ?[]const u8 {
        return self.sni orelse peer_hostname;
    }

    /// Check if client certificate is configured
    pub fn hasClientCert(self: *const PeerTlsConfig) bool {
        return (self.client_cert_path != null) or (self.client_cert_data != null);
    }

    /// Check if custom CA is configured
    pub fn hasCustomCa(self: *const PeerTlsConfig) bool {
        return (self.ca_path != null) or (self.ca_data != null);
    }
};

// ============================================================================
// PROXY Protocol
// ============================================================================

/// PROXY protocol version
pub const ProxyProtocolVersion = enum {
    /// PROXY protocol v1 (text-based)
    v1,
    /// PROXY protocol v2 (binary)
    v2,
};

/// PROXY protocol configuration
pub const ProxyProtocolConfig = struct {
    /// Enable PROXY protocol
    enabled: bool = false,
    /// Protocol version to use
    version: ProxyProtocolVersion = .v2,
    /// Timeout for receiving PROXY header (nanoseconds)
    timeout_ns: u64 = 3 * std.time.ns_per_s,
};

/// PROXY protocol header data (parsed from incoming connection)
pub const ProxyProtocolHeader = struct {
    /// Protocol version
    version: ProxyProtocolVersion,
    /// Source address
    src_addr: ?net.Address,
    /// Destination address
    dst_addr: ?net.Address,
    /// Additional TLVs (Type-Length-Value) for v2
    tlvs: ?[]const Tlv,

    pub const Tlv = struct {
        type_: u8,
        value: []const u8,
    };

    /// Parse PROXY protocol v1 header
    pub fn parseV1(data: []const u8) !ProxyProtocolHeader {
        // Format: PROXY TCP4/TCP6/UNKNOWN SRC_ADDR DST_ADDR SRC_PORT DST_PORT\r\n
        if (!std.mem.startsWith(u8, data, "PROXY ")) {
            return error.InvalidProxyHeader;
        }

        const line_end = std.mem.indexOf(u8, data, "\r\n") orelse return error.IncompleteHeader;
        const line = data[6..line_end];

        var parts = std.mem.splitScalar(u8, line, ' ');

        const proto = parts.next() orelse return error.InvalidProxyHeader;
        if (std.mem.eql(u8, proto, "UNKNOWN")) {
            return .{
                .version = .v1,
                .src_addr = null,
                .dst_addr = null,
                .tlvs = null,
            };
        }

        const src_ip = parts.next() orelse return error.InvalidProxyHeader;
        const dst_ip = parts.next() orelse return error.InvalidProxyHeader;
        const src_port_str = parts.next() orelse return error.InvalidProxyHeader;
        const dst_port_str = parts.next() orelse return error.InvalidProxyHeader;

        const src_port = std.fmt.parseInt(u16, src_port_str, 10) catch return error.InvalidProxyHeader;
        const dst_port = std.fmt.parseInt(u16, dst_port_str, 10) catch return error.InvalidProxyHeader;

        const src_addr = net.Address.parseIp(src_ip, src_port) catch return error.InvalidProxyHeader;
        const dst_addr = net.Address.parseIp(dst_ip, dst_port) catch return error.InvalidProxyHeader;

        return .{
            .version = .v1,
            .src_addr = src_addr,
            .dst_addr = dst_addr,
            .tlvs = null,
        };
    }

    /// Build PROXY protocol v1 header
    pub fn buildV1(src: net.Address, dst: net.Address, buf: []u8) ![]u8 {
        const family = if (src.any.family == std.posix.AF.INET6) "TCP6" else "TCP4";

        var src_buf: [64]u8 = undefined;
        var dst_buf: [64]u8 = undefined;

        const src_str = try formatAddress(src, &src_buf);
        const dst_str = try formatAddress(dst, &dst_buf);

        return std.fmt.bufPrint(buf, "PROXY {s} {s} {s} {d} {d}\r\n", .{
            family,
            src_str,
            dst_str,
            src.getPort(),
            dst.getPort(),
        }) catch error.BufferTooSmall;
    }

    fn formatAddress(addr: net.Address, buf: []u8) ![]u8 {
        if (addr.any.family == std.posix.AF.INET) {
            const ip = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch error.BufferTooSmall;
        } else {
            // IPv6 - simplified
            return std.fmt.bufPrint(buf, "::1", .{}) catch error.BufferTooSmall;
        }
    }

    /// Get header length
    pub fn headerLength(self: *const ProxyProtocolHeader, data: []const u8) usize {
        if (self.version == .v1) {
            if (std.mem.indexOf(u8, data, "\r\n")) |idx| {
                return idx + 2;
            }
        }
        // V2 has fixed header length + address length
        return 16; // Simplified
    }
};

// ============================================================================
// HTTP Peer
// ============================================================================

/// Full HTTP peer configuration
pub const HttpPeer = struct {
    /// Peer address
    address: PeerAddress,
    /// Peer hostname (for Host header and SNI)
    hostname: ?[]const u8,
    /// TLS configuration
    tls_config: PeerTlsConfig,
    /// PROXY protocol configuration
    proxy_protocol: ProxyProtocolConfig,
    /// Connection timeout (nanoseconds)
    connect_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// Read timeout (nanoseconds)
    read_timeout_ns: u64 = 60 * std.time.ns_per_s,
    /// Write timeout (nanoseconds)
    write_timeout_ns: u64 = 60 * std.time.ns_per_s,
    /// Idle timeout (nanoseconds)
    idle_timeout_ns: u64 = 90 * std.time.ns_per_s,
    /// Maximum number of connections to this peer
    max_connections: u32 = 128,
    /// Weight for load balancing
    weight: u32 = 1,
    /// Custom group/pool identifier
    group: ?[]const u8 = null,
    /// Metadata for user-defined purposes
    metadata: ?*anyopaque = null,
    /// Health check configuration
    health_check: ?HealthCheckConfig = null,

    pub const HealthCheckConfig = struct {
        /// Health check interval (nanoseconds)
        interval_ns: u64 = 5 * std.time.ns_per_s,
        /// Health check path (for HTTP health checks)
        path: []const u8 = "/health",
        /// Expected status codes
        expected_status: []const u16 = &[_]u16{ 200, 204 },
        /// Consecutive failures before marking unhealthy
        unhealthy_threshold: u32 = 3,
        /// Consecutive successes before marking healthy
        healthy_threshold: u32 = 2,
    };

    const Self = @This();

    /// Create a simple HTTP peer
    pub fn http(host: []const u8, port: u16) Self {
        return .{
            .address = .{ .hostname = .{ .host = host, .port = port } },
            .hostname = host,
            .tls_config = .{},
            .proxy_protocol = .{},
        };
    }

    /// Create an HTTPS peer
    pub fn https(host: []const u8, port: u16) Self {
        return .{
            .address = .{ .hostname = .{ .host = host, .port = port } },
            .hostname = host,
            .tls_config = .{
                .enabled = true,
                .alpn = AlpnConfig.http2_with_fallback,
            },
            .proxy_protocol = .{},
        };
    }

    /// Create a peer with custom CA
    pub fn withCustomCa(self: Self, ca_path: []const u8) Self {
        var peer = self;
        peer.tls_config.ca_path = ca_path;
        return peer;
    }

    /// Create a peer with client certificate
    pub fn withClientCert(self: Self, cert_path: []const u8, key_path: []const u8) Self {
        var peer = self;
        peer.tls_config.client_cert_path = cert_path;
        peer.tls_config.client_key_path = key_path;
        return peer;
    }

    /// Create a peer with SNI override
    pub fn withSni(self: Self, sni: []const u8) Self {
        var peer = self;
        peer.tls_config.sni = sni;
        return peer;
    }

    /// Create a peer with PROXY protocol
    pub fn withProxyProtocol(self: Self, version: ProxyProtocolVersion) Self {
        var peer = self;
        peer.proxy_protocol.enabled = true;
        peer.proxy_protocol.version = version;
        return peer;
    }

    /// Create a peer with custom weight
    pub fn withWeight(self: Self, weight: u32) Self {
        var peer = self;
        peer.weight = weight;
        return peer;
    }

    /// Create a peer with connection limits
    pub fn withMaxConnections(self: Self, max: u32) Self {
        var peer = self;
        peer.max_connections = max;
        return peer;
    }

    /// Create a peer with timeouts
    pub fn withTimeouts(self: Self, connect_ms: u64, read_ms: u64, write_ms: u64) Self {
        var peer = self;
        peer.connect_timeout_ns = connect_ms * std.time.ns_per_ms;
        peer.read_timeout_ns = read_ms * std.time.ns_per_ms;
        peer.write_timeout_ns = write_ms * std.time.ns_per_ms;
        return peer;
    }

    /// Get the effective SNI hostname
    pub fn getSni(self: *const Self) ?[]const u8 {
        return self.tls_config.getSni(self.hostname);
    }

    /// Check if this is a TLS peer
    pub fn isTls(self: *const Self) bool {
        return self.tls_config.enabled;
    }

    /// Check if PROXY protocol is enabled
    pub fn usesProxyProtocol(self: *const Self) bool {
        return self.proxy_protocol.enabled;
    }

    /// Get the hostname for Host header
    pub fn getHostHeader(self: *const Self) ?[]const u8 {
        return self.hostname;
    }
};

// ============================================================================
// Peer Pool Configuration
// ============================================================================

/// Configuration for a pool of peers
pub const PeerPoolConfig = struct {
    /// Pool name
    name: []const u8,
    /// Peers in the pool
    peers: []const HttpPeer,
    /// Load balancing algorithm
    load_balancing: LoadBalancing = .round_robin,
    /// Connection pool settings
    connection_pool: ConnectionPoolSettings = .{},
    /// Retry policy
    retry: RetryPolicy = .{},

    pub const LoadBalancing = enum {
        round_robin,
        weighted_round_robin,
        least_connections,
        random,
        consistent_hash,
    };

    pub const ConnectionPoolSettings = struct {
        /// Maximum connections per peer
        max_per_peer: u32 = 32,
        /// Maximum total connections in pool
        max_total: u32 = 256,
        /// Connection idle timeout (nanoseconds)
        idle_timeout_ns: u64 = 90 * std.time.ns_per_s,
        /// Maximum lifetime per connection (nanoseconds, 0 = unlimited)
        max_lifetime_ns: u64 = 0,
    };

    pub const RetryPolicy = struct {
        /// Maximum retry attempts
        max_retries: u32 = 2,
        /// Retry on connection errors
        retry_on_connect_error: bool = true,
        /// Retry on 502/503/504
        retry_on_bad_gateway: bool = true,
        /// Retry on timeout
        retry_on_timeout: bool = true,
        /// Backoff between retries (nanoseconds)
        backoff_ns: u64 = 100 * std.time.ns_per_ms,
    };
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "PeerAddress hostname" {
    const addr = PeerAddress{ .hostname = .{ .host = "example.com", .port = 443 } };
    var buf: [64]u8 = undefined;
    const str = try addr.format(&buf);
    try testing.expectEqualStrings("example.com:443", str);
}

test "PeerAddress unix" {
    const addr = PeerAddress{ .unix = "/var/run/app.sock" };
    var buf: [64]u8 = undefined;
    const str = try addr.format(&buf);
    try testing.expectEqualStrings("unix:/var/run/app.sock", str);
}

test "AlpnConfig isNegotiated" {
    const config = AlpnConfig.http2_with_fallback;

    try testing.expect(config.isNegotiated("h2"));
    try testing.expect(config.isNegotiated("http/1.1"));
    try testing.expect(!config.isNegotiated("h3"));
    try testing.expect(!config.isNegotiated(null));
}

test "AlpnConfig getEffectiveProtocol" {
    const config = AlpnConfig.http2_with_fallback;

    try testing.expectEqualStrings("h2", config.getEffectiveProtocol("h2").?);
    try testing.expectEqualStrings("http/1.1", config.getEffectiveProtocol("http/1.1").?);
    // Fallback for unknown
    try testing.expectEqualStrings("http/1.1", config.getEffectiveProtocol("unknown").?);
    // Fallback for null
    try testing.expectEqualStrings("http/1.1", config.getEffectiveProtocol(null).?);
}

test "PeerTlsConfig getSni" {
    const config1 = PeerTlsConfig{ .enabled = true };
    try testing.expectEqualStrings("example.com", config1.getSni("example.com").?);

    const config2 = PeerTlsConfig{ .enabled = true, .sni = "override.com" };
    try testing.expectEqualStrings("override.com", config2.getSni("example.com").?);
}

test "PeerTlsConfig hasClientCert" {
    const config1 = PeerTlsConfig{};
    try testing.expect(!config1.hasClientCert());

    const config2 = PeerTlsConfig{ .client_cert_path = "/path/to/cert.pem" };
    try testing.expect(config2.hasClientCert());

    const config3 = PeerTlsConfig{ .client_cert_data = "PEM DATA" };
    try testing.expect(config3.hasClientCert());
}

test "PeerTlsConfig hasCustomCa" {
    const config1 = PeerTlsConfig{};
    try testing.expect(!config1.hasCustomCa());

    const config2 = PeerTlsConfig{ .ca_path = "/path/to/ca.pem" };
    try testing.expect(config2.hasCustomCa());
}

test "HttpPeer http factory" {
    const peer = HttpPeer.http("api.example.com", 80);
    try testing.expectEqualStrings("api.example.com", peer.hostname.?);
    try testing.expect(!peer.isTls());
}

test "HttpPeer https factory" {
    const peer = HttpPeer.https("api.example.com", 443);
    try testing.expectEqualStrings("api.example.com", peer.hostname.?);
    try testing.expect(peer.isTls());
    try testing.expect(peer.tls_config.alpn != null);
}

test "HttpPeer builder pattern" {
    const peer = HttpPeer.https("api.example.com", 443)
        .withSni("custom-sni.example.com")
        .withWeight(10)
        .withMaxConnections(64)
        .withProxyProtocol(.v2);

    try testing.expectEqualStrings("custom-sni.example.com", peer.getSni().?);
    try testing.expectEqual(@as(u32, 10), peer.weight);
    try testing.expectEqual(@as(u32, 64), peer.max_connections);
    try testing.expect(peer.usesProxyProtocol());
}

test "HttpPeer withClientCert" {
    const peer = HttpPeer.https("api.example.com", 443)
        .withClientCert("/cert.pem", "/key.pem");

    try testing.expect(peer.tls_config.hasClientCert());
    try testing.expectEqualStrings("/cert.pem", peer.tls_config.client_cert_path.?);
    try testing.expectEqualStrings("/key.pem", peer.tls_config.client_key_path.?);
}

test "HttpPeer withCustomCa" {
    const peer = HttpPeer.https("api.example.com", 443)
        .withCustomCa("/ca.pem");

    try testing.expect(peer.tls_config.hasCustomCa());
    try testing.expectEqualStrings("/ca.pem", peer.tls_config.ca_path.?);
}

test "ProxyProtocolHeader parseV1" {
    const data = "PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n";
    const header = try ProxyProtocolHeader.parseV1(data);

    try testing.expectEqual(ProxyProtocolVersion.v1, header.version);
    try testing.expect(header.src_addr != null);
    try testing.expect(header.dst_addr != null);
}

test "ProxyProtocolHeader parseV1 unknown" {
    const data = "PROXY UNKNOWN\r\n";
    const header = try ProxyProtocolHeader.parseV1(data);

    try testing.expectEqual(ProxyProtocolVersion.v1, header.version);
    try testing.expect(header.src_addr == null);
    try testing.expect(header.dst_addr == null);
}

test "ProxyProtocolHeader invalid" {
    const data = "INVALID HEADER\r\n";
    try testing.expectError(error.InvalidProxyHeader, ProxyProtocolHeader.parseV1(data));
}

test "PeerPoolConfig defaults" {
    const config = PeerPoolConfig{
        .name = "backend",
        .peers = &[_]HttpPeer{},
    };

    try testing.expectEqual(PeerPoolConfig.LoadBalancing.round_robin, config.load_balancing);
    try testing.expectEqual(@as(u32, 2), config.retry.max_retries);
}
