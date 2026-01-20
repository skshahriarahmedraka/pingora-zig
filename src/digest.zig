//! pingora-zig: Connection Digest Module
//!
//! Extra information about connections including timing, socket info, TLS, and proxy details.
//! This is a pure Zig implementation inspired by Pingora's protocols/digest.rs.
//!
//! Features:
//! - Connection timing information (established timestamp)
//! - Socket digest (peer/local addresses, TCP info)
//! - TLS digest (SSL session information)
//! - Proxy digest (CONNECT proxy information)
//! - Protocol digest trait for uniform access

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

/// Timing information for a connection
pub const TimingDigest = struct {
    /// When this connection was established (nanoseconds since epoch)
    established_ts: i128,
    /// Time spent waiting to read (nanoseconds)
    read_pending_ns: u64 = 0,
    /// Time spent waiting to write (nanoseconds)
    write_pending_ns: u64 = 0,

    const Self = @This();

    /// Create a new TimingDigest with current timestamp
    pub fn init() Self {
        return .{
            .established_ts = std.time.nanoTimestamp(),
        };
    }

    /// Create a TimingDigest with a specific timestamp
    pub fn initWithTimestamp(ts: i128) Self {
        return .{
            .established_ts = ts,
        };
    }

    /// Get the age of this connection in nanoseconds
    pub fn age(self: *const Self) u64 {
        const now = std.time.nanoTimestamp();
        const diff = now - self.established_ts;
        return if (diff > 0) @intCast(diff) else 0;
    }

    /// Get the age in milliseconds
    pub fn ageMs(self: *const Self) u64 {
        return self.age() / std.time.ns_per_ms;
    }

    /// Get the age in seconds
    pub fn ageSec(self: *const Self) u64 {
        return self.age() / std.time.ns_per_s;
    }
};

/// Socket address type
pub const SocketAddr = union(enum) {
    /// IPv4 address
    ipv4: std.net.Address,
    /// IPv6 address  
    ipv6: std.net.Address,
    /// Unix domain socket path
    unix: []const u8,

    const Self = @This();

    /// Create from a std.net.Address
    pub fn fromAddress(addr: std.net.Address) Self {
        return switch (addr.any.family) {
            posix.AF.INET => .{ .ipv4 = addr },
            posix.AF.INET6 => .{ .ipv6 = addr },
            posix.AF.UNIX => .{ .unix = &addr.un.path },
            else => .{ .ipv4 = addr }, // Default to ipv4
        };
    }

    /// Check if this is an inet (IPv4/IPv6) address
    pub fn isInet(self: *const Self) bool {
        return switch (self.*) {
            .ipv4, .ipv6 => true,
            .unix => false,
        };
    }

    /// Get as inet address if applicable
    pub fn asInet(self: *const Self) ?std.net.Address {
        return switch (self.*) {
            .ipv4 => |addr| addr,
            .ipv6 => |addr| addr,
            .unix => null,
        };
    }

    /// Format the address as a string
    pub fn format(self: *const Self, buf: []u8) ![]const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        switch (self.*) {
            .ipv4 => |addr| {
                const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                try writer.print("{}.{}.{}.{}:{}", .{
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    std.mem.bigToNative(u16, addr.in.sa.port),
                });
            },
            .ipv6 => |addr| {
                // Format IPv6 address as hex
                for (addr.in6.sa.addr) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                try writer.print(":{}", .{std.mem.bigToNative(u16, addr.in6.sa.port)});
            },
            .unix => |path| {
                try writer.print("unix:{s}", .{path});
            },
        }
        return stream.getWritten();
    }
};

/// TCP connection information (similar to tcp_info struct)
pub const TcpInfo = struct {
    /// Retransmits count
    retransmits: u32 = 0,
    /// Round-trip time in microseconds
    rtt_us: u32 = 0,
    /// RTT variance in microseconds
    rtt_var_us: u32 = 0,
    /// Send congestion window
    snd_cwnd: u32 = 0,
    /// Receive window
    rcv_wnd: u32 = 0,
    /// Bytes in flight
    bytes_in_flight: u32 = 0,
    /// Total bytes sent
    bytes_sent: u64 = 0,
    /// Total bytes received
    bytes_received: u64 = 0,
    /// Packets sent
    segs_out: u32 = 0,
    /// Packets received
    segs_in: u32 = 0,

    const Self = @This();

    /// Create TcpInfo from a socket file descriptor
    pub fn fromFd(fd: posix.fd_t) ?Self {
        // Try to get TCP_INFO via getsockopt
        const info: Self = .{};

        // On Linux, we could use TCP_INFO sockopt
        // For now, return a basic struct
        // In production, use: posix.getsockopt(fd, posix.IPPROTO.TCP, posix.TCP.INFO, ...)
        _ = fd;
        return info;
    }
};

/// Socket-level digest information
pub const SocketDigest = struct {
    /// Raw file descriptor (Unix) or socket handle (Windows)
    raw_fd: posix.fd_t,
    /// Cached peer address
    peer_addr: ?SocketAddr = null,
    /// Cached local address
    local_addr: ?SocketAddr = null,
    /// Original destination (for transparent proxy)
    original_dst: ?SocketAddr = null,
    /// Receive buffer size
    recv_buf_size: ?usize = null,
    /// Send buffer size
    send_buf_size: ?usize = null,

    const Self = @This();

    /// Create a SocketDigest from a raw file descriptor
    pub fn fromRawFd(fd: posix.fd_t) Self {
        return .{
            .raw_fd = fd,
        };
    }

    /// Get the peer (remote) address
    pub fn peerAddr(self: *Self) ?SocketAddr {
        if (self.peer_addr) |addr| {
            return addr;
        }

        // Try to get peer address via getpeername
        const addr = posix.getpeername(self.raw_fd) catch return null;
        self.peer_addr = SocketAddr.fromAddress(addr);
        return self.peer_addr;
    }

    /// Get the local address
    pub fn localAddr(self: *Self) ?SocketAddr {
        if (self.local_addr) |addr| {
            return addr;
        }

        // Try to get local address via getsockname
        const addr = posix.getsockname(self.raw_fd) catch return null;
        self.local_addr = SocketAddr.fromAddress(addr);
        return self.local_addr;
    }

    /// Check if this is an inet socket
    pub fn isInet(self: *Self) bool {
        if (self.localAddr()) |addr| {
            return addr.isInet();
        }
        return false;
    }

    /// Get TCP info for this socket
    pub fn tcpInfo(self: *Self) ?TcpInfo {
        if (!self.isInet()) {
            return null;
        }
        return TcpInfo.fromFd(self.raw_fd);
    }

    /// Get receive buffer size
    pub fn getRecvBuf(self: *Self) ?usize {
        if (self.recv_buf_size) |size| {
            return size;
        }

        if (!self.isInet()) {
            return null;
        }

        // Get SO_RCVBUF
        const size = posix.getsockopt(
            self.raw_fd,
            posix.SOL.SOCKET,
            posix.SO.RCVBUF,
        ) catch return null;

        const buf_size: usize = @intCast(std.mem.bytesToValue(i32, size[0..4]));
        self.recv_buf_size = buf_size;
        return buf_size;
    }

    /// Get send buffer size
    pub fn getSndBuf(self: *Self) ?usize {
        if (self.send_buf_size) |size| {
            return size;
        }

        if (!self.isInet()) {
            return null;
        }

        // Get SO_SNDBUF
        const size = posix.getsockopt(
            self.raw_fd,
            posix.SOL.SOCKET,
            posix.SO.SNDBUF,
        ) catch return null;

        const buf_size: usize = @intCast(std.mem.bytesToValue(i32, size[0..4]));
        self.send_buf_size = buf_size;
        return buf_size;
    }
};

/// TLS/SSL session digest information
pub const SslDigest = struct {
    /// TLS protocol version (e.g., "TLSv1.3")
    protocol_version: ?[]const u8 = null,
    /// Cipher suite name
    cipher: ?[]const u8 = null,
    /// Server Name Indication (SNI)
    sni: ?[]const u8 = null,
    /// ALPN negotiated protocol
    alpn: ?[]const u8 = null,
    /// Whether session was resumed
    session_reused: bool = false,
    /// Certificate subject (if client cert)
    client_cert_subject: ?[]const u8 = null,
    /// Certificate issuer (if client cert)
    client_cert_issuer: ?[]const u8 = null,

    const Self = @This();

    /// Create an empty SSL digest
    pub fn init() Self {
        return .{};
    }

    /// Check if TLS is active
    pub fn isTls(self: *const Self) bool {
        return self.protocol_version != null;
    }

    /// Check if mutual TLS (client cert present)
    pub fn isMtls(self: *const Self) bool {
        return self.client_cert_subject != null;
    }
};

/// Proxy digest for CONNECT tunnel information
pub const ProxyDigest = struct {
    /// The upstream proxy address
    proxy_addr: ?SocketAddr = null,
    /// The target address requested via CONNECT
    target_addr: ?[]const u8 = null,
    /// Whether the proxy connection succeeded
    connected: bool = false,
    /// Proxy authentication user (if any)
    auth_user: ?[]const u8 = null,

    const Self = @This();

    /// Create an empty proxy digest
    pub fn init() Self {
        return .{};
    }
};

/// Main connection digest containing all connection information
pub const Digest = struct {
    /// TLS/SSL information
    ssl_digest: ?SslDigest = null,
    /// Timing information for each protocol layer
    timing_digest: std.ArrayListUnmanaged(TimingDigest) = .{},
    /// Proxy information (if using CONNECT)
    proxy_digest: ?ProxyDigest = null,
    /// Socket-level information
    socket_digest: ?SocketDigest = null,
    /// Allocator for dynamic allocations
    allocator: Allocator,

    const Self = @This();

    /// Create a new Digest
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.timing_digest.deinit(self.allocator);
    }

    /// Add a timing layer
    pub fn addTiming(self: *Self, timing: TimingDigest) !void {
        try self.timing_digest.append(self.allocator, timing);
    }

    /// Get the most recent timing (highest layer)
    pub fn getLatestTiming(self: *const Self) ?TimingDigest {
        if (self.timing_digest.items.len > 0) {
            return self.timing_digest.items[self.timing_digest.items.len - 1];
        }
        return null;
    }

    /// Get total read pending time across all layers
    pub fn getTotalReadPendingTime(self: *const Self) u64 {
        var total: u64 = 0;
        for (self.timing_digest.items) |timing| {
            total += timing.read_pending_ns;
        }
        return total;
    }

    /// Get total write pending time across all layers
    pub fn getTotalWritePendingTime(self: *const Self) u64 {
        var total: u64 = 0;
        for (self.timing_digest.items) |timing| {
            total += timing.write_pending_ns;
        }
        return total;
    }

    /// Check if this connection uses TLS
    pub fn isTls(self: *const Self) bool {
        if (self.ssl_digest) |ssl| {
            return ssl.isTls();
        }
        return false;
    }

    /// Check if this connection uses a proxy
    pub fn usesProxy(self: *const Self) bool {
        return self.proxy_digest != null;
    }
};

/// Interface for types that can provide protocol digest information
pub const ProtoDigest = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getDigest: *const fn (ptr: *anyopaque) ?*const Digest,
    };

    /// Get the digest from this protocol layer
    pub fn getDigest(self: ProtoDigest) ?*const Digest {
        return self.vtable.getDigest(self.ptr);
    }
};

/// Interface for types that can provide timing digest information
pub const GetTimingDigest = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getTimingDigest: *const fn (ptr: *anyopaque) []const TimingDigest,
        getReadPendingTime: *const fn (ptr: *anyopaque) u64,
        getWritePendingTime: *const fn (ptr: *anyopaque) u64,
    };

    /// Get timing digest for each layer
    pub fn getTimingDigest(self: GetTimingDigest) []const TimingDigest {
        return self.vtable.getTimingDigest(self.ptr);
    }

    /// Get read pending time
    pub fn getReadPendingTime(self: GetTimingDigest) u64 {
        return self.vtable.getReadPendingTime(self.ptr);
    }

    /// Get write pending time
    pub fn getWritePendingTime(self: GetTimingDigest) u64 {
        return self.vtable.getWritePendingTime(self.ptr);
    }
};

/// Interface for types that can provide/set proxy digest information
pub const GetProxyDigest = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getProxyDigest: *const fn (ptr: *anyopaque) ?*const ProxyDigest,
        setProxyDigest: *const fn (ptr: *anyopaque, digest: ProxyDigest) void,
    };

    /// Get the proxy digest
    pub fn getProxyDigest(self: GetProxyDigest) ?*const ProxyDigest {
        return self.vtable.getProxyDigest(self.ptr);
    }

    /// Set the proxy digest
    pub fn setProxyDigest(self: GetProxyDigest, digest: ProxyDigest) void {
        self.vtable.setProxyDigest(self.ptr, digest);
    }
};

/// Interface for types that can provide/set socket digest information
pub const GetSocketDigest = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getSocketDigest: *const fn (ptr: *anyopaque) ?*const SocketDigest,
        setSocketDigest: *const fn (ptr: *anyopaque, digest: SocketDigest) void,
    };

    /// Get the socket digest
    pub fn getSocketDigest(self: GetSocketDigest) ?*const SocketDigest {
        return self.vtable.getSocketDigest(self.ptr);
    }

    /// Set the socket digest
    pub fn setSocketDigest(self: GetSocketDigest, digest: SocketDigest) void {
        self.vtable.setSocketDigest(self.ptr, digest);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TimingDigest basic operations" {
    const timing = TimingDigest.init();

    // Age should be very small (just created)
    const age_ns = timing.age();
    try std.testing.expect(age_ns < 1_000_000_000); // Less than 1 second

    // Age in ms and sec should be 0 for fresh timing
    try std.testing.expectEqual(@as(u64, 0), timing.ageSec());
}

test "TimingDigest with specific timestamp" {
    // Create timing with timestamp 1 second ago
    const one_sec_ago = std.time.nanoTimestamp() - std.time.ns_per_s;
    const timing = TimingDigest.initWithTimestamp(one_sec_ago);

    // Age should be approximately 1 second
    const age_sec = timing.ageSec();
    try std.testing.expect(age_sec >= 1);
    try std.testing.expect(age_sec < 3); // Allow some slack
}

test "SocketAddr creation and formatting" {
    // Create an IPv4 address
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080);
    const socket_addr = SocketAddr.fromAddress(addr);

    try std.testing.expect(socket_addr.isInet());
    try std.testing.expect(socket_addr.asInet() != null);

    var buf: [64]u8 = undefined;
    const formatted = try socket_addr.format(&buf);
    try std.testing.expectEqualStrings("127.0.0.1:8080", formatted);
}

test "SslDigest" {
    var ssl = SslDigest.init();
    try std.testing.expect(!ssl.isTls());
    try std.testing.expect(!ssl.isMtls());

    ssl.protocol_version = "TLSv1.3";
    try std.testing.expect(ssl.isTls());
    try std.testing.expect(!ssl.isMtls());

    ssl.client_cert_subject = "CN=client";
    try std.testing.expect(ssl.isMtls());
}

test "Digest creation and timing layers" {
    var digest = Digest.init(std.testing.allocator);
    defer digest.deinit();

    try std.testing.expect(!digest.isTls());
    try std.testing.expect(!digest.usesProxy());
    try std.testing.expect(digest.getLatestTiming() == null);

    // Add timing layers
    try digest.addTiming(TimingDigest.init());
    try std.testing.expect(digest.getLatestTiming() != null);

    try digest.addTiming(TimingDigest.init());
    try std.testing.expectEqual(@as(usize, 2), digest.timing_digest.items.len);
}

test "Digest with SSL" {
    var digest = Digest.init(std.testing.allocator);
    defer digest.deinit();

    digest.ssl_digest = SslDigest{
        .protocol_version = "TLSv1.3",
        .cipher = "TLS_AES_256_GCM_SHA384",
    };

    try std.testing.expect(digest.isTls());
}

test "Digest with proxy" {
    var digest = Digest.init(std.testing.allocator);
    defer digest.deinit();

    digest.proxy_digest = ProxyDigest{
        .target_addr = "example.com:443",
        .connected = true,
    };

    try std.testing.expect(digest.usesProxy());
}

test "TcpInfo default values" {
    const info = TcpInfo{};
    try std.testing.expectEqual(@as(u32, 0), info.retransmits);
    try std.testing.expectEqual(@as(u32, 0), info.rtt_us);
}
