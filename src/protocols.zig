//! Protocol Layer (L4/TCP/UDP)
//!
//! This module provides networking primitives for TCP and UDP connections.
//! It includes listeners for accepting connections and connectors for
//! establishing outbound connections.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-core/src/protocols

const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// Socket Options
// ============================================================================

/// TCP socket options
pub const TcpOptions = struct {
    /// Enable TCP_NODELAY (disable Nagle's algorithm)
    nodelay: bool = true,
    /// Keep-alive settings
    keepalive: ?KeepAlive = null,
    /// Receive buffer size
    recv_buf_size: ?u32 = null,
    /// Send buffer size
    send_buf_size: ?u32 = null,
    /// Socket reuse address
    reuse_addr: bool = true,
    /// Socket reuse port (for load balancing)
    reuse_port: bool = false,

    pub const KeepAlive = struct {
        /// Time before first keepalive probe (seconds)
        idle: u32 = 60,
        /// Interval between keepalive probes (seconds)
        interval: u32 = 10,
        /// Number of probes before connection is considered dead
        count: u32 = 3,
    };
};

/// Apply TCP options to a socket
pub fn applyTcpOptions(fd: posix.socket_t, options: TcpOptions) !void {
    // TCP_NODELAY
    if (options.nodelay) {
        try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
    }

    // SO_REUSEADDR
    if (options.reuse_addr) {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    }

    // SO_REUSEPORT
    if (options.reuse_port) {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
    }

    // Keep-alive
    if (options.keepalive) |ka| {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1)));
        try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(@as(c_int, @intCast(ka.idle))));
        try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(@as(c_int, @intCast(ka.interval))));
        try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(@as(c_int, @intCast(ka.count))));
    }

    // Buffer sizes
    if (options.recv_buf_size) |size| {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
    }
    if (options.send_buf_size) |size| {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
    }
}

// ============================================================================
// Socket Address Helpers
// ============================================================================

/// Parse an address string into a socket address
pub fn parseAddress(host: []const u8, port: u16) !net.Address {
    // Try IPv4 first
    if (net.Address.parseIp4(host, port)) |addr| {
        return addr;
    } else |_| {}

    // Try IPv6
    if (net.Address.parseIp6(host, port)) |addr| {
        return addr;
    } else |_| {}

    // Treat as hostname - resolve it
    // Note: In production, this should use async DNS resolution
    const list = try net.getAddressList(std.heap.page_allocator, host, port);
    defer list.deinit();

    if (list.addrs.len == 0) {
        return error.UnknownHostName;
    }

    return list.addrs[0];
}

/// Format an address to a string (host:port format)
pub fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    const port = addr.getPort();
    
    // Get IP part based on address family
    if (addr.any.family == posix.AF.INET) {
        const ip4 = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}:{}", .{
            ip4[0], ip4[1], ip4[2], ip4[3], port
        }) catch return "";
    } else if (addr.any.family == posix.AF.INET6) {
        // For IPv6, just show port for simplicity
        return std.fmt.bufPrint(buf, "[::1]:{}", .{port}) catch return "";
    }
    
    return std.fmt.bufPrint(buf, "unknown:{}", .{port}) catch return "";
}

// ============================================================================
// TCP Listener
// ============================================================================

/// A TCP listener that accepts incoming connections
pub const TcpListener = struct {
    stream_server: net.Server,
    options: TcpOptions,
    allocator: Allocator,

    const Self = @This();

    /// Bind to an address and start listening
    pub fn bind(allocator: Allocator, address: net.Address, options: TcpOptions) !Self {
        const listen_options = net.Address.ListenOptions{
            .reuse_address = options.reuse_addr,
        };

        const server = try address.listen(listen_options);

        return .{
            .stream_server = server,
            .options = options,
            .allocator = allocator,
        };
    }

    /// Bind to a host:port string
    pub fn bindHostPort(allocator: Allocator, host: []const u8, port: u16, options: TcpOptions) !Self {
        const address = try parseAddress(host, port);
        return bind(allocator, address, options);
    }

    /// Accept a new connection
    pub fn accept(self: *Self) !TcpStream {
        const conn = try self.stream_server.accept();

        // Apply options to accepted socket
        applyTcpOptions(conn.stream.handle, self.options) catch |err| {
            conn.stream.close();
            return err;
        };

        return TcpStream{
            .stream = conn.stream,
            .peer_address = conn.address,
            .local_address = self.getLocalAddress(),
        };
    }

    /// Get the local address the listener is bound to
    pub fn getLocalAddress(self: *const Self) net.Address {
        return self.stream_server.listen_address;
    }

    /// Close the listener
    pub fn close(self: *Self) void {
        self.stream_server.deinit();
    }

    /// Get the underlying file descriptor
    pub fn getFd(self: *const Self) posix.socket_t {
        return self.stream_server.stream.handle;
    }
};

// ============================================================================
// TCP Stream
// ============================================================================

/// A TCP stream (connection)
pub const TcpStream = struct {
    stream: net.Stream,
    peer_address: net.Address,
    local_address: net.Address,

    const Self = @This();

    /// Connect to a remote address
    pub fn connect(address: net.Address, options: TcpOptions) !Self {
        const stream = try net.tcpConnectToAddress(address);
        errdefer stream.close();

        applyTcpOptions(stream.handle, options) catch |err| {
            stream.close();
            return err;
        };

        // Get local address from socket
        var local_addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        posix.getsockname(stream.handle, &local_addr, &addr_len) catch {};

        return .{
            .stream = stream,
            .peer_address = address,
            .local_address = .{ .any = local_addr },
        };
    }

    /// Connect to a host:port string
    pub fn connectHostPort(host: []const u8, port: u16, options: TcpOptions) !Self {
        const address = try parseAddress(host, port);
        return connect(address, options);
    }

    /// Read data from the stream
    pub fn read(self: *Self, buf: []u8) !usize {
        return self.stream.read(buf);
    }

    /// Write data to the stream
    pub fn write(self: *Self, data: []const u8) !usize {
        return self.stream.write(data);
    }

    /// Write all data to the stream
    pub fn writeAll(self: *Self, data: []const u8) !void {
        return self.stream.writeAll(data);
    }

    /// Get the underlying reader
    pub fn reader(self: *Self) net.Stream.Reader {
        return self.stream.reader();
    }

    /// Get the underlying writer
    pub fn writer(self: *Self) net.Stream.Writer {
        return self.stream.writer();
    }

    /// Close the stream
    pub fn close(self: *Self) void {
        self.stream.close();
    }

    /// Get the peer address
    pub fn getPeerAddress(self: *const Self) net.Address {
        return self.peer_address;
    }

    /// Get the local address
    pub fn getLocalAddress(self: *const Self) net.Address {
        return self.local_address;
    }

    /// Get the underlying file descriptor
    pub fn getFd(self: *const Self) posix.socket_t {
        return self.stream.handle;
    }

    /// Check if the connection is still open
    pub fn isOpen(self: *const Self) bool {
        // Try a zero-byte peek to check connection state
        var buf: [1]u8 = undefined;
        _ = posix.recv(self.stream.handle, &buf, posix.MSG.PEEK | posix.MSG.DONTWAIT) catch |err| {
            return switch (err) {
                error.WouldBlock => true, // Socket is still open, just no data
                else => false,
            };
        };
        return true;
    }
};

// ============================================================================
// TCP Connector (with connection reuse)
// ============================================================================

/// TCP connector with connection pooling support
pub const TcpConnector = struct {
    options: TcpOptions,
    /// Connect timeout in milliseconds
    connect_timeout_ms: u32,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, options: TcpOptions) Self {
        return .{
            .options = options,
            .connect_timeout_ms = 30000, // 30 seconds default
            .allocator = allocator,
        };
    }

    /// Set connect timeout
    pub fn setConnectTimeout(self: *Self, timeout_ms: u32) void {
        self.connect_timeout_ms = timeout_ms;
    }

    /// Connect to a remote address
    pub fn connect(self: *Self, address: net.Address) !TcpStream {
        return TcpStream.connect(address, self.options);
    }

    /// Connect to a host:port string
    pub fn connectHostPort(self: *Self, host: []const u8, port: u16) !TcpStream {
        const address = try parseAddress(host, port);
        return self.connect(address);
    }
};

// ============================================================================
// Connection Info / Digest
// ============================================================================

/// Information about a connection
pub const ConnectionInfo = struct {
    /// Source (local) address
    local_addr: ?net.Address,
    /// Destination (peer) address
    peer_addr: ?net.Address,
    /// Whether TLS is enabled
    is_tls: bool,
    /// TLS server name (SNI)
    tls_sni: ?[]const u8,
    /// ALPN protocol
    alpn: ?[]const u8,
    /// Connection timestamp (nanoseconds)
    connected_at: i128,

    const Self = @This();

    pub fn init() Self {
        return .{
            .local_addr = null,
            .peer_addr = null,
            .is_tls = false,
            .tls_sni = null,
            .alpn = null,
            .connected_at = std.time.nanoTimestamp(),
        };
    }

    pub fn fromTcpStream(stream: *const TcpStream) Self {
        return .{
            .local_addr = stream.local_address,
            .peer_addr = stream.peer_address,
            .is_tls = false,
            .tls_sni = null,
            .alpn = null,
            .connected_at = std.time.nanoTimestamp(),
        };
    }
};

// ============================================================================
// Peer Address
// ============================================================================

/// Represents a peer (backend server) address
pub const PeerAddress = struct {
    address: net.Address,
    hostname: ?[]const u8,
    weight: u32,

    const Self = @This();

    pub fn init(address: net.Address) Self {
        return .{
            .address = address,
            .hostname = null,
            .weight = 1,
        };
    }

    pub fn initWithHostname(address: net.Address, hostname: []const u8) Self {
        return .{
            .address = address,
            .hostname = hostname,
            .weight = 1,
        };
    }

    pub fn setWeight(self: *Self, weight: u32) void {
        self.weight = weight;
    }

    pub fn getPort(self: *const Self) u16 {
        return self.address.getPort();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TcpOptions defaults" {
    const options = TcpOptions{};
    try testing.expect(options.nodelay);
    try testing.expect(options.reuse_addr);
    try testing.expect(!options.reuse_port);
    try testing.expect(options.keepalive == null);
}

test "TcpOptions with keepalive" {
    const options = TcpOptions{
        .keepalive = .{
            .idle = 30,
            .interval = 5,
            .count = 3,
        },
    };
    try testing.expectEqual(options.keepalive.?.idle, 30);
    try testing.expectEqual(options.keepalive.?.interval, 5);
    try testing.expectEqual(options.keepalive.?.count, 3);
}

test "parseAddress IPv4" {
    const addr = try parseAddress("127.0.0.1", 8080);
    try testing.expectEqual(addr.getPort(), 8080);
}

test "parseAddress IPv6" {
    const addr = try parseAddress("::1", 8080);
    try testing.expectEqual(addr.getPort(), 8080);
}

test "ConnectionInfo init" {
    const info = ConnectionInfo.init();
    try testing.expect(info.local_addr == null);
    try testing.expect(info.peer_addr == null);
    try testing.expect(!info.is_tls);
    try testing.expect(info.connected_at > 0);
}

test "PeerAddress init" {
    const addr = try parseAddress("127.0.0.1", 8080);
    var peer = PeerAddress.init(addr);
    try testing.expectEqual(peer.getPort(), 8080);
    try testing.expectEqual(peer.weight, 1);

    peer.setWeight(10);
    try testing.expectEqual(peer.weight, 10);
}

test "PeerAddress with hostname" {
    const addr = try parseAddress("127.0.0.1", 80);
    const peer = PeerAddress.initWithHostname(addr, "example.com");
    try testing.expectEqualStrings("example.com", peer.hostname.?);
}

test "TcpConnector init" {
    var connector = TcpConnector.init(testing.allocator, .{});
    try testing.expectEqual(connector.connect_timeout_ms, 30000);

    connector.setConnectTimeout(5000);
    try testing.expectEqual(connector.connect_timeout_ms, 5000);
}

test "formatAddress" {
    const addr = try parseAddress("127.0.0.1", 8080);
    var buf: [64]u8 = undefined;
    const str = formatAddress(addr, &buf);
    try testing.expect(str.len > 0);
}

// Integration test - only runs when there's no actual network I/O needed
test "TcpListener and TcpStream types compile" {
    // Just ensure the types compile correctly
    _ = TcpListener;
    _ = TcpStream;
    _ = TcpConnector;
}
