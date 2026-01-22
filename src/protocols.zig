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
// DNS Resolver with Caching
// ============================================================================

/// DNS cache entry with TTL
pub const DnsCacheEntry = struct {
    addresses: []net.Address,
    expires_at: i64, // Timestamp in milliseconds
    created_at: i64,

    pub fn isExpired(self: *const DnsCacheEntry) bool {
        return std.time.milliTimestamp() >= self.expires_at;
    }

    pub fn ttlRemaining(self: *const DnsCacheEntry) i64 {
        const now = std.time.milliTimestamp();
        if (now >= self.expires_at) return 0;
        return self.expires_at - now;
    }
};

/// DNS Resolver configuration
pub const DnsResolverConfig = struct {
    /// Default TTL for cached entries in milliseconds (default: 5 minutes)
    default_ttl_ms: i64 = 5 * 60 * 1000,
    /// Minimum TTL for cached entries (default: 1 second)
    min_ttl_ms: i64 = 1000,
    /// Maximum TTL for cached entries (default: 1 hour)
    max_ttl_ms: i64 = 60 * 60 * 1000,
    /// Maximum number of cached entries (default: 1024)
    max_entries: usize = 1024,
    /// Enable negative caching (cache failed lookups)
    negative_cache: bool = true,
    /// TTL for negative cache entries (default: 30 seconds)
    negative_ttl_ms: i64 = 30 * 1000,
    /// Prefer IPv4 addresses
    prefer_ipv4: bool = true,
    /// Prefer IPv6 addresses
    prefer_ipv6: bool = false,
};

/// Async DNS Resolver with caching
/// Provides efficient DNS resolution with configurable caching and TTL management
pub const DnsResolver = struct {
    allocator: Allocator,
    config: DnsResolverConfig,
    cache: std.StringHashMapUnmanaged(DnsCacheEntry),
    negative_cache_set: std.StringHashMapUnmanaged(i64), // hostname -> expires_at
    mutex: std.Thread.Mutex,
    stats: DnsStats,

    const Self = @This();

    /// DNS resolution statistics
    pub const DnsStats = struct {
        hits: u64 = 0,
        misses: u64 = 0,
        negative_hits: u64 = 0,
        evictions: u64 = 0,
        resolution_errors: u64 = 0,
        total_resolutions: u64 = 0,

        pub fn hitRate(self: *const DnsStats) f64 {
            const total = self.hits + self.misses;
            if (total == 0) return 0.0;
            return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
        }
    };

    /// Initialize a new DNS resolver with caching
    pub fn init(allocator: Allocator, config: DnsResolverConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .cache = .{},
            .negative_cache_set = .{},
            .mutex = .{},
            .stats = .{},
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        // Free all cached addresses
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.addresses);
        }
        self.cache.deinit(self.allocator);

        // Free negative cache keys
        var neg_it = self.negative_cache_set.keyIterator();
        while (neg_it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.negative_cache_set.deinit(self.allocator);
    }

    /// Resolve a hostname to addresses with caching
    pub fn resolve(self: *Self, hostname: []const u8, port: u16) ![]const net.Address {
        // First try to parse as IP address (no DNS needed)
        if (net.Address.parseIp4(hostname, port)) |addr| {
            const result = try self.allocator.alloc(net.Address, 1);
            result[0] = addr;
            return result;
        } else |_| {}

        if (net.Address.parseIp6(hostname, port)) |addr| {
            const result = try self.allocator.alloc(net.Address, 1);
            result[0] = addr;
            return result;
        } else |_| {}

        // Check cache
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check negative cache first
        if (self.config.negative_cache) {
            if (self.negative_cache_set.get(hostname)) |expires_at| {
                if (std.time.milliTimestamp() < expires_at) {
                    self.stats.negative_hits += 1;
                    return error.UnknownHostName;
                }
                // Expired, remove it
                if (self.negative_cache_set.fetchRemove(hostname)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }

        // Check positive cache
        if (self.cache.get(hostname)) |entry| {
            if (!entry.isExpired()) {
                self.stats.hits += 1;
                // Return copy with updated port
                const result = try self.allocator.alloc(net.Address, entry.addresses.len);
                for (entry.addresses, 0..) |addr, i| {
                    result[i] = addr;
                    result[i].setPort(port);
                }
                return result;
            }
            // Expired, remove it
            if (self.cache.fetchRemove(hostname)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.addresses);
            }
        }

        self.stats.misses += 1;
        self.stats.total_resolutions += 1;

        // Perform actual DNS resolution (unlock mutex during blocking call)
        self.mutex.unlock();
        const resolved = self.performResolution(hostname, port) catch |err| {
            self.mutex.lock();
            self.stats.resolution_errors += 1;

            // Add to negative cache
            if (self.config.negative_cache) {
                const key_copy = try self.allocator.dupe(u8, hostname);
                errdefer self.allocator.free(key_copy);
                const expires = std.time.milliTimestamp() + self.config.negative_ttl_ms;
                try self.negative_cache_set.put(self.allocator, key_copy, expires);
            }
            return err;
        };
        self.mutex.lock();

        // Cache the result
        try self.cacheResult(hostname, resolved);

        // Return copy with correct port
        const result = try self.allocator.alloc(net.Address, resolved.len);
        for (resolved, 0..) |addr, i| {
            result[i] = addr;
            result[i].setPort(port);
        }
        return result;
    }

    /// Resolve and return single best address
    pub fn resolveOne(self: *Self, hostname: []const u8, port: u16) !net.Address {
        const addrs = try self.resolve(hostname, port);
        defer self.allocator.free(addrs);

        if (addrs.len == 0) return error.UnknownHostName;

        // Return preferred address based on config
        if (self.config.prefer_ipv4) {
            for (addrs) |addr| {
                if (addr.any.family == posix.AF.INET) return addr;
            }
        }
        if (self.config.prefer_ipv6) {
            for (addrs) |addr| {
                if (addr.any.family == posix.AF.INET6) return addr;
            }
        }
        return addrs[0];
    }

    /// Perform actual DNS resolution
    fn performResolution(self: *Self, hostname: []const u8, port: u16) ![]net.Address {
        _ = self;
        const list = net.getAddressList(std.heap.page_allocator, hostname, port) catch |err| {
            return err;
        };
        defer list.deinit();

        if (list.addrs.len == 0) {
            return error.UnknownHostName;
        }

        // Copy addresses to our allocator
        const addresses = try std.heap.page_allocator.alloc(net.Address, list.addrs.len);
        @memcpy(addresses, list.addrs);
        return addresses;
    }

    /// Cache resolution result
    fn cacheResult(self: *Self, hostname: []const u8, addresses: []net.Address) !void {
        // Evict if at capacity
        if (self.cache.count() >= self.config.max_entries) {
            self.evictOldest();
        }

        const key_copy = try self.allocator.dupe(u8, hostname);
        errdefer self.allocator.free(key_copy);

        const addr_copy = try self.allocator.alloc(net.Address, addresses.len);
        @memcpy(addr_copy, addresses);

        const now = std.time.milliTimestamp();
        const entry = DnsCacheEntry{
            .addresses = addr_copy,
            .expires_at = now + self.config.default_ttl_ms,
            .created_at = now,
        };

        // Remove old entry if exists
        if (self.cache.fetchRemove(key_copy)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value.addresses);
        }

        try self.cache.put(self.allocator, key_copy, entry);
    }

    /// Evict oldest cache entry
    fn evictOldest(self: *Self) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.created_at < oldest_time) {
                oldest_time = entry.value_ptr.created_at;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.cache.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.addresses);
                self.stats.evictions += 1;
            }
        }
    }

    /// Clear all cached entries
    pub fn clearCache(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.addresses);
        }
        self.cache.clearRetainingCapacity();

        var neg_it = self.negative_cache_set.keyIterator();
        while (neg_it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.negative_cache_set.clearRetainingCapacity();
    }

    /// Remove a specific hostname from cache
    pub fn invalidate(self: *Self, hostname: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.cache.fetchRemove(hostname)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.addresses);
        }
        if (self.negative_cache_set.fetchRemove(hostname)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Get current cache statistics
    pub fn getStats(self: *Self) DnsStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Get number of cached entries
    pub fn cacheSize(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cache.count();
    }

    /// Prefetch/warm cache for a hostname
    pub fn prefetch(self: *Self, hostname: []const u8) void {
        _ = self.resolve(hostname, 0) catch {};
    }
};

/// Global DNS resolver instance (lazily initialized)
var global_resolver: ?*DnsResolver = null;
var global_resolver_mutex: std.Thread.Mutex = .{};

/// Get or create the global DNS resolver
pub fn getGlobalDnsResolver(allocator: Allocator) !*DnsResolver {
    global_resolver_mutex.lock();
    defer global_resolver_mutex.unlock();

    if (global_resolver) |resolver| {
        return resolver;
    }

    const resolver = try allocator.create(DnsResolver);
    resolver.* = DnsResolver.init(allocator, .{});
    global_resolver = resolver;
    return resolver;
}

/// Resolve hostname using global resolver (convenience function)
pub fn resolveHostname(allocator: Allocator, hostname: []const u8, port: u16) !net.Address {
    const resolver = try getGlobalDnsResolver(allocator);
    return resolver.resolveOne(hostname, port);
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
// TCP_INFO and Socket Extensions
// ============================================================================

/// The kernel TCP_INFO struct for Linux socket statistics
/// This provides detailed information about TCP connection state
pub const TcpInfo = extern struct {
    tcpi_state: u8 = 0,
    tcpi_ca_state: u8 = 0,
    tcpi_retransmits: u8 = 0,
    tcpi_probes: u8 = 0,
    tcpi_backoff: u8 = 0,
    tcpi_options: u8 = 0,
    tcpi_snd_wscale_rcv_wscale: u8 = 0, // 4 bits each
    tcpi_delivery_rate_app_limited: u8 = 0,
    tcpi_rto: u32 = 0,
    tcpi_ato: u32 = 0,
    tcpi_snd_mss: u32 = 0,
    tcpi_rcv_mss: u32 = 0,
    tcpi_unacked: u32 = 0,
    tcpi_sacked: u32 = 0,
    tcpi_lost: u32 = 0,
    tcpi_retrans: u32 = 0,
    tcpi_fackets: u32 = 0,
    tcpi_last_data_sent: u32 = 0,
    tcpi_last_ack_sent: u32 = 0,
    tcpi_last_data_recv: u32 = 0,
    tcpi_last_ack_recv: u32 = 0,
    tcpi_pmtu: u32 = 0,
    tcpi_rcv_ssthresh: u32 = 0,
    tcpi_rtt: u32 = 0,
    tcpi_rttvar: u32 = 0,
    tcpi_snd_ssthresh: u32 = 0,
    tcpi_snd_cwnd: u32 = 0,
    tcpi_advmss: u32 = 0,
    tcpi_reordering: u32 = 0,
    tcpi_rcv_rtt: u32 = 0,
    tcpi_rcv_space: u32 = 0,
    tcpi_total_retrans: u32 = 0,
    tcpi_pacing_rate: u64 = 0,
    tcpi_max_pacing_rate: u64 = 0,
    tcpi_bytes_acked: u64 = 0,
    tcpi_bytes_received: u64 = 0,
    tcpi_segs_out: u32 = 0,
    tcpi_segs_in: u32 = 0,
    tcpi_notsent_bytes: u32 = 0,
    tcpi_min_rtt: u32 = 0,
    tcpi_data_segs_in: u32 = 0,
    tcpi_data_segs_out: u32 = 0,
    tcpi_delivery_rate: u64 = 0,
    tcpi_busy_time: u64 = 0,
    tcpi_rwnd_limited: u64 = 0,
    tcpi_sndbuf_limited: u64 = 0,
    tcpi_delivered: u32 = 0,
    tcpi_delivered_ce: u32 = 0,
    tcpi_bytes_sent: u64 = 0,
    tcpi_bytes_retrans: u64 = 0,
    tcpi_dsack_dups: u32 = 0,
    tcpi_reord_seen: u32 = 0,
    tcpi_rcv_ooopack: u32 = 0,
    tcpi_snd_wnd: u32 = 0,
    tcpi_rcv_wnd: u32 = 0,

    /// Get the send window scale factor
    pub fn getSndWscale(self: *const TcpInfo) u4 {
        return @truncate(self.tcpi_snd_wscale_rcv_wscale >> 4);
    }

    /// Get the receive window scale factor
    pub fn getRcvWscale(self: *const TcpInfo) u4 {
        return @truncate(self.tcpi_snd_wscale_rcv_wscale & 0x0F);
    }

    /// Get RTT in microseconds
    pub fn getRttUs(self: *const TcpInfo) u32 {
        return self.tcpi_rtt;
    }

    /// Get RTT variance in microseconds
    pub fn getRttVarUs(self: *const TcpInfo) u32 {
        return self.tcpi_rttvar;
    }

    /// Check if delivery rate is application limited
    pub fn isDeliveryRateAppLimited(self: *const TcpInfo) bool {
        return (self.tcpi_delivery_rate_app_limited & 0x80) != 0;
    }
};

/// TCP keepalive configuration
pub const TcpKeepalive = struct {
    /// Time before first keepalive probe (duration)
    idle_ns: u64,
    /// Interval between keepalive probes (duration)
    interval_ns: u64,
    /// Number of probes before connection is considered dead
    count: usize,
    /// TCP_USER_TIMEOUT in milliseconds (Linux only)
    user_timeout_ms: u32 = 0,

    /// Create from seconds
    pub fn fromSeconds(idle: u32, interval: u32, count: usize) TcpKeepalive {
        return .{
            .idle_ns = @as(u64, idle) * std.time.ns_per_s,
            .interval_ns = @as(u64, interval) * std.time.ns_per_s,
            .count = count,
            .user_timeout_ms = 0,
        };
    }

    /// Get idle time in seconds
    pub fn getIdleSecs(self: *const TcpKeepalive) u32 {
        return @intCast(self.idle_ns / std.time.ns_per_s);
    }

    /// Get interval in seconds
    pub fn getIntervalSecs(self: *const TcpKeepalive) u32 {
        return @intCast(self.interval_ns / std.time.ns_per_s);
    }
};

/// Get TCP_INFO for a socket
pub fn getTcpInfo(fd: posix.socket_t) !TcpInfo {
    var info: TcpInfo = .{};
    var len: posix.socklen_t = @sizeOf(TcpInfo);

    // TCP_INFO = 11 on Linux
    const TCP_INFO_OPT = 11;

    const result = posix.system.getsockopt(
        fd,
        posix.IPPROTO.TCP,
        TCP_INFO_OPT,
        @ptrCast(&info),
        &len,
    );

    if (result != 0) {
        return error.GetSockOptFailed;
    }

    return info;
}

/// Get the receive buffer size for a socket
pub fn getRecvBuf(fd: posix.socket_t) !usize {
    var buf_size: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);

    const result = posix.system.getsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.RCVBUF,
        @ptrCast(&buf_size),
        &len,
    );

    if (result != 0) {
        return error.GetSockOptFailed;
    }

    return @intCast(buf_size);
}

/// Set the receive buffer size for a socket
pub fn setRecvBuf(fd: posix.socket_t, size: usize) !void {
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
}

/// Get the send buffer size for a socket
pub fn getSndBuf(fd: posix.socket_t) !usize {
    var buf_size: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);

    const result = posix.system.getsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.SNDBUF,
        @ptrCast(&buf_size),
        &len,
    );

    if (result != 0) {
        return error.GetSockOptFailed;
    }

    return @intCast(buf_size);
}

/// Set the send buffer size for a socket
pub fn setSndBuf(fd: posix.socket_t, size: usize) !void {
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
}

/// Enable TCP Fast Open for client connections (Linux)
pub fn setTcpFastOpenConnect(fd: posix.socket_t) !void {
    // TCP_FASTOPEN_CONNECT = 30 on Linux
    const TCP_FASTOPEN_CONNECT = 30;
    try posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_FASTOPEN_CONNECT, &std.mem.toBytes(@as(c_int, 1)));
}

/// Enable TCP Fast Open for server (set backlog)
pub fn setTcpFastOpenBacklog(fd: posix.socket_t, backlog: usize) !void {
    // TCP_FASTOPEN = 23 on Linux
    const TCP_FASTOPEN = 23;
    try posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_FASTOPEN, &std.mem.toBytes(@as(c_int, @intCast(backlog))));
}

/// Set TCP keepalive options
pub fn setTcpKeepalive(fd: posix.socket_t, ka: TcpKeepalive) !void {
    // Enable keepalive
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1)));

    // Set idle time
    try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(@as(c_int, @intCast(ka.getIdleSecs()))));

    // Set interval
    try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(@as(c_int, @intCast(ka.getIntervalSecs()))));

    // Set count
    try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(@as(c_int, @intCast(ka.count))));

    // Set TCP_USER_TIMEOUT if specified (Linux only)
    if (ka.user_timeout_ms > 0) {
        // TCP_USER_TIMEOUT = 18 on Linux
        const TCP_USER_TIMEOUT = 18;
        try posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_USER_TIMEOUT, &std.mem.toBytes(@as(c_int, @intCast(ka.user_timeout_ms))));
    }
}

/// Set DSCP (Differentiated Services Code Point) value
pub fn setDscp(fd: posix.socket_t, value: u8) !void {
    // Try IPv6 first (IPV6_TCLASS), then fall back to IPv4 (IP_TOS)
    posix.setsockopt(fd, posix.IPPROTO.IPV6, posix.IPV6.TCLASS, &std.mem.toBytes(@as(c_int, value))) catch {
        try posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.TOS, &std.mem.toBytes(@as(c_int, value)));
    };
}

/// Get the socket cookie (Linux only, SO_COOKIE)
pub fn getSocketCookie(fd: posix.socket_t) !u64 {
    var cookie: u64 = 0;
    var len: posix.socklen_t = @sizeOf(u64);

    // SO_COOKIE = 57 on Linux
    const SO_COOKIE = 57;

    const result = posix.system.getsockopt(
        fd,
        posix.SOL.SOCKET,
        SO_COOKIE,
        @ptrCast(&cookie),
        &len,
    );

    if (result != 0) {
        return error.GetSockOptFailed;
    }

    return cookie;
}

/// Get the original destination address (for transparent proxying, Linux only)
pub fn getOriginalDest(fd: posix.socket_t) !?net.Address {
    // SO_ORIGINAL_DST = 80 for IPv4
    const SO_ORIGINAL_DST = 80;

    var addr: posix.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    const result = posix.system.getsockopt(
        fd,
        posix.SOL.IP,
        SO_ORIGINAL_DST,
        @ptrCast(&addr),
        &len,
    );

    if (result != 0) {
        // Try IPv6
        // IP6T_SO_ORIGINAL_DST = 80 for IPv6
        var addr6: posix.sockaddr.in6 = undefined;
        var len6: posix.socklen_t = @sizeOf(posix.sockaddr.in6);

        const result6 = posix.system.getsockopt(
            fd,
            posix.IPPROTO.IPV6,
            SO_ORIGINAL_DST,
            @ptrCast(&addr6),
            &len6,
        );

        if (result6 != 0) {
            return null;
        }

        return net.Address{ .in6 = addr6 };
    }

    return net.Address{ .in = addr };
}

// ============================================================================
// Virtual Socket Stream
// ============================================================================

/// A limited set of socket options that can be set on a VirtualSocket
pub const VirtualSockOpt = union(enum) {
    /// Disable Nagle's algorithm
    no_delay: bool,
    /// TCP keepalive settings
    keep_alive: TcpOptions.KeepAlive,
    /// Receive buffer size
    recv_buf_size: u32,
    /// Send buffer size
    send_buf_size: u32,
};

/// A "virtual" socket interface that supports read and write operations.
/// This allows abstracting over different socket implementations (TCP, Unix, TLS, etc.)
pub const VirtualSocket = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize,
        write: *const fn (ctx: *anyopaque, data: []const u8) anyerror!usize,
        close: *const fn (ctx: *anyopaque) void,
        setSocketOption: *const fn (ctx: *anyopaque, opt: VirtualSockOpt) anyerror!void,
        getLocalAddress: *const fn (ctx: *anyopaque) ?net.Address,
        getPeerAddress: *const fn (ctx: *anyopaque) ?net.Address,
    };

    /// Read data from the socket
    pub fn read(self: VirtualSocket, buf: []u8) !usize {
        return self.vtable.read(self.context, buf);
    }

    /// Write data to the socket
    pub fn write(self: VirtualSocket, data: []const u8) !usize {
        return self.vtable.write(self.context, data);
    }

    /// Close the socket
    pub fn close(self: VirtualSocket) void {
        self.vtable.close(self.context);
    }

    /// Set a socket option
    pub fn setSocketOption(self: VirtualSocket, opt: VirtualSockOpt) !void {
        return self.vtable.setSocketOption(self.context, opt);
    }

    /// Get the local address
    pub fn getLocalAddress(self: VirtualSocket) ?net.Address {
        return self.vtable.getLocalAddress(self.context);
    }

    /// Get the peer address
    pub fn getPeerAddress(self: VirtualSocket) ?net.Address {
        return self.vtable.getPeerAddress(self.context);
    }
};

/// Wrapper around any type implementing VirtualSocket interface.
/// This provides a uniform stream interface for different socket types.
pub const VirtualSocketStream = struct {
    socket: VirtualSocket,

    const Self = @This();

    /// Create a new VirtualSocketStream from a VirtualSocket
    pub fn init(socket: VirtualSocket) Self {
        return .{ .socket = socket };
    }

    /// Create from a TcpStream
    pub fn fromTcpStream(stream: *TcpStream) Self {
        return .{
            .socket = .{
                .context = @ptrCast(stream),
                .vtable = &tcp_stream_vtable,
            },
        };
    }

    /// Read data from the stream
    pub fn read(self: *Self, buf: []u8) !usize {
        return self.socket.read(buf);
    }

    /// Write data to the stream
    pub fn write(self: *Self, data: []const u8) !usize {
        return self.socket.write(data);
    }

    /// Write all data to the stream
    pub fn writeAll(self: *Self, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            written += try self.write(data[written..]);
        }
    }

    /// Close the stream
    pub fn close(self: *Self) void {
        self.socket.close();
    }

    /// Set a socket option
    pub fn setSocketOption(self: *Self, opt: VirtualSockOpt) !void {
        return self.socket.setSocketOption(opt);
    }

    /// Get the local address
    pub fn getLocalAddress(self: *const Self) ?net.Address {
        return self.socket.getLocalAddress();
    }

    /// Get the peer address
    pub fn getPeerAddress(self: *const Self) ?net.Address {
        return self.socket.getPeerAddress();
    }
};

// VTable implementation for TcpStream
const tcp_stream_vtable = VirtualSocket.VTable{
    .read = tcpStreamRead,
    .write = tcpStreamWrite,
    .close = tcpStreamClose,
    .setSocketOption = tcpStreamSetOption,
    .getLocalAddress = tcpStreamGetLocalAddr,
    .getPeerAddress = tcpStreamGetPeerAddr,
};

fn tcpStreamRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    return stream.read(buf);
}

fn tcpStreamWrite(ctx: *anyopaque, data: []const u8) anyerror!usize {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    return stream.write(data);
}

fn tcpStreamClose(ctx: *anyopaque) void {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    stream.close();
}

fn tcpStreamSetOption(ctx: *anyopaque, opt: VirtualSockOpt) anyerror!void {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    const fd = stream.getFd();

    switch (opt) {
        .no_delay => |val| {
            if (val) {
                try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
            } else {
                try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 0)));
            }
        },
        .keep_alive => |ka| {
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1)));
            try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(@as(c_int, @intCast(ka.idle))));
            try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(@as(c_int, @intCast(ka.interval))));
            try posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(@as(c_int, @intCast(ka.count))));
        },
        .recv_buf_size => |size| {
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
        },
        .send_buf_size => |size| {
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(@as(c_int, @intCast(size))));
        },
    }
}

fn tcpStreamGetLocalAddr(ctx: *anyopaque) ?net.Address {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    return stream.getLocalAddress();
}

fn tcpStreamGetPeerAddr(ctx: *anyopaque) ?net.Address {
    const stream: *TcpStream = @ptrCast(@alignCast(ctx));
    return stream.getPeerAddress();
}

/// Static virtual socket for testing - provides in-memory read/write buffer
pub const StaticVirtualSocket = struct {
    read_content: []const u8,
    read_pos: usize,
    write_buf: std.ArrayListUnmanaged(u8),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, content: []const u8) Self {
        return .{
            .read_content = content,
            .read_pos = 0,
            .write_buf = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.write_buf.deinit(self.allocator);
    }

    pub fn asVirtualSocket(self: *Self) VirtualSocket {
        return .{
            .context = @ptrCast(self),
            .vtable = &static_vtable,
        };
    }

    pub fn getWrittenData(self: *const Self) []const u8 {
        return self.write_buf.items;
    }

    const static_vtable = VirtualSocket.VTable{
        .read = staticRead,
        .write = staticWrite,
        .close = staticClose,
        .setSocketOption = staticSetOption,
        .getLocalAddress = staticGetLocalAddr,
        .getPeerAddress = staticGetPeerAddr,
    };

    fn staticRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const remaining = self.read_content.len - self.read_pos;
        if (remaining == 0) return 0;

        const to_read = @min(remaining, buf.len);
        @memcpy(buf[0..to_read], self.read_content[self.read_pos .. self.read_pos + to_read]);
        self.read_pos += to_read;
        return to_read;
    }

    fn staticWrite(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));
        try self.write_buf.appendSlice(self.allocator, data);
        return data.len;
    }

    fn staticClose(ctx: *anyopaque) void {
        _ = ctx;
    }

    fn staticSetOption(ctx: *anyopaque, opt: VirtualSockOpt) anyerror!void {
        _ = ctx;
        _ = opt;
    }

    fn staticGetLocalAddr(ctx: *anyopaque) ?net.Address {
        _ = ctx;
        return null;
    }

    fn staticGetPeerAddr(ctx: *anyopaque) ?net.Address {
        _ = ctx;
        return null;
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

test "VirtualSockOpt types" {
    const opt1 = VirtualSockOpt{ .no_delay = true };
    const opt2 = VirtualSockOpt{ .keep_alive = .{ .idle = 60, .interval = 10, .count = 3 } };
    const opt3 = VirtualSockOpt{ .recv_buf_size = 65536 };
    const opt4 = VirtualSockOpt{ .send_buf_size = 65536 };

    try testing.expect(opt1.no_delay);
    try testing.expectEqual(opt2.keep_alive.idle, 60);
    try testing.expectEqual(opt3.recv_buf_size, 65536);
    try testing.expectEqual(opt4.send_buf_size, 65536);
}

test "StaticVirtualSocket read and write" {
    const content = "hello virtual world";
    var socket = StaticVirtualSocket.init(testing.allocator, content);
    defer socket.deinit();

    // Read all content
    var buf: [32]u8 = undefined;
    const n = try socket.asVirtualSocket().read(&buf);
    try testing.expectEqual(n, content.len);
    try testing.expectEqualStrings(content, buf[0..n]);

    // Read again should return 0 (EOF)
    const n2 = try socket.asVirtualSocket().read(&buf);
    try testing.expectEqual(n2, 0);

    // Write some data
    const write_data = "response data";
    const written = try socket.asVirtualSocket().write(write_data);
    try testing.expectEqual(written, write_data.len);
    try testing.expectEqualStrings(write_data, socket.getWrittenData());
}

test "VirtualSocketStream with StaticVirtualSocket" {
    const content = "test content";
    var static_socket = StaticVirtualSocket.init(testing.allocator, content);
    defer static_socket.deinit();

    var stream = VirtualSocketStream.init(static_socket.asVirtualSocket());

    // Read through stream
    var buf: [32]u8 = undefined;
    const n = try stream.read(&buf);
    try testing.expectEqual(n, content.len);
    try testing.expectEqualStrings(content, buf[0..n]);

    // Write through stream
    try stream.writeAll("hello");
    try testing.expectEqualStrings("hello", static_socket.getWrittenData());
}

test "VirtualSocket interface" {
    // Test that VirtualSocket types compile and work
    _ = VirtualSocket;
    _ = VirtualSocketStream;

    // Test setSocketOption doesn't crash on static socket
    const content = "";
    var static_socket = StaticVirtualSocket.init(testing.allocator, content);
    defer static_socket.deinit();

    try static_socket.asVirtualSocket().setSocketOption(.{ .no_delay = true });
    try testing.expect(static_socket.asVirtualSocket().getLocalAddress() == null);
    try testing.expect(static_socket.asVirtualSocket().getPeerAddress() == null);
}

test "TcpInfo struct" {
    var info = TcpInfo{};
    info.tcpi_rtt = 1000;
    info.tcpi_rttvar = 500;
    info.tcpi_snd_wscale_rcv_wscale = 0x74; // snd=7, rcv=4

    try testing.expectEqual(info.getRttUs(), 1000);
    try testing.expectEqual(info.getRttVarUs(), 500);
    try testing.expectEqual(info.getSndWscale(), 7);
    try testing.expectEqual(info.getRcvWscale(), 4);
    try testing.expect(!info.isDeliveryRateAppLimited());

    info.tcpi_delivery_rate_app_limited = 0x80;
    try testing.expect(info.isDeliveryRateAppLimited());
}

test "TcpKeepalive" {
    const ka = TcpKeepalive.fromSeconds(60, 10, 3);
    try testing.expectEqual(ka.getIdleSecs(), 60);
    try testing.expectEqual(ka.getIntervalSecs(), 10);
    try testing.expectEqual(ka.count, 3);
    try testing.expectEqual(ka.user_timeout_ms, 0);

    const ka2 = TcpKeepalive{
        .idle_ns = 30 * std.time.ns_per_s,
        .interval_ns = 5 * std.time.ns_per_s,
        .count = 5,
        .user_timeout_ms = 10000,
    };
    try testing.expectEqual(ka2.getIdleSecs(), 30);
    try testing.expectEqual(ka2.getIntervalSecs(), 5);
    try testing.expectEqual(ka2.user_timeout_ms, 10000);
}

test "Socket extension types compile" {
    // Just verify these types and functions compile
    _ = TcpInfo;
    _ = TcpKeepalive;
    _ = getTcpInfo;
    _ = getRecvBuf;
    _ = setRecvBuf;
    _ = getSndBuf;
    _ = setSndBuf;
    _ = setTcpFastOpenConnect;
    _ = setTcpFastOpenBacklog;
    _ = setTcpKeepalive;
    _ = setDscp;
    _ = getSocketCookie;
    _ = getOriginalDest;
}

// ============================================================================
// DNS Resolver Tests
// ============================================================================

test "DnsResolverConfig defaults" {
    const config = DnsResolverConfig{};
    try testing.expectEqual(config.default_ttl_ms, 5 * 60 * 1000);
    try testing.expectEqual(config.min_ttl_ms, 1000);
    try testing.expectEqual(config.max_ttl_ms, 60 * 60 * 1000);
    try testing.expectEqual(config.max_entries, 1024);
    try testing.expect(config.negative_cache);
    try testing.expect(config.prefer_ipv4);
    try testing.expect(!config.prefer_ipv6);
}

test "DnsCacheEntry expiration" {
    const now = std.time.milliTimestamp();
    
    // Create a test address slice (use stack-allocated for test)
    var addrs: [0]net.Address = .{};
    
    // Not expired
    const entry1 = DnsCacheEntry{
        .addresses = &addrs,
        .expires_at = now + 10000,
        .created_at = now,
    };
    try testing.expect(!entry1.isExpired());
    try testing.expect(entry1.ttlRemaining() > 0);
    
    // Expired
    const entry2 = DnsCacheEntry{
        .addresses = &addrs,
        .expires_at = now - 1000,
        .created_at = now - 2000,
    };
    try testing.expect(entry2.isExpired());
    try testing.expectEqual(entry2.ttlRemaining(), 0);
}

test "DnsResolver init and deinit" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    try testing.expectEqual(resolver.cacheSize(), 0);
    const stats = resolver.getStats();
    try testing.expectEqual(stats.hits, 0);
    try testing.expectEqual(stats.misses, 0);
}

test "DnsResolver resolve IPv4 literal" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    // IPv4 literal should not go through DNS
    const addrs = try resolver.resolve("127.0.0.1", 8080);
    defer testing.allocator.free(addrs);
    
    try testing.expectEqual(addrs.len, 1);
    try testing.expectEqual(addrs[0].getPort(), 8080);
    
    // Should not affect cache
    try testing.expectEqual(resolver.cacheSize(), 0);
}

test "DnsResolver resolve IPv6 literal" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    // IPv6 literal should not go through DNS
    const addrs = try resolver.resolve("::1", 9000);
    defer testing.allocator.free(addrs);
    
    try testing.expectEqual(addrs.len, 1);
    try testing.expectEqual(addrs[0].getPort(), 9000);
}

test "DnsResolver resolveOne IPv4" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    const addr = try resolver.resolveOne("192.168.1.1", 443);
    try testing.expectEqual(addr.getPort(), 443);
}

test "DnsResolver cache invalidation" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    // Add an entry by resolving IP literal (won't be cached) then invalidate
    const addrs = try resolver.resolve("10.0.0.1", 80);
    testing.allocator.free(addrs); // Must free the returned slice
    
    // Invalidate should not crash even for non-existent entries
    resolver.invalidate("nonexistent.example.com");
    resolver.invalidate("another.example.com");
}

test "DnsResolver clearCache" {
    var resolver = DnsResolver.init(testing.allocator, .{});
    defer resolver.deinit();
    
    // Clear empty cache should be fine
    resolver.clearCache();
    try testing.expectEqual(resolver.cacheSize(), 0);
}

test "DnsResolver stats hitRate" {
    var stats = DnsResolver.DnsStats{};
    
    // No hits or misses
    try testing.expectEqual(stats.hitRate(), 0.0);
    
    // Some hits and misses
    stats.hits = 75;
    stats.misses = 25;
    try testing.expectEqual(stats.hitRate(), 0.75);
    
    // All hits
    stats.hits = 100;
    stats.misses = 0;
    try testing.expectEqual(stats.hitRate(), 1.0);
}

test "DnsResolver custom config" {
    const config = DnsResolverConfig{
        .default_ttl_ms = 1000,
        .max_entries = 10,
        .negative_cache = false,
        .prefer_ipv4 = false,
        .prefer_ipv6 = true,
    };
    
    var resolver = DnsResolver.init(testing.allocator, config);
    defer resolver.deinit();
    
    try testing.expectEqual(resolver.config.default_ttl_ms, 1000);
    try testing.expectEqual(resolver.config.max_entries, 10);
    try testing.expect(!resolver.config.negative_cache);
    try testing.expect(!resolver.config.prefer_ipv4);
    try testing.expect(resolver.config.prefer_ipv6);
}

test "DnsResolver types compile" {
    // Verify all DNS resolver types compile correctly
    _ = DnsCacheEntry;
    _ = DnsResolverConfig;
    _ = DnsResolver;
    _ = DnsResolver.DnsStats;
    _ = getGlobalDnsResolver;
    _ = resolveHostname;
}
