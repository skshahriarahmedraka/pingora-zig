//! pingora-zig: Raw CONNECT Protocol
//!
//! HTTP CONNECT method support for tunneling TCP connections through HTTP proxies.
//! Implements RFC 7231 Section 4.3.6.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const http = @import("http.zig");
const protocols = @import("protocols.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// CONNECT Request/Response
// ============================================================================

/// CONNECT request configuration
pub const ConnectRequest = struct {
    /// Target host to connect to
    host: []const u8,
    /// Target port
    port: u16,
    /// Optional authentication (Proxy-Authorization header)
    auth: ?ProxyAuth = null,
    /// Additional headers to send
    extra_headers: ?[]const Header = null,
    /// Connection timeout in nanoseconds (0 = no timeout)
    timeout_ns: u64 = 30 * std.time.ns_per_s,

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    /// Format the request target (host:port)
    pub fn formatTarget(self: *const ConnectRequest, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.host, self.port }) catch error.BufferTooSmall;
    }
};

/// Proxy authentication types
pub const ProxyAuth = union(enum) {
    /// Basic authentication (username:password base64 encoded)
    basic: BasicAuth,
    /// Bearer token
    bearer: []const u8,
    /// Raw header value
    raw: []const u8,

    pub const BasicAuth = struct {
        username: []const u8,
        password: []const u8,
    };

    /// Format as Proxy-Authorization header value
    pub fn format(self: ProxyAuth, allocator: Allocator) ![]u8 {
        return switch (self) {
            .basic => |auth| {
                // Format: "Basic base64(username:password)"
                const credentials_len = auth.username.len + 1 + auth.password.len;
                const credentials = try allocator.alloc(u8, credentials_len);
                defer allocator.free(credentials);

                @memcpy(credentials[0..auth.username.len], auth.username);
                credentials[auth.username.len] = ':';
                @memcpy(credentials[auth.username.len + 1 ..], auth.password);

                const encoded_len = std.base64.standard.Encoder.calcSize(credentials_len);
                const result = try allocator.alloc(u8, 6 + encoded_len); // "Basic " + encoded
                @memcpy(result[0..6], "Basic ");
                _ = std.base64.standard.Encoder.encode(result[6..], credentials);

                return result;
            },
            .bearer => |token| {
                const result = try allocator.alloc(u8, 7 + token.len); // "Bearer " + token
                @memcpy(result[0..7], "Bearer ");
                @memcpy(result[7..], token);
                return result;
            },
            .raw => |value| {
                return allocator.dupe(u8, value);
            },
        };
    }
};

/// CONNECT response result
pub const ConnectResponse = struct {
    /// HTTP status code (200 = success)
    status_code: u16,
    /// Status reason phrase
    reason: ?[]const u8,
    /// Response headers
    headers: std.StringHashMapUnmanaged([]const u8),
    /// Whether tunnel was established
    success: bool,
    /// Allocator used
    allocator: Allocator,

    pub fn deinit(self: *ConnectResponse) void {
        if (self.reason) |r| {
            self.allocator.free(r);
        }
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit(self.allocator);
    }

    /// Check if proxy requires authentication
    pub fn requiresAuth(self: *const ConnectResponse) bool {
        return self.status_code == 407;
    }

    /// Get Proxy-Authenticate header if present
    pub fn getProxyAuthenticate(self: *const ConnectResponse) ?[]const u8 {
        return self.headers.get("proxy-authenticate");
    }
};

// ============================================================================
// CONNECT Client
// ============================================================================

/// CONNECT tunnel client
pub const ConnectClient = struct {
    allocator: Allocator,
    /// Proxy address
    proxy_host: []const u8,
    /// Proxy port
    proxy_port: u16,

    const Self = @This();

    pub fn init(allocator: Allocator, proxy_host: []const u8, proxy_port: u16) Self {
        return .{
            .allocator = allocator,
            .proxy_host = proxy_host,
            .proxy_port = proxy_port,
        };
    }

    /// Establish a CONNECT tunnel
    pub fn connect(self: *Self, request: *const ConnectRequest) !ConnectResult {
        // Build CONNECT request
        var target_buf: [256]u8 = undefined;
        const target = try request.formatTarget(&target_buf);

        var req = try http.RequestHeader.build(self.allocator, .CONNECT, target, null);
        defer req.deinit();

        // Add Host header
        try req.appendHeader("Host", target);

        // Add Proxy-Authorization if present
        if (request.auth) |auth| {
            const auth_value = try auth.format(self.allocator);
            defer self.allocator.free(auth_value);
            try req.appendHeader("Proxy-Authorization", auth_value);
        }

        // Add extra headers
        if (request.extra_headers) |headers| {
            for (headers) |h| {
                try req.appendHeader(h.name, h.value);
            }
        }

        // Add Proxy-Connection header
        try req.appendHeader("Proxy-Connection", "keep-alive");

        // Serialize the request
        const request_data = try self.serializeRequest(&req);
        defer self.allocator.free(request_data);

        return ConnectResult{
            .request_data = try self.allocator.dupe(u8, request_data),
            .state = .pending,
            .allocator = self.allocator,
        };
    }

    /// Serialize request to bytes
    fn serializeRequest(self: *Self, req: *http.RequestHeader) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8){};
        errdefer buffer.deinit(self.allocator);

        // Request line: CONNECT host:port HTTP/1.1\r\n
        try buffer.appendSlice(self.allocator, "CONNECT ");
        try buffer.appendSlice(self.allocator, req.uri.raw);
        try buffer.appendSlice(self.allocator, " HTTP/1.1\r\n");

        // Headers
        for (req.headers.headers.items) |header| {
            try buffer.appendSlice(self.allocator, header.name.bytes);
            try buffer.appendSlice(self.allocator, ": ");
            try buffer.appendSlice(self.allocator, header.value);
            try buffer.appendSlice(self.allocator, "\r\n");
        }

        // End of headers
        try buffer.appendSlice(self.allocator, "\r\n");

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Parse CONNECT response
    pub fn parseResponse(self: *Self, data: []const u8) !ConnectResponse {
        // Find end of status line
        const status_end = std.mem.indexOf(u8, data, "\r\n") orelse return error.InvalidResponse;
        const status_line = data[0..status_end];

        // Parse status line: HTTP/1.1 200 Connection established
        if (!std.mem.startsWith(u8, status_line, "HTTP/1.")) {
            return error.InvalidResponse;
        }

        // Find status code
        const space1 = std.mem.indexOf(u8, status_line, " ") orelse return error.InvalidResponse;
        const rest = status_line[space1 + 1 ..];
        const space2 = std.mem.indexOf(u8, rest, " ");

        const code_str = if (space2) |s| rest[0..s] else rest;
        const status_code = std.fmt.parseInt(u16, code_str, 10) catch return error.InvalidResponse;

        const reason = if (space2) |s| rest[s + 1 ..] else null;

        // Parse headers
        var headers = std.StringHashMapUnmanaged([]const u8){};
        errdefer {
            var iter = headers.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            headers.deinit(self.allocator);
        }

        var header_start = status_end + 2;
        while (header_start < data.len) {
            const header_end = std.mem.indexOf(u8, data[header_start..], "\r\n") orelse break;
            const header_line = data[header_start..][0..header_end];

            if (header_line.len == 0) break; // Empty line = end of headers

            if (std.mem.indexOf(u8, header_line, ": ")) |sep| {
                const name = try self.allocator.dupe(u8, header_line[0..sep]);
                errdefer self.allocator.free(name);
                const value = try self.allocator.dupe(u8, header_line[sep + 2 ..]);
                try headers.put(self.allocator, name, value);
            }

            header_start += header_end + 2;
        }

        return ConnectResponse{
            .status_code = status_code,
            .reason = if (reason) |r| try self.allocator.dupe(u8, r) else null,
            .headers = headers,
            .success = status_code >= 200 and status_code < 300,
            .allocator = self.allocator,
        };
    }
};

/// Result of initiating a CONNECT tunnel
pub const ConnectResult = struct {
    /// Serialized request data to send to proxy
    request_data: []u8,
    /// Current state
    state: State,
    /// Allocator
    allocator: Allocator,

    pub const State = enum {
        /// Request built, waiting to send
        pending,
        /// Request sent, waiting for response
        sent,
        /// Tunnel established
        established,
        /// Failed
        failed,
    };

    pub fn deinit(self: *ConnectResult) void {
        self.allocator.free(self.request_data);
    }
};

// ============================================================================
// Tunnel Stream
// ============================================================================

/// Represents an established CONNECT tunnel
pub const TunnelStream = struct {
    /// Raw stream after CONNECT handshake
    /// In a real implementation, this would be a socket or connection handle
    state: State,
    /// Target host
    target_host: []const u8,
    /// Target port
    target_port: u16,
    /// Statistics
    stats: Stats,
    /// Allocator
    allocator: Allocator,

    pub const State = enum {
        /// Tunnel is open and ready
        open,
        /// Tunnel is closing
        closing,
        /// Tunnel is closed
        closed,
        /// Tunnel encountered an error
        errored,
    };

    pub const Stats = struct {
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
        established_at: i64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, target_host: []const u8, target_port: u16) !Self {
        return .{
            .state = .open,
            .target_host = try allocator.dupe(u8, target_host),
            .target_port = target_port,
            .stats = .{ .established_at = std.time.timestamp() },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.target_host);
        self.state = .closed;
    }

    /// Check if tunnel is open
    pub fn isOpen(self: *const Self) bool {
        return self.state == .open;
    }

    /// Close the tunnel
    pub fn close(self: *Self) void {
        if (self.state == .open) {
            self.state = .closing;
        }
        self.state = .closed;
    }

    /// Record bytes sent through tunnel
    pub fn recordSent(self: *Self, bytes: u64) void {
        self.stats.bytes_sent += bytes;
    }

    /// Record bytes received through tunnel
    pub fn recordReceived(self: *Self, bytes: u64) void {
        self.stats.bytes_received += bytes;
    }

    /// Get tunnel uptime in seconds
    pub fn uptime(self: *const Self) i64 {
        return std.time.timestamp() - self.stats.established_at;
    }
};

// ============================================================================
// CONNECT Handler (Server-side)
// ============================================================================

/// Configuration for handling CONNECT requests
pub const ConnectHandlerConfig = struct {
    /// Maximum idle time for tunnel (nanoseconds, 0 = no limit)
    idle_timeout_ns: u64 = 300 * std.time.ns_per_s,
    /// Maximum tunnel duration (nanoseconds, 0 = no limit)
    max_duration_ns: u64 = 0,
    /// Allowed destination ports (empty = all allowed)
    allowed_ports: []const u16 = &[_]u16{},
    /// Blocked destination ports
    blocked_ports: []const u16 = &[_]u16{},
    /// Whether to require authentication
    require_auth: bool = false,
};

/// Handler for incoming CONNECT requests (proxy server side)
pub const ConnectHandler = struct {
    config: ConnectHandlerConfig,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ConnectHandlerConfig) Self {
        return .{
            .config = config,
            .allocator = allocator,
        };
    }

    /// Validate a CONNECT request
    pub fn validateRequest(self: *Self, req: *const http.RequestHeader) ConnectValidation {
        // Check method
        if (req.method != .CONNECT) {
            return .{ .allowed = false, .reason = .invalid_method };
        }

        // Parse target
        const target = req.uri.raw;
        const host_port = self.parseTarget(target) catch {
            return .{ .allowed = false, .reason = .invalid_target };
        };

        // Check port restrictions
        if (self.config.allowed_ports.len > 0) {
            var allowed = false;
            for (self.config.allowed_ports) |p| {
                if (p == host_port.port) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                return .{ .allowed = false, .reason = .port_not_allowed };
            }
        }

        for (self.config.blocked_ports) |p| {
            if (p == host_port.port) {
                return .{ .allowed = false, .reason = .port_blocked };
            }
        }

        // Check authentication if required
        if (self.config.require_auth) {
            if (req.headers.get("Proxy-Authorization") == null) {
                return .{ .allowed = false, .reason = .auth_required };
            }
        }

        return .{
            .allowed = true,
            .reason = null,
            .host = host_port.host,
            .port = host_port.port,
        };
    }

    /// Parse host:port from CONNECT target
    fn parseTarget(_: *Self, target: []const u8) !HostPort {
        const colon = std.mem.lastIndexOf(u8, target, ":") orelse return error.InvalidTarget;
        const host = target[0..colon];
        const port_str = target[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidTarget;

        return .{ .host = host, .port = port };
    }

    /// Generate success response (200 Connection Established)
    pub fn successResponse(self: *Self) ![]u8 {
        const response = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: pingora-zig\r\n\r\n";
        return self.allocator.dupe(u8, response);
    }

    /// Generate error response
    pub fn errorResponse(self: *Self, status: u16, reason: []const u8) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "HTTP/1.1 ");

        var status_buf: [8]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch "500";
        try buf.appendSlice(self.allocator, status_str);
        try buf.appendSlice(self.allocator, " ");
        try buf.appendSlice(self.allocator, reason);
        try buf.appendSlice(self.allocator, "\r\n\r\n");

        return buf.toOwnedSlice(self.allocator);
    }

    /// Generate 407 Proxy Authentication Required response
    pub fn authRequiredResponse(self: *Self, realm: []const u8) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "HTTP/1.1 407 Proxy Authentication Required\r\n");
        try buf.appendSlice(self.allocator, "Proxy-Authenticate: Basic realm=\"");
        try buf.appendSlice(self.allocator, realm);
        try buf.appendSlice(self.allocator, "\"\r\n\r\n");

        return buf.toOwnedSlice(self.allocator);
    }
};

/// Host and port pair
pub const HostPort = struct {
    host: []const u8,
    port: u16,
};

/// Result of CONNECT request validation
pub const ConnectValidation = struct {
    allowed: bool,
    reason: ?DenyReason = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,

    pub const DenyReason = enum {
        invalid_method,
        invalid_target,
        port_not_allowed,
        port_blocked,
        auth_required,
        host_blocked,
    };

    pub fn statusCode(self: *const ConnectValidation) u16 {
        if (self.allowed) return 200;
        return switch (self.reason.?) {
            .invalid_method => 405,
            .invalid_target => 400,
            .port_not_allowed, .port_blocked, .host_blocked => 403,
            .auth_required => 407,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ConnectRequest formatTarget" {
    const request = ConnectRequest{
        .host = "example.com",
        .port = 443,
    };

    var buf: [256]u8 = undefined;
    const target = try request.formatTarget(&buf);
    try testing.expectEqualStrings("example.com:443", target);
}

test "ProxyAuth basic format" {
    const auth = ProxyAuth{ .basic = .{ .username = "user", .password = "pass" } };
    const formatted = try auth.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.startsWith(u8, formatted, "Basic "));
}

test "ProxyAuth bearer format" {
    const auth = ProxyAuth{ .bearer = "mytoken123" };
    const formatted = try auth.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("Bearer mytoken123", formatted);
}

test "ConnectClient connect" {
    var client = ConnectClient.init(testing.allocator, "proxy.example.com", 8080);

    const request = ConnectRequest{
        .host = "target.example.com",
        .port = 443,
    };

    var result = try client.connect(&request);
    defer result.deinit();

    try testing.expect(result.request_data.len > 0);
    try testing.expect(std.mem.indexOf(u8, result.request_data, "CONNECT target.example.com:443") != null);
    try testing.expect(std.mem.indexOf(u8, result.request_data, "HTTP/1.1") != null);
}

test "ConnectClient parseResponse success" {
    var client = ConnectClient.init(testing.allocator, "proxy.example.com", 8080);

    const response_data = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n";
    var response = try client.parseResponse(response_data);
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status_code);
    try testing.expect(response.success);
    try testing.expectEqualStrings("Connection Established", response.reason.?);
}

test "ConnectClient parseResponse auth required" {
    var client = ConnectClient.init(testing.allocator, "proxy.example.com", 8080);

    const response_data = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
    var response = try client.parseResponse(response_data);
    defer response.deinit();

    try testing.expectEqual(@as(u16, 407), response.status_code);
    try testing.expect(!response.success);
    try testing.expect(response.requiresAuth());
}

test "TunnelStream init and close" {
    var tunnel = try TunnelStream.init(testing.allocator, "example.com", 443);
    defer tunnel.deinit();

    try testing.expect(tunnel.isOpen());
    try testing.expectEqualStrings("example.com", tunnel.target_host);
    try testing.expectEqual(@as(u16, 443), tunnel.target_port);

    tunnel.recordSent(100);
    tunnel.recordReceived(200);
    try testing.expectEqual(@as(u64, 100), tunnel.stats.bytes_sent);
    try testing.expectEqual(@as(u64, 200), tunnel.stats.bytes_received);

    tunnel.close();
    try testing.expect(!tunnel.isOpen());
}

test "ConnectHandler validateRequest" {
    var handler = ConnectHandler.init(testing.allocator, .{
        .blocked_ports = &[_]u16{25}, // Block SMTP
    });

    // Valid request
    var req1 = try http.RequestHeader.build(testing.allocator, .CONNECT, "example.com:443", null);
    defer req1.deinit();
    const result1 = handler.validateRequest(&req1);
    try testing.expect(result1.allowed);

    // Blocked port
    var req2 = try http.RequestHeader.build(testing.allocator, .CONNECT, "mail.example.com:25", null);
    defer req2.deinit();
    const result2 = handler.validateRequest(&req2);
    try testing.expect(!result2.allowed);
    try testing.expectEqual(ConnectValidation.DenyReason.port_blocked, result2.reason.?);
}

test "ConnectHandler allowed ports" {
    var handler = ConnectHandler.init(testing.allocator, .{
        .allowed_ports = &[_]u16{ 80, 443 }, // Only HTTP/HTTPS
    });

    // Allowed port
    var req1 = try http.RequestHeader.build(testing.allocator, .CONNECT, "example.com:443", null);
    defer req1.deinit();
    const result1 = handler.validateRequest(&req1);
    try testing.expect(result1.allowed);

    // Not allowed port
    var req2 = try http.RequestHeader.build(testing.allocator, .CONNECT, "example.com:8080", null);
    defer req2.deinit();
    const result2 = handler.validateRequest(&req2);
    try testing.expect(!result2.allowed);
    try testing.expectEqual(ConnectValidation.DenyReason.port_not_allowed, result2.reason.?);
}

test "ConnectHandler responses" {
    var handler = ConnectHandler.init(testing.allocator, .{});

    // Success response
    const success = try handler.successResponse();
    defer testing.allocator.free(success);
    try testing.expect(std.mem.indexOf(u8, success, "200 Connection Established") != null);

    // Error response
    const err_resp = try handler.errorResponse(403, "Forbidden");
    defer testing.allocator.free(err_resp);
    try testing.expect(std.mem.indexOf(u8, err_resp, "403 Forbidden") != null);

    // Auth required response
    const auth_resp = try handler.authRequiredResponse("Proxy");
    defer testing.allocator.free(auth_resp);
    try testing.expect(std.mem.indexOf(u8, auth_resp, "407") != null);
    try testing.expect(std.mem.indexOf(u8, auth_resp, "Proxy-Authenticate") != null);
}

test "ConnectValidation statusCode" {
    const allowed = ConnectValidation{ .allowed = true };
    try testing.expectEqual(@as(u16, 200), allowed.statusCode());

    const auth_req = ConnectValidation{ .allowed = false, .reason = .auth_required };
    try testing.expectEqual(@as(u16, 407), auth_req.statusCode());

    const blocked = ConnectValidation{ .allowed = false, .reason = .port_blocked };
    try testing.expectEqual(@as(u16, 403), blocked.statusCode());
}
