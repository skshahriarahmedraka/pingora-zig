//! Simple Reverse Proxy Example
//!
//! This example demonstrates a basic reverse proxy that forwards
//! requests to a single upstream backend server.
//!
//! Usage:
//!   zig build-exe examples/simple_reverse_proxy.zig -M root=src/lib.zig
//!   ./simple_reverse_proxy
//!
//! Then test with:
//!   curl http://localhost:8080/

const std = @import("std");
const pingora = @import("../src/lib.zig");

const http = pingora.http;
const http_parser = pingora.http_parser;

/// Configuration for the reverse proxy
const Config = struct {
    /// Port to listen on
    listen_port: u16 = 8080,
    /// Upstream server address
    upstream_host: []const u8 = "127.0.0.1",
    /// Upstream server port
    upstream_port: u16 = 8000,
};

/// Simple reverse proxy implementation
pub const SimpleReverseProxy = struct {
    allocator: std.mem.Allocator,
    config: Config,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: Config) Self {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Forward a request to the upstream and return the response
    pub fn proxyRequest(
        self: *Self,
        request: []const u8,
    ) ![]u8 {
        // Parse the incoming request
        var headers_buf: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
        const parsed = try http_parser.parseRequestFull(request, &headers_buf);

        if (parsed == null) {
            return error.InvalidRequest;
        }

        // Build upstream request
        var upstream_request = std.ArrayList(u8).init(self.allocator);
        defer upstream_request.deinit();

        const writer = upstream_request.writer();

        // Request line
        try writer.print("{s} {s} HTTP/1.1\r\n", .{
            parsed.?.method,
            parsed.?.path,
        });

        // Forward headers, replacing Host
        for (parsed.?.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Host")) {
                try writer.print("Host: {s}:{d}\r\n", .{
                    self.config.upstream_host,
                    self.config.upstream_port,
                });
            } else {
                try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
            }
        }

        // Add proxy headers
        try writer.writeAll("X-Forwarded-By: pingora-zig\r\n");
        try writer.writeAll("\r\n");

        // Connect to upstream and send request
        const response = try self.sendToUpstream(upstream_request.items);
        return response;
    }

    fn sendToUpstream(self: *Self, request: []const u8) ![]u8 {
        // In a real implementation, this would use pingora's connection pool
        // For this example, we create a simple TCP connection

        const address = std.net.Address.parseIp4(self.config.upstream_host, self.config.upstream_port) catch {
            return error.InvalidUpstreamAddress;
        };

        const stream = std.net.tcpConnectToAddress(address) catch {
            return error.UpstreamConnectionFailed;
        };
        defer stream.close();

        // Send request
        _ = stream.write(request) catch {
            return error.UpstreamWriteFailed;
        };

        // Read response
        var response = std.ArrayList(u8).init(self.allocator);
        errdefer response.deinit();

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stream.read(&buf) catch break;
            if (n == 0) break;
            try response.appendSlice(buf[0..n]);

            // Check if we've received complete response
            if (std.mem.indexOf(u8, response.items, "\r\n\r\n")) |header_end| {
                // Check for Content-Length
                var resp_headers: [http_parser.MAX_HEADERS]http_parser.HeaderRef = undefined;
                if (http_parser.parseResponseFull(response.items, &resp_headers)) |parsed_resp| {
                    if (http_parser.findContentLength(parsed_resp.headers)) |content_length| {
                        const body_start = header_end + 4;
                        const body_len = response.items.len - body_start;
                        if (body_len >= content_length) break;
                    }
                } else |_| {}
            }
        }

        return response.toOwnedSlice();
    }

    /// Add security headers to response
    pub fn addSecurityHeaders(response: *std.ArrayList(u8)) !void {
        // Find end of headers
        if (std.mem.indexOf(u8, response.items, "\r\n\r\n")) |pos| {
            const security_headers =
                "X-Content-Type-Options: nosniff\r\n" ++
                "X-Frame-Options: DENY\r\n" ++
                "X-XSS-Protection: 1; mode=block\r\n";

            try response.insertSlice(pos + 2, security_headers);
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = Config{
        .listen_port = 8080,
        .upstream_host = "127.0.0.1",
        .upstream_port = 8000,
    };

    var proxy = SimpleReverseProxy.init(allocator, config);

    std.debug.print(
        \\
        \\=== Simple Reverse Proxy ===
        \\Listening on: http://localhost:{d}
        \\Upstream: http://{s}:{d}
        \\
        \\Press Ctrl+C to stop.
        \\
    , .{ config.listen_port, config.upstream_host, config.upstream_port });

    // Create TCP listener
    const address = try std.net.Address.parseIp4("127.0.0.1", config.listen_port);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    // Accept connections
    while (true) {
        var conn = server.accept() catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
            continue;
        };

        // Handle connection (in production, use thread pool)
        handleConnection(allocator, &proxy, &conn) catch |err| {
            std.debug.print("Connection error: {}\n", .{err});
        };
        conn.stream.close();
    }
}

fn handleConnection(
    allocator: std.mem.Allocator,
    proxy: *SimpleReverseProxy,
    conn: *std.net.Server.Connection,
) !void {
    var buf: [8192]u8 = undefined;
    const n = try conn.stream.read(&buf);
    if (n == 0) return;

    const request = buf[0..n];
    std.debug.print("Received request: {d} bytes\n", .{n});

    // Proxy the request
    const response = proxy.proxyRequest(request) catch |err| {
        std.debug.print("Proxy error: {}\n", .{err});
        // Send error response
        const error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
        _ = try conn.stream.write(error_response);
        return;
    };
    defer allocator.free(response);

    // Send response to client
    _ = try conn.stream.write(response);
}

test "SimpleReverseProxy init" {
    const allocator = std.testing.allocator;
    const config = Config{};
    var proxy = SimpleReverseProxy.init(allocator, config);
    _ = &proxy;
}
