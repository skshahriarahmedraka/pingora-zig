# HTTP/2 Support

Pingora-Zig provides comprehensive HTTP/2 protocol support including frame parsing, HPACK header compression, stream multiplexing, and flow control.

## Overview

HTTP/2 (RFC 7540) improves upon HTTP/1.1 with:
- **Binary framing** - More efficient parsing
- **Multiplexing** - Multiple requests over a single connection
- **Header compression** - HPACK reduces overhead (RFC 7541)
- **Flow control** - Per-stream and connection-level
- **Server push** - Proactive resource delivery

## HPACK Header Compression

HPACK is the header compression format for HTTP/2, defined in RFC 7541.

### Encoding Headers

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create encoder with default dynamic table size (4096 bytes)
    var encoder = pingora.http2.HpackEncoder.init(allocator, .{});
    defer encoder.deinit();

    // Define headers to encode
    const headers = [_]pingora.http2.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/api/users" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = "accept", .value = "application/json" },
        .{ .name = "user-agent", .value = "pingora-zig/1.0" },
    };

    // Encode to HPACK format
    const encoded = try encoder.encode(&headers);
    defer allocator.free(encoded);

    std.debug.print("Encoded {d} headers into {d} bytes\n", .{ 
        headers.len, 
        encoded.len 
    });
}
```

### Decoding Headers

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn decodeHeaders(allocator: std.mem.Allocator, data: []const u8) !void {
    var decoder = pingora.http2.HpackDecoder.init(allocator, .{});
    defer decoder.deinit();

    const headers = try decoder.decode(data);
    defer allocator.free(headers);

    for (headers) |h| {
        std.debug.print("{s}: {s}\n", .{ h.name, h.value });
    }
}
```

### Huffman Encoding

HPACK uses Huffman coding for additional compression:

```zig
const pingora = @import("pingora");

// Encode string with Huffman coding
var buf: [256]u8 = undefined;
const encoded = pingora.http2.huffman.encode("application/json", &buf);

// Decode Huffman-encoded string
var decoded_buf: [256]u8 = undefined;
const decoded = try pingora.http2.huffman.decode(encoded, &decoded_buf);
```

## HTTP/2 Frames

### Frame Types

| Frame Type | Code | Description |
|------------|------|-------------|
| DATA | 0x0 | Request/response body |
| HEADERS | 0x1 | HTTP headers |
| PRIORITY | 0x2 | Stream priority |
| RST_STREAM | 0x3 | Stream termination |
| SETTINGS | 0x4 | Connection settings |
| PUSH_PROMISE | 0x5 | Server push |
| PING | 0x6 | Connection health check |
| GOAWAY | 0x7 | Graceful shutdown |
| WINDOW_UPDATE | 0x8 | Flow control |
| CONTINUATION | 0x9 | Header continuation |

### Parsing Frames

```zig
const pingora = @import("pingora");

pub fn parseFrame(data: []const u8) !void {
    var parser = pingora.http2.FrameParser.init();
    
    if (try parser.parse(data)) |frame| {
        std.debug.print("Frame type: {s}\n", .{@tagName(frame.frame_type)});
        std.debug.print("Stream ID: {d}\n", .{frame.stream_id});
        std.debug.print("Flags: 0x{x}\n", .{frame.flags});
        std.debug.print("Payload length: {d}\n", .{frame.payload.len});
    }
}
```

### Building Frames

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn buildHeadersFrame(allocator: std.mem.Allocator) ![]u8 {
    // First encode headers with HPACK
    var encoder = pingora.http2.HpackEncoder.init(allocator, .{});
    defer encoder.deinit();

    const headers = [_]pingora.http2.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/json" },
    };

    const header_block = try encoder.encode(&headers);
    defer allocator.free(header_block);

    // Build HEADERS frame
    return try pingora.http2.FrameBuilder.buildHeadersFrame(
        allocator,
        1,                    // stream ID
        header_block,
        .{
            .end_headers = true,
            .end_stream = false,
        },
    );
}
```

## Stream Management

HTTP/2 multiplexes multiple streams over a single connection:

```zig
const pingora = @import("pingora");

const Stream = struct {
    id: u32,
    state: State,
    send_window: i32,
    recv_window: i32,

    const State = enum {
        idle,
        open,
        half_closed_local,
        half_closed_remote,
        closed,
    };
};

// Stream IDs:
// - Client-initiated: odd numbers (1, 3, 5, ...)
// - Server-initiated: even numbers (2, 4, 6, ...)
// - Connection-level: 0
```

## Flow Control

HTTP/2 provides per-stream and connection-level flow control:

```zig
const pingora = @import("pingora");

// Default window size: 65,535 bytes
const DEFAULT_WINDOW_SIZE = 65535;

// Send WINDOW_UPDATE to increase receive window
pub fn buildWindowUpdate(stream_id: u32, increment: u32) ![]u8 {
    return pingora.http2.FrameBuilder.buildWindowUpdateFrame(
        stream_id,
        increment,
    );
}
```

## Settings

Configure HTTP/2 connection parameters:

```zig
const pingora = @import("pingora");

const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
};

// Build SETTINGS frame
pub fn buildSettings(settings: Settings) ![]u8 {
    return pingora.http2.FrameBuilder.buildSettingsFrame(settings);
}

// Build SETTINGS ACK
pub fn buildSettingsAck() []u8 {
    return pingora.http2.FrameBuilder.buildSettingsAckFrame();
}
```

## Connection Preface

HTTP/2 connections begin with a connection preface:

```zig
// Client connection preface (24 bytes)
const CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// After sending preface, client sends SETTINGS frame
// Server responds with its own SETTINGS frame
```

## Best Practices

1. **Reuse connections** - HTTP/2 is designed for long-lived connections
2. **Set appropriate window sizes** - Balance memory usage and throughput
3. **Handle GOAWAY gracefully** - Don't start new streams after receiving GOAWAY
4. **Implement proper flow control** - Send WINDOW_UPDATE before windows are exhausted
5. **Use header compression** - HPACK significantly reduces overhead for repeated headers

## See Also

- [HTTP/3 & QUIC](http3.md) - Next generation HTTP
- [Connection Pooling](pooling.md) - Connection management
- [Proxy Phases](phase.md) - Request lifecycle
