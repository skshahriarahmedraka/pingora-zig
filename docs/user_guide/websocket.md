# WebSocket Support

Pingora-Zig provides full WebSocket protocol support (RFC 6455) with per-message deflate compression (RFC 7692).

## Overview

WebSocket enables bidirectional, full-duplex communication over a single TCP connection. It's ideal for:
- Real-time notifications
- Chat applications
- Live data feeds
- Gaming
- Collaborative editing

## Basic Concepts

### WebSocket Handshake

WebSocket connections begin with an HTTP upgrade handshake:

```
Client Request:
GET /ws HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

Server Response:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### Frame Types

| Opcode | Type | Description |
|--------|------|-------------|
| 0x0 | Continuation | Fragment continuation |
| 0x1 | Text | UTF-8 text data |
| 0x2 | Binary | Binary data |
| 0x8 | Close | Connection close |
| 0x9 | Ping | Keep-alive ping |
| 0xA | Pong | Ping response |

## Client Usage

### Creating a Handshake

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn createHandshake(allocator: std.mem.Allocator) ![]u8 {
    var client = pingora.websocket.WebSocketClient.init(allocator);
    defer client.deinit();

    // Create handshake request
    const handshake = client.createHandshake("example.com", "/ws");
    
    // Add optional subprotocols
    handshake.addProtocol("chat");
    handshake.addProtocol("json");

    // Build HTTP request
    return try handshake.build(allocator);
}
```

### Validating Server Response

```zig
const pingora = @import("pingora");

pub fn validateResponse(client: *pingora.websocket.WebSocketClient, response: []const u8) !void {
    // Parse and validate the 101 response
    try client.validateHandshakeResponse(response);
    
    // Check accepted subprotocol
    if (client.getAcceptedProtocol()) |protocol| {
        std.debug.print("Using protocol: {s}\n", .{protocol});
    }
}
```

### Sending Messages

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn sendMessages(allocator: std.mem.Allocator) !void {
    var client = pingora.websocket.WebSocketClient.init(allocator);
    defer client.deinit();

    // Send text message
    const text_frame = try client.sendText("Hello, WebSocket!");
    defer allocator.free(text_frame);

    // Send binary message
    const binary_data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const binary_frame = try client.sendBinary(&binary_data);
    defer allocator.free(binary_frame);

    // Send ping
    const ping_frame = try client.sendPing("ping");
    defer allocator.free(ping_frame);

    // Send close
    const close_frame = try client.sendClose(1000, "Goodbye");
    defer allocator.free(close_frame);
}
```

### Receiving Messages

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn receiveMessage(client: *pingora.websocket.WebSocketClient, data: []const u8) !void {
    if (try client.processFrame(data)) |message| {
        defer message.deinit();

        switch (message.opcode) {
            .text => {
                std.debug.print("Text: {s}\n", .{message.data});
            },
            .binary => {
                std.debug.print("Binary: {d} bytes\n", .{message.data.len});
            },
            .ping => {
                // Send pong response
                const pong = try client.sendPong(message.data);
                defer client.allocator.free(pong);
            },
            .pong => {
                std.debug.print("Received pong\n", .{});
            },
            .close => {
                std.debug.print("Connection closed\n", .{});
            },
            else => {},
        }
    }
}
```

## Server Usage

### Accepting Connections

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn acceptWebSocket(allocator: std.mem.Allocator, request: []const u8) ![]u8 {
    var server = pingora.websocket.WebSocketServer.init(allocator);
    defer server.deinit();

    // Validate client handshake
    const handshake = try server.parseHandshake(request);

    // Check requested subprotocols
    for (handshake.protocols) |protocol| {
        if (std.mem.eql(u8, protocol, "chat")) {
            server.selectProtocol("chat");
            break;
        }
    }

    // Build 101 response
    return try server.acceptHandshake(handshake);
}
```

### Server Frame Handling

```zig
const pingora = @import("pingora");

pub fn handleServerFrame(server: *pingora.websocket.WebSocketServer, data: []const u8) !void {
    // Server frames are masked by client
    if (try server.processFrame(data)) |message| {
        defer message.deinit();
        
        // Process message...
        
        // Server frames are NOT masked when sending
        const response = try server.sendText("Response");
        defer server.allocator.free(response);
    }
}
```

## Per-Message Deflate Compression

RFC 7692 defines WebSocket compression using the DEFLATE algorithm.

### Enabling Compression

```zig
const pingora = @import("pingora");

pub fn enableCompression(client: *pingora.websocket.WebSocketClient) !void {
    // Request compression in handshake
    client.requestPerMessageDeflate(.{
        .client_max_window_bits = 15,
        .server_max_window_bits = 15,
        .client_no_context_takeover = false,
        .server_no_context_takeover = false,
    });

    // After handshake, enable if server accepted
    if (client.compressionAccepted()) {
        try client.enablePerMessageDeflate(.{});
    }
}
```

### Compression Options

| Option | Description | Default |
|--------|-------------|---------|
| `client_max_window_bits` | Client LZ77 window size (8-15) | 15 |
| `server_max_window_bits` | Server LZ77 window size (8-15) | 15 |
| `client_no_context_takeover` | Reset compression context per message | false |
| `server_no_context_takeover` | Reset decompression context per message | false |

### Sending Compressed Messages

```zig
const pingora = @import("pingora");

pub fn sendCompressed(client: *pingora.websocket.WebSocketClient) !void {
    // Messages are automatically compressed if enabled
    const frame = try client.sendText("This message will be compressed");
    defer client.allocator.free(frame);
    
    // The RSV1 bit is set to indicate compression
}
```

## Frame Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

### Frame Flags

| Flag | Bit | Description |
|------|-----|-------------|
| FIN | 0 | Final fragment |
| RSV1 | 1 | Per-message compression |
| RSV2 | 2 | Reserved |
| RSV3 | 3 | Reserved |
| MASK | 8 | Payload is masked |

## Close Codes

| Code | Meaning |
|------|---------|
| 1000 | Normal closure |
| 1001 | Going away |
| 1002 | Protocol error |
| 1003 | Unsupported data type |
| 1007 | Invalid payload data |
| 1008 | Policy violation |
| 1009 | Message too big |
| 1010 | Extension required |
| 1011 | Internal server error |

## Proxy WebSocket Connections

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn proxyWebSocket(
    client_conn: *Connection,
    upstream_conn: *Connection,
) !void {
    // Bidirectional forwarding
    while (true) {
        // Forward client -> upstream
        if (client_conn.read()) |data| {
            try upstream_conn.write(data);
        }
        
        // Forward upstream -> client
        if (upstream_conn.read()) |data| {
            try client_conn.write(data);
        }
    }
}
```

## Best Practices

1. **Always respond to pings** - Send pong with same payload
2. **Use compression for text** - Significant size reduction for JSON/text
3. **Handle fragmentation** - Large messages may be fragmented
4. **Implement timeouts** - Close idle connections
5. **Validate UTF-8** - Text frames must be valid UTF-8
6. **Limit message size** - Prevent memory exhaustion attacks

## See Also

- [HTTP/2](http2.md) - HTTP/2 protocol support
- [Proxy Phases](phase.md) - Request lifecycle
- [Compression](compression.md) - HTTP compression
