# HTTP/3 & QUIC Support

Pingora-Zig provides HTTP/3 protocol support built on top of QUIC transport, offering improved performance and reliability compared to TCP-based HTTP.

## Overview

### What is QUIC?

QUIC (RFC 9000) is a UDP-based transport protocol that provides:
- **Encrypted by default** - TLS 1.3 integrated into the protocol
- **Multiplexed streams** - No head-of-line blocking at transport layer
- **Connection migration** - Survive network changes (e.g., WiFi to cellular)
- **0-RTT connection establishment** - Faster initial connections

### What is HTTP/3?

HTTP/3 (RFC 9114) is HTTP over QUIC, providing:
- **Same semantics as HTTP/1.1 and HTTP/2** - Methods, headers, status codes
- **QPACK header compression** - Similar to HPACK but designed for QUIC
- **Stream-per-request** - Independent streams without head-of-line blocking

## Requirements

HTTP/3 support requires the quiche library:

```bash
# Build with QUIC support
zig build -Dquiche=true

# Run QUIC tests
zig build test-quiche -Dquiche=true
```

## QUIC Transport

### Error Codes

```zig
const pingora = @import("pingora");

// QUIC transport error codes (RFC 9000)
const TransportError = pingora.quic.TransportError;

// Common errors:
// - no_error (0x00) - No error
// - internal_error (0x01) - Implementation error
// - connection_refused (0x02) - Server refusing connection
// - flow_control_error (0x03) - Flow control violated
// - stream_limit_error (0x04) - Too many streams
```

### Connection Configuration

```zig
const pingora = @import("pingora");

const QuicConfig = struct {
    /// Maximum idle timeout in milliseconds
    max_idle_timeout_ms: u64 = 30_000,
    
    /// Maximum UDP payload size
    max_udp_payload_size: u64 = 1350,
    
    /// Initial maximum data (connection-level)
    initial_max_data: u64 = 10_000_000,
    
    /// Initial maximum stream data (per-stream)
    initial_max_stream_data_bidi_local: u64 = 1_000_000,
    initial_max_stream_data_bidi_remote: u64 = 1_000_000,
    initial_max_stream_data_uni: u64 = 1_000_000,
    
    /// Maximum concurrent streams
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    
    /// Enable 0-RTT
    enable_early_data: bool = true,
};
```

### Stream Types

QUIC supports four types of streams:

| Type | Initiator | Direction |
|------|-----------|-----------|
| Client-initiated bidirectional | Client | Both |
| Server-initiated bidirectional | Server | Both |
| Client-initiated unidirectional | Client | Client → Server |
| Server-initiated unidirectional | Server | Server → Client |

```zig
// Stream IDs encode type in lower 2 bits:
// 0b00: Client-initiated bidirectional
// 0b01: Server-initiated bidirectional
// 0b10: Client-initiated unidirectional
// 0b11: Server-initiated unidirectional

pub fn streamType(stream_id: u64) StreamType {
    return @enumFromInt(stream_id & 0x3);
}
```

## HTTP/3 Protocol

### Frame Types

```zig
const pingora = @import("pingora");

// HTTP/3 frame types (RFC 9114)
const FrameType = pingora.http3.FrameType;

// DATA (0x00) - Request/response body
// HEADERS (0x01) - HTTP headers (QPACK encoded)
// CANCEL_PUSH (0x03) - Cancel server push
// SETTINGS (0x04) - Connection settings
// PUSH_PROMISE (0x05) - Server push
// GOAWAY (0x07) - Graceful shutdown
// MAX_PUSH_ID (0x0D) - Maximum push ID
```

### Error Codes

```zig
const pingora = @import("pingora");

// HTTP/3 error codes (RFC 9114)
const ErrorCode = pingora.http3.ErrorCode;

// h3_no_error (0x100) - No error
// h3_general_protocol_error (0x101) - Protocol error
// h3_internal_error (0x102) - Internal error
// h3_stream_creation_error (0x103) - Stream creation failed
// h3_closed_critical_stream (0x104) - Critical stream closed
// h3_frame_unexpected (0x105) - Unexpected frame
// h3_frame_error (0x106) - Frame format error
// h3_excessive_load (0x107) - Excessive load
// h3_settings_error (0x109) - Settings error
// h3_request_cancelled (0x10C) - Request cancelled
```

### Parsing Frames

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn parseH3Frame(data: []const u8) !void {
    var parser = pingora.http3.FrameParser.init();
    
    if (try parser.parse(data)) |frame| {
        switch (frame.frame_type) {
            .data => {
                std.debug.print("DATA frame: {d} bytes\n", .{frame.payload.len});
            },
            .headers => {
                std.debug.print("HEADERS frame\n", .{});
                // Decode with QPACK
            },
            .settings => {
                std.debug.print("SETTINGS frame\n", .{});
            },
            .goaway => {
                std.debug.print("GOAWAY frame\n", .{});
            },
            else => {},
        }
    }
}
```

## QPACK Header Compression

QPACK (RFC 9204) is the header compression format for HTTP/3.

### Key Differences from HPACK

| Feature | HPACK (HTTP/2) | QPACK (HTTP/3) |
|---------|---------------|----------------|
| Ordering | Strict ordering | Out-of-order delivery |
| Streams | Single stream | Encoder/decoder streams |
| Blocking | Can block | Configurable blocking |

### Encoding Headers

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn encodeQpackHeaders(allocator: std.mem.Allocator) !void {
    var encoder = pingora.http3.QpackEncoder.init(allocator, .{
        .max_table_capacity = 4096,
        .blocked_streams = 100,
    });
    defer encoder.deinit();

    const headers = [_]pingora.http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/api/data" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    const encoded = try encoder.encode(&headers, 0); // stream_id = 0
    defer allocator.free(encoded.header_block);

    std.debug.print("Encoded to {d} bytes\n", .{encoded.header_block.len});
}
```

### Static Table

QPACK includes a static table of common headers (RFC 9204 Appendix A):

| Index | Name | Value |
|-------|------|-------|
| 0 | :authority | (empty) |
| 1 | :path | / |
| 15 | :method | GET |
| 17 | :method | POST |
| 24 | :status | 200 |
| ... | ... | ... |

## Variable-Length Integers

HTTP/3 uses variable-length integer encoding (RFC 9000):

```zig
const pingora = @import("pingora");

// Encode integer
var buf: [8]u8 = undefined;
const len = pingora.http3.encodeVarint(12345, &buf);

// Decode integer
const result = try pingora.http3.decodeVarint(buf[0..len]);
std.debug.print("Value: {d}\n", .{result.value});
```

| Prefix | Length | Range |
|--------|--------|-------|
| 0b00 | 1 byte | 0-63 |
| 0b01 | 2 bytes | 0-16383 |
| 0b10 | 4 bytes | 0-1073741823 |
| 0b11 | 8 bytes | 0-4611686018427387903 |

## Connection Establishment

### Client Handshake

```
Client                                  Server
   |                                      |
   |  Initial (CRYPTO + Client Hello)     |
   |------------------------------------->|
   |                                      |
   |  Initial (CRYPTO + Server Hello)     |
   |  Handshake (CRYPTO + Encrypted Ext)  |
   |<-------------------------------------|
   |                                      |
   |  Handshake (CRYPTO + Finished)       |
   |------------------------------------->|
   |                                      |
   |  1-RTT Application Data              |
   |<------------------------------------>|
```

### 0-RTT Resumption

```
Client                                  Server
   |                                      |
   |  Initial + 0-RTT (early data)        |
   |------------------------------------->|
   |                                      |
   |  Initial + Handshake + 1-RTT         |
   |<-------------------------------------|
```

## HTTP/3 Connection Setup

After QUIC handshake, HTTP/3 requires:

1. **Create control streams** - Unidirectional streams for SETTINGS
2. **Exchange SETTINGS** - Both sides send HTTP/3 settings
3. **Create QPACK streams** - Encoder and decoder streams

```
Control Stream (Server -> Client): SETTINGS
Control Stream (Client -> Server): SETTINGS
QPACK Encoder Stream (Server -> Client)
QPACK Decoder Stream (Client -> Server)
QPACK Encoder Stream (Client -> Server)
QPACK Decoder Stream (Server -> Client)
```

## Best Practices

1. **Use 0-RTT carefully** - Early data may be replayed; only for idempotent requests
2. **Set appropriate limits** - Configure stream and data limits based on use case
3. **Handle migration** - QUIC connections can migrate; maintain connection state
4. **Monitor congestion** - QUIC has built-in congestion control
5. **Fallback to HTTP/2** - Not all clients support HTTP/3; provide fallback

## See Also

- [HTTP/2](http2.md) - TCP-based HTTP/2
- [Connection Pooling](pooling.md) - Connection management
- [TLS Configuration](conf.md#tls) - TLS settings
