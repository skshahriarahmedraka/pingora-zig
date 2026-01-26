# HTTP Compression

Pingora-Zig provides comprehensive HTTP compression support with multiple algorithms and content negotiation.

## Supported Algorithms

| Algorithm | Content-Encoding | Compression Ratio | Speed |
|-----------|------------------|-------------------|-------|
| Gzip | `gzip` | Good | Fast |
| Deflate | `deflate` | Good | Fast |
| Zstd | `zstd` | Excellent | Very Fast |
| Brotli | `br` | Best | Slower |

## Algorithm Selection

### From Accept-Encoding

Parse client preferences and select the best algorithm:

```zig
const pingora = @import("pingora");

pub fn selectAlgorithm(accept_encoding: []const u8) ?pingora.CompressionAlgorithm {
    // Automatically selects best supported algorithm
    // Priority: zstd > brotli > gzip > deflate
    return pingora.CompressionAlgorithm.fromAcceptEncoding(accept_encoding);
}

// Examples:
// "gzip, deflate" -> .gzip
// "br, gzip" -> .brotli
// "zstd, br, gzip" -> .zstd
// "identity" -> .identity (no compression)
```

### From Content-Encoding

Detect compression of incoming responses:

```zig
const pingora = @import("pingora");

pub fn detectCompression(content_encoding: []const u8) ?pingora.CompressionAlgorithm {
    return pingora.CompressionAlgorithm.fromContentEncoding(content_encoding);
}
```

## Compressing Responses

### Basic Compression

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn compressResponse(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    // Create compression context
    var ctx = try pingora.ResponseCompressionCtx.init(allocator, .gzip, .default);
    defer ctx.deinit();

    // Compress data
    const compressed = try ctx.compress(body);
    
    // Get compression statistics
    const stats = ctx.getStats();
    std.debug.print("Compression ratio: {d:.2}%\n", .{stats.compressionRatio() * 100});
    
    return compressed;
}
```

### Compression Levels

```zig
const pingora = @import("pingora");

// Available levels (0-9)
const Level = pingora.CompressionLevel;

// Level.none (0) - No compression (store only)
// Level.fast (1) - Fastest compression
// Level.default (6) - Balanced
// Level.best (9) - Maximum compression

// Example: Fast compression for real-time responses
var ctx = try pingora.ResponseCompressionCtx.init(allocator, .gzip, .fast);

// Example: Maximum compression for static assets
var ctx = try pingora.ResponseCompressionCtx.init(allocator, .gzip, .best);
```

### Streaming Compression

For large responses, use streaming compression:

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn streamCompress(
    allocator: std.mem.Allocator,
    reader: anytype,
    writer: anytype,
) !void {
    var ctx = try pingora.ResponseCompressionCtx.init(allocator, .gzip, .default);
    defer ctx.deinit();

    var buf: [8192]u8 = undefined;
    
    while (true) {
        const n = try reader.read(&buf);
        if (n == 0) break;
        
        const compressed = try ctx.compressChunk(buf[0..n], false);
        defer allocator.free(compressed);
        
        try writer.writeAll(compressed);
    }
    
    // Flush remaining data
    const final = try ctx.compressChunk(&.{}, true);
    defer allocator.free(final);
    try writer.writeAll(final);
}
```

## Decompressing Responses

### Basic Decompression

```zig
const std = @import("std");
const pingora = @import("pingora");

pub fn decompressResponse(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var ctx = try pingora.ResponseDecompressionCtx.init(allocator, .gzip);
    defer ctx.deinit();

    return try ctx.decompress(compressed);
}
```

### Automatic Detection

```zig
const pingora = @import("pingora");

pub fn autoDecompress(
    allocator: std.mem.Allocator,
    data: []const u8,
    content_encoding: []const u8,
) ![]u8 {
    const algo = pingora.CompressionAlgorithm.fromContentEncoding(content_encoding) orelse {
        // Not compressed, return as-is
        return allocator.dupe(u8, data);
    };

    if (algo == .identity) {
        return allocator.dupe(u8, data);
    }

    var ctx = try pingora.ResponseDecompressionCtx.init(allocator, algo);
    defer ctx.deinit();

    return try ctx.decompress(data);
}
```

## Content Type Detection

### Compressible Types

```zig
const pingora = @import("pingora");

// Check if content type should be compressed
pub fn shouldCompress(content_type: []const u8) bool {
    return pingora.isCompressibleContentType(content_type);
}

// Default compressible types:
// - text/html
// - text/plain
// - text/css
// - text/javascript
// - application/javascript
// - application/json
// - application/xml
// - image/svg+xml
// - application/xhtml+xml
```

### Custom Compressible Types

```zig
const pingora = @import("pingora");

const custom_types = [_][]const u8{
    "application/wasm",
    "application/graphql",
    "text/csv",
};

pub fn shouldCompressCustom(content_type: []const u8) bool {
    // Check default types
    if (pingora.isCompressibleContentType(content_type)) {
        return true;
    }
    
    // Check custom types
    for (custom_types) |t| {
        if (std.mem.startsWith(u8, content_type, t)) {
            return true;
        }
    }
    
    return false;
}
```

### Minimum Size Threshold

```zig
const pingora = @import("pingora");

// Don't compress small responses (overhead > benefit)
const MIN_SIZE = pingora.DEFAULT_MIN_SIZE; // 256 bytes

pub fn shouldCompressSize(content_length: usize) bool {
    return content_length >= MIN_SIZE;
}
```

## Compression Statistics

```zig
const pingora = @import("pingora");

pub fn logCompressionStats(stats: pingora.CompressionStats) void {
    std.debug.print("Input: {d} bytes\n", .{stats.total_in});
    std.debug.print("Output: {d} bytes\n", .{stats.total_out});
    std.debug.print("Ratio: {d:.2}%\n", .{stats.compressionRatio() * 100});
    std.debug.print("Duration: {d}μs\n", .{stats.duration_ns / 1000});
}
```

## Proxy Compression Patterns

### Compress Upstream Response

```zig
const pingora = @import("pingora");

pub fn compressUpstreamResponse(
    allocator: std.mem.Allocator,
    response: *Response,
    accept_encoding: []const u8,
) !void {
    // Check if already compressed
    if (response.headers.get("Content-Encoding") != null) {
        return;
    }
    
    // Check content type
    const content_type = response.headers.get("Content-Type") orelse return;
    if (!pingora.isCompressibleContentType(content_type)) {
        return;
    }
    
    // Check size
    if (response.body.len < pingora.DEFAULT_MIN_SIZE) {
        return;
    }
    
    // Select algorithm
    const algo = pingora.CompressionAlgorithm.fromAcceptEncoding(accept_encoding) orelse return;
    if (algo == .identity) return;
    
    // Compress
    var ctx = try pingora.ResponseCompressionCtx.init(allocator, algo, .default);
    defer ctx.deinit();
    
    const compressed = try ctx.compress(response.body);
    allocator.free(response.body);
    response.body = compressed;
    
    // Update headers
    try response.headers.put("Content-Encoding", algo.toContentEncoding());
    try response.headers.put("Content-Length", std.fmt.comptimePrint("{d}", .{compressed.len}));
    try response.headers.append("Vary", "Accept-Encoding");
}
```

### Decompress for Processing

```zig
const pingora = @import("pingora");

pub fn decompressForProcessing(
    allocator: std.mem.Allocator,
    response: *Response,
) !void {
    const encoding = response.headers.get("Content-Encoding") orelse return;
    
    const algo = pingora.CompressionAlgorithm.fromContentEncoding(encoding) orelse return;
    if (algo == .identity) return;
    
    var ctx = try pingora.ResponseDecompressionCtx.init(allocator, algo);
    defer ctx.deinit();
    
    const decompressed = try ctx.decompress(response.body);
    allocator.free(response.body);
    response.body = decompressed;
    
    // Remove Content-Encoding header
    response.headers.remove("Content-Encoding");
    try response.headers.put("Content-Length", std.fmt.comptimePrint("{d}", .{decompressed.len}));
}
```

## Algorithm Comparison

### Compression Ratio (typical HTML/JSON)

| Algorithm | Level | Ratio | Speed |
|-----------|-------|-------|-------|
| Gzip | fast | ~65% | 200 MB/s |
| Gzip | default | ~70% | 100 MB/s |
| Gzip | best | ~72% | 20 MB/s |
| Zstd | fast | ~68% | 400 MB/s |
| Zstd | default | ~73% | 200 MB/s |
| Brotli | fast | ~70% | 150 MB/s |
| Brotli | default | ~78% | 50 MB/s |

### Recommendations

| Use Case | Recommended |
|----------|-------------|
| Real-time API responses | Zstd (fast) or Gzip (fast) |
| Static assets | Brotli (default) or Zstd (default) |
| Legacy client support | Gzip |
| Maximum compression | Brotli (best) |

## Best Practices

1. **Check Accept-Encoding** - Only compress if client supports it
2. **Skip small responses** - Compression overhead exceeds benefit under ~256 bytes
3. **Skip already compressed** - Don't double-compress (images, video, etc.)
4. **Use appropriate level** - Balance CPU usage vs compression ratio
5. **Add Vary header** - Ensure caches differentiate by encoding
6. **Consider Zstd** - Best balance of speed and compression for modern clients

## See Also

- [WebSocket](websocket.md) - WebSocket per-message deflate
- [Proxy Phases](phase.md) - Where to apply compression
- [Configuration](conf.md) - Compression settings
