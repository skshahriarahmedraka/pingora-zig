# Internals

A deep dive into Pingora-Zig's architecture and implementation.

## Module Hierarchy

```
Level 5: proxy.zig
    │
    ├── Level 4: cache.zig, http2.zig, websocket.zig
    │       │
    │       ├── Level 3: http_client.zig, http_server.zig
    │       │       │    load_balancer.zig, upstream.zig, protocols.zig
    │       │       │
    │       │       ├── Level 2: header_serde.zig, runtime.zig, tls.zig, openssl.zig
    │       │       │       │
    │       │       │       ├── Level 1: http.zig, http_parser.zig, limits.zig
    │       │       │       │       │    memory_cache.zig, pool.zig
    │       │       │       │       │
    │       │       │       │       └── Level 0: error.zig, timeout.zig, lru.zig
    │       │       │       │                    tinyufo.zig, ketama.zig, linked_list.zig
```

## Memory Management

### Allocator Strategy

All modules use explicit allocators passed at initialization:

```zig
pub const HttpProxy = struct {
    allocator: Allocator,
    // ...

    pub fn init(allocator: Allocator, config: Config) !HttpProxy {
        return .{
            .allocator = allocator,
            .pool = try ConnectionPool.init(allocator),
            .cache = try HttpCache.init(allocator, config.cache),
            // ...
        };
    }

    pub fn deinit(self: *HttpProxy) void {
        self.pool.deinit();
        self.cache.deinit();
        // ...
    }
};
```

### Arena Allocators for Requests

Per-request allocations use arena allocators for fast cleanup:

```zig
fn handleRequest(self: *HttpProxy, conn: *Connection) !void {
    // Create arena for this request
    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();
    const request_allocator = arena.allocator();

    // All request-scoped allocations use request_allocator
    var session = Session.init(request_allocator);
    // ...
}
```

### Buffer Pooling

Reusable buffers reduce allocation overhead:

```zig
pub const BufferPool = struct {
    free_list: std.ArrayList(*Buffer),
    buffer_size: usize,

    pub fn acquire(self: *BufferPool) !*Buffer {
        if (self.free_list.popOrNull()) |buf| {
            return buf;
        }
        return try self.allocateNew();
    }

    pub fn release(self: *BufferPool, buf: *Buffer) void {
        buf.reset();
        self.free_list.append(buf) catch {
            self.allocator.destroy(buf);
        };
    }
};
```

## HTTP Parsing

### Zero-Copy Parsing

The HTTP parser returns references into the input buffer:

```zig
pub const HeaderRef = struct {
    name: []const u8,   // Slice into input buffer
    value: []const u8,  // Slice into input buffer
};

pub fn parseRequest(input: []const u8) ParseError!ParsedRequest {
    // Returns slices into input, no allocation
    return .{
        .method = input[0..method_end],
        .path = input[method_end + 1 .. path_end],
        .version = input[path_end + 1 .. version_end],
        .headers = headers[0..header_count],
        .bytes_consumed = total_bytes,
    };
}
```

### Incremental Parsing

Handles partial data for streaming:

```zig
pub fn parseRequest(input: []const u8) ParseError!ParsedRequest {
    // Find end of request line
    const line_end = std.mem.indexOf(u8, input, "\r\n") orelse {
        return error.IncompleteData;
    };

    // Find end of headers
    const header_end = std.mem.indexOf(u8, input, "\r\n\r\n") orelse {
        return error.IncompleteData;
    };

    // Parse complete request
    // ...
}
```

## Connection Pooling

### Pool Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ConnectionPool                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  pools: HashMap<HostPort, HostPool>                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│         ┌───────────────┼───────────────┐                  │
│         ▼               ▼               ▼                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │ HostPool   │  │ HostPool   │  │ HostPool   │           │
│  │ host:port1 │  │ host:port2 │  │ host:port3 │           │
│  ├────────────┤  ├────────────┤  ├────────────┤           │
│  │ idle: [C1] │  │ idle: []   │  │ idle: [C5] │           │
│  │       [C2] │  │            │  │       [C6] │           │
│  │ active: 3  │  │ active: 5  │  │ active: 1  │           │
│  └────────────┘  └────────────┘  └────────────┘           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Connection Lifecycle

```zig
pub const PooledConnection = struct {
    conn: TcpStream,
    created_at: i64,
    last_used: i64,
    requests_served: u32,
    state: State,

    pub const State = enum {
        idle,
        in_use,
        closing,
    };
};
```

## Cache Implementation

### TinyUFO Algorithm

Combines TinyLFU admission policy with S3-FIFO eviction:

```zig
pub const TinyUfo = struct {
    // Admission filter (TinyLFU)
    frequency: CountMinSketch,

    // S3-FIFO queues
    small_queue: FifoQueue,   // Recently added items
    main_queue: FifoQueue,    // Frequently accessed items
    ghost_queue: FifoQueue,   // Recently evicted (metadata only)

    pub fn get(self: *TinyUfo, key: []const u8) ?*Entry {
        if (self.main_queue.get(key)) |entry| {
            entry.frequency += 1;
            return entry;
        }
        if (self.small_queue.get(key)) |entry| {
            entry.frequency += 1;
            // Promote to main if accessed again
            if (entry.frequency > 1) {
                self.promote(entry);
            }
            return entry;
        }
        return null;
    }

    pub fn put(self: *TinyUfo, key: []const u8, value: anytype) void {
        // Check admission filter
        const estimated_freq = self.frequency.estimate(key);
        const victim_freq = self.small_queue.peekTail().?.frequency;

        if (estimated_freq > victim_freq) {
            // Admit new item
            self.small_queue.push(key, value);
        }
        // Else: reject (keep existing items)
    }
};
```

### HTTP Cache Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      HttpCache                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  index: HashMap<CacheKey, *CacheEntry>              │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eviction: TinyUfo                                  │   │
│  │  (manages eviction order)                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  storage: MemoryStorage                             │   │
│  │  (actual response data)                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## HTTP/2 Implementation

### Frame Processing

```zig
pub const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: FrameFlags,
    stream_id: u31,

    pub fn parse(data: []const u8) ?FrameHeader {
        if (data.len < 9) return null;

        return .{
            .length = (@as(u24, data[0]) << 16) |
                     (@as(u24, data[1]) << 8) |
                     data[2],
            .frame_type = @enumFromInt(data[3]),
            .flags = @bitCast(data[4]),
            .stream_id = (@as(u31, data[5] & 0x7f) << 24) |
                        (@as(u31, data[6]) << 16) |
                        (@as(u31, data[7]) << 8) |
                        data[8],
        };
    }
};
```

### HPACK Compression

Dynamic table for header compression:

```zig
pub const DynamicTable = struct {
    entries: std.ArrayList(TableEntry),
    size: usize,
    max_size: usize,

    pub fn add(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        const entry_size = 32 + name.len + value.len;

        // Evict if necessary
        while (self.size + entry_size > self.max_size) {
            self.evictOldest();
        }

        try self.entries.insert(0, .{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        });
        self.size += entry_size;
    }
};
```

### Stream Multiplexing

```zig
pub const Stream = struct {
    id: u31,
    state: StreamState,
    send_window: FlowControlWindow,
    recv_window: FlowControlWindow,
    priority: StreamPriority,

    pub const StreamState = enum {
        idle,
        reserved_local,
        reserved_remote,
        open,
        half_closed_local,
        half_closed_remote,
        closed,
    };
};
```

## WebSocket Implementation

### Frame Structure

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

### Per-Message Deflate

Uses zlib for compression:

```zig
pub const PerMessageDeflate = struct {
    deflate_stream: c.z_stream,
    inflate_stream: c.z_stream,
    params: PerMessageDeflateParams,

    pub fn compressMessage(self: *PerMessageDeflate, input: []const u8) ![]u8 {
        // Initialize deflate
        self.deflate_stream.next_in = input.ptr;
        self.deflate_stream.avail_in = @intCast(input.len);

        var output = std.ArrayList(u8).init(self.allocator);

        while (true) {
            var chunk: [4096]u8 = undefined;
            self.deflate_stream.next_out = &chunk;
            self.deflate_stream.avail_out = chunk.len;

            const ret = c.deflate(&self.deflate_stream, c.Z_SYNC_FLUSH);
            if (ret != c.Z_OK and ret != c.Z_STREAM_END) {
                return error.CompressionError;
            }

            const have = chunk.len - self.deflate_stream.avail_out;
            try output.appendSlice(chunk[0..have]);

            if (ret == c.Z_STREAM_END or self.deflate_stream.avail_out != 0) {
                break;
            }
        }

        // Remove trailing 0x00 0x00 0xff 0xff (per RFC 7692)
        if (output.items.len >= 4) {
            output.shrinkRetainingCapacity(output.items.len - 4);
        }

        return output.toOwnedSlice();
    }
};
```

## Load Balancing

### Ketama Consistent Hashing

```zig
pub const Continuum = struct {
    points: []Point,

    pub const Point = struct {
        hash: u32,
        backend_index: u32,
    };

    pub fn lookup(self: *Continuum, key: []const u8) u32 {
        const hash = hashKey(key);

        // Binary search for first point >= hash
        var left: usize = 0;
        var right: usize = self.points.len;

        while (left < right) {
            const mid = left + (right - left) / 2;
            if (self.points[mid].hash < hash) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        // Wrap around
        const index = if (left == self.points.len) 0 else left;
        return self.points[index].backend_index;
    }
};
```

## Testing Strategy

### Unit Tests

Each module has comprehensive unit tests:

```zig
test "HttpParser parses valid request" {
    const input = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const result = try parseRequestFull(input);

    try testing.expectEqualStrings("GET", result.method);
    try testing.expectEqualStrings("/path", result.path);
}
```

### Integration Tests

End-to-end tests verify component interaction:

```zig
test "integration: proxy session lifecycle" {
    // Create proxy
    var proxy = try HttpProxy.init(testing.allocator, config);
    defer proxy.deinit();

    // Simulate request
    var session = Session.init(testing.allocator);
    defer session.deinit();

    // Test full request flow
    try proxy.handleSession(&session);
}
```

### Fuzz Testing

Parser fuzzing for robustness:

```zig
test "fuzz HTTP parser" {
    // Random input should not crash
    var prng = std.rand.DefaultPrng.init(0);
    var buf: [1024]u8 = undefined;

    for (0..10000) |_| {
        prng.random().bytes(&buf);
        _ = parseRequest(&buf) catch {};
    }
}
```

## Performance Considerations

1. **Zero-copy parsing**: Avoid allocations in hot paths
2. **Connection pooling**: Reuse connections aggressively
3. **Buffer pooling**: Pre-allocate and reuse buffers
4. **Lock-free counters**: Use atomics for metrics
5. **Arena allocators**: Fast per-request cleanup
6. **Efficient eviction**: TinyUFO for cache management
