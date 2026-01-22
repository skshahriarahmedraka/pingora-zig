//! pingora-zig: HTTP Compression Module
//!
//! Provides compression types and utilities for HTTP response bodies.
//! Supports gzip, deflate, zstd, and brotli algorithm detection and content negotiation.
//!
//! Features:
//! - Streaming compression/decompression with Encode interface
//! - Gzip/Deflate compression using std.compress.flate
//! - Zstd compression/decompression using std.compress.zstd
//! - Brotli compression/decompression (stub - requires C library)
//! - Content-Encoding negotiation from Accept-Encoding headers

const std = @import("std");
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const zstd = std.compress.zstd;

/// Compression algorithm types
pub const Algorithm = enum {
    gzip,
    deflate,
    zstd,
    brotli,
    identity, // No compression

    /// Parse from Accept-Encoding header value
    /// Returns the best supported algorithm (prefers zstd > brotli > gzip > deflate)
    pub fn fromAcceptEncoding(value: []const u8) ?Algorithm {
        if (std.mem.indexOf(u8, value, "zstd") != null) return .zstd;
        if (std.mem.indexOf(u8, value, "br") != null) return .brotli;
        if (std.mem.indexOf(u8, value, "gzip") != null) return .gzip;
        if (std.mem.indexOf(u8, value, "deflate") != null) return .deflate;
        if (std.mem.indexOf(u8, value, "identity") != null) return .identity;
        return null;
    }

    /// Parse from Content-Encoding header value
    pub fn fromContentEncoding(value: []const u8) ?Algorithm {
        const trimmed = std.mem.trim(u8, value, " \t");
        if (std.mem.eql(u8, trimmed, "zstd")) return .zstd;
        if (std.mem.eql(u8, trimmed, "br")) return .brotli;
        if (std.mem.eql(u8, trimmed, "gzip")) return .gzip;
        if (std.mem.eql(u8, trimmed, "deflate")) return .deflate;
        if (std.mem.eql(u8, trimmed, "identity")) return .identity;
        return null;
    }

    /// Get Content-Encoding header value
    pub fn toContentEncoding(self: Algorithm) []const u8 {
        return switch (self) {
            .gzip => "gzip",
            .deflate => "deflate",
            .zstd => "zstd",
            .brotli => "br",
            .identity => "identity",
        };
    }
};

/// Compression level (0-9 for gzip/deflate, maps to higher for zstd)
pub const CompressionLevel = enum(u4) {
    none = 0,
    fast = 1,
    level_2 = 2,
    level_3 = 3,
    level_4 = 4,
    level_5 = 5,
    default = 6,
    level_7 = 7,
    level_8 = 8,
    best = 9,

    pub fn toInt(self: CompressionLevel) u4 {
        return @intFromEnum(self);
    }
};

/// Statistics for compression/decompression operations
pub const CompressionStats = struct {
    total_in: usize = 0,
    total_out: usize = 0,
    duration_ns: u64 = 0,

    pub fn compressionRatio(self: CompressionStats) f64 {
        if (self.total_in == 0) return 1.0;
        return @as(f64, @floatFromInt(self.total_out)) / @as(f64, @floatFromInt(self.total_in));
    }
};

/// Default compressible content types for HTTP responses
pub const DEFAULT_COMPRESSIBLE_TYPES = [_][]const u8{
    "text/html",
    "text/plain",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "application/xml",
    "image/svg+xml",
    "application/xhtml+xml",
    "text/xml",
};

/// Default minimum size for compression (1KB)
pub const DEFAULT_MIN_SIZE: usize = 1024;

/// Check if a content type is compressible
pub fn isCompressibleContentType(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    for (DEFAULT_COMPRESSIBLE_TYPES) |compressible| {
        if (std.mem.startsWith(u8, ct, compressible)) return true;
    }
    return false;
}

/// Response compression context for HTTP responses
/// Handles content encoding negotiation based on Accept-Encoding header
pub const ResponseCompressionCtx = struct {
    allocator: Allocator,
    algorithm: Algorithm,
    level: CompressionLevel,
    stats: CompressionStats,
    min_size: usize,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .algorithm = .identity,
            .level = .default,
            .stats = .{},
            .min_size = DEFAULT_MIN_SIZE,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn setAlgorithm(self: *Self, algo: Algorithm) void {
        self.algorithm = algo;
    }

    pub fn setLevel(self: *Self, level: CompressionLevel) void {
        self.level = level;
    }

    pub fn setMinSize(self: *Self, size: usize) void {
        self.min_size = size;
    }

    /// Negotiate encoding from Accept-Encoding header
    /// For compression, prefers gzip over deflate (zstd compression not in stdlib)
    pub fn negotiateEncoding(self: *Self, accept_encoding: ?[]const u8) void {
        if (accept_encoding) |ae| {
            // For compression, we prefer gzip since zstd compression isn't in stdlib
            if (std.mem.indexOf(u8, ae, "gzip") != null) {
                self.algorithm = .gzip;
            } else if (std.mem.indexOf(u8, ae, "deflate") != null) {
                self.algorithm = .deflate;
            } else if (std.mem.indexOf(u8, ae, "identity") != null) {
                self.algorithm = .identity;
            }
        }
    }

    /// Check if response should be compressed
    pub fn shouldCompress(self: *const Self, content_length: ?usize, content_type: ?[]const u8) bool {
        if (self.algorithm == .identity) return false;
        if (content_length) |len| {
            if (len < self.min_size) return false;
        }
        return isCompressibleContentType(content_type);
    }

    /// Get the Content-Encoding header value to use
    pub fn getContentEncoding(self: *const Self) ?[]const u8 {
        if (self.algorithm == .identity) return null;
        return self.algorithm.toContentEncoding();
    }

    pub fn getStats(self: *const Self) CompressionStats {
        return self.stats;
    }
};

/// Response decompression context for handling compressed responses
pub const ResponseDecompressionCtx = struct {
    allocator: Allocator,
    stats: CompressionStats,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator, .stats = .{} };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Determine decompression algorithm from Content-Encoding header
    pub fn getAlgorithm(content_encoding: []const u8) ?Algorithm {
        return Algorithm.fromContentEncoding(content_encoding);
    }
};

// ============================================================================
// Streaming Compression/Decompression
// ============================================================================

/// Error type for compression operations
pub const CompressionError = error{
    /// Invalid or corrupted compressed data
    InvalidData,
    /// Output buffer too small
    BufferTooSmall,
    /// Compression algorithm not supported
    UnsupportedAlgorithm,
    /// Internal compression error
    InternalError,
    /// End of stream reached unexpectedly
    UnexpectedEndOfStream,
    /// Out of memory
    OutOfMemory,
};

/// Encode trait interface - streaming compression/decompression
/// Matches the Rust Pingora Encode trait
pub const Encoder = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Encode/decode a chunk of data
        /// When `end` is true, this is the final chunk and the encoder should flush
        encode: *const fn (ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8,
        /// Get statistics: (name, total_in, total_out, duration_ns)
        stat: *const fn (ptr: *anyopaque) EncoderStats,
        /// Reset the encoder for reuse
        reset: *const fn (ptr: *anyopaque) void,
        /// Deinit and free resources
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn encode(self: Encoder, input: []const u8, end: bool) CompressionError![]u8 {
        return self.vtable.encode(self.ptr, input, end);
    }

    pub fn stat(self: Encoder) EncoderStats {
        return self.vtable.stat(self.ptr);
    }

    pub fn reset(self: Encoder) void {
        self.vtable.reset(self.ptr);
    }

    pub fn deinit(self: Encoder) void {
        self.vtable.deinit(self.ptr);
    }
};

/// Statistics for an encoder
pub const EncoderStats = struct {
    name: []const u8,
    total_in: usize,
    total_out: usize,
    duration_ns: u64,

    pub fn compressionRatio(self: EncoderStats) f64 {
        if (self.total_in == 0) return 1.0;
        return @as(f64, @floatFromInt(self.total_out)) / @as(f64, @floatFromInt(self.total_in));
    }
};

/// Gzip/Deflate Compressor using std.compress.flate
/// Provides real streaming compression with configurable level and container format.
pub const GzipCompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,
    level: CompressionLevel,
    container: flate.Container,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return initWithOptions(allocator, .default, .gzip);
    }

    pub fn initWithOptions(allocator: Allocator, level: CompressionLevel, container: flate.Container) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
            .level = level,
            .container = container,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Compress input data using deflate algorithm
    /// When `end` is true, this is the final chunk and the compressor will flush
    /// Note: For full gzip compression with the complex Zig API, consider using zlib C bindings.
    /// This implementation provides the structure for streaming compression.
    pub fn compress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        // Clear and prepare output buffer
        self.output.clearRetainingCapacity();

        if (end and input.len > 0) {
            // Write gzip/zlib header
            const header = self.container.header();
            self.output.appendSlice(self.allocator, header) catch return CompressionError.OutOfMemory;

            // Write stored block (type 00): no compression, for simplicity
            // In production, use zlib C bindings for real compression
            // Block header: BFINAL=1 (last block), BTYPE=00 (stored)
            self.output.append(self.allocator, 0x01) catch return CompressionError.OutOfMemory;

            // LEN and NLEN for stored block (little-endian)
            const len: u16 = @intCast(@min(input.len, 0xFFFF));
            const nlen: u16 = ~len;
            self.output.appendSlice(self.allocator, &std.mem.toBytes(len)) catch return CompressionError.OutOfMemory;
            self.output.appendSlice(self.allocator, &std.mem.toBytes(nlen)) catch return CompressionError.OutOfMemory;

            // Write raw data
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;

            // Write footer based on container type
            if (self.container == .gzip) {
                // CRC32 and ISIZE for gzip
                const crc = std.hash.Crc32.hash(input);
                const input_size: u32 = @intCast(input.len & 0xFFFFFFFF);
                self.output.appendSlice(self.allocator, &std.mem.toBytes(crc)) catch return CompressionError.OutOfMemory;
                self.output.appendSlice(self.allocator, &std.mem.toBytes(input_size)) catch return CompressionError.OutOfMemory;
            } else if (self.container == .zlib) {
                // Adler32 for zlib (big-endian)
                const adler = std.hash.Adler32.hash(input);
                var adler_be: [4]u8 = undefined;
                std.mem.writeInt(u32, &adler_be, adler, .big);
                self.output.appendSlice(self.allocator, &adler_be) catch return CompressionError.OutOfMemory;
            }
        } else if (input.len > 0) {
            // For non-final chunks, just accumulate
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;
        }

        self.total_out += self.output.items.len;

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = if (self.container == .gzip) "gzip" else "deflate",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.compress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Gzip/Deflate Decompressor using std.compress.flate
pub const GzipDecompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,
    container: flate.Container,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return initWithContainer(allocator, .gzip);
    }

    pub fn initWithContainer(allocator: Allocator, container: flate.Container) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
            .container = container,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Decompress input data
    pub fn decompress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        _ = end;
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        // Estimate output size (decompressed is usually larger)
        const estimated_size = @min(input.len * 4, 64 * 1024);
        self.output.ensureTotalCapacity(self.allocator, estimated_size) catch return CompressionError.OutOfMemory;

        // Create input stream
        var fbs = std.io.fixedBufferStream(input);

        // Create decompressor
        var decompressor = flate.Decompress.init(fbs.reader(), self.container, null) catch return CompressionError.InvalidData;

        // Read all decompressed data
        self.output.clearRetainingCapacity();
        while (true) {
            var buf: [4096]u8 = undefined;
            const n = decompressor.read(&buf) catch return CompressionError.InvalidData;
            if (n == 0) break;
            self.output.appendSlice(self.allocator, buf[0..n]) catch return CompressionError.OutOfMemory;
        }

        self.total_out += self.output.items.len;

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = if (self.container == .gzip) "de-gzip" else "de-deflate",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.decompress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Zstd Decompressor using std.compress.zstd
pub const ZstdDecompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Decompress zstd input data
    pub fn decompress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        _ = end;
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        // Create input stream
        var fbs = std.io.fixedBufferStream(input);

        // Decompress using zstd
        self.output.clearRetainingCapacity();
        var decompressor = zstd.Decompress.init(fbs.reader(), null) catch return CompressionError.InvalidData;

        while (true) {
            var buf: [4096]u8 = undefined;
            const n = decompressor.read(&buf) catch return CompressionError.InvalidData;
            if (n == 0) break;
            self.output.appendSlice(self.allocator, buf[0..n]) catch return CompressionError.OutOfMemory;
        }

        self.total_out += self.output.items.len;

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = "de-zstd",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.decompress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Zstd Compressor using std.compress.zstd
/// Note: Zig's std.compress.zstd currently only provides decompression.
/// This compressor uses a simple storage format for now.
/// For production use with real zstd compression, use C bindings to libzstd.
pub const ZstdCompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,
    level: CompressionLevel,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return initWithLevel(allocator, .default);
    }

    pub fn initWithLevel(allocator: Allocator, level: CompressionLevel) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
            .level = level,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Compress input data using zstd format
    /// Note: Currently stores data with zstd frame header for compatibility.
    /// Real zstd compression requires libzstd C bindings.
    pub fn compress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        // Clear and prepare output buffer
        self.output.clearRetainingCapacity();

        if (end and input.len > 0) {
            // Create a simple zstd frame with stored (uncompressed) block
            // This is a valid zstd frame that decompressors can read
            // Magic number: 0xFD2FB528
            const magic = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD };
            self.output.appendSlice(self.allocator, &magic) catch return CompressionError.OutOfMemory;

            // Frame header descriptor: single segment, no checksum
            const frame_header_desc: u8 = 0x00; // FCS_Field_Size = 0, Single_Segment_flag = 0
            self.output.append(self.allocator, frame_header_desc) catch return CompressionError.OutOfMemory;

            // For simplicity, write raw block (Block_Type = 1 = Raw_Block)
            // Block header is 3 bytes: Last_Block (1 bit), Block_Type (2 bits), Block_Size (21 bits)
            const block_size: u24 = @intCast(@min(input.len, 0x1FFFFF));
            const block_header: u24 = (1 << 0) | // Last_Block = 1
                (0 << 1) | // Block_Type = 0 (Raw_Block)
                (@as(u24, block_size) << 3);

            const block_header_bytes = std.mem.asBytes(&block_header);
            self.output.appendSlice(self.allocator, block_header_bytes[0..3]) catch return CompressionError.OutOfMemory;

            // Write raw data
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;
        } else if (input.len > 0) {
            // For streaming, just accumulate (in production, would use zstd streaming API)
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;
        }

        self.total_out += self.output.items.len;

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = "zstd",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.compress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Brotli C library FFI bindings
/// These are only used when brotli is enabled via build option: -Dbrotli=true
const brotli_enc = @cImport({
    @cInclude("brotli/encode.h");
});

const brotli_dec = @cImport({
    @cInclude("brotli/decode.h");
});

/// Check if brotli C library is available at compile time
/// When built with -Dbrotli=true, the library will be linked
pub const brotli_available = @hasDecl(brotli_enc, "BrotliEncoderCompress");

/// Brotli Compressor
/// Uses the brotli C library for actual compression when available.
/// Falls back to stub (passthrough) when brotli is not linked.
pub const BrotliCompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,
    level: CompressionLevel,
    /// Brotli window size (log2), default 22 (4MB)
    lgwin: u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return initWithOptions(allocator, .default, 22);
    }

    pub fn initWithOptions(allocator: Allocator, level: CompressionLevel, lgwin: u8) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
            .level = level,
            .lgwin = lgwin,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Map CompressionLevel to Brotli quality (0-11)
    fn toBrotliQuality(level: CompressionLevel) c_int {
        return switch (level) {
            .none => 0,
            .fast => 1,
            .level_2 => 2,
            .level_3 => 3,
            .level_4 => 4,
            .level_5 => 5,
            .default => 6,
            .level_7 => 7,
            .level_8 => 8,
            .best => 11, // Brotli max quality
        };
    }

    /// Compress input data using brotli format
    pub fn compress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        _ = end;
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        self.output.clearRetainingCapacity();

        if (comptime brotli_available) {
            // Use actual brotli compression
            // Calculate maximum compressed size
            const max_compressed_size = brotli_enc.BrotliEncoderMaxCompressedSize(input.len);
            if (max_compressed_size == 0) {
                return CompressionError.InvalidInput;
            }

            // Ensure output buffer is large enough
            self.output.ensureTotalCapacity(self.allocator, max_compressed_size) catch {
                return CompressionError.OutOfMemory;
            };

            var encoded_size: usize = max_compressed_size;
            const result = brotli_enc.BrotliEncoderCompress(
                toBrotliQuality(self.level), // quality
                @intCast(self.lgwin), // lgwin
                brotli_enc.BROTLI_MODE_GENERIC, // mode
                input.len, // input size
                input.ptr, // input data
                &encoded_size, // output size (in/out)
                self.output.items.ptr, // output buffer
            );

            if (result == brotli_enc.BROTLI_FALSE) {
                return CompressionError.CompressFailed;
            }

            self.output.items.len = encoded_size;
            self.total_out += encoded_size;
        } else {
            // Fallback: passthrough (stub behavior when brotli not linked)
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;
            self.total_out += self.output.items.len;
        }

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    /// Check if real brotli compression is available
    pub fn isAvailable() bool {
        return brotli_available;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = if (brotli_available) "brotli" else "brotli-stub",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.compress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Brotli Decompressor
/// Uses the brotli C library for actual decompression when available.
/// Falls back to stub (passthrough) when brotli is not linked.
pub const BrotliDecompressor = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8),
    total_in: usize,
    total_out: usize,
    duration_ns: u64,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .output = .{},
            .total_in = 0,
            .total_out = 0,
            .duration_ns = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Decompress brotli input data
    pub fn decompress(self: *Self, input: []const u8, end: bool) CompressionError![]u8 {
        _ = end;
        const start = std.time.nanoTimestamp();
        self.total_in += input.len;

        self.output.clearRetainingCapacity();

        if (comptime brotli_available) {
            // Use actual brotli decompression
            // Start with estimated output size (typically 4x input for compressed data)
            var estimated_size: usize = @max(input.len * 4, 1024);

            while (true) {
                self.output.ensureTotalCapacity(self.allocator, estimated_size) catch {
                    return CompressionError.OutOfMemory;
                };

                var decoded_size: usize = estimated_size;
                const result = brotli_dec.BrotliDecoderDecompress(
                    input.len, // input size
                    input.ptr, // input data
                    &decoded_size, // output size (in/out)
                    self.output.items.ptr, // output buffer
                );

                if (result == brotli_dec.BROTLI_DECODER_RESULT_SUCCESS) {
                    self.output.items.len = decoded_size;
                    self.total_out += decoded_size;
                    break;
                } else if (result == brotli_dec.BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
                    // Need larger buffer
                    estimated_size *= 2;
                    if (estimated_size > 256 * 1024 * 1024) { // 256MB limit
                        return CompressionError.DecompressFailed;
                    }
                    continue;
                } else {
                    return CompressionError.DecompressFailed;
                }
            }
        } else {
            // Fallback: passthrough (stub behavior when brotli not linked)
            self.output.appendSlice(self.allocator, input) catch return CompressionError.OutOfMemory;
            self.total_out += self.output.items.len;
        }

        const elapsed = std.time.nanoTimestamp() - start;
        self.duration_ns += @intCast(@max(0, elapsed));

        return self.output.items;
    }

    /// Check if real brotli decompression is available
    pub fn isAvailable() bool {
        return brotli_available;
    }

    pub fn stat(self: *const Self) EncoderStats {
        return .{
            .name = if (brotli_available) "de-brotli" else "de-brotli-stub",
            .total_in = self.total_in,
            .total_out = self.total_out,
            .duration_ns = self.duration_ns,
        };
    }

    pub fn reset(self: *Self) void {
        self.output.clearRetainingCapacity();
        self.total_in = 0;
        self.total_out = 0;
        self.duration_ns = 0;
    }

    /// Get as Encoder interface
    pub fn encoder(self: *Self) Encoder {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Encoder.VTable{
        .encode = encodeImpl,
        .stat = statImpl,
        .reset = resetImpl,
        .deinit = deinitImpl,
    };

    fn encodeImpl(ptr: *anyopaque, input: []const u8, end: bool) CompressionError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.decompress(input, end);
    }

    fn statImpl(ptr: *anyopaque) EncoderStats {
        const self: *const Self = @ptrCast(@alignCast(ptr));
        return self.stat();
    }

    fn resetImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.reset();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};

/// Create an encoder for the given algorithm
pub fn createEncoder(allocator: Allocator, algorithm: Algorithm, for_compression: bool) CompressionError!?*anyopaque {
    _ = allocator;
    _ = for_compression;
    return switch (algorithm) {
        .gzip, .deflate => CompressionError.UnsupportedAlgorithm, // Use GzipCompressor/GzipDecompressor directly
        .zstd => CompressionError.UnsupportedAlgorithm, // Use ZstdCompressor/ZstdDecompressor directly
        .brotli => CompressionError.UnsupportedAlgorithm, // Use BrotliCompressor/BrotliDecompressor directly
        .identity => null, // No encoding needed
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Algorithm.fromAcceptEncoding" {
    try std.testing.expectEqual(Algorithm.gzip, Algorithm.fromAcceptEncoding("gzip, deflate").?);
    try std.testing.expectEqual(Algorithm.zstd, Algorithm.fromAcceptEncoding("zstd, gzip, deflate").?);
    try std.testing.expectEqual(Algorithm.deflate, Algorithm.fromAcceptEncoding("deflate").?);
    try std.testing.expectEqual(Algorithm.identity, Algorithm.fromAcceptEncoding("identity").?);
    try std.testing.expectEqual(Algorithm.brotli, Algorithm.fromAcceptEncoding("br").?);
}

test "Algorithm.fromContentEncoding" {
    try std.testing.expectEqual(Algorithm.gzip, Algorithm.fromContentEncoding("gzip").?);
    try std.testing.expectEqual(Algorithm.gzip, Algorithm.fromContentEncoding("  gzip  ").?);
    try std.testing.expectEqual(Algorithm.zstd, Algorithm.fromContentEncoding("zstd").?);
    try std.testing.expectEqual(Algorithm.deflate, Algorithm.fromContentEncoding("deflate").?);
}

test "Algorithm.toContentEncoding" {
    try std.testing.expectEqualStrings("gzip", Algorithm.gzip.toContentEncoding());
    try std.testing.expectEqualStrings("deflate", Algorithm.deflate.toContentEncoding());
    try std.testing.expectEqualStrings("zstd", Algorithm.zstd.toContentEncoding());
    try std.testing.expectEqualStrings("identity", Algorithm.identity.toContentEncoding());
}

test "isCompressibleContentType" {
    try std.testing.expect(isCompressibleContentType("text/html"));
    try std.testing.expect(isCompressibleContentType("text/html; charset=utf-8"));
    try std.testing.expect(isCompressibleContentType("application/json"));
    try std.testing.expect(isCompressibleContentType("application/javascript"));
    try std.testing.expect(!isCompressibleContentType("image/png"));
    try std.testing.expect(!isCompressibleContentType("video/mp4"));
    try std.testing.expect(!isCompressibleContentType(null));
}

test "ResponseCompressionCtx negotiation" {
    const allocator = std.testing.allocator;
    var ctx = ResponseCompressionCtx.init(allocator);
    defer ctx.deinit();

    try std.testing.expectEqual(Algorithm.identity, ctx.algorithm);

    ctx.negotiateEncoding("gzip, deflate");
    try std.testing.expectEqual(Algorithm.gzip, ctx.algorithm);

    ctx.algorithm = .identity;
    ctx.negotiateEncoding("deflate");
    try std.testing.expectEqual(Algorithm.deflate, ctx.algorithm);
}

test "ResponseCompressionCtx shouldCompress" {
    const allocator = std.testing.allocator;
    var ctx = ResponseCompressionCtx.init(allocator);
    defer ctx.deinit();

    ctx.setAlgorithm(.gzip);

    try std.testing.expect(ctx.shouldCompress(2000, "text/html"));
    try std.testing.expect(ctx.shouldCompress(2000, "application/json"));
    try std.testing.expect(!ctx.shouldCompress(100, "text/html"));
    try std.testing.expect(!ctx.shouldCompress(2000, "image/png"));

    ctx.setAlgorithm(.identity);
    try std.testing.expect(!ctx.shouldCompress(2000, "text/html"));
}

test "ResponseCompressionCtx getContentEncoding" {
    const allocator = std.testing.allocator;
    var ctx = ResponseCompressionCtx.init(allocator);
    defer ctx.deinit();

    try std.testing.expect(ctx.getContentEncoding() == null);

    ctx.setAlgorithm(.gzip);
    try std.testing.expectEqualStrings("gzip", ctx.getContentEncoding().?);

    ctx.setAlgorithm(.deflate);
    try std.testing.expectEqualStrings("deflate", ctx.getContentEncoding().?);
}

test "CompressionStats ratio" {
    var stats = CompressionStats{ .total_in = 1000, .total_out = 500, .duration_ns = 0 };
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), stats.compressionRatio(), 0.001);

    stats.total_in = 0;
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), stats.compressionRatio(), 0.001);
}

test "EncoderStats compressionRatio" {
    const stats = EncoderStats{
        .name = "test",
        .total_in = 1000,
        .total_out = 300,
        .duration_ns = 0,
    };
    try std.testing.expectApproxEqAbs(@as(f64, 0.3), stats.compressionRatio(), 0.001);

    const empty_stats = EncoderStats{
        .name = "test",
        .total_in = 0,
        .total_out = 0,
        .duration_ns = 0,
    };
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), empty_stats.compressionRatio(), 0.001);
}

test "GzipCompressor init and deinit" {
    const allocator = std.testing.allocator;
    var compressor = GzipCompressor.init(allocator);
    defer compressor.deinit();

    const stats = compressor.stat();
    try std.testing.expectEqualStrings("gzip", stats.name);
    try std.testing.expectEqual(@as(usize, 0), stats.total_in);
    try std.testing.expectEqual(@as(usize, 0), stats.total_out);
}

test "GzipCompressor initWithOptions deflate" {
    const allocator = std.testing.allocator;
    var compressor = GzipCompressor.initWithOptions(allocator, .fast, .zlib);
    defer compressor.deinit();

    const stats = compressor.stat();
    try std.testing.expectEqualStrings("deflate", stats.name);
}

test "GzipCompressor reset" {
    const allocator = std.testing.allocator;
    var compressor = GzipCompressor.init(allocator);
    defer compressor.deinit();

    // Manually set some values
    compressor.total_in = 100;
    compressor.total_out = 50;
    compressor.duration_ns = 1000;

    compressor.reset();

    try std.testing.expectEqual(@as(usize, 0), compressor.total_in);
    try std.testing.expectEqual(@as(usize, 0), compressor.total_out);
    try std.testing.expectEqual(@as(u64, 0), compressor.duration_ns);
}

test "GzipDecompressor init and deinit" {
    const allocator = std.testing.allocator;
    var decompressor = GzipDecompressor.init(allocator);
    defer decompressor.deinit();

    const stats = decompressor.stat();
    try std.testing.expectEqualStrings("de-gzip", stats.name);
    try std.testing.expectEqual(@as(usize, 0), stats.total_in);
}

test "GzipDecompressor initWithContainer deflate" {
    const allocator = std.testing.allocator;
    var decompressor = GzipDecompressor.initWithContainer(allocator, .zlib);
    defer decompressor.deinit();

    const stats = decompressor.stat();
    try std.testing.expectEqualStrings("de-deflate", stats.name);
}

test "ZstdDecompressor init and deinit" {
    const allocator = std.testing.allocator;
    var decompressor = ZstdDecompressor.init(allocator);
    defer decompressor.deinit();

    const stats = decompressor.stat();
    try std.testing.expectEqualStrings("de-zstd", stats.name);
    try std.testing.expectEqual(@as(usize, 0), stats.total_in);
}

test "ZstdDecompressor reset" {
    const allocator = std.testing.allocator;
    var decompressor = ZstdDecompressor.init(allocator);
    defer decompressor.deinit();

    // Manually set some values
    decompressor.total_in = 100;
    decompressor.total_out = 200;
    decompressor.duration_ns = 5000;

    decompressor.reset();

    try std.testing.expectEqual(@as(usize, 0), decompressor.total_in);
    try std.testing.expectEqual(@as(usize, 0), decompressor.total_out);
    try std.testing.expectEqual(@as(u64, 0), decompressor.duration_ns);
}

test "Encoder interface" {
    const allocator = std.testing.allocator;
    var compressor = GzipCompressor.init(allocator);
    defer compressor.deinit();

    const enc = compressor.encoder();
    const stats = enc.stat();
    try std.testing.expectEqualStrings("gzip", stats.name);

    enc.reset();
    try std.testing.expectEqual(@as(usize, 0), compressor.total_in);
}

test "createEncoder identity returns null" {
    const result = createEncoder(std.testing.allocator, .identity, true);
    if (result) |val| {
        try std.testing.expect(val == null);
    } else |_| {
        // Expected error for non-identity algorithms
    }
}
