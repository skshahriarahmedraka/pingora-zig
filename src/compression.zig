//! pingora-zig: HTTP Compression Module
//!
//! Provides compression types and utilities for HTTP response bodies.
//! Supports gzip, deflate, zstd algorithm detection and content negotiation.
//!
//! Note: Full streaming compression/decompression requires Zig 0.15's new I/O API.
//! This module provides the types and negotiation logic for HTTP compression.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Compression algorithm types
pub const Algorithm = enum {
    gzip,
    deflate,
    zstd,
    identity, // No compression

    /// Parse from Accept-Encoding header value
    /// Returns the best supported algorithm (prefers zstd > gzip > deflate)
    pub fn fromAcceptEncoding(value: []const u8) ?Algorithm {
        if (std.mem.indexOf(u8, value, "zstd") != null) return .zstd;
        if (std.mem.indexOf(u8, value, "gzip") != null) return .gzip;
        if (std.mem.indexOf(u8, value, "deflate") != null) return .deflate;
        if (std.mem.indexOf(u8, value, "identity") != null) return .identity;
        return null;
    }

    /// Parse from Content-Encoding header value
    pub fn fromContentEncoding(value: []const u8) ?Algorithm {
        const trimmed = std.mem.trim(u8, value, " \t");
        if (std.mem.eql(u8, trimmed, "zstd")) return .zstd;
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
// Tests
// ============================================================================

test "Algorithm.fromAcceptEncoding" {
    try std.testing.expectEqual(Algorithm.gzip, Algorithm.fromAcceptEncoding("gzip, deflate").?);
    try std.testing.expectEqual(Algorithm.zstd, Algorithm.fromAcceptEncoding("zstd, gzip, deflate").?);
    try std.testing.expectEqual(Algorithm.deflate, Algorithm.fromAcceptEncoding("deflate").?);
    try std.testing.expectEqual(Algorithm.identity, Algorithm.fromAcceptEncoding("identity").?);
    try std.testing.expect(Algorithm.fromAcceptEncoding("br") == null);
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
