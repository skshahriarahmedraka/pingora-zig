//! pingora-zig: allocators
//!
//! High-performance memory allocators for the proxy framework.
//!
//! This module provides specialized allocators optimized for common proxy patterns:
//! - SlabAllocator: O(1) allocation for fixed-size objects (connection nodes, buckets)
//! - RequestArena: Request-scoped allocation with automatic cleanup
//! - StackFallbackAllocator: Stack buffer with heap fallback for small allocations
//!
//! These allocators reduce syscall overhead and memory fragmentation in hot paths.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// SlabAllocator - O(1) fixed-size object allocation
// ============================================================================

/// A slab allocator for fixed-size objects.
///
/// Pre-allocates objects in chunks (slabs) for O(1) allocation without syscalls.
/// Freed objects are returned to a free list for immediate reuse.
///
/// Use cases:
/// - Connection pool nodes
/// - Cache bucket entries
/// - LRU list nodes
/// - Any fixed-size structure allocated/freed frequently
///
/// Example:
/// ```zig
/// var slab = SlabAllocator(MyNode).init(allocator, .{});
/// defer slab.deinit();
///
/// const node = try slab.alloc();
/// defer slab.free(node);
/// ```
pub fn SlabAllocator(comptime T: type) type {
    return struct {
        allocator: Allocator,
        free_list: std.ArrayListUnmanaged(*T),
        slabs: std.ArrayListUnmanaged([]T),
        slab_size: usize,
        /// Statistics
        total_allocated: usize,
        total_freed: usize,

        const Self = @This();

        pub const Config = struct {
            /// Number of objects per slab (default: 64)
            slab_size: usize = 64,
            /// Pre-allocate this many slabs upfront (default: 0)
            initial_slabs: usize = 0,
        };

        /// Initialize a new slab allocator
        pub fn init(allocator: Allocator, config: Config) Self {
            var self = Self{
                .allocator = allocator,
                .free_list = .{},
                .slabs = .{},
                .slab_size = config.slab_size,
                .total_allocated = 0,
                .total_freed = 0,
            };

            // Pre-allocate initial slabs if requested
            if (config.initial_slabs > 0) {
                for (0..config.initial_slabs) |_| {
                    self.growSlab() catch break;
                }
            }

            return self;
        }

        /// Free all memory
        pub fn deinit(self: *Self) void {
            for (self.slabs.items) |slab| {
                self.allocator.free(slab);
            }
            self.slabs.deinit(self.allocator);
            self.free_list.deinit(self.allocator);
        }

        /// Allocate a new object - O(1) when free list is not empty
        pub fn alloc(self: *Self) !*T {
            // Try to get from free list first (O(1))
            if (self.free_list.pop()) |ptr| {
                self.total_allocated += 1;
                return ptr;
            }

            // Grow and try again
            try self.growSlab();
            self.total_allocated += 1;
            return self.free_list.pop() orelse unreachable;
        }

        /// Return an object to the free list - O(1)
        pub fn free(self: *Self, ptr: *T) void {
            self.total_freed += 1;
            self.free_list.append(self.allocator, ptr) catch {
                // If we can't add to free list, the object is leaked
                // This should be extremely rare (OOM during free)
            };
        }

        /// Get number of available objects in free list
        pub fn available(self: *const Self) usize {
            return self.free_list.items.len;
        }

        /// Get total capacity (all slabs)
        pub fn capacity(self: *const Self) usize {
            return self.slabs.items.len * self.slab_size;
        }

        /// Get number of currently allocated (in-use) objects
        pub fn inUse(self: *const Self) usize {
            return self.capacity() - self.available();
        }

        /// Get statistics
        pub fn stats(self: *const Self) Stats {
            return .{
                .total_allocated = self.total_allocated,
                .total_freed = self.total_freed,
                .capacity = self.capacity(),
                .available = self.available(),
                .in_use = self.inUse(),
                .num_slabs = self.slabs.items.len,
            };
        }

        pub const Stats = struct {
            total_allocated: usize,
            total_freed: usize,
            capacity: usize,
            available: usize,
            in_use: usize,
            num_slabs: usize,
        };

        fn growSlab(self: *Self) !void {
            const slab = try self.allocator.alloc(T, self.slab_size);
            errdefer self.allocator.free(slab);

            try self.slabs.append(self.allocator, slab);

            // Add all items in slab to free list
            try self.free_list.ensureUnusedCapacity(self.allocator, self.slab_size);
            for (slab) |*item| {
                self.free_list.appendAssumeCapacity(item);
            }
        }

        /// Shrink the allocator by releasing empty slabs
        /// Returns number of slabs released
        pub fn shrink(self: *Self) usize {
            // Only shrink if free list has at least one full slab worth of items
            if (self.free_list.items.len < self.slab_size) return 0;

            var released: usize = 0;
            // Simple heuristic: release slabs if we have more than 2x capacity needed
            const target_capacity = self.inUse() * 2;

            while (self.capacity() > target_capacity and self.slabs.items.len > 1) {
                // Try to release the last slab
                if (self.canReleaseSlab(self.slabs.items.len - 1)) {
                    self.releaseSlab(self.slabs.items.len - 1);
                    released += 1;
                } else {
                    break;
                }
            }

            return released;
        }

        fn canReleaseSlab(self: *Self, slab_idx: usize) bool {
            const slab = self.slabs.items[slab_idx];
            var free_count: usize = 0;

            for (self.free_list.items) |ptr| {
                const addr = @intFromPtr(ptr);
                const slab_start = @intFromPtr(slab.ptr);
                const slab_end = slab_start + slab.len * @sizeOf(T);

                if (addr >= slab_start and addr < slab_end) {
                    free_count += 1;
                }
            }

            return free_count == self.slab_size;
        }

        fn releaseSlab(self: *Self, slab_idx: usize) void {
            const slab = self.slabs.swapRemove(slab_idx);

            // Remove slab's items from free list
            const slab_start = @intFromPtr(slab.ptr);
            const slab_end = slab_start + slab.len * @sizeOf(T);

            var i: usize = 0;
            while (i < self.free_list.items.len) {
                const addr = @intFromPtr(self.free_list.items[i]);
                if (addr >= slab_start and addr < slab_end) {
                    _ = self.free_list.swapRemove(i);
                } else {
                    i += 1;
                }
            }

            self.allocator.free(slab);
        }
    };
}

// ============================================================================
// RequestArena - Request-scoped arena allocation
// ============================================================================

/// An arena allocator optimized for request-scoped allocations.
///
/// All allocations are freed together when the request completes,
/// avoiding individual free calls and reducing fragmentation.
///
/// Features:
/// - Single bulk free at end of request
/// - Optional memory limit to prevent runaway allocations
/// - Statistics tracking for monitoring
///
/// Example:
/// ```zig
/// var arena = RequestArena.init(allocator, .{ .max_bytes = 1024 * 1024 });
/// defer arena.deinit();
///
/// const alloc = arena.allocator();
/// const buf = try alloc.alloc(u8, 100);
/// // No need to free - cleaned up on arena.deinit() or arena.reset()
/// ```
pub const RequestArena = struct {
    inner: std.heap.ArenaAllocator,
    bytes_allocated: usize,
    allocation_count: usize,
    max_bytes: ?usize,
    high_water_mark: usize,

    const Self = @This();

    pub const Config = struct {
        /// Maximum bytes that can be allocated (null = unlimited)
        max_bytes: ?usize = null,
    };

    /// Initialize a new request arena
    pub fn init(backing_allocator: Allocator, config: Config) Self {
        return .{
            .inner = std.heap.ArenaAllocator.init(backing_allocator),
            .bytes_allocated = 0,
            .allocation_count = 0,
            .max_bytes = config.max_bytes,
            .high_water_mark = 0,
        };
    }

    /// Free all memory
    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }

    /// Reset the arena for reuse (keeps capacity, frees contents)
    pub fn reset(self: *Self) void {
        _ = self.inner.reset(.retain_capacity);
        self.bytes_allocated = 0;
        self.allocation_count = 0;
    }

    /// Get an allocator interface
    pub fn allocator(self: *Self) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        // Check memory limit
        if (self.max_bytes) |max| {
            if (self.bytes_allocated + len > max) {
                return null;
            }
        }

        const result = self.inner.allocator().rawAlloc(len, ptr_align, ret_addr);
        if (result != null) {
            self.bytes_allocated += len;
            self.allocation_count += 1;
            if (self.bytes_allocated > self.high_water_mark) {
                self.high_water_mark = self.bytes_allocated;
            }
        }
        return result;
    }

    fn resizeFn(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));

        // Check memory limit for growth
        if (new_len > buf.len) {
            if (self.max_bytes) |max| {
                const additional = new_len - buf.len;
                if (self.bytes_allocated + additional > max) {
                    return false;
                }
            }
        }

        const result = self.inner.allocator().rawResize(buf, buf_align, new_len, ret_addr);
        if (result) {
            if (new_len > buf.len) {
                self.bytes_allocated += new_len - buf.len;
            } else {
                self.bytes_allocated -= buf.len - new_len;
            }
            if (self.bytes_allocated > self.high_water_mark) {
                self.high_water_mark = self.bytes_allocated;
            }
        }
        return result;
    }

    fn remapFn(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        // Check memory limit for growth
        if (new_len > buf.len) {
            if (self.max_bytes) |max| {
                const additional = new_len - buf.len;
                if (self.bytes_allocated + additional > max) {
                    return null;
                }
            }
        }

        const result = self.inner.allocator().rawRemap(buf, buf_align, new_len, ret_addr);
        if (result != null) {
            if (new_len > buf.len) {
                self.bytes_allocated += new_len - buf.len;
            } else {
                self.bytes_allocated -= buf.len - new_len;
            }
            if (self.bytes_allocated > self.high_water_mark) {
                self.high_water_mark = self.bytes_allocated;
            }
        }
        return result;
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.bytes_allocated -|= buf.len; // Saturating subtract
        self.inner.allocator().rawFree(buf, buf_align, ret_addr);
    }

    /// Get statistics
    pub fn stats(self: *const Self) Stats {
        return .{
            .bytes_allocated = self.bytes_allocated,
            .allocation_count = self.allocation_count,
            .high_water_mark = self.high_water_mark,
        };
    }

    pub const Stats = struct {
        bytes_allocated: usize,
        allocation_count: usize,
        high_water_mark: usize,
    };
};

// ============================================================================
// StackFallbackAllocator - Stack buffer with heap fallback
// ============================================================================

/// A wrapper around Zig's standard stackFallback allocator with tracking.
///
/// Uses a stack buffer for small allocations, falling back to a backing 
/// allocator for larger ones.
///
/// Ideal for functions that usually need small buffers but occasionally need more.
///
/// Example:
/// ```zig
/// var stack_alloc = StackFallbackAllocator(4096).init(heap_allocator);
/// const alloc = stack_alloc.get();
///
/// // Small allocations use stack, large ones use heap
/// const small_buf = try alloc.alloc(u8, 100);  // Uses stack
/// defer alloc.free(small_buf);
/// ```
pub fn StackFallbackAllocator(comptime stack_size: usize) type {
    return struct {
        inner: std.heap.StackFallbackAllocator(stack_size),

        const Self = @This();

        pub fn init(backing_allocator: Allocator) Self {
            return .{
                .inner = std.heap.stackFallback(stack_size, backing_allocator),
            };
        }

        /// Get the allocator interface
        pub fn get(self: *Self) Allocator {
            return self.inner.get();
        }

        /// Legacy name for get() - for compatibility
        pub fn allocator(self: *Self) Allocator {
            return self.get();
        }
    };
}

// ============================================================================
// PooledBuffer - Reusable byte buffer pool
// ============================================================================

/// A pool of reusable byte buffers of fixed size.
///
/// Useful for I/O operations where temporary buffers are frequently needed.
///
/// Example:
/// ```zig
/// var pool = PooledBuffer.init(allocator, .{ .buffer_size = 4096, .pool_size = 8 });
/// defer pool.deinit();
///
/// const buf = try pool.acquire();
/// defer pool.release(buf);
///
/// // Use buf for I/O...
/// ```
pub const PooledBuffer = struct {
    allocator: Allocator,
    free_buffers: std.ArrayListUnmanaged([]u8),
    buffer_size: usize,
    max_pool_size: usize,
    total_created: usize,

    const Self = @This();

    pub const Config = struct {
        /// Size of each buffer
        buffer_size: usize = 4096,
        /// Maximum number of buffers to keep in pool
        pool_size: usize = 16,
        /// Pre-allocate this many buffers
        initial_buffers: usize = 0,
    };

    pub fn init(allocator: Allocator, config: Config) Self {
        var self = Self{
            .allocator = allocator,
            .free_buffers = .{},
            .buffer_size = config.buffer_size,
            .max_pool_size = config.pool_size,
            .total_created = 0,
        };

        // Pre-allocate initial buffers
        for (0..config.initial_buffers) |_| {
            const buf = allocator.alloc(u8, config.buffer_size) catch break;
            self.free_buffers.append(allocator, buf) catch {
                allocator.free(buf);
                break;
            };
            self.total_created += 1;
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.free_buffers.items) |buf| {
            self.allocator.free(buf);
        }
        self.free_buffers.deinit(self.allocator);
    }

    /// Get a buffer from the pool (or create new one)
    pub fn acquire(self: *Self) ![]u8 {
        if (self.free_buffers.pop()) |buf| {
            return buf;
        }

        // Create new buffer
        self.total_created += 1;
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    /// Return a buffer to the pool
    pub fn release(self: *Self, buf: []u8) void {
        // Validate buffer size
        if (buf.len != self.buffer_size) {
            self.allocator.free(buf);
            return;
        }

        // Return to pool if not full
        if (self.free_buffers.items.len < self.max_pool_size) {
            self.free_buffers.append(self.allocator, buf) catch {
                self.allocator.free(buf);
            };
        } else {
            self.allocator.free(buf);
        }
    }

    /// Get pool statistics
    pub fn stats(self: *const Self) Stats {
        return .{
            .available = self.free_buffers.items.len,
            .total_created = self.total_created,
            .buffer_size = self.buffer_size,
        };
    }

    pub const Stats = struct {
        available: usize,
        total_created: usize,
        buffer_size: usize,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "SlabAllocator basic operations" {
    const TestNode = struct {
        value: u64,
        next: ?*@This(),
    };

    var slab = SlabAllocator(TestNode).init(testing.allocator, .{ .slab_size = 4 });
    defer slab.deinit();

    // Allocate some nodes
    const n1 = try slab.alloc();
    const n2 = try slab.alloc();
    const n3 = try slab.alloc();

    n1.value = 1;
    n2.value = 2;
    n3.value = 3;

    try testing.expectEqual(@as(usize, 3), slab.inUse());
    try testing.expectEqual(@as(usize, 1), slab.available()); // 4 - 3 = 1

    // Free one
    slab.free(n2);
    try testing.expectEqual(@as(usize, 2), slab.inUse());

    // Allocate again (should reuse)
    const n4 = try slab.alloc();
    try testing.expect(n4 == n2); // Same pointer reused
}

test "SlabAllocator grows automatically" {
    var slab = SlabAllocator(u64).init(testing.allocator, .{ .slab_size = 2 });
    defer slab.deinit();

    // Allocate more than one slab
    var ptrs: [10]*u64 = undefined;
    for (&ptrs, 0..) |*p, i| {
        p.* = try slab.alloc();
        p.*.* = @intCast(i);
    }

    try testing.expectEqual(@as(usize, 10), slab.inUse());
    try testing.expectEqual(@as(usize, 5), slab.stats().num_slabs); // 10/2 = 5 slabs

    // Free all
    for (ptrs) |p| {
        slab.free(p);
    }

    try testing.expectEqual(@as(usize, 0), slab.inUse());
}

test "SlabAllocator with initial slabs" {
    var slab = SlabAllocator(u32).init(testing.allocator, .{
        .slab_size = 8,
        .initial_slabs = 2,
    });
    defer slab.deinit();

    try testing.expectEqual(@as(usize, 16), slab.capacity()); // 2 slabs * 8
    try testing.expectEqual(@as(usize, 16), slab.available());
}

test "RequestArena basic operations" {
    var arena = RequestArena.init(testing.allocator, .{});
    defer arena.deinit();

    const alloc = arena.allocator();

    // Allocate various sizes
    const buf1 = try alloc.alloc(u8, 100);
    const buf2 = try alloc.alloc(u8, 200);
    _ = buf1;
    _ = buf2;

    const stats_after = arena.stats();
    try testing.expect(stats_after.bytes_allocated >= 300);
    try testing.expectEqual(@as(usize, 2), stats_after.allocation_count);

    // Reset and reuse
    arena.reset();
    try testing.expectEqual(@as(usize, 0), arena.stats().bytes_allocated);
}

test "RequestArena memory limit" {
    var arena = RequestArena.init(testing.allocator, .{ .max_bytes = 100 });
    defer arena.deinit();

    const alloc = arena.allocator();

    // Should succeed
    const buf1 = try alloc.alloc(u8, 50);
    _ = buf1;

    // Should fail (over limit)
    const result = alloc.alloc(u8, 100);
    try testing.expect(result == error.OutOfMemory);
}

test "StackFallbackAllocator basic operations" {
    var stack_alloc = StackFallbackAllocator(256).init(testing.allocator);
    const alloc = stack_alloc.get();

    // Small allocation (uses stack)
    const small = try alloc.alloc(u8, 64);
    defer alloc.free(small);
    @memset(small, 'A');

    // Another small allocation
    const small2 = try alloc.alloc(u8, 32);
    defer alloc.free(small2);
    @memset(small2, 'B');

    // Verify allocations work
    try testing.expectEqual(@as(u8, 'A'), small[0]);
    try testing.expectEqual(@as(u8, 'B'), small2[0]);
}

test "PooledBuffer basic operations" {
    var pool = PooledBuffer.init(testing.allocator, .{
        .buffer_size = 64,
        .pool_size = 4,
        .initial_buffers = 2,
    });
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 2), pool.stats().available);

    // Acquire buffer
    const buf1 = try pool.acquire();
    try testing.expectEqual(@as(usize, 64), buf1.len);
    try testing.expectEqual(@as(usize, 1), pool.stats().available);

    // Acquire another
    const buf2 = try pool.acquire();
    try testing.expectEqual(@as(usize, 0), pool.stats().available);

    // Acquire one more (creates new)
    const buf3 = try pool.acquire();
    try testing.expectEqual(@as(usize, 3), pool.stats().total_created);

    // Release all
    pool.release(buf1);
    pool.release(buf2);
    pool.release(buf3);

    try testing.expectEqual(@as(usize, 3), pool.stats().available);
}

test "PooledBuffer max pool size" {
    var pool = PooledBuffer.init(testing.allocator, .{
        .buffer_size = 32,
        .pool_size = 2,
    });
    defer pool.deinit();

    // Acquire 4 buffers
    const b1 = try pool.acquire();
    const b2 = try pool.acquire();
    const b3 = try pool.acquire();
    const b4 = try pool.acquire();

    // Release all - only 2 should be kept
    pool.release(b1);
    pool.release(b2);
    pool.release(b3);
    pool.release(b4);

    try testing.expectEqual(@as(usize, 2), pool.stats().available);
}
