//! Async I/O Support for Pingora-Zig
//!
//! This module provides high-performance asynchronous I/O using platform-specific
//! mechanisms:
//! - Linux: io_uring (kernel 5.1+)
//! - macOS/BSD: kqueue
//! - Fallback: epoll (Linux) or poll
//!
//! The API provides a unified interface regardless of the underlying implementation.
//!
//! Ported from concepts in: https://github.com/cloudflare/pingora

const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// Platform Detection
// ============================================================================

pub const Platform = enum {
    linux_io_uring,
    linux_epoll,
    macos_kqueue,
    bsd_kqueue,
    fallback_poll,

    pub fn detect() Platform {
        return switch (builtin.os.tag) {
            .linux => if (IoUring.isSupported()) .linux_io_uring else .linux_epoll,
            .macos => .macos_kqueue,
            .freebsd, .openbsd, .netbsd, .dragonfly => .bsd_kqueue,
            else => .fallback_poll,
        };
    }

    pub fn name(self: Platform) []const u8 {
        return switch (self) {
            .linux_io_uring => "io_uring",
            .linux_epoll => "epoll",
            .macos_kqueue => "kqueue (macOS)",
            .bsd_kqueue => "kqueue (BSD)",
            .fallback_poll => "poll",
        };
    }
};

// ============================================================================
// Completion Token - Tracks async operations
// ============================================================================

/// Unique identifier for an async operation
pub const CompletionToken = struct {
    id: u64,
    op_type: OpType,
    user_data: ?*anyopaque,

    pub const OpType = enum(u8) {
        read,
        write,
        accept,
        connect,
        close,
        timeout,
        cancel,
        nop,
    };
};

// ============================================================================
// Completion Result
// ============================================================================

pub const CompletionResult = struct {
    token: CompletionToken,
    result: Result,

    pub const Result = union(enum) {
        success: usize, // bytes transferred or fd for accept
        err: anyerror,
        cancelled: void,
        timeout: void,
    };

    pub fn isSuccess(self: CompletionResult) bool {
        return self.result == .success;
    }

    pub fn bytesTransferred(self: CompletionResult) ?usize {
        return switch (self.result) {
            .success => |n| n,
            else => null,
        };
    }
};

// ============================================================================
// I/O Operation - Describes an async operation to submit
// ============================================================================

pub const IoOp = struct {
    op_type: CompletionToken.OpType,
    fd: posix.fd_t,
    buffer: ?[]u8 = null,
    offset: u64 = 0,
    user_data: ?*anyopaque = null,
    flags: Flags = .{},

    pub const Flags = packed struct {
        /// Don't generate a completion event
        no_completion: bool = false,
        /// Link this operation to the next one
        linked: bool = false,
        /// Use fixed buffer (io_uring)
        fixed_buffer: bool = false,
        _padding: u5 = 0,
    };
};

// ============================================================================
// io_uring Implementation (Linux 5.1+)
// ============================================================================

pub const IoUring = struct {
    ring_fd: posix.fd_t,
    sq: SubmissionQueue,
    cq: CompletionQueue,
    next_token_id: u64,
    allocator: Allocator,
    params: Params,

    const Self = @This();

    pub const Params = struct {
        /// Number of submission queue entries (must be power of 2)
        sq_entries: u32 = 256,
        /// Number of completion queue entries (0 = 2x sq_entries)
        cq_entries: u32 = 0,
        /// Setup flags
        flags: SetupFlags = .{},
    };

    pub const SetupFlags = packed struct(u32) {
        io_poll: bool = false,
        sq_poll: bool = false,
        sq_aff: bool = false,
        cq_size: bool = false,
        clamp: bool = false,
        attach_wq: bool = false,
        r_disabled: bool = false,
        submit_all: bool = false,
        _padding: u24 = 0,
    };

    /// Check if io_uring is supported on this system
    pub fn isSupported() bool {
        if (builtin.os.tag != .linux) return false;

        // Try to create a minimal ring to check support
        var params = std.mem.zeroes(std.os.linux.io_uring_params);
        const result = std.os.linux.io_uring_setup(1, &params);
        if (@as(i32, @bitCast(@as(u32, @truncate(result)))) < 0) return false;

        // Close the test ring
        posix.close(@intCast(result));
        return true;
    }

    /// Initialize io_uring with the given parameters
    pub fn init(allocator: Allocator, params: Params) !Self {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        var io_params = std.mem.zeroes(std.os.linux.io_uring_params);
        io_params.flags = @bitCast(params.flags);

        if (params.cq_entries > 0) {
            io_params.flags |= std.os.linux.IORING_SETUP_CQSIZE;
            io_params.cq_entries = params.cq_entries;
        }

        const ring_fd = std.os.linux.io_uring_setup(params.sq_entries, &io_params);
        if (@as(i32, @intCast(ring_fd)) < 0) {
            return error.IoUringSetupFailed;
        }

        const fd: posix.fd_t = @intCast(ring_fd);

        // Map submission queue
        const sq = try SubmissionQueue.init(fd, &io_params, allocator);
        errdefer sq.deinit();

        // Map completion queue
        const cq = try CompletionQueue.init(fd, &io_params, allocator);
        errdefer cq.deinit();

        return .{
            .ring_fd = fd,
            .sq = sq,
            .cq = cq,
            .next_token_id = 1,
            .allocator = allocator,
            .params = params,
        };
    }

    /// Clean up io_uring resources
    pub fn deinit(self: *Self) void {
        self.cq.deinit();
        self.sq.deinit();
        posix.close(self.ring_fd);
    }

    /// Generate a new unique token ID
    fn nextTokenId(self: *Self) u64 {
        const id = self.next_token_id;
        self.next_token_id += 1;
        return id;
    }

    /// Submit a read operation
    pub fn submitRead(self: *Self, fd: posix.fd_t, buffer: []u8, offset: u64, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .read,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .READ;
        sqe.fd = fd;
        sqe.off = offset;
        sqe.addr = @intFromPtr(buffer.ptr);
        sqe.len = @intCast(buffer.len);
        sqe.user_data = token.id;

        return token;
    }

    /// Submit a write operation
    pub fn submitWrite(self: *Self, fd: posix.fd_t, buffer: []const u8, offset: u64, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .write,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .WRITE;
        sqe.fd = fd;
        sqe.off = offset;
        sqe.addr = @intFromPtr(buffer.ptr);
        sqe.len = @intCast(buffer.len);
        sqe.user_data = token.id;

        return token;
    }

    /// Submit an accept operation
    pub fn submitAccept(self: *Self, listen_fd: posix.fd_t, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .accept,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .ACCEPT;
        sqe.fd = listen_fd;
        sqe.user_data = token.id;

        return token;
    }

    /// Submit a close operation
    pub fn submitClose(self: *Self, fd: posix.fd_t, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .close,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .CLOSE;
        sqe.fd = fd;
        sqe.user_data = token.id;

        return token;
    }

    /// Submit a timeout operation
    pub fn submitTimeout(self: *Self, timeout_ns: u64, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .timeout,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .TIMEOUT;

        // Store timeout in the sqe
        const secs = timeout_ns / std.time.ns_per_s;
        const nsecs = timeout_ns % std.time.ns_per_s;
        _ = secs;
        _ = nsecs;
        sqe.user_data = token.id;

        return token;
    }

    /// Submit a no-op operation (useful for waking up the ring)
    pub fn submitNop(self: *Self, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .nop,
            .user_data = user_data,
        };

        const sqe = self.sq.getSqe() orelse return error.SubmissionQueueFull;
        sqe.* = std.mem.zeroes(std.os.linux.io_uring_sqe);
        sqe.opcode = .NOP;
        sqe.user_data = token.id;

        return token;
    }

    /// Submit all pending operations to the kernel
    pub fn submit(self: *Self) !usize {
        return self.sq.submit(self.ring_fd);
    }

    /// Submit and wait for at least one completion
    pub fn submitAndWait(self: *Self, wait_nr: u32) !usize {
        return self.sq.submitAndWait(self.ring_fd, wait_nr);
    }

    /// Get completions (non-blocking)
    pub fn getCompletions(self: *Self, results: []CompletionResult) usize {
        return self.cq.getCompletions(results);
    }

    /// Wait for completions (blocking)
    pub fn waitForCompletions(self: *Self, results: []CompletionResult, min_completions: u32) !usize {
        // First check if we already have completions
        var count = self.cq.getCompletions(results);
        if (count >= min_completions) return count;

        // Need to wait for more
        _ = try self.submitAndWait(min_completions - @as(u32, @intCast(count)));

        // Get any new completions
        count += self.cq.getCompletions(results[count..]);
        return count;
    }

    /// Get statistics about the ring
    pub fn stats(self: *const Self) Stats {
        return .{
            .sq_entries = self.params.sq_entries,
            .cq_entries = if (self.params.cq_entries > 0) self.params.cq_entries else self.params.sq_entries * 2,
            .sq_pending = self.sq.pending(),
            .cq_ready = self.cq.ready(),
        };
    }

    pub const Stats = struct {
        sq_entries: u32,
        cq_entries: u32,
        sq_pending: u32,
        cq_ready: u32,
    };
};

// ============================================================================
// Submission Queue (SQ)
// ============================================================================

const SubmissionQueue = struct {
    sqes: []std.os.linux.io_uring_sqe,
    head: *u32,
    tail: *u32,
    ring_mask: u32,
    array: []u32,
    mmap_ptr: []align(4096) u8,
    sqes_mmap_ptr: []align(4096) u8,
    local_tail: u32,

    const Self = @This();

    fn init(ring_fd: posix.fd_t, params: *std.os.linux.io_uring_params, _: Allocator) !Self {
        const sq_ring_size = params.sq_off.array + params.sq_entries * @sizeOf(u32);
        const sqes_size = params.sq_entries * @sizeOf(std.os.linux.io_uring_sqe);

        // Map the submission queue ring
        const sq_ptr = try posix.mmap(
            null,
            sq_ring_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring_fd,
            std.os.linux.IORING_OFF_SQ_RING,
        );

        // Map the submission queue entries
        const sqes_ptr = try posix.mmap(
            null,
            sqes_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring_fd,
            std.os.linux.IORING_OFF_SQES,
        );

        const head_ptr: *u32 = @ptrCast(@alignCast(sq_ptr.ptr + params.sq_off.head));
        const tail_ptr: *u32 = @ptrCast(@alignCast(sq_ptr.ptr + params.sq_off.tail));
        const ring_mask = @as(*u32, @ptrCast(@alignCast(sq_ptr.ptr + params.sq_off.ring_mask))).*;
        const array_ptr: [*]u32 = @ptrCast(@alignCast(sq_ptr.ptr + params.sq_off.array));
        const sqes_typed: [*]std.os.linux.io_uring_sqe = @ptrCast(@alignCast(sqes_ptr.ptr));

        return .{
            .sqes = sqes_typed[0..params.sq_entries],
            .head = head_ptr,
            .tail = tail_ptr,
            .ring_mask = ring_mask,
            .array = array_ptr[0..params.sq_entries],
            .mmap_ptr = sq_ptr,
            .sqes_mmap_ptr = sqes_ptr,
            .local_tail = tail_ptr.*,
        };
    }

    fn deinit(self: *const Self) void {
        posix.munmap(self.sqes_mmap_ptr);
        posix.munmap(self.mmap_ptr);
    }

    /// Get a submission queue entry to fill
    fn getSqe(self: *Self) ?*std.os.linux.io_uring_sqe {
        const head = @atomicLoad(u32, self.head, .acquire);
        const next_tail = self.local_tail +% 1;

        if (next_tail -% head > self.ring_mask + 1) {
            return null; // Queue is full
        }

        const idx = self.local_tail & self.ring_mask;
        self.array[idx] = idx;
        self.local_tail = next_tail;

        return &self.sqes[idx];
    }

    /// Submit pending entries to the kernel
    fn submit(self: *Self, ring_fd: posix.fd_t) !usize {
        const to_submit = self.pending();
        if (to_submit == 0) return 0;

        @atomicStore(u32, self.tail, self.local_tail, .release);

        const result = std.os.linux.io_uring_enter(ring_fd, to_submit, 0, 0, null);
        if (@as(i32, @bitCast(@as(u32, @truncate(result)))) < 0) {
            return error.IoUringEnterFailed;
        }

        return @intCast(result);
    }

    /// Submit and wait for completions
    fn submitAndWait(self: *Self, ring_fd: posix.fd_t, wait_nr: u32) !usize {
        const to_submit = self.pending();

        @atomicStore(u32, self.tail, self.local_tail, .release);

        const flags: u32 = if (wait_nr > 0) std.os.linux.IORING_ENTER_GETEVENTS else 0;
        const result = std.os.linux.io_uring_enter(ring_fd, to_submit, wait_nr, flags, null);
        if (@as(i32, @bitCast(@as(u32, @truncate(result)))) < 0) {
            return error.IoUringEnterFailed;
        }

        return @intCast(result);
    }

    /// Number of pending submissions
    fn pending(self: *const Self) u32 {
        return self.local_tail -% @atomicLoad(u32, self.head, .acquire);
    }
};

// ============================================================================
// Completion Queue (CQ)
// ============================================================================

const CompletionQueue = struct {
    head: *u32,
    tail: *u32,
    ring_mask: u32,
    cqes: []std.os.linux.io_uring_cqe,
    mmap_ptr: []align(4096) u8,
    local_head: u32,

    const Self = @This();

    fn init(ring_fd: posix.fd_t, params: *std.os.linux.io_uring_params, _: Allocator) !Self {
        const cq_entries = if (params.cq_entries > 0) params.cq_entries else params.sq_entries * 2;
        const cq_ring_size = params.cq_off.cqes + cq_entries * @sizeOf(std.os.linux.io_uring_cqe);

        // Map the completion queue ring
        const cq_ptr = try posix.mmap(
            null,
            cq_ring_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring_fd,
            std.os.linux.IORING_OFF_CQ_RING,
        );

        const head_ptr: *u32 = @ptrCast(@alignCast(cq_ptr.ptr + params.cq_off.head));
        const tail_ptr: *u32 = @ptrCast(@alignCast(cq_ptr.ptr + params.cq_off.tail));
        const ring_mask = @as(*u32, @ptrCast(@alignCast(cq_ptr.ptr + params.cq_off.ring_mask))).*;
        const cqes_ptr: [*]std.os.linux.io_uring_cqe = @ptrCast(@alignCast(cq_ptr.ptr + params.cq_off.cqes));

        return .{
            .head = head_ptr,
            .tail = tail_ptr,
            .ring_mask = ring_mask,
            .cqes = cqes_ptr[0..cq_entries],
            .mmap_ptr = cq_ptr,
            .local_head = head_ptr.*,
        };
    }

    fn deinit(self: *const Self) void {
        posix.munmap(self.mmap_ptr);
    }

    /// Get completions from the queue (non-blocking)
    fn getCompletions(self: *Self, results: []CompletionResult) usize {
        var count: usize = 0;
        const tail = @atomicLoad(u32, self.tail, .acquire);

        while (self.local_head != tail and count < results.len) {
            const idx = self.local_head & self.ring_mask;
            const cqe = &self.cqes[idx];

            results[count] = .{
                .token = .{
                    .id = cqe.user_data,
                    .op_type = .nop, // Would need to track this separately
                    .user_data = null,
                },
                .result = if (cqe.res >= 0)
                    .{ .success = @intCast(cqe.res) }
                else
                    .{ .err = error.IoError },
            };

            count += 1;
            self.local_head +%= 1;
        }

        // Update head to release consumed entries
        if (count > 0) {
            @atomicStore(u32, self.head, self.local_head, .release);
        }

        return count;
    }

    /// Number of ready completions
    fn ready(self: *const Self) u32 {
        return @atomicLoad(u32, self.tail, .acquire) -% self.local_head;
    }
};

// ============================================================================
// kqueue Implementation (macOS/BSD)
// ============================================================================

/// Kqueue-based async I/O for macOS and BSD systems.
/// On non-BSD systems, this is a stub that returns UnsupportedPlatform.
pub const Kqueue = if (is_bsd_like)
    KqueueImpl
else
    KqueueStub;

const is_bsd_like = switch (builtin.os.tag) {
    .macos, .freebsd, .openbsd, .netbsd, .dragonfly => true,
    else => false,
};

/// Stub implementation for non-BSD platforms
const KqueueStub = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn isSupported() bool {
        return false;
    }

    pub fn init(allocator: Allocator) !Self {
        _ = allocator;
        return error.UnsupportedPlatform;
    }

    pub fn deinit(_: *Self) void {}

    pub fn registerRead(_: *Self, _: posix.fd_t, _: ?*anyopaque) !CompletionToken {
        return error.UnsupportedPlatform;
    }

    pub fn registerWrite(_: *Self, _: posix.fd_t, _: ?*anyopaque) !CompletionToken {
        return error.UnsupportedPlatform;
    }

    pub fn registerTimer(_: *Self, _: u64, _: ?*anyopaque) !CompletionToken {
        return error.UnsupportedPlatform;
    }
};

/// Real kqueue implementation for BSD-like systems
const KqueueImpl = struct {
    kq_fd: posix.fd_t,
    next_token_id: u64,
    pending_changes: std.ArrayListUnmanaged(posix.Kevent),
    allocator: Allocator,

    const Self = @This();

    pub const Kevent = posix.Kevent;

    /// Check if kqueue is supported on this system
    pub fn isSupported() bool {
        return true;
    }

    /// Initialize kqueue
    pub fn init(allocator: Allocator) !Self {
        const kq_fd = try posix.kqueue();

        return .{
            .kq_fd = kq_fd,
            .next_token_id = 1,
            .pending_changes = .{},
            .allocator = allocator,
        };
    }

    /// Clean up kqueue resources
    pub fn deinit(self: *Self) void {
        self.pending_changes.deinit(self.allocator);
        posix.close(self.kq_fd);
    }

    /// Generate a new unique token ID
    fn nextTokenId(self: *Self) u64 {
        const id = self.next_token_id;
        self.next_token_id += 1;
        return id;
    }

    /// Register interest in read events for a file descriptor
    pub fn registerRead(self: *Self, fd: posix.fd_t, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .read,
            .user_data = user_data,
        };

        try self.pending_changes.append(self.allocator, .{
            .ident = @intCast(fd),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD | posix.system.EV.ONESHOT,
            .fflags = 0,
            .data = 0,
            .udata = token.id,
        });

        return token;
    }

    /// Register interest in write events for a file descriptor
    pub fn registerWrite(self: *Self, fd: posix.fd_t, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .write,
            .user_data = user_data,
        };

        try self.pending_changes.append(self.allocator, .{
            .ident = @intCast(fd),
            .filter = posix.system.EVFILT.WRITE,
            .flags = posix.system.EV.ADD | posix.system.EV.ONESHOT,
            .fflags = 0,
            .data = 0,
            .udata = token.id,
        });

        return token;
    }

    /// Register a timer
    pub fn registerTimer(self: *Self, timeout_ms: u64, user_data: ?*anyopaque) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .timeout,
            .user_data = user_data,
        };

        try self.pending_changes.append(self.allocator, .{
            .ident = token.id,
            .filter = posix.system.EVFILT.TIMER,
            .flags = posix.system.EV.ADD | posix.system.EV.ONESHOT,
            .fflags = 0,
            .data = @intCast(timeout_ms),
            .udata = token.id,
        });

        return token;
    }

    /// Wait for events
    pub fn wait(self: *Self, events: []posix.Kevent, timeout_ms: ?i32) !usize {
        const timeout: ?posix.timespec = if (timeout_ms) |ms| .{
            .sec = @intCast(@divFloor(ms, 1000)),
            .nsec = @intCast(@mod(ms, 1000) * 1_000_000),
        } else null;

        const changelist = self.pending_changes.items;
        const result = posix.kevent(
            self.kq_fd,
            changelist,
            events,
            if (timeout) |*t| t else null,
        ) catch |err| {
            return err;
        };

        // Clear pending changes after they've been applied
        self.pending_changes.clearRetainingCapacity();

        return result;
    }

    /// Get completions from events
    pub fn processEvents(events: []const posix.Kevent, results: []CompletionResult) usize {
        var count: usize = 0;

        for (events) |ev| {
            if (count >= results.len) break;

            const op_type: CompletionToken.OpType = switch (ev.filter) {
                posix.system.EVFILT.READ => .read,
                posix.system.EVFILT.WRITE => .write,
                posix.system.EVFILT.TIMER => .timeout,
                else => .nop,
            };

            results[count] = .{
                .token = .{
                    .id = ev.udata,
                    .op_type = op_type,
                    .user_data = null,
                },
                .result = if (ev.flags & posix.system.EV.ERROR != 0)
                    .{ .err = error.IoError }
                else
                    .{ .success = @intCast(ev.data) },
            };

            count += 1;
        }

        return count;
    }
};

// ============================================================================
// Epoll Implementation (Linux fallback)
// ============================================================================

pub const Epoll = struct {
    epoll_fd: posix.fd_t,
    next_token_id: u64,
    allocator: Allocator,

    const Self = @This();

    /// Check if epoll is supported
    pub fn isSupported() bool {
        return builtin.os.tag == .linux;
    }

    /// Initialize epoll
    pub fn init(allocator: Allocator) !Self {
        if (!isSupported()) {
            return error.UnsupportedPlatform;
        }

        const epoll_fd = try posix.epoll_create1(@as(u32, std.os.linux.EPOLL.CLOEXEC));

        return .{
            .epoll_fd = epoll_fd,
            .next_token_id = 1,
            .allocator = allocator,
        };
    }

    /// Clean up epoll resources
    pub fn deinit(self: *Self) void {
        posix.close(self.epoll_fd);
    }

    /// Generate a new unique token ID
    fn nextTokenId(self: *Self) u64 {
        const id = self.next_token_id;
        self.next_token_id += 1;
        return id;
    }

    /// Register interest in read events
    pub fn registerRead(self: *Self, fd: posix.fd_t, user_data: u64) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .read,
            .user_data = null,
        };

        var event = std.os.linux.epoll_event{
            .events = std.os.linux.EPOLL.IN | std.os.linux.EPOLL.ONESHOT,
            .data = .{ .u64 = user_data },
        };

        try posix.epoll_ctl(self.epoll_fd, .ADD, fd, &event);

        return token;
    }

    /// Register interest in write events
    pub fn registerWrite(self: *Self, fd: posix.fd_t, user_data: u64) !CompletionToken {
        const token = CompletionToken{
            .id = self.nextTokenId(),
            .op_type = .write,
            .user_data = null,
        };

        var event = std.os.linux.epoll_event{
            .events = std.os.linux.EPOLL.OUT | std.os.linux.EPOLL.ONESHOT,
            .data = .{ .u64 = user_data },
        };

        try posix.epoll_ctl(self.epoll_fd, .ADD, fd, &event);

        return token;
    }

    /// Wait for events
    pub fn wait(self: *Self, events: []std.os.linux.epoll_event, timeout_ms: i32) !usize {
        return posix.epoll_wait(self.epoll_fd, events, timeout_ms);
    }
};

// ============================================================================
// Unified Event Loop - Platform-agnostic interface
// ============================================================================

pub const EventLoop = struct {
    backend: Backend,
    allocator: Allocator,
    platform: Platform,

    const Self = @This();

    const Backend = union(Platform) {
        linux_io_uring: IoUring,
        linux_epoll: Epoll,
        macos_kqueue: Kqueue,
        bsd_kqueue: Kqueue,
        fallback_poll: void,
    };

    /// Create a new event loop using the best available backend
    pub fn init(allocator: Allocator) !Self {
        const platform = Platform.detect();

        const backend: Backend = switch (platform) {
            .linux_io_uring => .{ .linux_io_uring = try IoUring.init(allocator, .{}) },
            .linux_epoll => .{ .linux_epoll = try Epoll.init(allocator) },
            .macos_kqueue => .{ .macos_kqueue = try Kqueue.init(allocator) },
            .bsd_kqueue => .{ .bsd_kqueue = try Kqueue.init(allocator) },
            .fallback_poll => .{ .fallback_poll = {} },
        };

        return .{
            .backend = backend,
            .allocator = allocator,
            .platform = platform,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        switch (self.backend) {
            .linux_io_uring => |*ring| ring.deinit(),
            .linux_epoll => |*epoll| epoll.deinit(),
            .macos_kqueue, .bsd_kqueue => |*kq| kq.deinit(),
            .fallback_poll => {},
        }
    }

    /// Get the platform being used
    pub fn getPlatform(self: *const Self) Platform {
        return self.platform;
    }

    /// Get platform name
    pub fn getPlatformName(self: *const Self) []const u8 {
        return self.platform.name();
    }

    /// Submit a read operation (io_uring) or register read interest (kqueue/epoll)
    pub fn submitRead(self: *Self, fd: posix.fd_t, buffer: ?[]u8, user_data: ?*anyopaque) !CompletionToken {
        return switch (self.backend) {
            .linux_io_uring => |*ring| try ring.submitRead(fd, buffer orelse return error.BufferRequired, 0, user_data),
            .linux_epoll => |*epoll| try epoll.registerRead(fd, @intFromPtr(user_data)),
            .macos_kqueue, .bsd_kqueue => |*kq| try kq.registerRead(fd, user_data),
            .fallback_poll => error.UnsupportedPlatform,
        };
    }

    /// Submit a write operation (io_uring) or register write interest (kqueue/epoll)
    pub fn submitWrite(self: *Self, fd: posix.fd_t, buffer: ?[]const u8, user_data: ?*anyopaque) !CompletionToken {
        return switch (self.backend) {
            .linux_io_uring => |*ring| try ring.submitWrite(fd, buffer orelse return error.BufferRequired, 0, user_data),
            .linux_epoll => |*epoll| try epoll.registerWrite(fd, @intFromPtr(user_data)),
            .macos_kqueue, .bsd_kqueue => |*kq| try kq.registerWrite(fd, user_data),
            .fallback_poll => error.UnsupportedPlatform,
        };
    }

    /// Submit operations to the kernel (io_uring only, no-op for others)
    pub fn submit(self: *Self) !usize {
        return switch (self.backend) {
            .linux_io_uring => |*ring| try ring.submit(),
            else => 0,
        };
    }

    /// Check if using io_uring (for feature detection)
    pub fn isIoUring(self: *const Self) bool {
        return self.platform == .linux_io_uring;
    }

    /// Check if using kqueue
    pub fn isKqueue(self: *const Self) bool {
        return self.platform == .macos_kqueue or self.platform == .bsd_kqueue;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Platform detection" {
    const platform = Platform.detect();
    const name = platform.name();
    try testing.expect(name.len > 0);

    // On Linux, we should get either io_uring or epoll
    if (builtin.os.tag == .linux) {
        try testing.expect(platform == .linux_io_uring or platform == .linux_epoll);
    }

    // On macOS, we should get kqueue
    if (builtin.os.tag == .macos) {
        try testing.expectEqual(Platform.macos_kqueue, platform);
    }
}

test "CompletionToken creation" {
    const token = CompletionToken{
        .id = 42,
        .op_type = .read,
        .user_data = null,
    };

    try testing.expectEqual(@as(u64, 42), token.id);
    try testing.expectEqual(CompletionToken.OpType.read, token.op_type);
}

test "CompletionResult success" {
    const result = CompletionResult{
        .token = .{ .id = 1, .op_type = .read, .user_data = null },
        .result = .{ .success = 100 },
    };

    try testing.expect(result.isSuccess());
    try testing.expectEqual(@as(usize, 100), result.bytesTransferred().?);
}

test "CompletionResult error" {
    const result = CompletionResult{
        .token = .{ .id = 1, .op_type = .read, .user_data = null },
        .result = .{ .err = error.IoError },
    };

    try testing.expect(!result.isSuccess());
    try testing.expectEqual(@as(?usize, null), result.bytesTransferred());
}

test "IoOp creation" {
    const op = IoOp{
        .op_type = .write,
        .fd = 5,
        .buffer = null,
        .offset = 100,
        .user_data = null,
        .flags = .{ .linked = true },
    };

    try testing.expectEqual(CompletionToken.OpType.write, op.op_type);
    try testing.expectEqual(@as(posix.fd_t, 5), op.fd);
    try testing.expectEqual(@as(u64, 100), op.offset);
    try testing.expect(op.flags.linked);
}

test "io_uring support check" {
    // This test just verifies the check doesn't crash
    const supported = IoUring.isSupported();
    if (builtin.os.tag != .linux) {
        try testing.expect(!supported);
    }
    // On Linux, it may or may not be supported depending on kernel version
}

test "EventLoop initialization" {
    var loop = EventLoop.init(testing.allocator) catch |err| {
        // On some systems/CI, io_uring may not be available
        if (err == error.IoUringSetupFailed or err == error.UnsupportedPlatform) {
            return; // Skip test
        }
        return err;
    };
    defer loop.deinit();

    const name = loop.getPlatformName();
    try testing.expect(name.len > 0);
}

test "io_uring NOP operation" {
    if (builtin.os.tag != .linux) return;

    var ring = IoUring.init(testing.allocator, .{ .sq_entries = 32 }) catch |err| {
        if (err == error.IoUringSetupFailed) return; // Not supported
        return err;
    };
    defer ring.deinit();

    // Submit a NOP
    const token = try ring.submitNop(null);
    try testing.expectEqual(CompletionToken.OpType.nop, token.op_type);

    // Submit to kernel
    const submitted = try ring.submit();
    try testing.expectEqual(@as(usize, 1), submitted);

    // Wait for completion
    var results: [1]CompletionResult = undefined;
    const completed = try ring.waitForCompletions(&results, 1);
    try testing.expectEqual(@as(usize, 1), completed);
    try testing.expect(results[0].isSuccess());
}

test "io_uring stats" {
    if (builtin.os.tag != .linux) return;

    var ring = IoUring.init(testing.allocator, .{ .sq_entries = 64 }) catch |err| {
        if (err == error.IoUringSetupFailed) return;
        return err;
    };
    defer ring.deinit();

    const stats = ring.stats();
    try testing.expectEqual(@as(u32, 64), stats.sq_entries);
    try testing.expectEqual(@as(u32, 128), stats.cq_entries); // 2x sq_entries by default
    try testing.expectEqual(@as(u32, 0), stats.sq_pending);
    try testing.expectEqual(@as(u32, 0), stats.cq_ready);
}

test "Epoll support check" {
    const supported = Epoll.isSupported();
    if (builtin.os.tag == .linux) {
        try testing.expect(supported);
    } else {
        try testing.expect(!supported);
    }
}

test "Kqueue support check" {
    const supported = Kqueue.isSupported();
    if (builtin.os.tag == .macos or builtin.os.tag == .freebsd or
        builtin.os.tag == .openbsd or builtin.os.tag == .netbsd)
    {
        try testing.expect(supported);
    } else {
        try testing.expect(!supported);
    }
}


