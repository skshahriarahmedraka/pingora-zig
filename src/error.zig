//! pingora-zig: error
//!
//! Error types and handling for the pingora framework.
//! Provides structured error types with context, chaining, and source tracking.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-error

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// Predefined types of errors
pub const ErrorType = enum {
    // Connect errors
    connect_timedout,
    connect_refused,
    connect_no_route,
    tls_want_x509_lookup,
    tls_handshake_failure,
    tls_handshake_timedout,
    invalid_cert,
    handshake_error,
    connect_error,
    bind_error,
    accept_error,
    socket_error,
    connect_proxy_failure,

    // Protocol errors
    invalid_http_header,
    h1_error,
    h2_error,
    h2_downgrade,
    invalid_h2,

    // IO errors on established connections
    read_error,
    write_error,
    read_timedout,
    write_timedout,
    connection_closed,

    // HTTP status code error
    http_status,

    // File related
    file_open_error,
    file_create_error,
    file_read_error,
    file_write_error,

    // Other errors
    internal_error,
    unknown_error,

    // Custom error
    custom,

    /// Get the string representation of this error type
    pub fn asStr(self: ErrorType) []const u8 {
        return switch (self) {
            .connect_timedout => "ConnectTimedout",
            .connect_refused => "ConnectRefused",
            .connect_no_route => "ConnectNoRoute",
            .tls_want_x509_lookup => "TLSWantX509Lookup",
            .tls_handshake_failure => "TLSHandshakeFailure",
            .tls_handshake_timedout => "TLSHandshakeTimedout",
            .invalid_cert => "InvalidCert",
            .handshake_error => "HandshakeError",
            .connect_error => "ConnectError",
            .bind_error => "BindError",
            .accept_error => "AcceptError",
            .socket_error => "SocketError",
            .connect_proxy_failure => "ConnectProxyFailure",
            .invalid_http_header => "InvalidHTTPHeader",
            .h1_error => "H1Error",
            .h2_error => "H2Error",
            .h2_downgrade => "H2Downgrade",
            .invalid_h2 => "InvalidH2",
            .read_error => "ReadError",
            .write_error => "WriteError",
            .read_timedout => "ReadTimedout",
            .write_timedout => "WriteTimedout",
            .connection_closed => "ConnectionClosed",
            .http_status => "HTTPStatus",
            .file_open_error => "FileOpenError",
            .file_create_error => "FileCreateError",
            .file_read_error => "FileReadError",
            .file_write_error => "FileWriteError",
            .internal_error => "InternalError",
            .unknown_error => "UnknownError",
            .custom => "Custom",
        };
    }
};

/// The source of the error
pub const ErrorSource = enum {
    /// The error is caused by the remote server
    upstream,
    /// The error is caused by the remote client
    downstream,
    /// The error is caused by the internal logic
    internal,
    /// Error source unknown or to be set
    unset,

    /// Get the string representation of this error source
    pub fn asStr(self: ErrorSource) []const u8 {
        return switch (self) {
            .upstream => "Upstream",
            .downstream => "Downstream",
            .internal => "Internal",
            .unset => "",
        };
    }
};

/// Whether the request can be retried after encountering this error
pub const RetryType = union(enum) {
    decided: bool,
    reused_only, // only retry when the error is from a reused connection

    pub fn fromBool(b: bool) RetryType {
        return .{ .decided = b };
    }

    pub fn decideReuse(self: *RetryType, reused: bool) void {
        switch (self.*) {
            .reused_only => self.* = .{ .decided = reused },
            .decided => {},
        }
    }

    pub fn retry(self: RetryType) bool {
        return switch (self) {
            .decided => |b| b,
            .reused_only => @panic("Retry is not decided"),
        };
    }
};

/// A string that can be either static or owned
pub const ImmutStr = union(enum) {
    static: []const u8,
    owned: []const u8,

    pub fn asStr(self: ImmutStr) []const u8 {
        return switch (self) {
            .static => |s| s,
            .owned => |s| s,
        };
    }

    pub fn isOwned(self: ImmutStr) bool {
        return self == .owned;
    }

    pub fn fromStatic(s: []const u8) ImmutStr {
        return .{ .static = s };
    }

    pub fn fromOwned(s: []const u8) ImmutStr {
        return .{ .owned = s };
    }

    pub fn deinit(self: *ImmutStr, allocator: Allocator) void {
        switch (self.*) {
            .owned => |s| allocator.free(s),
            .static => {},
        }
    }
};

/// The struct that represents an error
pub const Error = struct {
    /// The type of error
    etype: ErrorType,
    /// The source of error: from upstream, downstream or internal
    esource: ErrorSource,
    /// If the error is retry-able
    retry_type: RetryType,
    /// Chain to the cause of this error
    cause: ?*const Error,
    /// An arbitrary string that explains the context when the error happens
    context: ?ImmutStr,
    /// HTTP status code (only valid when etype is http_status)
    http_status_code: ?u16,
    /// Custom error name (only valid when etype is custom)
    custom_name: ?[]const u8,

    const Self = @This();

    /// Create a new error with the given type
    pub fn new(etype: ErrorType) Self {
        return .{
            .etype = etype,
            .esource = .unset,
            .retry_type = RetryType.fromBool(false),
            .cause = null,
            .context = null,
            .http_status_code = null,
            .custom_name = null,
        };
    }

    /// Create a new error with an HTTP status code
    pub fn httpStatus(code: u16) Self {
        var e = new(.http_status);
        e.http_status_code = code;
        return e;
    }

    /// Create a new custom error
    pub fn custom(name: []const u8) Self {
        var e = new(.custom);
        e.custom_name = name;
        return e;
    }

    /// Create an error with the given type and context
    pub fn explain(etype: ErrorType, context: []const u8) Self {
        var e = new(etype);
        e.context = ImmutStr.fromStatic(context);
        return e;
    }

    /// Create an error with the given type, context and cause
    pub fn because(etype: ErrorType, context: []const u8, cause: *const Error) Self {
        var e = new(etype);
        e.context = ImmutStr.fromStatic(context);
        e.cause = cause;
        e.retry_type = cause.retry_type;
        return e;
    }

    /// Create an error with upstream source
    pub fn newUp(etype: ErrorType) Self {
        var e = new(etype);
        e.esource = .upstream;
        return e;
    }

    /// Create an error with downstream source
    pub fn newDown(etype: ErrorType) Self {
        var e = new(etype);
        e.esource = .downstream;
        return e;
    }

    /// Create an error with internal source
    pub fn newIn(etype: ErrorType) Self {
        var e = new(etype);
        e.esource = .internal;
        return e;
    }

    /// Set the error source to upstream
    pub fn asUp(self: *Self) void {
        self.esource = .upstream;
    }

    /// Set the error source to downstream
    pub fn asDown(self: *Self) void {
        self.esource = .downstream;
    }

    /// Set the error source to internal
    pub fn asIn(self: *Self) void {
        self.esource = .internal;
    }

    /// Convert to upstream and return self
    pub fn intoUp(self: Self) Self {
        var e = self;
        e.esource = .upstream;
        return e;
    }

    /// Convert to downstream and return self
    pub fn intoDown(self: Self) Self {
        var e = self;
        e.esource = .downstream;
        return e;
    }

    /// Convert to internal and return self
    pub fn intoIn(self: Self) Self {
        var e = self;
        e.esource = .internal;
        return e;
    }

    /// Set the retry flag
    pub fn setRetry(self: *Self, can_retry: bool) void {
        self.retry_type = RetryType.fromBool(can_retry);
    }

    /// Check if error can be retried
    pub fn canRetry(self: Self) bool {
        return self.retry_type.retry();
    }

    /// Set context for this error
    pub fn setContext(self: *Self, ctx: []const u8) void {
        self.context = ImmutStr.fromStatic(ctx);
    }

    /// Set cause for this error
    pub fn setCause(self: *Self, cause: *const Error) void {
        self.cause = cause;
    }

    /// Get the reason string
    pub fn reasonStr(self: Self) []const u8 {
        if (self.etype == .custom) {
            return self.custom_name orelse "Custom";
        }
        return self.etype.asStr();
    }

    /// Get the source string
    pub fn sourceStr(self: Self) []const u8 {
        return self.esource.asStr();
    }

    /// Get the root error type by following the cause chain
    pub fn rootEtype(self: *const Self) ErrorType {
        if (self.cause) |c| {
            return c.rootEtype();
        }
        return self.etype;
    }

    /// Get the root cause error
    pub fn rootCause(self: *const Self) *const Self {
        if (self.cause) |c| {
            return c.rootCause();
        }
        return self;
    }

    /// Create a new error from self with same type and source, putting self as the cause
    pub fn moreContext(self: *const Self, context: []const u8) Self {
        var e = because(self.etype, context, self);
        e.esource = self.esource;
        e.retry_type = self.retry_type;
        return e;
    }

    /// Format the error for display
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try self.chainDisplay(null, writer);
    }

    fn chainDisplay(self: Self, previous: ?*const Self, writer: anytype) !void {
        // Write source if different from previous
        if (previous == null or previous.?.esource != self.esource) {
            try writer.writeAll(self.esource.asStr());
        }

        // Write type if different from previous
        if (previous == null or previous.?.etype != self.etype) {
            try writer.writeByte(' ');
            try writer.writeAll(self.reasonStr());
        }

        // Write context if present
        if (self.context) |ctx| {
            try writer.writeAll(" context: ");
            try writer.writeAll(ctx.asStr());
        }

        // Write cause if present
        if (self.cause) |cause| {
            try writer.writeAll(" cause: ");
            try cause.chainDisplay(&self, writer);
        }
    }
};

/// Helper to convert Result to Error with context
pub fn OrErr(comptime T: type) type {
    return struct {
        pub fn orErr(result: anyerror!T, etype: ErrorType, context: []const u8) Error!T {
            _ = etype;
            _ = context;
            return result catch {
                return error.PingoraError;
            };
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "ImmutStr static vs owned" {
    const s1 = ImmutStr.fromStatic("test");
    try testing.expect(!s1.isOwned());

    const s2 = ImmutStr.fromOwned("test");
    try testing.expect(s2.isOwned());
}

test "Error chain of error" {
    const e1 = Error.new(.internal_error);
    var e2 = Error.httpStatus(400);
    e2.setCause(&e1);

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try e2.format("", .{}, fbs.writer());
    const result = fbs.getWritten();

    try testing.expect(std.mem.indexOf(u8, result, "HTTPStatus") != null);
    try testing.expect(std.mem.indexOf(u8, result, "InternalError") != null);
    try testing.expectEqual(e2.rootEtype(), .internal_error);
}

test "Error with context" {
    var e1 = Error.new(.internal_error);
    e1.setContext("my context");

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try e1.format("", .{}, fbs.writer());
    const result = fbs.getWritten();

    try testing.expect(std.mem.indexOf(u8, result, "InternalError") != null);
    try testing.expect(std.mem.indexOf(u8, result, "context: my context") != null);
}

test "Error explain" {
    const e1 = Error.explain(.internal_error, "something went wrong");

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try e1.format("", .{}, fbs.writer());
    const result = fbs.getWritten();

    try testing.expect(std.mem.indexOf(u8, result, "InternalError") != null);
    try testing.expect(std.mem.indexOf(u8, result, "something went wrong") != null);
}

test "Error because" {
    const e1 = Error.new(.internal_error);
    const e2 = Error.because(.http_status, "test", &e1);

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try e2.format("", .{}, fbs.writer());
    const result = fbs.getWritten();

    try testing.expect(std.mem.indexOf(u8, result, "HTTPStatus") != null);
    try testing.expect(std.mem.indexOf(u8, result, "context: test") != null);
    try testing.expect(std.mem.indexOf(u8, result, "cause:") != null);
    try testing.expect(std.mem.indexOf(u8, result, "InternalError") != null);
}

test "Error source conversion" {
    var e = Error.new(.connect_error);
    try testing.expectEqual(e.esource, .unset);

    e.asUp();
    try testing.expectEqual(e.esource, .upstream);

    e.asDown();
    try testing.expectEqual(e.esource, .downstream);

    e.asIn();
    try testing.expectEqual(e.esource, .internal);

    const e2 = Error.newUp(.connect_error);
    try testing.expectEqual(e2.esource, .upstream);

    const e3 = Error.newDown(.connect_error);
    try testing.expectEqual(e3.esource, .downstream);

    const e4 = Error.newIn(.connect_error);
    try testing.expectEqual(e4.esource, .internal);
}

test "Error retry type" {
    var e = Error.new(.connect_error);
    e.setRetry(true);
    try testing.expect(e.canRetry());

    e.setRetry(false);
    try testing.expect(!e.canRetry());
}

test "RetryType decide reuse" {
    var rt: RetryType = .reused_only;
    (&rt).decideReuse(true);
    try testing.expectEqual(rt.decided, true);

    rt = .reused_only;
    (&rt).decideReuse(false);
    try testing.expectEqual(rt.decided, false);
}

test "Error more context" {
    const e1 = Error.new(.internal_error);
    const e2 = e1.moreContext("additional context");

    try testing.expectEqual(e2.etype, .internal_error);
    try testing.expect(e2.cause != null);
    try testing.expectEqualStrings("additional context", e2.context.?.asStr());
}

test "Error custom type" {
    const e = Error.custom("MyCustomError");
    try testing.expectEqual(e.etype, .custom);
    try testing.expectEqualStrings("MyCustomError", e.reasonStr());
}

test "ErrorType as_str" {
    try testing.expectEqualStrings("ConnectTimedout", ErrorType.connect_timedout.asStr());
    try testing.expectEqualStrings("InternalError", ErrorType.internal_error.asStr());
    try testing.expectEqualStrings("HTTPStatus", ErrorType.http_status.asStr());
}

test "ErrorSource as_str" {
    try testing.expectEqualStrings("Upstream", ErrorSource.upstream.asStr());
    try testing.expectEqualStrings("Downstream", ErrorSource.downstream.asStr());
    try testing.expectEqualStrings("Internal", ErrorSource.internal.asStr());
    try testing.expectEqualStrings("", ErrorSource.unset.asStr());
}

// Additional tests ported from Pingora

test "Error into source conversions" {
    const e1 = Error.new(.connect_error).intoUp();
    try testing.expectEqual(e1.esource, .upstream);

    const e2 = Error.new(.connect_error).intoDown();
    try testing.expectEqual(e2.esource, .downstream);

    const e3 = Error.new(.connect_error).intoIn();
    try testing.expectEqual(e3.esource, .internal);
}

test "Error root cause chain" {
    const e1 = Error.new(.internal_error);
    const e2 = Error.because(.connect_error, "connection failed", &e1);
    const e3 = Error.because(.http_status, "request failed", &e2);

    try testing.expectEqual(e3.rootEtype(), .internal_error);
    try testing.expectEqual(e3.rootCause().etype, .internal_error);
}

test "Error http status" {
    const e = Error.httpStatus(404);
    try testing.expectEqual(e.etype, .http_status);
    try testing.expectEqual(e.http_status_code, 404);
}

test "ImmutStr deinit owned" {
    var owned = ImmutStr.fromOwned(try testing.allocator.dupe(u8, "test"));
    defer owned.deinit(testing.allocator);
    try testing.expectEqualStrings("test", owned.asStr());
}

test "ImmutStr deinit static" {
    var static_str = ImmutStr.fromStatic("static");
    static_str.deinit(testing.allocator); // Should not crash
    try testing.expectEqualStrings("static", static_str.asStr());
}
