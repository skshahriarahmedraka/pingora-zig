//! pingora-zig: Server Framework
//!
//! Multi-service server with daemonization, graceful shutdown,
//! and configuration management.
//!
//! This is a pure Zig implementation. No C dependencies.

const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const http_server = @import("http_server.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Server Configuration
// ============================================================================

/// Server configuration
pub const ServerConfig = struct {
    /// Number of worker threads (0 = auto-detect based on CPU count)
    threads: u32 = 0,
    /// Whether to daemonize (run in background)
    daemon: bool = false,
    /// PID file path (for daemon mode)
    pid_file: ?[]const u8 = null,
    /// Working directory (for daemon mode)
    work_dir: ?[]const u8 = null,
    /// User to run as (for privilege dropping)
    user: ?[]const u8 = null,
    /// Group to run as (for privilege dropping)
    group: ?[]const u8 = null,
    /// Graceful shutdown timeout in seconds
    graceful_shutdown_timeout_s: u64 = 30,
    /// Whether to enable zero-downtime restart (Unix only)
    upgrade_enabled: bool = false,
    /// Path for upgrade socket (Unix only)
    upgrade_socket: ?[]const u8 = null,

    /// Get effective thread count
    pub fn getThreadCount(self: *const ServerConfig) u32 {
        if (self.threads == 0) {
            return @intCast(std.Thread.getCpuCount() catch 4);
        }
        return self.threads;
    }
};

/// Listener configuration
pub const ListenerConfig = struct {
    /// Address to bind to
    address: []const u8,
    /// Port to bind to
    port: u16,
    /// Whether TLS is enabled
    tls: bool = false,
    /// TLS certificate path
    cert_path: ?[]const u8 = null,
    /// TLS key path
    key_path: ?[]const u8 = null,
    /// Reuse port (SO_REUSEPORT)
    reuse_port: bool = true,
    /// Backlog for listen queue
    backlog: u31 = 1024,
};

// ============================================================================
// Server State
// ============================================================================

/// Server state
pub const ServerState = enum {
    /// Server is stopped
    stopped,
    /// Server is starting up
    starting,
    /// Server is running
    running,
    /// Server is shutting down gracefully
    shutting_down,
    /// Server encountered an error
    errored,
};

/// Server statistics
pub const ServerStats = struct {
    /// Start time (unix timestamp)
    start_time: i64,
    /// Total requests handled
    requests_total: u64,
    /// Active connections
    active_connections: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Total bytes sent
    bytes_sent: u64,

    pub fn init() ServerStats {
        return .{
            .start_time = std.time.timestamp(),
            .requests_total = 0,
            .active_connections = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        };
    }

    pub fn uptime(self: *const ServerStats) i64 {
        return std.time.timestamp() - self.start_time;
    }
};

// ============================================================================
// Service Interface
// ============================================================================

/// Service callback type
pub const ServiceHandler = *const fn (*ServiceContext) anyerror!void;

/// Service context passed to handlers
pub const ServiceContext = struct {
    /// Service name
    name: []const u8,
    /// Server reference
    server: *Server,
    /// Allocator
    allocator: Allocator,
    /// Service-specific data
    data: ?*anyopaque,
};

/// Service definition
pub const Service = struct {
    /// Service name
    name: []const u8,
    /// Listener configurations
    listeners: []const ListenerConfig,
    /// Handler function
    handler: ServiceHandler,
    /// Service-specific data
    data: ?*anyopaque,
    /// Whether service is enabled
    enabled: bool,

    pub fn create(name: []const u8, listeners: []const ListenerConfig, handler: ServiceHandler) Service {
        return .{
            .name = name,
            .listeners = listeners,
            .handler = handler,
            .data = null,
            .enabled = true,
        };
    }

    pub fn withData(self: Service, data: *anyopaque) Service {
        var s = self;
        s.data = data;
        return s;
    }
};

// ============================================================================
// Shutdown Controller
// ============================================================================

/// Controls graceful shutdown
pub const ShutdownController = struct {
    /// Shutdown requested flag
    shutdown_requested: std.atomic.Value(bool),
    /// Shutdown complete flag
    shutdown_complete: std.atomic.Value(bool),
    /// Active tasks counter
    active_tasks: std.atomic.Value(u64),
    /// Shutdown timeout (nanoseconds)
    timeout_ns: u64,
    /// Shutdown start time
    shutdown_start: ?i128,

    const Self = @This();

    pub fn init(timeout_seconds: u64) Self {
        return .{
            .shutdown_requested = std.atomic.Value(bool).init(false),
            .shutdown_complete = std.atomic.Value(bool).init(false),
            .active_tasks = std.atomic.Value(u64).init(0),
            .timeout_ns = timeout_seconds * std.time.ns_per_s,
            .shutdown_start = null,
        };
    }

    /// Request shutdown
    pub fn requestShutdown(self: *Self) void {
        if (!self.shutdown_requested.swap(true, .seq_cst)) {
            self.shutdown_start = std.time.nanoTimestamp();
        }
    }

    /// Check if shutdown is requested
    pub fn isShutdownRequested(self: *const Self) bool {
        return self.shutdown_requested.load(.seq_cst);
    }

    /// Check if shutdown is complete
    pub fn isShutdownComplete(self: *const Self) bool {
        return self.shutdown_complete.load(.seq_cst);
    }

    /// Register a task starting
    pub fn taskStart(self: *Self) void {
        _ = self.active_tasks.fetchAdd(1, .seq_cst);
    }

    /// Register a task completing
    pub fn taskComplete(self: *Self) void {
        const prev = self.active_tasks.fetchSub(1, .seq_cst);
        if (prev == 1 and self.isShutdownRequested()) {
            self.shutdown_complete.store(true, .seq_cst);
        }
    }

    /// Get number of active tasks
    pub fn getActiveTasks(self: *const Self) u64 {
        return self.active_tasks.load(.seq_cst);
    }

    /// Wait for shutdown to complete (with timeout)
    pub fn waitForShutdown(self: *Self) bool {
        const poll_interval_ns: u64 = 100_000_000; // 100ms

        while (!self.isShutdownComplete()) {
            // Check timeout
            if (self.shutdown_start) |start| {
                const elapsed = std.time.nanoTimestamp() - start;
                if (elapsed >= @as(i128, self.timeout_ns)) {
                    return false; // Timeout
                }
            }

            // Check if no active tasks
            if (self.getActiveTasks() == 0) {
                self.shutdown_complete.store(true, .seq_cst);
                return true;
            }

            std.Thread.sleep(poll_interval_ns);
        }

        return true;
    }
};

// ============================================================================
// Server
// ============================================================================

/// Multi-service server
pub const Server = struct {
    /// Server configuration
    config: ServerConfig,
    /// Registered services
    services: std.ArrayListUnmanaged(Service),
    /// Server state
    state: std.atomic.Value(u8),
    /// Statistics
    stats: ServerStats,
    /// Shutdown controller
    shutdown: ShutdownController,
    /// Worker threads
    workers: std.ArrayListUnmanaged(std.Thread),
    /// Allocator
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ServerConfig) Self {
        return .{
            .config = config,
            .services = .{},
            .state = std.atomic.Value(u8).init(@intFromEnum(ServerState.stopped)),
            .stats = ServerStats.init(),
            .shutdown = ShutdownController.init(config.graceful_shutdown_timeout_s),
            .workers = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Wait for workers
        for (self.workers.items) |worker| {
            worker.join();
        }
        self.workers.deinit(self.allocator);
        self.services.deinit(self.allocator);
    }

    /// Get current server state
    pub fn getState(self: *const Self) ServerState {
        return @enumFromInt(self.state.load(.seq_cst));
    }

    /// Set server state
    fn setState(self: *Self, new_state: ServerState) void {
        self.state.store(@intFromEnum(new_state), .seq_cst);
    }

    /// Add a service to the server
    pub fn addService(self: *Self, service: Service) !void {
        try self.services.append(self.allocator, service);
    }

    /// Start the server
    pub fn start(self: *Self) !void {
        if (self.getState() != .stopped) {
            return error.InvalidState;
        }

        self.setState(.starting);

        // Daemonize if configured (Unix only)
        if (self.config.daemon) {
            try self.daemonize();
        }

        // Start services
        for (self.services.items) |service| {
            if (!service.enabled) continue;

            // For each listener, spawn worker threads
            for (service.listeners) |_| {
                const thread_count = self.config.getThreadCount();
                for (0..thread_count) |_| {
                    const ctx = ServiceContext{
                        .name = service.name,
                        .server = self,
                        .allocator = self.allocator,
                        .data = service.data,
                    };
                    _ = ctx;
                    // In a real implementation, we would spawn threads here
                    // For now, we just track the service is registered
                }
            }
        }

        self.setState(.running);
        self.stats = ServerStats.init();
    }

    /// Stop the server gracefully
    pub fn stop(self: *Self) !void {
        const current_state = self.getState();
        if (current_state != .running) {
            return error.InvalidState;
        }

        self.setState(.shutting_down);
        self.shutdown.requestShutdown();

        // Wait for graceful shutdown
        const clean = self.shutdown.waitForShutdown();
        if (!clean) {
            // Timeout - force stop
            std.log.warn("Graceful shutdown timed out, forcing stop", .{});
        }

        self.setState(.stopped);
    }

    /// Request shutdown (signal handler friendly)
    pub fn requestShutdown(self: *Self) void {
        self.shutdown.requestShutdown();
    }

    /// Check if server is running
    pub fn isRunning(self: *const Self) bool {
        return self.getState() == .running;
    }

    /// Run the server until shutdown is requested
    pub fn run(self: *Self) !void {
        try self.start();

        // Main loop - wait for shutdown
        while (self.isRunning() and !self.shutdown.isShutdownRequested()) {
            std.Thread.sleep(100_000_000); // 100ms
        }

        try self.stop();
    }

    /// Daemonize the process (Unix only)
    fn daemonize(self: *Self) !void {
        if (builtin.os.tag == .windows) {
            return error.UnsupportedPlatform;
        }

        // Fork
        const pid = std.posix.fork() catch return error.ForkFailed;
        if (pid != 0) {
            // Parent exits
            std.posix.exit(0);
        }

        // Create new session
        _ = std.posix.setsid() catch return error.SetsidFailed;

        // Fork again to prevent acquiring a controlling terminal
        const pid2 = std.posix.fork() catch return error.ForkFailed;
        if (pid2 != 0) {
            std.posix.exit(0);
        }

        // Change working directory
        if (self.config.work_dir) |dir| {
            std.posix.chdir(dir) catch return error.ChdirFailed;
        }

        // Write PID file
        if (self.config.pid_file) |path| {
            try self.writePidFile(path);
        }
    }

    /// Write PID file
    fn writePidFile(_: *Self, path: []const u8) !void {
        const file = std.fs.cwd().createFile(path, .{}) catch return error.PidFileError;
        defer file.close();

        var buf: [32]u8 = undefined;
        if (builtin.os.tag != .windows) {
            const pid = std.os.linux.getpid();
            const written = std.fmt.bufPrint(&buf, "{d}\n", .{pid}) catch return error.PidFileError;
            file.writeAll(written) catch return error.PidFileError;
        }
    }

    /// Get server statistics
    pub fn getStats(self: *const Self) ServerStats {
        return self.stats;
    }
};

// ============================================================================
// Signal Handler (Unix only)
// ============================================================================

/// Global server reference for signal handling
var global_server: ?*Server = null;

/// Install signal handlers
pub fn installSignalHandlers(server: *Server) !void {
    if (builtin.os.tag == .windows) {
        return; // No Unix signals on Windows
    }

    global_server = server;

    // SIGTERM - graceful shutdown
    const sigterm_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSigterm },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sigterm_action, null) catch return error.SignalError;

    // SIGINT - graceful shutdown
    const sigint_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSigterm },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sigint_action, null) catch return error.SignalError;
}

fn handleSigterm(_: c_int) callconv(.C) void {
    if (global_server) |server| {
        server.requestShutdown();
    }
}

// ============================================================================
// Configuration Hot Reload
// ============================================================================

/// Configuration file format
pub const ConfigFormat = enum {
    /// JSON format
    json,
    // Future: yaml, toml
};

/// Configuration reload callback type
pub const ConfigReloadCallback = *const fn (old_config: ?*const anyopaque, new_config: *const anyopaque) bool;

/// Configuration manager for hot reloading
/// Monitors configuration file for changes and triggers reload callbacks
pub const ConfigManager = struct {
    allocator: Allocator,
    config_path: ?[]const u8,
    format: ConfigFormat,
    last_modified: i128,
    reload_callbacks: std.ArrayListUnmanaged(ConfigReloadCallback),
    current_config: ?[]u8,
    watch_interval_ms: u64,
    enabled: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .config_path = null,
            .format = .json,
            .last_modified = 0,
            .reload_callbacks = .{},
            .current_config = null,
            .watch_interval_ms = 1000,
            .enabled = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.config_path) |path| {
            self.allocator.free(path);
        }
        if (self.current_config) |config| {
            self.allocator.free(config);
        }
        self.reload_callbacks.deinit(self.allocator);
    }

    /// Set the configuration file path
    pub fn setConfigPath(self: *Self, path: []const u8) !void {
        if (self.config_path) |old_path| {
            self.allocator.free(old_path);
        }
        self.config_path = try self.allocator.dupe(u8, path);
    }

    /// Set the watch interval in milliseconds
    pub fn setWatchInterval(self: *Self, interval_ms: u64) void {
        self.watch_interval_ms = interval_ms;
    }

    /// Add a callback to be called on configuration reload
    pub fn addReloadCallback(self: *Self, callback: ConfigReloadCallback) !void {
        try self.reload_callbacks.append(self.allocator, callback);
    }

    /// Enable configuration watching
    pub fn enable(self: *Self) void {
        self.enabled = true;
    }

    /// Disable configuration watching
    pub fn disable(self: *Self) void {
        self.enabled = false;
    }

    /// Load configuration from file
    pub fn loadConfig(self: *Self) ![]const u8 {
        const path = self.config_path orelse return error.NoConfigPath;

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        self.last_modified = stat.mtime;

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024); // 1MB max

        if (self.current_config) |old| {
            self.allocator.free(old);
        }
        self.current_config = content;

        return content;
    }

    /// Check if configuration file has changed
    pub fn hasConfigChanged(self: *Self) bool {
        const path = self.config_path orelse return false;

        const file = std.fs.cwd().openFile(path, .{}) catch return false;
        defer file.close();

        const stat = file.stat() catch return false;
        return stat.mtime != self.last_modified;
    }

    /// Check for changes and reload if necessary
    /// Returns true if configuration was reloaded
    pub fn checkAndReload(self: *Self) !bool {
        if (!self.enabled) return false;
        if (!self.hasConfigChanged()) return false;

        const old_config = self.current_config;
        const new_config = try self.loadConfig();

        // Notify all callbacks
        var all_succeeded = true;
        for (self.reload_callbacks.items) |callback| {
            const old_ptr: ?*const anyopaque = if (old_config) |o| @ptrCast(o.ptr) else null;
            const new_ptr: *const anyopaque = @ptrCast(new_config.ptr);
            if (!callback(old_ptr, new_ptr)) {
                all_succeeded = false;
            }
        }

        return all_succeeded;
    }

    /// Get current configuration content
    pub fn getCurrentConfig(self: *const Self) ?[]const u8 {
        return self.current_config;
    }
};

/// SIGHUP handler for configuration reload
var global_config_manager: ?*ConfigManager = null;

pub fn setGlobalConfigManager(manager: *ConfigManager) void {
    global_config_manager = manager;
}

pub fn handleSighup() void {
    if (global_config_manager) |manager| {
        _ = manager.checkAndReload() catch {};
    }
}

// ============================================================================
// Zero-Downtime Restart / FD Transfer (Unix only)
// ============================================================================

/// Container for open file descriptors and their associated bind addresses
/// Used for transferring listening sockets during graceful upgrades
pub const Fds = struct {
    map: std.StringHashMapUnmanaged(std.posix.fd_t),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .map = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all keys (bind addresses)
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit(self.allocator);
    }

    /// Add a file descriptor with its bind address
    pub fn add(self: *Self, bind: []const u8, fd: std.posix.fd_t) !void {
        const key = try self.allocator.dupe(u8, bind);
        errdefer self.allocator.free(key);
        try self.map.put(self.allocator, key, fd);
    }

    /// Get a file descriptor by its bind address
    pub fn get(self: *const Self, bind: []const u8) ?std.posix.fd_t {
        return self.map.get(bind);
    }

    /// Get the number of file descriptors
    pub fn count(self: *const Self) usize {
        return self.map.count();
    }

    /// Serialize to arrays for transfer
    pub fn serialize(self: *const Self, allocator: Allocator) !struct { binds: [][]const u8, fds: []std.posix.fd_t } {
        const n = self.map.count();
        var binds = try allocator.alloc([]const u8, n);
        var fds = try allocator.alloc(std.posix.fd_t, n);

        var i: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            binds[i] = entry.key_ptr.*;
            fds[i] = entry.value_ptr.*;
            i += 1;
        }

        return .{ .binds = binds, .fds = fds };
    }

    /// Deserialize from arrays
    pub fn deserialize(self: *Self, binds: []const []const u8, fds: []const std.posix.fd_t) !void {
        std.debug.assert(binds.len == fds.len);
        for (binds, fds) |bind, fd| {
            try self.add(bind, fd);
        }
    }
};

/// Upgrade socket path for FD transfer
pub const DEFAULT_UPGRADE_SOCK_PATH = "/tmp/pingora_upgrade.sock";

/// Error type for upgrade operations
pub const UpgradeError = error{
    /// Platform not supported for upgrades
    PlatformNotSupported,
    /// Failed to create socket
    SocketCreationFailed,
    /// Failed to bind socket
    BindFailed,
    /// Failed to connect to upgrade socket
    ConnectFailed,
    /// Failed to send file descriptors
    SendFailed,
    /// Failed to receive file descriptors
    ReceiveFailed,
    /// Timeout waiting for connection
    Timeout,
    /// Invalid data received
    InvalidData,
    /// Socket operation failed
    SocketError,
};

/// Configuration for upgrade process
pub const UpgradeConfig = struct {
    /// Path to the Unix domain socket for FD transfer
    sock_path: []const u8 = DEFAULT_UPGRADE_SOCK_PATH,
    /// Maximum time to wait for upgrade in seconds
    timeout_secs: u32 = 60,
    /// Number of retries for connection
    max_retries: u32 = 5,
    /// Retry interval in milliseconds
    retry_interval_ms: u64 = 1000,
};

/// Upgrade coordinator for zero-downtime restarts
/// Handles FD transfer between old and new process
pub const UpgradeCoordinator = struct {
    config: UpgradeConfig,
    fds: Fds,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, config: UpgradeConfig) Self {
        return .{
            .config = config,
            .fds = Fds.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.fds.deinit();
    }

    /// Register a listening socket for transfer
    pub fn registerSocket(self: *Self, bind_address: []const u8, fd: std.posix.fd_t) !void {
        try self.fds.add(bind_address, fd);
    }

    /// Check if we're running as the new process in an upgrade
    /// (i.e., we should receive FDs from the old process)
    pub fn isUpgradeInProgress(self: *const Self) bool {
        // Check if upgrade socket exists
        const stat = std.fs.cwd().statFile(self.config.sock_path) catch return false;
        _ = stat;
        return true;
    }

    /// Send all registered FDs to the new process (called by old process)
    /// This is Linux-specific using SCM_RIGHTS
    pub fn sendFdsToNewProcess(self: *Self) UpgradeError!void {
        // Only supported on Linux
        if (comptime !@hasDecl(std.posix, "SCM") or @import("builtin").os.tag != .linux) {
            return UpgradeError.PlatformNotSupported;
        }

        if (self.fds.count() == 0) {
            return; // Nothing to send
        }

        // Create Unix domain socket and connect
        const sock_fd = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0) catch {
            return UpgradeError.SocketCreationFailed;
        };
        defer std.posix.close(sock_fd);

        // Connect to the listening socket (with retries)
        var retries: u32 = 0;
        while (retries < self.config.max_retries) : (retries += 1) {
            var addr: std.posix.sockaddr.un = .{ .family = std.posix.AF.UNIX, .path = undefined };
            @memset(&addr.path, 0);
            const path_bytes = self.config.sock_path;
            @memcpy(addr.path[0..path_bytes.len], path_bytes);

            std.posix.connect(sock_fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) catch {
                std.time.sleep(self.config.retry_interval_ms * std.time.ns_per_ms);
                continue;
            };
            break;
        } else {
            return UpgradeError.ConnectFailed;
        }

        // Serialize the bind addresses
        const serialized = self.fds.serialize(self.allocator) catch return UpgradeError.SendFailed;
        defer self.allocator.free(serialized.binds);
        defer self.allocator.free(serialized.fds);

        // Send FDs using SCM_RIGHTS (platform specific)
        // Note: Full implementation requires sendmsg with cmsg
        // For now, we serialize bind addresses and send as simple message
        var buf: [2048]u8 = undefined;
        var pos: usize = 0;

        // Write count
        const count_bytes = std.mem.asBytes(&@as(u32, @intCast(serialized.binds.len)));
        @memcpy(buf[pos..][0..4], count_bytes);
        pos += 4;

        // Write bind addresses (length-prefixed)
        for (serialized.binds) |bind| {
            const len_bytes = std.mem.asBytes(&@as(u32, @intCast(bind.len)));
            @memcpy(buf[pos..][0..4], len_bytes);
            pos += 4;
            @memcpy(buf[pos..][0..bind.len], bind);
            pos += bind.len;
        }

        // Send the message
        _ = std.posix.write(sock_fd, buf[0..pos]) catch return UpgradeError.SendFailed;

        return;
    }

    /// Receive FDs from old process (called by new process)
    /// This is Linux-specific using SCM_RIGHTS
    pub fn receiveFdsFromOldProcess(self: *Self) UpgradeError!void {
        // Only supported on Linux
        if (comptime !@hasDecl(std.posix, "SCM") or @import("builtin").os.tag != .linux) {
            return UpgradeError.PlatformNotSupported;
        }

        // Create and bind listening socket
        const listen_fd = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0) catch {
            return UpgradeError.SocketCreationFailed;
        };
        defer std.posix.close(listen_fd);

        // Remove old socket file if exists
        std.fs.cwd().deleteFile(self.config.sock_path) catch {};

        // Bind to socket path
        var addr: std.posix.sockaddr.un = .{ .family = std.posix.AF.UNIX, .path = undefined };
        @memset(&addr.path, 0);
        const path_bytes = self.config.sock_path;
        @memcpy(addr.path[0..path_bytes.len], path_bytes);

        std.posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) catch {
            return UpgradeError.BindFailed;
        };

        // Listen for connection
        std.posix.listen(listen_fd, 1) catch {
            return UpgradeError.SocketError;
        };

        // Accept connection (with timeout)
        const timeout_ns = @as(u64, self.config.timeout_secs) * std.time.ns_per_s;
        const start = std.time.nanoTimestamp();

        while (true) {
            const elapsed = @as(u64, @intCast(std.time.nanoTimestamp() - start));
            if (elapsed > timeout_ns) {
                // Cleanup
                std.fs.cwd().deleteFile(self.config.sock_path) catch {};
                return UpgradeError.Timeout;
            }

            _ = std.posix.accept(listen_fd, null, null) catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(100 * std.time.ns_per_ms);
                    continue;
                }
                std.fs.cwd().deleteFile(self.config.sock_path) catch {};
                return UpgradeError.SocketError;
            };

            // Connection accepted - receive FDs using SCM_RIGHTS
            // Note: Full implementation requires recvmsg with cmsg
            break;
        }

        // Cleanup socket file
        std.fs.cwd().deleteFile(self.config.sock_path) catch {};
    }

    /// Perform graceful upgrade
    /// Returns true if upgrade was successful
    pub fn performUpgrade(self: *Self) !bool {
        if (self.isUpgradeInProgress()) {
            // We're the new process, receive FDs
            self.receiveFdsFromOldProcess() catch |err| {
                if (err == UpgradeError.PlatformNotSupported) {
                    return false;
                }
                return err;
            };
            return true;
        }
        return false;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ServerConfig getThreadCount" {
    const config1 = ServerConfig{ .threads = 4 };
    try testing.expectEqual(@as(u32, 4), config1.getThreadCount());

    const config2 = ServerConfig{ .threads = 0 };
    try testing.expect(config2.getThreadCount() > 0);
}

test "ServerState transitions" {
    const stopped: ServerState = .stopped;
    const running: ServerState = .running;

    try testing.expect(stopped != running);
    try testing.expectEqual(@as(u8, 0), @intFromEnum(stopped));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(running));
}

test "ServerStats init and uptime" {
    const stats = ServerStats.init();
    try testing.expect(stats.start_time > 0);
    try testing.expectEqual(@as(u64, 0), stats.requests_total);

    // Uptime should be near 0
    const uptime = stats.uptime();
    try testing.expect(uptime >= 0);
    try testing.expect(uptime < 2);
}

test "ShutdownController basic" {
    var controller = ShutdownController.init(30);

    try testing.expect(!controller.isShutdownRequested());
    try testing.expect(!controller.isShutdownComplete());
    try testing.expectEqual(@as(u64, 0), controller.getActiveTasks());

    // Start and complete a task
    controller.taskStart();
    try testing.expectEqual(@as(u64, 1), controller.getActiveTasks());

    controller.taskComplete();
    try testing.expectEqual(@as(u64, 0), controller.getActiveTasks());

    // Request shutdown
    controller.requestShutdown();
    try testing.expect(controller.isShutdownRequested());
}

test "ShutdownController shutdown with no tasks" {
    var controller = ShutdownController.init(1);

    controller.requestShutdown();
    const success = controller.waitForShutdown();
    try testing.expect(success);
    try testing.expect(controller.isShutdownComplete());
}

test "Server init and deinit" {
    var server = Server.init(testing.allocator, .{});
    defer server.deinit();

    try testing.expectEqual(ServerState.stopped, server.getState());
}

test "Server add service" {
    var server = Server.init(testing.allocator, .{});
    defer server.deinit();

    const listeners = [_]ListenerConfig{
        .{ .address = "127.0.0.1", .port = 8080 },
    };

    const handler = struct {
        fn handle(_: *ServiceContext) anyerror!void {}
    }.handle;

    const service = Service.create("test", &listeners, handler);
    try server.addService(service);

    try testing.expectEqual(@as(usize, 1), server.services.items.len);
}

test "Service creation" {
    const listeners = [_]ListenerConfig{
        .{ .address = "0.0.0.0", .port = 80 },
        .{ .address = "0.0.0.0", .port = 443, .tls = true },
    };

    const handler = struct {
        fn handle(_: *ServiceContext) anyerror!void {}
    }.handle;

    const service = Service.create("http", &listeners, handler);

    try testing.expectEqualStrings("http", service.name);
    try testing.expectEqual(@as(usize, 2), service.listeners.len);
    try testing.expect(service.enabled);
}

test "ListenerConfig defaults" {
    const config = ListenerConfig{
        .address = "127.0.0.1",
        .port = 8080,
    };

    try testing.expect(!config.tls);
    try testing.expect(config.reuse_port);
    try testing.expectEqual(@as(u31, 1024), config.backlog);
}

test "Fds init and deinit" {
    const allocator = testing.allocator;
    var fds = Fds.init(allocator);
    defer fds.deinit();

    try testing.expectEqual(@as(usize, 0), fds.count());
}

test "Fds add and get" {
    const allocator = testing.allocator;
    var fds = Fds.init(allocator);
    defer fds.deinit();

    try fds.add("0.0.0.0:80", 10);
    try fds.add("0.0.0.0:443", 11);

    try testing.expectEqual(@as(usize, 2), fds.count());
    try testing.expectEqual(@as(std.posix.fd_t, 10), fds.get("0.0.0.0:80").?);
    try testing.expectEqual(@as(std.posix.fd_t, 11), fds.get("0.0.0.0:443").?);
    try testing.expect(fds.get("unknown") == null);
}

test "Fds serialize" {
    const allocator = testing.allocator;
    var fds = Fds.init(allocator);
    defer fds.deinit();

    try fds.add("0.0.0.0:80", 10);
    try fds.add("0.0.0.0:443", 11);

    const serialized = try fds.serialize(allocator);
    defer allocator.free(serialized.binds);
    defer allocator.free(serialized.fds);

    try testing.expectEqual(@as(usize, 2), serialized.binds.len);
    try testing.expectEqual(@as(usize, 2), serialized.fds.len);
}

test "UpgradeConfig defaults" {
    const config = UpgradeConfig{};

    try testing.expectEqualStrings(DEFAULT_UPGRADE_SOCK_PATH, config.sock_path);
    try testing.expectEqual(@as(u32, 60), config.timeout_secs);
    try testing.expectEqual(@as(u32, 5), config.max_retries);
}

test "UpgradeCoordinator init and deinit" {
    const allocator = testing.allocator;
    var coordinator = UpgradeCoordinator.init(allocator, .{});
    defer coordinator.deinit();

    try testing.expectEqual(@as(usize, 0), coordinator.fds.count());
}

test "UpgradeCoordinator registerSocket" {
    const allocator = testing.allocator;
    var coordinator = UpgradeCoordinator.init(allocator, .{});
    defer coordinator.deinit();

    try coordinator.registerSocket("0.0.0.0:8080", 42);

    try testing.expectEqual(@as(usize, 1), coordinator.fds.count());
    try testing.expectEqual(@as(std.posix.fd_t, 42), coordinator.fds.get("0.0.0.0:8080").?);
}

test "UpgradeCoordinator isUpgradeInProgress" {
    const allocator = testing.allocator;
    var coordinator = UpgradeCoordinator.init(allocator, .{ .sock_path = "/tmp/nonexistent_upgrade.sock" });
    defer coordinator.deinit();

    // Should return false when socket doesn't exist
    try testing.expect(!coordinator.isUpgradeInProgress());
}

test "ConfigFormat enum" {
    const format: ConfigFormat = .json;
    try testing.expectEqual(ConfigFormat.json, format);
}

test "ConfigManager init and deinit" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    try testing.expect(manager.config_path == null);
    try testing.expect(!manager.enabled);
    try testing.expectEqual(@as(u64, 1000), manager.watch_interval_ms);
}

test "ConfigManager setConfigPath" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    try manager.setConfigPath("/etc/pingora.json");
    try testing.expectEqualStrings("/etc/pingora.json", manager.config_path.?);

    // Replace path
    try manager.setConfigPath("/etc/new_config.json");
    try testing.expectEqualStrings("/etc/new_config.json", manager.config_path.?);
}

test "ConfigManager enable disable" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    try testing.expect(!manager.enabled);

    manager.enable();
    try testing.expect(manager.enabled);

    manager.disable();
    try testing.expect(!manager.enabled);
}

test "ConfigManager setWatchInterval" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    manager.setWatchInterval(5000);
    try testing.expectEqual(@as(u64, 5000), manager.watch_interval_ms);
}

test "ConfigManager addReloadCallback" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    const callback = struct {
        fn cb(_: ?*const anyopaque, _: *const anyopaque) bool {
            return true;
        }
    }.cb;

    try manager.addReloadCallback(callback);
    try testing.expectEqual(@as(usize, 1), manager.reload_callbacks.items.len);
}

test "ConfigManager hasConfigChanged no path" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    try testing.expect(!manager.hasConfigChanged());
}

test "ConfigManager checkAndReload disabled" {
    const allocator = testing.allocator;
    var manager = ConfigManager.init(allocator);
    defer manager.deinit();

    const result = try manager.checkAndReload();
    try testing.expect(!result);
}
