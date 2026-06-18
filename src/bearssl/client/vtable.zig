/// VTable operations and callback management for BearSSL TLS
///
/// This module provides all vtable implementations for the SecureSocket interface,
/// including connection handling, data I/O operations, and resource management.
///
/// Key features:
/// - Type-safe vtable context management
/// - Enhanced I/O callbacks with error handling
/// - Connection lifecycle management
/// - Resource cleanup and memory management
/// - Performance monitoring and debugging
const std = @import("std");
const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;
const memory = @import("memory.zig");
const ManagedTlsContext = memory.ManagedTlsContext;
const error_handling = @import("error.zig");
const TlsError = error_handling.TlsError;
const context_module = @import("context.zig");
const TypeSafeContext = context_module.TypeSafeContext;
const ContextType = context_module.ContextType;
const TypeSafeWrapper = context_module.TypeSafeWrapper;
const security = @import("security.zig");
const SecurityConfig = security.SecurityConfig;
const debug = @import("debug.zig");
const crypto = @import("crypto.zig");

const log = std.log.scoped(.bearssl_vtable);

const c = @cImport({
    @cInclude("bearssl.h");
});

/// Forward declaration for BearSSL type
const BearSSL = @import("../lib.zig").BearSSL;

/// Callback context data for BearSSL I/O operations.
/// This struct maintains the state needed for the BearSSL callbacks to
/// interact with the underlying socket and runtime.
///
/// Fields:
/// - socket: The raw socket used for transport
/// - runtime: Reference to the async runtime for non-blocking operations
/// - trace_enabled: When true, enables detailed TLS traffic logging
pub const CallbackContextData = struct {
    socket: Socket,
    runtime: ?*Runtime,
    trace_enabled: bool = false,

    /// Wrapper to dump TLS traffic data for debugging
    pub fn dump_blob(ctx: *const @This(), direction: []const u8, data: []const u8) void {
        debug.DebugUtils.dumpBlob(ctx.trace_enabled, direction, data);
    }
};

/// Type-safe callback context wrapper
pub const CallbackContext = TypeSafeWrapper(CallbackContextData, ContextType.callback_context);

/// Internal context data maintained for each BearSSL SecureSocket instance.
/// Uses ManagedTlsContext for unified memory management with RAII pattern.
///
/// This structure contains:
/// - Managed TLS context with automatic cleanup
/// - Reference to BearSSL configuration
/// - Callback context for socket interactions
/// - Error statistics for monitoring
/// - Security audit logging
/// - Performance monitoring
///
/// All memory is automatically managed - no manual cleanup required.
pub const VtableContextData = struct {
    /// Unified memory management for all TLS resources
    managed_ctx: ManagedTlsContext,

    /// Reference to BearSSL configuration
    bearssl: *BearSSL,

    /// Callback context for socket operations
    cb_ctx: *CallbackContext,

    /// Error statistics for monitoring and debugging
    error_stats: error_handling.ErrorStats,

    /// Security audit logging
    security_audit: ?*security.SecurityAudit,

    /// Performance monitoring
    performance_monitor: ?*debug.PerformanceMonitor,

    /// Logs the current state of the TLS engine for debugging
    ///
    /// This function provides detailed diagnostics about the current state of
    /// the TLS connection, including engine state, protocols, and certificate
    /// validation status.
    ///
    /// Parameters:
    /// - title: A description for the log entry (e.g., "Before handshake")
    pub fn logState(ctx: *@This(), title: []const u8) !void {
        const client_ctx = try ctx.managed_ctx.getClientCtx();
        const x509_ctx = try ctx.managed_ctx.getX509Ctx();

        const trust_count = if (ctx.bearssl.trust_store.anchors.items.len > 0)
            ctx.bearssl.trust_store.anchors.items.len
        else
            @import("trust.zig").TrustAnchors.getDefaultCount();

        const stats = ctx.managed_ctx.getMemoryStats();

        debug.StateInspector.logEngineState(title, client_ctx, x509_ctx, trust_count, stats, &ctx.error_stats);
    }

    /// Generate comprehensive diagnostics report
    pub fn generateDiagnosticsReport(self: *@This(), writer: anytype) !void {
        const client_ctx = try self.managed_ctx.getClientCtx();
        const x509_ctx = try self.managed_ctx.getX509Ctx();
        const stats = self.managed_ctx.getMemoryStats();

        try debug.StateInspector.generateDiagnosticsReport(writer, client_ctx, x509_ctx, stats, &self.error_stats);

        // Add performance report if available
        if (self.performance_monitor) |monitor| {
            try monitor.generatePerformanceReport(writer);
        }

        // Add security audit report if available
        if (self.security_audit) |audit| {
            try audit.generateReport(writer);
        }
    }
};

/// Type-safe vtable context wrapper
pub const VtableContext = TypeSafeWrapper(VtableContextData, ContextType.vtable_context);

/// Type-safe validation of callback context pointer
/// Returns the validated context or null
fn validateCallbackContext(ctx_ptr: ?*anyopaque) ?*CallbackContext {
    const ptr = ctx_ptr orelse {
        log.err("Received null context pointer in callback", .{});
        return null;
    };

    // Use type-safe validation and casting
    const cb_ctx = CallbackContext.fromOpaque(ptr) catch |err| {
        log.err("Failed to validate callback context: {s}", .{@errorName(err)});
        return null;
    };

    const data = cb_ctx.getData() catch |err| {
        log.err("Failed to get callback context data: {s}", .{@errorName(err)});
        return null;
    };

    if (data.runtime == null) {
        log.err("Runtime not available in callback", .{});
        return null;
    }

    return cb_ctx;
}

/// Type-safe retrieval and setup of VtableContext from an opaque pointer
/// A common function used by all vtable implementations
fn getVtableContext(i: *anyopaque, r: *Runtime) !*VtableContext {
    // Use type-safe validation and casting
    const ctx = try VtableContext.fromOpaque(i);
    const data = try ctx.getData();

    // Set up runtime in callback context
    const cb_data = try data.cb_ctx.getData();
    cb_data.runtime = r;

    // Set the callback context in the managed context
    data.managed_ctx.setCallbackCtx(data.cb_ctx.toOpaque());

    return ctx;
}

/// Enhanced BearSSL error handling using standardized error system
/// Returns proper error types and handles graceful closes
fn handleBearSslError(error_code: c_int, operation_name: []const u8) TlsError!usize {
    // Handle graceful close (error code 0)
    if (error_code == 0) {
        log.info("Connection closed gracefully during {s}", .{operation_name});
        return 0;
    }

    // Use standardized error handling
    const tls_error = error_handling.handleBearSslError(error_code, operation_name, null);
    return tls_error;
}

/// Enhanced BearSSL error handling with statistics tracking
/// Returns proper error types and records error statistics
fn handleBearSslErrorWithStats(data: *VtableContextData, error_code: c_int, operation_name: []const u8, bytes_processed: usize) TlsError!usize {
    // Handle graceful close (error code 0)
    if (error_code == 0) {
        log.info("Connection closed gracefully during {s}", .{operation_name});
        return bytes_processed;
    }

    // Use enhanced I/O error handling
    const tls_error = error_handling.handleIoError(error_code, operation_name, bytes_processed);

    // Record error statistics
    data.error_stats.recordError(tls_error);

    return tls_error;
}

/// Internal implementation of socket receive callback with Zig native calling convention.
/// This allows more compiler optimizations while keeping the same logic.
fn brssl_recv_callback_impl(ctx_ptr: ?*anyopaque, buf: [*c]u8, len: usize) c_int {
    // Validate input parameters
    const cb_ctx = validateCallbackContext(ctx_ptr) orelse return -1;

    // Handle empty read request
    if (len == 0) return 0;

    // Create a slice from the C buffer for safe access
    const buffer = buf[0..len];

    // Get callback context data
    const cb_data = cb_ctx.getData() catch |e| {
        log.err("Failed to get callback context data: {s}", .{@errorName(e)});
        return -1;
    };

    // Perform the read operation
    const received = cb_data.socket.recv(cb_data.runtime.?, buffer) catch |e| {
        log.err("Socket read failed: {s}", .{@errorName(e)});
        return -1;
    };

    // Log received data if tracing is enabled
    if (cb_data.trace_enabled and received > 0) {
        cb_data.dump_blob("RECEIVED", buffer[0..received]);
    }

    return @as(c_int, @intCast(received));
}

/// Implementation of BearSSL's recv callback for socket reads.
/// This function bridges between BearSSL's I/O requirements and the Socket interface.
/// It uses a thin C-compatible wrapper around the optimized Zig implementation.
///
/// When BearSSL needs to read data from the network during TLS operations,
/// it calls this function, which then delegates to the Socket.recv method.
pub fn brssl_recv_callback(ctx_ptr: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.c) c_int {
    return brssl_recv_callback_impl(ctx_ptr, buf, len);
}

/// Internal implementation of socket send callback with Zig native calling convention.
/// This allows more compiler optimizations while keeping the same logic.
fn brssl_send_callback_impl(ctx_ptr: ?*anyopaque, buf: [*c]const u8, len: usize) c_int {
    // Validate input parameters
    const cb_ctx = validateCallbackContext(ctx_ptr) orelse return -1;

    // Handle empty send request
    if (len == 0) return 0;

    // Create a slice from the C buffer for safe access
    const buffer = buf[0..len];

    // Get callback context data
    const cb_data = cb_ctx.getData() catch |e| {
        log.err("Failed to get callback context data: {s}", .{@errorName(e)});
        return -1;
    };

    // Log data to be sent if tracing is enabled
    if (cb_data.trace_enabled) {
        cb_data.dump_blob("SENDING", buffer);
    }

    // Perform the send operation
    const sent = cb_data.socket.send(cb_data.runtime.?, buffer) catch |e| {
        log.err("Socket write failed: {s}", .{@errorName(e)});
        return -1;
    };

    return @as(c_int, @intCast(sent));
}

/// Implementation of BearSSL's send callback for socket writes.
/// This function bridges between BearSSL's I/O requirements and the Socket interface.
/// It uses a thin C-compatible wrapper around the optimized Zig implementation.
///
/// When BearSSL needs to send data to the network during TLS operations,
/// it calls this function, which then delegates to the Socket.send method.
pub fn brssl_send_callback(ctx_ptr: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
    return brssl_send_callback_impl(ctx_ptr, buf, len);
}

/// Enhanced TLS handshake error processing using standardized error handling
/// Provides detailed context and logging for handshake failures
///
/// Common failures include:
/// - Certificate validation problems
/// - Protocol version mismatches
/// - MAC/integrity check failures
/// - Handshake protocol errors
fn handleHandshakeErrorImpl(data: *VtableContextData, server_name: ?[]const u8) anyerror {
    const client_ctx = data.managed_ctx.getClientCtx() catch |err| return err;
    const error_code = c.br_ssl_engine_last_error(&client_ctx.eng);

    // Use standardized handshake error handling
    const tls_error = error_handling.handleHandshakeError(error_code, server_name);

    // Record error statistics
    data.error_stats.recordError(tls_error);

    return tls_error;
}

/// Process TLS handshake errors with improved diagnostics.
/// C-compatible wrapper around the optimized Zig implementation.
///
/// This function analyzes BearSSL error codes and provides
/// more detailed logging about the nature of handshake failures.
fn handleHandshakeError(data: *VtableContextData, server_name: ?[]const u8) callconv(.C) anyerror {
    return handleHandshakeErrorImpl(data, server_name);
}

/// Get server name for SNI (Server Name Indication)
/// Returns default "localhost" if not configured
fn getServerName(config: anytype) []const u8 {
    return if (config) |cfg| cfg.server_name orelse "localhost" else "localhost";
}

/// Initialize the TLS engine with server name and callbacks
/// Returns error if engine initialization fails
fn initTlsEngine(data: *VtableContextData, server_name: []const u8) !void {
    const client_ctx = try data.managed_ctx.getClientCtx();
    const sslio_ctx = try data.managed_ctx.getSslIoCtx();

    // Get security configuration (use default if not provided)
    const default_config = SecurityConfig.init();
    const security_config = if (data.bearssl.tls_config) |cfg| &cfg.security_config else &default_config;

    // Apply hostname verification bypass if allowed
    const sni_name = if (security_config.allowsBypass(.hostname_verification)) blk: {
        security_config.logBypass(.hostname_verification, server_name);
        break :blk if (security_config.mode == .debug_insecure) null else server_name.ptr;
    } else server_name.ptr;
    log.info("BEFORE RESET", .{});
    // Reset the client context with SNI information
    if (c.br_ssl_client_reset(client_ctx, sni_name, 0) == 0) {
        log.err("Client reset with SNI failed", .{});
        return error.ClientResetFailed;
    }

    // Verify engine state before proceeding
    if (c.br_ssl_engine_current_state(&client_ctx.eng) == c.BR_SSL_CLOSED) {
        log.warn("SSL engine closed, cannot initialize I/O", .{});
        return error.SslEngineClosed;
    }

    // Initialize I/O with our callbacks
    c.br_sslio_init(sslio_ctx, &client_ctx.eng, brssl_recv_callback, data.cb_ctx.toOpaque(), brssl_send_callback, data.cb_ctx.toOpaque());
}

/// Perform TLS handshake with enhanced error handling
/// Returns error if handshake fails
fn performTlsHandshake(data: *VtableContextData, server_name: []const u8) !void {
    log.info("Starting TLS handshake", .{});

    const sslio_ctx = try data.managed_ctx.getSslIoCtx();

    // Get security configuration (use default if not provided)
    const default_config = SecurityConfig.init();
    const security_config = if (data.bearssl.tls_config) |cfg| &cfg.security_config else &default_config;

    // Record handshake start in performance monitor
    if (data.performance_monitor) |monitor| {
        monitor.recordHandshake();
    }

    // Log security audit event
    if (data.security_audit) |audit| {
        try audit.logEvent(.certificate_accepted, "TLS handshake initiated", security_config.mode);
    }

    // Trigger handshake with an empty write
    if (c.br_sslio_write(sslio_ctx, "", 0) < 0) {
        if (data.security_audit) |audit| {
            try audit.logEvent(.validation_failed, "TLS handshake write failed", security_config.mode);
        }
        return handleHandshakeErrorImpl(data, server_name);
    }

    // Flush to ensure handshake completion
    if (c.br_sslio_flush(sslio_ctx) < 0) {
        if (data.security_audit) |audit| {
            try audit.logEvent(.validation_failed, "TLS handshake flush failed", security_config.mode);
        }
        return handleHandshakeErrorImpl(data, server_name);
    }

    // Log successful handshake
    if (data.security_audit) |audit| {
        const context_msg = std.fmt.allocPrint(data.managed_ctx.allocator, "server: {s}", .{server_name}) catch "handshake completed";
        defer if (!std.mem.eql(u8, context_msg, "handshake completed")) data.managed_ctx.allocator.free(context_msg);
        try audit.logEvent(.certificate_accepted, context_msg, security_config.mode);
    }

    log.info("TLS handshake completed successfully", .{});
}

/// Internal implementation of TLS socket connection handling with Zig native calling convention
/// This allows more compiler optimizations while keeping the same logic.
fn vtable_connect_impl(s: Socket, r: *Runtime, i: *anyopaque) !void {
    // Type-safe context validation and setup
    const ctx = try getVtableContext(i, r);
    const data = try ctx.getData();

    // Connect the underlying socket
    try s.connect(r);

    // Get server name for SNI
    const server_name = getServerName(data.bearssl.tls_config);
    log.info("Setting SNI: {s}", .{server_name});

    // Initialize TLS engine
    try initTlsEngine(data, server_name);

    // Log state before starting handshake
    try data.logState("Before TLS handshake");

    // Perform the TLS handshake
    try performTlsHandshake(data, server_name);

    // Log final state
    try data.logState("After TLS handshake");
}

/// Handle TLS socket connection including handshake
/// Wrapper around the optimized Zig implementation.
pub fn vtable_connect(s: Socket, r: *Runtime, i: *anyopaque) !void {
    return vtable_connect_impl(s, r, i);
}

/// TLS client can't accept connections, only initiate them
pub fn vtable_accept(_: Socket, _: *Runtime, _: *anyopaque) !SecureSocket {
    return error.TLSClientCantAccept;
}

/// Internal implementation of resource cleanup with Zig native calling convention
fn vtable_deinit_impl(i: *anyopaque) void {
    // Type-safe context validation and cleanup
    const ctx = VtableContext.fromOpaque(i) catch |err| {
        log.err("Failed to validate context during deinit: {s}", .{@errorName(err)});
        return;
    };

    const data = ctx.getData() catch |err| {
        log.err("Failed to get context data during deinit: {s}", .{@errorName(err)});
        return;
    };

    // Gracefully shut down the TLS connection with enhanced safety
    // Get contexts if available and perform cleanup
    
    // SAFETY: Add null checks and error handling to prevent segmentation faults
    if (data.managed_ctx.getSslIoCtx()) |_| {
        // Skip SSL flush to prevent race condition - flush already removed from memory.zig
        log.debug("VTABLE: Skipping SSL I/O flush to prevent race condition", .{});
    } else |_| {
        log.debug("VTABLE: SSL I/O context not available for cleanup", .{});
    }

    if (data.managed_ctx.getClientCtx()) |client_ctx| {
        // Safe SSL engine close
        _ = c.br_ssl_engine_close(&client_ctx.eng);
        log.debug("VTABLE: SSL engine closed successfully", .{});
    } else |_| {
        log.debug("VTABLE: Client context not available for cleanup", .{});
    }

    // Get allocator before deinitializing managed context
    const allocator = data.managed_ctx.allocator;

    // Clean up performance monitor if present
    if (data.performance_monitor) |monitor| {
        allocator.destroy(monitor);
    }

    // Clean up security audit if present
    if (data.security_audit) |audit| {
        audit.deinit();
        allocator.destroy(audit);
    }

    // Mark context as destroyed first
    ctx.destroy();

    // RAII cleanup - managed context cleans up all its resources automatically
    data.managed_ctx.deinit();

    // Free callback context (not managed by ManagedTlsContext)
    allocator.destroy(data.cb_ctx);

    // Free the VtableContext itself
    allocator.destroy(ctx);
}

/// Clean up all resources allocated for the TLS connection
/// Wrapper around the optimized Zig implementation.
pub fn vtable_deinit(i: *anyopaque) void {
    vtable_deinit_impl(i);
}

/// Internal implementation of TLS read operations with enhanced error handling
fn vtable_recv_impl(_: Socket, r: *Runtime, i: *anyopaque, b: []u8) !usize {
    // Type-safe context validation and setup
    const ctx = try getVtableContext(i, r);
    const data = try ctx.getData();

    // Get managed contexts
    const sslio_ctx = try data.managed_ctx.getSslIoCtx();
    const client_ctx = try data.managed_ctx.getClientCtx();

    // Perform the TLS read operation
    const result = c.br_sslio_read(sslio_ctx, b.ptr, b.len);
    if (result < 0) {
        const error_code = c.br_ssl_engine_last_error(&client_ctx.eng);

        // Use enhanced error handling with statistics
        return handleBearSslErrorWithStats(data, error_code, "recv", 0);
    }

    const bytes_read = @as(usize, @intCast(result));

    // Record performance statistics
    if (data.performance_monitor) |monitor| {
        monitor.recordRead(bytes_read);
    }

    return bytes_read;
}

/// Read data from the TLS connection
/// Wrapper around the optimized Zig implementation.
pub fn vtable_recv(s: Socket, r: *Runtime, i: *anyopaque, b: []u8) !usize {
    return vtable_recv_impl(s, r, i, b);
}

/// Internal implementation of TLS send operations with enhanced error handling
fn vtable_send_impl(_: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
    // Type-safe context validation and setup
    const ctx = try getVtableContext(i, r);
    const data = try ctx.getData();

    // Get managed contexts
    const sslio_ctx = try data.managed_ctx.getSslIoCtx();
    const client_ctx = try data.managed_ctx.getClientCtx();

    // Write data to the TLS connection
    const write_result = c.br_sslio_write(sslio_ctx, b.ptr, b.len);
    if (write_result < 0) {
        const error_code = c.br_ssl_engine_last_error(&client_ctx.eng);

        // Use enhanced error handling with statistics
        return handleBearSslErrorWithStats(data, error_code, "send", 0);
    }

    // Flush data to ensure it's sent over the network
    const flush_result = c.br_sslio_flush(sslio_ctx);
    if (flush_result < 0) {
        const error_code = c.br_ssl_engine_last_error(&client_ctx.eng);

        // Special case: on graceful close during flush, return bytes written
        if (error_code == 0) {
            return @as(usize, @intCast(@max(0, write_result)));
        }

        // Use enhanced error handling for flush with statistics
        const bytes_written = @as(usize, @intCast(@max(0, write_result)));
        return handleBearSslErrorWithStats(data, error_code, "flush", bytes_written);
    }

    const bytes_sent = @as(usize, @intCast(write_result));

    // Record performance statistics
    if (data.performance_monitor) |monitor| {
        monitor.recordWrite(bytes_sent);
    }

    return bytes_sent;
}

/// Send data through the TLS connection
/// Wrapper around the optimized Zig implementation.
pub fn vtable_send(s: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
    return vtable_send_impl(s, r, i, b);
}

/// Create the SecureSocket vtable for a BearSSL client using type-safe context
pub fn createSecureSocketVtable(ctx: *VtableContext, socket: Socket) SecureSocket {
    return SecureSocket{
        .socket = socket,
        .vtable = .{
            .inner = ctx.toOpaque(),
            .deinit = vtable_deinit,
            .accept = vtable_accept,
            .connect = vtable_connect,
            .recv = vtable_recv,
            .send = vtable_send,
        },
    };
}
