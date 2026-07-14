/// Unified Memory Management for BearSSL TLS contexts
/// 
/// This module implements a RAII (Resource Acquisition Is Initialization) pattern
/// for managing all BearSSL-related memory allocations in a centralized, safe way.
///
/// Key features:
/// - Single ManagedTlsContext handles all resource allocation and cleanup
/// - Automatic cleanup on scope exit prevents memory leaks
/// - Zero manual memory management for clients
/// - Proper error handling with automatic rollback
const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.bearssl_memory);

const c = @cImport({
    @cInclude("bearssl.h");
});

/// ManagedTlsContext provides unified memory management for all BearSSL resources
/// using RAII pattern. All memory is automatically cleaned up when the context
/// is deinitialized.
pub const ManagedTlsContext = struct {
    /// Allocator used for all memory allocations
    allocator: Allocator,
    
    /// IO buffer for BearSSL operations (aligned for performance)
    io_buf: ?[]align(8) u8,
    
    /// BearSSL client context
    client_ctx: ?*c.br_ssl_client_context,
    
    /// X.509 validation context  
    x509_ctx: ?*c.br_x509_minimal_context,
    
    /// SSL I/O context
    sslio_ctx: ?*c.br_sslio_context,
    
    /// Callback context for socket operations
    callback_ctx: ?*anyopaque,
    
    /// Flag to track if resources have been initialized
    initialized: bool,

    /// Initialize a new ManagedTlsContext
    /// All fields are set to null initially - resources are allocated on demand
    pub fn init(allocator: Allocator) ManagedTlsContext {
        return .{
            .allocator = allocator,
            .io_buf = null,
            .client_ctx = null,
            .x509_ctx = null,
            .sslio_ctx = null,
            .callback_ctx = null,
            .initialized = false,
        };
    }

    /// Allocate and initialize all BearSSL resources
    /// This is called automatically when needed
    pub fn ensureInitialized(self: *ManagedTlsContext) !void {
        if (self.initialized) return;
        
        log.debug("Initializing BearSSL resources", .{});
        
        // Allocate aligned IO buffer for optimal performance
        self.io_buf = try std.heap.page_allocator.alignedAlloc(u8, 8, c.BR_SSL_BUFSIZE_BIDI);
        errdefer self.cleanupIoBuf();
        
        // Allocate client context
        self.client_ctx = try self.allocator.create(c.br_ssl_client_context);
        errdefer self.cleanupClientCtx();
        
        // Allocate X.509 context
        self.x509_ctx = try self.allocator.create(c.br_x509_minimal_context);
        errdefer self.cleanupX509Ctx();
        
        // Allocate SSL I/O context
        self.sslio_ctx = try self.allocator.create(c.br_sslio_context);
        errdefer self.cleanupSslIoCtx();
        
        self.initialized = true;
        log.debug("BearSSL resources initialized successfully", .{});
    }

    /// Get the IO buffer, allocating if necessary
    pub fn getIoBuf(self: *ManagedTlsContext) ![]align(8) u8 {
        try self.ensureInitialized();
        return self.io_buf.?;
    }

    /// Get the client context, allocating if necessary
    pub fn getClientCtx(self: *ManagedTlsContext) !*c.br_ssl_client_context {
        try self.ensureInitialized();
        return self.client_ctx.?;
    }

    /// Get the X.509 context, allocating if necessary
    pub fn getX509Ctx(self: *ManagedTlsContext) !*c.br_x509_minimal_context {
        try self.ensureInitialized();
        return self.x509_ctx.?;
    }

    /// Get the SSL I/O context, allocating if necessary
    pub fn getSslIoCtx(self: *ManagedTlsContext) !*c.br_sslio_context {
        try self.ensureInitialized();
        return self.sslio_ctx.?;
    }

    /// Set the callback context (external data, not managed by this struct)
    pub fn setCallbackCtx(self: *ManagedTlsContext, ctx: *anyopaque) void {
        self.callback_ctx = ctx;
    }

    /// Get the callback context
    pub fn getCallbackCtx(self: *ManagedTlsContext) ?*anyopaque {
        return self.callback_ctx;
    }

    /// Clean up IO buffer
    fn cleanupIoBuf(self: *ManagedTlsContext) void {
        if (self.io_buf) |buf| {
            std.heap.page_allocator.free(buf);
            self.io_buf = null;
            log.debug("IO buffer cleaned up", .{});
        }
    }

    /// Clean up client context
    fn cleanupClientCtx(self: *ManagedTlsContext) void {
        if (self.client_ctx) |ctx| {
            // Gracefully close the SSL engine if it was initialized
            _ = c.br_ssl_engine_close(&ctx.eng);
            self.allocator.destroy(ctx);
            self.client_ctx = null;
            log.debug("Client context cleaned up", .{});
        }
    }

    /// Clean up X.509 context
    fn cleanupX509Ctx(self: *ManagedTlsContext) void {
        if (self.x509_ctx) |ctx| {
            self.allocator.destroy(ctx);
            self.x509_ctx = null;
            log.debug("X.509 context cleaned up", .{});
        }
    }

    /// Clean up SSL I/O context
    fn cleanupSslIoCtx(self: *ManagedTlsContext) void {
        if (self.sslio_ctx) |ctx| {
            log.debug("Testing memory.zig SSL I/O context flush + destroy", .{});
            _ = c.br_sslio_flush(ctx);
            
            // Perform destroy operation to free memory
            self.allocator.destroy(ctx);
            self.sslio_ctx = null;
            log.debug("SSL I/O context cleaned up completely", .{});
        }
    }

    /// RAII cleanup - automatically called when ManagedTlsContext goes out of scope
    /// Cleans up all allocated resources in reverse order of allocation
    pub fn deinit(self: *ManagedTlsContext) void {
        if (!self.initialized) return;
        
        log.debug("Cleaning up ManagedTlsContext", .{});
        
        // Clean up in reverse order of allocation
        self.cleanupSslIoCtx();
        self.cleanupX509Ctx(); 
        self.cleanupClientCtx();
        self.cleanupIoBuf();
        
        // Note: callback_ctx is not managed by us, so we don't free it
        self.callback_ctx = null;
        self.initialized = false;
        
        log.debug("ManagedTlsContext cleanup complete", .{});
    }

    /// Check if the context has been initialized
    pub fn isInitialized(self: *const ManagedTlsContext) bool {
        return self.initialized;
    }

    /// Get memory usage statistics for debugging
    pub fn getMemoryStats(self: *const ManagedTlsContext) MemoryStats {
        return .{
            .io_buf_size = if (self.io_buf) |buf| buf.len else 0,
            .contexts_allocated = @as(u32, @intFromBool(self.client_ctx != null)) +
                                 @as(u32, @intFromBool(self.x509_ctx != null)) +
                                 @as(u32, @intFromBool(self.sslio_ctx != null)),
            .total_contexts = 3,
            .initialized = self.initialized,
        };
    }
};

/// Memory usage statistics for debugging and monitoring
pub const MemoryStats = struct {
    io_buf_size: usize,
    contexts_allocated: u32,
    total_contexts: u32,
    initialized: bool,
    
    /// Get total estimated memory usage
    pub fn getTotalMemoryUsage(self: MemoryStats) usize {
        return self.io_buf_size + 
               (self.contexts_allocated * @sizeOf(c.br_ssl_client_context));
    }
    
    /// Check if all contexts are allocated
    pub fn isFullyAllocated(self: MemoryStats) bool {
        return self.contexts_allocated == self.total_contexts;
    }
};

/// Convenience function to create a managed context with immediate initialization
/// This is useful when you know you'll need all resources right away
pub fn createInitializedContext(allocator: Allocator) !ManagedTlsContext {
    var ctx = ManagedTlsContext.init(allocator);
    try ctx.ensureInitialized();
    return ctx;
}

/// Resource guard for automatic cleanup in error scenarios
/// Usage: var guard = ResourceGuard.init(&managed_ctx); defer guard.release();
pub const ResourceGuard = struct {
    ctx: *ManagedTlsContext,
    released: bool,
    
    pub fn init(ctx: *ManagedTlsContext) ResourceGuard {
        return .{ .ctx = ctx, .released = false };
    }
    
    pub fn release(self: *ResourceGuard) void {
        if (!self.released) {
            self.ctx.deinit();
            self.released = true;
        }
    }
    
    /// Keep the resources (don't clean up on release)
    pub fn keep(self: *ResourceGuard) void {
        self.released = true;
    }
};