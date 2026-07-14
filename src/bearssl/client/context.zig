/// Type-Safe Context Management for BearSSL
///
/// This module provides type-safe context handling that eliminates unsafe pointer casting
/// and provides validated context operations with clear ownership and lifetime management.
///
/// Key features:
/// - Type-safe context validation and casting
/// - Clear ownership semantics 
/// - Runtime context validation
/// - Debug context tracking
/// - Zero unsafe pointer operations
const std = @import("std");

const log = std.log.scoped(.bearssl_context);

/// Context type enumeration for type-safe identification
pub const ContextType = enum(u32) {
    vtable_context = 0x56544142, // "VTAB" in hex
    callback_context = 0x43424B53, // "CBKS" in hex
    managed_tls_context = 0x4D544C53, // "MTLS" in hex
    
    /// Get a human-readable name for the context type
    pub fn name(self: ContextType) []const u8 {
        return switch (self) {
            .vtable_context => "VtableContext",
            .callback_context => "CallbackContext", 
            .managed_tls_context => "ManagedTlsContext",
        };
    }
};

/// Context validation magic numbers for runtime safety
pub const ContextMagic = struct {
    pub const VALID = 0xDEADBEEF;
    pub const DESTROYED = 0xDEADDEAD;
    pub const CORRUPTED = 0xBADCAFE;
};

/// Base type-safe context header that all contexts must include
pub const TypeSafeContextHeader = struct {
    /// Magic number for validation
    magic: u32,
    
    /// Context type identifier
    context_type: ContextType,
    
    /// Creation timestamp for debugging
    created_at: i64,
    
    /// Reference count for lifetime management
    ref_count: u32,
    
    /// Debug information
    debug_info: ?[]const u8,

    /// Initialize a new context header
    pub fn init(context_type: ContextType, debug_info: ?[]const u8) TypeSafeContextHeader {
        return .{
            .magic = ContextMagic.VALID,
            .context_type = context_type,
            .created_at = std.time.timestamp(),
            .ref_count = 1,
            .debug_info = debug_info,
        };
    }
    
    /// Validate the context header
    pub fn validate(self: *const TypeSafeContextHeader) !void {
        switch (self.magic) {
            ContextMagic.VALID => {},
            ContextMagic.DESTROYED => {
                log.err("Attempted to use destroyed context of type {s}", .{self.context_type.name()});
                return error.ContextDestroyed;
            },
            ContextMagic.CORRUPTED => {
                log.err("Attempted to use corrupted context of type {s}", .{self.context_type.name()});
                return error.ContextCorrupted;
            },
            else => {
                log.err("Invalid magic number {X} for context of type {s}", .{ self.magic, self.context_type.name() });
                return error.InvalidContextMagic;
            },
        }
    }
    
    /// Increment reference count
    pub fn addRef(self: *TypeSafeContextHeader) void {
        self.ref_count += 1;
        log.debug("Context {s} ref count incremented to {d}", .{ self.context_type.name(), self.ref_count });
    }
    
    /// Decrement reference count
    pub fn release(self: *TypeSafeContextHeader) u32 {
        if (self.ref_count > 0) {
            self.ref_count -= 1;
        }
        log.debug("Context {s} ref count decremented to {d}", .{ self.context_type.name(), self.ref_count });
        return self.ref_count;
    }
    
    /// Mark context as destroyed
    pub fn markDestroyed(self: *TypeSafeContextHeader) void {
        self.magic = ContextMagic.DESTROYED;
        self.ref_count = 0;
        log.debug("Context {s} marked as destroyed", .{self.context_type.name()});
    }
};

/// Type-safe context validation and casting utilities
pub const TypeSafeContext = struct {
    /// Validate and cast an opaque pointer to a specific context type
    pub fn validateAndCast(comptime T: type, ptr: *anyopaque, expected_type: ContextType) !*T {
        // First, cast to a context header to check the type
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        
        // Validate the header
        try header_ptr.validate();
        
        // Check the context type
        if (header_ptr.context_type != expected_type) {
            log.err("Context type mismatch: expected {s}, got {s}", .{
                expected_type.name(), header_ptr.context_type.name()
            });
            return error.ContextTypeMismatch;
        }
        
        // Safe cast to the target type
        const result = @as(*T, @ptrCast(@alignCast(ptr)));
        
        log.debug("Successfully validated and cast context to {s}", .{expected_type.name()});
        return result;
    }
    
    /// Create a type-safe opaque pointer from a typed context
    pub fn toOpaque(ptr: anytype) *anyopaque {
        return @as(*anyopaque, @ptrCast(ptr));
    }
    
    /// Validate an opaque pointer without casting (for checking only)
    pub fn validateOpaque(ptr: *anyopaque, expected_type: ContextType) !void {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        
        if (header_ptr.context_type != expected_type) {
            log.err("Context type validation failed: expected {s}, got {s}", .{
                expected_type.name(), header_ptr.context_type.name()
            });
            return error.ContextTypeMismatch;
        }
    }
    
    /// Get context type from opaque pointer
    pub fn getContextType(ptr: *anyopaque) !ContextType {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        return header_ptr.context_type;
    }
    
    /// Get context debug info
    pub fn getDebugInfo(ptr: *anyopaque) !?[]const u8 {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        return header_ptr.debug_info;
    }
};

/// Context lifetime management utilities
pub const ContextLifetime = struct {
    /// Add a reference to a context
    pub fn addRef(ptr: *anyopaque) !void {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        header_ptr.addRef();
    }
    
    /// Release a reference to a context
    /// Returns the remaining reference count
    pub fn release(ptr: *anyopaque) !u32 {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        return header_ptr.release();
    }
    
    /// Check if a context can be safely destroyed
    pub fn canDestroy(ptr: *anyopaque) !bool {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        return header_ptr.ref_count <= 1;
    }
    
    /// Mark a context as destroyed
    pub fn markDestroyed(ptr: *anyopaque) !void {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        header_ptr.markDestroyed();
    }
};

/// Context debugging and diagnostics
pub const ContextDebug = struct {
    /// Dump context information for debugging
    pub fn dumpContext(ptr: *anyopaque) void {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        
        log.debug("=== Context Debug Info ===", .{});
        log.debug("Magic: 0x{X}", .{header_ptr.magic});
        log.debug("Type: {s}", .{header_ptr.context_type.name()});
        log.debug("Created: {d}", .{header_ptr.created_at});
        log.debug("Ref Count: {d}", .{header_ptr.ref_count});
        
        if (header_ptr.debug_info) |info| {
            log.debug("Debug Info: {s}", .{info});
        }
        
        // Validate and report status
        header_ptr.validate() catch |err| {
            log.debug("Validation Error: {s}", .{@errorName(err)});
        };
    }
    
    /// Get context statistics
    pub fn getStats(ptr: *anyopaque) !ContextStats {
        const header_ptr = @as(*TypeSafeContextHeader, @ptrCast(@alignCast(ptr)));
        try header_ptr.validate();
        
        const age = std.time.timestamp() - header_ptr.created_at;
        
        return ContextStats{
            .context_type = header_ptr.context_type,
            .age_seconds = age,
            .ref_count = header_ptr.ref_count,
            .is_valid = header_ptr.magic == ContextMagic.VALID,
        };
    }
};

/// Context statistics structure
pub const ContextStats = struct {
    context_type: ContextType,
    age_seconds: i64,
    ref_count: u32,
    is_valid: bool,
};

/// Type-safe context wrapper for ensuring all contexts have proper headers
pub fn TypeSafeWrapper(comptime T: type, comptime context_type: ContextType) type {
    return struct {
        const Self = @This();
        
        /// Type-safe header (must be first field)
        header: TypeSafeContextHeader,
        
        /// The actual context data
        data: T,
        
        /// Create a new type-safe wrapper
        pub fn init(data: T, debug_info: ?[]const u8) Self {
            return Self{
                .header = TypeSafeContextHeader.init(context_type, debug_info),
                .data = data,
            };
        }
        
        /// Get a type-safe pointer to the wrapped data
        pub fn getData(self: *Self) !*T {
            try self.header.validate();
            return &self.data;
        }
        
        /// Get an opaque pointer for vtable usage
        pub fn toOpaque(self: *Self) *anyopaque {
            return TypeSafeContext.toOpaque(self);
        }
        
        /// Cast from opaque pointer back to this type
        pub fn fromOpaque(ptr: *anyopaque) !*Self {
            return TypeSafeContext.validateAndCast(Self, ptr, context_type);
        }
        
        /// Mark as destroyed and clean up
        pub fn destroy(self: *Self) void {
            self.header.markDestroyed();
        }
    };
}

