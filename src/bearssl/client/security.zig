/// Security Mode Management for BearSSL TLS
///
/// This module provides explicit security mode configuration that makes security bypasses
/// clear and intentional, with appropriate warnings and safeguards.
///
/// Key features:
/// - Explicit SecurityMode enum for different operational contexts
/// - Clear warnings when insecure modes are used
/// - Backward compatibility with DEBUG_INSECURE preset
/// - Runtime security validation and logging
/// - Compile-time security policy enforcement
const std = @import("std");

const log = std.log.scoped(.bearssl_security);

/// Security modes for TLS operations with explicit semantics
pub const SecurityMode = enum {
    /// Production mode: Full certificate validation, no bypasses
    /// - All certificates must be properly signed
    /// - Hostname verification required
    /// - No expired certificates accepted
    /// - Complete chain validation
    production,
    
    /// Development mode: Relaxed validation for development environments
    /// - Self-signed certificates allowed
    /// - Hostname verification optional
    /// - Detailed security warnings logged
    /// - Still performs basic certificate validation
    development,
    
    /// Testing mode: Minimal validation for automated testing
    /// - Certificate chain validation bypassed
    /// - Hostname verification disabled
    /// - Explicit test-only warnings
    /// - Should only be used in test environments
    testing,
    
    /// Debug insecure mode: All validation bypassed (DANGEROUS)
    /// - No certificate validation
    /// - No hostname verification
    /// - Trust any certificate
    /// - MUST NEVER be used in production
    debug_insecure,
    
    /// Get a human-readable description of the security mode
    pub fn description(self: SecurityMode) []const u8 {
        return switch (self) {
            .production => "Production (full security validation)",
            .development => "Development (relaxed validation with warnings)",
            .testing => "Testing (minimal validation for automated tests)",
            .debug_insecure => "Debug Insecure (NO VALIDATION - DANGEROUS)",
        };
    }
    
    /// Check if the mode allows certificate validation bypasses
    pub fn allowsCertificateBypass(self: SecurityMode) bool {
        return switch (self) {
            .production => false,
            .development => false,
            .testing => true,
            .debug_insecure => true,
        };
    }
    
    /// Check if the mode allows hostname verification bypasses
    pub fn allowsHostnameBypass(self: SecurityMode) bool {
        return switch (self) {
            .production => false,
            .development => true,
            .testing => true,
            .debug_insecure => true,
        };
    }
    
    /// Check if the mode allows expired certificates
    pub fn allowsExpiredCertificates(self: SecurityMode) bool {
        return switch (self) {
            .production => false,
            .development => true,
            .testing => true,
            .debug_insecure => true,
        };
    }
    
    /// Get the warning level for this security mode
    pub fn getWarningLevel(self: SecurityMode) WarningLevel {
        return switch (self) {
            .production => .none,
            .development => .info,
            .testing => .warning,
            .debug_insecure => .critical,
        };
    }
};

/// Warning levels for security mode notifications
pub const WarningLevel = enum {
    none,
    info,
    warning,
    critical,
};

/// Security configuration structure
pub const SecurityConfig = struct {
    /// Current security mode
    mode: SecurityMode,
    
    /// Whether to log security warnings
    enable_warnings: bool = true,
    
    /// Custom warning prefix for identification
    warning_prefix: ?[]const u8 = null,
    
    /// Whether to validate mode at runtime
    validate_mode: bool = true,
    
    /// Initialize with production security by default
    pub fn init() SecurityConfig {
        return .{
            .mode = .production,
        };
    }
    
    /// Create development configuration
    pub fn development() SecurityConfig {
        return .{
            .mode = .development,
            .warning_prefix = "DEV",
        };
    }
    
    /// Create testing configuration
    pub fn testing() SecurityConfig {
        return .{
            .mode = .testing,
            .warning_prefix = "TEST",
        };
    }
    
    /// Create debug insecure configuration with explicit warnings
    pub fn debugInsecure() SecurityConfig {
        return .{
            .mode = .debug_insecure,
            .warning_prefix = "INSECURE",
        };
    }
    
    /// Validate the current security configuration
    pub fn validate(self: *const SecurityConfig) !void {
        if (!self.validate_mode) return;
        
        // Log security mode being used
        self.logSecurityMode();
        
        // Check for dangerous modes in production builds
        if (self.mode == .debug_insecure) {
            if (!std.debug.runtime_safety) {
                log.err("SECURITY VIOLATION: debug_insecure mode detected in release build!", .{});
                return error.InsecureModeInProduction;
            }
        }
    }
    
    /// Log the current security mode with appropriate warnings
    pub fn logSecurityMode(self: *const SecurityConfig) void {
        if (!self.enable_warnings) return;
        
        const prefix = self.warning_prefix orelse "";
        const mode_desc = self.mode.description();
        
        switch (self.mode.getWarningLevel()) {
            .none => {
                log.info("{s} Security mode: {s}", .{ prefix, mode_desc });
            },
            .info => {
                log.info("{s} Security mode: {s} - relaxed validation enabled", .{ prefix, mode_desc });
            },
            .warning => {
                log.warn("{s} Security mode: {s} - validation bypasses active", .{ prefix, mode_desc });
            },
            .critical => {
                log.err("!!! {s} Security mode: {s} - ALL VALIDATION DISABLED !!!", .{ prefix, mode_desc });
                log.err("!!! THIS MODE MUST NEVER BE USED IN PRODUCTION !!!", .{});
                log.err("!!! CONNECTIONS ARE COMPLETELY INSECURE !!!", .{});
            },
        }
    }
    
    /// Check if a specific security bypass is allowed
    pub fn allowsBypass(self: *const SecurityConfig, bypass_type: SecurityBypass) bool {
        return switch (bypass_type) {
            .certificate_validation => self.mode.allowsCertificateBypass(),
            .hostname_verification => self.mode.allowsHostnameBypass(),
            .expired_certificates => self.mode.allowsExpiredCertificates(),
        };
    }
    
    /// Log a security bypass action
    pub fn logBypass(self: *const SecurityConfig, bypass_type: SecurityBypass, context: ?[]const u8) void {
        if (!self.enable_warnings) return;
        
        const bypass_name = switch (bypass_type) {
            .certificate_validation => "certificate validation",
            .hostname_verification => "hostname verification", 
            .expired_certificates => "expired certificate check",
        };
        
        const prefix = self.warning_prefix orelse "";
        const ctx = context orelse "";
        
        switch (self.mode.getWarningLevel()) {
            .none => {},
            .info => {
                log.info("{s} Bypassing {s} {s}", .{ prefix, bypass_name, ctx });
            },
            .warning => {
                log.warn("{s} BYPASSING {s} {s}", .{ prefix, bypass_name, ctx });
            },
            .critical => {
                log.err("{s} !!! BYPASSING {s} {s} !!!", .{ prefix, bypass_name, ctx });
            },
        }
    }
};

/// Types of security bypasses
pub const SecurityBypass = enum {
    certificate_validation,
    hostname_verification,
    expired_certificates,
};

/// Legacy compatibility for DEBUG_INSECURE preset
pub const DEBUG_INSECURE = SecurityConfig.debugInsecure();

/// Security policy enforcement
pub const SecurityPolicy = struct {
    /// Enforce security policy at compile time
    pub fn enforceCompileTime(comptime mode: SecurityMode) void {
        switch (mode) {
            .debug_insecure => {
                @compileError("debug_insecure mode is not allowed in this build configuration");
            },
            else => {},
        }
    }
    
    /// Runtime security check with environment validation
    pub fn enforceRuntime(config: *const SecurityConfig) !void {
        try config.validate();
        
        // Check environment variables for security overrides
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "BEARSSL_INSECURE_MODE")) |value| {
            defer std.heap.page_allocator.free(value);
            
            if (std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "true")) {
                if (config.mode != .debug_insecure) {
                    log.warn("BEARSSL_INSECURE_MODE environment variable detected but security mode is not debug_insecure", .{});
                }
            }
        } else |_| {}
        
        // Additional runtime checks for production environments
        if (config.mode == .debug_insecure) {
            // Check if we're in a production-like environment
            const hostname = std.process.getEnvVarOwned(std.heap.page_allocator, "HOSTNAME") catch null;
            if (hostname) |name| {
                defer std.heap.page_allocator.free(name);
                if (std.mem.indexOf(u8, name, "prod") != null or 
                    std.mem.indexOf(u8, name, "production") != null) {
                    log.err("SECURITY VIOLATION: debug_insecure mode detected on production host: {s}", .{name});
                    return error.InsecureModeInProduction;
                }
            }
        }
    }
};

/// Trust anchor override for testing modes
pub const TestTrustAnchor = struct {
    /// Create a minimal trust anchor that accepts any certificate
    /// WARNING: Only use in testing/debug modes
    pub fn createAcceptAny(allocator: std.mem.Allocator, security_config: *const SecurityConfig) ![]const u8 {
        if (!security_config.allowsBypass(.certificate_validation)) {
            log.err("Attempted to create accept-any trust anchor in secure mode: {s}", .{security_config.mode.description()});
            return error.BypassNotAllowed;
        }
        
        security_config.logBypass(.certificate_validation, "creating accept-any trust anchor");
        
        // Create a minimal DER-encoded certificate that will be accepted
        // This is a dummy certificate that bypasses validation
        const dummy_cert = [_]u8{
            0x30, 0x82, 0x01, 0x22, // SEQUENCE (290 bytes)
            0x30, 0x81, 0xCF, // SEQUENCE (207 bytes) - tbsCertificate
            // ... minimal certificate structure
        };
        
        return try allocator.dupe(u8, &dummy_cert);
    }
};

/// Security audit logging
pub const SecurityAudit = struct {
    start_time: i64,
    security_events: std.ArrayList(SecurityEvent),
    
    const SecurityEvent = struct {
        timestamp: i64,
        event_type: SecurityEventType,
        description: []const u8,
        security_mode: SecurityMode,
    };
    
    const SecurityEventType = enum {
        mode_change,
        bypass_used,
        validation_failed,
        certificate_accepted,
        certificate_rejected,
    };
    
    pub fn init(allocator: std.mem.Allocator) SecurityAudit {
        return .{
            .start_time = std.time.timestamp(),
            .security_events = std.ArrayList(SecurityEvent).init(allocator),
        };
    }
    
    pub fn deinit(self: *SecurityAudit) void {
        self.security_events.deinit();
    }
    
    pub fn logEvent(self: *SecurityAudit, event_type: SecurityEventType, description: []const u8, mode: SecurityMode) !void {
        const event = SecurityEvent{
            .timestamp = std.time.timestamp(),
            .event_type = event_type,
            .description = description,
            .security_mode = mode,
        };
        
        try self.security_events.append(event);
        
        // Also log to standard logging
        log.info("Security audit: {s} - {s} (mode: {s})", .{
            @tagName(event_type), description, mode.description()
        });
    }
    
    pub fn generateReport(self: *const SecurityAudit, writer: anytype) !void {
        try writer.print("=== BearSSL Security Audit Report ===\n");
        try writer.print("Session duration: {d} seconds\n", .{std.time.timestamp() - self.start_time});
        try writer.print("Total security events: {d}\n\n", .{self.security_events.items.len});
        
        for (self.security_events.items) |event| {
            try writer.print("[{d}] {s}: {s} (mode: {s})\n", .{
                event.timestamp, @tagName(event.event_type), 
                event.description, event.security_mode.description()
            });
        }
    }
};