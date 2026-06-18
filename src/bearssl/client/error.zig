/// Standardized Error Handling for BearSSL TLS operations
///
/// This module provides a unified error handling system with:
/// - Clear TlsError enum with semantic meanings
/// - Consistent error conversion from BearSSL codes
/// - Enhanced error context and logging
/// - Structured error information for better debugging
const std = @import("std");
const error_map = @import("error_map.zig");

const log = std.log.scoped(.bearssl_error);

const c = @cImport({
    @cInclude("bearssl.h");
});

/// Standardized TLS error types with clear semantic meanings
pub const TlsError = error{
    // Connection and I/O errors
    ConnectionFailed,
    ConnectionClosed,
    IoError,
    NetworkTimeout,
    
    // Handshake errors
    HandshakeFailed,
    ProtocolVersionMismatch,
    CipherSuiteNegotiationFailed,
    ServerNameMismatch,
    
    // Certificate validation errors
    CertificateValidationFailed,
    CertificateExpired,
    CertificateNotTrusted,
    CertificateInvalid,
    CertificateChainBroken,
    
    // Cryptographic errors
    InvalidSignature,
    MacVerificationFailed,
    CryptographicFailure,
    WeakCryptography,
    
    // Protocol errors
    BadMessage,
    UnexpectedMessage,
    ProtocolViolation,
    BadAlert,
    
    // Configuration errors
    InvalidConfiguration,
    UnsupportedFeature,
    InsufficientResources,
    
    // Memory and resource errors
    OutOfMemory,
    ResourceExhausted,
    
    // Generic errors
    InternalError,
    Unknown,
};

/// Enhanced error context providing detailed information about TLS errors
pub const TlsErrorContext = struct {
    /// The standardized TLS error type
    error_type: TlsError,
    
    /// Original BearSSL error code for debugging
    bearssl_code: i32,
    
    /// Human-readable error message
    message: []const u8,
    
    /// Operation that failed (e.g., "handshake", "send", "recv")
    operation: []const u8,
    
    /// Additional context (e.g., server name, certificate subject)
    context: ?[]const u8 = null,
    
    /// Timestamp when error occurred
    timestamp: i64,
    
    /// Indicates if this is a recoverable error
    recoverable: bool,

    /// Create a new TlsErrorContext
    pub fn init(error_type: TlsError, bearssl_code: i32, operation: []const u8, context: ?[]const u8) TlsErrorContext {
        return .{
            .error_type = error_type,
            .bearssl_code = bearssl_code,
            .message = error_map.getErrorMessage(bearssl_code),
            .operation = operation,
            .context = context,
            .timestamp = std.time.timestamp(),
            .recoverable = isRecoverable(error_type),
        };
    }
    
    /// Log the error with appropriate log level
    pub fn logError(self: *const TlsErrorContext) void {
        if (self.recoverable) {
            log.warn("TLS {s} failed (recoverable): {s} [BearSSL: {d}]", .{ 
                self.operation, self.message, self.bearssl_code 
            });
        } else {
            log.err("TLS {s} failed: {s} [BearSSL: {d}]", .{ 
                self.operation, self.message, self.bearssl_code 
            });
        }
        
        if (self.context) |ctx| {
            log.debug("Error context: {s}", .{ctx});
        }
    }
    
    /// Get a formatted error description
    pub fn format(self: *const TlsErrorContext, allocator: std.mem.Allocator) ![]u8 {
        if (self.context) |ctx| {
            return std.fmt.allocPrint(allocator, 
                "TLS {s} failed: {s} (context: {s}) [BearSSL code: {d}]", 
                .{ self.operation, self.message, ctx, self.bearssl_code }
            );
        } else {
            return std.fmt.allocPrint(allocator, 
                "TLS {s} failed: {s} [BearSSL code: {d}]", 
                .{ self.operation, self.message, self.bearssl_code }
            );
        }
    }
};

/// Determine if an error type is potentially recoverable
fn isRecoverable(error_type: TlsError) bool {
    return switch (error_type) {
        TlsError.NetworkTimeout,
        TlsError.ConnectionFailed,
        TlsError.IoError,
        TlsError.InsufficientResources,
        => true,
        
        else => false,
    };
}

/// Convert BearSSL error codes to standardized TLS errors
pub fn convertBearSslError(bearssl_code: i32) TlsError {
    return switch (bearssl_code) {
        // Success case
        c.BR_ERR_OK => TlsError.Unknown, // This shouldn't be called for success
        
        // I/O and connection errors
        c.BR_ERR_IO => TlsError.IoError,
        
        // Handshake errors
        c.BR_ERR_BAD_MAC => TlsError.MacVerificationFailed,
        c.BR_ERR_BAD_HANDSHAKE => TlsError.HandshakeFailed,
        c.BR_ERR_BAD_FINISHED => TlsError.HandshakeFailed,
        c.BR_ERR_UNSUPPORTED_VERSION => TlsError.ProtocolVersionMismatch,
        c.BR_ERR_BAD_VERSION => TlsError.ProtocolVersionMismatch,
        c.BR_ERR_BAD_CIPHER_SUITE => TlsError.CipherSuiteNegotiationFailed,
        c.BR_ERR_BAD_SNI => TlsError.ServerNameMismatch,
        
        // Protocol errors
        c.BR_ERR_BAD_PARAM => TlsError.InvalidConfiguration,
        c.BR_ERR_BAD_STATE => TlsError.ProtocolViolation,
        c.BR_ERR_UNEXPECTED => TlsError.UnexpectedMessage,
        c.BR_ERR_BAD_ALERT => TlsError.BadAlert,
        c.BR_ERR_BAD_CCS => TlsError.BadMessage,
        c.BR_ERR_BAD_COMPRESSION => TlsError.UnsupportedFeature,
        c.BR_ERR_BAD_FRAGLEN => TlsError.BadMessage,
        c.BR_ERR_BAD_SECRENEG => TlsError.ProtocolViolation,
        c.BR_ERR_EXTRA_EXTENSION => TlsError.ProtocolViolation,
        c.BR_ERR_BAD_HELLO_DONE => TlsError.BadMessage,
        c.BR_ERR_RESUME_MISMATCH => TlsError.HandshakeFailed,
        
        // Size and limit errors
        c.BR_ERR_TOO_LARGE => TlsError.ResourceExhausted,
        c.BR_ERR_LIMIT_EXCEEDED => TlsError.ResourceExhausted,
        c.BR_ERR_OVERSIZED_ID => TlsError.ResourceExhausted,
        
        // Cryptographic errors
        c.BR_ERR_INVALID_ALGORITHM => TlsError.UnsupportedFeature,
        c.BR_ERR_BAD_SIGNATURE => TlsError.InvalidSignature,
        c.BR_ERR_WRONG_KEY_USAGE => TlsError.CryptographicFailure,
        c.BR_ERR_NO_RANDOM => TlsError.CryptographicFailure,
        c.BR_ERR_UNKNOWN_TYPE => TlsError.UnsupportedFeature,
        c.BR_ERR_NO_CLIENT_AUTH => TlsError.InvalidConfiguration,
        
        // X.509 certificate errors
        33...63 => convertX509Error(bearssl_code),
        
        // Alert errors
        c.BR_ERR_RECV_FATAL_ALERT => TlsError.ConnectionClosed,
        c.BR_ERR_SEND_FATAL_ALERT => TlsError.ConnectionClosed,
        
        // Alert codes with offsets
        257...511 => TlsError.ConnectionClosed, // Received alerts
        513...767 => TlsError.ConnectionClosed, // Sent alerts
        
        else => TlsError.Unknown,
    };
}

/// Convert X.509 specific error codes to TLS errors
fn convertX509Error(bearssl_code: i32) TlsError {
    return switch (bearssl_code) {
        33...46 => TlsError.CertificateInvalid, // ASN.1 parsing errors
        47 => TlsError.CertificateInvalid, // Bad DN
        48 => TlsError.CertificateInvalid, // Bad time
        49 => TlsError.UnsupportedFeature, // Unsupported features
        50 => TlsError.ResourceExhausted, // Limits exceeded
        51 => TlsError.CryptographicFailure, // Wrong key type
        52 => TlsError.InvalidSignature, // Bad signature
        53 => TlsError.CertificateValidationFailed, // Time unknown
        54 => TlsError.CertificateExpired, // Expired
        55 => TlsError.CertificateChainBroken, // DN mismatch
        56 => TlsError.ServerNameMismatch, // Bad server name
        57 => TlsError.UnsupportedFeature, // Critical extension
        58 => TlsError.CertificateChainBroken, // Not CA
        59 => TlsError.CryptographicFailure, // Forbidden key usage
        60 => TlsError.WeakCryptography, // Weak public key
        62 => TlsError.CertificateNotTrusted, // Not trusted
        else => TlsError.CertificateValidationFailed,
    };
}

/// Create a TlsErrorContext from a BearSSL error code and operation
pub fn createErrorContext(bearssl_code: i32, operation: []const u8, context: ?[]const u8) TlsErrorContext {
    const error_type = convertBearSslError(bearssl_code);
    return TlsErrorContext.init(error_type, bearssl_code, operation, context);
}

/// Handle BearSSL errors with enhanced logging and context
pub fn handleBearSslError(bearssl_code: i32, operation: []const u8, context: ?[]const u8) TlsError {
    // Handle graceful close (code 0) specially
    if (bearssl_code == 0) {
        log.info("TLS connection closed gracefully during {s}", .{operation});
        return TlsError.ConnectionClosed;
    }
    
    // Create error context and log
    const error_ctx = createErrorContext(bearssl_code, operation, context);
    error_ctx.logError();
    
    return error_ctx.error_type;
}

/// Enhanced error handling for handshake failures
pub fn handleHandshakeError(bearssl_code: i32, server_name: ?[]const u8) TlsError {
    const context = if (server_name) |name| 
        std.fmt.allocPrint(std.heap.page_allocator, "server: {s}", .{name}) catch null
    else 
        null;
    defer if (context) |ctx| std.heap.page_allocator.free(ctx);
    
    return handleBearSslError(bearssl_code, "handshake", context);
}

/// Enhanced error handling for I/O operations
pub fn handleIoError(bearssl_code: i32, operation: []const u8, bytes_processed: usize) TlsError {
    const context = std.fmt.allocPrint(std.heap.page_allocator, "{d} bytes processed", .{bytes_processed}) catch null;
    defer if (context) |ctx| std.heap.page_allocator.free(ctx);
    
    return handleBearSslError(bearssl_code, operation, context);
}

/// Check if an error indicates the connection should be retried
pub fn shouldRetry(error_type: TlsError) bool {
    return switch (error_type) {
        TlsError.NetworkTimeout,
        TlsError.ConnectionFailed,
        TlsError.IoError,
        => true,
        else => false,
    };
}

/// Get error severity level for monitoring/alerting
pub const ErrorSeverity = enum {
    info,
    warning,
    err,
    critical,
};

pub fn getErrorSeverity(error_type: TlsError) ErrorSeverity {
    return switch (error_type) {
        TlsError.ConnectionClosed => .info,
        TlsError.NetworkTimeout, TlsError.IoError => .warning,
        TlsError.CertificateExpired, TlsError.WeakCryptography => .warning,
        TlsError.CertificateNotTrusted, TlsError.InvalidSignature => .err,
        TlsError.InternalError, TlsError.CryptographicFailure => .critical,
        else => .err,
    };
}

/// Error statistics for monitoring
pub const ErrorStats = struct {
    total_errors: u64 = 0,
    handshake_failures: u64 = 0,
    certificate_errors: u64 = 0,
    io_errors: u64 = 0,
    protocol_errors: u64 = 0,
    
    pub fn recordError(self: *ErrorStats, error_type: TlsError) void {
        self.total_errors += 1;
        
        switch (error_type) {
            TlsError.HandshakeFailed, TlsError.ProtocolVersionMismatch, TlsError.CipherSuiteNegotiationFailed => {
                self.handshake_failures += 1;
            },
            TlsError.CertificateValidationFailed, TlsError.CertificateExpired, TlsError.CertificateNotTrusted, 
            TlsError.CertificateInvalid, TlsError.CertificateChainBroken => {
                self.certificate_errors += 1;
            },
            TlsError.IoError, TlsError.ConnectionFailed, TlsError.NetworkTimeout => {
                self.io_errors += 1;
            },
            TlsError.BadMessage, TlsError.UnexpectedMessage, TlsError.ProtocolViolation, TlsError.BadAlert => {
                self.protocol_errors += 1;
            },
            else => {},
        }
    }
};