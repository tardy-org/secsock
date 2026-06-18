/// BearSSL error code mapping
///
/// This module provides automatic mapping between BearSSL error codes (BR_ERR_*)
/// and their corresponding string representations.
///
/// The error mappings are generated from BearSSL header files (bearssl_ssl.h
/// and bearssl_x509.h) to ensure completeness and accuracy.

const std = @import("std");

/// Error pair type for mapping error codes to descriptions
const ErrorPair = struct {
    code: i32,
    message: []const u8,
};

/// Error mapping table for BearSSL error codes
const ERROR_MESSAGES = [_]ErrorPair{
    // X.509 certificate validation errors (32-63)
    .{ .code = 32, .message = "Validation was successful (BR_ERR_X509_OK)" },
    .{ .code = 33, .message = "Invalid value in ASN.1 structure (BR_ERR_X509_INVALID_VALUE)" },
    .{ .code = 34, .message = "Truncated certificate (BR_ERR_X509_TRUNCATED)" },
    .{ .code = 35, .message = "Empty certificate chain (BR_ERR_X509_EMPTY_CHAIN)" },
    .{ .code = 36, .message = "Inner element extends beyond outer element size (BR_ERR_X509_INNER_TRUNC)" },
    .{ .code = 37, .message = "Unsupported tag class (BR_ERR_X509_BAD_TAG_CLASS)" },
    .{ .code = 38, .message = "Unsupported tag value (BR_ERR_X509_BAD_TAG_VALUE)" },
    .{ .code = 39, .message = "Indefinite length (BR_ERR_X509_INDEFINITE_LENGTH)" },
    .{ .code = 40, .message = "Extraneous element (BR_ERR_X509_EXTRA_ELEMENT)" },
    .{ .code = 41, .message = "Unexpected element (BR_ERR_X509_UNEXPECTED)" },
    .{ .code = 42, .message = "Expected constructed element, but is primitive (BR_ERR_X509_NOT_CONSTRUCTED)" },
    .{ .code = 43, .message = "Expected primitive element, but is constructed (BR_ERR_X509_NOT_PRIMITIVE)" },
    .{ .code = 44, .message = "BIT STRING length is not multiple of 8 (BR_ERR_X509_PARTIAL_BYTE)" },
    .{ .code = 45, .message = "BOOLEAN value has invalid length (BR_ERR_X509_BAD_BOOLEAN)" },
    .{ .code = 46, .message = "Value is off-limits (BR_ERR_X509_OVERFLOW)" },
    .{ .code = 47, .message = "Invalid distinguished name (BR_ERR_X509_BAD_DN)" },
    .{ .code = 48, .message = "Invalid date/time representation (BR_ERR_X509_BAD_TIME)" },
    .{ .code = 49, .message = "Unsupported certificate features (BR_ERR_X509_UNSUPPORTED)" },
    .{ .code = 50, .message = "Key or signature size exceeds internal limits (BR_ERR_X509_LIMIT_EXCEEDED)" },
    .{ .code = 51, .message = "Wrong key type (BR_ERR_X509_WRONG_KEY_TYPE)" },
    .{ .code = 52, .message = "Invalid signature (BR_ERR_X509_BAD_SIGNATURE)" },
    .{ .code = 53, .message = "Validation time is unknown (BR_ERR_X509_TIME_UNKNOWN)" },
    .{ .code = 54, .message = "Certificate is expired or not yet valid (BR_ERR_X509_EXPIRED)" },
    .{ .code = 55, .message = "Issuer/subject DN mismatch (BR_ERR_X509_DN_MISMATCH)" },
    .{ .code = 56, .message = "Expected server name not found (BR_ERR_X509_BAD_SERVER_NAME)" },
    .{ .code = 57, .message = "Unknown critical extension (BR_ERR_X509_CRITICAL_EXTENSION)" },
    .{ .code = 58, .message = "Not a CA, or path length constraint violation (BR_ERR_X509_NOT_CA)" },
    .{ .code = 59, .message = "Key Usage extension prohibits intended usage (BR_ERR_X509_FORBIDDEN_KEY_USAGE)" },
    .{ .code = 60, .message = "Public key is too small (BR_ERR_X509_WEAK_PUBLIC_KEY)" },
    .{ .code = 62, .message = "Chain could not be linked to a trust anchor (BR_ERR_X509_NOT_TRUSTED)" },

    // SSL/TLS protocol errors (0-31, 256, 512)
    .{ .code = 0, .message = "Success (BR_ERR_OK)" },
    .{ .code = 1, .message = "Bad parameter (BR_ERR_BAD_PARAM)" },
    .{ .code = 2, .message = "Bad state (BR_ERR_BAD_STATE)" },
    .{ .code = 3, .message = "Unsupported version (BR_ERR_UNSUPPORTED_VERSION)" },
    .{ .code = 4, .message = "Bad version (BR_ERR_BAD_VERSION)" },
    .{ .code = 5, .message = "Bad length (BR_ERR_BAD_LENGTH)" },
    .{ .code = 6, .message = "Too large (BR_ERR_TOO_LARGE)" },
    .{ .code = 7, .message = "Bad MAC - handshake integrity check failed (BR_ERR_BAD_MAC)" },
    .{ .code = 8, .message = "No random (BR_ERR_NO_RANDOM)" },
    .{ .code = 9, .message = "Unknown type (BR_ERR_UNKNOWN_TYPE)" },
    .{ .code = 10, .message = "Unexpected message (BR_ERR_UNEXPECTED)" },
    .{ .code = 12, .message = "Bad Change Cipher Spec (BR_ERR_BAD_CCS)" },
    .{ .code = 13, .message = "Bad alert (BR_ERR_BAD_ALERT)" },
    .{ .code = 14, .message = "Bad handshake (BR_ERR_BAD_HANDSHAKE)" },
    .{ .code = 15, .message = "Oversized ID (BR_ERR_OVERSIZED_ID)" },
    .{ .code = 16, .message = "Bad cipher suite (BR_ERR_BAD_CIPHER_SUITE)" },
    .{ .code = 17, .message = "Bad compression (BR_ERR_BAD_COMPRESSION)" },
    .{ .code = 18, .message = "Bad fragment length (BR_ERR_BAD_FRAGLEN)" },
    .{ .code = 19, .message = "Bad secure renegotiation (BR_ERR_BAD_SECRENEG)" },
    .{ .code = 20, .message = "Extra extension (BR_ERR_EXTRA_EXTENSION)" },
    .{ .code = 21, .message = "Bad SNI (BR_ERR_BAD_SNI)" },
    .{ .code = 22, .message = "Bad Hello Done (BR_ERR_BAD_HELLO_DONE)" },
    .{ .code = 23, .message = "Limit exceeded (BR_ERR_LIMIT_EXCEEDED)" },
    .{ .code = 24, .message = "Bad Finished message (BR_ERR_BAD_FINISHED)" },
    .{ .code = 25, .message = "Resume mismatch (BR_ERR_RESUME_MISMATCH)" },
    .{ .code = 26, .message = "Invalid algorithm (BR_ERR_INVALID_ALGORITHM)" },
    .{ .code = 27, .message = "Bad signature - verification failed (BR_ERR_BAD_SIGNATURE)" },
    .{ .code = 28, .message = "Wrong key usage (BR_ERR_WRONG_KEY_USAGE)" },
    .{ .code = 29, .message = "No client authentication (BR_ERR_NO_CLIENT_AUTH)" },
    .{ .code = 31, .message = "I/O error (BR_ERR_IO)" },
    .{ .code = 256, .message = "Received fatal alert (BR_ERR_RECV_FATAL_ALERT)" },
    .{ .code = 512, .message = "Sent fatal alert (BR_ERR_SEND_FATAL_ALERT)" },
};

/// Gets a human-readable error message for a BearSSL error code
pub fn getErrorMessage(error_code: i32) []const u8 {
    // Look up the error code in our table
    for (ERROR_MESSAGES) |err| {
        if (err.code == error_code) {
            return err.message;
        }
    }
    
    // Handle alerts with fixed offsets
    if (error_code > 256 and error_code < 512) {
        // Received alert
        const alert_code = error_code - 256;
        return std.fmt.allocPrint(std.heap.page_allocator, 
            "Received fatal alert: {d}", .{alert_code}) catch "Received unknown alert";
    } else if (error_code >= 512) {
        // Sent alert
        const alert_code = error_code - 512;
        return std.fmt.allocPrint(std.heap.page_allocator, 
            "Sent fatal alert: {d}", .{alert_code}) catch "Sent unknown alert";
    }
    
    return "Unknown error";
}

// Test function to make sure error codes map correctly
test "Error mapping test" {
    const testing = std.testing;
    
    try testing.expectEqualStrings("Chain could not be linked to a trust anchor (BR_ERR_X509_NOT_TRUSTED)", getErrorMessage(62));
    try testing.expectEqualStrings("Bad MAC - handshake integrity check failed (BR_ERR_BAD_MAC)", getErrorMessage(7));
    try testing.expectEqualStrings("Success (BR_ERR_OK)", getErrorMessage(0));
}