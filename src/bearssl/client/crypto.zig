/// Cryptographic algorithm configuration and utilities for BearSSL TLS
///
/// This module provides comprehensive cryptographic algorithm management,
/// including cipher suite configuration, crypto algorithm setup, and PRF configuration.
///
/// Key features:
/// - Type-safe cipher suite configuration with validation
/// - Cryptographic algorithm setup and validation  
/// - PRF (Pseudo-Random Function) configuration
/// - Security level assessment for crypto configurations
/// - Comptime-optimized configuration application
const std = @import("std");

const log = std.log.scoped(.bearssl_crypto);

const c = @cImport({
    @cInclude("bearssl.h");
});

/// Cipher suite configuration options with validation
pub const CipherSuites = struct {
    /// AES in CBC mode (enabled by default)
    aes_cbc: bool = true,

    /// AES in GCM mode (enabled by default)
    aes_gcm: bool = true,

    /// ChaCha20+Poly1305 suite (enabled by default)
    chacha_poly: bool = true,

    /// 3DES in CBC mode (disabled by default for security)
    des_cbc: bool = false,
    
    /// Validate cipher suite configuration
    pub fn validate(self: *const CipherSuites) !void {
        // Ensure at least one cipher suite is enabled
        if (!self.aes_cbc and !self.aes_gcm and !self.chacha_poly and !self.des_cbc) {
            log.err("No cipher suites enabled - at least one must be enabled", .{});
            return error.NoCipherSuitesEnabled;
        }
        
        // Warn about weak cipher suites
        if (self.des_cbc) {
            log.warn("3DES-CBC is enabled - consider disabling for better security", .{});
        }
        
        // Recommend modern cipher suites
        if (!self.aes_gcm and !self.chacha_poly) {
            log.warn("No AEAD cipher suites enabled - consider enabling AES-GCM or ChaCha20-Poly1305", .{});
        }
    }
    
    /// Get security level of current cipher suite configuration
    pub fn getSecurityLevel(self: *const CipherSuites) SecurityLevel {
        if (self.des_cbc and (!self.aes_gcm and !self.chacha_poly)) {
            return .weak;
        } else if (self.aes_gcm or self.chacha_poly) {
            return .strong;
        } else {
            return .moderate;
        }
    }
    
    /// Check if configuration uses only modern AEAD cipher suites
    pub fn isModernOnly(self: *const CipherSuites) bool {
        return (self.aes_gcm or self.chacha_poly) and !self.aes_cbc and !self.des_cbc;
    }
    
    /// Get list of enabled cipher suites for logging
    pub fn getEnabledSuites(self: *const CipherSuites, allocator: std.mem.Allocator) ![]const u8 {
        var suites = std.ArrayList([]const u8).init(allocator);
        defer suites.deinit();
        
        if (self.aes_gcm) try suites.append("AES-GCM");
        if (self.chacha_poly) try suites.append("ChaCha20-Poly1305");
        if (self.aes_cbc) try suites.append("AES-CBC");
        if (self.des_cbc) try suites.append("3DES-CBC");
        
        return std.mem.join(allocator, ", ", suites.items);
    }
};

/// Cryptographic algorithm configuration options
pub const CryptoAlgos = struct {
    /// RSA verification (enabled by default)
    rsa_verify: bool = true,

    /// ECDSA operations (enabled by default)
    ecdsa: bool = true,

    /// EC key operations (enabled by default)
    ec: bool = true,

    /// RSA public key operations (enabled by default)
    rsa_pub: bool = true,
    
    /// Validate crypto algorithm configuration
    pub fn validate(self: *const CryptoAlgos) !void {
        // Ensure at least one signature algorithm is enabled
        if (!self.rsa_verify and !self.ecdsa) {
            log.err("No signature verification algorithms enabled", .{});
            return error.NoSignatureAlgorithms;
        }
        
        // Ensure at least one key type is supported
        if (!self.rsa_pub and !self.ec) {
            log.err("No public key algorithms enabled", .{});
            return error.NoPublicKeyAlgorithms;
        }
        
        // Check for incomplete configurations
        if (self.ecdsa and !self.ec) {
            log.warn("ECDSA enabled but EC operations disabled - this may cause issues", .{});
        }
    }
    
    /// Get security level of current crypto algorithm configuration
    pub fn getSecurityLevel(self: *const CryptoAlgos) SecurityLevel {
        if (self.ec and self.ecdsa) {
            return .strong;
        } else if (self.rsa_verify and self.rsa_pub) {
            return .moderate;
        } else {
            return .weak;
        }
    }
    
    /// Check if configuration prefers elliptic curve cryptography
    pub fn prefersECC(self: *const CryptoAlgos) bool {
        return self.ec and self.ecdsa and !self.rsa_pub;
    }
    
    /// Get list of enabled algorithms for logging
    pub fn getEnabledAlgorithms(self: *const CryptoAlgos, allocator: std.mem.Allocator) ![]const u8 {
        var algos = std.ArrayList([]const u8).init(allocator);
        defer algos.deinit();
        
        if (self.ecdsa) try algos.append("ECDSA");
        if (self.rsa_verify) try algos.append("RSA-Verify");
        if (self.ec) try algos.append("EC");
        if (self.rsa_pub) try algos.append("RSA-Pub");
        
        return std.mem.join(allocator, ", ", algos.items);
    }
};

/// PRF implementation configuration options
pub const PrfAlgos = struct {
    /// TLS 1.0 PRF (enabled by default)
    tls10_prf: bool = true,

    /// TLS 1.2 SHA-256 PRF (enabled by default)
    tls12_sha256_prf: bool = true,

    /// TLS 1.2 SHA-384 PRF (enabled by default)
    tls12_sha384_prf: bool = true,
    
    /// Validate PRF algorithm configuration
    pub fn validate(self: *const PrfAlgos) !void {
        // Ensure at least one PRF is enabled
        if (!self.tls10_prf and !self.tls12_sha256_prf and !self.tls12_sha384_prf) {
            log.err("No PRF algorithms enabled", .{});
            return error.NoPrfAlgorithms;
        }
        
        // Recommend modern PRFs
        if (self.tls10_prf and (!self.tls12_sha256_prf and !self.tls12_sha384_prf)) {
            log.warn("Only TLS 1.0 PRF enabled - consider enabling TLS 1.2 PRFs", .{});
        }
    }
    
    /// Get security level of current PRF configuration
    pub fn getSecurityLevel(self: *const PrfAlgos) SecurityLevel {
        if (self.tls12_sha384_prf) {
            return .strong;
        } else if (self.tls12_sha256_prf) {
            return .moderate;
        } else {
            return .weak;
        }
    }
    
    /// Check if configuration uses only modern TLS 1.2+ PRFs
    pub fn isModernOnly(self: *const PrfAlgos) bool {
        return !self.tls10_prf and (self.tls12_sha256_prf or self.tls12_sha384_prf);
    }
    
    /// Get list of enabled PRFs for logging
    pub fn getEnabledPrfs(self: *const PrfAlgos, allocator: std.mem.Allocator) ![]const u8 {
        var prfs = std.ArrayList([]const u8).init(allocator);
        defer prfs.deinit();
        
        if (self.tls12_sha384_prf) try prfs.append("TLS1.2-SHA384");
        if (self.tls12_sha256_prf) try prfs.append("TLS1.2-SHA256");
        if (self.tls10_prf) try prfs.append("TLS1.0-PRF");
        
        return std.mem.join(allocator, ", ", prfs.items);
    }
};

/// Security level enumeration for cryptographic configurations
pub const SecurityLevel = enum {
    weak,
    moderate,
    strong,
    
    pub fn description(self: SecurityLevel) []const u8 {
        return switch (self) {
            .weak => "Weak (legacy compatibility)",
            .moderate => "Moderate (balanced security)",
            .strong => "Strong (modern security)",
        };
    }
    
    pub fn isAcceptableForProduction(self: SecurityLevel) bool {
        return self != .weak;
    }
};

/// Configure cipher suites based on TLS configuration
/// Uses a comptime-generated array of configuration pairs for optimal performance
pub fn configureCipherSuites(eng: *c.br_ssl_engine_context, cipher_config: *const CipherSuites) void {
    const CipherSetter = struct {
        field_name: []const u8,
        setter: fn ([*c]c.br_ssl_engine_context) callconv(.C) void,
    };

    // Define all available cipher setters with compile-time optimization
    inline for (comptime [_]CipherSetter{
        .{ .field_name = "aes_cbc", .setter = c.br_ssl_engine_set_default_aes_cbc },
        .{ .field_name = "aes_gcm", .setter = c.br_ssl_engine_set_default_aes_gcm },
        .{ .field_name = "chacha_poly", .setter = c.br_ssl_engine_set_default_chapol },
        .{ .field_name = "des_cbc", .setter = c.br_ssl_engine_set_default_des_cbc },
    }) |suite| {
        if (@field(cipher_config, suite.field_name)) {
            suite.setter(eng);
            log.debug("Enabled cipher suite: {s}", .{suite.field_name});
        }
    }
}

/// Configure crypto algorithms based on TLS configuration
/// Uses a comptime-generated array of configuration pairs for optimal performance
pub fn configureCryptoAlgos(client_ctx: *c.br_ssl_client_context, crypto_config: *const CryptoAlgos) void {
    const AlgoSetter = struct {
        field_name: []const u8,
        setter: fn ([*c]c.br_ssl_engine_context) callconv(.C) void,
    };

    // Apply engine crypto algorithms with compile-time optimization
    inline for (comptime [_]AlgoSetter{
        .{ .field_name = "rsa_verify", .setter = c.br_ssl_engine_set_default_rsavrfy },
        .{ .field_name = "ecdsa", .setter = c.br_ssl_engine_set_default_ecdsa },
        .{ .field_name = "ec", .setter = c.br_ssl_engine_set_default_ec },
    }) |algo| {
        if (@field(crypto_config, algo.field_name)) {
            algo.setter(&client_ctx.eng);
            log.debug("Enabled crypto algorithm: {s}", .{algo.field_name});
        }
    }

    // Special case - RSA public key operations use a different function
    if (crypto_config.rsa_pub) {
        c.br_ssl_client_set_default_rsapub(client_ctx);
        log.debug("Enabled RSA public key operations", .{});
    }
}

/// Configure PRF algorithms based on TLS configuration
/// Enables/disables specific PRF implementations according to provided config
pub fn configurePrfAlgos(eng: *c.br_ssl_engine_context, prf_config: *const PrfAlgos) void {
    // Configure TLS 1.0 PRF
    if (prf_config.tls10_prf) {
        c.br_ssl_engine_set_prf10(eng, c.br_tls10_prf);
        log.debug("Enabled TLS 1.0 PRF", .{});
    }

    // Configure TLS 1.2 SHA-256 PRF
    if (prf_config.tls12_sha256_prf) {
        c.br_ssl_engine_set_prf_sha256(eng, c.br_tls12_sha256_prf);
        log.debug("Enabled TLS 1.2 SHA-256 PRF", .{});
    }

    // Configure TLS 1.2 SHA-384 PRF
    if (prf_config.tls12_sha384_prf) {
        c.br_ssl_engine_set_prf_sha384(eng, c.br_tls12_sha384_prf);
        log.debug("Enabled TLS 1.2 SHA-384 PRF", .{});
    }
}

/// Comprehensive cryptographic configuration validation
pub fn validateCryptoConfiguration(cipher_suites: *const CipherSuites, crypto_algos: *const CryptoAlgos, prf_algos: *const PrfAlgos) !void {
    // Validate individual components
    try cipher_suites.validate();
    try crypto_algos.validate();
    try prf_algos.validate();
    
    // Check for compatibility issues
    try checkCryptoCompatibility(cipher_suites, crypto_algos, prf_algos);
}

/// Check for cryptographic configuration compatibility issues
fn checkCryptoCompatibility(cipher_suites: *const CipherSuites, crypto_algos: *const CryptoAlgos, prf_algos: *const PrfAlgos) !void {
    // Check AEAD cipher compatibility
    if (cipher_suites.aes_gcm and !prf_algos.tls12_sha256_prf and !prf_algos.tls12_sha384_prf) {
        log.warn("AES-GCM enabled but no TLS 1.2 PRF - may cause compatibility issues", .{});
    }
    
    // Check ChaCha20-Poly1305 compatibility
    if (cipher_suites.chacha_poly and !prf_algos.tls12_sha256_prf) {
        log.warn("ChaCha20-Poly1305 enabled but TLS 1.2 SHA-256 PRF disabled - may cause issues", .{});
    }
    
    // Check EC algorithm consistency
    if (crypto_algos.ecdsa and !crypto_algos.ec) {
        log.warn("ECDSA signature verification enabled but EC operations disabled", .{});
    }
    
    // Check for weak configurations
    if (cipher_suites.getSecurityLevel() == .weak or 
        crypto_algos.getSecurityLevel() == .weak or 
        prf_algos.getSecurityLevel() == .weak) {
        log.warn("Cryptographic configuration contains weak algorithms", .{});
    }
}

/// Generate comprehensive cryptographic configuration report
pub fn generateCryptoReport(cipher_suites: *const CipherSuites, crypto_algos: *const CryptoAlgos, prf_algos: *const PrfAlgos, allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("=== Cryptographic Configuration Report ===\n");
    
    // Cipher suites
    try writer.print("Cipher Suite Security Level: {s}\n", .{cipher_suites.getSecurityLevel().description()});
    const enabled_suites = try cipher_suites.getEnabledSuites(allocator);
    defer allocator.free(enabled_suites);
    try writer.print("Enabled Cipher Suites: {s}\n", .{enabled_suites});
    
    // Crypto algorithms
    try writer.print("Crypto Algorithm Security Level: {s}\n", .{crypto_algos.getSecurityLevel().description()});
    const enabled_algos = try crypto_algos.getEnabledAlgorithms(allocator);
    defer allocator.free(enabled_algos);
    try writer.print("Enabled Crypto Algorithms: {s}\n", .{enabled_algos});
    
    // PRF algorithms
    try writer.print("PRF Algorithm Security Level: {s}\n", .{prf_algos.getSecurityLevel().description()});
    const enabled_prfs = try prf_algos.getEnabledPrfs(allocator);
    defer allocator.free(enabled_prfs);
    try writer.print("Enabled PRF Algorithms: {s}\n", .{enabled_prfs});
    
    // Security assessment
    const overall_level = getOverallSecurityLevel(cipher_suites, crypto_algos, prf_algos);
    try writer.print("Overall Security Level: {s}\n", .{overall_level.description()});
    
    if (overall_level.isAcceptableForProduction()) {
        try writer.print("Production Readiness: ✅ Acceptable\n");
    } else {
        try writer.print("Production Readiness: ⚠️  Not recommended\n");
    }
    
    try writer.print("=== End Crypto Report ===\n");
}

/// Get overall security level based on all cryptographic components
pub fn getOverallSecurityLevel(cipher_suites: *const CipherSuites, crypto_algos: *const CryptoAlgos, prf_algos: *const PrfAlgos) SecurityLevel {
    const cipher_level = cipher_suites.getSecurityLevel();
    const crypto_level = crypto_algos.getSecurityLevel();
    const prf_level = prf_algos.getSecurityLevel();
    
    // Overall level is determined by the weakest component
    if (cipher_level == .weak or crypto_level == .weak or prf_level == .weak) {
        return .weak;
    } else if (cipher_level == .strong and crypto_level == .strong and prf_level == .strong) {
        return .strong;
    } else {
        return .moderate;
    }
}

/// Cryptographic configuration presets for common use cases
pub const CryptoPresets = struct {
    /// Maximum security configuration (modern algorithms only)
    pub fn maxSecurity() struct { CipherSuites, CryptoAlgos, PrfAlgos } {
        return .{
            .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = false,
                .des_cbc = false,
            },
            .{
                .rsa_verify = true,
                .ecdsa = true,
                .ec = true,
                .rsa_pub = false, // Prefer EC
            },
            .{
                .tls10_prf = false,
                .tls12_sha256_prf = false,
                .tls12_sha384_prf = true,
            },
        };
    }
    
    /// Balanced security and performance configuration
    pub fn balanced() struct { CipherSuites, CryptoAlgos, PrfAlgos } {
        return .{
            .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = true,
                .des_cbc = false,
            },
            .{
                .rsa_verify = true,
                .ecdsa = true,
                .ec = true,
                .rsa_pub = true,
            },
            .{
                .tls10_prf = false,
                .tls12_sha256_prf = true,
                .tls12_sha384_prf = true,
            },
        };
    }
    
    /// Legacy compatibility configuration
    pub fn legacyCompat() struct { CipherSuites, CryptoAlgos, PrfAlgos } {
        return .{
            .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = true,
                .des_cbc = true,
            },
            .{
                .rsa_verify = true,
                .ecdsa = true,
                .ec = true,
                .rsa_pub = true,
            },
            .{
                .tls10_prf = true,
                .tls12_sha256_prf = true,
                .tls12_sha384_prf = true,
            },
        };
    }
};