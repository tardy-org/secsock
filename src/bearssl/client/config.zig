/// Enhanced Configuration Management for BearSSL TLS
///
/// This module provides type-safe configuration validation, preset configurations
/// for common use cases, clear security mode selection, and improved debugging capabilities.
///
/// Key features:
/// - Type-safe configuration validation with comprehensive error checking
/// - Preset configurations for different environments and use cases
/// - Clear security mode selection with validation
/// - Enhanced debugging capabilities with configuration introspection
/// - Configuration templates for rapid setup
/// - Runtime configuration validation and warnings
const std = @import("std");
const security = @import("security.zig");
const SecurityConfig = security.SecurityConfig;
const SecurityMode = security.SecurityMode;

const log = std.log.scoped(.bearssl_config);

const c = @cImport({
    @cInclude("bearssl.h");
});

/// Configuration validation errors
pub const ConfigError = error{
    InvalidCipherSuite,
    InvalidProtocolVersion,
    InvalidCryptoAlgorithm,
    InvalidPrfAlgorithm,
    IncompatibleConfiguration,
    InvalidSecurityMode,
    ConfigurationConflict,
    MissingRequiredField,
    InvalidServerName,
    InvalidTrustAnchor,
    InsecureModeInProduction,
};

/// Debugging levels for configuration
pub const DebugLevel = enum {
    /// No debugging output
    none,
    /// Basic configuration info
    basic,
    /// Detailed configuration with warnings
    detailed,
    /// Verbose debugging with all internal state
    verbose,
    /// Complete trace including BearSSL internal calls
    trace,
    
    pub fn description(self: DebugLevel) []const u8 {
        return switch (self) {
            .none => "No debugging",
            .basic => "Basic configuration info",
            .detailed => "Detailed configuration with warnings", 
            .verbose => "Verbose debugging with internal state",
            .trace => "Complete trace including BearSSL calls",
        };
    }
};

/// Configuration presets for common use cases
pub const ConfigPreset = enum {
    /// Production-ready configuration with maximum security
    production_secure,
    /// Production configuration optimized for performance
    production_fast,
    /// Development configuration with helpful debugging
    development,
    /// Testing configuration with minimal validation
    testing,
    /// Local development with self-signed certificates
    local_dev,
    /// High-security configuration for sensitive applications
    high_security,
    /// Legacy compatibility configuration
    legacy_compat,
    /// Debug configuration with all validation disabled
    debug_insecure,
    
    pub fn description(self: ConfigPreset) []const u8 {
        return switch (self) {
            .production_secure => "Production (Maximum Security)",
            .production_fast => "Production (Performance Optimized)",
            .development => "Development (Debug Friendly)",
            .testing => "Testing (Minimal Validation)",
            .local_dev => "Local Development (Self-Signed OK)",
            .high_security => "High Security (Paranoid Mode)",
            .legacy_compat => "Legacy Compatibility",
            .debug_insecure => "Debug Insecure (NO VALIDATION)",
        };
    }
};

/// Enhanced cipher suite configuration with validation
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
    pub fn validate(self: *const CipherSuites) ConfigError!void {
        // Ensure at least one cipher suite is enabled
        if (!self.aes_cbc and !self.aes_gcm and !self.chacha_poly and !self.des_cbc) {
            log.err("No cipher suites enabled - at least one must be enabled", .{});
            return ConfigError.InvalidCipherSuite;
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
    
    /// Get security level of current configuration
    pub fn getSecurityLevel(self: *const CipherSuites) SecurityLevel {
        if (self.des_cbc and (!self.aes_gcm and !self.chacha_poly)) {
            return .weak;
        } else if (self.aes_gcm or self.chacha_poly) {
            return .strong;
        } else {
            return .moderate;
        }
    }
};

/// Enhanced cryptographic algorithm configuration
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
    pub fn validate(self: *const CryptoAlgos) ConfigError!void {
        // Ensure at least one signature algorithm is enabled
        if (!self.rsa_verify and !self.ecdsa) {
            log.err("No signature verification algorithms enabled", .{});
            return ConfigError.InvalidCryptoAlgorithm;
        }
        
        // Ensure at least one key type is supported
        if (!self.rsa_pub and !self.ec) {
            log.err("No public key algorithms enabled", .{});
            return ConfigError.InvalidCryptoAlgorithm;
        }
        
        // Check for incomplete configurations
        if (self.ecdsa and !self.ec) {
            log.warn("ECDSA enabled but EC operations disabled - this may cause issues", .{});
        }
    }
    
    /// Get security level of current configuration
    pub fn getSecurityLevel(self: *const CryptoAlgos) SecurityLevel {
        if (self.ec and self.ecdsa) {
            return .strong;
        } else if (self.rsa_verify and self.rsa_pub) {
            return .moderate;
        } else {
            return .weak;
        }
    }
};

/// Enhanced PRF algorithm configuration
pub const PrfAlgos = struct {
    /// TLS 1.0 PRF (enabled by default)
    tls10_prf: bool = true,

    /// TLS 1.2 SHA-256 PRF (enabled by default)
    tls12_sha256_prf: bool = true,

    /// TLS 1.2 SHA-384 PRF (enabled by default)
    tls12_sha384_prf: bool = true,
    
    /// Validate PRF algorithm configuration
    pub fn validate(self: *const PrfAlgos) ConfigError!void {
        // Ensure at least one PRF is enabled
        if (!self.tls10_prf and !self.tls12_sha256_prf and !self.tls12_sha384_prf) {
            log.err("No PRF algorithms enabled", .{});
            return ConfigError.InvalidPrfAlgorithm;
        }
        
        // Recommend modern PRFs
        if (self.tls10_prf and (!self.tls12_sha256_prf and !self.tls12_sha384_prf)) {
            log.warn("Only TLS 1.0 PRF enabled - consider enabling TLS 1.2 PRFs", .{});
        }
    }
    
    /// Get security level of current configuration
    pub fn getSecurityLevel(self: *const PrfAlgos) SecurityLevel {
        if (self.tls12_sha384_prf) {
            return .strong;
        } else if (self.tls12_sha256_prf) {
            return .moderate;
        } else {
            return .weak;
        }
    }
};

/// Security level enumeration
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
};

/// Enhanced TLS configuration with validation and presets
pub const EnhancedTlsConfig = struct {
    /// Server name for SNI (Server Name Indication)
    server_name: ?[]const u8 = null,

    /// Minimum TLS protocol version to support
    min_version: c_uint = c.BR_TLS10,

    /// Maximum TLS protocol version to support
    max_version: c_uint = c.BR_TLS12,

    /// Cipher suite configuration
    cipher_suites: CipherSuites = .{},

    /// Cryptographic algorithm configuration
    crypto_algos: CryptoAlgos = .{},

    /// PRF algorithm configuration
    prf_algos: PrfAlgos = .{},

    /// Security configuration and bypass policies
    security_config: SecurityConfig = SecurityConfig.init(),
    
    /// Debug level for configuration logging
    debug_level: DebugLevel = .basic,
    
    /// Custom validation rules
    strict_validation: bool = true,
    
    /// Performance optimization hints
    optimize_for_speed: bool = false,
    
    /// Create configuration from preset
    pub fn fromPreset(preset: ConfigPreset) EnhancedTlsConfig {
        return switch (preset) {
            .production_secure => productionSecure(),
            .production_fast => productionFast(),
            .development => development(),
            .testing => testing(),
            .local_dev => localDev(),
            .high_security => highSecurity(),
            .legacy_compat => legacyCompat(),
            .debug_insecure => debugInsecure(),
        };
    }
    
    /// Production configuration with maximum security
    pub fn productionSecure() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS12,
            .max_version = c.BR_TLS12,
            .cipher_suites = .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = false,
                .des_cbc = false,
            },
            .security_config = SecurityConfig.init(),
            .debug_level = .none,
            .strict_validation = true,
            .optimize_for_speed = false,
        };
    }
    
    /// Production configuration optimized for performance
    pub fn productionFast() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS11,
            .max_version = c.BR_TLS12,
            .cipher_suites = .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = true,
                .des_cbc = false,
            },
            .security_config = SecurityConfig.init(),
            .debug_level = .basic,
            .strict_validation = false,
            .optimize_for_speed = true,
        };
    }
    
    /// Development configuration with helpful debugging
    pub fn development() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS10,
            .max_version = c.BR_TLS12,
            .security_config = SecurityConfig.development(),
            .debug_level = .detailed,
            .strict_validation = false,
            .optimize_for_speed = false,
        };
    }
    
    /// Testing configuration with minimal validation
    pub fn testing() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS10,
            .max_version = c.BR_TLS12,
            .security_config = SecurityConfig.testing(),
            .debug_level = .verbose,
            .strict_validation = false,
            .optimize_for_speed = false,
        };
    }
    
    /// Local development with self-signed certificates
    pub fn localDev() EnhancedTlsConfig {
        return .{
            .server_name = "localhost",
            .min_version = c.BR_TLS10,
            .max_version = c.BR_TLS12,
            .security_config = SecurityConfig.development(),
            .debug_level = .detailed,
            .strict_validation = false,
            .optimize_for_speed = false,
        };
    }
    
    /// High-security configuration for sensitive applications
    pub fn highSecurity() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS12,
            .max_version = c.BR_TLS12,
            .cipher_suites = .{
                .aes_gcm = true,
                .chacha_poly = true,
                .aes_cbc = false,
                .des_cbc = false,
            },
            .crypto_algos = .{
                .rsa_verify = true,
                .ecdsa = true,
                .ec = true,
                .rsa_pub = false, // Prefer EC for higher security
            },
            .prf_algos = .{
                .tls10_prf = false,
                .tls12_sha256_prf = false,
                .tls12_sha384_prf = true,
            },
            .security_config = SecurityConfig.init(),
            .debug_level = .basic,
            .strict_validation = true,
            .optimize_for_speed = false,
        };
    }
    
    /// Legacy compatibility configuration
    pub fn legacyCompat() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS10,
            .max_version = c.BR_TLS12,
            .cipher_suites = .{
                .aes_cbc = true,
                .aes_gcm = true,
                .chacha_poly = true,
                .des_cbc = true,
            },
            .security_config = SecurityConfig.development(),
            .debug_level = .detailed,
            .strict_validation = false,
            .optimize_for_speed = false,
        };
    }
    
    /// Debug configuration with all validation disabled
    pub fn debugInsecure() EnhancedTlsConfig {
        return .{
            .min_version = c.BR_TLS10,
            .max_version = c.BR_TLS12,
            .security_config = SecurityConfig.debugInsecure(),
            .debug_level = .trace,
            .strict_validation = false,
            .optimize_for_speed = false,
        };
    }
    
    /// Comprehensive configuration validation
    pub fn validate(self: *const EnhancedTlsConfig) ConfigError!void {
        // Validate protocol versions
        try self.validateProtocolVersions();
        
        // Validate cipher suites
        try self.cipher_suites.validate();
        
        // Validate crypto algorithms
        try self.crypto_algos.validate();
        
        // Validate PRF algorithms
        try self.prf_algos.validate();
        
        // Validate security configuration
        try self.security_config.validate();
        
        // Check for configuration conflicts
        try self.checkCompatibility();
        
        // Validate server name if provided
        if (self.server_name) |name| {
            try self.validateServerName(name);
        }
        
        // Log configuration summary if debugging is enabled
        if (self.debug_level != .none) {
            self.logConfigurationSummary();
        }
    }
    
    /// Validate protocol version configuration
    fn validateProtocolVersions(self: *const EnhancedTlsConfig) ConfigError!void {
        if (self.min_version > self.max_version) {
            log.err("Minimum TLS version (0x{X}) is greater than maximum (0x{X})", .{
                self.min_version, self.max_version
            });
            return ConfigError.InvalidProtocolVersion;
        }
        
        // Check for deprecated versions
        if (self.min_version < c.BR_TLS11) {
            log.warn("TLS 1.0 is deprecated and should be avoided in production", .{});
        }
        
        // Recommend TLS 1.2+
        if (self.max_version < c.BR_TLS12) {
            log.warn("TLS 1.2 is recommended for modern security", .{});
        }
    }
    
    /// Check for configuration compatibility issues
    fn checkCompatibility(self: *const EnhancedTlsConfig) ConfigError!void {
        // Check security mode vs protocol version conflicts
        if (self.security_config.mode == .production and self.min_version < c.BR_TLS11) {
            log.warn("Production security mode with TLS 1.0 may not provide adequate security", .{});
        }
        
        // Check performance optimization conflicts
        if (self.optimize_for_speed and self.security_config.mode == .production) {
            if (!self.cipher_suites.aes_gcm) {
                log.warn("Performance optimization without AES-GCM may be suboptimal", .{});
            }
        }
        
        // Check strict validation conflicts
        if (self.strict_validation and self.security_config.allowsBypass(.certificate_validation)) {
            log.warn("Strict validation enabled but certificate bypass is allowed", .{});
        }
    }
    
    /// Validate server name format
    fn validateServerName(self: *const EnhancedTlsConfig, name: []const u8) ConfigError!void {
        _ = self;
        
        if (name.len == 0) {
            log.err("Server name cannot be empty", .{});
            return ConfigError.InvalidServerName;
        }
        
        if (name.len > 255) {
            log.err("Server name too long (max 255 characters)", .{});
            return ConfigError.InvalidServerName;
        }
        
        // Basic DNS name validation
        if (std.mem.indexOf(u8, name, " ") != null) {
            log.warn("Server name contains spaces - this may cause issues", .{});
        }
    }
    
    /// Log comprehensive configuration summary
    fn logConfigurationSummary(self: *const EnhancedTlsConfig) void {
        log.info("=== TLS Configuration Summary ===", .{});
        log.info("Debug Level: {s}", .{self.debug_level.description()});
        log.info("Security Mode: {s}", .{self.security_config.mode.description()});
        log.info("Protocol Versions: TLS {s} - {s}", .{
            self.getVersionString(self.min_version),
            self.getVersionString(self.max_version)
        });
        
        if (self.server_name) |name| {
            log.info("Server Name: {s}", .{name});
        }
        
        log.info("Cipher Suite Security: {s}", .{self.cipher_suites.getSecurityLevel().description()});
        log.info("Crypto Algorithm Security: {s}", .{self.crypto_algos.getSecurityLevel().description()});
        log.info("PRF Algorithm Security: {s}", .{self.prf_algos.getSecurityLevel().description()});
        
        if (self.strict_validation) {
            log.info("Strict Validation: Enabled", .{});
        } else {
            log.info("Strict Validation: Disabled", .{});
        }
        
        if (self.optimize_for_speed) {
            log.info("Performance Optimization: Enabled", .{});
        }
        
        log.info("=== End Configuration Summary ===", .{});
    }
    
    /// Get human-readable version string
    fn getVersionString(self: *const EnhancedTlsConfig, version: c_uint) []const u8 {
        _ = self;
        return switch (version) {
            c.BR_TLS10 => "1.0",
            c.BR_TLS11 => "1.1", 
            c.BR_TLS12 => "1.2",
            else => "Unknown",
        };
    }
    
    /// Get overall security assessment
    pub fn getSecurityAssessment(self: *const EnhancedTlsConfig) SecurityAssessment {
        const cipher_level = self.cipher_suites.getSecurityLevel();
        const crypto_level = self.crypto_algos.getSecurityLevel();
        const prf_level = self.prf_algos.getSecurityLevel();
        
        // Determine overall level based on weakest component
        const overall_level = switch (self.security_config.mode) {
            .production => blk: {
                if (cipher_level == .weak or crypto_level == .weak or prf_level == .weak) {
                    break :blk SecurityLevel.weak;
                } else if (cipher_level == .strong and crypto_level == .strong and prf_level == .strong) {
                    break :blk SecurityLevel.strong;
                } else {
                    break :blk SecurityLevel.moderate;
                }
            },
            .development, .testing => SecurityLevel.moderate,
            .debug_insecure => SecurityLevel.weak,
        };
        
        const has_warnings = (self.min_version < c.BR_TLS11) or 
                           (self.cipher_suites.des_cbc) or 
                           (self.security_config.mode != .production);
        
        return SecurityAssessment{
            .overall_level = overall_level,
            .cipher_level = cipher_level,
            .crypto_level = crypto_level,
            .prf_level = prf_level,
            .has_warnings = has_warnings,
            .is_production_ready = overall_level != .weak and self.security_config.mode == .production,
        };
    }
};

/// Security assessment summary
pub const SecurityAssessment = struct {
    overall_level: SecurityLevel,
    cipher_level: SecurityLevel,
    crypto_level: SecurityLevel,
    prf_level: SecurityLevel,
    has_warnings: bool,
    is_production_ready: bool,
    
    /// Generate security assessment report
    pub fn generateReport(self: *const SecurityAssessment, writer: anytype) !void {
        try writer.print("=== Security Assessment Report ===\n");
        try writer.print("Overall Security Level: {s}\n", .{self.overall_level.description()});
        try writer.print("Cipher Suite Security: {s}\n", .{self.cipher_level.description()});
        try writer.print("Crypto Algorithm Security: {s}\n", .{self.crypto_level.description()});
        try writer.print("PRF Algorithm Security: {s}\n", .{self.prf_level.description()});
        try writer.print("Production Ready: {s}\n", .{if (self.is_production_ready) "Yes" else "No"});
        
        if (self.has_warnings) {
            try writer.print("Status: ⚠️  Configuration has security warnings\n");
        } else {
            try writer.print("Status: ✅ Configuration is secure\n");
        }
        
        try writer.print("=== End Assessment Report ===\n");
    }
};

/// Configuration builder for fluent API
pub const ConfigBuilder = struct {
    config: EnhancedTlsConfig,
    
    pub fn init() ConfigBuilder {
        return .{ .config = EnhancedTlsConfig{} };
    }
    
    pub fn fromPreset(preset: ConfigPreset) ConfigBuilder {
        return .{ .config = EnhancedTlsConfig.fromPreset(preset) };
    }
    
    pub fn serverName(self: *ConfigBuilder, name: []const u8) *ConfigBuilder {
        self.config.server_name = name;
        return self;
    }
    
    pub fn protocolVersions(self: *ConfigBuilder, min: c_uint, max: c_uint) *ConfigBuilder {
        self.config.min_version = min;
        self.config.max_version = max;
        return self;
    }
    
    pub fn securityMode(self: *ConfigBuilder, mode: SecurityMode) *ConfigBuilder {
        self.config.security_config.mode = mode;
        return self;
    }
    
    pub fn debugLevel(self: *ConfigBuilder, level: DebugLevel) *ConfigBuilder {
        self.config.debug_level = level;
        return self;
    }
    
    pub fn strictValidation(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.strict_validation = enabled;
        return self;
    }
    
    pub fn optimizeForSpeed(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.optimize_for_speed = enabled;
        return self;
    }
    
    pub fn build(self: *ConfigBuilder) !EnhancedTlsConfig {
        try self.config.validate();
        return self.config;
    }
};