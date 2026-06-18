/// Modular BearSSL TLS client implementation for SecureSocket
///
/// This is the new modular implementation that replaces the monolithic client.zig.
/// It imports focused modules for specific concerns and provides a clean API.
///
/// Key features:
/// - Modular architecture with focused modules
/// - Type-safe operations with comprehensive validation
/// - Unified memory management with RAII pattern
/// - Enhanced security configuration and validation
/// - Comprehensive error handling and debugging
/// - Performance monitoring and audit logging
const std = @import("std");
const assert = std.debug.assert;

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;
const BearSSL = @import("../lib.zig").BearSSL;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = @import("../lib.zig").EngineStatus;

// Import focused modules
const memory = @import("client/memory.zig");
const ManagedTlsContext = memory.ManagedTlsContext;
const error_handling = @import("client/error.zig");
const TlsError = error_handling.TlsError;
const context_module = @import("client/context.zig");
const TypeSafeContext = context_module.TypeSafeContext;
const ContextType = context_module.ContextType;
const TypeSafeWrapper = context_module.TypeSafeWrapper;
const security = @import("client/security.zig");
const SecurityMode = security.SecurityMode;
const SecurityConfig = security.SecurityConfig;
const config_module = @import("client/config.zig");
const EnhancedTlsConfig = config_module.EnhancedTlsConfig;
const ConfigPreset = config_module.ConfigPreset;
const ConfigBuilder = config_module.ConfigBuilder;
const crypto = @import("client/crypto.zig");
const trust = @import("client/trust.zig");
const debug = @import("client/debug.zig");
const vtable = @import("client/vtable.zig");

const log = std.log.scoped(.@"bearssl/client");

const c = @cImport({
    @cInclude("bearssl.h");
});

/// Backward compatibility alias for DEBUG_INSECURE preset
pub const DEBUG_INSECURE = TlsConfig.debugInsecure();

/// Export enhanced configuration types for public API
pub const Config = config_module;
pub const ConfigPresets = ConfigPreset;
pub const ConfigurationBuilder = ConfigBuilder;

/// Export focused module APIs
pub const Memory = memory;
pub const ErrorHandling = error_handling;
pub const Context = context_module;
pub const Security = security;
pub const Crypto = crypto;
pub const Trust = trust;
pub const Debug = debug;
pub const Vtable = vtable;

/// Configuration options for TLS client connections.
/// Allows customizing the TLS behavior regarding protocols, ciphers,
/// crypto algorithms, and security policies.
pub const TlsConfig = struct {
    /// Cipher suite configuration options
    pub const CipherSuites = struct {
        /// AES in CBC mode (enabled by default)
        aes_cbc: bool = true,

        /// AES in GCM mode (enabled by default)
        aes_gcm: bool = true,

        /// ChaCha20+Poly1305 suite (enabled by default)
        chacha_poly: bool = true,

        /// 3DES in CBC mode (enabled by default, but consider security implications)
        des_cbc: bool = true,
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
    };

    /// PRF implementation configuration options
    pub const PrfAlgos = struct {
        /// TLS 1.0 PRF (enabled by default)
        tls10_prf: bool = true,

        /// TLS 1.2 SHA-256 PRF (enabled by default)
        tls12_sha256_prf: bool = true,

        /// TLS 1.2 SHA-384 PRF (enabled by default)
        tls12_sha384_prf: bool = true,
    };

    /// Server name for SNI (Server Name Indication)
    /// If null, "localhost" will be used as the default
    server_name: ?[]const u8 = null,

    /// Minimum TLS protocol version to support
    /// Defaults to TLS 1.0 (BR_TLS10)
    min_version: c_uint = c.BR_TLS10,

    /// Maximum TLS protocol version to support
    /// Defaults to TLS 1.2 (BR_TLS12)
    max_version: c_uint = c.BR_TLS12,

    /// Enable/disable specific cipher suites
    cipher_suites: CipherSuites = .{},

    /// Enable/disable specific crypto algorithms
    crypto_algos: CryptoAlgos = .{},

    /// Enable/disable specific PRF implementations
    prf_algos: PrfAlgos = .{},

    /// Security configuration and bypass policies
    security_config: SecurityConfig = SecurityConfig.init(),

    /// Create production configuration with full security
    pub fn production() TlsConfig {
        return .{
            .security_config = SecurityConfig.init(),
        };
    }

    /// Create development configuration with relaxed validation
    pub fn development() TlsConfig {
        return .{
            .security_config = SecurityConfig.development(),
        };
    }

    /// Create testing configuration with minimal validation
    pub fn testing() TlsConfig {
        return .{
            .security_config = SecurityConfig.testing(),
        };
    }

    /// Create debug insecure configuration (backward compatibility)
    /// This is equivalent to the old DEBUG_INSECURE preset
    pub fn debugInsecure() TlsConfig {
        return .{
            .security_config = SecurityConfig.debugInsecure(),
        };
    }

    /// Create configuration from enhanced preset with full validation
    pub fn fromPreset(preset: ConfigPreset) !TlsConfig {
        const enhanced = EnhancedTlsConfig.fromPreset(preset);
        try enhanced.validate();

        return .{
            .server_name = enhanced.server_name,
            .min_version = enhanced.min_version,
            .max_version = enhanced.max_version,
            .cipher_suites = .{
                .aes_cbc = enhanced.cipher_suites.aes_cbc,
                .aes_gcm = enhanced.cipher_suites.aes_gcm,
                .chacha_poly = enhanced.cipher_suites.chacha_poly,
                .des_cbc = enhanced.cipher_suites.des_cbc,
            },
            .crypto_algos = .{
                .rsa_verify = enhanced.crypto_algos.rsa_verify,
                .ecdsa = enhanced.crypto_algos.ecdsa,
                .ec = enhanced.crypto_algos.ec,
                .rsa_pub = enhanced.crypto_algos.rsa_pub,
            },
            .prf_algos = .{
                .tls10_prf = enhanced.prf_algos.tls10_prf,
                .tls12_sha256_prf = enhanced.prf_algos.tls12_sha256_prf,
                .tls12_sha384_prf = enhanced.prf_algos.tls12_sha384_prf,
            },
            .security_config = enhanced.security_config,
        };
    }

    /// Validate current configuration
    pub fn validate(self: *const TlsConfig) !void {
        // Create enhanced config for validation
        const enhanced = EnhancedTlsConfig{
            .server_name = self.server_name,
            .min_version = self.min_version,
            .max_version = self.max_version,
            .cipher_suites = .{
                .aes_cbc = self.cipher_suites.aes_cbc,
                .aes_gcm = self.cipher_suites.aes_gcm,
                .chacha_poly = self.cipher_suites.chacha_poly,
                .des_cbc = self.cipher_suites.des_cbc,
            },
            .crypto_algos = .{
                .rsa_verify = self.crypto_algos.rsa_verify,
                .ecdsa = self.crypto_algos.ecdsa,
                .ec = self.crypto_algos.ec,
                .rsa_pub = self.crypto_algos.rsa_pub,
            },
            .prf_algos = .{
                .tls10_prf = self.prf_algos.tls10_prf,
                .tls12_sha256_prf = self.prf_algos.tls12_sha256_prf,
                .tls12_sha384_prf = self.prf_algos.tls12_sha384_prf,
            },
            .security_config = self.security_config,
        };

        try enhanced.validate();
    }

    /// Get security assessment for this configuration
    pub fn getSecurityAssessment(self: *const TlsConfig) config_module.SecurityAssessment {
        const enhanced = EnhancedTlsConfig{
            .server_name = self.server_name,
            .min_version = self.min_version,
            .max_version = self.max_version,
            .cipher_suites = .{
                .aes_cbc = self.cipher_suites.aes_cbc,
                .aes_gcm = self.cipher_suites.aes_gcm,
                .chacha_poly = self.cipher_suites.chacha_poly,
                .des_cbc = self.cipher_suites.des_cbc,
            },
            .crypto_algos = .{
                .rsa_verify = self.crypto_algos.rsa_verify,
                .ecdsa = self.crypto_algos.ecdsa,
                .ec = self.crypto_algos.ec,
                .rsa_pub = self.crypto_algos.rsa_pub,
            },
            .prf_algos = .{
                .tls10_prf = self.prf_algos.tls10_prf,
                .tls12_sha256_prf = self.prf_algos.tls12_sha256_prf,
                .tls12_sha384_prf = self.prf_algos.tls12_sha384_prf,
            },
            .security_config = self.security_config,
        };

        return enhanced.getSecurityAssessment();
    }
};

/// Initialize the BearSSL client and X.509 validation contexts using managed context.
/// Optimized implementation with comprehensive validation and security enforcement.
///
/// This function sets up:
/// - The X.509 minimal validation context with the provided trust anchors
/// - The client SSL context with all required crypto algorithms
/// - Configurable cipher suites and protocol versions for TLS communication
/// - Security validation and policy enforcement
///
/// Parameters:
/// - managed_ctx: The managed TLS context that provides all BearSSL resources
/// - trust_anchors: Array of trust anchors to use for certificate validation
/// - trust_anchors_len: Number of trust anchors in the array
/// - config: Optional configuration for TLS parameters (defaults used if null)
fn init_ssl_context_impl(
    managed_ctx: *ManagedTlsContext,
    trust_anchors: [*c]const c.br_x509_trust_anchor,
    trust_anchors_len: usize,
    config: ?*const TlsConfig,
) !void {
    // Get contexts from managed context
    const client_ctx = try managed_ctx.getClientCtx();
    const x509_ctx = try managed_ctx.getX509Ctx();
    const io_buf = try managed_ctx.getIoBuf();

    // Use either provided config or defaults
    const cfg = config orelse &TlsConfig{};

    // Validate configuration if validation is enabled
    cfg.validate() catch |err| {
        log.warn("Configuration validation failed: {s}", .{@errorName(err)});
    };

    // Validate and enforce security configuration
    try security.SecurityPolicy.enforceRuntime(&cfg.security_config);
    cfg.security_config.logSecurityMode();

    // Log security assessment if debugging is enabled
    const assessment = cfg.getSecurityAssessment();
    if (!assessment.is_production_ready) {
        log.warn("Configuration is not production-ready", .{});
    }
    if (assessment.has_warnings) {
        log.warn("Configuration has security warnings - review recommended", .{});
    }

    // Apply security-aware certificate validation
    if (cfg.security_config.allowsBypass(.certificate_validation)) {
        cfg.security_config.logBypass(.certificate_validation, "during SSL context initialization");

        // In insecure modes, initialize with minimal validation
        c.br_x509_minimal_init(x509_ctx, null, null, 0);
        c.br_ssl_client_init_full(client_ctx, x509_ctx, null, 0);
    } else {
        // Normal secure initialization
        c.br_x509_minimal_init_full(x509_ctx, trust_anchors, trust_anchors_len);
        c.br_ssl_client_init_full(client_ctx, x509_ctx, trust_anchors, trust_anchors_len);
    }

    // Convert simple config types to enhanced crypto types for configuration
    const crypto_cipher_suites = crypto.CipherSuites{
        .aes_cbc = cfg.cipher_suites.aes_cbc,
        .aes_gcm = cfg.cipher_suites.aes_gcm,
        .chacha_poly = cfg.cipher_suites.chacha_poly,
        .des_cbc = cfg.cipher_suites.des_cbc,
    };

    const crypto_algos = crypto.CryptoAlgos{
        .rsa_verify = cfg.crypto_algos.rsa_verify,
        .ecdsa = cfg.crypto_algos.ecdsa,
        .ec = cfg.crypto_algos.ec,
        .rsa_pub = cfg.crypto_algos.rsa_pub,
    };

    const prf_algos = crypto.PrfAlgos{
        .tls10_prf = cfg.prf_algos.tls10_prf,
        .tls12_sha256_prf = cfg.prf_algos.tls12_sha256_prf,
        .tls12_sha384_prf = cfg.prf_algos.tls12_sha384_prf,
    };

    // Apply crypto, PRF, and cipher configurations using focused modules
    crypto.configureCryptoAlgos(client_ctx, &crypto_algos);
    crypto.configurePrfAlgos(&client_ctx.eng, &prf_algos);
    crypto.configureCipherSuites(&client_ctx.eng, &crypto_cipher_suites);

    // Set TLS protocol versions
    c.br_ssl_engine_set_versions(&client_ctx.eng, cfg.min_version, cfg.max_version);

    // Set X.509 verification algorithms only if not bypassed
    if (!cfg.security_config.allowsBypass(.certificate_validation)) {
        c.br_x509_minimal_set_rsa(x509_ctx, c.br_ssl_engine_get_rsavrfy(&client_ctx.eng));
        c.br_x509_minimal_set_ecdsa(x509_ctx, c.br_ssl_engine_get_ec(&client_ctx.eng), c.br_ssl_engine_get_ecdsa(&client_ctx.eng));
    }

    // Set up I/O buffer
    c.br_ssl_engine_set_buffer(&client_ctx.eng, io_buf.ptr, io_buf.len, 1);
}

/// Public API wrapper for initializing BearSSL client and X.509 validation contexts.
/// This function has the same signature but uses the C calling convention to ensure compatibility
/// with external code that might call it.
///
/// Parameters:
/// - managed_ctx: The managed TLS context that provides all BearSSL resources
/// - trust_anchors: Array of trust anchors to use for certificate validation
/// - trust_anchors_len: Number of trust anchors in the array
/// - config: Optional configuration for TLS parameters (defaults used if null)
fn init_ssl_context(
    managed_ctx: *ManagedTlsContext,
    trust_anchors: [*c]const c.br_x509_trust_anchor,
    trust_anchors_len: usize,
    config: ?*const TlsConfig,
) callconv(.C) !void {
    try init_ssl_context_impl(managed_ctx, trust_anchors, trust_anchors_len, config);
}

/// Allocates and initializes resources for a BearSSL client using type-safe unified memory management
/// Returns a properly initialized VtableContext with RAII cleanup
fn createVtableContext(
    self: *BearSSL,
    socket: Socket,
) !*vtable.VtableContext {
    // Create managed TLS context for unified memory management
    var managed_ctx = ManagedTlsContext.init(self.allocator);

    // Set up type-safe callback context
    const cb_data = vtable.CallbackContextData{ .runtime = null, .socket = socket, .trace_enabled = true };
    const cb_ctx = try self.allocator.create(vtable.CallbackContext);
    errdefer {
        self.allocator.destroy(cb_ctx);
        managed_ctx.deinit();
    }
    cb_ctx.* = vtable.CallbackContext.init(cb_data, "TLS callback context");

    // Create type-safe vtable context
    const context = try self.allocator.create(vtable.VtableContext);
    errdefer {
        self.allocator.destroy(cb_ctx);
        managed_ctx.deinit();
        self.allocator.destroy(context);
    }

    // Create security audit if enabled in security config
    const security_audit = if (self.tls_config) |cfg| blk: {
        if (cfg.security_config.enable_warnings) {
            const audit = try self.allocator.create(security.SecurityAudit);
            audit.* = security.SecurityAudit.init(self.allocator);
            break :blk audit;
        }
        break :blk null;
    } else null;

    // Create performance monitor if enabled
    const performance_monitor = if (self.tls_config) |cfg| blk: {
        if (cfg.security_config.mode == .development or cfg.security_config.mode == .testing) {
            const monitor = try self.allocator.create(debug.PerformanceMonitor);
            monitor.* = debug.PerformanceMonitor.init();
            break :blk monitor;
        }
        break :blk null;
    } else null;

    const context_data = vtable.VtableContextData{
        .managed_ctx = managed_ctx,
        .bearssl = self,
        .cb_ctx = cb_ctx,
        .error_stats = error_handling.ErrorStats{},
        .security_audit = security_audit,
        .performance_monitor = performance_monitor,
    };
    context.* = vtable.VtableContext.init(context_data, "TLS vtable context");

    return context;
}

/// Initialize SSL context with appropriate trust anchors using type-safe managed context
fn setupSslContext(self: *BearSSL, ctx: *vtable.VtableContext) !void {
    const data = try ctx.getData();

    if (self.trust_store.anchors.items.len > 0) {
        log.info("Using {d} trust anchors from PEM files", .{self.trust_store.anchors.items.len});
        try init_ssl_context_impl(&data.managed_ctx, self.trust_store.anchors.items.ptr, self.trust_store.anchors.items.len, self.tls_config);
    } else {
        log.info("Using {d} hardcoded trust anchors", .{trust.TrustAnchors.getDefaultCount()});
        try init_ssl_context_impl(&data.managed_ctx, trust.TrustAnchors.getDefaultAnchors(), trust.TrustAnchors.getDefaultCount(), self.tls_config);
    }

    // Initial engine reset
    log.info("Initializing client context", .{});
    // const client_ctx = try data.managed_ctx.getClientCtx();
    log.info("Initializing client context after try ", .{});
    // if (c.br_ssl_client_reset(client_ctx, null, 0) == 0) {
    //     log.err("Client reset failed", .{});
    //     return error.ClientResetFailed;
    // }
    log.info("Initializing client context after if", .{});
}

/// Create a SecureSocket client implementation using BearSSL.
///
/// This function takes a raw socket and wraps it in a TLS client connection.
/// It implements the SecureSocket interface, allowing use of TLS in the
/// same way as an unencrypted socket.
///
/// Memory management:
/// - Uses unified memory management with RAII pattern
/// - All memory is automatically cleaned up when SecureSocket is deinitialized
/// - Type-safe context operations with validation
///
/// The returned SecureSocket must be properly deinitialized with deinit()
/// when it is no longer needed.
///
/// Parameters:
/// - self: The BearSSL instance with configuration
/// - socket: The raw socket to wrap with TLS
///
/// Returns: A SecureSocket instance that encrypts all communication using TLS
pub fn to_secure_socket_client(self: *BearSSL, socket: Socket) !SecureSocket {
    log.info("Creating BearSSL client", .{});

    // Allocate and initialize client context using modular approach
    const context = try createVtableContext(self, socket);
    errdefer {
        if (context.getData()) |data| {
            data.managed_ctx.deinit();
            self.allocator.destroy(data.cb_ctx);
            if (data.security_audit) |audit| {
                audit.deinit();
                self.allocator.destroy(audit);
            }
            if (data.performance_monitor) |monitor| {
                self.allocator.destroy(monitor);
            }
        } else |_| {}
        self.allocator.destroy(context);
    }

    // Set up SSL context with trust anchors
    try setupSslContext(self, context);

    // Create and return the SecureSocket using focused vtable module
    return vtable.createSecureSocketVtable(context, socket);
}
