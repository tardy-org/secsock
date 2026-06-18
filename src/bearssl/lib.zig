const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const log_truststore = std.log.scoped(.secsock);

const c_truststore = @cImport({
    @cInclude("bearssl.h");
});

/// TrustAnchorStore manages a collection of trust anchors (certificates) used
/// for validating server certificates in TLS connections.
///
/// Memory Management:
/// - All trust anchors are deep-copied from source PEM/DER data
/// - The TrustAnchorStore owns all memory for the trust anchors (DN and key material)
/// - When deinit() is called, all memory is properly released
/// - The caller is responsible for calling deinit() when done with the store
///
/// Usage:
/// ```
/// var store = TrustAnchorStore.init(allocator);
/// defer store.deinit();
/// try store.addAnchorFromPem(pem_data);
/// // Use the anchors for certificate validation...
/// ```
const TrustAnchorStore = struct {
    /// The allocator used for all memory allocations in this store
    allocator: Allocator,

    /// List of trust anchors managed by this store
    anchors: ArrayList(c_truststore.br_x509_trust_anchor),

    /// Initialize a new TrustAnchorStore with the given allocator
    pub fn init(allocator: Allocator) TrustAnchorStore {
        return .{
            .allocator = allocator,
            .anchors = ArrayList(c_truststore.br_x509_trust_anchor).init(allocator),
        };
    }

    /// Release all resources associated with this TrustAnchorStore.
    ///
    /// This function:
    /// 1. Frees memory for each trust anchor's Distinguished Name (DN)
    /// 2. Frees key material (RSA n, e or EC q) based on key type
    /// 3. Releases the ArrayList storage
    ///
    /// After calling this function, the TrustAnchorStore should not be used.
    pub fn deinit(self: *TrustAnchorStore) void {
        log_truststore.debug("Cleaning up {d} trust anchors", .{self.anchors.items.len});

        // Free memory allocated for each trust anchor's DN and Key data
        for (self.anchors.items) |*anchor| {
            // Free the duplicated DN data
            if (anchor.dn.data) |ptr| {
                const slice = @as([*]u8, @ptrCast(ptr))[0..anchor.dn.len];
                self.allocator.free(slice);
            }

            // Free the duplicated key data based on type
            switch (anchor.pkey.key_type) {
                c_truststore.BR_KEYTYPE_RSA => {
                    // Free RSA modulus 'n'
                    if (anchor.pkey.key.rsa.n) |ptr| {
                        const slice = @as([*]u8, @ptrCast(ptr))[0..anchor.pkey.key.rsa.nlen];
                        self.allocator.free(slice);
                    }

                    // Free RSA exponent 'e' - we need to free this as we explicitly allocate it
                    if (anchor.pkey.key.rsa.e) |ptr| {
                        const slice = @as([*]u8, @ptrCast(ptr))[0..anchor.pkey.key.rsa.elen];
                        self.allocator.free(slice);
                    }
                },
                c_truststore.BR_KEYTYPE_EC => {
                    // Free 'q' for EC keys
                    if (anchor.pkey.key.ec.q) |ptr| {
                        const slice = @as([*]u8, @ptrCast(ptr))[0..anchor.pkey.key.ec.qlen];
                        self.allocator.free(slice);
                    }
                },
                else => {
                    // Handle other key types if necessary, or log warning
                    log_truststore.warn("Unsupported key type {d} in trust anchor during deinit", .{anchor.pkey.key_type});
                },
            }
            // Reset anchor fields to avoid dangling pointers if reused
            anchor.* = @as(c_truststore.br_x509_trust_anchor, undefined);
        }

        self.anchors.deinit(); // Free the ArrayList storage itself
        log_truststore.debug("Trust anchor cleanup complete", .{});
    }

    /// Adds a trust anchor from PEM-encoded certificate data.
    ///
    /// This function:
    /// 1. Decodes the PEM data to extract the DER-encoded certificate
    /// 2. Parses the certificate to extract the Distinguished Name and public key
    /// 3. Creates a trust anchor with deep copies of all certificate data
    /// 4. Adds the new trust anchor to the store
    ///
    /// Memory Management:
    /// - All certificate data is deep-copied using the store's allocator
    /// - The original pem_data is not modified or stored
    /// - On any error, all allocated memory is properly released
    ///
    /// Errors:
    /// - PemDecodeFailed: If the PEM data is invalid
    /// - PemSectionNotFound: If no "CERTIFICATE" section is found
    /// - X509DecodingError: If the certificate cannot be parsed
    /// - NoCertificatePublicKey: If no public key is found in the certificate
    /// - UnsupportedKeyType: If the certificate uses an unsupported key type
    /// - Various allocation errors if memory allocation fails
    ///
    /// Example:
    /// ```
    /// const pem_bytes = @embedFile("cert.pem");
    /// try trust_store.addAnchorFromPem(pem_bytes);
    /// ```
    pub fn addAnchorFromPem(self: *TrustAnchorStore, pem_data: []const u8) !void {
        log_truststore.debug("Attempting to decode PEM data for trust anchor ({d} bytes)", .{pem_data.len});

        // 1. Decode PEM to get DER certificate data
        const der_bytes = try decodePemToDer(self.allocator, pem_data, "CERTIFICATE");
        defer self.allocator.free(der_bytes);
        log_truststore.debug("PEM decoded to {d} bytes of DER data", .{der_bytes.len});

        // 2. Parse DER certificate to get DN and Public Key
        var dn_data: []u8 = undefined; // Will be filled by parseDerCertificate
        var pkey: c_truststore.br_x509_pkey = undefined;

        try parseDerCertificate(der_bytes, &dn_data, &pkey);
        defer std.heap.page_allocator.free(dn_data); // parseDerCertificate allocates this
        log_truststore.debug("DER certificate parsed. DN len: {d}, Key type: {d}", .{ dn_data.len, pkey.key_type });

        // 3. Make deep copies of all key data using our allocator
        // First copy the Distinguished Name (DN) data
        const dn_copy = try self.allocator.dupe(u8, dn_data);
        errdefer self.allocator.free(dn_copy);

        // Make a copy of the original pkey with new allocations
        var pkey_copy = pkey;

        // Deep copy the key-specific data (different for RSA vs EC keys)
        switch (pkey.key_type) {
            c_truststore.BR_KEYTYPE_RSA => {
                // For RSA keys we need to copy both 'n' and 'e' components
                if (pkey.key.rsa.n != null and pkey.key.rsa.nlen > 0) {
                    const n_slice = @as([*]const u8, @ptrCast(pkey.key.rsa.n))[0..pkey.key.rsa.nlen];
                    const n_copy = try self.allocator.dupe(u8, n_slice);
                    pkey_copy.key.rsa.n = n_copy.ptr;

                    // We don't want to free the original 'n' pointer here, as it belongs to
                    // the BearSSL key structure obtained from br_x509_decoder_get_pkey
                    // The memory will be cleaned up when the library is done with it
                }

                if (pkey.key.rsa.e != null and pkey.key.rsa.elen > 0) {
                    const e_slice = @as([*]const u8, @ptrCast(pkey.key.rsa.e))[0..pkey.key.rsa.elen];
                    const e_copy = try self.allocator.dupe(u8, e_slice);
                    pkey_copy.key.rsa.e = e_copy.ptr;

                    // Don't free the original 'e' pointer here either for the same reason as above
                }
            },
            c_truststore.BR_KEYTYPE_EC => {
                // For EC keys we need to copy the 'q' component
                if (pkey.key.ec.q != null and pkey.key.ec.qlen > 0) {
                    const q_slice = @as([*]const u8, @ptrCast(pkey.key.ec.q))[0..pkey.key.ec.qlen];
                    const q_copy = try self.allocator.dupe(u8, q_slice);
                    pkey_copy.key.ec.q = q_copy.ptr;

                    // Don't free the original 'q' pointer, as it belongs to
                    // the BearSSL key structure obtained from br_x509_decoder_get_pkey
                }
            },
            else => {
                log_truststore.err("Unsupported public key type for trust anchor: {d}", .{pkey.key_type});
                return error.UnsupportedKeyType;
            },
        }

        // Set up error cleanup in case we fail after key allocation
        errdefer {
            switch (pkey_copy.key_type) {
                c_truststore.BR_KEYTYPE_RSA => {
                    if (pkey_copy.key.rsa.n != null) {
                        const slice = @as([*]u8, @ptrCast(pkey_copy.key.rsa.n))[0..pkey_copy.key.rsa.nlen];
                        self.allocator.free(slice);
                    }
                    if (pkey_copy.key.rsa.e != null) {
                        const slice = @as([*]u8, @ptrCast(pkey_copy.key.rsa.e))[0..pkey_copy.key.rsa.elen];
                        self.allocator.free(slice);
                    }
                },
                c_truststore.BR_KEYTYPE_EC => {
                    if (pkey_copy.key.ec.q != null) {
                        const slice = @as([*]u8, @ptrCast(pkey_copy.key.ec.q))[0..pkey_copy.key.ec.qlen];
                        self.allocator.free(slice);
                    }
                },
                else => {},
            }
        }

        // 4. Create the trust anchor struct with our copies
        const ta = c_truststore.br_x509_trust_anchor{
            .dn = .{ .data = dn_copy.ptr, .len = dn_copy.len },
            // Set proper flags based on whether it's a CA certificate
            // We could check if it's a CA by examining certificate properties,
            // but for simplicity we'll just mark all as CAs which is safer for trust anchors
            .flags = c_truststore.BR_X509_TA_CA,
            .pkey = pkey_copy,
        };

        // 5. Add to the list of trust anchors
        try self.anchors.append(ta);
        log_truststore.info("Successfully added trust anchor. Total anchors: {d}", .{self.anchors.items.len});
    }

    /// Decodes a PEM-encoded certificate into DER format.
    ///
    /// This function searches for the specified section (e.g., "CERTIFICATE") in the PEM data
    /// and decodes it into the binary DER format that can be parsed by X.509 functions.
    ///
    /// Memory Management:
    /// - Allocates memory for the decoded DER data using the provided allocator
    /// - The caller is responsible for freeing this memory when done
    /// - On error, any allocated memory is automatically freed
    ///
    /// Parameters:
    /// - allocator: The allocator to use for the DER data allocation
    /// - pem: The PEM-encoded certificate data (not modified or stored)
    /// - section: The PEM section name to look for (usually "CERTIFICATE")
    ///
    /// Returns: A slice containing the DER-encoded certificate data.
    ///          The caller owns this memory and must free it when done.
    fn decodePemToDer(allocator: Allocator, pem: []const u8, section: []const u8) ![]u8 {
        log_truststore.debug("Decoding PEM to DER, looking for section '{s}'", .{section});

        // Use the same approach as in decode_pem
        var p_ctx: c_truststore.br_pem_decoder_context = undefined;
        c_truststore.br_pem_decoder_init(&p_ctx);

        var decoded = try std.ArrayListUnmanaged(u8).initCapacity(allocator, pem.len);
        defer decoded.deinit(allocator);

        c_truststore.br_pem_decoder_setdest(&p_ctx, struct {
            fn decoder(ctx: ?*anyopaque, src: ?*const anyopaque, size: usize) callconv(.c) void {
                var list: *std.ArrayListUnmanaged(u8) = @ptrCast(@alignCast(ctx.?));
                const data = @as([*c]const u8, @ptrCast(src.?))[0..size];
                list.appendSliceAssumeCapacity(data);
            }
        }.decoder, &decoded);

        var found = false;
        var written: usize = 0;

        while (written < pem.len) {
            written += c_truststore.br_pem_decoder_push(&p_ctx, pem[written..].ptr, pem.len - written);
            const event = c_truststore.br_pem_decoder_event(&p_ctx);
            switch (event) {
                0 => continue,
                c_truststore.BR_PEM_BEGIN_OBJ => {
                    const name = c_truststore.br_pem_decoder_name(&p_ctx);
                    if (std.mem.eql(u8, std.mem.span(name), section)) {
                        found = true;
                        decoded.clearRetainingCapacity();
                    }
                },
                c_truststore.BR_PEM_END_OBJ => if (found) {
                    log_truststore.debug("Found PEM section '{s}', decoded {d} bytes of DER", .{ section, decoded.items.len });
                    return decoded.toOwnedSlice(allocator);
                },
                c_truststore.BR_PEM_ERROR => {
                    log_truststore.err("PEM decoder error", .{});
                    return error.PemDecodeFailed;
                },
                else => return error.PemDecodeUnknownEvent,
            }
        }

        if (found) {
            log_truststore.err("PEM section '{s}' incomplete", .{section});
            return error.PemDecodeNotFinished;
        } else {
            log_truststore.err("PEM section '{s}' not found", .{section});
            return error.PemSectionNotFound;
        }
    }

    /// Extract certificate data from DER-encoded certificate using BearSSL's X.509 decoder.
    ///
    /// This function parses a DER-encoded X.509 certificate to extract:
    /// 1. The Distinguished Name (DN) - identifies the certificate subject
    /// 2. The public key - used for signature verification
    ///
    /// Memory Management:
    /// - This function allocates memory for DN and public key components
    /// - All allocations use the page_allocator (not the TrustAnchorStore's allocator)
    /// - The caller is responsible for freeing the allocated memory:
    ///   - The DN data in dn_data.*
    ///   - The key components (RSA n/e or EC q) in pkey.*
    /// - On error, any allocated memory is automatically freed
    ///
    /// Parameters:
    /// - der: The DER-encoded certificate data (not modified or stored)
    /// - dn_data: Output parameter that will receive the allocated DN data
    /// - pkey: Output parameter that will receive the public key info
    ///
    /// Note: This function is internal to the TrustAnchorStore implementation and
    /// should not be called directly from outside code.
    fn parseDerCertificate(der: []const u8, dn_data: *[]u8, pkey: *c_truststore.br_x509_pkey) !void {
        // Use the page allocator for intermediate allocations
        // These will be copied to the TrustAnchorStore's allocator by the caller
        const allocator = std.heap.page_allocator;
        log_truststore.debug("Parsing DER certificate data, {d} bytes", .{der.len});

        // We need to collect the DN data during parsing, using a simple vector to store it
        var dn_buf = ArrayList(u8).init(allocator);
        defer dn_buf.deinit();

        // Create X.509 decoder context with a callback for DN collection
        var x509_dc: c_truststore.br_x509_decoder_context = undefined;

        // Set up the callback to collect DN data
        c_truststore.br_x509_decoder_init(&x509_dc, struct {
            fn dn_append(ctx: ?*anyopaque, buf: ?*const anyopaque, len: usize) callconv(.C) void {
                const list = @as(*ArrayList(u8), @ptrCast(@alignCast(ctx.?)));
                if (buf != null and len > 0) {
                    const data = @as([*]const u8, @ptrCast(buf.?))[0..len];
                    list.appendSlice(data) catch {};
                }
            }
        }.dn_append, &dn_buf);

        // Push the entire DER certificate data for parsing
        c_truststore.br_x509_decoder_push(&x509_dc, der.ptr, der.len);

        // Check for parsing errors
        const err = c_truststore.br_x509_decoder_last_error(&x509_dc);
        if (err != 0) {
            log_truststore.err("X.509 decoder error: {d}", .{err});
            return error.X509DecodingError;
        }

        // Get the public key from the certificate
        const cert_pkey = c_truststore.br_x509_decoder_get_pkey(&x509_dc);
        if (cert_pkey == null) {
            log_truststore.err("Failed to extract public key from certificate", .{});
            return error.NoCertificatePublicKey;
        }

        // Copy the DN data collected by the callback
        dn_data.* = try allocator.dupe(u8, dn_buf.items);
        errdefer allocator.free(dn_data.*);

        // Now copy the public key details based on the key type
        const key = cert_pkey.?.*;
        pkey.* = key;

        // Deep copy key material based on type
        switch (key.key_type) {
            c_truststore.BR_KEYTYPE_RSA => {
                if (key.key.rsa.n != null and key.key.rsa.nlen > 0) {
                    const n_slice = @as([*]const u8, @ptrCast(key.key.rsa.n))[0..key.key.rsa.nlen];
                    const n_copy = try allocator.dupe(u8, n_slice);
                    errdefer allocator.free(n_copy);
                    pkey.key.rsa.n = n_copy.ptr;
                    pkey.key.rsa.nlen = key.key.rsa.nlen;
                }

                if (key.key.rsa.e != null and key.key.rsa.elen > 0) {
                    const e_slice = @as([*]const u8, @ptrCast(key.key.rsa.e))[0..key.key.rsa.elen];
                    const e_copy = try allocator.dupe(u8, e_slice);
                    errdefer allocator.free(e_copy);
                    pkey.key.rsa.e = e_copy.ptr;
                    pkey.key.rsa.elen = key.key.rsa.elen;
                }
            },
            c_truststore.BR_KEYTYPE_EC => {
                if (key.key.ec.q != null and key.key.ec.qlen > 0) {
                    const q_slice = @as([*]const u8, @ptrCast(key.key.ec.q))[0..key.key.ec.qlen];
                    const q_copy = try allocator.dupe(u8, q_slice);
                    errdefer allocator.free(q_copy);
                    pkey.key.ec.q = q_copy.ptr;
                    pkey.key.ec.qlen = key.key.ec.qlen;
                    pkey.key.ec.curve = key.key.ec.curve;
                }
            },
            else => {
                // Free the DN data we already allocated in case of error
                allocator.free(dn_data.*);
                log_truststore.err("Unsupported key type: {d}", .{key.key_type});
                return error.UnsupportedKeyType;
            },
        }

        log_truststore.debug("Certificate parsed, DN size: {d}, key_type: {d}", .{ dn_data.*.len, pkey.key_type });
    }
};

const std = @import("std");
const assert = std.debug.assert;

const c = @import("bearssl_h");
const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

pub const SecureSocket = @import("../lib.zig").SecureSocket;


const log = std.log.scoped(.bearssl);

pub const EngineStatus = enum {
    Ok,
    BadParam,
    BadState,
    UnsupportedVersion,
    BadVersion,
    TooLarge,
    BadMac,
    NoRandom,
    UnknownType,
    Unexpected,
    BadCcs,
    BadAlert,
    BadHandshake,
    OversizedId,
    BadCipherSuite,
    BadCompression,
    BadFragLen,
    BadSecretReneg,
    ExtraExtension,
    BadSNI,
    BadHelloDone,
    LimitExceeded,
    BadFinished,
    ResumeMismatch,
    InvalidAlgorithm,
    BadSignature,
    WrongKeyUsage,
    NoClientAuth,
    InputOutput,
    RecvFatal,
    SendFatal,
    Unknown,

    pub fn convert(status_code: c_int) EngineStatus {
        return switch (status_code) {
            c.BR_ERR_OK => .Ok,
            c.BR_ERR_BAD_PARAM => .BadParam,
            c.BR_ERR_BAD_STATE => .BadState,
            c.BR_ERR_UNSUPPORTED_VERSION => .UnsupportedVersion,
            c.BR_ERR_BAD_VERSION => .BadVersion,
            c.BR_ERR_TOO_LARGE => .TooLarge,
            c.BR_ERR_BAD_MAC => .BadMac,
            c.BR_ERR_NO_RANDOM => .NoRandom,
            c.BR_ERR_UNKNOWN_TYPE => .UnknownType,
            c.BR_ERR_UNEXPECTED => .Unexpected,
            c.BR_ERR_BAD_CCS => .BadCcs,
            c.BR_ERR_BAD_ALERT => .BadAlert,
            c.BR_ERR_BAD_HANDSHAKE => .BadHandshake,
            c.BR_ERR_OVERSIZED_ID => .OversizedId,
            c.BR_ERR_BAD_CIPHER_SUITE => .BadCipherSuite,
            c.BR_ERR_BAD_COMPRESSION => .BadCompression,
            c.BR_ERR_BAD_FRAGLEN => .BadFragLen,
            c.BR_ERR_BAD_SECRENEG => .BadSecretReneg,
            c.BR_ERR_EXTRA_EXTENSION => .ExtraExtension,
            c.BR_ERR_BAD_SNI => .BadSNI,
            c.BR_ERR_BAD_HELLO_DONE => .BadHelloDone,
            c.BR_ERR_LIMIT_EXCEEDED => .LimitExceeded,
            c.BR_ERR_BAD_FINISHED => .BadFinished,
            c.BR_ERR_RESUME_MISMATCH => .ResumeMismatch,
            c.BR_ERR_INVALID_ALGORITHM => .InvalidAlgorithm,
            c.BR_ERR_BAD_SIGNATURE => .BadSignature,
            c.BR_ERR_WRONG_KEY_USAGE => .WrongKeyUsage,
            c.BR_ERR_NO_CLIENT_AUTH => .NoClientAuth,
            c.BR_ERR_IO => .InputOutput,
            c.BR_ERR_RECV_FATAL_ALERT => .RecvFatal,
            c.BR_ERR_SEND_FATAL_ALERT => .SendFatal,
            else => .Unknown,
        };
    }
};

pub const BearSSL = struct {
    pub const PrivateKey = union(enum) {
        rsa: c.br_rsa_private_key,
        ec: c.br_ec_private_key,
    };

    allocator: std.mem.Allocator,
    x509: ?c.br_x509_certificate,
    pkey: ?PrivateKey,
    cert_signer_algo: ?c_int,
    trust_store: TrustAnchorStore,
    tls_config: ?*const @import("client.zig").TlsConfig = null,

    pub fn init(allocator: std.mem.Allocator) BearSSL {
        return .{
            .allocator = allocator,
            .x509 = null,
            .pkey = null,
            .cert_signer_algo = null,
            .trust_store = TrustAnchorStore.init(allocator), // Initialize store
        };
    }

    pub fn deinit(self: *BearSSL) void {
        if (self.x509) |x509| self.allocator.free(x509.data[0..x509.data_len]);

        if (self.pkey) |pkey| switch (pkey) {
            .rsa => |inner| {
                self.allocator.free(inner.p[0..inner.plen]);
                self.allocator.free(inner.q[0..inner.qlen]);
                self.allocator.free(inner.dp[0..inner.dplen]);
                self.allocator.free(inner.dq[0..inner.dqlen]);
                self.allocator.free(inner.iq[0..inner.iqlen]);
            },
            .ec => |inner| {
                self.allocator.free(inner.x[0..inner.xlen]);
            },
        };

        self.trust_store.deinit(); // Deinitialize store
    }

    /// This takes in the PEM section and the given bytes and decodes it into a byte format
    /// that can be ingested later by the BearSSL x509 certificate.
    fn decode_pem(allocator: std.mem.Allocator, section_title: ?[]const u8, bytes: []const u8) ![]const u8 {
        var p_ctx: c.br_pem_decoder_context = undefined;
        c.br_pem_decoder_init(&p_ctx);

        var decoded: std.ArrayList(u8) = try .initCapacity(allocator, bytes.len);
        defer decoded.deinit(allocator);

        c.br_pem_decoder_setdest(&p_ctx, struct {
            fn decoder(ctx: ?*anyopaque, src: ?*const anyopaque, size: usize) callconv(.c) void {
                var list: *std.ArrayList(u8) = @ptrCast(@alignCast(ctx.?));
                const data = @as([*]const u8, @ptrCast(src.?))[0..size];
                list.appendSliceAssumeCapacity(data);
            }
        }.decoder, &decoded);

        var found = false;
        var written: usize = 0;

        while (written < bytes.len) {
            written += c.br_pem_decoder_push(&p_ctx, bytes[written..].ptr, bytes.len - written);
            const event = c.br_pem_decoder_event(&p_ctx);
            switch (event) {
                0 => continue,
                c.BR_PEM_BEGIN_OBJ => {
                    const name = c.br_pem_decoder_name(&p_ctx);
                    if (section_title) |title| {
                        if (std.mem.eql(u8, std.mem.span(name), title)) {
                            found = true;
                            decoded.clearRetainingCapacity();
                        }
                    } else found = true;
                },
                c.BR_PEM_END_OBJ => if (found) return decoded.toOwnedSlice(allocator),
                c.BR_PEM_ERROR => return error.PemDecodeFailed,
                else => return error.PemDecodeUnknownEvent,
            }
        }

        return error.PemDecodeNotFinished;
    }

    fn decode_private_key(allocator: std.mem.Allocator, decoded_key: []const u8) !PrivateKey {
        var sk_ctx: c.br_skey_decoder_context = undefined;
        c.br_skey_decoder_init(&sk_ctx);
        c.br_skey_decoder_push(&sk_ctx, decoded_key.ptr, decoded_key.len);

        if (c.br_skey_decoder_last_error(&sk_ctx) != 0) return error.PrivateKeyDecodeFailed;
        const key_type = c.br_skey_decoder_key_type(&sk_ctx);

        return switch (key_type) {
            c.BR_KEYTYPE_RSA => key: {
                const key = c.br_skey_decoder_get_rsa(&sk_ctx)[0];

                const p = try allocator.dupe(u8, key.p[0..key.plen]);
                errdefer allocator.free(p);

                const q = try allocator.dupe(u8, key.q[0..key.qlen]);
                errdefer allocator.free(q);

                const dp = try allocator.dupe(u8, key.dp[0..key.dplen]);
                errdefer allocator.free(dp);

                const dq = try allocator.dupe(u8, key.dq[0..key.dqlen]);
                errdefer allocator.free(dq);

                const iq = try allocator.dupe(u8, key.iq[0..key.iqlen]);
                errdefer allocator.free(iq);

                break :key .{
                    .rsa = .{
                        .p = p.ptr,
                        .plen = key.plen,
                        .q = q.ptr,
                        .qlen = key.qlen,
                        .dp = dp.ptr,
                        .dplen = key.dplen,
                        .dq = dq.ptr,
                        .dqlen = key.dqlen,
                        .iq = iq.ptr,
                        .iqlen = key.iqlen,
                        .n_bitlen = key.n_bitlen,
                    },
                };
            },
            c.BR_KEYTYPE_EC => key: {
                const key = c.br_skey_decoder_get_ec(&sk_ctx)[0];
                const x = try allocator.dupe(u8, key.x[0..key.xlen]);
                errdefer allocator.free(x);

                break :key .{
                    .ec = .{
                        .x = x.ptr,
                        .xlen = key.xlen,
                        .curve = key.curve,
                    },
                };
            },
            else => return error.InvalidKeyType,
        };
    }

    fn get_cert_signer_algo(x509: *const c.br_x509_certificate) c_int {
        var x509_ctx: c.br_x509_decoder_context = undefined;

        c.br_x509_decoder_init(&x509_ctx, null, null);
        c.br_x509_decoder_push(&x509_ctx, x509.data.?, x509.data_len);
        if (c.br_x509_decoder_last_error(&x509_ctx) != 0) return 0;
        return c.br_x509_decoder_get_signer_key_type(&x509_ctx);
    }

    pub fn add_cert_chain(
        self: *BearSSL,
        cert_section_title: ?[]const u8,
        cert: []const u8,
        key_section_title: ?[]const u8,
        key: ?[]const u8,
    ) !void {
        const decoded_cert = try decode_pem(self.allocator, cert_section_title, cert);
        errdefer self.allocator.free(decoded_cert);
        self.x509 = .{ .data = @constCast(decoded_cert.ptr), .data_len = decoded_cert.len };

        // Only decode private key if provided
        if (key) |key_data| {
            const decoded_key = try decode_pem(self.allocator, key_section_title, key_data);
            defer self.allocator.free(decoded_key);
            self.pkey = try decode_private_key(self.allocator, decoded_key);
        }

        self.cert_signer_algo = get_cert_signer_algo(&self.x509.?);
    }

    /// Add a trusted certificate to be used for validating server certificates.
    ///
    /// This function loads a certificate from PEM data and adds it as a trust anchor.
    /// The trust anchors added with this function will be used for certificate validation
    /// during TLS handshakes.
    ///
    /// Parameters:
    ///   - cert_section_title: The PEM section title (not currently used, pass null or "CERTIFICATE")
    ///   - cert_pem: The PEM-encoded certificate data
    ///
    /// Memory Management:
    ///   - The certificate data is deep-copied; you can free cert_pem after this call
    ///   - All memory will be released when the BearSSL instance is deinitialized
    ///
    /// Example:
    /// ```
    /// const cert_bytes = @embedFile("trusted_cert.pem");
    /// try bearssl.add_trusted_cert("CERTIFICATE", cert_bytes);
    /// ```
    pub fn add_trusted_cert(
        self: *BearSSL, // Pointer receiver needed to modify store
        _: ?[]const u8, // cert_section_title is unused with this approach
        cert_pem: []const u8,
    ) !void {
        // Call the TrustAnchorStore's method to parse and add the anchor
        log.debug("Adding trusted cert PEM ({d} bytes) to TrustAnchorStore", .{cert_pem.len});
        try self.trust_store.addAnchorFromPem(cert_pem);
    }

    /// Set the TLS configuration options for the client.
    ///
    /// This method allows customizing the TLS behavior regarding protocols, ciphers,
    /// and crypto algorithms. The provided config will be used for all subsequent
    /// client connections created with this BearSSL instance.
    ///
    /// Note: The config object must remain valid for the lifetime of this BearSSL instance
    /// or until this method is called again with a different config or null.
    ///
    /// Parameters:
    ///   - config: Pointer to a TlsConfig structure that defines the TLS parameters,
    ///             or null to reset to default configuration
    pub fn setTlsConfig(self: *BearSSL, config: ?*const @import("client.zig").TlsConfig) void {
        self.tls_config = config;
    }

    pub fn to_secure_socket(self: *BearSSL, socket: Socket, mode: SecureSocket.Mode) !SecureSocket {
        switch (mode) {
            .client => return @import("client.zig").to_secure_socket_client(self, socket),
            .server => return @import("server.zig").to_secure_socket_server(self, socket),
        }
    }
};
