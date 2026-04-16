const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("s2n_tls", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addCSourceFiles(.{
        .root = upstream.path("utils/"),
        .files = utils_src,
    });

    mod.addCSourceFiles(.{
        .root = upstream.path("error/"),
        .files = error_src,
    });

    mod.addCSourceFiles(.{
        .root = upstream.path("stuffer/"),
        .files = stuffer_src,
    });

    mod.addCSourceFiles(.{
        .root = upstream.path("crypto/"),
        .files = crypto_src,
    });

    mod.addCSourceFiles(.{
        .root = upstream.path("tls/"),
        .flags = &.{ "-include", upstream.path("utils/s2n_prelude.h").getPath(b) },
        .files = tls_src,
    });

    mod.addCSourceFiles(.{
        .root = upstream.path("tls/extensions/"),
        .files = tls_extensions_src,
    });

    mod.addIncludePath(upstream.path("./"));
    mod.addIncludePath(upstream.path("api/"));

    const lib = b.addLibrary(.{
        .name = "s2n",
        .linkage = .static,
        .root_module = mod,
    });

    if (lib.rootModuleTarget().os.tag == .linux) {
        const openssl = b.dependency("openssl", .{
            .target = target,
            .optimize = optimize,
        });

        lib.linkLibrary(openssl.artifact("openssl"));
    } else {
        std.debug.print("On non-Linux platforms, you must provide libssl and libcrypto installed on system.", .{});
        lib.linkSystemLibrary("ssl");
        lib.linkSystemLibrary("crypto");
    }

    lib.installHeader(upstream.path("api/s2n.h"), "s2n.h");

    b.installArtifact(lib);
}

const utils_src = &.{
    "s2n_array.c",
    "s2n_atomic.c",
    "s2n_blob.c",
    "s2n_ensure.c",
    "s2n_fork_detection.c",
    "s2n_init.c",
    "s2n_io.c",
    "s2n_map.c",
    "s2n_mem.c",
    "s2n_random.c",
    "s2n_rfc5952.c",
    "s2n_safety.c",
    "s2n_socket.c",
    "s2n_timer.c",
};

const error_src = &.{
    "s2n_errno.c",
};

const stuffer_src = &.{
    "s2n_stuffer.c",
    "s2n_stuffer_base64.c",
    "s2n_stuffer_file.c",
    "s2n_stuffer_hex.c",
    "s2n_stuffer_network_order.c",
    "s2n_stuffer_pem.c",
    "s2n_stuffer_text.c",
};

const crypto_src = &.{
    "s2n_aead_cipher_aes_gcm.c",
    "s2n_aead_cipher_chacha20_poly1305.c",
    "s2n_cbc_cipher_3des.c",
    "s2n_cbc_cipher_aes.c",
    "s2n_certificate.c",
    "s2n_cipher.c",
    "s2n_composite_cipher_aes_sha.c",
    "s2n_crypto.c",
    "s2n_dhe.c",
    "s2n_drbg.c",
    "s2n_ecc_evp.c",
    "s2n_evp_kem.c",
    "s2n_fips.c",
    "s2n_fips_rules.c",
    "s2n_hash.c",
    "s2n_hkdf.c",
    "s2n_hmac.c",
    "s2n_libcrypto.c",
    "s2n_locking.c",
    "s2n_mldsa.c",
    "s2n_openssl_x509.c",
    "s2n_pkey.c",
    "s2n_pkey_evp.c",
    "s2n_pq.c",
    "s2n_prf_libcrypto.c",
    "s2n_rsa_pss.c",
    "s2n_sequence.c",
    "s2n_stream_cipher_null.c",
    "s2n_stream_cipher_rc4.c",
    "s2n_tls13_keys.c",
};

const tls_src = &.{
    "s2n_aead.c",
    "s2n_alerts.c",
    "s2n_async_pkey.c",
    "s2n_auth_selection.c",
    "s2n_cbc.c",
    "s2n_certificate_keys.c",
    "s2n_change_cipher_spec.c",
    "s2n_cipher_preferences.c",
    "s2n_cipher_suites.c",
    "s2n_client_cert.c",
    "s2n_client_cert_verify.c",
    "s2n_client_finished.c",
    "s2n_client_hello.c",
    "s2n_client_hello_request.c",
    "s2n_client_key_exchange.c",
    "s2n_config.c",
    "s2n_connection.c",
    "s2n_connection_serialize.c",
    "s2n_crl.c",
    "s2n_crypto.c",
    "s2n_early_data.c",
    "s2n_early_data_io.c",
    "s2n_ecc_preferences.c",
    "s2n_encrypted_extensions.c",
    "s2n_establish_session.c",
    "s2n_fingerprint.c",
    "s2n_fingerprint_ja3.c",
    "s2n_fingerprint_ja4.c",
    "s2n_handshake.c",
    "s2n_handshake_hashes.c",
    "s2n_handshake_io.c",
    "s2n_handshake_transcript.c",
    "s2n_handshake_type.c",
    "s2n_kem.c",
    "s2n_kem_preferences.c",
    "s2n_kex.c",
    "s2n_key_log.c",
    "s2n_key_update.c",
    "s2n_ktls.c",
    "s2n_ktls_io.c",
    "s2n_next_protocol.c",
    "s2n_ocsp_stapling.c",
    "s2n_post_handshake.c",
    "s2n_prf.c",
    "s2n_protocol_preferences.c",
    "s2n_psk.c",
    "s2n_quic_support.c",
    "s2n_record_read.c",
    "s2n_record_read_aead.c",
    "s2n_record_read_cbc.c",
    "s2n_record_read_composite.c",
    "s2n_record_read_stream.c",
    "s2n_record_write.c",
    "s2n_recv.c",
    "s2n_renegotiate.c",
    "s2n_resume.c",
    "s2n_security_policies.c",
    "s2n_security_rules.c",
    "s2n_send.c",
    "s2n_server_cert.c",
    "s2n_server_cert_request.c",
    "s2n_server_done.c",
    "s2n_server_extensions.c",
    "s2n_server_finished.c",
    "s2n_server_hello.c",
    "s2n_server_hello_retry.c",
    "s2n_server_key_exchange.c",
    "s2n_server_new_session_ticket.c",
    "s2n_shutdown.c",
    "s2n_signature_algorithms.c",
    "s2n_signature_scheme.c",
    "s2n_tls.c",
    "s2n_tls13.c",
    "s2n_tls13_certificate_verify.c",
    "s2n_tls13_handshake.c",
    "s2n_tls13_key_schedule.c",
    "s2n_tls13_secrets.c",
    "s2n_x509_validator.c",
};

const tls_extensions_src = &.{
    "s2n_cert_authorities.c",
    "s2n_cert_status.c",
    "s2n_cert_status_response.c",
    "s2n_client_alpn.c",
    "s2n_client_cert_status_request.c",
    "s2n_client_cookie.c",
    "s2n_client_early_data_indication.c",
    "s2n_client_ems.c",
    "s2n_client_key_share.c",
    "s2n_client_max_frag_len.c",
    "s2n_client_pq_kem.c",
    "s2n_client_psk.c",
    "s2n_client_renegotiation_info.c",
    "s2n_client_sct_list.c",
    "s2n_client_server_name.c",
    "s2n_client_session_ticket.c",
    "s2n_client_signature_algorithms.c",
    "s2n_client_supported_groups.c",
    "s2n_client_supported_versions.c",
    "s2n_ec_point_format.c",
    "s2n_extension_list.c",
    "s2n_extension_type.c",
    "s2n_extension_type_lists.c",
    "s2n_key_share.c",
    "s2n_npn.c",
    "s2n_nst_early_data_indication.c",
    "s2n_psk_key_exchange_modes.c",
    "s2n_quic_transport_params.c",
    "s2n_server_alpn.c",
    "s2n_server_cert_status_request.c",
    "s2n_server_cookie.c",
    "s2n_server_early_data_indication.c",
    "s2n_server_ems.c",
    "s2n_server_key_share.c",
    "s2n_server_max_fragment_length.c",
    "s2n_server_psk.c",
    "s2n_server_renegotiation_info.c",
    "s2n_server_sct_list.c",
    "s2n_server_server_name.c",
    "s2n_server_session_ticket.c",
    "s2n_server_signature_algorithms.c",
    "s2n_server_supported_versions.c",
    "s2n_supported_versions.c",
};
