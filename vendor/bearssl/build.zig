const std = @import("std");

const MacroPair = struct { mode: ?bool, name: []const u8 };

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("bearssl", .{
        .target = target,
        .optimize = optimize,
    });

    var macro_list: std.ArrayList(MacroPair) = .empty;
    defer macro_list.deinit(b.allocator);
    {
        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_64",
                "When enabled, 64-bit integers are assumed to be efficient",
            ),
            .name = "BR_64",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_LOWMUL",
                "When enabled, low multiplication of 32 bits are assumed to be efficient",
            ),
            .name = "BR_LOWMUL",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_SLOW_MUL",
                "When enabled, multiplications are assumed to be substationally slow",
            ),
            .name = "BR_SLOW_MUL",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_SLOW_MUL15",
                "When enabled, short multiplications are assumed to be substationally slow",
            ),
            .name = "BR_SLOW_MUL15",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_CT_MUL31",
                "When enabled, multiplications of 31 bit values use an alternate impl",
            ),
            .name = "BR_CT_MUL31",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_CT_MUL15",
                "When enabled, multiplications of 15 bit values use an alternate impl",
            ),
            .name = "BR_CT_MUL15",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_NO_ARITH_SHIFT",
                "When enabled, arithmetic right shifts are slower but avoids implementation-defined behavior",
            ),
            .name = "BR_NO_ARITH_SHIFT",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_RDRAND",
                "When enabled, the SSL engine will use RDRAND opcode to obtain quality randomness",
            ),
            .name = "BR_RDRAND",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_USE_RANDOM",
                "When enabled, the SSL engine will use /dev/urandom to obtain quality randomness",
            ),
            .name = "BR_USE_RANDOM",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_USE_WIN32_RAND",
                "When enabled, the SSL engine will use Win32 (CryptoAPI) to obtain quality randomness",
            ),
            .name = "BR_USE_WIN32_RAND",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_USE_UNIX_TIME",
                "When enabled, the X.509 validation engine uses time() and assumes Unix Epoch",
            ),
            .name = "BR_USE_UNIX_TIME",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_USE_WIN32_TIME",
                "When enabled, the X.509 validation engine uses GetSystemTimeAsFileTime()",
            ),
            .name = "BR_USE_WIN32_TIME",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_ARMEL_CORTEXM_GCC",
                "When enabled, some operations are replaced with inline assembly. Used only when target arch is ARM (thumb), endianness is little, and compiler is GCC or GCC compatible (for inline asm)",
            ),
            .name = "BR_ARMEL_CORTEXM_GCC",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_AES_X86NI",
                "When enabled, the AES implementation using the x86 \"NI\" instructions will be compiled",
            ),
            .name = "BR_AES_X86NI",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_SSE2",
                "When enabled, SSE2 instrinsics will be used for some algorithm implementations",
            ),
            .name = "BR_SSE2",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_POWER8",
                "When enabled, the AES implementation using the POWER ISA 2.07 opcodes is compiled",
            ),
            .name = "BR_POWER8",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_INT128",
                "When enabled, 'unsigned __int64' and 'unsigned __128' types will be used for 64x64->128 mul",
            ),
            .name = "BR_INT128",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_UMUL128",
                "When enabled, '_umul128()' and '_addcarry_u64()' instrincts will be used for 64x64->128 mul",
            ),
            .name = "BR_UMUL128",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_LE_UNALIGNED",
                "When enabled, the current architecture is assumed to use little-endian with little penalty to unaligned access",
            ),
            .name = "BR_LE_UNALIGNED",
        });

        try macro_list.append(b.allocator, .{
            .mode = b.option(
                bool,
                "BR_BE_UNALIGNED",
                "When enabled, the current architecture is assumed to use big-endian with little penalty to unaligned access",
            ),
            .name = "BR_BE_UNALIGNED",
        });
    }

    const mod = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    for (macro_list.items) |item| {
        if (item.mode) |mode| if (mode) {
            mod.addCMacro(
                item.name,
                try std.fmt.allocPrint(b.allocator, "{d}", .{@intFromBool(mode)}),
            );
        };
    }
    mod.addCSourceFile(.{ .file = upstream.path("src/settings.c") });

    mod.addIncludePath(upstream.path("src/"));
    const flags = &.{
        "-W",
        "-Wall",
        "-fPIC",
    };

    mod.addCSourceFiles(.{ .root = upstream.path("src/aead"), .files = aead_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/codec"), .files = codec_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/ec"), .files = ec_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/hash"), .files = hash_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/int"), .files = int_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/kdf"), .files = kdf_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/mac"), .files = mac_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/rand"), .files = rand_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/rsa"), .files = rsa_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/ssl"), .files = ssl_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/symcipher"), .files = symcipher_src, .flags = flags });
    mod.addCSourceFiles(.{ .root = upstream.path("src/x509"), .files = x509_src, .flags = flags });
    mod.addIncludePath(upstream.path("inc/"));

    const bearssl = b.addLibrary(.{
        .name = "bearssl",
        .linkage = .static,
        .root_module = mod,
    });

    bearssl.installHeadersDirectory(upstream.path("inc/"), "", .{});

    b.installArtifact(bearssl);
}

const aead_src = &.{
    "ccm.c",
    "eax.c",
    "gcm.c",
};

const codec_src = &.{
    "ccopy.c",
    "dec16be.c",
    "dec32le.c",
    "dec64le.c",
    "enc16le.c",
    "enc32le.c",
    "enc64le.c",
    //"pemdec.t0",
    "dec16be.c",
    "dec32be.c",
    "dec64be.c",
    "enc16be.c",
    "enc32be.c",
    "enc64be.c",
    "pemdec.c",
    "pemenc.c",
};

const ec_src = &.{
    "ec_all_m15.c",
    "ec_all_m31.c",
    "ec_c25519_i15.c",
    "ec_c25519_i31.c",
    "ec_c25519_m15.c",
    "ec_c25519_m31.c",
    "ec_curve25519.c",
    "ec_default.c",
    "ecdsa_atr.c",
    "ecdsa_default_sign_asn1.c",
    "ecdsa_default_sign_raw.c",
    "ecdsa_default_vrfy_asn1.c",
    "ecdsa_default_vrfy_raw.c",
    "ecdsa_i15_bits.c",
    "ecdsa_i15_sign_asn1.c",
    "ecdsa_i15_sign_raw.c",
    "ecdsa_i15_vrfy_asn1.c",
    "ecdsa_i15_vrfy_raw.c",
    "ecdsa_i31_bits.c",
    "ecdsa_i31_sign_asn1.c",
    "ecdsa_i31_sign_raw.c",
    "ecdsa_i31_vrfy_asn1.c",
    "ecdsa_i31_vrfy_raw.c",
    "ecdsa_rta.c",
    "ec_keygen.c",
    "ec_p256_m15.c",
    "ec_p256_m31.c",
    "ec_prime_i15.c",
    "ec_prime_i31.c",
    "ec_pubkey.c",
    "ec_secp256r1.c",
    "ec_secp384r1.c",
    "ec_secp521r1.c",
};

const hash_src = &.{
    "dig_oid.c",
    "dig_size.c",
    "ghash_ctmul32.c",
    "ghash_ctmul64.c",
    "ghash_ctmul.c",
    "ghash_pclmul.c",
    "ghash_pwr8.c",
    "md5.c",
    "md5sha1.c",
    "mgf1.c",
    "multihash.c",
    "sha1.c",
    "sha2big.c",
    "sha2small.c",
};

const int_src = &.{
    "i15_add.c",
    "i15_bitlen.c",
    "i15_decmod.c",
    "i15_decode.c",
    "i15_decred.c",
    "i15_encode.c",
    "i15_fmont.c",
    "i15_iszero.c",
    "i15_moddiv.c",
    "i15_modpow2.c",
    "i15_modpow.c",
    "i15_montmul.c",
    "i15_mulacc.c",
    "i15_muladd.c",
    "i15_ninv15.c",
    "i15_reduce.c",
    "i15_rshift.c",
    "i15_sub.c",
    "i15_tmont.c",
    "i31_add.c",
    "i31_bitlen.c",
    "i31_decmod.c",
    "i31_decode.c",
    "i31_decred.c",
    "i31_encode.c",
    "i31_fmont.c",
    "i31_iszero.c",
    "i31_moddiv.c",
    "i31_modpow2.c",
    "i31_modpow.c",
    "i31_montmul.c",
    "i31_mulacc.c",
    "i31_muladd.c",
    "i31_ninv31.c",
    "i31_reduce.c",
    "i31_rshift.c",
    "i31_sub.c",
    "i31_tmont.c",
    "i32_add.c",
    "i32_bitlen.c",
    "i32_decmod.c",
    "i32_decode.c",
    "i32_decred.c",
    "i32_div32.c",
    "i32_encode.c",
    "i32_fmont.c",
    "i32_iszero.c",
    "i32_modpow.c",
    "i32_montmul.c",
    "i32_mulacc.c",
    "i32_muladd.c",
    "i32_ninv32.c",
    "i32_reduce.c",
    "i32_sub.c",
    "i32_tmont.c",
    "i62_modpow2.c",
};

const kdf_src = &.{
    "hkdf.c",
};

const mac_src = &.{
    "hmac.c",
    "hmac_ct.c",
};

const rand_src = &.{
    "aesctr_drbg.c",
    "hmac_drbg.c",
    "sysrng.c",
};

const rsa_src = &.{
    "rsa_default_keygen.c",
    "rsa_default_modulus.c",
    "rsa_default_oaep_decrypt.c",
    "rsa_default_oaep_encrypt.c",
    "rsa_default_pkcs1_sign.c",
    "rsa_default_pkcs1_vrfy.c",
    "rsa_default_priv.c",
    "rsa_default_privexp.c",
    "rsa_default_pub.c",
    "rsa_default_pubexp.c",
    "rsa_i15_keygen.c",
    "rsa_i15_modulus.c",
    "rsa_i15_oaep_decrypt.c",
    "rsa_i15_oaep_encrypt.c",
    "rsa_i15_pkcs1_sign.c",
    "rsa_i15_pkcs1_vrfy.c",
    "rsa_i15_priv.c",
    "rsa_i15_privexp.c",
    "rsa_i15_pub.c",
    "rsa_i15_pubexp.c",
    "rsa_i31_keygen.c",
    "rsa_i31_keygen_inner.c",
    "rsa_i31_modulus.c",
    "rsa_i31_oaep_decrypt.c",
    "rsa_i31_oaep_encrypt.c",
    "rsa_i31_pkcs1_sign.c",
    "rsa_i31_pkcs1_vrfy.c",
    "rsa_i31_priv.c",
    "rsa_i31_privexp.c",
    "rsa_i31_pub.c",
    "rsa_i31_pubexp.c",
    "rsa_i32_oaep_decrypt.c",
    "rsa_i32_oaep_encrypt.c",
    "rsa_i32_pkcs1_sign.c",
    "rsa_i32_pkcs1_vrfy.c",
    "rsa_i32_priv.c",
    "rsa_i32_pub.c",
    "rsa_i62_keygen.c",
    "rsa_i62_oaep_decrypt.c",
    "rsa_i62_oaep_encrypt.c",
    "rsa_i62_pkcs1_sign.c",
    "rsa_i62_pkcs1_vrfy.c",
    "rsa_i62_priv.c",
    "rsa_i62_pub.c",
    "rsa_oaep_pad.c",
    "rsa_oaep_unpad.c",
    "rsa_pkcs1_sig_pad.c",
    "rsa_pkcs1_sig_unpad.c",
    "rsa_ssl_decrypt.c",
};

const ssl_src = &.{
    "prf.c",
    "prf_md5sha1.c",
    "prf_sha256.c",
    "prf_sha384.c",
    "ssl_ccert_single_ec.c",
    "ssl_ccert_single_rsa.c",
    "ssl_client.c",
    "ssl_client_default_rsapub.c",
    "ssl_client_full.c",
    "ssl_engine.c",
    "ssl_engine_default_aescbc.c",
    "ssl_engine_default_aesccm.c",
    "ssl_engine_default_aesgcm.c",
    "ssl_engine_default_chapol.c",
    "ssl_engine_default_descbc.c",
    "ssl_engine_default_ec.c",
    "ssl_engine_default_ecdsa.c",
    "ssl_engine_default_rsavrfy.c",
    "ssl_hashes.c",
    "ssl_hs_client.c",
    //"ssl_hs_client.t0",
    //"ssl_hs_common.t0",
    "ssl_hs_server.c",
    //"ssl_hs_server.t0",
    "ssl_io.c",
    "ssl_keyexport.c",
    "ssl_lru.c",
    "ssl_rec_cbc.c",
    "ssl_rec_ccm.c",
    "ssl_rec_chapol.c",
    "ssl_rec_gcm.c",
    "ssl_scert_single_ec.c",
    "ssl_scert_single_rsa.c",
    "ssl_server.c",
    "ssl_server_full_ec.c",
    "ssl_server_full_rsa.c",
    "ssl_server_mine2c.c",
    "ssl_server_mine2g.c",
    "ssl_server_minf2c.c",
    "ssl_server_minf2g.c",
    "ssl_server_minr2g.c",
    "ssl_server_minu2g.c",
    "ssl_server_minv2g.c",
};

const symcipher_src = &.{
    "aes_big_cbcdec.c",
    "aes_big_cbcenc.c",
    "aes_big_ctr.c",
    "aes_big_ctrcbc.c",
    "aes_big_dec.c",
    "aes_big_enc.c",
    "aes_common.c",
    "aes_ct64.c",
    "aes_ct64_cbcdec.c",
    "aes_ct64_cbcenc.c",
    "aes_ct64_ctr.c",
    "aes_ct64_ctrcbc.c",
    "aes_ct64_dec.c",
    "aes_ct64_enc.c",
    "aes_ct.c",
    "aes_ct_cbcdec.c",
    "aes_ct_cbcenc.c",
    "aes_ct_ctr.c",
    "aes_ct_ctrcbc.c",
    "aes_ct_dec.c",
    "aes_ct_enc.c",
    "aes_pwr8.c",
    "aes_pwr8_cbcdec.c",
    "aes_pwr8_cbcenc.c",
    "aes_pwr8_ctr.c",
    "aes_pwr8_ctrcbc.c",
    "aes_small_cbcdec.c",
    "aes_small_cbcenc.c",
    "aes_small_ctr.c",
    "aes_small_ctrcbc.c",
    "aes_small_dec.c",
    "aes_small_enc.c",
    "aes_x86ni.c",
    "aes_x86ni_cbcdec.c",
    "aes_x86ni_cbcenc.c",
    "aes_x86ni_ctr.c",
    "aes_x86ni_ctrcbc.c",
    "chacha20_ct.c",
    "chacha20_sse2.c",
    "des_ct.c",
    "des_ct_cbcdec.c",
    "des_ct_cbcenc.c",
    "des_support.c",
    "des_tab.c",
    "des_tab_cbcdec.c",
    "des_tab_cbcenc.c",
    "poly1305_ctmul32.c",
    "poly1305_ctmul.c",
    "poly1305_ctmulq.c",
    "poly1305_i15.c",
};

const x509_src = &.{
    "asn1enc.c",
    //"asn1.t0",
    "encode_ec_pk8der.c",
    "encode_ec_rawder.c",
    "encode_rsa_pk8der.c",
    "encode_rsa_rawder.c",
    "skey_decoder.c",
    //"skey_decoder.t0",
    "x509_decoder.c",
    //"x509_decoder.t0",
    "x509_knownkey.c",
    "x509_minimal.c",
    "x509_minimal_full.c",
    //"x509_minimal.t0",
};
