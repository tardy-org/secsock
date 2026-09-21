pub const BearSSL = @This();

x509: h.br_x509_certificate,
pkey: PrivateKey,
cert_signer_algo: c_int,

pub fn init(
    gpa: mem.Allocator,
    cert_section_title: ?[]const u8,
    cert: []const u8,
    key_section_title: ?[]const u8,
    key: []const u8,
) !BearSSL {
    var bearssl: BearSSL = undefined;

    try bearssl.add_cert_chain(
        gpa,
        cert_section_title,
        cert,
        key_section_title,
        key,
    );

    return bearssl;
}

pub fn deinit(bearssl: BearSSL, gpa: mem.Allocator) void {
    gpa.free(bearssl.x509.data[0..bearssl.x509.data_len]);

    switch (bearssl.pkey) {
        .rsa => |rsa| {
            gpa.free(rsa.p[0..rsa.plen]);
            gpa.free(rsa.q[0..rsa.qlen]);
            gpa.free(rsa.dp[0..rsa.dplen]);
            gpa.free(rsa.dq[0..rsa.dqlen]);
            gpa.free(rsa.iq[0..rsa.iqlen]);
        },
        .ec => |ec| {
            gpa.free(ec.x[0..ec.xlen]);
        },
    }
}

fn add_cert_chain(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    cert_section_title: ?[]const u8,
    cert: []const u8,
    key_section_title: ?[]const u8,
    key: []const u8,
) !void {
    const decoded_cert = try decode_pem(
        gpa,
        cert_section_title,
        cert,
    );
    errdefer gpa.free(decoded_cert);

    bearssl.x509 = .{
        .data = @constCast(decoded_cert.ptr),
        .data_len = decoded_cert.len,
    };

    const decoded_key = try decode_pem(
        gpa,
        key_section_title,
        key,
    );
    defer gpa.free(decoded_key);

    bearssl.pkey = try decode_private_key(
        gpa,
        decoded_key,
    );

    bearssl.cert_signer_algo = get_cert_signer_algo(&bearssl.x509);
}

/// This takes in the PEM section and the given bytes and decodes it into a byte format
/// that can be ingested later by the BearSSL x509 certificate.
fn decode_pem(
    gpa: mem.Allocator,
    section_title: ?[]const u8,
    bytes: []const u8,
) ![]const u8 {
    var p_ctx: h.br_pem_decoder_context = undefined;
    h.br_pem_decoder_init(&p_ctx);

    var decoded: std.ArrayList(u8) = try .initCapacity(
        gpa,
        bytes.len,
    );
    defer decoded.deinit(gpa);

    h.br_pem_decoder_setdest(&p_ctx, struct {
        fn decoder(
            ctx: ?*anyopaque,
            src: ?*const anyopaque,
            size: usize,
        ) callconv(.c) void {
            var list: *std.ArrayList(u8) = @ptrCast(@alignCast(ctx.?));
            const data = @as([*]const u8, @ptrCast(src.?))[0..size];
            list.appendSliceAssumeCapacity(data);
        }
    }.decoder, &decoded);

    var found = false;
    var written: usize = 0;

    while (written < bytes.len) {
        written += h.br_pem_decoder_push(
            &p_ctx,
            bytes[written..].ptr,
            bytes.len - written,
        );
        const event = h.br_pem_decoder_event(&p_ctx);
        switch (event) {
            0 => continue,
            h.BR_PEM_BEGIN_OBJ => {
                const name = h.br_pem_decoder_name(&p_ctx);
                if (section_title) |title| {
                    if (mem.eql(u8, mem.span(name), title)) {
                        found = true;
                        decoded.clearRetainingCapacity();
                    }
                } else found = true;
            },
            h.BR_PEM_END_OBJ => if (found)
                return decoded.toOwnedSlice(gpa),
            h.BR_PEM_ERROR => return error.PemDecodeFailed,
            else => return error.PemDecodeUnknownEvent,
        }
    }

    return error.PemDecodeNotFinished;
}

fn decode_private_key(gpa: mem.Allocator, decoded_key: []const u8) !PrivateKey {
    var sk_ctx: h.br_skey_decoder_context = undefined;
    h.br_skey_decoder_init(&sk_ctx);
    h.br_skey_decoder_push(
        &sk_ctx,
        decoded_key.ptr,
        decoded_key.len,
    );

    if (h.br_skey_decoder_last_error(&sk_ctx) != 0)
        return error.PrivateKeyDecodeFailed;

    const key_type = h.br_skey_decoder_key_type(&sk_ctx);

    return switch (key_type) {
        h.BR_KEYTYPE_RSA => key: {
            const key = h.br_skey_decoder_get_rsa(&sk_ctx)[0];

            const p = try gpa.dupe(u8, key.p[0..key.plen]);
            errdefer gpa.free(p);

            const q = try gpa.dupe(u8, key.q[0..key.qlen]);
            errdefer gpa.free(q);

            const dp = try gpa.dupe(u8, key.dp[0..key.dplen]);
            errdefer gpa.free(dp);

            const dq = try gpa.dupe(u8, key.dq[0..key.dqlen]);
            errdefer gpa.free(dq);

            const iq = try gpa.dupe(u8, key.iq[0..key.iqlen]);
            errdefer gpa.free(iq);

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
        h.BR_KEYTYPE_EC => key: {
            const key = h.br_skey_decoder_get_ec(&sk_ctx)[0];
            const x = try gpa.dupe(u8, key.x[0..key.xlen]);
            errdefer gpa.free(x);

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

fn get_cert_signer_algo(x509: *const h.br_x509_certificate) c_int {
    var x509_ctx: h.br_x509_decoder_context = undefined;

    h.br_x509_decoder_init(
        &x509_ctx,
        null,
        null,
    );
    h.br_x509_decoder_push(
        &x509_ctx,
        x509.data.?,
        x509.data_len,
    );

    if (h.br_x509_decoder_last_error(&x509_ctx) != 0) return 0;

    return h.br_x509_decoder_get_signer_key_type(&x509_ctx);
}

/// internal API
pub fn tlsWithSock(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    socket: *const Socket,
    mode: Socket.Mode,
) (OoM || error{ServerResetFailed})!Secsock {
    switch (mode) {
        .client => @panic("Client bearssl not supported yet!"),
        .server => {
            return server.to_secure_socket_server(
                bearssl,
                gpa,
                socket,
            );
        },
    }
}

pub fn tls(bearssl: *BearSSL, gpa: mem.Allocator, config: Socket.Config) !Secsock {
    const socket = gpa.create(Socket) catch @panic("OOM");
    socket.* = try .init(.{ .tcp = config });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    const secsock = try bearssl.tlsWithSock(
        gpa,
        socket,
        config.mode,
    );
    errdefer secsock.deinit(gpa);

    return secsock;
}

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
            h.BR_ERR_OK => .Ok,
            h.BR_ERR_BAD_PARAM => .BadParam,
            h.BR_ERR_BAD_STATE => .BadState,
            h.BR_ERR_UNSUPPORTED_VERSION => .UnsupportedVersion,
            h.BR_ERR_BAD_VERSION => .BadVersion,
            h.BR_ERR_TOO_LARGE => .TooLarge,
            h.BR_ERR_BAD_MAC => .BadMac,
            h.BR_ERR_NO_RANDOM => .NoRandom,
            h.BR_ERR_UNKNOWN_TYPE => .UnknownType,
            h.BR_ERR_UNEXPECTED => .Unexpected,
            h.BR_ERR_BAD_CCS => .BadCcs,
            h.BR_ERR_BAD_ALERT => .BadAlert,
            h.BR_ERR_BAD_HANDSHAKE => .BadHandshake,
            h.BR_ERR_OVERSIZED_ID => .OversizedId,
            h.BR_ERR_BAD_CIPHER_SUITE => .BadCipherSuite,
            h.BR_ERR_BAD_COMPRESSION => .BadCompression,
            h.BR_ERR_BAD_FRAGLEN => .BadFragLen,
            h.BR_ERR_BAD_SECRENEG => .BadSecretReneg,
            h.BR_ERR_EXTRA_EXTENSION => .ExtraExtension,
            h.BR_ERR_BAD_SNI => .BadSNI,
            h.BR_ERR_BAD_HELLO_DONE => .BadHelloDone,
            h.BR_ERR_LIMIT_EXCEEDED => .LimitExceeded,
            h.BR_ERR_BAD_FINISHED => .BadFinished,
            h.BR_ERR_RESUME_MISMATCH => .ResumeMismatch,
            h.BR_ERR_INVALID_ALGORITHM => .InvalidAlgorithm,
            h.BR_ERR_BAD_SIGNATURE => .BadSignature,
            h.BR_ERR_WRONG_KEY_USAGE => .WrongKeyUsage,
            h.BR_ERR_NO_CLIENT_AUTH => .NoClientAuth,
            h.BR_ERR_IO => .InputOutput,
            h.BR_ERR_RECV_FATAL_ALERT => .RecvFatal,
            h.BR_ERR_SEND_FATAL_ALERT => .SendFatal,
            else => .Unknown,
        };
    }
};

pub const PrivateKey = union(enum) {
    rsa: h.br_rsa_private_key,
    ec: h.br_ec_private_key,
};

const std = @import("std");
const mem = std.mem;
const OoM = mem.Allocator.Error;

pub const h = @import("bearssl.h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;

const server = @import("bearssl/server.zig");
const Secsock = @import("Secsock.zig");
