pub fn to_secure_socket_server(
    bearssl: *BearSSL,
    gpa: mem.Allocator,
    socket: *const Socket,
) !Secsock {
    const io_buf = try gpa.alloc(u8, h.BR_SSL_BUFSIZE_BIDI);
    errdefer gpa.free(io_buf);

    const cb_ctx = try gpa.create(Callback);
    errdefer gpa.destroy(cb_ctx);

    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const impl = try gpa.create(Impl);
    errdefer gpa.destroy(impl);

    impl.* = .{
        .bearssl = bearssl,
        .server = undefined,
        .io_buf = io_buf,
        .cb = cb_ctx,
        .sslio = undefined,
    };

    switch (bearssl.pkey) {
        .rsa => |*rsa| h.br_ssl_server_init_full_rsa(
            &impl.server,
            @ptrCast(&bearssl.x509),
            1,
            @ptrCast(rsa),
        ),
        .ec => |*ec| h.br_ssl_server_init_full_ec(
            &impl.server,
            @ptrCast(&bearssl.x509),
            1,
            @intCast(bearssl.cert_signer_algo),
            @ptrCast(ec),
        ),
    }

    h.br_ssl_engine_set_buffer(
        &impl.server.eng,
        io_buf.ptr,
        io_buf.len,
        1,
    );
    const reset_status = h.br_ssl_server_reset(&impl.server);
    if (reset_status <= 0) return error.ServerResetFailed;

    h.br_sslio_init(
        &impl.sslio,
        &impl.server.eng,
        Callback.recv,
        cb_ctx,
        Callback.send,
        cb_ctx,
    );

    return .{
        .impl = impl,
        .vtable = &vtable,
    };
}

const Impl = struct {
    bearssl: *BearSSL,
    io_buf: []const u8,
    sslio: h.br_sslio_context,
    cb: *Callback,
    server: h.br_ssl_server_context,

    fn info(i: *const anyopaque) Secsock.Info {
        const impl: *const Impl = @ptrCast(@alignCast(i));

        var buf: [21:0]u8 = @splat(0x0);
        _ = mem.print(&buf, "{f}", .{
            impl.cb.socket.addr,
        }) catch unreachable;

        return .{
            .name = .bearssl,
            .address = buf,
        };
    }

    fn deinit(i: *const anyopaque, gpa: mem.Allocator) void {
        const impl: *const Impl = @ptrCast(@alignCast(i));

        impl.cb.socket.close_blocking();
        gpa.destroy(impl.cb.socket);

        gpa.destroy(impl.cb);
        gpa.free(impl.io_buf);
        gpa.destroy(impl);
    }

    fn accept(i: *const anyopaque, r: *Runtime) !Secsock {
        const impl: *const Impl = @ptrCast(@alignCast(i));
        const cb = impl.cb;

        const client = r.gpa.create(Socket) catch @panic("OOM");
        client.* = try cb.socket.accept(r);
        errdefer r.gpa.destroy(client);
        errdefer client.close_blocking();

        const new_bearssl = try impl.bearssl.tlsWithSock(
            r.gpa,
            client,
            .server,
        );
        // if we fail, we want to clean this connection up.
        errdefer new_bearssl.deinit(r.gpa);

        const new_impl: *const Impl = @ptrCast(@alignCast(new_bearssl.impl));
        new_impl.cb.runtime = r;

        return new_bearssl;
    }

    fn connect(_: *const anyopaque, _: *Runtime) !void {
        return error.TLSServerCantConnect;
    }

    fn recv(i: *anyopaque, r: *Runtime, b: []u8) !usize {
        const impl: *Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;

        const result = h.br_sslio_read(&impl.sslio, b.ptr, b.len);

        if (result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&impl.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => |err| {
                    log.err("sslio recv failed: {t}", .{
                        err,
                    });
                    return error.TlsRecvFailed;
                },
            }
        }

        return @intCast(result);
    }

    fn send(i: *anyopaque, r: *Runtime, b: []const u8) !usize {
        const impl: *Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;

        const write_result = h.br_sslio_write(
            &impl.sslio,
            b.ptr,
            b.len,
        );
        if (write_result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&impl.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => |err| {
                    log.err("sslio send failed: {t}", .{err});
                    return error.TlsSendFailed;
                },
            }
        }

        // Force flush. We should be buffering a layer above this.
        const flush_result = h.br_sslio_flush(&impl.sslio);
        if (flush_result < 0) {
            const last_error: EngineStatus = .convert(
                h.br_ssl_engine_last_error(&impl.server.eng),
            );
            switch (last_error) {
                .InputOutput => return error.Closed,
                else => |err| {
                    log.err("sslio flush failed: {t}", .{
                        err,
                    });
                    return error.TlsSendFailed;
                },
            }
        }

        return @intCast(write_result);
    }
};

const Callback = struct {
    socket: *const Socket,
    runtime: ?*Runtime,

    fn recv(c: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const count = cb.socket.recv(
            cb.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio recv cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }

    fn send(c: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const count = cb.socket.send(
            cb.runtime.?,
            buf[0..len],
        ) catch |e| {
            log.err("sslio send cb failed: {t}", .{e});
            return -1;
        };
        return @intCast(count);
    }
};

const vtable: Secsock.VTable = .{
    .info = Impl.info,
    .deinit = Impl.deinit,
    .accept = Impl.accept,
    .connect = Impl.connect,
    .recv = Impl.recv,
    .send = Impl.send,
};

const log = std.log.scoped(.@"bearssl/server");

const std = @import("std");
const mem = std.mem;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("../Secsock.zig");
const BearSSL = Secsock.BearSSL;
const h = BearSSL.h;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = BearSSL.EngineStatus;
