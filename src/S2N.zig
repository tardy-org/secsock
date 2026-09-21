//! s2n-tls is an implementation of the TLS/SSL protocols by Amazon (AWS).
//! https://github.com/aws/s2n-tls
pub const S2N = @This();

config: *h.s2n_config,
cert: *h.s2n_cert_chain_and_key,

pub fn init(cert: []const u8, key: []const u8) !S2N {
    const init_rc = h.s2n_init();
    try handle_error("s2n_init", init_rc);

    const config = h.s2n_config_new();

    var s2n: S2N = .{ .config = config.?, .cert = undefined };
    try s2n.addCertChain(cert, key);

    return s2n;
}

pub fn deinit(s2n: S2N) void {
    _ = h.s2n_config_free(s2n.config);
    _ = h.s2n_cert_chain_and_key_free(s2n.cert);
    _ = h.s2n_cleanup();
}

fn addCertChain(s2n: *S2N, cert: []const u8, key: []const u8) !void {
    const chain = h.s2n_cert_chain_and_key_new();
    s2n.cert = chain.?;
    const load_pem_bytes_rc = h.s2n_cert_chain_and_key_load_pem_bytes(
        chain,
        @constCast(cert.ptr),
        @intCast(cert.len),
        @constCast(key.ptr),
        @intCast(key.len),
    );
    try handle_error("adding pem bytes to cert chain", load_pem_bytes_rc);
    const add_cert_chain_rc = h.s2n_config_add_cert_chain_and_key_to_store(
        s2n.config,
        chain,
    );
    try handle_error("adding cert chain to config", add_cert_chain_rc);
}

fn tlsWithSock(
    s2n: *S2N,
    gpa: mem.Allocator,
    socket: *const Socket,
    mode: Socket.Mode,
) !Secsock {
    const cb_ctx = try gpa.create(Callback);
    errdefer gpa.destroy(cb_ctx);

    cb_ctx.* = .{ .socket = socket, .runtime = null };

    const conn = try s2n.newConnection(mode);

    const set_recv_ctx_rc = h.s2n_connection_set_recv_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting recv cb ctx", set_recv_ctx_rc);

    const set_send_ctx_rc = h.s2n_connection_set_send_ctx(conn, @ptrCast(cb_ctx));
    try handle_error("setting send cb ctx", set_send_ctx_rc);

    const set_recv_cb_rc = h.s2n_connection_set_recv_cb(conn, Callback.recv);
    try handle_error("setting recv cb", set_recv_cb_rc);

    const set_send_cb_rc = h.s2n_connection_set_send_cb(conn, Callback.send);
    try handle_error("setting send cb", set_send_cb_rc);

    const impl = try gpa.create(Impl);
    errdefer gpa.destroy(impl);

    impl.* = .{
        .s2n = s2n,
        .conn = conn,
        .cb = cb_ctx,
    };

    return .{
        .impl = impl,
        .vtable = &vtable,
    };
}

pub fn tls(
    s2n: *S2N,
    gpa: mem.Allocator,
    config: Socket.Config,
) !Secsock {
    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .tcp = config });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    const secsock = try s2n.tlsWithSock(
        gpa,
        socket,
        config.mode,
    );
    errdefer secsock.deinit(gpa);

    return secsock;
}

fn newConnection(s2n: *S2N, mode: Socket.Mode) !*h.s2n_connection {
    const conn = h.s2n_connection_new(switch (mode) {
        .server => h.S2N_SERVER,
        .client => unreachable,
    });
    if (conn == null) return error.NewConnectionFailed;
    errdefer _ = h.s2n_connection_free(conn);

    const set_blind_rc = h.s2n_connection_set_blinding(
        conn,
        h.S2N_SELF_SERVICE_BLINDING,
    );
    try handle_error("setting blinding", set_blind_rc);

    const set_config_rc = h.s2n_connection_set_config(conn, s2n.config);
    try handle_error("setting config", set_config_rc);

    return conn.?;
}

fn handle_error(state: []const u8, rc: c_int) !void {
    if (rc < 0) {
        log.err("{s} failed: {s} | {s}", .{
            state,
            h.s2n_strerror(h.s2n_errno, "EN"),
            h.s2n_strerror_debug(h.s2n_errno, "EN"),
        });
        h.s2n_errno_location().* = h.S2N_ERR_T_OK;

        return error.InternalError;
    }
}

const Impl = struct {
    s2n: *S2N,
    conn: *h.s2n_connection,
    cb: *Callback,

    fn info(i: *const anyopaque) Secsock.Info {
        const impl: *const Impl = @ptrCast(@alignCast(i));

        var buf: [21:0]u8 = @splat(0x0);
        _ = mem.print(&buf, "{f}", .{
            impl.cb.socket.addr,
        }) catch unreachable;

        return .{
            .name = .@"s2n-tls",
            .address = buf,
        };
    }

    fn deinit(i: *const anyopaque, gpa: mem.Allocator) void {
        const impl: *const Impl = @ptrCast(@alignCast(i));

        var blocked_status: h.s2n_blocked_status = undefined;
        _ = h.s2n_shutdown(impl.conn, &blocked_status);
        _ = h.s2n_connection_free(impl.conn);

        impl.cb.socket.close_blocking();
        gpa.destroy(impl.cb.socket);
        gpa.destroy(impl.cb);
        gpa.destroy(impl);
    }

    fn accept(i: *const anyopaque, r: *Runtime) !Secsock {
        const impl: *const Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;

        const client = try impl.cb.socket.accept(r);
        errdefer client.close_blocking();

        const new_s2n = try impl.s2n.tlsWithSock(
            r.gpa,
            &client,
            .server,
        );
        // if we fail, we want to clean this connection up.
        errdefer new_s2n.deinit(r.gpa);

        const new_impl: *Impl = @ptrCast(@alignCast(new_s2n.impl));
        new_impl.cb.runtime = r;

        var blocked_status: h.s2n_blocked_status = h.S2N_NOT_BLOCKED;
        while (h.s2n_negotiate(new_impl.conn, &blocked_status) != h.S2N_SUCCESS) {
            switch (h.s2n_error_get_type(h.s2n_errno)) {
                h.S2N_ERR_T_BLOCKED => continue,
                h.S2N_ERR_T_CLOSED => return error.Closed,
                else => try handle_error(
                    "accept negotiating connection",
                    -1,
                ),
            }
        }

        return new_s2n;
    }

    fn connect(i: *const anyopaque, r: *Runtime) !void {
        const impl: *const Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;
        try impl.cb.socket.connect(r);

        var blocked_status: h.s2n_blocked_status = h.S2N_NOT_BLOCKED;
        while (h.s2n_negotiate(impl.conn, &blocked_status) != h.S2N_SUCCESS) {
            switch (h.s2n_error_get_type(h.s2n_errno)) {
                h.S2N_ERR_T_BLOCKED => continue,
                h.S2N_ERR_T_CLOSED => return error.Closed,
                else => try handle_error(
                    "connect negotiating connection",
                    -1,
                ),
            }
        }
    }

    fn recv(i: *anyopaque, r: *Runtime, buf: []u8) !usize {
        const impl: *Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;
        var blocked_status: h.s2n_blocked_status = undefined;

        const res = h.s2n_recv(impl.conn, buf.ptr, @intCast(buf.len), &blocked_status);

        if (res < 0) switch (h.s2n_error_get_type(h.s2n_errno)) {
            h.S2N_ERR_T_CLOSED => return error.Closed,
            else => return error.FailedRecv,
        };

        return @intCast(res);
    }

    fn send(i: *anyopaque, r: *Runtime, buf: []const u8) !usize {
        const impl: *Impl = @ptrCast(@alignCast(i));
        impl.cb.runtime = r;
        var blocked_status: h.s2n_blocked_status = undefined;

        const res = h.s2n_send(impl.conn, buf.ptr, @intCast(buf.len), &blocked_status);

        if (res < 0) switch (h.s2n_error_get_type(h.s2n_errno)) {
            h.S2N_ERR_T_CLOSED => return error.Closed,
            else => return error.FailedSend,
        };

        return @intCast(res);
    }
};

const Callback = struct {
    socket: *const Socket,
    runtime: ?*Runtime,

    fn recv(c: ?*anyopaque, buf: [*c]u8, len: u32) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const sock = cb.socket;
        const runtime = cb.runtime;

        const result = sock.recv(runtime.?, buf[0..len]) catch |err|
            switch (err) {
                error.Closed => return 0,
                // TODO: Properly handle errors.
                else => |e| {
                    log.err("error on recv: {t}", .{e});
                    return h.S2N_FAILURE;
                },
            };

        return @intCast(result);
    }

    fn send(c: ?*anyopaque, buf: [*c]const u8, len: u32) callconv(.c) c_int {
        const cb: *Callback = @ptrCast(@alignCast(c.?));
        const sock = cb.socket;
        const runtime = cb.runtime;

        const result = sock.send(runtime.?, buf[0..len]) catch |err|
            switch (err) {
                error.Closed => {
                    h.s2n_errno_location().* = h.S2N_ERR_T_CLOSED;
                    return h.S2N_FAILURE;
                },
                // TODO: Properly handle errors.
                else => |e| {
                    log.err("error on send: {t}", .{e});
                    return h.S2N_FAILURE;
                },
            };

        return @intCast(result);
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

const log = std.log.scoped(.s2n);

const std = @import("std");
const mem = std.mem;

const h = @import("s2n.h");
const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("Secsock.zig");
