const std = @import("std");

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("lib.zig").SecureSocket;

const c = @import("s2n_h");

const log = std.log.scoped(.s2n);

var initalized: bool = false;
var deinitalized: bool = false;

/// s2n-tls is an implementation of the TLS/SSL protocols by Amazon (AWS).
/// https://github.com/aws/s2n-tls
pub const s2n = struct {
    const CallbackContext = struct { socket: Socket, runtime: ?*Runtime };
    const VtableContext = struct {
        allocator: std.mem.Allocator,
        s2n: *s2n,
        conn: *c.s2n_connection,
        cb_ctx: *CallbackContext,
    };

    allocator: std.mem.Allocator,
    config: *c.s2n_config,
    cert: ?*c.s2n_cert_chain_and_key,
    // TODO: This needs to go.
    lock: std.Thread.Mutex = .{},

    fn handle_error(state: []const u8, rc: c_int) !void {
        if (rc < 0) {
            log.err(
                "{s} failed: {s} | {s}",
                .{ state, c.s2n_strerror(c.s2n_errno, "EN"), c.s2n_strerror_debug(c.s2n_errno, "EN") },
            );
            c.s2n_errno_location().* = c.S2N_ERR_T_OK;

            return error.InternalError;
        }
    }

    pub fn init(allocator: std.mem.Allocator) !s2n {
        if (initalized) @panic("Can only initalize s2n once!");
        initalized = true;

        const init_rc = c.s2n_init();
        try handle_error("s2n_init", init_rc);

        const config = c.s2n_config_new();

        return .{ .allocator = allocator, .config = config.?, .cert = null };
    }

    pub fn add_cert_chain(self: *s2n, cert: []const u8, key: []const u8) !void {
        const chain = c.s2n_cert_chain_and_key_new();
        self.cert = chain.?;
        const load_pem_bytes_rc = c.s2n_cert_chain_and_key_load_pem_bytes(
            chain,
            @constCast(cert.ptr),
            @intCast(cert.len),
            @constCast(key.ptr),
            @intCast(key.len),
        );
        try handle_error("adding pem bytes to cert chain", load_pem_bytes_rc);
        const add_cert_chain_rc = c.s2n_config_add_cert_chain_and_key_to_store(self.config, chain);
        try handle_error("adding cert chain to config", add_cert_chain_rc);
    }

    pub fn deinit(self: s2n) void {
        if (deinitalized) @panic("Can only deinitalize s2n once!");
        _ = c.s2n_config_free(self.config);
        if (self.cert) |cert| _ = c.s2n_cert_chain_and_key_free(cert);
        _ = c.s2n_cleanup();
    }

    pub fn to_secure_socket(self: *s2n, socket: Socket, mode: SecureSocket.Mode) !SecureSocket {
        self.lock.lock();
        defer self.lock.unlock();

        const conn = c.s2n_connection_new(switch (mode) {
            .client => c.S2N_CLIENT,
            .server => c.S2N_SERVER,
        });
        if (conn == null) return error.NewConnectionFailed;
        errdefer _ = c.s2n_connection_free(conn);

        const set_blind_rc = c.s2n_connection_set_blinding(conn, c.S2N_SELF_SERVICE_BLINDING);
        try handle_error("setting blinding", set_blind_rc);

        const set_config_rc = c.s2n_connection_set_config(conn, self.config);
        try handle_error("setting config", set_config_rc);

        const cb_ctx = try self.allocator.create(CallbackContext);
        errdefer self.allocator.destroy(cb_ctx);
        cb_ctx.* = .{ .socket = socket, .runtime = null };

        const set_recv_ctx_rc = c.s2n_connection_set_recv_ctx(conn, @ptrCast(cb_ctx));
        try handle_error("setting recv cb ctx", set_recv_ctx_rc);

        const set_send_ctx_rc = c.s2n_connection_set_send_ctx(conn, @ptrCast(cb_ctx));
        try handle_error("setting send cb ctx", set_send_ctx_rc);

        const set_recv_cb_rc = c.s2n_connection_set_recv_cb(conn, struct {
            fn recv_cb(context: ?*anyopaque, buf: [*c]u8, len: u32) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(context.?));
                const sock = ctx.socket;
                const runtime = ctx.runtime;

                const result = sock.recv(runtime.?, buf[0..len]) catch |e| switch (e) {
                    error.Closed => return 0,
                    // TODO: Properly handle errors.
                    else => {
                        log.err("error on recv: {t}", .{e});
                        return c.S2N_FAILURE;
                    },
                };

                return @intCast(result);
            }
        }.recv_cb);
        try handle_error("setting recv cb", set_recv_cb_rc);

        const set_send_cb_rc = c.s2n_connection_set_send_cb(conn, struct {
            fn send_cb(context: ?*anyopaque, buf: [*c]const u8, len: u32) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(context.?));
                const sock = ctx.socket;
                const runtime = ctx.runtime;

                const result = sock.send(runtime.?, buf[0..len]) catch |e| switch (e) {
                    error.Closed => {
                        c.s2n_errno_location().* = c.S2N_ERR_T_CLOSED;
                        return c.S2N_FAILURE;
                    },
                    // TODO: Properly handle errors.
                    else => {
                        log.err("error on send: {t}", .{e});
                        return c.S2N_FAILURE;
                    },
                };

                return @intCast(result);
            }
        }.send_cb);
        try handle_error("setting send cb", set_send_cb_rc);

        const vtable_ctx = try self.allocator.create(VtableContext);
        vtable_ctx.* = .{ .allocator = self.allocator, .s2n = self, .conn = conn.?, .cb_ctx = cb_ctx };

        return .{
            .socket = socket,
            .vtable = .{
                .inner = vtable_ctx,
                .deinit = struct {
                    fn deinit(i: *anyopaque) void {
                        const ctx: *VtableContext = @ptrCast(@alignCast(i));
                        const allocator = ctx.allocator;

                        var blocked_status: c.s2n_blocked_status = undefined;
                        _ = c.s2n_shutdown(ctx.conn, &blocked_status);
                        _ = c.s2n_connection_free(ctx.conn);
                        allocator.destroy(ctx.cb_ctx);
                        allocator.destroy(ctx);
                    }
                }.deinit,
                .accept = struct {
                    fn accept(s: Socket, r: *Runtime, i: *anyopaque) !SecureSocket {
                        const ctx: *VtableContext = @ptrCast(@alignCast(i));
                        ctx.cb_ctx.runtime = r;
                        const sock = try s.accept(r);
                        errdefer sock.close_blocking();

                        const child = try ctx.s2n.to_secure_socket(sock, .server);
                        // if we fail, we want to clean this connection up.
                        errdefer child.deinit();
                        const new_ctx: *VtableContext = @ptrCast(@alignCast(child.vtable.inner));
                        new_ctx.cb_ctx.runtime = r;

                        var blocked_status: c.s2n_blocked_status = c.S2N_NOT_BLOCKED;
                        while (c.s2n_negotiate(new_ctx.conn, &blocked_status) != c.S2N_SUCCESS) {
                            switch (c.s2n_error_get_type(c.s2n_errno)) {
                                c.S2N_ERR_T_BLOCKED => continue,
                                c.S2N_ERR_T_CLOSED => return error.Closed,
                                else => try handle_error("accept negotiating connection", -1),
                            }
                        }

                        return child;
                    }
                }.accept,
                .connect = struct {
                    fn connect(s: Socket, r: *Runtime, i: *anyopaque) !void {
                        const ctx: *VtableContext = @ptrCast(@alignCast(i));
                        ctx.cb_ctx.runtime = r;
                        try s.connect(r);

                        var blocked_status: c.s2n_blocked_status = c.S2N_NOT_BLOCKED;
                        while (c.s2n_negotiate(ctx.conn, &blocked_status) != c.S2N_SUCCESS) {
                            switch (c.s2n_error_get_type(c.s2n_errno)) {
                                c.S2N_ERR_T_BLOCKED => continue,
                                c.S2N_ERR_T_CLOSED => return error.Closed,
                                else => try handle_error("connect negotiating connection", -1),
                            }
                        }
                    }
                }.connect,
                .recv = struct {
                    fn recv(_: Socket, r: *Runtime, i: *anyopaque, buf: []u8) !usize {
                        const ctx: *VtableContext = @ptrCast(@alignCast(i));
                        ctx.cb_ctx.runtime = r;
                        var blocked_status: c.s2n_blocked_status = undefined;

                        const res = c.s2n_recv(ctx.conn, buf.ptr, @intCast(buf.len), &blocked_status);
                        if (res < 0) {
                            switch (c.s2n_error_get_type(c.s2n_errno)) {
                                c.S2N_ERR_T_CLOSED => return error.Closed,
                                else => return error.FailedRecv,
                            }
                        }

                        return @intCast(res);
                    }
                }.recv,
                .send = struct {
                    fn send(_: Socket, r: *Runtime, i: *anyopaque, buf: []const u8) !usize {
                        const ctx: *VtableContext = @ptrCast(@alignCast(i));
                        ctx.cb_ctx.runtime = r;
                        var blocked_status: c.s2n_blocked_status = undefined;

                        const res = c.s2n_send(ctx.conn, buf.ptr, @intCast(buf.len), &blocked_status);
                        if (res < 0) {
                            switch (c.s2n_error_get_type(c.s2n_errno)) {
                                c.S2N_ERR_T_CLOSED => return error.Closed,
                                else => return error.FailedSend,
                            }
                        }
                        return @intCast(res);
                    }
                }.send,
            },
        };
    }
};
