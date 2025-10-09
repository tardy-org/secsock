const std = @import("std");
const assert = std.debug.assert;

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;
const BearSSL = @import("lib.zig").BearSSL;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = @import("lib.zig").EngineStatus;

const log = std.log.scoped(.@"bearssl/server");

const c = @cImport({
    @cInclude("bearssl.h");
});

pub fn to_secure_socket_server(self: *BearSSL, socket: Socket) !SecureSocket {
    const CallbackContext = struct { socket: Socket, runtime: ?*Runtime };
    const VtableContext = struct {
        allocator: std.mem.Allocator,
        bearssl: *BearSSL,
        io_buf: []const u8,
        sslio_ctx: c.br_sslio_context,
        cb_ctx: *CallbackContext,
        context: c.br_ssl_server_context,
    };

    const io_buf = try self.allocator.alloc(u8, c.BR_SSL_BUFSIZE_BIDI);
    errdefer self.allocator.free(io_buf);

    const cb_ctx = try self.allocator.create(CallbackContext);
    errdefer self.allocator.destroy(cb_ctx);
    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const context = try self.allocator.create(VtableContext);
    errdefer self.allocator.destroy(context);
    context.* = .{
        .allocator = self.allocator,
        .bearssl = self,
        .context = undefined,
        .io_buf = io_buf,
        .cb_ctx = cb_ctx,
        .sslio_ctx = undefined,
    };

    switch (self.pkey.?) {
        .rsa => |*inner| c.br_ssl_server_init_full_rsa(
            &context.context,
            @ptrCast(&self.x509.?),
            1,
            @ptrCast(inner),
        ),
        .ec => |*inner| c.br_ssl_server_init_full_ec(
            &context.context,
            @ptrCast(&self.x509.?),
            1,
            @intCast(self.cert_signer_algo.?),
            @ptrCast(inner),
        ),
    }

    c.br_ssl_engine_set_buffer(&context.context.eng, io_buf.ptr, io_buf.len, 1);
    const reset_status = c.br_ssl_server_reset(&context.context);
    if (reset_status <= 0) return error.ServerResetFailed;

    c.br_sslio_init(
        &context.sslio_ctx,
        &context.context.eng,
        struct {
            fn recv_cb(i: ?*anyopaque, b: [*c]u8, l: usize) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.recv(ctx.runtime.?, b[0..l]) catch |e| {
                    log.err("sslio recv cb failed: {s}", .{@errorName(e)});
                    return -1;
                };
                return @intCast(len);
            }
        }.recv_cb,
        cb_ctx,
        struct {
            fn send_cb(i: ?*anyopaque, b: [*c]const u8, l: usize) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.send(ctx.runtime.?, b[0..l]) catch |e| {
                    log.err("sslio send cb failed: {s}", .{@errorName(e)});
                    return -1;
                };
                return @intCast(len);
            }
        }.send_cb,
        cb_ctx,
    );

    return SecureSocket{
        .socket = socket,
        .vtable = .{
            .inner = context,
            .deinit = struct {
                fn deinit(i: *anyopaque) void {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));

                    ctx.allocator.destroy(ctx.cb_ctx);
                    ctx.allocator.free(ctx.io_buf);
                    ctx.allocator.destroy(ctx);
                }
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, i: *anyopaque) !SecureSocket {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    const sock = try s.accept(r);
                    errdefer sock.close_blocking();

                    const child = try ctx.bearssl.to_secure_socket(sock, .server);
                    // if we fail, we want to clean this connection up.
                    errdefer child.deinit();
                    const new_ctx: *VtableContext = @ptrCast(@alignCast(child.vtable.inner));
                    new_ctx.cb_ctx.runtime = r;

                    return child;
                }
            }.accept,
            .connect = struct {
                fn connect(_: Socket, _: *Runtime, _: *anyopaque) !void {
                    return error.TLSServerCantConnect;
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, i: *anyopaque, b: []u8) !usize {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    ctx.cb_ctx.runtime = r;

                    const result = c.br_sslio_read(&ctx.sslio_ctx, b.ptr, b.len);
                    if (result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio recv failed: {s}", .{@tagName(last_error)});
                                return error.TlsRecvFailed;
                            },
                        }
                    }

                    return @intCast(result);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    ctx.cb_ctx.runtime = r;

                    const write_result = c.br_sslio_write(&ctx.sslio_ctx, b.ptr, b.len);
                    if (write_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio send failed: {s}", .{@tagName(last_error)});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    // Force flush. We should be buffering a layer above this.
                    const flush_result = c.br_sslio_flush(&ctx.sslio_ctx);
                    if (flush_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio flush failed: {s}", .{@tagName(last_error)});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    return @intCast(write_result);
                }
            }.send,
        },
    };
}
