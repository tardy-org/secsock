//! Secure Sockets - TLS functionality for Tardy Sockets
const std = @import("std");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.Socket;

pub const BearSSL = if (options.tls == .bearssl) @import("bearssl/lib.zig").BearSSL;

pub const s2n = if (options.tls == .s2n_tls) @import("s2n.zig").s2n;

pub const SecureSocket = struct {
    pub const Mode = enum { client, server };

    pub fn unsecured(socket: Socket) SecureSocket {
        return .{
            .socket = socket,
            .vtable = .{
                .inner = undefined,
                .deinit = struct {
                    fn deinit(_: *anyopaque) void {}
                }.deinit,
                .accept = struct {
                    fn accept(s: Socket, r: *Runtime, _: *anyopaque) !SecureSocket {
                        const child = try s.accept(r);
                        return SecureSocket.unsecured(child);
                    }
                }.accept,
                .connect = struct {
                    fn connect(s: Socket, r: *Runtime, _: *anyopaque) !void {
                        try s.connect(r);
                    }
                }.connect,
                .recv = struct {
                    fn recv(s: Socket, r: *Runtime, _: *anyopaque, buf: []u8) !usize {
                        return try s.recv(r, buf);
                    }
                }.recv,
                .send = struct {
                    fn send(s: Socket, r: *Runtime, _: *anyopaque, buf: []const u8) !usize {
                        return try s.send(r, buf);
                    }
                }.send,
            },
        };
    }

    const VTable = struct {
        inner: *anyopaque,
        deinit: *const fn (*anyopaque) void,
        accept: *const fn (Socket, *Runtime, *anyopaque) anyerror!SecureSocket,
        connect: *const fn (Socket, *Runtime, *anyopaque) anyerror!void,
        recv: *const fn (Socket, *Runtime, *anyopaque, []u8) anyerror!usize,
        send: *const fn (Socket, *Runtime, *anyopaque, []const u8) anyerror!usize,
    };

    socket: Socket,
    vtable: VTable,

    pub fn deinit(self: *const SecureSocket) void {
        return self.vtable.deinit(self.vtable.inner);
    }

    pub fn accept(self: *const SecureSocket, rt: *Runtime) !SecureSocket {
        return try self.vtable.accept(self.socket, rt, self.vtable.inner);
    }

    pub fn connect(self: *const SecureSocket, rt: *Runtime) !void {
        return try self.vtable.connect(self.socket, rt, self.vtable.inner);
    }

    pub fn recv(self: *const SecureSocket, rt: *Runtime, buffer: []u8) !usize {
        return try self.vtable.recv(self.socket, rt, self.vtable.inner, buffer);
    }

    pub fn send(self: *const SecureSocket, rt: *Runtime, buffer: []const u8) !usize {
        return try self.vtable.send(self.socket, rt, self.vtable.inner, buffer);
    }

    pub fn send_all(self: *const SecureSocket, rt: *Runtime, buffer: []const u8) !usize {
        var count: usize = 0;
        while (count != buffer.len) {
            count += self.send(rt, buffer[count..]) catch |e| switch (e) {
                error.Closed => return count,
                else => return e,
            };
        }

        return count;
    }
};
