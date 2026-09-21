//! Secure Sockets - TLS functionality for Tardy Sockets
pub const Secsock = @This();

impl: *anyopaque,
vtable: *const VTable,

pub fn info(tls: *const Secsock) Info {
    return tls.vtable.info(tls.impl);
}

pub fn deinit(tls: *const Secsock, gpa: mem.Allocator) void {
    tls.vtable.deinit(tls.impl, gpa);
}

pub fn accept(tls: *const Secsock, rt: *Runtime) !Secsock {
    return try tls.vtable.accept(tls.impl, rt);
}

pub fn connect(tls: *const Secsock, rt: *Runtime) !void {
    try tls.vtable.connect(tls.impl, rt);
}

pub fn recv(tls: *Secsock, rt: *Runtime, buffer: []u8) !usize {
    return try tls.vtable.recv(tls.impl, rt, buffer);
}

pub fn send(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
    return try tls.vtable.send(tls.impl, rt, buffer);
}

pub fn send_all(tls: *Secsock, rt: *Runtime, buffer: []const u8) !usize {
    var count: usize = 0;
    defer debug.assert(count == buffer.len);

    while (count != buffer.len) {
        count += tls.send(rt, buffer[count..]) catch |e|
            switch (e) {
                error.Closed => return count,
                else => return e,
            };
    }

    return count;
}

const Protocol = enum {
    http,
    https,
    http2,
};

/// https://github.com/httptoolkit/httpolyglot/blob/89064d5801caf500032461048ceb72884d40d0c4/src/index.ts
/// https://github.com/mscdex/httpolyglot/issues/3#issuecomment-173680155
/// https://httptoolkit.com/blog/http-https-same-port/
pub fn snifProtocol(socket: *const Socket) Protocol {
    var first_byte: [1]u8 = undefined;
    const count = tardy.AsyncIO.syscall.recv(
        socket.handle,
        &first_byte,
        std.posix.MSG.PEEK,
    ) catch unreachable;
    debug.assert(count == first_byte.len);

    const http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    switch (first_byte[0]) {
        // SSLv3+ or TLS handshake
        0x16 => return .https,
        0x21...0x4f, 0x51...0x7e => return .http,
        http2_preface[0] => {
            var preface_byte: [http2_preface.len]u8 = undefined;
            const preface_count = tardy.AsyncIO.syscall.recv(
                socket.handle,
                &preface_byte,
                std.posix.MSG.PEEK,
            ) catch unreachable;
            debug.assert(preface_count == preface_byte.len);

            if (mem.eql(u8, http2_preface, preface_byte[0..])) return .http2;

            const http_methods: [9][]const u8 = .{
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "DELETE",
                "CONNECT",
                "OPTIONS",
                "TRACE",
                "PATCH",
            };

            for (http_methods) |method| {
                if (mem.eql(u8, method, preface_byte[0..method.len]))
                    return .http;
            }

            unreachable;
        },
        else => @panic("Protocol Unsupported"),
    }
}

pub const Info = struct {
    name: Implementation,
    address: [21:0]u8,
};
const Implementation = enum(u8) {
    bearssl,
    @"s2n-tls",
    unsecured,
    unix,
};

pub const VTable = struct {
    info: *const fn (impl: *const anyopaque) Info,
    deinit: *const fn (impl: *const anyopaque, mem.Allocator) void,
    accept: *const fn (impl: *const anyopaque, *Runtime) anyerror!Secsock,
    connect: *const fn (impl: *const anyopaque, *Runtime) anyerror!void,
    recv: *const fn (impl: *anyopaque, *Runtime, []u8) anyerror!usize,
    send: *const fn (impl: *anyopaque, *Runtime, []const u8) anyerror!usize,
};

pub const BearSSL = if (options.tls == .bearssl) @import("BearSSL.zig");
pub const S2N = if (options.tls == .s2n_tls) @import("S2N.zig");
pub const Unix = if (builtin.os.tag != .windows) @import("Unix.zig");

const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const builtin = @import("builtin");

const options = @import("options");
const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.net.Socket;

pub const Unsecured = @import("Unsecured.zig");
