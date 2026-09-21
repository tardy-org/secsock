const Unix = @This();

pub const empty: Unix = .{};

pub fn deinit(_: Unix, io: Io, path: []const u8) void {
    Io.Dir.deleteFileAbsolute(io, path) catch unreachable;
}

pub fn unix(
    _: *const Unix,
    gpa: mem.Allocator,
    path: [:0]const u8,
) !Secsock {
    debug.assert(mem.endsWith(u8, path, ".sock"));

    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .unix = path });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(4096);

    return try unixWithSock(gpa, socket);
}

fn unixWithSock(
    gpa: mem.Allocator,
    socket: *const Socket,
) !Secsock {
    const impl = try gpa.create(Impl);
    errdefer gpa.destroy(impl);

    impl.* = .{ .socket = socket };

    return .{
        .impl = impl,
        .vtable = &vtable,
    };
}

const Impl = struct {
    socket: *const Socket,

    fn info(ct: *const anyopaque) Secsock.Info {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        var buf: [21:0]u8 = @splat(0x0);
        _ = mem.print(&buf, "{f}", .{
            impl.socket.addr,
        }) catch unreachable;

        return .{
            .name = .unix,
            .address = buf,
        };
    }

    fn deinit(ct: *const anyopaque, gpa: mem.Allocator) void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        debug.assert(impl.socket.addr.family() == .unix);

        impl.socket.close_blocking();

        gpa.destroy(impl.socket);
        gpa.destroy(impl);
    }

    fn accept(ct: *const anyopaque, r: *Runtime) !Secsock {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        const client = try r.gpa.create(Socket);
        client.* = try impl.socket.accept(r);
        errdefer r.gpa.destroy(client);
        errdefer client.close_blocking();

        // We only support unix domain on http
        switch (Secsock.snifProtocol(client)) {
            .https => return error.TlsUnSupported,
            else => {},
        }

        const new_unix = try unixWithSock(r.gpa, client);
        errdefer new_unix.deinit(r.gpa);

        return new_unix;
    }

    fn connect(ct: *const anyopaque, r: *Runtime) !void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        try impl.socket.connect(r);
    }

    fn recv(ct: *const anyopaque, r: *Runtime, buf: []u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.recv(r, buf);
    }

    fn send(ct: *const anyopaque, r: *Runtime, buf: []const u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.send(r, buf);
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

const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const mem = std.mem;
const debug = std.debug;

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("Secsock.zig");
