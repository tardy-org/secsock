const Unsecured = @This();

pub const empty: Unsecured = .{};

pub fn tcp(
    _: *const Unsecured,
    gpa: mem.Allocator,
    config: Socket.Config,
) !Secsock {
    const socket = try gpa.create(Socket);
    socket.* = try .init(.{ .tcp = config });
    errdefer gpa.destroy(socket);
    errdefer socket.close_blocking();

    try socket.bind();
    try socket.listen(config.backlog);

    return try tcpWithSock(gpa, socket);
}

fn tcpWithSock(
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
            .name = .unsecured,
            .address = buf,
        };
    }

    fn deinit(ct: *const anyopaque, gpa: mem.Allocator) void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        impl.socket.close_blocking();
        gpa.destroy(impl.socket);
        gpa.destroy(impl);
    }

    fn accept(ct: *const anyopaque, rt: *Runtime) !Secsock {
        const impl: *const Impl = @ptrCast(@alignCast(ct));

        const client = try rt.gpa.create(Socket);
        client.* = try impl.socket.accept(rt);
        errdefer rt.gpa.destroy(client);
        errdefer client.close_blocking();

        switch (try Secsock.snifProtocol(rt, client)) {
            .https => {
                log.warn("socket doesn't support https", .{});
                return error.HttpsUnsupported;
            },
            else => {},
        }

        const new_tcp = try tcpWithSock(rt.gpa, client);
        errdefer new_tcp.deinit(rt.gpa);

        return new_tcp;
    }

    fn connect(ct: *const anyopaque, rt: *Runtime) !void {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        try impl.socket.connect(rt);
    }

    fn recv(ct: *const anyopaque, rt: *Runtime, buf: []u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.recv(rt, buf, 0);
    }

    fn send(ct: *const anyopaque, rt: *Runtime, buf: []const u8) !usize {
        const impl: *const Impl = @ptrCast(@alignCast(ct));
        return try impl.socket.send(rt, buf);
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
const mem = std.mem;
const log = std.log.scoped(.@"Secsock/Unsecured");

const tardy = @import("tardy");
const Socket = tardy.net.Socket;
const Runtime = tardy.Runtime;

const Secsock = @import("Secsock.zig");
