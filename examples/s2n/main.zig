const std = @import("std");

const Runtime = @import("tardy").Runtime;
const secsock = @import("secsock");
const Socket = @import("tardy").Socket;
const Timer = @import("tardy").Timer;

const log = std.log.scoped(.@"examples/s2n");

const Tardy = @import("tardy").Tardy(.auto);

// curl -vk https://127.0.0.1:9862
pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var tardy: Tardy = try .init(allocator, .{ .threading = .single });
    defer tardy.deinit();

    // ideally, this is the pattern we can utilize where the
    // tls vendor is initialized outside of tardy and shared internally.
    var s2n = try secsock.s2n.init(allocator);
    defer s2n.deinit();
    try s2n.add_cert_chain(@embedFile("cert.pem"), @embedFile("key.pem"));

    try tardy.entry(&s2n, struct {
        fn entry(rt: *Runtime, s: *secsock.s2n) !void {
            try rt.spawn(.{ rt, s }, echo_frame, 1024 * 1024 * 16);
        }
    }.entry);
}

fn echo_frame(rt: *Runtime, s2n: *secsock.s2n) !void {
    const socket: Socket = try .init(.{ .tcp = .{ .host = "127.0.0.1", .port = 9862 } });
    defer socket.close_blocking();
    try socket.bind();
    try socket.listen(128);

    const secure = try s2n.to_secure_socket(socket, .server);
    defer secure.deinit();

    const connected = try secure.accept(rt);
    defer connected.deinit();
    defer connected.socket.close_blocking();

    while (true) {
        var buf: [1024]u8 = undefined;
        const count = connected.recv(rt, &buf) catch |e| if (e == error.Closed) break else return e;
        log.info("recv count: {d}", .{count});
        _ = connected.send(rt, buf[0..count]) catch |e| if (e == error.Closed) break else return e;
    }
}
