const std = @import("std");

const Runtime = @import("tardy").Runtime;
const secsock = @import("secsock");
const SecureSocket = secsock.SecureSocket;
const Socket = @import("tardy").Socket;
const Timer = @import("tardy").Timer;

const Tardy = @import("tardy").Tardy(.auto);

const log = std.log.scoped(.@"examples/bearssl");

// curl -vk https://127.0.0.1:9862
pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var tardy: Tardy = try .init(allocator, .{ .threading = .single });
    defer tardy.deinit();

    var bearssl: secsock.BearSSL = .init(allocator);
    defer bearssl.deinit();

    // try bearssl.add_cert_chain(
    //     "CERTIFICATE",
    //     @embedFile("certs/cert.pem"),
    //     "EC PRIVATE KEY",
    //     @embedFile("certs/key.pem"),
    // );

    try bearssl.add_cert_chain(
        "CERTIFICATE",
        @embedFile("certs/rsa_cert.pem"),
        "PRIVATE KEY",
        @embedFile("certs/rsa_key.pem"),
    );

    const socket: Socket = try .init(.{ .tcp = .{ .host = "127.0.0.1", .port = 9862 } });
    defer socket.close_blocking();
    try socket.bind();
    try socket.listen(128);

    const secure = try bearssl.to_secure_socket(socket, .server);
    defer secure.deinit();

    try tardy.entry(&secure, struct {
        fn entry(rt: *Runtime, s: *const SecureSocket) !void {
            try rt.spawn(.{ rt, s }, echo_frame, 1024 * 1024 * 16);
        }
    }.entry);
}

fn echo_frame(rt: *Runtime, secure: *const SecureSocket) !void {
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
