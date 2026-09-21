const Tardy = tardy.Tardy(.auto);

/// curl --unix-socket /tmp/zzz.sock http://localhost/
pub fn main(init: std.process.Init) !void {
    const unix_path = "/tmp/zzz.sock";

    const unsecured: Secsock.Unix = .empty;
    defer unsecured.deinit(init.io, unix_path);

    const unix: Secsock = try unsecured.unix(
        init.gpa,
        unix_path,
    );
    defer unix.deinit(init.gpa);

    const info = unix.info();
    log.info("tcp: '{t}', address: ({s})", .{ info.name, info.address });

    var td: Tardy = try .init(init.gpa, init.io, .{
        .threading = .single,
    });
    defer td.deinit();

    try td.entry(&unix, struct {
        fn entry(rt: *tardy.Runtime, raw_tcp: *const Secsock) !void {
            try rt.spawn(
                echo_frame,
                .{ rt, raw_tcp },
                .KiB(45),
            );
        }
    }.entry);
}

fn echo_frame(rt: *tardy.Runtime, tcp: *const Secsock) !void {
    var connected = try tcp.accept(rt);
    defer connected.deinit(rt.gpa);

    var buf: [1024]u8 = undefined;
    const count = connected.recv(rt, &buf) catch |err|
        switch (err) {
            error.Closed => return,
            else => |e| return e,
        };

    log.info("recv count: {d}\ncontent:\n{s}", .{ count, buf[0..count] });

    _ = connected.send(rt, buf[0..count]) catch |err|
        switch (err) {
            error.Closed => return,
            else => |e| return e,
        };
}

const log = std.log.scoped(.@"examples/unix");

const std = @import("std");

const Secsock = @import("secsock");
const tardy = @import("tardy");
