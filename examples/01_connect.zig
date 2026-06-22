//! Connect, prove the link is alive, read the server version, close cleanly.
//! The smallest end-to-end use of mantle.
//!
//!   zig build example-connect
//!
//! Override the target with MANTLE_HOST / MANTLE_PORT / MANTLE_USER /
//! MANTLE_PASSWORD (see examples/common.zig).

const std = @import("std");
const zio = @import("zio");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    // A zio runtime turns this main into a coroutine: the connect/query calls
    // below yield to the scheduler instead of blocking the thread.
    var rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();

    const gpa = init.gpa;
    const cfg = common.Config.fromEnv(init.environ_map);

    var db: common.Db = undefined;
    try db.connect(gpa, cfg);
    defer db.deinit(gpa);
    common.print("connected to {s}:{d} as {s}\n", .{ cfg.host, cfg.port, cfg.username });

    // COM_PING: a cheap round-trip that confirms the connection is usable.
    try db.conn.ping(gpa);
    common.print("ping ok (server thread id {d})\n", .{db.conn.serverThreadId()});

    // Read a single typed row over the text protocol.
    var table = try db.conn.queryOne(struct { version: []const u8 }, gpa, "SELECT VERSION() AS version");
    defer table.deinit();
    common.print("server version: {s}\n", .{(try table.one()).version});

    // A graceful COM_QUIT before the socket closes (deinit then closes the fd).
    try db.conn.close(gpa);
    common.print("closed cleanly\n", .{});
}
