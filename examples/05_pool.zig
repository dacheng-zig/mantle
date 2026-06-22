//! Connection pool: lease a connection, run a query, release it; then let many
//! concurrent coroutines share a capped pool.
//!
//!   zig build example-pool
//!
//! The pool dials lazily, reuses idle connections, and never exceeds
//! max_connections. SELECT CONNECTION_ID() exposes which physical connection
//! served each request.

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    var rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();

    const gpa = init.gpa;
    const cfg = common.Config.fromEnv(init.environ_map);

    var pool = mantle.TcpPool.init(gpa, mantle.TcpDriver.init(cfg.poolTarget()), .{
        .max_connections = 4,
    });
    defer pool.deinit();

    // Acquire -> use -> release. The lease borrows a connection; releasing it
    // returns it to the pool for reuse rather than closing it.
    {
        var db = try mantle.PooledConnection.acquire(&pool);
        defer db.release();
        var t = try db.conn.queryOne(struct { id: u64 }, gpa, "SELECT CONNECTION_ID() AS id");
        defer t.deinit();
        common.print("served by connection {d}; idle now {d}\n", .{ (try t.one()).id, pool.stats().idle });
    }

    // Eight workers contend for at most four connections. zio schedules them
    // cooperatively; each blocks on acquire until a permit frees up. Each worker
    // records the physical connection it got; main prints the results after the
    // group joins (stdout is driven from a single coroutine).
    const Worker = struct {
        pool: *mantle.TcpPool,
        gpa: std.mem.Allocator,
        conn_id: u64 = 0,

        fn run(w: *@This()) void {
            var db = mantle.PooledConnection.acquire(w.pool) catch return;
            defer db.release();
            var t = db.conn.queryOne(struct { id: u64 }, w.gpa, "SELECT CONNECTION_ID() AS id") catch return;
            defer t.deinit();
            w.conn_id = (t.one() catch return).id;
        }
    };

    var workers: [8]Worker = undefined;
    for (&workers) |*w| w.* = .{ .pool = &pool, .gpa = gpa };

    var group: zio.Group = .init;
    defer group.cancel();
    for (&workers) |*w| try group.spawn(Worker.run, .{w});
    try group.wait();

    for (&workers, 0..) |*w, i| common.print("worker {d} -> connection {d}\n", .{ i, w.conn_id });

    const s = pool.stats();
    common.print("pool: total={d} idle={d} (cap {d})\n", .{ s.total, s.idle, @as(usize, 4) });
}
