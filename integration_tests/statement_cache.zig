//! Integration tests for the per-connection prepared-statement cache.
//!
//! The offline tests in `src/connection.zig` pin the LRU bookkeeping; these
//! prove the real wire effect against MySQL via the session `Com_stmt_prepare`
//! counter. We assert the robust property — a cached statement adds ZERO
//! prepares on reuse, an uncached/stale one adds more — rather than an absolute
//! delta, because the server may bump the counter by more than one per prepare.

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");

const harness = @import("harness.zig");
const test_config = @import("config.zig").test_config;

const TestConn = harness.TestConn;

/// Read this session's `Com_stmt_prepare` counter via the text protocol (so the
/// read itself never prepares and never perturbs the count).
fn preparedCount(conn: *mantle.Connection, allocator: std.mem.Allocator) !u64 {
    var table = try conn.queryOne(
        struct { Variable_name: []const u8, Value: []const u8 },
        allocator,
        "SHOW SESSION STATUS LIKE 'Com_stmt_prepare'",
    );
    defer table.deinit();
    return std.fmt.parseInt(u64, (try table.one()).Value, 10);
}

fn poolTarget() mantle.TcpDriver.Target {
    return .{
        .host = test_config.host,
        .port = test_config.port,
        .options = test_config.options(),
    };
}

test "repeated prepared sql prepares once" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            const m0 = try preparedCount(&c.conn, a);
            {
                var t = try c.conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
                try std.testing.expectEqual(@as(i64, 1), (try t.one()).n);
            }
            const m1 = try preparedCount(&c.conn, a);
            try std.testing.expect(m1 > m0); // first call prepared

            // Two more identical executions must not prepare again.
            for (0..2) |_| {
                var t = try c.conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
            }
            const m2 = try preparedCount(&c.conn, a);
            try std.testing.expectEqual(m1, m2); // served from cache
        }
    }.task);
}

test "distinct sql each prepare once" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            const m0 = try preparedCount(&c.conn, a);
            {
                var t = try c.conn.queryOneParams(struct { a: i64 }, a, "SELECT ? AS a", .{@as(i64, 1)});
                defer t.deinit();
            }
            const m1 = try preparedCount(&c.conn, a);
            try std.testing.expect(m1 > m0); // first sql prepared

            {
                var t = try c.conn.queryOneParams(struct { b: i64 }, a, "SELECT ? AS b", .{@as(i64, 2)});
                defer t.deinit();
            }
            const m2 = try preparedCount(&c.conn, a);
            try std.testing.expect(m2 > m1); // distinct sql prepared

            // Repeat both: both hit the cache, no new prepares.
            {
                var t1 = try c.conn.queryOneParams(struct { a: i64 }, a, "SELECT ? AS a", .{@as(i64, 1)});
                defer t1.deinit();
                var t2 = try c.conn.queryOneParams(struct { b: i64 }, a, "SELECT ? AS b", .{@as(i64, 2)});
                defer t2.deinit();
            }
            const m3 = try preparedCount(&c.conn, a);
            try std.testing.expectEqual(m2, m3);
        }
    }.task);
}

test "schema change triggers automatic re-prepare" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_reprepare");
            try c.queryOk(a, "CREATE DATABASE mantle_it_reprepare");
            defer c.queryOk(a, "DROP DATABASE mantle_it_reprepare") catch {};
            try c.queryOk(a, "CREATE TABLE mantle_it_reprepare.t (id INT) ENGINE=InnoDB");
            try c.queryOk(a, "INSERT INTO mantle_it_reprepare.t (id) VALUES (1)");

            const Row = struct { id: i32 };
            const sql = "SELECT id FROM mantle_it_reprepare.t";

            const m0 = try preparedCount(&c.conn, a);
            {
                var t1 = try c.conn.queryAllParams(Row, a, sql, .{});
                defer t1.deinit();
                try std.testing.expectEqual(@as(usize, 1), t1.rows.len);
            }
            const m1 = try preparedCount(&c.conn, a);
            try std.testing.expect(m1 > m0); // initial prepare

            // Changing the table invalidates the cached prepared statement.
            try c.queryOk(a, "ALTER TABLE mantle_it_reprepare.t ADD COLUMN extra INT");

            // The cached statement now returns ER_NEED_REPREPARE; the driver must
            // evict it, re-prepare, and succeed transparently.
            {
                var t2 = try c.conn.queryAllParams(Row, a, sql, .{});
                defer t2.deinit();
                try std.testing.expectEqual(@as(usize, 1), t2.rows.len);
                try std.testing.expectEqual(@as(i32, 1), t2.rows[0].id);
            }
            const m2 = try preparedCount(&c.conn, a);
            try std.testing.expect(m2 > m1); // re-prepared after the schema change

            // The connection stays healthy and reusable afterward.
            try std.testing.expect(c.conn.canReuse());
        }
    }.task);
}

test "disabled cache prepares every time" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            c.conn.setStatementCacheCapacity(a, 0);

            const m0 = try preparedCount(&c.conn, a);
            {
                var t = try c.conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
            }
            const m1 = try preparedCount(&c.conn, a);
            try std.testing.expect(m1 > m0);

            // With caching disabled the identical sql prepares again.
            {
                var t = try c.conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
            }
            const m2 = try preparedCount(&c.conn, a);
            try std.testing.expect(m2 > m1);
        }
    }.task);
}

test "statement cache survives a pool checkout cycle" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{ .max_connections = 1 });
            defer pool.deinit();

            var m1: u64 = undefined;
            {
                var lease = try pool.acquire();
                defer lease.release();
                const conn = &lease.handle().conn;
                const m0 = try preparedCount(conn, a);
                var t = try conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
                m1 = try preparedCount(conn, a);
                try std.testing.expect(m1 > m0); // prepared on first lease
            }

            // Same physical connection (max_connections = 1): the cache persists.
            {
                var lease = try pool.acquire();
                defer lease.release();
                const conn = &lease.handle().conn;
                var t = try conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
                const m2 = try preparedCount(conn, a);
                try std.testing.expectEqual(m1, m2); // no re-prepare: cache survived
            }
        }
    }.task);
}
