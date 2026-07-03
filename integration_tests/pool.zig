//! Integration tests for the connection pool against a real MySQL server.
//!
//! These prove `TcpPool` round-trips end to end: acquire dials and handshakes,
//! a leased connection runs queries, release returns it, and a second acquire
//! reuses the same physical connection. The offline tests in `src/pool.zig`
//! pin the bookkeeping; these prove the real driver wiring.

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");

const test_config = @import("config.zig").test_config;

fn poolTarget() mantle.TcpDriver.Target {
    return .{
        .host = test_config.host,
        .port = test_config.port,
        .options = test_config.options(),
    };
}

/// Spawn `task` on a fresh single-threaded zio runtime (mirrors harness.run).
fn run(comptime task: fn (std.mem.Allocator) anyerror!void) !void {
    const runtime = try zio.Runtime.init(std.testing.allocator, .{});
    defer runtime.deinit();

    const Wrapper = struct {
        fn entry(result: *anyerror!void) void {
            result.* = task(std.testing.allocator) catch |err| {
                std.debug.print("pool integration task failed: {s}\n", .{@errorName(err)});
                result.* = err;
                return;
            };
        }
    };

    var result: anyerror!void = {};
    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(Wrapper.entry, .{&result});
    try group.wait();
    return result;
}

test "pool acquire runs a query and reuses on second acquire" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 2,
            });
            defer pool.deinit();

            var first_id: u64 = undefined;
            {
                var lease = try pool.acquire();
                defer lease.release();
                const conn = &lease.handle().conn;

                var table = try conn.queryOne(struct { n: u64 }, a, "SELECT 1 AS n");
                defer table.deinit();
                try std.testing.expectEqual(@as(u64, 1), (try table.one()).n);

                var tid = try conn.queryOne(struct { id: u64 }, a, "SELECT CONNECTION_ID() AS id");
                defer tid.deinit();
                first_id = (try tid.one()).id;
            }

            // Only one connection was ever opened; the second acquire reuses it.
            try std.testing.expectEqual(@as(usize, 1), pool.stats().idle);

            {
                var lease = try pool.acquire();
                defer lease.release();
                const conn = &lease.handle().conn;
                var tid = try conn.queryOne(struct { id: u64 }, a, "SELECT CONNECTION_ID() AS id");
                defer tid.deinit();
                // Same server-side connection id proves physical reuse.
                try std.testing.expectEqual(first_id, (try tid.one()).id);
            }
        }
    }.task);
}

test "pool serves concurrent acquirers within max_connections" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 2,
            });
            defer pool.deinit();

            const Worker = struct {
                pool: *mantle.TcpPool,
                allocator: std.mem.Allocator,
                ok: bool = false,
                fn run(w: *@This()) void {
                    var lease = w.pool.acquire() catch return;
                    defer lease.release();
                    const conn = &lease.handle().conn;
                    var table = conn.queryOne(struct { n: u64 }, w.allocator, "SELECT 1 AS n") catch return;
                    defer table.deinit();
                    const row = table.one() catch return;
                    w.ok = row.n == 1;
                }
            };

            var workers: [4]Worker = undefined;
            for (&workers) |*w| w.* = .{ .pool = &pool, .allocator = a };

            var group: zio.Group = .init;
            defer group.cancel();
            for (&workers) |*w| try group.spawn(Worker.run, .{w});
            try group.wait();

            for (&workers) |*w| try std.testing.expect(w.ok);
            // Never exceeded the cap.
            try std.testing.expect(pool.stats().total <= 2);
        }
    }.task);
}

test "pool clear forces fresh connections" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 2,
            });
            defer pool.deinit();

            var first_id: u64 = undefined;
            {
                var lease = try pool.acquire();
                defer lease.release();
                var tid = try lease.handle().conn.queryOne(struct { id: u64 }, a, "SELECT CONNECTION_ID() AS id");
                defer tid.deinit();
                first_id = (try tid.one()).id;
            }
            try std.testing.expectEqual(@as(usize, 1), pool.stats().idle);

            pool.clear();
            try std.testing.expectEqual(@as(usize, 0), pool.stats().idle);

            {
                var lease = try pool.acquire();
                defer lease.release();
                var tid = try lease.handle().conn.queryOne(struct { id: u64 }, a, "SELECT CONNECTION_ID() AS id");
                defer tid.deinit();
                // A new physical connection: different server-side id.
                try std.testing.expect((try tid.one()).id != first_id);
            }
        }
    }.task);
}

test "killQuery interrupts an in-flight query and leaves the connection reusable" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{ .max_connections = 1 });
            defer pool.deinit();

            var lease = try pool.acquire();
            defer lease.release();
            const conn = &lease.handle().conn;
            const tid = conn.serverThreadId();
            try std.testing.expect(tid != 0);

            // A sibling coroutine cancels the slow query once it is running. The
            // killer opens its own connection (outside the pool), so the pool's
            // single permit held by the victim does not block it.
            const Killer = struct {
                pool: *mantle.TcpPool,
                tid: u32,
                err: ?anyerror = null,
                fn run(k: *@This()) void {
                    zio.sleep(zio.Duration.fromMilliseconds(200)) catch {};
                    k.pool.killQuery(k.tid) catch |e| {
                        k.err = e;
                    };
                }
            };
            var killer: Killer = .{ .pool = &pool, .tid = tid };
            var group: zio.Group = .init;
            defer group.cancel();
            try group.spawn(Killer.run, .{&killer});

            // Blocks until the killer interrupts it (well before 5s). MySQL's
            // SLEEP() returns 1 when interrupted and 0 when it runs to
            // completion, so a result of 1 deterministically proves the cancel.
            var slept = try conn.queryOne(struct { s: i64 }, a, "SELECT SLEEP(5) AS s");
            defer slept.deinit();
            try group.wait();
            if (killer.err) |e| return e;
            try std.testing.expectEqual(@as(i64, 1), (try slept.one()).s);

            // A soft cancel leaves the connection reusable (queryOne
            // fully drained the interrupted result set).
            try std.testing.expect(conn.canReuse());
            var ping = try conn.queryOne(struct { n: i64 }, a, "SELECT 1 AS n");
            defer ping.deinit();
            try std.testing.expectEqual(@as(i64, 1), (try ping.one()).n);
        }
    }.task);
}

/// Poll `pool.stats().idle` until it reaches `target` or the budget elapses.
fn waitForIdle(pool: *mantle.TcpPool, target: usize, max_polls: usize) bool {
    var polls: usize = 0;
    while (polls < max_polls) : (polls += 1) {
        if (pool.stats().idle >= target) return true;
        zio.sleep(zio.Duration.fromMilliseconds(25)) catch return false;
    }
    return pool.stats().idle >= target;
}

test "queryTimed times out a slow query and retires the connection" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{ .max_connections = 2 });
            defer pool.deinit();

            var lease = try pool.acquire();
            // Bound a 5s sleep to 200ms: the watchdog soft-cancels it.
            const result = pool.queryTimed(lease, a, "SELECT SLEEP(5)", zio.Duration.fromMilliseconds(200));
            try std.testing.expectError(error.CommandTimeout, result);

            // The connection is marked broken (a pending KILL may linger).
            try std.testing.expect(lease.handle().conn.isBroken());
            lease.release(); // broken -> pool destroys it
            try std.testing.expectEqual(@as(usize, 0), pool.stats().total);

            // The pool still works afterward (fresh connection).
            var lease2 = try pool.acquire();
            defer lease2.release();
            var t = try lease2.handle().conn.queryOne(struct { n: i64 }, a, "SELECT 1 AS n");
            defer t.deinit();
            try std.testing.expectEqual(@as(i64, 1), (try t.one()).n);
        }
    }.task);
}

test "queryTimed returns normally when under the timeout" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{ .max_connections = 1 });
            defer pool.deinit();

            var lease = try pool.acquire();
            defer lease.release();
            var result = try pool.queryTimed(lease, a, "DO 1", zio.Duration.fromSeconds(5));
            defer result.deinit(a);
            try std.testing.expect(result == .ok);
            try std.testing.expect(lease.handle().conn.canReuse());
        }
    }.task);
}

test "background reaper prewarms min_idle and stops cleanly on deinit" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 4,
                .min_idle = 2,
                .reap_interval_ns = 50 * std.time.ns_per_ms,
            });
            defer pool.deinit(); // must cancel + join the reaper without hanging

            try std.testing.expectEqual(@as(usize, 0), pool.stats().idle);
            try pool.startReaper();

            // The background reaper opens connections up to min_idle on its own.
            try std.testing.expect(waitForIdle(&pool, 2, 80));
            const s = pool.stats();
            try std.testing.expectEqual(@as(usize, 2), s.idle);
            try std.testing.expectEqual(@as(usize, 2), s.total);

            // Those warm connections are real and usable.
            var lease = try pool.acquire();
            defer lease.release();
            var t = try lease.handle().conn.queryOne(struct { n: i64 }, a, "SELECT 1 AS n");
            defer t.deinit();
            try std.testing.expectEqual(@as(i64, 1), (try t.one()).n);
        }
    }.task);
}

test "background reaper retires idle connections past idle_timeout" {
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 4,
                .min_idle = 0,
                .idle_timeout_ns = 30 * std.time.ns_per_ms,
                .reap_interval_ns = 40 * std.time.ns_per_ms,
            });
            defer pool.deinit();

            // Create one idle connection.
            {
                var lease = try pool.acquire();
                lease.release();
            }
            try std.testing.expectEqual(@as(usize, 1), pool.stats().idle);

            try pool.startReaper();

            // The reaper retires it once it ages past idle_timeout.
            var polls: usize = 0;
            while (polls < 80 and pool.stats().idle > 0) : (polls += 1) {
                zio.sleep(zio.Duration.fromMilliseconds(25)) catch break;
            }
            const s = pool.stats();
            try std.testing.expectEqual(@as(usize, 0), s.idle);
            try std.testing.expectEqual(@as(usize, 0), s.total);
        }
    }.task);
}

test "pool teardown stays clean after binding a typed-null optional" {
    // Regression probe for "Invalid free at pool teardown after binding a
    // NULL optional" (observed under smp_allocator in app use; the testing
    // allocator turns any such invalid/double free into a test failure).
    // Mirrors the app shape: pooled connection, statement cache, a typed
    // `?u64` null bound alongside other params, then pool deinit.
    try run(struct {
        fn task(a: std.mem.Allocator) !void {
            var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(poolTarget()), .{
                .max_connections = 1,
            });
            defer pool.deinit();

            var db = try mantle.PooledConnection.acquire(&pool);
            defer db.release();

            try db.conn.execSimple(a, "DROP DATABASE IF EXISTS mantle_it_null_opt");
            try db.conn.execSimple(a, "CREATE DATABASE mantle_it_null_opt");
            defer db.conn.execSimple(a, "DROP DATABASE mantle_it_null_opt") catch {};
            try db.conn.execSimple(a,
                \\CREATE TEMPORARY TABLE mantle_it_null_opt.t (
                \\  secret_hash CHAR(64) NOT NULL,
                \\  user_id     BIGINT UNSIGNED NOT NULL,
                \\  expire_at   BIGINT UNSIGNED NULL,
                \\  unique_key  VARBINARY(32)   NULL
                \\)
            );

            const insert = "INSERT INTO mantle_it_null_opt.t (secret_hash, user_id, expire_at, unique_key) VALUES (?, ?, ?, ?)";
            // Both optional shapes: integer (`?u64`) and slice (`?[]const u8`).
            const no_key: ?[]const u8 = null;
            const ok_null = try db.conn.exec(a, insert, .{ "a" ** 64, @as(u64, 7), @as(?u64, null), no_key });
            try std.testing.expectEqual(@as(u64, 1), ok_null.affected_rows);
            // Same cached statement, now with the optionals present.
            const key: ?[]const u8 = "k" ** 32;
            const ok_some = try db.conn.exec(a, insert, .{ "b" ** 64, @as(u64, 8), @as(?u64, 12345), key });
            try std.testing.expectEqual(@as(u64, 1), ok_some.affected_rows);

            var table = try db.conn.queryOne(
                struct { cnt: u64, non_nulls: u64 },
                a,
                "SELECT COUNT(*) AS cnt, COUNT(expire_at) AS non_nulls FROM mantle_it_null_opt.t",
            );
            defer table.deinit();
            const row = try table.one();
            try std.testing.expectEqual(@as(u64, 2), row.cnt);
            try std.testing.expectEqual(@as(u64, 1), row.non_nulls);
        }
    }.task);
}
