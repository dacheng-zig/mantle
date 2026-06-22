const std = @import("std");
const zio = @import("zio");

const Pool = @import("pool.zig").Pool;

const Allocator = std.mem.Allocator;
const testing = std.testing;

// ---------------------------------------------------------------------------
// Offline tests: a mock driver with controllable connections and clock lets us
// pin the pool's bookkeeping deterministically, without a server.
// ---------------------------------------------------------------------------

const MockHandle = struct {
    broken: bool = false,
    reusable: bool = true,
    id: usize = 0,

    pub fn canReuse(self: *const MockHandle) bool {
        return self.reusable and !self.broken;
    }

    pub fn isBroken(self: *const MockHandle) bool {
        return self.broken;
    }
};

const MockDriver = struct {
    clock_ns: u64 = 0,
    open_count: usize = 0,
    close_count: usize = 0,
    next_id: usize = 0,
    fail_opens: bool = false,

    pub const Handle = MockHandle;

    pub fn open(self: *MockDriver, allocator: Allocator) !*MockHandle {
        if (self.fail_opens) return error.OpenFailed;
        const h = try allocator.create(MockHandle);
        self.next_id += 1;
        h.* = .{ .id = self.next_id };
        self.open_count += 1;
        return h;
    }

    pub fn close(self: *MockDriver, allocator: Allocator, handle: *MockHandle) void {
        self.close_count += 1;
        allocator.destroy(handle);
    }

    pub fn nowNs(self: *const MockDriver) u64 {
        return self.clock_ns;
    }
};

const MockPool = Pool(MockDriver);

/// Run `task` inside a zio coroutine: Mutex/Condition need a runtime context.
fn runPoolTest(comptime task: fn (*MockPool) anyerror!void, p: *MockPool) !void {
    const Ctx = struct {
        pool: *MockPool,
        result: anyerror!void = {},
        fn entry(ctx: *@This()) void {
            ctx.result = task(ctx.pool);
        }
    };
    const runtime = try zio.Runtime.init(testing.allocator, .{});
    defer runtime.deinit();

    var ctx: Ctx = .{ .pool = p };
    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(Ctx.entry, .{&ctx});
    try group.wait();
    return ctx.result;
}

test "acquire creates then release reuses the same connection" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 2 });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var lease = try p.acquire();
            const first_id = lease.handle().id;
            try testing.expectEqual(@as(usize, 1), p.stats().total);
            try testing.expectEqual(@as(usize, 1), p.stats().leased);

            lease.release();
            try testing.expectEqual(@as(usize, 1), p.stats().idle);
            try testing.expectEqual(@as(usize, 0), p.stats().leased);

            var again = try p.acquire();
            defer again.release();
            // Reused, not reopened.
            try testing.expectEqual(first_id, again.handle().id);
            try testing.expectEqual(@as(usize, 0), p.stats().idle);
        }
    }.task, &pool);

    try testing.expectEqual(@as(usize, 1), pool.driver.open_count);
}

test "broken connection is destroyed on release, not pooled" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 2 });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var lease = try p.acquire();
            lease.handle().broken = true;
            lease.release();

            const s = p.stats();
            try testing.expectEqual(@as(usize, 0), s.idle);
            try testing.expectEqual(@as(usize, 0), s.total);
        }
    }.task, &pool);

    try testing.expectEqual(@as(usize, 1), pool.driver.open_count);
    try testing.expectEqual(@as(usize, 1), pool.driver.close_count);
}

test "clear invalidates idle now and leased on release" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 4 });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            // One idle, one leased.
            var a = try p.acquire();
            var b = try p.acquire();
            a.release();
            try testing.expectEqual(@as(usize, 1), p.stats().idle);

            p.clear();
            // Idle connection closed immediately.
            try testing.expectEqual(@as(usize, 0), p.stats().idle);
            try testing.expectEqual(@as(usize, 1), p.stats().total); // b still leased

            // The leased connection is retired on release (generation mismatch).
            b.release();
            try testing.expectEqual(@as(usize, 0), p.stats().idle);
            try testing.expectEqual(@as(usize, 0), p.stats().total);
        }
    }.task, &pool);
}

test "max_lifetime retires a connection on release" {
    var pool = MockPool.init(testing.allocator, .{}, .{
        .max_connections = 2,
        .max_lifetime_ns = 1000,
    });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var lease = try p.acquire();
            p.driver.clock_ns = 1500; // past lifetime
            lease.release();
            // Exceeded lifetime: not pooled.
            try testing.expectEqual(@as(usize, 0), p.stats().idle);
            try testing.expectEqual(@as(usize, 0), p.stats().total);
        }
    }.task, &pool);
}

test "idle_timeout discards a stale idle connection on acquire" {
    var pool = MockPool.init(testing.allocator, .{}, .{
        .max_connections = 2,
        .idle_timeout_ns = 1000,
    });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var lease = try p.acquire();
            const first_id = lease.handle().id;
            lease.release();
            try testing.expectEqual(@as(usize, 1), p.stats().idle);

            p.driver.clock_ns = 2000; // idle too long
            var again = try p.acquire();
            defer again.release();
            // Stale idle was dropped and a fresh one opened.
            try testing.expect(again.handle().id != first_id);
        }
    }.task, &pool);

    try testing.expectEqual(@as(usize, 2), pool.driver.open_count);
}

test "acquire blocks at capacity and is served by a release" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 1 });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var held = try p.acquire();
            try testing.expectEqual(@as(usize, 1), p.stats().total);

            // A second acquire must wait; spawn it, then release to unblock.
            const Waiter = struct {
                pool: *MockPool,
                got: bool = false,
                fn run(w: *@This()) void {
                    var l = w.pool.acquire() catch return;
                    w.got = true;
                    l.release();
                }
            };
            var w: Waiter = .{ .pool = p };
            var group: zio.Group = .init;
            defer group.cancel();
            try group.spawn(Waiter.run, .{&w});

            // Let the waiter park, then hand off our connection.
            try zio.yield();
            try testing.expect(!w.got);
            held.release();
            try group.wait();
            try testing.expect(w.got);
        }
    }.task, &pool);

    // Only one physical connection ever existed.
    try testing.expectEqual(@as(usize, 1), pool.driver.open_count);
}

test "acquire times out when the pool stays at capacity" {
    var pool = MockPool.init(testing.allocator, .{}, .{
        .max_connections = 1,
        .acquire_timeout = .{ .duration = zio.Duration.fromMilliseconds(10) },
    });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            var held = try p.acquire();
            defer held.release();
            try testing.expectError(error.AcquireTimeout, p.acquire());
        }
    }.task, &pool);
}

test "reapOnce retires expired idle and prewarms to min_idle" {
    var pool = MockPool.init(testing.allocator, .{}, .{
        .max_connections = 4,
        .min_idle = 2,
        .idle_timeout_ns = 1000,
    });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            // Park one idle connection, then let it age out.
            var lease = try p.acquire();
            const aged_id = lease.handle().id;
            lease.release();
            try testing.expectEqual(@as(usize, 1), p.stats().idle);

            p.driver.clock_ns = 2000; // aged idle past idle_timeout
            p.reapOnce();

            // Aged one reaped; idle topped back up to min_idle (2).
            const s = p.stats();
            try testing.expectEqual(@as(usize, 2), s.idle);
            try testing.expectEqual(@as(usize, 2), s.total);

            // The aged connection is gone; the warmed ones are fresh.
            var a = try p.acquire();
            defer a.release();
            try testing.expect(a.handle().id != aged_id);
        }
    }.task, &pool);

    // 1 initial + 2 prewarmed = 3 opens; the aged one was closed.
    try testing.expectEqual(@as(usize, 3), pool.driver.open_count);
    try testing.expectEqual(@as(usize, 1), pool.driver.close_count);
}

test "acquire after deinit-style close returns PoolClosed" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 1 });

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            // Simulate the closed state the way deinit sets it.
            p.mutex.lockUncancelable();
            p.closed = true;
            p.mutex.unlock();
            try testing.expectError(error.PoolClosed, p.acquire());
        }
    }.task, &pool);

    // Reset so deinit runs cleanly.
    pool.closed = false;
    pool.deinit();
}

test "failed open rolls back the reserved slot" {
    var pool = MockPool.init(testing.allocator, .{}, .{ .max_connections = 2 });
    defer pool.deinit();

    try runPoolTest(struct {
        fn task(p: *MockPool) !void {
            p.driver.fail_opens = true;
            try testing.expectError(error.OpenFailed, p.acquire());
            // No leaked reservation.
            const s = p.stats();
            try testing.expectEqual(@as(usize, 0), s.total);
            try testing.expectEqual(@as(usize, 0), s.leased);

            // Recovery: opens succeed again.
            p.driver.fail_opens = false;
            var lease = try p.acquire();
            defer lease.release();
            try testing.expectEqual(@as(usize, 1), p.stats().total);
        }
    }.task, &pool);
}
