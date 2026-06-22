//! Benchmark program for mantle's hot paths. A standalone executable (like the
//! other programs in this directory), not a `zig build test` unit test: a
//! `--listen=-` test runner aborts its IPC shutdown the moment a test writes to
//! stderr, and a benchmark exists to print results. Running as an executable
//! sidesteps that protocol entirely.
//!
//!     zig build benchmark -Doptimize=ReleaseFast
//!
//! Reports latency percentiles (p50/p95/p99), mean, throughput, and
//! allocations/op for the hot paths — validating the pool and statement-cache
//! optimizations. Debug builds are slow and not representative; always pass
//! `-Doptimize=ReleaseFast`. This is a measurement tool: each operation is still
//! `try`-checked, so the run also fails if any path errors.
//!
//! Target the server with MANTLE_HOST / MANTLE_PORT / MANTLE_USER /
//! MANTLE_PASSWORD / MANTLE_DB (see common.zig).

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");
const common = @import("common.zig");

/// Wraps a backing allocator and counts allocation calls, so a benchmark can
/// report allocations/op for the measured loop.
const CountingAllocator = struct {
    backing: std.mem.Allocator,
    allocs: usize = 0,

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.allocs += 1;
        return self.backing.vtable.alloc(self.backing.ptr, len, alignment, ret_addr);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.resize(self.backing.ptr, memory, alignment, new_len, ret_addr);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.remap(self.backing.ptr, memory, alignment, new_len, ret_addr);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.backing.vtable.free(self.backing.ptr, memory, alignment, ret_addr);
    }
};

const Stats = struct {
    name: []const u8,
    iters: usize,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    mean_ns: u64,
    allocs_per_op: f64,

    fn report(self: Stats) void {
        common.print(
            "{s:<26} n={d:>4}  p50={d:>7.1}us  p95={d:>7.1}us  p99={d:>7.1}us  mean={d:>7.1}us  {d:>8.0} ops/s  allocs/op={d:.1}\n",
            .{
                self.name,
                self.iters,
                usOf(self.p50_ns),
                usOf(self.p95_ns),
                usOf(self.p99_ns),
                usOf(self.mean_ns),
                opsPerSec(self.mean_ns),
                self.allocs_per_op,
            },
        );
    }
};

fn usOf(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1000.0;
}

fn opsPerSec(mean_ns: u64) f64 {
    if (mean_ns == 0) return 0;
    return 1_000_000_000.0 / @as(f64, @floatFromInt(mean_ns));
}

fn percentile(sorted: []const u64, p: f64) u64 {
    if (sorted.len == 0) return 0;
    const idx_f = p * @as(f64, @floatFromInt(sorted.len - 1));
    const idx: usize = @intFromFloat(@round(idx_f));
    return sorted[@min(idx, sorted.len - 1)];
}

/// Time `body` over `iters` iterations into `samples`, counting allocations.
fn bench(
    name: []const u8,
    iters: usize,
    samples: []u64,
    counting: *CountingAllocator,
    a: std.mem.Allocator,
    ctx: anytype,
    comptime body: fn (@TypeOf(ctx), std.mem.Allocator, usize) anyerror!void,
) !Stats {
    counting.allocs = 0;
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const t0 = zio.now().toNanoseconds();
        try body(ctx, a, i);
        samples[i] = zio.now().toNanoseconds() - t0;
    }
    const total_allocs = counting.allocs;

    var sum: u64 = 0;
    for (samples[0..iters]) |s| sum += s;
    std.mem.sort(u64, samples[0..iters], {}, std.sort.asc(u64));
    return .{
        .name = name,
        .iters = iters,
        .p50_ns = percentile(samples[0..iters], 0.50),
        .p95_ns = percentile(samples[0..iters], 0.95),
        .p99_ns = percentile(samples[0..iters], 0.99),
        .mean_ns = sum / iters,
        .allocs_per_op = @as(f64, @floatFromInt(total_allocs)) / @as(f64, @floatFromInt(iters)),
    };
}

const Conn = *mantle.Connection;
const Pool = *mantle.TcpPool;

/// A zio runtime turns `main` into a coroutine: the connect/query calls below
/// yield to the scheduler instead of blocking the thread.
pub fn main(init: std.process.Init) !void {
    var rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();

    const cfg = common.Config.fromEnv(init.environ_map);

    var counting = CountingAllocator{ .backing = init.gpa };
    const a = counting.allocator();

    var samples: [2000]u64 = undefined;
    const iters: usize = 500;

    common.print("\n=== mantle benchmarks (build with -Doptimize=ReleaseFast for real numbers) ===\n", .{});

    // Full connect + handshake + close (fewer iters: it is the slow one). The
    // `Db` is pinned in the body's own frame and never escapes it.
    {
        const s = try bench("connect+handshake+close", 40, &samples, &counting, a, cfg, struct {
            fn body(c: common.Config, alloc: std.mem.Allocator, _: usize) !void {
                var db: common.Db = undefined;
                try db.connect(alloc, c);
                db.deinit(alloc);
            }
        }.body);
        s.report();
    }

    // A shared warm connection for the per-command benchmarks, pinned in this
    // frame so its reader/writer callbacks stay valid.
    var db: common.Db = undefined;
    try db.connect(a, cfg);
    defer db.deinit(a);

    {
        const s = try bench("ping", iters, &samples, &counting, a, &db.conn, struct {
            fn body(conn: Conn, alloc: std.mem.Allocator, _: usize) !void {
                try conn.ping(alloc);
            }
        }.body);
        s.report();
    }

    {
        const s = try bench("text query SELECT 1", iters, &samples, &counting, a, &db.conn, struct {
            fn body(conn: Conn, alloc: std.mem.Allocator, _: usize) !void {
                var t = try conn.queryOne(struct { n: i64 }, alloc, "SELECT 1 AS n");
                defer t.deinit();
            }
        }.body);
        s.report();
    }

    // Prepared execute, statement cache HIT (warm the cache first).
    {
        var warm = try db.conn.queryOneParams(struct { n: i64 }, a, "SELECT ? AS n", .{@as(i64, 1)});
        warm.deinit();
        const s = try bench("prepared exec (cache hit)", iters, &samples, &counting, a, &db.conn, struct {
            fn body(conn: Conn, alloc: std.mem.Allocator, _: usize) !void {
                var t = try conn.queryOneParams(struct { n: i64 }, alloc, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
            }
        }.body);
        s.report();
    }

    // Prepared execute, statement cache disabled (prepare+close each op).
    {
        db.conn.setStatementCacheCapacity(a, 0);
        const s = try bench("prepared exec (cache miss)", iters, &samples, &counting, a, &db.conn, struct {
            fn body(conn: Conn, alloc: std.mem.Allocator, _: usize) !void {
                var t = try conn.queryOneParams(struct { n: i64 }, alloc, "SELECT ? AS n", .{@as(i64, 1)});
                defer t.deinit();
            }
        }.body);
        s.report();
        db.conn.setStatementCacheCapacity(a, mantle.default_statement_cache_capacity);
    }

    // Typed multi-column row scan.
    {
        const s = try bench("typed row scan (3 cols)", iters, &samples, &counting, a, &db.conn, struct {
            fn body(conn: Conn, alloc: std.mem.Allocator, _: usize) !void {
                // 3.5e0 is a DOUBLE literal; a bare 3.5 would be DECIMAL.
                var t = try conn.queryOne(struct { a: i64, b: []const u8, c: f64 }, alloc, "SELECT 42 AS a, 'hello' AS b, 3.5e0 AS c");
                defer t.deinit();
            }
        }.body);
        s.report();
    }

    // Pool acquire/release on a warm pool (measures pool overhead, not connect).
    {
        var pool = mantle.TcpPool.init(a, mantle.TcpDriver.init(cfg.poolTarget()), .{ .max_connections = 4 });
        defer pool.deinit();
        {
            var warm = try pool.acquire();
            warm.release();
        }
        const s = try bench("pool acquire+release", iters, &samples, &counting, a, &pool, struct {
            fn body(p: Pool, _: std.mem.Allocator, _: usize) !void {
                var lease = try p.acquire();
                lease.release();
            }
        }.body);
        s.report();
    }

    common.print("=== done ===\n", .{});
}
