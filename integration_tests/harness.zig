const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");

const TestConfig = @import("config.zig").TestConfig;

/// A live connection to a real MySQL server for integration tests.
///
/// `TestConn` is heap-allocated and pinned: `mantle.Connection` stores an
/// `AnyReader`/`AnyWriter` whose context is the address of the embedded
/// `ZioStream`, so the owner must not move after `connect`. Returning a
/// `*TestConn` keeps that address stable.
///
/// Must be called from within a zio coroutine (e.g. a `Group.spawn`ed task),
/// because the underlying connect/read/write operations yield to the runtime.
pub const TestConn = struct {
    zs: mantle.transport.ZioStream,
    conn: mantle.Connection,

    pub fn connect(allocator: std.mem.Allocator, cfg: TestConfig) !*TestConn {
        const self = try allocator.create(TestConn);
        errdefer allocator.destroy(self);

        const addr = try zio.net.IpAddress.parseIp4(cfg.host, cfg.port);
        const stream = try addr.connect(.{});
        self.zs = mantle.transport.ZioStream.init(stream, .none);
        errdefer self.zs.stream.close();

        self.conn = mantle.Connection.init(.{
            .reader = self.zs.reader(),
            .writer = self.zs.writer(),
        }, cfg.options());
        try self.conn.finishHandshake(allocator);

        return self;
    }

    pub fn deinit(self: *TestConn, allocator: std.mem.Allocator) void {
        self.conn.deinit(allocator);
        self.zs.stream.close();
        allocator.destroy(self);
    }

    /// Run a statement expected to return OK (DDL, INSERT, transaction control).
    /// Fails on a result set or a server error.
    pub fn queryOk(self: *TestConn, allocator: std.mem.Allocator, sql: []const u8) !void {
        var result = try self.conn.query(allocator, sql);
        defer result.deinit(allocator);
        _ = try result.expectOk();
    }
};

/// Spawn `task` on a fresh single-threaded zio runtime and wait for it. The
/// task receives the shared `std.testing.allocator`. Integration tests use this
/// to obtain a coroutine context in which connecting and querying are valid.
pub fn run(comptime task: fn (std.mem.Allocator) anyerror!void) !void {
    const runtime = try zio.Runtime.init(std.testing.allocator, .{});
    defer runtime.deinit();

    const Wrapper = struct {
        fn entry(result: *anyerror!void) void {
            result.* = task(std.testing.allocator) catch |err| {
                std.debug.print("integration task failed: {s}\n", .{@errorName(err)});
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
