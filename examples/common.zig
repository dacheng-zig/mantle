//! Shared helpers for the mantle example programs.
//!
//! Every example is a standalone executable (`zig build example-connect`, etc.) and
//! needs the same three things: a server config (overridable via environment
//! variables), a pinned live connection, and a tiny stdout printer. Keeping
//! that boilerplate here lets each example focus on the one feature it shows.

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");

/// Scratch schema the table-backed examples create and `USE`. The integration
/// `TestConfig` selects no default database, and so do these examples, so any
/// `CREATE TABLE` needs an explicit database context first.
pub const scratch_db = "mantle_examples";

/// MySQL connection settings. Defaults target a local dev server; every field
/// can be overridden with a `MANTLE_*` environment variable so the examples run
/// against any server without recompiling.
pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 3306,
    username: []const u8 = "root",
    password: []const u8 = "root",
    database: ?[]const u8 = null,
    /// utf8mb4_general_ci, matching the rest of the codebase's default charset.
    character_set: u8 = 45,

    /// Read `MANTLE_HOST`, `MANTLE_PORT`, `MANTLE_USER`, `MANTLE_PASSWORD`, and
    /// `MANTLE_DB` from the process environment, falling back to the defaults.
    pub fn fromEnv(env: *const std.process.Environ.Map) Config {
        var cfg: Config = .{};
        if (env.get("MANTLE_HOST")) |v| cfg.host = v;
        if (env.get("MANTLE_PORT")) |v| cfg.port = std.fmt.parseInt(u16, v, 10) catch cfg.port;
        if (env.get("MANTLE_USER")) |v| cfg.username = v;
        if (env.get("MANTLE_PASSWORD")) |v| cfg.password = v;
        if (env.get("MANTLE_DB")) |v| cfg.database = if (v.len == 0) null else v;
        return cfg;
    }

    pub fn options(self: Config) mantle.ConnectionPhase.Options {
        return .{
            .username = self.username,
            .password = self.password,
            .database = self.database,
            .character_set = self.character_set,
        };
    }

    pub fn poolTarget(self: Config) mantle.TcpDriver.Target {
        return .{ .host = self.host, .port = self.port, .options = self.options() };
    }
};

/// A live connection pinned in the caller's stack frame.
///
/// `mantle.Connection` stores reader/writer callbacks whose context is the
/// address of the embedded `ZioStream`, so a `Db` must not move after
/// `connect`. Declare it as a local (`var db: common.Db = undefined;`) and pass
/// `&db` around — never return it by value or the callbacks dangle.
pub const Db = struct {
    zs: mantle.transport.ZioStream,
    conn: mantle.Connection,

    /// Dial the server and complete the MySQL handshake. Must run inside a zio
    /// runtime (the socket and handshake I/O yield to the scheduler).
    pub fn connect(self: *Db, gpa: std.mem.Allocator, cfg: Config) !void {
        const addr = try zio.net.IpAddress.parseIp4(cfg.host, cfg.port);
        const stream = try addr.connect(.{});
        self.zs = mantle.transport.ZioStream.init(stream, .none);
        errdefer self.zs.stream.close();

        self.conn = mantle.Connection.init(.{
            .reader = self.zs.reader(),
            .writer = self.zs.writer(),
        }, cfg.options());
        try self.conn.finishHandshake(gpa);
    }

    pub fn deinit(self: *Db, gpa: std.mem.Allocator) void {
        self.conn.deinit(gpa);
        self.zs.stream.close();
    }
};

/// Create (if needed) and `USE` the scratch schema so unqualified table names
/// in the examples resolve.
pub fn useScratch(conn: *mantle.Connection, gpa: std.mem.Allocator) !void {
    try execOk(conn, gpa, "CREATE DATABASE IF NOT EXISTS " ++ scratch_db);
    try execOk(conn, gpa, "USE " ++ scratch_db);
}

/// Run `sql` expecting an OK response (DDL, parameterless DML, transaction
/// control). A server ERR surfaces as `error.ServerError` via `expectOk`.
pub fn execOk(conn: *mantle.Connection, gpa: std.mem.Allocator, sql: []const u8) !void {
    var result = try conn.query(gpa, sql);
    defer result.deinit(gpa);
    _ = try result.expectOk();
}

// One stdout writer for the whole program, created lazily on the first print
// (inside the runtime). Reusing it matters: when stdout is a regular file the
// writer is in positional mode and tracks its own offset, so a fresh writer per
// call would write every line at offset 0 and clobber the last. Call only from
// the main coroutine — the shared buffer is not concurrency-safe.
const StdoutWriter = @TypeOf(zio.stdout().writer(@as([]u8, &.{})));
var stdout_buf: [4096]u8 = undefined;
var stdout_writer: ?StdoutWriter = null;

/// Print one line to stdout from inside the zio runtime. Fine for example
/// output, not for hot paths or concurrent coroutines.
pub fn print(comptime fmt: []const u8, args: anytype) void {
    if (stdout_writer == null) stdout_writer = zio.stdout().writer(&stdout_buf);
    const w = &stdout_writer.?;
    w.interface.print(fmt, args) catch return;
    w.interface.flush() catch return;
}
