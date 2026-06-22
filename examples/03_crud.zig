//! Prepared-statement CRUD: parameterized INSERT/SELECT/UPDATE/DELETE.
//!
//!   zig build example-crud
//!
//! exec / queryAllParams prepare on first use and serve repeats from the
//! per-connection statement cache, so reusing the same SQL text never
//! re-prepares. Parameters bind positionally from a struct or a tuple.

const std = @import("std");
const zio = @import("zio");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    var rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();

    const gpa = init.gpa;
    const cfg = common.Config.fromEnv(init.environ_map);

    var db: common.Db = undefined;
    try db.connect(gpa, cfg);
    defer db.deinit(gpa);

    try common.useScratch(&db.conn, gpa);
    try common.execOk(&db.conn, gpa, "DROP TABLE IF EXISTS users");
    try common.execOk(&db.conn, gpa,
        \\CREATE TABLE users (
        \\  id   INT PRIMARY KEY AUTO_INCREMENT,
        \\  name VARCHAR(32) NOT NULL,
        \\  age  INT NULL
        \\) ENGINE=InnoDB
    );

    // INSERT binds a struct: field order maps to the `?` placeholders. A null
    // optional becomes SQL NULL. The same prepared statement is reused each
    // iteration straight from the cache.
    const NewUser = struct { name: []const u8, age: ?i32 };
    const new_users = [_]NewUser{
        .{ .name = "alice", .age = 30 },
        .{ .name = "bob", .age = null },
        .{ .name = "carol", .age = 25 },
    };
    for (new_users) |u| {
        const ok = try db.conn.exec(gpa, "INSERT INTO users (name, age) VALUES (?, ?)", u);
        common.print("inserted {s} -> id {d}\n", .{ u.name, ok.last_insert_id });
    }

    // SELECT with a bound parameter, collected into typed rows.
    const Row = struct { id: i32, name: []const u8, age: ?i32 };
    var rows = try db.conn.queryAllParams(
        Row,
        gpa,
        "SELECT id, name, age FROM users WHERE age >= ? OR age IS NULL ORDER BY id",
        .{@as(i32, 26)},
    );
    defer rows.deinit();
    common.print("matched {d} rows:\n", .{rows.rows.len});
    for (rows.rows) |r| common.print("  #{d} {s} age={?d}\n", .{ r.id, r.name, r.age });

    // UPDATE / DELETE report affected_rows in the OK summary.
    const upd = try db.conn.exec(gpa, "UPDATE users SET age = age + 1 WHERE age IS NOT NULL", .{});
    common.print("aged {d} users\n", .{upd.affected_rows});

    const del = try db.conn.exec(gpa, "DELETE FROM users WHERE name = ?", .{@as([]const u8, "bob")});
    common.print("deleted {d} rows\n", .{del.affected_rows});

    var cnt = try db.conn.queryOne(struct { c: u64 }, gpa, "SELECT COUNT(*) AS c FROM users");
    defer cnt.deinit();
    common.print("remaining: {d}\n", .{(try cnt.one()).c});

    try common.execOk(&db.conn, gpa, "DROP TABLE users");
}
