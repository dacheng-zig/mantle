//! Text-protocol queries: decode a single typed row, iterate many rows, and
//! handle SQL NULL with an optional field.
//!
//!   zig build example-query
//!
//! Results scan straight into your own structs — field names match column
//! aliases, field types drive decoding.

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

    // queryOne expects exactly one row and scans it into the struct. A string
    // column borrows from the table's arena and is valid until table.deinit.
    {
        var t = try db.conn.queryOne(
            struct { answer: i64, pi: []const u8 },
            gpa,
            "SELECT 6 * 7 AS answer, '3.14159' AS pi",
        );
        defer t.deinit();
        const row = try t.one();
        common.print("answer={d} pi={s}\n", .{ row.answer, row.pi });
    }

    // Multiple rows: a connection-scoped temporary table, read back with
    // queryAll. The temp table vanishes when the connection closes.
    try common.useScratch(&db.conn, gpa);
    try common.execOk(&db.conn, gpa, "CREATE TEMPORARY TABLE langs (id INT, name VARCHAR(32)) ENGINE=InnoDB");
    try common.execOk(&db.conn, gpa, "INSERT INTO langs (id, name) VALUES (1,'Zig'),(2,'Rust'),(3,'Go')");

    var t = try db.conn.queryAll(
        struct { id: i32, name: []const u8 },
        gpa,
        "SELECT id, name FROM langs ORDER BY id",
    );
    defer t.deinit();
    common.print("{d} rows:\n", .{t.rows.len});
    for (t.rows) |row| common.print("  #{d} {s}\n", .{ row.id, row.name });

    // SQL NULL maps to a Zig optional: an ?i64 field is null when the column is.
    var n = try db.conn.queryOne(struct { maybe: ?i64 }, gpa, "SELECT NULL AS maybe");
    defer n.deinit();
    common.print("maybe is null: {}\n", .{(try n.one()).maybe == null});
}
