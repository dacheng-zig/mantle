//! Transactions: commit, rollback, and a partial rollback to a savepoint.
//!
//!   zig build example-transaction
//!
//! A Transaction is a scope around statements run on the same connection.
//! commit makes the writes durable; rollback (or rollbackTo a savepoint)
//! discards them.

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");
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
    try common.execOk(&db.conn, gpa, "DROP TABLE IF EXISTS accounts");
    try common.execOk(&db.conn, gpa, "CREATE TABLE accounts (id INT PRIMARY KEY, balance INT NOT NULL) ENGINE=InnoDB");
    try common.execOk(&db.conn, gpa, "INSERT INTO accounts (id, balance) VALUES (1, 100), (2, 0)");

    common.print("initial balance:\n", .{});
    try dumpBalances(&db.conn, gpa);

    // Scoped transact: the closure body runs inside a transaction that commits
    // when the body returns and rolls back if it fails. No errdefer to forget.
    try db.conn.transact(gpa, gpa, struct {
        fn run(a: std.mem.Allocator, tx: *mantle.Transaction) !void {
            try common.execOk(tx.conn, a, "UPDATE accounts SET balance = balance - 30 WHERE id = 1");
            try common.execOk(tx.conn, a, "UPDATE accounts SET balance = balance + 30 WHERE id = 2");
        }
    }.run);
    common.print("after commit:\n", .{});
    try dumpBalances(&db.conn, gpa);

    // Returning an error from the body rolls the whole transaction back.
    db.conn.transact(gpa, gpa, struct {
        fn run(a: std.mem.Allocator, tx: *mantle.Transaction) !void {
            try common.execOk(tx.conn, a, "UPDATE accounts SET balance = 0 WHERE id = 1");
            return error.Abort; // discards the write above
        }
    }.run) catch |err| switch (err) {
        error.Abort => {},
        else => return err,
    };
    common.print("after rollback (unchanged):\n", .{});
    try dumpBalances(&db.conn, gpa);

    // The manual guard is still available when control flow does not fit a
    // single closure body.
    {
        var tx = try db.conn.begin(gpa);
        errdefer tx.deinit(gpa);
        try common.execOk(&db.conn, gpa, "UPDATE accounts SET balance = balance WHERE id = 1");
        try tx.commit(gpa);
    }

    // Savepoint: keep the +5, drop the +1000 by rolling back to the savepoint.
    {
        var tx = try db.conn.begin(gpa);
        errdefer tx.deinit(gpa);
        try common.execOk(&db.conn, gpa, "UPDATE accounts SET balance = balance + 5 WHERE id = 1");
        try tx.savepoint(gpa, "bonus");
        try common.execOk(&db.conn, gpa, "UPDATE accounts SET balance = balance + 1000 WHERE id = 1");
        try tx.rollbackTo(gpa, "bonus");
        try tx.commit(gpa);
    }
    common.print("after savepoint rollback (+5 only):\n", .{});
    try dumpBalances(&db.conn, gpa);

    try common.execOk(&db.conn, gpa, "DROP TABLE accounts");
}

fn dumpBalances(conn: *mantle.Connection, gpa: std.mem.Allocator) !void {
    var t = try conn.queryAll(struct { id: i32, balance: i32 }, gpa, "SELECT id, balance FROM accounts ORDER BY id");
    defer t.deinit();
    for (t.rows) |r| common.print("  account {d}: {d}\n", .{ r.id, r.balance });
}
