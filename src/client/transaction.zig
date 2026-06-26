const std = @import("std");

const connection = @import("connection.zig");
const Connection = connection.Connection;

/// SQL transaction isolation level.
pub const IsolationLevel = enum {
    read_uncommitted,
    read_committed,
    repeatable_read,
    serializable,
};

/// Transaction access mode.
pub const AccessMode = enum { read_write, read_only };

/// Options for `Connection.beginWith`. A null field uses the server/session
/// default for that aspect.
pub const TxOptions = struct {
    isolation: ?IsolationLevel = null,
    access_mode: ?AccessMode = null,
};

pub fn isolationLevelSql(level: IsolationLevel) []const u8 {
    return switch (level) {
        .read_uncommitted => "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED",
        .read_committed => "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        .repeatable_read => "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        .serializable => "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    };
}

pub fn startTransactionSql(access_mode: ?AccessMode) []const u8 {
    return switch (access_mode orelse return "START TRANSACTION") {
        .read_write => "START TRANSACTION READ WRITE",
        .read_only => "START TRANSACTION READ ONLY",
    };
}

/// Build `<verb> `<name>`` with `name` backtick-quoted (internal backticks
/// doubled) so a savepoint identifier can never break out of the statement.
fn buildSavepointSql(allocator: std.mem.Allocator, verb: []const u8, name: []const u8) ![]u8 {
    if (name.len == 0) return error.InvalidSavepointName;

    var sql: std.ArrayList(u8) = .empty;
    errdefer sql.deinit(allocator);
    try sql.appendSlice(allocator, verb);
    try sql.append(allocator, '`');
    for (name) |ch| {
        if (ch == '`') try sql.append(allocator, '`'); // double internal backticks
        try sql.append(allocator, ch);
    }
    try sql.append(allocator, '`');
    return sql.toOwnedSlice(allocator);
}

/// Transaction guard returned by `Connection.begin`. Holds the connection for
/// the lifetime of the transaction. `deinit` performs a best-effort rollback if
/// the transaction was neither committed nor rolled back.
pub const Transaction = struct {
    conn: *Connection,
    finished: bool = false,

    /// Mark the transaction finished and release the connection's transaction
    /// ownership. Idempotent for the connection flag.
    fn markFinished(self: *Transaction) void {
        self.finished = true;
        self.conn.in_transaction = false;
    }

    pub fn commit(self: *Transaction, allocator: std.mem.Allocator) !void {
        try self.conn.execSimple(allocator, "COMMIT");
        self.markFinished();
    }

    pub fn rollback(self: *Transaction, allocator: std.mem.Allocator) !void {
        self.markFinished();
        self.conn.execSimple(allocator, "ROLLBACK") catch |err| {
            // A failed rollback leaves the transaction in an unknown state, so
            // the connection can no longer be trusted.
            self.conn.broken = true;
            return err;
        };
    }

    /// Create a savepoint within the transaction (`SAVEPOINT name`).
    pub fn savepoint(self: *Transaction, allocator: std.mem.Allocator, name: []const u8) !void {
        const sql = try buildSavepointSql(allocator, "SAVEPOINT ", name);
        defer allocator.free(sql);
        try self.conn.execSimple(allocator, sql);
    }

    /// Roll back to a savepoint, discarding work done after it while keeping the
    /// transaction (and the savepoint) open (`ROLLBACK TO SAVEPOINT name`).
    pub fn rollbackTo(self: *Transaction, allocator: std.mem.Allocator, name: []const u8) !void {
        const sql = try buildSavepointSql(allocator, "ROLLBACK TO SAVEPOINT ", name);
        defer allocator.free(sql);
        try self.conn.execSimple(allocator, sql);
    }

    /// Release a savepoint without affecting the transaction
    /// (`RELEASE SAVEPOINT name`).
    pub fn releaseSavepoint(self: *Transaction, allocator: std.mem.Allocator, name: []const u8) !void {
        const sql = try buildSavepointSql(allocator, "RELEASE SAVEPOINT ", name);
        defer allocator.free(sql);
        try self.conn.execSimple(allocator, sql);
    }

    /// Run `body` inside a savepoint scope: create `name`, then release it on
    /// success or `ROLLBACK TO SAVEPOINT name` on any error (keeping the
    /// transaction itself open), then propagate the error. Mirrors `transact`
    /// at savepoint granularity. A failed `ROLLBACK TO` marks the connection
    /// broken.
    pub fn withSavepoint(
        self: *Transaction,
        allocator: std.mem.Allocator,
        name: []const u8,
        ctx: anytype,
        comptime body: fn (@TypeOf(ctx), *Transaction) anyerror!void,
    ) !void {
        try self.savepoint(allocator, name);
        body(ctx, self) catch |err| {
            self.rollbackTo(allocator, name) catch {
                self.conn.broken = true;
            };
            return err;
        };
        try self.releaseSavepoint(allocator, name);
    }

    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        if (self.finished) return;
        self.markFinished();
        if (self.conn.isBroken()) return;
        // A failed best-effort rollback leaves the transaction in an unknown
        // state; mark the connection broken so the pool retires it rather than
        // reusing a connection that may still hold an open transaction. Mirrors
        // the explicit `rollback()` contract above.
        self.conn.execSimple(allocator, "ROLLBACK") catch {
            self.conn.broken = true;
        };
    }
};

test "buildSavepointSql backtick-quotes and escapes the identifier" {
    const allocator = std.testing.allocator;

    const plain = try buildSavepointSql(allocator, "SAVEPOINT ", "sp1");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("SAVEPOINT `sp1`", plain);

    // Internal backticks are doubled so the name cannot break out.
    const tricky = try buildSavepointSql(allocator, "ROLLBACK TO SAVEPOINT ", "we`ird");
    defer allocator.free(tricky);
    try std.testing.expectEqualStrings("ROLLBACK TO SAVEPOINT `we``ird`", tricky);

    try std.testing.expectError(error.InvalidSavepointName, buildSavepointSql(allocator, "SAVEPOINT ", ""));
}
