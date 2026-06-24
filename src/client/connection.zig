const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;
const column_reader = @import("../result/column_reader.zig");

const result_row = @import("../result/row.zig");
const TextRowResult = result_row.TextRowResult;
const BinaryRowResult = result_row.BinaryRowResult;

const Table = @import("table.zig").Table;

const transaction = @import("transaction.zig");
const Transaction = transaction.Transaction;
const TxOptions = transaction.TxOptions;
const isolationLevelSql = transaction.isolationLevelSql;
const startTransactionSql = transaction.startTransactionSql;

const statement_mod = @import("statement.zig");
const PreparedStatement = statement_mod.PreparedStatement;
const StatementCache = statement_mod.StatementCache;
const StatementCacheNode = statement_mod.StatementCacheNode;
const er_need_reprepare = statement_mod.er_need_reprepare;
const freeCacheNode = statement_mod.freeCacheNode;

pub const OkSummary = mantle.transport.OkSummary;
pub const ServerError = mantle.transport.ServerError;

/// Scoped logger for mantle's SQL diagnostics — server errors (`.warn`) and
/// statement tracing (`.debug`), tunable via the `.mantle` log scope.
const log = std.log.scoped(.mantle);

/// Trace one issued statement. `.debug`, not `.warn`: high-volume hot-path
/// logging, silent unless the `.mantle` scope opts in.
fn logSql(sql: []const u8) void {
    log.debug("sql: {s}", .{sql});
}

/// Result of a non-streaming command. The `err` variant owns its message;
/// call `deinit` once done. Use `expectOk` to collapse to an `OkSummary` or a
/// Zig error.
pub const QueryResult = mantle.transport.QueryResponse;

pub const DateTime = column_reader.DateTime;
pub const Time = column_reader.Time;
pub const Decimal = column_reader.Decimal;

pub const TextResult = struct {
    conn: *Connection,
    columns: []protocol.text_result.ColumnDefinition41,

    pub fn deinit(self: *TextResult, allocator: std.mem.Allocator) void {
        for (self.columns) |*column| {
            column.deinit(allocator);
        }
        allocator.free(self.columns);
    }

    pub fn next(self: *TextResult, allocator: std.mem.Allocator) !TextRowResult {
        var row = try self.conn.transport.readTextRow(allocator);
        if (row.server_error) |err| {
            self.conn.captureError(allocator, err);
            row.server_error = null;
        }
        return .{
            .tag = switch (row.tag) {
                .row => .row,
                .eof => .eof,
                .err => .err,
            },
            .values = row.values,
            .transport_row = row,
        };
    }

    pub fn drain(self: *TextResult, allocator: std.mem.Allocator) !void {
        while (true) {
            var row = try self.next(allocator);
            defer row.deinit(allocator);
            switch (row.tag) {
                .row => {},
                .eof => break,
                .err => return error.ServerError,
            }
        }
        try self.conn.drainRemainingResults(allocator);
    }
};

pub const BinaryResult = struct {
    conn: *Connection,
    columns: []protocol.text_result.ColumnDefinition41,

    pub fn deinit(self: *BinaryResult, allocator: std.mem.Allocator) void {
        for (self.columns) |*column| {
            column.deinit(allocator);
        }
        allocator.free(self.columns);
    }

    pub fn next(self: *BinaryResult, allocator: std.mem.Allocator) !BinaryRowResult {
        var row = try self.conn.transport.readBinaryRow(allocator, self.columns);
        if (row.server_error) |err| {
            self.conn.captureError(allocator, err);
            row.server_error = null;
        }
        return .{
            .tag = switch (row.tag) {
                .row => .row,
                .eof => .eof,
                .err => .err,
            },
            .values = row.values,
            .transport_row = row,
        };
    }

    pub fn drain(self: *BinaryResult, allocator: std.mem.Allocator) !void {
        while (true) {
            var row = try self.next(allocator);
            defer row.deinit(allocator);
            switch (row.tag) {
                .row => {},
                .eof => break,
                .err => return error.ServerError,
            }
        }
        try self.conn.drainRemainingResults(allocator);
    }
};

pub const Connection = struct {
    transport: mantle.Transport,
    /// Set when an I/O or protocol error desynchronizes the byte stream. A
    /// broken connection refuses further commands and must not be pooled.
    broken: bool = false,
    /// Set after an explicit graceful close. Closed connections refuse further
    /// commands but are not protocol-broken.
    closed: bool = false,
    /// Last structured server error swallowed into a Zig error on a path that
    /// does not return the `QueryResult` union (queryRows/executeRows/exec/ping).
    /// Owned; released by `deinit` or overwritten by the next captured error.
    last_error: ?ServerError = null,
    /// Per-connection prepared-statement cache. On by
    /// default; transparently reused by `exec`/`queryAllParams`/`queryOneParams`.
    statement_cache: StatementCache = .{},
    /// Set while a transaction is open on this connection; a transaction owns
    /// the connection exclusively. Guards against a second `begin` silently
    /// triggering MySQL's implicit commit. Cleared by commit/rollback/deinit/reset.
    in_transaction: bool = false,

    pub fn init(
        io: mantle.transport.Transport.Io,
        options: mantle.ConnectionPhase.Options,
    ) Connection {
        return .{ .transport = mantle.Transport.init(io, options) };
    }

    pub fn deinit(self: *Connection, allocator: std.mem.Allocator) void {
        // The statements die with the connection (COM_QUIT / socket close frees
        // them server-side), so skip per-statement COM_STMT_CLOSE here.
        self.statement_cache.clearAll(allocator, false);
        if (self.last_error) |*err| err.deinit(allocator);
        self.last_error = null;
    }

    /// Resize the prepared-statement cache. `0` disables caching and drops any
    /// existing entries (closing them server-side while the connection is live).
    pub fn setStatementCacheCapacity(self: *Connection, allocator: std.mem.Allocator, capacity: usize) void {
        self.statement_cache.capacity = capacity;
        if (capacity == 0) {
            self.statement_cache.clearAll(allocator, !self.isBroken() and !self.closed);
            return;
        }
        while (self.statement_cache.count > capacity) {
            const old = self.statement_cache.popTail() orelse break;
            freeCacheNode(allocator, old, !self.isBroken() and !self.closed);
        }
    }

    /// Get a cached prepared statement for `sql`, preparing and caching it on a
    /// miss. The returned node is owned by the cache (or transiently held when
    /// caching is disabled); pair every call with `releaseStatement`.
    fn cachedStatement(self: *Connection, allocator: std.mem.Allocator, sql: []const u8) !*StatementCacheNode {
        if (self.statement_cache.lookup(sql)) |node| return node;

        var stmt = try self.prepare(allocator, sql);
        errdefer stmt.deinit(allocator);
        const node = try allocator.create(StatementCacheNode);
        errdefer allocator.destroy(node);
        const key = try allocator.dupe(u8, sql);
        errdefer allocator.free(key);
        node.* = .{ .sql = key, .statement = stmt };
        try self.statement_cache.insert(allocator, node);

        // Evict the least-recently-used entries past the cap (never the one we
        // just inserted; it is at the head). Skipped when caching is disabled.
        if (self.statement_cache.capacity != 0) {
            while (self.statement_cache.count > self.statement_cache.capacity) {
                const old = self.statement_cache.popTail() orelse break;
                freeCacheNode(allocator, old, true);
            }
        }
        return node;
    }

    /// Return a node obtained from `cachedStatement`. Retained when caching is
    /// enabled; closed and freed when disabled.
    fn releaseStatement(self: *Connection, allocator: std.mem.Allocator, node: *StatementCacheNode) void {
        if (self.statement_cache.capacity != 0) return;
        self.statement_cache.remove(node);
        freeCacheNode(allocator, node, !self.isBroken() and !self.closed);
    }

    /// Drop a stale cached statement after `ER_NEED_REPREPARE`. The server-side
    /// id is already invalid, so no `COM_STMT_CLOSE` is sent.
    fn evictForReprepare(self: *Connection, allocator: std.mem.Allocator, node: *StatementCacheNode) void {
        self.statement_cache.remove(node);
        freeCacheNode(allocator, node, false);
    }

    pub fn close(self: *Connection, allocator: std.mem.Allocator) !void {
        try self.ensureUsable();
        errdefer |err| self.classifyError(err);
        try self.transport.sendNoResponseCommand(allocator, .quit);
        self.closed = true;
    }

    /// True if the connection can no longer be used safely (I/O/protocol
    /// desync or an unrecoverable handshake/auth failure).
    pub fn isBroken(self: *const Connection) bool {
        return self.broken or self.transport.packet_stream.phase.state == .failed;
    }

    pub fn canReuse(self: *const Connection) bool {
        return !self.closed and !self.isBroken() and self.transport.packet_stream.phase.state == .ready;
    }

    /// The last server error captured on a swallowing path, if any. Borrowed;
    /// valid until the next captured error or `deinit`.
    pub fn lastError(self: *const Connection) ?ServerError {
        return self.last_error;
    }

    /// The server-side connection/thread id from the handshake. Use it to
    /// cancel an in-flight query on this connection by issuing
    /// `KILL QUERY <id>` from another connection — e.g.
    /// `TcpPool.killQuery`. Zero before the handshake completes.
    pub fn serverThreadId(self: *const Connection) u32 {
        return self.transport.packet_stream.phase.server_connection_id;
    }

    /// Force the connection unusable. Use after a soft cancel / command timeout
    /// where a `KILL QUERY` may still be in flight: the
    /// connection might carry a pending cancellation, so it must not be reused
    /// or returned to a pool. The pool destroys it on release.
    pub fn markBroken(self: *Connection) void {
        self.broken = true;
    }

    fn ensureUsable(self: *Connection) !void {
        if (self.closed) return error.ConnectionClosed;
        if (self.isBroken()) return error.ConnectionBroken;
    }

    /// Mark the connection broken for errors that desynchronize the stream or
    /// otherwise make it unusable. Soft errors (validation, drained server
    /// errors) leave it reusable.
    fn classifyError(self: *Connection, err: anyerror) void {
        switch (err) {
            error.ConnectionBroken,
            error.ConnectionClosed,
            error.ServerError,
            error.UnexpectedOk,
            error.OutOfMemory,
            error.PreparedParameterCountMismatch,
            error.PreparedParameterIndexOutOfBounds,
            error.PreparedStatementClosed,
            error.PreparedStatementWrongConnection,
            error.UnsupportedPreparedParameters,
            => {},
            else => self.broken = true,
        }
    }

    /// Take ownership of `err`, replacing any previously captured one. As the
    /// sole funnel for swallowed server errors, it also logs them, so callers
    /// that never read `lastError()` still see the code, SQLSTATE, and message.
    fn captureError(self: *Connection, allocator: std.mem.Allocator, err: ServerError) void {
        // `.warn`, not `.err`: a server error is an application outcome
        // (duplicate key, constraint violation, ...), not a driver fault — the
        // caller decides whether it is fatal.
        if (err.sql_state) |state| {
            log.warn("server error {d} ({s}): {s}", .{ err.code, &state, err.message });
        } else {
            log.warn("server error {d}: {s}", .{ err.code, err.message });
        }
        if (self.last_error) |*prev| prev.deinit(allocator);
        self.last_error = err;
    }

    fn cloneAndCaptureError(self: *Connection, allocator: std.mem.Allocator, err: ServerError) !void {
        const last_error = try ServerError.cloneFrom(allocator, err);
        self.captureError(allocator, last_error);
    }

    fn clearLastError(self: *Connection, allocator: std.mem.Allocator) void {
        if (self.last_error) |*err| err.deinit(allocator);
        self.last_error = null;
    }

    fn ensureStatementUsable(self: *Connection, statement: *const PreparedStatement) !void {
        if (statement.conn) |owner| {
            if (owner != self) return error.PreparedStatementWrongConnection;
        }
        if (statement.closed) return error.PreparedStatementClosed;
    }

    pub fn finishHandshake(self: *Connection, allocator: std.mem.Allocator) !void {
        // Drive the handshake/auth exchange to completion. The number of server
        // packets depends on the auth plugin: mysql_native_password sends the
        // handshake then OK (2 reads), while caching_sha2_password fast-auth
        // inserts a "fast auth success" packet before OK (3 reads). Loop until
        // the phase reaches a terminal state instead of assuming a fixed count.
        while (true) {
            switch (self.transport.packet_stream.phase.state) {
                .ready => return,
                .failed => return error.HandshakeFailed,
                else => _ = try self.transport.receiveNext(allocator),
            }
        }
    }

    /// Run a parameterless statement that is expected to return OK (no rows),
    /// e.g. transaction control. Server errors are captured into `last_error`.
    pub fn execSimple(self: *Connection, allocator: std.mem.Allocator, sql: []const u8) !void {
        var result = try self.query(allocator, sql);
        switch (result) {
            .ok => {},
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                result.deinit(allocator);
                self.broken = true;
                return error.UnexpectedResultSet;
            },
        }
    }

    fn drainRemainingResults(self: *Connection, allocator: std.mem.Allocator) !void {
        while (self.transport.packet_stream.phase.state != .ready) {
            const response = try self.transport.readQueryResponse(allocator);
            switch (response) {
                .ok => {},
                .err => |err| {
                    self.captureError(allocator, err);
                    return error.ServerError;
                },
                .result_set => {
                    const columns = try self.transport.readTextResultMetadata(allocator);
                    defer freeColumns(allocator, columns);
                    switch (self.transport.packet_stream.result_format) {
                        .text => try self.drainTextRows(allocator),
                        .binary => try self.drainBinaryRows(allocator, columns),
                    }
                },
            }
        }
    }

    fn drainTextRows(self: *Connection, allocator: std.mem.Allocator) !void {
        while (true) {
            var row = try self.transport.readTextRow(allocator);
            defer row.deinit(allocator);
            if (row.server_error) |err| {
                self.captureError(allocator, err);
                row.server_error = null;
            }
            switch (row.tag) {
                .row => {},
                .eof => return,
                .err => return error.ServerError,
            }
        }
    }

    fn drainBinaryRows(
        self: *Connection,
        allocator: std.mem.Allocator,
        columns: []const protocol.text_result.ColumnDefinition41,
    ) !void {
        while (true) {
            var row = try self.transport.readBinaryRow(allocator, columns);
            defer row.deinit(allocator);
            if (row.server_error) |err| {
                self.captureError(allocator, err);
                row.server_error = null;
            }
            switch (row.tag) {
                .row => {},
                .eof => return,
                .err => return error.ServerError,
            }
        }
    }

    /// Begin a transaction and return a manual guard. The guard rolls back on
    /// `deinit` unless `commit` (or `rollback`) was called. Prefer the scoped
    /// `transact` for most call sites; reach for the guard when control flow
    /// does not fit a single closure body:
    ///
    ///     var tx = try conn.begin(allocator);
    ///     errdefer tx.deinit(allocator); // auto-rollback if not committed
    ///     try conn.exec(allocator, "UPDATE ...", .{...});
    ///     try tx.commit(allocator);
    pub fn begin(self: *Connection, allocator: std.mem.Allocator) !Transaction {
        return self.beginWith(allocator, .{});
    }

    /// Begin a transaction with an explicit isolation level and/or access mode.
    /// The isolation level, when set, is applied with
    /// `SET TRANSACTION ISOLATION LEVEL ...`, which scopes it to this next
    /// transaction only. Returns the same manual guard as `begin`.
    ///
    /// Returns `error.TransactionActive` if a transaction is already open on
    /// this connection, since nesting `START TRANSACTION` would silently commit
    /// the outer one — a transaction owns the connection.
    pub fn beginWith(self: *Connection, allocator: std.mem.Allocator, options: TxOptions) !Transaction {
        if (self.in_transaction) return error.TransactionActive;
        if (options.isolation) |level| {
            try self.execSimple(allocator, isolationLevelSql(level));
        }
        try self.execSimple(allocator, startTransactionSql(options.access_mode));
        self.in_transaction = true;
        return .{ .conn = self };
    }

    /// Run `body` inside a transaction, committing on success and rolling back
    /// on any error. This is the safe default: the
    /// commit/rollback decision can never be forgotten the way an `errdefer
    /// tx.deinit` can. `body` reaches the connection via `tx.conn`; return
    /// outputs through a pointer `ctx`.
    ///
    ///     const Ctx = struct { gpa: std.mem.Allocator };
    ///     try conn.transact(gpa, Ctx{ .gpa = gpa }, struct {
    ///         fn run(c: Ctx, tx: *mantle.Transaction) !void {
    ///             _ = try tx.conn.exec(c.gpa, "UPDATE ...", .{});
    ///         }
    ///     }.run);
    pub fn transact(
        self: *Connection,
        allocator: std.mem.Allocator,
        ctx: anytype,
        comptime body: fn (@TypeOf(ctx), *Transaction) anyerror!void,
    ) !void {
        return self.transactWith(allocator, .{}, ctx, body);
    }

    /// Like `transact` but with an explicit isolation level and/or access mode.
    /// If `body` commits or rolls back itself, this honors that and does not act
    /// again. A failed rollback marks the connection broken.
    pub fn transactWith(
        self: *Connection,
        allocator: std.mem.Allocator,
        options: TxOptions,
        ctx: anytype,
        comptime body: fn (@TypeOf(ctx), *Transaction) anyerror!void,
    ) !void {
        var tx = try self.beginWith(allocator, options);
        body(ctx, &tx) catch |err| {
            if (!tx.finished) tx.rollback(allocator) catch {};
            return err;
        };
        if (!tx.finished) try tx.commit(allocator);
    }

    /// Run a text query and collect every row into an owned `Table(T)`. Each
    /// row is scanned into `T`; `[]const u8` fields are duplicated into the
    /// table's arena, so the result is fully owned and freed by a single
    /// `Table.deinit`.
    pub fn queryAll(
        self: *Connection,
        comptime T: type,
        allocator: std.mem.Allocator,
        sql: []const u8,
    ) !Table(T) {
        var rows_result = try self.queryRows(allocator, sql);
        defer rows_result.deinit(allocator);
        errdefer |err| self.classifyError(err);

        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        var list: std.ArrayList(T) = .empty;
        while (true) {
            var row = try rows_result.next(allocator);
            defer row.deinit(allocator);
            switch (row.tag) {
                .eof => break,
                .err => return error.ServerError,
                .row => {
                    var item: T = undefined;
                    try row.scanAlloc(&item, rows_result.columns, arena_allocator);
                    try list.append(arena_allocator, item);
                },
            }
        }

        return .{ .rows = list.items, .arena = arena, .base = allocator };
    }

    /// Like `queryAll` but expects exactly one row, returning
    /// `error.UnexpectedRowCount` otherwise. The single row is `table.rows[0]`
    /// (or `table.one()`).
    pub fn queryOne(
        self: *Connection,
        comptime T: type,
        allocator: std.mem.Allocator,
        sql: []const u8,
    ) !Table(T) {
        var table = try self.queryAll(T, allocator, sql);
        errdefer table.deinit();
        if (table.rows.len != 1) return error.UnexpectedRowCount;
        return table;
    }

    /// Prepare `sql`, bind `params`, execute it, and collect every binary row
    /// into an owned `Table(T)`. String fields are duplicated into the table
    /// arena, matching `queryAll` ownership semantics.
    pub fn queryAllParams(
        self: *Connection,
        comptime T: type,
        allocator: std.mem.Allocator,
        sql: []const u8,
        params: anytype,
    ) !Table(T) {
        try self.ensureUsable();
        logSql(sql);
        var attempts: u8 = 0;
        while (true) {
            const node = try self.cachedStatement(allocator, sql);
            var rows_result = self.executeRows(allocator, &node.statement, params) catch |err| {
                // A stale cached statement surfaces as ER_NEED_REPREPARE here;
                // drop it and prepare fresh once.
                if (err == error.ServerError and attempts == 0 and self.statement_cache.capacity != 0) {
                    if (self.lastError()) |last| {
                        if (last.code == er_need_reprepare) {
                            self.evictForReprepare(allocator, node);
                            attempts += 1;
                            continue;
                        }
                    }
                }
                self.releaseStatement(allocator, node);
                return err;
            };
            defer rows_result.deinit(allocator);

            const table = self.collectRows(T, allocator, &rows_result) catch |err| {
                self.releaseStatement(allocator, node);
                return err;
            };
            self.releaseStatement(allocator, node);
            return table;
        }
    }

    /// Drain a binary result set into an owned `Table(T)` backed by an arena.
    fn collectRows(
        self: *Connection,
        comptime T: type,
        allocator: std.mem.Allocator,
        rows_result: *BinaryResult,
    ) !Table(T) {
        errdefer |err| self.classifyError(err);

        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        var list: std.ArrayList(T) = .empty;
        while (true) {
            var row = try rows_result.next(allocator);
            defer row.deinit(allocator);
            switch (row.tag) {
                .eof => break,
                .err => return error.ServerError,
                .row => {
                    var item: T = undefined;
                    try row.scanAlloc(&item, rows_result.columns, arena_allocator);
                    try list.append(arena_allocator, item);
                },
            }
        }

        return .{ .rows = list.items, .arena = arena, .base = allocator };
    }

    /// Like `queryAllParams` but expects exactly one row, returning
    /// `error.UnexpectedRowCount` otherwise.
    pub fn queryOneParams(
        self: *Connection,
        comptime T: type,
        allocator: std.mem.Allocator,
        sql: []const u8,
        params: anytype,
    ) !Table(T) {
        var table = try self.queryAllParams(T, allocator, sql, params);
        errdefer table.deinit();
        if (table.rows.len != 1) return error.UnexpectedRowCount;
        return table;
    }

    pub fn ping(self: *Connection, allocator: std.mem.Allocator) !void {
        try self.ensureUsable();
        errdefer |err| self.classifyError(err);
        try self.transport.sendCommand(allocator, .ping);
        var response = try self.transport.readQueryResponse(allocator);
        switch (response) {
            .ok => self.clearLastError(allocator),
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                response.deinit(allocator);
                return error.UnexpectedResultSet;
            },
        }
    }

    pub fn reset(self: *Connection, allocator: std.mem.Allocator) !void {
        try self.ensureUsable();
        errdefer |err| self.classifyError(err);
        try self.transport.sendCommand(allocator, .reset_connection);
        var response = try self.transport.readQueryResponse(allocator);
        switch (response) {
            // reset_connection rolls back any open transaction server-side.
            .ok => {
                self.in_transaction = false;
                self.clearLastError(allocator);
            },
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                response.deinit(allocator);
                self.broken = true;
                return error.UnexpectedResultSet;
            },
        }
    }

    pub fn query(
        self: *Connection,
        allocator: std.mem.Allocator,
        sql: []const u8,
    ) !QueryResult {
        try self.ensureUsable();
        var diagnostic_capture_failed = false;
        errdefer |err| if (!diagnostic_capture_failed) self.classifyError(err);
        logSql(sql);
        try self.transport.sendCommand(allocator, protocol.command.Command.initQuery(sql));
        var response = try self.transport.readQueryResponse(allocator);
        errdefer response.deinit(allocator);
        if (response == .err) {
            const last_error = ServerError.cloneFrom(allocator, response.err) catch {
                diagnostic_capture_failed = true;
                return error.OutOfMemory;
            };
            self.captureError(allocator, last_error);
        } else {
            self.clearLastError(allocator);
        }
        return response;
    }

    pub fn queryRows(
        self: *Connection,
        allocator: std.mem.Allocator,
        sql: []const u8,
    ) !TextResult {
        try self.ensureUsable();
        errdefer |err| self.classifyError(err);
        logSql(sql);
        try self.transport.sendCommand(allocator, protocol.command.Command.initQuery(sql));
        const response = try self.transport.readQueryResponse(allocator);
        switch (response) {
            .ok => {
                self.clearLastError(allocator);
                return error.UnexpectedOk;
            },
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                const columns = try self.transport.readTextResultMetadata(allocator);
                self.clearLastError(allocator);
                return .{ .conn = self, .columns = columns };
            },
        }
    }

    pub fn prepare(
        self: *Connection,
        allocator: std.mem.Allocator,
        sql: []const u8,
    ) !PreparedStatement {
        try self.ensureUsable();
        errdefer |err| self.classifyError(err);
        try self.transport.sendCommand(allocator, protocol.command.Command.initStmtPrepare(sql));
        var response = try self.transport.readPrepareResponse(allocator);
        const prepare_ok = switch (response) {
            .ok => |ok| ok,
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
        };
        defer response.deinit(allocator);

        const params = try self.transport.readColumnDefinitions(allocator, prepare_ok.parameter_count);
        errdefer freeColumns(allocator, params);
        const columns = try self.transport.readColumnDefinitions(allocator, prepare_ok.column_count);
        errdefer freeColumns(allocator, columns);

        self.clearLastError(allocator);
        return .{
            .id = prepare_ok.statement_id,
            .params = params,
            .columns = columns,
            .conn = self,
        };
    }

    pub fn closeStatement(self: *Connection, allocator: std.mem.Allocator, statement: *PreparedStatement) !void {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        errdefer |err| self.classifyError(err);
        try self.transport.sendNoResponseCommand(allocator, protocol.command.Command.initStmtClose(statement.id));
        statement.closed = true;
    }

    pub fn sendLongData(
        self: *Connection,
        allocator: std.mem.Allocator,
        statement: *const PreparedStatement,
        param_id: u16,
        data: []const u8,
    ) !void {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        if (param_id >= statement.params.len) return error.PreparedParameterIndexOutOfBounds;
        errdefer |err| self.classifyError(err);
        try self.transport.sendNoResponseCommand(
            allocator,
            protocol.command.Command.initStmtSendLongData(statement.id, param_id, data),
        );
    }

    pub fn resetStatement(self: *Connection, allocator: std.mem.Allocator, statement: *const PreparedStatement) !void {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        errdefer |err| self.classifyError(err);
        try self.transport.sendCommand(allocator, protocol.command.Command.initStmtReset(statement.id));
        var response = try self.transport.readQueryResponse(allocator);
        switch (response) {
            .ok => self.clearLastError(allocator),
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                response.deinit(allocator);
                self.broken = true;
                return error.UnexpectedResultSet;
            },
        }
    }

    /// High-level convenience for a non-row command: prepare the statement,
    /// bind `params`, execute, and return the server OK summary. The prepared
    /// statement is closed server-side and freed before returning.
    ///
    /// Intended for INSERT/UPDATE/DELETE/DDL. A row-producing statement yields
    /// `error.UnexpectedResultSet`; use `executeRows`/`queryRows` for those.
    pub fn exec(
        self: *Connection,
        allocator: std.mem.Allocator,
        sql: []const u8,
        params: anytype,
    ) !OkSummary {
        try self.ensureUsable();
        logSql(sql);
        var attempts: u8 = 0;
        while (true) {
            const node = try self.cachedStatement(allocator, sql);
            var result = self.executeParams(allocator, &node.statement, params) catch |err| {
                self.releaseStatement(allocator, node);
                return err;
            };
            switch (result) {
                .ok => |ok| {
                    self.releaseStatement(allocator, node);
                    return ok;
                },
                .err => |err| {
                    if (err.code == er_need_reprepare and attempts == 0 and self.statement_cache.capacity != 0) {
                        result.deinit(allocator);
                        self.evictForReprepare(allocator, node);
                        attempts += 1;
                        continue;
                    }
                    // `executeParams` already captured this into `last_error`
                    // (via `cloneAndCaptureError`); capturing again would re-log
                    // the same error. Free the result's copy instead —
                    // `lastError()` stays valid for the caller.
                    result.deinit(allocator);
                    self.releaseStatement(allocator, node);
                    return error.ServerError;
                },
                .result_set => {
                    result.deinit(allocator);
                    // The result set was never drained, so the stream is desynced.
                    self.broken = true;
                    self.releaseStatement(allocator, node);
                    return error.UnexpectedResultSet;
                },
            }
        }
    }

    pub fn execute(
        self: *Connection,
        allocator: std.mem.Allocator,
        statement: *const PreparedStatement,
    ) !QueryResult {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        if (statement.params.len != 0) return error.UnsupportedPreparedParameters;
        errdefer |err| self.classifyError(err);

        try self.transport.sendCommand(allocator, protocol.command.Command.initStmtExecute(statement.id));
        var response = try self.transport.readQueryResponse(allocator);
        errdefer response.deinit(allocator);
        if (response == .err) {
            try self.cloneAndCaptureError(allocator, response.err);
        } else {
            self.clearLastError(allocator);
        }
        return response;
    }

    pub fn executeParams(
        self: *Connection,
        allocator: std.mem.Allocator,
        statement: *const PreparedStatement,
        params: anytype,
    ) !QueryResult {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        if (statement.params.len != protocol.prepared_statement.paramCount(@TypeOf(params))) {
            return error.PreparedParameterCountMismatch;
        }
        errdefer |err| self.classifyError(err);

        var payload = protocol.PayloadWriter.init(allocator);
        defer payload.deinit();
        try protocol.prepared_statement.ExecuteRequest.writeWithParams(&payload, statement.id, params);

        try self.transport.sendCommandPayload(allocator, payload.bytes());
        var response = try self.transport.readQueryResponse(allocator);
        errdefer response.deinit(allocator);
        if (response == .err) {
            try self.cloneAndCaptureError(allocator, response.err);
        } else {
            self.clearLastError(allocator);
        }
        return response;
    }

    pub fn executeRows(
        self: *Connection,
        allocator: std.mem.Allocator,
        statement: *const PreparedStatement,
        params: anytype,
    ) !BinaryResult {
        try self.ensureUsable();
        try self.ensureStatementUsable(statement);
        if (statement.params.len != protocol.prepared_statement.paramCount(@TypeOf(params))) {
            return error.PreparedParameterCountMismatch;
        }
        errdefer |err| self.classifyError(err);

        var payload = protocol.PayloadWriter.init(allocator);
        defer payload.deinit();
        try protocol.prepared_statement.ExecuteRequest.writeWithParams(&payload, statement.id, params);

        try self.transport.sendCommandPayload(allocator, payload.bytes());
        const response = try self.transport.readQueryResponse(allocator);
        switch (response) {
            .ok => {
                self.clearLastError(allocator);
                return error.UnexpectedOk;
            },
            .err => |err| {
                self.captureError(allocator, err);
                return error.ServerError;
            },
            .result_set => {
                const columns = try self.transport.readTextResultMetadata(allocator);
                self.clearLastError(allocator);
                return .{ .conn = self, .columns = columns };
            },
        }
    }
};

fn freeColumns(allocator: std.mem.Allocator, columns: []protocol.text_result.ColumnDefinition41) void {
    for (columns) |*column| {
        column.deinit(allocator);
    }
    allocator.free(columns);
}
