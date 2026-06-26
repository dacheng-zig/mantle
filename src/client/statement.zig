const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;
const connection = @import("connection.zig");
const Connection = connection.Connection;

pub const PreparedStatement = struct {
    id: u32,
    params: []protocol.text_result.ColumnDefinition41,
    columns: []protocol.text_result.ColumnDefinition41,
    conn: ?*Connection = null,
    closed: bool = false,

    pub fn deinit(self: *PreparedStatement, allocator: std.mem.Allocator) void {
        if (!self.closed) {
            if (self.conn) |conn| conn.closeStatement(allocator, self) catch {};
        }
        for (self.params) |*param| {
            param.deinit(allocator);
        }
        allocator.free(self.params);
        for (self.columns) |*column| {
            column.deinit(allocator);
        }
        allocator.free(self.columns);
    }
};

/// MySQL `ER_NEED_REPREPARE`: a cached prepared statement went stale (e.g. the
/// underlying table's schema changed) and must be re-prepared before reuse.
pub const er_need_reprepare: u16 = 1615;

/// Default per-connection prepared-statement cache capacity. Caching is on by
/// default so repeated identical SQL skips the `COM_STMT_PREPARE` +
/// `COM_STMT_CLOSE` round-trips. Set to 0 to disable.
///
/// Tuning note: this is per connection, so the server-side handle count scales
/// as roughly `capacity * pool_size`. With a large pool and many distinct SQL
/// texts this can approach the server's global `max_prepared_stmt_count`
/// (default 16382); workloads issuing many unique statements also thrash
/// prepare/close. Lower the capacity (or disable caching) for such workloads.
pub const default_statement_cache_capacity: usize = 256;

pub const StatementCacheNode = struct {
    /// Owned copy of the SQL text; also the hash-map key.
    sql: []u8,
    statement: PreparedStatement,
    /// Intrusive LRU links (head = most-recently-used).
    prev: ?*StatementCacheNode = null,
    next: ?*StatementCacheNode = null,
};

/// Free a cache node. `send_close` controls whether the server-side statement
/// is closed (`COM_STMT_CLOSE`): true during live eviction, false when the
/// connection is gone/broken or the statement is already stale server-side.
pub fn freeCacheNode(allocator: std.mem.Allocator, node: *StatementCacheNode, send_close: bool) void {
    if (!send_close) node.statement.closed = true;
    node.statement.deinit(allocator);
    allocator.free(node.sql);
    allocator.destroy(node);
}

/// Per-connection LRU cache of prepared statements.
///
/// Statements belong to the connection that created them, so the cache is
/// strictly per-connection and is dropped wholesale when the connection is
/// closed or breaks. Intrusive doubly-linked list for O(1) LRU updates; a
/// `StringHashMap` for O(1) lookup by SQL.
pub const StatementCache = struct {
    capacity: usize = default_statement_cache_capacity,
    map: std.StringHashMapUnmanaged(*StatementCacheNode) = .{},
    head: ?*StatementCacheNode = null,
    tail: ?*StatementCacheNode = null,
    count: usize = 0,

    /// Look up by SQL, promoting a hit to most-recently-used.
    pub fn lookup(self: *StatementCache, sql: []const u8) ?*StatementCacheNode {
        const node = self.map.get(sql) orelse return null;
        self.moveToFront(node);
        return node;
    }

    fn linkFront(self: *StatementCache, node: *StatementCacheNode) void {
        node.prev = null;
        node.next = self.head;
        if (self.head) |h| h.prev = node else self.tail = node;
        self.head = node;
    }

    fn unlinkList(self: *StatementCache, node: *StatementCacheNode) void {
        if (node.prev) |p| p.next = node.next else self.head = node.next;
        if (node.next) |n| n.prev = node.prev else self.tail = node.prev;
        node.prev = null;
        node.next = null;
    }

    fn moveToFront(self: *StatementCache, node: *StatementCacheNode) void {
        if (self.head == node) return;
        self.unlinkList(node);
        self.linkFront(node);
    }

    /// Insert a freshly prepared node as most-recently-used. The node's `sql`
    /// must outlive the entry (the cache borrows it as the map key).
    pub fn insert(self: *StatementCache, allocator: std.mem.Allocator, node: *StatementCacheNode) !void {
        try self.map.put(allocator, node.sql, node);
        self.linkFront(node);
        self.count += 1;
    }

    /// Detach a node from the map and list without freeing it.
    pub fn remove(self: *StatementCache, node: *StatementCacheNode) void {
        _ = self.map.remove(node.sql);
        self.unlinkList(node);
        self.count -= 1;
    }

    pub fn popTail(self: *StatementCache) ?*StatementCacheNode {
        const node = self.tail orelse return null;
        self.remove(node);
        return node;
    }

    /// Free every entry and the map. `send_close` is forwarded to each node.
    pub fn clearAll(self: *StatementCache, allocator: std.mem.Allocator, send_close: bool) void {
        var node = self.head;
        while (node) |n| {
            node = n.next;
            freeCacheNode(allocator, n, send_close);
        }
        self.map.deinit(allocator);
        self.* = .{ .capacity = self.capacity };
    }
};
