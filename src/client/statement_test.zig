const std = @import("std");

const statement = @import("statement.zig");
const StatementCache = statement.StatementCache;
const StatementCacheNode = statement.StatementCacheNode;
const freeCacheNode = statement.freeCacheNode;

fn makeFakeCacheNode(allocator: std.mem.Allocator, sql: []const u8, id: u32) !*StatementCacheNode {
    const node = try allocator.create(StatementCacheNode);
    node.* = .{
        .sql = try allocator.dupe(u8, sql),
        // closed + no conn: deinit frees the (empty) metadata without any I/O.
        .statement = .{ .id = id, .params = &.{}, .columns = &.{}, .conn = null, .closed = true },
    };
    return node;
}

test "statement cache pops entries in least-recently-used order" {
    const allocator = std.testing.allocator;
    var cache = StatementCache{ .capacity = 8 };
    defer cache.clearAll(allocator, false);

    try cache.insert(allocator, try makeFakeCacheNode(allocator, "A", 1));
    try cache.insert(allocator, try makeFakeCacheNode(allocator, "B", 2));
    try cache.insert(allocator, try makeFakeCacheNode(allocator, "C", 3));
    try std.testing.expectEqual(@as(usize, 3), cache.count);

    // Insertion order A,B,C => LRU is A, then B, then C.
    const a = cache.popTail().?;
    try std.testing.expectEqual(@as(u32, 1), a.statement.id);
    freeCacheNode(allocator, a, false);
    const b = cache.popTail().?;
    try std.testing.expectEqual(@as(u32, 2), b.statement.id);
    freeCacheNode(allocator, b, false);
    try std.testing.expectEqual(@as(usize, 1), cache.count);
}

test "statement cache lookup promotes to most-recently-used" {
    const allocator = std.testing.allocator;
    var cache = StatementCache{ .capacity = 8 };
    defer cache.clearAll(allocator, false);

    try cache.insert(allocator, try makeFakeCacheNode(allocator, "A", 1));
    try cache.insert(allocator, try makeFakeCacheNode(allocator, "B", 2));

    // Touch A: it becomes MRU, so B is now the eviction victim.
    const hit = cache.lookup("A").?;
    try std.testing.expectEqual(@as(u32, 1), hit.statement.id);

    const victim = cache.popTail().?;
    try std.testing.expectEqual(@as(u32, 2), victim.statement.id);
    freeCacheNode(allocator, victim, false);

    try std.testing.expect(cache.lookup("B") == null);
    try std.testing.expect(cache.lookup("A") != null);
}

test "statement cache lookup misses return null" {
    const allocator = std.testing.allocator;
    var cache = StatementCache{ .capacity = 8 };
    defer cache.clearAll(allocator, false);

    try cache.insert(allocator, try makeFakeCacheNode(allocator, "A", 1));
    try std.testing.expect(cache.lookup("nope") == null);
    try std.testing.expect(cache.lookup("A") != null);
}

test "statement cache clearAll frees every entry" {
    const allocator = std.testing.allocator;
    var cache = StatementCache{ .capacity = 8 };

    try cache.insert(allocator, try makeFakeCacheNode(allocator, "A", 1));
    try cache.insert(allocator, try makeFakeCacheNode(allocator, "B", 2));
    try cache.insert(allocator, try makeFakeCacheNode(allocator, "C", 3));

    cache.clearAll(allocator, false);
    // Reset to empty; capacity preserved. (testing.allocator flags any leak.)
    try std.testing.expectEqual(@as(usize, 0), cache.count);
    try std.testing.expectEqual(@as(usize, 8), cache.capacity);
    try std.testing.expect(cache.head == null);
    try std.testing.expect(cache.tail == null);
}
