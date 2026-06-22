const std = @import("std");

/// Owned collection of typed rows returned by `Connection.queryAll`/`queryOne`.
/// All row data (including duplicated `[]const u8` fields) lives in `arena`, so
/// the whole result is released by a single `deinit`.
pub fn Table(comptime T: type) type {
    return struct {
        const Self = @This();

        rows: []T,
        arena: *std.heap.ArenaAllocator,
        base: std.mem.Allocator,

        pub fn deinit(self: Self) void {
            self.arena.deinit();
            self.base.destroy(self.arena);
        }

        /// Return the single row, or `error.UnexpectedRowCount` if there is not
        /// exactly one. Borrowed from the table; valid until `deinit`.
        pub fn one(self: Self) !T {
            if (self.rows.len != 1) return error.UnexpectedRowCount;
            return self.rows[0];
        }
    };
}
