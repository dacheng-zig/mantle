//! Integration tests that exercise mantle against a real MySQL server.
//!
//! Run with `zig build integration_test` (requires a reachable MySQL; see
//! config.zig for defaults and overrides). These complement the offline
//! protocol unit tests in src/*: the unit tests pin wire format and decoding
//! deterministically, while these prove the driver round-trips against a live
//! server.

const std = @import("std");
const mantle = @import("mantle");
const harness = @import("harness.zig");
const test_config = @import("config.zig").test_config;

const TestConn = harness.TestConn;

test "ping" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.conn.ping(a);
        }
    }.task);
}

test "create and drop database" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_db");
            try c.queryOk(a, "CREATE DATABASE mantle_it_db");
            try c.queryOk(a, "DROP DATABASE mantle_it_db");
        }
    }.task);
}

test "query syntax error returns server error" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            var result = try c.conn.query(a, "definitely not valid sql");
            defer result.deinit(a);
            try std.testing.expect(result == .err);
            const last = c.conn.lastError().?;
            try std.testing.expectEqual(result.err.code, last.code);
            if (result.err.sql_state) |state| {
                try std.testing.expectEqualSlices(u8, &state, &last.sql_state.?);
            } else {
                try std.testing.expect(last.sql_state == null);
            }
            try std.testing.expectEqualSlices(u8, result.err.message, last.message);
            // The connection stays usable after a drained server error.
            try c.conn.ping(a);
        }
    }.task);
}

test "select returns typed row" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            var table = try c.conn.queryOne(struct { n: u64 }, a, "SELECT 1 AS n");
            defer table.deinit();
            try std.testing.expectEqual(@as(u64, 1), (try table.one()).n);
        }
    }.task);
}

test "execute prepared statement with struct params" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_struct_params");
            try c.queryOk(a, "CREATE DATABASE mantle_it_struct_params");
            defer c.queryOk(a, "DROP DATABASE mantle_it_struct_params") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_struct_params.t (id INT, name VARCHAR(16), maybe_id INT NULL) ENGINE=InnoDB");

            const InsertParams = struct {
                id: i32,
                name: []const u8,
                maybe_id: ?i32,
            };
            const insert_params: InsertParams = .{
                .id = @as(i32, 42),
                .name = "bob",
                .maybe_id = null,
            };
            const ok = c.conn.exec(a, "INSERT INTO mantle_it_struct_params.t (id, name, maybe_id) VALUES (?, ?, ?)", insert_params) catch |err| {
                if (c.conn.lastError()) |server_err| {
                    std.debug.print("exec failed: {s}; server {d} {s}\n", .{ @errorName(err), server_err.code, server_err.message });
                } else {
                    std.debug.print("exec failed: {s}\n", .{@errorName(err)});
                }
                return err;
            };
            try std.testing.expectEqual(@as(u64, 1), ok.affected_rows);

            var table = try c.conn.queryOne(struct { cnt: u64 }, a, "SELECT COUNT(*) AS cnt FROM mantle_it_struct_params.t");
            defer table.deinit();
            try std.testing.expectEqual(@as(u64, 1), (try table.one()).cnt);
        }
    }.task);
}

test "execute prepared statement with temporal params" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_temporal_params");
            try c.queryOk(a, "CREATE DATABASE mantle_it_temporal_params");
            defer c.queryOk(a, "DROP DATABASE mantle_it_temporal_params") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_temporal_params.t (created_at DATETIME(6), elapsed TIME(6)) ENGINE=InnoDB");

            const created_at = mantle.DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 };
            const elapsed = mantle.Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 };

            const ok = try c.conn.exec(
                a,
                "INSERT INTO mantle_it_temporal_params.t (created_at, elapsed) VALUES (?, ?)",
                .{ created_at, elapsed },
            );
            try std.testing.expectEqual(@as(u64, 1), ok.affected_rows);

            var table = try c.conn.queryOne(
                struct {
                    created_at: mantle.DateTime,
                    elapsed: mantle.Time,
                },
                a,
                "SELECT created_at, elapsed FROM mantle_it_temporal_params.t",
            );
            defer table.deinit();

            const row = try table.one();
            try std.testing.expectEqual(created_at, row.created_at);
            try std.testing.expectEqual(elapsed, row.elapsed);
        }
    }.task);
}

test "round trips decimal columns with typed scan" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_decimal_params");
            try c.queryOk(a, "CREATE DATABASE mantle_it_decimal_params");
            defer c.queryOk(a, "DROP DATABASE mantle_it_decimal_params") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_decimal_params.t (amount DECIMAL(20,6), legacy DECIMAL(10,2)) ENGINE=InnoDB");

            const ok = try c.conn.exec(
                a,
                "INSERT INTO mantle_it_decimal_params.t (amount, legacy) VALUES (?, ?)",
                .{
                    mantle.Decimal{ .bytes = "-1234567890.123456" },
                    mantle.Decimal{ .bytes = "42.00" },
                },
            );
            try std.testing.expectEqual(@as(u64, 1), ok.affected_rows);

            var table = try c.conn.queryOne(
                struct {
                    amount: mantle.Decimal,
                    legacy: mantle.Decimal,
                },
                a,
                "SELECT amount, legacy FROM mantle_it_decimal_params.t",
            );
            defer table.deinit();

            const row = try table.one();
            try std.testing.expectEqualSlices(u8, "-1234567890.123456", row.amount.asBytes());
            try std.testing.expectEqualSlices(u8, "42.00", row.legacy.asBytes());
        }
    }.task);
}

test "reads bit columns as byte slices" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_bit_columns");
            try c.queryOk(a, "CREATE DATABASE mantle_it_bit_columns");
            defer c.queryOk(a, "DROP DATABASE mantle_it_bit_columns") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_bit_columns.t (flags BIT(8)) ENGINE=InnoDB");
            try c.queryOk(a, "INSERT INTO mantle_it_bit_columns.t (flags) VALUES (b'10101010')");

            var table = try c.conn.queryOne(
                struct { flags: []const u8 },
                a,
                "SELECT flags FROM mantle_it_bit_columns.t",
            );
            defer table.deinit();

            const row = try table.one();
            try std.testing.expectEqualSlices(u8, &.{0b10101010}, row.flags);
        }
    }.task);
}

test "reads geometry values as byte slices" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            var table = try c.conn.queryOne(
                struct { shape: []const u8 },
                a,
                "SELECT ST_AsWKB(ST_GeomFromText('POINT(1 2)')) AS shape",
            );
            defer table.deinit();

            const row = try table.one();
            try std.testing.expectEqualSlices(u8, &.{
                0x01,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xf0,
                0x3f,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x40,
            }, row.shape);
        }
    }.task);
}

test "executeRows prepared statement with struct params" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_struct_rows");
            try c.queryOk(a, "CREATE DATABASE mantle_it_struct_rows");
            defer c.queryOk(a, "DROP DATABASE mantle_it_struct_rows") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_struct_rows.t (id INT, name VARCHAR(16), maybe_id INT NULL) ENGINE=InnoDB");

            const InsertParams = struct {
                id: i32,
                name: []const u8,
                maybe_id: ?i32,
            };
            const insert_params: InsertParams = .{
                .id = @as(i32, 42),
                .name = "bob",
                .maybe_id = null,
            };

            var stmt = try c.conn.prepare(a, "SELECT ? AS id, ? AS name, ? AS maybe_id");
            defer stmt.deinit(a);

            var rows = try c.conn.executeRows(a, &stmt, insert_params);
            defer rows.deinit(a);

            var row = try rows.next(a);
            defer row.deinit(a);
            try std.testing.expectEqual(.row, row.tag);
            try std.testing.expectEqual(@as(i32, 42), (try row.intAt(i32, rows.columns, 0)).?);
            try std.testing.expectEqualSlices(u8, "bob", (try row.valueAt(1)).?);
            try std.testing.expect((try row.valueAt(2)) == null);

            var eof = try rows.next(a);
            defer eof.deinit(a);
            try std.testing.expectEqual(.eof, eof.tag);
        }
    }.task);
}

test "reset prepared statement keeps it executable" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            var stmt = try c.conn.prepare(a, "SELECT ? AS id");
            defer stmt.deinit(a);

            var first = try c.conn.executeRows(a, &stmt, .{@as(i32, 7)});
            defer first.deinit(a);
            var first_row = try first.next(a);
            defer first_row.deinit(a);
            try std.testing.expectEqual(.row, first_row.tag);
            try std.testing.expectEqual(@as(i32, 7), (try first_row.intAt(i32, first.columns, 0)).?);
            var first_eof = try first.next(a);
            defer first_eof.deinit(a);
            try std.testing.expectEqual(.eof, first_eof.tag);

            try c.conn.resetStatement(a, &stmt);

            var second = try c.conn.executeRows(a, &stmt, .{@as(i32, 9)});
            defer second.deinit(a);
            var second_row = try second.next(a);
            defer second_row.deinit(a);
            try std.testing.expectEqual(.row, second_row.tag);
            try std.testing.expectEqual(@as(i32, 9), (try second_row.intAt(i32, second.columns, 0)).?);
            var second_eof = try second.next(a);
            defer second_eof.deinit(a);
            try std.testing.expectEqual(.eof, second_eof.tag);
        }
    }.task);
}

test "queryOneParams prepared statement with struct params" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            const Params = struct {
                id: i32,
                name: []const u8,
            };
            const Row = struct {
                id: i32,
                name: []const u8,
            };

            var table = try c.conn.queryOneParams(Row, a, "SELECT ? AS id, ? AS name", Params{ .id = 42, .name = "bob" });
            defer table.deinit();

            const row = try table.one();
            try std.testing.expectEqual(@as(i32, 42), row.id);
            try std.testing.expectEqualSlices(u8, "bob", row.name);
        }
    }.task);
}

test "queryAllParams prepared statement with struct params" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);

            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_query_params");
            try c.queryOk(a, "CREATE DATABASE mantle_it_query_params");
            defer c.queryOk(a, "DROP DATABASE mantle_it_query_params") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_query_params.t (id INT, name VARCHAR(16)) ENGINE=InnoDB");
            try c.queryOk(a, "INSERT INTO mantle_it_query_params.t (id, name) VALUES (1, 'one'), (2, 'two'), (3, 'three')");

            const Params = struct {
                min_id: i32,
                max_id: i32,
            };
            const Row = struct {
                id: i32,
                name: []const u8,
            };

            var table = try c.conn.queryAllParams(
                Row,
                a,
                "SELECT id, name FROM mantle_it_query_params.t WHERE id >= ? AND id <= ? ORDER BY id",
                Params{ .min_id = 1, .max_id = 2 },
            );
            defer table.deinit();

            try std.testing.expectEqual(@as(usize, 2), table.rows.len);
            try std.testing.expectEqual(@as(i32, 1), table.rows[0].id);
            try std.testing.expectEqualSlices(u8, "one", table.rows[0].name);
            try std.testing.expectEqual(@as(i32, 2), table.rows[1].id);
            try std.testing.expectEqualSlices(u8, "two", table.rows[1].name);
        }
    }.task);
}

test "transaction commit persists rows" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            // The test_config selects no default database, so a schema is
            // created and the (connection-scoped) temp table is qualified with
            // it. The temp table drops automatically when the connection closes.
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_tx_commit");
            try c.queryOk(a, "CREATE DATABASE mantle_it_tx_commit");
            defer c.queryOk(a, "DROP DATABASE mantle_it_tx_commit") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_tx_commit.t (id INT) ENGINE=InnoDB");

            var tx = try c.conn.begin(a);
            errdefer tx.deinit(a);
            try c.queryOk(a, "INSERT INTO mantle_it_tx_commit.t (id) VALUES (1)");
            try tx.commit(a);

            var table = try c.conn.queryOne(struct { cnt: u64 }, a, "SELECT COUNT(*) AS cnt FROM mantle_it_tx_commit.t");
            defer table.deinit();
            try std.testing.expectEqual(@as(u64, 1), (try table.one()).cnt);
        }
    }.task);
}

test "transaction rollback discards rows" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_tx_rollback");
            try c.queryOk(a, "CREATE DATABASE mantle_it_tx_rollback");
            defer c.queryOk(a, "DROP DATABASE mantle_it_tx_rollback") catch {};
            try c.queryOk(a, "CREATE TEMPORARY TABLE mantle_it_tx_rollback.t (id INT) ENGINE=InnoDB");

            var tx = try c.conn.begin(a);
            errdefer tx.deinit(a);
            try c.queryOk(a, "INSERT INTO mantle_it_tx_rollback.t (id) VALUES (1)");
            try tx.rollback(a);

            var table = try c.conn.queryOne(struct { cnt: u64 }, a, "SELECT COUNT(*) AS cnt FROM mantle_it_tx_rollback.t");
            defer table.deinit();
            try std.testing.expectEqual(@as(u64, 0), (try table.one()).cnt);
        }
    }.task);
}

test "read-only transaction rejects writes" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_tx_ro");
            try c.queryOk(a, "CREATE DATABASE mantle_it_tx_ro");
            defer c.queryOk(a, "DROP DATABASE mantle_it_tx_ro") catch {};
            try c.queryOk(a, "CREATE TABLE mantle_it_tx_ro.t (id INT) ENGINE=InnoDB");

            var tx = try c.conn.beginWith(a, .{ .access_mode = .read_only });
            errdefer tx.deinit(a);

            // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION (1792).
            var result = try c.conn.query(a, "INSERT INTO mantle_it_tx_ro.t (id) VALUES (1)");
            defer result.deinit(a);
            try std.testing.expect(result == .err);
            try std.testing.expectEqual(@as(u16, 1792), result.err.code);

            try tx.rollback(a);
            try std.testing.expect(c.conn.canReuse());
        }
    }.task);
}

test "savepoint rollback discards later writes" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_savepoint");
            try c.queryOk(a, "CREATE DATABASE mantle_it_savepoint");
            defer c.queryOk(a, "DROP DATABASE mantle_it_savepoint") catch {};
            try c.queryOk(a, "CREATE TABLE mantle_it_savepoint.t (id INT) ENGINE=InnoDB");

            var tx = try c.conn.begin(a);
            errdefer tx.deinit(a);
            try c.queryOk(a, "INSERT INTO mantle_it_savepoint.t (id) VALUES (1)");
            try tx.savepoint(a, "sp1");
            try c.queryOk(a, "INSERT INTO mantle_it_savepoint.t (id) VALUES (2)");
            try tx.rollbackTo(a, "sp1"); // undo the second insert only
            try tx.commit(a);

            // Only the pre-savepoint row survives.
            var table = try c.conn.queryAll(struct { id: i32 }, a, "SELECT id FROM mantle_it_savepoint.t ORDER BY id");
            defer table.deinit();
            try std.testing.expectEqual(@as(usize, 1), table.rows.len);
            try std.testing.expectEqual(@as(i32, 1), table.rows[0].id);
        }
    }.task);
}

test "serializable transaction commits" {
    try harness.run(struct {
        fn task(a: std.mem.Allocator) !void {
            var c = try TestConn.connect(a, test_config);
            defer c.deinit(a);
            try c.queryOk(a, "DROP DATABASE IF EXISTS mantle_it_tx_iso");
            try c.queryOk(a, "CREATE DATABASE mantle_it_tx_iso");
            defer c.queryOk(a, "DROP DATABASE mantle_it_tx_iso") catch {};
            try c.queryOk(a, "CREATE TABLE mantle_it_tx_iso.t (id INT) ENGINE=InnoDB");

            var tx = try c.conn.beginWith(a, .{ .isolation = .serializable, .access_mode = .read_write });
            errdefer tx.deinit(a);
            try c.queryOk(a, "INSERT INTO mantle_it_tx_iso.t (id) VALUES (7)");
            try tx.commit(a);

            var table = try c.conn.queryOne(struct { cnt: u64 }, a, "SELECT COUNT(*) AS cnt FROM mantle_it_tx_iso.t");
            defer table.deinit();
            try std.testing.expectEqual(@as(u64, 1), (try table.one()).cnt);
        }
    }.task);
}
