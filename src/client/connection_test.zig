const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;

const Connection = mantle.Connection;
const PreparedStatement = mantle.PreparedStatement;
const ServerError = mantle.ServerError;
const DateTime = mantle.DateTime;
const Time = mantle.Time;
const Decimal = mantle.Decimal;

const result_row = @import("../result/row.zig");
const TextRowResult = result_row.TextRowResult;
const TextRowResultTag = result_row.TextRowResultTag;
const BinaryRowResult = result_row.BinaryRowResult;
const BinaryRowResultTag = result_row.BinaryRowResultTag;

const sample_handshake = [_]u8{
    0x0a, '8',  '.',  '0',  '.',  '3',  '6',  0x00,
    0x39, 0x30, 0x00, 0x00, 'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',  0x00, 0x00, 0x82, 0xff,
    0x02, 0x00, 0x08, 0x00, 21,   0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    'i',
    'j',  'k',  'l',  'm',  'n',  'o',  'p',  'q',
    'r',  's',  't',  0x00, 'm',  'y',  's',  'q',
    'l',  '_',  'n',  'a',  't',  'i',  'v',  'e',
    '_',  'p',  'a',  's',  's',  'w',  'o',  'r',
    'd',  0x00,
};

test "connection pings after handshake" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    try conn.ping(std.testing.allocator);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(u8, 0x0e), io.written.items[4]);
}

test "connection close sends quit command" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    try conn.close(std.testing.allocator);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(u8, 0x01), io.written.items[4]);
}

test "connection rejects commands after close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try conn.close(std.testing.allocator);

    try std.testing.expectError(error.ConnectionClosed, conn.ping(std.testing.allocator));
    try std.testing.expect(!conn.isBroken());
}

test "connection reset sends reset connection command and waits for ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    try conn.reset(std.testing.allocator);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(u8, 0x1f), io.written.items[4]);
}

test "connection reset captures structured server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd', ' ', 'r', 'e', 's', 'e', 't' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.ServerError, conn.reset(std.testing.allocator));
    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1045), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad reset", last.message);
}

test "connection reset clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select 1"));
    try std.testing.expect(conn.lastError() != null);

    try conn.reset(std.testing.allocator);

    try std.testing.expect(conn.lastError() == null);
}

test "connection can reuse after successful handshake" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expect(conn.canReuse());

    // A connection with an open transaction must not be pooled even though the
    // phase is `ready`, otherwise the next acquirer inherits the transaction.
    conn.in_transaction = true;
    try std.testing.expect(!conn.canReuse());
    conn.in_transaction = false;
    try std.testing.expect(conn.canReuse());
}

test "connection cannot reuse after graceful close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try conn.close(std.testing.allocator);

    try std.testing.expect(!conn.canReuse());
    try std.testing.expect(!conn.isBroken());
}

test "connection cannot reuse after protocol error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.EndOfStream, conn.ping(std.testing.allocator));

    try std.testing.expect(conn.isBroken());
    try std.testing.expect(!conn.canReuse());
}

test "connection cannot reuse while text result is streaming" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);

    try std.testing.expect(!conn.canReuse());

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);
    try std.testing.expect(!conn.canReuse());

    var eof = try rows.next(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.eof, eof.tag);
    try std.testing.expect(conn.canReuse());
}

test "text result drain consumes remaining rows and restores reuse" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '2' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, first.tag);
    try std.testing.expect(!conn.canReuse());

    try rows.drain(std.testing.allocator);

    try std.testing.expect(conn.canReuse());
}

test "text result drain consumes following result sets before reuse" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x0a, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 7, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 8, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 9, &.{ 0x01, '2' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 10, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select 1; select 2");
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, first.tag);
    try std.testing.expect(!conn.canReuse());

    try rows.drain(std.testing.allocator);

    try std.testing.expect(conn.canReuse());
}

test "text result drain captures streaming server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, first.tag);

    try std.testing.expectError(error.ServerError, rows.drain(std.testing.allocator));
    try std.testing.expect(!conn.isBroken());
    try std.testing.expect(conn.canReuse());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1045), last.code);
    try std.testing.expectEqualSlices(u8, "bad", last.message);
}

const TestByteStream = struct {
    input: []const u8,
    read_pos: usize = 0,
    written: std.ArrayList(u8) = .empty,

    fn init(input: []const u8) TestByteStream {
        return .{ .input = input };
    }

    fn deinit(self: *TestByteStream) void {
        self.written.deinit(std.testing.allocator);
    }

    fn reader(self: *TestByteStream) mantle.transport.AnyReader {
        return .{
            .context = self,
            .readFn = read,
        };
    }

    fn writer(self: *TestByteStream) mantle.transport.AnyWriter {
        return .{
            .context = self,
            .writeAllFn = writeAll,
        };
    }

    fn read(context: *anyopaque, dest: []u8) anyerror!usize {
        const self: *TestByteStream = @ptrCast(@alignCast(context));
        const n = @min(dest.len, self.input.len - self.read_pos);
        @memcpy(dest[0..n], self.input[self.read_pos..][0..n]);
        self.read_pos += n;
        return n;
    }

    fn writeAll(context: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *TestByteStream = @ptrCast(@alignCast(context));
        try self.written.appendSlice(std.testing.allocator, bytes);
    }
};

fn writeTestColumnDefinition(writer: *protocol.PayloadWriter, sequence_id: u8, name: []const u8, field_type: protocol.text_result.FieldType) !void {
    try writeTestColumnDefinitionWithFlags(writer, sequence_id, name, field_type, 0);
}

fn testColumn(name: []const u8, field_type: protocol.text_result.FieldType) protocol.text_result.ColumnDefinition41 {
    return .{
        .catalog = "def",
        .schema = "",
        .table = "",
        .org_table = "",
        .name = name,
        .org_name = name,
        .fixed_length_fields = 0x0c,
        .character_set = protocol.collation.binary,
        .column_length = 1024,
        .field_type = field_type,
        .flags = 0,
        .decimals = 0,
    };
}

fn writeTestColumnDefinitionWithFlags(
    writer: *protocol.PayloadWriter,
    sequence_id: u8,
    name: []const u8,
    field_type: protocol.text_result.FieldType,
    flags: u16,
) !void {
    var payload = protocol.PayloadWriter.init(std.testing.allocator);
    defer payload.deinit();
    try payload.writeLengthEncodedString("def");
    try payload.writeLengthEncodedString("");
    try payload.writeLengthEncodedString("");
    try payload.writeLengthEncodedString("");
    try payload.writeLengthEncodedString(name);
    try payload.writeLengthEncodedString(name);
    try payload.writeLengthEncodedInteger(0x0c);
    try payload.writeInt(u16, 63);
    try payload.writeInt(u32, 1024);
    try payload.writeInt(u8, @intFromEnum(field_type));
    try payload.writeInt(u16, flags);
    try payload.writeInt(u8, 0);
    try protocol.packet.writeLogicalPayload(writer, sequence_id, payload.bytes());
}

test "connection query returns ok for non-result-set command" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const result = try conn.query(std.testing.allocator, "create table t (id int)");

    try std.testing.expect(result == .ok);
    try std.testing.expectEqual(@as(u8, 0x03), io.written.items[4]);
    try std.testing.expectEqualSlices(u8, "create table t (id int)", io.written.items[5..]);
}

test "connection query reports result set for row-producing command" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const result = try conn.query(std.testing.allocator, "select 1");

    try std.testing.expect(result == .result_set);
}

test "connection query returns err for server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var result = try conn.query(std.testing.allocator, "bad sql");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result == .err);
}

test "connection queryRows streams text rows until eof" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfb, 0x03, 't', 'w', 'o' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var rows = try conn.queryRows(std.testing.allocator, "select id, name from t");
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, first.tag);
    try std.testing.expectEqualSlices(u8, "1", first.values[0].?);
    try std.testing.expectEqualSlices(u8, "one", first.values[1].?);

    var second = try rows.next(std.testing.allocator);
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, second.tag);
    try std.testing.expect(second.values[0] == null);
    try std.testing.expectEqualSlices(u8, "two", second.values[1].?);

    var eof = try rows.next(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.eof, eof.tag);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection queryAll scans text rows into structs via resolved indices" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0x01, '2', 0x03, 't', 'w', 'o' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const Row = struct { id: i32, name: []const u8 };
    var table = try conn.queryAll(Row, std.testing.allocator, "select id, name from t");
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 2), table.rows.len);
    try std.testing.expectEqual(@as(i32, 1), table.rows[0].id);
    try std.testing.expectEqualSlices(u8, "one", table.rows[0].name);
    try std.testing.expectEqual(@as(i32, 2), table.rows[1].id);
    try std.testing.expectEqualSlices(u8, "two", table.rows[1].name);
}

test "connection queryAll surfaces unknown column name from resolution" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    // The destination has a field with no matching column; resolution must fail.
    const Row = struct { missing: i32 };
    try std.testing.expectError(error.UnknownColumnName, conn.queryAll(Row, std.testing.allocator, "select id from t"));
}

test "connection queryRows drains column definitions before rows" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id, name from t");
    defer rows.deinit(std.testing.allocator);
    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);

    try std.testing.expectEqual(TextRowResultTag.row, first.tag);
    try std.testing.expectEqualSlices(u8, "1", first.values[0].?);
    try std.testing.expectEqualSlices(u8, "one", first.values[1].?);
}

test "connection queryRows exposes owned column metadata" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id, name from t");
    defer rows.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), rows.columns.len);
    try std.testing.expectEqualSlices(u8, "id", rows.columns[0].name);
    try std.testing.expectEqualSlices(u8, "id", rows.columns[0].org_name);
    try std.testing.expectEqual(protocol.text_result.FieldType.long, rows.columns[0].field_type);
    try std.testing.expectEqual(@as(u16, 63), rows.columns[0].character_set);
    try std.testing.expectEqual(@as(u32, 1024), rows.columns[0].column_length);
    try std.testing.expectEqual(@as(u16, 0), rows.columns[0].flags);
    try std.testing.expectEqual(@as(u8, 0), rows.columns[0].decimals);
    try std.testing.expectEqualSlices(u8, "name", rows.columns[1].name);
    try std.testing.expectEqual(protocol.text_result.FieldType.var_string, rows.columns[1].field_type);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.row, first.tag);
    try std.testing.expectEqualSlices(u8, "1", first.values[0].?);
    try std.testing.expectEqualSlices(u8, "one", first.values[1].?);
}

test "text row result supports value and integer accessors" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x02, '4', '2', 0x03, 'b', 'o', 'b' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id, name from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "42", (try row.valueAt(0)).?);
    try std.testing.expectEqualSlices(u8, "bob", (try row.valueByName(rows.columns, "name")).?);
    try std.testing.expectEqual(@as(i32, 42), (try row.intAt(i32, rows.columns, 0)).?);
    try std.testing.expectEqual(@as(u64, 42), (try row.intByName(u64, rows.columns, "id")).?);
    try std.testing.expectError(error.InvalidColumnType, row.intByName(u64, rows.columns, "name"));
    try std.testing.expectError(error.ColumnIndexOutOfBounds, row.valueAt(2));
    try std.testing.expectError(error.UnknownColumnName, row.valueByName(rows.columns, "missing"));
}

test "text row result supports decimal accessors and scan fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "amount", .newdecimal);
    try writeTestColumnDefinition(&server_bytes, 3, "legacy", .decimal);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x08, '-', '1', '2', '3', '.', '4', '5', '6', 0x05, '4', '2', '.', '0', '0' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select amount, legacy from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "-123.456", (try row.decimalAt(rows.columns, 0)).?.asBytes());
    try std.testing.expectEqualSlices(u8, "42.00", (try row.decimalByName(rows.columns, "legacy")).?.asBytes());

    const Amounts = struct {
        amount: Decimal,
        legacy: Decimal,
    };
    var amounts: Amounts = undefined;
    try row.scan(&amounts, rows.columns);

    try std.testing.expectEqualSlices(u8, "-123.456", amounts.amount.asBytes());
    try std.testing.expectEqualSlices(u8, "42.00", amounts.legacy.asBytes());
}

test "text row result scans bit columns as byte slices" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "flags", .bit);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    var row_payload = protocol.PayloadWriter.init(std.testing.allocator);
    defer row_payload.deinit();
    try row_payload.writeLengthEncodedString(&.{0b10101010});
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, row_payload.bytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select flags from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const expected = [_]u8{0b10101010};
    try std.testing.expectEqualSlices(u8, &expected, (try row.valueAt(0)).?);

    const Flags = struct { flags: []const u8 };
    var flags: Flags = undefined;
    try row.scan(&flags, rows.columns);

    try std.testing.expectEqualSlices(u8, &expected, flags.flags);
}

test "text row result scans geometry columns as byte slices" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "shape", .geometry);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    var row_payload = protocol.PayloadWriter.init(std.testing.allocator);
    defer row_payload.deinit();
    try row_payload.writeLengthEncodedString(&.{ 0x01, 0x02, 0x03, 0x04 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, row_payload.bytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select shape from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const expected = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectEqualSlices(u8, &expected, (try row.valueAt(0)).?);

    const Shape = struct { shape: []const u8 };
    var shape: Shape = undefined;
    try row.scan(&shape, rows.columns);

    try std.testing.expectEqualSlices(u8, &expected, shape.shape);
}

test "text row result scanAlloc duplicates decimal fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "amount", .newdecimal);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x08, '-', '1', '2', '3', '.', '4', '5', '6' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select amount from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const Amount = struct { amount: Decimal };
    var amount: Amount = undefined;
    try row.scanAlloc(&amount, rows.columns, arena.allocator());

    try std.testing.expectEqualSlices(u8, "-123.456", amount.amount.asBytes());
    try std.testing.expect(amount.amount.asBytes().ptr != (try row.decimalAt(rows.columns, 0)).?.asBytes().ptr);
}

test "text row result supports float accessors and scan fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "score", .float);
    try writeTestColumnDefinition(&server_bytes, 3, "ratio", .double);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x03, '1', '.', '5', 0x04, '2', '.', '2', '5' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select score, ratio from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(f32, 1.5), (try row.floatAt(f32, rows.columns, 0)).?);
    try std.testing.expectEqual(@as(f64, 2.25), (try row.floatByName(f64, rows.columns, "ratio")).?);

    const Metric = struct {
        score: f32,
        ratio: f64,
    };
    var metric: Metric = undefined;
    try row.scan(&metric, rows.columns);

    try std.testing.expectEqual(@as(f32, 1.5), metric.score);
    try std.testing.expectEqual(@as(f64, 2.25), metric.ratio);
}

test "text row result decodes datetime fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x04});
    try writeTestColumnDefinition(&server_bytes, 2, "created_on", .date);
    try writeTestColumnDefinition(&server_bytes, 3, "created_at", .datetime);
    try writeTestColumnDefinition(&server_bytes, 4, "updated_at", .timestamp);
    try writeTestColumnDefinition(&server_bytes, 5, "zero_at", .datetime);
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    var row_payload = protocol.PayloadWriter.init(std.testing.allocator);
    defer row_payload.deinit();
    try row_payload.writeLengthEncodedString("2026-06-16");
    try row_payload.writeLengthEncodedString("2026-06-16 12:34:56");
    try row_payload.writeLengthEncodedString("2026-06-16 12:34:56.123456");
    try row_payload.writeLengthEncodedString("0000-00-00 00:00:00");
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, row_payload.bytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 8, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select created_on, created_at, updated_at, zero_at from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16 }, (try row.dateTimeAt(rows.columns, 0)).?);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56 }, (try row.dateTimeByName(rows.columns, "created_at")).?);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 }, (try row.dateTimeByName(rows.columns, "updated_at")).?);
    try std.testing.expectEqual(DateTime{}, (try row.dateTimeByName(rows.columns, "zero_at")).?);

    const Event = struct {
        created_on: DateTime,
        created_at: DateTime,
        updated_at: DateTime,
        zero_at: DateTime,
    };
    var event: Event = undefined;
    try row.scan(&event, rows.columns);

    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16 }, event.created_on);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56 }, event.created_at);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 }, event.updated_at);
    try std.testing.expectEqual(DateTime{}, event.zero_at);
}

test "text row result decodes time fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "elapsed", .time);
    try writeTestColumnDefinition(&server_bytes, 3, "empty", .time);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    var row_payload = protocol.PayloadWriter.init(std.testing.allocator);
    defer row_payload.deinit();
    try row_payload.writeLengthEncodedString("-51:04:05.123456");
    try row_payload.writeLengthEncodedString("00:00:00");
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, row_payload.bytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select elapsed, empty from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, (try row.timeAt(rows.columns, 0)).?);
    try std.testing.expectEqual(Time{}, (try row.timeByName(rows.columns, "empty")).?);

    const Event = struct {
        elapsed: Time,
        empty: Time,
    };
    var event: Event = undefined;
    try row.scan(&event, rows.columns);

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, event.elapsed);
    try std.testing.expectEqual(Time{}, event.empty);
}

test "text row result supports bool accessors and scan fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "active", .tiny);
    try writeTestColumnDefinition(&server_bytes, 3, "archived", .tiny);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x01, '0' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select active, archived from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(true, (try row.boolAt(rows.columns, 0)).?);
    try std.testing.expectEqual(false, (try row.boolByName(rows.columns, "archived")).?);

    const Flags = struct {
        active: bool,
        archived: bool,
    };
    var flags: Flags = undefined;
    try row.scan(&flags, rows.columns);

    try std.testing.expectEqual(true, flags.active);
    try std.testing.expectEqual(false, flags.archived);
}

test "text row result rejects invalid bool values" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "active", .tiny);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '2' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select active from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidBoolValue, row.boolAt(rows.columns, 0));
}

test "text row result rejects ambiguous column names" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x01, '2' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id, id from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectError(error.AmbiguousColumnName, row.valueByName(rows.columns, "id"));
    try std.testing.expectError(error.AmbiguousColumnName, row.intByName(i32, rows.columns, "id"));
}

test "text row result returns null for nullable integer accessors" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{0xfb});
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expect((try row.valueAt(0)) == null);
    try std.testing.expect((try row.intAt(i32, rows.columns, 0)) == null);
    try std.testing.expect((try row.intByName(i32, rows.columns, "id")) == null);
}

test "connection queryRows rejects non-result-set response" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.UnexpectedOk, conn.queryRows(std.testing.allocator, "create table t (id int)"));
}

test "connection queryRows unexpected ok leaves connection reusable" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.UnexpectedOk, conn.queryRows(std.testing.allocator, "create table t (id int)"));
    try std.testing.expect(conn.canReuse());
    try conn.ping(std.testing.allocator);
}

test "connection queryRows unexpected ok clears stale server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    try std.testing.expectError(error.UnexpectedOk, conn.queryRows(std.testing.allocator, "create table t (id int)"));
    try std.testing.expect(conn.lastError() == null);
}

test "connection queryRows returns err row on streaming error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "value", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select 1");
    defer rows.deinit(std.testing.allocator);
    var err_row = try rows.next(std.testing.allocator);
    defer err_row.deinit(std.testing.allocator);

    try std.testing.expectEqual(TextRowResultTag.err, err_row.tag);
    // A streaming server error terminates the result set but leaves the
    // connection reusable.
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1045), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad", last.message);
}

test "text row result scans supported fields into struct" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x03});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try writeTestColumnDefinition(&server_bytes, 4, "maybe_id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0x02, '4', '2', 0x03, 'b', 'o', 'b', 0xfb });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id, name, maybe_id from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
        maybe_id: ?i32,
    };
    var user: User = undefined;
    try row.scan(&user, rows.columns);

    try std.testing.expectEqual(@as(i32, 42), user.id);
    try std.testing.expectEqualSlices(u8, "bob", user.name);
    try std.testing.expect(user.maybe_id == null);
}

test "text row result rejects null for non-optional scan field" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{0xfb});
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: i32,
    };
    var user: User = undefined;

    try std.testing.expectError(error.UnexpectedNullValue, row.scan(&user, rows.columns));
}

test "text row result rejects unsupported scan field type" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "active", .tiny);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select active from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const Metric = struct {
        active: *const u8,
    };
    var metric: Metric = undefined;

    try std.testing.expectError(error.UnsupportedScanFieldType, row.scan(&metric, rows.columns));
}

test "text row result rejects byte slice scan for non bytes like column" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const Row = struct {
        id: []const u8,
    };
    var scanned: Row = undefined;

    try std.testing.expectError(error.InvalidColumnType, row.scan(&scanned, rows.columns));
}

test "text row result records scan diagnostics on failure" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const Row = struct { id: []const u8 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.InvalidColumnType, row.scan(&scanned, rows.columns));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.InvalidColumnType, diag.reason);
    try std.testing.expectEqual(@as(usize, 0), diag.index.?);
    try std.testing.expectEqualSlices(u8, "id", diag.field_name);
    try std.testing.expectEqualSlices(u8, "id", diag.column_name.?);
    try std.testing.expectEqualSlices(u8, "[]const u8", diag.target_type);
}

test "text row result records scan diagnostics for unknown columns" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};
    var values = [_]?[]const u8{"1"};
    var payload: [0]u8 = .{};
    var row = TextRowResult{
        .tag = .row,
        .transport_row = .{ .tag = .row, .payload = payload[0..], .values = values[0..], .owns_values = false },
        .values = values[0..],
    };

    const Row = struct { missing: i32 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.UnknownColumnName, row.scan(&scanned, columns[0..]));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.UnknownColumnName, diag.reason);
    try std.testing.expect(diag.index == null);
    try std.testing.expectEqualSlices(u8, "missing", diag.field_name);
    try std.testing.expect(diag.column_name == null);
    try std.testing.expectEqualSlices(u8, "i32", diag.target_type);
}

test "text row result records scan diagnostics for null fields" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};
    var values = [_]?[]const u8{null};
    var payload: [0]u8 = .{};
    var row = TextRowResult{
        .tag = .row,
        .transport_row = .{ .tag = .row, .payload = payload[0..], .values = values[0..], .owns_values = false },
        .values = values[0..],
    };

    const Row = struct { id: i32 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.UnexpectedNullValue, row.scan(&scanned, columns[0..]));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.UnexpectedNullValue, diag.reason);
    try std.testing.expectEqual(@as(usize, 0), diag.index.?);
    try std.testing.expectEqualSlices(u8, "id", diag.field_name);
    try std.testing.expectEqualSlices(u8, "id", diag.column_name.?);
    try std.testing.expectEqualSlices(u8, "i32", diag.target_type);
}

test "text row result rejects scan fields without matching columns" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var rows = try conn.queryRows(std.testing.allocator, "select id from t");
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
    };
    var user: User = undefined;

    try std.testing.expectError(error.UnknownColumnName, row.scan(&user, rows.columns));
}

test "connection prepares statement and owns metadata" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{
        0x00,
        0x34,
        0x12,
        0x00,
        0x00,
        0x02,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    });
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 4, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 5, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = try conn.prepare(std.testing.allocator, "select id, name from users where id = ?");
    defer stmt.deinit(std.testing.allocator);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(u8, 0x16), io.written.items[4]);
    try std.testing.expectEqualSlices(u8, "select id, name from users where id = ?", io.written.items[5..]);
    try std.testing.expectEqual(@as(u32, 0x1234), stmt.id);
    try std.testing.expectEqual(@as(usize, 1), stmt.params.len);
    try std.testing.expectEqualSlices(u8, "id", stmt.params[0].name);
    try std.testing.expectEqual(@as(usize, 2), stmt.columns.len);
    try std.testing.expectEqualSlices(u8, "id", stmt.columns[0].name);
    try std.testing.expectEqualSlices(u8, "name", stmt.columns[1].name);
}

test "connection prepares statement without metadata" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{
        0x00,
        0x35,
        0x12,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var stmt = try conn.prepare(std.testing.allocator, "insert into users(name) values('bob')");
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 0x1235), stmt.id);
    try std.testing.expectEqual(@as(usize, 0), stmt.params.len);
    try std.testing.expectEqual(@as(usize, 0), stmt.columns.len);
}

test "connection prepare ok clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{
        0x00,
        0x35,
        0x12,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = try conn.prepare(std.testing.allocator, "select 1");
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expect(conn.lastError() == null);
}

test "connection surfaces structured error after prepare failure" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x64, 0x04, '#', '4', '2', '0', '0', '0', 'b', 'a', 'd', ' ', 'p', 'r', 'e', 'p', 'a', 'r', 'e' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.ServerError, conn.prepare(std.testing.allocator, "select bad"));
    try std.testing.expect(!conn.isBroken());

    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1124), last.code);
    try std.testing.expectEqualSlices(u8, "42000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad prepare", last.message);
}

test "connection closes prepared statement without waiting for response" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try conn.closeStatement(std.testing.allocator, &stmt);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x78, 0x56, 0x34, 0x12 }, io.written.items[4..]);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection sends prepared long data without waiting for response" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.dupe(protocol.text_result.ColumnDefinition41, &.{
            .{
                .catalog = "",
                .schema = "",
                .table = "",
                .org_table = "",
                .name = "payload",
                .org_name = "",
                .fixed_length_fields = 0x0c,
                .character_set = protocol.collation.utf8mb4_general_ci,
                .column_length = 0,
                .field_type = .blob,
                .flags = 0,
                .decimals = 0,
            },
        }),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    try conn.sendLongData(std.testing.allocator, &stmt, 0, "chunk");

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 'c', 'h', 'u', 'n', 'k' }, io.written.items[4..]);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection rejects prepared long data parameter index out of bounds" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.PreparedParameterIndexOutOfBounds, conn.sendLongData(std.testing.allocator, &stmt, 0, "chunk"));
    try std.testing.expectEqual(@as(usize, 0), io.written.items.len);
    try std.testing.expect(!conn.isBroken());
}

test "connection rejects long data after statement close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try conn.closeStatement(std.testing.allocator, &stmt);
    try std.testing.expectError(error.PreparedStatementClosed, conn.sendLongData(std.testing.allocator, &stmt, 0, "chunk"));
    try std.testing.expect(!conn.isBroken());
}

test "connection rejects long data with statement from another connection" {
    var owner_io = TestByteStream.init(&.{});
    defer owner_io.deinit();
    var owner = Connection.init(.{
        .reader = owner_io.reader(),
        .writer = owner_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var other_io = TestByteStream.init(&.{});
    defer other_io.deinit();
    var other = Connection.init(.{
        .reader = other_io.reader(),
        .writer = other_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .conn = &owner,
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.PreparedStatementWrongConnection, other.sendLongData(std.testing.allocator, &stmt, 0, "chunk"));
    try std.testing.expect(!other.isBroken());
    try std.testing.expectEqual(@as(usize, 0), other_io.written.items.len);
}

test "prepared statement deinit closes server statement" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = try conn.prepare(std.testing.allocator, "select 1");
    io.written.clearRetainingCapacity();

    stmt.deinit(std.testing.allocator);

    try std.testing.expect(io.written.items.len >= 4);
    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x78, 0x56, 0x34, 0x12 }, io.written.items[4..]);
}

test "prepared statement deinit does not close twice after explicit close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = try conn.prepare(std.testing.allocator, "select 1");
    io.written.clearRetainingCapacity();

    try conn.closeStatement(std.testing.allocator, &stmt);
    const close_len = io.written.items.len;
    stmt.deinit(std.testing.allocator);

    try std.testing.expectEqual(close_len, io.written.items.len);
}

test "connection rejects executeRows after statement close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x01, 0x00, 0x00 });
    try writeTestColumnDefinitionWithFlags(&server_bytes, 2, "id", .long, 0);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try writeTestColumnDefinitionWithFlags(&server_bytes, 4, "id", .long, 0);
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    var stmt = try conn.prepare(std.testing.allocator, "select ? as id");
    defer stmt.deinit(std.testing.allocator);

    try conn.closeStatement(std.testing.allocator, &stmt);
    try std.testing.expectError(error.PreparedStatementClosed, conn.executeRows(std.testing.allocator, &stmt, .{@as(i32, 1)}));
    try std.testing.expect(!conn.isBroken());
}

test "connection rejects reset after statement close" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    var stmt = try conn.prepare(std.testing.allocator, "select 1");
    defer stmt.deinit(std.testing.allocator);

    try conn.closeStatement(std.testing.allocator, &stmt);
    try std.testing.expectError(error.PreparedStatementClosed, conn.resetStatement(std.testing.allocator, &stmt));
    try std.testing.expect(!conn.isBroken());
}

test "connection rejects closing statement from another connection" {
    var owner_io = TestByteStream.init(&.{});
    defer owner_io.deinit();
    var owner = Connection.init(.{
        .reader = owner_io.reader(),
        .writer = owner_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var other_io = TestByteStream.init(&.{});
    defer other_io.deinit();
    var other = Connection.init(.{
        .reader = other_io.reader(),
        .writer = other_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .conn = &owner,
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.PreparedStatementWrongConnection, other.closeStatement(std.testing.allocator, &stmt));
    try std.testing.expect(!other.isBroken());
    try std.testing.expectEqual(@as(usize, 0), other_io.written.items.len);
}

test "connection rejects executeRows with statement from another connection" {
    var owner_io = TestByteStream.init(&.{});
    defer owner_io.deinit();
    var owner = Connection.init(.{
        .reader = owner_io.reader(),
        .writer = owner_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var other_io = TestByteStream.init(&.{});
    defer other_io.deinit();
    var other = Connection.init(.{
        .reader = other_io.reader(),
        .writer = other_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .conn = &owner,
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    try std.testing.expectError(error.PreparedStatementWrongConnection, other.executeRows(std.testing.allocator, &stmt, .{@as(i32, 1)}));
    try std.testing.expect(!other.isBroken());
    try std.testing.expectEqual(@as(usize, 0), other_io.written.items.len);
}

test "connection rejects reset with statement from another connection" {
    var owner_io = TestByteStream.init(&.{});
    defer owner_io.deinit();
    var owner = Connection.init(.{
        .reader = owner_io.reader(),
        .writer = owner_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var other_io = TestByteStream.init(&.{});
    defer other_io.deinit();
    var other = Connection.init(.{
        .reader = other_io.reader(),
        .writer = other_io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .conn = &owner,
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    try std.testing.expectError(error.PreparedStatementWrongConnection, other.resetStatement(std.testing.allocator, &stmt));
    try std.testing.expect(!other.isBroken());
    try std.testing.expectEqual(@as(usize, 0), other_io.written.items.len);
}

test "connection resets prepared statement and waits for ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try conn.resetStatement(std.testing.allocator, &stmt);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0x78, 0x56, 0x34, 0x12 }, io.written.items[4..]);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
    try std.testing.expect(!conn.isBroken());
}

test "connection resetStatement captures structured server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x4f, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd', ' ', 'r', 'e', 's', 'e', 't' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.ServerError, conn.resetStatement(std.testing.allocator, &stmt));

    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1103), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad reset", last.message);
}

test "connection resetStatement ok clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try conn.resetStatement(std.testing.allocator, &stmt);

    try std.testing.expect(conn.lastError() == null);
}

test "connection resetStatement marks broken on truncated response" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.EndOfStream, conn.resetStatement(std.testing.allocator, &stmt));
    try std.testing.expect(conn.isBroken());
    try std.testing.expectError(error.ConnectionBroken, conn.ping(std.testing.allocator));
}

test "connection rejects statement close before ready" {
    var io = TestByteStream.init(&.{});
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidConnectionPhaseState, conn.closeStatement(std.testing.allocator, &stmt));
}

test "connection executes no-param prepared statement returning ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    const result = try conn.execute(std.testing.allocator, &stmt);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x17, 0x78, 0x56, 0x34, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00 }, io.written.items[4..]);
    try std.testing.expect(result == .ok);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection execute ok clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    var result = try conn.execute(std.testing.allocator, &stmt);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .ok);

    try std.testing.expect(conn.lastError() == null);
}

test "connection execute captures structured server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x64, 0x04, '#', '4', '2', '0', '0', '0', 'b', 'a', 'd', ' ', 'e', 'x', 'e', 'c' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    var result = try conn.execute(std.testing.allocator, &stmt);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .err);

    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1124), last.code);
    try std.testing.expectEqualSlices(u8, "42000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad exec", last.message);
}

test "connection executes no-param prepared statement returning result set" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expect((try conn.execute(std.testing.allocator, &stmt)) == .result_set);
}

test "connection rejects prepared execute with parameters for now" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    const param = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1);
    param[0] = undefined;
    const stmt = PreparedStatement{
        .id = 1,
        .params = param,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    try std.testing.expectError(error.UnsupportedPreparedParameters, conn.execute(std.testing.allocator, &stmt));
}

test "connection executes prepared statement with parameters returning ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 3);
    params[0] = undefined;
    params[1] = undefined;
    params[2] = undefined;
    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = params,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    const result = try conn.executeParams(std.testing.allocator, &stmt, .{ @as(i32, 42), "bob", null });

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000100,
        0x01,
        0x03,
        0x00,
        0xfd,
        0x00,
        0x06,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, io.written.items[4..]);
    try std.testing.expect(result == .ok);
}

test "connection executeParams ok clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    var result = try conn.executeParams(std.testing.allocator, &stmt, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .ok);

    try std.testing.expect(conn.lastError() == null);
}

test "connection executeParams captures structured server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x64, 0x04, '#', '4', '2', '0', '0', '0', 'b', 'a', 'd', ' ', 'e', 'x', 'e', 'c' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    var result = try conn.executeParams(std.testing.allocator, &stmt, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .err);

    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1124), last.code);
    try std.testing.expectEqualSlices(u8, "42000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad exec", last.message);
}

test "connection executes prepared statement with float parameters returning ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2);
    params[0] = undefined;
    params[1] = undefined;
    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = params,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    const result = try conn.executeParams(std.testing.allocator, &stmt, .{ @as(f32, 1.5), @as(f64, 2.25) });

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x04,
        0x00,
        0x05,
        0x00,
        0x00,
        0x00,
        0xc0,
        0x3f,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x40,
    }, io.written.items[4..]);
    try std.testing.expect(result == .ok);
}

test "connection executes prepared statement with bool parameters returning ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2);
    params[0] = undefined;
    params[1] = undefined;
    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = params,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    const result = try conn.executeParams(std.testing.allocator, &stmt, .{ true, false });

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
    }, io.written.items[4..]);
    try std.testing.expect(result == .ok);
}

test "connection executes prepared statement with struct parameters returning ok" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const Params = struct {
        id: i32,
        name: []const u8,
        maybe_id: ?i32,
    };
    const bound_params: Params = .{
        .id = @as(i32, 42),
        .name = "bob",
        .maybe_id = null,
    };
    const params_buf = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 3);
    params_buf[0] = undefined;
    params_buf[1] = undefined;
    params_buf[2] = undefined;
    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = params_buf,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    const result = try conn.executeParams(std.testing.allocator, &stmt, bound_params);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000100,
        0x01,
        0x03,
        0x00,
        0xfd,
        0x00,
        0x03,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, io.written.items[4..]);
    try std.testing.expect(result == .ok);
}

test "connection rejects execute params count mismatch" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2);
    params[0] = undefined;
    params[1] = undefined;
    const stmt = PreparedStatement{
        .id = 1,
        .params = params,
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    try std.testing.expectError(error.PreparedParameterCountMismatch, conn.executeParams(std.testing.allocator, &stmt, .{@as(i32, 42)}));
    try std.testing.expectEqual(@as(usize, 0), io.written.items.len);
}

test "connection executeRows streams binary rows until eof" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x03});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try writeTestColumnDefinition(&server_bytes, 4, "maybe_id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{
        0x00,
        0b00010000,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 3),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.row, row.tag);
    try std.testing.expectEqualSlices(u8, &.{ 0x2a, 0x00, 0x00, 0x00 }, (try row.valueAt(0)).?);
    try std.testing.expectEqual(@as(i32, 42), (try row.intAt(i32, rows.columns, 0)).?);
    try std.testing.expectEqualSlices(u8, "bob", (try row.valueByName(rows.columns, "name")).?);
    try std.testing.expect((try row.valueByName(rows.columns, "maybe_id")) == null);

    var eof = try rows.next(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.eof, eof.tag);
}

test "connection executeRows result set clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    try std.testing.expect(conn.lastError() == null);

    var eof = try rows.next(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.eof, eof.tag);
}

test "connection executeRows unexpected ok clears stale server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
    };
    defer stmt.deinit(std.testing.allocator);

    try std.testing.expectError(error.UnexpectedOk, conn.executeRows(std.testing.allocator, &stmt, .{}));
    try std.testing.expect(conn.lastError() == null);
}

test "binary result drain consumes remaining rows and restores reuse" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.row, first.tag);
    try std.testing.expect(!conn.canReuse());

    try rows.drain(std.testing.allocator);

    try std.testing.expect(conn.canReuse());
}

test "binary result drain consumes following result sets before reuse" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x0a, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 7, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 8, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 9, &.{ 0x00, 0x00, 0xfb, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 10, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.row, first.tag);
    try std.testing.expect(!conn.canReuse());

    try rows.drain(std.testing.allocator);

    try std.testing.expect(conn.canReuse());
}

test "binary result drain captures streaming server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xff, 0x64, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'i', 'n', 'a', 'r', 'y', ' ', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var first = try rows.next(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(BinaryRowResultTag.row, first.tag);

    try std.testing.expectError(error.ServerError, rows.drain(std.testing.allocator));
    try std.testing.expect(!conn.isBroken());
    try std.testing.expect(conn.canReuse());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1124), last.code);
    try std.testing.expectEqualSlices(u8, "binary bad", last.message);
}

test "connection executeRows captures structured streaming server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xff, 0x64, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'i', 'n', 'a', 'r', 'y', ' ', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var err_row = try rows.next(std.testing.allocator);
    defer err_row.deinit(std.testing.allocator);

    try std.testing.expectEqual(BinaryRowResultTag.err, err_row.tag);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1124), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "binary bad", last.message);
}

test "binary row result decodes signed integer bytes using column flags" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinitionWithFlags(&server_bytes, 2, "value", .long, 0);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(i32, -1), (try row.intAt(i32, rows.columns, 0)).?);

    const Value = struct {
        value: i32,
    };
    var value: Value = undefined;
    try row.scan(&value, rows.columns);
    try std.testing.expectEqual(@as(i32, -1), value.value);
}

test "binary row result decodes unsigned integer bytes using column flags" {
    const unsigned_flag: u16 = 0x20;

    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinitionWithFlags(&server_bytes, 2, "value", .long, unsigned_flag);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 4294967295), (try row.intAt(u32, rows.columns, 0)).?);
}

test "binary row result decodes float and double fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "score", .float);
    try writeTestColumnDefinition(&server_bytes, 3, "ratio", .double);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{
        0x00,
        0x00,
        0x00,
        0x00,
        0xc0,
        0x3f,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x40,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(f32, 1.5), (try row.floatAt(f32, rows.columns, 0)).?);
    try std.testing.expectEqual(@as(f64, 2.25), (try row.floatByName(f64, rows.columns, "ratio")).?);

    const Metric = struct {
        score: f32,
        ratio: f64,
    };
    var metric: Metric = undefined;
    try row.scan(&metric, rows.columns);

    try std.testing.expectEqual(@as(f32, 1.5), metric.score);
    try std.testing.expectEqual(@as(f64, 2.25), metric.ratio);
}

test "binary row result supports bool accessors and scan fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "active", .tiny);
    try writeTestColumnDefinition(&server_bytes, 3, "archived", .tiny);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{
        0x00,
        0x00,
        0x01,
        0x00,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(true, (try row.boolAt(rows.columns, 0)).?);
    try std.testing.expectEqual(false, (try row.boolByName(rows.columns, "archived")).?);

    const Flags = struct {
        active: bool,
        archived: bool,
    };
    var flags: Flags = undefined;
    try row.scan(&flags, rows.columns);

    try std.testing.expectEqual(true, flags.active);
    try std.testing.expectEqual(false, flags.archived);
}

test "binary row result supports decimal accessors and scan fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "amount", .newdecimal);
    try writeTestColumnDefinition(&server_bytes, 3, "legacy", .decimal);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{
        0x00,
        0x00,
        0x08,
        '-',
        '1',
        '2',
        '3',
        '.',
        '4',
        '5',
        '6',
        0x05,
        '4',
        '2',
        '.',
        '0',
        '0',
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "-123.456", (try row.decimalAt(rows.columns, 0)).?.asBytes());
    try std.testing.expectEqualSlices(u8, "42.00", (try row.decimalByName(rows.columns, "legacy")).?.asBytes());

    const Amounts = struct {
        amount: Decimal,
        legacy: Decimal,
    };
    var amounts: Amounts = undefined;
    try row.scan(&amounts, rows.columns);

    try std.testing.expectEqualSlices(u8, "-123.456", amounts.amount.asBytes());
    try std.testing.expectEqualSlices(u8, "42.00", amounts.legacy.asBytes());
}

test "binary row result scans bit columns as byte slices" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "flags", .bit);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0x01,
        0b10101010,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const expected = [_]u8{0b10101010};
    try std.testing.expectEqualSlices(u8, &expected, (try row.valueAt(0)).?);

    const Flags = struct { flags: []const u8 };
    var flags: Flags = undefined;
    try row.scan(&flags, rows.columns);

    try std.testing.expectEqualSlices(u8, &expected, flags.flags);
}

test "binary row result scans geometry columns as byte slices" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "shape", .geometry);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0x04,
        0x01,
        0x02,
        0x03,
        0x04,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const expected = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectEqualSlices(u8, &expected, (try row.valueAt(0)).?);

    const Shape = struct { shape: []const u8 };
    var shape: Shape = undefined;
    try row.scan(&shape, rows.columns);

    try std.testing.expectEqualSlices(u8, &expected, shape.shape);
}

test "binary row result decodes datetime fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x04});
    try writeTestColumnDefinition(&server_bytes, 2, "created_on", .date);
    try writeTestColumnDefinition(&server_bytes, 3, "created_at", .datetime);
    try writeTestColumnDefinition(&server_bytes, 4, "updated_at", .timestamp);
    try writeTestColumnDefinition(&server_bytes, 5, "zero_at", .datetime);
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{
        0x00,
        0x00,
        0x04,
        0xea,
        0x07,
        0x06,
        0x10,
        0x07,
        0xea,
        0x07,
        0x06,
        0x10,
        0x0c,
        0x22,
        0x38,
        0x0b,
        0xea,
        0x07,
        0x06,
        0x10,
        0x0c,
        0x22,
        0x38,
        0x40,
        0xe2,
        0x01,
        0x00,
        0x00,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 8, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 4),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16 }, (try row.dateTimeAt(rows.columns, 0)).?);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 }, (try row.dateTimeByName(rows.columns, "updated_at")).?);
    try std.testing.expectEqual(DateTime{}, (try row.dateTimeByName(rows.columns, "zero_at")).?);

    const Event = struct {
        created_on: DateTime,
        created_at: DateTime,
        updated_at: DateTime,
        zero_at: DateTime,
    };
    var event: Event = undefined;
    try row.scan(&event, rows.columns);

    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16 }, event.created_on);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56 }, event.created_at);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 }, event.updated_at);
    try std.testing.expectEqual(DateTime{}, event.zero_at);
}

test "binary row result decodes time fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "elapsed", .time);
    try writeTestColumnDefinition(&server_bytes, 3, "empty", .time);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{
        0x00,
        0x00,
        0x0c,
        0x01,
        0x02,
        0x00,
        0x00,
        0x00,
        0x03,
        0x04,
        0x05,
        0x40,
        0xe2,
        0x01,
        0x00,
        0x00,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, (try row.timeAt(rows.columns, 0)).?);
    try std.testing.expectEqual(Time{}, (try row.timeByName(rows.columns, "empty")).?);

    const Event = struct {
        elapsed: Time,
        empty: Time,
    };
    var event: Event = undefined;
    try row.scan(&event, rows.columns);

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, event.elapsed);
    try std.testing.expectEqual(Time{}, event.empty);
}

test "binary row result scans optional datetime fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "deleted_at", .datetime);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0b00000100,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const Event = struct {
        deleted_at: ?DateTime,
    };
    var event: Event = undefined;
    try row.scan(&event, rows.columns);

    try std.testing.expect(event.deleted_at == null);
}

test "binary row result rejects datetime accessor for non-temporal column" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidColumnType, row.dateTimeAt(rows.columns, 0));
}

test "binary row result rejects invalid bool values" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "active", .tiny);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0x02,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidBoolValue, row.boolAt(rows.columns, 0));
}

test "binary row result scans supported fields into struct" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x03});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try writeTestColumnDefinition(&server_bytes, 4, "maybe_id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{
        0x00,
        0b00010000,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 3),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);

    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
        maybe_id: ?i32,
    };
    var user: User = undefined;
    try row.scan(&user, rows.columns);

    try std.testing.expectEqual(@as(i32, 42), user.id);
    try std.testing.expectEqualSlices(u8, "bob", user.name);
    try std.testing.expect(user.maybe_id == null);
}

test "binary row result scanAlloc duplicates string fields" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{
        0x00,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 0x12345678,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 2),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const User = struct {
        id: i32,
        name: []const u8,
    };
    var user: User = undefined;
    try row.scanAlloc(&user, rows.columns, arena.allocator());

    const borrowed = (try row.valueByName(rows.columns, "name")).?;
    try std.testing.expectEqual(@as(i32, 42), user.id);
    try std.testing.expectEqualSlices(u8, "bob", user.name);
    try std.testing.expect(user.name.ptr != borrowed.ptr);
}

test "binary row result rejects null for non-optional scan field" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0b00000100,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: i32,
    };
    var user: User = undefined;

    try std.testing.expectError(error.UnexpectedNullValue, row.scan(&user, rows.columns));
}

test "binary row result rejects unsupported scan field type" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{
        0x00,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
    });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    const stmt = PreparedStatement{
        .id = 1,
        .params = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 0),
        .columns = try std.testing.allocator.alloc(protocol.text_result.ColumnDefinition41, 1),
    };
    defer std.testing.allocator.free(stmt.params);
    defer std.testing.allocator.free(stmt.columns);

    var rows = try conn.executeRows(std.testing.allocator, &stmt, .{});
    defer rows.deinit(std.testing.allocator);
    var row = try rows.next(std.testing.allocator);
    defer row.deinit(std.testing.allocator);

    const User = struct {
        id: *const u8,
    };
    var user: User = undefined;

    try std.testing.expectError(error.UnsupportedScanFieldType, row.scan(&user, rows.columns));
}

test "binary row result records scan diagnostics on failure" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};
    var value_bytes = [_]u8{ 0x2a, 0x00, 0x00, 0x00 };
    var values = [_]?[]const u8{value_bytes[0..]};
    var payload: [0]u8 = .{};
    var row = BinaryRowResult{
        .tag = .row,
        .transport_row = .{ .tag = .row, .payload = payload[0..], .values = values[0..], .owns_values = false },
        .values = values[0..],
    };

    const Row = struct { id: []const u8 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.InvalidColumnType, row.scan(&scanned, columns[0..]));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.InvalidColumnType, diag.reason);
    try std.testing.expectEqual(@as(usize, 0), diag.index.?);
    try std.testing.expectEqualSlices(u8, "id", diag.field_name);
    try std.testing.expectEqualSlices(u8, "id", diag.column_name.?);
    try std.testing.expectEqualSlices(u8, "[]const u8", diag.target_type);
}

test "binary row result records scan diagnostics for null fields" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};
    var values = [_]?[]const u8{null};
    var payload: [0]u8 = .{};
    var row = BinaryRowResult{
        .tag = .row,
        .transport_row = .{ .tag = .row, .payload = payload[0..], .values = values[0..], .owns_values = false },
        .values = values[0..],
    };

    const Row = struct { id: i32 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.UnexpectedNullValue, row.scan(&scanned, columns[0..]));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.UnexpectedNullValue, diag.reason);
    try std.testing.expectEqual(@as(usize, 0), diag.index.?);
    try std.testing.expectEqualSlices(u8, "id", diag.field_name);
    try std.testing.expectEqualSlices(u8, "id", diag.column_name.?);
    try std.testing.expectEqualSlices(u8, "i32", diag.target_type);
}

test "binary row result records scan diagnostics for unknown columns" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};
    var value_bytes = [_]u8{ 0x2a, 0x00, 0x00, 0x00 };
    var values = [_]?[]const u8{value_bytes[0..]};
    var payload: [0]u8 = .{};
    var row = BinaryRowResult{
        .tag = .row,
        .transport_row = .{ .tag = .row, .payload = payload[0..], .values = values[0..], .owns_values = false },
        .values = values[0..],
    };

    const Row = struct { missing: i32 };
    var scanned: Row = undefined;
    try std.testing.expectError(error.UnknownColumnName, row.scan(&scanned, columns[0..]));

    const diag = row.lastScanError().?;
    try std.testing.expectEqual(error.UnknownColumnName, diag.reason);
    try std.testing.expect(diag.index == null);
    try std.testing.expectEqualSlices(u8, "missing", diag.field_name);
    try std.testing.expect(diag.column_name == null);
    try std.testing.expectEqualSlices(u8, "i32", diag.target_type);
}

test "connection query exposes ok summary" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    // OK: affected_rows=5, last_insert_id=10, status_flags=autocommit, warnings=1
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x05, 0x0a, 0x02, 0x00, 0x01, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    try conn.finishHandshake(std.testing.allocator);

    var result = try conn.query(std.testing.allocator, "insert into t values (1)");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result == .ok);
    try std.testing.expectEqual(@as(u64, 5), result.ok.affected_rows);
    try std.testing.expectEqual(@as(u64, 10), result.ok.last_insert_id);
    try std.testing.expectEqual(@as(u16, 1), result.ok.warnings);

    try std.testing.expectEqual(@as(u64, 5), (try result.expectOk()).affected_rows);
}

test "connection query exposes structured server error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var result = try conn.query(std.testing.allocator, "bad sql");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result == .err);
    try std.testing.expectEqual(@as(u16, 1045), result.err.code);
    try std.testing.expectEqualSlices(u8, "HY000", &result.err.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad", result.err.message);

    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1045), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad", last.message);

    try std.testing.expectError(error.ServerError, result.expectOk());
}

test "connection query server error cleans up on allocation failure" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
            defer server_bytes.deinit();
            try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
            try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
            try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

            var io = TestByteStream.init(server_bytes.bytes());
            defer io.deinit();
            var conn = Connection.init(.{
                .reader = io.reader(),
                .writer = io.writer(),
            }, .{
                .username = "root",
                .password = "secret",
                .character_set = protocol.collation.utf8mb4_general_ci,
            });
            defer conn.deinit(allocator);

            try conn.finishHandshake(std.testing.allocator);
            io.written.clearRetainingCapacity();

            var result = try conn.query(allocator, "bad sql");
            defer result.deinit(allocator);
            try std.testing.expect(result == .err);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}

test "connection query lastError allocation failure keeps connection reusable" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 5 });
    try std.testing.expectError(error.OutOfMemory, conn.query(failing_allocator.allocator(), "bad sql"));
    try std.testing.expect(!conn.isBroken());
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection surfaces structured error after queryRows failure" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));

    // A server (soft) error is fully diagnosable and leaves the connection usable.
    try std.testing.expect(!conn.isBroken());
    const last = conn.lastError().?;
    try std.testing.expectEqual(@as(u16, 1045), last.code);
    try std.testing.expectEqualSlices(u8, "HY000", &last.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad", last.message);
}

test "connection ping clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    try conn.ping(std.testing.allocator);

    try std.testing.expect(conn.lastError() == null);
}

test "connection query ok clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var result = try conn.query(std.testing.allocator, "delete from t where id = 1");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .ok);

    try std.testing.expect(conn.lastError() == null);
}

test "connection queryRows result set clears stale server error after success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    try std.testing.expectError(error.ServerError, conn.queryRows(std.testing.allocator, "select bad"));
    try std.testing.expect(conn.lastError() != null);

    var rows = try conn.queryRows(std.testing.allocator, "select id from users");
    defer rows.deinit(std.testing.allocator);
    try std.testing.expect(conn.lastError() == null);

    var eof = try rows.next(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(TextRowResultTag.eof, eof.tag);
}

test "connection rejects local infile request by default" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xfb, 'd', 'a', 't', 'a', '.', 'c', 's', 'v' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.LocalInfileDisabled, conn.query(std.testing.allocator, "load data local infile 'data.csv' into table t"));
    try std.testing.expect(conn.isBroken());
}

test "connection becomes broken on truncated response and refuses commands" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    // No response to the query: the stream ends, so readQueryResponse hits EndOfStream.

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    try std.testing.expectError(error.EndOfStream, conn.query(std.testing.allocator, "select 1"));
    try std.testing.expect(conn.isBroken());

    // A broken connection refuses further commands instead of corrupting the stream.
    try std.testing.expectError(error.ConnectionBroken, conn.ping(std.testing.allocator));
}

test "connection exec prepares binds and returns ok summary" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    // COM_STMT_PREPARE response: stmt_id=1, num_columns=0, num_params=1.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    // COM_STMT_EXECUTE response: OK with affected_rows=3.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00 });
    // The statement stays cached on the connection; it is freed by conn.deinit.

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const ok = try conn.exec(std.testing.allocator, "delete from t where id = ?", .{@as(i32, 7)});

    try std.testing.expectEqual(@as(u64, 3), ok.affected_rows);
    // After exec the connection is drained and ready for the next command.
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "exec handles a prepared statement id whose low byte is a length-enc marker" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    // COM_STMT_PREPARE response: statement_id=0x000000fb (251), 0 columns, 0
    // params. 0xfb is the length-encoded-integer NULL marker; if the PREPARE_OK
    // is misparsed as a generic OK packet, this byte is read as the OK packet's
    // length-encoded affected-rows and the stream desyncs.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    // COM_STMT_EXECUTE response: OK with affected_rows=1.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const ok = try conn.exec(std.testing.allocator, "delete from t", .{});
    try std.testing.expectEqual(@as(u64, 1), ok.affected_rows);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection stays usable after server command error" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    // First command: server error (e.g. duplicate key). Connection must remain reusable.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });
    // Second command: OK. Proves the connection accepted another command after the error.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    var first = try conn.query(std.testing.allocator, "insert duplicate");
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first == .err);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);

    var second = try conn.query(std.testing.allocator, "insert ok");
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(second == .ok);
    try std.testing.expectEqual(@as(u64, 1), second.ok.affected_rows);
}

fn okPacketBytes() [7]u8 {
    return .{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
}

test "connection queryAll collects owned typed rows" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '1', 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0x01, '2', 0x03, 't', 'w', 'o' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
    };

    var table = try conn.queryAll(User, std.testing.allocator, "select id, name from t");
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 2), table.rows.len);
    try std.testing.expectEqual(@as(i32, 1), table.rows[0].id);
    try std.testing.expectEqualSlices(u8, "one", table.rows[0].name);
    try std.testing.expectEqual(@as(i32, 2), table.rows[1].id);
    try std.testing.expectEqualSlices(u8, "two", table.rows[1].name);

    // Connection is drained and ready for the next command.
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection queryOne returns the single row" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x02, '4', '2', 0x03, 'b', 'o', 'b' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
    };

    var table = try conn.queryOne(User, std.testing.allocator, "select id, name from t where id = 42");
    defer table.deinit();

    const user = try table.one();
    try std.testing.expectEqual(@as(i32, 42), user.id);
    try std.testing.expectEqualSlices(u8, "bob", user.name);
}

test "connection queryOne rejects a multi-row result" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x01, '2' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const Row = struct { id: i32 };
    try std.testing.expectError(error.UnexpectedRowCount, conn.queryOne(Row, std.testing.allocator, "select id from t"));
}

test "connection queryAllParams collects owned typed rows from prepared statement" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    // COM_STMT_PREPARE response: stmt_id=1, num_columns=2, num_params=1.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 2, "min_id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 4, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 5, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    // COM_STMT_EXECUTE response: result set with two binary rows.
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 'o', 'n', 'e' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 't', 'w', 'o' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 7, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    // COM_STMT_CLOSE has no response.

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
    };
    const Params = struct { min_id: i32 };

    var table = try conn.queryAllParams(User, std.testing.allocator, "select id, name from t where id >= ?", Params{ .min_id = 1 });
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 2), table.rows.len);
    try std.testing.expectEqual(@as(i32, 1), table.rows[0].id);
    try std.testing.expectEqualSlices(u8, "one", table.rows[0].name);
    try std.testing.expectEqual(@as(i32, 2), table.rows[1].id);
    try std.testing.expectEqualSlices(u8, "two", table.rows[1].name);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);
}

test "connection queryOneParams returns the single prepared row" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try writeTestColumnDefinition(&server_bytes, 4, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 5, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x02});
    try writeTestColumnDefinition(&server_bytes, 2, "id", .long);
    try writeTestColumnDefinition(&server_bytes, 3, "name", .var_string);
    try protocol.packet.writeLogicalPayload(&server_bytes, 4, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 5, &.{ 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x03, 'b', 'o', 'b' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 6, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);

    const User = struct {
        id: i32,
        name: []const u8,
    };
    var table = try conn.queryOneParams(User, std.testing.allocator, "select id, name from t where id = ?", .{@as(i32, 42)});
    defer table.deinit();

    const user = try table.one();
    try std.testing.expectEqual(@as(i32, 42), user.id);
    try std.testing.expectEqualSlices(u8, "bob", user.name);
}

test "connection transaction begins and commits" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // COMMIT

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "START TRANSACTION") != null);

    try tx.commit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "COMMIT") != null);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, conn.transport.packet_stream.phase.state);

    // deinit after commit must be a no-op (no ROLLBACK sent).
    tx.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK") == null);
}

test "transaction rolls back when deinit without commit" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // ROLLBACK

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    tx.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK") != null);
}

// --- StatementCache unit tests ---------------------------------------------
// These pin the LRU list/map bookkeeping deterministically with fake (already
// closed, server-less) statements; the end-to-end "second call skips PREPARE"
// and ER_NEED_REPREPARE recovery are proven in the integration suite.

// --- Transaction options / savepoint tests ---------------------------------

test "beginWith emits isolation level and access mode" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // SET TRANSACTION ISOLATION LEVEL
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION READ ONLY

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.beginWith(std.testing.allocator, .{ .isolation = .serializable, .access_mode = .read_only });
    tx.finished = true; // no real server to ROLLBACK against on deinit

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "START TRANSACTION READ ONLY") != null);
}

test "transaction savepoint commands quote the identifier on the wire" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // SAVEPOINT
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // ROLLBACK TO SAVEPOINT
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // RELEASE SAVEPOINT

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    try tx.savepoint(std.testing.allocator, "sp1");
    try tx.rollbackTo(std.testing.allocator, "sp1");
    try tx.releaseSavepoint(std.testing.allocator, "sp1");
    tx.finished = true;

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "SAVEPOINT `sp1`") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK TO SAVEPOINT `sp1`") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "RELEASE SAVEPOINT `sp1`") != null);
}

test "connection captures the server thread id from the handshake" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 0), conn.serverThreadId()); // unknown before handshake
    try conn.finishHandshake(std.testing.allocator);
    // sample_handshake encodes connection_id = 0x3039 = 12345.
    try std.testing.expectEqual(@as(u32, 12345), conn.serverThreadId());
}

const Transaction = mantle.Transaction;

test "transact commits on success and releases the connection" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // COMMIT

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    try conn.transact(std.testing.allocator, {}, struct {
        fn run(_: void, _: *Transaction) anyerror!void {}
    }.run);

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "START TRANSACTION") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "COMMIT") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK") == null);
    try std.testing.expect(!conn.in_transaction);
}

test "transact rolls back when the body fails and releases the connection" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // ROLLBACK

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    const result = conn.transact(std.testing.allocator, {}, struct {
        fn run(_: void, _: *Transaction) anyerror!void {
            return error.Boom;
        }
    }.run);
    try std.testing.expectError(error.Boom, result);

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK") != null);
    try std.testing.expect(!conn.in_transaction);
    try std.testing.expect(!conn.isBroken());
}

test "transact does not double-act when the body finishes the transaction" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // COMMIT (by body)

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    // The body commits itself; transact must honor `finished` and not send a
    // second COMMIT (only one COMMIT ok packet is scripted).
    try conn.transact(std.testing.allocator, std.testing.allocator, struct {
        fn run(a: std.mem.Allocator, tx: *Transaction) anyerror!void {
            try tx.commit(a);
        }
    }.run);

    const first = std.mem.indexOf(u8, io.written.items, "COMMIT").?;
    try std.testing.expectEqual(first, std.mem.lastIndexOf(u8, io.written.items, "COMMIT").?);
    try std.testing.expect(!conn.in_transaction);
}

test "beginWith rejects a nested transaction" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    const after_begin = io.written.items.len;
    // A second begin must be refused before any bytes hit the wire, so that
    // MySQL's implicit commit of the outer transaction can never be triggered.
    try std.testing.expectError(error.TransactionActive, conn.beginWith(std.testing.allocator, .{}));
    try std.testing.expectEqual(after_begin, io.written.items.len);
    try std.testing.expect(conn.in_transaction);
    tx.finished = true; // skip auto-rollback in deinit (no bytes scripted)
}

test "withSavepoint releases the savepoint on success" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // SAVEPOINT
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // RELEASE SAVEPOINT
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // COMMIT

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    try tx.withSavepoint(std.testing.allocator, "sp1", {}, struct {
        fn run(_: void, _: *Transaction) anyerror!void {}
    }.run);
    try tx.commit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "SAVEPOINT `sp1`") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "RELEASE SAVEPOINT `sp1`") != null);
    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK TO SAVEPOINT") == null);
}

test "withSavepoint rolls back to the savepoint when the body fails" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &okPacketBytes());
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // START TRANSACTION
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // SAVEPOINT
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &okPacketBytes()); // ROLLBACK TO SAVEPOINT

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var conn = Connection.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    defer conn.deinit(std.testing.allocator);

    try conn.finishHandshake(std.testing.allocator);
    io.written.clearRetainingCapacity();

    var tx = try conn.begin(std.testing.allocator);
    const result = tx.withSavepoint(std.testing.allocator, "sp1", {}, struct {
        fn run(_: void, _: *Transaction) anyerror!void {
            return error.Boom;
        }
    }.run);
    try std.testing.expectError(error.Boom, result);

    try std.testing.expect(std.mem.indexOf(u8, io.written.items, "ROLLBACK TO SAVEPOINT `sp1`") != null);
    // The transaction is still open (the savepoint scope failed, not the tx).
    try std.testing.expect(!tx.finished);
    try std.testing.expect(conn.in_transaction);
    tx.finished = true; // skip auto-rollback in deinit (no bytes scripted)
}
