const std = @import("std");

const mantle = @import("mantle.zig");
const protocol = mantle.protocol;
const transport = @import("transport.zig");

const ResultRowTag = transport.ResultRowTag;

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

test "transport reads server handshake and writes framed client response" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    const action = try stream.receiveNext(std.testing.allocator);

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.send_handshake_response, action);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.authenticating, stream.packet_stream.phase.state);
    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 1), header.sequence_id);
    try std.testing.expect(header.payload_length > 0);
}

test "transport captures access-denied error from failed handshake" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    // ERR(1045) #28000 "Access denied" — the auth response gets rejected.
    const auth_err = [_]u8{ 0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0' } ++ "Access denied".*;
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &auth_err);

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    _ = try stream.receiveNext(std.testing.allocator); // handshake -> send response
    _ = try stream.receiveNext(std.testing.allocator); // auth ERR -> failed
    try std.testing.expectEqual(mantle.ConnectionPhase.State.failed, stream.packet_stream.phase.state);

    var captured = stream.takeHandshakeError() orelse return error.TestExpectedHandshakeError;
    defer captured.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 1045), captured.code);
    try std.testing.expectEqualSlices(u8, "28000", &captured.sql_state.?);
    try std.testing.expectEqualSlices(u8, "Access denied", captured.message);
    // Ownership transferred: a second take yields nothing.
    try std.testing.expect(stream.takeHandshakeError() == null);
}

test "transport writes command packet after connection is ready" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    _ = try stream.receiveNext(std.testing.allocator);
    io.written.clearRetainingCapacity();
    _ = try stream.receiveNext(std.testing.allocator);
    try stream.sendCommand(std.testing.allocator, .ping);

    const header = try protocol.types.PacketHeader.decode(io.written.items[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(usize, 1), header.payload_length);
    try std.testing.expectEqual(@as(u8, 0x0e), io.written.items[4]);
}

test "transport reads query result rows until eof" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x01, '1' });
    try protocol.packet.writeLogicalPayload(&server_bytes, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    _ = try stream.receiveNext(std.testing.allocator);
    io.written.clearRetainingCapacity();
    _ = try stream.receiveNext(std.testing.allocator);
    try stream.sendCommand(std.testing.allocator, protocol.command.Command.initQuery("select 1"));

    const response = try stream.readQueryResponse(std.testing.allocator);
    try std.testing.expect(response == .result_set);
    try std.testing.expectEqual(@as(usize, 1), stream.packet_stream.result_column_count);

    var row = try stream.readTextRow(std.testing.allocator);
    defer row.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultRowTag.row, row.tag);
    try std.testing.expectEqualSlices(u8, "1", row.values[0].?);

    var eof = try stream.readTextRow(std.testing.allocator);
    defer eof.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultRowTag.eof, eof.tag);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, stream.packet_stream.phase.state);
}

test "transport stays reusable after result row error packet" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' });

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    _ = try stream.receiveNext(std.testing.allocator);
    io.written.clearRetainingCapacity();
    _ = try stream.receiveNext(std.testing.allocator);
    try stream.sendCommand(std.testing.allocator, protocol.command.Command.initQuery("select 1"));
    try std.testing.expect((try stream.readQueryResponse(std.testing.allocator)) == .result_set);

    var err_row = try stream.readTextRow(std.testing.allocator);
    defer err_row.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultRowTag.err, err_row.tag);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, stream.packet_stream.phase.state);
}

test "transport rejects empty binary row payload" {
    var server_bytes = protocol.PayloadWriter.init(std.testing.allocator);
    defer server_bytes.deinit();
    try protocol.packet.writeLogicalPayload(&server_bytes, 0, &sample_handshake);
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    try protocol.packet.writeLogicalPayload(&server_bytes, 1, &.{0x01});
    try protocol.packet.writeLogicalPayload(&server_bytes, 2, &.{0x01});

    var io = TestByteStream.init(server_bytes.bytes());
    defer io.deinit();
    var stream = mantle.Transport.init(.{
        .reader = io.reader(),
        .writer = io.writer(),
    }, .{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });

    _ = try stream.receiveNext(std.testing.allocator);
    io.written.clearRetainingCapacity();
    _ = try stream.receiveNext(std.testing.allocator);
    try stream.sendCommand(std.testing.allocator, protocol.command.Command.initQuery("select 1"));
    try std.testing.expect((try stream.readQueryResponse(std.testing.allocator)) == .result_set);

    try std.testing.expectError(protocol.types.Error.EndOfPayload, stream.readBinaryRow(std.testing.allocator, &.{}));
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
