const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;

const connection_phase = @import("connection_phase.zig");
const ConnectionPhase = connection_phase.ConnectionPhase;

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

test "connection phase writes handshake response then reaches ready on ok" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const action = try phase.receiveInitialHandshake(&writer, &sample_handshake);

    try std.testing.expectEqual(ConnectionPhase.State.authenticating, phase.state);
    try std.testing.expectEqual(ConnectionPhase.Action.send_handshake_response, action);
    try std.testing.expect(writer.bytes().len > 0);

    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveAuthPacket(&writer, &ok_payload));
    try std.testing.expectEqual(ConnectionPhase.State.ready, phase.state);
}

test "connection phase negotiates only server-supported auth flags" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);

    const client_flags = std.mem.readInt(u32, writer.bytes()[0..4], .little);
    try std.testing.expect((client_flags & protocol.capability.client_protocol_41) != 0);
    try std.testing.expect((client_flags & protocol.capability.client_secure_connection) != 0);
    try std.testing.expect((client_flags & protocol.capability.client_plugin_auth) != 0);
    try std.testing.expectEqual(@as(u32, 0), client_flags & protocol.capability.client_plugin_auth_lenenc_client_data);
}

test "connection phase omits plugin auth flag when server did not negotiate it" {
    var handshake = sample_handshake;
    handshake[26] &= ~@as(u8, 0x08);

    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &handshake);

    const client_flags = std.mem.readInt(u32, writer.bytes()[0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), client_flags & protocol.capability.client_plugin_auth);
    try std.testing.expectEqual(@as(u32, 0), client_flags & protocol.capability.client_plugin_auth_lenenc_client_data);
    try std.testing.expect(std.mem.indexOf(u8, writer.bytes(), "mysql_native_password\x00") == null);
}

test "connection phase sets connect-with-db only when negotiated" {
    var handshake = sample_handshake;
    handshake[21] |= protocol.capability.client_connect_with_db;

    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .database = "app",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &handshake);

    const client_flags = std.mem.readInt(u32, writer.bytes()[0..4], .little);
    try std.testing.expect((client_flags & protocol.capability.client_connect_with_db) != 0);
    try std.testing.expect(std.mem.indexOf(u8, writer.bytes(), "app\x00") != null);
}

test "connection phase omits connect-with-db when server did not negotiate it" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .database = "app",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);

    const client_flags = std.mem.readInt(u32, writer.bytes()[0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), client_flags & protocol.capability.client_connect_with_db);
    try std.testing.expect(std.mem.indexOf(u8, writer.bytes(), "app\x00") == null);
}

test "connection phase writes auth response on auth switch request" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();

    const switch_payload = [_]u8{ 0xfe, 'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, 's', 'e', 'e', 'd' };
    const action = try phase.receiveAuthPacket(&writer, &switch_payload);

    try std.testing.expectEqual(ConnectionPhase.Action.send_auth_response, action);
    try std.testing.expectEqual(ConnectionPhase.State.authenticating, phase.state);
    try std.testing.expect(writer.bytes().len == 20);
}

test "connection phase handles caching sha2 fast auth success then ok" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();

    const more = [_]u8{ 0x01, protocol.auth.caching_sha2_password_fast_auth_success };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveAuthPacket(&writer, &more));
    try std.testing.expectEqual(ConnectionPhase.State.authenticating, phase.state);

    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveAuthPacket(&writer, &ok_payload));
    try std.testing.expectEqual(ConnectionPhase.State.ready, phase.state);
}

test "connection phase handles initial server err as failed" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const err_payload = [_]u8{ 0xff, 0x15, 0x04, 'n', 'o' };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveInitialHandshake(&writer, &err_payload));
    try std.testing.expectEqual(ConnectionPhase.State.failed, phase.state);
}

test "connection phase handles auth err as failed" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);

    const err_payload = [_]u8{ 0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'n', 'o' };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveAuthPacket(&writer, &err_payload));
    try std.testing.expectEqual(ConnectionPhase.State.failed, phase.state);
}

test "connection phase rejects input in invalid state" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try std.testing.expectError(protocol.types.Error.InvalidConnectionPhaseState, phase.receiveAuthPacket(&writer, &.{0x00}));
}

test "connection phase sends command only when ready and returns ready after ok" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try std.testing.expectError(protocol.types.Error.InvalidConnectionPhaseState, phase.sendCommand(&writer, .ping));

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);

    try std.testing.expectEqual(ConnectionPhase.Action.send_command, try phase.sendCommand(&writer, .ping));
    try std.testing.expectEqual(ConnectionPhase.State.command_inflight, phase.state);
    try std.testing.expectEqualSlices(u8, &.{0x0e}, writer.bytes());

    writer.clearRetainingCapacity();
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveCommandResponse(&ok_payload));
    try std.testing.expectEqual(ConnectionPhase.State.ready, phase.state);
}

test "connection phase continues after command ok with more results" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommand(&writer, protocol.command.Command.initQuery("call p()"));

    const ok_more = [_]u8{ 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveCommandResponse(&ok_more));
    try std.testing.expectEqual(ConnectionPhase.State.command_inflight, phase.state);

    try std.testing.expectEqual(ConnectionPhase.Action.start_result_stream, try phase.receiveCommandResponse(&.{0x01}));
    try std.testing.expectEqual(ConnectionPhase.State.result_streaming, phase.state);
}

test "connection phase sends no-response command only when ready and stays ready" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try std.testing.expectError(protocol.types.Error.InvalidConnectionPhaseState, phase.sendNoResponseCommand(&writer, protocol.command.Command.initStmtClose(1)));

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);

    try std.testing.expectEqual(ConnectionPhase.Action.send_command, try phase.sendNoResponseCommand(&writer, protocol.command.Command.initStmtClose(0x12345678)));
    try std.testing.expectEqual(ConnectionPhase.State.ready, phase.state);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x78, 0x56, 0x34, 0x12 }, writer.bytes());
}

test "connection phase enters result streaming for result set response" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommand(&writer, protocol.command.Command.initQuery("select 1"));

    const column_count_payload = [_]u8{0x01};
    try std.testing.expectEqual(ConnectionPhase.Action.start_result_stream, try phase.receiveCommandResponse(&column_count_payload));
    try std.testing.expectEqual(ConnectionPhase.State.result_streaming, phase.state);
}

test "connection phase drains result stream terminator back to ready" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommand(&writer, protocol.command.Command.initQuery("select 1"));
    _ = try phase.receiveCommandResponse(&.{0x01});

    const row = [_]u8{ 0x01, '1' };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveTextResultStreamPacket(&row, 1));
    try std.testing.expectEqual(ConnectionPhase.State.result_streaming, phase.state);

    const eof = [_]u8{ 0xfe, 0x00, 0x00, 0x02, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveTextResultStreamPacket(&eof, 1));
    try std.testing.expectEqual(ConnectionPhase.State.ready, phase.state);
}

test "connection phase continues after text result terminator with more results" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommand(&writer, protocol.command.Command.initQuery("select 1; select 2"));
    _ = try phase.receiveCommandResponse(&.{0x01});

    const eof_more = [_]u8{ 0xfe, 0x00, 0x00, 0x0a, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveTextResultStreamPacket(&eof_more, 1));
    try std.testing.expectEqual(ConnectionPhase.State.command_inflight, phase.state);

    try std.testing.expectEqual(ConnectionPhase.Action.start_result_stream, try phase.receiveCommandResponse(&.{0x01}));
    try std.testing.expectEqual(ConnectionPhase.State.result_streaming, phase.state);
}

test "connection phase continues after binary result terminator with more results" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommandPayload(&writer, &.{0x17});
    _ = try phase.receiveCommandResponse(&.{0x01});

    const eof_more = [_]u8{ 0xfe, 0x00, 0x00, 0x0a, 0x00 };
    try std.testing.expectEqual(ConnectionPhase.Action.none, try phase.receiveBinaryResultStreamPacket(&eof_more));
    try std.testing.expectEqual(ConnectionPhase.State.command_inflight, phase.state);

    try std.testing.expectEqual(ConnectionPhase.Action.start_result_stream, try phase.receiveCommandResponse(&.{0x01}));
    try std.testing.expectEqual(ConnectionPhase.State.result_streaming, phase.state);
}

test "connection phase rejects empty binary result stream packet" {
    var phase = ConnectionPhase.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    _ = try phase.receiveInitialHandshake(&writer, &sample_handshake);
    writer.clearRetainingCapacity();
    const ok_payload = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    _ = try phase.receiveAuthPacket(&writer, &ok_payload);
    _ = try phase.sendCommandPayload(&writer, &.{0x17});
    _ = try phase.receiveCommandResponse(&.{0x01});

    try std.testing.expectError(protocol.types.Error.EndOfPayload, phase.receiveBinaryResultStreamPacket(""));
}
