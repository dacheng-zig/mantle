const std = @import("std");

const packet_stream = @import("packet_stream.zig");
const PacketStream = packet_stream.PacketStream;

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;

test "packet stream reconstructs multi-fragment server packet" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, protocol.types.max_packet_payload_size + 1);
    defer allocator.free(payload);
    @memset(payload, 0x00);
    payload[0] = 0xff;
    payload[1] = 0x15;
    payload[2] = 0x04;

    var framed_server = protocol.PayloadWriter.init(allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, payload);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(allocator);
    defer framed_client.deinit();

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.none, try stream.receiveServerPackets(allocator, &framed_client, framed_server.bytes()));
    try std.testing.expectEqual(mantle.ConnectionPhase.State.failed, stream.phase.state);
}

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

test "packet stream turns framed handshake into framed client response" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();

    const action = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes());

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.send_handshake_response, action);
    try std.testing.expectEqual(mantle.ConnectionPhase.State.authenticating, stream.phase.state);
    const header = try protocol.types.PacketHeader.decode(framed_client.bytes()[0..4]);
    try std.testing.expectEqual(@as(u8, 1), header.sequence_id);
    try std.testing.expect(header.payload_length > 0);
}

test "packet stream turns framed ok into ready" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes());

    var framed_ok = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_ok.deinit();
    try protocol.packet.writeLogicalPayload(&framed_ok, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.none, try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_ok.bytes()));
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, stream.phase.state);
}

test "packet stream continues sequence after auth switch response" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes());
    framed_client.clearRetainingCapacity();

    var framed_switch = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_switch.deinit();
    const switch_payload = [_]u8{ 0xfe, 'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, 's', 'e', 'e', 'd' };
    try protocol.packet.writeLogicalPayload(&framed_switch, 2, &switch_payload);

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.send_auth_response, try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_switch.bytes()));
    const auth_response_header = try protocol.types.PacketHeader.decode(framed_client.bytes()[0..4]);
    try std.testing.expectEqual(@as(u8, 3), auth_response_header.sequence_id);

    var framed_ok = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_ok.deinit();
    try protocol.packet.writeLogicalPayload(&framed_ok, 4, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.none, try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_ok.bytes()));
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, stream.phase.state);
}

test "packet stream rejects server sequence mismatch" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 1, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();

    try std.testing.expectError(protocol.types.Error.SequenceMismatch, stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes()));
}

test "packet stream frames command with sequence zero after ready" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes());

    var framed_ok = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_ok.deinit();
    try protocol.packet.writeLogicalPayload(&framed_ok, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_ok.bytes());
    framed_client.clearRetainingCapacity();

    try std.testing.expectEqual(mantle.ConnectionPhase.Action.send_command, try stream.sendCommand(std.testing.allocator, &framed_client, .ping));
    const header = try protocol.types.PacketHeader.decode(framed_client.bytes()[0..4]);
    try std.testing.expectEqual(@as(u8, 0), header.sequence_id);
    try std.testing.expectEqual(@as(usize, 1), header.payload_length);
    try std.testing.expectEqual(@as(u8, 0x0e), framed_client.bytes()[4]);
}

test "packet stream drains result stream back to ready" {
    var framed_server = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_server.deinit();
    try protocol.packet.writeLogicalPayload(&framed_server, 0, &sample_handshake);

    var stream = PacketStream.init(.{
        .username = "root",
        .password = "secret",
        .character_set = protocol.collation.utf8mb4_general_ci,
    });
    var framed_client = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_client.deinit();
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_server.bytes());

    var framed_ok = protocol.PayloadWriter.init(std.testing.allocator);
    defer framed_ok.deinit();
    try protocol.packet.writeLogicalPayload(&framed_ok, 2, &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 });
    _ = try stream.receiveServerPackets(std.testing.allocator, &framed_client, framed_ok.bytes());
    framed_client.clearRetainingCapacity();

    _ = try stream.sendCommand(std.testing.allocator, &framed_client, protocol.command.Command.initQuery("select 1"));

    var column_count = protocol.PayloadWriter.init(std.testing.allocator);
    defer column_count.deinit();
    try protocol.packet.writeLogicalPayload(&column_count, 1, &.{0x01});
    try std.testing.expectEqual(mantle.ConnectionPhase.Action.start_result_stream, try stream.receiveServerPackets(std.testing.allocator, &framed_client, column_count.bytes()));
    try std.testing.expectEqual(@as(usize, 1), stream.result_column_count);

    var row = protocol.PayloadWriter.init(std.testing.allocator);
    defer row.deinit();
    try protocol.packet.writeLogicalPayload(&row, 2, &.{ 0x01, '1' });
    try std.testing.expectEqual(mantle.ConnectionPhase.Action.none, try stream.receiveServerPackets(std.testing.allocator, &framed_client, row.bytes()));
    try std.testing.expectEqual(mantle.ConnectionPhase.State.result_streaming, stream.phase.state);

    var eof = protocol.PayloadWriter.init(std.testing.allocator);
    defer eof.deinit();
    try protocol.packet.writeLogicalPayload(&eof, 3, &.{ 0xfe, 0x00, 0x00, 0x02, 0x00 });
    try std.testing.expectEqual(mantle.ConnectionPhase.Action.none, try stream.receiveServerPackets(std.testing.allocator, &framed_client, eof.bytes()));
    try std.testing.expectEqual(mantle.ConnectionPhase.State.ready, stream.phase.state);
}
