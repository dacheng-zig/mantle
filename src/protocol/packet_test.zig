const std = @import("std");

const packet = @import("packet.zig");
const protocol = @import("protocol.zig");

const writeLogicalPayload = packet.writeLogicalPayload;
const PacketBufferReader = packet.PacketBufferReader;

test "packet header encodes and decodes payload length and sequence id" {
    const header = protocol.types.PacketHeader{
        .payload_length = 0x123456,
        .sequence_id = 7,
    };
    var encoded: [4]u8 = undefined;

    try header.encode(&encoded);

    try std.testing.expectEqualSlices(u8, &.{ 0x56, 0x34, 0x12, 7 }, &encoded);
    try std.testing.expectEqual(header, try protocol.types.PacketHeader.decode(&encoded));
}

test "sequence tracker accepts expected sequence ids and wraps" {
    var tracker = protocol.types.SequenceTracker.init(254);

    try tracker.expect(254);
    try tracker.expect(255);
    try tracker.expect(0);
    tracker.reset();
    try tracker.expect(0);
}

test "sequence tracker rejects mismatched sequence id" {
    var tracker = protocol.types.SequenceTracker.init(0);

    try std.testing.expectError(protocol.types.Error.SequenceMismatch, tracker.expect(1));
}

test "packet writer splits logical payload on mysql packet boundaries" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, protocol.types.max_packet_payload_size + 1);
    defer allocator.free(payload);
    @memset(payload, 0xab);

    var writer = protocol.PayloadWriter.init(allocator);
    defer writer.deinit();

    try writeLogicalPayload(&writer, 3, payload);

    const bytes = writer.bytes();
    try std.testing.expectEqual(@as(usize, 4 + protocol.types.max_packet_payload_size + 4 + 1), bytes.len);
    try std.testing.expectEqual(protocol.types.PacketHeader{
        .payload_length = protocol.types.max_packet_payload_size,
        .sequence_id = 3,
    }, try protocol.types.PacketHeader.decode(bytes[0..4]));
    try std.testing.expectEqual(protocol.types.PacketHeader{
        .payload_length = 1,
        .sequence_id = 4,
    }, try protocol.types.PacketHeader.decode(bytes[4 + protocol.types.max_packet_payload_size ..][0..4]));
}

test "packet writer emits trailing empty packet for exact boundary payload" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, protocol.types.max_packet_payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xcd);

    var writer = protocol.PayloadWriter.init(allocator);
    defer writer.deinit();

    try writeLogicalPayload(&writer, 9, payload);

    const second_header_offset = 4 + protocol.types.max_packet_payload_size;
    try std.testing.expectEqual(protocol.types.PacketHeader{
        .payload_length = 0,
        .sequence_id = 10,
    }, try protocol.types.PacketHeader.decode(writer.bytes()[second_header_offset..][0..4]));
}

test "packet reader joins logical payload fragments and validates sequence" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, protocol.types.max_packet_payload_size + 2);
    defer allocator.free(payload);
    @memset(payload[0..protocol.types.max_packet_payload_size], 0x11);
    @memset(payload[protocol.types.max_packet_payload_size..], 0x22);

    var writer = protocol.PayloadWriter.init(allocator);
    defer writer.deinit();
    try writeLogicalPayload(&writer, 0, payload);

    var reader = PacketBufferReader.init(writer.bytes());
    const joined = try reader.readLogicalPayload(allocator, 0);
    defer allocator.free(joined);

    try std.testing.expectEqualSlices(u8, payload, joined);
}

test "packet reader rejects mismatched fragment sequence" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, protocol.types.max_packet_payload_size + 1);
    defer allocator.free(payload);
    @memset(payload, 0xee);

    var writer = protocol.PayloadWriter.init(allocator);
    defer writer.deinit();
    try writeLogicalPayload(&writer, 0, payload);

    const bad = try allocator.dupe(u8, writer.bytes());
    defer allocator.free(bad);
    bad[4 + protocol.types.max_packet_payload_size + 3] = 2;

    var reader = PacketBufferReader.init(bad);

    try std.testing.expectError(protocol.types.Error.SequenceMismatch, reader.readLogicalPayload(std.testing.allocator, 0));
}
