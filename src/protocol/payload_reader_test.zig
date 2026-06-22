const std = @import("std");

const payload_reader = @import("payload_reader.zig");
const protocol = @import("protocol.zig");

const PayloadReader = payload_reader.PayloadReader;

test "payload reader reads fixed-width little-endian integers" {
    var reader = PayloadReader.init(&.{ 0x34, 0x12, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89 });

    try std.testing.expectEqual(@as(u16, 0x1234), try reader.readInt(u16));
    try std.testing.expectEqual(@as(u24, 0x123456), try reader.readInt(u24));
    try std.testing.expectEqual(@as(u32, 0x89abcdef), try reader.readInt(u32));
    try std.testing.expect(reader.finished());
}

test "payload reader rejects truncated fixed-width integer" {
    var reader = PayloadReader.init(&.{0x01});

    try std.testing.expectError(protocol.types.Error.EndOfPayload, reader.readInt(u16));
}

test "payload reader reads length-encoded integer variants" {
    var reader = PayloadReader.init(&.{
        0xfa,
        0xfc,
        0xfb,
        0x00,
        0xfd,
        0x56,
        0x34,
        0x12,
        0xfe,
        0x88,
        0x77,
        0x66,
        0x55,
        0x44,
        0x33,
        0x22,
        0x11,
    });

    try std.testing.expectEqual(@as(u64, 250), try reader.readLengthEncodedInteger());
    try std.testing.expectEqual(@as(u64, 251), try reader.readLengthEncodedInteger());
    try std.testing.expectEqual(@as(u64, 0x123456), try reader.readLengthEncodedInteger());
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try reader.readLengthEncodedInteger());
}

test "payload reader rejects invalid length-encoded integer prefixes" {
    var null_prefix = PayloadReader.init(&.{0xfb});
    var invalid_prefix = PayloadReader.init(&.{0xff});

    try std.testing.expectError(protocol.types.Error.InvalidLengthEncodedInteger, null_prefix.readLengthEncodedInteger());
    try std.testing.expectError(protocol.types.Error.InvalidLengthEncodedInteger, invalid_prefix.readLengthEncodedInteger());
}

test "payload reader reads length-encoded and nul-terminated strings" {
    var reader = PayloadReader.init(&.{ 0x03, 'a', 'b', 'c', 'd', 'e', 'f', 0x00, 'x', 'y' });

    try std.testing.expectEqualSlices(u8, "abc", try reader.readLengthEncodedString());
    try std.testing.expectEqualSlices(u8, "def", try reader.readNullTerminatedString());
    try std.testing.expectEqualSlices(u8, "xy", reader.readRemaining());
    try std.testing.expect(reader.finished());
}

test "payload reader rejects missing nul terminator" {
    var reader = PayloadReader.init("abc");

    try std.testing.expectError(protocol.types.Error.MissingNullTerminator, reader.readNullTerminatedString());
}
