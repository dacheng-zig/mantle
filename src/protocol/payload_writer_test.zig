const std = @import("std");
const payload_writer = @import("payload_writer.zig");
const PayloadWriter = payload_writer.PayloadWriter;

test "payload writer writes fixed-width and length-encoded values" {
    var writer = PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeInt(u16, 0x1234);
    try writer.writeInt(u24, 0x123456);
    try writer.writeLengthEncodedInteger(250);
    try writer.writeLengthEncodedInteger(251);
    try writer.writeLengthEncodedString("abc");
    try writer.writeNullTerminatedString("def");

    try std.testing.expectEqualSlices(u8, &.{
        0x34, 0x12,
        0x56, 0x34,
        0x12, 0xfa,
        0xfc, 0xfb,
        0x00, 0x03,
        'a',  'b',
        'c',  'd',
        'e',  'f',
        0x00,
    }, writer.bytes());
}
