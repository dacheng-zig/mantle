const std = @import("std");

const text_result = @import("text_result.zig");

const ColumnCount = text_result.ColumnCount;
const FieldType = text_result.FieldType;
const ColumnDefinition41 = text_result.ColumnDefinition41;
const TextRow = text_result.TextRow;
const ResultPacketTag = text_result.ResultPacketTag;

test "text result parses column count packet" {
    const payload = [_]u8{0x02};

    try std.testing.expectEqual(@as(u64, 2), try ColumnCount.parse(&payload));
}

test "text result parses column definition 41" {
    const payload = [_]u8{
        0x03, 'd',  'e',  'f',
        0x02, 'd',  'b',  0x05,
        'u',  's',  'e',  'r',
        's',  0x05, 'u',  's',
        'e',  'r',  's',  0x02,
        'i',  'd',  0x02, 'i',
        'd',  0x0c, 0x3f, 0x00,
        0x0b, 0x00, 0x00, 0x00,
        0x03, 0x01, 0x00, 0x00,
    };

    const column = try ColumnDefinition41.parse(&payload);

    try std.testing.expectEqualSlices(u8, "def", column.catalog);
    try std.testing.expectEqualSlices(u8, "db", column.schema);
    try std.testing.expectEqualSlices(u8, "users", column.table);
    try std.testing.expectEqualSlices(u8, "id", column.name);
    try std.testing.expectEqual(@as(u8, 0x0c), column.fixed_length_fields);
    try std.testing.expectEqual(@as(u16, 63), column.character_set);
    try std.testing.expectEqual(@as(u32, 11), column.column_length);
    try std.testing.expectEqual(FieldType.long, column.field_type);
    try std.testing.expectEqual(@as(u16, 1), column.flags);
    try std.testing.expectEqual(@as(u8, 0), column.decimals);
}

test "text result parses row values and nulls" {
    const payload = [_]u8{ 0x01, '1', 0xfb, 0x03, 'b', 'o', 'b' };
    var row = try TextRow.parse(std.testing.allocator, &payload, 3);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "1", row.values[0].?);
    try std.testing.expect(row.values[1] == null);
    try std.testing.expectEqualSlices(u8, "bob", row.values[2].?);
}

test "text result classifies row terminators and errors" {
    try std.testing.expectEqual(ResultPacketTag.row, try ResultPacketTag.classify(&.{ 0x01, '1' }, 1));
    try std.testing.expectEqual(ResultPacketTag.eof, try ResultPacketTag.classify(&.{ 0xfe, 0x00, 0x00, 0x02, 0x00 }, 1));
    try std.testing.expectEqual(ResultPacketTag.err, try ResultPacketTag.classify(&.{ 0xff, 0x15, 0x04 }, 1));
}
