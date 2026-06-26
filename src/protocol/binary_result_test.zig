const std = @import("std");

const binary_result = @import("binary_result.zig");
const protocol = @import("protocol.zig");

const BinaryRow = binary_result.BinaryRow;

test "binary row parses integer string and null values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("id", .long),
        testColumn("name", .var_string),
        testColumn("maybe_id", .long),
    };
    const payload = [_]u8{
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
    };

    var row = try BinaryRow.parse(std.testing.allocator, &payload, &columns);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), row.values.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x2a, 0x00, 0x00, 0x00 }, row.values[0].?);
    try std.testing.expectEqualSlices(u8, "bob", row.values[1].?);
    try std.testing.expect(row.values[2] == null);
}

test "binary row parses enum and set length-encoded strings" {
    // Regression: ENUM (0xf7) and SET (0xf8) are transmitted as length-encoded
    // strings in the binary protocol; they were previously omitted from
    // `readValue` and failed with UnsupportedBinaryColumnType, inconsistent with
    // type_mapper which classifies them as text.
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("mood", .enum_),
        testColumn("tags", .set),
    };
    const payload = [_]u8{
        0x00,
        0x00, // null bitmap (no nulls)
        0x05, 'h', 'a', 'p', 'p', 'y',
        0x03, 'a', ',', 'b',
    };

    var row = try BinaryRow.parse(std.testing.allocator, &payload, &columns);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "happy", row.values[0].?);
    try std.testing.expectEqualSlices(u8, "a,b", row.values[1].?);
}

test "binary row parses float and double raw bytes" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("score", .float),
        testColumn("ratio", .double),
    };
    const payload = [_]u8{
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
    };

    var row = try BinaryRow.parse(std.testing.allocator, &payload, &columns);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0xc0, 0x3f }, row.values[0].?);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x40 }, row.values[1].?);
}

test "binary row parses temporal raw bytes" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created_on", .date),
        testColumn("created_at", .datetime),
        testColumn("updated_at", .timestamp),
        testColumn("zero_at", .datetime),
    };
    const payload = [_]u8{
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
    };

    var row = try BinaryRow.parse(std.testing.allocator, &payload, &columns);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0xea, 0x07, 0x06, 0x10 }, row.values[0].?);
    try std.testing.expectEqualSlices(u8, &.{ 0x07, 0xea, 0x07, 0x06, 0x10, 0x0c, 0x22, 0x38 }, row.values[1].?);
    try std.testing.expectEqualSlices(u8, &.{ 0x0b, 0xea, 0x07, 0x06, 0x10, 0x0c, 0x22, 0x38, 0x40, 0xe2, 0x01, 0x00 }, row.values[2].?);
    try std.testing.expectEqualSlices(u8, &.{0x00}, row.values[3].?);
}

test "binary row parses time raw bytes" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time),
    };
    const payload = [_]u8{
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
    };

    var row = try BinaryRow.parse(std.testing.allocator, &payload, &columns);
    defer row.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &.{ 0x0c, 0x01, 0x02, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x40, 0xe2, 0x01, 0x00 }, row.values[0].?);
}

test "binary row rejects invalid temporal length" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("created_at", .datetime)};
    const payload = [_]u8{
        0x00,
        0x00,
        0x05,
        0xea,
        0x07,
        0x06,
        0x10,
        0x0c,
    };

    try std.testing.expectError(error.InvalidBinaryTemporalLength, BinaryRow.parse(std.testing.allocator, &payload, &columns));
}

test "binary row rejects truncated temporal value" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("created_at", .datetime)};
    const payload = [_]u8{
        0x00,
        0x00,
        0x07,
        0xea,
        0x07,
        0x06,
        0x10,
    };

    try std.testing.expectError(error.EndOfPayload, BinaryRow.parse(std.testing.allocator, &payload, &columns));
}

test "binary row rejects invalid row header" {
    const columns = [_]protocol.text_result.ColumnDefinition41{testColumn("id", .long)};

    try std.testing.expectError(error.InvalidBinaryRowHeader, BinaryRow.parse(std.testing.allocator, &.{0x01}, &columns));
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
