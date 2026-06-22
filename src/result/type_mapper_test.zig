const std = @import("std");

const protocol = @import("../protocol/protocol.zig");
const type_mapper = @import("type_mapper.zig");

const LogicalType = type_mapper.LogicalType;
const fromColumn = type_mapper.fromColumn;
const unsigned_flag = type_mapper.unsigned_flag;

test "type mapper maps numeric column metadata" {
    try std.testing.expectEqual(LogicalType.signed_integer, fromColumn(testColumn("id", .long, 0)));
    try std.testing.expectEqual(LogicalType.unsigned_integer, fromColumn(testColumn("id", .longlong, unsigned_flag)));
    try std.testing.expectEqual(LogicalType.float, fromColumn(testColumn("score", .float, 0)));
    try std.testing.expectEqual(LogicalType.float, fromColumn(testColumn("ratio", .double, 0)));
    try std.testing.expectEqual(LogicalType.decimal, fromColumn(testColumn("amount", .newdecimal, 0)));
}

test "type mapper maps text blob temporal and null metadata" {
    try std.testing.expectEqual(LogicalType.text, fromColumn(testColumn("name", .var_string, 0)));
    try std.testing.expectEqual(LogicalType.blob, fromColumn(testColumn("payload", .blob, 0)));
    try std.testing.expectEqual(LogicalType.blob, fromColumn(testColumn("flags", .bit, 0)));
    try std.testing.expectEqual(LogicalType.blob, fromColumn(testColumn("shape", .geometry, 0)));
    try std.testing.expectEqual(LogicalType.temporal, fromColumn(testColumn("created", .datetime, 0)));
    try std.testing.expectEqual(LogicalType.null, fromColumn(testColumn("nothing", .null, 0)));
}

fn testColumn(name: []const u8, field_type: protocol.text_result.FieldType, flags: u16) protocol.text_result.ColumnDefinition41 {
    return .{
        .catalog = "def",
        .schema = "",
        .table = "",
        .org_table = "",
        .name = name,
        .org_name = name,
        .fixed_length_fields = 0x0c,
        .character_set = protocol.collation.utf8mb4_general_ci,
        .column_length = 0,
        .field_type = field_type,
        .flags = flags,
        .decimals = 0,
    };
}
