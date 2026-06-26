const std = @import("std");

const protocol = @import("../protocol/protocol.zig");
const column_reader = @import("column_reader.zig");

const unsigned_flag = column_reader.unsigned_flag;
const DateTime = column_reader.DateTime;
const Time = column_reader.Time;
const Context = column_reader.Context;
const readTextInt = column_reader.readTextInt;
const readTextFloat = column_reader.readTextFloat;
const readTextBool = column_reader.readTextBool;
const readTextBytes = column_reader.readTextBytes;
const readTextDecimal = column_reader.readTextDecimal;
const readTextDateTime = column_reader.readTextDateTime;
const readTextTime = column_reader.readTextTime;
const readBinaryInt = column_reader.readBinaryInt;
const readBinaryFloat = column_reader.readBinaryFloat;
const readBinaryBool = column_reader.readBinaryBool;
const readBinaryBytes = column_reader.readBinaryBytes;
const readBinaryDecimal = column_reader.readBinaryDecimal;
const readBinaryDateTime = column_reader.readBinaryDateTime;
const readBinaryTime = column_reader.readBinaryTime;

test "column read context validates index count and field type" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("id", .long, 0),
        testColumn("name", .var_string, 0),
    };
    const values = [_]?[]const u8{ "42", "bob" };

    const id = try Context.init(&columns, &values, 0);
    try id.expectIntegerType();
    try std.testing.expectEqualSlices(u8, "42", id.value.?);

    const name = try Context.init(&columns, &values, 1);
    try std.testing.expectError(error.InvalidColumnType, name.expectIntegerType());
    try std.testing.expectEqualSlices(u8, "bob", name.value.?);
}

test "column read context rejects invalid shape" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("id", .long, 0),
    };
    const values = [_]?[]const u8{ "42", "extra" };

    try std.testing.expectError(error.ColumnCountMismatch, Context.init(&columns, &values, 0));
    try std.testing.expectError(error.ColumnIndexOutOfBounds, Context.init(&columns, values[0..1], 1));
}

test "column reader reads text scalar values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("id", .long, 0),
        testColumn("ratio", .double, 0),
        testColumn("active", .tiny, 0),
    };
    const values = [_]?[]const u8{ "42", "1.5", "1" };

    try std.testing.expectEqual(@as(i32, 42), (try readTextInt(i32, &columns, &values, 0)).?);
    try std.testing.expectEqual(@as(f64, 1.5), (try readTextFloat(f64, &columns, &values, 1)).?);
    try std.testing.expectEqual(true, (try readTextBool(&columns, &values, 2)).?);
}

test "column reader reads string like byte values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("name", .var_string, 0),
        testColumn("payload", .blob, 0),
        testColumn("amount", .newdecimal, 0),
        testColumn("flags", .bit, 0),
        testColumn("shape", .geometry, 0),
    };
    const bit_value = [_]u8{0b10101010};
    const shape_value = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const values = [_]?[]const u8{ "bob", "bytes", "12.34", &bit_value, &shape_value };

    try std.testing.expectEqualSlices(u8, "bob", (try readTextBytes(&columns, &values, 0)).?);
    try std.testing.expectEqualSlices(u8, "bytes", (try readTextBytes(&columns, &values, 1)).?);
    try std.testing.expectEqualSlices(u8, "12.34", (try readTextBytes(&columns, &values, 2)).?);
    try std.testing.expectEqualSlices(u8, "12.34", (try readBinaryBytes(&columns, &values, 2)).?);
    try std.testing.expectEqualSlices(u8, &bit_value, (try readTextBytes(&columns, &values, 3)).?);
    try std.testing.expectEqualSlices(u8, &bit_value, (try readBinaryBytes(&columns, &values, 3)).?);
    try std.testing.expectEqualSlices(u8, &shape_value, (try readTextBytes(&columns, &values, 4)).?);
    try std.testing.expectEqualSlices(u8, &shape_value, (try readBinaryBytes(&columns, &values, 4)).?);
}

test "column reader reads decimal values as borrowed exact bytes" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("amount", .newdecimal, 0),
        testColumn("legacy", .decimal, 0),
        testColumn("name", .var_string, 0),
    };
    const values = [_]?[]const u8{ "-1234567890.123456", "42.00", "bob" };

    try std.testing.expectEqualSlices(u8, "-1234567890.123456", (try readTextDecimal(&columns, &values, 0)).?.asBytes());
    try std.testing.expectEqualSlices(u8, "42.00", (try readBinaryDecimal(&columns, &values, 1)).?.asBytes());
    try std.testing.expectError(error.InvalidColumnType, readTextDecimal(&columns, &values, 2));
}

test "column reader reads binary scalar values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("signed", .long, 0),
        testColumn("unsigned", .long, unsigned_flag),
        testColumn("ratio", .float, 0),
        testColumn("active", .tiny, 0),
    };
    const signed = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    const unsigned = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    const ratio = [_]u8{ 0x00, 0x00, 0xc0, 0x3f };
    const active = [_]u8{1};
    const values = [_]?[]const u8{ &signed, &unsigned, &ratio, &active };

    try std.testing.expectEqual(@as(i32, -1), (try readBinaryInt(i32, &columns, &values, 0)).?);
    try std.testing.expectEqual(@as(u32, 0xffffffff), (try readBinaryInt(u32, &columns, &values, 1)).?);
    try std.testing.expectEqual(@as(f32, 1.5), (try readBinaryFloat(f32, &columns, &values, 2)).?);
    try std.testing.expectEqual(true, (try readBinaryBool(&columns, &values, 3)).?);
}

test "column reader binary int returns error on overflow instead of panicking" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("big", .longlong, 0),
        testColumn("ubig", .longlong, unsigned_flag),
    };
    // 0x0000000100000000 = 4294967296: fits i64/u32-no, too big for i32.
    const big = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    // Unsigned u64 with the high bit set does not fit a signed target.
    const ubig = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const values = [_]?[]const u8{ &big, &ubig };

    try std.testing.expectError(error.IntegerOverflow, readBinaryInt(i32, &columns, &values, 0));
    try std.testing.expectError(error.IntegerOverflow, readBinaryInt(i64, &columns, &values, 1));
    // The full-width target still decodes correctly.
    try std.testing.expectEqual(@as(i64, 4294967296), (try readBinaryInt(i64, &columns, &values, 0)).?);
}

test "column reader reads binary datetime values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created", .datetime, 0),
        testColumn("empty", .timestamp, 0),
    };
    const created = [_]u8{ 7, 0xe8, 0x07, 6, 17, 12, 34, 56 };
    const empty = [_]u8{0};
    const values = [_]?[]const u8{ &created, &empty };

    const dt = (try readBinaryDateTime(&columns, &values, 0)).?;
    try std.testing.expectEqual(@as(u16, 2024), dt.year);
    try std.testing.expectEqual(@as(u8, 6), dt.month);
    try std.testing.expectEqual(@as(u8, 17), dt.day);
    try std.testing.expectEqual(@as(u8, 12), dt.hour);
    try std.testing.expectEqual(@as(u8, 34), dt.minute);
    try std.testing.expectEqual(@as(u8, 56), dt.second);

    try std.testing.expectEqual(DateTime{}, (try readBinaryDateTime(&columns, &values, 1)).?);
}

test "column reader reads binary time values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time, 0),
        testColumn("empty", .time, 0),
    };
    const elapsed = [_]u8{ 12, 1, 2, 0, 0, 0, 3, 4, 5, 0x40, 0xe2, 0x01, 0x00 };
    const empty = [_]u8{0};
    const values = [_]?[]const u8{ &elapsed, &empty };

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, (try readBinaryTime(&columns, &values, 0)).?);
    try std.testing.expectEqual(Time{}, (try readBinaryTime(&columns, &values, 1)).?);
}

test "column reader reads text time values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time, 0),
        testColumn("empty", .time, 0),
    };
    const values = [_]?[]const u8{ "-51:04:05.123456", "00:00:00" };

    try std.testing.expectEqual(Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 }, (try readTextTime(&columns, &values, 0)).?);
    try std.testing.expectEqual(Time{}, (try readTextTime(&columns, &values, 1)).?);
}

test "column reader rejects invalid text time values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time, 0),
    };
    const values = [_]?[]const u8{
        "-51:04",
    };

    try std.testing.expectError(error.InvalidTextTemporalLength, readTextTime(&columns, &values, 0));
}

test "column reader reads text datetime values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created_on", .date, 0),
        testColumn("created_at", .datetime, 0),
        testColumn("updated_at", .timestamp, 0),
        testColumn("zero_at", .datetime, 0),
    };
    const values = [_]?[]const u8{ "2026-06-16", "2026-06-16 12:34:56", "2026-06-16 12:34:56.123456", "0000-00-00 00:00:00" };

    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16 }, (try readTextDateTime(&columns, &values, 0)).?);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56 }, (try readTextDateTime(&columns, &values, 1)).?);
    try std.testing.expectEqual(DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 }, (try readTextDateTime(&columns, &values, 2)).?);
    try std.testing.expectEqual(DateTime{}, (try readTextDateTime(&columns, &values, 3)).?);
}

test "column reader rejects invalid binary datetime length" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created", .datetime, 0),
    };
    const invalid = [_]u8{ 7, 0xe8, 0x07 };
    const values = [_]?[]const u8{&invalid};

    try std.testing.expectError(error.InvalidBinaryTemporalLength, readBinaryDateTime(&columns, &values, 0));
}

test "column reader rejects invalid text datetime values" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created", .datetime, 0),
        testColumn("updated", .timestamp, 0),
    };
    const values = [_]?[]const u8{ "2026-06-16T12:34:56", "2026-06-16 12:34:56.1234567" };

    try std.testing.expectError(error.InvalidTextTemporalValue, readTextDateTime(&columns, &values, 0));
    try std.testing.expectError(error.InvalidTextTemporalLength, readTextDateTime(&columns, &values, 1));
}

test "column reader rejects incompatible logical types for scalar readers" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("name", .var_string, 0),
    };
    const values = [_]?[]const u8{"bob"};

    try std.testing.expectError(error.InvalidColumnType, readTextInt(i32, &columns, &values, 0));
    try std.testing.expectError(error.InvalidColumnType, readTextFloat(f64, &columns, &values, 0));
    try std.testing.expectError(error.InvalidColumnType, readBinaryInt(i32, &columns, &values, 0));
    try std.testing.expectError(error.InvalidColumnType, readBinaryDateTime(&columns, &values, 0));
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
