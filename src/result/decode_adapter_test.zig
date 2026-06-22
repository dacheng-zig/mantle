const std = @import("std");

const protocol = @import("../protocol/protocol.zig");
const column_reader = @import("column_reader.zig");
const decode_adapter = @import("decode_adapter.zig");

const DateTime = column_reader.DateTime;
const Time = column_reader.Time;
const decode = decode_adapter.decode;

fn testColumn(
    name: []const u8,
    field_type: protocol.text_result.FieldType,
    flags: u16,
) protocol.text_result.ColumnDefinition41 {
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

/// Owned copy of the raw decimal/text bytes — proves the borrowed slice is
/// delivered and is safe to retain only after copying.
const RawDecimal = struct {
    buf: [32]u8 = undefined,
    len: usize = 0,

    pub fn fromMantleText(bytes: []const u8) !RawDecimal {
        if (bytes.len > 32) return error.Overflow;
        var self: RawDecimal = .{};
        @memcpy(self.buf[0..bytes.len], bytes);
        self.len = bytes.len;
        return self;
    }

    fn slice(self: *const RawDecimal) []const u8 {
        return self.buf[0..self.len];
    }
};

const DateOnly = struct {
    year: u16,
    month: u8,
    day: u8,

    pub fn fromMantleDateTime(dt: DateTime) DateOnly {
        return .{ .year = dt.year, .month = dt.month, .day = dt.day };
    }
};

const Duration = struct {
    negative: bool,
    total_minutes: u32,

    pub fn fromMantleTime(t: Time) Duration {
        return .{
            .negative = t.negative,
            .total_minutes = (t.days * 24 + t.hour) * 60 + t.minute,
        };
    }
};

test "isDecodeAdapter detects fromMantle* conventions only" {
    try std.testing.expect(decode_adapter.isDecodeAdapter(RawDecimal));
    try std.testing.expect(decode_adapter.isDecodeAdapter(DateOnly));
    try std.testing.expect(decode_adapter.isDecodeAdapter(Duration));
    try std.testing.expect(!decode_adapter.isDecodeAdapter(i32));
    try std.testing.expect(!decode_adapter.isDecodeAdapter([]const u8));
    try std.testing.expect(!decode_adapter.isDecodeAdapter(column_reader.Decimal));
    try std.testing.expect(!decode_adapter.isDecodeAdapter(struct { x: u8 }));
}

test "fromMantleText receives decimal column bytes in both protocols" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("amount", .newdecimal, 0),
        testColumn("legacy", .decimal, 0),
    };
    const values = [_]?[]const u8{ "-1234567890.123456", "42.00" };

    const text = try decode(.text, RawDecimal, &columns, &values, 0);
    try std.testing.expectEqualStrings("-1234567890.123456", text.slice());

    const binary = try decode(.binary, RawDecimal, &columns, &values, 1);
    try std.testing.expectEqualStrings("42.00", binary.slice());
}

test "fromMantleText also covers plain text/blob columns" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("name", .var_string, 0),
        testColumn("payload", .blob, 0),
    };
    const values = [_]?[]const u8{ "bob", "raw" };

    try std.testing.expectEqualStrings("bob", (try decode(.text, RawDecimal, &columns, &values, 0)).slice());
    try std.testing.expectEqualStrings("raw", (try decode(.binary, RawDecimal, &columns, &values, 1)).slice());
}

test "fromMantleDateTime receives decoded components" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("created", .datetime, 0),
    };
    const created = [_]u8{ 7, 0xe8, 0x07, 6, 17, 12, 34, 56 }; // 2024-06-17 12:34:56
    const values = [_]?[]const u8{&created};

    const got = try decode(.binary, DateOnly, &columns, &values, 0);
    try std.testing.expectEqual(DateOnly{ .year = 2024, .month = 6, .day = 17 }, got);
}

test "fromMantleTime receives signed, over-24h duration" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time, 0),
    };
    const values = [_]?[]const u8{"-51:04:05.123456"}; // negative, 51h -> days=2,hour=3

    const got = try decode(.text, Duration, &columns, &values, 0);
    try std.testing.expectEqual(Duration{ .negative = true, .total_minutes = (2 * 24 + 3) * 60 + 4 }, got);
}

test "convention mapped onto incompatible column fails with InvalidColumnType" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("elapsed", .time, 0), // TIME column, but RawDecimal only has fromMantleText
        testColumn("id", .long, 0), // integer column, no text/temporal IR
    };
    const values = [_]?[]const u8{ "00:00:00", "42" };

    try std.testing.expectError(error.InvalidColumnType, decode(.text, RawDecimal, &columns, &values, 0));
    try std.testing.expectError(error.InvalidColumnType, decode(.text, RawDecimal, &columns, &values, 1));
}

test "fromMantleText error propagates through decode" {
    const columns = [_]protocol.text_result.ColumnDefinition41{
        testColumn("amount", .newdecimal, 0),
    };
    // 40 bytes exceeds RawDecimal's 32-byte buffer -> error.Overflow
    const values = [_]?[]const u8{"1234567890123456789012345678901234567890"};

    try std.testing.expectError(error.Overflow, decode(.text, RawDecimal, &columns, &values, 0));
}
