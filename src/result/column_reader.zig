const std = @import("std");

const protocol = @import("../protocol/protocol.zig");
const type_mapper = @import("type_mapper.zig");

pub const unsigned_flag: u16 = 0x20;

pub const DateTime = protocol.temporal.DateTime;
pub const Time = protocol.temporal.Time;
pub const Decimal = protocol.decimal.Decimal;

pub const Context = struct {
    column: protocol.text_result.ColumnDefinition41,
    value: ?[]const u8,

    pub fn init(
        columns: []const protocol.text_result.ColumnDefinition41,
        values: []const ?[]const u8,
        index: usize,
    ) !Context {
        if (index >= values.len) return error.ColumnIndexOutOfBounds;
        if (columns.len != values.len) return error.ColumnCountMismatch;
        return .{ .column = columns[index], .value = values[index] };
    }

    pub fn expectFieldType(self: Context, predicate: fn (protocol.text_result.FieldType) bool) !void {
        if (!predicate(self.column.field_type)) return error.InvalidColumnType;
    }

    pub fn logicalType(self: Context) type_mapper.LogicalType {
        return type_mapper.fromColumn(self.column);
    }

    pub fn expectLogicalType(self: Context, expected: type_mapper.LogicalType) !void {
        if (self.logicalType() != expected) return error.InvalidColumnType;
    }

    pub fn expectIntegerType(self: Context) !void {
        switch (self.logicalType()) {
            .signed_integer, .unsigned_integer => {},
            else => return error.InvalidColumnType,
        }
    }

    pub fn expectBytesType(self: Context) !void {
        switch (self.logicalType()) {
            .decimal, .text, .blob => {},
            else => return error.InvalidColumnType,
        }
    }

    pub fn expectDateTimeType(self: Context) !void {
        if (!isDateTimeFieldType(self.column.field_type)) return error.InvalidColumnType;
    }

    pub fn expectTimeType(self: Context) !void {
        if (!isTimeFieldType(self.column.field_type)) return error.InvalidColumnType;
    }
};

pub fn readTextInt(
    comptime T: type,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?T {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectIntegerType();
    const value = ctx.value orelse return null;
    return try std.fmt.parseInt(T, value, 10);
}

pub fn readTextFloat(
    comptime T: type,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?T {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectLogicalType(.float);
    const value = ctx.value orelse return null;
    return try std.fmt.parseFloat(T, value);
}

pub fn readTextBool(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?bool {
    const value = try readTextInt(u8, columns, values, index) orelse return null;
    return try boolFromInteger(value);
}

pub fn readTextBytes(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?[]const u8 {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectBytesType();
    return ctx.value;
}

pub fn readTextDecimal(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?Decimal {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectLogicalType(.decimal);
    const value = ctx.value orelse return null;
    return Decimal{ .bytes = value };
}

pub fn readTextDateTime(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?DateTime {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectDateTimeType();
    const value = ctx.value orelse return null;
    return try readTextDateTimeBytes(value);
}

pub fn readTextTime(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?Time {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectTimeType();
    const value = ctx.value orelse return null;
    return try readTextTimeBytes(value);
}

pub fn readBinaryInt(
    comptime T: type,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?T {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectIntegerType();
    const value = ctx.value orelse return null;
    return try readBinaryInteger(T, value, (ctx.column.flags & unsigned_flag) != 0);
}

pub fn readBinaryFloat(
    comptime T: type,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?T {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectLogicalType(.float);
    const value = ctx.value orelse return null;
    return try readBinaryFloatBytes(T, value);
}

pub fn readBinaryBool(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?bool {
    const value = try readBinaryInt(u8, columns, values, index) orelse return null;
    return try boolFromInteger(value);
}

pub fn readBinaryBytes(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?[]const u8 {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectBytesType();
    return ctx.value;
}

pub fn readBinaryDecimal(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?Decimal {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectLogicalType(.decimal);
    const value = ctx.value orelse return null;
    return Decimal{ .bytes = value };
}

pub fn readBinaryDateTime(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?DateTime {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectDateTimeType();
    const value = ctx.value orelse return null;
    return try readBinaryDateTimeBytes(value);
}

pub fn readBinaryTime(
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?Time {
    const ctx = try Context.init(columns, values, index);
    try ctx.expectTimeType();
    const value = ctx.value orelse return null;
    return try readBinaryTimeBytes(value);
}

fn isIntegerFieldType(field_type: protocol.text_result.FieldType) bool {
    return switch (field_type) {
        .tiny, .short, .long, .longlong, .int24, .year => true,
        else => false,
    };
}

fn isFloatFieldType(field_type: protocol.text_result.FieldType) bool {
    return switch (field_type) {
        .float, .double => true,
        else => false,
    };
}

fn isDateTimeFieldType(field_type: protocol.text_result.FieldType) bool {
    return switch (field_type) {
        .date, .datetime, .timestamp => true,
        else => false,
    };
}

fn isTimeFieldType(field_type: protocol.text_result.FieldType) bool {
    return field_type == .time;
}

/// Neutral decode category for a column, used by user-side decode conventions
/// to pick which intermediate representation (and reader) applies.
pub const DecodeCategory = enum {
    /// DATE / DATETIME / TIMESTAMP -> `DateTime` component IR.
    datetime,
    /// TIME -> `Time` component IR (signed, may exceed 24h).
    time,
    /// DECIMAL / text / blob -> raw value bytes IR.
    bytes,
    /// Anything else (integers, floats, null) has no text/temporal IR.
    other,
};

pub fn decodeCategory(column: protocol.text_result.ColumnDefinition41) DecodeCategory {
    if (isDateTimeFieldType(column.field_type)) return .datetime;
    if (isTimeFieldType(column.field_type)) return .time;
    return switch (type_mapper.fromColumn(column)) {
        .decimal, .text, .blob => .bytes,
        else => .other,
    };
}

fn boolFromInteger(value: anytype) !bool {
    return switch (value) {
        0 => false,
        1 => true,
        else => error.InvalidBoolValue,
    };
}

fn readBinaryInteger(comptime T: type, value: []const u8, is_unsigned: bool) !T {
    if (is_unsigned) {
        return switch (value.len) {
            1 => @intCast(std.mem.readInt(u8, value[0..1], .little)),
            2 => @intCast(std.mem.readInt(u16, value[0..2], .little)),
            4 => @intCast(std.mem.readInt(u32, value[0..4], .little)),
            8 => @intCast(std.mem.readInt(u64, value[0..8], .little)),
            else => error.InvalidBinaryIntegerLength,
        };
    }

    return switch (value.len) {
        1 => @intCast(@as(i8, @bitCast(std.mem.readInt(u8, value[0..1], .little)))),
        2 => @intCast(@as(i16, @bitCast(std.mem.readInt(u16, value[0..2], .little)))),
        4 => @intCast(@as(i32, @bitCast(std.mem.readInt(u32, value[0..4], .little)))),
        8 => @intCast(@as(i64, @bitCast(std.mem.readInt(u64, value[0..8], .little)))),
        else => error.InvalidBinaryIntegerLength,
    };
}

fn readBinaryFloatBytes(comptime T: type, value: []const u8) !T {
    return switch (value.len) {
        4 => @floatCast(@as(f32, @bitCast(std.mem.readInt(u32, value[0..4], .little)))),
        8 => @floatCast(@as(f64, @bitCast(std.mem.readInt(u64, value[0..8], .little)))),
        else => error.InvalidBinaryFloatLength,
    };
}

fn readTextDateTimeBytes(value: []const u8) !DateTime {
    if (value.len != 10 and value.len != 19 and (value.len < 21 or value.len > 26)) {
        return error.InvalidTextTemporalLength;
    }
    if (value[4] != '-' or value[7] != '-') return error.InvalidTextTemporalValue;
    if (value.len > 10 and (value[10] != ' ' or value[13] != ':' or value[16] != ':')) {
        return error.InvalidTextTemporalValue;
    }
    if (value.len > 19 and value[19] != '.') return error.InvalidTextTemporalValue;

    var result = DateTime{
        .year = try parseDigits(u16, value[0..4]),
        .month = try parseDigits(u8, value[5..7]),
        .day = try parseDigits(u8, value[8..10]),
    };

    if (value.len == 10) return result;

    result.hour = try parseDigits(u8, value[11..13]);
    result.minute = try parseDigits(u8, value[14..16]);
    result.second = try parseDigits(u8, value[17..19]);

    if (value.len > 19) {
        const fraction = value[20..];
        result.microsecond = try parseFractionalMicroseconds(fraction);
    }

    return result;
}

fn readTextTimeBytes(value: []const u8) !Time {
    if (value.len < 8) return error.InvalidTextTemporalLength;

    var offset: usize = 0;
    var negative = false;
    if (value[0] == '-') {
        negative = true;
        offset = 1;
    }

    const first_colon = std.mem.indexOfScalarPos(u8, value, offset, ':') orelse return error.InvalidTextTemporalValue;
    if (first_colon == offset) return error.InvalidTextTemporalValue;
    const second_colon = std.mem.indexOfScalarPos(u8, value, first_colon + 1, ':') orelse return error.InvalidTextTemporalValue;
    if (second_colon != first_colon + 3) return error.InvalidTextTemporalValue;

    const fraction_start = std.mem.indexOfScalarPos(u8, value, second_colon + 1, '.');
    const second_end = fraction_start orelse value.len;
    if (second_end != second_colon + 3) return error.InvalidTextTemporalValue;

    const total_hours = try parseDigits(u32, value[offset..first_colon]);
    const minute = try parseDigits(u8, value[first_colon + 1 .. second_colon]);
    const second = try parseDigits(u8, value[second_colon + 1 .. second_end]);
    const microsecond = if (fraction_start) |dot_index|
        try parseFractionalMicroseconds(value[dot_index + 1 ..])
    else
        0;

    return .{
        .negative = negative,
        .days = total_hours / 24,
        .hour = @intCast(total_hours % 24),
        .minute = minute,
        .second = second,
        .microsecond = microsecond,
    };
}

fn parseDigits(comptime T: type, bytes: []const u8) !T {
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidTextTemporalValue;
    }
    return try std.fmt.parseInt(T, bytes, 10);
}

fn parseFractionalMicroseconds(bytes: []const u8) !u32 {
    if (bytes.len == 0 or bytes.len > 6) return error.InvalidTextTemporalValue;
    var value: u32 = 0;
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidTextTemporalValue;
        value = value * 10 + byte - '0';
    }
    for (bytes.len..6) |_| {
        value *= 10;
    }
    return value;
}

fn readBinaryDateTimeBytes(value: []const u8) !DateTime {
    if (value.len == 0) return error.InvalidBinaryTemporalLength;

    const len = value[0];
    if (value.len != @as(usize, len) + 1) return error.InvalidBinaryTemporalLength;

    return switch (len) {
        0 => .{},
        4 => .{
            .year = std.mem.readInt(u16, value[1..3], .little),
            .month = value[3],
            .day = value[4],
        },
        7 => .{
            .year = std.mem.readInt(u16, value[1..3], .little),
            .month = value[3],
            .day = value[4],
            .hour = value[5],
            .minute = value[6],
            .second = value[7],
        },
        11 => .{
            .year = std.mem.readInt(u16, value[1..3], .little),
            .month = value[3],
            .day = value[4],
            .hour = value[5],
            .minute = value[6],
            .second = value[7],
            .microsecond = std.mem.readInt(u32, value[8..12], .little),
        },
        else => error.InvalidBinaryTemporalLength,
    };
}

fn readBinaryTimeBytes(value: []const u8) !Time {
    if (value.len == 0) return error.InvalidBinaryTemporalLength;

    const len = value[0];
    if (value.len != @as(usize, len) + 1) return error.InvalidBinaryTemporalLength;

    return switch (len) {
        0 => .{},
        8 => .{
            .negative = value[1] != 0,
            .days = std.mem.readInt(u32, value[2..6], .little),
            .hour = value[6],
            .minute = value[7],
            .second = value[8],
        },
        12 => .{
            .negative = value[1] != 0,
            .days = std.mem.readInt(u32, value[2..6], .little),
            .hour = value[6],
            .minute = value[7],
            .second = value[8],
            .microsecond = std.mem.readInt(u32, value[9..13], .little),
        },
        else => error.InvalidBinaryTemporalLength,
    };
}
