const std = @import("std");

const protocol = @import("../protocol/protocol.zig");

pub const unsigned_flag: u16 = 0x20;

pub const LogicalType = enum {
    signed_integer,
    unsigned_integer,
    float,
    decimal,
    text,
    blob,
    temporal,
    null,
};

pub fn fromColumn(column: protocol.text_result.ColumnDefinition41) LogicalType {
    return switch (column.field_type) {
        .tiny,
        .short,
        .long,
        .longlong,
        .int24,
        .year,
        => if ((column.flags & unsigned_flag) != 0) .unsigned_integer else .signed_integer,
        .float, .double => .float,
        .decimal, .newdecimal => .decimal,
        .varchar, .var_string, .string, .enum_, .set, .json => .text,
        .tiny_blob, .medium_blob, .long_blob, .blob, .bit, .geometry => .blob,
        .date, .datetime, .timestamp, .time => .temporal,
        .null => .null,
    };
}
