const std = @import("std");

const protocol = @import("protocol.zig");

pub const BinaryRow = struct {
    values: []?[]const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        payload: []const u8,
        columns: []const protocol.text_result.ColumnDefinition41,
    ) !BinaryRow {
        const values = try allocator.alloc(?[]const u8, columns.len);
        errdefer allocator.free(values);
        try fillValues(payload, columns, values);
        return .{ .values = values };
    }

    /// Decode the binary row's columns into `out` (length must equal
    /// `columns.len`), each value aliasing `payload`. Shared by the owned
    /// `parse` and the reused-buffer collector path
    /// (`Transport.readBinaryRowReusing`), so the collector decodes rows without
    /// a per-row `values` allocation.
    pub fn fillValues(
        payload: []const u8,
        columns: []const protocol.text_result.ColumnDefinition41,
        out: []?[]const u8,
    ) !void {
        if (payload.len == 0 or payload[0] != 0x00) return error.InvalidBinaryRowHeader;

        var reader = protocol.PayloadReader.init(payload);
        _ = try reader.readInt(u8);

        const null_bitmap_len = (columns.len + 7 + 2) / 8;
        if (reader.remaining() < null_bitmap_len) return error.EndOfPayload;
        const null_bitmap = reader.readBytes(null_bitmap_len) catch return error.EndOfPayload;

        for (columns, 0..) |column, index| {
            if (isNull(null_bitmap, index)) {
                out[index] = null;
                continue;
            }

            out[index] = try readValue(&reader, column.field_type);
        }

        if (!reader.finished()) return error.MalformedResultSetPacket;
    }

    pub fn deinit(self: *BinaryRow, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
    }
};

fn isNull(null_bitmap: []const u8, column_index: usize) bool {
    const bit_index = column_index + 2;
    return (null_bitmap[bit_index / 8] & (@as(u8, 1) << @intCast(bit_index % 8))) != 0;
}

fn readValue(
    reader: *protocol.PayloadReader,
    field_type: protocol.text_result.FieldType,
) ![]const u8 {
    return switch (field_type) {
        .tiny => try readFixed(reader, 1),
        .short, .year => try readFixed(reader, 2),
        .long, .int24 => try readFixed(reader, 4),
        .longlong => try readFixed(reader, 8),
        .float => try readFixed(reader, 4),
        .double => try readFixed(reader, 8),
        .date,
        .datetime,
        .timestamp,
        => try readTemporal(reader),
        .time => try readTime(reader),
        .decimal,
        .newdecimal,
        .varchar,
        .var_string,
        .string,
        .tiny_blob,
        .medium_blob,
        .long_blob,
        .blob,
        .json,
        .geometry,
        .bit,
        .enum_,
        .set,
        => try reader.readLengthEncodedString(),
        else => error.UnsupportedBinaryColumnType,
    };
}

fn readFixed(reader: *protocol.PayloadReader, len: usize) ![]const u8 {
    return reader.readBytes(len) catch return error.EndOfPayload;
}

fn readTemporal(reader: *protocol.PayloadReader) ![]const u8 {
    const start = reader.pos;
    const len = try reader.readInt(u8);

    switch (len) {
        0, 4, 7, 11 => {},
        else => return error.InvalidBinaryTemporalLength,
    }

    _ = reader.readBytes(len) catch return error.EndOfPayload;
    return reader.payload[start..reader.pos];
}

fn readTime(reader: *protocol.PayloadReader) ![]const u8 {
    const start = reader.pos;
    const len = try reader.readInt(u8);

    switch (len) {
        0, 8, 12 => {},
        else => return error.InvalidBinaryTemporalLength,
    }

    _ = reader.readBytes(len) catch return error.EndOfPayload;
    return reader.payload[start..reader.pos];
}
