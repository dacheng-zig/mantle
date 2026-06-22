const std = @import("std");

const protocol = @import("protocol.zig");

pub const ColumnCount = struct {
    pub fn parse(payload: []const u8) protocol.types.Error!u64 {
        var reader = protocol.PayloadReader.init(payload);
        const count = try reader.readLengthEncodedInteger();
        if (count == 0) return error.InvalidColumnCount;
        if (reader.remaining() != 0) return error.MalformedResultSetPacket;
        return count;
    }
};

pub const FieldType = enum(u8) {
    decimal = 0x00,
    tiny = 0x01,
    short = 0x02,
    long = 0x03,
    float = 0x04,
    double = 0x05,
    null = 0x06,
    timestamp = 0x07,
    longlong = 0x08,
    int24 = 0x09,
    date = 0x0a,
    time = 0x0b,
    datetime = 0x0c,
    year = 0x0d,
    varchar = 0x0f,
    bit = 0x10,
    json = 0xf5,
    newdecimal = 0xf6,
    enum_ = 0xf7,
    set = 0xf8,
    tiny_blob = 0xf9,
    medium_blob = 0xfa,
    long_blob = 0xfb,
    blob = 0xfc,
    var_string = 0xfd,
    string = 0xfe,
    geometry = 0xff,
};

pub const ColumnDefinition41 = struct {
    catalog: []const u8,
    schema: []const u8,
    /// Table name as referenced in the query (an alias when one is used).
    table: []const u8,
    /// `org` = original: the underlying physical table name, before aliasing.
    /// MySQL protocol field name `org_table`.
    org_table: []const u8,
    /// Column name as referenced in the query (an alias when one is used).
    name: []const u8,
    /// `org` = original: the underlying physical column name, before aliasing.
    /// MySQL protocol field name `org_name`.
    org_name: []const u8,
    fixed_length_fields: u8,
    character_set: u16,
    column_length: u32,
    field_type: FieldType,
    flags: u16,
    decimals: u8,

    pub fn parse(payload: []const u8) protocol.types.Error!ColumnDefinition41 {
        var reader = protocol.PayloadReader.init(payload);
        const catalog = try reader.readLengthEncodedString();
        const schema = try reader.readLengthEncodedString();
        const table = try reader.readLengthEncodedString();
        const org_table = try reader.readLengthEncodedString();
        const name = try reader.readLengthEncodedString();
        const org_name = try reader.readLengthEncodedString();
        const fixed_length_fields = try reader.readLengthEncodedInteger();
        if (fixed_length_fields != 0x0c) return error.InvalidColumnDefinition;
        const character_set = try reader.readInt(u16);
        const column_length = try reader.readInt(u32);
        const field_type_value = try reader.readInt(u8);
        const flags = try reader.readInt(u16);
        const decimals = try reader.readInt(u8);

        return .{
            .catalog = catalog,
            .schema = schema,
            .table = table,
            .org_table = org_table,
            .name = name,
            .org_name = org_name,
            .fixed_length_fields = @intCast(fixed_length_fields),
            .character_set = character_set,
            .column_length = column_length,
            .field_type = std.enums.fromInt(FieldType, field_type_value) orelse return error.InvalidColumnType,
            .flags = flags,
            .decimals = decimals,
        };
    }

    pub fn clone(self: ColumnDefinition41, allocator: std.mem.Allocator) !ColumnDefinition41 {
        const catalog = try allocator.dupe(u8, self.catalog);
        errdefer allocator.free(catalog);
        const schema = try allocator.dupe(u8, self.schema);
        errdefer allocator.free(schema);
        const table = try allocator.dupe(u8, self.table);
        errdefer allocator.free(table);
        const org_table = try allocator.dupe(u8, self.org_table);
        errdefer allocator.free(org_table);
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const org_name = try allocator.dupe(u8, self.org_name);
        errdefer allocator.free(org_name);

        return .{
            .catalog = catalog,
            .schema = schema,
            .table = table,
            .org_table = org_table,
            .name = name,
            .org_name = org_name,
            .fixed_length_fields = self.fixed_length_fields,
            .character_set = self.character_set,
            .column_length = self.column_length,
            .field_type = self.field_type,
            .flags = self.flags,
            .decimals = self.decimals,
        };
    }

    pub fn deinit(self: *ColumnDefinition41, allocator: std.mem.Allocator) void {
        allocator.free(self.catalog);
        allocator.free(self.schema);
        allocator.free(self.table);
        allocator.free(self.org_table);
        allocator.free(self.name);
        allocator.free(self.org_name);
    }
};

pub const TextRow = struct {
    values: []?[]const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        payload: []const u8,
        column_count: usize,
    ) !TextRow {
        const values = try allocator.alloc(?[]const u8, column_count);
        errdefer allocator.free(values);

        var reader = protocol.PayloadReader.init(payload);
        for (values) |*value| {
            if (reader.remaining() == 0) return error.EndOfPayload;
            if (try reader.peek() == 0xfb) {
                _ = try reader.readInt(u8);
                value.* = null;
            } else {
                value.* = try reader.readLengthEncodedString();
            }
        }
        if (reader.remaining() != 0) return error.MalformedResultSetPacket;
        return .{ .values = values };
    }

    pub fn deinit(self: *TextRow, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
    }
};

pub const ResultPacketTag = enum {
    row,
    eof,
    err,

    pub fn classify(payload: []const u8, column_count: usize) protocol.types.Error!ResultPacketTag {
        if (payload.len == 0) return error.EndOfPayload;
        if (payload[0] == 0xff) return .err;
        if (payload[0] == 0xfe and payload.len < 9) return .eof;

        var reader = protocol.PayloadReader.init(payload);
        for (0..column_count) |_| {
            if (reader.remaining() == 0) return error.EndOfPayload;
            if (try reader.peek() == 0xfb) {
                _ = try reader.readInt(u8);
            } else {
                _ = try reader.readLengthEncodedString();
            }
        }
        if (reader.remaining() != 0) return error.MalformedResultSetPacket;
        return .row;
    }
};
