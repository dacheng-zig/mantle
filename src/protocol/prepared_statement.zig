const std = @import("std");

const protocol = @import("protocol.zig");
const decimal = @import("decimal.zig");
const temporal = @import("temporal.zig");

pub const PrepareOk = struct {
    statement_id: u32,
    column_count: u16,
    parameter_count: u16,
    warning_count: ?u16,
    metadata_follows: ?u8,

    pub fn parse(payload: []const u8, capabilities: u32) protocol.types.Error!PrepareOk {
        var reader = protocol.PayloadReader.init(payload);
        const status = try reader.readInt(u8);
        if (status != 0x00) return error.InvalidPacketSignature;

        const statement_id = try reader.readInt(u32);
        const column_count = try reader.readInt(u16);
        const parameter_count = try reader.readInt(u16);
        _ = try reader.readInt(u8);

        var warning_count: ?u16 = null;
        var metadata_follows: ?u8 = null;
        if (reader.remaining() >= 2) {
            warning_count = try reader.readInt(u16);
            if ((capabilities & protocol.capability.client_optional_resultset_metadata) != 0 and reader.remaining() >= 1) {
                metadata_follows = try reader.readInt(u8);
            }
        }
        if (!reader.finished()) return error.MalformedResultSetPacket;

        return .{
            .statement_id = statement_id,
            .column_count = column_count,
            .parameter_count = parameter_count,
            .warning_count = warning_count,
            .metadata_follows = metadata_follows,
        };
    }
};

pub const ExecuteRequest = struct {
    pub fn writeWithParams(
        writer: *protocol.PayloadWriter,
        statement_id: u32,
        params: anytype,
    ) !void {
        const fields = comptime paramFields(@TypeOf(params));
        const param_count = fields.len;

        try writer.writeInt(u8, @intFromEnum(protocol.command.CommandCode.stmt_execute));
        try writer.writeInt(u32, statement_id);
        try writer.writeInt(u8, 0);
        try writer.writeInt(u32, 1);

        if (param_count == 0) return;

        try writeNullBitmap(writer, params);
        try writer.writeInt(u8, 1);

        inline for (fields) |field| {
            const field_type = comptime fieldTypeForParam(field.type);
            try writer.writeInt(u8, @intFromEnum(field_type));
            try writer.writeInt(u8, comptime unsignedFlagForParam(field.type));
        }

        inline for (fields) |field| {
            const param = @field(params, field.name);
            const field_type = comptime fieldTypeForParam(field.type);
            try writeParamValue(writer, field_type, param);
        }
    }
};

pub fn paramCount(comptime Params: type) usize {
    return paramFields(Params).len;
}

fn paramFields(comptime Params: type) []const std.builtin.Type.StructField {
    const params_info = @typeInfo(Params);
    if (params_info != .@"struct") {
        @compileError("prepared statement parameters must be a tuple or struct");
    }
    return params_info.@"struct".fields;
}

fn writeNullBitmap(writer: *protocol.PayloadWriter, params: anytype) !void {
    const fields = comptime paramFields(@TypeOf(params));
    const null_bitmap_len = (fields.len + 7) / 8;
    var null_bitmap = try writer.reserve(null_bitmap_len);
    @memset(null_bitmap, 0);

    inline for (fields, 0..) |field, index| {
        const param = @field(params, field.name);
        if (isNull(param)) {
            null_bitmap[index / 8] |= @as(u8, 1) << @intCast(index % 8);
        }
    }
}

fn isNull(param: anytype) bool {
    return switch (@typeInfo(@TypeOf(param))) {
        .null => true,
        .optional => param == null,
        else => false,
    };
}

// ---- user-side encode conventions (symmetric to result `fromMantle*`) ----
//
// A parameter type opts into custom encoding by declaring exactly one of:
//   - `toMantleText(self, buf: []u8) []const u8` — value -> text; sent as a
//       string parameter (MySQL coerces to the target column type, lossless for
//       DECIMAL). `buf` is at least `max_text_param_len` bytes; for arbitrary
//       length text pass a `[]const u8` parameter directly instead.
//   - `toMantleDateTime(self) DateTime` — value -> DATETIME components.
//   - `toMantleTime(self) Time`         — value -> TIME components.
// Each may return the IR directly or an error union of it. mantle owns the wire
// encoding; the type owns the value -> IR mapping, so mantle stays agnostic to
// any concrete decimal / datetime library.

const to_text_decl = "toMantleText";
const to_datetime_decl = "toMantleDateTime";
const to_time_decl = "toMantleTime";

/// Generous stack buffer for `toMantleText`; covers MySQL DECIMAL(65,30)
/// (65 digits + sign + point) with headroom.
const max_text_param_len = 96;

fn isEncodeAdapter(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => @hasDecl(T, to_text_decl) or
            @hasDecl(T, to_datetime_decl) or
            @hasDecl(T, to_time_decl),
        else => false,
    };
}

fn encodeAdapterFieldType(comptime T: type) protocol.text_result.FieldType {
    comptime validateEncodeAdapter(T);
    if (@hasDecl(T, to_datetime_decl)) return .datetime;
    if (@hasDecl(T, to_time_decl)) return .time;
    return .var_string; // toMantleText
}

fn writeEncodeAdapter(writer: *protocol.PayloadWriter, param: anytype) !void {
    const T = @TypeOf(param);
    comptime validateEncodeAdapter(T);
    // Conventions may return the IR directly or an error union of it; `try` only
    // compiles on the error-union branch since the condition is comptime-known.
    if (comptime @hasDecl(T, to_datetime_decl)) {
        const r = param.toMantleDateTime();
        const ir = if (comptime @typeInfo(@TypeOf(r)) == .error_union) try r else r;
        return writeDateTimeParam(writer, ir);
    } else if (comptime @hasDecl(T, to_time_decl)) {
        const r = param.toMantleTime();
        const ir = if (comptime @typeInfo(@TypeOf(r)) == .error_union) try r else r;
        return writeTimeParam(writer, ir);
    } else {
        var buf: [max_text_param_len]u8 = undefined;
        const r = param.toMantleText(&buf);
        const bytes = if (comptime @typeInfo(@TypeOf(r)) == .error_union) try r else r;
        try writer.writeLengthEncodedString(bytes);
    }
}

fn validateEncodeAdapter(comptime T: type) void {
    comptime var count: usize = 0;
    if (@hasDecl(T, to_text_decl)) {
        count += 1;
        assertEncodeText(T);
    }
    if (@hasDecl(T, to_datetime_decl)) {
        count += 1;
        assertEncodeValue(T, to_datetime_decl, temporal.DateTime);
    }
    if (@hasDecl(T, to_time_decl)) {
        count += 1;
        assertEncodeValue(T, to_time_decl, temporal.Time);
    }
    if (count != 1) {
        @compileError(@typeName(T) ++ " must declare exactly one toMantle* encode convention");
    }
}

fn encodeFn(comptime T: type, comptime name: []const u8) std.builtin.Type.Fn {
    const info = @typeInfo(@TypeOf(@field(T, name)));
    if (info != .@"fn") @compileError(@typeName(T) ++ "." ++ name ++ " must be a function");
    return info.@"fn";
}

fn returnsPayload(comptime R: ?type, comptime Want: type) bool {
    const Rt = R orelse return false;
    return Rt == Want or
        (@typeInfo(Rt) == .error_union and @typeInfo(Rt).error_union.payload == Want);
}

fn assertEncodeText(comptime T: type) void {
    const f = encodeFn(T, to_text_decl);
    const buf_ok = f.params.len == 2 and (f.params[1].type orelse void) == []u8;
    if (!buf_ok) {
        @compileError(@typeName(T) ++ "." ++ to_text_decl ++ " must take (self, buf: []u8)");
    }
    if (!returnsPayload(f.return_type, []const u8)) {
        @compileError(@typeName(T) ++ "." ++ to_text_decl ++ " must return []const u8 or an error union of it");
    }
}

fn assertEncodeValue(comptime T: type, comptime name: []const u8, comptime Ir: type) void {
    const f = encodeFn(T, name);
    if (f.params.len != 1) {
        @compileError(@typeName(T) ++ "." ++ name ++ " must take only self");
    }
    if (!returnsPayload(f.return_type, Ir)) {
        @compileError(@typeName(T) ++ "." ++ name ++ " must return " ++ @typeName(Ir) ++ " or an error union of it");
    }
}

fn fieldTypeForParam(comptime Param: type) protocol.text_result.FieldType {
    if (comptime isEncodeAdapter(Param)) return encodeAdapterFieldType(Param);
    if (Param == decimal.Decimal) return .newdecimal;
    if (Param == temporal.DateTime) return .datetime;
    if (Param == temporal.Time) return .time;

    return switch (@typeInfo(Param)) {
        .null => .null,
        .optional => |optional| fieldTypeForParam(optional.child),
        .bool => .tiny,
        .int => |int| {
            if (int.bits <= 8) return .tiny;
            if (int.bits <= 16) return .short;
            if (int.bits <= 32) return .long;
            if (int.bits <= 64) return .longlong;
            @compileError("prepared statement integer parameters must be 64 bits or smaller");
        },
        .comptime_int => .longlong,
        .float => |float| {
            if (float.bits <= 32) return .float;
            if (float.bits <= 64) return .double;
            @compileError("prepared statement float parameters must be 64 bits or smaller");
        },
        .comptime_float => .double,
        .pointer => |pointer| {
            if (pointer.size == .slice and pointer.child == u8) return .var_string;
            if (pointer.size == .one) {
                const child_info = @typeInfo(pointer.child);
                if (child_info == .array and child_info.array.child == u8) return .var_string;
            }
            @compileError("prepared statement pointer parameters must point to u8 bytes");
        },
        .array => |array| {
            if (array.child == u8) return .var_string;
            @compileError("prepared statement array parameters must contain u8");
        },
        else => @compileError("unsupported prepared statement parameter type"),
    };
}

fn unsignedFlagForParam(comptime Param: type) u8 {
    return switch (@typeInfo(Param)) {
        .optional => |optional| unsignedFlagForParam(optional.child),
        .int => |int| if (int.signedness == .unsigned) 0x80 else 0,
        else => 0,
    };
}

fn writeParamValue(
    writer: *protocol.PayloadWriter,
    comptime field_type: protocol.text_result.FieldType,
    param: anytype,
) !void {
    // User-side encode conventions take precedence over built-in struct types.
    if (comptime isEncodeAdapter(@TypeOf(param))) {
        return writeEncodeAdapter(writer, param);
    }
    return switch (@typeInfo(@TypeOf(param))) {
        .null => {},
        .optional => if (param) |value| try writeParamValue(writer, field_type, value),
        .bool => switch (field_type) {
            .tiny => try writer.writeInt(u8, if (param) 1 else 0),
            else => return error.UnsupportedPreparedParameterType,
        },
        .int, .comptime_int => switch (field_type) {
            .tiny => try writer.writeInt(u8, intStorage(u8, param)),
            .short => try writer.writeInt(u16, intStorage(u16, param)),
            .long => try writer.writeInt(u32, intStorage(u32, param)),
            .longlong => try writer.writeInt(u64, intStorage(u64, param)),
            else => return error.UnsupportedPreparedParameterType,
        },
        .float, .comptime_float => switch (field_type) {
            .float => try writer.writeInt(u32, floatStorage(u32, param)),
            .double => try writer.writeInt(u64, floatStorage(u64, param)),
            else => return error.UnsupportedPreparedParameterType,
        },
        .@"struct" => {
            if (@TypeOf(param) == decimal.Decimal) {
                return try writeDecimalParam(writer, param);
            }
            if (@TypeOf(param) == temporal.DateTime) {
                return try writeDateTimeParam(writer, param);
            }
            if (@TypeOf(param) == temporal.Time) {
                return try writeTimeParam(writer, param);
            }
            @compileError("unsupported prepared statement struct parameter type");
        },
        .pointer, .array => try writer.writeLengthEncodedString(stringBytes(param)),
        else => @compileError("unsupported prepared statement parameter type"),
    };
}

fn writeDecimalParam(writer: *protocol.PayloadWriter, value: decimal.Decimal) !void {
    try decimal.validateDecimal(value);
    try writer.writeLengthEncodedString(value.bytes);
}

fn writeDateTimeParam(writer: *protocol.PayloadWriter, value: temporal.DateTime) !void {
    try temporal.validateDateTime(value);

    if (value.year == 0 and value.month == 0 and value.day == 0 and value.hour == 0 and value.minute == 0 and value.second == 0 and value.microsecond == 0) {
        return writer.writeInt(u8, 0);
    }

    if (value.hour == 0 and value.minute == 0 and value.second == 0 and value.microsecond == 0) {
        try writer.writeInt(u8, 4);
        try writer.writeInt(u16, value.year);
        try writer.writeInt(u8, value.month);
        try writer.writeInt(u8, value.day);
        return;
    }

    if (value.microsecond == 0) {
        try writer.writeInt(u8, 7);
        try writer.writeInt(u16, value.year);
        try writer.writeInt(u8, value.month);
        try writer.writeInt(u8, value.day);
        try writer.writeInt(u8, value.hour);
        try writer.writeInt(u8, value.minute);
        try writer.writeInt(u8, value.second);
        return;
    }

    try writer.writeInt(u8, 11);
    try writer.writeInt(u16, value.year);
    try writer.writeInt(u8, value.month);
    try writer.writeInt(u8, value.day);
    try writer.writeInt(u8, value.hour);
    try writer.writeInt(u8, value.minute);
    try writer.writeInt(u8, value.second);
    try writer.writeInt(u32, value.microsecond);
}

fn writeTimeParam(writer: *protocol.PayloadWriter, value: temporal.Time) !void {
    try temporal.validateTime(value);

    if (!value.negative and value.days == 0 and value.hour == 0 and value.minute == 0 and value.second == 0 and value.microsecond == 0) {
        return writer.writeInt(u8, 0);
    }

    if (value.microsecond == 0) {
        try writer.writeInt(u8, 8);
        try writer.writeInt(u8, if (value.negative) 1 else 0);
        try writer.writeInt(u32, value.days);
        try writer.writeInt(u8, value.hour);
        try writer.writeInt(u8, value.minute);
        try writer.writeInt(u8, value.second);
        return;
    }

    try writer.writeInt(u8, 12);
    try writer.writeInt(u8, if (value.negative) 1 else 0);
    try writer.writeInt(u32, value.days);
    try writer.writeInt(u8, value.hour);
    try writer.writeInt(u8, value.minute);
    try writer.writeInt(u8, value.second);
    try writer.writeInt(u32, value.microsecond);
}

fn intStorage(comptime Storage: type, value: anytype) Storage {
    return switch (@typeInfo(@TypeOf(value))) {
        .comptime_int => @intCast(value),
        .int => |int| switch (int.signedness) {
            .signed => @bitCast(@as(std.meta.Int(.signed, @bitSizeOf(Storage)), @intCast(value))),
            .unsigned => @intCast(value),
        },
        else => @compileError("prepared statement integer storage requires an integer value"),
    };
}

fn floatStorage(comptime Storage: type, value: anytype) Storage {
    return switch (Storage) {
        u32 => @bitCast(@as(f32, @floatCast(value))),
        u64 => @bitCast(@as(f64, @floatCast(value))),
        else => @compileError("prepared statement float storage must be u32 or u64"),
    };
}

fn stringBytes(param: anytype) []const u8 {
    return switch (@typeInfo(@TypeOf(param))) {
        .pointer => |pointer| switch (pointer.size) {
            .one => param[0..],
            .slice => param,
            else => @compileError("prepared statement string pointer must be one or slice"),
        },
        .array => param[0..],
        else => @compileError("prepared statement string parameter must be []const u8 or an array"),
    };
}
