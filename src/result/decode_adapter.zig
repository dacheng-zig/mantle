//! User-side decode conventions for `scan`.
//!
//! A destination field type opts into custom decoding by declaring one of the
//! `fromMantle*` constructors below. mantle decodes the column into its neutral
//! intermediate representation (raw value bytes, or a `DateTime` / `Time`
//! component struct) and hands it to the matching constructor, so mantle stays
//! agnostic to any concrete decimal / datetime library.
//!
//! Conventions (each takes mantle's decoded IR and returns the user type,
//! optionally wrapped in an error union):
//!
//!   - `fromMantleText(bytes: []const u8) !T`  — DECIMAL / text / blob columns.
//!       The slice is **borrowed** and only valid for the duration of the call;
//!       parse it into an owned value, do not retain the slice.
//!   - `fromMantleDateTime(dt: DateTime) !T`   — DATE / DATETIME / TIMESTAMP columns.
//!   - `fromMantleTime(t: Time) !T`            — TIME columns (signed, may exceed 24h).
//!
//! Dispatch is driven by the column's actual type, not declaration order, so a
//! type may safely declare several conventions. A convention mapped onto an
//! incompatible column fails with `error.InvalidColumnType`.

const protocol = @import("../protocol/protocol.zig");
const column_reader = @import("column_reader.zig");

const DateTime = column_reader.DateTime;
const Time = column_reader.Time;

const text_decl = "fromMantleText";
const datetime_decl = "fromMantleDateTime";
const time_decl = "fromMantleTime";

/// Which row protocol the values came from; selects the temporal reader.
pub const Protocol = enum { text, binary };

/// True if `T` opts into any `fromMantle*` decode convention.
pub fn isDecodeAdapter(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => @hasDecl(T, text_decl) or
            @hasDecl(T, datetime_decl) or
            @hasDecl(T, time_decl),
        else => false,
    };
}

/// Decode column `index` into adapter type `T` via its declared convention.
/// Precondition: the value at `index` is non-null (callers exclude SQL NULL
/// before reaching here, mirroring the built-in scan readers).
pub fn decode(
    comptime proto: Protocol,
    comptime T: type,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !T {
    comptime validate(T);
    if (index >= columns.len) return error.ColumnIndexOutOfBounds;

    switch (column_reader.decodeCategory(columns[index])) {
        .datetime => if (comptime @hasDecl(T, datetime_decl)) {
            return T.fromMantleDateTime((try readDateTime(proto, columns, values, index)).?);
        },
        .time => if (comptime @hasDecl(T, time_decl)) {
            return T.fromMantleTime((try readTime(proto, columns, values, index)).?);
        },
        .bytes => if (comptime @hasDecl(T, text_decl)) {
            return T.fromMantleText((try readBytes(proto, columns, values, index)).?);
        },
        .other => {},
    }
    return error.InvalidColumnType;
}

fn readDateTime(
    comptime proto: Protocol,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?DateTime {
    return switch (proto) {
        .text => column_reader.readTextDateTime(columns, values, index),
        .binary => column_reader.readBinaryDateTime(columns, values, index),
    };
}

fn readTime(
    comptime proto: Protocol,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?Time {
    return switch (proto) {
        .text => column_reader.readTextTime(columns, values, index),
        .binary => column_reader.readBinaryTime(columns, values, index),
    };
}

fn readBytes(
    comptime proto: Protocol,
    columns: []const protocol.text_result.ColumnDefinition41,
    values: []const ?[]const u8,
    index: usize,
) !?[]const u8 {
    // DECIMAL / text / blob values are raw bytes in both protocols.
    return switch (proto) {
        .text => column_reader.readTextBytes(columns, values, index),
        .binary => column_reader.readBinaryBytes(columns, values, index),
    };
}

/// Compile-time check that each declared convention has the expected signature,
/// so a typo'd parameter or return type fails the build with a clear message
/// instead of silently mis-decoding.
fn validate(comptime T: type) void {
    if (@hasDecl(T, text_decl)) assertSignature(T, text_decl, []const u8);
    if (@hasDecl(T, datetime_decl)) assertSignature(T, datetime_decl, DateTime);
    if (@hasDecl(T, time_decl)) assertSignature(T, time_decl, Time);
}

fn assertSignature(comptime T: type, comptime name: []const u8, comptime Param: type) void {
    const decl = @field(T, name);
    const info = @typeInfo(@TypeOf(decl));
    if (info != .@"fn") {
        @compileError(@typeName(T) ++ "." ++ name ++ " must be a function taking one " ++
            @typeName(Param) ++ " parameter");
    }
    const f = info.@"fn";
    if (f.params.len != 1 or f.params[0].type != Param) {
        @compileError(@typeName(T) ++ "." ++ name ++ " must take exactly one " ++
            @typeName(Param) ++ " parameter");
    }
    const Return = f.return_type orelse {
        @compileError(@typeName(T) ++ "." ++ name ++ " must return " ++
            @typeName(T) ++ " or an error union of it");
    };
    const ok = Return == T or
        (@typeInfo(Return) == .error_union and @typeInfo(Return).error_union.payload == T);
    if (!ok) {
        @compileError(@typeName(T) ++ "." ++ name ++ " must return " ++
            @typeName(T) ++ " or an error union of it");
    }
}
