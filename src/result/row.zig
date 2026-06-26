const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;
const column_reader = @import("column_reader.zig");
const decode_adapter = @import("decode_adapter.zig");

const DateTime = column_reader.DateTime;
const Time = column_reader.Time;
const Decimal = column_reader.Decimal;

pub const ScanError = struct {
    reason: anyerror,
    field_name: []const u8,
    column_name: ?[]const u8,
    index: ?usize,
    target_type: []const u8,
};

pub const RowResultTag = enum {
    row,
    eof,
    err,
};

/// A decoded result-set row, parameterized by wire protocol. The text and
/// binary protocols share identical row semantics (raw value slices aliasing
/// the payload, the same scan/accessor surface); only the per-column reader and
/// the transport row type differ, so both are generated from this single
/// factory. `TextRowResult` / `BinaryRowResult` below are the concrete types.
pub fn RowResult(comptime proto: decode_adapter.Protocol) type {
    return struct {
        const Self = @This();
        const TransportRow = switch (proto) {
            .text => mantle.transport.ResultRow,
            .binary => mantle.transport.BinaryResultRow,
        };

        tag: RowResultTag,
        transport_row: TransportRow,
        /// Per-column raw values, each aliasing `transport_row.payload`. Valid
        /// until this row is `deinit`ed (or the next row is fetched). Scan into
        /// owned storage to retain values beyond the row's lifetime.
        values: []?[]const u8,
        last_scan_error: ?ScanError = null,

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.transport_row.deinit(allocator);
        }

        pub fn valueAt(self: *const Self, index: usize) !?[]const u8 {
            if (index >= self.values.len) return error.ColumnIndexOutOfBounds;
            return self.values[index];
        }

        pub fn valueByName(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?[]const u8 {
            return self.valueAt(try self.findColumnIndex(columns, name));
        }

        pub fn intAt(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?T {
            return switch (proto) {
                .text => column_reader.readTextInt(T, columns, self.values, index),
                .binary => column_reader.readBinaryInt(T, columns, self.values, index),
            };
        }

        pub fn intByName(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?T {
            return self.intAt(T, columns, try self.findColumnIndex(columns, name));
        }

        pub fn floatAt(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?T {
            return switch (proto) {
                .text => column_reader.readTextFloat(T, columns, self.values, index),
                .binary => column_reader.readBinaryFloat(T, columns, self.values, index),
            };
        }

        pub fn floatByName(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?T {
            return self.floatAt(T, columns, try self.findColumnIndex(columns, name));
        }

        pub fn boolAt(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?bool {
            return switch (proto) {
                .text => column_reader.readTextBool(columns, self.values, index),
                .binary => column_reader.readBinaryBool(columns, self.values, index),
            };
        }

        pub fn boolByName(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?bool {
            return self.boolAt(columns, try self.findColumnIndex(columns, name));
        }

        pub fn dateTimeAt(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?DateTime {
            return switch (proto) {
                .text => column_reader.readTextDateTime(columns, self.values, index),
                .binary => column_reader.readBinaryDateTime(columns, self.values, index),
            };
        }

        pub fn dateTimeByName(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?DateTime {
            return self.dateTimeAt(columns, try self.findColumnIndex(columns, name));
        }

        pub fn timeAt(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?Time {
            return switch (proto) {
                .text => column_reader.readTextTime(columns, self.values, index),
                .binary => column_reader.readBinaryTime(columns, self.values, index),
            };
        }

        pub fn timeByName(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?Time {
            return self.timeAt(columns, try self.findColumnIndex(columns, name));
        }

        pub fn decimalAt(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
        ) !?Decimal {
            return switch (proto) {
                .text => column_reader.readTextDecimal(columns, self.values, index),
                .binary => column_reader.readBinaryDecimal(columns, self.values, index),
            };
        }

        pub fn decimalByName(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !?Decimal {
            return self.decimalAt(columns, try self.findColumnIndex(columns, name));
        }

        pub fn lastScanError(self: *const Self) ?ScanError {
            return self.last_scan_error;
        }

        pub fn scan(
            self: *Self,
            dest: anytype,
            columns: []const protocol.text_result.ColumnDefinition41,
        ) !void {
            return self.scanImpl(dest, columns, null);
        }

        /// Like `scan`, but `[]const u8` fields are duplicated with
        /// `str_allocator` so the destination outlives the borrowed row buffer.
        /// Used by owned collection APIs such as `Connection.queryAll`.
        pub fn scanAlloc(
            self: *Self,
            dest: anytype,
            columns: []const protocol.text_result.ColumnDefinition41,
            str_allocator: std.mem.Allocator,
        ) !void {
            return self.scanImpl(dest, columns, str_allocator);
        }

        /// Resolve each field of `Dest` to its column index. Field names are
        /// comptime and column names are fixed for the whole result set, so a
        /// caller collecting many rows resolves once and reuses the result via
        /// `scanAllocResolved`, instead of rescanning column names per row. The
        /// name-resolution errors (Unknown/Ambiguous/Mismatch) are deterministic
        /// for the result set and surface here once.
        pub fn resolveScanColumns(
            comptime Dest: type,
            columns: []const protocol.text_result.ColumnDefinition41,
        ) ![std.meta.fields(Dest).len]usize {
            const fields = std.meta.fields(Dest);
            var indices: [fields.len]usize = undefined;
            inline for (fields, 0..) |field, i| {
                indices[i] = try findColumnIndexForValues(columns.len, columns, field.name);
            }
            return indices;
        }

        /// Like `scanAlloc`, but uses column indices precomputed by
        /// `resolveScanColumns` (whose length must match `Dest`'s field count),
        /// skipping the per-row column-name lookup.
        pub fn scanAllocResolved(
            self: *Self,
            dest: anytype,
            columns: []const protocol.text_result.ColumnDefinition41,
            indices: []const usize,
            str_allocator: std.mem.Allocator,
        ) !void {
            self.last_scan_error = null;
            if (columns.len != self.values.len) return error.ColumnCountMismatch;

            const DestPtr = @TypeOf(dest);
            const dest_ptr_info = @typeInfo(DestPtr);
            if (dest_ptr_info != .pointer or dest_ptr_info.pointer.size != .one) {
                @compileError("scan destination must be a pointer to a struct");
            }
            const Dest = dest_ptr_info.pointer.child;
            const dest_info = @typeInfo(Dest);
            if (dest_info != .@"struct") {
                @compileError("scan destination must be a pointer to a struct");
            }

            inline for (dest_info.@"struct".fields, 0..) |field, i| {
                const index = indices[i];
                @field(dest, field.name) = self.scanValue(field.type, columns, index, str_allocator) catch |err| {
                    self.recordScanError(field.name, columns[index].name, index, @typeName(field.type), err);
                    return err;
                };
            }
        }

        fn scanImpl(
            self: *Self,
            dest: anytype,
            columns: []const protocol.text_result.ColumnDefinition41,
            str_allocator: ?std.mem.Allocator,
        ) !void {
            self.last_scan_error = null;
            const DestPtr = @TypeOf(dest);
            const dest_ptr_info = @typeInfo(DestPtr);
            if (dest_ptr_info != .pointer or dest_ptr_info.pointer.size != .one) {
                @compileError("scan destination must be a pointer to a struct");
            }

            const Dest = dest_ptr_info.pointer.child;
            const dest_info = @typeInfo(Dest);
            if (dest_info != .@"struct") {
                @compileError("scan destination must be a pointer to a struct");
            }

            inline for (dest_info.@"struct".fields) |field| {
                const index = self.findColumnIndex(columns, field.name) catch |err| {
                    self.recordScanError(field.name, null, null, @typeName(field.type), err);
                    return err;
                };
                @field(dest, field.name) = self.scanValue(field.type, columns, index, str_allocator) catch |err| {
                    self.recordScanError(field.name, columns[index].name, index, @typeName(field.type), err);
                    return err;
                };
            }
        }

        fn recordScanError(
            self: *Self,
            field_name: []const u8,
            column_name: ?[]const u8,
            index: ?usize,
            target_type: []const u8,
            reason: anyerror,
        ) void {
            self.last_scan_error = .{
                .reason = reason,
                .field_name = field_name,
                .column_name = column_name,
                .index = index,
                .target_type = target_type,
            };
        }

        fn findColumnIndex(
            self: *const Self,
            columns: []const protocol.text_result.ColumnDefinition41,
            name: []const u8,
        ) !usize {
            return findColumnIndexForValues(self.values.len, columns, name);
        }

        fn scanValue(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
            str_allocator: ?std.mem.Allocator,
        ) !T {
            return switch (@typeInfo(T)) {
                .optional => |optional| {
                    const value = try self.scanOptionalValue(optional.child, columns, index, str_allocator);
                    return value;
                },
                else => {
                    if ((try self.valueAt(index)) == null) return error.UnexpectedNullValue;
                    return self.scanNonNullValue(T, columns, index, str_allocator);
                },
            };
        }

        fn scanOptionalValue(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
            str_allocator: ?std.mem.Allocator,
        ) !?T {
            if ((try self.valueAt(index)) == null) return null;
            return try self.scanNonNullValue(T, columns, index, str_allocator);
        }

        fn scanNonNullValue(
            self: *const Self,
            comptime T: type,
            columns: []const protocol.text_result.ColumnDefinition41,
            index: usize,
            str_allocator: ?std.mem.Allocator,
        ) !T {
            // User-side decode conventions (`fromMantle*`) take precedence over
            // the built-in IR types and own decoding for their column.
            if (comptime decode_adapter.isDecodeAdapter(T)) {
                return decode_adapter.decode(proto, T, columns, self.values, index);
            }
            return switch (@typeInfo(T)) {
                .int => (try self.intAt(T, columns, index)).?,
                .float => (try self.floatAt(T, columns, index)).?,
                .bool => (try self.boolAt(columns, index)).?,
                .@"struct" => {
                    if (T == DateTime) {
                        return (try self.dateTimeAt(columns, index)).?;
                    }
                    if (T == Time) {
                        return (try self.timeAt(columns, index)).?;
                    }
                    if (T == Decimal) {
                        const value = (try self.decimalAt(columns, index)).?;
                        if (str_allocator) |alloc| return Decimal{ .bytes = try alloc.dupe(u8, value.bytes) };
                        return value;
                    }
                    return error.UnsupportedScanFieldType;
                },
                .pointer => |pointer| {
                    if (pointer.size == .slice and pointer.is_const and pointer.child == u8) {
                        const value = switch (proto) {
                            .text => try column_reader.readTextBytes(columns, self.values, index),
                            .binary => try column_reader.readBinaryBytes(columns, self.values, index),
                        };
                        const bytes = value.?;
                        if (str_allocator) |alloc| return try alloc.dupe(u8, bytes);
                        return bytes;
                    }
                    return error.UnsupportedScanFieldType;
                },
                else => error.UnsupportedScanFieldType,
            };
        }
    };
}

pub const TextRowResult = RowResult(.text);
pub const BinaryRowResult = RowResult(.binary);

// Back-compat tag aliases: the tag type is now shared across protocols.
pub const TextRowResultTag = RowResultTag;
pub const BinaryRowResultTag = RowResultTag;

fn findColumnIndexForValues(
    value_count: usize,
    columns: []const protocol.text_result.ColumnDefinition41,
    name: []const u8,
) !usize {
    if (columns.len != value_count) return error.ColumnCountMismatch;

    var found: ?usize = null;
    for (columns, 0..) |column, index| {
        if (std.mem.eql(u8, column.name, name)) {
            if (found != null) return error.AmbiguousColumnName;
            found = index;
        }
    }

    return found orelse error.UnknownColumnName;
}
