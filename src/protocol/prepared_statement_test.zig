const std = @import("std");

const prepared_statement = @import("prepared_statement.zig");
const protocol = @import("protocol.zig");
const decimal = @import("decimal.zig");
const temporal = @import("temporal.zig");

const PrepareOk = prepared_statement.PrepareOk;
const ExecuteRequest = prepared_statement.ExecuteRequest;

test "prepared statement parses COM_STMT_PREPARE_OK" {
    const payload = [_]u8{
        0x00,
        0x78,
        0x56,
        0x34,
        0x12,
        0x02,
        0x00,
        0x01,
        0x00,
        0x00,
        0x03,
        0x00,
    };

    const ok = try PrepareOk.parse(&payload, protocol.capability.client_protocol_41);

    try std.testing.expectEqual(@as(u32, 0x12345678), ok.statement_id);
    try std.testing.expectEqual(@as(u16, 2), ok.column_count);
    try std.testing.expectEqual(@as(u16, 1), ok.parameter_count);
    try std.testing.expectEqual(@as(u16, 3), ok.warning_count.?);
    try std.testing.expect(ok.metadata_follows == null);
}

test "prepared statement rejects malformed COM_STMT_PREPARE_OK" {
    try std.testing.expectError(protocol.types.Error.InvalidPacketSignature, PrepareOk.parse(&.{ 0xff, 0x01 }, protocol.capability.client_protocol_41));
    try std.testing.expectError(protocol.types.Error.EndOfPayload, PrepareOk.parse(&.{ 0x00, 0x01 }, protocol.capability.client_protocol_41));
}

test "execute request encodes integer string and null parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{ @as(i32, 42), "bob", null });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000100,
        0x01,
        0x03,
        0x00,
        0xfd,
        0x00,
        0x06,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, writer.bytes());
}

test "execute request encodes sentinel-terminated string parameters without sentinel" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const name: [:0]const u8 = "bob";
    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{name});

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xfd,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, writer.bytes());
}

test "execute request encodes mutable byte buffer parameters as strings" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    var name = [_]u8{ 'b', 'o', 'b' };
    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{name[0..]});

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xfd,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, writer.bytes());
}

test "execute request encodes unsigned and optional parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const maybe_id: ?i32 = 7;
    const maybe_name: ?[]const u8 = null;
    try ExecuteRequest.writeWithParams(
        &writer,
        0x12345678,
        .{ @as(u64, 0x8000000000000000), maybe_id, maybe_name },
    );

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000100,
        0x01,
        0x08,
        0x80,
        0x03,
        0x00,
        0xfd,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        0x07,
        0x00,
        0x00,
        0x00,
    }, writer.bytes());
}

test "execute request encodes comptime integer parameter" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{42});

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x08,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    }, writer.bytes());
}

test "execute request encodes float double and comptime float parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{ @as(f32, 1.5), @as(f64, 2.25), 3.5 });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x04,
        0x00,
        0x05,
        0x00,
        0x05,
        0x00,
        0x00,
        0x00,
        0xc0,
        0x3f,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x40,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0c,
        0x40,
    }, writer.bytes());
}

test "execute request encodes bool and optional bool parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const maybe_enabled: ?bool = true;
    const maybe_deleted: ?bool = null;
    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{ true, false, maybe_enabled, maybe_deleted });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00001000,
        0x01,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
    }, writer.bytes());
}

test "execute request encodes decimal and optional decimal parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    const maybe_amount: ?decimal.Decimal = null;
    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        decimal.Decimal{ .bytes = "-123.456" },
        maybe_amount,
    });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000010,
        0x01,
        0xf6,
        0x00,
        0xf6,
        0x00,
        0x08,
        '-',
        '1',
        '2',
        '3',
        '.',
        '4',
        '5',
        '6',
    }, writer.bytes());
}

test "execute request rejects invalid decimal parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try std.testing.expectError(error.InvalidDecimalValue, ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        decimal.Decimal{ .bytes = "12x.34" },
    }));
}

test "execute request encodes datetime and time parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        temporal.DateTime{ .year = 2026, .month = 6, .day = 16, .hour = 12, .minute = 34, .second = 56, .microsecond = 123456 },
        temporal.Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5, .microsecond = 123456 },
    });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x0c,
        0x00,
        0x0b,
        0x00,
        0x0b,
        0xea,
        0x07,
        0x06,
        0x10,
        0x0c,
        0x22,
        0x38,
        0x40,
        0xe2,
        0x01,
        0x00,
        0x0c,
        0x01,
        0x02,
        0x00,
        0x00,
        0x00,
        0x03,
        0x04,
        0x05,
        0x40,
        0xe2,
        0x01,
        0x00,
    }, writer.bytes());
}

test "execute request rejects invalid temporal parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try std.testing.expectError(error.InvalidTemporalValue, ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        temporal.DateTime{ .year = 2026, .month = 13, .day = 16 },
    }));

    writer.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidTemporalValue, ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        temporal.Time{ .hour = 24 },
    }));
}

test "execute request encodes struct parameters" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try ExecuteRequest.writeWithParams(&writer, 0x12345678, .{
        .id = 42,
        .name = "bob",
        .maybe_id = null,
    });

    try std.testing.expectEqualSlices(u8, &.{
        0x17,
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0b00000100,
        0x01,
        0x08,
        0x00,
        0xfd,
        0x00,
        0x06,
        0x00,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        'b',
        'o',
        'b',
    }, writer.bytes());
}

// ---- user-side encode conventions (toMantle*) ----

const UserDecimal = struct {
    text: []const u8,
    pub fn toMantleText(self: UserDecimal, buf: []u8) []const u8 {
        @memcpy(buf[0..self.text.len], self.text);
        return buf[0..self.text.len];
    }
};

const FallibleDecimal = struct {
    text: []const u8,
    pub fn toMantleText(self: FallibleDecimal, buf: []u8) ![]const u8 {
        if (self.text.len > buf.len) return error.Overflow;
        @memcpy(buf[0..self.text.len], self.text);
        return buf[0..self.text.len];
    }
};

const UserDate = struct {
    y: u16,
    m: u8,
    d: u8,
    pub fn toMantleDateTime(self: UserDate) temporal.DateTime {
        return .{ .year = self.y, .month = self.m, .day = self.d };
    }
};

const UserDuration = struct {
    neg: bool,
    days: u32,
    h: u8,
    mi: u8,
    s: u8,
    pub fn toMantleTime(self: UserDuration) temporal.Time {
        return .{ .negative = self.neg, .days = self.days, .hour = self.h, .minute = self.mi, .second = self.s };
    }
};

test "encode adapter toMantleText matches a string parameter" {
    var w1 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w1.deinit();
    try ExecuteRequest.writeWithParams(&w1, 0x12345678, .{UserDecimal{ .text = "-123.456" }});

    var w2 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w2.deinit();
    try ExecuteRequest.writeWithParams(&w2, 0x12345678, .{@as([]const u8, "-123.456")});

    try std.testing.expectEqualSlices(u8, w2.bytes(), w1.bytes());
}

test "encode adapter toMantleDateTime matches built-in DateTime" {
    var w1 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w1.deinit();
    try ExecuteRequest.writeWithParams(&w1, 0x12345678, .{UserDate{ .y = 2026, .m = 6, .d = 16 }});

    var w2 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w2.deinit();
    try ExecuteRequest.writeWithParams(&w2, 0x12345678, .{temporal.DateTime{ .year = 2026, .month = 6, .day = 16 }});

    try std.testing.expectEqualSlices(u8, w2.bytes(), w1.bytes());
}

test "encode adapter toMantleTime matches built-in Time" {
    var w1 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w1.deinit();
    try ExecuteRequest.writeWithParams(&w1, 0x12345678, .{UserDuration{ .neg = true, .days = 2, .h = 3, .mi = 4, .s = 5 }});

    var w2 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w2.deinit();
    try ExecuteRequest.writeWithParams(&w2, 0x12345678, .{temporal.Time{ .negative = true, .days = 2, .hour = 3, .minute = 4, .second = 5 }});

    try std.testing.expectEqualSlices(u8, w2.bytes(), w1.bytes());
}

test "encode adapter propagates fallible toMantleText error" {
    var w = protocol.PayloadWriter.init(std.testing.allocator);
    defer w.deinit();

    var big: [200]u8 = undefined;
    @memset(&big, '9');
    try std.testing.expectError(error.Overflow, ExecuteRequest.writeWithParams(&w, 0x12345678, .{FallibleDecimal{ .text = &big }}));
}

test "encode adapter supports optional null parameter" {
    var w1 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w1.deinit();
    const none: ?UserDate = null;
    try ExecuteRequest.writeWithParams(&w1, 0x12345678, .{none});

    var w2 = protocol.PayloadWriter.init(std.testing.allocator);
    defer w2.deinit();
    const none_dt: ?temporal.DateTime = null;
    try ExecuteRequest.writeWithParams(&w2, 0x12345678, .{none_dt});

    try std.testing.expectEqualSlices(u8, w2.bytes(), w1.bytes());
}
