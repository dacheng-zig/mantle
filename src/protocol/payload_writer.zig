const std = @import("std");

pub const PayloadWriter = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) PayloadWriter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PayloadWriter) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn bytes(self: PayloadWriter) []const u8 {
        return self.buffer.items;
    }

    pub fn clearRetainingCapacity(self: *PayloadWriter) void {
        self.buffer.clearRetainingCapacity();
    }

    pub fn writeInt(self: *PayloadWriter, comptime Int: type, value: Int) !void {
        const byte_count = @divExact(@typeInfo(Int).int.bits, 8);
        const start = try self.appendUninitialized(byte_count);
        std.mem.writeInt(Int, self.buffer.items[start..][0..byte_count], value, .little);
    }

    pub fn writeLengthEncodedInteger(self: *PayloadWriter, value: u64) !void {
        if (value <= 250) {
            try self.writeInt(u8, @intCast(value));
        } else if (value <= std.math.maxInt(u16)) {
            try self.writeInt(u8, 0xfc);
            try self.writeInt(u16, @intCast(value));
        } else if (value <= std.math.maxInt(u24)) {
            try self.writeInt(u8, 0xfd);
            try self.writeInt(u24, @intCast(value));
        } else {
            try self.writeInt(u8, 0xfe);
            try self.writeInt(u64, value);
        }
    }

    pub fn writeLengthEncodedString(self: *PayloadWriter, value: []const u8) !void {
        try self.writeLengthEncodedInteger(value.len);
        try self.writeBytes(value);
    }

    pub fn writeNullTerminatedString(self: *PayloadWriter, value: []const u8) !void {
        try self.writeBytes(value);
        try self.writeInt(u8, 0);
    }

    pub fn writeBytes(self: *PayloadWriter, value: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, value);
    }

    pub fn reserve(self: *PayloadWriter, len: usize) ![]u8 {
        const start = try self.appendUninitialized(len);
        return self.buffer.items[start .. start + len];
    }

    fn appendUninitialized(self: *PayloadWriter, len: usize) !usize {
        const start = self.buffer.items.len;
        _ = try self.buffer.addManyAsSlice(self.allocator, len);
        return start;
    }
};
