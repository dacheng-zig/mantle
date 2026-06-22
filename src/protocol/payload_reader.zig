const std = @import("std");

const protocol = @import("protocol.zig");

pub const PayloadReader = struct {
    payload: []const u8,
    pos: usize = 0,

    pub fn init(payload: []const u8) PayloadReader {
        return .{ .payload = payload };
    }

    pub fn finished(self: PayloadReader) bool {
        return self.pos == self.payload.len;
    }

    pub fn remaining(self: PayloadReader) usize {
        return self.payload.len - self.pos;
    }

    pub fn peek(self: PayloadReader) protocol.types.Error!u8 {
        if (self.remaining() < 1) return error.EndOfPayload;
        return self.payload[self.pos];
    }

    pub fn readInt(self: *PayloadReader, comptime Int: type) protocol.types.Error!Int {
        const byte_count = @divExact(@typeInfo(Int).int.bits, 8);
        const bytes = try self.readBytes(byte_count);
        return std.mem.readInt(Int, bytes[0..byte_count], .little);
    }

    pub fn readLengthEncodedInteger(self: *PayloadReader) protocol.types.Error!u64 {
        const first = try self.readByte();
        return switch (first) {
            0x00...0xfa => first,
            0xfb, 0xff => error.InvalidLengthEncodedInteger,
            0xfc => try self.readInt(u16),
            0xfd => try self.readInt(u24),
            0xfe => try self.readInt(u64),
        };
    }

    pub fn readLengthEncodedString(self: *PayloadReader) protocol.types.Error![]const u8 {
        const len = try self.readLengthEncodedInteger();
        if (len > std.math.maxInt(usize)) return error.LengthOverflow;
        return self.readBytes(@intCast(len));
    }

    pub fn readNullTerminatedString(self: *PayloadReader) protocol.types.Error![]const u8 {
        const end = std.mem.indexOfScalarPos(u8, self.payload, self.pos, 0) orelse
            return error.MissingNullTerminator;
        const bytes = self.payload[self.pos..end];
        self.pos = end + 1;
        return bytes;
    }

    pub fn readRemaining(self: *PayloadReader) []const u8 {
        const bytes = self.payload[self.pos..];
        self.pos = self.payload.len;
        return bytes;
    }

    pub fn readFixedBytes(self: *PayloadReader, comptime len: usize) protocol.types.Error!*const [len]u8 {
        const bytes = try self.readBytes(len);
        return bytes[0..len];
    }

    pub fn readBytesAtMostUntilNul(self: *PayloadReader, max_len: usize) protocol.types.Error![]const u8 {
        const len = @min(max_len, self.remaining());
        const bytes = self.payload[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }

    fn readByte(self: *PayloadReader) protocol.types.Error!u8 {
        if (self.remaining() < 1) return error.EndOfPayload;
        const byte = self.payload[self.pos];
        self.pos += 1;
        return byte;
    }

    pub fn readBytes(self: *PayloadReader, len: usize) protocol.types.Error![]const u8 {
        if (self.remaining() < len) return error.EndOfPayload;
        const bytes = self.payload[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }
};
