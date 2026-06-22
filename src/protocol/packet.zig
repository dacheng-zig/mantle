const std = @import("std");

const protocol = @import("protocol.zig");

pub fn writeLogicalPayload(writer: *protocol.PayloadWriter, first_sequence_id: u8, payload: []const u8) !void {
    var tracker = protocol.types.SequenceTracker.init(first_sequence_id);
    var offset: usize = 0;

    while (offset < payload.len) {
        const chunk_len = @min(protocol.types.max_packet_payload_size, payload.len - offset);
        try writeFrame(writer, tracker.take(), payload[offset..][0..chunk_len]);
        offset += chunk_len;
    }

    if (payload.len == 0 or payload.len % protocol.types.max_packet_payload_size == 0) {
        try writeFrame(writer, tracker.take(), "");
    }
}

pub const PacketBufferReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    next_sequence_id: u8 = 0,

    pub fn init(bytes: []const u8) PacketBufferReader {
        return .{ .bytes = bytes };
    }

    pub fn readLogicalPayload(
        self: *PacketBufferReader,
        allocator: std.mem.Allocator,
        first_sequence_id: u8,
    ) ![]u8 {
        var tracker = protocol.types.SequenceTracker.init(first_sequence_id);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        while (true) {
            const header = try self.readHeader();
            try tracker.expect(header.sequence_id);

            if (self.remaining() < header.payload_length) return error.EndOfPacketStream;
            try out.appendSlice(allocator, self.bytes[self.pos .. self.pos + header.payload_length]);
            self.pos += header.payload_length;

            if (header.payload_length < protocol.types.max_packet_payload_size) {
                self.next_sequence_id = tracker.next;
                return out.toOwnedSlice(allocator);
            }
        }
    }

    fn readHeader(self: *PacketBufferReader) protocol.types.Error!protocol.types.PacketHeader {
        if (self.remaining() < 4) return error.EndOfPacketStream;
        const header = try protocol.types.PacketHeader.decode(self.bytes[self.pos..][0..4]);
        self.pos += 4;
        return header;
    }

    fn remaining(self: PacketBufferReader) usize {
        return self.bytes.len - self.pos;
    }
};

fn writeFrame(writer: *protocol.PayloadWriter, sequence_id: u8, payload: []const u8) !void {
    if (payload.len > protocol.types.max_packet_payload_size) return error.PacketTooLarge;
    var header_bytes: [4]u8 = undefined;
    const header = protocol.types.PacketHeader{
        .payload_length = payload.len,
        .sequence_id = sequence_id,
    };
    try header.encode(&header_bytes);
    try writer.writeBytes(&header_bytes);
    try writer.writeBytes(payload);
}
