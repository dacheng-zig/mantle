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

/// Backfill the 4-byte packet header reserved at `header_index` after the
/// command body was written directly into `writer` right after it. This frames
/// the command in place — no separate scratch buffer that then gets copied —
/// halving the write-side memcpy/allocation for the request payload.
///
/// The single-packet case (a body shorter than one packet, i.e. the near
/// universal case for commands) just patches the length and sequence id. A body
/// that fills or exceeds one packet is rare (a >16 MiB statement or parameter
/// set); it is re-fragmented via the general multi-packet path, paying one copy
/// for that uncommon case only. Produces byte-identical output to framing
/// through `writeLogicalPayload`.
pub fn finishInPlaceFrame(
    writer: *protocol.PayloadWriter,
    allocator: std.mem.Allocator,
    header_index: usize,
    first_sequence_id: u8,
) !void {
    const body_len = writer.bytes().len - header_index - 4;
    if (body_len < protocol.types.max_packet_payload_size) {
        var header_bytes: [4]u8 = undefined;
        const header = protocol.types.PacketHeader{
            .payload_length = body_len,
            .sequence_id = first_sequence_id,
        };
        try header.encode(&header_bytes);
        @memcpy(writer.buffer.items[header_index..][0..4], &header_bytes);
        return;
    }

    // Rare: the body fills or overflows one packet, so it must be split across
    // multiple framed packets (and an exact multiple needs a trailing empty
    // one). Copy the body out, rewind to the reserved header, and re-frame.
    const body = try allocator.dupe(u8, writer.bytes()[header_index + 4 ..]);
    defer allocator.free(body);
    writer.buffer.shrinkRetainingCapacity(header_index);
    try writeLogicalPayload(writer, first_sequence_id, body);
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

        var header = try self.readHeader();
        try tracker.expect(header.sequence_id);

        if (header.payload_length < protocol.types.max_packet_payload_size) {
            // Single-packet logical payload (common case): copy the exact bytes
            // out once, skipping the ArrayList growth + shrink-to-fit.
            if (self.remaining() < header.payload_length) return error.EndOfPacketStream;
            const payload = try allocator.dupe(u8, self.bytes[self.pos .. self.pos + header.payload_length]);
            self.pos += header.payload_length;
            self.next_sequence_id = tracker.next;
            return payload;
        }

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        while (true) {
            if (self.remaining() < header.payload_length) return error.EndOfPacketStream;
            try out.appendSlice(allocator, self.bytes[self.pos .. self.pos + header.payload_length]);
            self.pos += header.payload_length;

            if (header.payload_length < protocol.types.max_packet_payload_size) {
                self.next_sequence_id = tracker.next;
                return out.toOwnedSlice(allocator);
            }

            header = try self.readHeader();
            try tracker.expect(header.sequence_id);
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
