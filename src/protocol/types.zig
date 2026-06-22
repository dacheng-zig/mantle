//! Core packet-framing primitives shared across the protocol layer.
//!
//! Every (uncompressed) MySQL packet has a 4-byte header — a 3-byte
//! little-endian payload length followed by a 1-byte sequence id — and then
//! the payload. Payloads of `max_packet_payload_size` or longer are split
//! across multiple packets.
//!
//! Reference: MySQL Packets
//! <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html>

const std = @import("std");

/// Maximum payload carried by a single packet (`2^24 - 1`). A logical payload
/// of this size or larger is fragmented into multiple packets, terminated by a
/// packet shorter than this length (a zero-length packet when the total is an
/// exact multiple).
pub const max_packet_payload_size: usize = 0x00ff_ffff;

pub const Error = error{
    EndOfPayload,
    EndOfPacketStream,
    InvalidPacketSignature,
    InvalidLengthEncodedInteger,
    InvalidProtocolVersion,
    InvalidConnectionPhaseState,
    InvalidColumnCount,
    InvalidColumnDefinition,
    InvalidColumnType,
    InvalidSqlStateMarker,
    LengthOverflow,
    MalformedResultSetPacket,
    MissingNullTerminator,
    PacketTooLarge,
    SequenceMismatch,
    UnsupportedAuthPlugin,
    UnsupportedAuthExchange,
};

/// The 4-byte packet header: `int<3>` payload length + `int<1>` sequence id,
/// both excluding the header itself. The sequence id starts at 0 for each new
/// command and increments (wrapping) within one request/response exchange.
pub const PacketHeader = struct {
    payload_length: usize,
    sequence_id: u8,

    pub fn decode(bytes: []const u8) Error!PacketHeader {
        if (bytes.len < 4) return error.EndOfPacketStream;
        return .{
            .payload_length = std.mem.readInt(u24, bytes[0..3], .little),
            .sequence_id = bytes[3],
        };
    }

    pub fn encode(self: PacketHeader, dest: *[4]u8) Error!void {
        if (self.payload_length > max_packet_payload_size) return error.PacketTooLarge;
        std.mem.writeInt(u24, dest[0..3], @intCast(self.payload_length), .little);
        dest[3] = self.sequence_id;
    }
};

pub const SequenceTracker = struct {
    next: u8,

    pub fn init(first: u8) SequenceTracker {
        return .{ .next = first };
    }

    pub fn reset(self: *SequenceTracker) void {
        self.next = 0;
    }

    pub fn expect(self: *SequenceTracker, actual: u8) Error!void {
        if (actual != self.next) return error.SequenceMismatch;
        self.next +%= 1;
    }

    pub fn take(self: *SequenceTracker) u8 {
        const value = self.next;
        self.next +%= 1;
        return value;
    }
};
