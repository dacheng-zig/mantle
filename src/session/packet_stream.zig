const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;

pub const PacketStream = struct {
    phase: mantle.ConnectionPhase,
    /// Next sequence id in the current exchange's shared counter: both the id
    /// expected on the next inbound server packet and the id assigned to the
    /// next outbound client packet (MySQL uses one counter per exchange).
    next_sequence_id: u8,
    result_column_count: usize,
    result_format: ResultFormat,

    pub const ResultFormat = enum {
        text,
        binary,
    };

    pub fn init(options: mantle.ConnectionPhase.Options) PacketStream {
        return .{
            .phase = mantle.ConnectionPhase.init(options),
            .next_sequence_id = 0,
            .result_column_count = 0,
            .result_format = .text,
        };
    }

    pub fn receiveServerPackets(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
        framed_server: []const u8,
    ) !mantle.ConnectionPhase.Action {
        var reader = protocol.packet.PacketBufferReader.init(framed_server);
        const payload = try reader.readLogicalPayload(allocator, self.next_sequence_id);
        defer allocator.free(payload);
        self.next_sequence_id = reader.next_sequence_id;

        return self.receiveServerPayload(allocator, framed_client, payload);
    }

    pub fn receiveServerPayload(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
        payload: []const u8,
    ) !mantle.ConnectionPhase.Action {
        var client_payload = protocol.PayloadWriter.init(allocator);
        defer client_payload.deinit();

        const action = switch (self.phase.state) {
            .awaiting_handshake => try self.phase.receiveInitialHandshake(&client_payload, payload),
            .authenticating => try self.phase.receiveAuthPacket(&client_payload, payload),
            .command_inflight => action: {
                const action = try self.phase.receiveCommandResponse(payload);
                if (action == .start_result_stream) {
                    self.result_column_count = @intCast(try protocol.text_result.ColumnCount.parse(payload));
                }
                break :action action;
            },
            .result_streaming => try self.receiveResultStreamPacket(payload),
            else => return error.InvalidConnectionPhaseState,
        };

        if (client_payload.bytes().len > 0 or action == .send_handshake_response or action == .send_auth_response) {
            try protocol.packet.writeLogicalPayload(framed_client, self.nextClientSequence(), client_payload.bytes());
        }
        return action;
    }

    fn nextClientSequence(self: *PacketStream) u8 {
        const seq = self.next_sequence_id;
        self.next_sequence_id +%= 1;
        return seq;
    }

    pub fn sendCommand(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
        command: protocol.command.Command,
    ) !mantle.ConnectionPhase.Action {
        var payload = protocol.PayloadWriter.init(allocator);
        defer payload.deinit();

        const action = try self.phase.sendCommand(&payload, command);
        try protocol.packet.writeLogicalPayload(framed_client, 0, payload.bytes());
        self.next_sequence_id = 1;
        self.result_format = .text;
        return action;
    }

    pub fn sendCommandPayload(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
        command_payload: []const u8,
    ) !mantle.ConnectionPhase.Action {
        var payload = protocol.PayloadWriter.init(allocator);
        defer payload.deinit();

        const action = try self.phase.sendCommandPayload(&payload, command_payload);
        try protocol.packet.writeLogicalPayload(framed_client, 0, payload.bytes());
        self.next_sequence_id = 1;
        self.result_format = .binary;
        return action;
    }

    pub fn sendNoResponseCommand(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
        command: protocol.command.Command,
    ) !mantle.ConnectionPhase.Action {
        var payload = protocol.PayloadWriter.init(allocator);
        defer payload.deinit();

        const action = try self.phase.sendNoResponseCommand(&payload, command);
        try protocol.packet.writeLogicalPayload(framed_client, 0, payload.bytes());
        self.next_sequence_id = 0;
        return action;
    }

    fn receiveResultStreamPacket(
        self: *PacketStream,
        payload: []const u8,
    ) !mantle.ConnectionPhase.Action {
        return switch (self.result_format) {
            .text => try self.phase.receiveTextResultStreamPacket(payload, self.result_column_count),
            .binary => try self.phase.receiveBinaryResultStreamPacket(payload),
        };
    }
};
