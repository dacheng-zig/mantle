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

        if (client_payload.bytes().len > 0 or action == .send_handshake_response or action == .send_auth_response or action == .send_ssl_request) {
            try protocol.packet.writeLogicalPayload(framed_client, self.nextClientSequence(), client_payload.bytes());
        }
        return action;
    }

    /// Resume the handshake after a TLS upgrade: build the `HandshakeResponse41`
    /// the `SSLRequest` deferred and frame it at the next sequence id (the
    /// SSLRequest consumed the slot after the server handshake, so this lands at
    /// id 2). Returns `.send_handshake_response`.
    pub fn resumeAfterTlsUpgrade(
        self: *PacketStream,
        allocator: std.mem.Allocator,
        framed_client: *protocol.PayloadWriter,
    ) !mantle.ConnectionPhase.Action {
        var client_payload = protocol.PayloadWriter.init(allocator);
        defer client_payload.deinit();

        const action = try self.phase.resumeAfterTlsUpgrade(&client_payload);
        if (client_payload.bytes().len > 0) {
            try protocol.packet.writeLogicalPayload(framed_client, self.nextClientSequence(), client_payload.bytes());
        }
        return action;
    }

    /// Advance the state machine for a command-phase response (OK/ERR/result
    /// set/LOCAL INFILE) without a reply writer — these responses never produce
    /// a client packet. Mirrors the `command_inflight` arm of
    /// `receiveServerPayload`, including stashing the result-set column count.
    pub fn receiveCommandResponse(self: *PacketStream, payload: []const u8) !mantle.ConnectionPhase.Action {
        const action = try self.phase.receiveCommandResponse(payload);
        if (action == .start_result_stream) {
            self.result_column_count = @intCast(try protocol.text_result.ColumnCount.parse(payload));
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
        const header_index = framed_client.bytes().len;
        _ = try framed_client.reserve(4);
        const action = try self.phase.sendCommand(framed_client, command);
        try protocol.packet.finishInPlaceFrame(framed_client, allocator, header_index, 0);
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
        const header_index = framed_client.bytes().len;
        _ = try framed_client.reserve(4);
        const action = try self.phase.sendCommandPayload(framed_client, command_payload);
        try protocol.packet.finishInPlaceFrame(framed_client, allocator, header_index, 0);
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
        const header_index = framed_client.bytes().len;
        _ = try framed_client.reserve(4);
        const action = try self.phase.sendNoResponseCommand(framed_client, command);
        try protocol.packet.finishInPlaceFrame(framed_client, allocator, header_index, 0);
        self.next_sequence_id = 0;
        return action;
    }

    fn receiveResultStreamPacket(
        self: *PacketStream,
        payload: []const u8,
    ) !mantle.ConnectionPhase.Action {
        // The phase advances state and returns the row classification; a
        // result-stream packet never produces a client reply, so map it to
        // `.none` here.
        _ = switch (self.result_format) {
            .text => try self.phase.receiveTextResultStreamPacket(payload),
            .binary => try self.phase.receiveBinaryResultStreamPacket(payload),
        };
        return .none;
    }
};
