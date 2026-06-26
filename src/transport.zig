const std = @import("std");
const zio = @import("zio");

const mantle = @import("mantle.zig");
const protocol = mantle.protocol;

pub const AnyReader = struct {
    context: *anyopaque,
    readFn: *const fn (context: *anyopaque, dest: []u8) anyerror!usize,

    pub fn read(self: AnyReader, dest: []u8) !usize {
        return self.readFn(self.context, dest);
    }
};

pub const AnyWriter = struct {
    context: *anyopaque,
    writeAllFn: *const fn (context: *anyopaque, bytes: []const u8) anyerror!void,

    pub fn writeAll(self: AnyWriter, bytes: []const u8) !void {
        return self.writeAllFn(self.context, bytes);
    }
};

/// Structured summary of a server OK packet. Carries no owned memory.
pub const OkSummary = struct {
    affected_rows: u64,
    last_insert_id: u64,
    warnings: u16,
    status_flags: u16,
};

/// Structured server error (ERR packet). Owns `message`; call `deinit`.
pub const ServerError = struct {
    code: u16,
    sql_state: ?[5]u8,
    message: []const u8,

    pub fn deinit(self: *ServerError, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }

    pub fn clone(allocator: std.mem.Allocator, src: protocol.response.ErrorResponse) !ServerError {
        return .{
            .code = src.error_code,
            .sql_state = src.sql_state,
            .message = try allocator.dupe(u8, src.message),
        };
    }

    pub fn cloneFrom(allocator: std.mem.Allocator, src: ServerError) !ServerError {
        return .{
            .code = src.code,
            .sql_state = src.sql_state,
            .message = try allocator.dupe(u8, src.message),
        };
    }
};

/// Result of a command that does not stream rows. The `err` variant owns
/// memory and must be released with `deinit`.
pub const QueryResponse = union(enum) {
    ok: OkSummary,
    err: ServerError,
    result_set,

    pub fn deinit(self: *QueryResponse, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .err => |*err| err.deinit(allocator),
            else => {},
        }
    }

    /// Collapse to an `OkSummary`, mapping a server error or an unexpected
    /// result set to a Zig error. The owned error message (if any) still needs
    /// `deinit` by the caller via the original value.
    pub fn expectOk(self: QueryResponse) !OkSummary {
        return switch (self) {
            .ok => |ok| ok,
            .err => error.ServerError,
            .result_set => error.UnexpectedResultSet,
        };
    }
};

pub const PrepareResponse = union(enum) {
    ok: protocol.prepared_statement.PrepareOk,
    err: ServerError,

    pub fn deinit(self: *PrepareResponse, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .err => |*err| err.deinit(allocator),
            else => {},
        }
    }
};

pub const ResultRowTag = enum {
    row,
    eof,
    err,
};

pub const ResultRow = struct {
    tag: ResultRowTag,
    payload: []u8,
    values: []?[]const u8,
    owns_values: bool,
    server_error: ?ServerError = null,

    pub fn deinit(self: *ResultRow, allocator: std.mem.Allocator) void {
        if (self.server_error) |*err| err.deinit(allocator);
        if (self.owns_values) allocator.free(self.values);
        allocator.free(self.payload);
    }
};

pub const BinaryResultRow = struct {
    tag: ResultRowTag,
    payload: []u8,
    values: []?[]const u8,
    owns_values: bool,
    server_error: ?ServerError = null,

    pub fn deinit(self: *BinaryResultRow, allocator: std.mem.Allocator) void {
        if (self.server_error) |*err| err.deinit(allocator);
        if (self.owns_values) allocator.free(self.values);
        allocator.free(self.payload);
    }
};

pub const Transport = struct {
    io: Io,
    packet_stream: mantle.PacketStream,
    /// Server error from a failed handshake/auth exchange (e.g. "Access
    /// denied"), cloned before the source payload is freed. `finishHandshake`
    /// takes ownership via `takeHandshakeError`; null otherwise.
    handshake_error: ?ServerError = null,

    pub const Io = struct {
        reader: AnyReader,
        writer: AnyWriter,
    };

    pub fn init(io: Io, options: mantle.ConnectionPhase.Options) Transport {
        return .{
            .io = io,
            .packet_stream = mantle.PacketStream.init(options),
        };
    }

    /// Transfer ownership of a captured handshake error to the caller, which
    /// must `deinit` it. Clears the stored error.
    pub fn takeHandshakeError(self: *Transport) ?ServerError {
        defer self.handshake_error = null;
        return self.handshake_error;
    }

    pub fn receiveNext(self: *Transport, allocator: std.mem.Allocator) !mantle.ConnectionPhase.Action {
        const logical_payload = try readLogicalPayload(
            allocator,
            self.io.reader,
            self.packet_stream.next_sequence_id,
        );
        defer allocator.free(logical_payload.payload);
        self.packet_stream.next_sequence_id = logical_payload.next_sequence_id;

        // Captured before `receiveServerPayload` advances the state machine so
        // we know whether a failure came from the initial handshake (no
        // SQLSTATE) or the auth exchange (CLIENT_PROTOCOL_41 ERR with SQLSTATE).
        const prev_state = self.packet_stream.phase.state;

        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();

        const action = try self.packet_stream.receiveServerPayload(allocator, &framed_client, logical_payload.payload);
        if (framed_client.bytes().len > 0) {
            try self.io.writer.writeAll(framed_client.bytes());
        }

        if (self.packet_stream.phase.state == .failed and isErrorPayload(logical_payload.payload)) {
            self.captureHandshakeError(allocator, prev_state, logical_payload.payload);
        }
        return action;
    }

    /// Best-effort: clone the handshake/auth ERR so the caller can surface it.
    /// A parse or allocation failure leaves `handshake_error` null and the
    /// handshake still fails with the generic error, so it is never masked.
    fn captureHandshakeError(
        self: *Transport,
        allocator: std.mem.Allocator,
        prev_state: mantle.ConnectionPhase.State,
        payload: []const u8,
    ) void {
        const capabilities: u32 = switch (prev_state) {
            .awaiting_handshake => 0,
            else => protocol.capability.client_protocol_41,
        };
        const parsed = protocol.response.ErrorResponse.parse(payload, capabilities) catch return;
        const cloned = ServerError.clone(allocator, parsed) catch return;
        if (self.handshake_error) |*err| err.deinit(allocator);
        self.handshake_error = cloned;
    }

    pub fn sendCommand(
        self: *Transport,
        allocator: std.mem.Allocator,
        command: protocol.command.Command,
    ) !void {
        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();

        _ = try self.packet_stream.sendCommand(allocator, &framed_client, command);
        try self.io.writer.writeAll(framed_client.bytes());
    }

    pub fn sendCommandPayload(
        self: *Transport,
        allocator: std.mem.Allocator,
        command_payload: []const u8,
    ) !void {
        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();

        _ = try self.packet_stream.sendCommandPayload(allocator, &framed_client, command_payload);
        try self.io.writer.writeAll(framed_client.bytes());
    }

    pub fn sendNoResponseCommand(
        self: *Transport,
        allocator: std.mem.Allocator,
        command: protocol.command.Command,
    ) !void {
        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();

        _ = try self.packet_stream.sendNoResponseCommand(allocator, &framed_client, command);
        try self.io.writer.writeAll(framed_client.bytes());
    }

    pub fn readQueryResponse(self: *Transport, allocator: std.mem.Allocator) !QueryResponse {
        const payload = try self.readPayload(allocator);
        defer allocator.free(payload);

        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();
        const action = try self.packet_stream.receiveServerPayload(allocator, &framed_client, payload);
        return switch (action) {
            // A terminal command response (OK or ERR) is classified by the
            // packet payload, not connection state: a server ERR leaves the
            // connection reusable (back to `ready`), so state alone cannot
            // distinguish OK from ERR.
            .none => if (isErrorPayload(payload))
                .{ .err = try ServerError.clone(
                    allocator,
                    try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
                ) }
            else
                .{ .ok = try okSummaryFromPayload(payload) },
            .start_result_stream => .result_set,
            .local_infile_request => error.LocalInfileDisabled,
            else => error.InvalidConnectionPhaseState,
        };
    }

    pub fn readPrepareResponse(self: *Transport, allocator: std.mem.Allocator) !PrepareResponse {
        const payload = try self.readPayload(allocator);
        defer allocator.free(payload);

        // A PREPARE_OK packet is not a generic command response and must not be
        // routed through OK-packet parsing (its 0x00 lead byte is followed by
        // the statement id, not a length-encoded affected-rows count).
        try self.packet_stream.phase.receivePrepareResponse();

        // Classify by payload: a PREPARE_OK packet starts with 0x00, an ERR
        // packet with 0xff. Connection state is `ready` for both.
        if (isErrorPayload(payload)) return .{ .err = try ServerError.clone(
            allocator,
            try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
        ) };
        return .{ .ok = try protocol.prepared_statement.PrepareOk.parse(
            payload,
            protocol.capability.client_protocol_41,
        ) };
    }

    pub fn readTextRow(self: *Transport, allocator: std.mem.Allocator) !ResultRow {
        const payload = try self.readPayload(allocator);
        errdefer allocator.free(payload);

        const tag = try protocol.text_result.ResultPacketTag.classify(payload, self.packet_stream.result_column_count);
        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();
        _ = try self.packet_stream.receiveServerPayload(allocator, &framed_client, payload);
        return switch (tag) {
            .row => row: {
                const parsed = try protocol.text_result.TextRow.parse(allocator, payload, self.packet_stream.result_column_count);
                break :row .{
                    .tag = .row,
                    .payload = payload,
                    .values = parsed.values,
                    .owns_values = true,
                };
            },
            .eof => .{
                .tag = .eof,
                .payload = payload,
                .values = &.{},
                .owns_values = false,
            },
            .err => .{
                .tag = .err,
                .payload = payload,
                .values = &.{},
                .owns_values = false,
                .server_error = try ServerError.clone(
                    allocator,
                    try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
                ),
            },
        };
    }

    pub fn readBinaryRow(
        self: *Transport,
        allocator: std.mem.Allocator,
        columns: []const protocol.text_result.ColumnDefinition41,
    ) !BinaryResultRow {
        const payload = try self.readPayload(allocator);
        errdefer allocator.free(payload);

        if (payload.len == 0) return error.EndOfPayload;

        const tag: ResultRowTag = switch (payload[0]) {
            0xff => .err,
            0xfe => .eof,
            else => .row,
        };
        var framed_client = protocol.PayloadWriter.init(allocator);
        defer framed_client.deinit();
        _ = try self.packet_stream.receiveServerPayload(allocator, &framed_client, payload);
        return switch (tag) {
            .row => row: {
                const parsed = try protocol.binary_result.BinaryRow.parse(allocator, payload, columns);
                break :row .{
                    .tag = .row,
                    .payload = payload,
                    .values = parsed.values,
                    .owns_values = true,
                };
            },
            .eof => .{
                .tag = .eof,
                .payload = payload,
                .values = &.{},
                .owns_values = false,
            },
            .err => .{
                .tag = .err,
                .payload = payload,
                .values = &.{},
                .owns_values = false,
                .server_error = try ServerError.clone(
                    allocator,
                    try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
                ),
            },
        };
    }

    pub fn readTextResultMetadata(
        self: *Transport,
        allocator: std.mem.Allocator,
    ) ![]protocol.text_result.ColumnDefinition41 {
        const column_count = self.packet_stream.result_column_count;
        if (column_count == 0) return error.InvalidColumnCount;
        return self.readColumnDefinitions(allocator, column_count);
    }

    pub fn readColumnDefinitions(
        self: *Transport,
        allocator: std.mem.Allocator,
        column_count: usize,
    ) ![]protocol.text_result.ColumnDefinition41 {
        if (column_count == 0) return allocator.alloc(protocol.text_result.ColumnDefinition41, 0);

        const columns = try allocator.alloc(protocol.text_result.ColumnDefinition41, column_count);
        var initialized_columns: usize = 0;
        errdefer {
            for (columns[0..initialized_columns]) |*column| {
                column.deinit(allocator);
            }
            allocator.free(columns);
        }

        for (columns) |*column| {
            const payload = try self.readPayload(allocator);
            defer allocator.free(payload);
            const parsed = try protocol.text_result.ColumnDefinition41.parse(payload);
            column.* = try parsed.clone(allocator);
            initialized_columns += 1;
        }

        const eof_payload = try self.readPayload(allocator);
        defer allocator.free(eof_payload);
        if (try protocol.text_result.ResultPacketTag.classify(eof_payload, column_count) != .eof) {
            return error.MalformedResultSetPacket;
        }

        return columns;
    }

    fn readPayload(self: *Transport, allocator: std.mem.Allocator) ![]u8 {
        const logical_payload = try readLogicalPayload(
            allocator,
            self.io.reader,
            self.packet_stream.next_sequence_id,
        );
        self.packet_stream.next_sequence_id = logical_payload.next_sequence_id;
        return logical_payload.payload;
    }
};

fn isErrorPayload(payload: []const u8) bool {
    return payload.len > 0 and payload[0] == 0xff;
}

fn okSummaryFromPayload(payload: []const u8) !OkSummary {
    const ok = try protocol.response.OkResponse.parse(payload, protocol.capability.client_protocol_41);
    return .{
        .affected_rows = ok.affected_rows,
        .last_insert_id = ok.last_insert_id,
        .warnings = ok.warnings,
        .status_flags = ok.status_flags,
    };
}

pub const ZioStream = struct {
    stream: zio.net.Stream,
    timeout: zio.Timeout = .none,
    /// Inbound read buffer. MySQL replies arrive as a burst of small framed
    /// packets (a point SELECT is ~6 logical packets, each read as a 4-byte
    /// header then a small body). Without buffering each `readExact` is a raw
    /// `recv` syscall — ~12 per query — and under load most of them park the
    /// coroutine on the event loop, which dominates CPU as kernel time and caps
    /// throughput. One `recv` into this buffer absorbs the whole reply, so the
    /// per-packet reads become memcpys. Sized to the read class used elsewhere.
    read_buf: [read_buffer_size]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,

    /// 16 KiB matches talon's read-buffer class and comfortably holds a typical
    /// row-set reply in a single refill; larger replies just refill again.
    const read_buffer_size = 16 * 1024;

    pub fn init(stream: zio.net.Stream, timeout: zio.Timeout) ZioStream {
        return .{
            .stream = stream,
            .timeout = timeout,
        };
    }

    pub fn transport(self: *ZioStream, options: mantle.ConnectionPhase.Options) Transport {
        return Transport.init(.{
            .reader = self.reader(),
            .writer = self.writer(),
        }, options);
    }

    pub fn reader(self: *ZioStream) AnyReader {
        return .{
            .context = self,
            .readFn = read,
        };
    }

    pub fn writer(self: *ZioStream) AnyWriter {
        return .{
            .context = self,
            .writeAllFn = writeAll,
        };
    }

    fn read(context: *anyopaque, dest: []u8) anyerror!usize {
        const self: *ZioStream = @ptrCast(@alignCast(context));
        if (self.read_start == self.read_end) {
            // Buffer drained. For a request large enough to own the syscall,
            // read straight into it and skip the copy; otherwise refill once.
            if (dest.len >= self.read_buf.len) {
                return self.stream.read(dest, self.timeout);
            }
            const n = try self.stream.read(&self.read_buf, self.timeout);
            if (n == 0) return 0;
            self.read_start = 0;
            self.read_end = n;
        }
        const take = @min(self.read_end - self.read_start, dest.len);
        @memcpy(dest[0..take], self.read_buf[self.read_start..][0..take]);
        self.read_start += take;
        return take;
    }

    fn writeAll(context: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *ZioStream = @ptrCast(@alignCast(context));
        return self.stream.writeAll(bytes, self.timeout);
    }
};

fn readLogicalPayload(
    allocator: std.mem.Allocator,
    reader: AnyReader,
    first_sequence_id: u8,
) !LogicalPayload {
    var tracker = protocol.types.SequenceTracker.init(first_sequence_id);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        var header_bytes: [4]u8 = undefined;
        try readExact(reader, &header_bytes);
        const header = try protocol.types.PacketHeader.decode(&header_bytes);
        try tracker.expect(header.sequence_id);

        const old_len = out.items.len;
        try out.resize(allocator, old_len + header.payload_length);
        try readExact(reader, out.items[old_len..]);

        if (header.payload_length < protocol.types.max_packet_payload_size) {
            return .{
                .payload = try out.toOwnedSlice(allocator),
                .next_sequence_id = tracker.next,
            };
        }
    }
}

const LogicalPayload = struct {
    payload: []u8,
    next_sequence_id: u8,
};

fn readExact(reader: AnyReader, dest: []u8) !void {
    var offset: usize = 0;
    while (offset < dest.len) {
        const n = try reader.read(dest[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}
