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

/// Hook the transport invokes to upgrade the underlying byte stream to TLS,
/// after the `SSLRequest` has been written. The context is the stream
/// implementation (e.g. a `*ZioStream`); the upgrade is done in place so the
/// `AnyReader`/`AnyWriter` keep pointing at the same context — only their
/// behaviour switches to encrypted I/O. Absent (`null`) on plaintext transports.
pub const TlsUpgrade = struct {
    context: *anyopaque,
    upgradeFn: *const fn (context: *anyopaque, allocator: std.mem.Allocator) anyerror!void,

    pub fn perform(self: TlsUpgrade, allocator: std.mem.Allocator) !void {
        return self.upgradeFn(self.context, allocator);
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

/// The text and binary protocols decode rows into identical owned shapes (an
/// owned payload, value slices aliasing it, an optional owned server error), so
/// the binary row type is an alias rather than a duplicate struct. `row.zig`
/// keeps the per-protocol name for readability via the `proto` switch.
pub const BinaryResultRow = ResultRow;

/// Reusable scratch for collecting a whole result set without per-row
/// allocation: one growable payload buffer and one value-slice buffer, both
/// reused across rows via `readTextRowReusing` / `readBinaryRowReusing`. After
/// the first row the buffers stay sized, so subsequent rows allocate nothing.
/// Used by the owned collectors (`Connection.queryAll`/`queryAllParams`), which
/// copy each row into an arena before reading the next.
pub const RowScratch = struct {
    payload: std.ArrayList(u8) = .empty,
    values: std.ArrayList(?[]const u8) = .empty,

    pub fn deinit(self: *RowScratch, allocator: std.mem.Allocator) void {
        self.payload.deinit(allocator);
        self.values.deinit(allocator);
    }
};

/// A result row read into a `RowScratch`. For a `.row`, `values` alias the
/// scratch payload and are valid only until the next read into the same
/// scratch — scan them into owned storage first. The `.err` variant owns
/// `server_error`; the caller must capture or deinit it.
pub const RowView = struct {
    tag: ResultRowTag,
    values: []?[]const u8,
    server_error: ?ServerError = null,
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
        /// Optional TLS upgrade hook. Set on transports that can switch to TLS
        /// mid-handshake (see `ZioStream.upgradeHook`); null on plaintext-only
        /// transports. `receiveNext` invokes it when the phase emits an
        /// `SSLRequest`.
        upgrade: ?TlsUpgrade = null,
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

        // The SSLRequest has now reached the wire; upgrade the socket to TLS and
        // send the HandshakeResponse41 over the encrypted channel. Driving both
        // here (rather than returning to the caller) keeps the upgrade invisible
        // to `finishHandshake`, which only ever sees the resulting
        // `send_handshake_response` and an `authenticating` phase.
        if (action == .send_ssl_request) {
            const upgrade = self.io.upgrade orelse return error.TlsNotConfigured;
            try upgrade.perform(allocator);

            var framed_response = protocol.PayloadWriter.init(allocator);
            defer framed_response.deinit();
            const resumed = try self.packet_stream.resumeAfterTlsUpgrade(allocator, &framed_response);
            if (framed_response.bytes().len > 0) {
                try self.io.writer.writeAll(framed_response.bytes());
            }
            return resumed;
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

        // A command response never produces a client reply, so advance the state
        // machine directly instead of `receiveServerPayload` (which would build
        // an always-empty reply writer).
        const action = try self.packet_stream.receiveCommandResponse(payload);
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
                // The phase already parsed this OK packet to transition state;
                // reuse its captured summary instead of decoding it again.
                .{ .ok = okSummaryFromPhase(self.packet_stream.phase.command_ok) },
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

        // Advance the result-streaming state machine and reuse its row
        // classification. Driving the phase directly (instead of
        // `receiveServerPayload`) avoids an always-empty reply writer, and
        // reusing the returned tag avoids a second `classify` of the payload.
        const tag = try self.packet_stream.phase.receiveTextResultStreamPacket(payload);
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
    ) !ResultRow {
        const payload = try self.readPayload(allocator);
        errdefer allocator.free(payload);

        // Advance the state machine and reuse its row classification (see
        // `readTextRow`): binary rows never produce a client response.
        const tag = try self.packet_stream.phase.receiveBinaryResultStreamPacket(payload);
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

    /// Read one text result row into `scratch`, reusing its buffers instead of
    /// allocating a fresh payload and values slice per row. The returned `.row`
    /// values alias `scratch` and are valid only until the next read into it;
    /// the caller (an owned collector) copies them out before continuing. Mirror
    /// of `readTextRow` for the bulk-collection path.
    pub fn readTextRowReusing(self: *Transport, allocator: std.mem.Allocator, scratch: *RowScratch) !RowView {
        const payload = try self.readPayloadInto(allocator, &scratch.payload);
        const tag = try self.packet_stream.phase.receiveTextResultStreamPacket(payload);
        switch (tag) {
            .row => {
                const column_count = self.packet_stream.result_column_count;
                try scratch.values.resize(allocator, column_count);
                try protocol.text_result.TextRow.fillValues(payload, scratch.values.items);
                return .{ .tag = .row, .values = scratch.values.items };
            },
            .eof => return .{ .tag = .eof, .values = &.{} },
            .err => return .{
                .tag = .err,
                .values = &.{},
                .server_error = try ServerError.clone(
                    allocator,
                    try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
                ),
            },
        }
    }

    /// Binary counterpart of `readTextRowReusing`.
    pub fn readBinaryRowReusing(
        self: *Transport,
        allocator: std.mem.Allocator,
        columns: []const protocol.text_result.ColumnDefinition41,
        scratch: *RowScratch,
    ) !RowView {
        const payload = try self.readPayloadInto(allocator, &scratch.payload);
        const tag = try self.packet_stream.phase.receiveBinaryResultStreamPacket(payload);
        switch (tag) {
            .row => {
                try scratch.values.resize(allocator, columns.len);
                try protocol.binary_result.BinaryRow.fillValues(payload, columns, scratch.values.items);
                return .{ .tag = .row, .values = scratch.values.items };
            },
            .eof => return .{ .tag = .eof, .values = &.{} },
            .err => return .{
                .tag = .err,
                .values = &.{},
                .server_error = try ServerError.clone(
                    allocator,
                    try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41),
                ),
            },
        }
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
        if (try protocol.text_result.ResultPacketTag.classify(eof_payload) != .eof) {
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

    /// Read one logical payload into `buf`, reusing its capacity instead of
    /// allocating a fresh slice (see `RowScratch`). Returns the borrowed bytes
    /// (`buf.items`), valid until the next read into `buf`.
    fn readPayloadInto(self: *Transport, allocator: std.mem.Allocator, buf: *std.ArrayList(u8)) ![]const u8 {
        buf.clearRetainingCapacity();
        self.packet_stream.next_sequence_id = try readLogicalPayloadInto(
            self.io.reader,
            self.packet_stream.next_sequence_id,
            allocator,
            buf,
        );
        return buf.items;
    }
};

fn isErrorPayload(payload: []const u8) bool {
    return payload.len > 0 and payload[0] == 0xff;
}

fn okSummaryFromPhase(ok: mantle.ConnectionPhase.CommandOk) OkSummary {
    return .{
        .affected_rows = ok.affected_rows,
        .last_insert_id = ok.last_insert_id,
        .warnings = ok.warnings,
        .status_flags = ok.status_flags,
    };
}

// Vendored std TLS client, forked to answer MySQL's `CertificateRequest` with
// an empty client certificate (std's own client cannot, so it can't handshake
// any TLS-enabled MySQL). Same API surface as `std.crypto.tls.Client`.
const TlsClient = @import("crypto/tls_client.zig");
/// The std TLS client asserts its encrypted-side reader holds at least one
/// max-size ciphertext record. Every record buffer is sized to it for safety.
const tls_record_buf_len = TlsClient.min_buffer_len;

pub const ZioStream = struct {
    stream: zio.net.Stream,
    timeout: zio.Timeout = .none,
    /// TLS handshake parameters, set via `initTls`. When present, `upgradeTls`
    /// (driven by the MySQL `SSLRequest`) can promote this stream to TLS. Null
    /// on a plaintext-only stream.
    tls_opts: ?TlsOptions = null,
    /// The live TLS session, heap-pinned so the std TLS client's
    /// `@fieldParentPtr`-recovered reader/writer and its buffer pointers stay
    /// valid. Null until `upgradeTls` runs.
    tls_state: ?*TlsState = null,
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

    /// Parameters for a deferred TLS upgrade. `io` drives the handshake's
    /// entropy, wall clock, and CA bundle reads; `host` is the SNI / verified
    /// host name; `verification` selects the trust policy.
    pub const TlsOptions = struct {
        io: std.Io,
        host: []const u8,
        verification: mantle.tls.Verification,
    };

    pub fn init(stream: zio.net.Stream, timeout: zio.Timeout) ZioStream {
        return .{
            .stream = stream,
            .timeout = timeout,
        };
    }

    /// Like `init`, but arms the stream for a MySQL `CLIENT_SSL` upgrade. The
    /// stream starts plaintext (the initial handshake is unencrypted); once the
    /// phase emits an `SSLRequest`, `upgradeTls` promotes it to TLS in place.
    pub fn initTls(stream: zio.net.Stream, timeout: zio.Timeout, tls_opts: TlsOptions) ZioStream {
        return .{
            .stream = stream,
            .timeout = timeout,
            .tls_opts = tls_opts,
        };
    }

    pub fn transport(self: *ZioStream, options: mantle.ConnectionPhase.Options) Transport {
        return Transport.init(.{
            .reader = self.reader(),
            .writer = self.writer(),
            .upgrade = self.upgradeHook(),
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

    /// The TLS upgrade hook for the transport, or null when this stream was not
    /// armed for TLS (`init` rather than `initTls`). The hook captures the
    /// pinned `*ZioStream`, so callers must build it from the final address.
    pub fn upgradeHook(self: *ZioStream) ?TlsUpgrade {
        if (self.tls_opts == null) return null;
        return .{ .context = self, .upgradeFn = upgradeThunk };
    }

    fn read(context: *anyopaque, dest: []u8) anyerror!usize {
        const self: *ZioStream = @ptrCast(@alignCast(context));
        if (self.tls_state) |state| {
            // Decrypted-side read: fills `dest` from the TLS reader, returning a
            // short count (0 at end of stream) — matching `readExact`'s contract.
            return state.tls.reader.readSliceShort(dest);
        }
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
        if (self.tls_state) |state| {
            // Plaintext in → encrypt → push to socket. The std TLS writer's own
            // flush only encrypts into the encrypted-side writer's buffer; that
            // buffer must then be flushed to the wire, or the bytes never leave
            // this process. MySQL is request/response with no separate flush, so
            // every framed write must reach the wire here.
            try state.tls.writer.writeAll(bytes);
            try state.tls.writer.flush();
            try state.tcp_writer.interface.flush();
            return;
        }
        return self.stream.writeAll(bytes, self.timeout);
    }

    /// Per-connection TLS session, heap-pinned: the std TLS client recovers
    /// itself from its reader/writer via `@fieldParentPtr`, and the
    /// encrypted-side zio reader/writer hold pointers into the record buffers
    /// below, so none of this may move after `upgradeTls`.
    const TlsState = struct {
        allocator: std.mem.Allocator,
        /// Encrypted-side zio reader/writer: the TLS record transport over the
        /// socket.
        tcp_reader: zio.net.Stream.Reader,
        tcp_writer: zio.net.Stream.Writer,
        tls: TlsClient,
        // Record buffers (one max ciphertext record each):
        //   enc_read    — ciphertext pulled from the socket
        //   enc_write   — ciphertext pushed to the socket
        //   dec_read    — decrypted plaintext the driver reads
        //   clear_write — plaintext the driver writes before encryption
        enc_read_buf: [tls_record_buf_len]u8 = undefined,
        enc_write_buf: [tls_record_buf_len]u8 = undefined,
        dec_read_buf: [tls_record_buf_len]u8 = undefined,
        clear_write_buf: [tls_record_buf_len]u8 = undefined,
    };

    fn upgradeThunk(context: *anyopaque, allocator: std.mem.Allocator) anyerror!void {
        const self: *ZioStream = @ptrCast(@alignCast(context));
        return self.upgradeTls(allocator);
    }

    /// Promote the plaintext socket to TLS in place: build the encrypted-side
    /// reader/writer, run the std TLS handshake (its socket I/O rides the zio
    /// coroutine), and switch `read`/`writeAll` to the encrypted path. Called
    /// once, right after the `SSLRequest` reaches the wire.
    fn upgradeTls(self: *ZioStream, allocator: std.mem.Allocator) !void {
        const opts = self.tls_opts orelse return error.TlsNotConfigured;
        // The MySQL handshake is lock-step: the server sends only its initial
        // handshake, then waits for the SSLRequest before any TLS bytes. So the
        // plaintext read buffer must be fully drained here; leftover bytes would
        // be plaintext the TLS layer can never see (a desync), so refuse.
        if (self.read_start != self.read_end) return error.TlsUpgradeBufferedData;

        const state = try allocator.create(TlsState);
        errdefer allocator.destroy(state);
        state.* = .{
            .allocator = allocator,
            .tcp_reader = undefined,
            .tcp_writer = undefined,
            .tls = undefined,
        };
        // Wire the encrypted-side reader/writer at their final pinned addresses.
        state.tcp_reader = self.stream.reader(&state.enc_read_buf);
        state.tcp_writer = self.stream.writer(&state.enc_write_buf);
        // Bound the handshake's socket I/O by the per-connection timeout.
        state.tcp_reader.setTimeout(self.timeout);
        state.tcp_writer.setTimeout(self.timeout);

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        try std.Io.randomSecure(opts.io, &entropy);

        const host: @FieldType(TlsClient.Options, "host") = switch (opts.verification) {
            .insecure_no_verification => .no_verification,
            .system, .self_signed => .{ .explicit = opts.host },
        };
        const ca: @FieldType(TlsClient.Options, "ca") = switch (opts.verification) {
            .insecure_no_verification => .no_verification,
            .self_signed => .self_signed,
            .system => |store| .{ .bundle = .{
                .gpa = allocator,
                .io = opts.io,
                .lock = &store.lock,
                .bundle = &store.bundle,
            } },
        };

        state.tls = try TlsClient.init(&state.tcp_reader.interface, &state.tcp_writer.interface, .{
            .host = host,
            .ca = ca,
            .read_buffer = &state.dec_read_buf,
            .write_buffer = &state.clear_write_buf,
            .entropy = &entropy,
            .realtime_now = std.Io.Timestamp.now(opts.io, .real),
            // MySQL frames every packet by length, so a truncated stream is
            // detected by the protocol layer. Many servers close without a TLS
            // close_notify, so forward a bare EOF as end-of-stream rather than
            // erroring (matching how mainstream MySQL clients behave over TLS).
            .allow_truncation_attacks = true,
        });
        self.tls_state = state;
    }

    /// Close the stream: send a best-effort TLS close_notify (if upgraded),
    /// close the socket, and free the pinned TLS state. Use instead of touching
    /// `stream.close()` directly so a TLS session is torn down cleanly.
    pub fn close(self: *ZioStream) void {
        if (self.tls_state) |state| {
            state.tls.end() catch {};
            state.tcp_writer.interface.flush() catch {};
            self.stream.close();
            state.allocator.destroy(state);
            self.tls_state = null;
            return;
        }
        self.stream.close();
    }
};

fn readLogicalPayload(
    allocator: std.mem.Allocator,
    reader: AnyReader,
    first_sequence_id: u8,
) !LogicalPayload {
    var tracker = protocol.types.SequenceTracker.init(first_sequence_id);

    var header_bytes: [4]u8 = undefined;
    try readExact(reader, &header_bytes);
    var header = try protocol.types.PacketHeader.decode(&header_bytes);
    try tracker.expect(header.sequence_id);

    if (header.payload_length < protocol.types.max_packet_payload_size) {
        // Single-packet logical payload — the overwhelmingly common case. The
        // header gives the exact size, so allocate it once and read straight in,
        // skipping the ArrayList growth + shrink-to-fit on the hot path.
        const payload = try allocator.alloc(u8, header.payload_length);
        errdefer allocator.free(payload);
        try readExact(reader, payload);
        return .{ .payload = payload, .next_sequence_id = tracker.next };
    }

    // Payload >= 16 MiB: fragmented across packets, terminated by one shorter
    // than the threshold. Accumulate into a growable buffer.
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (true) {
        const old_len = out.items.len;
        try out.resize(allocator, old_len + header.payload_length);
        try readExact(reader, out.items[old_len..]);

        if (header.payload_length < protocol.types.max_packet_payload_size) {
            return .{
                .payload = try out.toOwnedSlice(allocator),
                .next_sequence_id = tracker.next,
            };
        }

        try readExact(reader, &header_bytes);
        header = try protocol.types.PacketHeader.decode(&header_bytes);
        try tracker.expect(header.sequence_id);
    }
}

const LogicalPayload = struct {
    payload: []u8,
    next_sequence_id: u8,
};

/// Read one logical payload (possibly fragmented across packets) by appending
/// into the caller-provided `out`, which it pre-clears via the caller and reuses
/// across rows. Returns the next sequence id. Unlike `readLogicalPayload` it
/// does not own/return a fresh slice — the reused buffer is the win on the
/// result-set hot path (`RowScratch`).
fn readLogicalPayloadInto(
    reader: AnyReader,
    first_sequence_id: u8,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
) !u8 {
    var tracker = protocol.types.SequenceTracker.init(first_sequence_id);
    while (true) {
        var header_bytes: [4]u8 = undefined;
        try readExact(reader, &header_bytes);
        const header = try protocol.types.PacketHeader.decode(&header_bytes);
        try tracker.expect(header.sequence_id);

        const old_len = out.items.len;
        try out.resize(allocator, old_len + header.payload_length);
        try readExact(reader, out.items[old_len..]);

        if (header.payload_length < protocol.types.max_packet_payload_size) return tracker.next;
    }
}

fn readExact(reader: AnyReader, dest: []u8) !void {
    var offset: usize = 0;
    while (offset < dest.len) {
        const n = try reader.read(dest[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}
