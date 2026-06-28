const std = @import("std");

const mantle = @import("../mantle.zig");
const protocol = mantle.protocol;

pub const ConnectionPhase = struct {
    pub const State = enum {
        awaiting_handshake,
        /// `SSLRequest` has been emitted; the transport must upgrade the socket
        /// to TLS and then resume with the `HandshakeResponse41`. Transient:
        /// `receiveNext` drives the upgrade and `resumeAfterTlsUpgrade` within a
        /// single call, so this state is never observed between reads.
        awaiting_tls,
        authenticating,
        ready,
        command_inflight,
        result_streaming,
        failed,
    };

    pub const Action = enum {
        none,
        /// Emit the buffered `SSLRequest`, then upgrade the transport to TLS and
        /// continue the handshake over the encrypted channel.
        send_ssl_request,
        send_handshake_response,
        send_auth_response,
        send_command,
        start_result_stream,
        local_infile_request,
    };

    /// Progress within the `authenticating` state. caching_sha2_password may
    /// fall back to full authentication (RSA public-key exchange) when the
    /// server's fast-auth cache check misses — which happens on a wrong password
    /// or a cold cache. See `receiveAuthPacket`.
    pub const AuthStep = enum {
        /// Initial scramble (or post-switch scramble) has been sent.
        scramble_sent,
        /// A public-key request has been sent; the next packet is the RSA key.
        public_key_requested,
        /// The RSA-encrypted password has been sent; awaiting OK/ERR.
        encrypted_password_sent,
    };

    pub const Options = struct {
        username: []const u8,
        password: []const u8,
        database: ?[]const u8 = null,
        character_set: u8 = protocol.collation.utf8mb4_general_ci,
        max_packet_size: u32 = 0,
        /// TLS upgrade policy. `.disabled` (default) keeps the connection
        /// plaintext; `.prefer`/`.require` send an `SSLRequest` when the server
        /// advertises `CLIENT_SSL`. The transport must be configured with the
        /// matching TLS parameters (see `transport.ZioStream.initTls`).
        tls: mantle.tls.Mode = .disabled,
    };

    state: State,
    options: Options,
    /// The server's connection/thread id from the initial handshake. Needed to
    /// target this session with `KILL QUERY` from another connection.
    /// Zero until the handshake is received.
    server_connection_id: u32 = 0,
    /// Auth plugin negotiated in the handshake (or switched to). Drives the
    /// full-authentication exchange.
    auth_plugin: protocol.auth.AuthPlugin = .unknown,
    /// Sub-state within `authenticating`.
    auth_step: AuthStep = .scramble_sent,
    /// The current auth seed (handshake nonce, or the switch request's data).
    /// Needed to obfuscate the password during RSA full authentication.
    auth_seed_storage: [32]u8 = @splat(0),
    auth_seed_len: usize = 0,
    /// Negotiated client flags stashed when an `SSLRequest` is sent, so the
    /// deferred `HandshakeResponse41` (built after the TLS upgrade) reuses the
    /// exact capability set advertised in the `SSLRequest`.
    pending_client_flags: u32 = 0,
    /// Database to send in the deferred `HandshakeResponse41` (caller-owned,
    /// stable for the connection's lifetime). Null unless `CLIENT_CONNECT_WITH_DB`
    /// was negotiated.
    pending_database: ?[]const u8 = null,
    /// Scalar summary of the most recent command-terminating OK/EOF packet,
    /// captured when the state transition parses it. The transport reads this to
    /// build its `OkSummary` instead of parsing the same packet a second time.
    /// Only valid immediately after a terminal OK response.
    command_ok: CommandOk = .{},

    /// Borrow-free OK summary stashed by `transitionAfterCommandTerminator`.
    pub const CommandOk = struct {
        affected_rows: u64 = 0,
        last_insert_id: u64 = 0,
        warnings: u16 = 0,
        status_flags: u16 = 0,
    };

    pub fn init(options: Options) ConnectionPhase {
        return .{
            .state = .awaiting_handshake,
            .options = options,
        };
    }

    fn setAuthSeed(self: *ConnectionPhase, seed: []const u8) void {
        const len = @min(seed.len, self.auth_seed_storage.len);
        @memcpy(self.auth_seed_storage[0..len], seed[0..len]);
        self.auth_seed_len = len;
    }

    fn authSeed(self: *const ConnectionPhase) []const u8 {
        return self.auth_seed_storage[0..self.auth_seed_len];
    }

    pub fn receiveInitialHandshake(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        payload: []const u8,
    ) !Action {
        if (self.state != .awaiting_handshake) return error.InvalidConnectionPhaseState;
        if (payload.len > 0 and payload[0] == 0xff) {
            _ = try protocol.response.ErrorResponse.parseFirst(payload);
            self.state = .failed;
            return .none;
        }

        const handshake = try protocol.handshake.HandshakeV10.parse(payload);
        self.server_connection_id = handshake.connection_id;

        const request_tls = self.options.tls != .disabled;
        const server_supports_ssl =
            (handshake.capability_flags & protocol.capability.client_ssl) != 0;
        if (self.options.tls == .require and !server_supports_ssl) {
            self.state = .failed;
            return error.TlsNotSupportedByServer;
        }

        const negotiation = protocol.handshake.negotiateClientFlags(.{
            .database = self.options.database,
            .request_tls = request_tls,
        }, handshake);
        const auth_plugin = protocol.auth.AuthPlugin.fromName(negotiation.auth_plugin_name);
        self.auth_plugin = auth_plugin;
        // The scramble lives in the handshake payload, which is freed after this
        // call returns; copy it now so the deferred (post-TLS) response can
        // still build the auth token.
        self.setAuthSeed(handshake.authPluginData());
        self.auth_step = .scramble_sent;

        if (negotiation.use_ssl) {
            // Emit only the SSLRequest (capability flags + max packet + charset).
            // The transport upgrades to TLS, then `resumeAfterTlsUpgrade` sends
            // the full HandshakeResponse41 over the encrypted channel.
            try protocol.handshake.SSLRequest.write(writer, .{
                .client_flags = negotiation.client_flags,
                .max_packet_size = self.options.max_packet_size,
                .character_set = self.options.character_set,
            });
            self.pending_client_flags = negotiation.client_flags;
            self.pending_database = negotiation.database;
            self.state = .awaiting_tls;
            return .send_ssl_request;
        }

        var auth_response_storage: [32]u8 = undefined;
        const auth_response = try makeAuthResponse(
            &auth_response_storage,
            auth_plugin,
            handshake.authPluginData(),
            self.options.password,
        );
        try protocol.handshake.HandshakeResponse41.write(writer, .{
            .client_flags = negotiation.client_flags,
            .max_packet_size = self.options.max_packet_size,
            .character_set = self.options.character_set,
            .username = self.options.username,
            .auth_response = auth_response,
            .database = negotiation.database,
            .auth_plugin_name = negotiation.client_plugin_name,
        });

        self.state = .authenticating;
        return .send_handshake_response;
    }

    /// Build the `HandshakeResponse41` after the transport has completed the TLS
    /// upgrade triggered by `receiveInitialHandshake`. Reuses the capability set
    /// and database stashed alongside the `SSLRequest`, and rebuilds the auth
    /// token from the stored scramble (the original handshake payload is gone by
    /// now). Mirrors the plaintext path's final response, just over TLS.
    pub fn resumeAfterTlsUpgrade(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
    ) !Action {
        if (self.state != .awaiting_tls) return error.InvalidConnectionPhaseState;

        var auth_response_storage: [32]u8 = undefined;
        const auth_response = try makeAuthResponse(
            &auth_response_storage,
            self.auth_plugin,
            self.authSeed(),
            self.options.password,
        );
        const client_plugin_name: ?[]const u8 =
            if ((self.pending_client_flags & protocol.capability.client_plugin_auth) != 0)
                self.auth_plugin.name()
            else
                null;
        try protocol.handshake.HandshakeResponse41.write(writer, .{
            .client_flags = self.pending_client_flags,
            .max_packet_size = self.options.max_packet_size,
            .character_set = self.options.character_set,
            .username = self.options.username,
            .auth_response = auth_response,
            .database = self.pending_database,
            .auth_plugin_name = client_plugin_name,
        });

        self.state = .authenticating;
        return .send_handshake_response;
    }

    pub fn receiveAuthPacket(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        payload: []const u8,
    ) !Action {
        if (self.state != .authenticating) return error.InvalidConnectionPhaseState;
        return switch (protocol.auth.AuthPacketTag.classify(payload)) {
            .ok => {
                _ = try protocol.response.OkResponse.parse(payload, protocol.capability.client_protocol_41);
                self.state = .ready;
                return .none;
            },
            .err => {
                self.state = .failed;
                return .none;
            },
            .auth_switch_request => {
                const request = try protocol.auth.AuthSwitchRequest.parse(payload);
                self.auth_plugin = request.plugin;
                self.setAuthSeed(request.plugin_data);
                self.auth_step = .scramble_sent;
                var storage: [32]u8 = undefined;
                const auth_response = try makeAuthResponse(
                    &storage,
                    request.plugin,
                    request.plugin_data,
                    self.options.password,
                );
                try protocol.auth.writeScrambleResponse(writer, auth_response);
                return .send_auth_response;
            },
            .auth_more_data => self.receiveAuthMoreData(writer, payload),
            .unknown => error.UnsupportedAuthExchange,
        };
    }

    /// Handle an AuthMoreData packet during `authenticating`. For
    /// caching_sha2_password this drives the full-authentication fallback the
    /// server requests when its fast-auth cache check misses (cold cache or
    /// wrong password): request the RSA public key, then send the encrypted
    /// password. Over a secure channel the server short-circuits with OK, which
    /// is handled by the `.ok` branch in `receiveAuthPacket` instead.
    fn receiveAuthMoreData(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        payload: []const u8,
    ) !Action {
        const more = try protocol.auth.AuthMoreData.parse(payload);
        switch (self.auth_step) {
            .public_key_requested => {
                // `more.data` is the server's PEM-encoded RSA public key.
                const encrypted = try protocol.auth.encryptPasswordWithPublicKey(
                    writer.allocator,
                    self.options.password,
                    self.authSeed(),
                    more.data,
                );
                defer writer.allocator.free(encrypted);
                try writer.writeBytes(encrypted);
                self.auth_step = .encrypted_password_sent;
                return .send_auth_response;
            },
            .scramble_sent, .encrypted_password_sent => {
                if (more.isCachingSha2FastAuthSuccess()) return .none;
                if (more.isCachingSha2FullAuthenticationStart()) {
                    try protocol.auth.writePublicKeyRequest(writer, self.auth_plugin);
                    self.auth_step = .public_key_requested;
                    return .send_auth_response;
                }
                return error.UnsupportedAuthExchange;
            },
        }
    }

    pub fn sendCommand(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        command: protocol.command.Command,
    ) !Action {
        if (self.state != .ready) return error.InvalidConnectionPhaseState;
        try command.write(writer);
        self.state = .command_inflight;
        return .send_command;
    }

    pub fn sendCommandPayload(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        payload: []const u8,
    ) !Action {
        if (self.state != .ready) return error.InvalidConnectionPhaseState;
        try writer.writeBytes(payload);
        self.state = .command_inflight;
        return .send_command;
    }

    pub fn sendNoResponseCommand(
        self: *ConnectionPhase,
        writer: *protocol.PayloadWriter,
        command: protocol.command.Command,
    ) !Action {
        if (self.state != .ready) return error.InvalidConnectionPhaseState;
        try command.write(writer);
        return .send_command;
    }

    /// Advance the phase for a `COM_STMT_PREPARE` response. Unlike a generic
    /// command response, a PREPARE_OK packet must NOT be parsed as an OK packet:
    /// both start with 0x00, but PREPARE_OK is followed by the statement id and
    /// column/param counts, not a length-encoded affected-rows value. Parsing it
    /// as an OK packet reads the statement-id's low byte as that length-encoded
    /// integer and desyncs the stream whenever that byte is >= 0xfb. The caller
    /// (`Transport.readPrepareResponse`) parses the PREPARE_OK / ERR body and
    /// then reads the param/column definition packets directly; afterwards the
    /// connection is ready for the next command.
    pub fn receivePrepareResponse(self: *ConnectionPhase) !void {
        if (self.state != .command_inflight) return error.InvalidConnectionPhaseState;
        self.state = .ready;
    }

    pub fn receiveCommandResponse(
        self: *ConnectionPhase,
        payload: []const u8,
    ) !Action {
        if (self.state != .command_inflight) return error.InvalidConnectionPhaseState;
        return switch (try protocol.response.GenericResponse.parse(payload, protocol.capability.client_protocol_41)) {
            .ok, .eof => {
                try self.transitionAfterCommandTerminator(payload);
                return .none;
            },
            .err => {
                // A command-level server error (syntax, duplicate key, ...) is
                // delivered as a single ERR packet that fully terminates the
                // command. The connection is drained and reusable per the MySQL
                // protocol, so it returns to `ready` rather than `failed`.
                _ = try protocol.response.ErrorResponse.parse(payload, protocol.capability.client_protocol_41);
                self.state = .ready;
                return .none;
            },
            .local_infile => {
                self.state = .failed;
                return .local_infile_request;
            },
            .result_set => {
                self.state = .result_streaming;
                return .start_result_stream;
            },
        };
    }

    /// Advance the result-streaming state machine for one text-protocol packet
    /// and return its classification, so the transport can decode the row from
    /// the same `classify` instead of repeating it.
    pub fn receiveTextResultStreamPacket(
        self: *ConnectionPhase,
        payload: []const u8,
    ) !protocol.text_result.ResultPacketTag {
        if (self.state != .result_streaming) return error.InvalidConnectionPhaseState;
        const tag = try protocol.text_result.ResultPacketTag.classify(payload);
        switch (tag) {
            .row => {},
            .eof => try self.transitionAfterResultTerminator(payload),
            // An ERR packet terminates the result set; the connection is drained
            // and reusable, so it returns to `ready`.
            .err => self.state = .ready,
        }
        return tag;
    }

    /// Binary counterpart of `receiveTextResultStreamPacket`. A binary row
    /// always begins with `0x00`, so the leading byte (ERR `0xff`, EOF `0xfe`,
    /// else row) classifies it; returns the shared row/eof/err tag.
    pub fn receiveBinaryResultStreamPacket(
        self: *ConnectionPhase,
        payload: []const u8,
    ) !protocol.text_result.ResultPacketTag {
        if (self.state != .result_streaming) return error.InvalidConnectionPhaseState;
        if (payload.len == 0) return error.EndOfPayload;
        const tag: protocol.text_result.ResultPacketTag = switch (payload[0]) {
            0xff => .err,
            0xfe => .eof,
            else => .row,
        };
        switch (tag) {
            // ERR terminates the binary result set; connection stays reusable.
            .err => self.state = .ready,
            .eof => try self.transitionAfterResultTerminator(payload),
            .row => {},
        }
        return tag;
    }

    fn transitionAfterResultTerminator(
        self: *ConnectionPhase,
        payload: []const u8,
    ) !void {
        const status_flags = try resultTerminatorStatusFlags(payload);
        self.state = if ((status_flags & protocol.capability.server_more_results_exists) != 0)
            .command_inflight
        else
            .ready;
    }

    fn transitionAfterCommandTerminator(
        self: *ConnectionPhase,
        payload: []const u8,
    ) !void {
        const ok = try protocol.response.OkResponse.parse(payload, protocol.capability.client_protocol_41);
        // Stash the summary so the transport need not re-parse this same OK
        // packet to surface affected-rows/last-insert-id/etc. to the caller.
        self.command_ok = .{
            .affected_rows = ok.affected_rows,
            .last_insert_id = ok.last_insert_id,
            .warnings = ok.warnings,
            .status_flags = ok.status_flags,
        };
        self.state = if ((ok.status_flags & protocol.capability.server_more_results_exists) != 0)
            .command_inflight
        else
            .ready;
    }
};

fn resultTerminatorStatusFlags(payload: []const u8) protocol.types.Error!u16 {
    if (payload.len == 0) return error.EndOfPayload;
    if (payload[0] == 0xfe and payload.len < 9) {
        var reader = protocol.PayloadReader.init(payload);
        _ = try reader.readInt(u8);
        _ = try reader.readInt(u16);
        return try reader.readInt(u16);
    }

    const ok = try protocol.response.OkResponse.parse(payload, protocol.capability.client_protocol_41);
    return ok.status_flags;
}

fn makeAuthResponse(
    storage: *[32]u8,
    plugin: protocol.auth.AuthPlugin,
    seed: []const u8,
    password: []const u8,
) ![]const u8 {
    if (protocol.auth.isEmptyPassword(password)) return "";
    return switch (plugin) {
        .mysql_native_password => blk: {
            const scrambled = protocol.auth.scrambleNativePassword(seed, password);
            @memcpy(storage[0..scrambled.len], &scrambled);
            break :blk storage[0..scrambled.len];
        },
        .caching_sha2_password => blk: {
            const scrambled = protocol.auth.scrambleCachingSha2Password(seed, password);
            @memcpy(storage[0..scrambled.len], &scrambled);
            break :blk storage[0..scrambled.len];
        },
        else => error.UnsupportedAuthPlugin,
    };
}
