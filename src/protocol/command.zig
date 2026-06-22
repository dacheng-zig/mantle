//! Command Phase request encoding.
//!
//! In the command phase the client sends a packet whose payload starts with a
//! one-byte command code and whose `sequence_id` is 0; the server replies with
//! an OK/ERR packet, a result set, or (for some commands) no reply at all.
//!
//! Reference: MySQL Source Code Documentation, Command Phase
//! <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html>

const std = @import("std");

const protocol = @import("protocol.zig");

/// Leading command byte (`COM_*`) of a command-phase request packet.
///
/// Values are the `enum_server_command` constants defined by the server in
/// `include/my_command.h`; only the subset this driver issues is modelled here.
///
/// Reference: Command Phase
/// <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html>
pub const CommandCode = enum(u8) {
    /// `COM_QUIT`: close the connection. No ordinary response is read.
    quit = 0x01,
    /// `COM_QUERY`: execute a SQL statement via the text protocol.
    /// <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html>
    query = 0x03,
    /// `COM_PING`: liveness check; the server replies with an OK packet.
    ping = 0x0e,
    /// `COM_RESET_CONNECTION`: reset session state without re-authenticating;
    /// used when recycling pooled connections. Replies with an OK packet.
    reset_connection = 0x1f,
    /// `COM_STMT_PREPARE`: create a server-side prepared statement.
    /// <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html>
    stmt_prepare = 0x16,
    /// `COM_STMT_EXECUTE`: execute a prepared statement with bound parameters.
    /// <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html>
    stmt_execute = 0x17,
    /// `COM_STMT_SEND_LONG_DATA`: stream a large parameter value in chunks
    /// before `COM_STMT_EXECUTE`. The server sends no response.
    stmt_send_long_data = 0x18,
    /// `COM_STMT_CLOSE`: release a prepared statement. The server sends no
    /// response; the `statement_id` must not be reused afterwards.
    stmt_close = 0x19,
    /// `COM_STMT_RESET`: reset a prepared statement's server-side state
    /// (parameters and long data). Replies with an OK or ERR packet.
    stmt_reset = 0x1a,
};

/// Payload of a `COM_STMT_SEND_LONG_DATA` request: appends `data` to the
/// parameter at `param_id` (0-based) of the statement `statement_id`.
pub const StmtSendLongData = struct {
    statement_id: u32,
    param_id: u16,
    data: []const u8,
};

/// A command-phase request, tagged by its `CommandCode`. `write` serializes it
/// into a payload (without the 4-byte packet header) for transmission.
pub const Command = union(enum) {
    quit,
    ping,
    reset_connection,
    query: []const u8,
    stmt_prepare: []const u8,
    stmt_execute: u32,
    stmt_send_long_data: StmtSendLongData,
    stmt_close: u32,
    stmt_reset: u32,

    pub fn initQuery(sql: []const u8) Command {
        return .{ .query = sql };
    }

    pub fn initStmtPrepare(sql: []const u8) Command {
        return .{ .stmt_prepare = sql };
    }

    pub fn initStmtExecute(statement_id: u32) Command {
        return .{ .stmt_execute = statement_id };
    }

    pub fn initStmtSendLongData(statement_id: u32, param_id: u16, data: []const u8) Command {
        return .{ .stmt_send_long_data = .{
            .statement_id = statement_id,
            .param_id = param_id,
            .data = data,
        } };
    }

    pub fn initStmtClose(statement_id: u32) Command {
        return .{ .stmt_close = statement_id };
    }

    pub fn initStmtReset(statement_id: u32) Command {
        return .{ .stmt_reset = statement_id };
    }

    pub fn initResetConnection() Command {
        return .{ .reset_connection = {} };
    }

    pub fn write(self: Command, writer: *protocol.PayloadWriter) !void {
        switch (self) {
            .quit => try writer.writeInt(u8, @intFromEnum(CommandCode.quit)),
            .ping => try writer.writeInt(u8, @intFromEnum(CommandCode.ping)),
            .reset_connection => try writer.writeInt(u8, @intFromEnum(CommandCode.reset_connection)),
            .query => |sql| {
                try writer.writeInt(u8, @intFromEnum(CommandCode.query));
                try writer.writeBytes(sql);
            },
            .stmt_prepare => |sql| {
                try writer.writeInt(u8, @intFromEnum(CommandCode.stmt_prepare));
                try writer.writeBytes(sql);
            },
            .stmt_execute => |statement_id| {
                // No-parameter form: flags = CURSOR_TYPE_NO_CURSOR (0),
                // iteration_count = 1 (always), and no parameter section.
                // See COM_STMT_EXECUTE for the full layout with bound params.
                try writer.writeInt(u8, @intFromEnum(CommandCode.stmt_execute));
                try writer.writeInt(u32, statement_id);
                try writer.writeInt(u8, 0);
                try writer.writeInt(u32, 1);
            },
            .stmt_send_long_data => |long_data| {
                try writer.writeInt(u8, @intFromEnum(CommandCode.stmt_send_long_data));
                try writer.writeInt(u32, long_data.statement_id);
                try writer.writeInt(u16, long_data.param_id);
                try writer.writeBytes(long_data.data);
            },
            .stmt_close => |statement_id| {
                try writer.writeInt(u8, @intFromEnum(CommandCode.stmt_close));
                try writer.writeInt(u32, statement_id);
            },
            .stmt_reset => |statement_id| {
                try writer.writeInt(u8, @intFromEnum(CommandCode.stmt_reset));
                try writer.writeInt(u32, statement_id);
            },
        }
    }
};
