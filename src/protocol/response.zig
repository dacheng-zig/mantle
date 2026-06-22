const std = @import("std");

const protocol = @import("protocol.zig");

pub const ResponseTag = enum {
    ok,
    err,
    eof,
    local_infile,
    result_set,
};

pub const GenericResponse = struct {
    pub fn parse(payload: []const u8, capabilities: u32) protocol.types.Error!ResponseTag {
        if (payload.len == 0) return error.EndOfPayload;
        return switch (payload[0]) {
            0x00 => .ok,
            0xfb => .local_infile,
            0xff => .err,
            0xfe => if (isEofPayload(payload, capabilities)) .eof else .result_set,
            else => .result_set,
        };
    }
};

pub const OkResponse = struct {
    affected_rows: u64,
    last_insert_id: u64,
    status_flags: u16,
    warnings: u16,
    info: []const u8,
    session_state_info: ?[]const u8,

    pub fn parse(payload: []const u8, capabilities: u32) protocol.types.Error!OkResponse {
        var reader = protocol.PayloadReader.init(payload);
        const signature = try reader.readInt(u8);
        if (signature != 0x00 and signature != 0xfe) return error.InvalidPacketSignature;

        const affected_rows = try reader.readLengthEncodedInteger();
        const last_insert_id = try reader.readLengthEncodedInteger();

        var status_flags: u16 = 0;
        var warnings: u16 = 0;
        if ((capabilities & protocol.capability.client_protocol_41) != 0) {
            status_flags = try reader.readInt(u16);
            warnings = try reader.readInt(u16);
        }

        var info: []const u8 = "";
        var session_state_info: ?[]const u8 = null;
        if ((capabilities & protocol.capability.client_session_track) != 0) {
            info = try reader.readLengthEncodedString();
            if ((status_flags & protocol.capability.server_session_state_changed) != 0) {
                session_state_info = try reader.readLengthEncodedString();
            }
        } else {
            info = reader.readRemaining();
        }

        return .{
            .affected_rows = affected_rows,
            .last_insert_id = last_insert_id,
            .status_flags = status_flags,
            .warnings = warnings,
            .info = info,
            .session_state_info = session_state_info,
        };
    }
};

pub const ErrorResponse = struct {
    error_code: u16,
    sql_state: ?[5]u8,
    message: []const u8,

    pub fn parse(payload: []const u8, capabilities: u32) protocol.types.Error!ErrorResponse {
        var reader = protocol.PayloadReader.init(payload);
        const signature = try reader.readInt(u8);
        if (signature != 0xff) return error.InvalidPacketSignature;

        const error_code = try reader.readInt(u16);
        var sql_state: ?[5]u8 = null;
        if ((capabilities & protocol.capability.client_protocol_41) != 0) {
            const marker = try reader.readInt(u8);
            if (marker != '#') return error.InvalidSqlStateMarker;
            const state = try reader.readFixedBytes(5);
            sql_state = state.*;
        }

        return .{
            .error_code = error_code,
            .sql_state = sql_state,
            .message = reader.readRemaining(),
        };
    }

    pub fn parseFirst(payload: []const u8) protocol.types.Error!ErrorResponse {
        return parse(payload, 0);
    }
};

fn isEofPayload(payload: []const u8, capabilities: u32) bool {
    _ = capabilities;
    return payload.len < 9;
}
