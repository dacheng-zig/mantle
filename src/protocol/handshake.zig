const std = @import("std");

const protocol = @import("protocol.zig");

/// Borrowed view: `server_version` and `auth_plugin_name` alias the parsed
/// `payload` and are valid only while it lives. The scramble is copied into the
/// inline `auth_plugin_data_storage`, so `authPluginData()` is self-owned.
pub const HandshakeV10 = struct {
    server_version: []const u8,
    connection_id: u32,
    capability_flags: u32,
    character_set: u8,
    status_flags: u16,
    auth_plugin_data_storage: [32]u8,
    auth_plugin_data_len: usize,
    auth_plugin_name: ?[]const u8,

    pub fn authPluginData(self: *const HandshakeV10) []const u8 {
        return self.auth_plugin_data_storage[0..self.auth_plugin_data_len];
    }

    pub fn parse(payload: []const u8) protocol.types.Error!HandshakeV10 {
        var reader = protocol.PayloadReader.init(payload);

        const protocol_version = try reader.readInt(u8);
        if (protocol_version != 10) return error.InvalidProtocolVersion;

        const server_version = try reader.readNullTerminatedString();
        const connection_id = try reader.readInt(u32);
        const auth_part_1 = try reader.readFixedBytes(8);
        _ = try reader.readInt(u8);

        const capability_flags_1 = try reader.readInt(u16);
        const character_set = try reader.readInt(u8);
        const status_flags = try reader.readInt(u16);
        const capability_flags_2 = try reader.readInt(u16);
        const capability_flags = (@as(u32, capability_flags_2) << 16) | capability_flags_1;
        const auth_plugin_data_len_field = try reader.readInt(u8);
        _ = try reader.readFixedBytes(10);

        const len_field: usize = auth_plugin_data_len_field;
        // Part 2 occupies max(13, len-8) bytes on the wire. We must consume the
        // whole window so the auth-plugin name that follows is positioned right.
        const auth_part_2_window_len = if ((capability_flags & protocol.capability.client_plugin_auth) != 0)
            @max(@as(usize, 13), len_field -| 8)
        else
            @as(usize, 13);
        const auth_part_2_window = try reader.readBytesAtMost(auth_part_2_window_len);
        // The scramble is random binary that may legitimately contain or end in
        // 0x00, so we must NOT trim trailing NULs. Part 2 carries exactly one
        // trailing NUL terminator after the scramble; derive the meaningful
        // length from the advertised total (`len_field`) instead of scanning.
        const meaningful_part_2_len = if (len_field > 8)
            @min(auth_part_2_window.len, len_field - 9) // len_field = 8 + scramble_part2 + 1 NUL
        else
            auth_part_2_window.len -| 1; // legacy: drop the single NUL terminator
        const auth_part_2 = auth_part_2_window[0..meaningful_part_2_len];
        const auth_plugin_data_len = auth_part_1.len + auth_part_2.len;
        if (auth_plugin_data_len > 32) return error.LengthOverflow;
        var auth_plugin_data_storage: [32]u8 = @splat(0);
        @memcpy(auth_plugin_data_storage[0..auth_part_1.len], auth_part_1);
        @memcpy(auth_plugin_data_storage[auth_part_1.len..auth_plugin_data_len], auth_part_2);

        const auth_plugin_name = if ((capability_flags & protocol.capability.client_plugin_auth) != 0 and reader.remaining() > 0)
            try reader.readNullTerminatedString()
        else
            null;

        return .{
            .server_version = server_version,
            .connection_id = connection_id,
            .capability_flags = capability_flags,
            .character_set = character_set,
            .status_flags = status_flags,
            .auth_plugin_data_storage = auth_plugin_data_storage,
            .auth_plugin_data_len = auth_plugin_data_len,
            .auth_plugin_name = auth_plugin_name,
        };
    }
};

pub const HandshakeResponse41 = struct {
    pub const Attribute = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const Options = struct {
        client_flags: u32,
        max_packet_size: u32,
        character_set: u8,
        username: []const u8,
        auth_response: []const u8,
        database: ?[]const u8 = null,
        auth_plugin_name: ?[]const u8 = null,
        attrs: []const Attribute = &.{},
    };

    pub fn write(writer: *protocol.PayloadWriter, options: Options) !void {
        try writer.writeInt(u32, options.client_flags);
        try writer.writeInt(u32, options.max_packet_size);
        try writer.writeInt(u8, options.character_set);
        try writeZeroes(writer, 23);
        try writer.writeNullTerminatedString(options.username);

        if ((options.client_flags & protocol.capability.client_plugin_auth_lenenc_client_data) != 0) {
            try writer.writeLengthEncodedString(options.auth_response);
        } else if ((options.client_flags & protocol.capability.client_secure_connection) != 0) {
            if (options.auth_response.len > std.math.maxInt(u8)) return error.LengthOverflow;
            try writer.writeInt(u8, @intCast(options.auth_response.len));
            try writer.writeBytes(options.auth_response);
        } else {
            try writer.writeNullTerminatedString(options.auth_response);
        }

        if ((options.client_flags & protocol.capability.client_connect_with_db) != 0) {
            try writer.writeNullTerminatedString(options.database orelse "");
        }

        if ((options.client_flags & protocol.capability.client_plugin_auth) != 0) {
            try writer.writeNullTerminatedString(options.auth_plugin_name orelse "");
        }

        if ((options.client_flags & protocol.capability.client_connect_attrs) != 0) {
            var attr_writer = protocol.PayloadWriter.init(writer.allocator);
            defer attr_writer.deinit();
            for (options.attrs) |attr| {
                try attr_writer.writeLengthEncodedString(attr.key);
                try attr_writer.writeLengthEncodedString(attr.value);
            }
            try writer.writeLengthEncodedString(attr_writer.bytes());
        }
    }
};

pub const NegotiatedHandshake = struct {
    client_flags: u32,
    auth_plugin_name: []const u8,
    client_plugin_name: ?[]const u8,
    database: ?[]const u8,
};

pub fn negotiateClientFlags(
    options: struct {
        database: ?[]const u8,
    },
    handshake: HandshakeV10,
) NegotiatedHandshake {
    const negotiated_plugin_auth = (handshake.capability_flags & protocol.capability.client_plugin_auth) != 0;
    const auth_plugin_name = if (negotiated_plugin_auth)
        handshake.auth_plugin_name orelse protocol.auth.AuthPlugin.mysql_native_password.name()
    else
        protocol.auth.AuthPlugin.mysql_native_password.name();

    var client_flags = protocol.capability.client_protocol_41 |
        protocol.capability.client_secure_connection;
    if (negotiated_plugin_auth) {
        client_flags |= protocol.capability.client_plugin_auth;
    }
    if (negotiated_plugin_auth and (handshake.capability_flags & protocol.capability.client_plugin_auth_lenenc_client_data) != 0) {
        client_flags |= protocol.capability.client_plugin_auth_lenenc_client_data;
    }
    if (options.database != null and (handshake.capability_flags & protocol.capability.client_connect_with_db) != 0) {
        client_flags |= protocol.capability.client_connect_with_db;
    }

    return .{
        .client_flags = client_flags,
        .auth_plugin_name = auth_plugin_name,
        .client_plugin_name = if (negotiated_plugin_auth) auth_plugin_name else null,
        .database = if ((client_flags & protocol.capability.client_connect_with_db) != 0) options.database else null,
    };
}

fn writeZeroes(writer: *protocol.PayloadWriter, comptime count: usize) !void {
    try writer.writeBytes(&([_]u8{0} ** count));
}
