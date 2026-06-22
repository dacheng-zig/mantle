const std = @import("std");

const handshake_mod = @import("handshake.zig");
const protocol = @import("protocol.zig");

const HandshakeV10 = handshake_mod.HandshakeV10;
const HandshakeResponse41 = handshake_mod.HandshakeResponse41;
const negotiateClientFlags = handshake_mod.negotiateClientFlags;

const sample_handshake = [_]u8{
    0x0a,
    '8',
    '.',
    '0',
    '.',
    '3',
    '6',
    0x00,
    0x39,
    0x30,
    0x00,
    0x00,
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    0x00,
    0x00,
    0x82,
    0xff,
    0x02,
    0x00,
    0x08,
    0x00,
    21,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    0x00,
    'c',
    'a',
    'c',
    'h',
    'i',
    'n',
    'g',
    '_',
    's',
    'h',
    'a',
    '2',
    '_',
    'p',
    'a',
    's',
    's',
    'w',
    'o',
    'r',
    'd',
    0x00,
};

test "handshake parses v10 server greeting" {
    const handshake = try HandshakeV10.parse(&sample_handshake);

    try std.testing.expectEqualSlices(u8, "8.0.36", handshake.server_version);
    try std.testing.expectEqual(@as(u32, 12345), handshake.connection_id);
    try std.testing.expectEqual(@as(u32, 0x0008_8200), handshake.capability_flags);
    try std.testing.expectEqual(@as(u8, 0xff), handshake.character_set);
    try std.testing.expectEqual(@as(u16, 0x0002), handshake.status_flags);
    try std.testing.expectEqualSlices(u8, "abcdefghijklmnopqrst", handshake.authPluginData());
    try std.testing.expectEqualSlices(u8, "caching_sha2_password", handshake.auth_plugin_name.?);
}

test "handshake rejects invalid protocol version" {
    var bad = sample_handshake;
    bad[0] = 9;

    try std.testing.expectError(protocol.types.Error.InvalidProtocolVersion, HandshakeV10.parse(&bad));
}

test "handshake rejects truncated payload and missing nul" {
    try std.testing.expectError(protocol.types.Error.MissingNullTerminator, HandshakeV10.parse(sample_handshake[0..3]));

    var bad = sample_handshake;
    bad[7] = 'x';
    try std.testing.expectError(protocol.types.Error.MissingNullTerminator, HandshakeV10.parse(bad[0..8]));
}

test "handshake response writes secure connection auth response" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try HandshakeResponse41.write(&writer, .{
        .client_flags = protocol.capability.client_protocol_41 | protocol.capability.client_secure_connection,
        .max_packet_size = 1024,
        .character_set = protocol.collation.utf8mb4_general_ci,
        .username = "root",
        .auth_response = "abc",
    });

    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x82, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00,
        45,  0,   0,   0, // character_set = utf8mb4_general_ci (collation 45)
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        'r', 'o', 'o', 't',
        0,   3,   'a', 'b',
        'c',
    }, writer.bytes());
}

test "handshake response writes lenenc auth database plugin and attrs" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try HandshakeResponse41.write(&writer, .{
        .client_flags = protocol.capability.client_protocol_41 |
            protocol.capability.client_plugin_auth_lenenc_client_data |
            protocol.capability.client_connect_with_db |
            protocol.capability.client_plugin_auth |
            protocol.capability.client_connect_attrs,
        .max_packet_size = 0,
        .character_set = protocol.collation.utf8mb4_general_ci,
        .username = "u",
        .auth_response = "secret",
        .database = "db",
        .auth_plugin_name = "mysql_native_password",
        .attrs = &.{
            .{ .key = "_client_name", .value = "mantle" },
            .{ .key = "program_name", .value = "test" },
        },
    });

    const expected_prefix = [_]u8{
        0x08, 0x02, 0x38, 0x00,
        0x00, 0x00, 0x00, 0x00,
        45,  0,   0,   0, // character_set = utf8mb4_general_ci (collation 45)
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        'u', 0,   6,   's',
        'e', 'c', 'r', 'e',
        't', 'd', 'b', 0,
        'm', 'y', 's', 'q',
        'l', '_', 'n', 'a',
        't', 'i', 'v', 'e',
        '_', 'p', 'a', 's',
        's', 'w', 'o', 'r',
        'd', 0,
    };
    try std.testing.expectEqualSlices(u8, &expected_prefix, writer.bytes()[0..expected_prefix.len]);
    try std.testing.expect(writer.bytes().len > expected_prefix.len);
}

test "handshake negotiates client flags from server capabilities" {
    const handshake = try HandshakeV10.parse(&sample_handshake);

    const negotiation = negotiateClientFlags(.{
        .database = "app",
    }, handshake);

    try std.testing.expect((negotiation.client_flags & protocol.capability.client_protocol_41) != 0);
    try std.testing.expect((negotiation.client_flags & protocol.capability.client_secure_connection) != 0);
    try std.testing.expect((negotiation.client_flags & protocol.capability.client_plugin_auth) != 0);
    try std.testing.expectEqual(@as(u32, 0), negotiation.client_flags & protocol.capability.client_plugin_auth_lenenc_client_data);
    try std.testing.expect((negotiation.client_flags & protocol.capability.client_connect_with_db) == 0);
    try std.testing.expectEqualSlices(u8, "caching_sha2_password", negotiation.auth_plugin_name);
    try std.testing.expect(negotiation.client_plugin_name != null);
    try std.testing.expect(negotiation.database == null);
}
