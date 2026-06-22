const std = @import("std");

const response_mod = @import("response.zig");
const protocol = @import("protocol.zig");

const ResponseTag = response_mod.ResponseTag;
const GenericResponse = response_mod.GenericResponse;
const OkResponse = response_mod.OkResponse;
const ErrorResponse = response_mod.ErrorResponse;

test "response parses basic OK packet" {
    const payload = [_]u8{
        0x00, // OK
        0x01, // affected rows
        0x02, // last insert id
        0x02, 0x00, // status autocommit
        0x01, 0x00, // warnings
        'o',  'k',
    };

    const response = try GenericResponse.parse(&payload, protocol.capability.client_protocol_41);

    try std.testing.expectEqual(ResponseTag.ok, response);
    const ok = try OkResponse.parse(&payload, protocol.capability.client_protocol_41);
    try std.testing.expectEqual(@as(u64, 1), ok.affected_rows);
    try std.testing.expectEqual(@as(u64, 2), ok.last_insert_id);
    try std.testing.expectEqual(@as(u16, protocol.capability.server_status_autocommit), ok.status_flags);
    try std.testing.expectEqual(@as(u16, 1), ok.warnings);
    try std.testing.expectEqualSlices(u8, "ok", ok.info);
    try std.testing.expect(ok.session_state_info == null);
}

test "response parses OK packet with session tracking" {
    const payload = [_]u8{
        0x00,
        0x00,
        0x00,
        0x02,
        0x40,
        0x00,
        0x00,
        0x04,
        'i',
        'n',
        'f',
        'o',
        0x03,
        's',
        't',
        's',
    };

    const ok = try OkResponse.parse(&payload, protocol.capability.client_protocol_41 | protocol.capability.client_session_track);

    try std.testing.expectEqual(@as(u16, protocol.capability.server_status_autocommit | protocol.capability.server_session_state_changed), ok.status_flags);
    try std.testing.expectEqualSlices(u8, "info", ok.info);
    try std.testing.expectEqualSlices(u8, "sts", ok.session_state_info.?);
}

test "response parses protocol 41 ERR packet" {
    const payload = [_]u8{ 0xff, 0x48, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'a', 'd' };

    const response = try GenericResponse.parse(&payload, protocol.capability.client_protocol_41);

    try std.testing.expectEqual(ResponseTag.err, response);
    const err = try ErrorResponse.parse(&payload, protocol.capability.client_protocol_41);
    try std.testing.expectEqual(@as(u16, 1096), err.error_code);
    try std.testing.expectEqualSlices(u8, "HY000", &err.sql_state.?);
    try std.testing.expectEqualSlices(u8, "bad", err.message);
}

test "response parses first ERR packet without sql state" {
    const payload = [_]u8{ 0xff, 0x15, 0x04, 'n', 'o' };

    const err = try ErrorResponse.parseFirst(&payload);

    try std.testing.expectEqual(@as(u16, 1045), err.error_code);
    try std.testing.expect(err.sql_state == null);
    try std.testing.expectEqualSlices(u8, "no", err.message);
}

test "response classifies EOF and result set placeholder" {
    const eof_payload = [_]u8{ 0xfe, 0x00, 0x00, 0x02, 0x00 };
    const resultset_payload = [_]u8{0x02};
    const lenenc_resultset_payload = [_]u8{ 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expectEqual(ResponseTag.eof, try GenericResponse.parse(&eof_payload, protocol.capability.client_protocol_41));
    try std.testing.expectEqual(ResponseTag.result_set, try GenericResponse.parse(&resultset_payload, protocol.capability.client_protocol_41));
    try std.testing.expectEqual(ResponseTag.result_set, try GenericResponse.parse(&lenenc_resultset_payload, protocol.capability.client_protocol_41));
}

test "response classifies local infile request" {
    const payload = [_]u8{ 0xfb, 'd', 'a', 't', 'a', '.', 'c', 's', 'v' };

    try std.testing.expectEqual(ResponseTag.local_infile, try GenericResponse.parse(&payload, protocol.capability.client_protocol_41));
}

test "response rejects malformed packets" {
    try std.testing.expectError(protocol.types.Error.EndOfPayload, OkResponse.parse(&.{0x00}, protocol.capability.client_protocol_41));
    try std.testing.expectError(protocol.types.Error.InvalidPacketSignature, ErrorResponse.parse(&.{ 0x00, 0x01, 0x00 }, protocol.capability.client_protocol_41));
    try std.testing.expectError(protocol.types.Error.InvalidSqlStateMarker, ErrorResponse.parse(&.{ 0xff, 0x01, 0x00, '!', 'H', 'Y', '0', '0', '0' }, protocol.capability.client_protocol_41));
}
