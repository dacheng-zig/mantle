const std = @import("std");

const auth = @import("auth.zig");
const protocol = @import("protocol.zig");

const AuthPlugin = auth.AuthPlugin;
const AuthPacketTag = auth.AuthPacketTag;
const AuthSwitchRequest = auth.AuthSwitchRequest;
const AuthMoreData = auth.AuthMoreData;
const scrambleNativePassword = auth.scrambleNativePassword;
const scrambleCachingSha2Password = auth.scrambleCachingSha2Password;
const isEmptyPassword = auth.isEmptyPassword;
const writeEmptyAuthResponse = auth.writeEmptyAuthResponse;
const writeScrambleResponse = auth.writeScrambleResponse;
const writePublicKeyRequest = auth.writePublicKeyRequest;
const caching_sha2_password_public_key_response = auth.caching_sha2_password_public_key_response;
const caching_sha2_password_public_key_request = auth.caching_sha2_password_public_key_request;
const caching_sha2_password_fast_auth_success = auth.caching_sha2_password_fast_auth_success;
const caching_sha2_password_full_authentication_start = auth.caching_sha2_password_full_authentication_start;

test "auth plugin maps known and unknown names" {
    try std.testing.expectEqual(AuthPlugin.mysql_native_password, AuthPlugin.fromName("mysql_native_password"));
    try std.testing.expectEqual(AuthPlugin.caching_sha2_password, AuthPlugin.fromName("caching_sha2_password"));
    try std.testing.expectEqual(AuthPlugin.sha256_password, AuthPlugin.fromName("sha256_password"));
    try std.testing.expectEqual(AuthPlugin.mysql_clear_password, AuthPlugin.fromName("mysql_clear_password"));
    try std.testing.expectEqual(AuthPlugin.unknown, AuthPlugin.fromName("not_real"));

    try std.testing.expectEqualSlices(u8, "caching_sha2_password", AuthPlugin.caching_sha2_password.name());
}

test "auth constants match mysql protocol markers" {
    try std.testing.expectEqual(@as(u8, 0x01), caching_sha2_password_public_key_response);
    try std.testing.expectEqual(@as(u8, 0x02), caching_sha2_password_public_key_request);
    try std.testing.expectEqual(@as(u8, 0x03), caching_sha2_password_fast_auth_success);
    try std.testing.expectEqual(@as(u8, 0x04), caching_sha2_password_full_authentication_start);
}

test "auth scrambles mysql native password" {
    const seed = [_]u8{ 10, 47, 74, 111, 75, 73, 34, 48, 88, 76, 114, 74, 37, 13, 3, 80, 82, 2, 23, 21 };

    try std.testing.expectEqual([20]u8{
        106, 20,  155, 221, 128, 189, 161, 235, 240, 250,
        43,  210, 207, 46,  151, 23,  254, 204, 52,  187,
    }, scrambleNativePassword(&seed, "secret"));
    try std.testing.expectEqual([20]u8{
        101, 15, 7,  223, 53, 60,  206, 83,  112, 238,
        163, 77, 88, 15,  46, 145, 24,  129, 139, 86,
    }, scrambleNativePassword(&seed, "secret2"));
}

test "auth scrambles caching sha2 password" {
    const seed = [_]u8{ 10, 47, 74, 111, 75, 73, 34, 48, 88, 76, 114, 74, 37, 13, 3, 80, 82, 2, 23, 21 };

    try std.testing.expectEqual([32]u8{ 244, 144, 231, 111, 102, 217, 216, 102, 101, 206, 84, 217, 140, 120, 208, 172, 254, 47, 176, 176, 139, 66, 61, 168, 7, 20, 72, 115, 211, 11, 49, 44 }, scrambleCachingSha2Password(&seed, "secret"));
    try std.testing.expectEqual([32]u8{ 171, 195, 147, 74, 1, 44, 243, 66, 232, 118, 7, 28, 142, 226, 2, 222, 81, 120, 91, 67, 2, 88, 167, 160, 19, 139, 199, 156, 77, 128, 11, 198 }, scrambleCachingSha2Password(&seed, "secret2"));
}

test "auth returns empty response for empty password" {
    try std.testing.expect(isEmptyPassword(""));
    try std.testing.expect(!isEmptyPassword("secret"));
}

test "auth classifies auth exchange packets" {
    try std.testing.expectEqual(AuthPacketTag.ok, AuthPacketTag.classify(&.{0x00}));
    try std.testing.expectEqual(AuthPacketTag.err, AuthPacketTag.classify(&.{0xff}));
    try std.testing.expectEqual(AuthPacketTag.auth_switch_request, AuthPacketTag.classify(&.{0xfe}));
    try std.testing.expectEqual(AuthPacketTag.auth_more_data, AuthPacketTag.classify(&.{0x01}));
    try std.testing.expectEqual(AuthPacketTag.unknown, AuthPacketTag.classify(&.{0x02}));
    try std.testing.expectEqual(AuthPacketTag.unknown, AuthPacketTag.classify(""));
}

test "auth parses auth switch request" {
    const payload = [_]u8{ 0xfe, 'c', 'a', 'c', 'h', 'i', 'n', 'g', '_', 's', 'h', 'a', '2', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, 's', 'e', 'e', 'd' };

    const request = try AuthSwitchRequest.parse(&payload);

    try std.testing.expectEqual(AuthPlugin.caching_sha2_password, request.plugin);
    try std.testing.expectEqualSlices(u8, "caching_sha2_password", request.plugin_name);
    try std.testing.expectEqualSlices(u8, "seed", request.plugin_data);
}

test "auth rejects malformed auth switch request" {
    try std.testing.expectError(protocol.types.Error.InvalidPacketSignature, AuthSwitchRequest.parse(&.{0x00}));
    try std.testing.expectError(protocol.types.Error.MissingNullTerminator, AuthSwitchRequest.parse(&.{ 0xfe, 'x' }));
}

test "auth parses auth more data and caching sha2 markers" {
    const fast = try AuthMoreData.parse(&.{ 0x01, caching_sha2_password_fast_auth_success });
    const full = try AuthMoreData.parse(&.{ 0x01, caching_sha2_password_full_authentication_start });
    const public_key = try AuthMoreData.parse(&.{ 0x01, caching_sha2_password_public_key_response, 'p', 'k' });

    try std.testing.expect(fast.isCachingSha2FastAuthSuccess());
    try std.testing.expect(full.isCachingSha2FullAuthenticationStart());
    try std.testing.expect(public_key.isCachingSha2PublicKeyResponse());
    try std.testing.expectEqualSlices(u8, &.{ caching_sha2_password_public_key_response, 'p', 'k' }, public_key.data);
}

test "auth rejects malformed auth more data" {
    try std.testing.expectError(protocol.types.Error.InvalidPacketSignature, AuthMoreData.parse(&.{0x00}));
    try std.testing.expectError(protocol.types.Error.EndOfPayload, AuthMoreData.parse(""));
}

test "auth writes empty response payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writeEmptyAuthResponse(&writer);

    try std.testing.expectEqualSlices(u8, "", writer.bytes());
}

test "auth writes raw scramble response payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writeScrambleResponse(&writer, &.{ 1, 2, 3 });

    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, writer.bytes());
}

test "auth writes public key request marker" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writePublicKeyRequest(&writer, .caching_sha2_password);

    try std.testing.expectEqualSlices(u8, &.{caching_sha2_password_public_key_request}, writer.bytes());
}
