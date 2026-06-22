const std = @import("std");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const protocol = @import("protocol.zig");

pub const AuthPlugin = enum {
    mysql_native_password,
    caching_sha2_password,
    sha256_password,
    mysql_clear_password,
    unknown,

    pub fn fromName(plugin_name: []const u8) AuthPlugin {
        return std.meta.stringToEnum(AuthPlugin, plugin_name) orelse .unknown;
    }

    pub fn name(self: AuthPlugin) []const u8 {
        return switch (self) {
            .mysql_native_password => "mysql_native_password",
            .caching_sha2_password => "caching_sha2_password",
            .sha256_password => "sha256_password",
            .mysql_clear_password => "mysql_clear_password",
            .unknown => "unknown",
        };
    }
};

pub const sha256_password_public_key_request: u8 = 0x01;
pub const caching_sha2_password_public_key_response: u8 = 0x01;
pub const caching_sha2_password_public_key_request: u8 = 0x02;
pub const caching_sha2_password_fast_auth_success: u8 = 0x03;
pub const caching_sha2_password_full_authentication_start: u8 = 0x04;

pub const AuthPacketTag = enum {
    ok,
    err,
    auth_switch_request,
    auth_more_data,
    unknown,

    pub fn classify(payload: []const u8) AuthPacketTag {
        if (payload.len == 0) return .unknown;
        return switch (payload[0]) {
            0x00 => .ok,
            0xff => .err,
            0xfe => .auth_switch_request,
            0x01 => .auth_more_data,
            else => .unknown,
        };
    }
};

pub const AuthSwitchRequest = struct {
    plugin: AuthPlugin,
    plugin_name: []const u8,
    plugin_data: []const u8,

    pub fn parse(payload: []const u8) protocol.types.Error!AuthSwitchRequest {
        var reader = protocol.PayloadReader.init(payload);
        const signature = try reader.readInt(u8);
        if (signature != 0xfe) return error.InvalidPacketSignature;
        const plugin_name = try reader.readNullTerminatedString();
        return .{
            .plugin = AuthPlugin.fromName(plugin_name),
            .plugin_name = plugin_name,
            .plugin_data = reader.readRemaining(),
        };
    }
};

pub const AuthMoreData = struct {
    data: []const u8,

    pub fn parse(payload: []const u8) protocol.types.Error!AuthMoreData {
        var reader = protocol.PayloadReader.init(payload);
        const signature = try reader.readInt(u8);
        if (signature != 0x01) return error.InvalidPacketSignature;
        if (reader.remaining() == 0) return error.EndOfPayload;
        return .{ .data = reader.readRemaining() };
    }

    pub fn isCachingSha2FastAuthSuccess(self: AuthMoreData) bool {
        return self.data.len == 1 and self.data[0] == caching_sha2_password_fast_auth_success;
    }

    pub fn isCachingSha2FullAuthenticationStart(self: AuthMoreData) bool {
        return self.data.len == 1 and self.data[0] == caching_sha2_password_full_authentication_start;
    }

    pub fn isCachingSha2PublicKeyResponse(self: AuthMoreData) bool {
        return self.data.len >= 1 and self.data[0] == caching_sha2_password_public_key_response;
    }
};

pub fn scrambleNativePassword(seed: []const u8, password: []const u8) [Sha1.digest_length]u8 {
    var stage_1 = sha1(password);
    const stage_2 = sha1(&stage_1);

    var hasher = Sha1.init(.{});
    hasher.update(seed);
    hasher.update(&stage_2);
    const mask = hasher.finalResult();

    xorInPlace(&stage_1, &mask);
    return stage_1;
}

pub fn scrambleCachingSha2Password(seed: []const u8, password: []const u8) [Sha256.digest_length]u8 {
    var stage_1 = sha256(password);
    const stage_2 = sha256(&stage_1);

    var hasher = Sha256.init(.{});
    hasher.update(&stage_2);
    hasher.update(seed);
    const mask = hasher.finalResult();

    xorInPlace(&stage_1, &mask);
    return stage_1;
}

pub fn isEmptyPassword(password: []const u8) bool {
    return password.len == 0;
}

pub fn writeEmptyAuthResponse(writer: *protocol.PayloadWriter) !void {
    _ = writer;
}

pub fn writeScrambleResponse(writer: *protocol.PayloadWriter, scramble: []const u8) !void {
    try writer.writeBytes(scramble);
}

pub fn writePublicKeyRequest(writer: *protocol.PayloadWriter, plugin: AuthPlugin) !void {
    const marker = switch (plugin) {
        .caching_sha2_password => caching_sha2_password_public_key_request,
        .sha256_password => sha256_password_public_key_request,
        else => return error.UnsupportedAuthPlugin,
    };
    try writer.writeInt(u8, marker);
}

fn sha1(bytes: []const u8) [Sha1.digest_length]u8 {
    var hasher = Sha1.init(.{});
    hasher.update(bytes);
    return hasher.finalResult();
}

fn sha256(bytes: []const u8) [Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(bytes);
    return hasher.finalResult();
}

fn xorInPlace(dest: anytype, mask: anytype) void {
    for (dest, mask) |*d, m| {
        d.* ^= m;
    }
}
