const std = @import("std");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const PublicKey = std.crypto.Certificate.rsa.PublicKey;
const protocol = @import("protocol.zig");

const pem_base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

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

// caching_sha2_password / sha256_password full authentication over an insecure
// channel. The server sends its RSA public key; the client returns
// RSA(XOR(password, seed)) using RSA_PKCS1_OAEP_PADDING with SHA-1.
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html

pub const DecodedPublicKey = struct {
    /// Backing buffer for the DER bytes that `value` borrows from.
    der_bytes: []u8,
    value: PublicKey,

    pub fn deinit(self: *const DecodedPublicKey, allocator: std.mem.Allocator) void {
        allocator.free(self.der_bytes);
    }
};

/// Encrypt `password` for the server using the PEM-encoded RSA public key the
/// server sent during full authentication. Returns the ciphertext (caller owns).
pub fn encryptPasswordWithPublicKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    seed: []const u8,
    public_key_pem: []const u8,
) ![]u8 {
    const decoded = try decodePublicKey(allocator, public_key_pem);
    defer decoded.deinit(allocator);
    return encryptPassword(allocator, password, seed, &decoded.value);
}

/// Parse a `-----BEGIN PUBLIC KEY-----` PEM block (SubjectPublicKeyInfo) into an
/// RSA public key. The returned key borrows from `der_bytes`, so keep the
/// `DecodedPublicKey` alive until encryption completes.
pub fn decodePublicKey(allocator: std.mem.Allocator, public_key_pem: []const u8) !DecodedPublicKey {
    const start_marker = "-----BEGIN PUBLIC KEY-----";
    const end_marker = "-----END PUBLIC KEY-----";

    const start = std.mem.indexOf(u8, public_key_pem, start_marker) orelse
        return error.InvalidPublicKey;
    const body_start = start + start_marker.len;
    const body_end = std.mem.indexOfPos(u8, public_key_pem, body_start, end_marker) orelse
        return error.InvalidPublicKey;
    const encoded = std.mem.trim(u8, public_key_pem[body_start..body_end], " \t\r\n");

    const der_bytes = try allocator.alloc(u8, pem_base64.calcSizeUpperBound(encoded.len));
    errdefer allocator.free(der_bytes);
    const der_len = try pem_base64.decode(der_bytes, encoded);
    const der = der_bytes[0..der_len];

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE {...}, subjectPublicKey BIT STRING }
    // The BIT STRING wraps the DER-encoded RSAPublicKey (modulus, exponent).
    const Element = std.crypto.Certificate.der.Element;
    const spki = try Element.parse(der, 0);
    const algorithm = try Element.parse(der, spki.slice.start);
    const bitstring = try Element.parse(der, algorithm.slice.end);
    const rsa_der = std.mem.trim(u8, der[bitstring.slice.start..bitstring.slice.end], &.{0});

    const parsed = try PublicKey.parseDer(rsa_der);
    const value = try PublicKey.fromBytes(parsed.exponent, parsed.modulus);
    return .{ .der_bytes = der_bytes, .value = value };
}

fn encryptPassword(
    allocator: std.mem.Allocator,
    password: []const u8,
    seed: []const u8,
    pk: *const PublicKey,
) ![]u8 {
    // A non-empty seed is required to obfuscate the password; guard against a
    // malformed server handshake rather than dividing by zero below.
    if (seed.len == 0) return error.InvalidAuthSeed;

    // Obfuscate the null-terminated password with the connection seed before
    // encrypting, matching the server's expectation.
    const plain = try allocator.alloc(u8, password.len + 1);
    defer allocator.free(plain);
    @memcpy(plain[0..password.len], password);
    plain[password.len] = 0;
    for (plain, 0..) |*c, i| c.* ^= seed[i % seed.len];

    return rsaEncryptOaep(allocator, plain, pk);
}

// RSAES-OAEP encryption (PKCS#1 v2.1) with SHA-1 and an empty label, mirroring
// MySQL's RSA_PKCS1_OAEP_PADDING. The seed is left zeroed: MySQL accepts a
// deterministic seed and we avoid depending on a CSPRNG here.
fn rsaEncryptOaep(allocator: std.mem.Allocator, msg: []const u8, pk: *const PublicKey) ![]u8 {
    const Hash = Sha1;
    const digest_len = Hash.digest_length;

    const l_hash = blk: {
        var hasher = Hash.init(.{});
        hasher.update(&.{});
        break :blk hasher.finalResult();
    };

    const k = (pk.n.bits() + 7) / 8; // modulus size in bytes
    if (msg.len > k - 2 * digest_len - 2) return error.PublicKeyTooSmall;

    var em = try allocator.alloc(u8, k);
    defer allocator.free(em);
    @memset(em, 0);
    const seed = em[1 .. 1 + digest_len];
    const db = em[1 + digest_len ..];

    @memcpy(db[0..digest_len], &l_hash);
    db[db.len - msg.len - 1] = 1;
    @memcpy(db[db.len - msg.len ..], msg);

    mgf1Xor(db, seed);
    mgf1Xor(seed, db);

    return encryptModExp(allocator, em, pk);
}

fn encryptModExp(allocator: std.mem.Allocator, em: []const u8, pk: *const PublicKey) ![]u8 {
    const max_modulus_bits = 4096;
    const Fe = std.crypto.ff.Modulus(max_modulus_bits).Fe;

    const m = try Fe.fromBytes(pk.n, em, .big);
    const c = try pk.n.powPublic(m, pk.e);

    const res = try allocator.alloc(u8, em.len);
    errdefer allocator.free(res);
    try c.toBytes(res, .big);
    return res;
}

// MGF1 mask generation (PKCS#1 v2.1) with SHA-1; XORs the mask into `dest`.
fn mgf1Xor(dest: []u8, seed: []const u8) void {
    const Hash = Sha1;
    var counter: [4]u8 = .{ 0, 0, 0, 0 };
    var done: usize = 0;
    while (done < dest.len) : (incrementCounter(&counter)) {
        var hasher = Hash.init(.{});
        hasher.update(seed);
        hasher.update(&counter);
        const digest = hasher.finalResult();
        for (digest) |d| {
            if (done >= dest.len) break;
            dest[done] ^= d;
            done += 1;
        }
    }
}

fn incrementCounter(counter: *[4]u8) void {
    inline for (.{ 3, 2, 1, 0 }) |i| {
        const sum = @addWithOverflow(counter[i], 1);
        counter[i] = sum[0];
        if (sum[1] == 0) return;
    }
}
