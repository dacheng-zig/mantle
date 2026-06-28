//! Connect to MySQL over TLS (the MySQL `CLIENT_SSL` upgrade), prove the channel
//! is encrypted, then close cleanly. The TLS-enabled sibling of 01_connect.
//!
//!   zig build example-tls
//!
//! mantle starts the handshake in plaintext, sends an `SSLRequest`, upgrades the
//! socket to TLS in place, and tunnels auth + every command inside TLS records.
//!
//! The certificate-verification policy is selected by MANTLE_TLS_VERIFY:
//!   insecure     no host and no CA verification (the default — runs against a
//!                stock MySQL's auto-generated self-signed certificate)
//!   self-signed  verify the host name, accept any otherwise-valid self-signed
//!                certificate
//!   system       full CA-chain + host verification against the OS trust store
//!
//! `insecure` defeats TLS authentication and is for local development only; the
//! example prints a warning when it is used. The production path is `.system`
//! against a server whose certificate name matches the host you connect to. A
//! stock MySQL ships an auto-generated self-signed certificate whose name does
//! not match 127.0.0.1, so `system` (and `self-signed`) reject it — point the
//! example at a properly provisioned server to try them:
//!
//!   MANTLE_TLS_VERIFY=system zig build example-tls
//!
//! Server and credentials come from MANTLE_* (see examples/common.zig).

const std = @import("std");
const zio = @import("zio");
const mantle = @import("mantle");
const common = @import("common.zig");

const VerifyMode = enum { system, self_signed, insecure };

fn verifyModeFromEnv(env: *const std.process.Environ.Map) VerifyMode {
    const v = env.get("MANTLE_TLS_VERIFY") orelse return .insecure;
    if (std.mem.eql(u8, v, "self-signed")) return .self_signed;
    if (std.mem.eql(u8, v, "system")) return .system;
    return .insecure;
}

pub fn main(init: std.process.Init) !void {
    var rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();
    // The TLS handshake needs `io` for entropy, the wall clock, and (for
    // `.system`) reading the OS trust store.
    const io = rt.io();

    const gpa = init.gpa;
    const cfg = common.Config.fromEnv(init.environ_map);
    const verify_mode = verifyModeFromEnv(init.environ_map);
    if (verify_mode != .system)
        common.print(
            "warning: TLS certificate verification is '{s}' — use MANTLE_TLS_VERIFY=system in production\n",
            .{@tagName(verify_mode)},
        );

    // `.system` verification reads the OS trust store once into a caller-owned
    // RootStore that must outlive the connection; the other modes need no store.
    var store: mantle.tls.RootStore = .{};
    defer store.deinit(gpa);
    const verification: mantle.tls.Verification = switch (verify_mode) {
        .system => blk: {
            try store.load(gpa, io);
            break :blk .{ .system = &store };
        },
        .self_signed => .self_signed,
        .insecure => .insecure_no_verification,
    };

    // Arm the socket for the TLS upgrade. The connection stays plaintext until
    // mantle emits the SSLRequest; `upgradeHook` then promotes it in place, so
    // the reader/writer keep pointing at the same (pinned) stream.
    const addr = try zio.net.IpAddress.parseIp4(cfg.host, cfg.port);
    const stream = try addr.connect(.{});
    var zs = mantle.transport.ZioStream.initTls(stream, .none, .{
        .io = io,
        .host = cfg.host,
        .verification = verification,
    });
    defer zs.close();

    // `tls = .require` fails the handshake unless the server advertises
    // CLIENT_SSL — no silent fallback to plaintext.
    var opts = cfg.options();
    opts.tls = .require;
    var conn = mantle.Connection.init(.{
        .reader = zs.reader(),
        .writer = zs.writer(),
        .upgrade = zs.upgradeHook(),
    }, opts);
    // A failed handshake captures the server's reason into `lastError`; release
    // it on the error path so a failed connect does not leak.
    defer conn.deinit(gpa);
    try conn.finishHandshake(gpa);
    common.print("connected to {s}:{d} over TLS (verify={s})\n", .{ cfg.host, cfg.port, @tagName(verify_mode) });

    // The server reports a non-empty Ssl_cipher only when the session actually
    // runs over TLS — proof the upgrade took effect rather than silently falling
    // back to plaintext.
    var status = try conn.queryOne(
        struct { @"Variable_name": []const u8, Value: []const u8 },
        gpa,
        "SHOW SESSION STATUS LIKE 'Ssl_cipher'",
    );
    defer status.deinit();
    common.print("negotiated cipher: {s}\n", .{(try status.one()).Value});

    // A graceful COM_QUIT (over TLS); `zs.close` then sends a TLS close_notify
    // and closes the socket.
    try conn.close(gpa);
    common.print("closed cleanly\n", .{});
}
