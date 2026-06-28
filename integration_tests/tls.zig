//! Integration tests for the MySQL `CLIENT_SSL` upgrade against a real server.
//!
//! These dial a live MySQL over TLS, complete the handshake on the encrypted
//! channel, and prove the session is actually using a cipher (not just that a
//! query succeeded). Verification is `.insecure_no_verification` because the
//! default MySQL ships an auto-generated self-signed certificate with no chain
//! the test harness can anchor to; the goal here is to exercise the protocol
//! upgrade and the encrypted transport, not certificate validation.
//!
//! MySQL sends a TLS `CertificateRequest` on every TLS connection (to allow
//! optional client-cert auth). mantle's vendored TLS client answers it with an
//! empty client certificate, so the handshake completes against a standard
//! MySQL — these tests run for real, they do not skip.
//!
//! Run with `zig build integration_test` (requires a reachable MySQL with TLS
//! enabled — true for MySQL 8.0+/9.x by default).

const std = @import("std");
const mantle = @import("mantle");
const harness = @import("harness.zig");
const test_config = @import("config.zig").test_config;

const TestConn = harness.TestConn;

const SslStatus = struct {
    @"Variable_name": []const u8,
    Value: []const u8,
};

test "tls handshake completes and the session is encrypted" {
    try harness.runWithIo(struct {
        fn task(a: std.mem.Allocator, io: std.Io) !void {
            var c = try TestConn.connectTls(a, io, test_config, .insecure_no_verification);
            defer c.deinit(a);

            // A round-trip over the encrypted channel.
            try c.conn.ping(a);

            // The server reports the negotiated cipher only when the session is
            // actually running over TLS — a non-empty value proves the upgrade
            // took effect rather than silently falling back to plaintext.
            var status = try c.conn.queryOne(
                SslStatus,
                a,
                "SHOW SESSION STATUS LIKE 'Ssl_cipher'",
            );
            defer status.deinit();
            try std.testing.expect((try status.one()).Value.len > 0);
        }
    }.task);
}

test "tls connection runs text and prepared queries over the encrypted channel" {
    try harness.runWithIo(struct {
        fn task(a: std.mem.Allocator, io: std.Io) !void {
            var c = try TestConn.connectTls(a, io, test_config, .insecure_no_verification);
            defer c.deinit(a);

            // Text protocol.
            var text = try c.conn.queryOne(struct { v: u32 }, a, "SELECT 1 AS v");
            defer text.deinit();
            try std.testing.expectEqual(@as(u32, 1), (try text.one()).v);

            // Binary/prepared protocol with a parameter, also over TLS.
            var bin = try c.conn.queryOneParams(
                struct { doubled: u32 },
                a,
                "SELECT ? * 2 AS doubled",
                .{@as(u32, 21)},
            );
            defer bin.deinit();
            try std.testing.expectEqual(@as(u32, 42), (try bin.one()).doubled);
        }
    }.task);
}
