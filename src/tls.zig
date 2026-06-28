//! TLS configuration for MySQL connections.
//!
//! Mantle speaks MySQL's `CLIENT_SSL` upgrade: after the server's initial
//! handshake the client sends an `SSLRequest`, performs a TLS handshake on the
//! raw socket, then tunnels the rest of the protocol (auth + commands) inside
//! TLS records. The crypto is `std.crypto.tls.Client` over the zio socket — no
//! third-party TLS library, mirroring talon's HTTPS transport.
//!
//! These types are the *policy* knobs (when to upgrade, how to verify the
//! server certificate, where the trust anchors come from). The mechanics live
//! in `transport.zig` (the `ZioStream` TLS upgrade) and the connection-phase
//! state machine.
//!
//! MySQL `CertificateRequest`: MySQL sends a TLS `CertificateRequest` on *every*
//! TLS connection (to allow optional client-cert auth — e.g. `REQUIRE X509`
//! users), regardless of `ssl_ca`. Upstream `std.crypto.tls.Client` cannot
//! answer it and rejects the handshake, so mantle uses a vendored, lightly
//! forked TLS client (`crypto/tls_client.zig`) that replies with an empty client
//! certificate (TLS 1.3). The handshake therefore completes against a standard
//! MySQL — exercised end-to-end by the TLS integration tests.
//!
//! Remaining limitations: no mutual TLS (mantle presents no real client
//! certificate, so a `REQUIRE X509` account is not satisfied), and the
//! certificate-answering path is TLS 1.3 only (MySQL 8.0+/9.x negotiate 1.3).

const std = @import("std");

/// When to attempt a TLS upgrade during the handshake.
pub const Mode = enum {
    /// Never request TLS; connect in plaintext. The default.
    disabled,
    /// Request TLS when the server advertises `CLIENT_SSL`; fall back to
    /// plaintext otherwise.
    prefer,
    /// Require TLS; fail the handshake (`error.TlsNotSupportedByServer`) if the
    /// server does not advertise `CLIENT_SSL`.
    require,
};

/// How the server certificate is verified. Defaults exist for testing, but the
/// production path is `.system` (full host + CA chain verification).
pub const Verification = union(enum) {
    /// Verify the host name (SNI + match) against the certificate AND the chain
    /// against a root store. The secure default.
    system: *RootStore,
    /// Verify the host name, but accept any otherwise-valid self-signed
    /// certificate (no chain-of-trust). Test/dev only.
    self_signed,
    /// No host and no CA verification — a trusted session cannot be
    /// established. DANGER: defeats TLS authentication. Test/dev only.
    insecure_no_verification,
};

/// System root certificate store, scanned once and shared across every TLS
/// connection (rescanning per-connection would re-read the OS trust store from
/// disk each time). Caller-owned and long-lived: build it, `load` it, hand a
/// pointer to the connection/pool config, and `deinit` it after the last
/// connection. The std TLS verifier reads the bundle under `lock` during the
/// handshake, so the store must outlive every connection that references it.
pub const RootStore = struct {
    bundle: std.crypto.Certificate.Bundle = .empty,
    /// Guards `bundle` for the std verifier (it takes a read lock during
    /// certificate-chain verification).
    lock: std.Io.RwLock = .init,

    /// Scans the OS trust store into `bundle`. One-time, off the hot path; the
    /// blocking file reads ride `io`.
    pub fn load(self: *RootStore, gpa: std.mem.Allocator, io: std.Io) !void {
        try self.bundle.rescan(gpa, io, std.Io.Timestamp.now(io, .real));
    }

    pub fn deinit(self: *RootStore, gpa: std.mem.Allocator) void {
        self.bundle.deinit(gpa);
    }
};

/// TLS settings handed to a connection driver (e.g. `TcpDriver.Target.tls`).
/// `io` drives the handshake's entropy, wall clock, and CA bundle reads; obtain
/// it from the zio runtime (`runtime.io()`).
pub const ClientConfig = struct {
    mode: Mode = .require,
    io: std.Io,
    verification: Verification,
};
