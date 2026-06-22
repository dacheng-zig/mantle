//! Capability flags and status flags used during connection and command phases.
//!
//! Capability flags (`CLIENT_*`) are negotiated in the handshake: the server
//! advertises what it supports and the client declares the subset it both
//! supports and wants enabled. Status flags (`SERVER_STATUS_*`) appear in
//! OK/EOF packets and describe server session state.
//!
//! References:
//! - Capability Flags <https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html>
//! - Generic Response Packets (status flags) <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_response_packets.html>

/// `CLIENT_PROTOCOL_41`: use the 4.1+ protocol layout. Baseline for modern clients.
pub const client_protocol_41: u32 = 1 << 9;
/// `CLIENT_SSL`: send an `SSLRequest`, then upgrade the connection to TLS.
pub const client_ssl: u32 = 1 << 11;
/// `CLIENT_SECURE_CONNECTION`: supports the 4.1 native authentication handshake.
pub const client_secure_connection: u32 = 1 << 15;
/// `CLIENT_CONNECT_WITH_DB`: handshake response carries an initial database.
pub const client_connect_with_db: u32 = 1 << 3;
/// `CLIENT_PLUGIN_AUTH`: supports pluggable authentication and Auth Switch.
pub const client_plugin_auth: u32 = 1 << 19;
/// `CLIENT_CONNECT_ATTRS`: handshake response carries connection attributes.
pub const client_connect_attrs: u32 = 1 << 20;
/// `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`: auth response length is length-encoded
/// (allowing payloads larger than 255 bytes).
pub const client_plugin_auth_lenenc_client_data: u32 = 1 << 21;
/// `CLIENT_SESSION_TRACK`: OK packets may carry session state-change information.
pub const client_session_track: u32 = 1 << 23;
/// `CLIENT_DEPRECATE_EOF`: server may replace EOF packets with OK packets.
pub const client_deprecate_eof: u32 = 1 << 24;
/// `CLIENT_OPTIONAL_RESULTSET_METADATA`: result-set column metadata may be omitted.
pub const client_optional_resultset_metadata: u32 = 1 << 25;

/// `SERVER_MORE_RESULTS_EXISTS`: another result set follows; keep draining.
pub const server_more_results_exists: u16 = 1 << 3;
/// `SERVER_STATUS_AUTOCOMMIT`: autocommit is enabled.
pub const server_status_autocommit: u16 = 1 << 1;
/// `SERVER_SESSION_STATE_CHANGED`: OK packet includes session state info.
pub const server_session_state_changed: u16 = 1 << 14;
