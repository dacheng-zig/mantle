//! Root of the integration test suite. Each submodule holds tests that run
//! against a real MySQL server. Wired into `zig build integration_test`.

test {
    _ = @import("connection.zig");
    _ = @import("pool.zig");
    _ = @import("statement_cache.zig");
}
