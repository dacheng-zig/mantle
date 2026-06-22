const std = @import("std");
const mantle = @import("mantle");

/// Connection settings for the integration suite.
pub const TestConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 3306,
    username: []const u8 = "root",
    password: []const u8 = "root",
    database: ?[]const u8 = null,
    /// utf8mb4_general_ci; matches the rest of the codebase's default charset.
    character_set: u8 = 45,

    pub fn options(self: TestConfig) mantle.ConnectionPhase.Options {
        return .{
            .username = self.username,
            .password = self.password,
            .database = self.database,
            .character_set = self.character_set,
        };
    }
};

pub const test_config: TestConfig = .{};
