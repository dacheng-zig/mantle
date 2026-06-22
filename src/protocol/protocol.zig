pub const auth = @import("auth.zig");
pub const capability = @import("capability.zig");
pub const collation = @import("collation.zig");
pub const handshake = @import("handshake.zig");
pub const response = @import("response.zig");
pub const prepared_statement = @import("prepared_statement.zig");
pub const decimal = @import("decimal.zig");
pub const temporal = @import("temporal.zig");
pub const binary_result = @import("binary_result.zig");
pub const text_result = @import("text_result.zig");
pub const types = @import("types.zig");
pub const PayloadReader = @import("payload_reader.zig").PayloadReader;
pub const PayloadWriter = @import("payload_writer.zig").PayloadWriter;
pub const command = @import("command.zig");
pub const packet = @import("packet.zig");

test {
    _ = auth;
    _ = capability;
    _ = collation;
    _ = handshake;
    _ = response;
    _ = prepared_statement;
    _ = decimal;
    _ = temporal;
    _ = binary_result;
    _ = text_result;
    _ = types;
    _ = PayloadReader;
    _ = PayloadWriter;
    _ = command;
    _ = packet;

    _ = @import("auth_test.zig");
    _ = @import("binary_result_test.zig");
    _ = @import("command_test.zig");
    _ = @import("decimal_test.zig");
    _ = @import("handshake_test.zig");
    _ = @import("packet_test.zig");
    _ = @import("payload_reader_test.zig");
    _ = @import("payload_writer_test.zig");
    _ = @import("prepared_statement_test.zig");
    _ = @import("response_test.zig");
    _ = @import("temporal_test.zig");
    _ = @import("text_result_test.zig");
}
