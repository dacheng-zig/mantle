const std = @import("std");

const command = @import("command.zig");
const protocol = @import("protocol.zig");

const Command = command.Command;

test "command encodes COM_PING payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try (Command{ .ping = {} }).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{0x0e}, writer.bytes());
}

test "command encodes COM_QUIT payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try (Command{ .quit = {} }).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{0x01}, writer.bytes());
}

test "command encodes COM_QUERY payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initQuery("select 1").write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x03, 's', 'e', 'l', 'e', 'c', 't', ' ', '1' }, writer.bytes());
}

test "command encodes COM_STMT_PREPARE payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initStmtPrepare("select ?").write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x16, 's', 'e', 'l', 'e', 'c', 't', ' ', '?' }, writer.bytes());
}

test "command encodes COM_STMT_CLOSE payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initStmtClose(0x12345678).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x78, 0x56, 0x34, 0x12 }, writer.bytes());
}

test "command encodes COM_STMT_RESET payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initStmtReset(0x12345678).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0x78, 0x56, 0x34, 0x12 }, writer.bytes());
}

test "command encodes COM_STMT_SEND_LONG_DATA payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initStmtSendLongData(0x12345678, 2, "chunk").write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 'c', 'h', 'u', 'n', 'k' }, writer.bytes());
}

test "command encodes COM_RESET_CONNECTION payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try (Command{ .reset_connection = {} }).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{0x1f}, writer.bytes());
}

test "command encodes no-param COM_STMT_EXECUTE payload" {
    var writer = protocol.PayloadWriter.init(std.testing.allocator);
    defer writer.deinit();

    try Command.initStmtExecute(0x12345678).write(&writer);

    try std.testing.expectEqualSlices(u8, &.{ 0x17, 0x78, 0x56, 0x34, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00 }, writer.bytes());
}
