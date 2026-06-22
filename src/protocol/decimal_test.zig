const std = @import("std");

const decimal = @import("decimal.zig");
const validateDecimal = decimal.validateDecimal;

test "decimal validation accepts common decimal byte forms" {
    try validateDecimal(.{ .bytes = "0" });
    try validateDecimal(.{ .bytes = "-123.456" });
    try validateDecimal(.{ .bytes = "+42.00" });
    try validateDecimal(.{ .bytes = ".5" });
    try validateDecimal(.{ .bytes = "5." });
}

test "decimal validation rejects malformed decimal byte forms" {
    try std.testing.expectError(error.InvalidDecimalValue, validateDecimal(.{ .bytes = "" }));
    try std.testing.expectError(error.InvalidDecimalValue, validateDecimal(.{ .bytes = "-" }));
    try std.testing.expectError(error.InvalidDecimalValue, validateDecimal(.{ .bytes = "." }));
    try std.testing.expectError(error.InvalidDecimalValue, validateDecimal(.{ .bytes = "12x.34" }));
    try std.testing.expectError(error.InvalidDecimalValue, validateDecimal(.{ .bytes = "1.2.3" }));
}
