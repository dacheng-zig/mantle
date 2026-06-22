const std = @import("std");

const temporal = @import("temporal.zig");
const validateDateTime = temporal.validateDateTime;
const validateTime = temporal.validateTime;

test "temporal validation accepts valid boundary values" {
    try validateDateTime(.{ .year = 2024, .month = 2, .day = 29, .hour = 23, .minute = 59, .second = 59, .microsecond = 999_999 });
    try validateDateTime(.{});
    try validateTime(.{ .days = 34, .hour = 22, .minute = 59, .second = 59, .microsecond = 999_999 });
}

test "temporal validation rejects invalid values" {
    try @import("std").testing.expectError(error.InvalidTemporalValue, validateDateTime(.{ .year = 2023, .month = 2, .day = 29 }));
    try @import("std").testing.expectError(error.InvalidTemporalValue, validateTime(.{ .days = 34, .hour = 23 }));
}
