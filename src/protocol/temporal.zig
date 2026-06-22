pub const DateTime = struct {
    year: u16 = 0,
    month: u8 = 0,
    day: u8 = 0,
    hour: u8 = 0,
    minute: u8 = 0,
    second: u8 = 0,
    microsecond: u32 = 0,
};

pub const Time = struct {
    negative: bool = false,
    days: u32 = 0,
    hour: u8 = 0,
    minute: u8 = 0,
    second: u8 = 0,
    microsecond: u32 = 0,
};

pub fn validateDateTime(value: DateTime) !void {
    if (value.year == 0 and value.month == 0 and value.day == 0 and value.hour == 0 and value.minute == 0 and value.second == 0 and value.microsecond == 0) {
        return;
    }

    if (value.year < 1000 or value.year > 9999) return error.InvalidTemporalValue;
    if (value.month < 1 or value.month > 12) return error.InvalidTemporalValue;
    if (value.day < 1 or value.day > daysInMonth(value.year, value.month)) return error.InvalidTemporalValue;
    if (value.hour > 23) return error.InvalidTemporalValue;
    if (value.minute > 59) return error.InvalidTemporalValue;
    if (value.second > 59) return error.InvalidTemporalValue;
    if (value.microsecond > 999_999) return error.InvalidTemporalValue;
}

pub fn validateTime(value: Time) !void {
    if (value.hour > 23) return error.InvalidTemporalValue;
    if (value.minute > 59) return error.InvalidTemporalValue;
    if (value.second > 59) return error.InvalidTemporalValue;
    if (value.microsecond > 999_999) return error.InvalidTemporalValue;

    const total_hours = @as(u64, value.days) * 24 + value.hour;
    if (total_hours > 838) return error.InvalidTemporalValue;
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}
