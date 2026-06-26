const std = @import("std");

pub const Decimal = struct {
    /// The raw decimal text. When produced by a column reader this borrows the
    /// row payload and is valid only until the next row is fetched; copy it
    /// (e.g. via a scan `str_allocator`) to retain it longer.
    bytes: []const u8,

    pub fn asBytes(self: Decimal) []const u8 {
        return self.bytes;
    }
};

pub fn validateDecimal(value: Decimal) !void {
    const bytes = value.bytes;
    if (bytes.len == 0) return error.InvalidDecimalValue;

    var index: usize = 0;
    if (bytes[0] == '-' or bytes[0] == '+') {
        index = 1;
        if (index == bytes.len) return error.InvalidDecimalValue;
    }

    var digits_before_dot: usize = 0;
    while (index < bytes.len and isDigit(bytes[index])) : (index += 1) {
        digits_before_dot += 1;
    }

    var digits_after_dot: usize = 0;
    if (index < bytes.len and bytes[index] == '.') {
        index += 1;
        while (index < bytes.len and isDigit(bytes[index])) : (index += 1) {
            digits_after_dot += 1;
        }
    }

    if (index != bytes.len) return error.InvalidDecimalValue;
    if (digits_before_dot == 0 and digits_after_dot == 0) return error.InvalidDecimalValue;
}

fn isDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}
