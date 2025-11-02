const std = @import("std");

pub fn main() !void {
    const input = [_]u8{};
    const n_output: usize = try calc_decode_length(&input);
    std.debug.print("{}\n", .{n_output});

    _ = Base64.init();
}

const Base64 = struct {
    const Self = @This();
    _table: *const [64]u8,

    pub fn init() Self {
        return .{ ._table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ++
            "abcdefghijklmnopqrstuvwxyz" ++
            "0123456789" ++
            "+/" };
    }

    pub fn at(self: Self, index: usize) u8 {
        return self._table[index];
    }
};

fn calc_encode_length(input: []const u8) !usize {
    return try std.math.divCeil(usize, input.len, 3) * 4;
}

fn calc_decode_length(input: []const u8) !usize {
    if (input.len < 4) {
        return 3;
    }

    return try std.math.divFloor(usize, input.len, 4) * 3;
}
