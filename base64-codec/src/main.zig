const std = @import("std");
const mem = std.mem;

pub fn main() !void {
    var memory_buffer = [_]u8{0} ** 1024;
    var fba = std.heap.FixedBufferAllocator.init(&memory_buffer);
    const allocator = fba.allocator();

    const input = "Hello world!";

    const b64 = Base64.init();
    const encoded = try b64.encode(allocator, input);
    const decoded = try b64.decode(allocator, encoded);
    std.debug.print("{s}\n", .{decoded});
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

    pub fn encode(self: Self, allocator: mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_out = try calc_encode_length(input);
        var out = try allocator.alloc(u8, n_out);
        var buf = [_]u8{ 0, 0, 0 };
        var count: u8 = 0;
        var idx_out: u64 = 0;

        for (input, 0..) |_, i| {
            buf[count] = input[i];
            count += 1;
            if (3 == count) {
                out[idx_out] = self.to_char(buf[0] >> 2);
                out[idx_out + 1] = self.to_char(((buf[0] & 0x03) << 4) | (buf[1] >> 4));
                out[idx_out + 2] = self.to_char(((buf[1] & 0x0f) << 2) | (buf[2] >> 6));
                out[idx_out + 3] = self.to_char(buf[2] & 0x3f);

                idx_out += 4;
                count = 0;
            }
        }

        if (2 == count) {
            out[idx_out] = self.to_char(buf[0] >> 2);
            out[idx_out + 1] = self.to_char(((buf[0] & 0x03) << 4) | (buf[1] >> 4));
            out[idx_out + 2] = self.to_char((buf[1] & 0x0f) << 2);
            out[idx_out + 3] = '=';
        }

        if (1 == count) {
            out[idx_out] = self.to_char(buf[0] >> 2);
            out[idx_out + 1] = self.to_char((buf[0] & 0x3) << 4);
            out[idx_out + 2] = '=';
            out[idx_out + 3] = '=';
        }

        return out;
    }

    fn decode(self: Self, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_output = try calc_decode_length(input);
        var count: u8 = 0;
        var idx_out: u64 = 0;
        var buf = [_]u8{ 0, 0, 0, 0 };
        var output = try allocator.alloc(u8, n_output);
        for (0..output.len) |i| {
            output[i] = 0;
        }

        for (0..input.len) |i| {
            buf[count] = self.char_to_index(input[i]);
            count += 1;
            if (count == 4) {
                output[idx_out] = (buf[0] << 2) | (buf[1] >> 4);
                if (buf[2] != 64) {
                    output[idx_out + 1] = (buf[1] << 4) | (buf[2] >> 2);
                }
                if (buf[3] != 64) {
                    output[idx_out + 2] = (buf[2] << 6) | buf[3];
                }
                idx_out += 3;
                count = 0;
            }
        }

        return output;
    }

    fn to_char(self: Self, index: usize) u8 {
        return self._table[index];
    }

    fn char_to_index(self: Self, char: u8) u8 {
        if (char == '=') {
            return 64;
        }

        var index: u8 = 0;
        for (0..63) |i| {
            if (self.to_char(i) == char) {
                break;
            }
            index += 1;
        }

        return index;
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

test "encode" {
    var memory_buffer = [_]u8{0} ** 1024;
    var fba = std.heap.FixedBufferAllocator.init(&memory_buffer);
    const allocator = fba.allocator();

    const b64 = Base64.init();

    const input_1 = "Here's a test";
    const output_1 = try b64.encode(allocator, input_1);
    try std.testing.expect(mem.eql(u8, output_1, "SGVyZSdzIGEgdGVzdA=="));

    const input_2 = "Testing some more stuff";
    const output_2 = try b64.encode(allocator, input_2);
    try std.testing.expect(mem.eql(u8, output_2, "VGVzdGluZyBzb21lIG1vcmUgc3R1ZmY="));

    const input_3 = "And now for a final test";
    const output_3 = try b64.encode(allocator, input_3);
    try std.testing.expect(mem.eql(u8, output_3, "QW5kIG5vdyBmb3IgYSBmaW5hbCB0ZXN0"));
}

test "decode" {
    var memory_buffer = [_]u8{0} ** 1024;
    var fba = std.heap.FixedBufferAllocator.init(&memory_buffer);
    const allocator = fba.allocator();

    const b64 = Base64.init();

    const input = "RGVjb2RlIHN1Y2Nlc3NmdWwh";
    const output = try b64.decode(allocator, input);
    try std.testing.expect(mem.eql(u8, output, "Decode successful!"));
}
