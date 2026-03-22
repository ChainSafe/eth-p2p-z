const std = @import("std");

pub fn main() !void {
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    std.debug.print("Run `zig build test` to run the tests.\n", .{});
}
