//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

pub const std_options = @import("std_options.zig").options;
pub const identity = @import("identity.zig");
pub const secp_context = @import("secp_context.zig");
pub const protobuf = @import("protobuf.zig");
pub const security = @import("security.zig");

pub const PubSubMessage = protobuf.rpc.Message;

// New comptime API modules (Zig 0.16 rewrite)
pub const tls = security.tls;
pub const ping = @import("protocol/ping.zig");
pub const quic_new = @import("transport/quic/quic.zig");
pub const quic_engine_new = @import("transport/quic/engine.zig");
pub const swarm = @import("switch.zig");
pub const Switch = swarm.Switch;

test {
    std.testing.refAllDecls(@This());
}
