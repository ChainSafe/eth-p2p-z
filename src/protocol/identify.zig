const std = @import("std");
const Io = std.Io;
const log = std.log.scoped(.identify);
const identify_pb = @import("../proto/identify.proto.zig");
const stream_util = @import("../util/stream.zig");

const writeAll = stream_util.writeAll;

/// Maximum identify message size (8 KiB, per spec).
const max_message_size: u32 = 8 * 1024;

pub const Error = error{
    UnexpectedEof,
    MessageTooLarge,
    InvalidProtobuf,
    TooManyListenAddrs,
    TooManyProtocols,
};

/// Configuration for building identify messages.
pub const Config = struct {
    protocol_version: ?[]const u8 = null,
    agent_version: ?[]const u8 = null,
    public_key: ?[]const u8 = null,
    listen_addrs: ?[]const []const u8 = null,
    observed_addr: ?[]const u8 = null,
    supported_protocols: ?[]const []const u8 = null,
    /// Maximum number of peer identify results retained in memory.
    max_peer_results: usize = 1024,
};

const max_listen_addrs: u32 = 64;
const max_protocols: u32 = 128;
const max_varint_bytes: u32 = 10;

/// Identify protocol handler.
/// Identify is stateful — stores per-peer results.
/// Applications should open this protocol explicitly after accepting a peer.
pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Per-peer identify results. Keys are owned copies of peer_id bytes.
    peer_results: std.StringArrayHashMap(IdentifyResult),

    /// Protocol identifier for libp2p identify.
    pub const id = "/ipfs/id/1.0.0";

    /// Protocol identifier for libp2p identify push.
    pub const push_id = "/ipfs/id/push/1.0.0";

    /// Clean up all stored peer results.
    pub fn deinit(self: *Handler) void {
        for (self.peer_results.keys(), self.peer_results.values()) |key, *value| {
            var result = value.*;
            result.deinit(self.allocator);
            self.allocator.free(key);
        }
        self.peer_results.deinit();
    }

    /// Called by Switch when a peer disconnects. Frees stored identify result.
    pub fn onPeerDisconnected(self: *Handler, io: Io, peer_id: []const u8) void {
        _ = io;
        if (self.peer_results.fetchOrderedRemove(peer_id)) |kv| {
            var result = kv.value;
            result.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    /// Get the stored identify result for a peer, if available.
    pub fn getPeerResult(self: *const Handler, peer_id: []const u8) ?*const IdentifyResult {
        return self.peer_results.getPtr(peer_id);
    }

    /// Handle inbound identify (responder): encode and send our identity.
    pub fn handleInbound(self: *Handler, io: Io, stream: anytype, _: anytype) Error!void {
        const allocator = self.allocator;
        const config = self.config;

        var msg = identify_pb.Identify{};
        msg.protocol_version = config.protocol_version;
        msg.agent_version = config.agent_version;
        msg.public_key = config.public_key;
        msg.observed_addr = config.observed_addr;

        // Convert listen_addrs []const []const u8 -> []const ?[]const u8
        var listen_addrs_buf: [max_listen_addrs]?[]const u8 = undefined;
        if (config.listen_addrs) |addrs| {
            if (addrs.len > max_listen_addrs) return Error.TooManyListenAddrs;
            for (addrs, 0..) |addr, i| {
                listen_addrs_buf[i] = addr;
            }
            msg.listen_addrs = listen_addrs_buf[0..addrs.len];
        }

        // Convert protocols
        var protocols_buf: [max_protocols]?[]const u8 = undefined;
        if (config.supported_protocols) |protos| {
            if (protos.len > max_protocols) return Error.TooManyProtocols;
            for (protos, 0..) |proto, i| {
                protocols_buf[i] = proto;
            }
            msg.protocols = protocols_buf[0..protos.len];
        }

        const encoded = msg.encode(allocator) catch return Error.InvalidProtobuf;
        defer allocator.free(encoded);

        if (encoded.len > max_message_size) return Error.MessageTooLarge;

        // Write varint length prefix followed by protobuf body.
        var len_buf: [10]u8 = undefined;
        var len_size: usize = 0;
        {
            var v = encoded.len;
            while (v >= 0x80) : (len_size += 1) {
                len_buf[len_size] = @intCast((v & 0x7f) | 0x80);
                v >>= 7;
            }
            len_buf[len_size] = @intCast(v);
            len_size += 1;
        }
        writeAll(io, stream, len_buf[0..len_size]) catch return Error.UnexpectedEof;
        writeAll(io, stream, encoded) catch return Error.UnexpectedEof;
        stream.closeWrite(io);
        log.info("identify: sent {d} byte response", .{encoded.len});
    }

    /// Handle outbound identify (initiator): read the remote's identity.
    /// Stores result in peer_results if ctx.peer_id is provided (via Switch.newStream).
    pub fn handleOutbound(self: *Handler, io: Io, stream: anytype, ctx: anytype) Error!void {
        const allocator = self.allocator;

        stream.closeWrite(io);

        const message_len = readLengthPrefixedSize(io, stream) catch return Error.UnexpectedEof;
        if (message_len > max_message_size) return Error.MessageTooLarge;

        const owned = allocator.alloc(u8, message_len) catch return Error.UnexpectedEof;
        errdefer allocator.free(owned);
        stream_util.readExact(io, stream, owned) catch return Error.UnexpectedEof;

        const reader = identify_pb.IdentifyReader.init(owned) catch {
            log.warn("identify: failed to parse {d} byte response (first bytes: {any})", .{
                owned.len,
                if (owned.len > 16) owned[0..16] else owned,
            });
            return Error.InvalidProtobuf;
        };

        var result: IdentifyResult = .{
            .reader = reader,
            .raw_bytes = owned,
        };

        // Store per-peer result if peer_id is available
        const peer_id: ?[]const u8 = if (@hasField(@TypeOf(ctx), "peer_id")) ctx.peer_id else null;
        if (peer_id) |pid| {
            // Remove old result if any
            if (self.peer_results.fetchOrderedRemove(pid)) |kv| {
                var old = kv.value;
                old.deinit(allocator);
                allocator.free(kv.key);
            }
            if (self.config.max_peer_results == 0) {
                result.deinit(allocator);
                return;
            }
            if (self.peer_results.count() >= self.config.max_peer_results) {
                const oldest_key = self.peer_results.keys()[0];
                var oldest_result = self.peer_results.values()[0];
                oldest_result.deinit(allocator);
                allocator.free(oldest_key);
                self.peer_results.orderedRemoveAt(0);
            }
            const key = allocator.dupe(u8, pid) catch {
                result.deinit(allocator);
                return Error.UnexpectedEof;
            };
            self.peer_results.put(key, result) catch {
                allocator.free(key);
                result.deinit(allocator);
                return Error.UnexpectedEof;
            };
        } else {
            // No peer_id context, just discard
            result.deinit(allocator);
        }
    }
};

fn readLengthPrefixedSize(io: Io, stream: anytype) Error!usize {
    var value: usize = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;
    while (bytes_read < max_varint_bytes) : (bytes_read += 1) {
        var buf: [1]u8 = undefined;
        const n = stream.read(io, &buf) catch return Error.UnexpectedEof;
        if (n == 0) return Error.UnexpectedEof;
        value |= @as(usize, buf[0] & 0x7f) << shift;
        if (buf[0] & 0x80 == 0) return value;
        shift += 7;
    }
    return Error.InvalidProtobuf;
}

fn writeLengthPrefix(buf: *[10]u8, len: usize) usize {
    var v = len;
    var size: usize = 0;
    while (v >= 0x80) : (size += 1) {
        buf[size] = @intCast((v & 0x7f) | 0x80);
        v >>= 7;
    }
    buf[size] = @intCast(v);
    return size + 1;
}

/// Result from an outbound identify handshake.
/// Caller must call `deinit()` to free the backing buffer.
pub const IdentifyResult = struct {
    reader: identify_pb.IdentifyReader,
    raw_bytes: []const u8,

    pub fn deinit(self: *IdentifyResult, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_bytes);
        self.* = undefined;
    }

    pub fn protocolVersion(self: *const IdentifyResult) []const u8 {
        return self.reader.getProtocolVersion();
    }

    pub fn agentVersion(self: *const IdentifyResult) []const u8 {
        return self.reader.getAgentVersion();
    }

    pub fn publicKey(self: *const IdentifyResult) []const u8 {
        return self.reader.getPublicKey();
    }

    pub fn observedAddr(self: *const IdentifyResult) []const u8 {
        return self.reader.getObservedAddr();
    }
};

// --- Tests ---

const MockStream = stream_util.MockStream;

test "handleInbound encodes and writes identify message" {
    const allocator = std.testing.allocator;

    var stream = MockStream.init(allocator, &.{});
    defer stream.deinit();

    var handler: Handler = .{
        .allocator = allocator,
        .config = .{
            .protocol_version = "test/1.0.0",
            .agent_version = "zig-libp2p/0.1.0",
        },
        .peer_results = std.StringArrayHashMap(IdentifyResult).init(allocator),
    };
    defer handler.deinit();
    try handler.handleInbound(undefined, &stream, .{});
    try std.testing.expect(stream.write_closed);

    // Decode what was written
    var framed_stream = MockStream.init(allocator, stream.write_buf.items);
    defer framed_stream.deinit();
    const body_len = try readLengthPrefixedSize(undefined, &framed_stream);
    try std.testing.expectEqual(body_len, stream.write_buf.items.len - framed_stream.read_pos);
    var reader = try identify_pb.IdentifyReader.init(stream.write_buf.items[framed_stream.read_pos..]);
    try std.testing.expectEqualStrings("test/1.0.0", reader.getProtocolVersion());
    try std.testing.expectEqualStrings("zig-libp2p/0.1.0", reader.getAgentVersion());
}

test "handleOutbound reads and decodes identify message" {
    const allocator = std.testing.allocator;

    var msg = identify_pb.Identify{
        .protocol_version = "ipfs/0.1.0",
        .agent_version = "go-libp2p/0.35.0",
        .public_key = "test-key",
    };
    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    var len_buf: [10]u8 = undefined;
    const len_size = writeLengthPrefix(&len_buf, encoded.len);
    const framed = try std.mem.concat(allocator, u8, &.{ len_buf[0..len_size], encoded });
    defer allocator.free(framed);

    var stream = MockStream.init(allocator, framed);
    defer stream.deinit();

    var handler: Handler = .{
        .allocator = allocator,
        .config = .{},
        .peer_results = std.StringArrayHashMap(IdentifyResult).init(allocator),
    };
    defer handler.deinit();

    const peer_id = "test-peer-id";
    try handler.handleOutbound(undefined, &stream, .{ .peer_id = @as(?[]const u8, peer_id) });
    try std.testing.expect(stream.write_closed);

    // Result should be stored
    const result = handler.getPeerResult(peer_id) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("ipfs/0.1.0", result.protocolVersion());
    try std.testing.expectEqualStrings("go-libp2p/0.35.0", result.agentVersion());
    try std.testing.expectEqualStrings("test-key", result.publicKey());
}

test "handleOutbound rejects empty stream" {
    const allocator = std.testing.allocator;

    var stream = MockStream.init(allocator, &.{});
    defer stream.deinit();

    var handler: Handler = .{
        .allocator = allocator,
        .config = .{},
        .peer_results = std.StringArrayHashMap(IdentifyResult).init(allocator),
    };
    defer handler.deinit();
    const result = handler.handleOutbound(undefined, &stream, .{});
    try std.testing.expectError(Error.UnexpectedEof, result);
}

test "handleOutbound evicts oldest peer result when cache is full" {
    const allocator = std.testing.allocator;

    var msg = identify_pb.Identify{
        .protocol_version = "ipfs/0.1.0",
        .agent_version = "go-libp2p/0.35.0",
        .public_key = "test-key",
    };
    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    var len_buf: [10]u8 = undefined;
    const len_size = writeLengthPrefix(&len_buf, encoded.len);
    const framed = try std.mem.concat(allocator, u8, &.{ len_buf[0..len_size], encoded });
    defer allocator.free(framed);

    var handler: Handler = .{
        .allocator = allocator,
        .config = .{ .max_peer_results = 1 },
        .peer_results = std.StringArrayHashMap(IdentifyResult).init(allocator),
    };
    defer handler.deinit();

    {
        var stream = MockStream.init(allocator, framed);
        defer stream.deinit();
        try handler.handleOutbound(undefined, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });
    }
    {
        var stream = MockStream.init(allocator, framed);
        defer stream.deinit();
        try handler.handleOutbound(undefined, &stream, .{ .peer_id = @as(?[]const u8, "peer-2") });
    }

    try std.testing.expect(handler.getPeerResult("peer-1") == null);
    try std.testing.expect(handler.getPeerResult("peer-2") != null);
    try std.testing.expectEqual(@as(usize, 1), handler.peer_results.count());
}
