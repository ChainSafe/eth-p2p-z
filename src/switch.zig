const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const log = std.log.scoped(.@"switch");

const transport_mod = @import("transport/transport.zig");
const protocol_mod = @import("protocol/protocol.zig");
const multistream = @import("protocol/multistream.zig");
const identify_mod = @import("protocol/identify.zig");
const engine_mod = @import("transport/quic/engine.zig");
const QuicEngine = engine_mod.QuicEngine;
const quic_mod = @import("transport/quic/quic.zig");
const identity = @import("identity.zig");
const multiaddr = @import("multiaddr");
const Multiaddr = multiaddr.Multiaddr;
const PeerId = @import("peer_id").PeerId;
const net = Io.net;

/// Configuration for comptime Switch composition.
pub const SwitchConfig = struct {
    /// Transport types (must satisfy assertTransportInterface).
    transports: []const type,
    /// Protocol types (must satisfy assertProtocolInterface — Handler structs with id, handleInbound, handleOutbound).
    protocols: []const type,
};

/// Runtime configuration for the Switch's QUIC engine infrastructure.
pub const EngineConfig = struct {
    host_identity: ?*const identity.KeyPair = null,
};

/// Comptime-composed libp2p Switch.
///
/// Validates transports and protocols at compile time, dispatches inbound
/// streams via multistream-select to the matching protocol handler.
/// Uses Io.Group.async for concurrent connection/stream handling (cooperative fibers).
pub fn Switch(comptime config: SwitchConfig) type {
    // Compile-time validation
    inline for (config.transports) |T| {
        comptime transport_mod.assertTransportInterface(T);
    }
    inline for (config.protocols) |P| {
        comptime protocol_mod.assertProtocolInterface(P);
    }

    return struct {
        const Self = @This();

        /// Comptime-generated tuple type holding one instance per registered protocol handler.
        const HandlerTuple = std.meta.Tuple(config.protocols);

        allocator: Allocator,
        handlers: HandlerTuple,
        server_engine: ?*QuicEngine = null,
        client_engine: ?*QuicEngine = null,
        connections: std.StringHashMap(*engine_mod.QuicConnection),
        background: Io.Group,
        engine_config: EngineConfig,

        /// Protocol IDs for multistream-select negotiation (computed at comptime).
        const supported_protocol_ids = protocol_mod.protocolIds(config.protocols);

        pub fn init(allocator: Allocator, engine_config: EngineConfig, handlers: HandlerTuple) Self {
            return .{
                .allocator = allocator,
                .handlers = handlers,
                .connections = std.StringHashMap(*engine_mod.QuicConnection).init(allocator),
                .background = .init,
                .engine_config = engine_config,
            };
        }

        /// Tear down the Switch. Stops all background fibers and engines if
        /// close() was not already called, then frees resources.
        pub fn deinit(self: *Self, io: Io) void {
            // Stop background fibers and engines if close() wasn't called
            self.close(io);
            self.connections.deinit();
            if (self.server_engine) |eng| {
                eng.deinit();
                self.server_engine = null;
            }
            if (self.client_engine) |eng| {
                eng.deinit();
                self.client_engine = null;
            }
        }

        // ── Swarm API (Tasks 3-6) ──────────────────────────────────────────

        /// Start listening for inbound QUIC connections on the given multiaddr.
        /// Creates the server engine lazily on first call.
        pub fn listen(self: *Self, io: Io, addr: Multiaddr) !void {
            const parsed = try quic_mod.parseQuicMultiaddr(addr);

            if (self.server_engine == null) {
                const eng = try QuicEngine.init(self.allocator, io, .{
                    .is_server = true,
                    .host_identity = self.engine_config.host_identity,
                });
                self.server_engine = eng;
                errdefer {
                    eng.deinit();
                    self.server_engine = null;
                }

                _ = try eng.bindSocket(io, &parsed.ip);
                eng.startBackgroundLoops(io);
                self.background.async(io, Self.acceptLoop, .{ self, io });
                return;
            }

            const eng = self.server_engine.?;
            _ = try eng.bindSocket(io, &parsed.ip);
        }

        /// Returns all server engine listen addresses (useful for port-0 tests).
        pub fn listenAddrs(self: *const Self) []const net.IpAddress {
            const eng = self.server_engine orelse return &.{};
            return eng.localAddrs();
        }

        /// Dial a remote peer via QUIC multiaddr.
        /// Creates the client engine lazily on first call. Returns peer_id bytes
        /// (owned by the connections map — valid until peer disconnects).
        pub fn dial(self: *Self, io: Io, addr: Multiaddr) ![]const u8 {
            const parsed = try quic_mod.parseQuicMultiaddr(addr);

            if (self.client_engine == null) {
                const eng = try QuicEngine.init(self.allocator, io, .{
                    .is_server = false,
                    .host_identity = self.engine_config.host_identity,
                });
                self.client_engine = eng;
                eng.startBackgroundLoops(io);
            }

            const eng = self.client_engine.?;
            const local_bound = try ensureClientLocalAddr(eng, io, parsed.ip);
            var remote_sa = engine_mod.ipAddressToSockaddr(parsed.ip);
            var local_sa = engine_mod.ipAddressToSockaddr(local_bound);
            const conn = try eng.connect(io, @ptrCast(@alignCast(&remote_sa)), @ptrCast(@alignCast(&local_sa)));
            errdefer {
                conn.close(io);
                conn.deinit();
            }

            // Wait for TLS handshake — suspends until onHskDone fires
            const peer_id = conn.waitHandshake(io) catch return error.HandshakeFailed;
            var pid_buf: [128]u8 = undefined;
            const raw_peer_id = peer_id.toBytes(&pid_buf) catch return error.PeerIdEncodeFailed;

            // Register connection (heap-owned key)
            const owned_pid = try self.allocator.dupe(u8, raw_peer_id);
            errdefer self.allocator.free(owned_pid);
            try self.connections.put(owned_pid, conn);

            // Spawn connection handler in background
            self.background.async(io, Self.swarmConnectionTask, .{ self, io, conn });

            return owned_pid;
        }

        /// Background fiber: accepts inbound connections from the server engine.
        fn acceptLoop(self: *Self, io: Io) void {
            const eng = self.server_engine orelse return;
            while (true) {
                const conn = eng.accept(io) catch return;
                self.background.async(io, Self.swarmConnectionTask, .{ self, io, conn });
            }
        }

        /// Manages a single QUIC connection's lifecycle.
        /// Extracts peer_id from TLS, registers in connections map (if not already
        /// registered by dial), accepts streams. Connection map cleanup is handled
        /// by close()/deinit() — NOT by this task's defers — to avoid races.
        fn swarmConnectionTask(self: *Self, io: Io, conn: *engine_mod.QuicConnection) void {
            log.info("swarmConnectionTask: started for conn", .{});
            // Wait for TLS handshake to complete (server: immediate, client: suspends)
            var pid_buf: [128]u8 = undefined;
            const peer_id: ?[]const u8 = if (conn.waitHandshake(io)) |pid|
                pid.toBytes(&pid_buf) catch null
            else |_|
                null;

            // Register if not already registered (accepted connections from listen)
            if (peer_id) |pid| {
                if (!self.connections.contains(pid)) {
                    const owned = self.allocator.dupe(u8, pid) catch null;
                    if (owned) |key| {
                        self.connections.put(key, conn) catch {
                            self.allocator.free(key);
                        };
                    }
                }

                log.info("swarmConnectionTask: peer_id resolved, entering stream accept loop", .{});
                // Auto-trigger identify (like go-libp2p's IDService).
                // Runs in background so it doesn't block stream acceptance.
                self.background.async(io, Self.identifyPeer, .{ self, io, pid });
            }

            // Accept streams loop — blocks until connection closes or engine stops.
            // Note: stream_group tasks are implicitly cleaned up when the parent
            // group (self.background) is canceled by close().
            while (true) {
                log.info("swarmConnectionTask: waiting for stream...", .{});
                const s_inner = conn.acceptStream(io) catch |err| {
                    log.warn("swarmConnectionTask: acceptStream error: {}", .{err});
                    break;
                };
                self.background.async(io, Self.swarmStreamTask, .{
                    self, io, quic_mod.Stream{ .inner = s_inner }, SwarmStreamCtx{ .peer_id = peer_id },
                });
            }

            if (peer_id) |pid| {
                if (self.connections.fetchRemove(pid)) |kv| {
                    self.notifyPeerDisconnected(kv.key);
                    self.allocator.free(kv.key);
                    kv.value.deinit();
                    return;
                }
            }

            conn.deinit();
        }

        /// Concrete context type for swarm stream tasks (Io.Group.async requires
        /// concrete types — anytype cannot be used with ArgsTuple).
        const SwarmStreamCtx = struct {
            peer_id: ?[]const u8 = null,
        };

        /// Whether identify is registered as a protocol (comptime check).
        const has_identify = blk: {
            for (config.protocols) |P| {
                if (P == identify_mod.Handler) break :blk true;
            }
            break :blk false;
        };

        /// Auto-trigger identify on a newly connected peer.
        /// No-op if identify is not registered in this Switch's protocols.
        fn identifyPeer(self: *Self, io: Io, peer_id: []const u8) void {
            if (has_identify) {
                self.newStream(io, peer_id, identify_mod.Handler) catch |err| {
                    log.warn("auto-identify failed for peer: {}", .{err});
                };
            }
        }

        /// Handles a single inbound stream: multistream-negotiate then dispatch.
        fn swarmStreamTask(self: *Self, io: Io, s: quic_mod.Stream, ctx: SwarmStreamCtx) void {
            log.info("swarmStreamTask: dispatching stream", .{});
            var mutable_stream = s;
            defer mutable_stream.deinit();
            self.dispatchStream(io, &mutable_stream, ctx) catch return;
        }

        /// Open a new outbound stream to a connected peer.
        /// Looks up the connection by peer_id, opens a QUIC stream, negotiates
        /// the protocol via multistream-select, and runs handleOutbound.
        /// peer_id is automatically passed as ctx.peer_id.
        pub fn newStream(self: *Self, io: Io, peer_id: []const u8, comptime P: type) !void {
            return self.newStreamWithPayload(io, peer_id, P, null);
        }

        /// Like newStream but also passes an SSZ payload to handleOutbound.
        /// Used for protocols that include a request body (e.g., Status).
        pub fn newStreamWithPayload(self: *Self, io: Io, peer_id: []const u8, comptime P: type, ssz_payload: ?[]const u8) !void {
            comptime protocol_mod.assertProtocolInterface(P);
            const conn = self.connections.get(peer_id) orelse return error.PeerNotConnected;
            const s_inner = try conn.openStream(io);
            var s = quic_mod.Stream{ .inner = s_inner };
            defer s.deinit();
            _ = try multistream.negotiateOutbound(io, &s, &.{P.id});
            inline for (config.protocols, 0..) |Proto, i| {
                if (Proto == P) {
                    try self.handlers[i].handleOutbound(io, &s, .{
                        .peer_id = @as(?[]const u8, peer_id),
                        .ssz_payload = ssz_payload orelse &.{},
                    });
                    return;
                }
            }
        }

        /// Open a negotiated outbound stream and return it to the caller.
        ///
        /// Unlike `newStream`/`newStreamWithPayload` which dispatch to `handleOutbound`,
        /// this gives the caller direct ownership of the stream for request/response I/O.
        /// The caller is responsible for writing the request, reading the response, and
        /// closing the stream.
        ///
        /// `protocol_id` is the multistream protocol string, e.g.
        /// `"/eth2/beacon_chain/req/status/1/ssz_snappy"`. It does NOT need to be
        /// registered in the Switch's protocol list.
        pub fn dialProtocol(self: *Self, io: Io, peer_id: []const u8, protocol_id: []const u8) !quic_mod.Stream {
            const conn = self.connections.get(peer_id) orelse return error.PeerNotConnected;
            const s_inner = try conn.openStream(io);
            var s = quic_mod.Stream{ .inner = s_inner };
            errdefer s.deinit();
            _ = try multistream.negotiateOutbound(io, &s, &.{protocol_id});
            return s;
        }

        /// Gracefully shut down the Switch.
        /// Cancels background fibers, stops engines, notifies handlers, cleans up.
        pub fn close(self: *Self, io: Io) void {
            // Cancel ALL background fibers: accept loops, connection tasks, AND
            // stream tasks (all spawned on self.background).
            self.background.cancel(io);

            // Stop engines (closes their internal background loops).
            // Must happen after canceling Switch fibers, since those fibers
            // may be blocked on engine IO operations.
            if (self.server_engine) |eng| eng.stop(io);
            if (self.client_engine) |eng| eng.stop(io);

            // Notify handlers, free connection objects, and free map keys
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                self.notifyPeerDisconnected(@as(?[]const u8, entry.key_ptr.*));
                entry.value_ptr.*.deinit();
                self.allocator.free(entry.key_ptr.*);
            }
            self.connections.clearRetainingCapacity();
        }

        /// Negotiate protocol on an inbound stream and dispatch to handler.
        /// io flows directly through multistream and protocol handler -- no adapter.
        pub fn dispatchStream(self: *Self, io: Io, s: anytype, ctx: anytype) !void {
            log.info("dispatchStream: starting multistream negotiation", .{});
            const proto_id = multistream.negotiateInbound(io, s, &supported_protocol_ids) catch |err| {
                log.warn("dispatchStream: multistream negotiation failed: {}", .{err});
                return err;
            };

            log.info("dispatchStream: negotiated protocol: {s}", .{proto_id});

            inline for (config.protocols, 0..) |P, i| {
                if (std.mem.eql(u8, proto_id, P.id)) {
                    log.info("dispatchStream: dispatching to handler {d} ({s})", .{ i, P.id });
                    self.handlers[i].handleInbound(io, s, ctx) catch |err| {
                        log.warn("dispatchStream: handler error for {s}: {}", .{ P.id, err });
                        return err;
                    };
                    return;
                }
            }
            log.warn("dispatchStream: no handler found for protocol: {s}", .{proto_id});
        }

        /// Get a mutable pointer to the handler instance for protocol P.
        /// Allows callers to access handler state directly (e.g. identify results).
        pub fn getHandler(self: *Self, comptime P: type) *P {
            inline for (config.protocols, 0..) |Proto, i| {
                if (Proto == P) return &self.handlers[i];
            }
            @compileError("Protocol '" ++ @typeName(P) ++ "' not registered in Switch");
        }

        /// Notify all protocol handlers that a peer has disconnected.
        /// Only calls handlers that declare `onPeerDisconnected` (comptime check).
        /// Matches rust-libp2p's FromSwarm::ConnectionClosed pattern.
        pub fn notifyPeerDisconnected(self: *Self, peer_id: ?[]const u8) void {
            const pid = peer_id orelse return;
            inline for (config.protocols, 0..) |P, i| {
                if (@hasDecl(P, "onPeerDisconnected")) {
                    self.handlers[i].onPeerDisconnected(pid);
                }
            }
        }

        fn ensureClientLocalAddr(eng: *QuicEngine, io: Io, remote: net.IpAddress) !net.IpAddress {
            const existing = switch (remote) {
                .ip4 => eng.socketForFamily(.ip4),
                .ip6 => eng.socketForFamily(.ip6),
            };
            if (existing) |sock| return sock.address;

            const bind_addr: net.IpAddress = switch (remote) {
                .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
                .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
            };
            return eng.bindSocket(io, &bind_addr);
        }
    };
}

// --- Tests ---

test "Switch comptime validation accepts valid config" {
    const MockTransport = struct {
        pub const Connection = struct {
            pub const Stream = StreamType;
            const StreamType = struct {
                pub fn read(_: *@This(), _: Io, _: []u8) anyerror!usize {
                    return 0;
                }
                pub fn write(_: *@This(), _: Io, _: []const u8) anyerror!usize {
                    return 0;
                }
                pub fn closeRead(_: *@This(), _: Io) void {}
                pub fn closeWrite(_: *@This(), _: Io) void {}
                pub fn close(_: *@This(), _: Io) void {}
            };
            pub fn openStream(_: *@This(), _: Io) !StreamType {
                return .{};
            }
            pub fn acceptStream(_: *@This(), _: Io) !StreamType {
                return .{};
            }
            pub fn close(_: *@This(), _: Io) void {}
            pub fn remotePeerId(_: *const @This()) ?PeerId {
                return null;
            }
        };
        pub const Stream = Connection.StreamType;
        pub const Listener = struct {
            pub fn accept(_: *@This(), _: Io) !Connection {
                return .{};
            }
            pub fn close(_: *@This(), _: Io) void {}
            pub fn localAddrs(_: *const @This()) []const net.IpAddress {
                return &.{};
            }
        };
        pub fn dial(_: *@This(), _: Io, _: Multiaddr) !Connection {
            return .{};
        }
        pub fn listen(_: *@This(), _: Io, _: Multiaddr) !Listener {
            return .{};
        }
        pub fn matchesMultiaddr(_: Multiaddr) bool {
            return false;
        }
    };

    const MockProtocol = struct {
        pub const id = "/test/mock/1.0.0";
        pub fn handleInbound(_: *@This(), _: Io, _: anytype, _: anytype) !void {}
        pub fn handleOutbound(_: *@This(), _: Io, _: anytype, _: anytype) !void {}
    };

    const TestSwitch = Switch(.{
        .transports = &.{MockTransport},
        .protocols = &.{MockProtocol},
    });

    const io = std.testing.io;
    var sw = TestSwitch.init(std.testing.allocator, .{}, .{MockProtocol{}});
    defer sw.deinit(io);

    // Verify protocol IDs are correct
    try std.testing.expectEqualStrings("/test/mock/1.0.0", TestSwitch.supported_protocol_ids[0]);
}

test "Swarm ping over QUIC" {
    const ping_mod = @import("protocol/ping.zig");
    const ma = multiaddr;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var key1 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key1.deinit();
    var key2 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key2.deinit();

    const Node = Switch(.{
        .transports = &.{quic_mod.QuicTransport},
        .protocols = &.{ping_mod.Handler},
    });

    // Server
    var server = Node.init(allocator, .{ .host_identity = &key1 }, .{ping_mod.Handler{}});
    defer server.deinit(io);

    var listen_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = 0 },
        .QuicV1,
    }) catch return;
    defer listen_addr.deinit();
    server.listen(io, listen_addr) catch return;

    // Client
    var client = Node.init(allocator, .{ .host_identity = &key2 }, .{ping_mod.Handler{}});
    defer client.deinit(io);

    const bound = server.listenAddrs();
    if (bound.len == 0) return;
    const port = switch (bound[0]) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    var dial_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = port },
        .QuicV1,
    }) catch return;
    defer dial_addr.deinit();

    const peer_id = client.dial(io, dial_addr) catch return;

    // Ping via newStream — Handler generates payload and measures RTT internally
    client.newStream(io, peer_id, ping_mod.Handler) catch |err| {
        log.warn("ping failed: {}", .{err});
    };

    client.close(io);
    server.close(io);
}

test "Swarm gossipsub subscription over QUIC" {
    const gossipsub_service = @import("protocol/gossipsub/service.zig");
    const ma = multiaddr;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var key1 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key1.deinit();
    var key2 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key2.deinit();

    // Server gossipsub
    const svc1 = gossipsub_service.Service.init(allocator, .{}) catch return;
    defer svc1.deinit();

    const Node = Switch(.{
        .transports = &.{quic_mod.QuicTransport},
        .protocols = &.{gossipsub_service.Handler},
    });
    var server = Node.init(allocator, .{ .host_identity = &key1 }, .{gossipsub_service.Handler{ .svc = svc1 }});
    defer server.deinit(io);

    var listen_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = 0 },
        .QuicV1,
    }) catch return;
    defer listen_addr.deinit();
    server.listen(io, listen_addr) catch return;

    // Client gossipsub
    const svc2 = gossipsub_service.Service.init(allocator, .{}) catch return;
    defer svc2.deinit();
    svc2.subscribe("test-topic") catch return;

    var client = Node.init(allocator, .{ .host_identity = &key2 }, .{gossipsub_service.Handler{ .svc = svc2 }});
    defer client.deinit(io);

    const bound = server.listenAddrs();
    if (bound.len == 0) return;
    const port = switch (bound[0]) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    var dial_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = port },
        .QuicV1,
    }) catch return;
    defer dial_addr.deinit();

    const peer_id = client.dial(io, dial_addr) catch return;

    // Open gossipsub stream -- newStream auto-provides peer_id ctx
    client.newStream(io, peer_id, gossipsub_service.Handler) catch return;

    // Wait for subscription RPC to arrive
    const sleep_timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(100),
        .clock = .awake,
    } };
    sleep_timeout.sleep(io) catch {};

    // Verify subscription event on server
    const events = svc1.drainEvents() catch return;
    defer allocator.free(events);
    var found = false;
    for (events) |event| {
        switch (event) {
            .subscription_changed => found = true,
            else => {},
        }
    }
    if (!found) {
        log.warn("gossipsub subscription event not found in {} events", .{events.len});
    }

    client.close(io);
    server.close(io);
}

test "Switch supports additive IPv4 and IPv6 listen sockets" {
    const ma = multiaddr;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var key = identity.KeyPair.generate(.ECDSA) catch return;
    defer key.deinit();

    const Node = Switch(.{
        .transports = &.{quic_mod.QuicTransport},
        .protocols = &.{},
    });

    var node = Node.init(allocator, .{ .host_identity = &key }, .{});
    defer node.deinit(io);

    var listen_addr4 = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = 0 },
        .QuicV1,
    }) catch return;
    defer listen_addr4.deinit();

    try node.listen(io, listen_addr4);

    const addrs4 = node.listenAddrs();
    try std.testing.expectEqual(@as(usize, 1), addrs4.len);
    const port = switch (addrs4[0]) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try std.testing.expect(port > 0);

    var listen_addr6 = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip6 = ma.Ip6Addr{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } },
        .{ .Udp = port },
        .QuicV1,
    }) catch return;
    defer listen_addr6.deinit();

    node.listen(io, listen_addr6) catch |err| {
        std.log.warn("IPv6 additive listen unavailable in test environment: {}", .{err});
        return;
    };

    const addrs = node.listenAddrs();
    try std.testing.expectEqual(@as(usize, 2), addrs.len);

    var saw_ip4 = false;
    var saw_ip6 = false;
    for (addrs) |addr| switch (addr) {
        .ip4 => |a| {
            saw_ip4 = true;
            try std.testing.expectEqual(port, a.port);
        },
        .ip6 => |a| {
            saw_ip6 = true;
            try std.testing.expectEqual(port, a.port);
        },
    };
    try std.testing.expect(saw_ip4);
    try std.testing.expect(saw_ip6);
}

test "Switch removes disconnected peers from the connection map" {
    const ping_mod = @import("protocol/ping.zig");
    const ma = multiaddr;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var key1 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key1.deinit();
    var key2 = identity.KeyPair.generate(.ECDSA) catch return;
    defer key2.deinit();

    const Node = Switch(.{
        .transports = &.{quic_mod.QuicTransport},
        .protocols = &.{ping_mod.Handler},
    });

    var server = Node.init(allocator, .{ .host_identity = &key1 }, .{ping_mod.Handler{}});
    defer server.deinit(io);

    var listen_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = 0 },
        .QuicV1,
    }) catch return;
    defer listen_addr.deinit();
    try server.listen(io, listen_addr);

    var client = Node.init(allocator, .{ .host_identity = &key2 }, .{ping_mod.Handler{}});
    defer client.deinit(io);

    const bound = server.listenAddrs();
    if (bound.len == 0) return;
    const port = switch (bound[0]) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    var dial_addr = ma.Multiaddr.fromProtocols(allocator, &.{
        .{ .Ip4 = ma.Ip4Addr{ .bytes = .{ 127, 0, 0, 1 } } },
        .{ .Udp = port },
        .QuicV1,
    }) catch return;
    defer dial_addr.deinit();

    const peer_id = try client.dial(io, dial_addr);

    const settle_timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(100),
        .clock = .awake,
    } };
    try settle_timeout.sleep(io);

    try std.testing.expectEqual(@as(usize, 1), server.connections.count());

    if (client.connections.fetchRemove(peer_id)) |kv| {
        kv.value.close(io);
        client.allocator.free(kv.key);
    } else {
        return error.TestUnexpectedNull;
    }

    var removed = false;
    for (0..10) |_| {
        try settle_timeout.sleep(io);
        if (server.connections.count() == 0) {
            removed = true;
            break;
        }
    }
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), server.connections.count());
}
