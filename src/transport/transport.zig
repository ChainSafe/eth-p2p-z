const std = @import("std");
const Io = std.Io;
const Multiaddr = @import("multiaddr").Multiaddr;
const PeerId = @import("peer_id").PeerId;

fn assertFnParamTypes(
    comptime owner: type,
    comptime name: []const u8,
    comptime expected_params: []const type,
) void {
    const fn_type = @TypeOf(@field(owner, name));
    const fn_info = switch (@typeInfo(fn_type)) {
        .@"fn" => |info| info,
        else => @compileError("Decl '" ++ @typeName(owner) ++ "." ++ name ++ "' is not a function"),
    };

    if (fn_info.params.len != expected_params.len) {
        @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' has the wrong number of parameters");
    }

    inline for (expected_params, 0..) |expected, i| {
        const actual = fn_info.params[i].type orelse {
            @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' parameter " ++ std.fmt.comptimePrint("{d}", .{i}) ++ " has no concrete type");
        };
        if (actual != expected) {
            @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' parameter " ++ std.fmt.comptimePrint("{d}", .{i}) ++ " has the wrong type");
        }
    }
}

fn assertReturnType(comptime owner: type, comptime name: []const u8, comptime expected_return: type) void {
    const fn_info = @typeInfo(@TypeOf(@field(owner, name))).@"fn";
    const actual = fn_info.return_type orelse {
        @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' has no return type");
    };
    if (actual != expected_return) {
        @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' has the wrong return type");
    }
}

fn assertErrorUnionPayload(comptime owner: type, comptime name: []const u8, comptime expected_payload: type) void {
    const fn_info = @typeInfo(@TypeOf(@field(owner, name))).@"fn";
    const actual = fn_info.return_type orelse {
        @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' has no return type");
    };
    switch (@typeInfo(actual)) {
        .error_union => |err| {
            if (err.payload != expected_payload) {
                @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' has the wrong success payload type");
            }
        },
        else => @compileError("Method '" ++ @typeName(owner) ++ "." ++ name ++ "' must return an error union"),
    }
}

/// Asserts at comptime that type T satisfies the Transport interface.
/// A Transport must provide:
///   - Connection type with: openStream, acceptStream, close, remotePeerId
///   - Stream type with: read, write, close
///   - Listener type with: accept, close, localAddr
///   - fn dial(self: *Self, io: std.Io, addr: Multiaddr) DialError!Connection
///   - fn listen(self: *Self, io: std.Io, addr: Multiaddr) ListenError!Listener
///   - fn matchesMultiaddr(addr: Multiaddr) bool
///
/// `remoteAddr` is transport-specific and optional because returning a concrete
/// `Multiaddr` usually requires allocation/lifetime policy that this interface
/// does not model.
pub fn assertTransportInterface(comptime T: type) void {
    // Required associated types
    if (!@hasDecl(T, "Connection")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'Connection' type");
    }
    if (!@hasDecl(T, "Stream")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'Stream' type");
    }
    if (!@hasDecl(T, "Listener")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'Listener' type");
    }

    // Required methods
    if (!@hasDecl(T, "dial")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'dial' method");
    }
    if (!@hasDecl(T, "listen")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'listen' method");
    }
    if (!@hasDecl(T, "matchesMultiaddr")) {
        @compileError("Transport '" ++ @typeName(T) ++ "' missing 'matchesMultiaddr' method");
    }

    // Validate associated types
    const Conn = T.Connection;
    const Stream = T.Stream;
    const Listener = T.Listener;

    // Validate Connection type
    if (!@hasDecl(Conn, "openStream")) {
        @compileError("Connection type of '" ++ @typeName(T) ++ "' missing 'openStream'");
    }
    if (!@hasDecl(Conn, "acceptStream")) {
        @compileError("Connection type of '" ++ @typeName(T) ++ "' missing 'acceptStream'");
    }
    if (!@hasDecl(Conn, "close")) {
        @compileError("Connection type of '" ++ @typeName(T) ++ "' missing 'close'");
    }
    if (!@hasDecl(Conn, "remotePeerId")) {
        @compileError("Connection type of '" ++ @typeName(T) ++ "' missing 'remotePeerId'");
    }
    assertFnParamTypes(Conn, "openStream", &.{ *Conn, Io });
    assertErrorUnionPayload(Conn, "openStream", Stream);
    assertFnParamTypes(Conn, "acceptStream", &.{ *Conn, Io });
    assertErrorUnionPayload(Conn, "acceptStream", Stream);
    assertFnParamTypes(Conn, "close", &.{ *Conn, Io });
    assertReturnType(Conn, "close", void);
    assertFnParamTypes(Conn, "remotePeerId", &.{*const Conn});
    assertReturnType(Conn, "remotePeerId", ?PeerId);

    // Validate Stream type
    if (!@hasDecl(Stream, "read")) {
        @compileError("Stream type of '" ++ @typeName(T) ++ "' missing 'read'");
    }
    if (!@hasDecl(Stream, "write")) {
        @compileError("Stream type of '" ++ @typeName(T) ++ "' missing 'write'");
    }
    if (!@hasDecl(Stream, "close")) {
        @compileError("Stream type of '" ++ @typeName(T) ++ "' missing 'close'");
    }
    assertFnParamTypes(Stream, "read", &.{ *Stream, Io, []u8 });
    assertErrorUnionPayload(Stream, "read", usize);
    assertFnParamTypes(Stream, "write", &.{ *Stream, Io, []const u8 });
    assertErrorUnionPayload(Stream, "write", usize);
    assertFnParamTypes(Stream, "close", &.{ *Stream, Io });
    assertReturnType(Stream, "close", void);

    // Validate Listener type
    if (!@hasDecl(Listener, "accept")) {
        @compileError("Listener type of '" ++ @typeName(T) ++ "' missing 'accept'");
    }
    if (!@hasDecl(Listener, "close")) {
        @compileError("Listener type of '" ++ @typeName(T) ++ "' missing 'close'");
    }
    if (!@hasDecl(Listener, "localAddr")) {
        @compileError("Listener type of '" ++ @typeName(T) ++ "' missing 'localAddr'");
    }
    assertFnParamTypes(Listener, "accept", &.{ *Listener, Io });
    assertErrorUnionPayload(Listener, "accept", Conn);
    assertFnParamTypes(Listener, "close", &.{ *Listener, Io });
    assertReturnType(Listener, "close", void);
    assertFnParamTypes(Listener, "localAddr", &.{*const Listener});
    assertReturnType(Listener, "localAddr", ?Io.net.IpAddress);

    assertFnParamTypes(T, "dial", &.{ *T, Io, Multiaddr });
    assertErrorUnionPayload(T, "dial", Conn);
    assertFnParamTypes(T, "listen", &.{ *T, Io, Multiaddr });
    assertErrorUnionPayload(T, "listen", Listener);
    assertFnParamTypes(T, "matchesMultiaddr", &.{Multiaddr});
    assertReturnType(T, "matchesMultiaddr", bool);
}

/// Asserts at comptime that type S satisfies the Stream interface.
pub fn assertStreamInterface(comptime S: type) void {
    if (!@hasDecl(S, "read")) @compileError("Stream '" ++ @typeName(S) ++ "' missing 'read'");
    if (!@hasDecl(S, "write")) @compileError("Stream '" ++ @typeName(S) ++ "' missing 'write'");
    if (!@hasDecl(S, "close")) @compileError("Stream '" ++ @typeName(S) ++ "' missing 'close'");
    assertFnParamTypes(S, "read", &.{ *S, Io, []u8 });
    assertErrorUnionPayload(S, "read", usize);
    assertFnParamTypes(S, "write", &.{ *S, Io, []const u8 });
    assertErrorUnionPayload(S, "write", usize);
    assertFnParamTypes(S, "close", &.{ *S, Io });
    assertReturnType(S, "close", void);
}

/// Type-erased stream for heterogeneous storage at the application boundary.
/// This is the ONLY VTable in the system.
pub const AnyStream = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readFn: *const fn (ptr: *anyopaque, io: Io, buf: []u8) anyerror!usize,
        writeFn: *const fn (ptr: *anyopaque, io: Io, data: []const u8) anyerror!usize,
        closeFn: *const fn (ptr: *anyopaque, io: Io) void,
    };

    pub fn read(self: AnyStream, io: Io, buf: []u8) anyerror!usize {
        return self.vtable.readFn(self.ptr, io, buf);
    }

    pub fn write(self: AnyStream, io: Io, data: []const u8) anyerror!usize {
        return self.vtable.writeFn(self.ptr, io, data);
    }

    pub fn close(self: AnyStream, io: Io) void {
        self.vtable.closeFn(self.ptr, io);
    }

    pub fn wrap(comptime StreamT: type, stream: *StreamT) AnyStream {
        const Wrapper = struct {
            fn readFn(ptr: *anyopaque, io: Io, buf: []u8) anyerror!usize {
                const s: *StreamT = @ptrCast(@alignCast(ptr));
                return s.read(io, buf);
            }
            fn writeFn(ptr: *anyopaque, io: Io, data: []const u8) anyerror!usize {
                const s: *StreamT = @ptrCast(@alignCast(ptr));
                return s.write(io, data);
            }
            fn closeFn(ptr: *anyopaque, io: Io) void {
                const s: *StreamT = @ptrCast(@alignCast(ptr));
                s.close(io);
            }
            const vtable_instance = VTable{
                .readFn = readFn,
                .writeFn = writeFn,
                .closeFn = closeFn,
            };
        };
        return .{
            .ptr = @ptrCast(stream),
            .vtable = &Wrapper.vtable_instance,
        };
    }
};

test "assertTransportInterface catches missing types" {
    const BadTransport = struct {};
    // This should fail at comptime:
    // comptime assertTransportInterface(BadTransport);
    // We can't test compile errors directly, but we verify the function exists
    _ = &assertTransportInterface;
    _ = BadTransport;
}

test "AnyStream wrap creates valid vtable" {
    const MockStream = struct {
        pub fn read(_: *@This(), _: Io, _: []u8) anyerror!usize {
            return 1;
        }
        pub fn write(_: *@This(), _: Io, _: []const u8) anyerror!usize {
            return 5;
        }
        pub fn close(_: *@This(), _: Io) void {}
    };

    var mock = MockStream{};
    const any = AnyStream.wrap(MockStream, &mock);
    // Verify ptr was set correctly
    try std.testing.expectEqual(@as(*anyopaque, @ptrCast(&mock)), any.ptr);
}
