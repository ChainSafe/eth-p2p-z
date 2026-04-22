const std = @import("std");
const rpc = @import("../../proto/rpc.proto.zig");

/// Function type for computing message IDs from a Message.
pub const MessageIdFn = *const fn (allocator: std.mem.Allocator, message: *const rpc.Message) anyerror![]const u8;

/// Default message ID: concatenate `from` and `seqno` fields.
pub fn defaultMsgId(allocator: std.mem.Allocator, msg: *const rpc.Message) error{ BothFromAndSeqNoNull, OutOfMemory }![]const u8 {
    if (msg.from == null and msg.seqno == null) {
        return error.BothFromAndSeqNoNull;
    }
    return std.mem.concat(allocator, u8, &.{ msg.from orelse "", msg.seqno orelse "" });
}

pub const EntryState = enum {
    missing,
    pending,
    validated,
    discarded,
};

pub const PendingValidationStats = struct {
    count: usize = 0,
    retained_bytes: usize = 0,
    oldest_age_ms: ?u64 = null,
};

const PendingOriginPeers = std.StringHashMap(void);

const PendingMetadata = struct {
    source_peer: []const u8,
    first_seen_ms: u64,
    originating_peers: PendingOriginPeers,

    fn init(allocator: std.mem.Allocator, source_peer: []const u8, first_seen_ms: u64) !PendingMetadata {
        var originating_peers = PendingOriginPeers.init(allocator);
        errdefer originating_peers.deinit();

        const owned_source_peer = try allocator.dupe(u8, source_peer);
        errdefer allocator.free(owned_source_peer);

        const gop = try originating_peers.getOrPut(source_peer);
        if (!gop.found_existing) {
            gop.key_ptr.* = owned_source_peer;
            gop.value_ptr.* = {};
        } else {
            allocator.free(owned_source_peer);
        }

        return .{
            .source_peer = gop.key_ptr.*,
            .first_seen_ms = first_seen_ms,
            .originating_peers = originating_peers,
        };
    }

    fn notePeer(self: *PendingMetadata, allocator: std.mem.Allocator, peer_id: []const u8) !bool {
        const owned_peer_id = try allocator.dupe(u8, peer_id);
        errdefer allocator.free(owned_peer_id);

        const gop = try self.originating_peers.getOrPut(peer_id);
        if (gop.found_existing) {
            allocator.free(owned_peer_id);
            return false;
        }
        gop.key_ptr.* = owned_peer_id;
        gop.value_ptr.* = {};
        return true;
    }

    fn retainedBytes(self: *const PendingMetadata, mid_len: usize, backing_len: usize) usize {
        var total = mid_len + backing_len;
        var iter = self.originating_peers.keyIterator();
        while (iter.next()) |key| {
            total += key.*.len;
        }
        return total;
    }

    fn deinit(self: *PendingMetadata, allocator: std.mem.Allocator) void {
        var iter = self.originating_peers.keyIterator();
        while (iter.next()) |key| {
            allocator.free(key.*);
        }
        self.originating_peers.deinit();
        self.* = undefined;
    }
};

/// A message stored in the cache with a single contiguous backing buffer.
/// All slices in `message` point into `backing`. Freeing `backing` releases
/// all field data in one allocation.
const StoredMessage = struct {
    message: rpc.Message,
    backing: []u8,
    validation: Validation,

    const Validation = union(enum) {
        validated,
        pending: PendingMetadata,
        discarded,
    };

    fn entryState(self: *const StoredMessage) EntryState {
        return switch (self.validation) {
            .validated => .validated,
            .pending => .pending,
            .discarded => .discarded,
        };
    }

    fn deinit(self: *StoredMessage, allocator: std.mem.Allocator) void {
        switch (self.validation) {
            .pending => |*pending| pending.deinit(allocator),
            else => {},
        }
        allocator.free(self.backing);
        self.* = undefined;
    }
};

/// Sliding-window message cache for GossipSub.
///
/// Messages are stored in a map for fast lookup and tracked in a sliding
/// window for age-based eviction. Entries may remain pending application
/// validation inside the cache before they are marked validated for gossip,
/// forwarding, and IWANT fulfillment. Per-peer transmission counts prevent
/// duplicate sends during IWANT fulfillment.
///
/// The first `gossip_window_count` windows are included in IHAVE gossip.
/// On each `shift()`, windows slide right and the oldest window is evicted.
///
/// ## Allocation strategy
///
/// Each stored message uses a single contiguous backing buffer for all field
/// data (from, seqno, topic, data, signature, key). This reduces allocations
/// per `put()` from 7 to 2 (message ID + backing buffer) and makes `shift()`
/// eviction cheaper with only 2 frees per message.
pub const MessageCache = struct {
    allocator: std.mem.Allocator,
    msgs: std.StringHashMap(StoredMessage),
    peertx: std.StringHashMap(PeerTransmissionMap),
    history: std.ArrayList(?std.ArrayList(CacheEntry)),
    gossip_window_count: u32,
    msg_id_fn: MessageIdFn,
    pending_unvalidated_count: usize,

    /// Maps a peer identifier (arbitrary bytes) to its transmission count.
    const PeerTransmissionMap = std.StringHashMap(i32);

    const CacheEntry = struct {
        mid: []const u8,
        topic: []const u8,
    };

    pub const Error = error{
        DuplicateMessage,
        MissingTopic,
        HistoryLengthExceeded,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        gossip_window_count: u32,
        history_size: u32,
        msg_id_fn: MessageIdFn,
    ) (Error || error{OutOfMemory})!MessageCache {
        if (gossip_window_count > history_size) {
            return Error.HistoryLengthExceeded;
        }

        var history: std.ArrayList(?std.ArrayList(CacheEntry)) = .empty;
        errdefer history.deinit(allocator);

        try history.resize(allocator, history_size);
        @memset(history.items, null);
        history.items[0] = .empty;

        return MessageCache{
            .allocator = allocator,
            .msgs = std.StringHashMap(StoredMessage).init(allocator),
            .peertx = std.StringHashMap(PeerTransmissionMap).init(allocator),
            .history = history,
            .gossip_window_count = gossip_window_count,
            .msg_id_fn = msg_id_fn,
            .pending_unvalidated_count = 0,
        };
    }

    pub fn deinit(self: *MessageCache) void {
        var msgs_iter = self.msgs.iterator();
        while (msgs_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.msgs.deinit();

        var peertx_iter = self.peertx.iterator();
        while (peertx_iter.next()) |entry| {
            var peer_map = entry.value_ptr.*;
            var key_iter = peer_map.keyIterator();
            while (key_iter.next()) |key| {
                self.allocator.free(key.*);
            }
            peer_map.deinit();
        }
        self.peertx.deinit();

        for (self.history.items) |maybe_window| {
            if (maybe_window) |w| {
                var window = w;
                window.deinit(self.allocator);
            }
        }
        self.history.deinit(self.allocator);

        self.* = undefined;
    }

    /// Store a message. Generates the message ID via `msg_id_fn`.
    /// Returns `DuplicateMessage` if the ID already exists.
    pub fn put(self: *MessageCache, msg: *const rpc.Message) !void {
        const mid = try self.msg_id_fn(self.allocator, msg);
        defer self.allocator.free(mid);
        try self.putWithId(mid, msg);
    }

    /// Store a message with a pre-computed ID.
    pub fn putWithId(self: *MessageCache, mid: []const u8, msg: *const rpc.Message) !void {
        var stored = try cloneMessage(self.allocator, msg, .validated);
        var caller_owns_stored = true;
        errdefer if (caller_owns_stored) stored.deinit(self.allocator);

        try self.insertStoredWithId(mid, &stored, &caller_owns_stored);
        std.debug.assert(!caller_owns_stored);
    }

    pub fn putPendingWithId(self: *MessageCache, mid: []const u8, msg: *const rpc.Message, source_peer: []const u8, first_seen_ms: u64) !void {
        var pending = try PendingMetadata.init(self.allocator, source_peer, first_seen_ms);
        var pending_consumed = false;
        errdefer if (!pending_consumed) pending.deinit(self.allocator);

        var stored = try cloneMessage(self.allocator, msg, .{ .pending = pending });
        pending_consumed = true;
        var caller_owns_stored = true;
        errdefer if (caller_owns_stored) stored.deinit(self.allocator);

        try self.insertStoredWithId(mid, &stored, &caller_owns_stored);
        std.debug.assert(!caller_owns_stored);
        self.pending_unvalidated_count += 1;
    }

    pub fn entryState(self: *const MessageCache, mid: []const u8) EntryState {
        const stored = self.msgs.get(mid) orelse return .missing;
        return stored.entryState();
    }

    pub fn pendingCount(self: *const MessageCache) usize {
        return self.pending_unvalidated_count;
    }

    pub fn pendingValidationStats(self: *const MessageCache, now_ms: u64) PendingValidationStats {
        var stats = PendingValidationStats{};

        var iter = self.msgs.iterator();
        while (iter.next()) |entry| {
            const stored = entry.value_ptr;
            switch (stored.validation) {
                .pending => |*pending| {
                    stats.count += 1;
                    stats.retained_bytes += pending.retainedBytes(entry.key_ptr.*.len, stored.backing.len);
                    const age_ms = now_ms -| pending.first_seen_ms;
                    if (stats.oldest_age_ms == null or age_ms > stats.oldest_age_ms.?) {
                        stats.oldest_age_ms = age_ms;
                    }
                },
                else => {},
            }
        }

        return stats;
    }

    pub fn notePendingOriginatingPeer(self: *MessageCache, mid: []const u8, peer_id: []const u8) !bool {
        const stored = self.msgs.getPtr(mid) orelse return false;
        switch (stored.validation) {
            .pending => |*pending| return pending.notePeer(self.allocator, peer_id),
            else => return false,
        }
    }

    pub fn listPendingOriginatingPeers(self: *const MessageCache, allocator: std.mem.Allocator, mid: []const u8) !?[][]const u8 {
        const stored = self.msgs.get(mid) orelse return null;
        switch (stored.validation) {
            .pending => |pending| {
                var peers: std.ArrayList([]const u8) = .empty;
                errdefer peers.deinit(allocator);

                var iter = pending.originating_peers.keyIterator();
                while (iter.next()) |key| {
                    try peers.append(allocator, key.*);
                }

                return @as(?[][]const u8, try peers.toOwnedSlice(allocator));
            },
            else => return null,
        }
    }

    pub fn sourcePeer(self: *const MessageCache, mid: []const u8) ?[]const u8 {
        const stored = self.msgs.get(mid) orelse return null;
        return switch (stored.validation) {
            .pending => |pending| pending.source_peer,
            else => null,
        };
    }

    pub fn pendingContainsOriginatingPeer(self: *const MessageCache, mid: []const u8, peer_id: []const u8) bool {
        const stored = self.msgs.get(mid) orelse return false;
        return switch (stored.validation) {
            .pending => |pending| pending.originating_peers.contains(peer_id),
            else => false,
        };
    }

    pub fn visitPendingOriginatingPeers(self: *const MessageCache, mid: []const u8, context: anytype, comptime visit: fn (@TypeOf(context), []const u8) void) bool {
        const stored = self.msgs.get(mid) orelse return false;
        switch (stored.validation) {
            .pending => |pending| {
                var iter = pending.originating_peers.keyIterator();
                while (iter.next()) |key| {
                    visit(context, key.*);
                }
                return true;
            },
            else => return false,
        }
    }

    pub fn markValidated(self: *MessageCache, mid: []const u8) bool {
        const stored = self.msgs.getPtr(mid) orelse return false;
        switch (stored.validation) {
            .pending => |*pending| {
                pending.deinit(self.allocator);
                stored.validation = .validated;
                std.debug.assert(self.pending_unvalidated_count > 0);
                self.pending_unvalidated_count -= 1;
                const topic = stored.message.topic orelse return true;
                if (!self.moveHistoryEntryToCurrent(mid, topic)) {
                    _ = self.remove(mid);
                }
                return true;
            },
            .validated => return true,
            .discarded => return false,
        }
    }

    pub fn discard(self: *MessageCache, mid: []const u8) bool {
        const stored = self.msgs.getPtr(mid) orelse return false;
        switch (stored.validation) {
            .pending => |*pending| {
                pending.deinit(self.allocator);
                stored.validation = .discarded;
                std.debug.assert(self.pending_unvalidated_count > 0);
                self.pending_unvalidated_count -= 1;
            },
            .validated => stored.validation = .discarded,
            .discarded => {},
        }
        self.clearPeerTransmissions(mid);
        return true;
    }

    pub fn remove(self: *MessageCache, mid: []const u8) bool {
        self.clearPeerTransmissions(mid);
        self.removeHistoryEntries(mid);
        if (self.msgs.fetchRemove(mid)) |kv| {
            if (kv.value.entryState() == .pending) {
                std.debug.assert(self.pending_unvalidated_count > 0);
                self.pending_unvalidated_count -= 1;
            }
            self.allocator.free(kv.key);
            var removed = kv.value;
            removed.deinit(self.allocator);
            return true;
        }
        return false;
    }

    /// Look up a message by ID.
    pub fn get(self: *MessageCache, mid: []const u8) ?*rpc.Message {
        const stored = self.msgs.getPtr(mid) orelse return null;
        if (stored.entryState() == .discarded) return null;
        return &stored.message;
    }

    /// Look up a message and track per-peer transmission count.
    /// Returns null if the message is not found.
    pub fn getForPeer(self: *MessageCache, mid: []const u8, peer_id: []const u8) !?struct { msg: *rpc.Message, count: i32 } {
        const stored = self.msgs.getPtr(mid) orelse return null;
        if (stored.entryState() != .validated) return null;

        const tx_result = try self.peertx.getOrPut(self.msgs.getKey(mid).?);
        if (!tx_result.found_existing) {
            tx_result.value_ptr.* = PeerTransmissionMap.init(self.allocator);
        }

        const peer_result = try tx_result.value_ptr.getOrPut(peer_id);
        if (!peer_result.found_existing) {
            peer_result.key_ptr.* = try self.allocator.dupe(u8, peer_id);
            peer_result.value_ptr.* = 0;
        }
        peer_result.value_ptr.* += 1;

        return .{ .msg = &stored.message, .count = peer_result.value_ptr.* };
    }

    /// Return message IDs from the gossip windows for a given topic.
    /// Caller owns the returned slice.
    pub fn getGossipIDs(self: *MessageCache, topic: []const u8) ![][]const u8 {
        var mids: std.ArrayList([]const u8) = .empty;
        errdefer mids.deinit(self.allocator);

        for (0..self.gossip_window_count) |i| {
            if (self.history.items[i]) |*window| {
                for (window.items) |entry| {
                    const stored = self.msgs.get(entry.mid) orelse continue;
                    if (stored.entryState() == .validated and std.mem.eql(u8, entry.topic, topic)) {
                        try mids.append(self.allocator, entry.mid);
                    }
                }
            }
        }

        return mids.toOwnedSlice(self.allocator);
    }

    /// Slide the window: evict the oldest window and create a new current one.
    pub fn shift(self: *MessageCache) void {
        const history_len = self.history.items.len;
        if (history_len == 0) return;

        var retained_last_window = self.history.items[history_len - 1];
        if (retained_last_window) |*last_window| {
            var i: usize = 0;
            while (i < last_window.items.len) {
                const entry = last_window.items[i];
                const stored = self.msgs.get(entry.mid) orelse {
                    _ = last_window.orderedRemove(i);
                    continue;
                };
                if (stored.entryState() == .pending) {
                    i += 1;
                    continue;
                }

                self.clearPeerTransmissions(entry.mid);
                if (self.msgs.fetchRemove(entry.mid)) |*kv| {
                    self.allocator.free(kv.key);
                    var removed = kv.value;
                    removed.deinit(self.allocator);
                }
                _ = last_window.orderedRemove(i);
            }
        }

        if (history_len > 1) {
            std.mem.copyBackwards(
                ?std.ArrayList(CacheEntry),
                self.history.items[1..],
                self.history.items[0 .. history_len - 1],
            );
        }

        self.history.items[0] = .empty;
        if (retained_last_window) |last_window| {
            if (last_window.items.len == 0) {
                var empty_last_window = last_window;
                empty_last_window.deinit(self.allocator);
            } else if (self.history.items[history_len - 1]) |*existing_last_window| {
                for (last_window.items) |entry| {
                    existing_last_window.append(self.allocator, entry) catch {
                        _ = self.remove(entry.mid);
                    };
                }
                var merged_last_window = last_window;
                merged_last_window.deinit(self.allocator);
            } else {
                self.history.items[history_len - 1] = last_window;
            }
        }
    }

    fn insertStoredWithId(self: *MessageCache, mid: []const u8, stored: *StoredMessage, caller_owns_stored: *bool) !void {
        const topic = stored.message.topic orelse return Error.MissingTopic;

        const cloned_key = try self.allocator.dupe(u8, mid);
        var key_consumed = false;
        errdefer if (!key_consumed) self.allocator.free(cloned_key);

        const gop = try self.msgs.getOrPut(mid);
        if (gop.found_existing) {
            return Error.DuplicateMessage;
        }

        var inserted_into_map = false;
        errdefer if (inserted_into_map) {
            if (self.msgs.fetchRemove(cloned_key)) |kv| {
                self.allocator.free(kv.key);
                var removed = kv.value;
                removed.deinit(self.allocator);
            }
        };

        gop.key_ptr.* = cloned_key;
        gop.value_ptr.* = stored.*;
        caller_owns_stored.* = false;
        stored.* = undefined;
        key_consumed = true;
        inserted_into_map = true;

        try self.history.items[0].?.append(self.allocator, .{
            .mid = cloned_key,
            .topic = topic,
        });
    }

    fn clearPeerTransmissions(self: *MessageCache, mid: []const u8) void {
        if (self.peertx.fetchRemove(mid)) |*kv| {
            var peer_map = kv.value;
            var key_iter = peer_map.keyIterator();
            while (key_iter.next()) |key| {
                self.allocator.free(key.*);
            }
            peer_map.deinit();
        }
    }

    fn moveHistoryEntryToCurrent(self: *MessageCache, mid: []const u8, topic: []const u8) bool {
        if (!self.historyContains(0, mid)) {
            self.history.items[0].?.append(self.allocator, .{
                .mid = self.msgs.getKey(mid) orelse return false,
                .topic = topic,
            }) catch return false;
        }
        self.removeHistoryEntriesFromOffset(mid, 1);
        return true;
    }

    fn removeHistoryEntries(self: *MessageCache, mid: []const u8) void {
        self.removeHistoryEntriesFromOffset(mid, 0);
    }

    fn removeHistoryEntriesFromOffset(self: *MessageCache, mid: []const u8, start_window: usize) void {
        for (self.history.items[start_window..]) |*maybe_window| {
            if (maybe_window.*) |*window| {
                var i: usize = 0;
                while (i < window.items.len) {
                    if (std.mem.eql(u8, window.items[i].mid, mid)) {
                        _ = window.orderedRemove(i);
                        continue;
                    }
                    i += 1;
                }
            }
        }
    }

    fn historyContains(self: *MessageCache, window_index: usize, mid: []const u8) bool {
        const maybe_window = self.history.items[window_index];
        if (maybe_window) |window| {
            for (window.items) |entry| {
                if (std.mem.eql(u8, entry.mid, mid)) return true;
            }
        }
        return false;
    }
};

/// Clone a message into a single contiguous backing buffer.
/// Returns a StoredMessage where all slice fields point into the backing buffer.
/// Only 1 allocation for all field data.
fn cloneMessage(allocator: std.mem.Allocator, msg: *const rpc.Message, validation: StoredMessage.Validation) error{OutOfMemory}!StoredMessage {
    // Calculate total size needed
    var total_len: usize = 0;
    if (msg.from) |f| total_len += f.len;
    if (msg.seqno) |s| total_len += s.len;
    if (msg.topic) |t| total_len += t.len;
    if (msg.data) |d| total_len += d.len;
    if (msg.signature) |s| total_len += s.len;
    if (msg.key) |k| total_len += k.len;

    const backing = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    const from = if (msg.from) |f| copyField(backing, &offset, f) else null;
    const seqno = if (msg.seqno) |s| copyField(backing, &offset, s) else null;
    const topic = if (msg.topic) |t| copyField(backing, &offset, t) else null;
    const data = if (msg.data) |d| copyField(backing, &offset, d) else null;
    const signature = if (msg.signature) |s| copyField(backing, &offset, s) else null;
    const key = if (msg.key) |k| copyField(backing, &offset, k) else null;

    std.debug.assert(offset == total_len);

    return .{
        .message = .{
            .from = from,
            .seqno = seqno,
            .topic = topic,
            .data = data,
            .signature = signature,
            .key = key,
        },
        .backing = backing,
        .validation = validation,
    };
}

/// Copy a field into the backing buffer at the current offset, returning a slice into it.
inline fn copyField(backing: []u8, offset: *usize, source: []const u8) []const u8 {
    const start = offset.*;
    @memcpy(backing[start..][0..source.len], source);
    offset.* = start + source.len;
    return backing[start..][0..source.len];
}

// --- Tests ---

fn createTestMessage(
    allocator: std.mem.Allocator,
    from: []const u8,
    seqno: []const u8,
    topic: []const u8,
    data: []const u8,
) error{OutOfMemory}!StoredMessage {
    return cloneMessage(allocator, &.{
        .from = from,
        .seqno = seqno,
        .topic = topic,
        .data = data,
        .signature = null,
        .key = null,
    }, .validated);
}

fn freeTestMessage(allocator: std.mem.Allocator, stored: *const StoredMessage) void {
    var owned = stored.*;
    owned.deinit(allocator);
}

fn makeTestMessage(allocator: std.mem.Allocator, n: usize) !StoredMessage {
    var seqno_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seqno_bytes, @intCast(n), .big);

    const data_str = try std.fmt.allocPrint(allocator, "{d}", .{n});
    defer allocator.free(data_str);

    return createTestMessage(allocator, "test", &seqno_bytes, "test", data_str);
}

fn putWithIdAllocationFailureImpl(allocator: std.mem.Allocator) !void {
    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    try cache.putWithId(mid, &stored.message);
    try std.testing.expectEqual(EntryState.validated, cache.entryState(mid));
}

fn putPendingWithIdAllocationFailureImpl(allocator: std.mem.Allocator) !void {
    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    try cache.putPendingWithId(mid, &stored.message, "peer1", 1_000);
    try std.testing.expectEqual(EntryState.pending, cache.entryState(mid));
}

test "MessageCache putWithId survives allocation failures after ownership transfer" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, putWithIdAllocationFailureImpl, .{});
}

test "MessageCache putPendingWithId survives allocation failures after ownership transfer" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, putPendingWithIdAllocationFailureImpl, .{});
}

test "MessageCache init basic" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    try std.testing.expectEqual(@as(u32, 3), cache.gossip_window_count);
    try std.testing.expectEqual(@as(usize, 5), cache.history.items.len);
    try std.testing.expectEqual(@as(u32, 0), cache.msgs.count());
}

test "MessageCache init rejects gossip > history" {
    const allocator = std.testing.allocator;
    const result = MessageCache.init(allocator, 6, 5, defaultMsgId);
    try std.testing.expectError(MessageCache.Error.HistoryLengthExceeded, result);
}

test "defaultMsgId concatenates from and seqno" {
    const allocator = std.testing.allocator;

    var msg = rpc.Message{
        .from = "peer123",
        .seqno = "seq456",
        .topic = "test",
        .data = null,
        .signature = null,
        .key = null,
    };

    const result = try defaultMsgId(allocator, &msg);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("peer123seq456", result);
}

test "defaultMsgId rejects null from and seqno" {
    const allocator = std.testing.allocator;

    var msg = rpc.Message{
        .from = null,
        .seqno = null,
        .topic = "test",
        .data = null,
        .signature = null,
        .key = null,
    };

    const result = defaultMsgId(allocator, &msg);
    try std.testing.expectError(error.BothFromAndSeqNoNull, result);
}

test "MessageCache put and get" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);

    try cache.put(&stored.message);
    try std.testing.expectEqual(@as(u32, 1), cache.msgs.count());

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);
    const retrieved = cache.get(mid);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings("hello", retrieved.?.data.?);
}

test "MessageCache pending entries stay out of gossip and IWANT until validated" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    try cache.putPendingWithId(mid, &stored.message, "peer1", 1_000);
    try std.testing.expectEqual(EntryState.pending, cache.entryState(mid));
    try std.testing.expect(cache.get(mid) != null);

    const gossip_before = try cache.getGossipIDs("topic-a");
    defer allocator.free(gossip_before);
    try std.testing.expectEqual(@as(usize, 0), gossip_before.len);
    try std.testing.expect((try cache.getForPeer(mid, "peer-z")) == null);

    const pending_stats = cache.pendingValidationStats(1_250);
    try std.testing.expectEqual(@as(usize, 1), pending_stats.count);
    try std.testing.expectEqual(@as(?u64, 250), pending_stats.oldest_age_ms);

    try std.testing.expect(try cache.notePendingOriginatingPeer(mid, "peer2"));
    const origin_peers = try cache.listPendingOriginatingPeers(allocator, mid);
    defer allocator.free(origin_peers.?);
    try std.testing.expectEqual(@as(usize, 2), origin_peers.?.len);

    try std.testing.expect(cache.markValidated(mid));
    try std.testing.expectEqual(EntryState.validated, cache.entryState(mid));
    try std.testing.expectEqual(@as(usize, 0), cache.pendingValidationStats(1_250).count);

    const gossip_after = try cache.getGossipIDs("topic-a");
    defer allocator.free(gossip_after);
    try std.testing.expectEqual(@as(usize, 1), gossip_after.len);
    try std.testing.expect((try cache.getForPeer(mid, "peer-z")) != null);
}

test "MessageCache discard removes pending entry from validation stats" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "ignored");
    defer freeTestMessage(allocator, &stored);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    try cache.putPendingWithId(mid, &stored.message, "peer1", 2_000);
    try std.testing.expect(cache.discard(mid));
    try std.testing.expectEqual(EntryState.discarded, cache.entryState(mid));
    try std.testing.expectEqual(@as(usize, 0), cache.pendingValidationStats(2_100).count);
    try std.testing.expect(cache.get(mid) == null);

    const gossip_ids = try cache.getGossipIDs("topic-a");
    defer allocator.free(gossip_ids);
    try std.testing.expectEqual(@as(usize, 0), gossip_ids.len);
}

test "MessageCache keeps pending entries across shifts and reintroduces them on validation" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 2, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    try cache.putPendingWithId(mid, &stored.message, "peer1", 1_000);
    cache.shift();
    cache.shift();
    cache.shift();

    const gossip_before = try cache.getGossipIDs("topic-a");
    defer allocator.free(gossip_before);
    try std.testing.expectEqual(@as(usize, 0), gossip_before.len);
    try std.testing.expectEqual(EntryState.pending, cache.entryState(mid));
    try std.testing.expectEqual(@as(usize, 1), cache.pendingCount());
    try std.testing.expect(cache.get(mid) != null);

    try std.testing.expect(cache.markValidated(mid));
    try std.testing.expectEqual(EntryState.validated, cache.entryState(mid));
    const gossip_ids = try cache.getGossipIDs("topic-a");
    defer allocator.free(gossip_ids);
    try std.testing.expectEqual(@as(usize, 1), gossip_ids.len);
    try std.testing.expectEqualStrings(mid, gossip_ids[0]);
}

test "MessageCache rejects duplicate" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var s1 = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &s1);
    var s2 = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "world");
    defer freeTestMessage(allocator, &s2);

    try cache.put(&s1.message);
    const result = cache.put(&s2.message);
    try std.testing.expectError(MessageCache.Error.DuplicateMessage, result);
    try std.testing.expectEqual(@as(u32, 1), cache.msgs.count());
}

test "MessageCache getForPeer tracks transmission count" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "peer1", "seq1", "topic-a", "hello");
    defer freeTestMessage(allocator, &stored);
    try cache.put(&stored.message);

    const mid = try defaultMsgId(allocator, &stored.message);
    defer allocator.free(mid);

    const r1 = try cache.getForPeer(mid, "peerA");
    try std.testing.expect(r1 != null);
    try std.testing.expectEqual(@as(i32, 1), r1.?.count);

    const r2 = try cache.getForPeer(mid, "peerA");
    try std.testing.expectEqual(@as(i32, 2), r2.?.count);

    const r3 = try cache.getForPeer(mid, "peerB");
    try std.testing.expectEqual(@as(i32, 1), r3.?.count);
}

test "MessageCache getForPeer returns null for missing message" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    const result = try cache.getForPeer("nonexistent", "peerA");
    try std.testing.expect(result == null);
}

test "MessageCache getGossipIDs filters by topic" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 2, 5, defaultMsgId);
    defer cache.deinit();

    var s1 = try createTestMessage(allocator, "p1", "s1", "topic-a", "d1");
    defer freeTestMessage(allocator, &s1);
    var s2 = try createTestMessage(allocator, "p2", "s2", "topic-b", "d2");
    defer freeTestMessage(allocator, &s2);
    var s3 = try createTestMessage(allocator, "p3", "s3", "topic-a", "d3");
    defer freeTestMessage(allocator, &s3);

    try cache.put(&s1.message);
    try cache.put(&s2.message);
    try cache.put(&s3.message);

    const ids = try cache.getGossipIDs("topic-a");
    defer allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 2), ids.len);
}

test "MessageCache shift evicts oldest window" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 2, 3, defaultMsgId);
    defer cache.deinit();

    var stored = try createTestMessage(allocator, "p1", "s1", "topic-a", "d1");
    defer freeTestMessage(allocator, &stored);
    try cache.put(&stored.message);

    try std.testing.expectEqual(@as(u32, 1), cache.msgs.count());
    _ = try cache.getForPeer("p1s1", "peer-a");
    try std.testing.expectEqual(@as(u32, 1), cache.peertx.count());

    cache.shift();
    try std.testing.expectEqual(@as(u32, 1), cache.msgs.count());
    try std.testing.expectEqual(@as(u32, 1), cache.peertx.count());

    cache.shift();
    try std.testing.expectEqual(@as(u32, 1), cache.msgs.count());
    try std.testing.expectEqual(@as(u32, 1), cache.peertx.count());

    cache.shift();
    try std.testing.expectEqual(@as(u32, 0), cache.msgs.count());
    try std.testing.expectEqual(@as(u32, 0), cache.peertx.count());
}

test "MessageCache shift empty cache" {
    const allocator = std.testing.allocator;

    var cache = try MessageCache.init(allocator, 3, 5, defaultMsgId);
    defer cache.deinit();

    cache.shift();
    try std.testing.expectEqual(@as(u32, 0), cache.msgs.count());
}

test "MessageCache memory management" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) {
            std.testing.expect(false) catch @panic("Memory leak detected!");
        }
    }
    const allocator = gpa.allocator();

    {
        var cache = try MessageCache.init(allocator, 2, 3, defaultMsgId);
        defer cache.deinit();

        for (0..10) |i| {
            var stored = try makeTestMessage(allocator, i);
            defer freeTestMessage(allocator, &stored);
            try cache.put(&stored.message);
        }

        for (0..5) |_| {
            cache.shift();
        }

        var test_stored = try createTestMessage(allocator, "test", "test", "test", "test");
        defer freeTestMessage(allocator, &test_stored);
        try cache.put(&test_stored.message);

        const mid = try defaultMsgId(allocator, &test_stored.message);
        defer allocator.free(mid);

        _ = try cache.getForPeer(mid, "peer1");
        _ = try cache.getForPeer(mid, "peer2");
    }
}

test "cloneMessage uses single backing buffer" {
    const allocator = std.testing.allocator;

    const stored = try cloneMessage(allocator, &.{
        .from = "alice",
        .seqno = "0001",
        .topic = "chat",
        .data = "hello world",
        .signature = "sig",
        .key = "pubkey",
    }, .validated);
    defer allocator.free(stored.backing);

    // All fields should point into the single backing buffer
    const backing_start = @intFromPtr(stored.backing.ptr);
    const backing_end = backing_start + stored.backing.len;

    inline for (.{ stored.message.from, stored.message.seqno, stored.message.topic, stored.message.data, stored.message.signature, stored.message.key }) |maybe_field| {
        if (maybe_field) |field| {
            const field_start = @intFromPtr(field.ptr);
            try std.testing.expect(field_start >= backing_start);
            try std.testing.expect(field_start + field.len <= backing_end);
        }
    }

    // Verify content
    try std.testing.expectEqualStrings("alice", stored.message.from.?);
    try std.testing.expectEqualStrings("0001", stored.message.seqno.?);
    try std.testing.expectEqualStrings("chat", stored.message.topic.?);
    try std.testing.expectEqualStrings("hello world", stored.message.data.?);
    try std.testing.expectEqualStrings("sig", stored.message.signature.?);
    try std.testing.expectEqualStrings("pubkey", stored.message.key.?);

    // Total backing = 5 + 4 + 4 + 11 + 3 + 6 = 33 bytes, 1 allocation
    try std.testing.expectEqual(@as(usize, 33), stored.backing.len);
}
