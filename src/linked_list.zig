//! pingora-zig: linked_list
//!
//! Doubly linked list implementation optimized for LRU cache.
//! Features: preallocated consecutive memory, no shrinking, no memory fragmentation.
//!
//! Ported from: https://github.com/cloudflare/pingora/tree/main/pingora-lru

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const Index = usize;
const NULL: Index = std.math.maxInt(Index);
const HEAD: Index = 0;
const TAIL: Index = 1;
const OFFSET: usize = 2;

const Node = struct {
    prev: Index,
    next: Index,
    data: u64,
};

/// Doubly linked list with preallocated memory
pub const LinkedList = struct {
    allocator: Allocator,
    nodes: std.ArrayListUnmanaged(Node),
    head: Node,
    tail: Node,
    free: std.ArrayListUnmanaged(Index),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .nodes = .{},
            .head = .{ .prev = NULL, .next = TAIL, .data = 0 },
            .tail = .{ .prev = HEAD, .next = NULL, .data = 0 },
            .free = .{},
        };
    }

    pub fn initCapacity(allocator: Allocator, capacity: usize) !Self {
        var nodes: std.ArrayListUnmanaged(Node) = .{};
        try nodes.ensureTotalCapacity(allocator, capacity);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .head = .{ .prev = NULL, .next = TAIL, .data = 0 },
            .tail = .{ .prev = HEAD, .next = NULL, .data = 0 },
            .free = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
        self.free.deinit(self.allocator);
    }

    fn getNode(self: *Self, index: Index) *Node {
        return switch (index) {
            HEAD => &self.head,
            TAIL => &self.tail,
            else => &self.nodes.items[index - OFFSET],
        };
    }

    fn getNodeConst(self: *const Self, index: Index) Node {
        return switch (index) {
            HEAD => self.head,
            TAIL => self.tail,
            else => self.nodes.items[index - OFFSET],
        };
    }

    fn newNode(self: *Self, data: u64) !Index {
        if (self.free.pop()) |index| {
            self.getNode(index).data = data;
            return index;
        }
        const node = Node{ .prev = NULL, .next = NULL, .data = data };
        try self.nodes.append(self.allocator, node);
        return self.nodes.items.len - 1 + OFFSET;
    }

    /// Number of nodes in the list (excluding sentinels)
    pub fn len(self: *const Self) usize {
        return self.nodes.items.len - self.free.items.len;
    }

    fn validIndex(self: *const Self, index: Index) bool {
        return index != HEAD and index != TAIL and index < self.nodes.items.len + OFFSET;
    }

    /// Peek into the list at the given index
    pub fn peek(self: *const Self, index: Index) ?u64 {
        if (!self.validIndex(index)) return null;
        return self.getNodeConst(index).data;
    }

    /// Check if value exists near head (up to search_limit nodes)
    pub fn existNearHead(self: *const Self, value: u64, search_limit: usize) bool {
        var current = HEAD;
        for (0..search_limit) |_| {
            current = self.getNodeConst(current).next;
            if (current == TAIL) return false;
            if (self.getNodeConst(current).data == value) return true;
        }
        return false;
    }

    fn insertAfter(self: *Self, node_index: Index, at: Index) void {
        std.debug.assert(at != TAIL and at != node_index);

        const at_node = self.getNode(at);
        const next = at_node.next;
        at_node.next = node_index;

        const node = self.getNode(node_index);
        node.next = next;
        node.prev = at;

        self.getNode(next).prev = node_index;
    }

    /// Push data at the head of the list
    pub fn pushHead(self: *Self, data: u64) !Index {
        const new_index = try self.newNode(data);
        self.insertAfter(new_index, HEAD);
        return new_index;
    }

    /// Push data at the tail of the list
    pub fn pushTail(self: *Self, data: u64) !Index {
        const new_index = try self.newNode(data);
        self.insertAfter(new_index, self.tail.prev);
        return new_index;
    }

    fn lift(self: *Self, index: Index) u64 {
        std.debug.assert(index != HEAD and index != TAIL);

        const node = self.getNode(index);
        const prev = node.prev;
        const next = node.next;
        const data = node.data;

        std.debug.assert(prev != NULL and next != NULL);

        node.prev = NULL;
        node.next = NULL;

        self.getNode(prev).next = next;
        self.getNode(next).prev = prev;

        return data;
    }

    /// Remove the node at the index
    pub fn remove(self: *Self, index: Index) !u64 {
        try self.free.append(self.allocator, index);
        return self.lift(index);
    }

    /// Remove and return the tail data
    pub fn popTail(self: *Self) ?u64 {
        const data_tail = self.tail.prev;
        if (data_tail == HEAD) return null;
        return self.remove(data_tail) catch null;
    }

    /// Move a node to the head
    pub fn promote(self: *Self, index: Index) void {
        if (self.head.next == index) return;
        _ = self.lift(index);
        self.insertAfter(index, HEAD);
    }

    /// Get the head index
    pub fn getHead(self: *const Self) ?Index {
        const data_head = self.head.next;
        if (data_head == TAIL) return null;
        return data_head;
    }

    /// Get the tail index
    pub fn getTail(self: *const Self) ?Index {
        const data_tail = self.tail.prev;
        if (data_tail == HEAD) return null;
        return data_tail;
    }

    /// Iterator over the list
    pub fn iter(self: *const Self) Iterator {
        return .{ .list = self, .head = HEAD, .tail = TAIL, .remaining = self.len() };
    }

    pub const Iterator = struct {
        list: *const LinkedList,
        head: Index,
        tail: Index,
        remaining: usize,

        pub fn next(self: *Iterator) ?u64 {
            const next_index = self.list.getNodeConst(self.head).next;
            if (next_index == TAIL or next_index == NULL) return null;
            self.head = next_index;
            self.remaining -= 1;
            return self.list.getNodeConst(next_index).data;
        }

        pub fn nextBack(self: *Iterator) ?u64 {
            const prev_index = self.list.getNodeConst(self.tail).prev;
            if (prev_index == HEAD or prev_index == NULL) return null;
            self.tail = prev_index;
            self.remaining -= 1;
            return self.list.getNodeConst(prev_index).data;
        }
    };
};

// Tests
test "LinkedList insert" {
    var list = LinkedList.init(testing.allocator);
    defer list.deinit();

    try testing.expectEqual(list.len(), 0);
    try testing.expectEqual(list.getHead(), null);
    try testing.expectEqual(list.getTail(), null);

    const index1 = try list.pushHead(2);
    try testing.expectEqual(list.len(), 1);
    try testing.expectEqual(list.peek(index1), 2);

    const index2 = try list.pushHead(3);
    try testing.expectEqual(list.getHead(), index2);
    try testing.expectEqual(list.getTail(), index1);

    const index3 = try list.pushTail(4);
    try testing.expectEqual(list.getHead(), index2);
    try testing.expectEqual(list.getTail(), index3);

    // Check order: 3, 2, 4
    var it = list.iter();
    try testing.expectEqual(it.next(), 3);
    try testing.expectEqual(it.next(), 2);
    try testing.expectEqual(it.next(), 4);
    try testing.expectEqual(it.next(), null);
}

test "LinkedList pop" {
    var list = LinkedList.init(testing.allocator);
    defer list.deinit();

    _ = try list.pushHead(2);
    _ = try list.pushHead(3);
    _ = try list.pushTail(4);

    try testing.expectEqual(list.popTail(), 4);
    try testing.expectEqual(list.popTail(), 2);
    try testing.expectEqual(list.popTail(), 3);
    try testing.expectEqual(list.popTail(), null);
}

test "LinkedList promote" {
    var list = LinkedList.init(testing.allocator);
    defer list.deinit();

    const index2 = try list.pushHead(2);
    const index3 = try list.pushHead(3);
    const index4 = try list.pushTail(4);

    // Order: 3, 2, 4
    list.promote(index3);
    var it = list.iter();
    try testing.expectEqual(it.next(), 3);
    try testing.expectEqual(it.next(), 2);
    try testing.expectEqual(it.next(), 4);

    list.promote(index2);
    it = list.iter();
    try testing.expectEqual(it.next(), 2);
    try testing.expectEqual(it.next(), 3);
    try testing.expectEqual(it.next(), 4);

    list.promote(index4);
    it = list.iter();
    try testing.expectEqual(it.next(), 4);
    try testing.expectEqual(it.next(), 2);
    try testing.expectEqual(it.next(), 3);
}

test "LinkedList exist_near_head" {
    var list = LinkedList.init(testing.allocator);
    defer list.deinit();

    _ = try list.pushHead(2);
    _ = try list.pushHead(3);
    _ = try list.pushTail(4);

    // Order: 3, 2, 4
    try testing.expect(!list.existNearHead(4, 1));
    try testing.expect(!list.existNearHead(4, 2));
    try testing.expect(list.existNearHead(4, 3));
    try testing.expect(list.existNearHead(4, 4));
    try testing.expect(list.existNearHead(3, 1));
}

test "LinkedList reverse iterator" {
    var list = LinkedList.init(testing.allocator);
    defer list.deinit();

    _ = try list.pushHead(2);
    _ = try list.pushHead(3);
    _ = try list.pushTail(4);

    // Order: 3, 2, 4 -> reverse: 4, 2, 3
    var it = list.iter();
    try testing.expectEqual(it.nextBack(), 4);
    try testing.expectEqual(it.nextBack(), 2);
    try testing.expectEqual(it.nextBack(), 3);
    try testing.expectEqual(it.nextBack(), null);
}
