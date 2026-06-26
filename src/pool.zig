//! Connection pool.
//!
//! `Pool(Driver)` manages a bounded set of reusable physical connections.
//! `acquire` hands out a `Lease`; `release` returns the connection to the idle
//! set or destroys it. The pool is generic over a `Driver` so the real
//! `TcpDriver` (zio.net + `Connection`) and an offline mock can share one
//! engine — the mock injects controllable connections and a controllable clock
//! so the hard bookkeeping (generation invalidation, lifetime/idle expiry,
//! reuse/destroy decisions, capacity blocking, leak accounting) is verified
//! deterministically without a server.
//!
//! Concurrency model: a single `Mutex` guards pool state and a `Condition`
//! (`idle_available`) parks `acquire` callers when the pool is at capacity.
//! Every connection open (acquire path and reaper prewarm) is guarded by
//! `total_count < max_connections` under the mutex, so `total_count` never
//! exceeds the limit. I/O (`driver.open`/`driver.close`) always runs OUTSIDE
//! the mutex, after reserving/releasing the slot, so a slow connect never
//! stalls other coroutines holding the lock.
//!
//! Pinning: `Pool` must not be moved after `init` — a `Lease` holds `*Pool` and
//! the background reaper captures `*Pool`. `Driver.Handle` must also be pinned
//! (the real handle embeds a `Connection` whose reader/writer point at an
//! embedded `ZioStream`), so `Driver.open` returns a heap pointer the driver
//! owns.

const std = @import("std");
const zio = @import("zio");

const mantle = @import("mantle.zig");

const Allocator = std.mem.Allocator;

/// Pool tuning. Durations of `0` mean "unlimited" for the lifetime/idle caps.
pub const Config = struct {
    /// Hard upper bound on physical connections (leased + idle).
    max_connections: usize = 10,
    /// Connections the reaper keeps warm in the idle set.
    min_idle: usize = 0,
    /// How long `acquire` waits for a slot before `error.AcquireTimeout`.
    acquire_timeout: zio.Timeout = .{ .duration = zio.Duration.fromSeconds(30) },
    /// Retire a connection this long after it was opened. `0` disables.
    max_lifetime_ns: u64 = 0,
    /// Retire an idle connection unused for this long. `0` disables.
    idle_timeout_ns: u64 = 0,
    /// Background reaper period.
    reap_interval_ns: u64 = 30 * std.time.ns_per_s,
};

/// Point-in-time pool counters for diagnostics. Snapshot under the mutex.
pub const Stats = struct {
    idle: usize,
    leased: usize,
    total: usize,
    generation: u64,
    closed: bool,
};

pub const AcquireError = error{
    PoolClosed,
    AcquireTimeout,
    Canceled,
};

/// A connection pool generic over a connection `Driver`.
///
/// `Driver` must expose:
///   - `pub const Handle = T;`
///   - `pub fn open(self: *Driver, a: Allocator) !*Handle`
///   - `pub fn close(self: *Driver, a: Allocator, h: *Handle) void`
///   - `pub fn nowNs(self: *const Driver) u64`
/// `Handle` must expose `canReuse()` and `isBroken()` (and, for ergonomics,
/// whatever accessor users need to run queries — e.g. a public `conn` field).
///
/// Optional capability: a `Driver` that also exposes
/// `pub fn killQuery(self: *Driver, a: Allocator, thread_id: u32) !void` and
/// whose `Handle` has a `conn: Connection` field unlocks the TCP-oriented
/// `killQuery` / `watchdog` / `queryTimed` helpers below. Pools over drivers
/// without it (e.g. the offline mock) simply never instantiate those methods;
/// calling them is a clear compile error.
pub fn Pool(comptime Driver: type) type {
    return struct {
        const Self = @This();
        pub const Handle = Driver.Handle;

        /// Pool-side wrapper around a physical connection. Heap-allocated and
        /// linked into the idle stack via `next`.
        const Session = struct {
            handle: *Handle,
            generation: u64,
            created_ns: u64,
            last_used_ns: u64,
            next: ?*Session = null,
        };

        /// A checked-out connection. Return it with `release`; dropping a lease
        /// without releasing leaks the connection (tracked in `Stats.leased`).
        pub const Lease = struct {
            pool: *Self,
            session: *Session,

            /// The underlying driver handle (e.g. `lease.handle().conn`).
            pub fn handle(self: Lease) *Handle {
                return self.session.handle;
            }

            /// Return the connection to the pool. The lease is spent afterward.
            pub fn release(self: *Lease) void {
                self.pool.release(self.session);
                self.session = undefined;
            }
        };

        allocator: Allocator,
        driver: Driver,
        config: Config,

        mutex: zio.Mutex = .init,
        idle_available: zio.Condition = .init,

        idle_head: ?*Session = null,
        idle_count: usize = 0,
        /// Physical connections in existence: leased + idle. Bounded by
        /// `config.max_connections`.
        total_count: usize = 0,
        /// Currently checked-out connections. Diagnostic / leak detection.
        leased_count: usize = 0,
        generation: u64 = 0,
        closed: bool = false,

        reaper: ?zio.JoinHandle(void) = null,

        /// Allocate the pool. Pure: no I/O and no background task. The returned
        /// value must be pinned (do not move it after `init`).
        pub fn init(allocator: Allocator, driver: Driver, config: Config) Self {
            return .{ .allocator = allocator, .driver = driver, .config = config };
        }

        /// Stop the reaper, close every idle connection, and free pool memory.
        /// Leased connections are not owned here; releasing them after deinit is
        /// a use-after-free, so callers must drain leases first.
        pub fn deinit(self: *Self) void {
            self.mutex.lockUncancelable();
            self.closed = true;
            self.idle_available.broadcast();
            self.mutex.unlock();

            if (self.reaper) |*handle| {
                handle.cancel();
                handle.join();
                self.reaper = null;
            }

            // Drain idle outside the lock (close() does I/O); no other coroutine
            // touches the pool once it is closed and the reaper has joined.
            var node = self.takeIdleChain();
            while (node) |sess| {
                node = sess.next;
                self.driver.close(self.allocator, sess.handle);
                self.allocator.destroy(sess);
            }
        }

        /// Spawn the background reaper (idle reaping + `min_idle` prewarm). Must
        /// be called from within a zio runtime. Optional: without it the pool
        /// still works, just without periodic maintenance. Returns
        /// `error.ReaperAlreadyRunning` if already started.
        pub fn startReaper(self: *Self) !void {
            if (self.reaper != null) return error.ReaperAlreadyRunning;
            self.reaper = try zio.spawn(reaperLoop, .{self});
        }

        fn reaperLoop(self: *Self) void {
            const interval = zio.Duration.fromNanoseconds(self.config.reap_interval_ns);
            while (true) {
                zio.sleep(interval) catch break; // canceled on deinit
                if (self.isClosed()) break;
                self.reapOnce();
            }
        }

        fn isClosed(self: *Self) bool {
            self.mutex.lockUncancelable();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// Check out a connection, blocking up to `acquire_timeout` when the
        /// pool is at capacity.
        pub fn acquire(self: *Self) !Lease {
            // Resolve the timeout to a fixed deadline once: re-passing a
            // `.duration` to `timedWait` would restart the clock every loop.
            const deadline = self.config.acquire_timeout.toDeadline();

            self.mutex.lock() catch return error.Canceled;
            while (true) {
                if (self.closed) {
                    self.mutex.unlock();
                    return error.PoolClosed;
                }

                if (self.popIdle()) |sess| {
                    const now = self.driver.nowNs();
                    if (self.canLeaseIdle(sess, now)) {
                        self.leased_count += 1;
                        self.mutex.unlock();
                        return .{ .pool = self, .session = sess };
                    }
                    // Stale idle connection: drop it (frees a slot) and retry.
                    self.total_count -= 1;
                    self.mutex.unlock();
                    self.driver.close(self.allocator, sess.handle);
                    self.allocator.destroy(sess);
                    self.mutex.lockUncancelable();
                    self.idle_available.signal();
                    continue;
                }

                if (self.total_count < self.config.max_connections) {
                    // Reserve the slot, then open without holding the lock.
                    self.total_count += 1;
                    self.leased_count += 1;
                    const gen = self.generation;
                    self.mutex.unlock();
                    return self.openLeased(gen) catch |err| {
                        self.mutex.lockUncancelable();
                        self.total_count -= 1;
                        self.leased_count -= 1;
                        self.idle_available.signal();
                        self.mutex.unlock();
                        return err;
                    };
                }

                // At capacity: wait for a release or a freed slot.
                self.idle_available.timedWait(&self.mutex, deadline) catch |err| {
                    self.mutex.unlock();
                    return switch (err) {
                        error.Timeout => error.AcquireTimeout,
                        error.Canceled => error.Canceled,
                    };
                };
            }
        }

        /// Open a fresh connection for an already-reserved leased slot. Runs
        /// outside the mutex.
        fn openLeased(self: *Self, generation: u64) !Lease {
            const handle = try self.driver.open(self.allocator);
            const sess = self.allocator.create(Session) catch |err| {
                self.driver.close(self.allocator, handle);
                return err;
            };
            const now = self.driver.nowNs();
            sess.* = .{
                .handle = handle,
                .generation = generation,
                .created_ns = now,
                .last_used_ns = now,
            };
            return .{ .pool = self, .session = sess };
        }

        fn release(self: *Self, sess: *Session) void {
            self.mutex.lockUncancelable();
            self.leased_count -= 1;
            const now = self.driver.nowNs();
            const reusable = !self.closed and
                sess.generation == self.generation and
                sess.handle.canReuse() and
                !self.lifetimeExceeded(sess, now);
            if (reusable) {
                sess.last_used_ns = now;
                self.pushIdle(sess);
                self.idle_available.signal();
                self.mutex.unlock();
                return;
            }
            // Retire: free the slot, then close outside the lock.
            self.total_count -= 1;
            self.mutex.unlock();
            self.driver.close(self.allocator, sess.handle);
            self.allocator.destroy(sess);
            self.mutex.lockUncancelable();
            self.idle_available.signal();
            self.mutex.unlock();
        }

        /// Invalidate every current connection. Idle connections are closed
        /// now; leased connections are retired on `release` (generation
        /// mismatch). New connections start at the new generation.
        pub fn clear(self: *Self) void {
            self.mutex.lockUncancelable();
            self.generation += 1;
            const dead = self.takeIdleChain();
            self.mutex.unlock();

            var node = dead;
            var freed: usize = 0;
            while (node) |sess| {
                node = sess.next;
                self.driver.close(self.allocator, sess.handle);
                self.allocator.destroy(sess);
                freed += 1;
            }
            if (freed > 0) {
                self.mutex.lockUncancelable();
                self.total_count -= freed;
                self.idle_available.broadcast();
                self.mutex.unlock();
            }
        }

        /// One reaper pass: retire expired/stale idle connections, then top the
        /// idle set back up to `min_idle`. Pure bookkeeping + I/O; exposed so
        /// offline tests can drive it synchronously.
        pub fn reapOnce(self: *Self) void {
            self.mutex.lockUncancelable();
            const now = self.driver.nowNs();

            // Partition idle into survivors (relinked) and dead (closed below).
            var survivors: ?*Session = null;
            var dead: ?*Session = null;
            var dead_count: usize = 0;
            var node = self.idle_head;
            while (node) |sess| {
                node = sess.next;
                if (self.shouldRetire(sess, now)) {
                    sess.next = dead;
                    dead = sess;
                    dead_count += 1;
                } else {
                    sess.next = survivors;
                    survivors = sess;
                }
            }
            self.idle_head = survivors;
            self.idle_count -= dead_count;
            self.total_count -= dead_count;

            // Reserve prewarm slots under the same `total_count < max` guard.
            var need: usize = 0;
            if (!self.closed and self.idle_count < self.config.min_idle) {
                const want = self.config.min_idle - self.idle_count;
                const room = self.config.max_connections - self.total_count;
                need = @min(want, room);
                self.total_count += need;
            }
            const gen = self.generation;
            self.mutex.unlock();

            // Close retired connections (I/O) outside the lock.
            var d = dead;
            while (d) |sess| {
                d = sess.next;
                self.driver.close(self.allocator, sess.handle);
                self.allocator.destroy(sess);
            }
            if (dead_count > 0) {
                self.mutex.lockUncancelable();
                self.idle_available.broadcast();
                self.mutex.unlock();
            }

            // Prewarm: open reserved slots and park them in the idle set.
            var i: usize = 0;
            while (i < need) : (i += 1) {
                const handle = self.driver.open(self.allocator) catch {
                    self.mutex.lockUncancelable();
                    self.total_count -= 1;
                    self.idle_available.signal();
                    self.mutex.unlock();
                    continue;
                };
                const sess = self.allocator.create(Session) catch {
                    self.driver.close(self.allocator, handle);
                    self.mutex.lockUncancelable();
                    self.total_count -= 1;
                    self.idle_available.signal();
                    self.mutex.unlock();
                    continue;
                };
                const now2 = self.driver.nowNs();
                sess.* = .{
                    .handle = handle,
                    .generation = gen,
                    .created_ns = now2,
                    .last_used_ns = now2,
                };
                self.mutex.lockUncancelable();
                self.pushIdle(sess);
                self.idle_available.signal();
                self.mutex.unlock();
            }
        }

        /// Soft-cancel an in-flight query on one of this pool's connections by
        /// issuing `KILL QUERY <thread_id>` from a separate connection.
        /// Read the target id from the leased
        /// `Connection.serverThreadId()`. The killed connection stays reusable;
        /// the interrupted query returns ER_QUERY_INTERRUPTED. Only available
        /// when the driver implements `killQuery` (e.g. `TcpDriver`).
        pub fn killQuery(self: *Self, thread_id: u32) !void {
            if (!@hasDecl(Driver, "killQuery"))
                @compileError(@typeName(Driver) ++ " does not support killQuery; this helper " ++
                    "requires a driver that exposes `killQuery` (e.g. TcpDriver)");
            return self.driver.killQuery(self.allocator, thread_id);
        }

        /// A timeout watchdog: after `arm`, it soft-cancels (`KILL QUERY`) the
        /// target server thread once `timeout` elapses, unless `disarm` runs
        /// first. Bound a command's duration by arming before it and disarming
        /// after (see `queryTimed` for the composed form). Must be kept pinned
        /// between `arm` and `disarm` (the watchdog coroutine holds a pointer).
        pub const Watchdog = struct {
            pool: *Self,
            thread_id: u32,
            timeout_ns: u64,
            fired: bool = false,
            join_handle: ?zio.JoinHandle(void) = null,

            fn run(self: *Watchdog) void {
                // Canceled (disarm before timeout) -> return without firing.
                zio.sleep(zio.Duration.fromNanoseconds(self.timeout_ns)) catch return;
                self.fired = true;
                self.pool.killQuery(self.thread_id) catch {};
            }

            pub fn arm(self: *Watchdog) !void {
                self.join_handle = try zio.spawn(run, .{self});
            }

            /// Stop the watchdog. Returns true if it had already fired (i.e. the
            /// command timed out and a `KILL QUERY` was sent).
            pub fn disarm(self: *Watchdog) bool {
                if (self.join_handle) |*handle| {
                    handle.cancel();
                    handle.join();
                    self.join_handle = null;
                }
                return self.fired;
            }
        };

        /// Create (but do not arm) a `Watchdog` targeting `thread_id`.
        pub fn watchdog(self: *Self, thread_id: u32, timeout: zio.Duration) Watchdog {
            return .{ .pool = self, .thread_id = thread_id, .timeout_ns = timeout.toNanoseconds() };
        }

        /// Run a text query on `lease` bounded by `timeout`. On timeout the query
        /// is soft-cancelled (`KILL QUERY`), the connection is marked broken (a
        /// pending cancellation may linger) so the pool retires it on
        /// release, and `error.CommandTimeout` is returned. Otherwise behaves
        /// like `Connection.query`.
        pub fn queryTimed(
            self: *Self,
            lease: Lease,
            allocator: Allocator,
            sql: []const u8,
            timeout: zio.Duration,
        ) !mantle.QueryResult {
            if (!@hasDecl(Driver, "killQuery"))
                @compileError(@typeName(Driver) ++ " does not support queryTimed; this helper " ++
                    "requires a driver with `killQuery` and a `Handle.conn` connection (e.g. TcpDriver)");
            const conn = &lease.handle().conn;
            var guard = self.watchdog(conn.serverThreadId(), timeout);
            try guard.arm();
            const result = conn.query(allocator, sql);
            if (guard.disarm()) {
                conn.markBroken();
                if (result) |res| {
                    var owned = res;
                    owned.deinit(allocator);
                } else |_| {}
                return error.CommandTimeout;
            }
            return result;
        }

        /// Snapshot the counters. Mostly for tests and diagnostics.
        pub fn stats(self: *Self) Stats {
            self.mutex.lockUncancelable();
            defer self.mutex.unlock();
            return .{
                .idle = self.idle_count,
                .leased = self.leased_count,
                .total = self.total_count,
                .generation = self.generation,
                .closed = self.closed,
            };
        }

        // --- helpers (all callers hold the mutex unless noted) ---

        fn pushIdle(self: *Self, sess: *Session) void {
            sess.next = self.idle_head;
            self.idle_head = sess;
            self.idle_count += 1;
        }

        fn popIdle(self: *Self) ?*Session {
            const sess = self.idle_head orelse return null;
            self.idle_head = sess.next;
            sess.next = null;
            self.idle_count -= 1;
            return sess;
        }

        /// Detach the whole idle chain (does not adjust counts).
        fn takeIdleChain(self: *Self) ?*Session {
            const head = self.idle_head;
            self.idle_head = null;
            self.idle_count = 0;
            return head;
        }

        fn lifetimeExceeded(self: *Self, sess: *Session, now: u64) bool {
            const max = self.config.max_lifetime_ns;
            return max != 0 and now -| sess.created_ns >= max;
        }

        fn idleExceeded(self: *Self, sess: *Session, now: u64) bool {
            const max = self.config.idle_timeout_ns;
            return max != 0 and now -| sess.last_used_ns >= max;
        }

        /// Can a popped idle session be handed out right now?
        fn canLeaseIdle(self: *Self, sess: *Session, now: u64) bool {
            return sess.generation == self.generation and
                sess.handle.canReuse() and
                !self.lifetimeExceeded(sess, now) and
                !self.idleExceeded(sess, now);
        }

        /// Should an idle session be reaped?
        fn shouldRetire(self: *Self, sess: *Session, now: u64) bool {
            return sess.generation != self.generation or
                !sess.handle.canReuse() or
                self.lifetimeExceeded(sess, now) or
                self.idleExceeded(sess, now);
        }
    };
}

/// Real TCP driver: dials MySQL over zio.net and completes the handshake.
pub const TcpDriver = struct {
    /// Where and how to connect. `options` carries credentials/charset.
    pub const Target = struct {
        host: []const u8,
        port: u16 = 3306,
        options: mantle.ConnectionPhase.Options,
        /// Per-connection socket read/write timeout.
        timeout: zio.Timeout = .none,
        /// connect(2) timeout.
        connect_timeout: zio.Timeout = .none,
    };

    target: Target,

    pub const Handle = struct {
        zs: mantle.transport.ZioStream,
        conn: mantle.Connection,

        pub fn canReuse(self: *const Handle) bool {
            return self.conn.canReuse();
        }

        pub fn isBroken(self: *const Handle) bool {
            return self.conn.isBroken();
        }
    };

    pub fn init(target: Target) TcpDriver {
        return .{ .target = target };
    }

    pub fn open(self: *TcpDriver, allocator: Allocator) !*Handle {
        const handle = try allocator.create(Handle);
        errdefer allocator.destroy(handle);

        const addr = try zio.net.IpAddress.parseIp4(self.target.host, self.target.port);
        const stream = try addr.connect(.{ .timeout = self.target.connect_timeout });
        handle.zs = mantle.transport.ZioStream.init(stream, self.target.timeout);
        errdefer handle.zs.stream.close();

        handle.conn = mantle.Connection.init(.{
            .reader = handle.zs.reader(),
            .writer = handle.zs.writer(),
        }, self.target.options);
        // A failed handshake captures the server's reason (e.g. "Access denied")
        // into `conn.last_error`, whose duped message must be released; `close`
        // is never reached on this path, so deinit the connection explicitly.
        errdefer handle.conn.deinit(allocator);
        try handle.conn.finishHandshake(allocator);

        return handle;
    }

    pub fn close(self: *TcpDriver, allocator: Allocator, handle: *Handle) void {
        _ = self;
        // Best-effort graceful COM_QUIT when the connection is still healthy;
        // a broken/closed connection just drops the socket.
        if (handle.conn.canReuse()) {
            handle.conn.close(allocator) catch {};
        }
        handle.conn.deinit(allocator);
        handle.zs.stream.close();
        allocator.destroy(handle);
    }

    pub fn nowNs(self: *const TcpDriver) u64 {
        _ = self;
        return zio.now().toNanoseconds();
    }

    /// MySQL `ER_NO_SUCH_THREAD`: the target thread already finished, so there
    /// is nothing to cancel — treated as success.
    const er_no_such_thread: u16 = 1094;

    /// Open a short-lived connection to the same target and issue
    /// `KILL QUERY <thread_id>` to cancel an in-flight query on that thread.
    pub fn killQuery(self: *TcpDriver, allocator: Allocator, thread_id: u32) !void {
        const handle = try self.open(allocator);
        defer self.close(allocator, handle);

        var buf: [32]u8 = undefined;
        const sql = try std.fmt.bufPrint(&buf, "KILL QUERY {d}", .{thread_id});
        var result = try handle.conn.query(allocator, sql);
        defer result.deinit(allocator);
        switch (result) {
            .ok => {},
            // The query already finished: nothing left to kill.
            .err => |err| if (err.code != er_no_such_thread) return error.ServerError,
            .result_set => return error.UnexpectedResultSet,
        }
    }
};

/// The concrete pool most consumers want.
pub const TcpPool = Pool(TcpDriver);

/// A leased TCP connection with a concrete, editor-navigable surface.
///
/// Wraps a `TcpPool.Lease` but exposes the connection as a plain
/// `conn: *mantle.Connection` field instead of routing through the generic
/// `Lease.handle().conn`. Because the field type is the concrete
/// `*Connection` written out literally — no generic `Handle` indirection for the
/// language server to resolve — editor "go to definition" follows `db.conn.query`
/// straight into the connection's methods.
///
///     var db = try mantle.PooledConnection.acquire(&pool);
///     defer db.release();
///     var t = try db.conn.queryOne(Row, gpa, "SELECT ...");
///
/// The connection pointer targets the pinned heap `Handle`, so moving the
/// `PooledConnection` by value (e.g. returning it from `acquire`) is safe.
pub const PooledConnection = struct {
    /// The leased connection. Valid until `release`; do not use afterward.
    conn: *mantle.Connection,
    lease: TcpPool.Lease,

    /// Check out a connection from `pool` (blocking up to its acquire timeout).
    pub fn acquire(pool: *TcpPool) !PooledConnection {
        const lease = try pool.acquire();
        return .{ .conn = &lease.handle().conn, .lease = lease };
    }

    /// Return the connection to the pool. Spent afterward.
    pub fn release(self: *PooledConnection) void {
        self.lease.release();
        self.conn = undefined;
    }
};
