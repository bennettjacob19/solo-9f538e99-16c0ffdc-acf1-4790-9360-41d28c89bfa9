"""SQLite layer: schema, connections and the built-in old pool/leases.

Free address space lives in `free_intervals` as half-open [start, end)
ranges of delegation slots. Allocation only touches the first free range,
so its cost depends on the number of *free fragments*, never on the number
of leases inside a contiguous occupied run. The ranges are persisted, so
restart never scans leases to rebuild them.

`routes` holds the committed gateway forwarding table: the minimal CIDR
cover of the new pool's leased slots, maintained incrementally (buddy
merge / expiry split) by the writer process. `route_state` is a one-row
table with the operator-set entry limit (NULL = unlimited) and the
committed entry count, kept as a running counter so leasing and clock
commits never rescan the whole route table.
"""
import ipaddress
import os
import sqlite3

from .common import (DB_PATH, LEASE_SECONDS, block_prefix, decompose_slots,
                     slot_prefix)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    now_seconds INTEGER NOT NULL,
    new_pool_id INTEGER REFERENCES pools(id),
    pending_id INTEGER REFERENCES clock_advance(id)
);

CREATE TABLE IF NOT EXISTS pools(
    id INTEGER PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,
    prefix_len INTEGER NOT NULL,
    deleg_len INTEGER NOT NULL,
    slot_count INTEGER NOT NULL,
    is_new INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS free_intervals(
    pool_id INTEGER NOT NULL REFERENCES pools(id),
    start_slot INTEGER NOT NULL,
    end_slot INTEGER NOT NULL,
    PRIMARY KEY (pool_id, start_slot)
);

CREATE TABLE IF NOT EXISTS leases(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id INTEGER NOT NULL REFERENCES pools(id),
    slot INTEGER NOT NULL,
    prefix TEXT NOT NULL,
    starts_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'expired'))
);
-- At most one active lease per (pool, slot); expired rows stay for history.
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_slot
    ON leases(pool_id, slot) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS clock_advance(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_seconds INTEGER NOT NULL,
    snapshot_ids TEXT NOT NULL,
    snapshot_max_id INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'aborted'))
);

CREATE TABLE IF NOT EXISTS clock_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advance_id INTEGER REFERENCES clock_advance(id),
    event TEXT NOT NULL,
    from_seconds INTEGER,
    to_seconds INTEGER,
    detail TEXT,
    at_seconds INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS withdrawal_publish(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pool_id INTEGER REFERENCES pools(id),
    cidr TEXT,
    earliest_seconds INTEGER,
    published_at INTEGER NOT NULL
);

-- Committed gateway forwarding entries: the minimal CIDR cover of the new
-- pool's leased slots. Blocks are aligned and mutually disjoint, so one
-- pool never holds two entries with the same start_slot.
CREATE TABLE IF NOT EXISTS routes(
    pool_id INTEGER NOT NULL REFERENCES pools(id),
    prefix TEXT NOT NULL,
    prefix_len INTEGER NOT NULL,
    start_slot INTEGER NOT NULL,
    PRIMARY KEY (pool_id, prefix)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_routes_slot
    ON routes(pool_id, start_slot);

-- One-row route-table state: operator limit (NULL = unlimited) and the
-- committed entry count as a running counter (no COUNT(*) rescans).
CREATE TABLE IF NOT EXISTS route_state(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_entries INTEGER,
    entry_count INTEGER NOT NULL DEFAULT 0
);
"""

# Built-in old pool and its leases (simulated time, seconds since epoch).
OLD_CIDR = "2001:db8:aaaa::/48"
OLD_DELEG = 60
# slot -> expiry offset (seconds). Slot 4 is already expired at t=0.
OLD_LEASES = {
    0: 3600,
    1: 3600,
    2: 7200,
    4: 0,        # expired before the drill starts
    5: 7200,
    6: 10800,
}


def connect(db_path=None, readonly=False):
    path = db_path or DB_PATH
    if not os.path.exists(path) and readonly:
        raise FileNotFoundError(path)
    uri = "file:%s%s" % (path, "?mode=ro" if readonly else "")
    conn = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(db_path=None, force=False):
    """Create schema and seed the old pool, its leases, free ranges and the
    initial withdrawal publication. Idempotent unless force=True."""
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if force and os.path.exists(path):
        os.remove(path)
        for side in ("-wal", "-shm"):
            extra = path + side
            if os.path.exists(extra):
                os.remove(extra)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        _migrate_route_tables(conn)
        seeded = conn.execute("SELECT 1 FROM pools WHERE is_new = 0").fetchone()
        if seeded:
            return conn
        conn.execute("BEGIN IMMEDIATE")
        net = ipaddress.IPv6Network(OLD_CIDR)
        slot_count = 1 << (OLD_DELEG - net.prefixlen)
        cur = conn.execute(
            "INSERT INTO pools(cidr, prefix_len, deleg_len, slot_count, is_new)"
            " VALUES (?, ?, ?, ?, 0)",
            (OLD_CIDR, net.prefixlen, OLD_DELEG, slot_count))
        pool_id = cur.lastrowid
        for slot, expiry in sorted(OLD_LEASES.items()):
            status = "active" if expiry > 0 else "expired"
            conn.execute(
                "INSERT INTO leases(pool_id, slot, prefix, starts_at,"
                " expires_at, status) VALUES (?, ?, ?, ?, ?, ?)",
                (pool_id, slot, slot_prefix(net, OLD_DELEG, slot),
                 -LEASE_SECONDS if expiry > 0 else -7200,
                 expiry, status))
        # Free complement of slots with an ACTIVE lease. The pre-expired
        # lease (slot 4) stays occupied until a clock-advance transaction
        # releases its slot, which is the only path that mutates free space.
        occupied = {slot for slot, expiry in OLD_LEASES.items() if expiry > 0}
        start = None
        for slot in range(slot_count + 1):
            if slot < slot_count and slot not in occupied:
                if start is None:
                    start = slot
            elif start is not None:
                conn.execute(
                    "INSERT INTO free_intervals(pool_id, start_slot, end_slot)"
                    " VALUES (?, ?, ?)", (pool_id, start, slot))
                start = None
        conn.execute(
            "INSERT INTO meta(id, now_seconds, new_pool_id, pending_id)"
            " VALUES (1, 0, NULL, NULL)")
        # First publication: no new pool -> every old lease is uncovered.
        conn.execute(
            "INSERT INTO withdrawal_publish(id, pool_id, cidr,"
            " earliest_seconds, published_at) VALUES (1, NULL, NULL, ?, 0)",
            (_earliest_old_expiry(conn, pool_id),))
        conn.execute(
            "INSERT INTO clock_log(advance_id, event, from_seconds, to_seconds,"
            " detail, at_seconds) VALUES (NULL, 'seed', NULL, NULL, ?, 0)",
            ("内置旧池 %s，%d 条租约（含 1 条已到期）"
             % (OLD_CIDR, len(OLD_LEASES)),))
        conn.execute("COMMIT")
        return conn
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _earliest_old_expiry(conn, old_pool_id):
    row = conn.execute(
        "SELECT MIN(expires_at) AS t FROM leases"
        " WHERE pool_id = ? AND status = 'active'", (old_pool_id,)).fetchone()
    return row["t"]


def _migrate_route_tables(conn):
    """One-time upgrade for volumes created before route tracking existed.

    Inserts the route_state row and, if a new pool is already live, derives
    its committed routes from the persisted free intervals: leased slots
    are exactly the complement of free space, so the minimal cover is
    rebuilt without scanning leases and without expanding the pool slot by
    slot. On a fresh database this only plants the empty route_state row.
    """
    if conn.execute("SELECT 1 FROM route_state WHERE id = 1").fetchone():
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute("SELECT 1 FROM route_state WHERE id = 1").fetchone():
            conn.execute("COMMIT")
            return
        conn.execute(
            "INSERT INTO route_state(id, max_entries, entry_count)"
            " VALUES (1, NULL, 0)")
        new = conn.execute("SELECT * FROM pools WHERE is_new = 1").fetchone()
        if new is not None:
            net = ipaddress.IPv6Network(new["cidr"])
            free_rows = conn.execute(
                "SELECT start_slot, end_slot FROM free_intervals"
                " WHERE pool_id = ? ORDER BY start_slot",
                (new["id"],)).fetchall()
            blocks = []
            pos = 0
            for row in free_rows:
                blocks.extend(decompose_slots(pos, row["start_slot"]))
                pos = row["end_slot"]
            blocks.extend(decompose_slots(pos, new["slot_count"]))
            for start, span in blocks:
                plen = new["deleg_len"] - (span.bit_length() - 1)
                conn.execute(
                    "INSERT INTO routes(pool_id, prefix, prefix_len,"
                    " start_slot) VALUES (?, ?, ?, ?)",
                    (new["id"],
                     block_prefix(net, new["deleg_len"], start, plen),
                     plen, start))
            conn.execute(
                "UPDATE route_state SET entry_count = ? WHERE id = 1",
                (len(blocks),))
            conn.execute(
                "INSERT INTO clock_log(advance_id, event, from_seconds,"
                " to_seconds, detail, at_seconds)"
                " VALUES (NULL, 'route-migrate', NULL, NULL, ?,"
                " (SELECT now_seconds FROM meta WHERE id = 1))",
                ("旧卷升级：按持久化空闲区间的补集重建新池 %s 的已生效路由"
                 " %d 条，未回扫租约" % (new["cidr"], len(blocks)),))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def recover_pending(conn):
    """Roll back any prepared-but-not-committed advance left by a crash.

    The clock and issued leases are already committed state, so recovery
    only discards the staging row; both sides then resume from the same
    committed state.
    """
    row = conn.execute(
        "SELECT id FROM clock_advance WHERE state = 'pending'").fetchone()
    if not row:
        return None
    conn.execute("BEGIN IMMEDIATE")
    now = conn.execute("SELECT now_seconds FROM meta WHERE id = 1").fetchone()["now_seconds"]
    conn.execute(
        "UPDATE clock_advance SET state = 'aborted' WHERE id = ?", (row["id"],))
    conn.execute("UPDATE meta SET pending_id = NULL WHERE id = 1")
    conn.execute(
        "INSERT INTO clock_log(advance_id, event, from_seconds, to_seconds,"
        " detail, at_seconds) VALUES (?, 'recover-abort', ?, ?, ?, ?)",
        (row["id"], now, now, "重启时发现未提交推进，按已提交状态恢复", now))
    conn.execute("COMMIT")
    return row["id"]
