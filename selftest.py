"""End-to-end self tests for the IPv6 pool-swap drill (stdlib only).

Run:  python3 selftest.py
Covers: seed data, invalid config rollback, disjoint pool swap, /56 and /60
boundaries, first-fit leasing and pool-full, clock expiry including leases
taken during the pause, list-changed redo, fault-injected commit
interruption, read-only gateway, restart recovery without lease scans,
O(1)-ish allocation cost — plus the gateway route table: entry limit and
usage, batch buddy-merge and expiry split against the minimal CIDR cover,
limit-overflow rollback for both leasing and clock commit, committed-only
probes with table-size-independent read counts, restart persistence and
old-volume migration.
"""
import ipaddress
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.db import connect, init_db, recover_pending          # noqa: E402
from app.gateway import create_app as gateway_app             # noqa: E402
from app.web import create_app as web_app                     # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s %s" % (name, detail))
    else:
        FAIL += 1
        print("  FAIL  %s %s" % (name, detail))


def fresh_db():
    tmp = tempfile.mkdtemp(prefix="drill-")
    path = os.path.join(tmp, "test.db")
    init_db(path, force=True).close()
    return path


def jpost(client, url, payload=None, raw=False):
    if raw:
        resp = client.post(url, data=payload or {})
    else:
        resp = client.post(url, json=payload or {})
    return resp.status_code, resp.get_json()


def db_routes(path):
    """Committed route prefixes of the new pool, plus the counter state."""
    conn = connect(path)
    rows = conn.execute(
        "SELECT r.prefix FROM routes r JOIN pools p ON p.id = r.pool_id"
        " ORDER BY r.start_slot").fetchall()
    st = conn.execute("SELECT * FROM route_state WHERE id = 1").fetchone()
    raw_count = conn.execute("SELECT COUNT(*) AS c FROM routes").fetchone()["c"]
    conn.close()
    return sorted(r["prefix"] for r in rows), st, raw_count


def reference_cover(cidr, deleg_len, slots):
    """Minimal CIDR cover of the given leased slots, computed from scratch
    with ipaddress.summarize_address_range (the oracle for route tests)."""
    net = ipaddress.IPv6Network(cidr)
    base = int(net.network_address)
    unit = 1 << (128 - deleg_len)
    slots = sorted(slots)
    out, i = [], 0
    while i < len(slots):
        j = i
        while j + 1 < len(slots) and slots[j + 1] == slots[j] + 1:
            j += 1
        out += [str(p) for p in ipaddress.summarize_address_range(
            ipaddress.IPv6Address(base + slots[i] * unit),
            ipaddress.IPv6Address(base + (slots[j] + 1) * unit - 1))]
        i = j + 1
    return sorted(out)


def active_slots(path, pool_id=2):
    conn = connect(path)
    rows = conn.execute(
        "SELECT slot FROM leases WHERE pool_id = ? AND status = 'active'",
        (pool_id,)).fetchall()
    conn.close()
    return [r["slot"] for r in rows]


def check_routes_consistent(path, cidr, deleg_len, label):
    """Routes must equal the minimal cover of active leases, and the
    running counter must equal the real row count."""
    routes, st, raw_count = db_routes(path)
    expect = reference_cover(cidr, deleg_len, active_slots(path))
    check("%s：路由=最简覆盖且计数器一致（%d 条）" % (label, len(expect)),
          routes == expect and st["entry_count"] == len(expect)
          and raw_count == len(expect))


# --------------------------------------------------------------------------
def test_seed_and_gateway():
    print("[1] 种子数据与只读网关撤路视图")
    path = fresh_db()
    conn = connect(path)
    rows = conn.execute("SELECT slot, status FROM leases ORDER BY slot").fetchall()
    check("内置 6 条旧租约（5 active + 1 expired）", len(rows) == 6
          and sum(1 for r in rows if r["status"] == "active") == 5)
    fr = conn.execute(
        "SELECT start_slot,end_slot FROM free_intervals ORDER BY start_slot"
    ).fetchall()
    # slot 4's lease is already expired at drill start, so its slot is free;
    # free ranges are [3,5) and [7,4096). No candidate prefix list is built.
    check("旧池空闲区间为 [3,5) 与 [7,4096)，未展开候选前缀",
          [(r["start_slot"], r["end_slot"]) for r in fr] == [(3, 5), (7, 4096)])
    check("模拟时钟初始为 0",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 0)
    conn.close()

    gw = gateway_app(path).test_client()
    resp = gw.get("/withdrawal")
    body = resp.get_json()
    check("无新池时最早撤路时刻=最早旧租约到期 3600",
          body["earliest_withdrawal_seconds"] == 3600)
    check("无新池时 5 条有效旧租约全部未覆盖", body["uncovered_count"] == 5)

    ro = connect(path, readonly=True)
    try:
        blocked = False
        try:
            ro.execute("UPDATE meta SET now_seconds = 1")
        except sqlite3.OperationalError:
            blocked = True
        check("网关连接为只读，写入被 SQLite 拒绝", blocked)
    finally:
        ro.close()


def test_invalid_config_keeps_state():
    print("[2] 无效新池配置保留原状")
    path = fresh_db()
    client = web_app(path).test_client()
    before = connect(path).execute(
        "SELECT now_seconds, new_pool_id FROM meta").fetchone()
    bad_inputs = [
        ("not-a-cidr", 60),
        ("2001:db8::/128", 60),          # deleg shorter than pool prefix
        ("2001:db8::/56", 64),           # deleg not 56/60
        ("2001:db8::1/56", 56),          # host bits set, strict parse fails
        ("10.0.0.0/24", 60),             # IPv4
    ]
    for cidr, deleg in bad_inputs:
        code, body = jpost(client, "/api/pool", {"cidr": cidr, "deleg_len": deleg})
        check("拒绝无效配置 %s /%d" % (cidr, deleg),
              code == 400 and body["ok"] is False)
    after = connect(path).execute(
        "SELECT now_seconds, new_pool_id FROM meta").fetchone()
    check("全部拒绝后时钟与池状态不变", tuple(before) == tuple(after))


def test_swap_disjoint_rule():
    print("[3] 换池须与旧池不相交；交叠配置整单回滚")
    path = fresh_db()
    client = web_app(path).test_client()
    gw = gateway_app(path).test_client()

    # A new pool inside the old aggregate must be rejected, state preserved.
    code, body = jpost(client, "/api/pool",
                       {"cidr": "2001:db8:aaaa:20::/60", "deleg_len": 60})
    check("旧池内部的新池被拒（交叠）", code == 400 and "不相交" in body["error"])
    code, body = jpost(client, "/api/pool",
                       {"cidr": "2001:db8:aaaa::/47", "deleg_len": 56})
    check("包含旧池的新池同样被拒", code == 400 and "不相交" in body["error"])
    conn = connect(path)
    check("交叠配置回滚后无新池、时钟为 0",
          tuple(conn.execute(
              "SELECT new_pool_id, now_seconds FROM meta").fetchone())
          == (None, 0))
    conn.close()

    code, body = jpost(client, "/api/pool",
                       {"cidr": "2001:db8:bbbb::/56", "deleg_len": 56})
    check("不相交新池上线成功", code == 200 and body["slots"] == 1)
    view = gw.get("/withdrawal").get_json()
    check("不相交新池不覆盖任何旧租约，未覆盖=5", view["uncovered_count"] == 5)
    check("最早撤路时刻仍为 3600", view["earliest_withdrawal_seconds"] == 3600)
    routes, st, _ = db_routes(path)
    check("换池后路由表为空、用量 0、未设限",
          routes == [] and st["entry_count"] == 0
          and st["max_entries"] is None)

    code, body = jpost(client, "/api/pool",
                       {"cidr": "2001:db8:zzzz::/56", "deleg_len": 56})
    check("单次演练禁止二次换池", code == 400)


def test_slash56_boundary():
    print("[3b] /56 委派长度与严格边界")
    path = fresh_db()
    client = web_app(path).test_client()
    # /56 pool with /56 delegation: one slot, strict boundary network.
    code, body = jpost(client, "/api/pool",
                       {"cidr": "2001:db8:bbbb::/56", "deleg_len": 56})
    check("/56 池 + /56 委派合法（1 个前缀）", code == 200 and body["slots"] == 1)
    code, body = jpost(client, "/api/lease", {"count": 1})
    check("/56 委派前缀正确", code == 200
          and body["issued"][0]["prefix"] == "2001:db8:bbbb::/56")


def test_lease_and_pool_full():
    print("[4] 领址：60 分钟、避开未到期前缀、池满提示")
    path = fresh_db()
    client = web_app(path).test_client()
    # First lease on the old pool must take the first free slot = 3.
    code, body = jpost(client, "/api/lease", {"count": 1})
    check("首笔领址取空闲区间首槽 slot3（不回扫在租明细）",
          code == 200 and body["issued"][0]["slot"] == 3
          and body["issued"][0]["expires_at"] == 3600)

    # One-slot pool: /60 CIDR with /60 delegation.
    path2 = fresh_db()
    c2 = web_app(path2).test_client()
    jpost(c2, "/api/pool", {"cidr": "2001:db8:cccc::/60", "deleg_len": 60})
    code, body = jpost(c2, "/api/lease", {"count": 1})
    check("单槽池首次领址成功", code == 200 and body["issued"][0]["slot"] == 0)
    code, body = jpost(c2, "/api/lease", {"count": 1})
    check("池满返回 400 提示且不写入", code == 400 and "池满" in body["error"])
    conn = connect(path2)
    check("池满后新池在租仍为 1 条", conn.execute(
        "SELECT COUNT(*) c FROM leases l JOIN pools p ON p.id=l.pool_id"
        " WHERE p.is_new=1 AND l.status='active'").fetchone()["c"] == 1)
    conn.close()


def test_expiry_with_pause_leases():
    print("[5] 时钟推进：暂停期间新领且本次到期的租约须计入")
    path = fresh_db()
    client = web_app(path).test_client()
    gw = gateway_app(path).test_client()

    code, body = jpost(client, "/api/advance", {"target_seconds": 3600})
    check("暂停核算成功，预计到期旧租约 2 条（slot0/1）",
          code == 200 and sorted(body["expected_expiries"]) == [1, 2])

    # Leasing stays available while paused; new lease expires at 0+3600.
    code, leased = jpost(client, "/api/lease", {"count": 1})
    new_id = leased["issued"][0]["id"]
    check("暂停期间照常领址", code == 200 and leased["issued"][0]["expires_at"] == 3600)
    # Gateway keeps answering with committed state during the pause.
    check("暂停期间网关仍可查撤路",
          gw.get("/withdrawal").status_code == 200)

    code, body = jpost(client, "/api/advance/commit")
    check("提交成功", code == 200)
    check("本次到期共 3 条，暂停新领租约计入 added",
          sorted(body["settled"]) == [1, 2, new_id] and body["added"] == [new_id])
    conn = connect(path)
    check("时钟推进到 3600",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 3600)
    check("到期租约状态为 expired", conn.execute(
        "SELECT COUNT(*) c FROM leases WHERE id IN (1,2,?) AND status='expired'",
        (new_id,)).fetchone()["c"] == 3)
    # Slots 0,1 and the new slot-3 lease expire together, but slot 2 is still
    # leased until t=7200, so its gap must remain. The released ranges
    # coalesce to [0,2) and [3,5); slot 4's pre-expired range stays inside.
    fr = [tuple(r) for r in conn.execute(
        "SELECT start_slot,end_slot FROM free_intervals ORDER BY start_slot")]
    check("释放槽位按占用缺口合并：[0,2),[3,5),[7,4096)",
          fr == [(0, 2), (3, 5), (7, 4096)])
    check("未到期旧租约（slot2/5/6）保持 active", conn.execute(
        "SELECT COUNT(*) c FROM leases WHERE status='active'").fetchone()["c"] == 3)
    conn.close()
    view = gw.get("/withdrawal").get_json()
    check("撤路结论随提交同时生效：最早撤路变为 7200",
          view["earliest_withdrawal_seconds"] == 7200
          and view["uncovered_count"] == 3)

    # Second batch: slots 2 and 5 expire at t=7200; the whole [0,6) run must
    # now collapse into one maximal range despite cross-batch release order.
    jpost(client, "/api/advance", {"target_seconds": 7200})
    code, body = jpost(client, "/api/advance/commit")
    check("第二批推进成功", code == 200 and sorted(body["settled"]) == [3, 5])
    conn = connect(path)
    fr2 = [tuple(r) for r in conn.execute(
        "SELECT start_slot,end_slot FROM free_intervals ORDER BY start_slot")]
    check("跨批次相邻释放塌缩为 [0,6),[7,4096)", fr2 == [(0, 6), (7, 4096)])
    conn.close()


def test_list_changed_redo():
    print("[6] 名单变化退回：提示重做，保留原时钟与已领租约")
    path = fresh_db()
    client = web_app(path).test_client()
    jpost(client, "/api/advance", {"target_seconds": 3600})
    code, leased = jpost(client, "/api/lease", {"count": 1})
    kept_id = leased["issued"][0]["id"]

    # Simulate an external change to the due list (lease 2 no longer due).
    conn = connect(path)
    conn.execute("UPDATE leases SET expires_at = 9000 WHERE id = 2")
    conn.close()

    code, body = jpost(client, "/api/advance/commit")
    check("名单变化返回 409 并要求重做", code == 409 and body.get("redo_required"))
    conn = connect(path)
    check("退回后时钟仍为 0",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 0)
    check("退回后 pending 已清除",
          conn.execute("SELECT pending_id FROM meta").fetchone()[0] is None)
    check("暂停期间所领租约保留且 active", conn.execute(
        "SELECT status FROM leases WHERE id=?", (kept_id,)).fetchone()[0] == "active")
    check("被改动租约的修改也未回滚（仅推进事务退回）", conn.execute(
        "SELECT expires_at FROM leases WHERE id=2").fetchone()[0] == 9000)
    conn.close()

    # Redo at the same target: lease 2 is no longer due, while lease 1 and
    # the lease taken during the aborted pause (kept_id) still expire at 3600.
    code, body = jpost(client, "/api/advance", {"target_seconds": 3600})
    check("可重新发起推进", code == 200
          and sorted(body["expected_expiries"]) == sorted([1, kept_id]))
    code, body = jpost(client, "/api/advance/commit")
    check("重做后提交成功", code == 200
          and sorted(body["settled"]) == sorted([1, kept_id]))


def test_commit_interruption():
    print("[7] 提交中断：进程在 COMMIT 前丢失，按同一已提交状态恢复")
    path = fresh_db()
    client = web_app(path).test_client()
    gw = gateway_app(path).test_client()
    jpost(client, "/api/advance", {"target_seconds": 7200})
    code, leased = jpost(client, "/api/lease", {"count": 2})
    kept_ids = [x["id"] for x in leased["issued"]]

    resp = client.post("/api/advance/commit", json={"fault_inject": True})
    check("故障注入返回 500", resp.status_code == 500
          and resp.get_json()["restart_recovery"])

    # A new request triggers startup-style recovery of the stale pending row.
    recovered = recover_pending(connect(path))
    check("恢复流程识别并中止悬挂推进", recovered is not None)
    conn = connect(path)
    check("恢复后时钟仍为 0（无部分生效）",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 0)
    check("恢复后无 pending",
          conn.execute("SELECT pending_id FROM meta").fetchone()[0] is None)
    check("已领租约全部保留 active", conn.execute(
        "SELECT COUNT(*) c FROM leases WHERE id IN (%s) AND status='active'"
        % ",".join("?" * len(kept_ids)), kept_ids).fetchone()["c"] == 2)
    check("无租约被提前到期", conn.execute(
        "SELECT COUNT(*) c FROM leases WHERE status='expired'"
    ).fetchone()["c"] == 1)  # only the pre-seeded expired one
    conn.close()
    check("网关在恢复后读到一致已提交状态",
          gw.get("/withdrawal").get_json()["earliest_withdrawal_seconds"] == 3600)


def test_restart_and_no_scan():
    print("[8] 重启不回扫在租明细；找空位开销不随连续占用段增长")
    path = fresh_db()
    env = dict(os.environ, DRILL_DB=path, PYTHONPATH=os.path.dirname(
        os.path.abspath(__file__)))
    code = ("from app.web import create_app;"
            "create_app(%r).run(port=8077, use_reloader=False)" % path)
    proc = subprocess.Popen([sys.executable, "-c", code], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_port(8077)
        def call(url, payload):
            import json
            req = urllib.request.Request(
                "http://127.0.0.1:8077" + url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            return json.loads(urllib.request.urlopen(req).read())
        # /48 pool with /60 delegation -> 4096 slots; take 500 contiguous.
        call("/api/pool", {"cidr": "2001:db8:dddd::/48", "deleg_len": 60})
        call("/api/lease", {"count": 500})
    finally:
        proc.kill()
        proc.wait()

    conn = connect(path)
    frags = conn.execute(
        "SELECT COUNT(*) c FROM free_intervals WHERE pool_id=2").fetchone()["c"]
    check("重启前空闲区间仅 1 个连续段 [500,4096)", frags == 1)
    conn.close()

    # Restart: no lease scan rebuilds free space; persisted ranges are used.
    proc = subprocess.Popen([sys.executable, "-c", code], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_port(8077)
        import json
        req = urllib.request.Request(
            "http://127.0.0.1:8077/api/lease",
            data=json.dumps({"count": 1}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        t0 = time.perf_counter()
        body = json.loads(urllib.request.urlopen(req).read())
        elapsed_ms = (time.perf_counter() - t0) * 1000
        check("重启后首笔领址直接命中持久化区间首槽 slot500",
              body["issued"][0]["slot"] == 500)
        check("找空位耗时不随 500 条连续占用增长（实测 %.2fms < 200ms）" % elapsed_ms,
              elapsed_ms < 200)
    finally:
        proc.kill()
        proc.wait()


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("port %d not ready" % port)


def test_abort_and_non_advance():
    print("[9] 手动退回与非法推进参数")
    path = fresh_db()
    client = web_app(path).test_client()
    code, _ = jpost(client, "/api/advance", {"target_seconds": 3600})
    check("可暂停", code == 200)
    code, body = jpost(client, "/api/advance", {"target_seconds": 7200})
    check("暂停中拒绝第二次暂停", code == 400)
    code, _ = jpost(client, "/api/advance/abort")
    check("手动退回成功", code == 200)
    code, body = jpost(client, "/api/advance", {"target_seconds": 0})
    check("目标时刻不大于当前时钟被拒", code == 400)
    conn = connect(path)
    check("退回/拒绝后时钟保持 0",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 0)
    conn.close()


NEW_CIDR, NEW_DELEG = "2001:db8:eeee::/48", 60


def test_route_limit_and_lease_overflow():
    print("[10] 路由限额：设置/查看/低于用量不生效/领址超限整单回滚")
    path = fresh_db()
    client = web_app(path).test_client()
    jpost(client, "/api/pool", {"cidr": NEW_CIDR, "deleg_len": NEW_DELEG})

    code, body = jpost(client, "/api/route-limit", {"limit": "abc"})
    check("非整数限额被拒", code == 400)
    code, body = jpost(client, "/api/route-limit", {"limit": -2})
    check("负数限额被拒", code == 400)

    code, _ = jpost(client, "/api/lease", {"count": 2})
    routes, st, _ = db_routes(path)
    check("领址 2 个合并为 1 条 /59，用量可见",
          routes == ["2001:db8:eeee::/59"] and st["entry_count"] == 1)

    code, body = jpost(client, "/api/route-limit", {"limit": 0})
    check("限额 0 低于当前用量 1，不生效", code == 400 and "未生效" in body["error"])
    _, st, _ = db_routes(path)
    check("原限额保持不变（未设限）", st["max_entries"] is None)

    code, body = jpost(client, "/api/route-limit", {"limit": 2})
    check("限额 2（≥ 用量 1）生效", code == 200 and body["max_entries"] == 2
          and body["usage"] == 1)

    code, _ = jpost(client, "/api/lease", {"count": 2})
    routes, st, _ = db_routes(path)
    check("再领 2 个塌缩为 1 条 /58，未超限",
          routes == ["2001:db8:eeee::/58"] and st["entry_count"] == 1)

    # A batch of 3 more leases would need 3 entries (/58 + /59 + /60).
    code, body = jpost(client, "/api/lease", {"count": 3})
    check("领址超限被拒并提示所需条目数 3 与上限 2",
          code == 400 and "共需 3 条" in body["error"]
          and "上限 2 条" in body["error"])
    conn = connect(path)
    check("回滚后新池在租仍为 4 条、时钟 0",
          conn.execute("SELECT COUNT(*) c FROM leases"
                       " WHERE pool_id = 2 AND status = 'active'"
                       ).fetchone()["c"] == 4
          and conn.execute("SELECT now_seconds FROM meta"
                           ).fetchone()[0] == 0)
    conn.close()
    routes, st, _ = db_routes(path)
    check("回滚后路由保持 1 条 /58",
          routes == ["2001:db8:eeee::/58"] and st["entry_count"] == 1)

    code, body = jpost(client, "/api/route-limit", {"limit": ""})
    check("留空清除限额", code == 200 and body["max_entries"] is None)
    code, _ = jpost(client, "/api/lease", {"count": 3})
    check("清除后同批领址成功", code == 200)
    check_routes_consistent(path, NEW_CIDR, NEW_DELEG, "领址 7 个后")


def test_route_merge_split_and_commit_overflow():
    print("[11] 批量合并与到期拆分；提交超限保留原时钟/租约/路由")
    path = fresh_db()
    client = web_app(path).test_client()
    jpost(client, "/api/pool", {"cidr": NEW_CIDR, "deleg_len": NEW_DELEG})

    jpost(client, "/api/lease", {"count": 4})            # slots 0-3, exp 3600
    routes, _, _ = db_routes(path)
    check("4 连租合并为 1 条 /58", routes == ["2001:db8:eeee::/58"])

    jpost(client, "/api/advance", {"target_seconds": 1800})
    jpost(client, "/api/advance/commit")                 # nothing expires
    jpost(client, "/api/lease", {"count": 4})            # slots 4-7, exp 5400
    routes, st, _ = db_routes(path)
    check("整批 8 连租塌缩为 1 条 /57",
          routes == ["2001:db8:eeee::/57"] and st["entry_count"] == 1)

    jpost(client, "/api/advance", {"target_seconds": 3600})
    jpost(client, "/api/advance/commit")                 # new slots 0-3 expire
    routes, _, _ = db_routes(path)
    check("前半到期后余 4-7 为 1 条 /58",
          routes == ["2001:db8:eeee:40::/58"])

    jpost(client, "/api/lease", {"count": 2})            # slots 0,1 exp 7200
    jpost(client, "/api/advance", {"target_seconds": 5400})
    jpost(client, "/api/advance/commit")                 # slots 4-7 expire
    routes, _, _ = db_routes(path)
    check("再到期后余 0-1 为 1 条 /59", routes == ["2001:db8:eeee::/59"])

    jpost(client, "/api/lease", {"count": 4})            # slots 2-5 exp 9000
    jpost(client, "/api/lease", {"count": 2})            # slots 6,7 exp 9000
    routes, _, _ = db_routes(path)
    check("重新并满 0-7 为 1 条 /57", routes == ["2001:db8:eeee::/57"])

    code, _ = jpost(client, "/api/route-limit", {"limit": 1})
    check("限额 1（= 当前用量）生效", code == 200)

    # Advance to 7200: new slots 0,1 expire, the /57 must split into 2.
    jpost(client, "/api/advance", {"target_seconds": 7200})
    code, body = jpost(client, "/api/advance/commit")
    check("到期拆分需 2 条超过限额 1，提交被拒并提示所需条目数",
          code == 400 and "共需 2 条" in body["error"])
    conn = connect(path)
    check("原时钟保留在 5400",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 5400)
    check("推进保持待提交，可提高限额后重试",
          conn.execute("SELECT pending_id FROM meta").fetchone()[0] is not None)
    check("应到期的新池租约全部保留 active",
          conn.execute("SELECT COUNT(*) c FROM leases"
                       " WHERE pool_id = 2 AND status = 'active'"
                       ).fetchone()["c"] == 8)
    conn.close()
    routes, st, _ = db_routes(path)
    check("路由保持 1 条 /57",
          routes == ["2001:db8:eeee::/57"] and st["entry_count"] == 1)

    code, _ = jpost(client, "/api/route-limit", {"limit": 5})
    check("提高限额至 5", code == 200)
    code, _ = jpost(client, "/api/advance/commit")
    check("重试提交成功", code == 200)
    routes, st, _ = db_routes(path)
    check("到期拆分生效：/57 拆为 /59 + /58 共 2 条",
          routes == ["2001:db8:eeee:20::/59", "2001:db8:eeee:40::/58"]
          and st["entry_count"] == 2)
    conn = connect(path)
    check("时钟推进到 7200",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 7200)
    conn.close()
    check_routes_consistent(path, NEW_CIDR, NEW_DELEG, "拆分提交后")

    # Fault-injected commit: the split must roll back with everything else.
    jpost(client, "/api/advance", {"target_seconds": 9000})
    resp = client.post("/api/advance/commit", json={"fault_inject": True})
    check("故障注入返回 500", resp.status_code == 500)
    rec = recover_pending(connect(path))
    check("恢复流程中止悬挂推进", rec is not None)
    conn = connect(path)
    check("中断后时钟仍为 7200",
          conn.execute("SELECT now_seconds FROM meta").fetchone()[0] == 7200)
    conn.close()
    routes, st, _ = db_routes(path)
    check("中断后路由保持拆分后的 2 条（无部分生效）",
          routes == ["2001:db8:eeee:20::/59", "2001:db8:eeee:40::/58"]
          and st["entry_count"] == 2)
    check_routes_consistent(path, NEW_CIDR, NEW_DELEG, "中断恢复后")


def test_gateway_probe():
    print("[12] 网关探测：命中/丢弃/只按已提交路由/读取数不随表项增长")
    path = fresh_db()
    client = web_app(path).test_client()
    gw = gateway_app(path).test_client()
    jpost(client, "/api/pool", {"cidr": NEW_CIDR, "deleg_len": NEW_DELEG})
    jpost(client, "/api/lease", {"count": 4})            # slots 0-3 -> /58

    resp = gw.get("/probe?address=2001:db8:eeee::1")
    body = resp.get_json()
    check("在租地址命中 /58", resp.status_code == 200
          and body["action"] == "hit"
          and body["prefix"] == "2001:db8:eeee::/58")
    body = gw.get("/probe?address=2001:db8:eeee:50::").get_json()
    check("池内空闲地址丢弃", body["action"] == "drop" and body["prefix"] is None)
    miss_lookups = body["route_lookups"]
    check("旧池地址丢弃",
          gw.get("/probe?address=2001:db8:aaaa::").get_json()["action"] == "drop")
    check("非法地址返回 400", gw.get("/probe?address=not-an-ip").status_code == 400)

    # A route written but not committed must be invisible to the gateway.
    conn = connect(path)
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO routes(pool_id, prefix, prefix_len, start_slot)"
        " VALUES (2, '2001:db8:eeee:50::/60', 60, 5)")
    body = gw.get("/probe?address=2001:db8:eeee:50::1").get_json()
    check("未提交路由对网关不可见（仍丢弃）", body["action"] == "drop")
    conn.execute("ROLLBACK")
    conn.close()

    # Grow the table to 6 entries; a miss probe reads the same number of
    # route records as with the 1-entry table.
    jpost(client, "/api/lease", {"count": 500})
    _, st, _ = db_routes(path)
    check("表项增长到 6 条", st["entry_count"] == 6)
    body = gw.get("/probe?address=2001:db8:eeee:3e80::").get_json()  # slot 1000
    check("丢弃探测读取数不随表项增长（%d == %d）"
          % (body["route_lookups"], miss_lookups),
          body["route_lookups"] == miss_lookups)
    check("读取数不超过池前缀长度范围（≤13）", body["route_lookups"] <= 13)
    body = gw.get("/probe?address=2001:db8:eeee::1").get_json()
    check("大表下命中仍正确（/52）", body["action"] == "hit"
          and body["prefix"] == "2001:db8:eeee::/52")

    resp = gw.get("/")
    check("网关探测网页可打开",
          resp.status_code == 200 and "路由探测" in resp.get_data(as_text=True))
    page = gw.get("/?address=2001:db8:eeee::1").get_data(as_text=True)
    check("网页显示命中前缀", "命中" in page and "2001:db8:eeee::/52" in page)
    page = gw.get("/?address=2001:db8:aaaa::").get_data(as_text=True)
    check("网页显示丢弃", "丢弃" in page)


def test_restart_persistence_and_migration():
    print("[13] 重启保留限额与已生效路由；旧卷一次性迁移重建路由")
    path = fresh_db()
    client = web_app(path).test_client()
    jpost(client, "/api/pool", {"cidr": NEW_CIDR, "deleg_len": NEW_DELEG})
    jpost(client, "/api/lease", {"count": 6})            # slots 0-5
    jpost(client, "/api/route-limit", {"limit": 9})
    before, before_st, _ = db_routes(path)
    check("初始用量 2 条（/58 + /59）",
          before == ["2001:db8:eeee:40::/59", "2001:db8:eeee::/58"]
          and before_st["entry_count"] == 2)

    # Restart: a fresh app instance on the same volume file.
    web_app(path)
    routes, st, _ = db_routes(path)
    check("重启后限额与已生效路由保留",
          routes == before and st["max_entries"] == 9
          and st["entry_count"] == before_st["entry_count"])
    gw = gateway_app(path).test_client()
    check("重启后网关探测仍命中",
          gw.get("/probe?address=2001:db8:eeee::1"
                 ).get_json()["action"] == "hit")

    # Simulate a volume written before route tracking existed.
    conn = connect(path)
    conn.execute("DROP TABLE routes")
    conn.execute("DROP TABLE route_state")
    conn.close()
    web_app(path)  # startup migration rebuilds from free intervals
    routes, st, _ = db_routes(path)
    expect = reference_cover(NEW_CIDR, NEW_DELEG, active_slots(path))
    check("旧卷迁移按空闲区间补集重建路由（不回扫租约）",
          routes == expect == before and st["entry_count"] == 2
          and st["max_entries"] is None)
    row = connect(path).execute(
        "SELECT detail FROM clock_log WHERE event = 'route-migrate'"
    ).fetchone()
    check("迁移写入日志", row is not None and "重建" in row["detail"])


def test_routes_fuzz_minimal_cover():
    print("[14] 随机批量领址/推进：路由恒等于最简覆盖，计数器一致")
    path = fresh_db()
    client = web_app(path).test_client()
    cidr, deleg = "2001:db8:ffff::/52", 60               # 256 slots
    jpost(client, "/api/pool", {"cidr": cidr, "deleg_len": deleg})
    rng = random.Random(20261124)
    ok, merges, splits, prev = True, 0, 0, 0
    for step in range(60):
        if rng.random() < 0.6:
            jpost(client, "/api/lease", {"count": rng.randint(1, 6)})
        else:
            now = connect(path).execute(
                "SELECT now_seconds FROM meta").fetchone()[0]
            code, _ = jpost(client, "/api/advance",
                            {"target_seconds":
                             now + rng.choice([600, 1800, 3600, 7200])})
            if code == 200:
                jpost(client, "/api/advance/commit")
        routes, st, raw = db_routes(path)
        expect = reference_cover(cidr, deleg, active_slots(path))
        if not (routes == expect and st["entry_count"] == len(expect)
                and raw == len(expect)):
            ok = False
            print("    第 %d 步不一致：routes=%s expect=%s" % (step, routes, expect))
            break
        merges += len(expect) < prev
        splits += len(expect) > prev
        prev = len(expect)
    check("60 步随机批量合并/到期拆分后路由恒为最简覆盖", ok)
    check("过程中合并与拆分都真实发生（合并 %d 次、拆分 %d 次）" % (merges, splits),
          merges > 0 and splits > 0)


if __name__ == "__main__":
    tests = [test_seed_and_gateway, test_invalid_config_keeps_state,
             test_swap_disjoint_rule, test_slash56_boundary,
             test_lease_and_pool_full,
             test_expiry_with_pause_leases, test_list_changed_redo,
             test_commit_interruption, test_restart_and_no_scan,
             test_abort_and_non_advance,
             test_route_limit_and_lease_overflow,
             test_route_merge_split_and_commit_overflow,
             test_gateway_probe,
             test_restart_persistence_and_migration,
             test_routes_fuzz_minimal_cover]
    for t in tests:
        t()
    print("\n结果：%d 通过, %d 失败" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
