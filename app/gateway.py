"""Independent gateway process: read-only withdrawal and route queries.

This process never writes. It opens SQLite in read-only mode and serves:
  GET /            probe page: enter a destination IPv6 address, see the
                   committed route it hits, or "drop"
  GET /probe       JSON form of the same longest-prefix-match probe
  GET /withdrawal  published earliest withdrawal time + uncovered old leases

Only committed routes are ever consulted: the routes table changes only
inside writer transactions, and this read-only connection always observes
the last committed state. One probe issues at most (deleg_len -
pool_prefix_len + 1) indexed point lookups, so the number of route
records read never grows with the number of entries in the table.
"""
from flask import Flask, jsonify, render_template_string, request

from .common import DB_PATH
from .db import connect
from .logic import (DrillError, probe_route, read_published,
                    read_uncovered_old_leases, route_status)

PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>网关 · 路由探测（只读）</title>
<style>
  body { font-family: system-ui, "PingFang SC", sans-serif; margin: 24px; color: #1a2330; }
  .card { border: 1px solid #c9d2de; border-radius: 8px; padding: 14px 16px; margin-bottom: 14px; max-width: 760px; }
  input { padding: 6px 8px; font-size: 13px; }
  button { padding: 6px 14px; font-size: 13px; cursor: pointer; }
  code { background: #f2f4f7; padding: 1px 5px; border-radius: 4px; }
  .hit { background: #d9f2e3; color: #0d6b35; padding: 8px 12px; border-radius: 6px; display: inline-block; }
  .drop { background: #fdecdc; color: #9a4a12; padding: 8px 12px; border-radius: 6px; display: inline-block; }
  .err { background: #fbe1e1; color: #8f1d1d; padding: 8px 12px; border-radius: 6px; display: inline-block; }
  .muted { color: #66717f; font-size: 12px; }
</style>
</head>
<body>
<h2>网关路由探测（只读，仅按已提交路由转发）</h2>
<div class="card">
  <p>已提交路由条目：<strong>{{ st.entry_count }}</strong> 条 ／ 上限：
    {% if st.max_entries is none %}未设限{% else %}{{ st.max_entries }} 条{% endif %}
    {% if pub.cidr %}　·　新池 <code>{{ pub.cidr }}</code>{% endif %}</p>
  <form method="get" action="/">
    <p><label>目的 IPv6 地址：<input name="address" size="42"
        value="{{ address }}" placeholder="2001:db8:eeee::1" required></label>
       <button type="submit">探测</button></p>
  </form>
  {% if result %}
    {% if result.error %}
      <p class="err">输入无效：{{ result.error }}</p>
    {% elif result.hit %}
      <p class="hit">命中前缀 <code>{{ result.hit }}</code> → 转发</p>
    {% else %}
      <p class="drop">丢弃：无匹配的已提交路由</p>
    {% endif %}
    {% if not result.error %}
      <p class="muted">本次探测读取路由记录 {{ result.lookups }} 条（与表项总数无关，仅取决于池前缀长度范围）。</p>
    {% endif %}
  {% endif %}
  <p class="muted">撤路视图：<a href="/withdrawal">GET /withdrawal</a>　·　JSON 探测：<code>GET /probe?address=…</code></p>
</div>
</body>
</html>
"""


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or DB_PATH

    def ro_db():
        # Read-only URI connection: no schema bootstrap, no recovery writes.
        return connect(app.config["DB_PATH"], readonly=True)

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True, role="gateway", readonly=True)

    @app.get("/withdrawal")
    def withdrawal():
        """Published earliest withdrawal time + the uncovered old leases."""
        conn = ro_db()
        try:
            pub = read_published(conn)
            uncovered = read_uncovered_old_leases(conn)
            return jsonify({
                "published_new_pool": pub["cidr"],
                "published_at_seconds": pub["published_at"],
                "earliest_withdrawal_seconds": pub["earliest_seconds"],
                "can_withdraw_now": pub["earliest_seconds"] is None,
                "uncovered_count": len(uncovered),
                "uncovered_leases": [
                    {"lease_id": row["id"], "prefix": row["prefix"],
                     "expires_at": row["expires_at"]}
                    for row in uncovered],
            })
        finally:
            conn.close()

    @app.get("/probe")
    def probe():
        """JSON probe: longest-prefix match over committed routes only."""
        address = request.args.get("address", "")
        conn = ro_db()
        try:
            hit, lookups = probe_route(conn, address)
            return jsonify({
                "ok": True,
                "address": address,
                "action": "hit" if hit else "drop",
                "prefix": hit,
                "route_lookups": lookups,
            })
        except DrillError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        finally:
            conn.close()

    @app.get("/")
    def index():
        address = request.args.get("address", "").strip()
        conn = ro_db()
        try:
            result = None
            if address:
                try:
                    hit, lookups = probe_route(conn, address)
                    result = {"hit": hit, "lookups": lookups, "error": None}
                except DrillError as exc:
                    result = {"hit": None, "lookups": 0, "error": str(exc)}
            return render_template_string(
                PAGE, address=address, result=result,
                st=route_status(conn), pub=read_published(conn))
        finally:
            conn.close()

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8001)
