"""Alert storage, deduplication and outgoing notifications (D52)."""

from __future__ import annotations

import json
from datetime import timedelta

from privasoc.store import Store, parse_ts, utcnow

OPEN = ("new", "acknowledged")
STATUSES = ("new", "acknowledged", "closed_tp", "closed_fp")
LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COLS = (
    "id", "kind", "rule_id", "title", "level", "source", "group_key", "first_seen",
    "last_seen", "count", "status", "created_at", "updated_at", "detail", "triage", "notified",
)  # fmt: skip
MAX_EVENTS = 200  # events linked to one alert


def _row(r) -> dict:
    d = dict(zip(COLS, r, strict=True))
    d["detail"] = json.loads(d["detail"]) if d["detail"] else {}
    d["triage"] = json.loads(d["triage"]) if d["triage"] else None
    return d


def raise_alert(
    store: Store,
    *,
    kind: str,
    rule_id: str,
    title: str,
    level: str,
    source: str,
    at: str,
    group_key: str = "",
    event_ids: list[int] = (),
    detail: dict | None = None,
    dedup_minutes: int = 60,
    count: int | None = None,
) -> tuple[int, bool]:
    """Open a new alert, or update the open one for the same rule, host and group seen in
    the last `dedup_minutes`. Returns (alert id, created)."""
    now = utcnow()
    since = (parse_ts(at) - timedelta(minutes=dedup_minutes)).isoformat()
    with store.conn:
        row = store.conn.execute(
            "SELECT id, count FROM alerts WHERE kind=? AND rule_id=? AND source=? AND "
            "group_key=? AND status IN ('new','acknowledged') AND last_seen >= ? "
            "ORDER BY id DESC LIMIT 1",
            (kind, rule_id, source, group_key, since),
        ).fetchone()
        if row:
            aid, created = row[0], False
            store.conn.execute(
                "UPDATE alerts SET last_seen=MAX(last_seen, ?), updated_at=?, "
                "count=CASE WHEN ? IS NULL THEN count+1 ELSE MAX(count, ?) END, "
                "detail=COALESCE(?, detail) WHERE id=?",
                (at, now, count, count, json.dumps(detail) if detail else None, aid),
            )
        else:
            cur = store.conn.execute(
                "INSERT INTO alerts(kind, rule_id, title, level, source, group_key, first_seen,"
                " last_seen, count, status, created_at, updated_at, detail) "
                "VALUES (?,?,?,?,?,?,?,?,?,'new',?,?,?)",
                (
                    kind, rule_id, title, level, source, group_key, at, at,
                    count or 1, now, now, json.dumps(detail or {}),
                ),
            )  # fmt: skip
            aid, created = cur.lastrowid, True
        linked = store.conn.execute(
            "SELECT COUNT(*) FROM alert_events WHERE alert_id=?", (aid,)
        ).fetchone()[0]
        for eid in list(event_ids)[: max(0, MAX_EVENTS - linked)]:
            store.conn.execute(
                "INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)", (aid, eid)
            )
    return aid, created


def has_alert(store: Store, kind: str, rule_id: str, source: str, open_only: bool) -> bool:
    q = "SELECT 1 FROM alerts WHERE kind=? AND rule_id=? AND source=?"
    if open_only:
        q += " AND status IN ('new','acknowledged')"
    return store.conn.execute(q, (kind, rule_id, source)).fetchone() is not None


def alerts(
    store: Store, status: str | None = None, level: str | None = None, limit: int = 200
) -> list[dict]:
    q, args = f"SELECT {', '.join(COLS)} FROM alerts WHERE 1=1", []  # noqa: S608 - fixed cols
    if status == "open":
        q += " AND status IN ('new','acknowledged')"
    elif status and status != "all":
        q, args = q + " AND status=?", [*args, status]
    if level:
        q, args = q + " AND level=?", [*args, level]
    rows = store.conn.execute(q + " ORDER BY last_seen DESC LIMIT ?", (*args, limit))
    return [_row(r) for r in rows]


def alert(store: Store, aid: int) -> dict | None:
    r = store.conn.execute(
        f"SELECT {', '.join(COLS)} FROM alerts WHERE id=?",  # noqa: S608 - fixed cols
        (aid,),
    ).fetchone()
    return _row(r) if r else None


def alert_events(store: Store, aid: int, limit: int = 50) -> list[dict]:
    rows = store.conn.execute(
        "SELECT e.id, e.source, e.received_at, e.parser_id, e.ecs FROM alert_events a "
        "JOIN events e ON e.id = a.event_id WHERE a.alert_id=? ORDER BY e.id DESC LIMIT ?",
        (aid, limit),
    ).fetchall()
    keys = ("id", "source", "received_at", "parser_id", "ecs")
    return [{**dict(zip(keys, r, strict=True)), "ecs": json.loads(r[4])} for r in rows]


def set_status(store: Store, aid: int, status: str) -> None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    with store.conn:
        store.conn.execute(
            "UPDATE alerts SET status=?, updated_at=? WHERE id=?", (status, utcnow(), aid)
        )


def save_triage(store: Store, aid: int, triage: dict) -> None:
    with store.conn:
        store.conn.execute(
            "UPDATE alerts SET triage=?, updated_at=? WHERE id=?",
            (json.dumps(triage), utcnow(), aid),
        )


def counts(store: Store) -> dict:
    out = {lvl: 0 for lvl in LEVEL_RANK}
    for lvl, n in store.conn.execute(
        "SELECT level, COUNT(*) FROM alerts WHERE status IN ('new','acknowledged') GROUP BY level"
    ):
        out[lvl] = n
    out["open"] = sum(out[lvl] for lvl in LEVEL_RANK)
    return out


# ------------------------------------------------------------------ notifications


def notification_body(a: dict, fmt: str, base_url: str = "") -> tuple[dict | str, dict]:
    """What leaves the machine: title, level, count, id. Never event content or host names."""
    link = f"{base_url.rstrip('/')}/ui/alert?id={a['id']}" if base_url else f"alert #{a['id']}"
    text = f"[privasoc] {a['level'].upper()}: {a['title']} (x{a['count']}) {link}"
    if fmt == "ntfy":
        headers = {"Title": f"privasoc {a['level']}", "Priority": str(1 + LEVEL_RANK[a["level"]])}
        return text, headers
    if fmt == "discord":
        return {"content": text}, {}
    if fmt == "slack":
        return {"text": text}, {}
    return {
        "id": a["id"],
        "title": a["title"],
        "level": a["level"],
        "count": a["count"],
        "kind": a["kind"],
        "link": link,
    }, {}


def notify_pending(store: Store, url: str, fmt: str, min_level: str, base_url: str = "") -> dict:
    import httpx

    sent = failed = 0
    rows = store.conn.execute(
        f"SELECT {', '.join(COLS)} FROM alerts WHERE notified=0 ORDER BY id"  # noqa: S608
    ).fetchall()
    for r in rows:
        a = _row(r)
        if not url or LEVEL_RANK[a["level"]] < LEVEL_RANK.get(min_level, 3):
            flag = 2
        else:
            body, headers = notification_body(a, fmt, base_url)
            try:
                if isinstance(body, str):
                    resp = httpx.post(url, content=body.encode(), headers=headers, timeout=10)
                else:
                    resp = httpx.post(url, json=body, headers=headers, timeout=10)
                resp.raise_for_status()
                flag, sent = 1, sent + 1
            except httpx.HTTPError:
                flag, failed = -1, failed + 1
        with store.conn:
            store.conn.execute("UPDATE alerts SET notified=? WHERE id=?", (flag, a["id"]))
    return {"sent": sent, "failed": failed}
