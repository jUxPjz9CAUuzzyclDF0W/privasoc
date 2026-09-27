"""Rules written in privasoc (by the model or by hand) and rules switched off (D54)."""

from __future__ import annotations

import json

from privasoc.store import Store, utcnow

_SELECT = (
    "SELECT id, yaml, title, status, origin, ref, request, model, replaces, backtest, "
    "created_at, decided_at FROM custom_rules"
)
COLS = ("id", "yaml", "title", "status", "origin", "ref", "request", "model", "replaces",
        "backtest", "created_at", "decided_at")  # fmt: skip


def _row(r) -> dict:
    d = dict(zip(COLS, r, strict=True))
    d["backtest"] = json.loads(d["backtest"]) if d["backtest"] else None
    return d


def save(store: Store, rid: str, yaml_text: str, title: str, origin: str, *, ref=None,
         request=None, model=None, replaces=None, backtest=None) -> None:  # fmt: skip
    with store.conn:
        store.conn.execute(
            "INSERT OR REPLACE INTO custom_rules(id, yaml, title, status, origin, ref, request, "
            "model, replaces, backtest, created_at) VALUES (?,?,?,'proposed',?,?,?,?,?,?,?)",
            (rid, yaml_text, title, origin, ref, request, model, replaces,
             json.dumps(backtest) if backtest is not None else None, utcnow()),
        )  # fmt: skip


def get(store: Store, rid: str) -> dict | None:
    r = store.conn.execute(_SELECT + " WHERE id=?", (rid,)).fetchone()
    return _row(r) if r else None


def listing(store: Store, status: str | None = None) -> list[dict]:
    q, args = _SELECT, ()
    if status:
        q, args = q + " WHERE status=?", (status,)
    return [_row(r) for r in store.conn.execute(q + " ORDER BY created_at DESC", args)]


def set_status(store: Store, rid: str, status: str) -> None:
    with store.conn:
        store.conn.execute(
            "UPDATE custom_rules SET status=?, decided_at=? WHERE id=?", (status, utcnow(), rid)
        )


def disable(store: Store, rule_id: str, reason: str) -> None:
    with store.conn:
        store.conn.execute(
            "INSERT OR REPLACE INTO disabled_rules(rule_id, reason, at) VALUES (?,?,?)",
            (rule_id, reason, utcnow()),
        )


def enable(store: Store, rule_id: str) -> None:
    with store.conn:
        store.conn.execute("DELETE FROM disabled_rules WHERE rule_id=?", (rule_id,))


def disabled(store: Store) -> dict[str, str]:
    return dict(store.conn.execute("SELECT rule_id, reason FROM disabled_rules"))
