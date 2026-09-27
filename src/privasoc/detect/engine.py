"""Incremental detection over the events table (D51, D52).

Each run reads the events stored since the last run (a cursor in the `state` table),
evaluates every supported rule, stores the matches, evaluates correlations on the matches
of their time window, and raises or updates alerts. It also raises the two non-Sigma
alerts: a host whose health turns critical (D47) and a new sender waiting for approval.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from privasoc.detect import alerts as al
from privasoc.detect.sigma import Rule, get, load_rules
from privasoc.store import Store, parse_ts

BUILTIN_RULES = Path(__file__).parent / "rules"


def rule_dirs(sigma_dir: Path) -> list[tuple[Path, str]]:
    return [(BUILTIN_RULES, "privasoc"), (sigma_dir / "rules", "sigmahq")]


def event_time(ecs: dict, received_at: str) -> str:
    ts = ecs.get("@timestamp")
    if isinstance(ts, str):
        try:
            return parse_ts(ts).isoformat()
        except ValueError:
            pass
    return parse_ts(received_at).isoformat()


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        ok = [r for r in rules if r.unsupported is None and not r.disabled]
        self.correlations = [r for r in ok if r.correlation]
        self.base = [r for r in ok if not r.correlation]
        by_ref = {}
        for r in self.base:
            by_ref[r.id] = r
            if r.name:
                by_ref[r.name] = r
        # Sigma 2: rules used by a correlation do not raise alerts of their own.
        self.silent: set[str] = set()
        for c in self.correlations:
            refs = [by_ref.get(x) for x in c.correlation["rules"]]
            if not all(refs):
                missing = [x for x, r in zip(c.correlation["rules"], refs, strict=True) if not r]
                c.unsupported = f"correlation refers to unknown or unsupported rule(s) {missing}"
                continue
            c.correlation["base_ids"] = [r.id for r in refs]
            self.silent.update(r.id for r in refs)
        self.correlations = [c for c in self.correlations if c.unsupported is None]

    @classmethod
    def from_dirs(cls, sigma_dir: Path) -> Engine:
        return cls(load_rules(rule_dirs(sigma_dir)))

    def stats(self) -> dict:
        return {
            "rules": len(self.rules),
            "supported": sum(r.unsupported is None for r in self.rules),
            "disabled": sum(bool(r.disabled) for r in self.rules),
            "local": sum(r.origin == "ai" for r in self.rules),
            "correlations": len(self.correlations),
        }

    # -------------------------------------------------------------- run

    def run(self, store: Store, limit: int = 5000, dedup_minutes: int = 60) -> dict:
        cursor = int(_state(store, "detect_cursor", "0"))
        rows = store.conn.execute(
            "SELECT id, source, received_at, ecs FROM events WHERE id > ? ORDER BY id LIMIT ?",
            (cursor, limit),
        ).fetchall()
        raised = matched = 0
        for eid, source, received_at, raw in rows:
            ecs = json.loads(raw)
            at = event_time(ecs, received_at)
            hit_ids = []
            for r in self.base:
                try:
                    if not (r.applies(ecs) and r.match(ecs)):
                        continue
                except Exception:  # noqa: BLE001, S112 - a rule must never stop detection
                    continue
                matched += 1
                hit_ids.append(r.id)
                with store.conn:
                    store.conn.execute(
                        "INSERT OR IGNORE INTO sigma_matches(rule_id, event_id, at) VALUES (?,?,?)",
                        (r.id, eid, at),
                    )
                if r.id not in self.silent:
                    _, new = al.raise_alert(
                        store, kind="sigma", rule_id=r.id, title=r.title, level=r.level,
                        source=source, at=at, event_ids=[eid], dedup_minutes=dedup_minutes,
                    )  # fmt: skip
                    raised += new
            for c in self.correlations:
                if set(c.correlation["base_ids"]) & set(hit_ids):
                    raised += self._correlate(store, c, source, ecs, at, dedup_minutes)
            cursor = eid
        _set_state(store, "detect_cursor", str(cursor))
        return {"events": len(rows), "matches": matched, "new_alerts": raised}

    def _correlate(self, store, c: Rule, source: str, ecs: dict, at: str, dedup: int) -> int:
        cor = c.correlation
        group = {f: get(ecs, f) for f in cor["group_by"]}
        if any(v in (None, "", []) for v in group.values()):
            return 0  # the event does not carry the grouping field
        start = (parse_ts(at) - timedelta(seconds=cor["timespan"])).isoformat()
        rows = {}
        for rid in cor["base_ids"]:
            for eid, raw in store.conn.execute(
                "SELECT e.id, e.ecs FROM sigma_matches m JOIN events e ON e.id=m.event_id "
                "WHERE m.rule_id=? AND m.at BETWEEN ? AND ? AND e.source=?",
                (rid, start, at, source),
            ):
                rows[eid] = raw
        rows = sorted(rows.items())
        ids, values = [], set()
        for eid, raw in rows:
            doc = json.loads(raw)
            if all(get(doc, f) == v for f, v in group.items()):
                ids.append(eid)
                if cor["type"] == "value_count":
                    values.add(json.dumps(get(doc, cor["field"]), sort_keys=True))
        n = len(values) if cor["type"] == "value_count" else len(ids)
        op, ref = cor["op"]
        ok = {"gt": n > ref, "gte": n >= ref, "lt": n < ref, "lte": n <= ref, "eq": n == ref}[op]
        if not ok:
            return 0
        _, new = al.raise_alert(
            store, kind="sigma", rule_id=c.id, title=c.title, level=c.level, source=source,
            at=at, group_key=json.dumps(group, sort_keys=True), event_ids=ids,
            detail={"group": group, "value": n, "type": cor["type"]},
            dedup_minutes=dedup, count=n,
        )  # fmt: skip
        return int(new)


def host_alerts(store: Store, health_fn, dedup_minutes: int = 60) -> int:
    """New senders waiting for approval (low) and approved hosts turning critical (high)."""
    from privasoc.store import utcnow

    raised = 0
    for h in store.hosts():
        if h["status"] == "pending" and not al.has_alert(
            store, "host", "new_sender", h["source"], open_only=False
        ):
            _, new = al.raise_alert(
                store, kind="host", rule_id="new_sender", level="low", source=h["source"],
                title="New sender waiting for approval", at=h["first_seen"],
                detail={"lines": h["lines"]}, dedup_minutes=dedup_minutes,
            )  # fmt: skip
            raised += new
        elif h["status"] == "approved":
            hs = health_fn(store, h)
            if hs["status"] == "critical" and not al.has_alert(
                store, "health", "host_critical", h["source"], open_only=True
            ):
                _, new = al.raise_alert(
                    store, kind="health", rule_id="host_critical", level="high",
                    source=h["source"], title="Host health critical: " + "; ".join(hs["reasons"]),
                    at=utcnow(), detail=hs, dedup_minutes=dedup_minutes,
                )  # fmt: skip
                raised += new
    return raised


def _state(store: Store, key: str, default: str) -> str:
    row = store.conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_state(store: Store, key: str, value: str) -> None:
    with store.conn:
        store.conn.execute(
            "INSERT INTO state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
            "value=excluded.value",
            (key, value),
        )


def backtest(store: Store, rules: list[Rule], hours: float | None = None, limit: int = 20000):
    """Run rules over stored events without touching alerts (proposals, hunts).

    Base rules report their matching events; correlations report the groups (per sender)
    whose count reaches the threshold in some window, with the events of the best window."""
    from datetime import UTC, datetime

    eng = Engine(rules)
    rows = store.conn.execute(
        "SELECT id, source, received_at, ecs FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    since = None
    if hours:
        since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    events = []
    for eid, source, received_at, raw in reversed(rows):
        ecs = json.loads(raw)
        at = event_time(ecs, received_at)
        if since and at < since:
            continue
        events.append((eid, source, at, ecs))
    matches: dict[str, list[tuple]] = {r.id: [] for r in eng.base}
    for ev in events:
        for r in eng.base:
            try:
                if r.applies(ev[3]) and r.match(ev[3]):
                    matches[r.id].append(ev)
            except Exception:  # noqa: BLE001, S112 - same policy as the live engine
                continue
    out = []
    for r in eng.base:
        ids = [e[0] for e in matches[r.id]]
        # a base rule of a correlation raises no alert, but its matches help the reviewer
        kind = "base" if r.id in eng.silent else "rule"
        out.append({"id": r.id, "title": r.title, "kind": kind, "matches": len(ids),
                    "event_ids": ids})  # fmt: skip
    for c in eng.correlations:
        out.append({"id": c.id, "title": c.title, "kind": "correlation",
                    **_correlate_offline(c, matches)})  # fmt: skip
    unsupported = [{"title": r.title, "reason": r.unsupported} for r in rules if r.unsupported]
    return {"events": len(events), "results": out, "unsupported": unsupported}


def _correlate_offline(c: Rule, matches: dict) -> dict:
    cor = c.correlation
    evs = sorted({e[0]: e for rid in cor["base_ids"] for e in matches[rid]}.values(),
                 key=lambda e: e[2])  # fmt: skip
    groups: dict[str, list] = {}
    for e in evs:
        g = {f: get(e[3], f) for f in cor["group_by"]}
        if any(v in (None, "", []) for v in g.values()):
            continue
        key = json.dumps({"sender": e[1], **g}, sort_keys=True, default=str)
        groups.setdefault(key, []).append(e)
    op, ref = cor["op"]
    fired = []
    for key, gevs in groups.items():
        best, best_ids = -1, []
        start = 0
        for end in range(len(gevs)):
            t_end = parse_ts(gevs[end][2])
            while parse_ts(gevs[start][2]) < t_end - timedelta(seconds=cor["timespan"]):
                start += 1
            win = gevs[start : end + 1]
            if cor["type"] == "value_count":
                n = len({json.dumps(get(e[3], cor["field"]), default=str) for e in win})
            else:
                n = len(win)
            if n > best:
                best, best_ids = n, [e[0] for e in win]
        ok = {"gt": best > ref, "gte": best >= ref, "lt": best < ref, "lte": best <= ref,
              "eq": best == ref}[op]  # fmt: skip
        if ok:
            fired.append({"group": json.loads(key), "value": best, "event_ids": best_ids})
    fired.sort(key=lambda g: -g["value"])
    return {"matches": sum(len(g["event_ids"]) for g in fired), "groups": fired,
            "event_ids": sorted({i for g in fired for i in g["event_ids"]})}  # fmt: skip
