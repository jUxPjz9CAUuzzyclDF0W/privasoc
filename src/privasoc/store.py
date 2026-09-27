"""SQLite event store: normalised events and the quarantine of unparsed lines (D10, D26)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    received_at TEXT NOT NULL,
    parser_id   TEXT NOT NULL,
    ecs         TEXT NOT NULL  -- JSON document in ECS
);
CREATE INDEX IF NOT EXISTS events_source_time ON events(source, received_at);

CREATE TABLE IF NOT EXISTS unparsed (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    received_at TEXT NOT NULL,
    raw         TEXT NOT NULL,
    template_id TEXT            -- filled by Drain clustering (D35)
);
CREATE INDEX IF NOT EXISTS unparsed_source_time ON unparsed(source, received_at);

CREATE TABLE IF NOT EXISTS parsers (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status     TEXT NOT NULL,   -- proposed | approved | rejected | failed | needs_escalation
    provider   TEXT NOT NULL,
    model      TEXT NOT NULL,
    vrl        TEXT,
    report     TEXT NOT NULL    -- JSON: metrics, attempts, pseudonymised transcript
);
CREATE TABLE IF NOT EXISTS hosts (          -- D45: every sender, approved by a human
    source      TEXT PRIMARY KEY,
    status      TEXT NOT NULL,              -- pending | approved | rejected
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    lines       INTEGER NOT NULL DEFAULT 0,
    decided_at  TEXT,
    format      TEXT,                       -- builtin:<name> | parser:<id> | unknown
    thresholds  TEXT                        -- JSON overrides for health (D47)
);
CREATE TABLE IF NOT EXISTS host_stats (     -- D47: per-minute counters
    source      TEXT NOT NULL,
    minute      TEXT NOT NULL,              -- YYYY-MM-DDTHH:MM (UTC)
    total       INTEGER NOT NULL DEFAULT 0,
    parsed      INTEGER NOT NULL DEFAULT 0,
    skew_sum    REAL NOT NULL DEFAULT 0,    -- seconds, |received - @timestamp|
    skew_n      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source, minute)
);
CREATE TABLE IF NOT EXISTS health_history (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    at          TEXT NOT NULL,
    status      TEXT NOT NULL,
    reasons     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sigma_matches (  -- step 6: which rule matched which event
    rule_id     TEXT NOT NULL,
    event_id    INTEGER NOT NULL,
    at          TEXT NOT NULL,              -- event time (UTC ISO)
    PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX IF NOT EXISTS sigma_matches_time ON sigma_matches(rule_id, at);
CREATE TABLE IF NOT EXISTS alerts (         -- D52
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,              -- sigma | health | host
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    level       TEXT NOT NULL,
    source      TEXT NOT NULL,
    group_key   TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'new', -- new | acknowledged | closed_tp | closed_fp
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    detail      TEXT,                       -- JSON: reasons, group values
    triage      TEXT,                       -- JSON: latest AI triage (pseudonymised)
    notified    INTEGER NOT NULL DEFAULT 0  -- 0 pending, 1 sent, -1 failed, 2 below level
);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(status, kind, rule_id, source);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id    INTEGER NOT NULL,
    event_id    INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS llm_calls (
    id          INTEGER PRIMARY KEY,
    at          TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    detail      TEXT NOT NULL   -- JSON: sizes, latency, tokens (never content)
);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class Record:
    """One line as delivered by the collector (Vector) or a file import."""

    source: str
    raw: str
    received_at: str | None = None
    ecs: dict | None = None  # present when an approved parser already normalised it
    parser_id: str | None = None


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        # migration for databases created before D45: lines of unapproved hosts are held
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(unparsed)")}
        if "held" not in cols:
            self.conn.execute("ALTER TABLE unparsed ADD COLUMN held INTEGER NOT NULL DEFAULT 0")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def ingest(self, records: Iterable[Record], auto_approve: bool = False) -> dict[str, int]:
        """Route each record (D45): unknown sender -> pending host, lines held; rejected host
        -> dropped; approved host -> events if parsed, otherwise quarantine.
        `auto_approve` is for explicit admin imports (a file given on the command line)."""
        counts = {"events": 0, "unparsed": 0, "held": 0, "dropped": 0}
        status_cache: dict[str, str] = {}
        with self.conn:
            for r in records:
                ts = r.received_at or utcnow()
                status = status_cache.get(r.source) or self._touch_host(r.source, ts, auto_approve)
                status_cache[r.source] = status
                self.conn.execute(
                    "UPDATE hosts SET last_seen=MAX(last_seen, ?), lines=lines+1 WHERE source=?",
                    (ts, r.source),
                )
                if status == "rejected":
                    counts["dropped"] += 1
                    continue
                parsed = status == "approved" and r.ecs is not None and bool(r.parser_id)
                self._count(r.source, ts, parsed, r.ecs if parsed else None)
                if parsed:
                    self.conn.execute(
                        "INSERT INTO events(source, received_at, parser_id, ecs) VALUES (?,?,?,?)",
                        (r.source, ts, r.parser_id, json.dumps(r.ecs, separators=(",", ":"))),
                    )
                    counts["events"] += 1
                else:
                    held = int(status != "approved")
                    self.conn.execute(
                        "INSERT INTO unparsed(source, received_at, raw, held) VALUES (?,?,?,?)",
                        (r.source, ts, r.raw, held),
                    )
                    counts["held" if held else "unparsed"] += 1
        return counts

    # ------------------------------------------------------------------ hosts (D45)

    def _touch_host(self, source: str, ts: str, auto_approve: bool) -> str:
        row = self.conn.execute("SELECT status FROM hosts WHERE source=?", (source,)).fetchone()
        if row:
            return row[0]
        status = "approved" if auto_approve else "pending"
        self.conn.execute(
            "INSERT INTO hosts(source, status, first_seen, last_seen, decided_at) "
            "VALUES (?,?,?,?,?)",
            (source, status, ts, ts, ts if auto_approve else None),
        )
        return status

    def hosts(self, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM hosts", ()
        if status:
            q, args = q + " WHERE status=?", (status,)
        cols = (
            "source",
            "status",
            "first_seen",
            "last_seen",
            "lines",
            "decided_at",
            "format",
            "thresholds",
        )
        out = []
        for row in self.conn.execute(q + " ORDER BY first_seen", args):
            d = dict(zip(cols, row, strict=True))
            d["thresholds"] = json.loads(d["thresholds"]) if d["thresholds"] else {}
            out.append(d)
        return out

    def host(self, source: str) -> dict | None:
        return next((h for h in self.hosts() if h["source"] == source), None)

    def set_host(
        self,
        source: str,
        status: str | None = None,
        fmt: str | None = None,
        thresholds: dict | None = None,
    ) -> None:
        with self.conn:
            if status:
                self.conn.execute(
                    "UPDATE hosts SET status=?, decided_at=? WHERE source=?",
                    (status, utcnow(), source),
                )
                if status == "approved":  # held lines become normal quarantine
                    self.conn.execute("UPDATE unparsed SET held=0 WHERE source=?", (source,))
                elif status == "rejected":
                    self.conn.execute("DELETE FROM unparsed WHERE source=? AND held=1", (source,))
            if fmt is not None:
                self.conn.execute("UPDATE hosts SET format=? WHERE source=?", (fmt, source))
            if thresholds is not None:
                self.conn.execute(
                    "UPDATE hosts SET thresholds=? WHERE source=?", (json.dumps(thresholds), source)
                )

    def quarantine_rows(self, source: str, limit: int = 5000) -> list[tuple[int, str, str]]:
        """(id, received_at, raw) of the quarantined (not held) lines of a source, oldest first."""
        return self.conn.execute(
            "SELECT id, received_at, raw FROM unparsed WHERE source=? AND held=0 ORDER BY id "
            "LIMIT ?",
            (source, limit),
        ).fetchall()

    def backfill(self, source: str, parser_id: str, rows: list[tuple[int, str, dict]]) -> int:
        """Move quarantined lines that the new parser handles into events (D45 step 6)."""
        with self.conn:
            for rid, received_at, ecs in rows:
                self.conn.execute(
                    "INSERT INTO events(source, received_at, parser_id, ecs) VALUES (?,?,?,?)",
                    (source, received_at, parser_id, json.dumps(ecs, separators=(",", ":"))),
                )
                self.conn.execute("DELETE FROM unparsed WHERE id=?", (rid,))
                # the line was counted as unparsed on arrival: it is parsed now (D47 stats)
                skew = _skew_seconds(received_at, ecs)
                self.conn.execute(
                    "UPDATE host_stats SET parsed=parsed+1, skew_sum=skew_sum+?, "
                    "skew_n=skew_n+? WHERE source=? AND minute=?",
                    (skew or 0.0, int(skew is not None), source, received_at[:16]),
                )
        return len(rows)

    # ------------------------------------------------------------------ health (D47)

    def _count(self, source: str, ts: str, parsed: bool, ecs: dict | None) -> None:
        skew = _skew_seconds(ts, ecs)
        self.conn.execute(
            "INSERT INTO host_stats(source, minute, total, parsed, skew_sum, skew_n) "
            "VALUES (?,?,1,?,?,?) ON CONFLICT(source, minute) DO UPDATE SET "
            "total=total+1, parsed=parsed+excluded.parsed, skew_sum=skew_sum+excluded.skew_sum, "
            "skew_n=skew_n+excluded.skew_n",
            (source, ts[:16], int(parsed), skew or 0.0, int(skew is not None)),
        )

    def stats(self, source: str, since_minute: str) -> list[tuple]:
        return self.conn.execute(
            "SELECT minute, total, parsed, skew_sum, skew_n FROM host_stats "
            "WHERE source=? AND minute>=? ORDER BY minute",
            (source, since_minute),
        ).fetchall()

    def record_health(self, source: str, status: str, reasons: list[str]) -> None:
        last = self.conn.execute(
            "SELECT status, reasons FROM health_history WHERE source=? ORDER BY id DESC LIMIT 1",
            (source,),
        ).fetchone()
        if last and last[0] == status and json.loads(last[1]) == reasons:
            return  # history keeps changes only
        with self.conn:
            self.conn.execute(
                "INSERT INTO health_history(source, at, status, reasons) VALUES (?,?,?,?)",
                (source, utcnow(), status, json.dumps(reasons)),
            )

    def health_history(self, source: str, limit: int = 50) -> list[tuple[str, str, list]]:
        rows = self.conn.execute(
            "SELECT at, status, reasons FROM health_history WHERE source=? ORDER BY id DESC "
            "LIMIT ?",
            (source, limit),
        ).fetchall()
        return [(a, st, json.loads(r)) for a, st, r in rows]

    def quarantine_stats(self) -> list[tuple[str, int, str, str]]:
        """(source, lines, first_seen, last_seen) per source."""
        return self.conn.execute(
            "SELECT source, COUNT(*), MIN(received_at), MAX(received_at) "
            "FROM unparsed WHERE held=0 GROUP BY source ORDER BY COUNT(*) DESC"
        ).fetchall()

    def quarantine_sample(self, source: str, limit: int = 10) -> list[str]:
        rows = self.conn.execute(
            "SELECT raw FROM unparsed WHERE source = ? AND held=0 ORDER BY id DESC LIMIT ?",
            (source, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def quarantine_lines(self, source: str, limit: int = 500) -> list[str]:
        rows = self.conn.execute(
            "SELECT raw FROM unparsed WHERE source = ? AND held=0 ORDER BY id DESC LIMIT ?",
            (source, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def save_parser(
        self,
        pid: str,
        source: str,
        status: str,
        provider: str,
        model: str,
        vrl: str | None,
        report: dict,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO parsers VALUES (?,?,?,?,?,?,?,?)",
                (pid, source, utcnow(), status, provider, model, vrl, json.dumps(report)),
            )

    def parser(self, pid: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM parsers WHERE id = ?", (pid,)).fetchone()
        return _parser_row(row) if row else None

    def parsers(self, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM parsers", ()
        if status:
            q, args = q + " WHERE status = ?", (status,)
        return [_parser_row(r) for r in self.conn.execute(q + " ORDER BY created_at", args)]

    def set_parser_status(self, pid: str, status: str) -> None:
        with self.conn:
            if status == "approved":  # one active parser per source
                src = self.conn.execute("SELECT source FROM parsers WHERE id=?", (pid,)).fetchone()
                self.conn.execute(
                    "UPDATE parsers SET status='superseded' WHERE source=? AND status='approved'",
                    (src[0],),
                )
            self.conn.execute("UPDATE parsers SET status=? WHERE id=?", (status, pid))

    def log_llm_call(self, detail: dict) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO llm_calls(at, provider, model, detail) VALUES (?,?,?,?)",
                (utcnow(), detail["provider"], detail["model"], json.dumps(detail)),
            )

    def event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def latest_events(self, source: str | None = None, limit: int = 50) -> list[dict]:
        q, args = "SELECT id, source, received_at, parser_id, ecs FROM events", ()
        if source:
            q, args = q + " WHERE source=?", (source,)
        rows = self.conn.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        keys = ("id", "source", "received_at", "parser_id", "ecs")
        return [{**dict(zip(keys, r, strict=True)), "ecs": json.loads(r[4])} for r in rows]

    def summary(self) -> dict[str, int]:
        """Counters for the dashboard (step 4)."""

        def one(q: str) -> int:
            return self.conn.execute(q).fetchone()[0]

        out = {f"hosts_{st}": 0 for st in ("pending", "approved", "rejected")}
        for st, n in self.conn.execute("SELECT status, COUNT(*) FROM hosts GROUP BY status"):
            out[f"hosts_{st}"] = n
        out["events"] = one("SELECT COUNT(*) FROM events")
        out["quarantined"] = one("SELECT COUNT(*) FROM unparsed WHERE held=0")
        out["held"] = one("SELECT COUNT(*) FROM unparsed WHERE held=1")
        out["parsers_proposed"] = one("SELECT COUNT(*) FROM parsers WHERE status='proposed'")
        out["parsers_approved"] = one("SELECT COUNT(*) FROM parsers WHERE status='approved'")
        return out

    def recent_raw(self, source: str | None = None, limit: int = 500) -> list[str]:
        """Latest raw lines of approved hosts: quarantined ones and the originals kept in
        normalised events (step 5 learns from both). Held lines are never included."""
        args = (source, source, limit)
        q = self.conn.execute(
            "SELECT raw FROM unparsed WHERE held=0 AND (? IS NULL OR source=?) "
            "ORDER BY id DESC LIMIT ?",
            args,
        ).fetchall()
        e = self.conn.execute(
            "SELECT json_extract(ecs, '$.event.original') FROM events "
            "WHERE json_extract(ecs, '$.event.original') IS NOT NULL "
            "AND (? IS NULL OR source=?) ORDER BY id DESC LIMIT ?",
            args,
        ).fetchall()
        return [r[0] for r in q + e][:limit]

    def held_sample(self, source: str, limit: int = 10) -> list[str]:
        """Latest lines of a pending host, for the approval decision."""
        rows = self.conn.execute(
            "SELECT raw FROM unparsed WHERE source=? AND held=1 ORDER BY id DESC LIMIT ?",
            (source, limit),
        ).fetchall()
        return [r[0] for r in rows]


def _parser_row(row) -> dict:
    keys = ("id", "source", "created_at", "status", "provider", "model", "vrl", "report")
    d = dict(zip(keys, row, strict=True))
    d["report"] = json.loads(d["report"])
    return d


def parse_ts(ts: str) -> datetime:
    """ISO timestamps as produced by Vector (nanoseconds, Z) or by privasoc (+00:00)."""
    import re

    m = re.match(r"(.*?\d\d:\d\d:\d\d)(\.\d+)?(.*)$", ts.strip().replace("Z", "+00:00"))
    if not m:
        raise ValueError(ts)
    base, frac, tz = m.groups()
    dt = datetime.fromisoformat(base + (frac or "")[:7] + tz)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _skew_seconds(received_at: str, ecs: dict | None) -> float | None:
    if not ecs or not isinstance(ecs.get("@timestamp"), str):
        return None
    try:
        return abs((parse_ts(received_at) - parse_ts(ecs["@timestamp"])).total_seconds())
    except ValueError:
        return None
