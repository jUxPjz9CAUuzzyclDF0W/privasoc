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

    def close(self) -> None:
        self.conn.close()

    def ingest(self, records: Iterable[Record]) -> dict[str, int]:
        """Route each record: parsed -> events, otherwise -> quarantine."""
        counts = {"events": 0, "unparsed": 0}
        with self.conn:
            for r in records:
                ts = r.received_at or utcnow()
                if r.ecs is not None and r.parser_id:
                    self.conn.execute(
                        "INSERT INTO events(source, received_at, parser_id, ecs) VALUES (?,?,?,?)",
                        (r.source, ts, r.parser_id, json.dumps(r.ecs, separators=(",", ":"))),
                    )
                    counts["events"] += 1
                else:
                    self.conn.execute(
                        "INSERT INTO unparsed(source, received_at, raw) VALUES (?,?,?)",
                        (r.source, ts, r.raw),
                    )
                    counts["unparsed"] += 1
        return counts

    def quarantine_stats(self) -> list[tuple[str, int, str, str]]:
        """(source, lines, first_seen, last_seen) per source."""
        return self.conn.execute(
            "SELECT source, COUNT(*), MIN(received_at), MAX(received_at) "
            "FROM unparsed GROUP BY source ORDER BY COUNT(*) DESC"
        ).fetchall()

    def quarantine_sample(self, source: str, limit: int = 10) -> list[str]:
        rows = self.conn.execute(
            "SELECT raw FROM unparsed WHERE source = ? ORDER BY id DESC LIMIT ?",
            (source, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
