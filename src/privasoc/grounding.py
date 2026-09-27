"""Hallucination check (D38b): every extracted value must be grounded in the raw line."""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any

from privasoc.ecs import ALLOWED, flatten

SKIP = {"message", "event.original", "ecs.version"}
CONSTANT_FIELDS = set(ALLOWED) | {
    "observer.vendor",
    "observer.product",
    "observer.type",
    "event.module",
    "event.dataset",
    "event.provider",
    "event.action",  # chosen by the source/parser in ECS, like the categorisation fields
}
PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")


def _grounded(path: str, value: Any, raw: str, low: str) -> bool:
    if isinstance(value, bool) or value is None:
        return True
    if path in CONSTANT_FIELDS:
        return True  # categorisation constants are chosen, not extracted
    s = str(value)
    if s.lower() in low:
        return True
    if isinstance(value, float) and value.is_integer() and str(int(value)) in raw:
        return True
    if path == "network.transport" and any(
        re.search(rf"\b{n}\b", raw) and s.lower() == p for n, p in PROTO.items()
    ):
        return True
    m = _ISO.match(s)
    if m and path == "@timestamp":
        y, mo, d, h, mi, se = m.groups()
        if f"{h}:{mi}:{se}" in raw or f"{y}-{mo}-{d}" in raw:
            return True
        # A timezone offset shifts the hour (and maybe the day), never minutes and seconds.
        if y in raw and f":{mi}:{se}" in raw:
            return True
        # RFC 3164 syslog has no year or offset. Vector supplies the current year and renders
        # the parsed local time in UTC. Require both the unchanged minute/second and the raw
        # month/day (allowing one day of offset at midnight); the year alone is not grounded.
        if f":{mi}:{se}" in raw:
            try:
                output_day = date(int(y), int(mo), int(d))
            except ValueError:
                return False
            for delta in (-1, 0, 1):
                raw_day = output_day + timedelta(days=delta)
                month = raw_day.strftime("%b")
                if re.search(rf"\b{month}\s+0?{raw_day.day}\b", raw, re.IGNORECASE):
                    return True
        return bool(re.search(r"\b1\d{9}\b", raw))  # epoch seconds
    return False


def ungrounded(doc: dict, raw: str) -> list[tuple[str, Any]]:
    low = raw.lower()
    bad = []
    for path, value in flatten(doc):
        if path in SKIP or path.startswith("related."):
            continue
        for v in value if isinstance(value, list) else [value]:
            if not _grounded(path, v, raw, low):
                bad.append((path, v))
    return bad
