"""Deterministic structure detection (I23): what does not need a model, is not asked of one.

Before the LLM sees a sample, privasoc looks for a known header (syslog RFC 3164/5424,
ISO timestamp, Common Log Format) and for key/value pairs. The model is then asked only
for what needs judgement: which ECS field each key or group means, and regexes for the
free-text shapes. Everything here runs on the already pseudonymised sample.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

HEADERS = [
    (
        "syslog RFC 5424",
        r"^<\d+>\d+ (?P<ts>\d{4}-\d\d-\d\dT\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
        r"(?P<msgid>\S+) (?P<rest>.*)$",
        "%Y-%m-%dT%H:%M:%S%.fZ",
    ),
    (
        "syslog RFC 3164 with program",
        r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d) (?P<host>[^\s:\[]+) "
        r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<rest>.*)$",
        "%b %d %H:%M:%S",
    ),
    (
        "syslog RFC 3164",
        r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d) (?P<host>[^\s:]+):? "
        r"(?P<rest>.*)$",
        "%b %d %H:%M:%S",
    ),
    (
        "ISO timestamp",
        r"^(?:<\d+>)?(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?) "
        r"(?P<rest>.*)$",
        None,
    ),
    (
        "Common Log Format",
        r"^(?P<client>\S+) (?P<ident>\S+) (?P<auth>\S+) \[(?P<ts>[^\]]+)\] (?P<rest>.*)$",
        "%d/%b/%Y:%H:%M:%S %z",
    ),
]
KV_STYLES = [  # (value delimiter, field delimiter, pair regex)
    ("=", " ", r'(?:^|\s)([A-Za-z_][\w./-]*)=("[^"]*"|[^\s"]*)'),
    (":", "; ", r'(?:^|[\[;]\s?)([A-Za-z_][\w./-]*):"([^"]*)"'),
    ("=", ", ", r'(?:^|,\s?)([A-Za-z_][\w./-]*)=("[^"]*"|[^,"]*)'),
    ("=", "|", r"(?:^|\|)([A-Za-z_][\w./-]*)=([^|]*)"),
]


@dataclass
class Structure:
    header: str | None = None
    prefix: str | None = None
    timestamp_format: str | None = None
    kv: tuple[str, str] | None = None  # (value delimiter, field delimiter)
    keys: list[tuple[str, str]] = field(default_factory=list)  # (key, example value)

    def describe(self) -> str:
        if not self.header and not self.kv:
            return ""
        out = ["Structure detected by privasoc (reuse it; do not reinvent it):"]
        if self.header:
            out += [f"- header: {self.header}", f"  prefix: '{self.prefix}'", "  body: rest"]
            if self.timestamp_format:
                out.append(f"  timestamp: {{group: ts, format: '{self.timestamp_format}'}}")
        if self.kv:
            vd, fd = self.kv
            out += [
                f"- key/value pairs: use `kv` with field_delimiter: '{fd}' and "
                f"value_delimiter: '{vd}'. Keys seen (with an example value):"
            ]
            out += [f"    {k} = {v[:40]}" for k, v in self.keys[:40]]
            out.append("  Map every key that has an ECS meaning in kv.fields.")
        return "\n".join(out)


def _iso_format(sample: str) -> str:
    fmt = "%Y-%m-%dT%H:%M:%S" if "T" in sample else "%Y-%m-%d %H:%M:%S"
    if re.search(r"[.,]\d+", sample):
        fmt += "%.f"
    if sample.endswith("Z"):
        fmt += "Z"
    elif re.search(r"[+-]\d\d:?\d\d$", sample):
        fmt += "%z"
    return fmt


def detect(lines: list[str]) -> Structure:
    st = Structure()
    rests = lines
    for name, rx, fmt in HEADERS:
        c = re.compile(rx)
        ms = [c.match(ln) for ln in lines]
        if lines and sum(m is not None for m in ms) >= 0.9 * len(lines):
            st.header, st.prefix = name, rx
            first = next(m for m in ms if m)
            ts = first.group("ts")
            st.timestamp_format = fmt or _iso_format(ts)
            if fmt == "%b %d %H:%M:%S" and re.search(r" \d{4} ", ts):
                st.timestamp_format = "%b %d %Y %H:%M:%S"
            rests = [m.group("rest") for m in ms if m]
            break
    best = None
    for vd, fd, rx in KV_STYLES:
        c = re.compile(rx)
        pairs = [c.findall(r) for r in rests]
        avg = sum(len(p) for p in pairs) / max(1, len(rests))
        if avg >= 3 and (best is None or avg > best[0]):
            best = (avg, vd, fd, pairs)
    if best:
        _, vd, fd, pairs = best
        st.kv = (vd, fd)
        counts = Counter(k for p in pairs for k, _ in p)
        examples = {}
        for p in pairs:
            for k, v in p:
                examples.setdefault(k, v.strip('"'))
        st.keys = [(k, examples[k]) for k, _ in counts.most_common()]
    return st
