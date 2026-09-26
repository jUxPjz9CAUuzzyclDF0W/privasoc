"""Minimal ECS validation: enough to give an LLM precise, actionable feedback (D8, D19)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from pathlib import Path
from typing import Any

TOP_LEVEL = {
    "@timestamp",
    "message",
    "tags",
    "labels",
    "agent",
    "as",
    "client",
    "cloud",
    "container",
    "data_stream",
    "destination",
    "device",
    "dll",
    "dns",
    "ecs",
    "email",
    "error",
    "event",
    "faas",
    "file",
    "geo",
    "group",
    "host",
    "http",
    "interface",
    "log",
    "network",
    "observer",
    "orchestrator",
    "organization",
    "package",
    "process",
    "registry",
    "related",
    "rule",
    "server",
    "service",
    "source",
    "threat",
    "tls",
    "trace",
    "transaction",
    "span",
    "url",
    "user",
    "user_agent",
    "vulnerability",
    "vlan",
    "hash",
    "code_signature",
    "pe",
    "elf",
}
ALLOWED = {
    "event.kind": {
        "alert",
        "asset",
        "enrichment",
        "event",
        "metric",
        "state",
        "pipeline_error",
        "signal",
    },
    "event.category": {
        "api",
        "authentication",
        "configuration",
        "database",
        "driver",
        "email",
        "file",
        "host",
        "iam",
        "intrusion_detection",
        "library",
        "malware",
        "network",
        "package",
        "process",
        "registry",
        "session",
        "threat",
        "vulnerability",
        "web",
    },
    "event.type": {
        "access",
        "admin",
        "allowed",
        "change",
        "connection",
        "creation",
        "deletion",
        "denied",
        "end",
        "error",
        "group",
        "indicator",
        "info",
        "installation",
        "protocol",
        "start",
        "user",
    },
    "event.outcome": {"failure", "success", "unknown"},
}
IP_FIELDS = {
    "source.ip",
    "destination.ip",
    "client.ip",
    "server.ip",
    "host.ip",
    "observer.ip",
    "source.nat.ip",
    "destination.nat.ip",
    "dns.resolved_ip",
}


FIELDS = frozenset(
    ln.strip()
    for ln in (Path(__file__).with_name("ecs_fields.txt")).read_text(encoding="utf-8").splitlines()
    if ln.strip() and not ln.startswith("#")
)
# Names small models use for ECS fields that exist under another name.
ALIASES = {
    "http.method": "http.request.method",
    "http.uri": "url.original",
    "http.url": "url.original",
    "http.path": "url.path",
    "http.user_agent": "user_agent.original",
    "http.useragent": "user_agent.original",
    "http.status_code": "http.response.status_code",
    "http.status": "http.response.status_code",
    "http.referer": "http.request.referrer",
    "http.referrer": "http.request.referrer",
    "http.bytes": "http.response.body.bytes",
    "response.body_size": "http.response.body.bytes",
    "url.path_original": "url.original",
    "source.hostname": "source.domain",
    "destination.hostname": "destination.domain",
    "user.username": "user.name",
    "source.user": "source.user.name",
    "network.direction_name": "network.direction",
    "dns.query": "dns.question.name",
    "dns.question.class_name": "dns.question.class",
    "dns.type": "dns.question.type",
}


def known(path: str) -> bool:
    return path in FIELDS or path.startswith("labels.")


def suggest(path: str) -> str | None:
    """Closest real ECS field for an invented name, or None."""
    if path in ALIASES:
        return ALIASES[path]
    parts = path.split(".")
    same = [f for f in FIELDS if f.split(".")[-1] == parts[-1] and f.split(".")[0] == parts[0]]
    if len(same) == 1:
        return same[0]
    if len(parts) >= 2:
        tail = ".".join(parts[-2:])
        cands = [f for f in FIELDS if f.endswith("." + tail) or f == tail]
        if len(cands) == 1:
            return cands[0]
    return None


def flatten(doc: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from flatten(v, f"{prefix}.{k}" if prefix else str(k))
    else:
        yield prefix, doc


def validate(doc: dict) -> list[str]:
    errors = []
    for key in doc:
        if key not in TOP_LEVEL:
            errors.append(
                f"`{key}` is not an ECS field set; put vendor data under `labels` "
                "or a proper ECS field"
            )
    leaves = [(p, v) for p, v in flatten(doc) if p not in {"message", "event.original"}]
    if not leaves:
        errors.append("no ECS field extracted")
    for path, value in leaves:
        if not known(path) and path.split(".")[0] in TOP_LEVEL:
            hint = suggest(path)
            errors.append(
                f"`{path}` is not an ECS field" + (f"; did you mean `{hint}`?" if hint else "")
            )
        values = value if isinstance(value, list) else [value]
        if path in ALLOWED:
            bad = [v for v in values if v not in ALLOWED[path]]
            if bad:
                errors.append(
                    f"`{path}` has invalid value(s) {bad}; allowed: {sorted(ALLOWED[path])}"
                )
        if path in IP_FIELDS:
            for v in values:
                try:
                    ipaddress.ip_address(str(v))
                except ValueError:
                    errors.append(f"`{path}` = {v!r} is not an IP address")
        if path.endswith(".port"):
            for v in values:
                if not isinstance(v, int) or not 0 <= v <= 65535:
                    errors.append(f"`{path}` = {v!r} must be an integer 0-65535 (use to_int!)")
    return errors
