"""Minimal ECS validation: enough to give an LLM precise, actionable feedback (D8, D19)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
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
}


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
