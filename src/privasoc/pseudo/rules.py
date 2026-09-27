"""Learned pseudonymisation rules (step 5, D25, D33).

Three rule types, each tied to a pseudonym kind (`user` or `host`):

- `key`: a key name whose value is sensitive (`suser=...`, `"device": "..."`). Generalises to
  every value of that key, including values never seen before.
- `regex`: a pattern with at most one capture group (the sensitive part). Written by a human;
  the model only proposes keys and values.
- `value`: one literal value (`nas01`, `jdoe`) when no key or context generalises it.

Rules live in the encrypted vault (their patterns may themselves be personal data), are
proposed by the local model or by a human, and only change detection once a human approves
them. A rule never replaces an existing pseudonym and never matches common log vocabulary.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

KINDS = ("user", "host")
TYPES = ("key", "regex", "value")
STATUSES = ("proposed", "approved", "rejected")

# Values that are never personal data, whatever a rule says.
SKIP_VALUES = {
    "-", "", "null", "none", "n/a", "na", "unknown", "true", "false", "yes", "no",
    "0", "1", "local", "localhost", "any", "all", "default", "system", "root",
}  # fmt: skip
# Keys whose values are free text or enumerations: a key rule on them would hide the
# structure the parser needs without protecting anyone. The value is proposed instead.
GENERIC_KEYS = {
    "msg", "message", "reason", "action", "act", "desc", "description", "text", "info",
    "status", "result", "type", "proto", "protocol", "rule", "policy", "level", "severity",
    "sev", "cat", "category", "outcome", "event", "method", "code", "id", "time", "date",
    "timestamp", "ts", "dir", "direction", "service", "app", "product", "vendor", "version",
}  # fmt: skip
_KEY_NAME = re.compile(r"^[A-Za-z_][\w.-]{0,63}$")
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
_TOKEN = re.compile(r"^(?:user|host)-[0-9a-f]{6}$|^d[0-9a-f]{6}(?:\.|$)")


class RuleError(ValueError):
    """A rule that would be unsafe or useless."""


@dataclass(frozen=True)
class Rule:
    rtype: str
    kind: str
    pattern: str
    status: str = "proposed"
    origin: str = "human"  # human | llm
    note: str = ""
    created_at: str = ""

    @property
    def id(self) -> str:
        return rule_id(self.rtype, self.kind, self.pattern)

    def label(self) -> str:
        return {"key": f"key {self.pattern}=", "regex": f"regex /{self.pattern}/"}.get(
            self.rtype, f"value {self.pattern!r}"
        )


def rule_id(rtype: str, kind: str, pattern: str) -> str:
    norm = pattern if rtype == "regex" else pattern.lower()
    return "r" + hashlib.sha256(f"{rtype}\x00{kind}\x00{norm}".encode()).hexdigest()[:7]


def plausible_value(value: str) -> bool:
    v = value.strip()
    return (
        2 <= len(v) <= 128
        and v.lower() not in SKIP_VALUES
        and not _TOKEN.match(v)
        and re.search(r"[A-Za-z]", v) is not None  # numbers alone are ports, ids, counts
        and "\n" not in v
    )


def validate(rtype: str, kind: str, pattern: str) -> str:
    """Return the normalised pattern or raise RuleError."""
    if kind not in KINDS:
        raise RuleError(f"kind must be one of {KINDS}")
    if rtype == "key":
        p = pattern.strip().strip("\"'")
        if not _KEY_NAME.match(p):
            raise RuleError("a key is a name like suser or src_user_name")
        if p.lower() in GENERIC_KEYS:
            raise RuleError(f"{p!r} holds free text or an enumeration: add a value rule instead")
        return p
    if rtype == "value":
        p = pattern.strip()
        if not plausible_value(p):
            raise RuleError("a value needs 2-128 characters, a letter, and no common word")
        return p
    if rtype == "regex":
        if not 1 <= len(pattern) <= 300:
            raise RuleError("a regex needs 1-300 characters")
        if _NESTED_QUANT.search(pattern):
            raise RuleError("nested quantifiers like (a+)+ can take exponential time")
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise RuleError(f"invalid regex: {exc}") from exc
        if rx.groups > 1:
            raise RuleError("use at most one capture group: the sensitive part")
        if rx.search(""):
            raise RuleError("the regex matches the empty string")
        return pattern
    raise RuleError(f"type must be one of {TYPES}")


def _key_regex(key: str) -> re.Pattern:
    return re.compile(
        rf"(?i)(?<![\w.-])[\"']?{re.escape(key)}[\"']?\s*[=:]\s*"
        r"(?:\"(?P<q>[^\"]{1,128})\"|'(?P<s>[^']{1,128})'|(?P<v>[^\s\",;|}\]\[)(]+))"
    )


def _value_regex(value: str) -> re.Pattern:
    return re.compile(rf"(?i)(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])")


class RuleSet:
    """Compiled rules, used by the detectors as an extra source of entities."""

    MAX_LINE = 8192  # regex rules only ever see bounded input

    def __init__(self, rules: Iterable[Rule] = ()):
        self.rules = list(rules)
        self._compiled = []
        for r in self.rules:
            if r.rtype == "key":
                self._compiled.append((r, _key_regex(r.pattern)))
            elif r.rtype == "value":
                self._compiled.append((r, _value_regex(r.pattern)))
            else:
                self._compiled.append((r, re.compile(r.pattern)))

    def __len__(self) -> int:
        return len(self.rules)

    def plus(self, extra: Iterable[Rule]) -> RuleSet:
        return RuleSet([*self.rules, *extra])

    def find(self, text: str) -> list[tuple[str, int, int, str]]:
        """(kind, start, end, value) for every match of every rule."""
        out = []
        text = text[: self.MAX_LINE]
        for rule, rx in self._compiled:
            for m in rx.finditer(text):
                if rule.rtype == "key":
                    g = next(g for g in ("q", "s", "v") if m.group(g) is not None)
                elif rule.rtype == "regex" and rx.groups == 1:
                    g = 1
                    if m.group(1) is None:
                        continue
                else:
                    g = 0
                value = m.group(g)
                if plausible_value(value):
                    out.append((rule.kind, m.start(g), m.end(g), value))
        return out


def key_before(line: str, start: int) -> str | None:
    """The key name written just before position `start` (`key=`, `key: `, `"key":"`)."""
    m = re.search(r"(?P<key>[A-Za-z_][\w.-]{0,63})[\"']?\s*[=:]\s*[\"']?$", line[:start])
    return m.group("key") if m else None
