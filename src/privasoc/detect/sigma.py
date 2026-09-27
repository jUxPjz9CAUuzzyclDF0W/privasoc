"""A small Sigma evaluator on ECS documents (D51).

Supported: selections (maps, lists of maps, keyword lists), wildcards `*` and `?`,
modifiers contains / startswith / endswith / all / re / cidr / exists / gt / gte / lt / lte,
conditions with and / or / not / parentheses / `1 of x*` / `all of x*` / `them`, and Sigma 2
correlation rules (event_count, value_count) with group-by and timespan.

A rule that needs anything else (another modifier, a Sigma field privasoc cannot map to
ECS, an aggregation in the condition) is kept as *unsupported* with the reason, so the
coverage of the rule set is always visible.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LEVELS = ("informational", "low", "medium", "high", "critical")

# Sigma taxonomy field -> ECS, per logsource (D51). `None` in a logsource means the rule's
# fields are ECS already (privasoc's own rules).
FIELD_MAP: dict[str, dict[str, str]] = {
    "dns": {
        "query": "dns.question.name",
        "record_type": "dns.question.type",
        "answer": "dns.answers.data",
        "src_ip": "source.ip",
    },
    "firewall": {
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "src_port": "source.port",
        "dst_port": "destination.port",
        "action": "event.action",
        "protocol": "network.transport",
    },
    "webserver": {
        "cs-method": "http.request.method",
        "cs-uri-query": "url.query",
        "cs-uri-stem": "url.path",
        "cs-uri": "url.original",
        "sc-status": "http.response.status_code",
        "cs-user-agent": "user_agent.original",
        "cs-referer": "http.request.referrer",
        "c-ip": "source.ip",
    },
    "proxy": {
        "c-useragent": "user_agent.original",
        "c-uri": "url.original",
        "cs-uri": "url.original",
        "c-uri-query": "url.query",
        "c-uri-extension": "url.extension",
        "cs-host": "url.domain",
        "cs-method": "http.request.method",
        "sc-status": "http.response.status_code",
        "dst_ip": "destination.ip",
        "src_ip": "source.ip",
        "cs-referrer": "http.request.referrer",
    },
}
KEYWORD_FIELDS = ("event.original", "message")


class Unsupported(Exception):
    """The rule uses something this engine does not implement (the reason is shown)."""


# ------------------------------------------------------------------ ECS access


def get(doc: dict, path: str) -> Any:
    """Dotted path in a nested document; a list on the way yields the list of values."""
    if path in doc:
        return doc[path]
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list):
            cur = [c.get(part) for c in cur if isinstance(c, dict)]
        else:
            return None
    return cur


def _values(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            out.extend(_values(x))
        return out
    return [v]


# ------------------------------------------------------------------ logsources


def _has(doc: dict, *paths: str) -> bool:
    return any(get(doc, p) not in (None, "", []) for p in paths)


def _proc(doc: dict) -> str:
    return str(get(doc, "process.name") or "").lower()


def logsource_key(ls: dict) -> str:
    return ls.get("category") or ls.get("service") or ls.get("product") or "?"


def logsource_matcher(ls: dict):
    """(matcher(doc) -> bool, field map or None) for a Sigma logsource."""
    product, category, service = ls.get("product"), ls.get("category"), ls.get("service")
    if product == "privasoc":
        return (lambda d: True), None
    if category == "dns":
        return (lambda d: _has(d, "dns.question.name")), FIELD_MAP["dns"]
    if category == "firewall":
        return (
            lambda d: _has(d, "destination.ip", "destination.port") and not _has(d, "dns", "http")
        ), FIELD_MAP["firewall"]
    if category in ("webserver", "proxy"):
        return (lambda d: _has(d, "url.original", "url.path", "http.request.method")), FIELD_MAP[
            category
        ]
    if category and category not in ("dns", "firewall", "webserver", "proxy"):
        raise Unsupported(f"logsource category {category!r} is not normalised by privasoc yet")
    if product == "linux" or service:
        if product not in (None, "linux"):
            raise Unsupported(f"logsource product {product!r} is not normalised by privasoc yet")
        if service in ("apache", "nginx"):
            return (lambda d: _has(d, "url.original", "http.request.method")), {}
        if service:
            name = {"auth": "sshd"}.get(service, service)
            if service == "syslog":
                return (lambda d: _has(d, "event.original")), {}
            return (lambda d: name in _proc(d)), {}
        return (lambda d: _has(d, "process.name", "log.syslog")), {}
    raise Unsupported(f"logsource {ls} is not normalised by privasoc yet")


# ------------------------------------------------------------------ values and modifiers


def _wildcard(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.I | re.S)


_CMP = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists"}
SUPPORTED_MODS |= {"gt", "gte", "lt", "lte", "i", "m", "s"}


def _value_matcher(value: Any, mods: list[str]):
    """Predicate on one field value for one Sigma value."""
    if value is None:
        return lambda v: v in (None, "", [])
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0)
        flags |= re.S if "s" in mods else 0
        rx = re.compile(str(value), flags)
        return lambda v: v is not None and rx.search(str(v)) is not None
    if "cidr" in mods:
        net = ipaddress.ip_network(str(value), strict=False)

        def in_net(v):
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net
    ops = [m for m in mods if m in _CMP]
    if ops:
        cmp, ref = _CMP[ops[0]], float(value)

        def num(v):
            try:
                return cmp(float(v), ref)
            except (TypeError, ValueError):
                return False

        return num
    if isinstance(value, bool | int | float) and not isinstance(value, str):
        return lambda v: v is not None and str(v).lower() == str(value).lower()
    s = str(value)
    if "contains" in mods:
        s = f"*{s}*"
    elif "startswith" in mods:
        s = f"{s}*"
    elif "endswith" in mods:
        s = f"*{s}"
    rx = _wildcard(s)
    return lambda v: v is not None and rx.match(str(v)) is not None


def _field_matcher(key: str, value: Any, fmap: dict | None, logsource: str):
    name, *mods = key.split("|")
    bad = [m for m in mods if m not in SUPPORTED_MODS]
    if bad:
        raise Unsupported(f"modifier {'|'.join(bad)} not supported")
    if fmap is None:
        path = name
    elif name in fmap:
        path = fmap[name]
    else:
        raise Unsupported(f"field {name!r} has no ECS mapping for {logsource}")
    if "exists" in mods:
        want = bool(value)
        return lambda d: (get(d, path) not in (None, "", [])) == want
    raw = value if isinstance(value, list) else [value]
    preds = [_value_matcher(v, mods) for v in raw]
    need_all = "all" in mods

    def match(d):
        vals = _values(get(d, path)) or [None]
        hits = [any(p(v) for v in vals) for p in preds]
        return all(hits) if need_all else any(hits)

    return match


def _keywords(values: list, mods: tuple = ()):
    """Keywords are searched in the raw line; `|all` requires every one of them."""
    preds = [_value_matcher(v, ["contains"]) for v in values]
    need_all = "all" in mods

    def match(d):
        texts = [str(t) for f in KEYWORD_FIELDS for t in _values(get(d, f))]
        hits = [any(p(t) for t in texts) for p in preds]
        return all(hits) if need_all else any(hits)

    return match


def _selection(spec: Any, fmap: dict | None, logsource: str):
    if isinstance(spec, dict):
        parts = []
        for k, v in spec.items():
            name, *mods = k.split("|")
            if name == "":  # `'|all': [...]`: keywords with modifiers
                if set(mods) - {"all", "contains"}:
                    raise Unsupported(f"keyword modifier {'|'.join(mods)} not supported")
                parts.append(_keywords(v if isinstance(v, list) else [v], tuple(mods)))
                continue
            parts.append(_field_matcher(k, v, fmap, logsource))
        return lambda d: all(p(d) for p in parts)
    if isinstance(spec, list):
        if all(isinstance(x, dict) for x in spec):
            subs = [_selection(x, fmap, logsource) for x in spec]
            return lambda d: any(s(d) for s in subs)
        if all(not isinstance(x, dict | list) for x in spec):
            return _keywords(spec)
        raise Unsupported("mixed keyword and map selection")
    if isinstance(spec, str | int):
        return _keywords([spec])
    raise Unsupported(f"selection of type {type(spec).__name__}")


# ------------------------------------------------------------------ conditions

_TOKEN = re.compile(r"\s*(\(|\)|[\w*.-]+)")


def _tokens(cond: str) -> list[str]:
    toks, pos = [], 0
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            if cond[pos:].strip() == "":
                break
            raise Unsupported(f"condition syntax near {cond[pos : pos + 20]!r}")
        toks.append(m.group(1))
        pos = m.end()
    return toks


def compile_condition(cond: str, sels: dict):
    if "|" in cond:
        raise Unsupported("aggregation in the condition (use a correlation rule)")
    toks = _tokens(cond)
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def names(pat: str) -> list[str]:
        if pat == "them":
            return [n for n in sels if not n.startswith("_")]
        rx = _wildcard(pat)
        found = [n for n in sels if rx.match(n)]
        if not found:
            raise Unsupported(f"no selection matches {pat!r}")
        return found

    def atom():
        t = peek()
        if t is None:
            raise Unsupported("condition ends early")
        if t == "(":
            take()
            e = expr()
            if peek() != ")":
                raise Unsupported("missing )")
            take()
            return e
        if t == "not":
            take()
            a = atom()
            return lambda d: not a(d)
        if t in ("1", "all", "any") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            quant = take().lower()
            take()
            subs = [sels[n] for n in names(take())]
            if quant == "all":
                return lambda d: all(s(d) for s in subs)
            return lambda d: any(s(d) for s in subs)
        name = take()
        if name not in sels:
            raise Unsupported(f"unknown selection {name!r}")
        s = sels[name]
        return lambda d: s(d)

    def conj():
        left = atom()
        while peek() == "and":
            take()
            right = atom()
            left = (lambda a, b: lambda d: a(d) and b(d))(left, right)
        return left

    def expr():
        left = conj()
        while peek() == "or":
            take()
            right = conj()
            left = (lambda a, b: lambda d: a(d) or b(d))(left, right)
        return left

    e = expr()
    if pos != len(toks):
        raise Unsupported(f"unexpected {toks[pos]!r} in condition")
    return e


# ------------------------------------------------------------------ rules


@dataclass
class Rule:
    id: str
    title: str
    level: str
    origin: str  # sigmahq | privasoc
    path: str
    description: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    name: str | None = None  # referenced by correlations
    unsupported: str | None = None
    match: Any = None  # callable(doc) -> bool
    applies: Any = None  # callable(doc) -> bool
    correlation: dict | None = None  # Sigma 2 correlation block, normalised

    @property
    def attack(self) -> list[str]:
        return sorted(
            t.split(".", 1)[1].upper()
            for t in self.tags
            if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())
        )

    def licence(self) -> str:
        return "DRL 1.1 (SigmaHQ)" if self.origin == "sigmahq" else "MIT (privasoc)"


_SPAN = re.compile(r"^(\d+)([smhd])$")


def seconds(span: str) -> int:
    m = _SPAN.match(str(span).strip())
    if not m:
        raise Unsupported(f"timespan {span!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _compile(doc: dict, origin: str, path: str) -> Rule:
    level = str(doc.get("level", "medium")).lower()
    r = Rule(
        id=str(doc.get("id") or doc.get("name") or path),
        title=str(doc.get("title", "untitled")),
        level=level if level in LEVELS else "medium",
        origin=origin,
        path=path,
        description=str(doc.get("description", "")).strip(),
        author=str(doc.get("author", "")),
        tags=[str(t) for t in doc.get("tags") or []],
        falsepositives=[str(f) for f in doc.get("falsepositives") or []],
        logsource=doc.get("logsource") or {},
        name=doc.get("name"),
    )
    try:
        if "correlation" in doc:
            c = doc["correlation"]
            ctype = c.get("type")
            if ctype not in ("event_count", "value_count"):
                raise Unsupported(f"correlation type {ctype!r}")
            cond = c.get("condition") or {}
            ops = {k: v for k, v in cond.items() if k in ("gt", "gte", "lt", "lte", "eq")}
            if len(ops) != 1:
                raise Unsupported("correlation condition needs one of gt/gte/lt/lte/eq")
            if ctype == "value_count" and not cond.get("field"):
                raise Unsupported("value_count needs condition.field")
            gb = c.get("group-by") or []
            r.correlation = {
                "type": ctype,
                "rules": [str(x) for x in (c.get("rules") or [])],
                "group_by": [gb] if isinstance(gb, str) else list(gb),
                "timespan": seconds(c.get("timespan", "5m")),
                "op": next(iter(ops.items())),
                "field": cond.get("field"),
            }
            if not r.correlation["rules"]:
                raise Unsupported("correlation without rules")
            return r
        det = doc.get("detection") or {}
        if "timeframe" in det:
            raise Unsupported("timeframe aggregation (use a correlation rule)")
        applies, fmap = logsource_matcher(r.logsource)
        key = logsource_key(r.logsource)
        sels = {n: _selection(v, fmap, key) for n, v in det.items() if n not in ("condition",)}
        cond = det.get("condition")
        if isinstance(cond, list):
            if len(cond) != 1:
                raise Unsupported("several conditions")
            cond = cond[0]
        if not isinstance(cond, str):
            raise Unsupported("missing condition")
        pred = compile_condition(cond, sels)
        r.applies, r.match = applies, pred
    except Unsupported as exc:
        r.unsupported = str(exc)
    except (re.error, ValueError, TypeError) as exc:
        r.unsupported = f"invalid rule: {exc}"
    return r


def load_rules(dirs: list[tuple[Path, str]]) -> list[Rule]:
    """Every rule from each (directory, origin); multi-document files are supported."""
    rules = []
    for base, origin in dirs:
        if not base.exists():
            continue
        for p in sorted(base.rglob("*.yml")) + sorted(base.rglob("*.yaml")):
            try:
                docs = [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if d]
            except yaml.YAMLError as exc:
                rules.append(
                    Rule(p.stem, p.stem, "low", origin, str(p), unsupported=f"YAML: {exc}")
                )
                continue
            for d in docs:
                if isinstance(d, dict) and ("detection" in d or "correlation" in d):
                    rules.append(_compile(d, origin, str(p.relative_to(base))))
    return rules
