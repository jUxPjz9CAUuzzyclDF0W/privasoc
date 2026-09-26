"""Structured parser mode (D44): the model writes regexes and an ECS mapping, we write the VRL.

Small local models struggle with VRL syntax but are decent at regexes. In this mode the
model answers with a small YAML spec; privasoc validates it in Python (fast, precise
feedback) and compiles it to VRL with a deterministic, tested compiler. The resulting VRL
then goes through exactly the same sandbox, ECS and grounding checks as free-form VRL.

Spec:
    prefix: '<regex with named groups, applied to the whole line>'   # optional
    body: rest              # prefix group the shapes apply to (default: whole line)
    timestamp: {group: ts, format: '%Y-%m-%d %H:%M:%S%.3f'}         # optional
    constants: {event.kind: event, event.category: [network]}
    fields: {host.hostname: host}           # prefix groups -> ECS
    shapes:                                  # one per line shape, tried in order
      - name: query
        regex: '<regex with named groups, applied to body>'
        fields: {dns.question.name: qname}
        constants: {event.type: [info]}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from privasoc.ecs import IP_FIELDS

INT_SUFFIXES = (".port", ".pid", ".bytes", ".packets", ".status_code", ".code", ".ttl")
_UNSUPPORTED = [
    (r"\(\?=|\(\?!", "lookahead `(?=` / `(?!` is not supported (Rust regex)"),
    (r"\(\?<=|\(\?<!", "lookbehind `(?<=` / `(?<!` is not supported (Rust regex)"),
    (r"\\[1-9]", "backreferences like \\1 are not supported (Rust regex)"),
]
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ECS_PATH = re.compile(r"^@?[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$")


class SpecError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class Shape:
    name: str
    regex: re.Pattern
    fields: dict[str, str]
    constants: dict


@dataclass
class Spec:
    prefix: re.Pattern | None
    body: str | None
    timestamp: dict | None
    constants: dict
    fields: dict[str, str]
    shapes: list[Shape]
    repairs: list[str] = field(default_factory=list)
    kv: dict | None = None  # {field_delimiter, value_delimiter, fields: {ecs: key}}


def _regex(src, where: str, problems: list[str]) -> re.Pattern | None:
    if not isinstance(src, str) or not src:
        problems.append(f"{where}: regex must be a non-empty string")
        return None
    for pat, msg in _UNSUPPORTED:
        if re.search(pat, src):
            problems.append(f"{where}: {msg}")
            return None
    try:
        return re.compile(src)
    except re.error as exc:
        problems.append(f"{where}: invalid regex ({exc})")
        return None


def _ecs_problem(ecs: str) -> str | None:
    from privasoc.ecs import TOP_LEVEL

    if not _ECS_PATH.match(ecs):
        return f"`{ecs}` is not a valid ECS field path"
    if ecs.split(".")[0] not in TOP_LEVEL:
        return (
            f"`{ecs}` is not an ECS field (ECS fields look like source.ip, "
            "dns.question.name, event.action)"
        )
    return None


def _mapping(
    obj, where: str, groups: set[str], problems: list[str], repairs: list[str]
) -> dict[str, str]:
    """Mappings that cannot work (non-ECS field, group the regex does not define) are
    dropped and reported: dropping a mapping can lose data but never invent any."""
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        problems.append(f"{where}: must be a mapping `ecs.field: group`")
        return {}
    out = {}
    for ecs, group in obj.items():
        bad = _ecs_problem(str(ecs))
        if bad:
            repairs.append(f"{where}: dropped `{ecs}` ({bad})")
        elif str(group) not in groups:
            repairs.append(
                f"{where}: dropped `{ecs}: {group}` because `{group}` is not a named group "
                f"of this regex (its groups: {sorted(groups) or 'none'})"
            )
        else:
            out[str(ecs)] = str(group)
    return out


def _scan_groups(pattern: str):
    """Yield (index, kind) for each '(' outside escapes and character classes, where kind is
    'capture' for a plain '(' and 'other' for '(?...'; and (index, ')') for closers."""
    i, in_class = 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            yield i, "other" if pattern.startswith("(?", i) else "capture"
        elif c == ")":
            yield i, ")"
        i += 1


def _name_unnamed(pattern: str) -> tuple[str, int]:
    out, last, n = [], 0, 0
    for i, kind in _scan_groups(pattern):
        if kind == "capture":
            n += 1
            out += [pattern[last:i], f"(?P<g{n}>"]
            last = i + 1
    out.append(pattern[last:])
    return "".join(out), n


def _group_end(pattern: str, name: str) -> int | None:
    start = pattern.find(f"(?P<{name}>")
    if start < 0:
        return None
    depth = 0
    for i, kind in _scan_groups(pattern):
        if i < start:
            continue
        depth += -1 if kind == ")" else 1
        if depth == 0:
            return i
    return None


def _py_format(fmt: str) -> str:
    for chrono in ("%.3f", "%.6f", "%.9f", "%.f"):
        fmt = fmt.replace(chrono, ".%f")
    return fmt.replace("%3f", "%f").replace("%6f", "%f")


def _ts_parses(value: str, fmt: str) -> bool:
    from datetime import datetime

    try:
        if fmt == "%s":
            return value.isdigit()
        py = _py_format(fmt)
        if "%Y" not in py and "%y" not in py:
            value, py = "2000 " + value, "%Y " + py
        datetime.strptime(value, py)  # noqa: DTZ007 - only a shape check
        return True
    except ValueError:
        return False


def adopt_header(raw: dict, lines: list[str], structure) -> list[str]:
    """If the model's prefix matches fewer lines than the header privasoc detected, use the
    detected one (value-free: only the regex and timestamp format change)."""
    if structure is None or not structure.prefix or not lines:
        return []

    def rate(rx: str | None) -> float:
        try:
            c = re.compile(rx) if rx else None
        except re.error:
            return 0.0
        return sum(bool(c and c.search(ln)) for ln in lines) / len(lines)

    mine = raw.get("prefix") if isinstance(raw.get("prefix"), str) else None
    if rate(mine) >= 0.9 or rate(structure.prefix) < 0.9:
        return []
    raw["prefix"], raw["body"] = structure.prefix, "rest"
    if structure.timestamp_format:
        raw["timestamp"] = {"group": "ts", "format": structure.timestamp_format}
    return [
        f"prefix: replaced by the detected {structure.header} header (yours matched "
        f"{rate(mine):.0%} of the lines)"
    ]


def autorepair(raw: dict, lines: list[str]) -> list[str]:
    """Deterministic, value-free fixes for the prefix mistakes small models keep repeating
    (seen on real runs): unnamed groups, a timestamp group under another name, and a prefix
    that swallows what the shapes expect. Mutates `raw`; returns the repairs made."""
    repairs: list[str] = []
    pattern = raw.get("prefix")
    if not isinstance(pattern, str) or not lines:
        return repairs
    named, n = _name_unnamed(pattern)
    if n:
        pattern = raw["prefix"] = named
        repairs.append(f"prefix: named {n} unnamed group(s) g1..g{n}")
    try:
        prefix = re.compile(pattern)
    except re.error:
        return repairs
    m0 = prefix.search(lines[0])
    ts = raw.get("timestamp")
    if m0 and isinstance(ts, dict) and isinstance(ts.get("format"), str):
        if str(ts.get("group")) not in prefix.groupindex:
            for g in sorted(prefix.groupindex, key=prefix.groupindex.get):
                if m0.group(g) and _ts_parses(m0.group(g), ts["format"]):
                    repairs.append(f"timestamp: used prefix group `{g}` (it holds the date)")
                    ts["group"] = g
                    break
    shapes = []
    for sh in raw.get("shapes") or []:
        if isinstance(sh, dict) and isinstance(sh.get("regex"), str):
            try:
                shapes.append(re.compile(sh["regex"]))
            except re.error:
                pass
    tsg = ts.get("group") if isinstance(ts, dict) else None
    if not shapes or tsg not in prefix.groupindex:
        return repairs

    def rate(get_text) -> float:
        hits = 0
        for line in lines:
            m = prefix.search(line)
            text = get_text(line, m) if m else None
            hits += bool(text is not None and any(s.search(text) for s in shapes))
        return hits / len(lines)

    body = raw.get("body")
    as_is = rate(lambda line, m: (m.group(body) or "") if body in prefix.groupindex else line)
    after_ts = rate(lambda line, m: line[m.end(tsg) :].lstrip())
    end = _group_end(pattern, tsg)
    if after_ts > as_is and end is not None:
        head = pattern[: end + 1]
        raw["prefix"] = (head if head.startswith("^") else "^" + head) + r"\s+(?P<rest>.*)$"
        raw["body"] = "rest"
        repairs.append(
            f"prefix: kept only the timestamp and put the rest in `rest` (shapes matched "
            f"{after_ts:.0%} of lines this way, {as_is:.0%} before)"
        )
    return repairs


def _constants(obj, where: str, problems: list[str], repairs: list[str]) -> dict:
    """Categorisation values outside the ECS enumerations are dropped, not fatal: small
    models keep repeating them, the fix is mechanical, and removing a value can never
    introduce a hallucination. Every repair is reported to the model and the reviewer."""
    from privasoc.ecs import ALLOWED

    if not isinstance(obj, dict):
        problems.append(f"{where}: must be a mapping `ecs.field: value`")
        return {}
    from privasoc.grounding import CONSTANT_FIELDS

    out = {}
    for ecs, value in obj.items():
        key = str(ecs)
        bad = _ecs_problem(key)
        if bad:
            repairs.append(f"{where}: dropped `{key}` ({bad})")
            continue
        if key not in CONSTANT_FIELDS and not key.startswith("observer."):
            # A constant anywhere else is a value not read from the line: a hallucination.
            repairs.append(
                f"{where}: dropped constant `{key}: {value}` (only categorisation fields "
                "may be constants; map it from a regex group if it is in the line)"
            )
            continue
        if key in ALLOWED:
            values = value if isinstance(value, list) else [value]
            kept = [v for v in values if v in ALLOWED[key]]
            wrong = [v for v in values if v not in ALLOWED[key]]
            if wrong:
                repairs.append(
                    f"{where}: removed invalid `{key}` value(s) {wrong} "
                    f"(allowed: {sorted(ALLOWED[key])})"
                )
            if not kept:
                continue
            value = kept if isinstance(value, list) else kept[0]
            if key in {"event.kind", "event.outcome"} and isinstance(value, list):
                value = value[0]  # single-valued in ECS (category/type are arrays)
        out[key] = value
    return out


_UNNAMED = re.compile(r"(?<!\\)\((?!\?)")


def load(text: str, lines: list[str] | None = None, structure=None) -> Spec:
    """Parse and validate a spec; with sample `lines`, apply deterministic repairs first."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(
            [f"invalid YAML ({str(exc).splitlines()[0]}); put regexes in single quotes"]
        ) from exc
    if not isinstance(raw, dict):
        raise SpecError(["the spec must be a YAML mapping with `shapes`"])
    problems: list[str] = []
    repairs: list[str] = adopt_header(raw, lines or [], structure)
    repairs += autorepair(raw, lines) if lines else []
    prefix = _regex(raw["prefix"], "prefix", problems) if raw.get("prefix") else None
    pgroups = set(prefix.groupindex) if prefix else set()
    body = raw.get("body")
    if body is not None and str(body) not in pgroups:
        problems.append(f"body: `{body}` is not a group of prefix")
    if prefix is not None and _UNNAMED.search(prefix.pattern):
        repairs.append("prefix: unnamed groups are ignored; name the groups you use")
    ts = raw.get("timestamp")
    if ts is not None:
        if not isinstance(ts, dict) or not isinstance(ts.get("format"), str):
            problems.append("timestamp: needs {group: <prefix group>, format: '<strftime>'}")
            ts = None
        elif str(ts.get("group")) not in pgroups:
            problems.append(
                f"timestamp: group `{ts.get('group')}` is not a named group of prefix "
                f"(prefix groups: {sorted(pgroups) or 'none'}); name the date part of the "
                f"prefix (?P<{ts.get('group')}>...)"
            )
            ts = None
    fields = _mapping(raw.get("fields"), "fields", pgroups, problems, repairs)
    constants = _constants(raw.get("constants") or {}, "constants", problems, repairs)
    shapes = []
    kv = None
    raw_kv = raw.get("kv")
    if raw_kv is not None:
        if not isinstance(raw_kv, dict):
            problems.append("kv: must be {field_delimiter, value_delimiter, fields}")
        else:
            kv_fields = {}
            for ecs, key in (raw_kv.get("fields") or {}).items():
                bad = _ecs_problem(str(ecs))
                if bad:
                    repairs.append(f"kv.fields: dropped `{ecs}` ({bad})")
                else:
                    kv_fields[str(ecs)] = str(key)
            kv = {
                "field_delimiter": str(raw_kv.get("field_delimiter", " ")),
                "value_delimiter": str(raw_kv.get("value_delimiter", "=")),
                "fields": kv_fields,
            }
            if not kv_fields:
                problems.append("kv.fields: map at least one key to an ECS field")
    raw_shapes = raw.get("shapes") or []
    if not isinstance(raw_shapes, list) or (not raw_shapes and kv is None):
        problems.append("shapes: give at least one shape (or a kv section)")
        raw_shapes = []
    for i, sh in enumerate(raw_shapes):
        where = f"shapes[{i}]"
        if not isinstance(sh, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        rx = _regex(sh.get("regex"), f"{where}.regex", problems)
        if rx is None:
            continue
        sconst = _constants(sh.get("constants") or {}, f"{where}.constants", problems, repairs)
        shapes.append(
            Shape(
                str(sh.get("name", f"shape{i}")),
                rx,
                _mapping(
                    sh.get("fields"), f"{where}.fields", set(rx.groupindex), problems, repairs
                ),
                sconst if isinstance(sconst, dict) else {},
            )
        )
    for g in list(pgroups) + [g for s in shapes for g in s.regex.groupindex]:
        if not _IDENT.match(g):
            problems.append(f"group name `{g}` must be an identifier")
    if problems:
        raise SpecError(problems)
    return Spec(prefix, str(body) if body else None, ts, constants, fields, shapes, repairs, kv)


def matches(spec: Spec, line: str) -> bool:
    target = line
    if spec.prefix:
        m = spec.prefix.search(line)
        if not m:
            return False
        if spec.body:
            target = m.group(spec.body) or ""
    return spec.kv is not None or any(s.regex.search(target) for s in spec.shapes)


def check_lines(spec: Spec, lines: list[str]) -> list[str]:
    """Python dry-run: which sample lines does the spec fail to match?"""
    problems = []
    for i, line in enumerate(lines, 1):
        target = line
        if spec.prefix:
            m = spec.prefix.search(line)
            if not m:
                problems.append(f"line {i} `{line[:200]}`: prefix does not match")
                continue
            if spec.body:
                target = m.group(spec.body) or ""
        if spec.kv is None and not any(s.regex.search(target) for s in spec.shapes):
            msg = f"line {i} `{line[:200]}`: no shape matches `{target[:160]}`"
            if spec.prefix and spec.prefix.groups:
                # Would a shape match if the prefix kept only its first group (the date)?
                after_first = line[m.end(1) :].lstrip() if m.end(1) >= 0 else line
                if any(s.regex.search(after_first) for s in spec.shapes):
                    msg += (
                        " - your prefix captures too much: keep only the timestamp in the "
                        "prefix and put the rest of the line in the body group, e.g. "
                        "'^(?P<ts>...) (?P<rest>.*)$' with body: rest"
                    )
            problems.append(msg)
    return problems


def _lit(value) -> str:
    """A VRL literal for a YAML constant."""
    import json

    return json.dumps(value)


def _raw_regex(rx: re.Pattern) -> str:
    return "r'" + rx.pattern.replace("'", r"\x27") + "'"


def _assign(var: str, ecs: str, group: str, expr: str | None = None) -> list[str]:
    """Assign `var.group` (or any `expr`) to an ECS field, with type-specific guards."""
    safe = re.sub(r"\W", "_", group)
    tmp = f"v_{var}_{safe}"
    src = expr or f"{var}.{group}"
    # The `if true` gives the value type string|null whatever the source (a prefix group
    # is a plain string), so fallible conversions with `??` type-check in every case.
    lines = [f"{tmp} = if true {{ {src} }} else {{ null }}"]
    if ecs.endswith(INT_SUFFIXES):
        return lines + [f"if {tmp} != null {{ .{ecs} = to_int({tmp}) ?? null }}"]
    if ecs in IP_FIELDS:
        # Only real IPs reach an IP field (Pi-hole answers "NODATA-IPv6", "<CNAME>"...).
        s = f'(string({tmp}) ?? "")'
        return lines + [f"if is_ipv4{s} || is_ipv6{s} {{ .{ecs} = {tmp} }}"]
    # "-" is the usual "no value" placeholder (web logs, CLF, many firewalls)
    return lines + [f'if {tmp} != null && {tmp} != "" && {tmp} != "-" {{ .{ecs} = {tmp} }}']


def compile_vrl(spec: Spec) -> str:
    out = ["# compiled by privasoc from a structured spec"]
    if spec.prefix:
        out.append(f"p = parse_regex!(.message, {_raw_regex(spec.prefix)})")
        target = f"string!(p.{spec.body})" if spec.body else "string!(.message)"
    else:
        target = "string!(.message)"
    if spec.timestamp:
        g, fmt = spec.timestamp["group"], spec.timestamp["format"]
        if "%Y" not in fmt and "%y" not in fmt and "%s" not in fmt:
            out.append(
                f'.@timestamp = parse_timestamp!(format_timestamp!(now(), format: "%Y")'
                f' + " " + string!(p.{g}), format: {_lit("%Y " + fmt)})'
            )
        elif fmt == "%s":
            out.append(f".@timestamp = from_unix_timestamp!(to_int!(p.{g}))")
        else:
            out.append(f".@timestamp = parse_timestamp!(string!(p.{g}), format: {_lit(fmt)})")
    for ecs, value in spec.constants.items():
        out.append(f".{ecs} = {_lit(value)}")
    for ecs, group in spec.fields.items():
        out += _assign("p", ecs, group)
    out.append(f"t = {target}")
    indent = ""
    for i, sh in enumerate(spec.shapes):
        var = f"s{i}"
        out.append(f"{indent}{var} = parse_regex(t, {_raw_regex(sh.regex)}) ?? null")
        out.append(f"{indent}if {var} != null {{")
        body = [f".{e} = {_lit(v)}" for e, v in sh.constants.items()]
        for ecs, group in sh.fields.items():
            body += _assign(var, ecs, group)
        out += [f"{indent}  {ln}" for ln in (body or ["null"])]
        out.append(f"{indent}}} else {{")
        indent += "  "
    if spec.kv:
        kv = spec.kv
        out.append(
            f"kv = parse_key_value(t, key_value_delimiter: {_lit(kv['value_delimiter'])}, "
            f"field_delimiter: {_lit(kv['field_delimiter'])}) ?? {{}}"
        )
        for i, (ecs, key) in enumerate(kv["fields"].items()):
            out += _assign("kv", ecs, f"k{i}", expr=f"get(kv, [{_lit(key)}]) ?? null")
    # With a kv section every line is handled; otherwise an unknown shape aborts.
    out.append(f"{indent}{'null' if spec.kv else 'abort'}")
    for _ in spec.shapes:
        indent = indent[:-2]
        out.append(f"{indent}}}")
    return "\n".join(out) + "\n"
