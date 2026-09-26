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


def _mapping(obj, where: str, groups: set[str], problems: list[str]) -> dict[str, str]:
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        problems.append(f"{where}: must be a mapping `ecs.field: group`")
        return {}
    out = {}
    for ecs, group in obj.items():
        bad = _ecs_problem(str(ecs))
        if bad:
            problems.append(f"{where}: {bad}")
        elif str(group) not in groups:
            problems.append(
                f"{where}: `{ecs}: {group}` but `{group}` is not a named group of this regex "
                f"(its groups: {sorted(groups) or 'none'}). If `{group}` is a fixed value, "
                f"move it to `constants`; otherwise add (?P<{group}>...) to the regex."
            )
        else:
            out[str(ecs)] = str(group)
    return out


def _constants(obj, where: str, problems: list[str], repairs: list[str]) -> dict:
    """Categorisation values outside the ECS enumerations are dropped, not fatal: small
    models keep repeating them, the fix is mechanical, and removing a value can never
    introduce a hallucination. Every repair is reported to the model and the reviewer."""
    from privasoc.ecs import ALLOWED

    if not isinstance(obj, dict):
        problems.append(f"{where}: must be a mapping `ecs.field: value`")
        return {}
    out = {}
    for ecs, value in obj.items():
        key = str(ecs)
        bad = _ecs_problem(key)
        if bad:
            problems.append(f"{where}: {bad}")
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
        out[key] = value
    return out


_UNNAMED = re.compile(r"(?<!\\)\((?!\?)")


def load(text: str) -> Spec:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(
            [f"invalid YAML ({str(exc).splitlines()[0]}); put regexes in single quotes"]
        ) from exc
    if not isinstance(raw, dict):
        raise SpecError(["the spec must be a YAML mapping with `shapes`"])
    problems: list[str] = []
    repairs: list[str] = []
    prefix = _regex(raw["prefix"], "prefix", problems) if raw.get("prefix") else None
    pgroups = set(prefix.groupindex) if prefix else set()
    body = raw.get("body")
    if body is not None and str(body) not in pgroups:
        problems.append(f"body: `{body}` is not a group of prefix")
    if prefix is not None and _UNNAMED.search(prefix.pattern):
        problems.append(
            "prefix: has an unnamed group `( ... )`; name it, e.g. (?P<ts>...), "
            "or make it non-capturing with (?: ... )"
        )
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
    fields = _mapping(raw.get("fields"), "fields", pgroups, problems)
    constants = _constants(raw.get("constants") or {}, "constants", problems, repairs)
    shapes = []
    raw_shapes = raw.get("shapes") or []
    if not isinstance(raw_shapes, list) or not raw_shapes:
        problems.append("shapes: give at least one shape")
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
                _mapping(sh.get("fields"), f"{where}.fields", set(rx.groupindex), problems),
                sconst if isinstance(sconst, dict) else {},
            )
        )
    for g in list(pgroups) + [g for s in shapes for g in s.regex.groupindex]:
        if not _IDENT.match(g):
            problems.append(f"group name `{g}` must be an identifier")
    if problems:
        raise SpecError(problems)
    return Spec(prefix, str(body) if body else None, ts, constants, fields, shapes, repairs)


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
        if not any(s.regex.search(target) for s in spec.shapes):
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


def _assign(var: str, ecs: str, group: str) -> list[str]:
    v = f"{var}.{group}"
    if ecs.endswith(INT_SUFFIXES):
        return [f"if {v} != null {{ .{ecs} = to_int({v}) ?? null }}"]
    return [f'if {v} != null && {v} != "" {{ .{ecs} = {v} }}']


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
    out.append(f"{indent}abort")
    for _ in spec.shapes:
        indent = indent[:-2]
        out.append(f"{indent}}}")
    return "\n".join(out) + "\n"
