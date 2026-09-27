"""The model writes Sigma rules; privasoc checks and backtests them (step 7, D54, D55).

Everything the model sees is pseudonymised: the request, the catalogue of fields with
example values, the example events. It answers Sigma YAML on ECS fields; privasoc compiles
it with the production engine, rejects fields that never occur in the events (with close
names as suggestions), feeds errors back for a few attempts, then re-identifies the values
the model copied from the examples so the rule works on real data. The result is only a
proposal: a human approves it after seeing what it matches.
"""

from __future__ import annotations

import difflib
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field

import yaml

from privasoc.detect.sigma import Unsupported, compile_text, used_fields

FEW_SHOT = """title: SSH authentication failure
name: ssh_failure
description: One failed SSH login.
logsource:
  product: privasoc
detection:
  selection:
    process.name: sshd
    event.outcome: failure
  filter_internal:
    source.ip|cidr: 10.0.0.0/8
  condition: selection and not filter_internal
level: low
---
title: SSH brute force from one source
correlation:
  type: event_count
  rules:
    - ssh_failure
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 10
level: high
tags:
  - attack.t1110"""

SYSTEM = f"""You write detection rules in Sigma YAML for privasoc.
Events are ECS documents. Use only the field names of the catalogue given with the task,
exactly as written. Values like user-1a2b3c, host-1a2b3c, d1a2b3c.com and the IP addresses
are pseudonyms of real values: copy them as they are when the rule needs them.

A rule has: title, description, level (informational, low, medium, high or critical),
optional tags (attack.tXXXX) and falsepositives, `logsource: {{product: privasoc}}`, and
`detection`: named selections plus a `condition`.
- A selection maps fields to values; several fields = AND; a list of values = OR.
- Modifiers after the field: contains, startswith, endswith, all, re, cidr, exists, gt,
  gte, lt, lte. No other modifier exists (no length, no count): for lengths or text
  patterns use |re with a regular expression. Wildcards * and ? work in plain values.
  Matching is case-insensitive. Values are plain strings or numbers, or lists of them.
  Quote a value that starts with a special character (> | * & ! % @) or contains ": ".
- Condition: selection names with and, or, not, parentheses, `1 of sel_*`, `all of them`.
Only when the question asks for a count or a threshold ("more than N", "at least N per
source"), add a second YAML document
after `---`: a correlation rule with `type: event_count` (number of events) or
`value_count` (number of distinct values of `condition.field`), `rules` = the `name` of
the first rule, `group-by`, `timespan` (like 30s, 5m, 1h) and `condition` (gte, gt, lte,
lt or eq; for value_count also `field`, e.g. `condition: {{field: destination.port, gte: 15}}`).
Give the first rule a `name`. Without a count or threshold in the question, write a single
rule and no correlation.

Example:
```yaml
{FEW_SHOT}
```
Answer with one fenced ```yaml block and nothing else."""

_FENCE = re.compile(r"```[ \t]*(?:ya?ml)?[ \t]*\n(.*?)```", re.S | re.I)
MAX_FIELDS = 80


def flatten(doc: dict, prefix: str = "") -> list[tuple[str, object]]:
    out = []
    for k, v in doc.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.extend(flatten(v, path))
        else:
            out.append((path, v))
    return out


def catalogue(docs: list[dict]) -> dict[str, dict]:
    """Field -> {count, examples} over recent events (examples are real values here)."""
    counts: Counter = Counter()
    examples: dict[str, list[str]] = {}
    for d in docs:
        for path, v in flatten(d):
            if path in ("event.original", "@timestamp"):
                counts[path] += 1
                continue
            counts[path] += 1
            vals = v if isinstance(v, list) else [v]
            ex = examples.setdefault(path, [])
            for x in vals:
                s = str(x)[:60]
                if len(ex) < 4 and s not in ex:
                    ex.append(s)
    return {
        f: {"count": n, "examples": examples.get(f, [])} for f, n in counts.most_common(MAX_FIELDS)
    }


@dataclass
class Draft:
    status: str  # proposed | failed
    yaml: str | None = None  # real values (re-identified)
    title: str = ""
    attempts: list[dict] = field(default_factory=list)
    reason: str = ""


class _Ctx:
    """Pseudonymised prompt pieces and the originals the leak guard must look for."""

    def __init__(self, pz):
        from privasoc.pseudo import Pseudonymizer

        self.pz, self.P = pz, Pseudonymizer
        self.mapping: dict[str, str] = {}
        self.originals: set[str] = set()

    def text(self, t: str) -> str:
        r = self.pz.pseudonymize(t)
        self.mapping.update(r.mapping)
        self.originals |= r.originals
        return r.text

    def field(self, path: str, value: str) -> str:
        r = self.pz.field_value(path, value)
        self.mapping.update(r.mapping)
        self.originals |= r.originals
        return self.P.propagate(r.text, self.mapping)

    def doc(self, d: dict) -> str:
        r = self.pz.pseudonymize_doc(d)
        self.mapping.update(r.mapping)
        self.originals |= r.originals
        return r.text

    def finish(self, t: str) -> str:
        return self.P.propagate(t, self.mapping)


def build_task(request: str, cat: dict, events: list[dict], pz, extra: str = "") -> tuple:
    ctx = _Ctx(pz)
    lines = ["Task: " + ctx.text(request), "", "Field catalogue (field: events with it; examples):"]
    for f, info in cat.items():
        ex = ", ".join(ctx.field(f, e) for e in info["examples"])
        lines.append(f"- {f}: {info['count']}" + (f"; e.g. {ex}" if ex else ""))
    if events:
        lines += ["", "Example events:"]
        for e in events:
            lines.append(f"event {e['id']}: " + ctx.doc(e["ecs"])[:900])
    if extra:
        lines += ["", ctx.text(extra)]
    return ctx.finish("\n".join(lines)), ctx


def check(text: str, known_fields: set[str]) -> tuple[list, list[str], str | None]:
    """(compiled rules, errors, normalised yaml). Forces the privasoc logsource and ids."""
    m = _FENCE.search(text)
    body = m.group(1) if m else text
    try:
        docs = [d for d in yaml.safe_load_all(body) if d is not None]
    except yaml.YAMLError as exc:
        return (
            [],
            [
                f"invalid YAML: {str(exc)[:200]}. Quote values that start with a "
                "special character (> | * & ! % @) or contain ': '"
            ],
            None,
        )
    if not docs or not all(isinstance(d, dict) for d in docs):
        return [], ["the answer must be one or more YAML mappings"], None
    errors = []
    if not any("detection" in d for d in docs):
        errors.append("there is no rule with a `detection` section")
    namespace = "ai_" + uuid.uuid4().hex[:12]
    aliases: dict[str, str] = {}
    detection_index = 0
    for d in docs:
        old_id = str(d.get("id") or "")
        old_name = str(d.get("name") or "")
        d["id"] = str(uuid.uuid4())
        d.setdefault("status", "experimental")
        if "detection" in d:
            safe_name = f"{namespace}_{detection_index}"
            detection_index += 1
            d["name"] = safe_name
            for alias in filter(None, (old_id, old_name)):
                if alias in aliases and aliases[alias] != safe_name:
                    errors.append(f"duplicate rule id or name {alias!r}")
                else:
                    aliases[alias] = safe_name
            d["logsource"] = {"product": "privasoc"}
        for k, v in (d.get("detection") or {}).items():
            items = v if isinstance(v, list) else [v]
            for sel in items:
                if isinstance(sel, dict):
                    for fk, fv in sel.items():
                        vals = fv if isinstance(fv, list) else [fv]
                        if any(isinstance(x, dict | list) for x in vals):
                            errors.append(
                                f"{k}: the value of {fk!r} must be a plain value or a list of "
                                "them; put the modifier after the field instead "
                                "(e.g. `user.name|contains: [a, b]`)"
                            )
        for f in sorted(used_fields(d)):
            if f not in known_fields:
                near = difflib.get_close_matches(f, list(known_fields), n=3, cutoff=0.5)
                hint = f"; did you mean {', '.join(near)}" if near else ""
                errors.append(f"field {f!r} does not occur in the events{hint}")
    for d in docs:
        correlation = d.get("correlation") or {}
        refs = correlation.get("rules") or []
        if isinstance(refs, str):
            errors.append("correlation rules must be a YAML list")
            refs = [refs]
        rewritten = []
        for ref in refs:
            safe_name = aliases.get(str(ref))
            if safe_name is None:
                errors.append(f"correlation refers to {ref!r}, which is not a rule's name")
                rewritten.append(str(ref))
            else:
                rewritten.append(safe_name)
        if correlation:
            correlation["rules"] = rewritten
    normalised = "\n---\n".join(yaml.safe_dump(d, sort_keys=False, allow_unicode=True)
                                for d in docs)  # fmt: skip
    try:
        rules = compile_text(normalised, "ai")
    except Unsupported as exc:
        return [], [*errors, str(exc)], normalised
    for r in rules:
        if r.unsupported:
            errors.append(f"rule {r.title!r}: {r.unsupported}")
    return rules, errors, normalised


def write(llm, pz, request: str, cat: dict, events: list[dict], *, extra: str = "",
          attempts: int = 3, progress=None) -> Draft:  # fmt: skip
    """Ask for a rule until it compiles and uses real fields, or give up."""
    from privasoc.generator import _guarded

    say = progress or (lambda _m: None)
    task, ctx = build_task(request, cat, events, pz, extra)
    known = set(cat)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
    draft = Draft("failed")
    for n in range(1, attempts + 1):
        # values that are also in our own fixed instructions (10.0.0.0 in the example) are
        # not personal data there
        guard = {o for o in _guarded(ctx.originals) if o.lower() not in SYSTEM.lower()}
        reply = llm.chat(messages, originals=guard, json_mode=False,
                         temperature=0.1 + 0.2 * (n - 1))  # fmt: skip
        rules, errors, normalised = check(reply.text, known)
        draft.attempts.append({"n": n, "errors": errors, "latency_s": round(reply.latency_s, 1)})
        say(f"attempt {n}: " + ("ok" if not errors else "; ".join(errors)[:300]))
        if not errors:
            real = pz.reidentify(normalised)
            try:
                compile_text(real, "ai")
            except Unsupported as exc:
                draft.reason = f"re-identified rule does not compile: {exc}"
                return draft
            draft.status, draft.yaml = "proposed", real
            draft.title = next((r.title for r in rules if r.correlation), rules[0].title)
            return draft
        # A value the model wrote itself (e.g. 10.0.0.0/8 from general knowledge) is not a
        # leak when its own answer is sent back to it; everything else stays guarded.
        ctx.originals = {o for o in ctx.originals if o.lower() not in reply.text.lower()}
        messages += [
            {"role": "assistant", "content": reply.text},
            {"role": "user", "content": "Fix these problems and answer with the whole rule "
             "again:\n- " + "\n- ".join(errors)},
        ]  # fmt: skip
        draft.reason = "; ".join(errors)[:500]
    return draft
