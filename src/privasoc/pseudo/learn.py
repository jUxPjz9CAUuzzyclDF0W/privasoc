"""Local-model pass for residual personal data, and the rules it teaches (step 5, D25, D33).

The regex detectors miss values without a recognisable shape or key: a user name in a
positional column, a bare machine name. Here the **local** model reads lines that were
already pseudonymised by the current rules and lists what still identifies a person or a
machine. privasoc then keeps only what is really in the lines (grounding), turns each value
into the most general rule it can justify (the key it is written after, else the literal
value) and measures the effect of every rule on the latest lines. A human approves or
rejects each rule; only approved rules change detection.

This pass sends lines that still contain personal data, so it only ever talks to a model on
this machine or the local network (`ensure_local`), never to the remote API.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

from privasoc.pseudo.rules import GENERIC_KEYS, KINDS, Rule, RuleSet, key_before, plausible_value

LEARN_SYSTEM = """You check log lines for names still in clear, before they are shared.
Values like user-1a2b3c, host-1a2b3c, d1a2b3c.com and IP addresses are already pseudonyms:
ignore them.

For EACH line, answer one output line: the line number, a colon, then every person name
(user, login, account) and machine name (host, device, firewall, server) still in clear in
that line, as `value (user)` or `value (host)`, separated by commas; `-` if there is none.
Copy each value exactly as written. A missed name leaks; an extra one is only a question
for the reviewer.
Not names: timestamps, numbers, ports, protocols, actions, severities, program or process
names (sshd, dnsmasq, kernel), interface names, file names, countries.

Example:
1: mike.r (user), core-sw2 (host)
2: -"""

_FENCE = re.compile(r"```[ \t]*(?:ya?ml)?[ \t]*\n(.*?)```", re.S | re.I)
_PSEUDONYM = re.compile(r"\b(?:user|host)-[0-9a-f]{6}\b|\bd[0-9a-f]{6}(?:\.[\w-]+)+")


class LocalOnlyError(RuntimeError):
    """The residual pass must not send clear-text lines off the local network."""


def ensure_local(url: str) -> None:
    """Accept only loopback, private or link-local addresses (names are resolved)."""
    host = urlparse(url).hostname
    if not host:
        raise LocalOnlyError(f"cannot read a host in {url!r}")
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise LocalOnlyError(f"cannot resolve {host!r}: {exc}") from exc
        addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    bad = [a for a in addrs if not (a.is_loopback or a.is_private or a.is_link_local)]
    if bad:
        raise LocalOnlyError(
            f"{host} resolves to a public address; the residual pass sends clear-text lines "
            "and only runs against a model on this machine or the local network"
        )


@dataclass
class Finding:
    value: str
    kind: str
    lines: int  # lines of the batch that contain it
    key: str | None = None  # the key it is written after, when one generalises it
    contexts: list[str] = field(default_factory=list)  # regexes from the words around it


CONTEXT_VALUE = r"([\w.$@-]+)"


def context_regex(line: str, start: int, end: int) -> str | None:
    """`\bUser (value) IP\b` from `... User testuser IP ...`: the words right before and
    after a value, when both are plain words. Two-sided anchors keep the rule narrow."""
    before = line[:start]
    after = line[end:]
    mb = re.search(r"(?:^|\s)([A-Za-z]{2,24}) $", before)
    ma = re.match(r" ([A-Za-z]{2,24})(?:\s|$|[.,;:])", after)
    if not mb or not ma:
        return None
    return rf"\b{mb.group(1)} {CONTEXT_VALUE} {ma.group(1)}\b"


def _masked(text: str) -> str:
    """Pseudonyms blanked out, so a value is only found where it is still in clear."""
    return _PSEUDONYM.sub(lambda m: " " * len(m.group(0)), text)


_LINE_ANSWER = re.compile(r"^\s*(\d+)\s*[:.)-]\s*(.*)$")
_ITEM = re.compile(r"^(?P<v>.+?)\s*\((?P<k>user|host)\)\s*$", re.I)


def parse_answer(text: str) -> list[tuple[str, str]]:
    """Per-line answers (`3: jdoe (user), nas01 (host)`), or a YAML list as a fallback."""
    out = []
    for line in text.splitlines():
        m = _LINE_ANSWER.match(line)
        if not m:
            continue
        for item in m.group(2).split(","):
            it = _ITEM.match(item.strip().strip("`"))
            if it:
                out.append((it.group("v").strip().strip("`'\""), it.group("k").lower()))
    if out:
        return out
    fence = _FENCE.search(text)
    try:
        data = yaml.safe_load(fence.group(1) if fence else text)
    except yaml.YAMLError:
        return []
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [])
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and item.get("value") is not None:
            kind = str(item.get("kind", "user")).strip().lower()
            out.append((str(item["value"]).strip(), kind if kind in KINDS else "user"))
    return out


def ground(candidates: list[tuple[str, str]], texts: list[str]) -> list[Finding]:
    """Keep only plausible values that really appear in clear in the lines."""
    masked = [_masked(t) for t in texts]
    found: dict[str, Finding] = {}
    for value, kind in candidates:
        if not plausible_value(value) or value.lower() in found:
            continue
        rx = re.compile(rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])")
        hits = [(t, m) for t in masked for m in [rx.search(t)] if m]
        if not hits:
            continue  # not in the lines: invented, or already pseudonymised
        keys = {key_before(t, m.start()) for t, m in hits}
        key = keys.pop() if len(keys) == 1 else None
        if key and key.lower() in GENERIC_KEYS:
            key = None
        contexts = Counter(c for t, m in hits if (c := context_regex(t, m.start(), m.end())))
        best = [] if key else [c for c, _ in contexts.most_common(3)]
        found[value.lower()] = Finding(value, kind, len(hits), key, best)
    return list(found.values())


def to_rules(findings: list[Finding], origin: str = "llm") -> list[Rule]:
    """The most general rule each finding justifies: its key, else the literal value."""
    rules: dict[str, Rule] = {}
    for f in findings:
        if f.key:
            r = Rule("key", f.kind, f.key, origin=origin, note=f"seen with {f.value!r}")
        else:
            r = Rule("value", f.kind, f.value, origin=origin, note=f"in {f.lines} line(s)")
            for ctx in f.contexts:  # the words around it may catch unseen names too
                c = Rule("regex", f.kind, ctx, origin=origin, note=f"around {f.value!r}")
                rules.setdefault(c.id, c)
        rules.setdefault(r.id, r)
    return list(rules.values())


def residual_pass(
    llm,
    pz,
    lines: list[str],
    batch: int = 20,
    max_chars: int = 400,
    progress: Callable[[str], None] | None = None,
    cache: dict | None = None,
) -> list[Finding]:
    """Ask the local model for what the current rules still miss in `lines`."""
    say = progress or (lambda _m: None)
    ensure_local(llm.endpoint.url)
    if llm.endpoint.remote:
        raise LocalOnlyError("the residual pass only uses the local model")
    texts = [pz.pseudonymize(ln).text[:max_chars] for ln in lines]
    findings: dict[str, Finding] = {}
    for i in range(0, len(texts), batch):
        chunk = texts[i : i + batch]
        user = "Lines:\n" + "\n".join(f"{n}: {t}" for n, t in enumerate(chunk, 1))
        # originals=set(): these lines are meant to carry clear values, to a local model only
        key = hashlib.sha256(
            f"{llm.endpoint.model}\x00{LEARN_SYSTEM}\x00{user}".encode()
        ).hexdigest()
        text = cache.get(key) if cache is not None else None
        if text is None:
            reply = llm.chat(
                [{"role": "system", "content": LEARN_SYSTEM}, {"role": "user", "content": user}],
                originals=set(),
                json_mode=False,
                temperature=0.1,
            )
            text = reply.text
            if cache is not None:  # lets a long evaluation resume batch by batch
                cache[key] = text
        cands = parse_answer(text)
        kept = ground(cands, chunk)
        say(f"lines {i + 1}-{i + len(chunk)}: model listed {len(cands)}, {len(kept)} grounded")
        for f in kept:
            prev = findings.get(f.value.lower())
            if prev:
                prev.lines += f.lines
                prev.key = prev.key if prev.key == f.key else None
                prev.contexts = list(dict.fromkeys(prev.contexts + f.contexts))[:3]
            else:
                findings[f.value.lower()] = f
    return list(findings.values())


def preview(pz, rule: Rule, lines: list[str], examples: int = 5) -> dict:
    """Effect of one rule on real lines (local display only): lines it changes, the values
    it catches (a key or regex that is too broad shows up here) and before/after examples."""
    single = RuleSet([rule])
    with_rule = pz.with_rules([rule])
    values: Counter = Counter()
    changed, shown = 0, []
    for ln in lines:
        hits = [v for _k, _a, _b, v in single.find(ln)]
        if not hits:
            continue
        values.update(hits)
        before = pz.pseudonymize(ln).text
        after = with_rule.pseudonymize(ln).text
        if before != after:
            changed += 1
            if len(shown) < examples:
                shown.append({"before": before, "after": after})
    return {
        "lines": len(lines),
        "changed": changed,
        "values": values.most_common(20),
        "distinct": len(values),
        "examples": shown,
    }
