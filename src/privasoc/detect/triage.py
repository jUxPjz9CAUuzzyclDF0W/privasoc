"""Structured AI triage of one alert (D53).

The model receives pseudonymised evidence (the rule and up to 20 matched events) and must
answer a fixed JSON structure. Every claim must cite event ids that exist in the evidence,
every ATT&CK id must be well formed, and every pseudonym or address it mentions must come
from the evidence. What fails these checks is kept and flagged, so the analyst sees how far
to trust the answer. The model suggests; the analyst closes the alert.
"""

from __future__ import annotations

import json
import re

from privasoc.detect.sigma import LEVELS

VERDICTS = ("true_positive", "benign", "false_positive", "needs_more_info")
MAX_EVENTS = 20

SYSTEM = """You are a SOC analyst triaging one security alert from a home or small-office
network. The evidence is pseudonymised: user-1a2b3c, host-1a2b3c, d1a2b3c.com and the
addresses are consistent stand-ins for real values. Use only the evidence given.

Answer with JSON only, exactly these keys:
{"verdict": "true_positive" | "benign" | "false_positive" | "needs_more_info",
 "severity": "informational" | "low" | "medium" | "high" | "critical",
 "confidence": number between 0 and 1,
 "summary": "at most three sentences",
 "reasons": [{"claim": "one fact from the evidence", "events": [event ids]}],
 "next_steps": ["short concrete action", ...],
 "attack": ["MITRE ATT&CK technique id such as T1110", ...]}

Every claim cites the ids of the events that show it. Say needs_more_info rather than
guess."""

_ATTACK = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ENTITY = re.compile(
    r"\b(?:user|host)-[0-9a-f]{6}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b|\bd[0-9a-f]{6}(?:\.[\w-]+)+"
)


def _compact(ecs: dict) -> dict:
    doc = json.loads(json.dumps(ecs))
    ev = doc.get("event")
    if isinstance(ev, dict) and isinstance(ev.get("original"), str):
        ev["original"] = ev["original"][:400]
    return doc


def build_evidence(alert: dict, rule, events: list[dict], pz) -> tuple[str, set[str], list[int]]:
    """(pseudonymised prompt text, originals for the leak guard, event ids shown)."""
    from privasoc.pseudo import Pseudonymizer

    events = events[:MAX_EVENTS]
    # The sender's name is chosen by privasoc (`syslog:<ip>`, a file name...), not detected:
    # it gets a host pseudonym of its own. Events are pseudonymised field by field (D53).
    sender = pz.vault.token_for("host", alert["source"])
    mapping, originals = {alert["source"]: sender}, {alert["source"]}
    docs = [pz.pseudonymize_doc(_compact(e["ecs"])) for e in events]
    for r in docs:
        mapping.update(r.mapping)
        originals |= r.originals
    lines = [f"sender: {sender}"] + [
        f"event {e['id']} (received {e['received_at'][:19]}): "
        + Pseudonymizer.propagate(r.text, mapping)
        for e, r in zip(events, docs, strict=True)
    ]
    rule_part = [
        f"alert: {alert['title']} (level {alert['level']}, {alert['count']} occurrence(s), "
        f"first {alert['first_seen'][:19]}, last {alert['last_seen'][:19]})",
    ]
    if rule is not None:
        rule_part += [
            f"rule: {rule.title}",
            f"rule description: {rule.description or '-'}",
            f"known false positives: {'; '.join(rule.falsepositives) or '-'}",
            f"rule ATT&CK tags: {', '.join(rule.attack) or '-'}",
        ]
    if alert.get("detail"):
        rule_part.append("alert detail: " + json.dumps(alert["detail"], default=str)[:600])
    detail_line = pz.pseudonymize(rule_part[-1]) if alert.get("detail") else None
    if detail_line:
        originals |= detail_line.originals
        rule_part[-1] = Pseudonymizer.propagate(detail_line.text, mapping)
    prompt = "\n".join(rule_part + [lines[0], "evidence:"] + lines[1:])
    prompt = Pseudonymizer.propagate(prompt, {alert["source"]: sender})
    return prompt, originals, [e["id"] for e in events]


def _parse(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def validate(answer: dict | None, event_ids: list[int], rule_attack: list[str], evidence: str):
    """Normalised triage plus the list of problems found (D53)."""
    problems: list[str] = []
    if answer is None:
        return None, ["the answer is not valid JSON"]
    ids = set(event_ids)
    verdict = str(answer.get("verdict", "")).lower()
    if verdict not in VERDICTS:
        problems.append(f"unknown verdict {verdict!r}")
        verdict = "needs_more_info"
    severity = str(answer.get("severity", "")).lower()
    if severity not in LEVELS:
        problems.append(f"unknown severity {severity!r}")
        severity = "medium"
    try:
        confidence = min(1.0, max(0.0, float(answer.get("confidence", 0))))
    except (TypeError, ValueError):
        problems.append("confidence is not a number")
        confidence = 0.0
    reasons = []
    for r in answer.get("reasons") or []:
        if not isinstance(r, dict):
            continue
        cited = []
        for x in r.get("events") or []:
            try:
                cited.append(int(str(x).removeprefix("event ").strip()))
            except ValueError:
                pass
        bad = [x for x in cited if x not in ids]
        ok = [x for x in cited if x in ids]
        flag = None
        if bad:
            flag = f"cites events not in the evidence: {bad}"
        elif not ok:
            flag = "cites no event"
        if flag:
            problems.append(f"claim {str(r.get('claim'))[:60]!r} {flag}")
        reasons.append({"claim": str(r.get("claim", "")), "events": ok, "flag": flag})
    attack = []
    for t in answer.get("attack") or []:
        t = str(t).strip().upper()
        if not _ATTACK.match(t):
            problems.append(f"malformed ATT&CK id {t!r}")
            continue
        base = t.split(".")[0]
        tagged = t in rule_attack or base in {a.split(".")[0] for a in rule_attack}
        attack.append({"id": t, "in_rule_tags": tagged})
    text = " ".join([str(answer.get("summary", ""))] + [r["claim"] for r in reasons])
    invented = sorted({e for e in _ENTITY.findall(text) if e not in evidence})
    if invented:
        problems.append(f"mentions values absent from the evidence: {invented}")
    return {
        "verdict": verdict,
        "severity": severity,
        "confidence": round(confidence, 2),
        "summary": str(answer.get("summary", ""))[:1500],
        "reasons": reasons[:12],
        "next_steps": [str(x)[:300] for x in (answer.get("next_steps") or [])][:8],
        "attack": attack[:8],
    }, problems


def triage(alert: dict, rule, events: list[dict], llm, pz) -> dict:
    """Ask the model, validate, return the stored record (pseudonymised text)."""
    from privasoc.generator import _guarded

    prompt, originals, ids = build_evidence(alert, rule, events, pz)
    reply = llm.chat(
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        originals=_guarded(originals),
        json_mode=True,
        temperature=0.1,
    )
    result, problems = validate(_parse(reply.text), ids, rule.attack if rule else [], prompt)
    return {
        "result": result,
        "problems": problems,
        "provider": llm.endpoint.name,
        "model": llm.endpoint.model,
        "events": len(ids),
        "pseudonymised_values": len(originals),
        "latency_s": round(reply.latency_s, 1),
    }
