"""The core loop (D19, D27, D34, D38): pseudonymised samples -> LLM writes VRL -> sandbox
-> ECS + grounding checks -> feedback -> at most N attempts -> proposal for human review."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field

from privasoc import prompts
from privasoc.ecs import validate
from privasoc.grounding import ungrounded
from privasoc.llm import LLMClient
from privasoc.pseudo import Pseudonymizer
from privasoc.sampling import stratified_sample
from privasoc.sandbox import Sandbox

_JSON = re.compile(r"\{.*\}", re.S)


@dataclass
class Attempt:
    n: int
    status: str
    error_class: str | None
    details: list[str]
    latency_s: float
    vrl: str | None = None


@dataclass
class Outcome:
    parser_id: str
    source: str
    status: str  # proposed | needs_escalation | failed
    reason: str
    provider: str
    model: str
    vrl: str | None
    attempts: list[Attempt] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    templates: list[str] = field(default_factory=list)
    preview: list[dict] = field(default_factory=list)  # parser run on REAL lines (local only)

    def report(self) -> dict:
        return {
            "reason": self.reason,
            "metrics": self.metrics,
            "templates": self.templates,
            "attempts": [a.__dict__ for a in self.attempts],
            "preview": self.preview,
        }


def _parse_answer(text: str) -> dict | None:
    m = _JSON.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def evaluate(sandbox: Sandbox, vrl: str, lines: list[str]) -> tuple[str | None, list[str], dict]:
    """Return (error_class, details, metrics) for a program on lines."""
    res = sandbox.run(vrl, lines)
    if res.compile_error:
        return "compile", [res.compile_error[:1500]], {"compiled": False}
    metrics = {"compiled": True, "lines": len(lines), "parsed": len(res.outputs)}
    if res.runtime_errors:
        details = [f"line {i + 1}: {r.error[:300]}" for i, r in enumerate(res.lines) if r.error]
        return "runtime", details, metrics
    schema, ungr, n_values = [], [], 0
    for i, (r, raw) in enumerate(zip(res.lines, lines, strict=True)):
        for e in validate(r.output):
            schema.append(f"line {i + 1}: {e}")
        bad = ungrounded(r.output, raw)
        n_values += sum(1 for _ in _leaves(r.output))
        ungr += [f"line {i + 1}: `{p}` = {v!r} is not in the line" for p, v in bad]
    metrics["ungrounded_values"] = len(ungr)
    metrics["values"] = n_values
    if schema:
        return "schema", sorted(set(schema)), metrics
    if ungr:
        return "ungrounded", ungr, metrics
    return None, [], metrics


def _leaves(doc, prefix=""):
    from privasoc.ecs import flatten

    return flatten(doc, prefix)


def generate(
    source: str,
    raw_lines: list[str],
    llm: LLMClient,
    pz: Pseudonymizer,
    sandbox: Sandbox,
    k: int = 10,
    max_attempts: int = 5,
    examples: list[dict] | None = None,
) -> Outcome:
    idx, clusters = stratified_sample(raw_lines, k)
    raw_sample = [raw_lines[i] for i in idx]
    pres = [pz.pseudonymize(line) for line in raw_sample]
    sample = [p.text for p in pres]
    originals = set().union(*(p.originals for p in pres)) if pres else set()
    # Templates are computed on pseudonymised lines so they never carry originals.
    _, pclusters = stratified_sample(sample, len(sample))
    templates = [c.template for c in pclusters]

    ep = llm.endpoint
    out = Outcome(
        uuid.uuid4().hex[:8], source, "failed", "", ep.name, ep.model, None, templates=templates
    )
    messages = [
        {"role": "system", "content": prompts.PARSER_SYSTEM},
        {"role": "user", "content": prompts.parser_user(source, sample, templates, examples)},
    ]
    previous_class = None
    total_latency = 0.0
    for n in range(1, max_attempts + 1):
        reply = llm.chat(messages, originals=originals)
        total_latency += reply.latency_s
        answer = _parse_answer(reply.text)
        if answer is None or not isinstance(answer.get("vrl"), str):
            err, details, vrl, status = (
                "json",
                ["answer must be a JSON object with `vrl`"],
                None,
                "?",
            )
        else:
            status = str(answer.get("status", "ok"))
            vrl = answer["vrl"]
            if status in {"cannot_parse", "unsure"}:  # D38a: the model admits its limit
                out.attempts.append(
                    Attempt(n, status, None, [str(answer.get("reason"))], reply.latency_s, vrl)
                )
                out.status, out.reason = "needs_escalation", f"model reported {status}"
                break
            err, details, metrics = evaluate(sandbox, vrl, sample)
            out.metrics = metrics
        out.attempts.append(Attempt(n, status, err, details, reply.latency_s, vrl))
        if err is None:
            out.status, out.reason, out.vrl = "proposed", "all checks passed", vrl
            break
        if err == previous_class and err in {"ungrounded", "runtime", "compile", "schema"}:
            # D38c: stagnation (same failure class repeatedly)
            out.status, out.reason = "needs_escalation", f"stagnation on {err} errors"
            out.vrl = vrl
            break
        previous_class = err
        messages.append({"role": "assistant", "content": reply.text})
        messages.append({"role": "user", "content": prompts.parser_feedback(err, details)})
    else:
        out.status, out.reason = (
            "needs_escalation",
            f"no valid parser after {max_attempts} attempts",
        )
        out.vrl = out.attempts[-1].vrl if out.attempts else None

    out.metrics.update(
        {
            "attempts": len(out.attempts),
            "llm_latency_s": round(total_latency, 2),
            "templates": len(templates),
        }
    )
    if out.status == "proposed":
        # Shape-preservation check: the parser was written on pseudonymised data; it must
        # also work on the real lines. This runs locally and is shown to the reviewer only.
        err, details, m = evaluate(sandbox, out.vrl, raw_sample)
        out.metrics["real_lines_ok"] = err is None
        res = sandbox.run(out.vrl, raw_lines[: min(len(raw_lines), 20)])
        out.metrics["coverage_recent"] = round(len(res.outputs) / max(1, len(res.lines)), 3)
        out.preview = [
            {"raw": r, "ecs": x.output, "error": x.error}
            for r, x in zip(raw_lines[:5], res.lines[:5], strict=False)
        ]
    return out
