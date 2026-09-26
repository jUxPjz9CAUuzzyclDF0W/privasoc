"""The core loop (D19, D27, D34, D38): pseudonymised samples -> LLM writes VRL -> sandbox
-> ECS + grounding checks -> feedback -> at most N attempts -> proposal for human review."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field

import httpx

from privasoc import prompts
from privasoc.ecs import validate
from privasoc.grounding import ungrounded
from privasoc.llm import LeakError, LLMClient
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
    spec: str | None = None  # structured mode: the model's YAML, compiled into `vrl`


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
    spec: str | None = None  # structured mode: the spec the proposed VRL was compiled from

    def report(self) -> dict:
        return {
            "reason": self.reason,
            "metrics": self.metrics,
            "templates": self.templates,
            "attempts": [a.__dict__ for a in self.attempts],
            "preview": self.preview,
            "spec": self.spec,
        }


_STATUS = re.compile(r"^\s*STATUS\s*:\s*(\w+)", re.I | re.M)
_REASON = re.compile(r"^\s*REASON\s*:\s*(.+)$", re.I | re.M)
_FENCE = re.compile(
    r"```[ \t]*(?:vrl|yaml|yml|coffee|ruby|rust|text)?[ \t]*\n(.*?)```", re.S | re.I
)


def _parse_answer(text: str) -> tuple[dict | None, str]:
    """Return (answer, problem). Preferred format: STATUS/REASON lines + a ```vrl block.

    Code is never requested inside JSON: small models break JSON string escaping on
    regexes (\\d, \\S...). JSON is still accepted for models that insist on it.
    """
    status = _STATUS.search(text)
    fence = _FENCE.search(text)
    if status or fence:
        st = status.group(1).lower() if status else "ok"
        reason = _REASON.search(text)
        if st == "ok" and not fence:
            return None, "STATUS is ok but there is no fenced code block"
        return {
            "status": st,
            "reason": reason.group(1).strip() if reason else "",
            "vrl": fence.group(1).strip() if fence else "",
        }, ""
    m = _JSON.search(text)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict) and isinstance(obj.get("vrl"), str):
                return obj, ""
        except json.JSONDecodeError as exc:
            return None, f"invalid JSON ({exc.msg}); use the STATUS / REASON / ```vrl format"
    return None, "answer must contain STATUS, REASON and a ```vrl code block"


def _compile_spec(
    spec_text: str, sample: list[str], structure=None
) -> tuple[str | None, str | None, list[str], list[int]]:
    """Structured mode: repair + validate the model's spec, compile it to VRL.

    Returns (vrl, error_class, details, covered line indices). A spec that loads but misses
    some sample lines is still compiled, so it can be kept as a partial candidate."""
    from privasoc import structured

    try:
        spec = structured.load(spec_text, sample, structure)
    except structured.SpecError as exc:
        return None, "spec", exc.problems, []
    unmatched = structured.check_lines(spec, sample)
    vrl = structured.compile_vrl(spec)
    missed = {int(m.split()[1]) - 1 for m in unmatched}
    covered = [i for i in range(len(sample)) if i not in missed]
    if unmatched:
        return vrl, "spec", unmatched + spec.repairs, covered
    return vrl, None, spec.repairs, covered


_VOCAB: set[str] | None = None


def _guarded(originals: set[str]) -> set[str]:
    """Originals the leak guard must look for. Values that are also words of our own fixed
    texts (prompts, ECS enumerations: a user called `admin` vs the event.type `admin`) are
    left out: in data they are already replaced everywhere by propagation, and in our own
    texts they are not personal data. Without this, feedback listing ECS values was blocked."""
    global _VOCAB
    if _VOCAB is None:
        from privasoc.ecs import ALLOWED

        text = (
            prompts.PARSER_SYSTEM
            + prompts.STRUCTURED_SYSTEM
            + " ".join(" ".join(v) for v in ALLOWED.values())
            + " ".join(prompts.VRL_HINTS.values())
        )
        words = {w.lower() for w in re.findall(r"[A-Za-z][\w.-]*", text)}
        # also every part of dotted names: `host.hostname` contains the word `hostname`
        _VOCAB = words | {p for w in words for p in re.split(r"[._-]", w) if p}
    return {o for o in originals if o.lower() not in _VOCAB}


def _real_coverage(spec_text, sample, raw_lines, pz, originals, metrics, repairs, structure=None):
    """Held-out check on up to 500 REAL lines of the source (local dry run). The sample can
    miss a shape (e.g. `cached x is NODATA-IPv6`); unmatched lines are shown to the model,
    pseudonymised first and added to the leak check."""
    from privasoc import structured

    spec = structured.load(spec_text, sample, structure)
    pool = raw_lines[:500]
    missed = [ln for ln in pool if not structured.matches(spec, ln)]
    metrics["line_coverage"] = round(1 - len(missed) / max(1, len(pool)), 3)
    if not missed:
        return None, repairs
    idx, _ = stratified_sample(missed, 5)
    shown = [pz.pseudonymize(missed[i]) for i in idx]
    mapping: dict[str, str] = {}
    for p in shown:
        originals.update(p.originals)
        mapping.update(getattr(p, "mapping", {}) or {})
    for p in shown:
        p.text = Pseudonymizer.propagate(p.text, mapping)
    details = [
        f"line of the same source matching no shape ({len(missed)} such lines): `{p.text}`"
        for p in shown
    ]
    return "coverage", details + repairs


def _line_coverage(spec_text: str, sample: list[str], lines: list[str], structure=None) -> float:
    from privasoc import structured

    spec = structured.load(spec_text, sample, structure)
    return 1 - len(structured.check_lines(spec, lines)) / max(1, len(lines))


def _signature(err: str | None, details: list[str]) -> tuple:
    """D38c stagnation = the *same* failure twice in a row: same class and same error codes
    (compile) or same offending fields. A different error is progress, not stagnation."""
    text = " ".join(details)
    codes = tuple(sorted(set(re.findall(r"\bE\d{3}\b", text))))
    fields = tuple(sorted(set(re.findall(r"`([\w@.]+)`", text))))
    return (err, codes or fields or (re.sub(r"\d+", "#", details[0][:80]) if details else ""))


def evaluate(sandbox: Sandbox, vrl: str, lines: list[str]) -> tuple[str | None, list[str], dict]:
    """Return (error_class, details, metrics) for a program on lines."""
    res = sandbox.run(vrl, lines)
    if res.compile_error:
        return "compile", [res.compile_error[:1500]], {"compiled": False}
    metrics = {"compiled": True, "lines": len(lines), "parsed": len(res.outputs)}
    if res.runtime_errors:
        # Show the failing line itself: the model must see what its regex did not match.
        details = [
            f"line {i + 1} `{lines[i][:200]}`: {r.error[:200]}"
            for i, r in enumerate(res.lines)
            if r.error
        ]
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
    progress=None,
    mode: str = "structured",
    min_coverage: float = 0.8,
) -> Outcome:
    if getattr(pz, "identity", False) and llm.endpoint.remote:
        # D0b: the no-pseudonymisation ablation exists for local models only.
        raise ValueError("pseudonymisation cannot be disabled for a remote provider")
    idx, clusters = stratified_sample(raw_lines, k)
    raw_sample = [raw_lines[i] for i in idx]
    pres = [pz.pseudonymize(line) for line in raw_sample]
    mapping: dict[str, str] = {}
    for p in pres:
        mapping.update(getattr(p, "mapping", {}) or {})
    sample = [Pseudonymizer.propagate(p.text, mapping) if mapping else p.text for p in pres]
    originals = set().union(*(p.originals for p in pres)) if pres else set()
    # Templates are computed on pseudonymised lines so they never carry originals.
    _, pclusters = stratified_sample(sample, len(sample))
    templates = [c.template for c in pclusters]
    # I23: deterministic structure detection on the pseudonymised sample.
    from privasoc import analyze

    structure = analyze.detect(sample)

    ep = llm.endpoint
    out = Outcome(
        uuid.uuid4().hex[:8], source, "failed", "", ep.name, ep.model, None, templates=templates
    )
    messages = [
        {"role": "system", "content": prompts.system_for(mode)},
        {
            "role": "user",
            "content": prompts.parser_user(
                source,
                sample,
                templates,
                examples,
                mode,
                structure.describe() if mode == "structured" else "",
            ),
        },
    ]
    previous_class = None
    total_latency = 0.0
    best = None  # structured mode: best partial-coverage candidate
    say = progress or (lambda _msg: None)
    base = messages[:]
    say(f"sampled {len(sample)} lines covering {len(templates)} templates")
    for n in range(1, max_attempts + 1):
        say(f"attempt {n}/{max_attempts}: waiting for {ep.name} model {ep.model}...")
        try:
            # Raise the temperature on retries so a small model does not resend the same answer.
            temperature = min(0.2 + 0.2 * (n - 1), 0.8)
            reply = llm.chat(
                messages,
                originals=_guarded(originals),
                json_mode=False,
                temperature=temperature,
            )
        except LeakError as exc:  # never crash, never send
            out.attempts.append(Attempt(n, "error", "leak_blocked", [str(exc)], 0.0))
            out.status, out.reason = "failed", "outgoing prompt blocked by the leak guard"
            break
        except httpx.TimeoutException:
            say(f"attempt {n}: no answer within {llm.timeout:.0f}s")
            out.attempts.append(Attempt(n, "timeout", "timeout", [], llm.timeout))
            out.status = "needs_escalation"
            out.reason = f"local model too slow (> {llm.timeout:.0f}s per answer)"
            break
        except httpx.HTTPError as exc:
            out.attempts.append(Attempt(n, "error", "http", [str(exc)[:300]], 0.0))
            out.status, out.reason = "failed", f"LLM server error: {str(exc)[:200]}"
            break
        total_latency += reply.latency_s
        if getattr(reply, "prompt_truncated", False):
            say(f"attempt {n}: warning: prompt filled the model's context window")
        answer, problem = _parse_answer(reply.text)
        if reply.finish_reason == "length":
            problem = "your answer was cut off (too long): write a shorter program, no prose"
        if answer is None or problem:
            err, details, vrl, status = "format", [problem], None, "?"
        else:
            status = str(answer.get("status", "ok"))
            vrl = answer["vrl"]
            if status in {"cannot_parse", "unsure"}:  # D38a: the model admits its limit
                out.attempts.append(
                    Attempt(n, status, None, [str(answer.get("reason"))], reply.latency_s, vrl)
                )
                out.status, out.reason = "needs_escalation", f"model reported {status}"
                break
            spec_text = None
            if mode == "structured":
                spec_text = vrl
                vrl, err, details, covered = _compile_spec(spec_text, sample, structure)
                if err == "spec" and vrl and covered:
                    # Partial candidate: must be fully valid on the lines it covers.
                    sub = [sample[i] for i in covered]
                    perr, _, pm = evaluate(sandbox, vrl, sub)
                    # Coverage is measured on up to 500 REAL lines (local Python dry-run, never
                    # sent anywhere): the stratified sample over-represents rare shapes.
                    cov = _line_coverage(spec_text, sample, raw_lines[:500], structure)
                    if perr is None and (best is None or cov > best["coverage"]):
                        best = {
                            "coverage": cov,
                            "vrl": vrl,
                            "spec": spec_text,
                            "n": n,
                            "metrics": pm,
                            "covered": covered,
                        }
            repairs = details if mode == "structured" and err is None else []
            if mode != "structured" or err is None:
                err, details, metrics = evaluate(sandbox, vrl, sample)
                details = details + repairs  # repairs are reported, never silent
                metrics["auto_repairs"] = len(repairs)
                out.metrics = metrics
                if mode == "structured" and err is None:
                    err, details = _real_coverage(
                        spec_text, sample, raw_lines, pz, originals, metrics, repairs, structure
                    )
                    if err and (best is None or metrics["line_coverage"] > best["coverage"]):
                        best = {
                            "coverage": metrics["line_coverage"],
                            "vrl": vrl,
                            "spec": spec_text,
                            "n": n,
                            "metrics": dict(metrics),
                            "covered": list(range(len(sample))),
                        }
        out.attempts.append(Attempt(n, status, err, details, reply.latency_s, vrl))
        if mode == "structured" and answer is not None:
            out.attempts[-1].spec = spec_text
        say(
            f"attempt {n}: {err or 'ok'} after {reply.latency_s:.0f}s"
            + (f" ({details[0][:120]})" if details else "")
        )
        if err is None:
            out.status, out.reason, out.vrl = "proposed", "all checks passed", vrl
            out.spec = out.attempts[-1].spec
            break
        signature = _signature(err, details)
        if signature == previous_class and err in {
            "ungrounded",
            "runtime",
            "compile",
            "schema",
            "spec",
            "coverage",
        }:
            # D38c: stagnation (same failure class repeatedly)
            out.status, out.reason = "needs_escalation", f"stagnation on {err} errors"
            out.vrl = vrl
            break
        previous_class = signature
        # Keep only the latest attempt in context: small local models have small windows.
        messages = [
            *base,
            {"role": "assistant", "content": reply.text},
            {
                "role": "user",
                "content": prompts.parser_feedback(
                    err, details, None if mode == "structured" else vrl
                ),
            },
        ]
    else:
        out.status, out.reason = (
            "needs_escalation",
            f"no valid parser after {max_attempts} attempts",
        )
        out.vrl = out.attempts[-1].vrl if out.attempts else None

    if out.status != "proposed" and best and best["coverage"] >= min_coverage:
        # D44/I16: a parser covering most line shapes is proposed; the lines it does not
        # match keep going to the quarantine, and the reviewer sees the coverage.
        out.status, out.vrl, out.spec = "proposed", best["vrl"], best["spec"]
        out.reason = (
            f"partial: covers {best['coverage']:.0%} of the source's lines "
            f"(attempt {best['n']}); the rest stays in quarantine"
        )
        out.metrics = {**best["metrics"], "line_coverage": round(best["coverage"], 3)}
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
        partial = out.reason.startswith("partial")
        check = [raw_sample[i] for i in best["covered"]] if partial else raw_sample
        err, details, m = evaluate(sandbox, out.vrl, check)
        out.metrics["real_lines_ok"] = err is None
        res = sandbox.run(out.vrl, raw_lines[: min(len(raw_lines), 20)])
        out.metrics["coverage_recent"] = round(len(res.outputs) / max(1, len(res.lines)), 3)
        out.preview = [
            {"raw": r, "ecs": x.output, "error": x.error}
            for r, x in zip(raw_lines[:5], res.lines[:5], strict=False)
        ]
    return out
