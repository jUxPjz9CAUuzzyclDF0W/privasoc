"""Evaluation harness (D14, D19, D20): how well, how fast and how privately does a model
write parsers for formats it has never seen?

For every fixture x configuration (mode, provider, pseudonymisation) x run:
- the first half of the lines is the only thing the generator sees (sampling, held-out
  coverage check); the second half is never shown and is used for scoring;
- the proposed parser runs in the sandbox on the held-out half and is scored field by field
  against Elastic's expected ECS output.

Results are appended to a JSONL file (one line per run), so an interrupted evaluation
resumes where it stopped.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from privasoc.ecs import flatten
from privasoc.fixtures import Fixture
from privasoc.pseudo import PseudoResult

# Fields a parser can extract from the line itself. Vendor namespaces, enrichment (geo,
# related.*), categorisation choices and timestamps (timezone conventions differ) are out.
SCORED = (
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "source.address",
    "destination.address",
    "user.name",
    "host.hostname",
    "process.name",
    "process.pid",
    "network.transport",
    "dns.question.name",
    "url.original",
    "url.path",
    "http.request.method",
    "http.response.status_code",
    "http.version",
    "user_agent.original",
    "source.nat.ip",
    "destination.nat.ip",
)
# Values the pseudonymiser must hide, used for the leakage evaluation.
SENSITIVE = (
    "source.ip",
    "destination.ip",
    "source.address",
    "destination.address",
    "client.ip",
    "server.ip",
    "host.hostname",
    "host.name",
    "user.name",
    "source.user.name",
    "destination.user.name",
    "dns.question.name",
    "url.domain",
    "source.domain",
    "destination.domain",
    "source.nat.ip",
    "destination.nat.ip",
    "observer.name",
)


class IdentityPseudonymizer:
    """`--pseudo off`: the ablation that measures what pseudonymisation costs in quality.
    Only ever used with a local model (enforced by `generate`)."""

    identity = True

    def pseudonymize(self, text: str) -> PseudoResult:
        return PseudoResult(text=text)


def _norm(v) -> str:
    return str(v).strip().lower()


def _values(doc: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for path, value in flatten(doc):
        if path in SCORED:
            vals = value if isinstance(value, list) else [value]
            out[path] = {_norm(v) for v in vals if v is not None and v != ""}
    return {k: v for k, v in out.items() if v}


def score(predicted: list[dict | None], expected: list[dict]) -> dict:
    """Micro-averaged field precision/recall/F1 over SCORED fields."""
    tp = fp = fn = 0
    for pred, exp in zip(predicted, expected, strict=True):
        e = _values(exp)
        p = _values(pred) if pred else {}
        for f in set(e) | set(p):
            if f in e and f in p:
                if p[f] & e[f]:
                    tp += 1
                else:
                    fp += 1
                    fn += 1
            elif f in e:
                fn += 1
            else:
                fp += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


@dataclass
class RunResult:
    fixture: str
    mode: str
    provider: str
    model: str
    pseudo: bool
    run: int
    status: str
    reason: str
    attempts: int
    llm_latency_s: float
    wall_s: float
    heldout_lines: int
    heldout_parsed: float  # share of held-out lines the parser handled
    precision: float
    recall: float
    f1: float
    ungrounded_values: int
    auto_repairs: int
    error_classes: list[str]

    def key(self) -> tuple:
        return (self.fixture, self.mode, self.provider, self.model, self.pseudo, self.run)


def split(fx: Fixture) -> tuple[list[str], list[str], list[dict]]:
    half = max(1, len(fx.lines) // 2)
    return fx.lines[:half], fx.lines[half:], fx.expected[half:]


def run_one(
    fx: Fixture,
    run: int,
    llm,
    pz,
    sandbox,
    mode: str,
    k: int,
    max_attempts: int,
    min_coverage: float,
) -> RunResult:
    from privasoc.generator import generate

    train, test, expected = split(fx)
    t0 = time.monotonic()
    out = generate(
        fx.name,
        train,
        llm,
        pz,
        sandbox,
        k=k,
        max_attempts=max_attempts,
        mode=mode,
        min_coverage=min_coverage,
    )
    wall = time.monotonic() - t0
    parsed, metrics = 0.0, {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    if out.status == "proposed" and out.vrl and test:
        res = sandbox.run(out.vrl, test)
        preds = [r.output for r in res.lines]
        parsed = sum(p is not None for p in preds) / len(test)
        metrics = score(preds, expected)
    m = out.metrics
    return RunResult(
        fx.name,
        mode,
        llm.endpoint.name,
        llm.endpoint.model,
        not getattr(pz, "identity", False),
        run,
        out.status,
        out.reason,
        len(out.attempts),
        float(m.get("llm_latency_s", 0.0)),
        round(wall, 2),
        len(test),
        round(parsed, 3),
        metrics["precision"],
        metrics["recall"],
        metrics["f1"],
        int(m.get("ungrounded_values", 0) or 0),
        int(m.get("auto_repairs", 0) or 0),
        [a.error_class or "ok" for a in out.attempts],
    )


def load_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def append(path: Path, result: RunResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(result)) + "\n")


# ---------------------------------------------------------------- leakage (no LLM needed)


def _sensitive_values(doc: dict) -> list[tuple[str, str]]:
    out = []
    for path, value in flatten(doc):
        if path not in SENSITIVE:
            continue
        for v in value if isinstance(value, list) else [value]:
            s = str(v)
            if not s or s.lower() in {"-", "localhost", "unknown", "none"}:
                continue
            try:  # loopback/unspecified addresses are deliberately left as is
                ip = ipaddress.ip_address(s)
                if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                    continue
            except ValueError:
                pass
            out.append((path, s))
    return out


def leakage(fixtures: list[Fixture], pz) -> dict:
    """Share of known-sensitive values (from Elastic's expected output) that survive
    pseudonymisation of the raw line, per field. Measures the detectors, not a model."""
    per_field: dict[str, list[int]] = {}
    examples: dict[str, list[str]] = {}
    for fx in fixtures:
        for line, doc in zip(fx.lines, fx.expected, strict=True):
            text = pz.pseudonymize(line).text
            for path, value in _sensitive_values(doc):
                if value not in line:
                    continue  # normalised by the pipeline; not literally in the line
                leaked = bool(re.search(rf"(?<![\w.-]){re.escape(value)}(?![\w-])", text))
                hit = per_field.setdefault(path, [0, 0])
                hit[0] += leaked
                hit[1] += 1
                if leaked and len(examples.setdefault(path, [])) < 3:
                    examples[path].append(f"{fx.name}: {value}")
    total_leaked = sum(v[0] for v in per_field.values())
    total = sum(v[1] for v in per_field.values())
    return {
        "values": total,
        "leaked": total_leaked,
        "leak_rate": round(total_leaked / total, 4) if total else 0.0,
        "per_field": {
            k: {"leaked": v[0], "total": v[1], "rate": round(v[0] / v[1], 3)}
            for k, v in sorted(per_field.items())
        },
        "examples": examples,
    }
