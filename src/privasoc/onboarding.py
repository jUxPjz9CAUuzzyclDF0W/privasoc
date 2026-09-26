"""Source onboarding (D45): approve a host, use a known format when there is one, otherwise
leave the lines in quarantine for the LLM path; deploy approved parsers and backfill."""

from __future__ import annotations

import hashlib

from privasoc import builtins, vectorgen


def deploy(store, settings) -> str | None:
    """Regenerate and validate Vector's pipeline; returns the error text or None."""
    vectorgen.write(store.parsers("approved"), settings.vector_dir)
    return vectorgen.validate(settings.vector_bin, settings.vector_dir)


def backfill(store, sandbox, source: str, parser_id: str, vrl: str, limit: int = 5000) -> dict:
    """Re-process the quarantined lines of `source` with a newly approved parser (step 6)."""
    rows = store.quarantine_rows(source, limit)
    if not rows:
        return {"backfilled": 0, "still_quarantined": 0}
    res = sandbox.run(vrl, [raw for _, _, raw in rows])
    ok = []
    for (rid, received_at, raw), line in zip(rows, res.lines, strict=True):
        if line.output is not None:
            ecs = dict(line.output)
            ecs.setdefault("event", {})
            if isinstance(ecs["event"], dict):
                ecs["event"]["original"] = raw
            ok.append((rid, received_at, ecs))
    store.backfill(source, parser_id, ok)
    return {"backfilled": len(ok), "still_quarantined": len(rows) - len(ok)}


def approve_host(store, settings, sandbox, source: str) -> dict:
    """Human approved the sender: detect a known format and ingest, or report 'unknown'."""
    store.set_host(source, "approved")
    sample = [raw for _, _, raw in store.quarantine_rows(source, 200)]
    found = builtins.detect(sandbox, sample)
    if not found:
        store.set_host(source, fmt="unknown")
        return {"source": source, "format": "unknown", "quarantined": len(sample)}
    b, rate = found
    pid = "b" + hashlib.sha256(f"{source}:{b.name}".encode()).hexdigest()[:7]
    store.save_parser(
        pid,
        source,
        "proposed",
        "builtin",
        b.name,
        b.vrl,
        {
            "reason": f"known format: Vector built-in {b.name}",
            "metrics": {"sample_coverage": round(rate, 3)},
        },
    )
    store.set_parser_status(pid, "approved")  # the host approval covers a built-in parser
    error = deploy(store, settings)
    if error:
        store.set_parser_status(pid, "rejected")
        deploy(store, settings)
        store.set_host(source, fmt="unknown")
        return {"source": source, "format": "unknown", "error": error[:500]}
    store.set_host(source, fmt=f"builtin:{b.name}")
    return {
        "source": source,
        "format": f"builtin:{b.name}",
        "coverage": round(rate, 3),
        **backfill(store, sandbox, source, pid, b.vrl),
    }


def after_parser_approval(store, sandbox, parser: dict) -> dict:
    store.set_host(parser["source"], fmt=f"parser:{parser['id']}")
    return backfill(store, sandbox, parser["source"], parser["id"], parser["vrl"])
