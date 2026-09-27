"""privasoc command line."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer
from cryptography.fernet import Fernet

from privasoc import service
from privasoc.config import Settings, get_settings
from privasoc.pseudo import Pseudonymizer
from privasoc.store import Record, Store

app = typer.Typer(help="Privacy-first, local-LLM SOC analyst.", no_args_is_help=True)

SECRET_GENERATORS = {
    "PRIVASOC_API_TOKEN": lambda: secrets.token_urlsafe(32),
    "PRIVASOC_HMAC_KEY": lambda: secrets.token_urlsafe(32),
    "PRIVASOC_VAULT_KEY": lambda: Fernet.generate_key().decode(),
}


def _pseudonymizer() -> Pseudonymizer:
    return service.pseudonymizer(get_settings())


@app.command()
def init(env_file: Path = Path(".env"), example: Path = Path(".env.example")) -> None:
    """Create .env with freshly generated secrets (existing values are kept, nothing printed)."""
    lines = (env_file if env_file.exists() else example).read_text().splitlines()
    present = {ln.partition("=")[0] for ln in lines if "=" in ln}
    added = []
    if env_file.exists() and example.exists():  # bring in settings added since
        for ln in example.read_text().splitlines():
            key = ln.partition("=")[0]
            if "=" in ln and not ln.startswith("#") and key not in present:
                lines.append(ln)
                added.append(key)
    out, generated = [], []
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key in SECRET_GENERATORS and not value.strip():
            line = f"{key}={SECRET_GENERATORS[key]()}"
            generated.append(key)
        out.append(line)
    env_file.write_text("\n".join(out) + "\n")
    env_file.chmod(0o600)
    typer.echo(f"{env_file}: generated {', '.join(generated) or 'nothing (already set)'}")
    if added:
        typer.echo(f"added new settings with defaults: {', '.join(added)}")
    typer.echo("Keep PRIVASOC_VAULT_KEY safe: without it the vault cannot be re-identified.")


@app.command()
def serve() -> None:
    """Run the API (ingestion endpoint for Vector)."""
    import uvicorn

    from privasoc import vectorgen
    from privasoc.api import create_app

    s = get_settings()
    vectorgen.write(Store(s.db_path).parsers("approved"), s.vector_dir)
    uvicorn.run(create_app(s), host=s.host, port=s.port)


@app.command("import")
def import_file(
    path: Path,
    source: Annotated[str, typer.Option(help="Source name, e.g. pihole or checkpoint")],
) -> None:
    """Import a log file line by line (offline alternative to Vector)."""
    s = get_settings()
    store = Store(s.db_path)
    new_host = store.host(source) is None
    with path.open(encoding="utf-8", errors="replace") as fh:
        counts = store.ingest(
            (Record(source=source, raw=ln.rstrip("\r\n")) for ln in fh if ln.strip()),
            auto_approve=True,  # importing a file is itself the admin's explicit decision
        )
    typer.echo(f"{counts['events']} events, {counts['unparsed']} quarantined")
    if new_host:
        _approve_flow(store, s, source)


def _approve_flow(store: Store, s: Settings, source: str) -> None:
    r = _do(service.approve_host, store, s, source)
    if r["format"] == "unknown":
        typer.echo(
            f"{source}: format not known by Vector; {r.get('quarantined', 0)} lines in "
            f"quarantine. Next: privasoc propose --source {source}"
        )
    else:
        typer.echo(
            f"{source}: known format {r['format']} (coverage {r['coverage']:.0%}); "
            f"{r['backfilled']} lines ingested, {r['still_quarantined']} left in quarantine"
        )


def _do(action, *args, **kwargs):
    """Run a shared action; its refusals become a clean CLI error."""
    try:
        return action(*args, **kwargs)
    except service.ActionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


hosts_app = typer.Typer(help="Senders: approval (D45) and health (D47).", no_args_is_help=True)
app.add_typer(hosts_app, name="hosts")


@hosts_app.command("list")
def hosts_list(status: str | None = None) -> None:
    """Every sender with its status, format and health."""
    store = Store(get_settings().db_path)
    rows = store.hosts(status)
    if not rows:
        typer.echo("No host yet: point a device at privasoc (syslog 5514) or import a file.")
    for h in rows:
        line = f"{h['source']:28} {h['status']:9} {h['format'] or '-':24} lines={h['lines']}"
        if h["status"] == "approved":
            hs = service.host_health(store, h)
            line += f"  health={hs['status']}" + (
                f" ({'; '.join(hs['reasons'])})" if hs["reasons"] else ""
            )
        typer.echo(line)


@hosts_app.command("approve")
def hosts_approve(source: str) -> None:
    """Approve a pending sender: known formats are ingested, others go to quarantine."""
    s = get_settings()
    _approve_flow(Store(s.db_path), s, source)


@hosts_app.command("reject")
def hosts_reject(source: str) -> None:
    """Reject a sender: its held lines are deleted and future lines dropped."""
    _do(service.reject_host, Store(get_settings().db_path), source)
    typer.echo(f"{source} rejected")


@hosts_app.command("health")
def hosts_health(source: str) -> None:
    """Current health of a host, its metrics and the history of status changes."""
    import json

    store = Store(get_settings().db_path)
    h = store.host(source)
    if not h:
        raise typer.BadParameter(f"unknown host {source!r}")
    typer.echo(json.dumps(service.host_health(store, h), indent=2))
    for at, st, reasons in store.health_history(source, 10):
        typer.echo(f"  {at}  {st:8} {'; '.join(reasons)}")


@hosts_app.command("thresholds")
def hosts_thresholds(
    source: str,
    values: Annotated[
        list[str],
        typer.Argument(help="key=value pairs, e.g. silence_min_minutes=30 parse_warning=0.8"),
    ],
) -> None:
    """Override health thresholds for one host (key= removes an override)."""
    pairs = dict(kv.partition("=")[::2] for kv in values)
    th = _do(service.set_thresholds, Store(get_settings().db_path), source, pairs)
    typer.echo(f"{source}: {th}")


@app.command()
def quarantine(
    source: Annotated[str | None, typer.Option(help="Show a sample for this source")] = None,
    sample: int = 10,
    raw: Annotated[bool, typer.Option(help="Show raw lines instead of pseudonymised")] = False,
) -> None:
    """Lines no approved parser recognises, per source."""
    store = Store(get_settings().db_path)
    if source is None:
        rows = store.quarantine_stats()
        if not rows:
            typer.echo("Quarantine is empty.")
        for src, count, first, last in rows:
            typer.echo(f"{src:30} {count:>8} lines   {first} -> {last}")
        return
    lines = store.quarantine_sample(source, sample)
    p = None if raw else _pseudonymizer()
    for ln in lines:
        typer.echo(ln if p is None else p.pseudonymize(ln).text)


@app.command()
def pseudo(
    text: Annotated[str | None, typer.Argument(help="Text to process (default: stdin)")] = None,
    reverse: Annotated[bool, typer.Option("--reidentify", help="Re-identify instead")] = False,
) -> None:
    """Pseudonymise (or re-identify) text with the local vault."""
    p = _pseudonymizer()
    data = text if text is not None else sys.stdin.read()
    for line in data.splitlines():
        if reverse:
            typer.echo(p.reidentify(line))
        else:
            r = p.pseudonymize(line)
            leaks = p.leaks(r.text, r.originals)
            if leaks:
                raise typer.Exit(code=2)  # never print a line that still leaks
            typer.echo(r.text)


parsers_app = typer.Typer(help="Review AI-generated parsers (D23).", no_args_is_help=True)
app.add_typer(parsers_app, name="parsers")


def _endpoint(s: Settings, provider: str):
    return service._endpoint(s, provider)


@app.command()
def propose(
    source: Annotated[str, typer.Option(help="Quarantined source to learn")],
    provider: Annotated[str, typer.Option(help="local (default) or remote")] = "local",
    mode: Annotated[
        str | None, typer.Option(help="structured (regex + ECS mapping) or vrl (free-form)")
    ] = None,
) -> None:
    """Ask the LLM to write a parser for a quarantined source."""
    s = get_settings()
    out = _do(
        service.propose,
        Store(s.db_path),
        s,
        source,
        provider,
        mode,
        progress=lambda msg: typer.echo(f"  {msg}"),
    )
    typer.echo(f"{out['parser_id']}: {out['status']} ({out['reason']})  {out['metrics']}")
    if out["status"] == "proposed":
        typer.echo(f"Review with: privasoc parsers show {out['parser_id']} (or in the web UI)")


@parsers_app.command("list")
def parsers_list(status: str | None = None) -> None:
    for p in Store(get_settings().db_path).parsers(status):
        m = p["report"].get("metrics", {})
        typer.echo(
            f"{p['id']}  {p['status']:17} {p['source']:25} {p['provider']}:{p['model']}"
            f"  attempts={m.get('attempts')}"
        )


@parsers_app.command("show")
def parsers_show(parser_id: str) -> None:
    """Show the VRL, checks and a preview on the latest real lines (local display only)."""
    p = Store(get_settings().db_path).parser(parser_id)
    if not p:
        raise typer.BadParameter("unknown parser")
    r = p["report"]
    typer.echo(
        f"# {p['id']}  source={p['source']}  status={p['status']}  "
        f"model={p['provider']}:{p['model']}"
    )
    typer.echo(f"# {r.get('reason')}  metrics={r.get('metrics')}")
    # The spec the proposed VRL was compiled from (a partial parser may come from an
    # earlier attempt than the last one).
    spec = r.get("spec")
    if spec is None:  # proposals stored before the spec was recorded
        import re as _re

        m = _re.search(r"\(attempt (\d+)\)", r.get("reason") or "")
        n = int(m.group(1)) if m else len(r.get("attempts", []))
        spec = next((a.get("spec") for a in r.get("attempts", []) if a.get("n") == n), None)
    if spec:
        typer.echo("\n--- spec (written by the model) ---\n" + spec)
    typer.echo("\n--- VRL ---\n" + (p["vrl"] or "(none)"))
    typer.echo("\n--- preview on latest real lines ---")
    for item in r.get("preview", []):
        typer.echo(f"raw: {item['raw']}")
        typer.echo(
            f"ecs: {item['ecs'] if item['ecs'] is not None else 'ERROR ' + str(item['error'])}\n"
        )


def _set_status(parser_id: str, status: str) -> None:
    s = get_settings()
    r = _do(service.set_parser_status, Store(s.db_path), s, parser_id, status)
    typer.echo(f"{parser_id} {status}; regenerated and validated {r['config']}")
    if status == "approved":  # D45 step 6: the lines that waited in quarantine
        typer.echo(
            f"backfill: {r['backfilled']} quarantined lines ingested, "
            f"{r['still_quarantined']} still in quarantine"
        )


@parsers_app.command("approve")
def parsers_approve(parser_id: str) -> None:
    """Activate a proposed parser (human decision, D23)."""
    _set_status(parser_id, "approved")


@parsers_app.command("reject")
def parsers_reject(parser_id: str) -> None:
    _set_status(parser_id, "rejected")


@app.command("vector-config")
def vector_config() -> None:
    """(Re)generate vector/pipeline.yaml from approved parsers."""
    from privasoc import vectorgen

    s = get_settings()
    path = vectorgen.write(Store(s.db_path).parsers("approved"), s.vector_dir)
    typer.echo(f"wrote {path}")


eval_app = typer.Typer(help="Evaluation harness (step 3).", no_args_is_help=True)
app.add_typer(eval_app, name="eval")


def _fixture_dir(s: Settings) -> Path:
    return s.data_dir / "fixtures"


@eval_app.command("fetch")
def eval_fetch() -> None:
    """Download the Elastic ground-truth fixtures (not redistributed, D20)."""
    from privasoc import fixtures

    names = fixtures.fetch(_fixture_dir(get_settings()))
    typer.echo(f"fetched {len(names)} fixtures @ {fixtures.ELASTIC_SHA[:10]}: {', '.join(names)}")


@eval_app.command("leak")
def eval_leak(out: Path = Path("reports/leakage.json")) -> None:
    """Measure residual leakage of the pseudonymiser on the fixtures (no LLM needed)."""
    import json

    from privasoc import evaluation, fixtures

    s = get_settings()
    result = evaluation.leakage(fixtures.load(_fixture_dir(s)), _pseudonymizer())
    out.parent.mkdir(parents=True, exist_ok=True)
    # Example values come from Elastic's (ELv2) fixtures: shown locally, never written out.
    saved = {k: v for k, v in result.items() if k != "examples"}
    out.write_text(json.dumps(saved, indent=2), encoding="utf-8")
    typer.echo(
        f"{result['leaked']}/{result['values']} sensitive values leaked "
        f"({result['leak_rate']:.1%}); details in {out}"
    )
    for field, v in result["per_field"].items():
        typer.echo(f"  {field:24} {v['leaked']:>4}/{v['total']:<4} {v['rate']:.0%}")


@eval_app.command("run")
def eval_run(
    runs: Annotated[int, typer.Option(help="Runs per fixture and configuration (k)")] = 3,
    modes: Annotated[str, typer.Option(help="Comma-separated: structured,vrl")] = "structured",
    providers: Annotated[str, typer.Option(help="Comma-separated: local,remote")] = "local",
    pseudo: Annotated[str, typer.Option(help="Comma-separated: on,off (off: local only)")] = "on",
    only: Annotated[str | None, typer.Option(help="Comma-separated fixture names")] = None,
    fixture_set: Annotated[str, typer.Option("--set", help="dev, holdout or all")] = "dev",
    results: Path = Path("data/eval/results.jsonl"),
    budget: Annotated[
        float | None, typer.Option(help="Stop starting new runs after this many seconds")
    ] = None,
) -> None:
    """Run the parser-generation evaluation; resumes from existing results."""
    import time

    started = time.monotonic()
    from privasoc import evaluation, fixtures
    from privasoc.llm import LLMClient
    from privasoc.sandbox import Sandbox

    s = get_settings()
    fxs = fixtures.load(_fixture_dir(s), only.split(",") if only else fixtures.SETS[fixture_set])
    sandbox = Sandbox(s.vector_bin)
    typer.echo(f"sandbox: {sandbox.check()}")
    done = {
        tuple(r[k] for k in ("fixture", "mode", "provider", "model", "pseudo", "run"))
        for r in evaluation.load_results(results)
    }
    store = Store(s.db_path)
    for provider in providers.split(","):
        if provider == "reference":  # hand-written specs: pipeline ceiling, no LLM
            llm = evaluation.ReferenceLLM(Path("evaluation/reference"))
            ep = llm.endpoint
        else:
            ep = _endpoint(s, provider)
            llm = LLMClient(
                ep,
                call_log=store.log_llm_call,
                timeout=s.llm_timeout,
                max_tokens=s.llm_max_tokens,
                num_ctx=s.llm_num_ctx,
            )
            llm.check()
        for p in pseudo.split(","):
            if p == "off" and ep.name == "remote":
                typer.echo("skipping pseudo=off for remote provider (never allowed)")
                continue
            pz = _pseudonymizer() if p == "on" else evaluation.IdentityPseudonymizer()
            for mode in modes.split(","):
                for fx in fxs:
                    if provider == "reference" and not llm.available(fx.name):
                        continue
                    k = 1 if provider == "reference" else runs
                    for run in range(1, k + 1):
                        key = (fx.name, mode, ep.name, ep.model, p == "on", run)
                        if key in done:
                            continue
                        if budget is not None and time.monotonic() - started > budget:
                            typer.echo("budget reached; rerun the same command to resume")
                            return
                        r = evaluation.run_one(
                            fx,
                            run,
                            llm,
                            pz,
                            sandbox,
                            mode,
                            s.sample_size,
                            s.max_attempts,
                            s.min_coverage,
                        )
                        evaluation.append(results, r)
                        typer.echo(
                            f"{fx.name:11} {mode:10} {ep.model} pseudo={p} run {run}: "
                            f"{r.status:16} F1={r.f1:.2f} parsed={r.heldout_parsed:.0%} "
                            f"attempts={r.attempts} {r.llm_latency_s:.0f}s"
                        )


@eval_app.command("report")
def eval_report(
    results: Annotated[list[Path] | None, typer.Option(help="Result files (repeatable)")] = None,
    leak: Path = Path("reports/leakage.json"),
    out_dir: Path = Path("reports"),
) -> None:
    """Write reports/eval.md and reports/eval.html from the results."""
    import json

    from privasoc import evaluation, fixtures, report

    paths = results or [
        *sorted(Path("evaluation").glob("results-*.jsonl")),
        Path("data/eval/results.jsonl"),
    ]
    rs = [r for p in paths for r in evaluation.load_results(p)]
    lk = json.loads(leak.read_text(encoding="utf-8")) if leak.exists() else None
    md = report.markdown(report.summarise(rs), lk, report.meta(fixtures.ELASTIC_SHA))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.md").write_text(md, encoding="utf-8")
    (out_dir / "eval.html").write_text(report.to_html(md), encoding="utf-8")
    typer.echo(md)


if __name__ == "__main__":
    app()
