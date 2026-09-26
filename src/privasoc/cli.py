"""privasoc command line."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer
from cryptography.fernet import Fernet

from privasoc.config import Settings, get_settings
from privasoc.pseudo import Pseudonymizer, Vault
from privasoc.store import Record, Store

app = typer.Typer(help="Privacy-first, local-LLM SOC analyst.", no_args_is_help=True)

SECRET_GENERATORS = {
    "PRIVASOC_API_TOKEN": lambda: secrets.token_urlsafe(32),
    "PRIVASOC_HMAC_KEY": lambda: secrets.token_urlsafe(32),
    "PRIVASOC_VAULT_KEY": lambda: Fernet.generate_key().decode(),
}


def _pseudonymizer() -> Pseudonymizer:
    s = get_settings()
    s.require_secrets()
    vault = Vault(
        s.vault_path,
        s.hmac_key.get_secret_value().encode(),
        s.vault_key.get_secret_value().encode(),
    )
    return Pseudonymizer(vault)


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
    store = Store(get_settings().db_path)
    with path.open(encoding="utf-8", errors="replace") as fh:
        counts = store.ingest(
            Record(source=source, raw=ln.rstrip("\r\n")) for ln in fh if ln.strip()
        )
    typer.echo(f"{counts['events']} events, {counts['unparsed']} quarantined")


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
    from privasoc.llm import Endpoint

    if provider == "remote":
        return Endpoint(
            "remote", s.llm_remote_url, s.llm_remote_model, s.llm_remote_api_key.get_secret_value()
        )
    return Endpoint("local", s.llm_local_url, s.llm_local_model, think=s.llm_local_think)


def _run_generation(
    source: str, provider: str, store: Store, s: Settings, lines: list[str], mode: str
):
    from privasoc.generator import generate
    from privasoc.llm import LLMClient
    from privasoc.sandbox import Sandbox

    llm = LLMClient(
        _endpoint(s, provider),
        call_log=store.log_llm_call,
        timeout=s.llm_timeout,
        max_tokens=s.llm_max_tokens,
    )
    sandbox = Sandbox(s.vector_bin)
    try:  # fail fast, before minutes of LLM time
        typer.echo(f"sandbox: {sandbox.check()}")
        llm.check()
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    return generate(
        source,
        lines,
        llm,
        _pseudonymizer(),
        sandbox,
        k=s.sample_size,
        max_attempts=s.max_attempts,
        progress=lambda msg: typer.echo(f"  {msg}"),
        mode=mode,
        min_coverage=s.min_coverage,
    )


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
    mode = mode or s.parser_mode
    if mode not in {"structured", "vrl"}:
        raise typer.BadParameter("mode must be structured or vrl")
    store = Store(s.db_path)
    lines = store.quarantine_lines(source)
    if not lines:
        raise typer.BadParameter(f"no quarantined lines for {source!r}")
    typer.echo(f"{len(lines)} lines, asking {provider} model...")
    out = _run_generation(source, provider, store, s, lines, mode)
    if out.status == "needs_escalation" and provider == "local":
        if s.auto_fallback and s.llm_remote_url:
            typer.echo(f"local model: {out.reason}; falling back to remote API (pseudonymised)")
            store.save_parser(
                out.parser_id, source, "failed", out.provider, out.model, out.vrl, out.report()
            )
            out = _run_generation(source, "remote", store, s, lines, mode)
        else:
            typer.echo(
                f"local model: {out.reason}. Retry with --provider remote if you accept "
                "sending pseudonymised samples to the API."
            )
    store.save_parser(
        out.parser_id, source, out.status, out.provider, out.model, out.vrl, out.report()
    )
    typer.echo(f"{out.parser_id}: {out.status} ({out.reason})  {out.metrics}")
    if out.status == "proposed":
        typer.echo(f"Review with: privasoc parsers show {out.parser_id}")


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
    from privasoc import vectorgen

    s = get_settings()
    store = Store(s.db_path)
    p = store.parser(parser_id)
    if not p:
        raise typer.BadParameter("unknown parser")
    if status == "approved" and p["status"] != "proposed":
        raise typer.BadParameter(f"only a proposed parser can be approved (is {p['status']})")
    previous = p["status"]
    active = [x["id"] for x in store.parsers("approved") if x["source"] == p["source"]]
    store.set_parser_status(parser_id, status)
    path = vectorgen.write(store.parsers("approved"), s.vector_dir)
    error = vectorgen.validate(s.vector_bin, s.vector_dir)
    if error:  # never leave Vector with a config it cannot load
        store.set_parser_status(parser_id, "rejected" if status == "approved" else previous)
        for pid in active:  # restore the parser that was active before
            store.set_parser_status(pid, "approved")
        vectorgen.write(store.parsers("approved"), s.vector_dir)
        typer.echo(error, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{parser_id} {status}; regenerated and validated {path}")


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
    results: Path = Path("data/eval/results.jsonl"),
) -> None:
    """Run the parser-generation evaluation; resumes from existing results."""
    from privasoc import evaluation, fixtures
    from privasoc.llm import LLMClient
    from privasoc.sandbox import Sandbox

    s = get_settings()
    fxs = fixtures.load(_fixture_dir(s), only.split(",") if only else None)
    sandbox = Sandbox(s.vector_bin)
    typer.echo(f"sandbox: {sandbox.check()}")
    done = {
        tuple(r[k] for k in ("fixture", "mode", "provider", "model", "pseudo", "run"))
        for r in evaluation.load_results(results)
    }
    store = Store(s.db_path)
    for provider in providers.split(","):
        ep = _endpoint(s, provider)
        llm = LLMClient(
            ep, call_log=store.log_llm_call, timeout=s.llm_timeout, max_tokens=s.llm_max_tokens
        )
        llm.check()
        for p in pseudo.split(","):
            if p == "off" and ep.remote:
                typer.echo("skipping pseudo=off for remote provider (never allowed)")
                continue
            pz = _pseudonymizer() if p == "on" else evaluation.IdentityPseudonymizer()
            for mode in modes.split(","):
                for fx in fxs:
                    for run in range(1, runs + 1):
                        key = (fx.name, mode, ep.name, ep.model, p == "on", run)
                        if key in done:
                            continue
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
    results: Path = Path("data/eval/results.jsonl"),
    leak: Path = Path("reports/leakage.json"),
    out_dir: Path = Path("reports"),
) -> None:
    """Write reports/eval.md and reports/eval.html from the results."""
    import json

    from privasoc import evaluation, fixtures, report

    rs = evaluation.load_results(results)
    lk = json.loads(leak.read_text(encoding="utf-8")) if leak.exists() else None
    md = report.markdown(report.summarise(rs), lk, report.meta(fixtures.ELASTIC_SHA))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.md").write_text(md, encoding="utf-8")
    (out_dir / "eval.html").write_text(report.to_html(md), encoding="utf-8")
    typer.echo(md)


if __name__ == "__main__":
    app()
