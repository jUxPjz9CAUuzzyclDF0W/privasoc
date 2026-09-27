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
    if s.detect_interval > 0:  # step 6: detection in the background, own connection
        import threading
        import time

        def loop() -> None:
            store = Store(s.db_path)
            while True:
                try:
                    service.detect_run(store, s)
                except Exception as exc:  # noqa: BLE001 - keep detecting, report it
                    typer.echo(f"detection error: {exc}", err=True)
                time.sleep(s.detect_interval)

        threading.Thread(target=loop, name="privasoc-detect", daemon=True).start()
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


rules_app = typer.Typer(
    help="Learned pseudonymisation rules (step 5): proposed by the local model, approved by you.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list(status: str | None = None) -> None:
    """Rules with their status (patterns are shown: this is a local terminal)."""
    rows = _do(service.list_rules, get_settings(), status)
    if not rows:
        typer.echo("No rule yet: privasoc rules learn --source <host>")
    for r in rows:
        typer.echo(f"{r.id}  {r.status:9} {r.kind:5} {r.origin:6} {r.label()}")


@rules_app.command("learn")
def rules_learn(source: Annotated[str, typer.Option(help="Approved host to learn from")]) -> None:
    """Ask the LOCAL model what the detectors still miss; results are proposals."""
    s = get_settings()
    out = _do(
        service.learn_rules, Store(s.db_path), s, source, progress=lambda m: typer.echo(f"  {m}")
    )
    if not out:
        typer.echo("Nothing new: the local model found no residual personal data.")
    for r in out:
        state = "new" if r["new"] else f"already {r['status']}"
        typer.echo(
            f"{r['id']}  {state:17} {r['kind']:5} {r['label']}  changes {r['changed']} lines"
        )
    if any(r["new"] for r in out):
        typer.echo("Review with: privasoc rules preview <id>, then approve or reject.")


@rules_app.command("add")
def rules_add(
    rtype: Annotated[str, typer.Argument(help="key, regex or value")],
    kind: Annotated[str, typer.Argument(help="user or host")],
    pattern: str,
    approve: Annotated[bool, typer.Option(help="Approve at once")] = False,
) -> None:
    """Add a rule by hand, e.g. `privasoc rules add key user cs1`."""
    r = _do(service.add_rule, get_settings(), rtype, kind, pattern, approve)
    typer.echo(f"{r.id} {r.status}: {r.label()}")


@rules_app.command("preview")
def rules_preview(rule_id: str, source: str | None = None) -> None:
    """What a rule would change on the latest real lines (local display only)."""
    s = get_settings()
    p = _do(service.rule_preview, Store(s.db_path), s, rule_id, source)
    r = p["rule"]
    typer.echo(f"{r.id} {r.status} {r.kind} {r.label()}  ({r.origin}) {r.note}")
    typer.echo(f"changes {p['changed']} of {p['lines']} lines; {p['distinct']} distinct values:")
    for v, n in p["values"]:
        typer.echo(f"  {n:>5}  {v}")
    for ex in p["examples"]:
        typer.echo(f"before: {ex['before']}\nafter:  {ex['after']}\n")


@rules_app.command("approve")
def rules_approve(rule_id: str) -> None:
    r = _do(service.set_rule_status, get_settings(), rule_id, "approved")
    typer.echo(f"{r.id} approved: {r.label()} now applies to every pseudonymisation")


@rules_app.command("reject")
def rules_reject(rule_id: str) -> None:
    r = _do(service.set_rule_status, get_settings(), rule_id, "rejected")
    typer.echo(f"{r.id} rejected: it will not be proposed again")


sigma_app = typer.Typer(help="Sigma rules (step 6, D50).", no_args_is_help=True)
app.add_typer(sigma_app, name="sigma")
alerts_app = typer.Typer(help="Alerts and AI triage (step 6, D52, D53).", no_args_is_help=True)
app.add_typer(alerts_app, name="alerts")


@sigma_app.command("fetch")
def sigma_fetch() -> None:
    """Download the SigmaHQ rules privasoc can normalise (kept out of git, DRL 1.1)."""
    r = _do(service.sigma_fetch, get_settings())
    typer.echo(
        f"SigmaHQ {r['tag']}: {r['files']} rule files; {r['supported']}/{r['rules']} rules "
        f"supported (including privasoc's own), {r['correlations']} correlations"
    )


@sigma_app.command("list")
def sigma_list(
    unsupported: Annotated[bool, typer.Option(help="Only rules the engine cannot run")] = False,
) -> None:
    for r in service.engine(get_settings()).rules:
        if unsupported and r.unsupported is None:
            continue
        typer.echo(f"{r.id[:36]:36} ", nl=False)
        state = "ok" if r.unsupported is None else f"unsupported: {r.unsupported}"
        if r.disabled:
            state = f"disabled: {r.disabled}"
        typer.echo(f"{r.level:13} {r.origin:8} {r.title[:60]:60} {state}")


@app.command()
def detect() -> None:
    """Run detection once on the events stored since the last run."""
    s = get_settings()
    r = service.detect_run(Store(s.db_path), s)
    typer.echo(
        f"{r['events']} events, {r['matches']} matches, {r['new_alerts']} new Sigma alerts, "
        f"{r['host_alerts']} host alerts, {r['sent']} notifications sent"
    )


@alerts_app.command("list")
def alerts_list(status: str = "open") -> None:
    from privasoc.detect import alerts as al

    rows = al.alerts(Store(get_settings().db_path), None if status == "all" else status)
    if not rows:
        typer.echo("No alert.")
    for a in rows:
        verdict = (a["triage"] or {}).get("result") or {}
        typer.echo(
            f"#{a['id']:<5} {a['level']:13} {a['status']:12} x{a['count']:<4} "
            f"{a['source'][:24]:24} {a['title'][:60]}"
            + (f"  [AI: {verdict.get('verdict')}]" if verdict else "")
        )


@alerts_app.command("show")
def alerts_show(alert_id: int) -> None:
    """An alert, its rule, its events and the latest triage (re-identified locally)."""
    import json

    from privasoc.detect import alerts as al

    s = get_settings()
    store = Store(s.db_path)
    a = al.alert(store, alert_id)
    if not a:
        raise typer.BadParameter("unknown alert")
    typer.echo(f"#{a['id']} {a['level']} {a['status']} {a['title']}  ({a['kind']}, x{a['count']})")
    rule = service.find_rule(s, a["rule_id"])
    if rule:
        typer.echo(f"rule: {rule.title} [{rule.licence()}] {', '.join(rule.attack)}")
    for e in al.alert_events(store, alert_id, 10):
        typer.echo(f"  event {e['id']}: {(e['ecs'].get('event') or {}).get('original', '')[:160]}")
    if a["triage"]:
        typer.echo(json.dumps(service.reidentify_obj(s, a["triage"]), indent=2))


@alerts_app.command("triage")
def alerts_triage(alert_id: int, provider: str = "local") -> None:
    """AI triage on pseudonymised evidence; the analyst decides."""
    import json

    s = get_settings()
    rec = _do(
        service.triage_alert, Store(s.db_path), s, alert_id, provider,
        progress=lambda m: typer.echo(f"  {m}"),
    )  # fmt: skip
    typer.echo(json.dumps(service.reidentify_obj(s, rec), indent=2))


@alerts_app.command("close")
def alerts_close(
    alert_id: int,
    verdict: Annotated[str, typer.Argument(help="tp (true positive) or fp (false positive)")],
) -> None:
    status = {"tp": "closed_tp", "fp": "closed_fp"}.get(verdict)
    if not status:
        raise typer.BadParameter("verdict is tp or fp")
    _do(service.set_alert_status, Store(get_settings().db_path), alert_id, status)
    typer.echo(f"#{alert_id} {status}")


@alerts_app.command("ack")
def alerts_ack(alert_id: int) -> None:
    _do(service.set_alert_status, Store(get_settings().db_path), alert_id, "acknowledged")
    typer.echo(f"#{alert_id} acknowledged")


airules_app = typer.Typer(
    help="Rules written by the model (step 7): proposals you approve.", no_args_is_help=True
)
app.add_typer(airules_app, name="ai-rules")


def _show_backtest(bt: dict) -> None:
    typer.echo(f"backtest on {bt['events']} stored events:")
    for r in bt["results"]:
        note = " (base of a correlation, raises no alert itself)" if r["kind"] == "base" else ""
        typer.echo(f"  {r['title']}: {r['matches']} matching event(s){note}")
        for g in r.get("groups", [])[:10]:
            typer.echo(f"    {g['group']} -> {g['value']}")
    if not any(r["matches"] for r in bt["results"] if r["kind"] != "base"):
        typer.echo("  (matches nothing: check the rule before keeping it)")
    fp = bt.get("false_positive")
    if fp:
        typer.echo(
            f"  past alerts: {fp['fp_removed']}/{fp['fp']} false positives removed, "
            f"{fp['tp_kept']}/{fp['tp']} true positives still detected"
            + (f"; WOULD HIDE true positives {fp['tp_lost']}" if fp["tp_lost"] else "")
        )


def _author(origin: str, request: str = "", ref: int | None = None, provider: str = "local",
            hours: float | None = None) -> None:  # fmt: skip
    s = get_settings()
    out = _do(service.author_rule, Store(s.db_path), s, origin, request, ref, provider,
              progress=lambda m: typer.echo(f"  {m}"), hours=hours)  # fmt: skip
    if out["status"] != "proposed":
        typer.echo(f"no valid rule after {len(out['attempts'])} attempts: {out['reason']}")
        raise typer.Exit(code=1)
    typer.echo(out["yaml"])
    _show_backtest(out["backtest"])
    typer.echo(f"{out['id']} ({'hunt, not a rule yet' if origin == 'hunt' else 'proposed'})")


@app.command()
def hunt(
    question: str,
    hours: Annotated[float, typer.Option(help="Look back this many hours (0 = all)")] = 24,
    provider: str = "local",
) -> None:
    """Ask a question about your events; the model answers with a Sigma rule that is run."""
    _author("hunt", question, provider=provider, hours=hours or None)


@airules_app.command("write")
def airules_write(request: str, provider: str = "local") -> None:
    """Describe what to detect; the model writes the rule, privasoc backtests it."""
    _author("request", request, provider=provider)


@airules_app.command("from-alert")
def airules_from_alert(
    alert_id: int,
    false_positive: Annotated[bool, typer.Option("--false-positive")] = False,
    provider: str = "local",
) -> None:
    """A rule that catches these events, or (--false-positive) a fix of the alert's rule."""
    _author("false_positive" if false_positive else "event", ref=alert_id, provider=provider)


@airules_app.command("list")
def airules_list(status: str | None = None) -> None:
    from privasoc.detect import authored

    for c in authored.listing(Store(get_settings().db_path), status):
        typer.echo(f"{c['id']}  {c['status']:9} {c['origin']:15} {c['title'][:60]}")


@airules_app.command("show")
def airules_show(rule_id: str) -> None:
    from privasoc.detect import authored

    c = authored.get(Store(get_settings().db_path), rule_id)
    if not c:
        raise typer.BadParameter("unknown rule")
    typer.echo(f"# {c['id']} {c['status']} ({c['origin']}, {c['model']}): {c['request']}")
    typer.echo(c["yaml"])
    if c["backtest"]:
        _show_backtest(c["backtest"])


def _decide(rule_id: str, status: str) -> None:
    s = get_settings()
    c = _do(service.decide_rule, Store(s.db_path), s, rule_id, status)
    typer.echo(f"{c['id']} {c['status']}")


@airules_app.command("approve")
def airules_approve(rule_id: str) -> None:
    _decide(rule_id, "approved")


@airules_app.command("keep")
def airules_keep(rule_id: str) -> None:
    """Turn a hunt into a rule proposal."""
    _decide(rule_id, "proposed")


@airules_app.command("reject")
def airules_reject(rule_id: str) -> None:
    _decide(rule_id, "rejected")


@airules_app.command("disable")
def airules_disable(rule_id: str) -> None:
    _decide(rule_id, "disabled")


@sigma_app.command("disable")
def sigma_disable(rule_id: str, reason: str = "") -> None:
    """Switch a rule off (a correlation takes its base rules with it)."""
    s = get_settings()
    _do(service.toggle_rule, Store(s.db_path), s, rule_id, True, reason)
    typer.echo(f"{rule_id} disabled")


@sigma_app.command("enable")
def sigma_enable(rule_id: str) -> None:
    s = get_settings()
    _do(service.toggle_rule, Store(s.db_path), s, rule_id, False)
    typer.echo(f"{rule_id} enabled")


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


@eval_app.command("learn")
def eval_learn(
    fixture_set: Annotated[str, typer.Option("--set", help="dev, holdout or all")] = "dev",
    results: Path = Path("evaluation/results-learn.jsonl"),
    budget: Annotated[float, typer.Option(help="Stop after this many seconds")] = 0,
) -> None:
    """Step 5: learn rules on half of each fixture (local model), measure leakage on the other
    half. Resumable: fixtures already in the results file are skipped."""
    import json
    import time

    from privasoc import evaluation, fixtures
    from privasoc.pseudo import Pseudonymizer, Vault

    s = get_settings()
    llm = _do(service._local_llm, Store(s.db_path), s)
    done = set()
    if results.exists():
        done = {
            (r["fixture"], r["model"], r.get("think", False))
            for r in map(json.loads, results.read_text(encoding="utf-8").splitlines())
        }

    def fresh_pz():  # throwaway vault: an evaluation never touches the real one
        return Pseudonymizer(Vault(":memory:", secrets.token_bytes(32), Fernet.generate_key()))

    # Model answers are cached per batch (local file next to the results, it holds
    # fixture text): an interrupted run resumes without asking the model again.
    cache_path = results.with_suffix(".cache.json")

    class Cache(dict):
        def __setitem__(self, k, v):
            super().__setitem__(k, v)
            cache_path.write_text(json.dumps(self), encoding="utf-8")

    cache = Cache(json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {})
    t0 = time.monotonic()
    results.parent.mkdir(parents=True, exist_ok=True)
    for fx in fixtures.load(_fixture_dir(s), fixtures.SETS[fixture_set]):
        if (fx.name, llm.endpoint.model, llm.endpoint.think) in done:
            continue
        if budget and time.monotonic() - t0 > budget:
            typer.echo("budget reached; run again to continue")
            return
        typer.echo(f"{fx.name}:")
        row = evaluation.learning_one(
            fx,
            fresh_pz,
            llm,
            s.learn_sample,
            s.learn_batch,
            progress=lambda m: typer.echo(f"  {m}"),
            cache=cache,
        )
        with results.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        typer.echo(
            f"  leaked {row['leaked_before']} -> {row['leaked_after']} of {row['values']}; "
            f"{row['rules']} rules; caught {row['caught_sensitive']} sensitive, "
            f"{row['caught_other']} other"
        )
    rows = [json.loads(x) for x in results.read_text(encoding="utf-8").splitlines()]
    typer.echo(json.dumps(evaluation.learning_summary(rows), indent=2))


@eval_app.command("hunt")
def eval_hunt(
    fixture_set: Annotated[str, typer.Option("--set", help="dev, holdout or all")] = "dev",
    results: Path = Path("evaluation/results-hunt.jsonl"),
    budget: Annotated[float, typer.Option(help="Stop after this many seconds")] = 0,
    runs: Annotated[int, typer.Option(help="Runs per case")] = 1,
) -> None:
    """Step 7 bench (D56): hand-written hunts on synthetic events with a known answer.
    Resumable: (case, model, run) already in the results file are skipped."""
    import json
    import time

    from privasoc import bench_hunt
    from privasoc.llm import LLMClient
    from privasoc.pseudo import Pseudonymizer, Vault

    s = get_settings()
    llm = LLMClient(service._endpoint(s, "local"), timeout=s.llm_timeout,
                    max_tokens=s.llm_max_tokens, num_ctx=s.llm_num_ctx)  # fmt: skip
    _do(llm.check)
    rows = []
    if results.exists():
        rows = [json.loads(x) for x in results.read_text(encoding="utf-8").splitlines()]
    done = {(r["n"], r["model"], r.get("run", 1)) for r in rows}

    def fresh_pz():
        return Pseudonymizer(Vault(":memory:", secrets.token_bytes(32), Fernet.generate_key()))

    t0 = time.monotonic()
    results.parent.mkdir(parents=True, exist_ok=True)
    for run in range(1, runs + 1):
        for case in bench_hunt.load_cases():
            if fixture_set != "all" and case["set"] != fixture_set:
                continue
            if (case["n"], llm.endpoint.model, run) in done:
                continue
            if budget and time.monotonic() - t0 > budget:
                typer.echo("budget reached; run again to continue")
                return
            row = {**bench_hunt.run_case(case, llm, fresh_pz), "run": run}
            with results.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
            rows.append(row)
            typer.echo(
                f"#{case['n']:<3} {'valid' if row['valid'] else 'INVALID':8} "
                f"P={row['precision']:.2f} R={row['recall']:.2f} exact={row['exact']} "
                f"attempts={row['attempts']} {row['llm_s']}s  {case['request']}"
            )
    typer.echo(json.dumps(bench_hunt.summary(rows), indent=2))


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
