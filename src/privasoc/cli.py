"""privasoc command line."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer
from cryptography.fernet import Fernet

from privasoc.config import get_settings
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
    typer.echo("Keep PRIVASOC_VAULT_KEY safe: without it the vault cannot be re-identified.")


@app.command()
def serve() -> None:
    """Run the API (ingestion endpoint for Vector)."""
    import uvicorn

    from privasoc.api import create_app

    s = get_settings()
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


if __name__ == "__main__":
    app()
