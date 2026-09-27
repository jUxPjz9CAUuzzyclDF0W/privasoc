"""HTTP API: ingestion endpoint for Vector, hosts and health, and the review UI (step 4).

Vector's `http` sink posts newline-delimited JSON; each object carries the raw line in
`message` and, once parsers exist, the normalised document in `ecs` + `parser_id`.
"""

from __future__ import annotations

import hmac
import json
import threading
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from privasoc import __version__
from privasoc.config import Settings, get_settings
from privasoc.store import Record, Store

MAX_BODY = 10 * 1024 * 1024


def create_app(
    settings: Settings | None = None, store: Store | None = None, ui: bool = True
) -> FastAPI:
    settings = settings or get_settings()
    settings.require_secrets()
    store = store or Store(settings.db_path)
    token = settings.api_token.get_secret_value()
    app = FastAPI(title="privasoc", version=__version__)
    # One SQLite connection is shared by the API and the UI: writes are serialised here,
    # and blocking work runs in the thread pool, never on the event loop.
    lock = threading.RLock()

    def locked(fn, *args):
        with lock:
            return fn(*args)

    def auth(authorization: Annotated[str | None, Header()] = None) -> None:
        expected = f"Bearer {token}"
        if not authorization or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid token")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.post("/ingest", dependencies=[Depends(auth)])
    async def ingest(request: Request) -> dict:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(status_code=413, detail="payload too large")
        records = []
        for n, line in enumerate(body.decode("utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail=f"line {n}: invalid JSON") from exc
            items = obj if isinstance(obj, list) else [obj]
            for it in items:
                records.append(_to_record(it))
        return await run_in_threadpool(locked, store.ingest, records)

    @app.get("/hosts", dependencies=[Depends(auth)])
    def hosts() -> list[dict]:
        return locked(store.hosts)

    @app.get("/health/hosts", dependencies=[Depends(auth)])
    def hosts_health() -> list[dict]:
        """D47: health of every approved host."""
        from privasoc import service

        with lock:
            return [service.host_health(store, h) for h in store.hosts("approved")]

    if ui:
        from privasoc import web

        web.install(app, settings, store, lock)
    app.state.store = store
    return app


def _to_record(obj: dict) -> Record:
    raw = obj.get("message")
    if not isinstance(raw, str):
        raise HTTPException(status_code=400, detail="each event needs a string `message`")
    source = obj.get("privasoc_source") or "unknown"
    ecs = obj.get("ecs") if isinstance(obj.get("ecs"), dict) else None
    return Record(
        source=str(source),
        raw=raw,
        received_at=obj.get("timestamp"),
        ecs=ecs,
        parser_id=obj.get("parser_id"),
    )
