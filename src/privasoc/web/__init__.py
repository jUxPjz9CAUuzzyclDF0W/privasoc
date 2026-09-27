"""Review web UI (step 4, D29, D41): hosts, parsers, quarantine, events and jobs.

Server-rendered pages (Jinja) with a little htmx for polling. No JavaScript of our own and
no third-party host: htmx is vendored, and the Content-Security-Policy only allows 'self'.

Access (D41): the same single token as the API. The browser gets an HttpOnly, SameSite=Strict
session cookie derived from the token (HMAC), never the token itself; every form carries a
CSRF token. Rotating PRIVASOC_API_TOKEN logs every browser out.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from privasoc import __version__, service
from privasoc.config import Settings
from privasoc.health import DEFAULTS
from privasoc.store import Store
from privasoc.web.jobs import Jobs

HERE = Path(__file__).parent
COOKIE = "privasoc_session"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def _derive(token: str, purpose: str) -> str:
    return hmac.new(token.encode(), f"privasoc-ui:{purpose}".encode(), hashlib.sha256).hexdigest()


def _safe_next(target: str | None) -> str:
    """Only local UI paths: no open redirect through ?next=."""
    if target and target.startswith("/ui/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/ui/"


class _Redirect(Exception):
    def __init__(self, url: str):
        self.url = url


def create_router(settings: Settings, store: Store, lock: threading.RLock) -> APIRouter:
    token = settings.api_token.get_secret_value()
    session_value = _derive(token, "session")
    csrf_value = _derive(token, "csrf")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False)
    templates.env.filters["q"] = lambda v: quote(str(v), safe="")
    templates.env.globals["version"] = __version__
    jobs = Jobs()
    router = APIRouter(prefix="/ui", include_in_schema=False)

    # ------------------------------------------------------------------ helpers

    def logged_in(request: Request) -> None:
        cookie = request.cookies.get(COOKIE, "")
        if not hmac.compare_digest(cookie, session_value):
            target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            raise _Redirect("/ui/login?" + urlencode({"next": target}))

    def csrf(token_field: Annotated[str, Form(alias="csrf")] = "") -> None:
        if not hmac.compare_digest(token_field, csrf_value):
            raise HTTPException(status_code=403, detail="invalid CSRF token: reload the page")

    auth = [Depends(logged_in)]
    post = [Depends(logged_in), Depends(csrf)]

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        ctx.setdefault("msg", request.query_params.get("msg", "")[:500])
        ctx.setdefault("level", request.query_params.get("level", "ok"))
        running = jobs.running()
        return templates.TemplateResponse(
            request, name, {"csrf": csrf_value, "running_job": running, **ctx}
        )

    def back(url: str, msg: str, level: str = "ok") -> RedirectResponse:
        sep = "&" if "?" in url else "?"
        return RedirectResponse(
            f"{url}{sep}{urlencode({'msg': msg[:500], 'level': level})}", status_code=303
        )

    def pseudo_lines(lines: list[str], raw: bool) -> list[str]:
        if raw:
            return lines
        pz = service.pseudonymizer(settings)
        try:
            return [pz.pseudonymize(ln).text for ln in lines]
        finally:
            pz.vault.close()

    def health_rows() -> list[dict]:
        rows = []
        for h in store.hosts():
            h = dict(h)
            h["health"] = service.host_health(store, h) if h["status"] == "approved" else None
            rows.append(h)
        return rows

    # ------------------------------------------------------------------ login

    @router.get("/login")
    def login_form(request: Request, next: str = "/ui/") -> HTMLResponse:  # noqa: A002
        return page(request, "login.html", next=_safe_next(next))

    @router.post("/login")
    def login(
        request: Request,
        access_token: Annotated[str, Form()] = "",
        next: Annotated[str, Form()] = "/ui/",  # noqa: A002
    ) -> Response:
        if not token or not hmac.compare_digest(access_token.encode(), token.encode()):
            time.sleep(0.5)  # slow down guessing; the token is 256 random bits anyway
            return page(
                request, "login.html", next=_safe_next(next), msg="wrong token", level="error"
            )
        resp = RedirectResponse(_safe_next(next), status_code=303)
        resp.set_cookie(
            COOKIE,
            session_value,
            max_age=12 * 3600,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/ui",
        )
        return resp

    @router.post("/logout", dependencies=post)
    def logout() -> Response:
        resp = RedirectResponse("/ui/login", status_code=303)
        resp.delete_cookie(COOKIE, path="/ui")
        return resp

    # ------------------------------------------------------------------ dashboard

    @router.get("/", dependencies=auth)
    def dashboard(request: Request) -> HTMLResponse:
        with lock:
            summary = store.summary()
            hosts = health_rows()
            proposed = store.parsers("proposed")
        return page(
            request,
            "dashboard.html",
            summary=summary,
            pending=[h for h in hosts if h["status"] == "pending"],
            unhealthy=[h for h in hosts if h["health"] and h["health"]["status"] != "ok"],
            proposed=proposed,
        )

    # ------------------------------------------------------------------ hosts (D45, D47)

    @router.get("/hosts", dependencies=auth)
    def hosts_page(request: Request) -> HTMLResponse:
        with lock:
            rows = health_rows()
        return page(request, "hosts.html", hosts=rows)

    @router.get("/hosts/table", dependencies=auth)
    def hosts_table(request: Request) -> HTMLResponse:
        with lock:
            rows = health_rows()
        return page(request, "_hosts_table.html", hosts=rows)

    @router.get("/host", dependencies=auth)
    def host_page(request: Request, source: str, raw: bool = False) -> HTMLResponse:
        with lock:
            h = store.host(source)
            if not h:
                raise HTTPException(status_code=404, detail="unknown host")
            hs = service.host_health(store, h) if h["status"] == "approved" else None
            held = store.held_sample(source, 10)
            quarantined = store.quarantine_sample(source, 10)
            qcount = next((n for s, n, _, _ in store.quarantine_stats() if s == source), 0)
            history = store.health_history(source, 20)
            parsers = [p for p in store.parsers() if p["source"] == source]
        return page(
            request,
            "host.html",
            host=h,
            health=hs,
            held=pseudo_lines(held, raw),
            quarantined=pseudo_lines(quarantined, raw),
            qcount=qcount,
            history=history,
            parsers=parsers,
            raw=raw,
            defaults=DEFAULTS,
            remote=bool(settings.llm_remote_url),
            mode=settings.parser_mode,
        )

    def host_url(source: str) -> str:
        return "/ui/host?" + urlencode({"source": source})

    @router.post("/host/approve", dependencies=post)
    def host_approve(source: Annotated[str, Form()]) -> Response:
        try:
            with lock:
                r = service.approve_host(store, settings, source)
        except service.ActionError as exc:
            return back(host_url(source), str(exc), "error")
        if r["format"] == "unknown":
            msg = (
                f"approved; format not known by Vector, {r.get('quarantined', 0)} lines in "
                "quarantine. Propose a parser below."
            )
            if r.get("error"):
                msg += f" (built-in refused by Vector: {r['error'][:200]})"
        else:
            msg = (
                f"approved; known format {r['format']} (coverage {r['coverage']:.0%}): "
                f"{r['backfilled']} lines ingested, {r['still_quarantined']} left in quarantine"
            )
        return back(host_url(source), msg)

    @router.post("/host/reject", dependencies=post)
    def host_reject(source: Annotated[str, Form()]) -> Response:
        try:
            with lock:
                service.reject_host(store, source)
        except service.ActionError as exc:
            return back("/ui/hosts", str(exc), "error")
        return back("/ui/hosts", f"{source} rejected: held lines deleted, future lines dropped")

    @router.post("/host/thresholds", dependencies=post)
    async def host_thresholds(request: Request) -> Response:
        form = await request.form()
        source = str(form.get("source", ""))
        values = {k: str(form.get(k, "")).strip() for k in DEFAULTS}

        def save() -> dict:
            with lock:
                return service.set_thresholds(store, source, values)

        try:
            th = await run_in_threadpool(save)  # never hold the lock on the event loop
        except service.ActionError as exc:
            return back(host_url(source), str(exc), "error")
        return back(host_url(source), f"thresholds saved: {th or 'defaults'}")

    @router.post("/host/propose", dependencies=post)
    def host_propose(
        source: Annotated[str, Form()],
        provider: Annotated[str, Form()] = "local",
        mode: Annotated[str, Form()] = "",
    ) -> Response:
        if provider == "remote" and not settings.llm_remote_url:
            return back(host_url(source), "no remote API configured", "error")

        def work(say):
            job_store = Store(store.path)  # own connection: runs in its own thread
            try:
                return service.propose(job_store, settings, source, provider, mode or None, say)
            finally:
                job_store.close()

        try:
            job = jobs.start("propose", source, work)
        except RuntimeError as exc:
            return back(host_url(source), str(exc), "error")
        return RedirectResponse(f"/ui/job?id={job.id}", status_code=303)

    # ------------------------------------------------------------------ jobs

    @router.get("/jobs", dependencies=auth)
    def jobs_page(request: Request) -> HTMLResponse:
        return page(request, "jobs.html", jobs=jobs.all())

    @router.get("/job", dependencies=auth)
    def job_page(request: Request, id: str) -> HTMLResponse:  # noqa: A002
        job = jobs.get(id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown job (jobs live in memory)")
        return page(request, "job.html", job=job)

    @router.get("/job/fragment", dependencies=auth)
    def job_fragment(request: Request, id: str) -> HTMLResponse:  # noqa: A002
        job = jobs.get(id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown job")
        return page(request, "_job.html", job=job)

    # ------------------------------------------------------------------ parsers (D23)

    @router.get("/parsers", dependencies=auth)
    def parsers_page(request: Request, status: str = "") -> HTMLResponse:
        with lock:
            rows = store.parsers(status or None)
        return page(request, "parsers.html", parsers=list(reversed(rows)), status=status)

    @router.get("/parser", dependencies=auth)
    def parser_page(request: Request, id: str) -> HTMLResponse:  # noqa: A002
        with lock:
            p = store.parser(id)
        if not p:
            raise HTTPException(status_code=404, detail="unknown parser")
        return page(request, "parser.html", p=p, r=p["report"])

    @router.get("/parser/try", dependencies=auth)
    def parser_try(request: Request, id: str) -> HTMLResponse:  # noqa: A002
        try:
            with lock:
                items = service.try_parser(store, settings, id)
            error = None
        except service.ActionError as exc:
            items, error = [], str(exc)
        return page(request, "_preview.html", items=items, error=error, live=True)

    def parser_decision(pid: str, status: str) -> Response:
        url = "/ui/parser?" + urlencode({"id": pid})
        try:
            with lock:
                r = service.set_parser_status(store, settings, pid, status)
        except service.ActionError as exc:
            return back(url, str(exc), "error")
        msg = f"{pid} {status}; Vector configuration regenerated and validated"
        if status == "approved":
            msg += (
                f"; backfill: {r['backfilled']} quarantined lines ingested, "
                f"{r['still_quarantined']} still in quarantine"
            )
        return back(url, msg)

    @router.post("/parser/approve", dependencies=post)
    def parser_approve(id: Annotated[str, Form()]) -> Response:  # noqa: A002
        return parser_decision(id, "approved")

    @router.post("/parser/reject", dependencies=post)
    def parser_reject(id: Annotated[str, Form()]) -> Response:  # noqa: A002
        return parser_decision(id, "rejected")

    # ------------------------------------------------------------------ data

    @router.get("/quarantine", dependencies=auth)
    def quarantine_page(request: Request, source: str = "", raw: bool = False) -> HTMLResponse:
        with lock:
            stats = store.quarantine_stats()
            lines = store.quarantine_sample(source, 50) if source else []
        return page(
            request,
            "quarantine.html",
            stats=stats,
            source=source,
            lines=pseudo_lines(lines, raw),
            raw=raw,
        )

    @router.get("/events", dependencies=auth)
    def events_page(request: Request, source: str = "", limit: int = 50) -> HTMLResponse:
        limit = max(1, min(limit, 500))
        with lock:
            events = store.latest_events(source or None, limit)
            sources = [h["source"] for h in store.hosts("approved")]
        return page(
            request, "events.html", events=events, source=source, sources=sources, limit=limit
        )

    return router


def install(app, settings: Settings, store: Store, lock: threading.RLock) -> None:
    """Mount the UI, its static files and the security headers on the API app."""
    from fastapi.staticfiles import StaticFiles

    app.include_router(create_router(settings, store, lock))
    app.mount("/ui/static", StaticFiles(directory=str(HERE / "static")), name="ui-static")

    @app.exception_handler(_Redirect)
    async def _redirect(_request: Request, exc: _Redirect) -> Response:
        return RedirectResponse(exc.url, status_code=303)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/ui"):
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/", include_in_schema=False)
    def _root() -> Response:
        return RedirectResponse("/ui/", status_code=307)
