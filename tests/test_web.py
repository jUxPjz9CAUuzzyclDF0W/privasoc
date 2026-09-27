"""Step 4: review web UI (access, CSRF, headers, and the D45 decisions through the browser)."""

import re
import shutil
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from privasoc.api import create_app
from privasoc.config import Settings
from privasoc.store import Record, Store
from tests.test_generator import GOOD, VECTOR
from tests.test_onboarding import COMBINED

ROOT = Path(__file__).parent.parent
TOKEN = "ui-test-token"  # noqa: S105 - test value
needs_vector = pytest.mark.skipif(not VECTOR, reason="vector binary not available")
PIHOLE = (ROOT / "examples" / "pihole.log").read_text().splitlines()


def make(tmp_path, **extra):
    shutil.copy(ROOT / "vector" / "vector.yaml", tmp_path / "vector.yaml")
    s = Settings(
        api_token=SecretStr(TOKEN),
        hmac_key=SecretStr("h" * 32),
        vault_key=SecretStr(Fernet.generate_key().decode()),
        data_dir=tmp_path,
        **{"vector_bin": VECTOR or "vector", "vector_dir": tmp_path, **extra},
    )
    store = Store(s.db_path)
    return TestClient(create_app(s, store), follow_redirects=False), store


def login(c):
    r = c.post("/ui/login", data={"access_token": TOKEN, "next": "/ui/hosts"})
    assert r.status_code == 303 and r.headers["location"] == "/ui/hosts"
    return r


def csrf(c, url="/ui/"):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(url).text).group(1)


def test_pages_require_login_and_the_cookie_is_not_the_token(tmp_path):
    c, _ = make(tmp_path)
    r = c.get("/ui/parsers")
    assert r.status_code == 303 and r.headers["location"].startswith("/ui/login?next=")
    bad = c.post("/ui/login", data={"access_token": "nope"})
    assert "wrong token" in bad.text and "privasoc_session" not in bad.headers.get("set-cookie", "")
    cookie = login(c).headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and TOKEN not in cookie
    assert c.get("/ui/parsers").status_code == 200


def test_login_does_not_redirect_off_site(tmp_path):
    c, _ = make(tmp_path)
    for target in ("//evil.example/x", "https://evil.example/", "/ui/..\\x"):
        r = c.post("/ui/login", data={"access_token": TOKEN, "next": target})
        assert r.headers["location"] == "/ui/"


def test_security_headers_and_vendored_assets(tmp_path):
    c, _ = make(tmp_path)
    login(c)
    r = c.get("/ui/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert "http" not in re.sub(r'href="/|src="/', "", r.text.split("<body>")[0])  # no CDN
    assert c.get("/ui/static/htmx.min.js").status_code == 200


def test_post_without_csrf_is_refused(tmp_path):
    c, store = make(tmp_path)
    store.ingest([Record("syslog:10.0.0.9", "x")])
    login(c)
    r = c.post("/ui/host/reject", data={"source": "syslog:10.0.0.9"})
    assert r.status_code == 403
    assert store.host("syslog:10.0.0.9")["status"] == "pending"


def test_pending_host_is_shown_pseudonymised_and_can_be_rejected(tmp_path):
    c, store = make(tmp_path)
    line = (
        "Sep 26 10:00:02 dnsmasq[812]: query[A] a.example.org from 192.168.1.57 <script>x</script>"
    )
    store.ingest([Record("syslog:10.0.0.9", line)])
    login(c)
    dash = c.get("/ui/").text
    assert "syslog:10.0.0.9" in dash and "hosts waiting for approval" in dash
    page = c.get("/ui/host", params={"source": "syslog:10.0.0.9"}).text
    assert "192.168.1.57" not in page  # pseudonymised by default
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page  # escaped
    raw = c.get("/ui/host", params={"source": "syslog:10.0.0.9", "raw": 1}).text
    assert "192.168.1.57" in raw
    token = csrf(c)
    r = c.post("/ui/host/reject", data={"source": "syslog:10.0.0.9", "csrf": token})
    assert r.status_code == 303 and "rejected" in r.headers["location"]
    assert store.host("syslog:10.0.0.9")["status"] == "rejected"
    assert store.summary()["held"] == 0


def test_thresholds_form_validates(tmp_path):
    c, store = make(tmp_path)
    store.ingest([Record("fw", "x")], auto_approve=True)
    login(c)
    token = csrf(c)
    r = c.post(
        "/ui/host/thresholds",
        data={"source": "fw", "csrf": token, "silence_min_minutes": "30", "parse_warning": ""},
    )
    assert r.status_code == 303 and store.host("fw")["thresholds"] == {"silence_min_minutes": 30}
    r = c.post("/ui/host/thresholds", data={"source": "fw", "csrf": token, "volume_drop": "a"})
    assert "level=error" in r.headers["location"]


@needs_vector
def test_approving_a_known_format_ingests_and_shows_events(tmp_path):
    c, store = make(tmp_path)
    store.ingest([Record("web01", ln) for ln in COMBINED])
    login(c)
    r = c.post("/ui/host/approve", data={"source": "web01", "csrf": csrf(c)})
    assert r.status_code == 303 and "apache_combined" in r.headers["location"]
    assert store.host("web01")["format"] == "builtin:apache_combined"
    events = c.get("/ui/events", params={"source": "web01"}).text
    assert "10.1.1.0" in events and events.count("<details>") == len(COMBINED)
    assert "health" in c.get("/ui/hosts").text.lower()


@needs_vector
def test_review_try_and_approve_a_proposed_parser(tmp_path):
    c, store = make(tmp_path)
    store.ingest([Record("pihole", ln) for ln in PIHOLE], auto_approve=True)
    store.save_parser("p1", "pihole", "proposed", "local", "fake", GOOD, {"reason": "r"})
    login(c)
    page = c.get("/ui/parser", params={"id": "p1"}).text
    assert "Approve and deploy" in page and "parse_regex" in page
    live = c.get("/ui/parser/try", params={"id": "p1"}).text
    assert "parsed" in live and "dns" in live
    r = c.post("/ui/parser/approve", data={"id": "p1", "csrf": csrf(c)})
    assert r.status_code == 303 and "backfill" in r.headers["location"]
    assert store.parser("p1")["status"] == "approved"
    assert (tmp_path / "pipeline.yaml").exists()
    assert store.summary()["events"] > 0
    # approving twice is refused with a message, not a crash
    r = c.post("/ui/parser/approve", data={"id": "p1", "csrf": csrf(c)})
    assert "level=error" in r.headers["location"]


@needs_vector
def test_propose_runs_as_a_background_job(tmp_path):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Server(BaseHTTPRequestHandler):
        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path.startswith("/api/"):
                self.send_response(404)
                self.end_headers()
                return
            self._send({"data": [{"id": "fake:1b"}]})

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            answer = json.dumps({"status": "ok", "reason": "r", "vrl": GOOD})
            self._send({"choices": [{"message": {"content": answer}}]})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c, store = make(
            tmp_path,
            llm_local_url=f"http://127.0.0.1:{srv.server_port}/v1",
            llm_local_model="fake:1b",
            parser_mode="vrl",
        )
        store.ingest([Record("pihole", ln) for ln in PIHOLE], auto_approve=True)
        login(c)
        r = c.post("/ui/host/propose", data={"source": "pihole", "csrf": csrf(c), "mode": "vrl"})
        assert r.status_code == 303
        job_id = r.headers["location"].split("id=")[1]
        for _ in range(120):
            frag = c.get("/ui/job/fragment", params={"id": job_id}).text
            if "hx-trigger" not in frag:
                break
            time.sleep(0.5)
        assert "proposed" in frag and "attempt 1: ok" in frag
        assert store.parsers("proposed")
    finally:
        srv.shutdown()


def test_api_still_works_with_the_bearer_token(tmp_path):
    c, store = make(tmp_path)
    r = c.post(
        "/ingest",
        content=b'{"message": "hello", "privasoc_source": "s1"}',
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert r.status_code == 200 and r.json()["held"] == 1
    assert c.get("/ui/").status_code == 303  # the bearer header does not open the UI


def test_missing_vector_is_reported_not_a_crash(tmp_path):
    c, store = make(tmp_path, vector_bin=str(tmp_path / "no-vector"))
    store.ingest([Record("pihole", PIHOLE[0])], auto_approve=True)
    store.save_parser("p1", "pihole", "proposed", "local", "fake", GOOD, {"reason": "r"})
    login(c)
    r = c.get("/ui/parser/try", params={"id": "p1"})
    assert r.status_code == 200 and "Vector could not run" in r.text
    r = c.post("/ui/parser/approve", data={"id": "p1", "csrf": csrf(c)})
    assert r.status_code == 303 and "level=error" in r.headers["location"]
    assert store.parser("p1")["status"] == "proposed"  # rolled back


def test_pseudonymisation_rules_page(tmp_path):
    c, store = make(tmp_path)
    store.ingest([Record("nas", "backup finished on nas-cave for carol")], auto_approve=True)
    login(c)
    assert "Ask the local model" in c.get("/ui/rules").text
    r = c.post(
        "/ui/rules/add",
        data={"rtype": "value", "kind": "host", "pattern": "nas-cave", "csrf": csrf(c)},
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/ui/rule?id=")
    rid = r.headers["location"].split("id=")[1].split("&")[0]
    page = c.get("/ui/rule", params={"id": rid}).text
    assert "of 1 lines changed" in page and "nas-cave" in page
    r = c.post("/ui/rule/approve", data={"id": rid, "csrf": csrf(c)})
    assert "approved" in r.headers["location"]
    q = c.get("/ui/quarantine", params={"source": "nas"}).text
    assert "nas-cave" not in q  # the approved rule now applies to the display too
    bad = c.post(
        "/ui/rules/add", data={"rtype": "key", "kind": "user", "pattern": "msg", "csrf": csrf(c)}
    )
    assert "level=error" in bad.headers["location"]
