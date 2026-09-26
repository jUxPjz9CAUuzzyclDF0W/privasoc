from typer.testing import CliRunner

from privasoc.cli import app


def test_init_generates_secrets_and_merges_new_settings(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("PRIVASOC_API_TOKEN=\nPRIVASOC_VECTOR_BIN=vector\n")
    env = tmp_path / ".env"
    env.write_text("PRIVASOC_API_TOKEN=\n")  # an .env created by an older version
    r = CliRunner().invoke(app, ["init", "--env-file", str(env), "--example", str(example)])
    assert r.exit_code == 0, r.output
    text = env.read_text()
    assert "PRIVASOC_VECTOR_BIN=vector" in text
    token = [ln for ln in text.splitlines() if ln.startswith("PRIVASOC_API_TOKEN=")][0]
    assert len(token) > len("PRIVASOC_API_TOKEN=") + 20
    assert token.split("=", 1)[1] not in r.output  # secrets are never printed


def test_propose_end_to_end_with_openai_compatible_server(tmp_path, monkeypatch):
    """Wiring test: CLI -> preflight -> LLM over HTTP -> sandbox -> stored proposal."""
    import json
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from pathlib import Path

    import pytest
    from cryptography.fernet import Fernet

    from privasoc.config import get_settings
    from tests.test_generator import GOOD, VECTOR

    if not VECTOR:
        pytest.skip("vector binary not available")

    class Server(BaseHTTPRequestHandler):
        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            self._send({"data": [{"id": "fake:1b"}]})

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            answer = json.dumps({"status": "ok", "reason": "r", "vrl": GOOD})
            self._send({"choices": [{"message": {"content": answer}}]})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = {
        "PRIVASOC_API_TOKEN": "t",
        "PRIVASOC_HMAC_KEY": "h",
        "PRIVASOC_VAULT_KEY": Fernet.generate_key().decode(),
        "PRIVASOC_DATA_DIR": str(tmp_path),
        "PRIVASOC_VECTOR_BIN": VECTOR,
        "PRIVASOC_VECTOR_DIR": str(tmp_path),
        "PRIVASOC_LLM_LOCAL_URL": f"http://127.0.0.1:{srv.server_port}/v1",
        "PRIVASOC_LLM_LOCAL_MODEL": "fake:1b",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    runner = CliRunner()
    sample = Path(__file__).parent.parent / "examples" / "pihole.log"
    assert runner.invoke(app, ["import", str(sample), "--source", "pihole"]).exit_code == 0
    r = runner.invoke(app, ["propose", "--source", "pihole"])
    srv.shutdown()
    get_settings.cache_clear()
    assert r.exit_code == 0, r.output
    assert "proposed" in r.output and "attempt 1: ok" in r.output
    assert os.path.exists(tmp_path / "privasoc.db")
