import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from privasoc.llm import Endpoint, LLMClient


class FakeOpenAI(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOpenAI.seen.append((self.path, self.headers.get("Authorization"), body))
        answer = {
            "choices": [{"message": {"content": '<think>hmm</think>{"status":"ok","vrl":".a=1"}'}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 5},
        }
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_openai_compatible_call_strips_thinking_and_logs_metadata_only():
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    logged = []
    ep = Endpoint("remote", f"http://127.0.0.1:{srv.server_port}/v1", "m", api_key="k")
    reply = LLMClient(ep, call_log=logged.append).chat(
        [{"role": "user", "content": "parse user-1a2b3c"}], originals={"jdoe"}
    )
    srv.shutdown()
    assert reply.text == '{"status":"ok","vrl":".a=1"}'
    path, auth, body = FakeOpenAI.seen[-1]
    assert path == "/v1/chat/completions" and auth == "Bearer k"
    assert body["response_format"] == {"type": "json_object"}
    assert logged[0]["prompt_tokens"] == 12
    assert "content" not in json.dumps(logged)  # never the prompt itself


def test_local_thinking_off_adds_soft_switch():
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ep = Endpoint("local", f"http://127.0.0.1:{srv.server_port}/v1", "qwen3:8b", think=False)
    LLMClient(ep).chat([{"role": "user", "content": "hi"}], originals=set())
    srv.shutdown()
    assert FakeOpenAI.seen[-1][2]["messages"][-1]["content"].endswith("/no_think")


def test_missing_vector_binary_fails_fast():
    import pytest

    from privasoc.sandbox import Sandbox

    with pytest.raises(RuntimeError, match="PRIVASOC_VECTOR_BIN"):
        Sandbox("/nonexistent/vector").check()


class FakeModels(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/"):  # not an Ollama server
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps({"data": [{"id": "qwen3:8b"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_preflight_check_validates_server_and_model():
    import pytest

    srv = HTTPServer(("127.0.0.1", 0), FakeModels)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/v1"
    LLMClient(Endpoint("local", url, "qwen3:8b")).check()
    with pytest.raises(RuntimeError, match="not served"):
        LLMClient(Endpoint("local", url, "missing:1b")).check()
    srv.shutdown()
    with pytest.raises(RuntimeError, match="unreachable"):
        LLMClient(Endpoint("local", url, "qwen3:8b")).check()


def test_local_no_think_sends_reasoning_effort_none_but_remote_does_not():
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/v1"
    LLMClient(Endpoint("local", url, "m", think=False)).chat(
        [{"role": "user", "content": "x"}], originals=set()
    )
    assert FakeOpenAI.seen[-1][2]["reasoning_effort"] == "none"
    LLMClient(Endpoint("remote", url, "m", think=False)).chat(
        [{"role": "user", "content": "x"}], originals=set()
    )
    srv.shutdown()
    assert "reasoning_effort" not in FakeOpenAI.seen[-1][2]


class FakeOllama(BaseHTTPRequestHandler):
    seen: list = []

    def _send(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        self._send({"data": [{"id": "qwen3:8b"}]} if self.path == "/v1/models" else {"models": []})

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOllama.seen.append((self.path, body))
        self._send(
            {
                "message": {"content": "STATUS: ok"},
                "done_reason": "stop",
                "prompt_eval_count": 8192,
                "eval_count": 3,
            }
        )

    def log_message(self, *args):
        pass


def test_ollama_native_api_sets_context_window_and_detects_truncation():
    """Regression: through /v1, Ollama used a 4096-token window and silently dropped the
    start of long prompts (system prompt included)."""
    srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ep = Endpoint("local", f"http://127.0.0.1:{srv.server_port}/v1", "qwen3:8b", think=False)
    client = LLMClient(ep, num_ctx=8192)
    client.check()
    reply = client.chat([{"role": "user", "content": "x"}], originals=set())
    srv.shutdown()
    path, body = FakeOllama.seen[-1]
    assert path == "/api/chat" and body["options"]["num_ctx"] == 8192 and body["think"] is False
    assert reply.text == "STATUS: ok" and reply.prompt_truncated
