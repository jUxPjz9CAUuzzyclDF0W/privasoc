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
