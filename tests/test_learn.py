"""Step 5: learned pseudonymisation rules and the local residual pass."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from privasoc import service
from privasoc.config import Settings
from privasoc.pseudo import Pseudonymizer, Vault
from privasoc.pseudo.learn import (
    LocalOnlyError,
    ensure_local,
    ground,
    parse_answer,
    preview,
    residual_pass,
    to_rules,
)
from privasoc.pseudo.rules import Rule, RuleError, RuleSet, validate
from privasoc.store import Record, Store
from tests.test_generator import VECTOR

LINES = [
    "Sep 26 10:00:01 fw01 kernel: DROP cs1=alice4 src=192.168.1.5 dst=8.8.8.8",
    "Sep 26 10:00:02 fw01 kernel: DROP cs1=bob77 src=192.168.1.6 dst=8.8.4.4",
    "Sep 26 10:00:03 backup job finished on nas-cave for carol",
]


# ------------------------------------------------------------------ rules


@pytest.mark.parametrize(
    ("rtype", "pattern"),
    [
        ("key", "msg"),  # free text
        ("key", "a b"),
        ("regex", "(a+)+"),  # catastrophic backtracking
        ("regex", "(a)(b)"),  # two groups
        ("regex", "x*"),  # matches the empty string
        ("value", "12345"),  # numbers only
        ("value", "root"),  # common word
    ],
)
def test_unsafe_or_useless_rules_are_refused(rtype, pattern):
    with pytest.raises(RuleError):
        validate(rtype, "user", pattern)


def test_key_rule_catches_every_writing_of_the_key():
    rs = RuleSet([Rule("key", "user", "cs1")])
    for text, value in [
        ("cs1=alice4 x", "alice4"),
        ('cs1="Alice Smith" x', "Alice Smith"),
        ('{"cs1": "alice4"}', "alice4"),
        ("CS1: alice4", "alice4"),
    ]:
        assert [v for *_, v in rs.find(text)] == [value], text
    assert rs.find("xcs1=alice4") == []  # another key
    assert rs.find("cs1=-") == []  # placeholder


def test_rules_are_encrypted_and_only_approved_ones_apply(tmp_path, vault):
    rule = Rule("value", "host", "nas-cave", origin="llm")
    assert vault.add_rule(rule) and not vault.add_rule(rule)  # never proposed twice
    assert b"nas-cave" not in (tmp_path / "vault.db").read_bytes()
    assert "nas-cave" in Pseudonymizer(vault).pseudonymize(LINES[2]).text  # proposed only
    vault.set_rule_status(rule.id, "approved")
    out = Pseudonymizer(vault).pseudonymize(LINES[2]).text
    assert "nas-cave" not in out and "host-" in out


def test_key_rule_value_is_propagated_in_the_line(vault):
    vault.add_rule(Rule("key", "user", "cs1", status="approved"))
    out = Pseudonymizer(vault).pseudonymize("cs1=alice4 login by alice4 ok").text
    assert "alice4" not in out and out.count("user-") == 2


# ------------------------------------------------------------------ residual pass


def test_answer_parsing_and_grounding(pz):
    assert parse_answer("```yaml\n- value: bob\n  kind: user\n```") == [("bob", "user")]
    assert parse_answer("- value: [unclosed") == []
    texts = [pz.pseudonymize(ln).text for ln in LINES]
    found = ground(
        [
            ("alice4", "user"),
            ("bob77", "user"),
            ("carol", "user"),
            ("nas-cave", "host"),
            ("dave", "user"),  # invented: not in the lines
            ("192.168.1.5", "host"),  # already pseudonymised, and not a name
            ("kernel", "host"),  # in clear, a program name: left to the human review
        ],
        texts,
    )
    by = {f.value: f for f in found}
    assert "dave" not in by and "192.168.1.5" not in by
    assert by["alice4"].key == "cs1" and by["carol"].key is None
    rules = {r.label() for r in to_rules(found)}
    assert "key cs1=" in rules and "value 'carol'" in rules and "value 'nas-cave'" in rules


def test_residual_pass_refuses_a_public_model():
    ensure_local("http://127.0.0.1:11434/v1")
    ensure_local("http://192.168.50.4:11434")
    ensure_local("http://localhost:11434")
    with pytest.raises(LocalOnlyError):
        ensure_local("https://8.8.8.8/v1")
    llm = SimpleNamespace(endpoint=SimpleNamespace(url="https://1.1.1.1", remote=False))
    with pytest.raises(LocalOnlyError):
        residual_pass(llm, None, LINES)


def test_residual_pass_and_preview_with_a_fake_model(pz):
    class FakeLLM:
        endpoint = SimpleNamespace(url="http://127.0.0.1:1", remote=False, model="fake")

        def chat(self, messages, **kw):
            assert kw["originals"] == set()
            return SimpleNamespace(
                text="- value: alice4\n  kind: user\n- value: nas-cave\n  kind: host"
            )

    found = residual_pass(FakeLLM(), pz, LINES)
    rules = to_rules(found)
    key = next(r for r in rules if r.rtype == "key")
    p = preview(pz, key, LINES)
    assert p["changed"] == 2 and dict(p["values"]) == {"alice4": 1, "bob77": 1}
    assert "alice4" in p["examples"][0]["before"] and "alice4" not in p["examples"][0]["after"]


# ------------------------------------------------------------------ end to end


def _server(answer_for):
    """A fake OpenAI-compatible server that records every prompt it receives."""
    seen = []

    class H(BaseHTTPRequestHandler):
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
            self._send({"data": [{"id": "m"}]})

        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            prompt = "\n".join(m["content"] for m in body["messages"])
            seen.append(prompt)
            self._send({"choices": [{"message": {"content": answer_for(prompt)}}]})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def _settings(tmp_path, **kw):
    return Settings(
        api_token=SecretStr("t"),
        hmac_key=SecretStr("h" * 32),
        vault_key=SecretStr(Fernet.generate_key().decode()),
        data_dir=tmp_path,
        vector_dir=tmp_path,
        **kw,
    )


def test_learn_rules_end_to_end_and_held_hosts_are_refused(tmp_path):
    srv, seen = _server(lambda _p: "```yaml\n- value: carol\n  kind: user\n```")
    try:
        s = _settings(
            tmp_path, llm_local_url=f"http://127.0.0.1:{srv.server_port}/v1", llm_local_model="m"
        )
        store = Store(s.db_path)
        store.ingest([Record("nas", ln) for ln in LINES], auto_approve=True)
        store.ingest([Record("new", "x carol y")])  # pending host
        with pytest.raises(service.ActionError, match="pending"):
            service.learn_rules(store, s, "new")
        out = service.learn_rules(store, s, "nas")
        assert [(r["label"], r["new"]) for r in out] == [("value 'carol'", True)]
        assert out[0]["changed"] == 1
        assert service.learn_rules(store, s, "nas")[0]["new"] is False
        rid = out[0]["id"]
        service.set_rule_status(s, rid, "approved")
        assert service.rule_preview(store, s, rid)["changed"] == 1  # measured without itself
        assert "carol" in seen[0]  # the local model saw the clear value, by design
    finally:
        srv.shutdown()


@pytest.mark.skipif(not VECTOR, reason="vector binary not available")
def test_remote_call_gets_the_local_findings_first(tmp_path):
    """The privacy property of step 5: a value the regexes miss reaches the local model
    but never the remote API."""
    good_vrl = '.event.kind = "event"\n'
    local, local_seen = _server(lambda _p: "- value: carol\n  kind: user")
    remote, remote_seen = _server(
        lambda _p: json.dumps({"status": "ok", "reason": "r", "vrl": good_vrl})
    )
    try:
        s = _settings(
            tmp_path,
            llm_local_url=f"http://127.0.0.1:{local.server_port}/v1",
            llm_local_model="m",
            llm_remote_url=f"http://127.0.0.1:{remote.server_port}/v1",
            llm_remote_model="m",
            parser_mode="vrl",
            max_attempts=1,
            vector_bin=VECTOR,
        )
        store = Store(s.db_path)
        store.ingest([Record("nas", ln) for ln in LINES], auto_approve=True)
        out = service._generate(store, s, "nas", "remote", LINES, "vrl", lambda m: None)
        assert out.provider == "remote" and remote_seen
        assert local_seen and "carol" in local_seen[0]
        assert not any("carol" in p for p in remote_seen)
        assert [r.label() for r in service.list_rules(s, "proposed")] == ["value 'carol'"]
    finally:
        local.shutdown()
        remote.shutdown()


def test_remote_call_is_refused_without_the_local_pass(tmp_path):
    s = _settings(
        tmp_path,
        llm_local_url="http://127.0.0.1:9/v1",
        llm_local_model="m",
        llm_remote_url="http://127.0.0.1:9/v1",
        llm_remote_model="m",
    )
    store = Store(s.db_path)
    with pytest.raises(service.ActionError, match="residual pass unavailable"):
        service._local_residual_rules(store, s, LINES, lambda m: None)


def test_vault_fixture_is_isolated(vault):
    assert isinstance(vault, Vault) and vault.rules() == []


def test_per_line_answers_and_context_rules(pz):
    assert parse_answer("1: testuser (user)\n2: -\n3: core-sw2 (host), `bob` (user)") == [
        ("testuser", "user"),
        ("core-sw2", "host"),
        ("bob", "user"),
    ]
    texts = [pz.pseudonymize("Group sales User testuser IP 10.0.0.1 session ended").text]
    rules = to_rules(ground([("testuser", "user")], texts))
    ctx = next(r for r in rules if r.rtype == "regex")
    validate(ctx.rtype, ctx.kind, ctx.pattern)
    caught = RuleSet([ctx]).find("Group ops User alice IP 10.0.0.2 session ended")
    assert [v for *_, v in caught] == ["alice"]  # a name never seen by the model
