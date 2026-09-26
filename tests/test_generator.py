"""Parser-generation loop, with a scripted LLM and the real Vector VRL runtime."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from privasoc import vectorgen
from privasoc.generator import generate
from privasoc.llm import Endpoint, LeakError, LLMClient, Reply
from privasoc.sandbox import Sandbox

VECTOR = os.environ.get("PRIVASOC_VECTOR_BIN") or shutil.which("vector")
needs_vector = pytest.mark.skipif(not VECTOR, reason="vector binary not available")
EXAMPLES = Path(__file__).parent.parent / "examples"

GOOD = r"""
p = parse_regex!(.message, r'^(?P<ts>\w{3} +\d+ [\d:]+) (?P<proc>\w+)\[(?P<pid>\d+)\]: (?P<rest>.*)$')
.@timestamp = parse_timestamp!(format_timestamp!(now(), format: "%Y") + " " + p.ts, format: "%Y %b %d %H:%M:%S")
.process.name = p.proc
.process.pid = to_int!(p.pid)
.event.kind = "event"
.event.category = ["network"]
q = parse_regex(p.rest, r'^query\[(?P<t>\w+)\] (?P<name>\S+) from (?P<ip>\S+)$') ?? {}
if exists(q.name) {
  .dns.question.name = q.name
  .dns.question.type = q.t
  .source.ip = q.ip
}
"""
HALLUCINATING = GOOD + '\n.host.name = "dns-server-01"\n'
BROKEN = ".x = parse_regex!(.message"


class ScriptedLLM(LLMClient):
    """Returns canned answers and records every prompt it was asked to send."""

    def __init__(self, answers):
        super().__init__(Endpoint("local", "http://fake", "scripted"))
        self.answers = list(answers)
        self.sent = []

    def chat(self, messages, *, originals, json_mode=True, temperature=0.2):
        from privasoc.pseudo import Pseudonymizer

        text = "\n".join(m["content"] for m in messages)
        if Pseudonymizer.leaks(text, originals):
            raise LeakError("leak")
        self.sent.append(text)
        return Reply(self.answers.pop(0), 0.01)


def ok(vrl, status="ok"):
    return json.dumps({"status": status, "reason": "r", "vrl": vrl})


@pytest.fixture
def lines():
    return (EXAMPLES / "pihole.log").read_text().splitlines()


@needs_vector
def test_loop_recovers_from_compile_error_and_hallucination(pz, lines):
    llm = ScriptedLLM([ok(BROKEN), ok(HALLUCINATING), ok(GOOD)])
    out = generate("file:pihole.log", lines, llm, pz, Sandbox(VECTOR), k=10, mode="vrl")
    assert [a.error_class for a in out.attempts] == ["compile", "ungrounded", None]
    assert out.status == "proposed" and out.vrl == GOOD
    assert out.metrics["real_lines_ok"] is True  # written on pseudonyms, works on real data
    assert out.preview and out.preview[0]["raw"] == lines[0]
    # Nothing identifying ever left: sample IPs/domains were pseudonymised in every prompt.
    for prompt in llm.sent:
        assert "192.168.1." not in prompt and "updates.example.org" not in prompt


@needs_vector
def test_stagnation_escalates(pz, lines):
    llm = ScriptedLLM([ok(HALLUCINATING), ok(HALLUCINATING)])
    out = generate("s", lines, llm, pz, Sandbox(VECTOR), k=10, mode="vrl")
    assert out.status == "needs_escalation" and "stagnation" in out.reason


def test_model_admitting_limit_escalates(pz, lines):
    llm = ScriptedLLM([ok("", status="cannot_parse")])
    out = generate("s", lines, llm, pz, Sandbox("unused"), k=5, mode="vrl")
    assert out.status == "needs_escalation" and len(out.attempts) == 1


@needs_vector
def test_sandbox_blocks_environment_access():
    res = Sandbox(VECTOR).run('.x = get_env_var!("HOME")', ["a"])
    assert res.compile_error and "forbidden" in res.compile_error


def test_llm_client_refuses_to_send_originals():
    llm = LLMClient(Endpoint("remote", "http://unused", "m"))
    with pytest.raises(LeakError):
        llm.chat([{"role": "user", "content": "host 192.168.1.5"}], originals={"192.168.1.5"})


@needs_vector
def test_generated_vector_pipeline_is_valid(tmp_path):
    root = Path(__file__).parent.parent / "vector"
    shutil.copy(root / "vector.yaml", tmp_path / "vector.yaml")
    vectorgen.write([{"id": "abc123", "source": "file:pihole.log", "vrl": GOOD}], tmp_path)
    (tmp_path / "inbox").mkdir()
    env = {
        **os.environ,
        "PRIVASOC_API_TOKEN": "x",
        "VECTOR_DATA_DIR": str(tmp_path),
        "PRIVASOC_INBOX": str(tmp_path / "inbox"),
    }
    proc = subprocess.run(  # noqa: S603
        [VECTOR, "validate", "--skip-healthchecks", "--config-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_timeout_escalates_cleanly(pz, lines):
    import httpx

    class SlowLLM(ScriptedLLM):
        def chat(self, messages, **kw):
            raise httpx.ReadTimeout("timed out")

    llm = SlowLLM([])
    llm.timeout = 1
    out = generate("s", lines, llm, pz, Sandbox("unused"), k=5, mode="vrl")
    assert out.status == "needs_escalation" and "too slow" in out.reason


def test_answer_formats():
    from privasoc.generator import _parse_answer

    fenced = "STATUS: ok\nREASON: dnsmasq lines\n```vrl\n.a = parse_regex!(.message, r'\\d+')\n```"
    ans, problem = _parse_answer(fenced)
    assert problem == "" and ans["vrl"] == ".a = parse_regex!(.message, r'\\d+')"
    ans, _ = _parse_answer("STATUS: cannot_parse\nREASON: binary data")
    assert ans["status"] == "cannot_parse"
    # the failure seen with small models: a regex inside a JSON string
    ans, problem = _parse_answer('{"status": "ok", "vrl": "parse_regex!(.message, r\'\\d+\')"}')
    assert ans is None and "invalid JSON" in problem


@needs_vector
def test_fenced_answer_goes_through_the_loop(pz, lines):
    llm = ScriptedLLM([f"STATUS: ok\nREASON: r\n```vrl\n{GOOD}\n```"])
    out = generate("s", lines, llm, pz, Sandbox(VECTOR), k=10, mode="vrl")
    assert out.status == "proposed"


def test_truncated_answer_gets_specific_feedback(pz, lines):
    class Truncating(ScriptedLLM):
        def chat(self, messages, **kw):
            self.sent.append(messages[-1]["content"])
            return Reply("STATUS: ok\n```vrl\n.a = 1", 0.1, finish_reason="length")

    llm = Truncating([])
    out = generate("s", lines, llm, pz, Sandbox("unused"), k=5, max_attempts=2, mode="vrl")
    assert out.attempts[0].error_class == "format"
    assert "cut off" in llm.sent[-1]


def test_feedback_gives_hint_and_numbered_program():
    from privasoc import prompts

    fb = prompts.parser_feedback(
        "compile",
        ["error[E701]: call to undefined variable"],
        "parse_regex!(.message, r'x')\nif exists(p.ts) {}",
    )
    assert "Assign first" in fb and "  2 | if exists(p.ts) {}" in fb


def test_different_compile_errors_are_progress_not_stagnation():
    from privasoc.generator import _signature

    assert _signature("compile", ["error[E701]: x"]) != _signature("compile", ["error[E103]: y"])
    assert _signature("compile", ["error[E701]: p"]) == _signature("compile", ["error[E701]: q"])


@needs_vector
def test_prompt_example_is_itself_a_valid_parser():
    """The worked example in the system prompt must pass our own checks."""
    import re

    from privasoc import prompts
    from privasoc.generator import evaluate

    line = re.search(r"^line: (.*)$", prompts.PARSER_SYSTEM, re.M).group(1)
    vrl = re.search(r"```vrl\n(.*?)```", prompts.PARSER_SYSTEM, re.S).group(1)
    err, details, _ = evaluate(Sandbox(VECTOR), vrl, [line])
    assert err is None, details


@needs_vector
def test_config_loads_with_windows_style_paths(tmp_path, monkeypatch):
    """Regression: a Windows temp path (C:\\Users\\...) interpolated into a double-quoted
    YAML string broke `parsers reject` ("expected hexadecimal number")."""
    shutil.copy(Path(__file__).parent.parent / "vector" / "vector.yaml", tmp_path)
    vectorgen.write([], tmp_path)
    monkeypatch.setenv("PRIVASOC_INBOX", r"C:\Users\someone\AppData\Local\Temp\x")
    env = {**os.environ, "PRIVASOC_API_TOKEN": "x", "VECTOR_DATA_DIR": str(tmp_path)}
    proc = subprocess.run(  # noqa: S603
        [
            VECTOR,
            "validate",
            "--skip-healthchecks",
            "--no-environment",
            "--config-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_originals_that_are_our_own_vocabulary_do_not_block_feedback():
    """Regression (cisco_asa eval): user `admin` blocked feedback listing the ECS
    event.type value `admin`."""
    from privasoc.generator import _guarded

    assert _guarded({"admin", "jdoe", "10.1.2.3"}) == {"jdoe", "10.1.2.3"}
    assert _guarded({"Hostname"}) == set()  # part of `host.hostname` in the prompt


def test_leak_guard_ends_the_run_cleanly(pz, lines):
    class Blocking(ScriptedLLM):
        def chat(self, messages, **kw):
            raise LeakError("1 original value(s) in the prompt; refusing to send")

    out = generate("s", lines, Blocking([]), pz, Sandbox("unused"), k=5, mode="vrl")
    assert out.status == "failed" and out.attempts[0].error_class == "leak_blocked"
