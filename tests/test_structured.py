"""Structured mode: spec validation, Python dry-run, compiler, and the real VRL runtime."""

import re
import shutil
from pathlib import Path

import pytest

from privasoc import prompts, structured, vectorgen
from privasoc.generator import evaluate, generate
from privasoc.sandbox import Sandbox
from tests.test_generator import VECTOR, ScriptedLLM, needs_vector

EXAMPLES = Path(__file__).parent.parent / "examples"

PIHOLE_V6 = r"""
prefix: '^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<rest>.*)$'
body: rest
timestamp: {group: ts, format: '%Y-%m-%d %H:%M:%S%.3f'}
constants: {event.kind: event, event.category: [network], observer.product: pihole}
shapes:
  - name: query
    regex: '^query\[(?P<qtype>\w+)\] (?P<name>\S+) from (?P<client>\S+)$'
    fields: {dns.question.type: qtype, dns.question.name: name, source.ip: client}
    constants: {event.action: query}
  - name: forwarded
    regex: '^forwarded (?P<name>\S+) to (?P<upstream>\S+)$'
    fields: {dns.question.name: name, destination.ip: upstream}
  - name: answer
    regex: '^(?P<action>.+?) (?P<name>\S+) is (?P<answer>\S+)$'
    fields: {event.action: action, dns.question.name: name}
"""


def lines():
    return (EXAMPLES / "pihole-v6.log").read_text().splitlines()


def test_spec_errors_are_precise():
    bad = "prefix: '(?P<a>x)(?=y)'\nshapes: [{regex: '(?P<b>z)', fields: {user.name: nope}}]"
    with pytest.raises(structured.SpecError) as e:
        structured.load(bad)
    text = " ".join(e.value.problems)
    assert "lookahead" in text and "`nope`" in text


def test_python_dry_run_reports_unmatched_lines():
    only_queries = PIHOLE_V6.split("  - name: forwarded")[0]
    problems = structured.check_lines(structured.load(only_queries), lines()[:20])
    assert problems and "no shape matches" in problems[0]


@needs_vector
def test_compiled_spec_parses_every_line_with_grounded_values():
    vrl = structured.compile_vrl(structured.load(PIHOLE_V6))
    err, details, metrics = evaluate(Sandbox(VECTOR), vrl, lines())
    assert err is None, details
    assert metrics["parsed"] == len(lines()) and metrics["ungrounded_values"] == 0


@needs_vector
def test_line_matching_no_shape_is_rejected_not_silently_passed():
    vrl = structured.compile_vrl(structured.load(PIHOLE_V6))
    res = Sandbox(VECTOR).run(vrl, ["2026-09-26 14:00:00.000 something else entirely"])
    assert res.lines[0].error and "no known shape" in res.lines[0].error


@needs_vector
def test_prompt_example_spec_is_valid():
    text = prompts.STRUCTURED_SYSTEM
    example_lines = re.search(r"^lines:\n(.*?)\nSTATUS", text, re.S | re.M).group(1).splitlines()
    spec = re.search(r"```yaml\n(.*?)```", text, re.S).group(1)
    vrl = structured.compile_vrl(structured.load(spec))
    err, details, _ = evaluate(Sandbox(VECTOR), vrl, example_lines)
    assert err is None, details


@needs_vector
def test_structured_loop_end_to_end(pz):
    llm = ScriptedLLM(
        [
            "STATUS: ok\nREASON: r\n```yaml\nprefix: '^(?P<ts>\\S+ \\S+) (?P<rest>.*)$'\n"
            "body: rest\nshapes: [{regex: '^query'}]\n```",  # misses most shapes
            f"STATUS: ok\nREASON: r\n```yaml{PIHOLE_V6}```",
        ]
    )
    out = generate("pihole", lines(), llm, pz, Sandbox(VECTOR), k=10, mode="structured")
    assert [a.error_class for a in out.attempts] == ["spec", None]
    assert "no shape matches" in llm.sent[-1]  # the model saw which lines failed
    assert out.status == "proposed" and out.metrics["real_lines_ok"]
    assert "Write the YAML spec" in llm.sent[0]


@needs_vector
def test_compiled_spec_loads_in_vector(tmp_path):
    shutil.copy(Path(__file__).parent.parent / "vector" / "vector.yaml", tmp_path)
    vrl = structured.compile_vrl(structured.load(PIHOLE_V6))
    vectorgen.write([{"id": "s1", "source": "pihole", "vrl": vrl}], tmp_path)
    assert vectorgen.validate(VECTOR, tmp_path) is None


def test_feedback_on_the_mistakes_seen_with_qwen3_8b():
    """Regression: the first real structured attempt (unnamed ts group, a constant written
    as a group, non-ECS field names, invalid categorisation values)."""
    spec = r"""
prefix: '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<rest>.*)$'
body: rest
timestamp: {group: ts, format: '%Y-%m-%d %H:%M:%S%.3f'}
constants: {event.kind: event, event.category: [dns]}
fields: {domain: rest}
shapes:
  - regex: '^cached (?P<domain>\S+) is <CNAME>'
    fields: {dns.question.name: domain, dns.question.type: CNAME}
    constants: {event.outcome: stale}
"""
    with pytest.raises(structured.SpecError) as e:
        structured.load(spec)
    text = "\n".join(e.value.problems)
    assert "unnamed group" in text
    assert "(?P<ts>...)" in text
    assert "move it to `constants`" in text
    assert "`domain` is not an ECS field" in text
    # categorisation values are repaired rather than rejected (see next tests)


def test_invalid_categorisation_values_are_repaired_and_reported():
    spec = structured.load(
        "prefix: '^(?P<ts>\\S+) (?P<rest>.*)$'\nbody: rest\n"
        "constants: {event.type: [dns, info], event.outcome: blocked}\n"
        "shapes: [{regex: '^q'}]"
    )
    assert spec.constants == {"event.type": ["info"]}
    assert len(spec.repairs) == 2 and "removed invalid `event.outcome`" in spec.repairs[1]


def test_prefix_that_captures_too_much_gets_a_hint():
    spec = structured.load(
        "prefix: '^(?P<ts>\\S+ \\S+) (?P<type>\\w+)(?P<extra> .*)?$'\nbody: extra\n"
        "shapes: [{regex: '^reply (?P<name>\\S+) is (?P<ip>\\S+)'}]"
    )
    problems = structured.check_lines(
        spec, ["2026-09-26 14:43:33.885 reply a.example.com is 1.2.3.4"]
    )
    assert "prefix captures too much" in problems[0]
