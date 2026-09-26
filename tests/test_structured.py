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
    assert "lookahead" in text


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


def test_repairs_for_the_mistakes_seen_with_qwen3_8b():
    """Regression: the model's real specs (unnamed date group, greedy prefix, a constant
    written as a group, non-ECS field names, invented constants) are repaired, not rejected."""
    spec_text = r"""
prefix: '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<type>\w+)(?P<extra> .*)?$'
body: extra
timestamp: {group: ts, format: '%Y-%m-%d %H:%M:%S%.3f'}
constants: {event.kind: event, event.type: [dns], network.transport: udp}
fields: {domain: extra, source.ip: src_ip}
shapes:
  - regex: '^cached (?P<name>\S+) is <CNAME>'
    fields: {dns.question.name: name, dns.question.type: CNAME}
  - regex: '^reply (?P<name>\S+) is (?P<ip>\S+)'
    fields: {dns.question.name: name}
"""
    sample = lines()
    spec = structured.load(spec_text, sample)
    text = "\n".join(spec.repairs)
    for expected in (
        "named 1 unnamed group",
        "used prefix group `g1`",
        "kept only the timestamp",
        "dropped `dns.question.type: CNAME`",
        "`domain` is not an ECS field",
        "dropped constant `network.transport: udp`",
        "removed invalid `event.type`",
    ):
        assert expected in text, expected
    assert spec.body == "rest"
    assert not structured.check_lines(spec, [ln for ln in sample if " reply " in ln])


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


@needs_vector
def test_partial_spec_is_proposed_when_it_covers_most_lines(pz):
    """A spec missing a rare shape is still useful: proposed with its coverage, the
    unmatched lines keep going to quarantine. Below the threshold it is not proposed."""
    no_forward = PIHOLE_V6.replace("  - name: forwarded", "  - name: fwd").replace(
        "'^forwarded (?P<name>\\S+) to (?P<upstream>\\S+)$'", "'^never-matches$'"
    )
    answer = f"STATUS: ok\nREASON: r\n```yaml{no_forward}```"
    out = generate(
        "p",
        lines(),
        ScriptedLLM([answer, answer]),
        pz,
        Sandbox(VECTOR),
        k=10,
        mode="structured",
        max_attempts=2,
    )
    assert out.status == "proposed" and out.reason.startswith("partial")
    assert out.report()["spec"] == no_forward.strip() or "never-matches" in out.report()["spec"]
    assert 0.8 <= out.metrics["line_coverage"] < 1 and out.metrics["real_lines_ok"]
    out = generate(
        "p",
        lines(),
        ScriptedLLM([answer, answer]),
        pz,
        Sandbox(VECTOR),
        k=10,
        mode="structured",
        max_attempts=2,
        min_coverage=0.95,
    )
    assert out.status == "needs_escalation"


def test_single_valued_categorisation_fields_are_unwrapped():
    spec = structured.load(
        "constants: {event.kind: [event], event.outcome: [success], event.category: [network]}\n"
        "shapes: [{regex: 'x'}]"
    )
    assert spec.constants == {
        "event.kind": "event",
        "event.outcome": "success",
        "event.category": ["network"],
    }


@needs_vector
def test_non_ip_answers_never_reach_ip_fields():
    """Regression from the first real parser: `dns.resolved_ip: NODATA-IPv6`."""
    spec = structured.load(
        "prefix: '^(?P<ts>\\S+ \\S+) (?P<rest>.*)$'\nbody: rest\n"
        "shapes: [{regex: '^cached (?P<name>\\S+) is (?P<ip>\\S+)', "
        "fields: {dns.question.name: name, dns.resolved_ip: ip}}]"
    )
    vrl = structured.compile_vrl(spec)
    res = Sandbox(VECTOR).run(
        vrl,
        [
            "2026-09-26 14:46:17.289 cached a.home.lan is NODATA-IPv6",
            "2026-09-26 14:46:17.289 cached a.home.lan is 10.1.2.3",
        ],
    )
    assert "resolved_ip" not in res.lines[0].output["dns"]
    assert res.lines[1].output["dns"]["resolved_ip"] == "10.1.2.3"


@needs_vector
def test_held_out_real_lines_catch_a_shape_the_sample_missed(pz):
    """Regression from a real run: 10/10 sample lines passed but `cached x is NODATA-IPv6`
    (same Drain template as the sampled lines) was never matched."""
    src = [
        f"2026-09-26 14:00:{i:02d}.000 cached host{i}.example.com is 10.0.0.{i + 1}"
        for i in range(20)
    ] + ["2026-09-26 14:00:59.000 cached host9.example.com is NODATA-IPv6"]

    def spec(ip_regex):
        return (
            "STATUS: ok\nREASON: r\n```yaml\n"
            "prefix: '^(?P<ts>\\S+ \\S+) (?P<rest>.*)$'\nbody: rest\n"
            f"shapes: [{{regex: '^cached (?P<name>\\S+) is (?P<ip>{ip_regex})$', "
            "fields: {dns.question.name: name, dns.resolved_ip: ip}}]\n```"
        )

    llm = ScriptedLLM([spec("[0-9.]+"), spec("\\S+")])
    out = generate("p", src, llm, pz, Sandbox(VECTOR), k=10, mode="structured")
    assert [a.error_class for a in out.attempts] == ["coverage", None]
    assert "NODATA-IPv6" in llm.sent[-1]  # the model was shown the missed line
    assert "host9.example.com" not in llm.sent[-1]  # ... pseudonymised
    assert out.status == "proposed" and out.metrics["line_coverage"] == 1.0


@needs_vector
def test_ip_field_from_a_prefix_group_compiles():
    """Regression (reference nginx spec): a prefix group is a plain string, so the IP guard
    `string(x) ?? ""` was an unnecessary coalescing error (E651)."""
    spec = structured.load(
        "prefix: '^(?P<client>\\S+) (?P<rest>.*)$'\nbody: rest\n"
        "fields: {source.ip: client}\nshapes: [{regex: '^(?P<t>.*)$'}]"
    )
    res = Sandbox(VECTOR).run(structured.compile_vrl(spec), ["10.1.2.3 GET /", "web-01 GET /"])
    assert res.lines[0].output["source"]["ip"] == "10.1.2.3"
    assert "source" not in res.lines[1].output


def test_timestamp_converted_to_utc_is_still_grounded():
    from privasoc.grounding import ungrounded

    raw = '1.2.3.4 - - [25/Oct/2016:14:49:33 +0200] "GET / HTTP/1.1" 200 612'
    assert ungrounded({"@timestamp": "2016-10-25T12:49:33Z"}, raw) == []
    assert ungrounded({"@timestamp": "2016-10-25T12:50:00Z"}, raw) != []


@needs_vector
def test_kv_section_parses_key_value_formats():
    """Check Point-style `key:"value"; ...` and firewall `key=value` formats: the model
    maps keys instead of writing one regex per shape (the 8B model gave up on these)."""
    spec = structured.load(
        "prefix: '^(?P<ts>\\S+) (?P<host>\\S+) \\[(?P<rest>.*)\\]$'\nbody: rest\n"
        "kv: {field_delimiter: '; ', value_delimiter: ':', fields: "
        "{source.ip: src, destination.port: service, event.action: action, vendor: x}}"
    )
    assert any("dropped `vendor`" in r for r in spec.repairs)
    vrl = structured.compile_vrl(spec)
    lines = [
        '2020-03-29T13:19:20Z gw [action:"Accept"; src:"10.1.1.1"; service:"443"]',
        '2020-03-29T13:19:21Z gw [action:"Drop"; i/f_dir:"in"]',
    ]
    res = Sandbox(VECTOR).run(vrl, lines)
    a, b = res.lines[0].output, res.lines[1].output
    assert a["source"]["ip"] == "10.1.1.1" and a["destination"]["port"] == 443
    assert b["event"]["action"] == "Drop" and "source" not in b
    assert structured.check_lines(spec, lines) == []


@needs_vector
def test_prompt_kv_example_is_valid():
    text = prompts.STRUCTURED_SYSTEM
    part = text[text.index("Key=value example") :]
    line = re.search(r"^line: (.*)$", part, re.M).group(1)
    spec = re.search(r"```yaml\n(.*?)```", part, re.S).group(1)
    err, details, _ = evaluate(
        Sandbox(VECTOR), structured.compile_vrl(structured.load(spec)), [line]
    )
    assert err is None, details


@needs_vector
def test_network_transport_numbers_become_names():
    spec = structured.load(
        "kv: {field_delimiter: ' ', value_delimiter: '=', fields: {network.transport: proto}}"
    )
    res = Sandbox(VECTOR).run(structured.compile_vrl(spec), ["proto=6 a=1", "proto=UDP a=2"])
    assert res.lines[0].output["network"]["transport"] == "tcp"
    assert res.lines[1].output["network"]["transport"] == "udp"
    from privasoc.grounding import ungrounded

    assert ungrounded(res.lines[0].output, "proto=6 a=1") == []
