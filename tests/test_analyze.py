import re

from privasoc import analyze, structured


def test_detects_rfc5424_header_and_semicolon_kv():
    lines = [
        f'<134>1 2020-03-29T13:19:2{i}Z gw-1 CheckPoint 1930 - [action:"Accept"; '
        f'src:"10.0.0.{i}"; dst:"10.9.9.9"; service:"443"]'
        for i in range(5)
    ]
    st = analyze.detect(lines)
    assert st.header == "syslog RFC 5424" and st.kv == (":", "; ")
    assert {k for k, _ in st.keys} >= {"action", "src", "dst", "service"}
    assert "kv" in st.describe() and "field_delimiter: '; '" in st.describe()


def test_detects_common_log_format_and_syslog_with_year():
    clf = ['1.2.3.4 - bob [25/Oct/2016:14:49:33 +0200] "GET / HTTP/1.1" 200 612'] * 3
    assert analyze.detect(clf).timestamp_format == "%d/%b/%Y:%H:%M:%S %z"
    asa = ["Oct 20 2019 15:15:15 dev01: %ASA-5-106100: x"] * 3
    assert analyze.detect(asa).timestamp_format == "%b %d %Y %H:%M:%S"


def test_model_prefix_replaced_by_detected_header():
    lines = ["Feb 21 21:54:44 host-1 sshd[3402]: Accepted password for u from 10.0.0.1 port 1"] * 3
    st = analyze.detect(lines)
    spec = structured.load(
        "prefix: '^(?P<ts>\\d{4}-\\d\\d) (?P<rest>.*)$'\nbody: rest\n"
        "shapes: [{regex: '^Accepted \\w+ for (?P<u>\\S+)', fields: {user.name: u}}]",
        lines,
        st,
    )
    assert any("replaced by the detected" in r for r in spec.repairs)
    assert structured.check_lines(spec, lines) == []
    assert re.search("sshd", "sshd")


def test_kv_lines_prefix_and_misplaced_mappings_are_repaired():
    """Regression (FortiGate, qwen3:8b): prefix regex over the pairs, ECS mappings to kv
    keys under `fields`, and a kv mapping written key: ecs."""
    lines = [
        f'date=2020-09-28 time=15:36:2{i} logid="0114" type="event" srcip=10.0.0.{i} '
        f"dstip=10.9.9.9 dstport={i}443"
        for i in range(6)
    ]
    lines += ['date=2021-01-26 time=15:51:37 type="traffic" level="notice" srcip=10.1.1.1']
    st = analyze.detect(lines)
    spec = structured.load(
        "prefix: '^date=(?P<d>\\S+) time=(?P<t>\\S+) logid=\"(?P<logid>\\d+)\" (?P<rest>.*)$'\n"
        "body: rest\nfields: {source.ip: srcip, destination.port: dstport}\n"
        "kv: {field_delimiter: ' ', value_delimiter: '=', fields: {dstip: destination.ip}}",
        lines,
        st,
    )
    text = "\n".join(spec.repairs)
    assert "prefix: removed" in text and "moved `source.ip: srcip`" in text and "swapped" in text
    assert spec.kv["fields"] == {
        "source.ip": "srcip",
        "destination.port": "dstport",
        "destination.ip": "dstip",
    }
    assert structured.check_lines(spec, lines) == []


def test_identity_kv_mapping_uses_standard_ecs_hint():
    """Regression (Check Point, qwen3:8b): kv.fields listed `src: src`, `dst: dst`..."""
    lines = [f'[src:"10.0.0.{i}"; dst:"10.9.9.9"; s_port:"5{i}"; flags:"1"]' for i in range(5)]
    st = analyze.detect(lines)
    spec = structured.load(
        "kv: {field_delimiter: '; ', value_delimiter: ':', "
        "fields: {src: src, dst: dst, s_port: s_port, flags: flags}}",
        lines,
        st,
    )
    assert spec.kv["fields"] == {
        "source.ip": "src",
        "destination.ip": "dst",
        "source.port": "s_port",
    }


def test_kv_spec_tolerates_lines_without_the_header():
    """Regression (SonicWall held-out lines): some lines have no syslog header."""
    import os
    import shutil

    import pytest

    from privasoc.sandbox import Sandbox

    vector = os.environ.get("PRIVASOC_VECTOR_BIN") or shutil.which("vector")
    if not vector:
        pytest.skip("vector binary not available")
    spec = structured.load(
        "prefix: '^(?P<ts>[A-Z][a-z]{2} +\\d+ [\\d:]+) (?P<host>\\S+) (?P<rest>.*)$'\n"
        "body: rest\ntimestamp: {group: ts, format: '%b %d %H:%M:%S'}\n"
        "fields: {host.hostname: host}\n"
        "kv: {field_delimiter: ' ', value_delimiter: '=', fields: {destination.ip: dst}}"
    )
    lines = [
        "Jan  3 13:45:50 fw01 id=firewall dst=10.9.9.9 pri=1",
        "id=firewall sn=X dst=10.8.8.8 pri=5",
    ]
    res = Sandbox(vector).run(structured.compile_vrl(spec), lines)
    assert res.lines[0].output["host"]["hostname"] == "fw01" and "@timestamp" in res.lines[0].output
    assert res.lines[1].output["destination"]["ip"] == "10.8.8.8"
    assert structured.check_lines(spec, lines) == []
