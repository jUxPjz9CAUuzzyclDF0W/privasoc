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
