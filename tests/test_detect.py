"""Step 6: Sigma evaluator, correlations, alerts, notifications and AI triage."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet
from pydantic import SecretStr

from privasoc import service
from privasoc.config import Settings
from privasoc.detect import alerts as al
from privasoc.detect import triage
from privasoc.detect.engine import BUILTIN_RULES, Engine, host_alerts
from privasoc.detect.sigma import _compile, load_rules
from privasoc.store import Record, Store
from tests.test_learn import _server


def rule(detection, logsource=None, **kw):
    return _compile(
        {"title": "t", "id": "r1", "logsource": logsource or {"product": "privasoc"},
         "detection": detection, **kw},
        "privasoc",
        "test.yml",
    )  # fmt: skip


DOC = {
    "event": {"original": "sshd[1]: Failed password for bob from 10.0.0.5", "action": "Deny"},
    "process": {"name": "sshd"},
    "source": {"ip": "10.0.0.5", "port": 5555},
    "destination": {"port": 22},
    "dns": {"question": {"name": "a.example.org"}},
    "tags": ["x", "y"],
}


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ({"s": {"process.name": "SSHD"}, "condition": "s"}, True),  # case-insensitive
        ({"s": {"process.name": "ss*"}, "condition": "s"}, True),
        ({"s": {"process.name": "s?hd"}, "condition": "s"}, True),
        ({"s": {"event.original|contains": "failed PASSWORD"}, "condition": "s"}, True),
        ({"s": {"dns.question.name|endswith": ".org"}, "condition": "s"}, True),
        ({"s": {"dns.question.name|startswith": "b."}, "condition": "s"}, False),
        ({"s": {"source.ip|cidr": "10.0.0.0/8"}, "condition": "s"}, True),
        ({"s": {"source.port|gte": 5000}, "condition": "s"}, True),
        ({"s": {"destination.port": 22}, "condition": "s"}, True),
        ({"s": {"tags|all": ["x", "y"]}, "condition": "s"}, True),
        ({"s": {"tags|all": ["x", "z"]}, "condition": "s"}, False),
        ({"s": {"user.name|exists": False}, "condition": "s"}, True),
        ({"s": {"event.original|re": r"for \w+ from"}, "condition": "s"}, True),
        ({"s": ["nothing", "*Failed password*"], "condition": "s"}, True),  # keywords
        (
            {
                "a": {"process.name": "sshd"},
                "b": {"destination.port": 80},
                "condition": "a and not b",
            },
            True,
        ),  # fmt: skip
        (
            {
                "sel_a": {"process.name": "x"},
                "sel_b": {"destination.port": 22},
                "condition": "1 of sel_*",
            },
            True,
        ),  # fmt: skip
        (
            {
                "sel_a": {"process.name": "x"},
                "sel_b": {"destination.port": 22},
                "condition": "all of them",
            },
            False,
        ),  # fmt: skip
        (
            {
                "a": {"process.name": "x"},
                "b": {"destination.port": 22},
                "c": {"source.port": 1},
                "condition": "(a or b) and not c",
            },
            True,
        ),  # fmt: skip
        ({"s": [{"process.name": "x"}, {"source.ip": "10.0.0.5"}], "condition": "s"}, True),
    ],
)
def test_sigma_evaluator(detection, expected):
    r = rule(detection)
    assert r.unsupported is None, r.unsupported
    assert r.match(DOC) is expected


def test_unsupported_rules_say_why():
    assert "modifier base64" in rule({"s": {"a|base64": "x"}, "condition": "s"}).unsupported
    assert "aggregation" in rule({"s": {"a": 1}, "condition": "s | count() > 5"}).unsupported
    dns = {"category": "dns"}
    assert "no ECS mapping" in rule({"s": {"weird": 1}, "condition": "s"}, dns).unsupported
    assert "not normalised" in rule({"s": {"x": 1}, "condition": "s"},
                                    {"category": "process_creation"}).unsupported  # fmt: skip


def test_sigma_taxonomy_is_mapped_to_ecs():
    r = rule({"s": {"query|endswith": ".org"}, "condition": "s"}, {"category": "dns"})
    assert r.applies(DOC) and r.match(DOC)
    assert not r.applies({"source": {"ip": "1.2.3.4"}})  # not a DNS event


def test_bundled_rules_are_all_supported():
    rules = load_rules([(BUILTIN_RULES, "privasoc")])
    assert rules and all(r.unsupported is None for r in rules), [r.unsupported for r in rules]
    eng = Engine(rules)
    assert len(eng.correlations) == 3 and all(c.unsupported is None for c in eng.correlations)


# ------------------------------------------------------------------ engine and alerts

T0 = datetime(2026, 9, 26, 10, 0, tzinfo=UTC)


def ev(i, doc, source="sshbox"):
    ts = (T0 + timedelta(seconds=i)).isoformat()
    return Record(source, doc["event"]["original"], ts, {"@timestamp": ts, **doc}, "p1")


def ssh_fail(ip, n=0):
    return {"event": {"original": f"sshd[9]: Failed password for root from {ip} port {n}"},
            "process": {"name": "sshd"}, "source": {"ip": ip}}  # fmt: skip


def test_ssh_brute_force_correlation_and_dedup(tmp_path):
    store = Store(tmp_path / "d.db")
    eng = Engine(load_rules([(BUILTIN_RULES, "privasoc")]))
    store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(9)], auto_approve=True)
    store.ingest([ev(i, ssh_fail("198.51.100.7", i)) for i in range(3)])
    r = eng.run(store)
    assert r["events"] == 12 and r["new_alerts"] == 0  # 9 < 10: no alert; base rules silent
    store.ingest([ev(20 + i, ssh_fail("203.0.113.9", i)) for i in range(3)])
    assert eng.run(store)["new_alerts"] == 1
    a = al.alerts(store, "open")
    assert len(a) == 1 and a[0]["title"] == "SSH brute force from one source"
    assert a[0]["count"] == 12 and a[0]["detail"]["group"] == {"source.ip": "203.0.113.9"}
    assert len(al.alert_events(store, a[0]["id"])) == 12
    assert eng.run(store)["events"] == 0  # cursor
    store.ingest([ev(40, ssh_fail("203.0.113.9", 99))])
    eng.run(store)
    assert len(al.alerts(store, "open")) == 1 and al.alerts(store)[0]["count"] == 13  # updated


def test_port_scan_counts_distinct_ports(tmp_path):
    store = Store(tmp_path / "d.db")
    eng = Engine(load_rules([(BUILTIN_RULES, "privasoc")]))

    def blocked(i, port):
        return {"event": {"original": f"kernel: DROP IN=eth0 SRC=203.0.113.4 DPT={port}"},
                "source": {"ip": "203.0.113.4"}, "destination": {"port": port}}  # fmt: skip

    store.ingest([ev(i, blocked(i, 22), "fw") for i in range(30)], auto_approve=True)
    assert eng.run(store)["new_alerts"] == 0  # 30 drops, one port
    store.ingest([ev(40 + i, blocked(i, 1000 + i), "fw") for i in range(20)])
    eng.run(store)
    (a,) = al.alerts(store, "open")
    assert a["title"] == "Port scan from one source" and a["detail"]["value"] == 21


def test_host_alerts_and_notifications_leak_nothing(tmp_path):
    store = Store(tmp_path / "d.db")
    store.ingest([Record("syslog:192.168.1.23", "hello")])  # pending sender
    critical = {"status": "critical", "reasons": ["silent for 99 min"], "metrics": {}}
    store.ingest([Record("fw01", "x")], auto_approve=True)
    assert host_alerts(store, lambda st, h: critical) == 2
    assert host_alerts(store, lambda st, h: critical) == 0  # not twice while open
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    got = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            got.append(self.rfile.read(int(self.headers["Content-Length"])).decode())
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/hook"
        r = al.notify_pending(store, url, "json", "high")
        assert r == {"sent": 1, "failed": 0}  # the high one only
        assert al.notify_pending(store, url, "json", "high")["sent"] == 0  # once
        assert "fw01" not in got[0] and "Host health critical" in got[0]
    finally:
        srv.shutdown()


def test_notification_body_has_no_host_name():
    a = {"id": 3, "title": "Port scan from one source", "level": "high", "count": 4,
         "kind": "sigma", "source": "syslog:192.168.1.23"}  # fmt: skip
    for fmt in ("json", "ntfy", "discord", "slack"):
        body, _ = al.notification_body(a, fmt, "http://privasoc.lab:8000")
        assert "192.168" not in json.dumps(body) and "/ui/alert?id=3" in json.dumps(body)


# ------------------------------------------------------------------ triage


def test_triage_validation_flags_what_is_not_grounded():
    ans = {
        "verdict": "true_positive", "severity": "high", "confidence": 1.7,
        "summary": "Brute force from 10.9.9.9 on host-abcdef.",
        "reasons": [{"claim": "12 failures", "events": [1, 2]},
                    {"claim": "made up", "events": [99]}],
        "next_steps": ["block the source"], "attack": ["T1110.001", "T9999", "bad"],
    }  # fmt: skip
    res, problems = triage.validate(ans, [1, 2, 3], ["T1110"], "event 1 ... 10.1.1.1")
    assert res["confidence"] == 1.0
    assert res["reasons"][1]["flag"] and res["reasons"][0]["flag"] is None
    assert [x["in_rule_tags"] for x in res["attack"]] == [True, False]
    joined = " ".join(problems)
    assert "not in the evidence: [99]" in joined and "malformed ATT&CK id 'BAD'" in joined
    assert "10.9.9.9" in joined and "host-abcdef" in joined
    assert triage.validate(None, [], [], "")[1] == ["the answer is not valid JSON"]


def test_triage_end_to_end_is_pseudonymised(tmp_path):
    answer = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 0.8,
        "summary": "Many failures.",
        "reasons": [],
        "next_steps": [],
        "attack": ["T1110"],
    }
    srv, seen = _server(lambda _p: json.dumps(answer))
    try:
        s = Settings(
            api_token=SecretStr("t"), hmac_key=SecretStr("h" * 32),
            vault_key=SecretStr(Fernet.generate_key().decode()), data_dir=tmp_path,
            llm_local_url=f"http://127.0.0.1:{srv.server_port}/v1", llm_local_model="m",
        )  # fmt: skip
        store = Store(s.db_path)
        store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(12)], auto_approve=True)
        service._ENGINE.clear()
        service.detect_run(store, s)
        (a,) = [x for x in al.alerts(store, "open") if x["kind"] == "sigma"]
        rec = service.triage_alert(store, s, a["id"])
        assert rec["result"]["verdict"] == "true_positive" and rec["problems"] == []
        assert rec["result"]["attack"] == [{"id": "T1110", "in_rule_tags": True}]
        assert seen and all("203.0.113.9" not in p and "sshbox" not in p for p in seen)
        assert al.alert(store, a["id"])["triage"]["model"] == "m"
    finally:
        srv.shutdown()


def test_sigma_rules_parse_from_disk(tmp_path):
    d = tmp_path / "rules" / "network" / "dns"
    d.mkdir(parents=True)
    (d / "r.yml").write_text(yaml.safe_dump({
        "title": "Suspicious TLD", "id": "x1", "level": "high", "tags": ["attack.t1071.004"],
        "logsource": {"category": "dns"},
        "detection": {"s": {"query|endswith": [".zip", ".mov"]}, "condition": "s"},
    }))  # fmt: skip
    eng = Engine.from_dirs(tmp_path)
    r = next(x for x in eng.rules if x.origin == "sigmahq")
    assert r.unsupported is None and r.attack == ["T1071.004"] and "DRL" in r.licence()
    assert Path(r.path).name == "r.yml"


def test_keywords_with_all_modifier():
    r = rule({"k": {"|all": ["failed", "bob"]}, "condition": "k"})
    assert r.unsupported is None and r.match(DOC)
    assert not rule({"k": {"|all": ["failed", "alice"]}, "condition": "k"}).match(DOC)


def test_new_sender_alert_is_resolved_by_the_decision(tmp_path):
    s = Settings(api_token=SecretStr("t"), hmac_key=SecretStr("h" * 32),
                 vault_key=SecretStr(Fernet.generate_key().decode()), data_dir=tmp_path)  # fmt: skip
    store = Store(s.db_path)
    store.ingest([Record("syslog:192.0.2.9", "x"), Record("syslog:192.0.2.8", "y")])
    host_alerts(store, lambda st, h: {"status": "ok", "reasons": []})
    service.reject_host(store, "syslog:192.0.2.9")
    st = {a["source"]: a["status"] for a in al.alerts(store, "all")}
    assert st == {"syslog:192.0.2.9": "resolved", "syslog:192.0.2.8": "new"}
    host_alerts(store, lambda st, h: {"status": "ok", "reasons": []})
    assert len(al.alerts(store, "all")) == 2  # never raised twice for the same sender
