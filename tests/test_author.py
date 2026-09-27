"""Step 7: rules written by the model, backtests, false-positive fixes, bench."""

import json
from types import SimpleNamespace

import pytest
import yaml
from cryptography.fernet import Fernet
from pydantic import SecretStr

from privasoc import bench_hunt, service
from privasoc.config import Settings
from privasoc.detect import alerts as al
from privasoc.detect import author, authored
from privasoc.detect.engine import BUILTIN_RULES, Engine, backtest, load_rules
from privasoc.detect.sigma import compile_text
from privasoc.store import Record, Store
from tests.test_learn import _server

KNOWN = {"process.name", "source.ip", "event.outcome", "destination.port", "url.path"}


def test_check_explains_what_is_wrong():
    rules, errors, _ = author.check("x: [unclosed", KNOWN)
    assert errors and "invalid YAML" in errors[0] and "Quote" in errors[0]
    bad = """title: t
detection:
  s:
    proces.name: sshd
    source.ip:
      - contains: 10.
  condition: s
---
title: c
correlation: {type: event_count, rules: [nope], group-by: [source.ip], timespan: 5m, condition: {gte: 3}}
"""
    _, errors, normalised = author.check(bad, KNOWN)
    joined = " ".join(errors)
    assert "'proces.name' does not occur" in joined and "did you mean process.name" in joined
    assert "must be a plain value" in joined and "refers to 'nope'" in joined
    assert "product: privasoc" in normalised  # logsource forced
    ok = "```yaml\ntitle: t\ndetection:\n  s: {process.name: sshd}\n  condition: s\n```"
    rules, errors, _ = author.check(ok, KNOWN)
    assert errors == [] and rules[0].match({"process": {"name": "sshd"}})


def test_check_replaces_model_ids_and_names_with_isolated_ones():
    text = """title: base
id: existing-rule-id
name: shared_name
detection:
  s: {process.name: sshd}
  condition: s
---
title: correlation
id: another-existing-id
correlation:
  type: event_count
  rules: [shared_name]
  group-by: [source.ip]
  timespan: 5m
  condition: {gte: 3}
"""
    rules, errors, normalised = author.check(text, KNOWN)
    assert errors == []
    docs = list(yaml.safe_load_all(normalised))
    assert all(d["id"] not in {"existing-rule-id", "another-existing-id"} for d in docs)
    assert docs[0]["name"].startswith("ai_")
    assert docs[1]["correlation"]["rules"] == [docs[0]["name"]]
    eng = Engine(rules)
    assert len(eng.correlations) == 1 and eng.correlations[0].unsupported is None


def _bench_store():
    store = Store(":memory:")
    evs = bench_hunt.events()
    store.ingest([Record(e.source, e.ecs["event"]["original"], e.ecs["@timestamp"], e.ecs, "b")
                  for e in evs], auto_approve=True)  # fmt: skip
    ids = [r[0] for r in store.conn.execute("SELECT id FROM events ORDER BY id")]
    return store, list(zip(ids, evs, strict=True))


REFERENCE = {  # hand-written answers: they must score exact, or the bench itself is wrong
    3: """title: f
name: f
logsource: {product: privasoc}
detection:
  s: {process.name: sshd, event.outcome: failure}
  condition: s
---
title: c
correlation: {type: event_count, rules: [f], group-by: [source.ip], timespan: 5m, condition: {gt: 20}}
""",
    7: """title: d
name: d
logsource: {product: privasoc}
detection:
  s: {event.action: drop}
  condition: s
---
title: c
correlation: {type: value_count, rules: [d], group-by: [source.ip], timespan: 2m,
  condition: {field: destination.port, gt: 15}}
""",
    10: """title: l
logsource: {product: privasoc}
detection:
  s: {dns.question.name|re: '(^|\\.)[^.]{41,}(\\.|$)'}
  condition: s
""",
    11: """title: s
logsource: {product: privasoc}
detection:
  s: {process.name: sshd, event.outcome: success}
  internal: {source.ip|cidr: 10.0.0.0/8}
  condition: s and not internal
""",
    16: """title: a
logsource: {product: privasoc}
detection:
  s: {url.path|startswith: /admin}
  condition: s
""",
}


@pytest.mark.parametrize("n", sorted(REFERENCE))
def test_bench_answers_are_reachable(n):
    store, numbered = _bench_store()
    case = next(c for c in bench_hunt.load_cases() if c["n"] == n)
    kind, want = bench_hunt.expected(case, numbered)
    bt = backtest(store, compile_text(REFERENCE[n], "ai"))
    got = bench_hunt.answer(bt, kind, case.get("group_field"))
    assert bench_hunt.score(want, got)["exact"], (want, got)


def test_bench_has_twenty_cases_split_dev_holdout():
    cases = bench_hunt.load_cases()
    assert len(cases) == 20 and sum(c["set"] == "holdout" for c in cases) == 10


def test_write_retries_and_reidentifies(pz):
    replies = iter([
        "```yaml\ntitle: t\ndetection:\n  s: {user.nam: X}\n  condition: s\n```",
        "```yaml\ntitle: t\ndetection:\n  s: {source.ip: IP}\n  condition: s\n```",
    ])  # fmt: skip
    events = [{"id": 1, "ecs": {"source": {"ip": "192.168.1.50"}, "user": {"name": "bob"}}}]
    cat = author.catalogue([e["ecs"] for e in events])
    token = pz.pseudonymize("192.168.1.50").text

    class LLM:
        endpoint = SimpleNamespace(name="local", model="fake", url="http://127.0.0.1:1")

        def chat(self, messages, **kw):
            sent = "\n".join(m["content"] for m in messages)
            assert "192.168.1.50" not in sent and "bob" not in sent  # pseudonymised
            return SimpleNamespace(text=next(replies).replace("IP", token), latency_s=0.1)

    d = author.write(LLM(), pz, "find traffic from that machine", cat, events)
    assert d.status == "proposed" and len(d.attempts) == 2
    assert "did you mean user.name" in d.attempts[0]["errors"][0]
    assert "192.168.1.50" in d.yaml and token not in d.yaml  # works on real data


def _settings(tmp_path, url):
    return Settings(
        api_token=SecretStr("t"), hmac_key=SecretStr("h" * 32),
        vault_key=SecretStr(Fernet.generate_key().decode()), data_dir=tmp_path,
        llm_local_url=url, llm_local_model="m",
    )  # fmt: skip


def test_false_positive_fix_end_to_end(tmp_path):
    from tests.test_detect import ev, ssh_fail

    derived = """```yaml
title: SSH authentication failure (tuned)
name: privasoc_ssh_auth_failure
logsource: {product: privasoc}
detection:
  process: {process.name|contains: sshd}
  failure: {event.original|contains: [Failed password]}
  filter_scanner: {source.ip: SCANNER}
  condition: process and failure and not filter_scanner
level: low
---
title: SSH brute force from one source (tuned)
correlation: {type: event_count, rules: [privasoc_ssh_auth_failure], group-by: [source.ip],
  timespan: 5m, condition: {gte: 10}}
level: high
```"""
    holder = {}
    srv, seen = _server(lambda _p: derived.replace("SCANNER", holder["token"]))
    try:
        s = _settings(tmp_path, f"http://127.0.0.1:{srv.server_port}/v1")
        holder["token"] = service.pseudonymizer(s).pseudonymize("203.0.113.9").text
        store = Store(s.db_path)
        store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(12)], auto_approve=True)
        service._ENGINE.clear()
        service.detect_run(store, s)
        (a,) = [x for x in al.alerts(store, "open") if x["kind"] == "sigma"]
        service.set_alert_status(store, a["id"], "closed_fp")
        out = service.author_rule(store, s, "false_positive", ref=a["id"])
        assert out["status"] == "proposed", out
        assert all("203.0.113.9" not in p for p in seen)
        assert "203.0.113.9" in out["yaml"]  # re-identified
        fp = out["backtest"]["false_positive"]
        assert fp == {"fp": 1, "fp_removed": 1, "tp": 0, "tp_kept": 0, "tp_lost": []}
        c = service.decide_rule(store, s, out["id"], "approved")
        assert c["status"] == "approved"
        eng = service.engine(s)
        old = [r for r in eng.rules if r.origin == "privasoc" and "SSH" in r.title]
        assert old and all(r.disabled for r in old)  # the original pair is switched off
        assert any(r.origin == "ai" for r in eng.correlations)
        service.decide_rule(store, s, out["id"], "disabled")
        assert not any(r.disabled for r in service.engine(s).rules if r.origin == "privasoc")
    finally:
        srv.shutdown()


def test_false_positive_effect_honours_the_correlation_threshold(tmp_path):
    from tests.test_detect import ev, ssh_fail

    store = Store(tmp_path / "d.db")
    store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(12)], auto_approve=True)
    Engine(load_rules([(BUILTIN_RULES, "privasoc")])).run(store)
    (alert,) = al.alerts(store, "open")
    al.set_status(store, alert["id"], "closed_tp")
    candidate = compile_text(
        """title: narrowed base
name: narrowed
logsource: {product: privasoc}
detection:
  one: {event.original|endswith: 'port 0'}
  condition: one
---
title: narrowed correlation
correlation:
  type: event_count
  rules: [narrowed]
  group-by: [source.ip]
  timespan: 5m
  condition: {gte: 10}
""",
        "ai",
    )
    effect = service._fp_effect(store, alert["rule_id"], candidate)
    assert effect == {
        "fp": 0,
        "fp_removed": 0,
        "tp": 1,
        "tp_kept": 0,
        "tp_lost": [alert["id"]],
    }


def test_false_positive_authoring_requires_a_false_positive_verdict(tmp_path):
    from tests.test_detect import ev, ssh_fail

    s = _settings(tmp_path, "http://127.0.0.1:1/v1")
    store = Store(s.db_path)
    store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(12)], auto_approve=True)
    Engine(load_rules([(BUILTIN_RULES, "privasoc")])).run(store)
    (alert,) = al.alerts(store, "open")
    with pytest.raises(service.ActionError, match="closed as a false positive"):
        service.author_rule(store, s, "false_positive", ref=alert["id"])


def test_engine_cache_is_isolated_by_database(tmp_path):
    from pathlib import Path

    first = SimpleNamespace(sigma_dir=Path(tmp_path / "sigma"), db_path=Path(tmp_path / "a.db"))
    second = SimpleNamespace(sigma_dir=first.sigma_dir, db_path=Path(tmp_path / "b.db"))
    yaml_text = """title: local
id: local-rule
logsource: {product: privasoc}
detection:
  s: {process.name: sshd}
  condition: s
"""
    one = Store(first.db_path)
    Store(second.db_path).close()
    authored.save(one, "proposal", yaml_text, "local", "request")
    authored.set_status(one, "proposal", "approved")
    one.close()
    service._ENGINE.clear()
    assert any(r.origin == "ai" for r in service.engine(first).rules)
    assert not any(r.origin == "ai" for r in service.engine(second).rules)


def test_remote_false_positive_pass_checks_the_current_rule(tmp_path, monkeypatch):
    from tests.test_detect import ev, ssh_fail

    answer = """```yaml
title: narrowed SSH failures
logsource: {product: privasoc}
detection:
  s: {event.original|contains: Failed password}
  condition: s
```"""
    srv, _ = _server(lambda _p: answer)
    captured = []
    try:
        url = f"http://127.0.0.1:{srv.server_port}/v1"
        s = _settings(tmp_path, url)
        s.llm_remote_url = url
        s.llm_remote_model = "m"
        store = Store(s.db_path)
        store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(12)], auto_approve=True)
        Engine(load_rules([(BUILTIN_RULES, "privasoc")])).run(store)
        (alert,) = al.alerts(store, "open")
        al.set_status(store, alert["id"], "closed_fp")

        def residual(_store, _settings, lines, _say):
            captured.extend(lines)
            return []

        monkeypatch.setattr(service, "_local_residual_rules", residual)
        out = service.author_rule(store, s, "false_positive", ref=alert["id"], provider="remote")
        assert out["status"] == "proposed"
        assert any("Current rule:" in line and "correlation:" in line for line in captured)
    finally:
        srv.shutdown()


def test_hunt_is_not_a_rule_until_kept(tmp_path):
    from tests.test_detect import ev, ssh_fail

    rule = "```yaml\ntitle: root\ndetection:\n  s: {process.name: sshd}\n  condition: s\n```"
    srv, _ = _server(lambda _p: rule)
    try:
        s = _settings(tmp_path, f"http://127.0.0.1:{srv.server_port}/v1")
        store = Store(s.db_path)
        store.ingest([ev(i, ssh_fail("203.0.113.9", i)) for i in range(3)], auto_approve=True)
        out = service.author_rule(store, s, "hunt", "ssh events?")
        assert out["backtest"]["results"][0]["matches"] == 3
        assert authored.get(store, out["id"])["status"] == "hunt"
        with pytest.raises(service.ActionError):
            service.decide_rule(store, s, out["id"], "approved")  # keep it first
        service.decide_rule(store, s, out["id"], "proposed")
        service.decide_rule(store, s, out["id"], "approved")
        assert any(r.origin == "ai" for r in service.engine(s).rules)
        assert json.loads(json.dumps(authored.listing(store)))  # serialisable
    finally:
        srv.shutdown()
