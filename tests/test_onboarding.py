"""D45 onboarding and D47 health."""

import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from privasoc import builtins, health, onboarding
from privasoc.config import Settings
from privasoc.sandbox import Sandbox
from privasoc.store import Record, Store

VECTOR = os.environ.get("PRIVASOC_VECTOR_BIN") or shutil.which("vector")
needs_vector = pytest.mark.skipif(not VECTOR, reason="vector binary not available")
ROOT = Path(__file__).parent.parent

COMBINED = [
    f'10.1.1.{i} - jdoe [25/Oct/2016:14:49:3{i} +0200] "GET /p{i} HTTP/1.1" 200 61{i} '
    f'"-" "Mozilla/5.0"'
    for i in range(8)
]


def settings(tmp_path):
    shutil.copy(ROOT / "vector" / "vector.yaml", tmp_path / "vector.yaml")
    return Settings(
        api_token=SecretStr("t"),
        hmac_key=SecretStr("h"),
        vault_key=SecretStr("v"),
        data_dir=tmp_path,
        vector_bin=VECTOR or "vector",
        vector_dir=tmp_path,
    )


def test_rejected_host_is_dropped_and_its_held_lines_deleted(tmp_path):
    st = Store(tmp_path / "d.db")
    st.ingest([Record("syslog:10.0.0.9", "x"), Record("syslog:10.0.0.9", "y")])
    st.set_host("syslog:10.0.0.9", "rejected")
    assert st.conn.execute("SELECT COUNT(*) FROM unparsed").fetchone()[0] == 0
    assert st.ingest([Record("syslog:10.0.0.9", "z")])["dropped"] == 1


@needs_vector
def test_builtin_parsers_are_valid_and_detect_web_logs():
    sb = Sandbox(VECTOR)
    for b in builtins.BUILTINS:  # every built-in compiles
        assert not sb.run(b.vrl, ["x"]).compile_error, b.name
    found = builtins.detect(sb, COMBINED)
    assert found and found[0].name == "apache_combined" and found[1] == 1.0
    assert (
        builtins.detect(sb, ["Sep 26 10:01:02 dnsmasq[812]: query[A] a.lab from 10.0.0.1"]) is None
    )


@needs_vector
def test_approving_a_host_with_a_known_format_ingests_its_held_lines(tmp_path):
    s = settings(tmp_path)
    st = Store(s.db_path)
    st.ingest([Record("syslog:10.0.0.5", ln) for ln in COMBINED])
    assert st.event_count() == 0  # pending: held
    r = onboarding.approve_host(st, s, Sandbox(VECTOR), "syslog:10.0.0.5")
    assert r["format"] == "builtin:apache_combined" and r["backfilled"] == 8
    assert st.event_count() == 8 and st.quarantine_rows("syslog:10.0.0.5") == []
    assert (tmp_path / "pipeline.yaml").exists()
    import json

    ecs = json.loads(st.conn.execute("SELECT ecs FROM events LIMIT 1").fetchone()[0])
    assert ecs["source"]["ip"] == "10.1.1.0" and ecs["http"]["response"]["status_code"] == 200
    assert ecs["event"]["original"] == COMBINED[0]
    # backfilled lines count as parsed in the health statistics (regression: 33 % after e2e)
    rows = st.stats("syslog:10.0.0.5", "0000")
    assert sum(r[1] for r in rows) == sum(r[2] for r in rows) == 8


@needs_vector
def test_unknown_format_goes_to_quarantine_then_backfills_after_parser_approval(tmp_path):
    from tests.test_generator import GOOD

    s = settings(tmp_path)
    st = Store(s.db_path)
    lines = (ROOT / "examples" / "pihole.log").read_text().splitlines()
    st.ingest([Record("syslog:10.0.0.7", ln) for ln in lines])
    r = onboarding.approve_host(st, s, Sandbox(VECTOR), "syslog:10.0.0.7")
    assert r["format"] == "unknown" and len(st.quarantine_lines("syslog:10.0.0.7")) == 60
    st.save_parser("p1", "syslog:10.0.0.7", "proposed", "local", "m", GOOD, {})
    st.set_parser_status("p1", "approved")
    out = onboarding.after_parser_approval(st, Sandbox(VECTOR), st.parser("p1"))
    assert out == {"backfilled": 60, "still_quarantined": 0} and st.event_count() == 60
    assert st.host("syslog:10.0.0.7")["format"] == "parser:p1"


def _seed(st, source, now, minutes, per_minute, parsed_ratio=1.0, skew=None):
    for m in range(minutes):
        ts = (now - timedelta(minutes=m + 1)).isoformat()
        for i in range(per_minute):
            parsed = i < per_minute * parsed_ratio
            ecs = (
                {"@timestamp": (now - timedelta(minutes=m + 1, seconds=skew or 0)).isoformat()}
                if parsed
                else None
            )
            st.ingest(
                [Record(source, "l", received_at=ts, ecs=ecs, parser_id="p" if parsed else None)],
                auto_approve=True,
            )


def test_health_ok_silence_drift_and_skew(tmp_path):
    now = datetime.now(UTC)
    st = Store(tmp_path / "h.db")
    _seed(st, "a", now, 120, 2)
    st.set_host("a", fmt="parser:p")
    assert health.compute(st, st.host("a"), now)["status"] == "ok"

    later = now + timedelta(minutes=45)  # nothing for 45 min, usual gap 0.5 min
    hs = health.compute(st, st.host("a"), later)
    assert hs["status"] == "critical" and "silent" in hs["reasons"][0]

    st2 = Store(tmp_path / "h2.db")
    _seed(st2, "b", now, 90, 4, parsed_ratio=0.25, skew=900)
    st2.set_host("b", fmt="parser:p")
    hs = health.compute(st2, st2.host("b"), now)
    assert hs["status"] == "critical"
    assert any("parse rate 25%" in r for r in hs["reasons"])
    assert any("clock skew" in r for r in hs["reasons"])
    st2.record_health("b", hs["status"], hs["reasons"])
    st2.record_health("b", hs["status"], hs["reasons"])  # unchanged: not duplicated
    assert len(st2.health_history("b")) == 1


def test_thresholds_are_per_host(tmp_path):
    now = datetime.now(UTC)
    st = Store(tmp_path / "t.db")
    _seed(st, "c", now, 90, 2)
    st.set_host("c", fmt="parser:p", thresholds={"silence_min_minutes": 120})
    assert health.compute(st, st.host("c"), now + timedelta(minutes=45))["status"] == "ok"
