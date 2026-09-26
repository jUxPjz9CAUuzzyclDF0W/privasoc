import json

import pytest

from privasoc import evaluation, report
from privasoc.fixtures import Fixture
from tests.test_generator import GOOD, VECTOR, ScriptedLLM, needs_vector


def test_score_micro_f1():
    exp = [{"source": {"ip": "1.2.3.4", "port": 22}, "user": {"name": "bob"}}]
    assert evaluation.score(exp, exp)["f1"] == 1.0
    pred = [
        {"source": {"ip": "1.2.3.4", "port": "22"}, "user": {"name": "alice"}, "vendor": {"x": 1}}
    ]
    s = evaluation.score(pred, exp)  # ip + port right (types normalised), user wrong
    assert s["precision"] == pytest.approx(2 / 3, abs=0.01) and s["recall"] == pytest.approx(
        2 / 3, abs=0.01
    )
    assert evaluation.score([None], exp)["recall"] == 0.0


def test_leakage_counts_only_values_literally_in_the_line(pz):
    fx = Fixture(
        "t",
        ["user=bob from 10.1.2.3 via gw-01"],
        [
            {
                "user": {"name": "bob"},
                "source": {"ip": "10.1.2.3"},
                "host": {"hostname": "normalised-away"},
            }
        ],
    )
    r = evaluation.leakage([fx], pz)
    assert r["values"] == 2 and r["leaked"] == 0


def test_no_pseudo_ablation_is_refused_for_remote(pz):
    from privasoc.generator import generate
    from privasoc.llm import Endpoint
    from privasoc.sandbox import Sandbox

    llm = ScriptedLLM([])
    llm.endpoint = Endpoint("remote", "http://x", "m")
    with pytest.raises(ValueError, match="remote"):
        generate("s", ["a"], llm, evaluation.IdentityPseudonymizer(), Sandbox("x"))


@needs_vector
def test_run_one_scores_on_held_out_half(pz, tmp_path):
    from pathlib import Path

    from privasoc.sandbox import Sandbox

    lines = (Path(__file__).parent.parent / "examples" / "pihole.log").read_text().splitlines()
    expected = []
    for ln in lines:
        doc = {"process": {"name": "dnsmasq", "pid": 812}}
        if "query[" in ln:
            parts = ln.split()
            doc["source"] = {"ip": parts[-1]}
            doc["dns"] = {"question": {"name": parts[-3]}}
        expected.append(doc)
    fx = Fixture("pihole", lines, expected)
    llm = ScriptedLLM([json.dumps({"status": "ok", "vrl": GOOD})])
    r = evaluation.run_one(fx, 1, llm, pz, Sandbox(VECTOR), "vrl", 10, 3, 0.8)
    assert r.status == "proposed" and r.heldout_lines == 30 and r.heldout_parsed == 1.0
    assert r.f1 == 1.0
    evaluation.append(tmp_path / "r.jsonl", r)
    summary = report.summarise(evaluation.load_results(tmp_path / "r.jsonl"))
    md = report.markdown(summary, None, {"date": "d", "sha": "abc"})
    assert "100%" in md and "<table>" in report.to_html(md)
