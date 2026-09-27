"""Bench for step 7 (D56): a synthetic, labelled event set and hand-written hunts.

Events look like the output of privasoc's parsers (ECS). Each carries hidden labels (kept
outside the document) so the exact answer of every hunt is known. Nothing here comes from
real logs: addresses are documentation ranges, names are invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

T0 = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
CASES = Path(__file__).resolve().parents[2] / "evaluation" / "hunt_cases.yaml"


@dataclass
class Event:
    source: str
    ecs: dict
    labels: set[str] = field(default_factory=set)


def _ts(sec: float) -> str:
    return (T0 + timedelta(seconds=sec)).isoformat()


def _ssh(t, ip, user, ok, labels, port=40000, invalid=False):
    if ok:
        text = f"Accepted password for {user} from {ip} port {port} ssh2"
    elif invalid:
        text = f"Invalid user {user} from {ip} port {port}"
    else:
        text = f"Failed password for {user} from {ip} port {port} ssh2"
    return Event("syslog:192.0.2.1", {
        "@timestamp": _ts(t), "event": {"original": f"sshd[811]: {text}", "kind": "event",
        "category": ["authentication"], "outcome": "success" if ok else "failure"},
        "process": {"name": "sshd", "pid": 811}, "host": {"hostname": "bastion"},
        "source": {"ip": ip, "port": port}, "user": {"name": user},
    }, set(labels))  # fmt: skip


def _fw(t, src, dport, action, labels, dst="192.0.2.2", proto="tcp"):
    return Event("syslog:192.0.2.254", {
        "@timestamp": _ts(t), "event": {"original": f"fw: {action.upper()} {proto} "
        f"{src}:{50000 + dport % 1000} -> {dst}:{dport}", "kind": "event",
        "category": ["network"], "action": action},
        "source": {"ip": src, "port": 50000 + dport % 1000},
        "destination": {"ip": dst, "port": dport}, "network": {"transport": proto},
        "observer": {"hostname": "edge-fw"},
    }, set(labels))  # fmt: skip


def _dns(t, client, name, labels, qtype="A", rcode="NOERROR"):
    return Event("syslog:192.0.2.53", {
        "@timestamp": _ts(t), "event": {"original": f"dnsmasq[90]: query[{qtype}] {name} "
        f"from {client}", "kind": "event", "category": ["network"]},
        "process": {"name": "dnsmasq"}, "source": {"ip": client},
        "dns": {"question": {"name": name, "type": qtype}, "response_code": rcode},
    }, set(labels))  # fmt: skip


def _web(t, client, method, path, status, ua, labels):
    return Event("web01", {
        "@timestamp": _ts(t), "event": {"original": f'{client} - - "{method} {path} HTTP/1.1" '
        f'{status} 512 "-" "{ua}"', "kind": "event", "category": ["web"]},
        "source": {"ip": client}, "http": {"request": {"method": method},
        "response": {"status_code": status}}, "url": {"path": path, "original": path},
        "user_agent": {"original": ua},
    }, set(labels))  # fmt: skip


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0"


def events() -> list[Event]:
    ev: list[Event] = []
    # SSH: a brute force, a slow guesser, an invalid-user sweep, normal logins, then the
    # brute-forcing source logs in as root.
    for i in range(40):
        ev.append(
            _ssh(60 + i * 4, "203.0.113.50", "root", False, {"ssh_fail", "bf_203"}, 41000 + i)
        )
    for i in range(8):
        ev.append(_ssh(300 + i * 420, "198.51.100.20", "oracle", False, {"ssh_fail"}, 42000 + i))
    for i in range(5):
        ev.append(_ssh(900 + i * 30, "192.0.2.77", "admin", False,
                       {"ssh_fail", "invalid_user"}, 43000 + i, invalid=True))  # fmt: skip
    for i in range(6):
        ev.append(_ssh(1200 + i * 600, "10.0.0.5", "alice", True, {"ssh_ok"}, 44000 + i))
    ev.append(_ssh(260, "203.0.113.50", "root", True, {"ssh_ok", "bf_success"}, 41999))
    # Firewall: a port scan, telnet noise, blocked SSH/RDP, allowed inbound RDP, normal traffic.
    for i in range(30):
        ev.append(_fw(2000 + i * 1.5, "198.51.100.99", 1000 + i, "drop", {"fw_drop", "scan"}))
    for i in range(12):
        src = f"203.0.113.{100 + i}"
        ev.append(_fw(2200 + i * 90, src, 23, "drop", {"fw_drop", "telnet"}))
    for i, port in enumerate([22, 22, 3389, 3389, 22]):
        ev.append(_fw(2600 + i * 20, "192.0.2.200", port, "drop", {"fw_drop", "blocked_ssh_rdp"}))
    ev.append(_fw(2900, "203.0.113.9", 3389, "allow", {"fw_allow", "rdp_inbound"}))
    for i in range(10):
        ev.append(_fw(3000 + i * 30, "10.0.0.5", 443, "allow", {"fw_allow"},
                      dst=f"198.51.100.{10 + i}"))  # fmt: skip
    # DNS: normal lookups, a .zip lure, a tunnelling-like label, pastebin.
    names = ["example.org", "updates.vendor.example.com", "mail.example.net", "cdn.example.org"]
    for i in range(24):
        ev.append(_dns(3600 + i * 15, "10.0.0.5", names[i % 4], {"dns"}))
    ev.append(_dns(3700, "10.0.0.7", "invoice-2026.zip", {"dns", "zip_tld"}))
    ev.append(_dns(3705, "10.0.0.7", "claims-form.zip", {"dns", "zip_tld"}))
    label = "a" * 12 + "4f3c9e1b7d2a6e8f0c5b3a9d1e7f2c4b6a8d0e3f5b7c9d1"
    ev.append(_dns(3800, "10.0.0.9", f"{label}.t.example.net", {"dns", "long_label"}, "TXT"))
    ev.append(_dns(3900, "10.0.0.7", "pastebin.com", {"dns", "pastebin"}))
    # Web: normal browsing, a 404 scan, sqlmap, WordPress login brute force, /admin access.
    pages = ["/", "/about", "/contact", "/blog/post-1"]
    for i in range(20):
        ev.append(_web(4000 + i * 20, "198.51.100.5", "GET", pages[i % 4], 200, BROWSER, {"web"}))
    ev.append(_web(4100, "198.51.100.5", "GET", "/old-page", 404, BROWSER, {"web", "web_404"}))
    ev.append(_web(4150, "198.51.100.6", "GET", "/favicon2.ico", 404, BROWSER, {"web", "web_404"}))
    for i in range(50):
        ev.append(
            _web(
                4400 + i * 3,
                "192.0.2.10",
                "GET",
                f"/backup{i}.zip",
                404,
                "Mozilla/5.0 (compatible; scanner)",
                {"web", "web_404", "web_scan"},
            )
        )
    for i in range(3):
        ev.append(
            _web(
                4700 + i * 5,
                "203.0.113.60",
                "GET",
                f"/item.php?id={i}' OR 1=1",
                500,
                "sqlmap/1.8#stable (https://sqlmap.org)",
                {"web", "sqlmap"},
            )
        )
    for i in range(12):
        ev.append(
            _web(
                5000 + i * 20,
                "198.51.100.30",
                "POST",
                "/wp-login.php",
                200,
                BROWSER,
                {"web", "wp_login"},
            )
        )
    ev.append(_web(5400, "10.0.0.8", "GET", "/admin", 200, BROWSER, {"web", "admin_access"}))
    ev.append(_web(5410, "10.0.0.8", "GET", "/admin/users", 200, BROWSER, {"web", "admin_access"}))
    return sorted(ev, key=lambda e: e.ecs["@timestamp"])


def load_cases(path: Path = CASES) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["cases"]


def expected(case: dict, evs: list[tuple[int, Event]]) -> tuple[str, set]:
    """('events', event ids) or ('groups', values of the group field)."""
    if "groups" in case:
        return "groups", {str(g) for g in case["groups"]}
    want = set(case["labels"])
    return "events", {eid for eid, e in evs if e.labels & want}


def answer(bt: dict, kind: str, group_field: str | None) -> set:
    """What a hunt returned, in the form of the expected answer."""
    if kind == "groups":
        out = set()
        for r in bt["results"]:
            for g in r.get("groups", []):
                v = g["group"].get(group_field)
                if v is not None:
                    out.add(str(v))
        return out
    return {i for r in bt["results"] if r["kind"] != "base" for i in r["event_ids"]}


def score(want: set, got: set) -> dict:
    tp = len(want & got)
    p = tp / len(got) if got else 0.0
    r = tp / len(want) if want else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "exact": want == got,
            "expected": len(want), "returned": len(got)}  # fmt: skip


def run_case(case: dict, llm, make_pz) -> dict:
    """One hunt: the model writes a rule on the synthetic events, the engine runs it."""
    import time

    from privasoc.detect import author
    from privasoc.detect.engine import backtest
    from privasoc.detect.sigma import compile_text
    from privasoc.store import Record, Store

    store = Store(":memory:")
    evs = events()
    store.ingest(
        [Record(e.source, e.ecs["event"]["original"], e.ecs["@timestamp"], e.ecs, "bench")
         for e in evs],
        auto_approve=True,
    )  # fmt: skip
    ids = [r[0] for r in store.conn.execute("SELECT id FROM events ORDER BY id")]
    numbered = list(zip(ids, evs, strict=True))
    kind, want = expected(case, numbered)
    docs = [e.ecs for e in evs]
    seen, examples = set(), []
    for eid, e in numbered:
        if e.source not in seen:
            seen.add(e.source)
            examples.append({"id": eid, "ecs": e.ecs})
    t0 = time.monotonic()
    draft = author.write(
        llm, make_pz(),
        "Write a rule that answers this question when run over past events: " + case["request"],
        author.catalogue(docs), examples,
    )  # fmt: skip
    row = {"n": case["n"], "set": case["set"], "model": llm.endpoint.model,
           "valid": draft.status == "proposed", "attempts": len(draft.attempts),
           "llm_s": round(time.monotonic() - t0, 1), "yaml": draft.yaml,
           "errors": [a["errors"] for a in draft.attempts]}  # fmt: skip
    if draft.status == "proposed":
        bt = backtest(store, compile_text(draft.yaml, "ai"))
        row.update(score(want, answer(bt, kind, case.get("group_field"))))
    else:
        row.update(score(want, set()))
    row["kind"] = kind
    return row


def summary(rows: list[dict]) -> dict:
    out = {}
    for name in sorted({r["set"] for r in rows}):
        rs = [r for r in rows if r["set"] == name]
        out[name] = {
            "cases": len(rs),
            "valid_rule": round(sum(r["valid"] for r in rs) / len(rs), 3),
            "exact": round(sum(r["exact"] for r in rs) / len(rs), 3),
            "precision": round(sum(r["precision"] for r in rs) / len(rs), 3),
            "recall": round(sum(r["recall"] for r in rs) / len(rs), 3),
            "mean_attempts": round(sum(r["attempts"] for r in rs) / len(rs), 2),
        }
    return out
