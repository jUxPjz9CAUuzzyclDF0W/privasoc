"""Ground truth for the parser evaluation (D20): Elastic integrations pipeline tests.

Each fixture pairs raw log lines with the ECS documents Elastic's own ingest pipeline
produces. The files are licensed under the Elastic License 2.0, so they are downloaded at
evaluation time into data/fixtures (git-ignored) and never redistributed. The commit is
pinned for reproducibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import httpx

ELASTIC_SHA = "354ff4c940c3bbd6fcc709d9767bd5a9e12a22bc"
BASE = f"https://raw.githubusercontent.com/elastic/integrations/{ELASTIC_SHA}/packages"

# name -> (package, data stream, test file)
FIXTURES = {
    "checkpoint": ("checkpoint", "firewall", "test-checkpoint.log"),
    "cisco_asa": ("cisco_asa", "log", "test-additional-messages.log"),
    "fortigate": ("fortinet_fortigate", "log", "test-fortinet-7-4.log"),
    "pfsense": ("pfsense", "log", "test-pfsense-bsd.log"),
    "iptables": ("iptables", "log", "test-iptables-raw.log"),
    "nginx": ("nginx", "access", "test-access.log"),
    "apache": ("apache", "access", "test-access-basic.log"),
    "sshd_auth": ("system", "auth", "test-auth.log"),
    "squid": ("squid", "log", "test-access.log"),
    "sonicwall": ("sonicwall_firewall", "log", "test-general.log"),
}


@dataclass
class Fixture:
    name: str
    lines: list[str]  # raw lines (from event.original, so they align with `expected`)
    expected: list[dict]


def fetch(dest: Path, names: list[str] | None = None) -> list[str]:
    """Download fixtures (expected ECS documents) into dest/<name>.json."""
    dest.mkdir(parents=True, exist_ok=True)
    done = []
    for name in names or list(FIXTURES):
        pkg, ds, test = FIXTURES[name]
        url = f"{BASE}/{pkg}/data_stream/{ds}/_dev/test/pipeline/{test}-expected.json"
        r = httpx.get(url, timeout=60, follow_redirects=True)
        r.raise_for_status()
        docs = [d for d in r.json()["expected"] if d and (d.get("event") or {}).get("original")]
        (dest / f"{name}.json").write_text(
            json.dumps({"source": url, "sha": ELASTIC_SHA, "expected": docs}), encoding="utf-8"
        )
        done.append(name)
    return done


def load(dest: Path, names: list[str] | None = None) -> list[Fixture]:
    out = []
    for name in names or list(FIXTURES):
        path = dest / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"{path} missing: run `privasoc eval fetch` first")
        docs = json.loads(path.read_text(encoding="utf-8"))["expected"]
        out.append(Fixture(name, [d["event"]["original"] for d in docs], docs))
    return out
