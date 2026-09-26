"""Drain template clustering and stratified sampling (D35).

Drain groups log lines into templates ("Accepted password for <*> from <*>"). We use it
so the K lines shown to the LLM cover every variant of a format, and to report which
share of templates a parser handles.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

logging.getLogger("drain3").setLevel(logging.WARNING)


@dataclass
class Cluster:
    cluster_id: int
    template: str
    indices: list[int]


def cluster(lines: list[str]) -> list[Cluster]:
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    miner = TemplateMiner(config=cfg)
    members: dict[int, list[int]] = {}
    for i, line in enumerate(lines):
        r = miner.add_log_message(line)
        members.setdefault(r["cluster_id"], []).append(i)
    templates = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    out = [Cluster(cid, templates.get(cid, ""), idx) for cid, idx in members.items()]
    return sorted(out, key=lambda c: -len(c.indices))


def stratified_sample(lines: list[str], k: int) -> tuple[list[int], list[Cluster]]:
    """Round-robin over templates (largest first) until k lines are picked."""
    clusters = cluster(lines)
    picked: list[int] = []
    depth = 0
    while len(picked) < min(k, len(lines)):
        progressed = False
        for c in clusters:
            if depth < len(c.indices) and len(picked) < k:
                picked.append(c.indices[depth])
                progressed = True
        if not progressed:
            break
        depth += 1
    return picked, clusters
