"""Background jobs for the web UI: parser generation takes minutes on a small GPU, so the
request returns at once and the page polls the job's log (htmx)."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from privasoc.store import utcnow


@dataclass
class Job:
    id: str
    kind: str
    target: str
    started_at: str
    status: str = "running"  # running | done | error
    log: list[str] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None


class Jobs:
    """At most one generation at a time: the local model runs on one GPU."""

    def __init__(self, keep: int = 20):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._keep = keep

    def running(self) -> Job | None:
        with self._lock:
            return next((j for j in self._jobs.values() if j.status == "running"), None)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)

    def start(self, kind: str, target: str, fn: Callable[[Callable[[str], None]], dict]) -> Job:
        with self._lock:
            if any(j.status == "running" for j in self._jobs.values()):
                raise RuntimeError("a generation is already running; wait for it to finish")
            job = Job(secrets.token_hex(6), kind, target, utcnow())
            self._jobs[job.id] = job
            for old in sorted(self._jobs.values(), key=lambda j: j.started_at)[: -self._keep]:
                if old.status != "running":
                    del self._jobs[old.id]

        def run() -> None:
            try:
                job.result = fn(job.log.append)
                job.status = "done"
            except Exception as exc:  # noqa: BLE001 - shown to the operator, never raised
                job.error, job.status = str(exc)[:2000], "error"

        threading.Thread(target=run, name=f"privasoc-{kind}", daemon=True).start()
        return job
