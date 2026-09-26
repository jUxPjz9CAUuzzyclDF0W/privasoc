"""Run a VRL program on sample lines inside Vector's VRL runtime (D9, D19).

VRL cannot execute code, open files or reach the network, which is why LLM-written
parsers are VRL and not Python. We still harden the call: a static denylist rejects the
few functions that read the host environment, the process runs with an empty environment,
and every line runs in its own process with a timeout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

DENYLIST = (
    "get_env_var",
    "get_hostname",
    "get_secret",
    "set_secret",
    "remove_secret",
    "http_request",
    "dns_lookup",
    "reverse_dns",
    "get_timezone_name",
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_LOGLINE = re.compile(r"^\S+Z\s+(INFO|WARN|DEBUG)\s")
_TIMESTAMP = re.compile(r"t'([^']*)'")


@dataclass
class LineResult:
    output: dict | None = None
    error: str | None = None


@dataclass
class SandboxResult:
    compile_error: str | None = None
    lines: list[LineResult] = field(default_factory=list)

    @property
    def outputs(self) -> list[dict]:
        return [r.output for r in self.lines if r.output is not None]

    @property
    def runtime_errors(self) -> list[str]:
        return [r.error for r in self.lines if r.error]


def _clean(text: str) -> str:
    lines = [ln for ln in _ANSI.sub("", text).splitlines() if not _LOGLINE.match(ln)]
    return "\n".join(lines).strip()


def _parse_object(text: str) -> dict:
    """`vector vrl --print-object` prints VRL values; timestamps look like t'...'."""
    return json.loads(_TIMESTAMP.sub(lambda m: json.dumps(m.group(1)), text))


class Sandbox:
    def __init__(self, vector_bin: str = "vector", timeout: float = 20.0, workers: int = 4):
        self.vector_bin = vector_bin
        self.timeout = timeout
        self.workers = workers

    def check(self) -> str:
        """Return the Vector version, or raise a clear error if the binary is unusable."""
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv
                [self.vector_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (FileNotFoundError, PermissionError) as exc:
            raise RuntimeError(
                f"Vector binary not found at {self.vector_bin!r}: set PRIVASOC_VECTOR_BIN"
            ) from exc
        if proc.returncode != 0:
            raise RuntimeError(f"{self.vector_bin} --version failed: {proc.stderr[:300]}")
        return proc.stdout.strip()

    def _run(self, program_path: Path, raw: str, tmp: Path, i: int) -> tuple[int, str, str]:
        inp = tmp / f"in{i}.json"
        inp.write_text(json.dumps({"message": raw}) + "\n", encoding="utf-8")
        env = {"NO_COLOR": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}  # Windows needs it
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                self.vector_bin,
                "vrl",
                "--input",
                str(inp),
                "--program",
                str(program_path),
                "--print-object",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",  # Vector writes UTF-8; Windows would default to cp1252
            errors="replace",
            timeout=self.timeout,
            env=env,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def run(self, program: str, raw_lines: list[str]) -> SandboxResult:
        banned = [f for f in DENYLIST if re.search(rf"\b{f}\s*!?\s*\(", program)]
        if banned:
            return SandboxResult(compile_error=f"forbidden function(s): {', '.join(banned)}")
        with tempfile.TemporaryDirectory(prefix="privasoc-vrl-") as d:
            tmp = Path(d)
            prog = tmp / "program.vrl"
            prog.write_text(program, encoding="utf-8")
            # Compile check once, on the first line.
            rc, out, err = self._run(prog, raw_lines[0] if raw_lines else "", tmp, 0)
            if rc != 0:
                return SandboxResult(compile_error=_clean(err + "\n" + out) or f"exit {rc}")
            with ThreadPoolExecutor(self.workers) as ex:
                runs = list(
                    ex.map(lambda a: self._run(prog, a[1], tmp, a[0]), enumerate(raw_lines))
                )
        result = SandboxResult()
        for rc, out, err in runs:
            out = _clean(out)
            if rc != 0:
                result.lines.append(LineResult(error=_clean(err) or f"exit {rc}"))
            elif not out:
                result.lines.append(LineResult(error=_clean(err) or "no output"))
            else:
                try:
                    result.lines.append(LineResult(output=_parse_object(out.splitlines()[-1])))
                except json.JSONDecodeError:
                    result.lines.append(LineResult(error=f"unreadable output: {out[:200]}"))
        return result
