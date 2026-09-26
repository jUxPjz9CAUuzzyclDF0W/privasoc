"""One client for every OpenAI-compatible server, local or remote (D12, D28, D36).

The client refuses to send a message that contains any original (un-pseudonymised) value:
the leak check is enforced here, at the only door to the outside, for every provider.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx

from privasoc.pseudo import Pseudonymizer

_THINK = re.compile(r"<think>.*?</think>", re.S)


class LeakError(RuntimeError):
    """An outgoing prompt still contains original values."""


@dataclass(frozen=True)
class Endpoint:
    name: str  # "local" or "remote"
    url: str
    model: str
    api_key: str = ""
    think: bool = True  # False: ask reasoning models to answer directly (much faster)

    @property
    def remote(self) -> bool:
        return self.name != "local"


@dataclass
class Reply:
    text: str
    latency_s: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    finish_reason: str | None = None  # "length" = truncated by max_tokens


class LLMClient:
    def __init__(
        self, endpoint: Endpoint, timeout: float = 300.0, call_log=None, max_tokens: int = 2048
    ):
        if not endpoint.url or not endpoint.model:
            raise ValueError(f"{endpoint.name} LLM needs a URL and a model name")
        self.endpoint = endpoint
        self.timeout = timeout
        self.call_log = call_log  # callable(dict) -> None
        self.max_tokens = max_tokens  # a runaway generation must not block for minutes

    def _headers(self) -> dict:
        key = self.endpoint.api_key
        return {"Authorization": f"Bearer {key}"} if key else {}

    def check(self) -> None:
        """Fail fast with a clear message if the server or the model is missing."""
        url = f"{self.endpoint.url.rstrip('/')}/models"
        try:
            r = httpx.get(url, headers=self._headers(), timeout=10)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"{self.endpoint.name} LLM unreachable at {self.endpoint.url}: {exc}"
            ) from exc
        ids = {m.get("id") for m in r.json().get("data", [])}
        if ids and self.endpoint.model not in ids:
            raise RuntimeError(
                f"model {self.endpoint.model!r} not served; available: {sorted(ids)}"
            )

    def chat(
        self,
        messages: list[dict],
        *,
        originals: set[str],
        json_mode: bool = True,
        temperature: float = 0.2,
    ) -> Reply:
        if not self.endpoint.think and messages and messages[-1]["role"] == "user":
            # Qwen3-style soft switch; ignored by models without a reasoning mode.
            messages = [
                *messages[:-1],
                {**messages[-1], "content": messages[-1]["content"] + "\n/no_think"},
            ]
        outgoing = "\n".join(m["content"] for m in messages)
        leaks = Pseudonymizer.leaks(outgoing, originals)
        if leaks:
            raise LeakError(f"{len(leaks)} original value(s) in the prompt; refusing to send")
        body = {
            "model": self.endpoint.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if not self.endpoint.think and not self.endpoint.remote:
            body["reasoning_effort"] = "none"  # Ollama: disables thinking (the only way on /v1)
        headers = (
            {"Authorization": f"Bearer {self.endpoint.api_key}"} if self.endpoint.api_key else {}
        )
        t0 = time.monotonic()
        resp = httpx.post(
            f"{self.endpoint.url.rstrip('/')}/chat/completions",
            json=body,
            headers=headers,
            timeout=self.timeout,
        )
        if resp.status_code == 400 and "reasoning_effort" in body:
            body.pop("reasoning_effort")  # a server that does not know the field
            resp = httpx.post(
                f"{self.endpoint.url.rstrip('/')}/chat/completions",
                json=body,
                headers=headers,
                timeout=self.timeout,
            )
        latency = time.monotonic() - t0
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage") or {}
        text = _THINK.sub("", data["choices"][0]["message"].get("content") or "").strip()
        reply = Reply(
            text,
            latency,
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
            data["choices"][0].get("finish_reason"),
        )
        if self.call_log:
            self.call_log(
                {
                    "provider": self.endpoint.name,
                    "model": self.endpoint.model,
                    "prompt_chars": len(outgoing),
                    "pseudonymised_values": len(originals),
                    "latency_s": round(latency, 3),
                    "prompt_tokens": reply.prompt_tokens,
                    "completion_tokens": reply.completion_tokens,
                }
            )
        return reply
