"""Actions shared by the command line and the web UI (step 4).

Each function takes the store and the settings, does one human decision or one job, and
returns a plain dict. Front-ends only format the result, so the CLI and the UI can never
drift apart on what "approve" means.
"""

from __future__ import annotations

from collections.abc import Callable

from privasoc import onboarding, vectorgen
from privasoc.config import Settings
from privasoc.pseudo import Pseudonymizer, Vault
from privasoc.sandbox import Sandbox
from privasoc.store import Store


class ActionError(Exception):
    """A decision that cannot be applied (unknown id, wrong state, Vector refused...)."""


def _vector_errors(fn):
    """A missing or broken Vector binary is an operator problem, not a crash."""
    import functools
    import subprocess

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ActionError(f"Vector could not run ({exc}); check PRIVASOC_VECTOR_BIN") from exc

    return wrapper


def pseudonymizer(s: Settings) -> Pseudonymizer:
    s.require_secrets()
    vault = Vault(
        s.vault_path,
        s.hmac_key.get_secret_value().encode(),
        s.vault_key.get_secret_value().encode(),
    )
    return Pseudonymizer(vault)


# ---------------------------------------------------------------------- hosts (D45, D47)


def _host(store: Store, source: str) -> dict:
    h = store.host(source)
    if not h:
        raise ActionError(f"unknown host {source!r}")
    return h


@_vector_errors
def approve_host(store: Store, s: Settings, source: str) -> dict:
    """Known format: ingested at once. Unknown: lines stay in quarantine for `propose`."""
    _host(store, source)
    return onboarding.approve_host(store, s, Sandbox(s.vector_bin), source)


def reject_host(store: Store, source: str) -> dict:
    _host(store, source)
    store.set_host(source, "rejected")
    return {"source": source, "status": "rejected"}


def set_thresholds(store: Store, source: str, values: dict[str, str | float]) -> dict:
    """Per-host health overrides; an empty value removes the override."""
    from privasoc.health import DEFAULTS

    th = dict(_host(store, source)["thresholds"])
    for k, v in values.items():
        if k not in DEFAULTS:
            raise ActionError(f"unknown threshold {k!r}; known: {sorted(DEFAULTS)}")
        if v in ("", None):
            th.pop(k, None)
            continue
        try:
            num = float(v)
        except ValueError as exc:
            raise ActionError(f"{k}: {v!r} is not a number") from exc
        if num < 0:
            raise ActionError(f"{k}: must be positive")
        th[k] = num
    store.set_host(source, thresholds=th)
    return th


def host_health(store: Store, host: dict) -> dict:
    """Current health (D47), recorded in the history when it changes."""
    from privasoc import health

    hs = health.compute(store, host)
    store.record_health(host["source"], hs["status"], hs["reasons"])
    return hs


# ---------------------------------------------------------------------- parsers (D23)


@_vector_errors
def set_parser_status(store: Store, s: Settings, parser_id: str, status: str) -> dict:
    """Approve or reject a parser. Vector's config is regenerated and validated; if Vector
    refuses it, everything is rolled back. An approval backfills the quarantine (D45)."""
    p = store.parser(parser_id)
    if not p:
        raise ActionError(f"unknown parser {parser_id!r}")
    if status == "approved" and p["status"] != "proposed":
        raise ActionError(f"only a proposed parser can be approved (is {p['status']})")
    if status == "rejected" and p["status"] not in {"proposed", "approved"}:
        raise ActionError(f"parser is already {p['status']}")
    previous = p["status"]
    active = [x["id"] for x in store.parsers("approved") if x["source"] == p["source"]]
    store.set_parser_status(parser_id, status)
    path = vectorgen.write(store.parsers("approved"), s.vector_dir)
    error = vectorgen.validate(s.vector_bin, s.vector_dir)
    if error:  # never leave Vector with a config it cannot load
        # Vector refusing the new parser is the parser's fault; Vector not running is not.
        refused = status == "approved" and not error.startswith("cannot run ")
        store.set_parser_status(parser_id, "rejected" if refused else previous)
        for pid in active:  # restore the parser that was active before
            store.set_parser_status(pid, "approved")
        vectorgen.write(store.parsers("approved"), s.vector_dir)
        raise ActionError(f"Vector configuration not applied, rolled back:\n{error[:2000]}")
    out: dict = {"id": parser_id, "status": status, "config": str(path)}
    if status == "approved":
        out.update(
            onboarding.after_parser_approval(store, Sandbox(s.vector_bin), store.parser(parser_id))
        )
    return out


@_vector_errors
def try_parser(store: Store, s: Settings, parser_id: str, limit: int = 20) -> list[dict]:
    """Run a parser now on the latest quarantined lines of its source (local display only):
    the reviewer sees what it would do on today's logs, not only on the generation sample."""
    p = store.parser(parser_id)
    if not p or not p["vrl"]:
        raise ActionError(f"parser {parser_id!r} has no program")
    lines = store.quarantine_sample(p["source"], limit)
    if not lines:
        return []
    res = Sandbox(s.vector_bin).run(p["vrl"], lines)
    if res.compile_error:
        raise ActionError(f"does not compile: {res.compile_error[:500]}")
    return [
        {"raw": raw, "ecs": r.output, "error": r.error}
        for raw, r in zip(lines, res.lines, strict=True)
    ]


def _endpoint(s: Settings, provider: str):
    from privasoc.llm import Endpoint

    if provider == "remote":
        return Endpoint(
            "remote", s.llm_remote_url, s.llm_remote_model, s.llm_remote_api_key.get_secret_value()
        )
    return Endpoint("local", s.llm_local_url, s.llm_local_model, think=s.llm_local_think)


def _generate(store, s, source, provider, lines, mode, say):
    from privasoc.generator import generate
    from privasoc.llm import LLMClient

    if provider == "remote" and not s.llm_remote_url:
        raise ActionError("no remote API configured (PRIVASOC_LLM_REMOTE_URL)")
    llm = LLMClient(
        _endpoint(s, provider),
        call_log=store.log_llm_call,
        timeout=s.llm_timeout,
        max_tokens=s.llm_max_tokens,
        num_ctx=s.llm_num_ctx,
    )
    sandbox = Sandbox(s.vector_bin)
    try:  # fail fast, before minutes of LLM time
        say(f"sandbox: {sandbox.check()}")
        llm.check()
    except RuntimeError as exc:
        raise ActionError(str(exc)) from exc
    pz = pseudonymizer(s)
    if provider == "remote" and s.remote_residual_pass:
        # Step 5: the local model first looks for what the detectors missed. Its findings
        # are applied to this call at once and kept as proposals for a human to review.
        extra = _local_residual_rules(store, s, lines, say)
        pz = pz.with_rules(extra)
    return generate(
        source,
        lines,
        llm,
        pz,
        sandbox,
        k=s.sample_size,
        max_attempts=s.max_attempts,
        progress=say,
        mode=mode,
        min_coverage=s.min_coverage,
    )


def propose(
    store: Store,
    s: Settings,
    source: str,
    provider: str = "local",
    mode: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Ask the LLM for a parser of a quarantined source (pseudonymised samples only)."""
    say = progress or (lambda _msg: None)
    mode = mode or s.parser_mode
    if mode not in {"structured", "vrl"}:
        raise ActionError("mode must be structured or vrl")
    if provider not in {"local", "remote"}:
        raise ActionError("provider must be local or remote")
    host = store.host(source)
    if host and host["status"] != "approved":
        raise ActionError(f"{source!r} is {host['status']}: approve the host first")
    lines = store.quarantine_lines(source)
    if not lines:
        raise ActionError(f"no quarantined lines for {source!r}")
    say(f"{len(lines)} lines, asking {provider} model...")
    out = _generate(store, s, source, provider, lines, mode, say)
    if out.status == "needs_escalation" and provider == "local":
        if s.auto_fallback and s.llm_remote_url:
            say(f"local model: {out.reason}; falling back to remote API (pseudonymised)")
            store.save_parser(
                out.parser_id, source, "failed", out.provider, out.model, out.vrl, out.report()
            )
            out = _generate(store, s, source, "remote", lines, mode, say)
        else:
            say(
                f"local model: {out.reason}. Retry with the remote provider if you accept "
                "sending pseudonymised samples to the API."
            )
    store.save_parser(
        out.parser_id, source, out.status, out.provider, out.model, out.vrl, out.report()
    )
    return {
        "parser_id": out.parser_id,
        "status": out.status,
        "reason": out.reason,
        "metrics": out.metrics,
    }


# ---------------------------------------------------------------------- learned pseudonymisation
# (step 5, D25, D33)


def _local_llm(store: Store, s: Settings):
    import dataclasses

    from privasoc.llm import LLMClient
    from privasoc.pseudo.learn import LocalOnlyError, ensure_local

    if not s.llm_local_model:
        raise ActionError("no local model configured (PRIVASOC_LLM_LOCAL_MODEL)")
    try:
        ensure_local(s.llm_local_url)
    except LocalOnlyError as exc:
        raise ActionError(str(exc)) from exc
    llm = LLMClient(
        dataclasses.replace(_endpoint(s, "local"), think=s.learn_think),
        call_log=store.log_llm_call,
        timeout=s.llm_timeout,
        max_tokens=s.learn_max_tokens,
        num_ctx=s.llm_num_ctx,
    )
    try:
        llm.check()
    except RuntimeError as exc:
        raise ActionError(str(exc)) from exc
    return llm


def _learn(store: Store, s: Settings, lines: list[str], say, origin: str = "llm") -> list[dict]:
    import httpx

    from privasoc.pseudo import learn
    from privasoc.sampling import stratified_sample

    llm = _local_llm(store, s)
    pz = pseudonymizer(s)
    try:
        idx, _ = stratified_sample(lines, s.learn_sample)
        sample = [lines[i] for i in sorted(idx)]
        say(f"{len(sample)} lines (one per template first) shown to the local model")
        try:
            findings = learn.residual_pass(llm, pz, sample, batch=s.learn_batch, progress=say)
        except httpx.HTTPError as exc:
            raise ActionError(f"local model error: {exc}") from exc
        out = []
        for rule in learn.to_rules(findings, origin):
            new = pz.vault.add_rule(rule)
            stored = pz.vault.rule(rule.id)
            eff = learn.preview(pz, rule, lines, examples=0)
            out.append(
                {
                    "id": rule.id,
                    "label": rule.label(),
                    "kind": rule.kind,
                    "new": new,
                    "status": stored.status if stored else rule.status,
                    "changed": eff["changed"],
                    "rule": rule,
                }
            )
        return out
    finally:
        pz.vault.close()


def _local_residual_rules(store: Store, s: Settings, lines: list[str], say) -> list:
    """Rules to apply to one remote call: new proposals plus earlier proposals that are
    still waiting (never the rejected ones)."""
    try:
        found = _learn(store, s, lines, say, origin="llm")
    except ActionError as exc:
        raise ActionError(
            f"local residual pass unavailable ({exc}). The remote API is only called after "
            "the local model has checked the samples; set PRIVASOC_REMOTE_RESIDUAL_PASS=false "
            "to rely on the regex detectors alone."
        ) from exc
    extra = [f["rule"] for f in found if f["status"] == "proposed"]
    say(f"local residual pass: {len(extra)} extra rule(s) applied to this remote call")
    return extra


def learn_rules(
    store: Store, s: Settings, source: str, progress: Callable[[str], None] | None = None
) -> list[dict]:
    """Ask the local model what the current rules miss in a source's latest lines."""
    say = progress or (lambda _m: None)
    host = store.host(source)
    if not host:
        raise ActionError(f"unknown host {source!r}")
    if host["status"] != "approved":
        raise ActionError(f"{source!r} is {host['status']}: its lines go to no model")
    lines = store.recent_raw(source, 500)
    if not lines:
        raise ActionError(f"no line for {source!r} yet")
    return [{k: v for k, v in f.items() if k != "rule"} for f in _learn(store, s, lines, say)]


def list_rules(s: Settings, status: str | None = None) -> list:
    pz = pseudonymizer(s)
    try:
        return pz.vault.rules(status)
    finally:
        pz.vault.close()


def add_rule(s: Settings, rtype: str, kind: str, pattern: str, approve: bool = False):
    from privasoc.pseudo.rules import Rule, RuleError, validate

    try:
        pattern = validate(rtype, kind, pattern)
    except RuleError as exc:
        raise ActionError(str(exc)) from exc
    rule = Rule(rtype, kind, pattern, "approved" if approve else "proposed", "human")
    pz = pseudonymizer(s)
    try:
        if not pz.vault.add_rule(rule):
            raise ActionError(f"rule {rule.id} already exists ({pz.vault.rule(rule.id).status})")
    finally:
        pz.vault.close()
    return rule


def set_rule_status(s: Settings, rule_id: str, status: str):
    if status not in {"approved", "rejected"}:
        raise ActionError("status must be approved or rejected")
    pz = pseudonymizer(s)
    try:
        rule = pz.vault.rule(rule_id)
        if not rule:
            raise ActionError(f"unknown rule {rule_id!r}")
        if status == "approved":  # re-validate: the model's proposals are untrusted input
            from privasoc.pseudo.rules import RuleError, validate

            try:
                validate(rule.rtype, rule.kind, rule.pattern)
            except RuleError as exc:
                raise ActionError(f"cannot approve: {exc}") from exc
        pz.vault.set_rule_status(rule_id, status)
        return pz.vault.rule(rule_id)
    finally:
        pz.vault.close()


def rule_preview(store: Store, s: Settings, rule_id: str, source: str | None = None) -> dict:
    """Effect of a rule on the latest real lines (all approved hosts, or one)."""
    from privasoc.pseudo import learn

    pz = pseudonymizer(s)
    try:
        rule = pz.vault.rule(rule_id)
        if not rule:
            raise ActionError(f"unknown rule {rule_id!r}")
        # measured against the other approved rules, without this one
        pz.rules = type(pz.rules)([r for r in pz.rules.rules if r.id != rule_id])
        lines = store.recent_raw(source, 1000)
        return {"rule": rule, **learn.preview(pz, rule, lines)}
    finally:
        pz.vault.close()
