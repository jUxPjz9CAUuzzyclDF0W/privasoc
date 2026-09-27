"""Pseudonymise text before any LLM call, re-identify answers, and check for leaks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from privasoc.pseudo.detectors import Entity, detect
from privasoc.pseudo.rules import RuleSet
from privasoc.pseudo.vault import Vault


@dataclass
class PseudoResult:
    text: str
    # (kind, token) for every replacement, in order of appearance
    replacements: list[tuple[str, str]] = field(default_factory=list)
    # originals that must never appear in anything derived from `text`
    originals: set[str] = field(default_factory=set)
    # original -> pseudonym, for propagation across several lines
    mapping: dict[str, str] = field(default_factory=dict)


class Pseudonymizer:
    def __init__(self, vault: Vault, rules: RuleSet | None = None):
        self.vault = vault
        # Learned rules (step 5): only the approved ones change what is detected.
        self.rules = rules if rules is not None else RuleSet(vault.rules("approved"))

    def reload_rules(self) -> None:
        self.rules = RuleSet(self.vault.rules("approved"))

    def with_rules(self, extra) -> Pseudonymizer:
        """Same vault, approved rules plus `extra` (a preview, or a one-off local pass)."""
        return Pseudonymizer(self.vault, self.rules.plus(extra))

    def _register_fqdn_suffixes(self, fqdn: str) -> None:
        # So that a bare parent domain written by the LLM can be re-identified too.
        labels = fqdn.split(".")
        for i in range(1, len(labels) - 1):
            self.vault.token_for("fqdn", ".".join(labels[i:]))

    def pseudonymize(self, text: str) -> PseudoResult:
        result = PseudoResult(text=text)
        pieces: list[str] = []
        cursor = 0
        for ent in detect(text, self.rules):
            token = self.vault.token_for(ent.kind, ent.value)
            if ent.kind == "fqdn":
                self._register_fqdn_suffixes(ent.value)
            elif ent.kind == "email":
                domain = ent.value.partition("@")[2]
                self.vault.token_for("fqdn", domain)
                self._register_fqdn_suffixes(domain)
            pieces.append(text[cursor : ent.start])
            pieces.append(token)
            cursor = ent.end
            result.replacements.append((ent.kind, token))
            result.originals.add(ent.value)
        pieces.append(text[cursor:])
        out = "".join(pieces)
        # Propagation: a value detected once (e.g. a keyed user) is replaced everywhere in
        # the text, including free-text mentions no detector would have caught.
        seen = {}
        for ent in detect(text, self.rules):
            seen[ent.value] = self.vault.token_for(ent.kind, ent.value)
        for original in sorted(seen, key=len, reverse=True):
            out = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])",
                lambda _m, t=seen[original]: t,
                out,
                flags=re.I,
            )
        result.text = out
        result.mapping = seen
        result.originals |= set(seen)
        return result

    def field_value(self, path: str, value: str) -> PseudoResult:
        """Pseudonymise one ECS field value, using the field's meaning when the text alone
        says nothing (`"user": {"name": "bob"}` holds a user whatever `bob` looks like)."""
        kind = sensitive_kind(path, value)
        if kind is None:
            return self.pseudonymize(value)
        token = self.vault.token_for(kind, value)
        if kind == "fqdn":
            self._register_fqdn_suffixes(value)
        return PseudoResult(token, [(kind, token)], {value}, {value: token})

    def pseudonymize_doc(self, doc: dict) -> PseudoResult:
        """A whole ECS document: sensitive fields by meaning first, then every string by the
        detectors, with the values found propagated everywhere (event.original included).
        Returns the JSON text of the pseudonymised document."""
        import json

        mapping: dict[str, str] = {}
        originals: set[str] = set()

        def first(x, path=""):
            if isinstance(x, dict):
                for k, v in x.items():
                    first(v, f"{path}.{k}" if path else k)
            elif isinstance(x, list):
                for v in x:
                    first(v, path)
            elif isinstance(x, str) and sensitive_kind(path, x):
                r = self.field_value(path, x)
                mapping.update(r.mapping)
                originals.update(r.originals)

        first(doc)

        def walk(x):
            if isinstance(x, dict):
                return {k: walk(v) for k, v in x.items()}
            if isinstance(x, list):
                return [walk(v) for v in x]
            if isinstance(x, str):
                # detectors first, then values known from other fields: the other order
                # would pseudonymise a pseudonym (an IP token is itself an IP)
                r = self.pseudonymize(x)
                mapping.update(r.mapping)
                originals.update(r.originals)
                return Pseudonymizer.propagate(r.text, mapping)
            return x

        out = walk(doc)
        text = json.dumps(out, separators=(",", ":"), ensure_ascii=False)
        return PseudoResult(Pseudonymizer.propagate(text, mapping), [], originals, mapping)

    @staticmethod
    def propagate(text: str, mapping: dict[str, str]) -> str:
        """Replace values detected in *other* lines (a host keyed in one line may appear
        bare in the next: found by the leak guard on iptables logs)."""
        for original in sorted(mapping, key=len, reverse=True):
            text = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])",
                lambda _m, t=mapping[original]: t,
                text,
                flags=re.I,
            )
        return text

    def reidentify(self, text: str) -> str:
        """Replace every known pseudonym in `text` by its original (display only)."""
        pieces: list[str] = []
        cursor = 0
        for ent in _detect_with_tokens(text):
            original = self.vault.original(ent.value)
            if original is None:
                continue
            pieces.append(text[cursor : ent.start])
            pieces.append(original)
            cursor = ent.end
        pieces.append(text[cursor:])
        return "".join(pieces)

    @staticmethod
    def leaks(outgoing: str, originals: set[str]) -> list[str]:
        """Originals that still appear in an outgoing prompt (must be empty to send)."""
        found = []
        for o in originals:
            if o and re.search(rf"(?<![A-Za-z0-9]){re.escape(o)}(?![A-Za-z0-9])", outgoing, re.I):
                found.append(o)
        return sorted(found)


def _detect_with_tokens(text: str):
    """Detectors, but with our own user-/host- tokens reported instead of skipped."""
    ents = list(detect(text))
    for m in re.finditer(r"\b(?:user|host)-[0-9a-f]{6}\b", text):
        ents.append(Entity("token", m.start(), m.end(), m.group(0)))
    return sorted(ents, key=lambda e: e.start)


_USER_FIELDS = ("user.name", "user.full_name", "user.email", "user.target.name",
                "user.effective.name", "user.changes.name")  # fmt: skip
_HOST_FIELDS = ("host.name", "host.hostname", "observer.name", "observer.hostname",
                "client.domain", "server.domain", "source.domain", "destination.domain",
                "user.domain", "host.domain")  # fmt: skip


def sensitive_kind(path: str, value: str) -> str | None:
    """Pseudonym kind implied by an ECS field, or None when the field says nothing."""
    import ipaddress

    v = value.strip()
    if not v or v in {"-", "unknown", "localhost", "root", "system", "SYSTEM"}:
        return None
    if path.endswith(("user.email",)) and "@" in v:
        return "email"
    if path.endswith(_USER_FIELDS) or path == "user.id" and not v.isdigit():
        return "user"
    if path.endswith(_HOST_FIELDS):
        try:
            ipaddress.ip_address(v)
            return None  # the IP detectors handle it with their own shape
        except ValueError:
            pass
        return "fqdn" if "." in v and v.split(".")[-1].isalpha() else "host"
    return None
