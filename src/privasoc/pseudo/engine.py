"""Pseudonymise text before any LLM call, re-identify answers, and check for leaks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from privasoc.pseudo.detectors import Entity, detect
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
    def __init__(self, vault: Vault):
        self.vault = vault

    def _register_fqdn_suffixes(self, fqdn: str) -> None:
        # So that a bare parent domain written by the LLM can be re-identified too.
        labels = fqdn.split(".")
        for i in range(1, len(labels) - 1):
            self.vault.token_for("fqdn", ".".join(labels[i:]))

    def pseudonymize(self, text: str) -> PseudoResult:
        result = PseudoResult(text=text)
        pieces: list[str] = []
        cursor = 0
        for ent in detect(text):
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
        for ent in detect(text):
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
