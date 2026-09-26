"""Shape-preserving pseudonym generation (D15, D25).

A token keeps the lexical shape of what it replaces (an IP stays a valid IP, an email a
valid email...), so that a parser written on pseudonymised samples still works on real data.
Every function is deterministic given (key, value, salt); the salt is only bumped by the
vault to resolve the rare collision.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

INTERNAL_TLDS = {"local", "lan", "home", "internal", "corp", "localdomain", "intra"}


def _h(key: bytes, *parts: str) -> bytes:
    return hmac.new(key, "\x00".join(parts).encode(), hashlib.sha256).digest()


def _hex(key: bytes, *parts: str, n: int = 6) -> str:
    return _h(key, *parts).hex()[:n]


def user_token(key: bytes, value: str, salt: int = 0) -> str:
    return f"user-{_hex(key, 'user', value.lower(), str(salt))}"


def host_token(key: bytes, value: str, salt: int = 0) -> str:
    return f"host-{_hex(key, 'host', value.lower(), str(salt))}"


def fqdn_token(key: bytes, value: str, salt: int = 0) -> str:
    """Label-wise, suffix-consistent: a.corp.lan and b.corp.lan share the same pseudonymised
    suffix, so domain hierarchy survives. The TLD is kept (not identifying on its own)."""
    labels = value.lower().split(".")
    out = [labels[-1]]
    for i in range(len(labels) - 2, -1, -1):
        suffix = ".".join(labels[i:])
        s = str(salt) if i == 0 else "0"
        out.insert(0, "d" + _hex(key, "fqdn", suffix, s))
    return ".".join(out)


def email_token(key: bytes, value: str, salt: int = 0) -> str:
    local, _, domain = value.partition("@")
    return (
        f"u{_hex(key, 'email', local.lower(), domain.lower(), str(salt))}@{fqdn_token(key, domain)}"
    )


def ipv4_token(key: bytes, value: str, salt: int = 0) -> str:
    """Private stays private (10/8), public maps to 198.18.0.0/15 (benchmarking range, never
    routed). The /24 is mapped consistently, so hosts of one subnet stay in one subnet."""
    ip = ipaddress.IPv4Address(value)
    prefix = ".".join(value.split(".")[:3])
    p = _h(key, "ipv4-prefix", prefix)
    last = 1 + _h(key, "ipv4", value, str(salt))[0] % 254
    if ip.is_private or ip.is_link_local or ip.is_reserved:
        return f"10.{p[0]}.{p[1]}.{last}"
    return f"198.{18 + (p[0] & 1)}.{p[1]}.{last}"


def ipv6_token(key: bytes, value: str, salt: int = 0) -> str:
    """Mapped into the documentation prefix 2001:db8::/32; the /64 is kept consistent."""
    ip = ipaddress.IPv6Address(value)
    prefix64 = ip.exploded[:19]
    p = _h(key, "ipv6-prefix", prefix64)
    h = _h(key, "ipv6", ip.exploded, str(salt))
    groups = [p[0:2], p[2:4], h[0:2], h[2:4], h[4:6], h[6:8]]
    return str(ipaddress.IPv6Address("2001:db8:" + ":".join(g.hex() for g in groups)))


def mac_token(key: bytes, value: str, salt: int = 0) -> str:
    """Locally administered unicast (02:...) with the original separator."""
    sep = "-" if "-" in value else ":"
    h = _h(key, "mac", value.lower().replace("-", ":"), str(salt))
    return sep.join(["02", *(f"{b:02x}" for b in h[:5])])


def sid_token(key: bytes, value: str, salt: int = 0) -> str:
    """Domain part pseudonymised consistently, RID kept (500, 512... carry meaning)."""
    parts = value.split("-")
    domain = "-".join(parts[4:7])
    h = _h(key, "sid", domain, str(salt))
    subs = [str(int.from_bytes(h[i : i + 4], "big")) for i in (0, 4, 8)]
    rid = parts[7:] if len(parts) > 7 else []
    return "-".join(["S", "1", "5", "21", *subs, *rid])


GENERATORS = {
    "user": user_token,
    "host": host_token,
    "fqdn": fqdn_token,
    "email": email_token,
    "ipv4": ipv4_token,
    "ipv6": ipv6_token,
    "mac": mac_token,
    "sid": sid_token,
}
