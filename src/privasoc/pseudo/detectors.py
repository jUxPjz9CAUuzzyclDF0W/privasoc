"""Typed detectors for sensitive values in arbitrary (possibly unknown-format) log text.

Detection is deliberately format-agnostic: we do not have a parser yet when we need to
pseudonymise the samples sent to the LLM that will write one. Detectors are regexes plus
key=value heuristics; overlaps are resolved by priority then length.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Entity:
    kind: str  # ipv4 | ipv6 | mac | email | fqdn | sid | user | host
    start: int
    end: int
    value: str


# Priority for overlap resolution: higher wins.
PRIORITY = {
    "email": 90,
    "sid": 80,
    "mac": 70,
    "ipv6": 65,
    "ipv4": 60,
    "user": 50,  # user paths and keyed values
    "fqdn": 40,
    "host": 30,
    "token": 100,  # an existing pseudonym: never re-pseudonymise
}

# Last labels that look like TLDs but are file extensions or code namespaces.
NOT_TLDS = {
    "list",
    "lock",
    "pid",
    "sock",
    "bak",
    "old",
    "service",
    "socket",
    "timer",
    "exe",
    "dll",
    "sys",
    "log",
    "txt",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "js",
    "py",
    "sh",
    "json",
    "xml",
    "yml",
    "yaml",
    "conf",
    "cfg",
    "ini",
    "tmp",
    "dat",
    "db",
    "gz",
    "zip",
    "tar",
    "msi",
    "lnk",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "pdf",
    "png",
    "jpg",
    "html",
    "htm",
    "php",
    "asp",
    "aspx",
    "jsp",
    "md",
    "rs",
    "go",
    "cs",
    "vb",
    "ps",
    "pl",
    "rb",
    "so",
}
# Accept any 2-letter ccTLD (minus NOT_TLDS) plus these.
LONG_TLDS = {
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "io",
    "dev",
    "app",
    "cloud",
    "online",
    "site",
    "xyz",
    "top",
    "local",
    "lan",
    "home",
    "internal",
    "corp",
    "arpa",
    "localdomain",
    "intra",
    "example",
    "test",
    "invalid",
    "localhost",
    "tech",
    "store",
    "shop",
    "live",
    "news",
    "blog",
    "google",
    "microsoft",
    "amazon",
    "aws",
}

_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b")
_MAC = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_FQDN = re.compile(
    r"(?<![\w@.\-/\\])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
)
_WIN_PATH_USER = re.compile(r"(?i)\b[A-Z]:\\{1,2}Users\\{1,2}([^\\\s\"',;]+)")
_NIX_PATH_USER = re.compile(r"(?<![\w.])/(?:home|Users)/([^/\s\"',;]+)")
_TOKEN = re.compile(r"\b(?:user|host)-[0-9a-f]{6}\b")

_USER_KEYS = (
    r"user(?:_?name)?|suser|duser|usr|xauthuser|remuser|administrator|src_?user(?:_?name)?"
    r"|dst_?user(?:_?name)?|account(?:_?name)?"
    r"|login|uid|owner|target_?user(?:_?name)?|subject_?user(?:_?name)?"
)
_HOST_KEYS = (
    r"host(?:_?name)?|shost|dhost|src_?host|dst_?host|computer(?:_?name)?|device(?:_?name)?"
    r"|machine(?:_?name)?|workstation(?:_?name)?|client_?name|origin_?sic_?name"
    r"|devname|dvchost|dvc_?host|fqdn|server_?name|srcname|dstname"
)
_KV = re.compile(
    rf"(?i)(?<![\w-])\"?(?:(?P<ukey>{_USER_KEYS})|(?P<hkey>{_HOST_KEYS}))\"?\s*[=:]\s*"
    r"(?:\"(?P<qval>[^\"]{2,64})\"|(?P<val>[^\s\",;|}\]\[]+))"
)
_KV_SKIP = {
    "-",
    "",
    "null",
    "none",
    "n/a",
    "na",
    "unknown",
    "system",
    "local",
    "localhost",
    "true",
    "false",
    "0",
    "anonymous",
}


def _tld_ok(name: str) -> bool:
    """Known TLDs are always accepted. Any other alphabetic TLD is accepted when the whole
    name is lowercase: private TLDs (.lan, .home, .lab...) are common in homelabs, while
    code namespaces (System.Management.Automation) are capitalised."""
    t = name.rsplit(".", 1)[1].lower()
    if t in NOT_TLDS:
        return False
    return len(t) == 2 or t in LONG_TLDS or name == name.lower()


def _ipv4_sensitive(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip == ipaddress.IPv4Address("255.255.255.255")
    )


def _ipv6_sensitive(value: str) -> bool:
    if value.count(":") < 2:
        return False
    try:
        ip = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


# Context patterns (added after measuring leakage on real vendor formats, see I20).
_SYSLOG_HOST = re.compile(  # RFC 3164 / RFC 5424 header: the field after the timestamp
    r"^(?:<\d+>)?(?:\d+ )?(?:[A-Z][a-z]{2} +\d{1,2} (?:\d{4} )?\d\d:\d\d:\d\d"
    r"|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?) (?P<host>[A-Za-z0-9][\w.-]*?):? "
)
_USER_PHRASES = re.compile(
    r"(?i)\b(?:(?:accepted|failed) \w+ for (?:invalid user )?|(?:invalid|illegal) user |"
    r"session (?:opened|closed) for user |for user |by user |user(?:name)? ['\"]|"
    r"authentication failure for |user <)(?P<user>[A-Za-z0-9._\\$@-]{2,})"
)
_PRI_HOST = re.compile(r"^<\d+>(?P<host>[A-Za-z][\w.-]*) [%:]")
_SUDO_USER = re.compile(r"\bsudo:\s+(?P<user>[A-Za-z0-9._-]+) : ")
_DOMAIN_USER = re.compile(  # DOMAIN\user or DOMAIN\group\user
    r"(?<![\w\\])[A-Za-z][\w-]{1,15}\\(?:[\w-]+\\)?(?P<user>[A-Za-z][\w.$-]*)"
)
_CLF_USER = re.compile(  # Common/Combined Log Format: host ident authuser [date]
    r"^(?P<client>\S+) (?P<ident>\S+) (?P<auth>\S+) \[\d"
)
_URL_HOST = re.compile(r"\b[a-zA-Z][\w+.-]*://(?:[^@/\s]*@)?(?P<host>[\w.-]+)")
_HEXRUN = re.compile(r"[0-9A-Fa-f:]{4,}")


def _ipv6_candidates(text: str):
    """Longest valid IPv6 inside each hex/colon run: handles `outside:2a02:...` prefixes,
    which a lookbehind cannot tell apart from the address itself."""
    for run in _HEXRUN.finditer(text):
        s = run.group(0)
        if s.count(":") < 2:
            continue
        starts = [0] + [i + 1 for i, c in enumerate(s) if c == ":"]
        for st in starts:
            cand = s[st:].rstrip(":") if not s.endswith("::") else s[st:]
            if _ipv6_sensitive(cand):
                yield run.start() + st, run.start() + st + len(cand), cand
                break


def detect(text: str) -> list[Entity]:
    """Return non-overlapping sensitive entities, sorted by position."""
    found: list[Entity] = []

    def add(kind: str, m: re.Match, group: int | str = 0) -> None:
        found.append(Entity(kind, m.start(group), m.end(group), m.group(group)))

    for m in _TOKEN.finditer(text):
        add("token", m)
    for m in _EMAIL.finditer(text):
        add("email", m)
    for m in _SID.finditer(text):
        add("sid", m)
    for m in _MAC.finditer(text):
        add("mac", m)
    for m in _IPV4.finditer(text):
        if _ipv4_sensitive(m.group(0)):
            add("ipv4", m)
    for a, b, v in _ipv6_candidates(text):
        found.append(Entity("ipv6", a, b, v))
    for m in _FQDN.finditer(text):
        if _tld_ok(m.group(0)):
            add("fqdn", m)
    for rx in (_WIN_PATH_USER, _NIX_PATH_USER):
        for m in rx.finditer(text):
            if m.group(1).lower() not in {"public", "default", "all users", "shared"}:
                add("user", m, 1)
    m = _SYSLOG_HOST.match(text)
    if m and m.group("host").lower() not in _KV_SKIP and not m.group("host").isdigit():
        add("host", m, "host")
    for m in _USER_PHRASES.finditer(text):
        if m.group("user").lower() not in _KV_SKIP:
            add("user", m, "user")
    m = _CLF_USER.match(text)
    if m:
        for g in ("ident", "auth"):
            if m.group(g) != "-":
                add("user", m, g)
        if m.group("client").lower() not in _KV_SKIP:
            add("host", m, "client")  # an IP here is won by the IP detectors (priority)
    for m in _URL_HOST.finditer(text):
        h = m.group("host")
        if not _ipv4_sensitive(h) and "." in h and h.lower() != "localhost":
            found.append(Entity("fqdn", m.start("host"), m.end("host"), h))
    m = _PRI_HOST.match(text)
    if m:
        add("host", m, "host")
    for m in _SUDO_USER.finditer(text):
        add("user", m, "user")
    for m in _DOMAIN_USER.finditer(text):
        add("user", m, "user")
    for m in _KV.finditer(text):
        g = "qval" if m.group("qval") is not None else "val"
        val = m.group(g)
        if val.lower() in _KV_SKIP or len(val) < 2 or val.lower().startswith("unknown"):
            continue
        add("user" if m.group("ukey") else "host", m, g)

    # Resolve overlaps: highest priority, then longest span, wins.
    found.sort(key=lambda e: (-PRIORITY[e.kind], -(e.end - e.start), e.start))
    chosen: list[Entity] = []
    for e in found:
        if all(e.end <= c.start or e.start >= c.end for c in chosen):
            chosen.append(e)
    return sorted((e for e in chosen if e.kind != "token"), key=lambda e: e.start)
