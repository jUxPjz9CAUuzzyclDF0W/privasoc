import ipaddress
import os
import re

import pytest

from privasoc.pseudo.detectors import detect

LINES = [
    # Pi-hole / dnsmasq
    "Sep 26 10:01:02 dnsmasq[812]: query[A] laptop-01.home.lan from 192.168.1.45",
    # Check Point-like key=value
    'time="1727344862" src="192.168.1.10" dst="8.8.8.8" user="jdoe" origin_sic_name="gw01"',
    # Windows-ish
    r"New process C:\Users\jdoe\AppData\Local\Temp\x.exe by S-1-5-21-111-222-333-1001",
    # sshd
    "Accepted password for bob from 2a01:e0a:1f2:3::10 port 51022 ssh2 mac=aa:bb:cc:dd:ee:ff",
    # JSON
    '{"user":"alice","host":"srv-db-01","email":"alice@corp.example.com"}',
]


def kinds(text):
    return [(e.kind, e.value) for e in detect(text)]


def test_detects_typed_entities():
    assert ("fqdn", "laptop-01.home.lan") in kinds(LINES[0])
    assert ("ipv4", "192.168.1.45") in kinds(LINES[0])
    k = kinds(LINES[1])
    assert ("user", "jdoe") in k and ("host", "gw01") in k and ("ipv4", "8.8.8.8") in k
    k = kinds(LINES[2])
    assert ("user", "jdoe") in k and ("sid", "S-1-5-21-111-222-333-1001") in k
    k = kinds(LINES[3])
    assert ("ipv6", "2a01:e0a:1f2:3::10") in k and ("mac", "aa:bb:cc:dd:ee:ff") in k
    k = kinds(LINES[4])
    assert ("email", "alice@corp.example.com") in k and ("host", "srv-db-01") in k


@pytest.mark.parametrize(
    "benign",
    [
        "loaded C:\\Windows\\System32\\svchost.exe and kernel32.dll",
        "listening on 127.0.0.1:8080 and 0.0.0.0",
        "at 12:34:56 version 1.2.3",
        "user=- host=N/A",
    ],
)
def test_no_false_positive_on_benign(benign):
    assert detect(benign) == []


@pytest.mark.parametrize("line", LINES)
def test_no_leak_and_shape_preserved(pz, line):
    r = pz.pseudonymize(line)
    assert r.replacements, "something should have been replaced"
    assert pz.leaks(r.text, r.originals) == []
    for kind, token in r.replacements:
        if kind == "ipv4":
            ipaddress.IPv4Address(token)
        elif kind == "ipv6":
            assert ipaddress.IPv6Address(token) in ipaddress.IPv6Network("2001:db8::/32")
        elif kind == "email":
            assert re.fullmatch(r"u[0-9a-f]{6}@[a-z0-9.-]+", token)
        elif kind == "mac":
            assert re.fullmatch(r"02(:[0-9a-f]{2}){5}", token)


def test_private_stays_private_public_stays_public(pz):
    priv = pz.pseudonymize("192.168.1.45").text
    pub = pz.pseudonymize("8.8.8.8").text
    assert ipaddress.IPv4Address(priv) in ipaddress.IPv4Network("10.0.0.0/8")
    assert ipaddress.IPv4Address(pub) in ipaddress.IPv4Network("198.18.0.0/15")


def test_subnet_and_domain_consistency(pz):
    a = pz.pseudonymize("192.168.1.10").text
    b = pz.pseudonymize("192.168.1.20").text
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0] and a != b
    x = pz.pseudonymize("a.corp.lan").text
    y = pz.pseudonymize("b.corp.lan").text
    assert x.split(".", 1)[1] == y.split(".", 1)[1] and x != y and x.endswith(".lan")


def test_deterministic_and_reversible(pz):
    line = LINES[1]
    r1, r2 = pz.pseudonymize(line), pz.pseudonymize(line)
    assert r1.text == r2.text
    assert pz.reidentify(r1.text) == line


def test_propagation_catches_free_text_mentions(pz):
    line = 'user="jdoe" msg="login failed for jdoe"'
    r = pz.pseudonymize(line)
    assert "jdoe" not in r.text
    assert pz.leaks(r.text, r.originals) == []


def test_vault_is_encrypted_at_rest(tmp_path, pz, vault):
    pz.pseudonymize("secret-user-name@private-domain.lan and 192.168.99.77")
    blob = (tmp_path / "vault.db").read_bytes()
    assert b"secret-user-name" not in blob and b"192.168.99.77" not in blob
    if os.name == "posix":
        assert oct((tmp_path / "vault.db").stat().st_mode & 0o777) == "0o600"


def test_leak_detector_flags_residual_values(pz):
    assert pz.leaks("contact bob now", {"bob"}) == ["bob"]
    assert pz.leaks("bobby is fine", {"bob"}) == []


def test_private_tlds_are_detected_but_paths_and_namespaces_are_not():
    # regression: a homelab TLD leaked a hostname into an LLM prompt
    k = kinds("2026-09-26 14:46:00 query[A] media.jdoe.lab from 192.168.1.9")
    assert ("fqdn", "media.jdoe.lab") in k
    assert detect("/etc/pihole/hosts/custom.list read") == []
    assert detect("System.Management.Automation loaded") == []
