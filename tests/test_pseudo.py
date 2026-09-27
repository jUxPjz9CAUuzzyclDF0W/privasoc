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


@pytest.mark.parametrize(
    "line,kind,value",
    [
        # regressions from the leakage evaluation on Elastic fixtures (I20)
        ("May  5 17:51:17 dev01: %FTD-6-302013: Built", "host", "dev01"),
        ("Oct 20 2019 15:15:15 dev01: %ASA-5-106100: acc", "host", "dev01"),
        ("<134>1 2020-03-29T13:19:20Z gw-da58d3 CheckPoint 1930 - [x]", "host", "gw-da58d3"),
        ("<166>CHI-ASAv-UG %ASA-6-315011: x", "host", "CHI-ASAv-UG"),
        ("sshd[3402]: Accepted publickey for vagrant from 10.0.2.2 port 63673", "user", "vagrant"),
        ("illegal user test from test.example.com", "user", "test"),
        ("sudo:      tsg : user NOT in sudoers", "user", "tsg"),
        ("icmp src srcif:192.168.1.2(LOCAL\\testgroup\\testuser) dst", "user", "testuser"),
        ("Group <VPN5Policy> User <john> IP <192.168.5.1>", "user", "john"),
        ('frank - frank [26/Dec/2016:16:22:13 +0000] "GET / HTTP/1.1"', "user", "frank"),
        ('devname="use2-dmz-fw02" devid="FG"', "host", "use2-dmz-fw02"),
        ('xauthuser="user1" group="N/A"', "user", "user1"),
        ("GET http://www.goonernews.com/ badeyek", "fqdn", "www.goonernews.com"),
        (
            "to outside:2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6/53",
            "ipv6",
            "2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6",
        ),
        ("Connection from 172.16.0.1.", "ipv4", "172.16.0.1"),
    ],
)
def test_vendor_format_regressions(line, kind, value):
    assert (kind, value) in kinds(line), kinds(line)


def test_cross_line_propagation(pz):
    """Regression (iptables eval): a host detected in one line's syslog header appeared bare
    in another line; the leak guard blocked the prompt."""
    a = pz.pseudonymize("Oct 10 07:25:12 fw-lab-01 kernel: IN=eth0 SRC=10.1.1.1")
    b = pz.pseudonymize("[7231651.1] [fw-lab-01 RULE] IN=eth0 SRC=10.1.1.2")
    assert "fw-lab-01" in b.text
    fixed = pz.propagate(b.text, {**a.mapping, **b.mapping})
    assert "fw-lab-01" not in fixed and pz.leaks(fixed, a.originals | b.originals) == []


def test_key_fingerprint_is_not_an_ipv6(pz):
    fp = "39:33:99:e9:a0:dc:f2:33:1c:9a:ad:61:15:02:5b:a1"
    line = f"Accepted publickey for bob from 10.0.0.1 port 22 ssh2: RSA {fp}"
    assert fp in pz.pseudonymize(line).text
    assert "2001:db8" in pz.pseudonymize("from 2a02:8070:1:2::5 port 22").text
