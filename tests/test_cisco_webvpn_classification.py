"""Cisco ASA/AnyConnect SSL-VPN requests must be classified as Cisco.

`GET /+CSCOE+/logon.html` is the first thing any ASA scanner asks for. Every existing
AnyConnect rule keyed on a POSTed body, so the plain GET matched nothing and inherited
whatever else fired. On the fleet it was arriving as:

    AI_DETECTED   on :8080  (an AI-written rule with nothing behind it)
    PANOS_PROBE   on :4443  (the PAN-OS decoy answered, so it was called Palo Alto)
    FORTI_PROBE   on :10443 (the FortiGate decoy answered)
    (none)        most of the time

The vendor mislabels are the interesting half. A decoy's `UNKNOWN_PATH` is a statement
about the decoy — "I don't serve this" — and the ingest was converting it into a
statement about the attacker's target. What was requested is in the path, not in which
port happened to answer.
"""

from __future__ import annotations

import pytest

from honeylens.classification.rules import register_all
from honeylens.classification.text_rules import compile_rule


@pytest.fixture(scope="module")
def rules():
    """Every registered rule as {name: (attack_type, compiled)}."""
    out = {}

    def add(attack_type, name, pattern, flags=0, *, min_count=None):
        # compile_rule, not re.compile: a counting rule must be built the way production
        # builds it, or it degrades here into "one occurrence" and the table lies.
        out[name] = (attack_type, compile_rule(pattern, flags, min_count=min_count))

    register_all(add)
    return out


def fired(rules, text):
    return {name for name, (_at, rx) in rules.items() if rx.search(text)}


def type_of(rules, name):
    return rules[name][0]


# --- the request the user reported ----------------------------------------------


def test_the_portal_probe_is_cisco_recon(rules):
    hits = fired(rules, "GET /+CSCOE+/logon.html HTTP/1.1")
    assert "cisco_webvpn_portal_probe" in hits
    assert type_of(rules, "cisco_webvpn_portal_probe") == "VPN_RECON"


@pytest.mark.parametrize(
    "path",
    [
        "/+CSCOE+/logon.html",
        "/+CSCOE+/portal.html",
        "/+CSCOE+/logout.html",
        "/+CSCOE+/session.js",
        "/+webvpn+/index.html",
        "/+CSCOU+/logon.html",
        "/%2bCSCOE%2b/logon.html",  # percent-encoded, as scanners also send it
        "/%2BCSCOE%2B/LOGON.HTML",  # and in either case
        "/+CSCOU+/csco_logo.gif",  # a portal asset, fetched to fingerprint an ASA
        "/+CSCOE+/win.js",
    ],
)
def test_the_whole_portal_surface_is_covered(rules, path):
    assert "cisco_webvpn_portal_probe" in fired(rules, f"GET {path} HTTP/1.1")


def test_oem_customization_is_recon_not_exploit(rules):
    """The real AnyConnect client requests this during a normal profile fetch."""
    text = "GET /+CSCOT+/oem-customization?app=AnyConnect&type=oem HTTP/1.1"
    hits = fired(rules, text)
    assert "cisco_anyconnect_oem_customization" in hits
    assert "cisco_cve_2020_3452_file_read" not in hits, (
        "a clean profile fetch must not be reported as a file-read exploit"
    )


def test_cve_2020_3452_is_an_exploit_not_recon(rules):
    """The traversal seen on our sensors. Reading a file off the appliance is not the
    same event as noticing that a portal exists, and must not share its class."""
    text = (
        "GET /+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=.."
        "&resource-type=..&name=%2BCSCOE%2B/portal_inc.lua HTTP/1.1"
    )
    hits = fired(rules, text)
    assert "cisco_cve_2020_3452_file_read" in hits
    assert type_of(rules, "cisco_cve_2020_3452_file_read") == "APPLIANCE_EXPLOIT"


def test_the_translation_table_variant_is_caught(rules):
    text = (
        "GET /+CSCOT+/translation-table?type=mst&textdomain=%2bCSCOE%2b/portal_inc.lua"
        "&default-language&lang=../ HTTP/1.1"
    )
    assert "cisco_cve_2020_3452_file_read" in fired(rules, text)


# --- what must NOT fire -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "GET /index.html HTTP/1.1",
        "GET /global-protect/login.esp HTTP/1.1",  # Palo Alto, a different vendor
        "GET /remote/login?lang=en HTTP/1.1",  # FortiGate
        "GET /api/v2/cmdb/system/admin HTTP/1.1",
        "POST /cgi-bin/../../bin/sh HTTP/1.1",  # traversal, not a Cisco path
    ],
)
def test_other_vendors_and_plain_traversal_do_not_match(rules, text):
    hits = fired(rules, text)
    assert not {
        h for h in hits if h.startswith("cisco_webvpn") or h.startswith("cisco_cve_2020_3452")
    }, hits


def test_plus_is_treated_as_a_literal_not_a_quantifier(rules):
    """`+` is a regex quantifier. Unescaped, `/+CSCOE+/` would match `/CSCOE/` and
    friends — a silent widening that only shows up as odd matches months later."""
    assert "cisco_webvpn_portal_probe" not in fired(rules, "GET /CSCOE/logon.html HTTP/1.1")
    assert "cisco_webvpn_portal_probe" not in fired(rules, "GET //CSCOE//logon.html HTTP/1.1")


def test_the_body_rules_still_work(rules):
    """The pre-existing AnyConnect rules must be untouched by this change."""
    assert "cisco_anyconnect_auth_init" in fired(rules, '<config-auth client="vpn" type="init">')
    assert "cisco_anyconnect_forged_mac" in fired(
        rules, "<mac-address>a3:11:22:33:44:55</mac-address>"
    )


# --- the ingest side: a decoy must not assert a vendor it cannot see --------------


def test_an_unrecognised_path_is_named_by_the_path():
    from honeylens.ingest import foreign_path

    got = foreign_path.classify({"method": "GET", "path": "/+CSCOE+/logon.html"})
    assert any(at == "VPN_RECON" for at, _sev, _rule in got), got


def test_the_deciding_rule_travels_with_the_verdict():
    """The attack_patterns row must record which rule decided.

    Without this the stored row read `paloalto_unknown_path` while carrying VPN_RECON —
    the verdict correct, the provenance misleading, and nothing in the table to say
    whether the decoy or the classifier produced it."""
    from honeylens.ingest import foreign_path

    got = foreign_path.classify({"method": "GET", "path": "/+CSCOE+/logon.html"})
    assert any(rule == "cisco_webvpn_portal_probe" for _at, _sev, rule in got), got


def test_a_genuinely_unknown_path_yields_nothing():
    """So the caller keeps its vendor label — which is right for a path nobody claims."""
    from honeylens.ingest import foreign_path

    assert foreign_path.classify({"method": "GET", "path": "/zzz-nothing-here"}) == []


def test_an_empty_event_is_not_classified():
    from honeylens.ingest import foreign_path

    assert foreign_path.classify({}) == []
    assert foreign_path.classify(None) == []


def test_request_text_includes_the_query_string():
    """CVE-2020-3452 lives entirely in the query; dropping it would hide the exploit."""
    from honeylens.ingest import foreign_path

    text = foreign_path.request_text(
        {"method": "GET", "path": "/+CSCOT+/oem-customization", "query": "platform=.."}
    )
    assert "platform=.." in text and "oem-customization" in text


def test_credentials_in_the_url_are_a_credential_event(rules):
    """AI rule id=11 caught this and called it AI_DETECTED — a label that records that
    a rule fired and nothing about what happened. A password in a query string is a
    credential event whichever verb carries it."""
    text = "GET /webvpn/index.html?username=admin&password=Passw0rd&Login=Login HTTP/1.1"
    hits = fired(rules, text)
    assert "cisco_webvpn_credentials_in_query" in hits
    assert type_of(rules, "cisco_webvpn_credentials_in_query") == "CREDENTIAL"


def test_the_portal_page_alone_is_not_a_credential_event(rules):
    """Recon and credential capture must not collapse into one class."""
    hits = fired(rules, "GET /+webvpn+/index.html HTTP/1.1")
    assert "cisco_webvpn_credentials_in_query" not in hits
    assert "cisco_webvpn_portal_probe" in hits


# --- the SMB false positive the user reported (sensor-c) --------------------------


def test_anyconnect_init_is_not_tagged_smb(rules):
    """An AnyConnect init POST is VPN_RECON, never SMB. The bare "pth" alternative in
    smb_pass_the_hash used to match the substring inside a random computer-name
    (e.g. "jwebspthgm") and tag HTTPS payloads as SMB — there is no SMB in an HTTP body."""
    payload = (
        "POST / HTTP/1.1\r\n\r\n"
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<config-auth client="vpn" type="init" aggregate-auth-version="2">'
        '<device-id computer-name="jwebspthgm" device-type="Lenovo">win</device-id>'
        "</config-auth>"
    )
    hits = fired(rules, payload)
    assert "cisco_anyconnect_auth_init" in hits
    assert type_of(rules, "cisco_anyconnect_auth_init") == "VPN_RECON"
    assert not {n for n in hits if type_of(rules, n) in ("SMB", "SMB2")}


def test_pass_the_hash_pth_token_still_detected(rules):
    """The word-bounded "pth" must still catch a real pass-the-hash reference."""
    assert "smb_pass_the_hash" in fired(rules, "running a pth attack with mimikatz")
    assert "smb_pass_the_hash" not in fired(rules, "pthread_create() depth=5")


# --- Citrix NetScaler CVE-2026-88771 (watchTowr PoC) ----------------------------


def test_netscaler_cve_2026_88771_pitboss_cmdi(rules):
    """The pre-auth command injection's pitboss/NSPPE log-poisoning payload is flagged,
    raw and URL-encoded, and a benign Gateway login is not."""
    import urllib.parse

    poc = "login=pitboss PPE unexpectedly died NSPPE;id>/var/tmp/watchTowr;# X&passwd=x"
    enc = "login=" + urllib.parse.quote(
        "pitboss PPE unexpectedly died NSPPE;id>/var/tmp/watchTowr;# X", safe=""
    )
    rule = "citrix_cve_2026_88771_pitboss_cmdi"
    assert rule in fired(rules, poc)
    assert rule in fired(rules, enc)
    assert type_of(rules, rule) == "APPLIANCE_EXPLOIT"
    assert rule not in fired(rules, "login=jdoe&passwd=secret&nsg-x1-logon-button=Log+On")
    assert rule not in fired(rules, "the pitboss shuffled the deck")


# --- cross-protocol false positives on HTTP (Oct-5) ---------------------------


def test_modbus_unity_not_on_benign_http(rules):
    """Schneider "Unity" must be the product, not the substring in community/opportunity/.tsx."""
    assert "modbus_schneider_unity" not in fired(rules, "join our community forum")
    assert "modbus_schneider_unity" not in fired(rules, "GET /src/App.tsx HTTP/1.1")
    assert "modbus_schneider_unity" in fired(rules, "Unity Pro project download")
    assert "modbus_schneider_unity" in fired(rules, "GET /modicon/config")


def test_oracle_default_creds_not_on_url_path(rules):
    """A user/pass pair that is actually a URL path segment (/system/admin) is not Oracle."""
    assert "oracle_default_creds" not in fired(rules, "GET /api/v2/cmdb/system/admin HTTP/1.1")
    assert "oracle_default_creds" not in fired(rules, "GET /bi/manager")
    assert "oracle_default_creds" in fired(rules, "sqlplus system/manager@orcl")
    assert "oracle_default_creds" in fired(rules, "scott/tiger@//db:1521/XE")
