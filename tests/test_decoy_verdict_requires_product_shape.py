"""A product verdict requires a product-shaped request.

B6. The PAN-OS captive portal registers three real paths and one catch-all:

    app.router.add_get("/php/uid.php", self.handle_captive_uid)
    app.router.add_post("/php/uid.php", self.handle_captive_login)
    app.router.add_get("/php/cp.php", self.handle_captive_cp)
    app.router.add_route("*", r"/{path:.*}", self.handle_captive_redirect)

The catch-all logs `CAPTIVE_REDIRECT`, and `ingest/paloalto.WEB_EVENT_TO_ATTACK` maps that to
`PANOS_CAPTIVE`. So the verdict asserts a PAN-OS captive-portal interaction for every request
that reached the route meaning *"this is not one of the PAN-OS captive paths"* -- the verdict
says the opposite of what the route means.

Measured on `sensor-b` over 30 days, 2,301 rows on the captive decoy: 1,878 of them were not
PAN-OS-shaped, including **200 WordPress rows** (`/wp-json/…`, `/wp-content/…`), 585 bare `/`,
152 `/favicon.ico`, and Magento, Lotus Domino, JBoss, MobileIron and Patroni paths. On `sensor-a` a
path traversal came back as `LFI,PANOS_CAPTIVE` and Confluence as `AUTH_ATTACK,PANOS_CAPTIVE`.
The operator's spot-check actor sent 118 requests to :6082 on 2026-11-02; all 118 were
`PANOS_CAPTIVE` and **six** asked for a PAN-OS path. Present on three sensors: `sensor-b` 1,878 of
2,301, `sensor-a` 588 of 746, `prod` 278 of 446.

**The sibling was already fixed and this one was missed.** `UNKNOWN_PATH` had the identical
defect -- `ingest/foreign_path.py` exists because a Cisco AnyConnect probe on :4443 was filed as
Palo Alto reconnaissance -- and its ingest now asks the text rules what the path is and keeps
the vendor label only when nothing else identifies it. This applies that same mechanism to the
captive catch-all.

What the decoy records does not change: it still answers and still logs every request. Only the
verdict changes, and `source` already carries which decoy received it, so naming the product in
`attack_types` as well was never carrying information.
"""

from __future__ import annotations

import pytest

from honeylens.ingest.paloalto import decide_attack_types


def _types(event_type, path, method="GET", **extra):
    data = {"path": path, "method": method, **extra}
    attack_types, _rules = decide_attack_types(event_type, data, "web")
    return {at[0] for at in attack_types}


def _rules_for(event_type, path, method="GET", **extra):
    data = {"path": path, "method": method, **extra}
    _attack_types, rule_for_type = decide_attack_types(event_type, data, "web")
    return rule_for_type


# ---------------------------------------------------------------------------
# A real PAN-OS captive path keeps its verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        ("CAPTIVE_AUTH_PAGE", "PANOS_CAPTIVE"),
        ("CAPTIVE_CP_PAGE", "PANOS_CAPTIVE"),
        ("CAPTIVE_LOGIN", "PANOS_CAPTIVE_CRED"),
    ],
)
def test_the_three_real_captive_paths_keep_their_verdict(event_type, expected):
    """These have their own routes, so they never reach the catch-all. `PANOS_CAPTIVE` stays
    alive and meaningful — it just stops being applied to everything else."""
    assert expected in _types(event_type, "/php/uid.php")


# ---------------------------------------------------------------------------
# The catch-all stops asserting PAN-OS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/wp-json/wp/v2/posts?per_page=1",
        "/wp-content/plugins/revslider/tout.php",
        "/favicon.ico",
        "/index.php/catalogsearch/result/",
        "/names.nsf/People",
        "/invoker/JMXInvokerServlet",
        "/mifs/user/login.jsp",
        "/robots.txt",
    ],
)
def test_a_request_for_another_product_is_not_a_panos_captive_interaction(path):
    """1,878 of 2,301 rows on `sensor-b`, 200 of them WordPress."""
    assert "PANOS_CAPTIVE" not in _types("CAPTIVE_REDIRECT", path)


def test_a_bare_slash_is_a_port_probe_named_as_one():
    """585 rows on `sensor-b`. The precedent is `k8s_proxy_port_probe`, which exists after 20,432
    rows of `GET /` were called K8s attacks on `prod`."""
    types = _types("CAPTIVE_REDIRECT", "/")

    assert "PANOS_CAPTIVE" not in types
    assert "RECON" in types


def test_a_traversal_keeps_its_own_verdict_and_loses_the_vendor_one():
    """Measured on `sensor-a` as `LFI,PANOS_CAPTIVE`."""
    types = _types("CAPTIVE_REDIRECT", "/../../../../../../etc/passwd")

    assert "LFI" in types
    assert "PANOS_CAPTIVE" not in types


def test_the_sibling_mechanism_is_what_names_a_cisco_probe():
    """`foreign_path` already does this for `UNKNOWN_PATH`; B6 is wiring the captive catch-all
    into the same thing rather than inventing a second mechanism."""
    types = _types("CAPTIVE_REDIRECT", "/+CSCOE+/logon.html")

    assert "PANOS_CAPTIVE" not in types
    assert types, "a Cisco portal probe must still be named something"


def test_an_unidentifiable_path_is_a_probe_at_this_decoy_not_a_captive_interaction():
    """The honest residue: we do not know what they wanted, only that it arrived here. That is
    `PANOS_PROBE` — a probe aimed at the PAN-OS decoy — and not `PANOS_CAPTIVE`, which claims a
    captive-portal interaction that did not happen."""
    types = _types("CAPTIVE_REDIRECT", "/zzz-nothing-matches-this-9f3a")

    assert "PANOS_CAPTIVE" not in types
    assert "PANOS_PROBE" in types


def test_the_deciding_rule_travels_with_the_verdict():
    """Without it the `attack_patterns` row says `paloalto_captive_redirect` while carrying
    somebody else's attack type — verdict right, provenance misleading."""
    rules = _rules_for("CAPTIVE_REDIRECT", "/+CSCOE+/logon.html")

    assert rules, "no rule name recorded for an identified path"
    assert all(not r.startswith("paloalto_") for r in rules.values()), rules


# ---------------------------------------------------------------------------
# Nothing else moves
# ---------------------------------------------------------------------------


def test_the_unknown_path_behaviour_is_unchanged():
    """The fix that already existed must keep working."""
    types = _types("UNKNOWN_PATH", "/+CSCOE+/logon.html")

    assert "PANOS_PROBE" not in types
    assert types


def test_a_genuinely_unknown_path_still_keeps_the_vendor_probe_label():
    assert "PANOS_PROBE" in _types("UNKNOWN_PATH", "/zzz-nothing-matches-this-9f3a")


def test_credential_capture_is_untouched():
    types = _types("CAPTIVE_LOGIN", "/php/uid.php", method="POST", username="admin")

    assert "PANOS_CRED" in types


def test_default_credentials_still_escalate():
    types = _types(
        "CAPTIVE_LOGIN", "/php/uid.php", method="POST", username="admin", default_creds=True
    )

    assert "PANOS_DEFAULT_CRED" in types


def test_a_cve_in_the_event_still_classifies():
    from honeylens.ingest.paloalto import CVE_ATTACK_TYPES

    cve = next(iter(CVE_ATTACK_TYPES))
    types = _types("UNKNOWN_PATH", "/whatever", cve=cve)

    assert CVE_ATTACK_TYPES[cve] in types


# ---------------------------------------------------------------------------
# The INSERT path, which no test reached before
# ---------------------------------------------------------------------------


class _CapturingConn:
    """Enough of a connection for `insert_event` to run without a database."""

    def __init__(self):
        self.sql: list[tuple] = []

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.sql.append((sql, params))

    def fetchone(self):
        return None

    def commit(self):
        pass


def test_an_event_carrying_a_cve_inserts_without_blowing_up():
    """Splitting the verdict logic out of `insert_event` moved the `cve` binding with it and
    left the `attack_patterns` matched-text branch a NameError on every event carrying a CVE.
    The whole suite passed — nothing reached that branch. ruff's F821 caught it instead, so
    this test exists to make the next such slip a test failure rather than a lint finding."""
    from honeylens.ingest.paloalto import CVE_ATTACK_TYPES, insert_event

    cve = next(iter(CVE_ATTACK_TYPES))
    conn = _CapturingConn()

    insert_event(
        conn,
        {
            "event_type": "UNKNOWN_PATH",
            "timestamp": "2026-11-05T00:00:00+00:00",
            "path": "/whatever",
            "method": "GET",
            "data": {"path": "/whatever", "method": "GET", "cve": cve, "detail": "probe"},
        },
        "evt-cve-1",
        "web",
    )

    pattern_rows = [p for sql, p in conn.sql if "attack_patterns" in sql]
    assert pattern_rows, conn.sql
    assert any(cve in str(p) for p in pattern_rows), pattern_rows
