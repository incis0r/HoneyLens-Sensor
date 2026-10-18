"""A CVE label belongs to the service that CVE affects, not to whatever port answered.

Measured on the fleet 2026-11-04 (the 4 Oct-4 Nov fleet review §5.6), two distinct
defects hid behind "a CVE on the wrong port":

* **bind** — our nginx rule (sid 9026731) put ``CVE-2026-42533`` on 402 rows of which **3** were
  on the nginx decoy: 287 on ``:80`` (the Apache bait on ``sensor-a``/``prod``, the NetScaler decoy on
  ``sensor-b``), 66 on ``:2379`` (etcd), 27 on the alternate HTTP port, the rest on WAGO and K8s ports. Our Apache
  ``mod_http2`` rule (sid 9026500) put ``CVE-2026-23918`` on 575 rows spread over 28 ports,
  including telnet, SMTP, MySQL, RDP, VNC, OPC UA, EtherNet/IP, Fox and AFP.
* **demote** — ``CVE-2002-1149`` came from **ET sid 2019526, "WEB-PHP phpinfo access"**: 393 rows
  on ten web ports. Asking for ``phpinfo`` is reconnaissance, so no port binding can fix it; the
  rule's declared CVE simply must not become a finding.

Suppressing the CVE never blanks a row — the measured base verdict underneath is ``DOS``,
``SCANNER``, ``SURICATA_ALERT``, ``RCE`` or ``WEB_EXPLOIT``.
"""

from __future__ import annotations

from honeylens.ingest.cve_service_ports import (
    cve_is_a_finding,
    cve_is_in_service,
    decoy_ports,
    normalise_cve,
    service_ports_for,
)

# --- normalisation ------------------------------------------------------------------


def test_suricata_underscore_form_and_dashed_form_are_the_same_cve():
    assert normalise_cve("CVE_2026_42533") == "CVE-2026-42533"
    assert normalise_cve("CVE-2026-42533") == "CVE-2026-42533"
    assert normalise_cve("cve_2026_42533") == "CVE-2026-42533"


def test_rubbish_normalises_to_empty_rather_than_raising():
    # The CVE comes from a third-party rule's metadata; it is not ours to trust.
    assert normalise_cve(None) == ""
    assert normalise_cve("") == ""
    assert normalise_cve("not-a-cve") == ""


# --- binding: the nginx script-engine CVE -------------------------------------------


def test_42533_on_the_nginx_decoy_ports_is_promoted():
    assert cve_is_in_service("CVE_2026_42533", 8000) is True
    assert cve_is_in_service("CVE_2026_42533", 8443) is True


def test_42533_off_the_nginx_decoy_is_not_promoted():
    # The six ports it was measured on that the nginx decoy does not own.
    for port in (80, 2379, 8888, 8080, 8090, 50080):
        assert cve_is_in_service("CVE_2026_42533", port) is False, port


def test_nginx_ports_come_from_the_manifest_not_from_a_literal():
    # If someone moves the decoy in manifest.py, the binding must move with it.
    assert service_ports_for("CVE-2026-42533") == decoy_ports(("nginx",))


# --- binding: the Apache mod_http2 CVE ----------------------------------------------


def test_23918_on_the_apache_bait_is_promoted():
    assert cve_is_in_service("CVE-2026-23918", 80) is True
    assert service_ports_for("CVE-2026-23918") == decoy_ports(("http",))


def test_a_decoy_binding_names_both_the_protocol_port_and_the_bound_port():
    """A honeypot row carries the protocol port; Suricata reports the wire port, and which one
    that is depends on where the host's DNAT sits. Measured on sensor-b: the NetScaler decoy's own
    rows say :80, Suricata's rows for the same decoy say :50080. Naming one of the pair would
    suppress real findings on whichever sensor is plumbed the other way round."""
    assert decoy_ports(("http",)) == frozenset({80, 30080})
    assert decoy_ports(("netscaler",)) == frozenset({80, 443, 50080, 50443})
    # Ports at or above 1024 with no block are bound as themselves, so the pair collapses.
    assert decoy_ports(("nginx",)) == frozenset({8000, 8443})


def test_23918_is_not_promoted_on_services_that_cannot_speak_http2():
    # Measured ports, 2 rows each from one source sweeping everything on sensor-a.
    for port in (23, 25, 548, 1883, 1911, 3306, 3389, 4840, 5900, 6379, 9600, 44818, 62222):
        assert cve_is_in_service("CVE-2026-23918", port) is False, port


def test_23918_is_not_promoted_on_the_nginx_or_k8s_decoys():
    # Where its weight actually was: 210 rows on :8000 and 241 on :8080, neither of them Apache.
    assert cve_is_in_service("CVE-2026-23918", 8000) is False
    assert cve_is_in_service("CVE-2026-23918", 8080) is False


# --- the three ways a gate must stay out of the way ---------------------------------


def test_an_unbound_cve_is_never_suppressed():
    # Most CVEs are third-party rules for products we do not impersonate. They stay as they are.
    assert cve_is_in_service("CVE-2025-30208", 8080) is True
    assert cve_is_in_service("CVE-2099-0001", 2379) is True
    assert service_ports_for("CVE-2099-0001") is None


def test_a_missing_or_zero_port_never_suppresses():
    # Absence of a port is not evidence the CVE is wrong.
    assert cve_is_in_service("CVE_2026_42533", None) is True
    assert cve_is_in_service("CVE_2026_42533", 0) is True


def test_an_unparseable_cve_never_suppresses():
    assert cve_is_in_service("not-a-cve", 2379) is True


# --- demotion: a CVE token that misdescribes the behaviour --------------------------


def test_a_phpinfo_access_does_not_become_a_2002_exploit():
    assert cve_is_a_finding("CVE_2002_1149", 2019526) is False


def test_the_same_cve_from_a_different_rule_is_still_a_finding():
    # The demotion is a property of one rule's declaration, not of the CVE.
    assert cve_is_a_finding("CVE-2002-1149", 9026999) is True


def test_our_own_exploit_rules_remain_findings():
    assert cve_is_a_finding("CVE_2026_42533", 9026731) is True
    assert cve_is_a_finding("CVE-2025-55182", 2066027) is True


def test_a_missing_sid_leaves_the_cve_a_finding():
    assert cve_is_a_finding("CVE-2002-1149", None) is True
