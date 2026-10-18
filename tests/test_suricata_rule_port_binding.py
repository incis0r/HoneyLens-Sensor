"""A HoneyLens rule that declares a CVE must name the ports of the affected service.

The invariant has no exceptions, and it is the rule-layer half of the ingest gate in
``honeylens.ingest.cve_service_ports``. Both layers exist because either alone is incomplete: a
port qualifier cannot be added to a third-party rule (``suricata-update`` overwrites a local
edit), and the ingest gate cannot stop an alert being generated, filestored and counted in
``ruleset-stats``.

What it was like before 2026-11-04, measured on the fleet:

* ``9026731`` (CVE-2026-42533, nginx) — 402 rows, **three** on the nginx decoy.
* ``9026500`` (CVE-2026-23918, Apache) — 575 rows over 28 ports, telnet, SMTP, MySQL, RDP, VNC,
  OPC UA, EtherNet/IP, Fox and AFP among them.
* ``9026701`` (CVE-2026-49975, the h2 bomb served by ``hp_nginx``) — 1,040 rows on ``sensor-a``, and
  its port list named the Apache bait and the PAN-OS captive ports but not the nginx decoy, so
  **none** of them was on the affected service.
* ``9026754`` ("WAGO WBM default credentials submitted") — fired on ``:443``, the alternate HTTP port and
  ``:30000``; the WAGO decoy is ``:8090``.
* ``9026311`` — an actor-UA indicator whose own comment says it fires "regardless of which
  CVE/vector they're probing", while declaring ``cve CVE_2026_0300``. That one lost the CVE
  instead of gaining a port, which is why ``test_an_actor_indicator_declares_no_cve`` exists.

A rule with no CVE in its metadata is free to be port-agnostic — the AI canary and the
self-doxxing-UA indicators are, deliberately.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from honeylens.ingest.cve_service_ports import decoy_ports, service_ports_for

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "suricata"

_SID_RE = re.compile(r"sid:(\d+)")
_DST_RE = re.compile(r"->\s*\$HOME_NET\s*(\S+?)\s*\(")
_CVE_RE = re.compile(r"metadata:[^;]*?\bcve\s+(CVE[_\-0-9]+)")
_MSG_RE = re.compile(r'msg:"([^"]+)"')


class Rule:
    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.text = text
        sid = _SID_RE.search(text)
        dst = _DST_RE.search(text)
        cve = _CVE_RE.search(text)
        msg = _MSG_RE.search(text)
        self.sid = int(sid.group(1)) if sid else 0
        self.dst = dst.group(1) if dst else ""
        self.cve = cve.group(1) if cve else ""
        self.msg = msg.group(1) if msg else ""

    @property
    def ports(self) -> frozenset[int]:
        """The destination ports the rule names; empty for ``any``."""
        body = self.dst.strip("[]")
        if body == "any":
            return frozenset()
        return frozenset(int(p) for p in body.split(",") if p.strip().isdigit())

    def __repr__(self) -> str:
        return f"sid:{self.sid} ({self.path.name})"


def _rules() -> list[Rule]:
    out: list[Rule] = []
    for path in sorted(RULES_DIR.glob("*.rules")):
        joined = path.read_text().replace("\\\n", " ")
        for line in joined.splitlines():
            if line.lstrip().startswith("alert"):
                out.append(Rule(path, line))
    return out


ALL_RULES = _rules()
CVE_RULES = [r for r in ALL_RULES if r.cve]


def test_the_rules_directory_parses_and_is_not_empty():
    # A parser that silently finds nothing would make every assertion below vacuous.
    assert len(ALL_RULES) >= 59, len(ALL_RULES)
    assert all(r.sid for r in ALL_RULES), [r for r in ALL_RULES if not r.sid]
    assert len(CVE_RULES) >= 20, len(CVE_RULES)


@pytest.mark.parametrize("rule", CVE_RULES, ids=lambda r: str(r.sid))
def test_a_rule_that_declares_a_cve_names_its_service_ports(rule: Rule):
    assert rule.ports, (
        f"{rule} declares {rule.cve} but is destination-port-agnostic: {rule.msg!r}. "
        "Either bind it to the ports its affected service occupies, or drop the CVE from the "
        "metadata if the rule is an actor or behaviour indicator rather than a product exploit."
    )


def test_every_sid_is_unique():
    # Two rules with one sid abort the whole ruleset load; prod has been here already.
    sids = [r.sid for r in ALL_RULES]
    assert len(sids) == len(set(sids)), sorted(s for s in sids if sids.count(s) > 1)


def test_every_message_is_attributable_to_us():
    for rule in ALL_RULES:
        assert rule.msg.startswith("HONEYLENS"), rule


def test_the_nginx_cve_rules_use_the_nginx_decoy_ports():
    """The port list must not drift from the manifest, in either layer."""
    expected = decoy_ports(("nginx",))
    for sid in (9026730, 9026731, 9026732, 9026420, 9026700, 9026701):
        rule = next(r for r in ALL_RULES if r.sid == sid)
        assert rule.ports == expected, rule


def test_the_apache_cve_rules_use_the_apache_bait_port():
    expected = decoy_ports(("http",))
    for sid in (9026500, 9026501, 9026502, 9026503):
        rule = next(r for r in ALL_RULES if r.sid == sid)
        assert rule.ports == expected, rule


def test_the_wago_rules_use_the_wago_decoy_port():
    expected = decoy_ports(("wago",))
    for rule in ALL_RULES:
        if "WAGO" in rule.msg:
            assert rule.ports == expected, rule


def test_the_rule_layer_and_the_ingest_gate_agree():
    """Where both layers bind the same CVE, they must bind it to the same ports."""
    for rule in CVE_RULES:
        gated = service_ports_for(rule.cve)
        if gated is None:
            continue
        assert rule.ports == gated, (
            f"{rule} names {sorted(rule.ports)} but cve_service_ports binds {rule.cve} to "
            f"{sorted(gated)}"
        )


def test_an_actor_indicator_declares_no_cve():
    """9026311 fires on an actor's UA literal on any port; a CVE claim there is unsupportable."""
    rule = next(r for r in ALL_RULES if r.sid == 9026311)
    assert rule.cve == "", rule
    assert not rule.ports, "an actor indicator should stay port-agnostic"


def test_the_h2c_behaviour_rule_carries_no_cve_and_keeps_its_coverage():
    """Binding 9026701 to nginx would have dropped 1,040 rows/month of real detection."""
    rule = next(r for r in ALL_RULES if r.sid == 9026706)
    assert rule.cve == ""
    assert 80 in rule.ports and 8080 in rule.ports and 6082 in rule.ports
    assert 8443 not in rule.ports, "inside TLS the IDS cannot see the preface; hp_nginx handles it"
