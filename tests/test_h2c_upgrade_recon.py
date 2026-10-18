"""A bare h2c upgrade binds to no CVE (Task 7)."""

from __future__ import annotations

from pathlib import Path

from honeylens.honeypots import hp_http
from honeylens.honeypots.h2_capture import H2Observation, decide
from honeylens.honeypots.hp_http import HTTPHoneypot

from .test_hp_http_h2 import _H2C_HEADERS, _h2c_upgrade_bytes, _raiser, _run_h2, _run_h2_both


def _hp():
    return HTTPHoneypot.__new__(HTTPHoneypot)


def test_a_bare_h2c_upgrade_is_recon_and_names_no_cve():
    hit = _hp()._classify("/", None, {"upgrade": "h2c"})
    assert hit == ("h2c_upgrade_recon", "LOW")


def test_the_user_agent_branch_also_stops_naming_the_cve():
    hit = _hp()._classify("/", None, {"user-agent": "python-h2/4.1.0"})
    assert hit and "23918" not in hit[0]


def test_a_real_attack_still_outranks_the_upgrade_header():
    hit = _hp()._classify("/etc/passwd", None, {"upgrade": "h2c"})
    assert hit[0] == "lfi"


def test_the_old_name_is_gone_from_the_tree():
    # Resolved from this file, not the working directory: a relative "src/" made grep fail
    # with "no such file" from anywhere but the repo root, leaving stdout empty and the
    # assertion passing. And the set is proved non-empty first: a test that scans a set
    # has to show the set is not empty, or it only tests that nothing went wrong while
    # finding nothing.
    src = Path(__file__).resolve().parents[1] / "src"
    files = sorted(src.rglob("*.py"))
    assert files, f"no sources found under {src}"
    old = "cve_2026_23918_recon"
    assert [str(f) for f in files if old in f.read_text(encoding="utf-8")] == []


# ---- decisions made while fixing, each pinned on its own ------------------------------


def test_the_user_agent_branch_is_recon_at_low_too():
    assert _hp()._classify("/", None, {"user-agent": "python-h2/4.1.0"}) == (
        "h2c_upgrade_recon",
        "LOW",
    )


def test_an_attack_in_the_body_or_under_a_user_agent_also_outranks_the_headers():
    assert _hp()._classify("/", "<script>x", {"upgrade": "h2c"}) == ("xss", "MEDIUM")
    assert _hp()._classify("/etc/passwd", None, {"user-agent": "python-h2/4"})[0] == "lfi"


def test_the_h2_token_is_recon_with_or_without_spaces_after_the_comma():
    # `_h2c_settings` strips each token, so `websocket, h2` is upgraded; `_classify` has
    # to read it the same way or an upgraded connection ends with no verdict at all.
    for value in ("h2", "h2,h2c", "websocket, h2", "websocket,h2"):
        assert _hp()._classify("/", None, {"upgrade": value}) == ("h2c_upgrade_recon", "LOW")
    assert _hp()._classify("/", None, {"upgrade": "websocket"}) is None


def _classify_none(path, body, headers):
    return None


def test_a_negotiated_upgrade_is_not_prior_knowledge():
    verdicts, sev = decide(H2Observation(entry="upgrade"), _classify_none)
    assert verdicts == [] and sev is None


def test_a_preface_connection_still_gets_the_baseline():
    verdicts, sev = decide(H2Observation(entry="preface"), _classify_none)
    assert verdicts == ["h2_prior_knowledge"] and sev == "LOW"


def test_an_upgrade_connection_keeps_the_verdicts_it_earns():
    obs = H2Observation(entry="upgrade", shape_matches=1, headers_frames=1)
    verdicts, _ = decide(obs, _classify_none)
    assert verdicts == ["cve_2026_119618_probe"]


def test_the_upgrade_row_is_named_for_the_upgrade_verdict_not_a_baseline(monkeypatch):
    seen = _run_h2(monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n")
    event = seen[0]["data"]
    assert event["h2_entry"] == "upgrade"
    assert event["rule"] == "h2c_upgrade_recon"
    assert event["h2_verdicts"] == ["h2c_upgrade_recon"]
    assert seen[0]["attack_type"] == "h2c_upgrade_recon" and seen[0]["severity"] == "LOW"


def test_an_attack_on_the_upgrade_request_names_the_row_and_is_not_shadowed(monkeypatch):
    raw = b"GET /etc/passwd HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    seen = _run_h2(monkeypatch, raw)
    event = seen[0]["data"]
    assert event["rule"] == "lfi"
    assert event["h2_verdicts"] == ["lfi"]
    assert event["upgrade_request"]["verdicts"] == ["lfi"]
    assert seen[0]["severity"] == "HIGH"


def test_with_several_verdicts_the_row_is_named_for_the_first_in_precedence_order(monkeypatch):
    # `decide`'s verdicts lead in its own precedence (the fixture's text/plain stream also
    # matches the 119618 shape); the upgrade request's own verdict is appended behind
    # them, and neither is replaced by a baseline.
    seen = _run_h2(monkeypatch, _h2c_upgrade_bytes("/wp-login.php"))
    event = seen[0]["data"]
    assert event["h2_verdicts"] == [
        "cve_2026_119618_probe",
        "wordpress_scan",
        "h2c_upgrade_recon",
    ]
    assert event["rule"] == "cve_2026_119618_probe"


def test_the_same_attack_with_the_upgrade_header_keeps_its_verdict_over_http_1_1(monkeypatch):
    # The h2 flag is off here: the shadowing was never an HTTP/2 problem.
    from .test_hp_http_h2 import _run

    raw = b"GET /etc/passwd HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n\r\n"
    seen = _run(monkeypatch, raw)
    assert seen[0]["attack_type"] == "lfi"


def test_a_preface_row_is_still_named_for_the_baseline(monkeypatch):
    from honeylens.honeypots import h2_capture

    seen = _run_h2(monkeypatch, h2_capture.PREFACE)
    assert seen[0]["data"]["rule"] == "h2_prior_knowledge"


def test_an_upgrade_row_no_verdict_earned_falls_back_to_the_connection(monkeypatch):
    # The capture broke before the upgrade request could be judged: nothing earned the row,
    # and it must not borrow the preface baseline's claim.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2c_request_record", _raiser)
    seen, _ = _run_h2_both(monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n")
    event = seen[0]["data"]
    assert event["h2_verdicts"] == [] and event["rule"] == "h2_connection"
    assert seen[0]["attack_type"] is None
