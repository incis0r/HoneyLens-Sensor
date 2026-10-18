"""Verdicts for one observed HTTP/2 connection (Task 5)."""

from __future__ import annotations

from honeylens.honeypots import h2_capture, h2bomb
from honeylens.honeypots.h2_capture import (
    H2Observation,
    H2Stream,
    attack_type_field,
    decide,
)
from honeylens.honeypots.hp_http import HTTPHoneypot


def _classify_none(path, body, headers):
    return None


def _hp():
    return HTTPHoneypot.__new__(HTTPHoneypot)


def _obs(**kw):
    kw.setdefault("entry", "preface")
    # h2_capture only counts a CANCEL inside the total, so total >= cancel structurally.
    kw.setdefault("rst_stream_total", kw.get("rst_stream_cancel", 0))
    return H2Observation(**kw)


def _stream(path="/", method="GET", shaped=False):
    return H2Stream(
        stream_id=1,
        method=method,
        path=path,
        end_stream=True,
        content_type="application/x-www-form-urlencoded" if shaped else None,
        ended_by="reset",
    )


def test_a_single_shaped_probe_is_a_probe():
    verdicts, sev = decide(_obs(shape_matches=1, headers_frames=1), _classify_none)
    assert verdicts[0] == "cve_2026_119618_probe" and sev == "MEDIUM"


def test_the_shape_at_flood_volume_with_cancels_is_a_flood():
    obs = _obs(shape_matches=3456, headers_frames=3458, rst_stream_cancel=3456)
    verdicts, sev = decide(obs, _classify_none)
    assert verdicts[0] == "cve_2026_119618_flood" and sev == "HIGH"


def test_a_flood_without_the_shape_is_rapid_reset_not_119618():
    obs = _obs(shape_matches=0, headers_frames=3458, rst_stream_cancel=3456)
    verdicts, _ = decide(obs, _classify_none)
    assert verdicts == ["h2_rapid_reset"]
    assert not any("119618" in v for v in verdicts)


def test_the_49975_markers_win_over_rapid_reset():
    obs = _obs(
        shape_matches=0, headers_frames=200, rst_stream_cancel=200, settings_initial_window_size=0
    )
    verdicts, sev = decide(obs, _classify_none)
    assert "cve_2026_49975_zero_window" in verdicts
    assert "h2_rapid_reset" not in verdicts
    assert sev == "HIGH"


def test_an_ordinary_connection_is_prior_knowledge_not_abuse():
    verdicts, sev = decide(_obs(headers_frames=1, shape_matches=0), _classify_none)
    assert verdicts == ["h2_prior_knowledge"] and sev == "LOW"
    assert "PROTO_ABUSE" not in verdicts


def test_an_attack_over_h2_keeps_the_verdict_it_has_over_http_1_1():
    obs = _obs(headers_frames=1, streams=[_stream(path="/etc/passwd")])
    verdicts, _ = decide(obs, HTTPHoneypot._classify.__get__(_hp()))
    assert "lfi" in verdicts


def test_a_mixed_connection_carries_both_verdicts_in_precedence_order():
    obs = _obs(
        shape_matches=1,
        headers_frames=2,
        streams=[_stream(path="/", shaped=True), _stream(path="/etc/passwd")],
    )
    verdicts, _ = decide(obs, HTTPHoneypot._classify.__get__(_hp()))
    assert verdicts[0] == "cve_2026_119618_probe"  # one shaped stream is below any flood threshold
    assert "lfi" in verdicts


def test_a_stream_with_no_path_does_not_raise_through_classify(caplog):
    obs = _obs(headers_frames=1, streams=[_stream(path=None, method=None)])
    with caplog.at_level("DEBUG", logger="honeylens.honeypots.h2_capture"):
        verdicts, _ = decide(obs, HTTPHoneypot._classify.__get__(_hp()))
    assert verdicts == ["h2_prior_knowledge"]
    assert not [r for r in caplog.records if r.name == "honeylens.honeypots.h2_capture"]


def test_the_joined_field_never_exceeds_the_column_or_splits_a_name():
    field = attack_type_field(["cve_2026_119618_flood", "cve_2026_49975_zero_window", "lfi"])
    assert len(field) <= 64
    assert all(
        part in {"cve_2026_119618_flood", "cve_2026_49975_zero_window", "lfi"}
        for part in field.split(",")
    )


# ---- additions beyond the brief: the decisions the brief's tests leave open ----


def test_classify_never_sees_the_http_1_1_header_branches():
    seen = []

    def spy(path, body, headers):
        seen.append(headers)
        return None

    stream = _stream()
    stream.headers = {"user-agent": "python-h2/4.3.0"}
    decide(_obs(headers_frames=1, streams=[stream]), spy)
    assert seen == [None]


def test_a_legitimate_python_h2_client_is_not_recon():
    stream = _stream()
    stream.headers = {"user-agent": "python-h2/4.3.0", "upgrade": "h2c"}
    verdicts, _ = decide(
        _obs(headers_frames=1, streams=[stream]), HTTPHoneypot._classify.__get__(_hp())
    )
    assert verdicts == ["h2_prior_knowledge"]


def test_each_stream_records_the_verdict_it_earned():
    stream = _stream(path="/etc/passwd")
    decide(_obs(headers_frames=1, streams=[stream]), HTTPHoneypot._classify.__get__(_hp()))
    assert stream.verdict == "lfi"


def test_a_classify_that_raises_does_not_raise_through_decide():
    def boom(path, body, headers):
        raise RuntimeError("x")

    verdicts, sev = decide(_obs(headers_frames=1, streams=[_stream()]), boom)
    assert verdicts == ["h2_prior_knowledge"] and sev == "LOW"


def test_a_peer_that_never_declared_a_window_is_not_a_zero_window():
    obs = _obs(headers_frames=1, settings_initial_window_size=None)
    verdicts, _ = decide(obs, _classify_none)
    assert not any("zero_window" in v for v in verdicts)


def test_a_shaped_flood_that_mostly_completes_is_a_probe_not_a_flood():
    obs = _obs(shape_matches=60, headers_frames=60, rst_stream_cancel=30)
    verdicts, sev = decide(obs, _classify_none)
    assert verdicts[0] == "cve_2026_119618_probe" and sev == "MEDIUM"


def test_a_headers_flood_without_cancels_is_the_hpack_bomb_not_rapid_reset():
    obs = _obs(headers_frames=200, rst_stream_cancel=0)
    verdicts, _ = decide(obs, _classify_none)
    assert verdicts == ["cve_2026_49975_hpack_bomb"]


def test_a_flood_just_below_the_stream_floor_is_not_rapid_reset():
    n = h2_capture.SHAPE_FLOOD_STREAMS - 1
    verdicts, _ = decide(_obs(headers_frames=n, rst_stream_cancel=n), _classify_none)
    assert verdicts == ["h2_prior_knowledge"]


def test_severity_is_the_heaviest_present_not_the_first():
    streams = [_stream(path="/a"), _stream(path="/b")]
    results = iter([("lfi", "HIGH"), ("recon", "LOW")])
    obs = _obs(shape_matches=1, headers_frames=2, streams=streams)
    verdicts, sev = decide(obs, lambda p, b, h: next(results))
    assert verdicts == ["cve_2026_119618_probe", "lfi", "recon"] and sev == "HIGH"


def test_the_flood_floor_never_exceeds_the_h2bomb_floor():
    assert h2_capture.SHAPE_FLOOD_STREAMS <= h2bomb._FLOOD_COUNT


def test_the_field_drops_whole_names_from_the_tail_and_skips_an_overlong_one():
    assert attack_type_field([]) is None
    assert attack_type_field(["x" * 70, "lfi"]) == "lfi"
    names = ["cve_2026_119618_flood", "cve_2026_49975_zero_window", "cve_2026_49975_window_drip"]
    assert attack_type_field(names) == ",".join(names[:2])
    # a later, shorter name must not take the place of a heavier one that did not fit
    assert attack_type_field([*names, "lfi"]) == ",".join(names[:2])


# ---- fix round 1 ----


def test_a_critical_web_verdict_beside_a_probe_keeps_critical():
    obs = _obs(shape_matches=1, headers_frames=2, streams=[_stream(path="/cgi-bin/x?cmd=/bin/sh")])
    verdicts, sev = decide(obs, HTTPHoneypot._classify.__get__(_hp()))
    assert verdicts == ["cve_2026_119618_probe", "rce_attempt"] and sev == "CRITICAL"


def test_a_critical_web_verdict_alone_is_not_null_severity():
    obs = _obs(headers_frames=1, streams=[_stream(path="/cgi-bin/x?cmd=/bin/sh")])
    assert decide(obs, HTTPHoneypot._classify.__get__(_hp())) == (["rce_attempt"], "CRITICAL")


def test_an_unrecognised_severity_still_beats_none():
    obs = _obs(headers_frames=1, streams=[_stream()])
    assert decide(obs, lambda p, b, h: ("x", "SEVERE")) == (["x"], "SEVERE")


def test_a_reset_flood_without_cancel_is_rapid_reset_not_the_bomb():
    obs = _obs(headers_frames=3458, rst_stream_total=3458, rst_stream_cancel=0)
    assert decide(obs, _classify_none) == (["h2_rapid_reset"], "MEDIUM")


def test_a_headers_flood_with_no_resets_at_all_stays_the_bomb():
    obs = _obs(headers_frames=3458, rst_stream_total=0, rst_stream_cancel=0)
    assert decide(obs, _classify_none)[0] == ["cve_2026_49975_hpack_bomb"]


def test_a_continuation_train_is_the_bomb_as_it_is_on_8443():
    obs = _obs(headers_frames=1, continuation_frames=63)
    verdicts, sev = decide(obs, _classify_none)
    assert verdicts == ["cve_2026_49975_hpack_bomb"] and sev == "MEDIUM"


def test_a_reset_flood_with_a_window_marker_is_49975_not_rapid_reset():
    obs = _obs(
        headers_frames=200,
        rst_stream_total=200,
        rst_stream_cancel=200,
        window_update_count=30,
        window_update_min_increment=1,
    )
    verdicts, _ = decide(obs, _classify_none)
    assert "cve_2026_49975_window_drip" in verdicts
    assert "h2_rapid_reset" not in verdicts  # the bomb is not lone, so it is not dropped


def test_the_reference_capture_is_exactly_the_119618_flood():
    obs = _obs(
        shape_matches=3456, headers_frames=3458, rst_stream_total=3456, rst_stream_cancel=3456
    )
    assert decide(obs, _classify_none) == (["cve_2026_119618_flood"], "HIGH")


def test_a_shaped_flood_is_a_flood_whatever_reset_code_tore_it_down():
    # The reference capture's CANCEL is the proof-of-concept's choice, not a precondition:
    # the race fires on stream teardown and any RST_STREAM code causes one.
    obs = _obs(shape_matches=3456, headers_frames=3458, rst_stream_total=3456, rst_stream_cancel=0)
    assert decide(obs, _classify_none)[0] == ["cve_2026_119618_flood"]


def test_49975_is_listed_before_the_shape_verdict():
    obs = _obs(shape_matches=1, headers_frames=1, settings_initial_window_size=0)
    verdicts, sev = decide(obs, _classify_none)
    assert verdicts == ["cve_2026_49975_zero_window", "cve_2026_119618_probe"]
    assert sev == "HIGH"


def test_a_single_shaped_stream_does_not_explain_a_continuation_train():
    obs = _obs(shape_matches=1, headers_frames=1, continuation_frames=63)
    assert decide(obs, _classify_none)[0][0] == "cve_2026_49975_hpack_bomb"


def test_a_reset_flood_carrying_continuation_frames_is_still_the_bomb():
    obs = _obs(headers_frames=60, continuation_frames=600, rst_stream_total=60)
    assert decide(obs, _classify_none)[0] == ["cve_2026_49975_hpack_bomb"]


def test_every_severity_hp_http_can_emit_is_ranked():
    import inspect
    import re

    from honeylens.honeypots.hp_http import HTTPHoneypot as H

    emitted = {sev for _, _, sev in H._ATTACK_PATTERNS}
    literals = set(re.findall(r'return "[a-z0-9_]+", "([A-Z]+)"', inspect.getsource(H._classify)))
    # The literal returns (h2c_upgrade_recon, LOW, in both header branches) must still be found:
    # if _classify is reformatted the regex goes blind and this fails instead of narrowing.
    assert literals == {"LOW"}
    emitted |= literals
    assert emitted and emitted <= set(h2_capture._SEVERITY_RANK)


def test_an_unrecognised_severity_is_logged_once_per_label(caplog):
    streams = [_stream(path="/a"), _stream(path="/b")]
    with caplog.at_level("WARNING", logger="honeylens.honeypots.h2_capture"):
        decide(_obs(headers_frames=2, streams=streams), lambda p, b, h: ("x", "SEVERE"))
    assert len([r for r in caplog.records if "unrecognised severity" in r.getMessage()]) == 1


def test_one_shaped_stream_among_an_uncancelled_headers_flood_keeps_the_bomb():
    obs = _obs(shape_matches=1, headers_frames=60)
    assert decide(obs, _classify_none)[0] == ["cve_2026_49975_hpack_bomb", "cve_2026_119618_probe"]


def test_one_shaped_stream_does_not_hide_a_reset_flood():
    obs = _obs(shape_matches=1, headers_frames=3458, rst_stream_total=3456)
    assert decide(obs, _classify_none)[0] == ["h2_rapid_reset", "cve_2026_119618_probe"]


def test_the_additive_matrix_rows():
    cases = [
        (
            dict(shape_matches=49, headers_frames=3458, rst_stream_total=3456),
            ["h2_rapid_reset", "cve_2026_119618_probe"],
        ),
        (
            dict(shape_matches=1, headers_frames=60, rst_stream_total=60),
            ["h2_rapid_reset", "cve_2026_119618_probe"],
        ),
        (
            dict(shape_matches=3456, headers_frames=3458, rst_stream_total=3456),
            ["cve_2026_119618_flood"],
        ),
        (dict(shape_matches=60, headers_frames=60, rst_stream_total=30), ["cve_2026_119618_probe"]),
        (dict(headers_frames=3458, rst_stream_total=3456), ["h2_rapid_reset"]),
        (
            dict(shape_matches=1, headers_frames=60),
            ["cve_2026_49975_hpack_bomb", "cve_2026_119618_probe"],
        ),
        (
            dict(shape_matches=1, headers_frames=1, settings_initial_window_size=0),
            ["cve_2026_49975_zero_window", "cve_2026_119618_probe"],
        ),
    ]
    for kw, expected in cases:
        assert decide(_obs(**kw), _classify_none)[0] == expected, kw
