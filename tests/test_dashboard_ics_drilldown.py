"""The ICS screen: a side drawer, a packet view, honest empty states, a cutover marker.

One page that an OT automation engineer and a blue-team analyst can both read: the plain
fact comes first and the identifier second. There is no PostgreSQL and no browser here, so
the screen is tested by rendering: the Python render functions return HTML that is asserted
on, and the inline script is pinned by reading the template source.
"""

from __future__ import annotations

import html as htmllib
import inspect
import re

from honeylens.routes import ics as ics_routes
from honeylens.routes.ics import _decoded_block
from honeylens.webui import dashboard_ics
from honeylens.webui.dashboard_ics import (
    _CUTOVER,
    _CUTOVER_SQL,
    _ics_dashboard_html,
    _render_cutover_marker,
    _render_packet_view,
)
from tests.test_ics_event_detail_decoded import FakeConn, FakeCursor

SC = "680e2a0000002d0106000100640000" + "01"


def iec104_command_decoded():
    return _decoded_block("iec104", {"asdu_hex": SC})


def modbus_fc90_decoded():
    return _decoded_block("modbus", {"frame_hex": "5a0020001400000000000002"})


def no_bytes_decoded():
    return _decoded_block("modbus", {})


def undecodable_decoded():
    return _decoded_block("modbus", {"frame_hex": "zz"})


def tail_decoded():
    return _decoded_block("modbus", {"frame_hex": "0600"})


def _render_ics_dashboard(window_days=30):
    """The page as the route builds it, with a window that does or does not reach
    back across the cutover (the route's SQL counts rows on each side)."""
    before = 120 if window_days >= 30 else 0
    # the banner counts the same table the funnel does: its denominator is the summary total
    after = 500
    data = {
        "summary": {"total": before + after, "intent_command": 3, "intent_unknown": before},
        "cutover": {"before": before, "after": after},
    }
    return _ics_dashboard_html(data)


def _template():
    return dashboard_ics._TEMPLATE


# ── the top line ────────────────────────────────────────────────────────────


def test_the_top_line_does_not_sum_commands_into_reads():
    html = _render_ics_dashboard()
    assert "command" in html and html.count('id="kpi-total"') == 1


def test_the_funnel_has_six_buckets_each_with_its_own_cell():
    """The API emitted intent_anomaly and intent_unknown while the page drew four
    buckets, so two figures were computed and thrown away."""
    html = _render_ics_dashboard()
    for b in ("command", "write", "recon", "enumeration", "anomaly", "unknown"):
        assert html.count(f'id="kpi-{b}"') == 1, b
    # the script fills exactly those six cells from the summary the API sends
    m = re.search(r"var BUCKETS=\[([^\]]*)\]", _template())
    assert m and re.findall(r"'(\w+)'", m.group(1)) == [
        "command",
        "write",
        "recon",
        "enumeration",
        "anomaly",
        "unknown",
    ]
    assert "s['intent_'+b]" in _template()


def test_anomaly_and_unknown_do_not_look_alike_and_neither_looks_ordinary():
    """unknown = we do not know what the bytes were; anomaly = the function code is
    outside the specification, a positive finding. Two grey pills would hide that."""
    t = _template()
    m = re.search(r"var INTENT=\{(.*?)\};\n", t, re.S)
    assert m, "INTENT table not found"
    table = m.group(1)
    for b in ("anomaly", "unknown"):
        assert b in table
    anomaly = re.search(r"anomaly:\{([^}]*)\}", table).group(1)
    unknown = re.search(r"unknown:\{([^}]*)\}", table).group(1)
    assert anomaly != unknown
    colour = lambda s: re.search(r"c:'(#\w+)'", s).group(1)  # noqa: E731
    ordinary = {
        colour(v) for v in re.findall(r"(?:command|write|recon|enumeration):\{([^}]*)\}", table)
    }
    assert colour(anomaly) != colour(unknown)
    assert colour(anomaly) not in ordinary and colour(unknown) not in ordinary
    # the identifiers both selects offer are the six the API filters on
    sel = re.search(r'<select id="fIntent">(.*?)</select>', t, re.S).group(1)
    for b in ("anomaly", "unknown"):
        assert f'value="{b}"' in sel


def test_unknown_is_never_reported_as_quiet():
    """Every row before 2026-10-25 has NULL semantics. 'No ICS activity' must not be
    the reading of a window whose only events are of unknown meaning."""
    t = _template()
    assert "else if(unk){st='UNCLASSIFIED'" in t


# ── the drawer ──────────────────────────────────────────────────────────────


def test_the_drawer_has_three_tabs_over_the_same_incident():
    t = _template()
    for v in ("event", "address", "honeypot"):
        assert f'data-act="dtab" data-v="{v}"' in t
    # the old pair of drawers is gone: one drawer, one incident
    assert 'id="dwEvent"' not in t and 'id="dwIp"' not in t
    assert t.count('id="dw"') == 1


def test_escape_closes_and_arrows_walk_the_list():
    t = _template()
    assert "'Escape'" in t and "'ArrowDown'" in t and "'ArrowUp'" in t
    # arrows must not hijack typing in the filter box
    for tag in ("INPUT", "SELECT", "TEXTAREA"):
        assert f"t==='{tag}'" in t


def test_the_list_is_not_covered_by_a_modal_overlay():
    """A side drawer exists so the reader keeps their place in the list. A dimming
    full-screen overlay that swallows clicks defeats it."""
    assert 'id="ov"' not in _template()


def test_the_honeypot_tab_is_this_decoy_on_this_sensor_not_fleet_wide():
    t = _template()
    assert "this decoy on this sensor" in t.lower()
    assert "DATA.by_protocol" in t


# ── the packet view ─────────────────────────────────────────────────────────


def test_every_field_row_carries_its_byte_range_for_the_colour_link():
    html = _render_packet_view(iec104_command_decoded())
    assert 'data-offset="6"' in html and 'data-length="1"' in html


def test_every_field_of_the_block_has_a_row_with_its_own_range():
    d = iec104_command_decoded()
    html = _render_packet_view(d)
    for f in d["fields"]:
        assert f'data-offset="{f["offset"]}" data-length="{f["length"]}"' in html, f["name"]


def test_bytes_carry_their_index_so_hovering_bytes_can_find_the_field():
    """The link runs both ways: field -> bytes by range, bytes -> field by index."""
    d = iec104_command_decoded()
    html = _render_packet_view(d)
    n = len(d["hex"]) // 2
    assert html.count('class="by') == n
    assert 'data-i="6"' in html and f'data-i="{n - 1}"' in html
    t = _template()
    assert "mouseover" in t and "mouseout" in t


def test_hex_is_left_of_the_fields_and_the_sentence_is_under_them():
    html = _render_packet_view(iec104_command_decoded())
    assert html.index('class="pk-hex"') < html.index('class="pk-fields"')
    assert html.index('class="pk-fields"') < html.index('class="pk-sentence"')


def test_the_unparsed_tail_is_rendered_with_its_reason():
    html = _render_packet_view(modbus_fc90_decoded())
    assert "90" in html and "specification" in html


def test_the_three_empty_states_are_three_different_sentences():
    a = _render_packet_view(no_bytes_decoded())
    b = _render_packet_view(undecodable_decoded())
    c = _render_packet_view(tail_decoded())
    assert len({a, b, c}) == 3
    state = lambda h: re.search(r'<div class="pk-state[^"]*"[^>]*>(.*?)</div>', h, re.S).group(1)  # noqa: E731
    sa, sb, sc = state(a), state(b), state(c)
    assert len({sa, sb, sc}) == 3
    assert "No bytes were stored" in sa
    assert "could not be decoded" in sb and "stored bytes are not valid hex" in sb
    assert "not placed" in sc and "offset 1" in sc


def test_an_empty_hex_with_a_reason_renders_the_reason_not_a_blank_box():
    """The API can send hex "" with the reason 'stored bytes are not valid hex'. A
    single empty pane for every kind of nothing is the defect this screen exists to end."""
    d = undecodable_decoded() | {"hex": ""}
    html = _render_packet_view(d)
    assert "stored bytes are not valid hex" in html
    assert 'class="pk-hex"' in html
    pane = html.split('class="pk-hex"', 1)[1].split('class="pk-fields"', 1)[0]
    assert re.sub(r"<[^>]+>", "", pane).strip(), "the hex pane is blank"


def test_a_clean_decode_says_it_ran_to_the_last_byte():
    html = _render_packet_view(iec104_command_decoded())
    assert "to the last byte" in html and "pk-state" in html


def test_the_plain_sentence_comes_before_the_identifier():
    html = _render_packet_view(iec104_command_decoded())
    assert html.index("output 100") < html.index("T0855")


def test_an_anomaly_asserts_no_technique_and_says_why():
    html = _render_packet_view(modbus_fc90_decoded())
    assert not re.search(r"T08\d\d", html)
    assert "finding" in html


def test_a_field_value_is_escaped_and_the_api_redaction_is_shown_as_sent():
    """Rendering a value as markup would let an attacker's string become the page, and
    the API's <redacted:N> must arrive intact, not be re-read as a tag."""
    d = iec104_command_decoded()
    d["fields"][0] = d["fields"][0] | {"value": "<script>x()</script>", "meaning": "<redacted:7>"}
    html = _render_packet_view(d)
    assert "<script>x()" not in html
    assert htmllib.escape("<redacted:7>") in html


def test_the_view_renders_only_the_masked_hex_the_api_sent():
    """The API masks credentials; the view must not rebuild bytes from anywhere else."""
    d = iec104_command_decoded() | {"hex": "aabb", "raw_hex": "deadbeef", "payload": "cafe"}
    html = _render_packet_view(d)
    assert ">aa<" in html and ">bb<" in html
    for leaked in ("de", "ad", "be", "ef", "ca", "fe"):
        assert f">{leaked}<" not in html


def test_a_truncated_capture_and_a_truncated_page_view_are_told_apart():
    d = iec104_command_decoded() | {
        "hex_truncated": True,
        "capture_truncated": False,
        "raw_len": 9000,
    }
    assert "9000" in _render_packet_view(d)
    d2 = iec104_command_decoded() | {"capture_truncated": True}
    assert "captured" in _render_packet_view(d2)


# ── two independent readings of the function code ──────────────────────────


def test_the_decoy_and_the_decoder_readings_are_labelled_and_a_difference_is_shown():
    d = iec104_command_decoded()
    same = _render_packet_view(d, recorded_code=45)
    assert "recorded by the decoy" in same and "read by the decoder" in same
    assert "differ" not in same
    diff = _render_packet_view(d, recorded_code=44)
    assert "differ" in diff and "44" in diff and "45" in diff


def test_a_null_function_code_on_s7comm_is_by_design_not_a_gap():
    d = _decoded_block("s7comm", {"frame_hex": "ff"})
    html = _render_packet_view(d, recorded_code=None)
    assert "not recorded" in html and "by design" in html


# ── the cutover ─────────────────────────────────────────────────────────────


def test_a_window_crossing_the_cutover_says_so():
    """Rows before 2026-10-25 12:00 UTC carry fewer facts. A figure computed across
    that boundary without saying so is wrong, and an empty pre-cutover field is not
    evidence that nothing happened."""
    assert "25" in _render_ics_dashboard(window_days=30)  # the marker is present
    assert _CUTOVER.tzinfo is not None  # compared in UTC, not local
    # not the bare word: the shared nav stylesheet has ::marker in it
    assert "cutover-marker" not in _render_ics_dashboard(window_days=1)
    assert "cutover-marker" in _render_ics_dashboard(window_days=30)


def test_the_marker_names_the_instant_in_utc_and_the_count_it_qualifies():
    html = _render_cutover_marker({"window_days": 30, "before": 120, "after": 500})
    assert "25 Oct 2026 12:00 UTC" in html and "120" in html
    assert _render_cutover_marker({"window_days": 1, "before": 0, "after": 9}) == ""
    assert _render_cutover_marker(None) == ""


def test_the_cutover_is_evaluated_in_utc_not_sensor_local_time():
    """One sensor runs UTC and the rest Europe/Warsaw, and the offset changed on
    25 October — the same day as the cutover."""
    assert "AT TIME ZONE 'UTC'" in _CUTOVER_SQL
    assert "NOW()" not in _CUTOVER_SQL.split("WHERE", 1)[0]


def test_the_rendered_cutover_constant_is_the_cutover_instant():
    """The placeholder was replaced without consuming its fallback digit, so the page held
    17929296000000 (year 2538) and every row, post-cutover ones included, was flagged as
    recorded before the cutover. A test of the identifier let it through; this pins the value."""
    html = _render_ics_dashboard()
    m = re.search(r"var CUT_MS=(\d+);", html)
    assert m and int(m.group(1)) == int(_CUTOVER.timestamp() * 1000)
    assert "Date.parse" in html


def test_the_stats_route_runs_the_cutover_sql_through_the_module_constant():
    src = inspect.getsource(ics_routes.ics_stats)
    assert "_CUTOVER_SQL" in src and "cutover=cutover" in src


# ── the packet fragment route ───────────────────────────────────────────────


def test_the_packet_route_serves_the_same_view_with_both_function_code_readings(monkeypatch):
    event = {
        "event_id": "evt_1",
        "protocol": "iec104",
        "function_code": 45,
        "metadata": {"asdu_hex": SC},
    }
    cur = FakeCursor(event)
    monkeypatch.setattr(ics_routes, "db", lambda: FakeConn(cur))
    monkeypatch.setattr(ics_routes, "_ics_table_exists", lambda: True)
    resp = ics_routes.ics_event_packet("evt_1", None)
    body = resp.body.decode()
    assert "output 100" in body and "recorded by the decoy" in body
    assert body.index("output 100") < body.index("T0855")


# ── one column answers "was it a write?" ────────────────────────────────────


def test_no_figure_on_the_screen_counts_writes_from_the_superseded_booleans():
    """is_write/is_control/is_read/is_discovery were set by a substring heuristic on the rule
    name and are known-wrong for every row before the cutover, where semantics is NULL. The
    write/command card, needs-attention, the per-protocol and per-function columns and the
    impact filter sat next to a funnel computed from semantics: two answers to one question."""
    pat = r"(?:FILTER \(WHERE|WHERE \(|AND \(?|OR )\s*is_(?:write|control|read|discovery)\b(?!\s*=\s*%s)"  # the explicit is_write= API parameter filters the column on purpose
    for fn in (ics_routes.ics_stats, ics_routes.ics_events):
        hits = re.findall(pat, inspect.getsource(fn))
        assert not hits, (fn.__name__, hits)
    assert "semantics IN ('write','command','control')" in inspect.getsource(ics_routes.ics_stats)


def test_the_banner_denominator_is_the_scope_of_the_figures_it_qualifies():
    """The cutover count was windowed to 30 days while the summary and funnel it sits above
    are full-table, so it could say 'of 620' above a funnel counting more."""
    assert "make_interval" not in _CUTOVER_SQL and "NOW()" not in _CUTOVER_SQL
    html = _render_cutover_marker({"before": 120, "after": 500})
    assert "120 of the 620" in html and "last 30 days" not in html


def test_the_recon_cell_does_not_claim_only_values_were_read():
    """The recon bucket also holds discovery, host/port scanning."""
    html = _render_ics_dashboard()
    assert "Values read, and host/port scans" in html


def test_a_frame_that_ended_early_is_not_said_to_have_unplaced_bytes():
    """raw_len 1 with the tail at offset 1: no byte exists at or after the offset."""
    d = tail_decoded() | {"raw_len": 1, "hex": "06", "tail": {"offset": 1, "reason": "ended"}}
    html = _render_packet_view(d)
    assert "it ended before the next field" in html and "not placed" not in html
    odd = tail_decoded() | {"raw_len": 5}
    assert "4 byte(s) from offset 1 are not placed" in _render_packet_view(odd)
    unk = tail_decoded() | {"raw_len": None}
    assert "the bytes from offset 1 are not placed" in _render_packet_view(unk)


def test_a_non_integer_tail_offset_does_not_500_the_packet_endpoint():
    d = tail_decoded() | {"tail": {"offset": "x", "reason": "odd"}}
    assert "odd" in _render_packet_view(d)


def test_the_anomaly_and_unknown_cells_keep_their_hover_feedback():
    """.fb:hover came before the [data-b=...] rules and lost to them on both cells."""
    t = _template()
    assert ".fb[data-b=anomaly]:hover" in t and ".fb[data-b=unknown]:hover" in t


def test_no_plain_language_text_claims_less_than_its_bucket_holds():
    """recon also holds host/port scans; anomaly also holds undefined, reserved and cut-short
    frames; unknown is NULL semantics, which is bytes not kept AND bytes not understood. A
    narrower gloss on the pill, the drawer line or the cell contradicts the bucket."""
    t = _template()
    p = lambda k: re.search(k + r":\{[^}]*p:'([^']*)'", t).group(1)  # noqa: E731
    assert "scanned" in p("recon")
    assert "understood" in p("unknown") and "not kept" in p("unknown")
    assert "outside the specification" not in t.lower()
    # A merely truncated frame keeps its real semantics (a cut-off write is a write), so
    # anomaly must not be glossed as holding cut-short frames.
    assert "cut short" not in t.lower()
    # Deliberate: the short chip "OUT OF SPEC" and the select option "anomaly (outside spec)"
    # are abbreviations for the genuinely-undefined case and are narrower than the bucket on
    # purpose; the full gloss beside them is the one that must stay accurate.
    assert "OUT OF SPEC" in t and "outside spec)" in t
    assert "attempt" in p("command") and "attempt" in p("write")
