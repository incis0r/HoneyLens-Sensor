"""The backfill must classify an event with the context the ingest had.

Measured 2026-11-04 on `sensor-a` and `prod`: 70,772 of the fleet's 71,356 `ICS_ATTACK`
pattern rows sit on :3389 under one rule name,
`claude_s7comm_cotp_connection_request_detection`, source `honeypot-rdp`. The live ingest
cannot produce them -- it passes `protocol="RDP"`, which `_ENCRYPTED_PROTOCOLS` excludes
from every text rule. `backfill_attacks` produced them: it selected `event_id, payload`
only and called `classify_payload`, documented as classifying "without event context", so
`protocol` was `None`, `dst_port` was unknown, and every protocol and port gate in the
classifier was bypassed on every pass.

The same bytes, in one run:

    ingest   (protocol="RDP", metadata={"dst_port": 3389}) -> []
    backfill (classify_payload(payload))                   -> ICS_ATTACK

This is the second instance of one defect family. Phase A's `repair_suricata_tags` mirrored
`process_alert` instead of calling it and so had no `dst_port`; here the backfill reaches
the classifier through a convenience wrapper that drops the context on the floor.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row

# A real row, read off sensor-a: the RDP decoy logs its X.224 Connection Request as a JSON
# envelope with the frame in a "hex" key. 0x0300 is the TPKT header, which RDP shares with
# S7comm's COTP -- which is why an unanchored hex regex matches it inside the JSON.
RDP_X224_PAYLOAD = (
    '{"phase": "x224_request", "hex": "030000130ee00000000000010008000b000000", '
    '"size": 19, "cookie": "", "dst_port": 3389}'
)
RDP_X224_METADATA = {
    "hex": "030000130ee00000000000010008000b000000",
    "size": 19,
    "phase": "x224_request",
    "cookie": "",
    "dst_port": 3389,
}

# Also read off sensor-a: a well-formed Modbus Read Device Identification frame (protocol id
# 0x0000, FC 0x2B, MEI 0x0E) delivered to the Java RMI decoy on :1099. The decoy itself
# recorded `is_rmi: false`. This frame is real Modbus and must keep saying so.
MODBUS_FC43_HEX = "5a4700000005002b0e0100"
MODBUS_FC43_PAYLOAD = (
    '{"phase": "initial", "hex": "5a4700000005002b0e0100", "is_rmi": false, '
    '"size": 11, "dst_port": 1099}'
)


def _rows(payload, protocol, metadata, dst_port):
    return [("evt-1", payload, protocol, metadata, dst_port)]


def _patterns_for(payload, protocol, metadata, dst_port):
    from honeylens.tools.backfill_attacks import classify_batch

    _updates, patterns = classify_batch(
        _rows(payload, protocol, metadata, dst_port), include_severity=False
    )
    return patterns


def _rule_names(patterns):
    return {p[2] for p in patterns}


def _attack_types(patterns):
    return {p[1] for p in patterns}


# ---------------------------------------------------------------------------
# The query has to carry the context before the classifier can use it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reprocess_all", [True, False])
@pytest.mark.parametrize("last_event_id", [None, "evt-123"])
def test_the_backfill_selects_the_context_its_gates_need(monkeypatch, reprocess_all, last_event_id):
    """All four page queries, not just the one the happy path happens to take."""
    from honeylens.tools import backfill_attacks

    class _Conn:
        def __init__(self):
            self.sql = []

        def cursor(self):
            return self

        def execute(self, sql, params=None):
            self.sql.append(sql)

        def fetchall(self):
            return []

    conn = _Conn()
    monkeypatch.setattr(backfill_attacks, "get_connection", lambda: conn)
    monkeypatch.setattr(backfill_attacks, "put_connection", lambda c: None)

    backfill_attacks.fetch_event_batch_cursor(last_event_id, 100, reprocess_all=reprocess_all)

    sql = conn.sql[-1]
    assert "protocol" in sql, sql
    assert "metadata" in sql, sql
    assert "dst_port" in sql, sql


# ---------------------------------------------------------------------------
# The invariant: the two paths agree
# ---------------------------------------------------------------------------


def test_the_backfill_and_the_ingest_agree_on_an_rdp_x224_request():
    """The defect, stated as the thing that must not happen again: 70,772 rows."""
    ingest = classify_event_row(
        payload=RDP_X224_PAYLOAD, protocol="RDP", metadata=RDP_X224_METADATA
    )
    backfilled = _patterns_for(RDP_X224_PAYLOAD, "RDP", RDP_X224_METADATA, 3389)

    assert _rule_names(backfilled) == {h[1] for h in ingest}


def test_an_rdp_connection_request_is_not_an_ics_attack():
    patterns = _patterns_for(RDP_X224_PAYLOAD, "RDP", RDP_X224_METADATA, 3389)

    assert "ICS_ATTACK" not in _attack_types(patterns)
    assert "claude_s7comm_cotp_connection_request_detection" not in _rule_names(patterns)


def test_the_dst_port_column_supplies_the_gate_when_the_stored_json_does_not():
    """A Suricata or eBPF row keeps its port in the column, not in `metadata`. Without the
    column the port gates see `None` and a port-context verdict is dropped unjudged, so the
    same frame would classify differently depending on which writer stored it."""
    from honeylens.tools.backfill_attacks import _context_for, classify_batch

    portless = {"hex": MODBUS_FC43_HEX}

    assert _context_for(portless, 502) == {"hex": MODBUS_FC43_HEX, "dst_port": 502}

    _updates, patterns = classify_batch(
        [("evt-1", MODBUS_FC43_PAYLOAD, None, portless, 502)], include_severity=False
    )

    assert "ICS_ATTACK" in _attack_types(patterns)


def test_the_stored_port_wins_over_the_column():
    """`HONEYLENS_PORT_MAP` translates a decoy's bound port back to the protocol port, and
    what the decoy recorded is the protocol's own view. The column only fills a gap."""
    from honeylens.tools.backfill_attacks import _context_for

    assert _context_for({"dst_port": 502}, 51502) == {"dst_port": 502}
    assert _context_for(None, None) is None


# ---------------------------------------------------------------------------
# No coverage lost: real industrial traffic still classifies
# ---------------------------------------------------------------------------


def test_a_modbus_frame_on_the_modbus_port_still_classifies():
    patterns = _patterns_for(
        MODBUS_FC43_PAYLOAD, "modbus", {"hex": MODBUS_FC43_HEX, "dst_port": 502}, 502
    )

    assert "ICS_ATTACK" in _attack_types(patterns)


def test_a_modbus_frame_keeps_the_verdict_the_frame_itself_proves():
    """On :1099 the frame still parses as Modbus, so the parsed verdict stays. What goes is
    `Modbus_Unauthenticated_Write_Attempt` -- a hex literal duplicating the binary detector
    under a name that asserts a write, while FC 0x2B / MEI 0x0E is a read."""
    patterns = _patterns_for(
        MODBUS_FC43_PAYLOAD, "javarmi", {"hex": MODBUS_FC43_HEX, "dst_port": 1099}, 1099
    )
    names = _rule_names(patterns)

    assert "modbus_fc43_read_device_id" in names
    assert "Modbus_Unauthenticated_Write_Attempt" not in names


# ---------------------------------------------------------------------------
# The loose ICS text rules need an ICS port, not merely a non-HTTP one
# ---------------------------------------------------------------------------


def test_an_ssh_username_containing_s7_is_not_a_plc_password_change():
    """`s7comm_set_password` is `s7.*(set.?password|password|authentication)`: "s7" anywhere,
    then "password" anywhere. A telnet or SSH auth record carries both. Measured: 7 rows on
    :23 and :2200."""
    payload = '{"phase": "auth_retry", "username": "s7Secret", "password": "x"}'

    hits = classify_event_row(payload=payload, protocol="telnet", metadata={"dst_port": 23})

    assert "ICS_ATTACK" not in {h[0] for h in hits}


def test_the_word_recipient_is_not_a_cip_stop_service_request():
    """`cip_stop_service` is `cip.*(stop|abort|halt)` and "recipient" contains "cip".
    Measured: one row on the SMTP decoy, whose payload is an email body."""
    payload = '{"phase": "data", "body": "Recipient list, please stop sending"}'

    hits = classify_event_row(payload=payload, protocol="smtp", metadata={"dst_port": 25})

    assert "ICS_ATTACK" not in {h[0] for h in hits}


def test_a_redis_session_transcript_is_not_an_s7_plc_control_command():
    """`s7comm_plc_control` is `s7.*(plc.?control|memory.?copy|compress|insert)`. A Redis
    cron-write session ends with `config set rdbcompression`, and some earlier byte pair
    spells "s7". Measured: 80 rows on :6379, all of them real Redis RCE attempts that were
    also labelled ICS."""
    payload = (
        '{"phase": "session_end", "commands": 35, "command_list": '
        '["info server", "s7x", "config set rdbcompression no"]}'
    )

    hits = classify_event_row(payload=payload, protocol="REDIS", metadata={"dst_port": 6379})

    assert "ICS_ATTACK" not in {h[0] for h in hits}


def test_those_same_rules_still_fire_on_an_ics_port():
    """Gating on context must not silence the rules where they mean something.

    Note which case this is. Naming the protocol (`protocol="s7comm"`) puts the row in
    `_BINARY_PROTOCOLS`, where the text rules are skipped altogether and the binary
    detectors own the verdict -- so these rules are unreachable on the very protocol they
    describe, and only an unnamed protocol on an ICS port reaches them. That is the case
    worth keeping, and the one asserted here."""
    s7 = classify_event_row(
        payload="s7 set password 0x1234", protocol=None, metadata={"dst_port": 102}
    )
    cip = classify_event_row(
        payload="cip stop service request", protocol=None, metadata={"dst_port": 44818}
    )

    assert "s7comm_set_password" in {h[1] for h in s7}
    assert "cip_stop_service" in {h[1] for h in cip}
