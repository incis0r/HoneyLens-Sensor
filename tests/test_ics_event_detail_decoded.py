"""`/ics/event/{id}` serves the decoded frame, masks every hex key, and no longer says caldera.

The handler is called directly over a hand-written cursor (no live PostgreSQL here). The
fake cursor builds the row from the SELECT's own column list, so a column the SELECT asks
for that the test did not supply comes back None, and a column dropped from the SELECT is
dropped from the row.
"""

from __future__ import annotations

import inspect
import json
import re

from honeylens.ics import ICS_HEX_KEYS, MASKERS, decode_hex
from honeylens.routes import ics
from tests.test_ics_decode_mqtt import connect

SC = "680e2a0000002d0106000100640000" + "01"
# Not English-like: a window such as "use" would match the word "username" in a sentence.
USER, PASS = b"zq7kx-vrt", b"Pw9#mXq2LZ"


class FakeCursor:
    def __init__(self, event: dict | None, sensor: tuple | None = None):
        self.event, self.sensor, self.sql = event, sensor, []

    def execute(self, sql, params=None):
        self.sql.append(sql)

    def fetchone(self):
        sql = self.sql[-1]
        if "FROM ics_events" in sql:
            if self.event is None:
                return None
            head = sql.split("SELECT", 1)[1].split("FROM", 1)[0]
            cols = [c.strip().split("::")[0] for c in head.split(",") if c.strip()]
            return tuple(self.event.get(c) for c in cols)
        return self.sensor


class FakeConn:
    def __init__(self, cur):
        self.cur = cur

    def cursor(self):
        return self.cur

    def close(self):
        pass


def _get(monkeypatch, protocol, metadata, **extra):
    event = {"event_id": "evt_1", "protocol": protocol, "metadata": metadata, **extra}
    cur = FakeCursor(event)
    monkeypatch.setattr(ics, "db", lambda: FakeConn(cur))
    monkeypatch.setattr(ics, "_ics_table_exists", lambda: True)
    return ics.ics_event_detail("evt_1", None)


def _decoded(monkeypatch, protocol, metadata):
    return _get(monkeypatch, protocol, metadata)["decoded"]


def test_the_detail_endpoint_returns_fields_with_byte_offsets(monkeypatch):
    d = _decoded(monkeypatch, "iec104", {"asdu_hex": SC})
    assert d["semantics"] == "command" and d["code"] == 45
    assert {"name", "label", "offset", "length", "value", "meaning"} <= set(d["fields"][0])
    assert d["tail"] is None and d["raw_len"] == len(SC) // 2 and d["hex"] == SC
    assert d["hex_truncated"] is False and d["sentence"]


def test_an_undecodable_row_says_why_and_is_not_an_error(monkeypatch):
    d = _decoded(monkeypatch, "s7comm", {"frame_hex": "ff"})
    assert d["fields"] == [] and d["tail"]["reason"]


def test_a_pre_cutover_row_with_no_bytes_is_a_third_distinct_state(monkeypatch):
    """No hex key at all must not be reported as the 'not valid hex' of a damaged row."""
    d = _decoded(monkeypatch, "iec104", {"function": "x"})
    assert d["raw_len"] == 0 and d["hex"] == "" and d["tail"]["reason"]
    bad = _decoded(monkeypatch, "iec104", {"asdu_hex": "zz"})
    assert bad["tail"]["reason"] != d["tail"]["reason"]


def test_a_frame_at_the_capture_cap_is_not_served_whole(monkeypatch):
    """Defect guarded: a 64 KB dump rendered into the page."""
    big = SC + "00" * (64 * 1024 - len(SC) // 2)
    d = _decoded(monkeypatch, "iec104", {"asdu_hex": big})
    assert d["hex_truncated"] is True and len(d["hex"]) <= 2 * 4096
    assert d["raw_len"] == 64 * 1024  # the stored length is still reported whole


def test_the_cap_is_applied_to_the_emitted_hex_not_only_the_pane(monkeypatch):
    """Metadata carries the same bytes under its own keys; they are capped too."""
    big = "ab" * 10000
    meta = _get(monkeypatch, "modbus", {"pdu_hex": big})["metadata"]
    assert len(meta["pdu_hex"]) <= 2 * 4096


def test_the_decoder_reads_the_key_the_ingest_classified(monkeypatch):
    """One precedence list, not two: pdu_hex outranks frame_hex."""
    a, b = SC, "6804430000" + "00"
    d = _decoded(monkeypatch, "iec104", {"frame_hex": b, "pdu_hex": a})
    assert d["hex"] == a and d["semantics"] == "command"
    assert "ICS_HEX_KEYS" in inspect.getsource(ics)


def test_a_mask_that_returns_empty_carries_the_reason_through(monkeypatch):
    """mask_hex drops invalid hex for a hooked protocol; the pane must say why it is empty."""
    d = _decoded(monkeypatch, "mqtt", {"payload_hex": "not-hex", "pkt_type": 1})
    assert d["hex"] == "" and d["raw_len"] == 0
    assert d["tail"]["reason"] == decode_hex("mqtt", "").tail_reason


def test_no_ics_response_mentions_caldera(monkeypatch):
    r = _get(monkeypatch, "iec104", {"asdu_hex": SC})
    assert "caldera" not in json.dumps(r, default=str).lower()
    src = inspect.getsource(ics)
    assert "caldera_ability" not in src and "caldera_tactic" not in src


def test_function_code_and_decoded_code_are_two_readings(monkeypatch):
    """The decoy's own function_code is kept as-is next to the decoder's code."""
    r = _get(monkeypatch, "iec104", {"asdu_hex": SC}, function_code=99)
    assert r["function_code"] == 99 and r["decoded"]["code"] == 45


# ---------------------------------------------------------------- credentials


def _every_leaf(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _every_leaf(v)
    elif isinstance(value, list):
        for v in value:
            yield from _every_leaf(v)
    else:
        yield value


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _windows(secret: bytes):
    return [secret[i : i + 3] for i in range(len(secret) - 2)]


def _assert_no_secret(response, *secrets: bytes):
    text = json.dumps(response, default=str).lower()
    for s in secrets:
        assert s.decode().lower() not in text
        assert s.hex() not in text
        for w in _windows(s):
            assert w.decode().lower() not in text, w
            assert w.hex() not in text, w


def test_a_connect_packet_leaves_the_api_with_no_credential_bytes(monkeypatch):
    """Defect guarded: the MQTT decoy stores credentials under payload_hex AND frame_hex,
    and the key-based redactor cannot see inside hex. Whole string and every 3-byte window,
    in the metadata, the hex pane and the fields."""
    pkt = connect(username=USER, password=PASS)
    meta = {"pkt_type": 1, "payload_hex": pkt[2:].hex(), "frame_hex": pkt.hex()}
    r = _get(monkeypatch, "mqtt", meta)
    _assert_no_secret(r, USER, PASS)
    assert r["decoded"]["raw_len"] == len(pkt)


def test_every_hex_key_in_mqtt_metadata_is_masked_including_unnamed_ones(monkeypatch):
    """A decoy that later stores the packet under a key nobody named must still be masked."""
    pkt = connect(username=USER, password=PASS)
    meta = {
        "pkt_type": 1,
        "future_dump_hex": pkt.hex(),
        "nested": {"other_hex": pkt.hex()},
        "frames_hex": [pkt.hex(), [pkt.hex()]],
        "session_hex": {"first": pkt.hex(), "more": [{"x": pkt.hex()}]},
    }
    for key in ICS_HEX_KEYS:
        meta[key] = pkt.hex()
    r = _get(monkeypatch, "mqtt", meta)
    _assert_no_secret(r, USER, PASS)
    served = r["metadata"]

    def hex_keys(v, path=""):
        if isinstance(v, dict):
            for k, x in v.items():
                if k.endswith("_hex"):
                    yield path + k, x
                yield from hex_keys(x, path + k + ".")

    found = dict(hex_keys(served))
    assert {"future_dump_hex", "nested.other_hex", *ICS_HEX_KEYS} <= set(found)
    for key, value in found.items():
        for leaf in _strings(value):
            assert USER.hex() not in leaf and PASS.hex() not in leaf, key
            assert len(leaf) == len(pkt.hex()), key  # masked in place, length preserved


def test_a_non_connect_mqtt_row_keeps_its_bytes_when_the_pkt_type_hint_is_passed(monkeypatch):
    """Defect guarded: without pkt_type, mask_hex zeroes an HTTP probe stored on the MQTT
    port, blanking real evidence."""
    probe = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    d = _decoded(monkeypatch, "mqtt", {"frame_hex": probe.hex(), "pkt_type": 4})
    assert d["hex"] == probe.hex()
    z = _decoded(monkeypatch, "mqtt", {"frame_hex": probe.hex()})
    assert set(z["hex"]) == {"0"}  # no hint: fails closed


def test_the_hooked_protocol_set_is_what_this_test_file_assumes():
    assert "mqtt" in MASKERS  # a second hooked protocol needs its own test here
    assert set(MASKERS) == {"mqtt"}


def test_a_hex_key_with_trailing_whitespace_is_still_masked(monkeypatch):
    """Defect guarded: "frame_hex " failed the suffix test and was served raw."""
    pkt = connect(username=USER, password=PASS)
    r = _get(monkeypatch, "mqtt", {"pkt_type": 1, "frame_hex ": pkt.hex(), "A_HEX\t": pkt.hex()})
    _assert_no_secret(r, USER, PASS)


def test_a_hex_string_used_as_a_dict_key_under_a_hex_key_is_masked(monkeypatch):
    """Defect guarded: leaf() masked values but not keys, so {"x_hex": {hex: 1}} leaked."""
    pkt = connect(username=USER, password=PASS)
    meta = {"pkt_type": 1, "x_hex": {pkt.hex(): 1, "plain": [{pkt.hex(): 2}]}}
    r = _get(monkeypatch, "mqtt", meta)
    _assert_no_secret(r, USER, PASS)
    assert len(r["metadata"]["x_hex"]) == 2  # no entry lost


def test_a_non_string_under_a_hex_key_is_kept_for_an_unhooked_protocol(monkeypatch):
    """Defect guarded: {"pdu_hex": 5} on a modbus row came back "" with no reason."""
    assert _get(monkeypatch, "modbus", {"pdu_hex": 5})["metadata"]["pdu_hex"] == 5
    assert _get(monkeypatch, "mqtt", {"payload_hex": 5})["metadata"]["payload_hex"] == ""


def test_every_site_that_serves_a_dict_goes_through_servable_metadata():
    """One chokepoint: no call site may pair redact_structure and the hex mask by hand."""
    src = inspect.getsource(ics)
    uses = [ln for ln in src.splitlines() if re.search(r"(?<!\w)redact_structure\(", ln)]
    assert len(uses) == 1 and "_mask_hex_keys(" in uses[0], uses
    assert src.count("servable_metadata(") >= 4


def test_the_api_route_does_not_import_the_ingest():
    """Defect: routes/ics.py imported a private alias from honeylens.ingest.honeypot, which
    dragged the ingest, its helpers and logcleanup into the API process for a tuple that
    honeylens.ics already exports."""
    import subprocess
    import sys

    code = (
        "import sys, honeylens.routes.ics; "
        "bad = [m for m in sys.modules if m.startswith('honeylens.ingest')]; "
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0
