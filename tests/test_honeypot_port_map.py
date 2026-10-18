"""Bound port vs protocol port: the process binds high, the event says what was attacked.

Inside the container the honeypot is not root, so SSH listens on 30022 and the host DNATs
22 to it. Everything downstream — the classifier's ICS/HTTP port tables, ics_events,
the dashboard's "port" column — must still see 22, so the translation happens at the one
place every honeypot goes through: the sink.
"""

from __future__ import annotations

import json

from honeylens import config
from honeylens.honeypots import _base, sink


def test_public_port_translates_only_what_is_mapped(monkeypatch):
    monkeypatch.setattr(sink, "PORT_MAP", {30502: 502})
    assert sink.public_port(30502) == 502
    assert sink.public_port(6379) == 6379
    assert sink.public_port(None) is None


def test_the_record_and_its_metadata_carry_the_protocol_port(monkeypatch, tmp_path):
    monkeypatch.setattr(sink, "PORT_MAP", {30502: 502})
    monkeypatch.setattr(sink, "HONEYPOTNG_LOG_DIR", tmp_path)
    record = _base.log_event("modbus", ("203.0.113.9", 1), {"dst_port": 30502, "payload": "FC=3"})
    assert record["dst_port"] == 502
    assert record["event"]["dst_port"] == 502, "the classifier reads dst_port from metadata"
    line = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert line["dst_port"] == 502


def test_a_malformed_map_entry_is_dropped_not_fatal():
    assert sink._parse_port_map("30502:502, junk ,30022:22") == {30502: 502, 30022: 22}


def test_services_table_from_env_matches_the_manifest_shape():
    assert config.parse_services("") == config._HONEYPOTNG_SERVICES_DEFAULT
    assert config.parse_services("30021:ftp,30022:ssh, 8443:https") == {
        30021: "ftp",
        30022: "ssh",
        8443: "https",
    }
