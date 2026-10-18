import tempfile
from pathlib import Path

import pytest

from honeylens.ingest import pcap_export_hook as hook


class Cursor:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def execute(self, statement, parameters):
        if self.fail:
            raise RuntimeError("database unavailable")
        self.calls.append((statement, parameters))


def test_high_pcap_is_spooled_and_queued(monkeypatch):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source.pcap"
        source.write_bytes(b"\xd4\xc3\xb2\xa1payload")
        monkeypatch.setattr(hook, "SPOOL_ROOT", root / "spool")
        cursor = Cursor()

        queued = hook.queue_export_candidate(
            cursor,
            source,
            "evt-1",
            "HIGH",
            "2026-08-04T12:00:00Z",
            "http",
            "198.51.100.1",
            12345,
            "192.0.2.10",
            80,
            {"test": True},
        )

        assert queued is True
        assert (root / "spool" / "evt-1.pcap").read_bytes() == source.read_bytes()
        assert len(cursor.calls) == 1


def test_low_pcap_is_not_spooled(monkeypatch):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source.pcap"
        source.write_bytes(b"\xd4\xc3\xb2\xa1payload")
        monkeypatch.setattr(hook, "SPOOL_ROOT", root / "spool")

        assert (
            hook.queue_export_candidate(
                Cursor(),
                source,
                "evt-1",
                "LOW",
                "2026-08-04T12:00:00Z",
                "http",
                "198.51.100.1",
                12345,
                "192.0.2.10",
                80,
                {},
            )
            is False
        )
        assert not (root / "spool").exists()


def test_database_failure_removes_new_spool_copy(monkeypatch):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source.pcap"
        source.write_bytes(b"\xd4\xc3\xb2\xa1payload")
        monkeypatch.setattr(hook, "SPOOL_ROOT", root / "spool")

        with pytest.raises(RuntimeError, match="database unavailable"):
            hook.queue_export_candidate(
                Cursor(fail=True),
                source,
                "evt-1",
                "CRITICAL",
                "2026-08-04T12:00:00Z",
                "http",
                "198.51.100.1",
                12345,
                "192.0.2.10",
                80,
                {},
            )
        assert not (root / "spool" / "evt-1.pcap").exists()
