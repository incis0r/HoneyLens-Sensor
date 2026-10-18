"""core.dissection — shared deep-dissection port state for sensor.py and ingest/ebpf."""

from __future__ import annotations

import psycopg2
import pytest

from honeylens import dissection


@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        (0, 256),
        (255, 256),
        (256, 256),
        (1023, 256),
        (1024, 1024),
        (4095, 1024),
        (4096, 4096),
        (99999, 4096),
    ],
)
def test_quantize_depth_snaps_to_bpf_tiers(depth: int, expected: int) -> None:
    assert dissection.quantize_depth(depth) == expected


def test_build_desired_state_merges_config_and_db_with_db_winning(monkeypatch) -> None:
    monkeypatch.setattr(
        dissection,
        "_static_ports",
        lambda: {25: {"capture_depth": 300}, 21: {"capture_depth": 1024}},
    )
    monkeypatch.setattr(dissection, "load_dissection_ports_from_db", lambda: {25: 4096, 8080: 1024})
    assert dissection.build_desired_state() == {25: 4096, 21: 1024, 8080: 1024}


def test_db_read_failure_keeps_static_config(monkeypatch) -> None:
    monkeypatch.setattr(dissection, "_static_ports", lambda: {25: {"capture_depth": 4096}})

    def boom():
        raise psycopg2.OperationalError("no db")

    monkeypatch.setattr(dissection, "legacy_get_db", boom)
    assert dissection.load_dissection_ports_from_db() == {}
    assert dissection.build_desired_state() == {25: 4096}


def test_cached_state_refreshes_on_interval_only(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(dissection, "build_desired_state", lambda: calls.append(1) or {25: 4096})
    clock = [1000.0]
    monkeypatch.setattr(dissection.time, "monotonic", lambda: clock[0])
    st = dissection.CachedState(refresh_sec=30)
    assert st.is_monitored(25) and not st.is_monitored(80)
    assert st.get() == {25: 4096} and len(calls) == 1
    clock[0] += 10
    st.get()
    assert len(calls) == 1
    clock[0] += 25
    st.get()
    assert len(calls) == 2


def test_cached_state_minimum_interval_is_five_seconds() -> None:
    assert dissection.CachedState(refresh_sec=1).refresh_sec == 5
