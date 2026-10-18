"""Every ingest stores whose traffic it was, and an un-migrated host loses no event.

Phase C, Task C3. `source_class` is decided once per event, by the ingest that saw it, because
provenance is a fact about the moment of capture: a CIDR list changes under the data, and 12.8%
of the store is already mislabelled by report-time guessing.

**Seven insert sites, not the five the plan listed.** Enumerating
`INSERT INTO sensor_events` across `src/` finds `honeypot.py`, `suricata.py`, `ebpf.py`,
`fortigate.py`, `paloalto.py` twice, and `tools/honeypot_generator.py` — the last one writes real
attacker events from a generated decoy and the plan missed it. The enumeration is a test here, so
the next writer cannot be missed either.

**The column goes last, everywhere.** That is what makes the pre-0013 fallback a one-line
`params[:-1]` instead of a second tuple per site, and `prod`'s schema is older than the rest of
the fleet's — `attack_types` is still `text` there — so "the column might not exist yet" is a
live case, not a hypothetical. An INSERT naming a column that does not exist fails the whole
statement, and on this ingest path that means the event is gone.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from honeylens.intelligence import source_class as sc

VALIDATION_HOST = "203.0.113.9"
EXTERNAL_HOST = "91.92.40.12"
INTERNAL_HOST = "10.9.9.9"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    """Configure the classes, and forget the schema probe.

    `source_class_supported` caches per process, which is right on a sensor and wrong across
    tests that deliberately present a migrated and an un-migrated host."""
    from honeylens.ingest import _schema

    monkeypatch.setattr(sc, "_OWN_INFRA", sc._compile(("192.0.2.0/24",)))
    monkeypatch.setattr(sc, "_VALIDATION", sc._compile((VALIDATION_HOST,)))
    _schema.reset_capability_cache()
    yield
    _schema.reset_capability_cache()


class _Cursor:
    """Enough of a cursor to record the statements an ingest runs.

    `has_source_class` drives the `information_schema` probe, so the same fake exercises a
    migrated and an un-migrated host.
    """

    def __init__(self, has_source_class: bool = True):
        self.has_source_class = has_source_class
        self.statements: list[tuple[str, tuple | None]] = []
        self._last = ""

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        self._last = sql

    def fetchone(self):
        low = self._last.lower()
        if "information_schema.columns" in low:
            if "source_class" in low:
                return (1 if self.has_source_class else 0,)
            if "full_payload" in low:
                return (2,)
            return (0,)
        return None

    def fetchall(self):
        return []

    def close(self):
        pass

    # --- helpers for the assertions -------------------------------------------------
    def event_inserts(self) -> list[tuple[str, tuple | None]]:
        return [(s, p) for s, p in self.statements if "INSERT INTO sensor_events" in s]

    def only_event_insert(self) -> tuple[str, tuple | None]:
        inserts = self.event_inserts()
        assert len(inserts) == 1, f"expected one event insert, got {len(inserts)}"
        return inserts[0]


class _Conn:
    def __init__(self, cur: _Cursor):
        self._cur = cur

    def cursor(self, *args, **kwargs):
        return self._cur

    def commit(self):
        pass

    def rollback(self):
        pass


def _stored_class(cur: _Cursor) -> str | None:
    """The value the ingest bound to `source_class` — the last parameter, by convention."""
    sql, params = cur.only_event_insert()
    assert "source_class" in sql, sql
    assert params is not None
    return params[-1]


# ---------------------------------------------------------------------------
# No insert site is left out
# ---------------------------------------------------------------------------

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "honeylens"
_INSERT_RE = re.compile(r"INSERT INTO sensor_events\s*\(([^)]*)\)", re.IGNORECASE)


def _insert_sites() -> list[tuple[str, str]]:
    """`(relative path, column list)` for every event INSERT written out as a literal.

    A column list containing `{` is an f-string composed from constants — only `ebpf.py` does
    that, and it is asserted separately below, because its columns are not readable here.
    """
    sites: list[tuple[str, str]] = []
    for path in sorted(_SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in _INSERT_RE.finditer(text):
            columns = match.group(1)
            if "{" in columns:
                continue
            sites.append((str(path.relative_to(_SRC)), columns))
    return sites


def _files_with_inserts() -> list[str]:
    return sorted({path for path, _cols in _insert_sites()})


def test_the_tree_has_the_insert_sites_this_task_covers():
    """Five files, and the fifth is `tools/honeypot_generator.py` — a generated decoy writing
    real attacker events, which the plan's list of ingests did not include. `ebpf.py` composes
    its statement from constants, so it has its own assertion below."""
    assert _files_with_inserts() == [
        "ingest/fortigate.py",
        "ingest/honeypot.py",
        "ingest/paloalto.py",
        "ingest/suricata.py",
        "tools/honeypot_generator.py",
    ]


@pytest.mark.parametrize("path", _files_with_inserts())
def test_every_insert_shape_has_a_pre_migration_twin(path):
    """The invariant that survives a new writer: in each file, the statements naming
    `source_class` and the statements not naming it come in equal numbers, and the file holds
    the `source_class_supported` guard that chooses between them.

    One statement without a twin means either an event lost on an un-migrated host, or own
    traffic stored as NULL — which reads as "a real actor" and is the defect this phase exists
    to end."""
    columns = [cols for p, cols in _insert_sites() if p == path]
    with_col = [c for c in columns if "source_class" in c]
    without_col = [c for c in columns if "source_class" not in c]
    text = (_SRC / path).read_text(encoding="utf-8")

    assert with_col, f"{path} has no insert naming source_class"
    assert len(with_col) == len(without_col), (
        f"{path}: {len(with_col)} with the column, {len(without_col)} without"
    )
    assert "source_class_supported(" in text, f"{path} has no guard to choose between them"


def test_the_ebpf_insert_is_built_from_its_column_constants():
    """`ebpf.py` composes its statement at import from module constants, so the regex above
    cannot read its columns and the shape depends on what the probe found. The invariant that
    holds either way is the one that breaks an insert when it is wrong: the column it adds and
    the placeholder it adds come in step.

    Asserted without a database, so here the probe has found nothing and the statement is the
    pre-0013 one — which is itself the case worth having a test for."""
    from honeylens.ingest import ebpf

    columns = ebpf.INSERT_SQL[ebpf.INSERT_SQL.index("(") + 1 : ebpf.INSERT_SQL.index(")")]
    placeholders = ebpf.INSERT_SQL.count("%s")

    assert placeholders == len(columns.split(",")), (columns, placeholders)
    assert ("source_class" in columns) == ebpf._HAS_SOURCE_CLASS_COL
    assert "source_class" in ebpf._has_source_class_column.__doc__


def test_the_ebpf_row_gains_the_value_only_when_the_column_is_there():
    """The row is built up with the same two conditions as the column list, in the same order.
    A mismatch is a `psycopg2.ProgrammingError` on every packet, so it is worth pinning in
    text: this module cannot be exercised without a kernel probe and a database."""
    import inspect

    from honeylens.ingest import ebpf

    src = inspect.getsource(ebpf)
    column_add = src.index('_EXTRA_COLS += ", source_class"')
    value_add = src.index("row = (*row, classify_source(src_ip))")

    assert "if _HAS_SOURCE_CLASS_COL:" in src[column_add - 200 : column_add]
    assert "if _HAS_SOURCE_CLASS_COL:" in src[value_add - 200 : value_add]


# ---------------------------------------------------------------------------
# Per ingest: the class is stored
# ---------------------------------------------------------------------------


def test_the_honeypot_ingest_stores_the_class():
    from honeylens.ingest import honeypot

    cur = _Cursor()
    honeypot.process_record(
        cur,
        {
            "schema": "honeylens-event/1",
            "timestamp": "2026-11-05T10:00:00+00:00",
            "peer_ip": VALIDATION_HOST,
            "peer_port": 40000,
            "protocol": "http",
            "dst_port": 80,
            "payload": "GET / HTTP/1.1",
            "source": "honeypot-http",
        },
    )

    assert _stored_class(cur) == sc.VALIDATION


def test_the_honeypot_ingest_stores_null_for_an_actor():
    from honeylens.ingest import honeypot

    cur = _Cursor()
    honeypot.process_record(
        cur,
        {
            "schema": "honeylens-event/1",
            "timestamp": "2026-11-05T10:00:00+00:00",
            "peer_ip": EXTERNAL_HOST,
            "peer_port": 40000,
            "protocol": "http",
            "dst_port": 80,
            "payload": "GET / HTTP/1.1",
            "source": "honeypot-http",
        },
    )

    assert _stored_class(cur) is None


def test_the_suricata_ingest_stores_the_class():
    from honeylens.ingest import suricata

    cur = _Cursor()
    suricata.process_alert(
        _Conn(cur),
        {
            "event_type": "alert",
            "timestamp": "2026-11-05T10:00:00.000000+0000",
            "src_ip": VALIDATION_HOST,
            "src_port": 40000,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 9026706,
                "signature": "HONEYLENS test signature",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
    )

    assert _stored_class(cur) == sc.VALIDATION


def test_the_fortigate_ingest_stores_the_class():
    from honeylens.ingest import fortigate

    cur = _Cursor()
    fortigate.insert_event(
        _Conn(cur),
        {
            "timestamp": "2026-11-05T10:00:00+00:00",
            "src_ip": INTERNAL_HOST,
            "src_port": 40000,
            "event_type": "LOGIN_ATTEMPT",
            "path": "/remote/login",
            "data": {},
        },
        "evt-fg-1",
    )

    assert _stored_class(cur) == sc.INTERNAL


def test_the_paloalto_ingest_stores_the_class():
    from honeylens.ingest import paloalto

    cur = _Cursor()
    paloalto.insert_event(
        _Conn(cur),
        {
            "event_type": "UNKNOWN_PATH",
            "timestamp": "2026-11-05T10:00:00+00:00",
            "src_ip": VALIDATION_HOST,
            "src_port": 40000,
            "path": "/zzz",
            "method": "GET",
            "data": {"path": "/zzz", "method": "GET"},
        },
        "evt-pa-1",
        "web",
    )

    assert _stored_class(cur) == sc.VALIDATION


def test_the_paloalto_raw_body_branch_stores_it_too():
    """Two insert sites in one function, and the one that carries the request bytes is the one
    a reader is most likely to hunt over."""
    from honeylens.ingest import paloalto

    cur = _Cursor()
    paloalto.insert_event(
        _Conn(cur),
        {
            "event_type": "UNKNOWN_PATH",
            "timestamp": "2026-11-05T10:00:00+00:00",
            "src_ip": VALIDATION_HOST,
            "src_port": 40000,
            "path": "/zzz",
            "method": "POST",
            "raw_body_b64": "QQA=",
            "data": {"path": "/zzz", "method": "POST"},
        },
        "evt-pa-2",
        "web",
    )

    sql, params = cur.only_event_insert()
    assert "full_payload" in sql, "expected the raw-body branch"
    assert params[-1] == sc.VALIDATION


# ---------------------------------------------------------------------------
# An un-migrated host still stores the event
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    ["honeypot", "suricata", "fortigate", "paloalto"],
)
def test_without_the_column_the_event_is_still_inserted(call):
    """`prod`'s schema is older than the rest of the fleet's. An INSERT naming a column that
    does not exist fails the whole statement, and on this path that means the event is gone —
    so each site falls back to the pre-0013 statement instead."""
    cur = _Cursor(has_source_class=False)
    event = {
        "schema": "honeylens-event/1",
        "timestamp": "2026-11-05T10:00:00+00:00",
        "peer_ip": VALIDATION_HOST,
        "peer_port": 40000,
        "src_ip": VALIDATION_HOST,
        "src_port": 40000,
        "protocol": "http",
        "dst_port": 80,
        "payload": "GET / HTTP/1.1",
        "source": "honeypot-http",
        "event_type": "UNKNOWN_PATH",
        "path": "/zzz",
        "method": "GET",
        "data": {"path": "/zzz", "method": "GET"},
    }
    if call == "honeypot":
        from honeylens.ingest import honeypot

        honeypot.process_record(cur, event)
    elif call == "suricata":
        from honeylens.ingest import suricata

        suricata.process_alert(
            _Conn(cur),
            {
                "event_type": "alert",
                "timestamp": "2026-11-05T10:00:00.000000+0000",
                "src_ip": VALIDATION_HOST,
                "src_port": 40000,
                "dest_ip": "10.0.0.1",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {
                    "signature_id": 9026706,
                    "signature": "HONEYLENS test signature",
                    "category": "Attempted Information Leak",
                    "severity": 2,
                },
            },
        )
    elif call == "fortigate":
        from honeylens.ingest import fortigate

        fortigate.insert_event(_Conn(cur), event, "evt-fg-2")
    else:
        from honeylens.ingest import paloalto

        paloalto.insert_event(_Conn(cur), event, "evt-pa-3", "web")

    sql, params = cur.only_event_insert()
    assert "source_class" not in sql
    assert params is not None
    assert sc.VALIDATION not in params, "the value must go with the column, not trail behind it"
