"""Unit guards for the NetScaler-tag repair tool (todo C1).

The tool writes to the database and was written in response to the 2026-10-04 data-loss
incident, so it must not drift untested. These tests mock the DB connection — no real
database — and pin the request reconstruction plus both ``main()`` branches (dry-run reports
without writing; apply re-derives the decoy tags and inserts them).
"""

from __future__ import annotations

import psycopg2.extras

from honeylens.tools import repair_netscaler_tags as r

# --- _request_from_meta: pure reconstruction -------------------------------------------


def test_request_from_meta_rebuilds_the_request():
    meta = {"method": "GET", "path": "/vpns/cfg/smb.conf", "query": "a=1", "headers": {"H": "v"}}
    method, path_qs, headers, body = r._request_from_meta(meta)
    assert method == "GET"
    assert path_qs == "/vpns/cfg/smb.conf?a=1"  # query folded back in
    assert headers == {"H": "v"}
    assert body == b""


def test_request_from_meta_rejects_unusable_metadata():
    assert r._request_from_meta("not a dict") is None
    assert r._request_from_meta({}) is None  # no method/path
    assert r._request_from_meta({"method": "GET"}) is None  # no path
    # a non-dict headers / str body are tolerated, not fatal
    _m, _p, h, b = r._request_from_meta(
        {"method": "POST", "path": "/x", "headers": 3, "body_sample": "ab"}
    )
    assert h == {} and b == b"ab"


# --- DB doubles ------------------------------------------------------------------------


class _Cur:
    def __init__(self, fetchall=None):
        self._fetchall = fetchall or []
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._fetchall


class _Conn:
    def __init__(self, fetchall=None):
        self.cur = _Cur(fetchall)
        self.commits = 0

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1


# A stored NetScaler event whose request re-derives a decoy tag: smb.conf is a traversal
# artefact -> ns-path-traversal / CVE-2019-19781.
_EVENTS = [("evt-1", {"method": "GET", "path": "/vpns/cfg/smb.conf", "query": "", "headers": {}})]


def test_main_dry_run_reports_without_writing(monkeypatch):
    conn = _Conn(fetchall=_EVENTS)
    monkeypatch.setattr(r, "get_connection", lambda: conn)
    monkeypatch.setattr(r, "put_connection", lambda c: None)
    monkeypatch.setattr("sys.argv", ["repair", "--dry-run"])
    # execute_batch / rebuild must NOT be called in a dry run
    called = {"batch": 0, "rebuild": 0}
    monkeypatch.setattr(
        psycopg2.extras,
        "execute_batch",
        lambda *a, **k: called.__setitem__("batch", called["batch"] + 1),
    )
    monkeypatch.setattr(
        r, "rebuild_attack_types", lambda ids: called.__setitem__("rebuild", called["rebuild"] + 1)
    )
    assert r.main() == 0
    assert called == {"batch": 0, "rebuild": 0}


def test_main_apply_reinserts_the_decoy_tags(monkeypatch):
    conns = [_Conn(fetchall=_EVENTS), _Conn()]  # 1st = SELECT, 2nd = INSERT
    monkeypatch.setattr(r, "get_connection", lambda: conns.pop(0))
    monkeypatch.setattr(r, "put_connection", lambda c: None)
    monkeypatch.setattr("sys.argv", ["repair"])
    captured = {}
    monkeypatch.setattr(
        psycopg2.extras,
        "execute_batch",
        lambda cur, sql, rows, page_size=1000: captured.update(rows=rows, sql=sql),
    )
    rebuilt = {}
    monkeypatch.setattr(r, "rebuild_attack_types", lambda ids: rebuilt.update(ids=list(ids)))
    assert r.main() == 0
    assert captured["rows"], "the re-derived ns-* rows were inserted"
    row = captured["rows"][0]
    assert row[0] == "evt-1" and row[1] == "ns-path-traversal" and row[2] == "CVE-2019-19781"
    assert rebuilt["ids"] == ["evt-1"], "the touched event's summary was rebuilt"
