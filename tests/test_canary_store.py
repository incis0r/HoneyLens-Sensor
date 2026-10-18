"""Durable canary registry + cross-process correlation (Idea 52).

The gap these cover: the LLM honeypot issues a canary, the callback arrives on the
K8s honeypot's port in a different process, and in-memory correlation can never see
it. The registry is what ties the two together.
"""

from datetime import UTC, datetime, timedelta
from typing import ClassVar

import honeylens.ingest.honeypot as ih
from honeylens.intelligence import canary_store as cs


class FakeCursor:
    """Minimal cursor: records SQL, replays queued results, can be told to fail."""

    def __init__(self, results=None, fail=False):
        self.sql = []
        self.params = []
        self._results = list(results or [])
        self._last = None
        self.rowcount = 0
        self.fail = fail

    def execute(self, sql, params=None):
        if self.fail:
            raise RuntimeError("no such table")
        self.sql.append(" ".join(sql.split()))
        self.params.append(params)
        self._last = self._results.pop(0) if self._results else None
        self.rowcount = 1 if self._last else 0

    def fetchone(self):
        return self._last


NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)


# --- store -----------------------------------------------------------------


def test_record_issue_is_idempotent_sql():
    cur = FakeCursor(results=[("x",)])
    assert cs.record_issue(cur, "abc123", origin_protocol="llm") is True
    assert "ON CONFLICT (nonce) DO NOTHING" in cur.sql[0]


def test_record_issue_ignores_empty_nonce():
    cur = FakeCursor()
    assert cs.record_issue(cur, "") is False
    assert cur.sql == []


def test_store_never_raises_into_the_caller():
    """A honeypot must keep answering the attacker even if the DB is unreachable."""
    cur = FakeCursor(fail=True)
    assert cs.record_issue(cur, "abc123") is False
    assert cs.record_callback(cur, "abc123") is None


def test_record_callback_returns_issuing_context():
    cur = FakeCursor(results=[("llm", "/v1/chat/completions", "9.9.9.9", NOW)])
    origin = cs.record_callback(cur, "abc123", src_ip="8.8.8.8")
    assert origin["origin_protocol"] == "llm"
    assert origin["origin_src_ip"] == "9.9.9.9"
    assert "callback_at IS NULL" in cur.sql[0]  # first answer wins


def test_record_callback_falls_back_to_lookup_when_already_answered():
    cur = FakeCursor(results=[None, ("k8s", "/api/v1/secrets/x", "1.2.3.4", NOW)])
    origin = cs.record_callback(cur, "abc123")
    assert origin["origin_protocol"] == "k8s"
    assert len(cur.sql) == 2  # UPDATE, then SELECT


def test_record_callback_unknown_nonce():
    assert cs.record_callback(FakeCursor(results=[None, None]), "abc123") is None


def test_callback_delay():
    assert cs.callback_delay_ms(NOW, NOW + timedelta(milliseconds=250)) == 250
    assert cs.callback_delay_ms(None, NOW) is None
    assert cs.callback_delay_ms(NOW, "not-a-time") is None


# --- ingest correlation ----------------------------------------------------


def test_ingest_registers_an_issued_canary():
    cur = FakeCursor(results=[("x",)])
    data = {
        "canary_nonce": "n1",
        "action": "secret_read",
        "protocol": "https",
        "path": "/api/v1/namespaces/prod/secrets/cicd",
        "peer_ip": "8.8.8.8",
    }
    ih._canary_register(cur, data, "evt-1", NOW.isoformat())
    assert "INSERT INTO ai_prompt_canaries" in cur.sql[0]


def test_ingest_correlates_a_cross_process_callback():
    """The K8s honeypot cannot know an LLM-issued canary — the registry supplies it."""
    cur = FakeCursor(results=[("llm", "/v1/chat/completions", "9.9.9.9", NOW)])
    data = {
        "canary_nonce": "n1",
        "action": "ai_canary_callback",
        "peer_ip": "8.8.8.8",
        "user_agent": "agent/1.0",
    }
    ih._canary_register(cur, data, "evt-2", (NOW + timedelta(seconds=2)).isoformat())
    assert data["canary_correlated"] is True
    assert data["origin_protocol"] == "llm"
    assert data["origin_path"] == "/v1/chat/completions"
    assert data["origin_src_ip"] == "9.9.9.9"
    assert data["callback_delay_ms"] == 2000


def test_ingest_keeps_the_honeypots_own_correlation():
    """Same-process correlation already filled these in; do not overwrite them."""
    cur = FakeCursor(results=[("llm", "/other", "9.9.9.9", NOW)])
    data = {
        "canary_nonce": "n1",
        "action": "ai_canary_callback",
        "origin_path": "/api/v1/secrets/real",
        "callback_delay_ms": 12,
    }
    ih._canary_register(cur, data, "evt-3", NOW.isoformat())
    assert data["origin_path"] == "/api/v1/secrets/real"
    assert data["callback_delay_ms"] == 12


def test_ingest_leaves_uncorrelatable_callback_alone():
    cur = FakeCursor(results=[None, None])
    data = {"canary_nonce": "n1", "action": "ai_canary_callback"}
    ih._canary_register(cur, data, "evt-4", NOW.isoformat())
    assert "canary_correlated" not in data


def test_ingest_survives_a_missing_registry(monkeypatch):
    monkeypatch.setattr(ih, "canary_store", None)
    data = {"canary_nonce": "n1", "action": "ai_canary_callback"}
    ih._canary_register(FakeCursor(fail=True), data, "evt-5", NOW.isoformat())
    assert "canary_correlated" not in data


# --- /canary/stats registry path -------------------------------------------


def test_stats_from_registry_shapes_the_response():
    """The registry path exists because deriving these numbers from events joins
    attack_patterns to sensor_events, which times out on a busy sensor."""
    import honeylens.routes.canary as rc

    class Req:
        headers: ClassVar[dict] = {}
        query_params: ClassVar[dict] = {}

    rows = [
        (NOW, "8.8.8.8", "9.9.9.9", "llm", "/v1/chat/completions", "agent/1.0", 496.0),
        (NOW, "8.8.8.8", None, None, None, None, None),
    ]
    out = rc._from_registry(Req(), "30 days", {"issued": 5, "answered": 2, "correlated": 1}, rows)
    assert out["source"] == "registry"
    assert (out["issued"], out["callbacks"], out["correlated"]) == (5, 2, 1)
    assert out["avg_latency_ms"] == 496  # None delay ignored
    assert out["recent"][0]["origin_path"] == "llm /v1/chat/completions"
    assert out["recent"][0]["origin_src_ip"] == "9.9.9.9"
    assert out["recent"][1]["correlated"] is False  # nothing to tie it to
    assert out["top_agents"][0]["user_agent"] in ("agent/1.0", "?")


def test_stats_render_returns_json_for_api_callers(monkeypatch):
    import honeylens.routes.canary as rc

    monkeypatch.setattr(rc, "wants_html", lambda r: False)
    assert rc._render(object(), {"x": 1}) == {"x": 1}
