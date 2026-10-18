"""The honeypot read API hands a key holder exactly one decoy's traffic, and nothing of ours.

These are the guards for the defects the first version of this feature shipped with. Each
test names the property, not the implementation, because the property is what a key holder
is promised:

* a key scoped to one decoy cannot read another decoy's events (the first version offered
  `protocol` as an alternative to `source`, and because the vendor and LLM decoys list
  `http` and `https` among their protocols, one key read every HTTP event on the sensor --
  measured on a live sensor: an `llm` key saw 210,194 events where 0 were the LLM decoy's);
* our own traffic never leaves this API;
* the key travels in a header, never in a query string this service writes to its log;
* every query is bounded, so no caller can pin a database backend.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from honeylens.auth import api_key_manager
from honeylens.auth.api_key_manager import (
    VALID_HONEYPOTS,
    HoneypotApiKey,
    honeypot_scope_sql,
)
from honeylens.routes import honeypot_api
from honeylens.routes.honeypot_api import _extract_raw_api_key, _query_honeypot_events

_DECOY_SCOPES = sorted(VALID_HONEYPOTS - {"*"})


class _RecordingCursor:
    """A cursor that remembers every statement, so a test can read the SQL that was built."""

    def __init__(self) -> None:
        self.statements: list[tuple[str, Any]] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.statements.append((sql, params))

    def fetchall(self) -> list[Any]:
        return []

    def fetchone(self) -> tuple[int]:
        return (0,)

    @property
    def sql(self) -> str:
        return "\n".join(s for s, _ in self.statements)


def _run_query(**kwargs: Any) -> tuple[dict[str, Any], _RecordingCursor]:
    cur = _RecordingCursor()
    ctx = MagicMock()
    ctx.__enter__.return_value = cur
    # `external_only` probes the live schema; here it stands in for a migrated sensor.
    with (
        patch("honeylens.routes.honeypot_api.db_cursor", return_value=ctx),
        patch(
            "honeylens.routes.honeypot_api.external_only",
            return_value="se.source_class IS NULL",
        ),
    ):
        result = _query_honeypot_events(**kwargs)
    return result, cur


class TestOneKeyReadsOneDecoy:
    @pytest.mark.parametrize("scope", _DECOY_SCOPES)
    def test_protocol_is_never_an_alternative_to_the_source(self, scope: str) -> None:
        """`protocol` may only narrow the monolith's rows, never stand in for `source`."""
        sql, _params = honeypot_scope_sql(scope)
        if "se.protocol" not in sql:
            return
        # The only legal shape: source equality AND, within the monolith's source alone, a
        # protocol narrowing. Never `source = ... OR protocol = ...`.
        assert sql.startswith("(se.source = ANY(%s) AND ("), (
            f"scope {scope!r} resolves events through a bare protocol: {sql}"
        )
        assert "se.source <> 'honeypotng' OR LOWER(se.protocol)" in sql

    @pytest.mark.parametrize("scope", ["fortigate", "paloalto", "paloalto-ssh", "llm", "netscaler"])
    def test_a_web_protocol_never_buys_another_decoys_events(self, scope: str) -> None:
        """This is the measured regression: http/https must not appear anywhere in the scope."""
        _sql, params = honeypot_scope_sql(scope)
        for values in params:
            assert "http" not in values
            assert "https" not in values

    def test_the_monolith_web_traffic_belongs_to_the_monolith_scope_alone(self) -> None:
        sql_monolith, params_monolith = honeypot_scope_sql("honeypot")
        assert ["http", "https"] in params_monolith
        assert "se.source <> 'honeypotng'" in sql_monolith

        # ...and the standalone `http` decoy must not claim the monolith's web rows.
        sql_http, _params_http = honeypot_scope_sql("http")
        assert "honeypotng" not in sql_http

    def test_a_decoy_the_monolith_serves_is_reachable_by_its_protocol(self) -> None:
        """`wago` only ever appears as a protocol under `honeypotng`, never as a source."""
        _sql, params = honeypot_scope_sql("wago")
        assert "honeypotng" in params[0]
        assert ["wago"] in params

    @pytest.mark.parametrize("scope", _DECOY_SCOPES)
    def test_scope_values_are_exact_not_patterns(self, scope: str) -> None:
        """Equality against a known value, so nothing the caller sends can widen the scope.

        `honeypot_ssh` and friends do contain an underscore; it is not a wildcard here
        because the predicate never builds a LIKE pattern.
        """
        sql, params = honeypot_scope_sql(scope)
        assert "LIKE" not in sql.upper()
        assert "se.source = ANY(%s)" in sql
        for values in params:
            for value in values:
                assert "%" not in value

    @pytest.mark.parametrize("scope", _DECOY_SCOPES)
    def test_the_scope_stays_on_one_indexed_column(self, scope: str) -> None:
        """An OR across source, metadata and protocol left the planner no index to use, so
        it walked the timestamp index and filtered. That is cheap for a busy decoy and
        ruinous for a quiet one: a page for a decoy with 3 events in the window took 30.34 s
        against 0.002 s for this form, because it had to walk the whole window to find them.
        """
        sql, _params = honeypot_scope_sql(scope)
        assert "metadata" not in sql
        assert sql.count("se.source = ANY(%s)") == 1
        # protocol may appear only as the monolith narrowing, never as its own branch
        assert " OR se.protocol" not in sql
        assert "se.protocol = ANY" not in sql

    def test_the_all_scope_is_the_decoys_and_not_the_whole_event_store(self) -> None:
        _sql, params = honeypot_scope_sql("*")
        sources = params[0]
        assert "suricata" not in sources, "the read API is not a Suricata feed"
        assert "honeypotng" in sources
        assert "honeypot-vnc" in sources


class TestOurOwnTrafficStaysHere:
    def test_every_query_asks_only_for_a_real_actors_rows(self) -> None:
        """`source_class IS NULL` is migration 0013's 'a real actor'; anything else is ours."""
        _result, cur = _run_query(effective_honeypot="fortigate")
        assert "se.source_class IS NULL" in cur.sql

    def test_the_filter_survives_every_endpoints_shape(self) -> None:
        for kwargs in (
            {"effective_honeypot": "*"},
            {"effective_honeypot": "ssh", "ip": "185.220.101.1"},
            {"effective_honeypot": "ssh", "ip": "185.220.101.0/24"},
        ):
            _result, cur = _run_query(**kwargs)
            assert "se.source_class IS NULL" in cur.sql


class TestTheQueryIsBounded:
    def test_a_lower_time_bound_is_always_present(self) -> None:
        result, cur = _run_query(effective_honeypot="ssh")
        assert "se.timestamp >= %s" in cur.sql
        assert result["filters"]["since"] is not None

    def test_a_statement_timeout_is_set_on_the_connection(self) -> None:
        _result, cur = _run_query(effective_honeypot="ssh")
        assert any("statement_timeout" in sql for sql, _ in cur.statements)

    def test_a_deep_page_is_refused_rather_than_scanned(self) -> None:
        with pytest.raises(HTTPException) as exc:
            _run_query(effective_honeypot="ssh", limit=1000, page=10_000)
        assert exc.value.status_code == 400

    def test_the_page_is_fetched_before_the_count(self) -> None:
        """A count too expensive to finish costs the caller the total, not the events."""
        _result, cur = _run_query(effective_honeypot="ssh")
        data_at = next(i for i, (sql, _) in enumerate(cur.statements) if "ORDER BY" in sql)
        count_at = next(i for i, (sql, _) in enumerate(cur.statements) if "COUNT(*)" in sql)
        assert data_at < count_at


class TestFiltersAskByLabelNotBySubstring:
    @patch(
        "honeylens.routes.honeypot_api._label_vocabulary",
        side_effect=lambda col, scope: (
            ("FORTI_CVE",) if col == "attack_type" else ("forti_cve_2024_21762",)
        ),
    )
    def test_an_attack_term_resolves_to_exact_labels(self, _vocab: MagicMock) -> None:
        result, cur = _run_query(effective_honeypot="fortigate", attack="FORTI_CVE")
        assert "ap.attack_type = ANY(%s)" in cur.sql
        assert "ILIKE" not in cur.sql.upper()
        assert "FORTI_CVE" in result["matched_labels"]["attack"]

    @patch(
        "honeylens.routes.honeypot_api._label_vocabulary", side_effect=lambda col, scope: ("SQLI",)
    )
    def test_a_wildcard_is_not_a_wildcard(self, _vocab: MagicMock) -> None:
        """`attack=%` used to be spliced into an ILIKE pattern and matched every event."""
        with pytest.raises(HTTPException) as exc:
            _run_query(effective_honeypot="ssh", attack="%")
        assert exc.value.status_code == 400
        assert "no searchable characters" in str(exc.value.detail)

    @patch(
        "honeylens.routes.honeypot_api._label_vocabulary",
        side_effect=lambda col, scope: () if col == "attack_type" else ("forti_cve_2024_21762",),
    )
    def test_a_cve_search_does_not_read_bodies(self, _vocab: MagicMock) -> None:
        """Searching `payload` and `metadata::text` did not finish inside 45 s on a live store."""
        _result, cur = _run_query(effective_honeypot="fortigate", cve="CVE-2024-21762")
        assert "se.payload ILIKE" not in cur.sql
        assert "metadata::text" not in cur.sql
        assert "ap.rule_name = ANY(%s)" in cur.sql

    @patch("honeylens.routes.honeypot_api._label_vocabulary", side_effect=lambda col, scope: ())
    def test_a_term_this_sensor_never_saw_matches_nothing_and_says_so(
        self, _vocab: MagicMock
    ) -> None:
        """A CVE this sensor has not seen yet is an empty page with a warning, never a 400
        the caller can never clear -- and never a filter quietly dropped, which would have
        widened the query to the whole scope."""
        result, cur = _run_query(effective_honeypot="ssh", attack="NOTHING_LIKE_THIS")
        assert result["events"] == []
        assert result["matched_labels"]["attack"] == []
        assert len(result["warnings"]) == 1
        assert "/api/v1/honeypot/labels" in result["warnings"][0]
        # the clause is still in the query, matching nothing
        assert "ap.attack_type = ANY(%s)" in cur.sql

    @patch("honeylens.routes.honeypot_api._label_vocabulary", side_effect=lambda col, scope: ())
    def test_an_unmatched_filter_is_never_dropped_from_the_query(self, _vocab: MagicMock) -> None:
        _result, cur = _run_query(effective_honeypot="ssh", cve="CVE-2024-21762")
        data_sql = next(sql for sql, _ in cur.statements if "ORDER BY" in sql)
        assert data_sql.count("FROM attack_patterns ap") == 1


class TestTheKeyTravelsInAHeader:
    def test_the_key_is_not_read_from_the_query_string(self) -> None:
        request = MagicMock()
        request.headers = {}
        request.query_params = {"api_key": "hlk_leaked_in_the_access_log"}
        assert _extract_raw_api_key(request) is None

    def test_the_key_is_read_from_the_header(self) -> None:
        request = MagicMock()
        request.headers = {"X-API-Key": "  hlk_token  "}
        assert _extract_raw_api_key(request) == "hlk_token"

    def test_neither_reader_mentions_the_query_parameter(self) -> None:
        """The middleware has its own copy of this logic; both must stay header-only."""
        from honeylens import api as api_module

        extractor = inspect.getsource(_extract_raw_api_key)
        assert 'query_params.get("api_key")' not in extractor

        middleware = inspect.getsource(api_module.AuthMiddleware.dispatch)
        assert 'query_params.get("api_key")' not in middleware


class TestTheSchemaComesFromTheMigration:
    def test_the_manager_does_not_create_its_own_table(self) -> None:
        """A CREATE TABLE per request was a second copy of the schema, already drifted from
        0014, and it would have silently created the table in the 0.9 database when
        HONEYLENS_ENV_FILE was unset."""
        source = inspect.getsource(api_key_manager)
        assert "CREATE TABLE IF NOT EXISTS honeypot_api_keys" not in source

    def test_the_migration_is_asserted_instead(self) -> None:
        source = inspect.getsource(api_key_manager.assert_api_keys_table)
        assert "to_regclass" in source
        assert "0014_honeypot_api_keys.sql" in source


class TestKeyScopeStillGatesTheRequest:
    def _key(self, honeypot: str) -> HoneypotApiKey:
        now = datetime.now(UTC)
        return HoneypotApiKey(
            id=1,
            key_name="k",
            honeypot=honeypot,
            basic_username="apiaccess1",
            api_key_prefix="hlk_x...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now,
            expires_at=now + timedelta(days=90),
        )

    def test_a_scoped_key_cannot_name_another_decoy(self) -> None:
        with pytest.raises(HTTPException) as exc:
            honeypot_api._resolve_effective_honeypot(self._key("ssh"), "fortigate")
        assert exc.value.status_code == 403

    def test_a_scoped_key_defaults_to_its_own_scope(self) -> None:
        assert honeypot_api._resolve_effective_honeypot(self._key("ssh"), None) == "ssh"


class TestOwnTrafficIsExcludedTwice:
    """`source_class IS NULL` alone fails open on rows written before migration 0013.

    On those rows NULL means "not computed", not "a real actor". For a reader whose output
    leaves this project that is the expensive direction, so the configured own, validation
    and internal networks are excluded at query time as well.
    """

    def test_the_configured_networks_are_excluded_in_sql(self) -> None:
        _result, cur = _run_query(effective_honeypot="fortigate")
        assert "se.source_class IS NULL" in cur.sql
        assert "se.src_ip <<= ANY(%s::inet[])" in cur.sql

    def test_a_row_with_no_address_has_nothing_to_leak_and_stays_visible(self) -> None:
        _result, cur = _run_query(effective_honeypot="fortigate")
        assert "se.src_ip IS NULL OR NOT" in cur.sql

    def test_the_networks_come_from_the_ingests_own_authority(self) -> None:
        from honeylens.intelligence import source_class

        networks = source_class.excluded_networks()
        assert "10.0.0.0/8" in networks
        assert "127.0.0.0/8" in networks
        _result, cur = _run_query(effective_honeypot="fortigate")
        passed = [p for _sql, params in cur.statements if params for p in params]
        assert any(isinstance(p, list) and "10.0.0.0/8" in p for p in passed)

    @patch("honeylens.routes.honeypot_api.excluded_networks", return_value=())
    def test_an_unconfigured_sensor_still_filters_on_the_stored_class(
        self, _nets: MagicMock
    ) -> None:
        _result, cur = _run_query(effective_honeypot="fortigate")
        assert "se.source_class IS NULL" in cur.sql
        assert "<<= ANY" not in cur.sql


class TestTheLabelVocabularyIsScopedToo:
    """Sensor-wide, the vocabulary told a key holder which verdicts every other decoy had
    produced -- not the events, but their existence, which is the disclosure the scope
    predicate exists to prevent. It is also what `attack` and `cve` resolve against, so an
    unscoped vocabulary leaked the same thing back through `matched_labels`."""

    def test_the_vocabulary_query_is_joined_under_the_scope(self) -> None:
        cur = _RecordingCursor()
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        honeypot_api.reset_label_cache()
        with (
            patch("honeylens.routes.honeypot_api.db_cursor", return_value=ctx),
            patch(
                "honeylens.routes.honeypot_api.external_only",
                return_value="se.source_class IS NULL",
            ),
        ):
            honeypot_api._label_vocabulary("attack_type", "fortigate")
        honeypot_api.reset_label_cache()
        assert "JOIN sensor_events se" in cur.sql
        assert "se.source = ANY(%s)" in cur.sql
        assert "se.source_class IS NULL" in cur.sql
        assert "se.timestamp >= %s" in cur.sql

    def test_the_cache_does_not_carry_one_scope_into_another(self) -> None:
        honeypot_api.reset_label_cache()
        calls: list[str] = []

        def fake(column: str, scope: str) -> tuple[str, ...]:
            calls.append(scope)
            return ("X",)

        with patch("honeylens.routes.honeypot_api._label_vocabulary", side_effect=fake):
            honeypot_api.resolve_labels("X", "fortigate")
            honeypot_api.resolve_labels("X", "ssh")
        assert "fortigate" in calls and "ssh" in calls

    @patch("honeylens.routes.honeypot_api._label_vocabulary", side_effect=lambda col, scope: ())
    def test_a_filter_resolves_within_the_keys_scope(self, vocab: MagicMock) -> None:
        _run_query(effective_honeypot="fortigate", attack="ANYTHING")
        for call in vocab.call_args_list:
            assert call.args[1] == "fortigate"

    def test_the_labels_endpoint_reports_the_scope_it_answered_for(self) -> None:
        request = MagicMock()
        request.state.honeypot_api_key = None
        request.state.user = object()
        request.state.is_admin = False
        request.headers = {}
        with patch(
            "honeylens.routes.honeypot_api._label_vocabulary",
            side_effect=lambda col, scope: ("A",),
        ):
            result = honeypot_api.list_honeypot_labels(request)
        assert result["honeypot_scope"] == "*"
        assert result["attack_types"] == ["A"]


class TestTheTotalIsHonestAboutItself:
    def test_a_total_below_the_cap_is_exact(self) -> None:
        result, _cur = _run_query(effective_honeypot="ssh")
        assert result["total"] == 0
        assert result["total_exact"] is True

    def test_a_total_at_the_cap_says_it_is_not_exact(self) -> None:
        """An exact count for a `*` key took 10.54 s against 0.004 s for the page; through
        the capped subquery it is 0.106 s, and the caller is told the number is a floor."""

        class _AtCap(_RecordingCursor):
            def fetchone(self) -> tuple[int]:
                return (honeypot_api._COUNT_CAP,)

        cur = _AtCap()
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with (
            patch("honeylens.routes.honeypot_api.db_cursor", return_value=ctx),
            patch(
                "honeylens.routes.honeypot_api.external_only",
                return_value="se.source_class IS NULL",
            ),
        ):
            result = _query_honeypot_events(effective_honeypot="*")
        assert result["total"] == honeypot_api._COUNT_CAP
        assert result["total_exact"] is False

    def test_the_count_is_capped_in_sql(self) -> None:
        _result, cur = _run_query(effective_honeypot="*")
        count_sql = next(sql for sql, _ in cur.statements if "COUNT(*)" in sql)
        assert f"LIMIT {honeypot_api._COUNT_CAP}" in count_sql

    def test_a_timed_out_count_costs_the_total_and_not_the_events(self) -> None:
        from psycopg2.errors import QueryCanceled

        class _CountTimesOut(_RecordingCursor):
            def execute(self, sql: str, params: Any = None) -> None:
                super().execute(sql, params)
                if "COUNT(*)" in sql:
                    raise QueryCanceled("canceling statement due to statement timeout")

            def fetchall(self) -> list[Any]:
                return [
                    (
                        "evt_1",
                        datetime.now(UTC),
                        "203.0.113.4/32",
                        1234,
                        None,
                        443,
                        "https",
                        "fortigate-honeypot",
                        "FORTI_CVE",
                        "GET /",
                        {},
                    )
                ]

        cur = _CountTimesOut()
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with (
            patch("honeylens.routes.honeypot_api.db_cursor", return_value=ctx),
            patch(
                "honeylens.routes.honeypot_api.external_only",
                return_value="se.source_class IS NULL",
            ),
        ):
            result = _query_honeypot_events(effective_honeypot="fortigate")
        assert result["count"] == 1
        assert result["events"][0]["src_ip"] == "203.0.113.4"
        assert result["total"] is None
        assert result["total_exact"] is False


class TestAnUnmigratedSensorRefusesToAnswer:
    def test_without_source_class_the_api_serves_nothing(self) -> None:
        """The dashboards degrade to TRUE on an un-migrated sensor so the panels keep
        working. Showing our own traffic to the operator is a cosmetic defect; handing it to
        a key holder is not, so here the request is refused instead."""
        cur = _RecordingCursor()
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with (
            patch("honeylens.routes.honeypot_api.db_cursor", return_value=ctx),
            patch("honeylens.routes.honeypot_api.external_only", return_value="TRUE"),
            pytest.raises(HTTPException) as exc,
        ):
            _query_honeypot_events(effective_honeypot="fortigate")
        assert exc.value.status_code == 503
        assert "0013_sensor_events_source_class.sql" in str(exc.value.detail)

    def test_the_provenance_predicate_is_the_dashboards_own(self) -> None:
        """Shared on purpose: this API must not drift from what the dashboards call
        "from outside"."""
        from honeylens.routes import _helpers

        source = inspect.getsource(honeypot_api._own_traffic_exclusion)
        assert 'external_only("se")' in source
        assert _helpers.EXTERNAL_ONLY == "source_class IS NULL"


class TestEveryKeyIsAudited:
    """`admin_audit_log.admin_user_id` is nullable so an action with no operator account
    behind it is still recorded. Passing a placeholder `0` instead violated the foreign key
    to `users`, and because `log_admin_action` swallows its own errors, the entry was lost
    with only a line in the journal. Measured on a live sensor: creating and revoking a key
    programmatically produced two "Failed to log admin action" warnings and no audit rows.
    """

    def test_no_placeholder_admin_id_is_ever_passed(self) -> None:
        source = inspect.getsource(api_key_manager)
        assert "or 0," not in source
        assert "admin_user_id=created_by," in source
        assert "admin_user_id=revoked_by," in source

    def test_the_audit_signature_admits_no_operator(self) -> None:
        from honeylens.auth.auth import log_admin_action

        annotation = inspect.signature(log_admin_action).parameters["admin_user_id"].annotation
        assert annotation == "int | None"

    @patch("honeylens.auth.api_key_manager.log_admin_action")
    @patch("honeylens.auth.api_key_manager.assert_api_keys_table")
    @patch("honeylens.auth.api_key_manager._insert_api_key")
    def test_a_programmatic_creation_audits_with_a_null_actor(
        self, insert: MagicMock, _assert: MagicMock, audit: MagicMock
    ) -> None:
        now = datetime.now(UTC)
        insert.return_value = ("apiaccess1", 1, now, now + timedelta(days=90))
        created, err = api_key_manager.create_api_key(honeypot="ssh", created_by=None)
        assert err is None and created is not None
        assert audit.call_args.kwargs["admin_user_id"] is None
