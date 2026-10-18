"""`OPEN_PROXY_RELAY`: someone asked this sensor to forward a connection.

The family these pin was the largest unlabelled one in the fleet when it was measured --
12,197 CONNECT requests from 207 sources in 30 days on the public sensor, 11,622 of them
(95%) with no verdict, and no rule for the method anywhere in the rules package.

Every case below is a payload shape taken from the live store, not an invention, because the
decoys do not agree on one shape and a rule written against only the common one would have
missed 1,188 rows.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import ATTACK_TYPE_SEVERITY, classify_event_row
from honeylens.classification.mitre_mapping import ATTACK_TO_MITRE
from honeylens.classification.scoring import get_severity

VERDICT = "OPEN_PROXY_RELAY"


def rules_for(payload: str, metadata: dict | None = None) -> list[str]:
    """The `OPEN_PROXY_RELAY` rule names this payload fires, sorted."""
    hits = classify_event_row(payload, "http", metadata or {})
    return sorted(name for atype, name, _snippet in hits if atype == VERDICT)


class TestEveryShapeTheDecoysWrite:
    def test_the_monolith_writes_a_request_line(self) -> None:
        assert rules_for(
            "CONNECT tls.bunnyfeet.baby:443 User-Agent: Mozilla/5.0",
            {"path": "tls.bunnyfeet.baby:443", "method": "CONNECT"},
        ) == ["open_proxy_connect_request"]

    def test_honeypot_http_writes_a_json_summary(self) -> None:
        """1,188 of the measured rows look like this. `metadata["method"]` is not a usable
        target -- the classifier's metadata sweep does not read that key, and each rule is
        matched against each target separately, so no rule can require method AND path."""
        assert rules_for(
            '{"phase": "request", "method": "CONNECT", "path": "51.195.40.238:7000", "body_len": 0}'
        ) == ["open_proxy_connect_json"]

    def test_a_doubled_port_still_matches(self) -> None:
        """150 rows arrive as `host:443:443`. The authority pattern is not anchored at the
        end, so the malformed tail costs nothing."""
        assert rules_for("CONNECT c1.dstatbot.win:443:443") == ["open_proxy_connect_request"]

    def test_connect_to_an_absolute_uri_still_matches(self) -> None:
        """`CONNECT https://c1.dstatbots.win/dstat` — an absolute URI where an authority
        belongs. Found by the backfill reporting 199 of 201 candidates matched on one sensor;
        chasing the other two turned up this shape, from the same actor family as the
        `dstatbot.win` destinations elsewhere."""
        assert rules_for("CONNECT https://c1.dstatbots.win/dstat") == [
            "open_proxy_connect_no_authority"
        ]

    def test_connect_with_no_authority_has_its_own_rule(self) -> None:
        """`CONNECT /` names no destination: nine requests from nine separate sources, the
        shape of a one-shot survey. It needs its own rule because the authority pattern
        cannot match it, and loosening that one to `\\S+` would fire on prose."""
        assert rules_for("CONNECT / User-Agent: Mozilla/5.0 zgrab/0.x") == [
            "open_proxy_connect_no_authority"
        ]

    @pytest.mark.parametrize(
        "payload",
        [
            "(CONNECT_DATA=(COMMAND=VERSION))",  # Oracle TNS, see rules/database.py
            "please CONNECT to the database server now",
            "Connection: keep-alive",
            "",
        ],
    )
    def test_the_word_alone_is_not_a_proxy_request(self, payload: str) -> None:
        assert rules_for(payload) == []


class TestTheSurveysAreNotTheCampaign:
    """89 of the 12,197 were reachability checks: Shadowserver's survey, a proxy-list
    harvester, and what-is-my-IP endpoints. One CONNECT cannot establish intent, so the
    verdict is the same and the distinction lives in the rule name -- which is also why
    migration 0015 indexed `attack_patterns.rule_name`."""

    @pytest.mark.parametrize(
        "payload",
        [
            "CONNECT www.shadowserver.org:443 User-Agent: Mozilla/5.0 zgrab/0.x",
            "CONNECT api.ipify.org:443 User-Agent: Mozilla/5.0 (+https://best-proxies.ru/faq/#from)",
            "CONNECT ip.ipcount.org:443:443",
            "CONNECT icanhazip.com:80",
        ],
    )
    def test_a_reachability_check_fires_both_rules(self, payload: str) -> None:
        names = rules_for(payload)
        assert "open_proxy_connect_request" in names
        assert "open_proxy_reachability_check" in names

    def test_the_campaign_does_not_fire_the_reachability_rule(self) -> None:
        for payload in (
            "CONNECT cdn.tooyoungtoholdon.world:7000",
            "CONNECT c2.dstatbot.win:443",
            "CONNECT 51.222.140.50:80",
        ):
            assert rules_for(payload) == ["open_proxy_connect_request"], payload

    def test_a_survey_is_graded_below_a_tunnel(self) -> None:
        assert get_severity(VERDICT, "open_proxy_reachability_check") == "low"
        assert get_severity(VERDICT, "open_proxy_connect_request") == "medium"


class TestTheVerdictClaimsOnlyWhatOneRequestShows:
    def test_the_verdict_is_medium_not_high(self) -> None:
        """A CONNECT establishes the attempt, not the intent. The lesson is the one
        `sp-webshell-aspx` taught: a verdict that claims more than the evidence is a defect
        even when the traffic really is hostile."""
        assert ATTACK_TYPE_SEVERITY[VERDICT] == "medium"

    def test_it_maps_to_proxy_and_to_scanning(self) -> None:
        techniques = [t["technique"] for t in ATTACK_TO_MITRE[VERDICT]]
        assert "T1090" in techniques  # Proxy, command-and-control
        assert "T1595" in techniques  # Active Scanning, for the surveys

    def test_it_is_added_and_never_substituted(self) -> None:
        """A CONNECT whose body also carries an exploit must keep the exploit verdict. The
        classifier has no detection short-circuit and this is the guard for it."""
        hits = classify_event_row(
            "CONNECT evil.example:443\r\n\r\n' UNION SELECT username, password FROM users-- ",
            "http",
            {},
        )
        types = {atype for atype, _name, _snippet in hits}
        assert VERDICT in types
        assert len(types) > 1, f"the exploit verdict was lost, only got {types}"


class TestTheRulesAreRegisteredAndCheap:
    def test_the_module_is_in_the_rules_package(self) -> None:
        """A rename or a dropped import would silently un-label the whole family again."""
        from honeylens.classification.rules import _GROUPS, proxy_relay

        assert proxy_relay in _GROUPS

    def test_all_four_rules_reach_the_registry(self) -> None:
        from honeylens.classification import text_rules

        names = {name for atype, name, _rx in text_rules._RULES if atype == VERDICT}
        assert names == {
            "open_proxy_connect_request",
            "open_proxy_connect_json",
            "open_proxy_connect_no_authority",
            "open_proxy_reachability_check",
        }

    def test_no_pattern_backtracks(self) -> None:
        """Five committed rules already cost 471-842 ms an event. These are checked with the
        validator's own cost ladder rather than by eye."""
        from honeylens.analysis.rule_validator import _redos_cost
        from honeylens.classification import text_rules

        for atype, name, rx in text_rules._RULES:
            if atype != VERDICT:
                continue
            seconds, offender = _redos_cost(rx)
            assert offender is None, f"{name} backtracks on {offender!r}"
            assert seconds < 0.05, f"{name} cost {seconds:.3f}s"


class TestTheBackfillIsAdditive:
    """The fleet's general tool for a rule change reprocesses every event with
    `replace_patterns=True` and is the job whose first unattended run in that mode wiped
    decoy tags fleet-wide. This change tightens nothing -- four rules added, none removed --
    so its backfill touches only the rows those rules match, and deletes nothing."""

    def test_it_never_deletes(self) -> None:
        import inspect

        from honeylens.tools import backfill_rule_profile as tool

        # The SQL it runs, not its prose: the module's own docstring names
        # `replace_patterns=True` while explaining what it does *not* do, so grepping the
        # source text asks the wrong question.
        statements = [
            value
            for name, value in vars(tool).items()
            if name.endswith("_SQL") and isinstance(value, str)
        ]
        assert statements, "no SQL constants found — did they get renamed?"
        for sql in statements:
            upper = sql.upper()
            assert "DELETE" not in upper
            assert "TRUNCATE" not in upper
        # and it does not reach for the authoritative reprocessor
        assert not hasattr(tool, "BackfillConfig")
        assert "BackfillConfig" not in inspect.getsource(tool)

    def test_membership_is_a_token_test_not_a_substring(self) -> None:
        """`attack_types` has no canonical order and a longer label can contain a shorter
        one, so `LIKE '%OPEN_PROXY_RELAY%'` is the wrong question."""
        from honeylens.tools.backfill_rule_profile import _UPDATE_TYPES_SQL, _tokens

        assert "OPEN_PROXY_RELAY" in _tokens("OPEN_PROXY_RELAY")
        assert "OPEN_PROXY_RELAY" in _tokens("SCANNER,OPEN_PROXY_RELAY,CREDENTIAL")
        assert "OPEN_PROXY_RELAY" in _tokens(" OPEN_PROXY_RELAY , SCANNER ")
        assert "OPEN_PROXY_RELAY" not in _tokens("SCANNER,CREDENTIAL")
        assert _tokens(None) == set()
        assert _tokens("") == set()
        # and the same question in SQL
        assert "string_to_array" in _UPDATE_TYPES_SQL
        assert "LIKE" not in _UPDATE_TYPES_SQL.upper()

    def test_a_dry_run_writes_nothing(self) -> None:
        from unittest.mock import MagicMock, patch

        from honeylens.tools import backfill_rule_profile as tool

        row = (
            "evt_1",
            "CONNECT tls.bunnyfeet.baby:443",
            "http",
            {"path": "tls.bunnyfeet.baby:443"},
            None,
        )
        cur = MagicMock()
        cur.fetchall.return_value = [row]
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        # one day = one slice, so the one row is seen once
        with patch.object(tool, "db_cursor", return_value=ctx):
            counts = tool.backfill(tool.PROFILES["open-proxy-relay"], since_days=1, apply=False)
        assert counts["matched"] == 1
        assert counts["types_written"] == 0
        assert counts["patterns_written"] == 0
        statements = [c.args[0] for c in cur.execute.call_args_list]
        assert not any("INSERT" in s.upper() or "UPDATE" in s.upper() for s in statements)
        assert any("statement_timeout" in s for s in statements), (
            "each slice must bound its own statement -- the server default differs per "
            "deployment and the first version of this tool timed out on the busiest sensor"
        )

    def test_it_writes_the_summary_and_the_pattern_rows(self) -> None:
        """A verdict in `attack_types` with no `attack_patterns` row is the defect this
        project has already paid for twice."""
        from unittest.mock import MagicMock, patch

        from honeylens.tools import backfill_rule_profile as tool

        row = (
            "evt_1",
            "CONNECT api.ipify.org:443",
            "http",
            {"path": "api.ipify.org:443"},
            "SCANNER",
        )
        cur = MagicMock()
        cur.fetchall.return_value = [row]
        cur.rowcount = 1
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with patch.object(tool, "db_cursor", return_value=ctx):
            counts = tool.backfill(tool.PROFILES["open-proxy-relay"], since_days=1, apply=True)
        statements = " ".join(c.args[0] for c in cur.execute.call_args_list).upper()
        assert "INSERT INTO ATTACK_PATTERNS" in statements
        assert "UPDATE SENSOR_EVENTS" in statements
        assert "ON CONFLICT DO NOTHING" in statements
        # both rules fire on a reachability check, so both get a pattern row
        assert counts["patterns_written"] == 2


class TestTheNightlyTimerIsNotArmedByAnAdditiveChange:
    """Every host's `honeylens-auto-backfill.timer` runs with `--apply`, and its trigger is
    the rule fingerprint. Adding four rules changes that fingerprint, which would have armed
    an unattended authoritative reprocess -- `reprocess_all` with `replace_patterns` -- of
    the whole event store at the next firing. Measured before the deploy: stored equalled
    current on the fleet, so these four rules were the entire delta.
    """

    def test_mark_applied_stores_without_reprocessing(self) -> None:
        import inspect

        from honeylens.tools import auto_backfill

        source = inspect.getsource(auto_backfill.main)
        mark = source.index("args.mark_applied")
        backfill_call = source.index("BackfillConfig")
        assert mark < backfill_call, "--mark-applied must return before the reprocess"
        assert "return 0" in source[mark:backfill_call]

    def test_it_refuses_to_be_a_no_op_claim(self) -> None:
        """Marking an unchanged fingerprint says nothing, so it says so instead."""
        import inspect

        from honeylens.tools import auto_backfill

        assert "already stored" in inspect.getsource(auto_backfill.main)
