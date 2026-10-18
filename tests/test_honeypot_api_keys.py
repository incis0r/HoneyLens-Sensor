"""
Unit and endpoint tests for per-honeypot API Key + Basic Auth functionality.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from honeylens.auth.api_key_manager import (
    HoneypotApiKey,
    authenticate_api_key,
    create_api_key,
    generate_basic_password,
    get_rotation_alerts,
    hash_api_key,
    honeypot_scope_sql,
    normalize_honeypot_name,
    revoke_api_key,
)
from honeylens.auth.auth import hash_password
from honeylens.routes.honeypot_api import (
    _normalize_cve,
    _resolve_effective_honeypot,
    _validate_ip_or_cidr,
    read_honeypot_events_by_attack,
    read_honeypot_events_by_cve,
    read_honeypot_events_by_honeypot,
    read_honeypot_events_by_ip,
    resolve_honeypot_api_access,
)


class TestHoneypotNormalization:
    def test_normalize_known_honeypots(self) -> None:
        assert normalize_honeypot_name("ssh") == "ssh"
        assert normalize_honeypot_name("honeypot-ssh") == "ssh"
        assert normalize_honeypot_name("hp_fortigate") == "fortigate"
        assert normalize_honeypot_name("fortigate-honeypot") == "fortigate"
        assert normalize_honeypot_name("cms") == "cms"
        assert normalize_honeypot_name("all") == "*"
        assert normalize_honeypot_name("*") == "*"

    def test_normalize_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown honeypot"):
            normalize_honeypot_name("nonexistent_decoy_xyz")

    def test_scope_sql_matches_the_decoys_own_source_values(self) -> None:
        sql, params = honeypot_scope_sql("fortigate")
        sources = params[0]
        assert "fortigate-honeypot" in sources
        assert "honeypot-fortigate" in sources
        assert sql == "se.source = ANY(%s)"


class TestApiKeyGenerationAndPolicy:
    def test_basic_password_never_contains_colon(self) -> None:
        for _ in range(25):
            pwd = generate_basic_password(24)
            assert ":" not in pwd
            assert len(pwd) == 24

    @patch("honeylens.auth.api_key_manager.log_admin_action")
    @patch("honeylens.auth.api_key_manager.assert_api_keys_table")
    @patch("honeylens.auth.api_key_manager.db_cursor")
    def test_create_standard_90d_key_allocates_sequential_apiaccess(
        self,
        mock_db_cursor: MagicMock,
        _mock_ensure: MagicMock,
        _mock_audit: MagicMock,
    ) -> None:
        now = datetime.now(UTC)
        exp = now + timedelta(days=90)
        cur = MagicMock()
        # Simulate existing apiaccess1 and apiaccess2
        cur.fetchall.return_value = [("apiaccess1",), ("apiaccess2",)]
        cur.fetchone.return_value = (3, now, exp)
        mock_db_cursor.return_value.__enter__.return_value = cur

        created, err = create_api_key(
            honeypot="fortigate",
            key_name="Forti SIEM",
            max_age_days=90,
            acknowledge_risk=False,
            created_by=1,
            ip_address="127.0.0.1",
        )
        assert err is None
        assert created is not None
        assert created["basic_username"] == "apiaccess3"
        assert created["honeypot"] == "fortigate"
        assert created["max_age_days"] == 90
        assert created["risk_acknowledged"] is False
        assert created["api_key"].startswith("hlk_")
        assert created["basic_auth_pair"].startswith("apiaccess3:")
        assert created["basic_auth_header"].startswith("Basic ")

    def test_create_365d_key_rejected_without_risk_acknowledgment(self) -> None:
        created, err = create_api_key(
            honeypot="ssh",
            key_name="Long lived key",
            max_age_days=365,
            acknowledge_risk=False,
        )
        assert created is None
        assert err is not None
        assert "require explicit confirmation of security risks" in err

    @patch("honeylens.auth.api_key_manager.log_admin_action")
    @patch("honeylens.auth.api_key_manager.assert_api_keys_table")
    @patch("honeylens.auth.api_key_manager.db_cursor")
    def test_create_365d_key_succeeds_with_risk_acknowledgment(
        self,
        mock_db_cursor: MagicMock,
        _mock_ensure: MagicMock,
        _mock_audit: MagicMock,
    ) -> None:
        now = datetime.now(UTC)
        exp = now + timedelta(days=365)
        cur = MagicMock()
        cur.fetchall.return_value = []
        cur.fetchone.return_value = (1, now, exp)
        mock_db_cursor.return_value.__enter__.return_value = cur

        created, err = create_api_key(
            honeypot="ssh",
            key_name="365d SIEM key",
            max_age_days=365,
            acknowledge_risk=True,
            created_by=1,
        )
        assert err is None
        assert created is not None
        assert created["basic_username"] == "apiaccess1"
        assert created["max_age_days"] == 365
        assert created["risk_acknowledged"] is True

    def test_create_key_invalid_max_age_rejected(self) -> None:
        created, err = create_api_key(honeypot="ssh", max_age_days=0)
        assert created is None
        assert err is not None

        created2, err2 = create_api_key(honeypot="ssh", max_age_days=400, acknowledge_risk=True)
        assert created2 is None
        assert err2 is not None


class TestExpirationRotationAndRevocation:
    def test_rotation_alerts_detect_expiring_and_expired_keys(self) -> None:
        now = datetime.now(UTC)
        active_key = HoneypotApiKey(
            id=1,
            key_name="healthy",
            honeypot="ssh",
            basic_username="apiaccess1",
            api_key_prefix="hlk_111...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now - timedelta(days=10),
            expires_at=now + timedelta(days=80),
        )
        expiring_key = HoneypotApiKey(
            id=2,
            key_name="soon",
            honeypot="fortigate",
            basic_username="apiaccess2",
            api_key_prefix="hlk_222...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now - timedelta(days=80),
            expires_at=now + timedelta(days=5),
        )
        expired_key = HoneypotApiKey(
            id=3,
            key_name="old",
            honeypot="k8s",
            basic_username="apiaccess3",
            api_key_prefix="hlk_333...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now - timedelta(days=95),
            expires_at=now - timedelta(days=5),
        )
        revoked_key = HoneypotApiKey(
            id=4,
            key_name="revoked",
            honeypot="paloalto",
            basic_username="apiaccess4",
            api_key_prefix="hlk_444...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now - timedelta(days=95),
            expires_at=now - timedelta(days=5),
            revoked=True,
        )

        assert active_key.status == "active"
        assert active_key.needs_rotation is False
        assert expiring_key.status == "expiring_soon"
        assert expiring_key.needs_rotation is True
        assert expired_key.status == "expired"
        assert expired_key.needs_rotation is True
        assert revoked_key.status == "revoked"
        assert revoked_key.needs_rotation is False

        alerts = get_rotation_alerts([active_key, expiring_key, expired_key, revoked_key])
        assert alerts["expiring_soon_count"] == 1
        assert alerts["expired_count"] == 1
        assert alerts["needs_rotation_count"] == 2

    @patch("honeylens.auth.api_key_manager.log_admin_action")
    @patch("honeylens.auth.api_key_manager.assert_api_keys_table")
    @patch("honeylens.auth.api_key_manager.db_cursor")
    def test_revoke_api_key(
        self,
        mock_db_cursor: MagicMock,
        _mock_ensure: MagicMock,
        _mock_audit: MagicMock,
    ) -> None:
        cur = MagicMock()
        cur.fetchone.return_value = ("apiaccess1", "ssh", False)
        mock_db_cursor.return_value.__enter__.return_value = cur

        ok, err = revoke_api_key(key_id=1, revoked_by=1, reason="Compromised")
        assert ok is True
        assert err is None

    @patch("honeylens.auth.api_key_manager.assert_api_keys_table")
    @patch("honeylens.auth.api_key_manager.db_cursor")
    def test_authenticate_api_key_checks_basic_auth_and_revocation_and_expiry(
        self,
        mock_db_cursor: MagicMock,
        _mock_ensure: MagicMock,
    ) -> None:
        now = datetime.now(UTC)
        pw = "RandomPass123!@#"
        pw_hash, pw_salt = hash_password(pw)
        raw_key = "hlk_test_token_value"

        cur = MagicMock()
        mock_db_cursor.return_value.__enter__.return_value = cur

        # 1. Valid active key
        cur.fetchone.return_value = (
            1,
            "ssh-key",
            "ssh",
            "apiaccess1",
            pw_hash,
            pw_salt,
            "hlk_test_tok...",
            90,
            False,
            1,
            now - timedelta(days=1),
            now + timedelta(days=89),
            None,
            None,
            False,
            None,
            None,
            None,
        )
        key_obj, err = authenticate_api_key("apiaccess1", pw, raw_key, "10.0.0.5")
        assert err is None
        assert key_obj is not None
        assert key_obj.honeypot == "ssh"

        # 2. Wrong Basic Auth password
        key_obj2, err2 = authenticate_api_key("apiaccess1", "WrongPass999!", raw_key)
        assert key_obj2 is None
        assert err2 == "Invalid Basic Auth password for API key"

        # 3. Revoked key
        cur.fetchone.return_value = (
            1,
            "ssh-key",
            "ssh",
            "apiaccess1",
            pw_hash,
            pw_salt,
            "hlk_test_tok...",
            90,
            False,
            1,
            now - timedelta(days=1),
            now + timedelta(days=89),
            None,
            None,
            True,
            now,
            1,
            "Revoked",
        )
        key_obj3, err3 = authenticate_api_key("apiaccess1", pw, raw_key)
        assert key_obj3 is None
        assert err3 == "API key has been revoked"

        # 4. Expired key
        cur.fetchone.return_value = (
            1,
            "ssh-key",
            "ssh",
            "apiaccess1",
            pw_hash,
            pw_salt,
            "hlk_test_tok...",
            90,
            False,
            1,
            now - timedelta(days=95),
            now - timedelta(days=5),
            None,
            None,
            False,
            None,
            None,
            None,
        )
        key_obj4, err4 = authenticate_api_key("apiaccess1", pw, raw_key)
        assert key_obj4 is None
        assert err4 == "API key has expired and must be rotated"


class TestHoneypotReadApiRoutes:
    def _make_key(self, honeypot: str = "ssh") -> HoneypotApiKey:
        now = datetime.now(UTC)
        return HoneypotApiKey(
            id=10,
            key_name="test-key",
            honeypot=honeypot,
            basic_username="apiaccess1",
            api_key_prefix="hlk_test...",
            max_age_days=90,
            risk_acknowledged=False,
            created_by=1,
            created_at=now,
            expires_at=now + timedelta(days=90),
        )

    def _make_request_with_key(self, honeypot: str = "ssh") -> Any:
        req = MagicMock()
        req.state.honeypot_api_key = self._make_key(honeypot)
        return req

    def test_scope_enforcement_blocks_other_honeypots(self) -> None:
        ssh_key = self._make_key("ssh")
        # Allowed: default (*) resolves to key's scope ("ssh")
        assert _resolve_effective_honeypot(ssh_key, None) == "ssh"
        assert _resolve_effective_honeypot(ssh_key, "ssh") == "ssh"

        # Blocked: requesting fortigate with an ssh-scoped key raises 403
        with pytest.raises(HTTPException) as exc_info:
            _resolve_effective_honeypot(ssh_key, "fortigate")
        assert exc_info.value.status_code == 403
        assert "scoped exclusively to honeypot 'ssh'" in str(exc_info.value.detail)

    def test_cve_and_ip_validators(self) -> None:
        assert _normalize_cve("cve-2024-3400") == ("CVE-2024-3400", "CVE_2024_3400")
        assert _normalize_cve("2025-53770") == ("CVE-2025-53770", "CVE_2025_53770")
        with pytest.raises(HTTPException):
            _normalize_cve("NOT-A-CVE")

        assert _validate_ip_or_cidr("185.220.101.1") == ("185.220.101.1", False)
        assert _validate_ip_or_cidr("185.220.101.0/24") == ("185.220.101.0/24", True)
        with pytest.raises(HTTPException):
            _validate_ip_or_cidr("999.999.999.999")

    @patch(
        "honeylens.routes.honeypot_api._label_vocabulary",
        side_effect=lambda col, scope: (
            ("FORTI_CVE",) if col == "attack_type" else ("forti_cve_2024_21762",)
        ),
    )
    @patch(
        "honeylens.routes.honeypot_api.external_only",
        return_value="se.source_class IS NULL",
    )
    @patch("honeylens.routes.honeypot_api.db_cursor")
    def test_queries_per_attack_per_ip_per_cve_per_honeypot(
        self,
        mock_db_cursor: MagicMock,
        _mock_external_only: MagicMock,
        _mock_vocab: MagicMock,
    ) -> None:
        now = datetime.now(UTC)
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        cur.fetchall.return_value = [
            (
                "evt_001",
                now,
                "185.220.101.5/32",
                54321,
                "10.0.0.10/32",
                10443,
                "https",
                "fortigate-honeypot",
                "FORTI_CVE",
                "GET /remote/login",
                {"cve": "CVE-2024-21762", "honeypot": "fortigate"},
            )
        ]
        mock_db_cursor.return_value.__enter__.return_value = cur

        req = self._make_request_with_key("fortigate")

        # 1. Per attack
        res_attack = read_honeypot_events_by_attack("FORTI_CVE", req)
        assert res_attack["honeypot_scope"] == "fortigate"
        assert res_attack["total"] == 1
        assert res_attack["events"][0]["src_ip"] == "185.220.101.5"

        # 2. Per IP
        res_ip = read_honeypot_events_by_ip("185.220.101.5", req)
        assert res_ip["filters"]["ip"] == "185.220.101.5"
        assert res_ip["count"] == 1

        # 3. Per CVE
        res_cve = read_honeypot_events_by_cve("CVE-2024-21762", req)
        assert res_cve["filters"]["cve"] == "CVE-2024-21762"
        assert res_cve["count"] == 1

        # 4. Per Honeypot (allowed for own honeypot)
        res_hp = read_honeypot_events_by_honeypot("fortigate", req)
        assert res_hp["honeypot_scope"] == "fortigate"
        assert res_hp["count"] == 1

        # 5. Per Honeypot (denied for different honeypot)
        with pytest.raises(HTTPException) as exc_info:
            read_honeypot_events_by_honeypot("ssh", req)
        assert exc_info.value.status_code == 403

    def test_missing_dual_credentials_rejected(self) -> None:
        req = MagicMock()
        req.state = MagicMock()
        req.state.honeypot_api_key = None
        req.state.user = None
        req.state.is_admin = False
        # Provide Basic Auth with apiaccess1, but omit X-API-Key
        b64 = base64.b64encode(b"apiaccess1:somepass").decode("ascii")
        req.headers = {"Authorization": f"Basic {b64}"}
        req.query_params = {}

        with pytest.raises(HTTPException) as exc_info:
            resolve_honeypot_api_access(req)
        assert exc_info.value.status_code == 401
        assert "X-API-Key" in str(exc_info.value.detail)
        assert hash_api_key("test") != ""
