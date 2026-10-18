"""
intelligence/credential_vault.py — Encrypted API Key Storage
==============================================================
AES-256-GCM encrypted credential vault backed by PostgreSQL.
Allows OSINT API keys to be stored, rotated, and managed via the
admin panel without file access or service restarts.

Falls back to .env values when the vault is not configured or
when a key is not found in the database.

Usage:
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    key = vault.get_key("abuseipdb")  # DB → .env → ""

Requires: cryptography>=41.0.0
Requires: VAULT_MASTER_KEY set in .env (64-char hex or 44-char base64)

If VAULT_MASTER_KEY is empty, the vault is disabled and all keys
are read from .env variables (graceful degradation).
"""

from __future__ import annotations

import base64
import logging
import os

logger = logging.getLogger("credential_vault")

# Lazy import — don't break startup if cryptography not installed
_AESGCM = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _AESGCM = AESGCM
except ImportError:
    logger.info("cryptography package not installed — vault encryption unavailable")


class CredentialVault:
    """
    Encrypted credential vault backed by PostgreSQL.

    Encryption: AES-256-GCM with random 12-byte nonce per key.
    Storage: nonce (12 bytes) + ciphertext in BYTEA column.
    """

    def __init__(self, master_key_hex: str = "") -> None:
        self._aesgcm = None
        self._enabled = False

        if not master_key_hex or _AESGCM is None:
            return

        try:
            # Accept hex (64 chars) or base64 (44 chars)
            if len(master_key_hex) == 64:
                key_bytes = bytes.fromhex(master_key_hex)
            else:
                key_bytes = base64.b64decode(master_key_hex)

            if len(key_bytes) != 32:
                logger.error("VAULT_MASTER_KEY must be 256 bits (32 bytes)")
                return

            self._aesgcm = _AESGCM(key_bytes)
            self._enabled = True
            logger.info("Credential vault enabled (AES-256-GCM)")
        except Exception as e:
            logger.error("Vault key initialisation failed: %s", e)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt API key → nonce (12B) + ciphertext."""
        if not self._aesgcm:
            raise RuntimeError("Vault not initialised")
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ct

    def decrypt(self, data: bytes) -> str:
        """Decrypt nonce+ciphertext → API key string."""
        if not self._aesgcm:
            raise RuntimeError("Vault not initialised")
        if len(data) < 13:
            raise ValueError("Encrypted data too short")
        nonce, ct = data[:12], data[12:]
        return self._aesgcm.decrypt(nonce, ct, None).decode("utf-8")

    def get_key(self, provider: str) -> str:
        """
        Get API key for an OSINT provider.

        Resolution order:
          1. Database credential_vault (encrypted)
          2. .env file (OSINT_{PROVIDER}_KEY)
          3. Empty string (provider disabled)

        Args:
            provider: Provider name (e.g. "abuseipdb", "virustotal")

        Returns:
            Decrypted API key string, or empty string.
        """
        # 1. Try database vault
        if self._enabled:
            try:
                row = self._query_vault(provider)
                if row and row.get("api_key_enc"):
                    self._bump_usage(provider)
                    return self.decrypt(bytes(row["api_key_enc"]))
            except Exception as e:
                logger.warning("Vault read failed for %s: %s", provider, e)

        # 2. Fallback to .env
        from honeylens.env import env

        env_key = f"OSINT_{provider.upper()}_KEY"
        val = env(env_key, "")
        if val:
            return val

        # Special cases (Censys uses ID+SECRET)
        if provider.lower() == "censys":
            cid = env("OSINT_CENSYS_ID", "")
            csec = env("OSINT_CENSYS_SECRET", "")
            if cid and csec:
                return f"{cid}:{csec}"

        return ""

    def store_key(
        self,
        provider: str,
        plaintext_key: str,
        rate_limit_rpm: int | None = None,
        notes: str | None = None,
    ) -> bool:
        """Store (or update) an encrypted API key in the vault."""
        if not self._enabled:
            logger.error("Cannot store key — vault not enabled")
            return False

        encrypted = self.encrypt(plaintext_key)

        try:
            from honeylens.database import db_cursor

            with db_cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO credential_vault (provider, api_key_enc, rate_limit_rpm, notes)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (provider) DO UPDATE SET
                        api_key_enc = EXCLUDED.api_key_enc,
                        rate_limit_rpm = EXCLUDED.rate_limit_rpm,
                        notes = EXCLUDED.notes,
                        last_rotated = NOW(),
                        updated_at = NOW()
                """,
                    (provider.lower(), encrypted, rate_limit_rpm, notes),
                )
            logger.info("Vault: stored key for %s", provider)
            return True
        except Exception as e:
            logger.error("Vault store failed for %s: %s", provider, e)
            return False

    def deactivate_key(self, provider: str) -> bool:
        """Mark a provider key as inactive (soft delete)."""
        try:
            from honeylens.database import db_cursor

            with db_cursor() as cur:
                cur.execute(
                    """
                    UPDATE credential_vault SET is_active = FALSE, updated_at = NOW()
                    WHERE provider = %s
                """,
                    (provider.lower(),),
                )
            return True
        except Exception as e:
            logger.error("Vault deactivate failed for %s: %s", provider, e)
            return False

    def list_providers(self) -> list[dict]:
        """list all vault entries (keys are NOT decrypted)."""
        try:
            from honeylens.database import db_cursor

            with db_cursor() as cur:
                cur.execute("""
                    SELECT provider, is_active, rate_limit_rpm, last_used,
                           last_rotated, usage_count, notes
                    FROM credential_vault
                    ORDER BY provider
                """)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]
        except Exception as e:
            logger.error("Vault list failed: %s", e)
            return []

    # -- internal helpers --

    def _query_vault(self, provider: str) -> dict | None:
        from honeylens.database import db_cursor

        with db_cursor() as cur:
            cur.execute(
                """
                SELECT api_key_enc FROM credential_vault
                WHERE provider = %s AND is_active = TRUE
            """,
                (provider.lower(),),
            )
            row = cur.fetchone()
            if row:
                return {"api_key_enc": row[0]}
        return None

    def _bump_usage(self, provider: str) -> None:
        try:
            from honeylens.database import db_cursor

            with db_cursor() as cur:
                cur.execute(
                    """
                    UPDATE credential_vault
                    SET usage_count = usage_count + 1, last_used = NOW()
                    WHERE provider = %s
                """,
                    (provider.lower(),),
                )
        except Exception as exc:
            logger.debug("usage_count update failed: %s", exc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_vault_instance: CredentialVault | None = None


def get_vault() -> CredentialVault:
    """Get (or create) the global vault instance."""
    global _vault_instance
    if _vault_instance is None:
        from honeylens.config import VAULT_MASTER_KEY

        _vault_instance = CredentialVault(VAULT_MASTER_KEY)
    return _vault_instance
