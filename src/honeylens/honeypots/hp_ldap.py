"""
honeypots/hp_ldap.py — Modular LDAP honeypot service
=====================================================
Speaks enough LDAP (manual BER/ASN.1 parsing) to capture bind credentials
and search enumeration attempts from AD recon tools.

Run standalone:
    python -m honeypots.hp_ldap
    HP_LDAP_PORT=389 python -m honeypots.hp_ldap
"""

from __future__ import annotations

import asyncio
from typing import Any

from honeylens.honeypots._base import BaseHoneypot, log_event


class LDAPHoneypot(BaseHoneypot):
    """Low-interaction LDAP honeypot for credential and enumeration capture."""

    PROTOCOL = "ldap"
    DEFAULT_PORT = 389
    TTL_PROFILE = "windows"
    CONNECTION_TIMEOUT = 90

    def __init__(self):
        super().__init__()
        self._base_dn = self.profile.get("base_dn", "DC=corp,DC=example,DC=com")
        self._domain = self.profile.get("domain", "corp.example.com")
        self._dc_name = self.profile.get("dc_name", "DC01.corp.example.com")
        self._org = self.profile.get("org", "Example Corporation")
        self._fake_users = self.profile.get("fake_users", ["admin"])
        self._fake_groups = self.profile.get("fake_groups", ["Domain Admins"])

    # ---- BER / ASN.1 helpers ------------------------------------------------

    @staticmethod
    def _ber_read_length(data: bytes, offset: int) -> tuple[int, int]:
        """Read a BER length field. Returns (length, new_offset)."""
        if offset >= len(data):
            return 0, offset
        first = data[offset]
        if first < 0x80:
            return first, offset + 1
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + 1 + num_bytes > len(data):
            return 0, offset + 1
        length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
        return length, offset + 1 + num_bytes

    @staticmethod
    def _ber_read_element(data: bytes, offset: int) -> tuple[int, bytes, int]:
        """Read one BER TLV element. Returns (tag, value, new_offset)."""
        if offset >= len(data):
            return 0, b"", offset
        tag = data[offset]
        length, off = LDAPHoneypot._ber_read_length(data, offset + 1)
        end = min(off + length, len(data))
        return tag, data[off:end], end

    @staticmethod
    def _ber_encode_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(encoded)]) + encoded

    @classmethod
    def _ber_wrap(cls, tag: int, value: bytes) -> bytes:
        return bytes([tag]) + cls._ber_encode_length(len(value)) + value

    @staticmethod
    def _ber_read_int(data: bytes) -> int:
        """Decode a BER INTEGER value."""
        return int.from_bytes(data, "big", signed=True) if data else 0

    @staticmethod
    def _ber_read_string(data: bytes) -> str:
        """Decode a BER OCTET STRING value as UTF-8."""
        return data.decode("utf-8", errors="replace")

    # ---- LDAP response builders ---------------------------------------------

    def _bind_response(self, message_id: int, result_code: int = 49) -> bytes:
        """Build an LDAP BindResponse (tag 0x61) with the given result code."""
        msg_id = self._ber_wrap(
            0x02, message_id.to_bytes(max(1, (message_id.bit_length() + 7) // 8), "big")
        )
        result = self._ber_wrap(0x0A, bytes([result_code]))  # resultCode ENUM
        matched_dn = self._ber_wrap(0x04, b"")  # matchedDN
        diag_msg = self._ber_wrap(0x04, b"invalidCredentials" if result_code == 49 else b"")
        bind_resp = self._ber_wrap(0x61, result + matched_dn + diag_msg)
        return self._ber_wrap(0x30, msg_id + bind_resp)

    def _search_result_done(self, message_id: int) -> bytes:
        """Build a SearchResultDone (tag 0x65) with no entries."""
        msg_id = self._ber_wrap(
            0x02, message_id.to_bytes(max(1, (message_id.bit_length() + 7) // 8), "big")
        )
        result = self._ber_wrap(0x0A, bytes([0]))  # success
        matched_dn = self._ber_wrap(0x04, b"")
        diag_msg = self._ber_wrap(0x04, b"")
        done = self._ber_wrap(0x65, result + matched_dn + diag_msg)
        return self._ber_wrap(0x30, msg_id + done)

    # ---- request parsers ----------------------------------------------------

    def _parse_bind_request(self, value: bytes) -> dict:
        """Parse BindRequest fields: version, DN, password."""
        info: dict[str, Any] = {}
        off = 0
        # version (INTEGER)
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x02:
            info["version"] = self._ber_read_int(v)
        # name / DN (OCTET STRING)
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x04:
            info["bind_dn"] = self._ber_read_string(v)
        # authentication choice — simple auth is tag 0x80
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x80:
            info["password"] = self._ber_read_string(v)
        elif tag == 0xA3:
            info["sasl_mechanism"] = self._ber_read_string(
                v[: v.find(b"\x00")] if b"\x00" in v else v
            )
        return info

    def _parse_search_request(self, value: bytes) -> dict:
        """Parse SearchRequest fields: base DN, scope, filter (raw)."""
        info: dict[str, Any] = {}
        off = 0
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x04:
            info["base_dn"] = self._ber_read_string(v)
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x0A:
            info["scope"] = self._ber_read_int(v)
        tag, v, off = self._ber_read_element(value, off)
        if tag == 0x0A:
            info["deref"] = self._ber_read_int(v)
        # sizeLimit, timeLimit
        for _ in range(2):
            tag, v, off = self._ber_read_element(value, off)
        # typesOnly
        tag, v, off = self._ber_read_element(value, off)
        # filter (constructed, just capture raw hex for logging)
        tag, v, off = self._ber_read_element(value, off)
        info["filter_hex"] = v.hex() if v else ""
        return info

    # ---- connection handler -------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        msg_count = 0
        try:
            while msg_count < 100:
                # Read LDAP message envelope (SEQUENCE tag 0x30)
                first = await asyncio.wait_for(reader.readexactly(1), timeout=30)
                if first[0] != 0x30:
                    break

                # Read length
                lb = await asyncio.wait_for(reader.readexactly(1), timeout=10)
                if lb[0] < 0x80:
                    total_len = lb[0]
                else:
                    num = lb[0] & 0x7F
                    lb2 = await asyncio.wait_for(reader.readexactly(num), timeout=10)
                    total_len = int.from_bytes(lb2, "big")

                if total_len > 0x100000 or total_len < 2:
                    break
                body = await asyncio.wait_for(reader.readexactly(total_len), timeout=30)

                # Parse messageID
                off = 0
                tag, mid_bytes, off = self._ber_read_element(body, off)
                message_id = self._ber_read_int(mid_bytes) if tag == 0x02 else 0

                # Parse protocol operation
                op_tag, op_value, off = self._ber_read_element(body, off)

                if op_tag == 0x60:  # BindRequest
                    bind = self._parse_bind_request(op_value)
                    self.logger.warning("[LDAP] %s Bind: dn=%s", peer[0], bind.get("bind_dn", ""))
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "bind_request",
                            "bind_dn": bind.get("bind_dn"),
                            "password": bind.get("password", ""),
                            "sasl": bind.get("sasl_mechanism"),
                            "version": bind.get("version"),
                            "dst_port": self.port,
                            "rule": "ldap_bind",
                        },
                        attack_type="LDAP_ATTACK",
                        severity="HIGH",
                    )
                    writer.write(self._bind_response(message_id, result_code=49))
                    await writer.drain()

                elif op_tag == 0x63:  # SearchRequest
                    search = self._parse_search_request(op_value)
                    self.logger.info(
                        "[LDAP] %s Search: base=%s scope=%s",
                        peer[0],
                        search.get("base_dn", ""),
                        search.get("scope", ""),
                    )
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "search_request",
                            "base_dn": search.get("base_dn"),
                            "scope": search.get("scope"),
                            "filter_hex": search.get("filter_hex"),
                            "dst_port": self.port,
                            "rule": "ldap_search",
                        },
                        attack_type="LDAP_RECON",
                        severity="MEDIUM",
                    )
                    writer.write(self._search_result_done(message_id))
                    await writer.drain()

                elif op_tag == 0x42:  # UnbindRequest
                    self.logger.debug("[LDAP] %s Unbind", peer[0])
                    break

                else:
                    self.logger.debug("[LDAP] %s Unknown op 0x%02X", peer[0], op_tag)
                    break

                msg_count += 1

        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    LDAPHoneypot().run()
