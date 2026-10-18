#!/usr/bin/env python3
"""
honeypots/hp_cassandra.py — Apache Cassandra (CQL) Honeypot
=============================================================
Simulates a Cassandra node speaking CQL Native Protocol v4.
Requires authentication, captures credentials and CQL queries,
returns fake cluster metadata for system.local queries.

Run: python -m honeypots.hp_cassandra
Service: sensor-hp-cassandra (port 9042)
"""

from __future__ import annotations

import asyncio
import json
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# CQL Native Protocol v4 opcodes
OP_ERROR = 0x00
OP_STARTUP = 0x01
OP_READY = 0x02
OP_AUTHENTICATE = 0x03
OP_QUERY = 0x07
OP_RESULT = 0x08
OP_AUTH_RESPONSE = 0x0F
OP_AUTH_SUCCESS = 0x10

CQL_HEADER_SIZE = 9  # version(1) + flags(1) + stream(2) + opcode(1) + length(4)


class CassandraHoneypot(BaseHoneypot):
    PROTOCOL = "cassandra"
    DEFAULT_PORT = 9042
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        super().__init__()
        p = self.profile
        self.cluster_name = p.get("cluster_name", "production-cluster")
        self.dc_name = p.get("dc_name", "dc1")
        self.version = p.get("version", "4.1.3")

    # ── Frame helpers ────────────────────────────────────────────

    @staticmethod
    def _parse_frame(data: bytes):
        """Parse CQL frame header → (version, flags, stream, opcode, body)."""
        version, flags, stream, opcode, length = struct.unpack(">BBhBI", data[:CQL_HEADER_SIZE])
        return version, flags, stream, opcode, length

    @staticmethod
    def _build_frame(stream: int, opcode: int, body: bytes, version: int = 0x84) -> bytes:
        """Build a CQL response frame (version with response bit 0x80)."""
        header = struct.pack(">BBhBI", version, 0x00, stream, opcode, len(body))
        return header + body

    @staticmethod
    def _encode_string(s: str) -> bytes:
        """CQL [string]: 2-byte length + UTF-8 bytes."""
        encoded = s.encode("utf-8")
        return struct.pack(">H", len(encoded)) + encoded

    @staticmethod
    def _decode_string(data: bytes, offset: int = 0):
        """Decode a CQL [string] at offset → (value, new_offset)."""
        if offset + 2 > len(data):
            return "", offset
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        value = data[offset : offset + length].decode("utf-8", errors="ignore")
        return value, offset + length

    # ── Response builders ────────────────────────────────────────

    def _authenticate_body(self) -> bytes:
        """AUTHENTICATE response body: authenticator class name."""
        return self._encode_string("org.apache.cassandra.auth.PasswordAuthenticator")

    def _auth_success_body(self) -> bytes:
        """AUTH_SUCCESS body (empty token)."""
        return struct.pack(">i", -1)  # null token

    def _error_body(self, code: int, message: str) -> bytes:
        """ERROR body: error code (4 bytes) + message."""
        return struct.pack(">I", code) + self._encode_string(message)

    def _system_local_result(self) -> bytes:
        """RESULT body for SELECT * FROM system.local — Rows kind with fake metadata."""
        rows = json.dumps(
            {
                "cluster_name": self.cluster_name,
                "data_center": self.dc_name,
                "release_version": self.version,
                "partitioner": "org.apache.cassandra.dht.Murmur3Partitioner",
                "cql_version": "3.4.6",
            }
        ).encode("utf-8")
        # kind = 0x0002 (Rows), flags = 0, columns_count = 1, rows_count = 1
        body = struct.pack(">I", 0x0002)  # kind: Rows
        body += struct.pack(">I", 0x0001)  # flags: Global_tables_spec
        body += struct.pack(">I", 1)  # columns_count
        body += self._encode_string("system")  # keyspace
        body += self._encode_string("local")  # table
        body += self._encode_string("result")  # col name
        body += struct.pack(">H", 0x000D)  # col type: varchar
        body += struct.pack(">I", 1)  # rows_count
        body += struct.pack(">I", len(rows)) + rows  # cell value
        return body

    # ── Connection handler ───────────────────────────────────────

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[Cassandra] Connection from %s:%d", peer[0], peer[1])

        try:
            while True:
                raw_hdr = await asyncio.wait_for(reader.readexactly(CQL_HEADER_SIZE), timeout=30)
                _version, _flags, stream, opcode, length = self._parse_frame(raw_hdr)

                body = b""
                if length > 0:
                    body = await asyncio.wait_for(reader.readexactly(length), timeout=30)

                if opcode == OP_STARTUP:
                    # Require authentication
                    reply = self._build_frame(stream, OP_AUTHENTICATE, self._authenticate_body())
                    writer.write(reply)
                    await writer.drain()

                elif opcode == OP_AUTH_RESPONSE:
                    # Body is [bytes]: 4-byte length + data; data = \x00user\x00password
                    username, password = "unknown", ""
                    try:
                        cred_len = struct.unpack(">i", body[:4])[0]
                        cred_data = body[4 : 4 + cred_len] if cred_len > 0 else body[4:]
                        parts = cred_data.split(b"\x00")
                        # Format: ["", username, password]
                        parts_str = [p.decode("utf-8", errors="ignore") for p in parts]
                        if len(parts_str) >= 3:
                            username, password = parts_str[1], parts_str[2]
                        elif len(parts_str) == 2:
                            username, password = parts_str[0], parts_str[1]
                    except (struct.error, IndexError, ValueError):
                        pass  # silent: expected from malformed auth frame

                    self.logger.info("[Cassandra] Auth from %s — user: %s", peer[0], username)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "auth",
                            "rule": "cassandra_auth",
                            "username": username,
                            "password_len": len(password),
                            "payload": body[:128].hex(),
                        },
                        attack_type="CASSANDRA_ATTACK",
                        severity="HIGH",
                    )

                    # Send AUTH_SUCCESS to keep session alive for query capture
                    reply = self._build_frame(stream, OP_AUTH_SUCCESS, self._auth_success_body())
                    writer.write(reply)
                    await writer.drain()

                elif opcode == OP_QUERY:
                    # Body: [long string](4-byte len + query) + consistency(2) + flags
                    query_str = ""
                    try:
                        q_len = struct.unpack(">I", body[:4])[0]
                        query_str = body[4 : 4 + q_len].decode("utf-8", errors="ignore")
                    except (struct.error, IndexError):
                        pass  # silent: expected from malformed query frame

                    self.logger.info("[Cassandra] Query from %s: %.120s", peer[0], query_str)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "query",
                            "rule": "cassandra_query",
                            "query": query_str[:500],
                            "payload": body[:128].hex(),
                        },
                        attack_type="CASSANDRA_RECON",
                        severity="MEDIUM",
                    )

                    # Return fake result for system.local, otherwise empty result
                    if "system.local" in query_str.lower():
                        result_body = self._system_local_result()
                    else:
                        # RESULT kind=0x0001 (Void)
                        result_body = struct.pack(">I", 0x0001)

                    writer.write(self._build_frame(stream, OP_RESULT, result_body))
                    await writer.drain()

                else:
                    # Unsupported opcode — send error
                    err = self._error_body(0x000A, "Protocol error")
                    writer.write(self._build_frame(stream, OP_ERROR, err))
                    await writer.drain()
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    CassandraHoneypot().run()
