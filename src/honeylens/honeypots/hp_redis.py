"""
honeypots/hp_redis.py — Modular Redis honeypot service
========================================================
Emulates a Redis 8.6.4 server (+ RedisBloom) with RESP protocol. Captures
credentials, detects SSH key injection (CONFIG SET dir/dbfilename),
SLAVEOF/REPLICAOF RCE, MODULE LOAD, Lua EVAL, and credential brute force.

Run standalone:
    python -m honeypots.hp_redis
    HP_REDIS_PORT=6379 python -m honeypots.hp_redis
"""

from __future__ import annotations

import asyncio
import logging
import time

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(data: bytes, max_len: int = 500) -> str:
    return data.decode(errors="ignore").replace("\x00", "").strip()[:max_len]


_STREAM_CMDS = {
    "XADD",
    "XGROUP",
    "XREADGROUP",
    "XACK",
    "XCLAIM",
    "XAUTOCLAIM",
    "XLEN",
    "XINFO",
    "XREAD",
    "XDEL",
    "XSETID",
}


def _to_int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


# Fake INFO response
_FAKE_INFO = """\
# Server
redis_version:8.6.4
redis_mode:standalone
os:Linux 5.15.0-91-generic x86_64
arch_bits:64
tcp_port:6379
uptime_in_seconds:847293
uptime_in_days:9

# Clients
connected_clients:1
blocked_clients:0

# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_peak:2097152
used_memory_peak_human:2.00M
maxmemory:0
maxmemory_human:0B

# Stats
total_connections_received:1847
total_commands_processed:28493
keyspace_hits:24102
keyspace_misses:4391

# Replication
role:master
connected_slaves:0

# Keyspace
db0:keys=0,expires=0,avg_ttl=0
"""


class RedisHoneypot(BaseHoneypot):
    """Interactive Redis honeypot with RESP protocol and attack detection."""

    PROTOCOL = "redis"
    DEFAULT_PORT = 6379
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 120

    def _resp_simple(self, msg: str) -> bytes:
        return f"+{msg}\r\n".encode()

    def _resp_error(self, msg: str) -> bytes:
        return f"-ERR {msg}\r\n".encode()

    def _resp_integer(self, n: int) -> bytes:
        return f":{n}\r\n".encode()

    def _resp_bulk(self, data: str | None) -> bytes:
        if data is None:
            return b"$-1\r\n"
        encoded = data.encode()
        return f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"

    def _resp_mixed_array(self, items: list) -> bytes:
        """RESP array of mixed str/int items (for HELLO / MODULE LIST)."""
        out = f"*{len(items)}\r\n".encode()
        for it in items:
            out += self._resp_integer(it) if isinstance(it, int) else self._resp_bulk(str(it))
        return out

    def _resp_array(self, items: list) -> bytes:
        result = f"*{len(items)}\r\n".encode()
        for item in items:
            result += self._resp_bulk(item)
        return result

    def _detect_exploit_chain(self, commands, peer):
        """Emit one correlated CVE event when a session shows an exploit chain."""
        upper = [c.upper() for c in commands]
        has_restore = any(c.startswith("RESTORE") for c in upper)
        has_readgroup = any("XREADGROUP" in c for c in upper)
        has_delconsumer = any("XGROUP" in c and "DELCONSUMER" in c for c in upper)
        if has_restore and has_readgroup and has_delconsumer:
            chain = [
                c[:80]
                for c in commands
                if c.upper().startswith(("RESTORE", "XGROUP", "XREADGROUP", "XACK", "XCLAIM"))
            ][:12]
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "exploit_chain",
                    "cve": "CVE-2026-25243",
                    "chain": chain,
                    "dst_port": self.port,
                },
                attack_type="REDIS_EXPLOIT_CHAIN",
                severity="CRITICAL",
            )

    def _handle_exploit_cmd(self, cmd, cmd_args, peer, writer):
        """Capture + plausibly answer the redis-poc exploit commands."""
        if cmd == "RESTORE":
            key = (cmd_args[0] if cmd_args else "")[:100]
            ttl = (cmd_args[1] if len(cmd_args) > 1 else "")[:20]
            blob = cmd_args[2] if len(cmd_args) > 2 else ""
            import base64
            import hashlib

            blob_b = blob.encode("utf-8", "ignore")
            data = {
                "phase": "restore",
                "key": key,
                "ttl": ttl,
                "blob_len": len(blob),
                "blob_b64": base64.b64encode(blob_b[:2048]).decode(),
                "blob_sha256": hashlib.sha256(blob_b).hexdigest(),
                "dst_port": self.port,
            }
            if len(blob) > 1024:
                data["cve"] = "CVE-2026-25243"
                log_event(
                    self.PROTOCOL, peer, data, attack_type="REDIS_HEAP_CORRUPT", severity="CRITICAL"
                )
            else:
                log_event(
                    self.PROTOCOL, peer, data, attack_type="REDIS_RESTORE_PAYLOAD", severity="HIGH"
                )
            writer.write(self._resp_simple("OK"))

        elif cmd in _STREAM_CMDS:
            sub = (cmd_args[0].upper() if cmd_args else "") if cmd == "XGROUP" else ""
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "stream",
                    "command": cmd,
                    "subcmd": sub,
                    "args": " ".join(cmd_args)[:200],
                    "dst_port": self.port,
                },
                attack_type="REDIS_STREAM_OP",
                severity="MEDIUM",
            )
            if cmd == "XADD":
                writer.write(self._resp_bulk(f"{int(time.time() * 1000)}-0"))
            elif cmd == "XREADGROUP":
                writer.write(b"*-1\r\n")  # nil array
            elif cmd in ("XACK", "XDEL", "XLEN"):
                writer.write(self._resp_integer(0 if cmd == "XLEN" else 1))
            elif cmd in ("XCLAIM", "XAUTOCLAIM", "XINFO", "XREAD"):
                writer.write(self._resp_array([]))
            else:  # XGROUP, XSETID
                writer.write(self._resp_simple("OK"))

        else:  # TOPK.* / TDIGEST.* (RedisBloom)
            nums = [n for n in (_to_int(x) for x in cmd_args) if n is not None]
            anomalous = any(n < 0 or n > 1_000_000 for n in nums)
            data = {
                "phase": "bloom",
                "command": cmd,
                "args": " ".join(cmd_args)[:200],
                "dst_port": self.port,
            }
            if anomalous:
                data["cve"] = "CVE-2026-25589"
                at = "REDIS_TOPK_WILDFREE" if cmd.startswith("TOPK.") else "REDIS_TDIGEST_OVERFLOW"
                log_event(self.PROTOCOL, peer, data, attack_type=at, severity="CRITICAL")
            else:
                log_event(
                    self.PROTOCOL, peer, data, attack_type="REDIS_BLOOM_OP", severity="MEDIUM"
                )
            if cmd.endswith((".QUERY", ".RANK", ".LIST", ".INFO", ".QUANTILE")):
                writer.write(self._resp_array([]))
            else:
                writer.write(self._resp_simple("OK"))

    async def _read_command(self, reader) -> list | None:
        """Parse RESP command. Returns list of strings or None."""
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line:
                return None
            line = line.decode(errors="ignore").strip()

            # RESP array format: *N\r\n$len\r\narg\r\n...
            if line.startswith("*"):
                argc = int(line[1:])
                if argc < 1 or argc > 100:
                    return None
                args = []
                for _ in range(argc):
                    size_line = await asyncio.wait_for(reader.readline(), timeout=10)
                    size_line = size_line.decode(errors="ignore").strip()
                    if not size_line.startswith("$"):
                        return None
                    size = int(size_line[1:])
                    if size < 0 or size > 65536:
                        return None
                    data = await asyncio.wait_for(reader.readexactly(size + 2), timeout=10)
                    args.append(data[:size].decode(errors="ignore"))
                return args

            # Inline command format: COMMAND arg1 arg2
            if line:
                return line.split()

            return None
        except (TimeoutError, ValueError, ConnectionError):
            return None

    async def handle_connection(self, reader, writer, peer):
        """Handle a Redis client session."""
        commands_received = []
        auth_attempts = []

        try:
            while True:
                args = await self._read_command(reader)
                if args is None:
                    break

                cmd = args[0].upper()
                cmd_args = args[1:] if len(args) > 1 else []
                commands_received.append(" ".join(args)[:200])

                # --- PING ---
                if cmd == "PING":
                    writer.write(self._resp_simple("PONG"))

                # --- HELLO (RESP handshake — advertise 8.6.4 + RedisBloom) ---
                elif cmd == "HELLO":
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "hello",
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_ENUM",
                        severity="LOW",
                    )
                    writer.write(
                        self._resp_mixed_array(
                            [
                                "server",
                                "redis",
                                "version",
                                "8.6.4",
                                "proto",
                                2,
                                "id",
                                1,
                                "mode",
                                "standalone",
                                "role",
                                "master",
                            ]
                        )
                    )

                # --- AUTH ---
                elif cmd == "AUTH":
                    password = cmd_args[0] if cmd_args else ""
                    auth_attempts.append(password)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "auth",
                            "password": password[:200],
                            "dst_port": self.port,
                        },
                        attack_type="CREDENTIAL_CAPTURE",
                        severity="MEDIUM",
                    )
                    writer.write(self._resp_error("invalid password"))

                # --- INFO ---
                elif cmd == "INFO":
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "info",
                            "section": cmd_args[0] if cmd_args else "all",
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_ENUM",
                        severity="LOW",
                    )
                    writer.write(self._resp_bulk(_FAKE_INFO))

                # --- CONFIG ---
                elif cmd == "CONFIG":
                    subcmd = cmd_args[0].upper() if cmd_args else ""
                    config_key = cmd_args[1] if len(cmd_args) > 1 else ""
                    config_val = cmd_args[2] if len(cmd_args) > 2 else ""

                    severity = "MEDIUM"
                    attack = "REDIS_CONFIG"

                    # SSH key injection detection
                    if subcmd == "SET" and config_key.lower() in ("dir", "dbfilename"):
                        if (
                            ".ssh" in config_val
                            or "authorized_keys" in config_val
                            or "crontab" in config_val
                            or "/var/spool" in config_val
                        ):
                            severity = "CRITICAL"
                            attack = "REDIS_SSH_INJECT"
                        else:
                            severity = "HIGH"
                            attack = "REDIS_CONFIG_WRITE"

                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "config",
                            "subcmd": subcmd,
                            "key": config_key[:100],
                            "value": config_val[:200],
                            "dst_port": self.port,
                        },
                        attack_type=attack,
                        severity=severity,
                    )

                    if subcmd == "GET":
                        writer.write(self._resp_array([]))
                    else:
                        writer.write(self._resp_simple("OK"))

                # --- SLAVEOF / REPLICAOF (RCE vector) ---
                elif cmd in ("SLAVEOF", "REPLICAOF"):
                    host = cmd_args[0] if cmd_args else ""
                    port = cmd_args[1] if len(cmd_args) > 1 else ""
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "replicaof",
                            "target_host": host[:100],
                            "target_port": port,
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_REPLICAOF_RCE",
                        severity="CRITICAL",
                    )
                    writer.write(self._resp_simple("OK"))

                # --- MODULE (LIST advertises RedisBloom; LOAD is an inject attempt) ---
                elif cmd == "MODULE":
                    subcmd = cmd_args[0].upper() if cmd_args else ""
                    if subcmd == "LIST":
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "module_list",
                                "dst_port": self.port,
                            },
                            attack_type="REDIS_ENUM",
                            severity="LOW",
                        )
                        writer.write(
                            b"*1\r\n" + self._resp_mixed_array(["name", "bf", "ver", 80600])
                        )
                    else:
                        module_path = cmd_args[1] if len(cmd_args) > 1 else ""
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "module",
                                "subcmd": subcmd,
                                "path": module_path[:200],
                                "dst_port": self.port,
                            },
                            attack_type="REDIS_MODULE_INJECT",
                            severity="CRITICAL",
                        )
                        writer.write(self._resp_error("Loading modules is not allowed"))

                # --- EVAL (Lua RCE) ---
                elif cmd == "EVAL":
                    script = cmd_args[0] if cmd_args else ""
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "eval",
                            "script": script[:500],
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_LUA_RCE",
                        severity="CRITICAL",
                    )
                    writer.write(self._resp_error("Scripting is disabled"))

                # --- redis-poc exploit surface (RESTORE / streams / RedisBloom) ---
                elif (
                    cmd == "RESTORE" or cmd in _STREAM_CMDS or cmd.startswith(("TOPK.", "TDIGEST."))
                ):
                    self._handle_exploit_cmd(cmd, cmd_args, peer, writer)

                # --- FLUSHALL / FLUSHDB ---
                elif cmd in ("FLUSHALL", "FLUSHDB"):
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "flush",
                            "command": cmd,
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_FLUSH",
                        severity="HIGH",
                    )
                    writer.write(self._resp_simple("OK"))

                # --- SAVE / BGSAVE ---
                elif cmd in ("SAVE", "BGSAVE"):
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "save",
                            "command": cmd,
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_SAVE",
                        severity="HIGH",
                    )
                    writer.write(self._resp_simple("OK"))

                # --- SET / GET / DEL / KEYS ---
                elif cmd == "SET":
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "set",
                            "key": (cmd_args[0] if cmd_args else "")[:100],
                            "value": (cmd_args[1] if len(cmd_args) > 1 else "")[:200],
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_WRITE",
                        severity="MEDIUM",
                    )
                    writer.write(self._resp_simple("OK"))

                elif cmd == "GET":
                    writer.write(self._resp_bulk(None))

                elif cmd in ("KEYS", "SCAN"):
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "enum",
                            "command": cmd,
                            "pattern": cmd_args[0] if cmd_args else "*",
                            "dst_port": self.port,
                        },
                        attack_type="REDIS_ENUM",
                        severity="MEDIUM",
                    )
                    writer.write(self._resp_array([]))

                elif cmd == "DBSIZE":
                    writer.write(self._resp_integer(0))

                elif cmd == "CLIENT":
                    writer.write(self._resp_bulk("id=1 addr=127.0.0.1:0 fd=5 name= db=0"))

                elif cmd == "SELECT":
                    writer.write(self._resp_simple("OK"))

                elif cmd in ("QUIT", "EXIT"):
                    writer.write(self._resp_simple("OK"))
                    break

                elif cmd == "COMMAND":
                    writer.write(self._resp_array([]))

                # --- Unknown ---
                else:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "unknown",
                            "command": " ".join(args)[:300],
                            "dst_port": self.port,
                        },
                    )
                    writer.write(self._resp_error(f"unknown command '{cmd}'"))

                await writer.drain()

        except (
            TimeoutError,
            ConnectionError,
            BrokenPipeError,
        ) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)

        # Log session summary if any commands were received
        if commands_received:
            self._detect_exploit_chain(commands_received, peer)
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "session_end",
                    "commands": len(commands_received),
                    "auth_attempts": len(auth_attempts),
                    "command_list": commands_received[:30],
                    "dst_port": self.port,
                },
            )


if __name__ == "__main__":
    RedisHoneypot().run()
