"""
honeypots/hp_memcached.py — Modular Memcached honeypot service
================================================================
Emulates a Memcached 1.6 server with text protocol. Captures stats
enumeration, cachedump data theft, flush_all, and cache poisoning.

Run standalone:
    python -m honeypots.hp_memcached
    HP_MEMCACHED_PORT=11211 python -m honeypots.hp_memcached
"""

from __future__ import annotations

import asyncio
import logging
import time

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(data: bytes, max_len: int = 500) -> str:
    return data.decode(errors="ignore").replace("\x00", "").strip()[:max_len]


_UPTIME = int(time.time()) - 847293

_FAKE_STATS = f"""\
STAT pid 12345
STAT uptime 847293
STAT time {int(time.time())}
STAT version 1.6.22
STAT pointer_size 64
STAT rusage_user 4.280000
STAT rusage_system 8.120000
STAT max_connections 1024
STAT curr_connections 5
STAT total_connections 1847
STAT rejected_connections 0
STAT connection_structures 10
STAT cmd_get 28493
STAT cmd_set 9281
STAT cmd_flush 0
STAT get_hits 24102
STAT get_misses 4391
STAT delete_misses 0
STAT delete_hits 0
STAT bytes_read 2847293
STAT bytes_written 19283744
STAT limit_maxbytes 67108864
STAT accepting_conns 1
STAT listen_disabled_num 0
STAT threads 4
STAT curr_items 0
STAT total_items 0
STAT evictions 0
STAT reclaimed 0
END\r\n"""

_FAKE_STATS_SLABS = """\
STAT 1:chunk_size 96
STAT 1:chunks_per_page 10922
STAT 1:total_pages 1
STAT 1:total_chunks 10922
STAT 1:used_chunks 0
STAT 1:free_chunks 10922
STAT 1:free_chunks_end 0
STAT 1:mem_requested 0
STAT 1:get_hits 0
STAT 1:cmd_set 0
STAT 1:delete_hits 0
STAT 1:cas_hits 0
STAT 1:cas_badval 0
STAT active_slabs 1
STAT total_malloced 1048576
END\r\n"""

_FAKE_STATS_ITEMS = """\
STAT items:1:number 0
STAT items:1:age 0
STAT items:1:evicted 0
STAT items:1:outofmemory 0
END\r\n"""


class MemcachedHoneypot(BaseHoneypot):
    """Interactive Memcached honeypot with text protocol."""

    PROTOCOL = "memcached"
    DEFAULT_PORT = 11211
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    async def handle_connection(self, reader, writer, peer):
        commands_received = []

        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30)
                except TimeoutError:
                    break
                if not line:
                    break

                cmd_line = _sanitize(line)
                if not cmd_line:
                    continue

                parts = cmd_line.split()
                cmd = parts[0].lower()
                commands_received.append(cmd_line[:200])

                # --- stats ---
                if cmd == "stats":
                    subcmd = parts[1].lower() if len(parts) > 1 else ""

                    if subcmd == "slabs":
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "stats_slabs",
                                "dst_port": self.port,
                            },
                            attack_type="MEMCACHED_ENUM",
                            severity="LOW",
                        )
                        writer.write(_FAKE_STATS_SLABS.encode())

                    elif subcmd == "items":
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "stats_items",
                                "dst_port": self.port,
                            },
                            attack_type="MEMCACHED_ENUM",
                            severity="MEDIUM",
                        )
                        writer.write(_FAKE_STATS_ITEMS.encode())

                    elif subcmd == "cachedump":
                        slab = parts[2] if len(parts) > 2 else "0"
                        limit = parts[3] if len(parts) > 3 else "0"
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "cachedump",
                                "slab": slab,
                                "limit": limit,
                                "dst_port": self.port,
                            },
                            attack_type="MEMCACHED_DUMP",
                            severity="HIGH",
                        )
                        writer.write(b"END\r\n")

                    else:
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "stats",
                                "section": subcmd or "general",
                                "dst_port": self.port,
                            },
                            attack_type="MEMCACHED_ENUM",
                            severity="MEDIUM",
                        )
                        writer.write(_FAKE_STATS.encode())

                # --- version ---
                elif cmd == "version":
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "version",
                            "dst_port": self.port,
                        },
                        attack_type="MEMCACHED_ENUM",
                        severity="LOW",
                    )
                    writer.write(b"VERSION 1.6.22\r\n")

                # --- get ---
                elif cmd == "get" or cmd == "gets":
                    keys = parts[1:] if len(parts) > 1 else ["?"]
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "get",
                            "keys": [k[:100] for k in keys[:10]],
                            "dst_port": self.port,
                        },
                        attack_type="MEMCACHED_READ",
                        severity="LOW",
                    )
                    writer.write(b"END\r\n")

                # --- set / add / replace / append / prepend ---
                elif cmd in ("set", "add", "replace", "append", "prepend"):
                    key = parts[1] if len(parts) > 1 else ""
                    # Read the data block (flags exptime bytes\r\ndata\r\n)
                    nbytes = 0
                    if len(parts) >= 5:
                        try:
                            nbytes = int(parts[4])
                        except (
                            ValueError
                        ) as exc:  # silent: expected from malformed memcached command
                            logging.getLogger(__name__).debug("ignored: %s", exc)
                    if 0 < nbytes < 65536:
                        try:
                            data = await asyncio.wait_for(
                                reader.readexactly(nbytes + 2), timeout=10
                            )
                            value = _sanitize(data[:nbytes], 200)
                        except (TimeoutError, ConnectionError):
                            value = ""
                    else:
                        value = ""

                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "write",
                            "command": cmd,
                            "key": key[:100],
                            "value": value[:200],
                            "bytes": nbytes,
                            "dst_port": self.port,
                        },
                        attack_type="MEMCACHED_WRITE",
                        severity="MEDIUM",
                    )
                    writer.write(b"STORED\r\n")

                # --- delete ---
                elif cmd == "delete":
                    key = parts[1] if len(parts) > 1 else ""
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "delete",
                            "key": key[:100],
                            "dst_port": self.port,
                        },
                        attack_type="MEMCACHED_WRITE",
                        severity="MEDIUM",
                    )
                    writer.write(b"NOT_FOUND\r\n")

                # --- flush_all ---
                elif cmd == "flush_all":
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "flush",
                            "dst_port": self.port,
                        },
                        attack_type="MEMCACHED_FLUSH",
                        severity="HIGH",
                    )
                    writer.write(b"OK\r\n")

                # --- quit ---
                elif cmd == "quit":
                    break

                # --- unknown ---
                else:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "unknown",
                            "command": cmd_line[:300],
                            "dst_port": self.port,
                        },
                    )
                    writer.write(b"ERROR\r\n")

                await writer.drain()

        except (
            TimeoutError,
            ConnectionError,
            BrokenPipeError,
        ) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)

        if commands_received:
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "session_end",
                    "commands": len(commands_received),
                    "command_list": commands_received[:20],
                    "dst_port": self.port,
                },
            )


if __name__ == "__main__":
    MemcachedHoneypot().run()
