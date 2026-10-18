"""
ingest.py — Sensor Event Ingestion Pipeline (Enhanced)

NOTE (port 1.0): importing this module performs four schema checks against the database
(_has_attack_column, _has_attack_table, _has_dissection_columns, _has_ics_table), each
with its own connection. Without a database the module imports and degrades silently; with
an unreachable host each check waits DB_CONNECT_TIMEOUT. Inherited from 0.9, to be moved
into main() in a separate step.
=======================================================
Reads events.json produced by sensor.py, enriches each event with
protocol detection, port entropy, scan score, OS fingerprint data,
and optional PCAP analysis, then upserts into sensor_events.

PCAPs are deleted after successful ingestion.

Requires: Python >= 3.9 (Rocky Linux 9 default)

Run manually or from cron:
    python ingest.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import psycopg2
from scapy.all import IP, TCP, UDP, rdpcap

# In 0.9 each of these imports sat in a try/except ImportError with a _HAS_* flag, because
# the modules lay loose and depended on sys.path. In the package they are always present; the
# only genuinely optional thing — the "analyze_pcap" PCAP analyser — did not exist even in
# 0.9, so that branch never worked and has been removed.
#
# JA4+ (JA4S/H/X/SSH/T) is deliberately not imported here: when the honeylens_ja4_plus
# plugin is loaded, the ingest paths take the variants from the plugin registry on demand.
from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.ja3 import identify_ja3, parse_client_hello, parse_server_hello
from honeylens.classification.ja4 import parse_tls_client_hello_ja4
from honeylens.classification.scoring import classify_attack_summary, get_severity
from honeylens.config import EVENTS_JSON, PCAP_DIR
from honeylens.dissection import CachedState as _DissectionCache
from honeylens.ingest.ics_helpers import ics_port_consistent, pick_ics_mitre
from honeylens.ingest.pcap_export_hook import queue_export_candidate
from honeylens.sanitise import safe_json_dumps, safe_str, strip_nul

logger = logging.getLogger("honeylens.ingest.ebpf")

# Shared deep-dissection port state (Idea 30); same refresh cadence as sensor.py.
_DISSECTION_STATE = _DissectionCache(refresh_sec=30)


# ---------------------------------------------------------------------------
# NUL byte sanitisation — PostgreSQL text columns cannot contain 0x00
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# JA3 TLS Fingerprint Extraction
# ---------------------------------------------------------------------------


def extract_ja3_from_pcap(pcap_path: str) -> dict | None:
    """
    Extract JA3 fingerprint from TLS ClientHello in a PCAP file.

    Returns dict with ja3_hash, ja3_string, sni, identified client, etc.
    Returns None if no TLS ClientHello found or JA3 module not available.
    """
    try:
        packets = rdpcap(pcap_path)

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue

            payload = bytes(pkt[TCP].payload)

            # Check for TLS Handshake (0x16) + ClientHello (0x01 at offset 5)
            if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
                ja3_info = parse_client_hello(payload)
                if ja3_info:
                    # Add identification if known
                    if ja3_info.get("ja3_hash"):
                        identified = identify_ja3(ja3_info["ja3_hash"])
                        if identified:
                            ja3_info["ja3_identified"] = identified
                    return ja3_info

            # Also check for TLS ServerHello to get JA3S
            if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x02:
                ja3s_info = parse_server_hello(payload)
                if ja3s_info:
                    return {"ja3s": ja3s_info}

        return None

    except Exception as e:
        logger.debug("JA3 extraction failed for %s: %s", pcap_path, e)
        return None


def extract_ja3_from_payload(payload: bytes) -> dict | None:
    """
    Extract JA3 fingerprint directly from raw payload bytes.

    Useful when the payload is already extracted from a packet.
    """
    if not payload:
        return None

    try:
        # Check for TLS ClientHello
        if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
            ja3_info = parse_client_hello(payload)
            if ja3_info and ja3_info.get("ja3_hash"):
                identified = identify_ja3(ja3_info["ja3_hash"])
                if identified:
                    ja3_info["ja3_identified"] = identified
            return ja3_info
        return None
    except Exception as e:
        logger.debug("JA3 payload extraction error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db():
    from honeylens.database import legacy_get_db

    return legacy_get_db()


# ---------------------------------------------------------------------------
# Analytics helpers
# ---------------------------------------------------------------------------


def calculate_entropy(ports: list[int]) -> float:
    if not ports:
        return 0.0
    counter = Counter(ports)
    total = len(ports)
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def calculate_scan_score(
    unique_ports: int, entropy: float, payload_size: int, scan_type: str = ""
) -> float:
    score = unique_ports * 0.6 + entropy * 2.5
    if payload_size == 0:
        score += 2
    if scan_type and scan_type != "Normal Traffic":
        score += 3
    return round(score, 2)


def detect_protocol(pkt) -> str:
    """
    Layer-7 protocol heuristic from packet payload.

    Signature references:
      - Wireshark SampleCaptures:  https://wiki.wireshark.org/SampleCaptures
      - Wireshark dissector source: https://gitlab.com/wireshark/wireshark/-/tree/master/epan/dissectors
      - TLS record types:  RFC 8446 §5.1 — ContentType 0x14-0x18, version 0x03xx
      - MQTT fixed header:  OASIS MQTT v3.1.1/v5.0 — byte[0]=PacketType<<4|Flags
      - Modbus TCP MBAP:   Modbus spec §3.1.3 — protocol_id MUST be 0x0000
      - SMB:  MS-SMB §2.1 — magic \\xFFSMB; MS-SMB2 §2.1 — magic \\xFESMB
      - DNP3: IEEE 1815 — start bytes 0x05 0x64

    Classification order matters — more specific / unambiguous signatures
    must come BEFORE loose heuristics to prevent false positives.
    For example, TLS ClientHello (0x16 0x03) must be checked before MQTT
    because 0x16 >> 4 == 1 would falsely match the MQTT CONNECT type.
    """
    if pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
        plen = len(payload)
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if plen == 0:
            # No payload — classify by TCP flags / port heuristic
            flags = pkt[TCP].flags
            if flags == 0x02:  # SYN only
                return "TCP/SYN"
            if flags == 0x12:  # SYN-ACK
                return "TCP/SYN-ACK"
            return "TCP"

        # ---- Unambiguous multi-byte signatures (check first) ----

        # TLS / SSL — ContentType 0x16 (Handshake) + version 0x03xx
        # Must come before MQTT: 0x16 >> 4 == 1 would false-match MQTT
        if plen >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
            if payload[2] == 0x03:
                return "TLS/1.2+"
            if payload[2] == 0x01:
                return "TLS/1.0"
            return "TLS"

        # TLS other record types (ChangeCipherSpec=0x14, Alert=0x15,
        # ApplicationData=0x17, Heartbeat=0x18) — still TLS
        # Ref: RFC 8446 §5.1, RFC 6520 (Heartbeat), Wireshark "packet-tls.c"
        if plen >= 3 and payload[0] in (0x14, 0x15, 0x17, 0x18) and payload[1] == 0x03:
            return "TLS"

        # SSH — starts with "SSH-"
        if payload[:4] == b"SSH-":
            return "SSH"

        # HTTP request methods
        if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"PATC", b"OPTI"):
            return "HTTP"

        # HTTP response
        if payload[:5] == b"HTTP/":
            return "HTTP"

        # ---- Protocol-specific binary signatures ----

        # TPKT header: version=3, reserved=0 — shared by RDP, S7comm, COTP
        # Ref: Wireshark dissectors "tpkt"/"rdp"/"s7comm", RFC 1006
        # SampleCaptures: "S7COMM - S7 Communication", "CredSSP" (RDP/NLA)
        if plen >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
            if dport == 102 or sport == 102:
                return "S7comm"
            return "RDP"

        # MySQL server greeting
        # Ref: Wireshark dissector "mysql", SampleCaptures "MySQL protocol"
        # Wire format: pkt_len(3 LE) + seq_id(1) + protocol_ver(1=0x0a) + version_str
        # Also match MySQL client login (starts with pkt_len + seq + caps)
        if plen >= 5 and (dport == 3306 or sport == 3306):
            proto_ver = payload[4]
            if proto_ver == 0x0A:  # Standard greeting
                return "MySQL"
            # Client auth response has capability flags
            return "MySQL"

        # PostgreSQL — startup message: length(4 bytes) + protocol version 196608 (3.0)
        # or SSLRequest magic 80877103
        if plen >= 8:
            try:
                struct.unpack(">I", payload[0:4])[0]
                version = struct.unpack(">I", payload[4:8])[0]
                if version == 196608:  # Protocol 3.0
                    return "PostgreSQL"
                if version == 80877103:  # SSLRequest
                    return "PostgreSQL/SSL"
            except struct.error:
                pass  # silent: malformed packet header

        # PostgreSQL server responses — single-byte tag + 4-byte length
        if plen >= 5 and payload[0:1] in (b"R", b"E", b"K", b"S", b"Z"):
            try:
                msg_body_len = struct.unpack(">I", payload[1:5])[0]
                if 4 < msg_body_len < 65536:
                    return "PostgreSQL"
            except struct.error:
                pass  # silent: malformed packet header

        # Modbus TCP — MBAP header: transaction_id(2) + protocol_id(2, MUST be 0x0000) +
        # length(2) + unit_id(1) + function_code(1)
        # Ref: Wireshark dissector "mbtcp", Modbus Application Protocol Specification
        # SampleCaptures: captures using port 502
        # protocol_id MUST be 0x0000, length 1..253, unit_id 0..247,
        # function_code 1..127 (MSB=0 for request, MSB=1 for exception)
        if plen >= 8 and payload[2:4] == b"\x00\x00":
            modbus_len = struct.unpack(">H", payload[4:6])[0]
            unit_id = payload[6]
            func_code = payload[7]
            if 1 <= modbus_len <= 253 and unit_id <= 247 and 1 <= (func_code & 0x7F) <= 127:
                return "Modbus"

        # MQTT CONNECT — fixed header: type=1 (upper nibble), remaining length
        # Byte 0: 0x10 (CONNECT, no flags) — must be exactly 0x10, not 0x16!
        if plen >= 4 and payload[0] == 0x10:
            # Validate: bytes after variable-length should contain "MQTT" or "MQIs"
            # Skip variable-length encoding (1-4 bytes)
            idx = 1
            remaining = 0
            shift = 0
            for _ in range(4):
                if idx >= plen:
                    break
                b = payload[idx]
                remaining |= (b & 0x7F) << shift
                idx += 1
                shift += 7
                if not (b & 0x80):
                    break
            # Protocol name should be "MQTT" or "MQIsdp"
            if idx + 4 <= plen:
                proto_name_len = struct.unpack(">H", payload[idx : idx + 2])[0]
                proto_name = payload[idx + 2 : idx + 2 + proto_name_len]
                if proto_name in (b"MQTT", b"MQIsdp"):
                    return "MQTT"
            # If we can't validate the inner protocol name, still flag if
            # the port is a known MQTT port
            if dport in (1883, 8883):
                return "MQTT"

        # Other MQTT packet types (PUBLISH=3, SUBSCRIBE=8, etc.) on known ports
        if dport in (1883, 8883) or sport in (1883, 8883):
            pkt_type = (payload[0] >> 4) & 0x0F
            if 1 <= pkt_type <= 14:
                return "MQTT"

        # Oracle TNS — packet_length(2) + packet_checksum(2) + type(1)
        # Type 1 = Connect, 2 = Accept, 4 = Refuse, 6 = Data, 12 = Resend
        # Ref: Wireshark dissector "tns", SampleCaptures "Oracle TNS"
        if plen >= 8 and (dport == 1521 or sport == 1521):
            tns_type = payload[4]
            if tns_type in (1, 2, 4, 5, 6, 11, 12):
                return "Oracle/TNS"

        # Java RMI — magic "JRMI"
        if payload[:4] == b"JRMI":
            return "Java-RMI"

        # SMTP — server greeting "220 "
        if payload[:4] == b"220 " and (dport == 25 or sport == 25 or dport == 587):
            return "SMTP"

        # FTP — server greeting "220 " on port 21
        if payload[:4] == b"220 " and (dport == 21 or sport == 21):
            return "FTP"

        # Telnet — IAC negotiation (0xFF 0xFB/0xFD/0xFE/0xFC ...)
        if plen >= 3 and payload[0] == 0xFF and payload[1] in (0xFB, 0xFC, 0xFD, 0xFE):
            return "Telnet"

        # DNS over TCP — 2-byte length prefix + DNS header
        if plen >= 14 and (dport == 53 or sport == 53):
            return "DNS/TCP"

        # EtherNet/IP — encapsulation header, command at bytes 0-1
        # Ref: [WS:enip]
        if dport == 44818 or sport == 44818:
            return "EtherNet/IP"

        # BACnet/IP over TCP (rare but possible)
        if dport == 47808 or sport == 47808:
            return "BACnet"

        # VNC — "RFB " protocol version
        if payload[:4] == b"RFB ":
            return "VNC"

        # Redis — RESP protocol or inline commands (with Redis-specific context)
        # RESP arrays start with *<count>\r\n$<len>\r\n
        # Inline commands: PING, INFO, CONFIG, CLIENT, DBSIZE, etc.
        # Avoid matching SMTP "AUTH LOGIN" by requiring Redis-specific patterns
        if payload[:5] == b"*1\r\n$" or payload[:5] == b"*2\r\n$" or payload[:5] == b"*3\r\n$":
            return "Redis"
        # Redis inline PING (exactly "PING\r\n" or just "PING")
        if payload[:4] == b"PING" and (plen == 4 or payload[4:6] == b"\r\n"):
            return "Redis"
        # Redis INFO, CONFIG, CLIENT, DBSIZE, KEYS, SCAN commands
        if payload[:4] in (b"INFO", b"KEYS", b"SCAN", b"TYPE", b"ECHO") and (
            plen == 4 or payload[4:5] in (b"\r", b" ")
        ):
            return "Redis"
        if payload[:6] in (b"CONFIG", b"CLIENT", b"DBSIZE", b"SELECT", b"FLUSHD"):
            return "Redis"
        # Redis AUTH requires Redis port context to avoid SMTP "AUTH LOGIN"
        if payload[:4] == b"AUTH" and dport == 6379:
            return "Redis"

        # MSSQL TDS — TDS packet type at byte 0: 0x12 = pre-login, 0x07 = login7
        if plen >= 8 and payload[0] in (0x12, 0x07, 0x04) and (dport == 1433 or sport == 1433):
            return "MSSQL/TDS"

        # LDAP — BER-encoded sequence (0x30) on LDAP ports
        # Ref: Wireshark dissector "ldap", heuristic on BER SEQUENCE tag
        if payload[0] == 0x30 and dport in (389, 636, 3268, 3269):
            return "LDAP"

        # SMB/SMB2 — NetBIOS session header + SMB magic
        # Ref: Wireshark dissectors "smb" (\xFFSMB) and "smb2" (\xFESMB)
        if plen >= 8:
            if payload[4:8] == b"\xffSMB" or payload[4:8] == b"\xfeSMB":
                return "SMB"

        # DNP3 — Distributed Network Protocol 3, used in SCADA/ICS
        # Ref: Wireshark dissector "dnp3", magic bytes 0x0564
        if plen >= 2 and payload[0] == 0x05 and payload[1] == 0x64:
            return "DNP3"

        # IEC 60870-5-104 — SCADA telecontrol, APCI starts with 0x68
        # Ref: Wireshark dissector "iec60870_104", port 2404
        if plen >= 2 and payload[0] == 0x68 and (dport == 2404 or sport == 2404):
            return "IEC-104"

        # RTSP — Real Time Streaming Protocol
        # Ref: Wireshark dissector "rtsp"
        if payload[:5] == b"RTSP/" or payload[:8] in (
            b"DESCRIBE",
            b"ANNOUNCE",
            b"SETUP   ",
            b"PLAY    ",
        ):
            return "RTSP"
        if payload[:5] in (b"DESCR", b"ANNOU", b"SETUP", b"PLAY ", b"TEARS", b"PAUSE"):
            if dport == 554 or sport == 554:
                return "RTSP"

        # SIP — Session Initiation Protocol
        # Ref: Wireshark dissector "sip"
        if payload[:4] in (b"SIP/", b"INVI", b"REGI", b"OPTI", b"BYE ", b"ACK ", b"CANC"):
            return "SIP"
        if dport == 5060 or sport == 5060:
            return "SIP"

        # IMAP — Internet Message Access Protocol
        # Ref: Wireshark dissector "imap", port 143/993
        if dport in (143, 993) or sport in (143, 993):
            if plen >= 4 and (payload[:2] == b"* " or payload[:4] in (b"A001", b"a001")):
                return "IMAP"

        # POP3 — Post Office Protocol
        # Ref: Wireshark dissector "pop", port 110/995
        if dport in (110, 995) or sport in (110, 995):
            if payload[:3] in (b"+OK", b"-ER"):
                return "POP3"

        # IRC — Internet Relay Chat
        # Ref: Wireshark dissector "irc", common commands
        if payload[:4] in (b"NICK", b"USER", b"JOIN", b"PRIV", b"PING", b"PONG", b"QUIT"):
            if dport in (6667, 6668, 6669, 6697) or sport in (6667, 6668, 6669, 6697):
                return "IRC"

        # XMPP / Jabber
        # Ref: Wireshark dissector "xmpp"
        if b"<stream:stream" in payload[:64] or b"jabber" in payload[:64]:
            return "XMPP"

        # Bitcoin protocol — magic bytes vary by network
        # Ref: Wireshark dissector "bitcoin"
        if plen >= 4 and payload[:4] in (b"\xf9\xbe\xb4\xd9", b"\xfa\xbf\xb5\xda"):
            return "Bitcoin"

        # SCTP-over-TCP is unusual but DIAMETER is common on 3868
        # Ref: Wireshark dissector "diameter"
        if dport == 3868 or sport == 3868:
            return "Diameter"

        # Kafka — port-based, binary protocol
        if dport == 9092 or sport == 9092:
            return "Kafka"

        # Memcached — text protocol or binary (0x80/0x81 magic)
        if dport == 11211 or sport == 11211:
            if plen >= 1 and payload[0] in (0x80, 0x81):
                return "Memcached/bin"
            return "Memcached"

        # Elasticsearch — HTTP on port 9200
        if dport == 9200 or sport == 9200:
            return "Elasticsearch"

        # Generic fallback
        return "TCP"

    if pkt.haslayer(UDP):
        payload = bytes(pkt[UDP].payload)
        plen = len(payload)
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport

        # Ref: Wireshark dissector "dns"
        if dport == 53 or sport == 53:
            return "DNS"
        # Ref: Wireshark dissector "ntp"
        if dport == 123 or sport == 123:
            return "NTP"
        # Ref: Wireshark dissector "snmp"
        if dport == 161 or sport == 161 or dport == 162:
            return "SNMP"
        # Ref: Wireshark dissector "syslog"
        if dport == 514 or sport == 514:
            return "Syslog"
        if dport == 1883:
            return "MQTT"
        # Ref: Wireshark dissector "mdns"
        if dport == 5353 or sport == 5353:
            return "mDNS"
        # Ref: Wireshark dissector "ssdp"
        if dport == 1900 or sport == 1900:
            return "SSDP"
        # Ref: Wireshark dissector "bacnet"
        if dport == 47808 or sport == 47808:
            return "BACnet"
        # Ref: Wireshark dissector "vxlan"
        if dport == 4789:
            return "VXLAN"
        # Ref: Wireshark dissectors "isakmp"/"ike"
        if dport in (500, 4500) or sport in (500, 4500):
            return "IKE"

        # Ref: Wireshark dissector "dhcp" (was "bootp")
        if (dport == 67 and sport == 68) or (dport == 68 and sport == 67):
            return "DHCP"

        # Ref: Wireshark dissector "tftp"
        if dport == 69 or sport == 69:
            return "TFTP"

        # Ref: Wireshark dissector "sip" (SIP over UDP)
        if dport == 5060 or sport == 5060:
            return "SIP"

        # Ref: Wireshark dissector "rtp" — even port, version=2 in first nibble
        if plen >= 12 and (payload[0] >> 6) == 2:
            if dport % 2 == 0 and dport >= 1024:
                return "RTP"

        # Ref: Wireshark dissector "radius"
        if dport in (1812, 1813) or sport in (1812, 1813):
            return "RADIUS"

        # Ref: Wireshark dissector "nbns" / NetBIOS
        if dport == 137 or sport == 137 or dport == 138:
            return "NetBIOS"

        # Ref: Wireshark dissector "stun"
        if dport == 3478 or sport == 3478:
            return "STUN"

        # Ref: Wireshark dissector "coap"
        if dport == 5683 or sport == 5683:
            return "CoAP"

        # Ref: Wireshark dissector "wireguard"
        if dport == 51820 or sport == 51820:
            return "WireGuard"

        # Ref: Wireshark dissector "quic" — long header form bit
        if (
            plen >= 5
            and (payload[0] & 0x80)
            and payload[1:5]
            in (
                b"\x00\x00\x00\x01",  # QUIC v1
                b"\xff\x00\x00\x1d",  # draft-29
                b"\xff\x00\x00\x1e",  # draft-30
            )
        ):
            return "QUIC"
        # QUIC on 443
        if dport == 443 or sport == 443:
            if plen >= 1 and (payload[0] & 0x80):
                return "QUIC"

        return "UDP"

    # ICMP
    if pkt.haslayer("ICMP"):
        return "ICMP"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Ingestion — detect schema at startup
# ---------------------------------------------------------------------------


def _has_attack_column() -> bool:
    """Check if sensor_events has the attack_types column."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'sensor_events' AND column_name = 'attack_types'
            )
        """)
        result = cur.fetchone()[0]
        conn.close()
        return result
    except Exception as e:
        logger.debug("Schema check for attack_types column: %s", e)
        return False


def _has_attack_table() -> bool:
    """Check if attack_patterns table exists."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'attack_patterns'
            )
        """)
        result = cur.fetchone()[0]
        conn.close()
        return result
    except Exception as e:
        logger.debug("Schema check for attack_patterns table: %s", e)
        return False


_HAS_ATK_COL = _has_attack_column()
_HAS_ATK_TBL = _has_attack_table()


def _has_dissection_columns():
    """Check if Idea 30 Phase 0 columns are present on sensor_events."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name FROM information_schema.columns
             WHERE table_name = 'sensor_events'
               AND column_name IN ('full_payload', 'full_payload_hash', 'tcp_seq')
        """)
        cols = {r[0] for r in cur.fetchall()}
        conn.close()
        return cols == {"full_payload", "full_payload_hash", "tcp_seq"}
    except Exception as e:
        logger.debug("Schema check for dissection columns: %s", e)
        return False


_HAS_DISSECTION_COLS = _has_dissection_columns()

# Cached port → depth state for full-payload storage gating. Refreshes from
# DB (ebpf_dissection_ports) every 30 s; same cadence as sensor.py's BPF
# map reconciliation thread, so the two converge on identical state.


def _has_ics_table() -> bool:
    """Check if ics_events table exists."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'ics_events'
            )
        """)
        result = cur.fetchone()[0]
        conn.close()
        return result
    except Exception as e:
        logger.debug("Schema check for ics_events table: %s", e)
        return False


_HAS_ICS_TBL = _has_ics_table()
if _HAS_ICS_TBL:
    logger.info("ics_events table found — ICS/OT detection enabled")
else:
    logger.info("ics_events table not found — run setup_db.py to enable ICS detection")


# ICS protocol identifiers
ICS_PROTOCOLS = {
    "MODBUS": {"ports": [502], "name": "Modbus"},
    "DNP3": {"ports": [20000, 19999], "name": "DNP3"},
    "S7COMM": {"ports": [102], "name": "S7comm"},
    "ENIP": {"ports": [44818, 2222], "name": "EtherNet/IP"},
    "BACNET": {"ports": [47808], "name": "BACnet"},
    "OPCUA": {"ports": [4840], "name": "OPC-UA"},
    "IEC104": {"ports": [2404], "name": "IEC-104"},
    "MQTT": {"ports": [1883, 8883], "name": "MQTT"},
}

# ICS function code classifications
ICS_FUNCTION_CLASSES = {
    # Modbus
    # ── text-rule names (MODBUS attack_type) ────────────────────────────────
    "modbus_read_coils": {"fc": 1, "is_read": True, "severity": "LOW"},
    "modbus_read_discrete": {"fc": 2, "is_read": True, "severity": "LOW"},
    "modbus_read_holding": {"fc": 3, "is_read": True, "severity": "LOW"},
    "modbus_read_input": {"fc": 4, "is_read": True, "severity": "LOW"},
    "modbus_write_single_coil": {"fc": 5, "is_write": True, "severity": "HIGH"},
    "modbus_write_single_register": {"fc": 6, "is_write": True, "severity": "HIGH"},
    "modbus_write_multiple_coils": {"fc": 15, "is_write": True, "severity": "HIGH"},
    "modbus_write_multiple_registers": {"fc": 16, "is_write": True, "severity": "HIGH"},
    "modbus_mask_write_register": {"fc": 22, "is_write": True, "severity": "HIGH"},
    "modbus_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_diagnostics": {"fc": 8, "is_control": True, "severity": "HIGH"},
    "modbus_restart_comm": {"fc": 8, "is_control": True, "severity": "CRITICAL"},
    # ── binary-detector names (ICS_ATTACK attack_type) ──────────────────────
    "modbus_fc01_read_coils": {"fc": 1, "is_read": True, "severity": "LOW"},
    "modbus_fc02_read_discrete_inputs": {"fc": 2, "is_read": True, "severity": "LOW"},
    "modbus_fc03_read_holding_registers": {"fc": 3, "is_read": True, "severity": "LOW"},
    "modbus_fc04_read_input_registers": {"fc": 4, "is_read": True, "severity": "LOW"},
    "modbus_fc05_write_single_coil": {"fc": 5, "is_write": True, "severity": "HIGH"},
    "modbus_fc06_write_single_register": {"fc": 6, "is_write": True, "severity": "HIGH"},
    "modbus_fc08_diagnostics": {"fc": 8, "is_control": True, "severity": "HIGH"},
    "modbus_fc15_write_multiple_coils": {"fc": 15, "is_write": True, "severity": "HIGH"},
    "modbus_fc16_write_multiple_registers": {"fc": 16, "is_write": True, "severity": "HIGH"},
    "modbus_fc17_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_fc22_mask_write_register": {"fc": 22, "is_write": True, "severity": "HIGH"},
    "modbus_fc23_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_fc43_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_illegal_fc": {"is_anomaly": True, "severity": "HIGH"},
    "modbus_user_defined_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    "modbus_reserved_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    "modbus_broadcast_attack": {"is_write": True, "is_control": True, "severity": "HIGH"},
    "modbus_write_zeros": {"is_write": True, "severity": "HIGH"},
    "modbus_write_max_value": {"is_write": True, "severity": "HIGH"},
    # S7comm
    "s7comm_stop_cpu": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_write_var": {"is_write": True, "severity": "HIGH"},
    "s7comm_download_block": {"is_write": True, "severity": "CRITICAL"},
    # DNP3
    "dnp3_cold_restart": {"is_control": True, "severity": "CRITICAL"},
    "dnp3_warm_restart": {"is_control": True, "severity": "HIGH"},
    "dnp3_direct_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_write_request": {"is_write": True, "severity": "HIGH"},
    # BACnet
    "bacnet_write_property": {"is_write": True, "severity": "HIGH"},
    "bacnet_reinitialize": {"is_control": True, "severity": "CRITICAL"},
    # OPC-UA
    "opcua_write": {"is_write": True, "severity": "HIGH"},
    "opcua_call_method": {"is_control": True, "severity": "HIGH"},
    # IEC-104
    "iec104_single_command": {"is_write": True, "severity": "HIGH"},
    "iec104_double_command": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint": {"is_write": True, "severity": "HIGH"},
    "iec104_reset_process": {"is_control": True, "severity": "CRITICAL"},
}


# ---------------------------------------------------------------------------
# ICS MITRE selector — shared helper used by all ingest paths
# ---------------------------------------------------------------------------
_ICS_RULE_WRITE = frozenset(
    [
        "write",
        "operate",
        "direct_operate",
        "set_attribute",
        "set_password",
        "setpoint",
        "double_command",
        "single_command",
        "regulating_step",
        "download_block",
        "write_var",
        "write_property",
        "write_property_multiple",
        "opcua_write",
        "cip_set_attribute",
        "cip_execute",
        "bacnet_reinitialize",
        "bacnet_reinitialize_device",
        "iec104_setpoint_command",
        "iec104_parameter_change",
    ]
)
_ICS_RULE_CONTROL = frozenset(
    [
        "restart",
        "cold_restart",
        "warm_restart",
        "stop_cpu",
        "plc_stop",
        "plc_control",
        "reset_process",
        "parameter_activation",
        "diagnostics",
        "reinitialize",
        "cip_reset",
        "cip_stop_service",
        "stopdt",
        "disable_unsolicited",
        "dnp3_broadcast",
        "iec104_stopdt_act",
    ]
)
_ICS_RULE_SCAN = frozenset(
    [
        "scanner",
        "shodan",
        "banner_grab",
        "port_scan",
        "nmap",
        "plcscan",
        "plcinfo",
        "aegis",
        "bacpypes",
        "ics_port_scan",
        "ics_shodan_query",
        "ics_banner_grab",
        "metasploit",
        "caldera",
    ]
)
_ICS_RULE_ENUMERATE = frozenset(
    [
        "list_identity",
        "list_services",
        "list_interfaces",
        "list_blocks",
        "whois",
        "whohas",
        "iam",
        "device_discovery",
        "get_attributes",
        "get_all_attributes",
        "interrogation",
        "counter_interrogation",
        "bacnet_whois",
        "bacnet_whohas",
        "enip_list",
        "report_slave_id",
        "read_device_id",
        "find_servers",
        "read_szl",
        "cpu_info",
        "s7comm_header",
        "data_link_probe",
    ]
)
_ICS_RULE_DISCOVERY = frozenset(
    [
        "browse",
        "opcua_browse",
        "opcua_find_servers",
        "opcua_create_subscription",
        "bacnet_subscribe_cov",
        "read_range",
        "history_read",
        "enip_register_session",
        "enip_send_rr_data",
        "register_session",
        "startdt",
        "agent_beacon",
        "c2_api",
        "cotp_connect",
    ]
)
_ICS_RULE_READ = frozenset(
    [
        "read_property",
        "read_property_multiple",
        "read_request",
        "read_attributes",
        "read_command",
        "opcua_read_attributes",
        "bacnet_read_property",
        "bacnet_read_property_multiple",
        "iec104_read_command",
        "dnp3_read_request",
        "clear_restart_iin",
        "enable_unsolicited",
    ]
)


def parse_ics_event(attack_type, rule_name, payload, dst_port, src_ip, dst_ip, src_port):
    """
    Parse an ICS attack detection into an ics_events record.

    Returns dict with ics_events fields, or None if not ICS.
    """
    if attack_type not in ("MODBUS", "ICS_ATTACK"):
        return None

    # Determine protocol from rule name or port
    protocol = None
    if rule_name.startswith("modbus_"):
        protocol = "modbus"
    elif rule_name.startswith("dnp3_"):
        protocol = "dnp3"
    elif rule_name.startswith("s7comm_"):
        protocol = "s7comm"
    elif rule_name.startswith("enip_") or rule_name.startswith("cip_"):
        protocol = "enip"
    elif rule_name.startswith("bacnet_"):
        protocol = "bacnet"
    elif rule_name.startswith("opcua_"):
        protocol = "opcua"
    elif rule_name.startswith("iec104_"):
        protocol = "iec104"
    elif rule_name.startswith("caldera_"):
        protocol = "caldera"
    elif rule_name.startswith("ics_"):
        # Generic ICS - try to detect from port
        if dst_port == 502:
            protocol = "modbus"
        elif dst_port == 102:
            protocol = "s7comm"
        elif dst_port in (20000, 19999):
            protocol = "dnp3"
        elif dst_port == 44818:
            protocol = "enip"
        elif dst_port == 47808:
            protocol = "bacnet"
        elif dst_port == 4840:
            protocol = "opcua"
        elif dst_port == 2404:
            protocol = "iec104"
        else:
            protocol = "ics-generic"
    else:
        protocol = "ics-generic"

    # Direction/port sanity: drop detections whose flow involves no matching
    # ICS service port. This is the sensor's own outbound traffic (e.g. the
    # Ollama API on :11434) misclassified as ICS by the payload-only detectors.
    if not ics_port_consistent(protocol, src_port, dst_port):
        return None

    # Get classification from rule
    fc_info = ICS_FUNCTION_CLASSES.get(rule_name, {})

    # Determine MITRE mapping
    mitre_technique, mitre_tactic = pick_ics_mitre(attack_type, rule_name, fc_info)

    # Extract function code from Modbus payload (if present)
    function_code = fc_info.get("fc")
    function_name = rule_name.replace("modbus_", "").replace("dnp3_", "").replace("s7comm_", "")
    function_name = function_name.replace("_", " ").title()

    # Determine severity
    severity = fc_info.get("severity", "MEDIUM")
    if "scanner" in rule_name or "probe" in rule_name:
        severity = "LOW"
    elif "restart" in rule_name or "stop" in rule_name or "crash" in rule_name:
        severity = "CRITICAL"
    elif "write" in rule_name or "download" in rule_name:
        severity = "HIGH"

    return {
        "protocol": protocol,
        "function_code": function_code,
        "function_name": function_name,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "is_read": fc_info.get("is_read", False),
        "is_write": fc_info.get("is_write", False),
        "is_control": fc_info.get("is_control", False),
        "is_discovery": fc_info.get("is_discovery", False),
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "attack_type": attack_type,
        "rule_name": rule_name,
        "severity": severity,
        "source": "sensor",
    }


_BASE_COLS = (
    "event_id, timestamp, source, protocol, "
    "src_ip, src_port, dst_ip, dst_port, "
    "payload, payload_hash, "
    "scan_score, port_entropy, "
    "ja3, metadata"
)
_BASE_PLACEHOLDERS = ",".join(["%s"] * 14)
_EXTRA_COLS = ""
_EXTRA_PLACEHOLDERS = ""
if _HAS_ATK_COL:
    _EXTRA_COLS += ", attack_types"
    _EXTRA_PLACEHOLDERS += ",%s"
else:
    logger.info("attack_types column not found — running without attack classification")
if _HAS_DISSECTION_COLS:
    _EXTRA_COLS += ", full_payload, full_payload_hash, tcp_seq"
    _EXTRA_PLACEHOLDERS += ",%s,%s,%s"
    logger.info(
        "Idea 30 Phase 0 columns present — full_payload storage enabled for monitored ports"
    )

INSERT_SQL = (
    f"INSERT INTO sensor_events ({_BASE_COLS}{_EXTRA_COLS}) "  # noqa: S608 # nosec B608 — module constants, not external data
    f"VALUES ({_BASE_PLACEHOLDERS}{_EXTRA_PLACEHOLDERS}) "
    f"ON CONFLICT (event_id) DO NOTHING"
)

INSERT_ATTACK_SQL = """
    INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text, severity)
    VALUES (%s, %s, %s, %s, %s)
"""

# ICS events insertion
INSERT_ICS_SQL = """
    INSERT INTO ics_events (
        event_id, timestamp, protocol, function_code, function_name,
        src_ip, src_port, dst_ip, dst_port,
        is_read, is_write, is_control, is_discovery,
        mitre_tactic, mitre_technique, attack_type, rule_name,
        source, severity
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (event_id) DO NOTHING
"""

# JA4+ fingerprint insertion (if table exists)
INSERT_JA4_SQL = """
    INSERT INTO ja4_fingerprints (
        event_id, fingerprint_type, fingerprint,
        fingerprint_a, fingerprint_b, fingerprint_c,
        fingerprint_raw, tls_version, sni, alpn,
        cipher_count, extension_count, identified, metadata
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT DO NOTHING
"""

# Check if ja4_fingerprints table exists
_HAS_JA4_TABLE = False
try:
    from honeylens.database import db_cursor as _db_cursor

    with _db_cursor() as _test_cur:
        _test_cur.execute("""
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'ja4_fingerprints'
        """)
        _HAS_JA4_TABLE = _test_cur.fetchone() is not None
    if _HAS_JA4_TABLE:
        logger.info("ja4_fingerprints table found — JA4+ storage enabled")
    else:
        logger.info("ja4_fingerprints table not found — run setup_db.py to enable JA4+")
except Exception as e:
    logger.debug("Schema check for ja4_fingerprints table: %s", e)


POSITION_FILE = os.path.join(os.path.dirname(EVENTS_JSON), ".ingest_ebpf.pos")
BATCH_SIZE = 500
MAX_EVENTS_FILE_SIZE = 500 * 1024 * 1024  # 500 MB — truncate after full pass


def _get_position() -> int:
    """Read byte offset of last processed position in events.json."""
    try:
        with open(POSITION_FILE) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _save_position(pos: int) -> None:
    try:
        with open(POSITION_FILE, "w") as f:
            f.write(str(pos))
    except OSError as e:
        logger.debug("Could not save position file: %s", e)


def _file_uid(path: Path | str) -> str:
    """Owner uid of `path` as a string, or "?" if it cannot be read."""
    try:
        return str(os.stat(path).st_uid)
    except OSError:
        return "?"


def _truncate_events_json() -> None:
    """Truncate events.json and reset position after full processing.

    Only called when all events have been processed (position == file size)
    and the file exceeds MAX_EVENTS_FILE_SIZE.
    """
    try:
        size = os.path.getsize(EVENTS_JSON)
    except OSError as e:
        logger.debug("Could not stat events.json: %s", e)
        return

    if size <= MAX_EVENTS_FILE_SIZE:
        return

    try:
        with open(EVENTS_JSON, "w"):
            pass  # truncate to 0
    except OSError as e:
        # sensor.py needs CAP_NET_RAW so it runs as root and creates events.json
        # 0644 root:root, while this ingest runs as `sensor`. The truncate then
        # fails with EACCES — and logged at debug, that failure is invisible while
        # the file grows without bound. Found 2026-08-26 on two hosts at once:
        # 7 GB on one (root filesystem at 100%), 72 GB on another. Loud by design.
        logger.warning(
            "Could not truncate events.json (%d MB, owned by uid %s, running as uid %s): "
            "%s — the file will keep growing until the filesystem fills. "
            "Fix the ownership so this ingest can write it.",
            size // (1024 * 1024),
            _file_uid(EVENTS_JSON),
            os.getuid(),
            e,
        )
        return

    _save_position(0)
    logger.info("Truncated events.json (was %d MB)", size // (1024 * 1024))


def ingest() -> None:
    if not os.path.exists(EVENTS_JSON):
        logger.info("No events.json found — nothing to ingest.")
        return

    start_pos = _get_position()
    file_size = os.path.getsize(EVENTS_JSON)

    # Nothing new since last run
    if start_pos >= file_size:
        # File may have been truncated externally (pos > size)
        if start_pos > file_size:
            _save_position(0)
            start_pos = 0
        else:
            return

    db = get_db()
    cur = db.cursor()

    port_tracker: defaultdict[str, list[int]] = defaultdict(list)
    processed = 0
    skipped = 0
    no_pcap = 0

    with open(EVENTS_JSON) as fh:
        fh.seek(start_pos)

        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            pcap_path = os.path.join(PCAP_DIR, "{}.pcap".format(event["event_id"]))

            # Fast check — skip if PCAP already deleted (prior ingest)
            if not os.path.exists(pcap_path):
                no_pcap += 1
                continue

            try:
                packets = rdpcap(pcap_path)
            except Exception as e:
                logger.debug("PCAP read error for %s: %s", pcap_path, e)
                skipped += 1
                continue

            if not packets:
                skipped += 1
                continue

            pkt = packets[0]

            if not pkt.haslayer(IP):
                skipped += 1
                continue

            protocol = detect_protocol(pkt)
            payload_size = len(pkt)

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = (
                pkt[TCP].sport
                if pkt.haslayer(TCP)
                else (pkt[UDP].sport if pkt.haslayer(UDP) else None)
            )
            dst_port = (
                pkt[TCP].dport
                if pkt.haslayer(TCP)
                else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
            )

            # Defence-in-depth filter — drop events whose src_ip matches
            # IGNORE_LOCAL_SOURCES even if sensor.py's filter let them
            # through (observed in production: 1.5K events/h with
            # src=us survived the BPF capture filter for reasons we
            # couldn't trace; this catches them at ingest time so they
            # never reach Claude analysis or the dashboard).
            try:
                from honeylens.config import should_ignore_traffic as _filter

                if _filter(src_port=src_port, dst_port=dst_port, src_ip=src_ip):
                    continue
            except Exception as exc:
                logger.debug("optional field skipped: %s", exc)

            if dst_port:
                port_tracker[src_ip].append(dst_port)

            entropy = calculate_entropy(port_tracker[src_ip])
            unique_ports = len(set(port_tracker[src_ip]))
            scan_type = event.get("scan_type", "")
            scan_score = calculate_scan_score(unique_ports, entropy, payload_size, scan_type)

            # Optional deep PCAP analysis + JA3 extraction
            analysis = {}
            ja3 = None
            ja3_info = None

            # Try external analyzer first

            # JA3 fingerprint extraction (if not already obtained)
            if not ja3:
                try:
                    ja3_info = extract_ja3_from_pcap(pcap_path)
                    if ja3_info:
                        ja3 = ja3_info.get("ja3_hash")
                        # Add JA3 details to analysis
                        analysis["ja3"] = {
                            "hash": ja3_info.get("ja3_hash"),
                            "string": ja3_info.get("ja3_string"),
                            "sni": ja3_info.get("sni"),
                            "identified": ja3_info.get("ja3_identified"),
                            "tls_version": ja3_info.get("tls_version_str"),
                            "cipher_suites_count": ja3_info.get("cipher_suites_count"),
                            "extensions_count": ja3_info.get("extensions_count"),
                        }
                        # Log interesting fingerprints
                        if ja3_info.get("ja3_identified"):
                            logger.info(
                                "JA3 identified: %s -> %s (SNI: %s)",
                                src_ip,
                                ja3_info.get("ja3_identified"),
                                ja3_info.get("sni", "-"),
                            )
                except Exception as e:
                    logger.debug("JA3 extraction error: %s", e)

            # JA4+ fingerprint extraction
            ja4_info = None
            if _HAS_JA4_TABLE:
                try:
                    # Use already-loaded packets instead of re-reading PCAP
                    for p in packets:
                        if not p.haslayer(TCP):
                            continue

                        # Use same payload extraction as JA3 (TCP.payload, not Raw.load)
                        tls_payload = bytes(p[TCP].payload)

                        # Check for TLS Handshake (0x16) + ClientHello (0x01 at offset 5)
                        if (
                            len(tls_payload) >= 6
                            and tls_payload[0] == 0x16
                            and tls_payload[5] == 0x01
                        ):
                            ja4_info = parse_tls_client_hello_ja4(tls_payload)
                            if ja4_info:
                                analysis["ja4"] = {
                                    "fingerprint": ja4_info.get("ja4"),
                                    "fingerprint_a": ja4_info.get("ja4_a"),
                                    "fingerprint_b": ja4_info.get("ja4_b"),
                                    "fingerprint_c": ja4_info.get("ja4_c"),
                                    "sni": ja4_info.get("sni"),
                                    "alpn": ja4_info.get("alpn"),
                                    "tls_version": ja4_info.get("tls_version_str"),
                                    "identified": ja4_info.get("identified"),
                                }
                                if ja4_info.get("identified"):
                                    logger.info(
                                        "JA4 identified: %s -> %s (SNI: %s)",
                                        src_ip,
                                        ja4_info.get("identified"),
                                        ja4_info.get("sni", "-"),
                                    )
                                else:
                                    logger.debug(
                                        "JA4 extracted: %s -> %s", src_ip, ja4_info.get("ja4")
                                    )
                                break
                except Exception as e:
                    logger.debug("JA4 extraction error: %s", e)

            # ---------------------------------------------------------------
            # Sanitise ALL values that will touch PostgreSQL
            # ---------------------------------------------------------------

            # Build metadata from PCAP-extracted values (event dict is slim
            # since sensor.py v0.9_003 — only event_id/timestamp/payload_hash/scan_type)
            metadata_obj = strip_nul(
                {
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol_detected": protocol,
                    "payload_size": payload_size,
                    "scan_type": event.get("scan_type", ""),
                    "ttl": pkt[IP].ttl if pkt.haslayer(IP) else None,
                    "analysis": analysis,
                }
            )
            metadata_json = safe_json_dumps(metadata_obj)

            # Extract payload text — strip NUL thoroughly
            payload_text = None
            raw_payload = b""
            if pkt.haslayer(TCP):
                raw_payload = bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                raw_payload = bytes(pkt[UDP].payload)

            if raw_payload:
                # Cap bumped 4096 → 16384 (2026-05-07): the qassam-315
                # CVE-2026-0300 PoC body was 2,248 bytes and the 4 KB
                # cap was tripping with a still-truncated tail; 16 KB
                # safely covers a single-MTU exploit body and most large
                # multi-segment POSTs that fit in one packet.
                payload_text = safe_str(raw_payload[:16384])

            # Clean every string field individually
            event_id_clean = strip_nul(event.get("event_id", ""))
            timestamp_clean = strip_nul(str(event.get("timestamp", "")))
            payload_hash_clean = strip_nul(event.get("payload_hash", ""))
            ja3_clean = strip_nul(ja3) if ja3 else None

            # ---------------------------------------------------------------
            # Attack pattern classification
            # ---------------------------------------------------------------
            attack_types_str = None
            attack_hits = []
            try:
                attack_hits = classify_event_row(
                    payload=payload_text,
                    protocol=protocol,
                    metadata=metadata_obj,
                )
                attack_types_str = classify_attack_summary(attack_hits)
                if attack_types_str:
                    attack_types_str = strip_nul(attack_types_str)
            except Exception as exc:
                logger.debug("Attack classify error: %s", exc)

            try:
                row: tuple[Any, ...] = (
                    event_id_clean,
                    timestamp_clean,
                    "sensor",
                    strip_nul(protocol),
                    strip_nul(src_ip),
                    src_port,
                    strip_nul(dst_ip),
                    dst_port,
                    payload_text,
                    payload_hash_clean,
                    scan_score,
                    entropy,
                    ja3_clean,
                    metadata_json,
                )
                if _HAS_ATK_COL:
                    row = (*row, attack_types_str)
                if _HAS_DISSECTION_COLS:
                    # Idea 30 Phase 0: store full payload bytes + sha256 +
                    # TCP sequence number when the destination port is opted
                    # into deep capture via EBPF_DISSECTION_PORTS or the
                    # ebpf_dissection_ports DB table. Un-monitored ports get
                    # NULLs — current behaviour preserved.
                    full_payload_bytes = None
                    full_payload_hash_hex = None
                    tcp_seq_val = None
                    if (
                        _DISSECTION_STATE is not None
                        and raw_payload
                        and len(raw_payload) > 256
                        and _DISSECTION_STATE.is_monitored(dst_port or -1)
                    ):
                        # Cap at the BPF program's hard ceiling (4 KB) since
                        # that is the maximum the in-kernel capture path can
                        # produce. Userspace pcap path may show more, but
                        # we store at most what the BPF tier would have caught.
                        full_payload_bytes = raw_payload[:4096]
                        full_payload_hash_hex = hashlib.sha256(full_payload_bytes).hexdigest()
                    if pkt.haslayer(TCP):
                        try:
                            tcp_seq_val = int(pkt[TCP].seq)
                        except Exception:
                            tcp_seq_val = None
                    # psycopg2 expects bytea as memoryview / bytes / Binary
                    row = (
                        *row,
                        psycopg2.Binary(full_payload_bytes) if full_payload_bytes else None,
                        full_payload_hash_hex,
                        tcp_seq_val,
                    )
                cur.execute(INSERT_SQL, row)

                # Fan-out to configured SIEM forwarders (no-op when none configured).
                try:
                    from honeylens.siem import forward_event_dict as _fwd_siem

                    _fwd_siem(
                        {
                            "event_id": event_id_clean,
                            "source": "sensor",
                            "protocol": protocol,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "payload": payload_text or "",
                            "payload_hash": payload_hash_clean or "",
                            "attack_types": attack_types_str if _HAS_ATK_COL else "",
                        }
                    )
                except Exception as exc:
                    logger.debug("optional field skipped: %s", exc)

                # Insert individual attack pattern rows
                if _HAS_ATK_TBL:
                    for atype, rule, matched in attack_hits:
                        try:
                            cur.execute(
                                INSERT_ATTACK_SQL,
                                (
                                    event_id_clean,
                                    strip_nul(atype),
                                    strip_nul(rule),
                                    strip_nul(matched[:500]),
                                    strip_nul(get_severity(atype, rule)),
                                ),
                            )
                        except psycopg2.Error as e:
                            logger.debug("Attack pattern insert skipped (dup FK): %s", e)

                # Insert ICS events for MODBUS/ICS_ATTACK detections
                if _HAS_ICS_TBL:
                    for atype, rule, _matched in attack_hits:
                        if atype in ("MODBUS", "ICS_ATTACK"):
                            try:
                                ics_data = parse_ics_event(
                                    atype, rule, payload_text, dst_port, src_ip, dst_ip, src_port
                                )
                                if ics_data:
                                    cur.execute(
                                        INSERT_ICS_SQL,
                                        (
                                            event_id_clean,
                                            timestamp_clean,
                                            strip_nul(ics_data["protocol"]),
                                            ics_data.get("function_code"),
                                            strip_nul(ics_data.get("function_name")),
                                            strip_nul(ics_data["src_ip"]),
                                            ics_data["src_port"],
                                            strip_nul(ics_data["dst_ip"]),
                                            ics_data["dst_port"],
                                            ics_data["is_read"],
                                            ics_data["is_write"],
                                            ics_data["is_control"],
                                            ics_data["is_discovery"],
                                            strip_nul(ics_data.get("mitre_tactic")),
                                            strip_nul(ics_data.get("mitre_technique")),
                                            strip_nul(ics_data["attack_type"]),
                                            strip_nul(ics_data["rule_name"]),
                                            strip_nul(ics_data["source"]),
                                            strip_nul(ics_data["severity"]),
                                        ),
                                    )
                            except Exception as e:
                                logger.debug("ICS insert error: %s", e)

                # Insert JA4+ fingerprint
                if _HAS_JA4_TABLE and ja4_info:
                    try:
                        cur.execute(
                            INSERT_JA4_SQL,
                            (
                                event_id_clean,
                                "ja4",
                                strip_nul(ja4_info.get("ja4", "")),
                                strip_nul(ja4_info.get("ja4_a")),
                                strip_nul(ja4_info.get("ja4_b")),
                                strip_nul(ja4_info.get("ja4_c")),
                                strip_nul(ja4_info.get("ja4_r")),
                                strip_nul(ja4_info.get("tls_version_str")),
                                strip_nul(ja4_info.get("sni")),
                                strip_nul(ja4_info.get("alpn")),
                                ja4_info.get("cipher_count"),
                                ja4_info.get("extension_count"),
                                strip_nul(ja4_info.get("identified")),
                                safe_json_dumps(
                                    strip_nul(
                                        {
                                            "cipher_suites": ja4_info.get("cipher_suites", []),
                                            "extensions": ja4_info.get("extensions", []),
                                            "signature_algorithms": ja4_info.get(
                                                "signature_algorithms", []
                                            ),
                                        }
                                    )
                                ),
                            ),
                        )
                    except Exception as e:
                        logger.debug("JA4 insert error: %s", e)

                # A HIGH/CRITICAL PCAP must enter the durable outbox before
                # the raw capture below is removed.  A hand-off failure keeps
                # the original file for operator recovery.
                preserve_pcap = False
                if attack_hits:
                    severities = [
                        get_severity(atype, rule).upper() for atype, rule, _ in attack_hits
                    ]
                    candidate_severity = max(
                        severities,
                        key=lambda value: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                            value, 0
                        ),
                    )
                    if candidate_severity in {"HIGH", "CRITICAL"}:
                        try:
                            queue_export_candidate(
                                cur,
                                pcap_path,
                                event_id_clean,
                                candidate_severity,
                                timestamp_clean,
                                protocol,
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                metadata_obj,
                            )
                            # HIGH/CRITICAL volume is intentionally small.
                            # Commit immediately so the outbox row is durable
                            # before the source PCAP is removed below.
                            db.commit()
                        except Exception as exc:
                            preserve_pcap = True
                            logger.error(
                                "PCAP outbox hand-off failed for %s: %s", event_id_clean, exc
                            )
                            raise
            except Exception as exc:
                logger.error(
                    "DB insert failed for event %s: %s", event.get("event_id", "?")[:16], exc
                )
                db.rollback()
                skipped += 1
                continue

            # Remove PCAP only after queued for commit
            if not preserve_pcap:
                try:
                    os.remove(pcap_path)
                except OSError as e:
                    logger.debug("Could not remove PCAP %s: %s", pcap_path, e)

            processed += 1

            # Batch commit every BATCH_SIZE events to limit transaction size
            if processed % BATCH_SIZE == 0:
                db.commit()

        # Save position at end of file
        end_pos = fh.tell()

    db.commit()
    cur.close()
    db.close()

    _save_position(end_pos)

    # Truncate events.json if fully processed and oversized
    if end_pos >= file_size:
        _truncate_events_json()

    if processed or skipped:
        logger.info(
            "Ingestion complete — %d inserted, %d skipped, %d no-pcap (from pos %d)",
            processed,
            skipped,
            no_pcap,
            start_pos,
        )


def main() -> int:
    """Entry point for ``honeylens-ingest-ebpf`` (systemd unit sensor-ingest)."""
    from honeylens.logging_setup import setup_logging

    setup_logging()
    ingest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
