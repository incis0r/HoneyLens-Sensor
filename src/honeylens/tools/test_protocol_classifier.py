#!/usr/bin/env python3
"""
test_protocol_classifier.py — Protocol Classification Validation Suite
========================================================================
Tests detect_protocol() from ingest.py against synthetic packets that
replicate the byte-level signatures documented on:

    https://wiki.wireshark.org/SampleCaptures

Each test constructs a mock packet with the EXACT magic bytes, header
structures, and port numbers that Wireshark's dissectors use.

Uses mock objects instead of scapy so this can run WITHOUT scapy installed
(useful in CI/offline). The same tests also work on the real sensor box.

Run:
    python test_protocol_classifier.py

References in comments use the format:
    [WS:dissector_name] = Wireshark dissector source name
    [WS:SampleCaptures#section] = SampleCaptures wiki section
"""

from __future__ import annotations

import sys
import types
from typing import Any

# ---------------------------------------------------------------------------
# Mock scapy packet objects — matches the interface detect_protocol() uses
# ---------------------------------------------------------------------------


class MockLayer:
    """A minimal mock of a scapy layer (TCP, UDP, ICMP)."""

    def __init__(self, sport=0, dport=0, flags=0, payload=b""):
        self.sport = sport
        self.dport = dport
        self.flags = flags
        self._payload = payload

    @property
    def payload(self):
        return self._payload


class MockPacket:
    """A minimal mock of a scapy IP packet."""

    def __init__(self, layers, src="10.0.0.1", dst="10.0.0.2"):
        self._layers = layers  # dict: layer_name -> MockLayer
        self.src = src
        self.dst = dst

    def haslayer(self, layer):
        if isinstance(layer, str):
            return layer in self._layers
        # scapy classes — match by name
        name = getattr(layer, "__name__", str(layer))
        return name in self._layers

    def __getitem__(self, layer):
        if isinstance(layer, str):
            return self._layers[layer]
        name = getattr(layer, "__name__", str(layer))
        return self._layers[name]


# Dummy scapy class references for __getitem__ matching
class TCP:
    __name__ = "TCP"


class UDP:
    __name__ = "UDP"


class IP:
    __name__ = "IP"


class ICMP:
    __name__ = "ICMP"


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------


def tcp_pkt(payload_bytes, dport=80, sport=12345, flags=0x02):
    """Build a mock IP/TCP packet."""
    return MockPacket(
        {
            "IP": MockLayer(),
            "TCP": MockLayer(sport=sport, dport=dport, flags=flags, payload=payload_bytes),
        }
    )


def udp_pkt(payload_bytes, dport=53, sport=12345):
    """Build a mock IP/UDP packet."""
    return MockPacket(
        {
            "IP": MockLayer(),
            "UDP": MockLayer(sport=sport, dport=dport, payload=payload_bytes),
        }
    )


def icmp_pkt(payload_bytes=b"ping"):
    """Build a mock ICMP packet."""
    return MockPacket(
        {
            "IP": MockLayer(),
            "ICMP": MockLayer(payload=payload_bytes),
        }
    )


def tcp_syn(dport=80, sport=12345):
    """TCP SYN — no payload, flags=0x02."""
    return tcp_pkt(b"", dport=dport, sport=sport, flags=0x02)


def tcp_synack(dport=80, sport=12345):
    """TCP SYN-ACK — no payload, flags=0x12."""
    return tcp_pkt(b"", dport=dport, sport=sport, flags=0x12)


def tcp_ack(dport=80, sport=12345):
    """TCP ACK — no payload, flags=0x10."""
    return tcp_pkt(b"", dport=dport, sport=sport, flags=0x10)


# ---------------------------------------------------------------------------
# Mock out config and scapy so we can import detect_protocol
# ---------------------------------------------------------------------------

# Fake config module
_fake_config: Any = types.ModuleType("config")
_fake_config.DB_CONFIG = {}
_fake_config.EVENTS_JSON = "/dev/null"
_fake_config.PCAP_DIR = "/tmp"  # nosec B108
sys.modules["config"] = _fake_config

# Fake psycopg2
sys.modules["psycopg2"] = types.ModuleType("psycopg2")

# Fake scapy
_fake_scapy = types.ModuleType("scapy")
_fake_scapy_all: Any = types.ModuleType("scapy.all")
_fake_scapy_all.IP = IP
_fake_scapy_all.TCP = TCP
_fake_scapy_all.UDP = UDP
_fake_scapy_all.ICMP = ICMP
_fake_scapy_all.rdpcap = lambda x: []
sys.modules["scapy"] = _fake_scapy
sys.modules["scapy.all"] = _fake_scapy_all


from honeylens.ingest.ebpf import detect_protocol

# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

TESTS: list[Any] = []


def test(expected, description):
    def decorator(func):
        TESTS.append((expected, description, func))
        return func

    return decorator


# ===================================================================
# TLS / SSL
# [WS:tls] [WS:SampleCaptures#ssl-with-decryption-keys]
# ContentType: Handshake=0x16, CCS=0x14, Alert=0x15, AppData=0x17
# Version: TLS1.0=0x0301, TLS1.1=0x0302, TLS1.2+=0x0303
# ===================================================================


@test("TLS/1.2+", "TLS 1.2 ClientHello (0x16 0x03 0x03) — MUST NOT be MQTT")
def _():
    return tcp_pkt(b"\x16\x03\x03\x00\xf1\x01\x00\x00\xed\x03\x03", dport=443)


@test("TLS/1.0", "TLS 1.0 ClientHello (0x16 0x03 0x01)")
def _():
    return tcp_pkt(b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x01", dport=443)


@test("TLS", "TLS ChangeCipherSpec (0x14 0x03 0x03)")
def _():
    return tcp_pkt(b"\x14\x03\x03\x00\x01\x01", dport=443)


@test("TLS", "TLS Alert (0x15 0x03 0x03)")
def _():
    return tcp_pkt(b"\x15\x03\x03\x00\x02\x02\x28", dport=443)


@test("TLS", "TLS ApplicationData (0x17 0x03 0x03)")
def _():
    return tcp_pkt(b"\x17\x03\x03\x00\x20" + b"\xaa" * 32, dport=443)


@test("TLS/1.2+", "TLS on API port 3443 — MUST be TLS, not MQTT")
def _():
    return tcp_pkt(b"\x16\x03\x03\x00\xf1\x01\x00\x00\xed\x03\x03", dport=3443)


@test("TLS/1.2+", "TLS on random high port — MUST be TLS")
def _():
    return tcp_pkt(b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00", dport=9999)


# ===================================================================
# SSH
# [WS:ssh] [WS:SampleCaptures#ssh-with-decryption-keys]
# Banner: "SSH-" at start of payload
# ===================================================================


@test("SSH", "SSH-2.0 server banner")
def _():
    return tcp_pkt(b"SSH-2.0-OpenSSH_8.9\r\n", dport=22)


@test("SSH", "SSH on non-standard port")
def _():
    return tcp_pkt(b"SSH-2.0-dropbear_2022.83\r\n", dport=2222)


# ===================================================================
# HTTP
# [WS:http] [WS:SampleCaptures#hypertext-transport-protocol-http]
# Request methods: GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS
# Response: "HTTP/" prefix
# ===================================================================


@test("HTTP", "HTTP GET request")
def _():
    return tcp_pkt(b"GET /index.html HTTP/1.1\r\n", dport=80)


@test("HTTP", "HTTP POST request")
def _():
    return tcp_pkt(b"POST /api/data HTTP/1.1\r\n", dport=80)


@test("HTTP", "HTTP response")
def _():
    return tcp_pkt(b"HTTP/1.1 200 OK\r\n", sport=80)


@test("HTTP", "HTTP HEAD request")
def _():
    return tcp_pkt(b"HEAD / HTTP/1.1\r\n", dport=80)


@test("HTTP", "HTTP DELETE request")
def _():
    return tcp_pkt(b"DELETE /item/42 HTTP/1.1\r\n", dport=8080)


@test("HTTP", "HTTP OPTIONS request")
def _():
    return tcp_pkt(b"OPTIONS * HTTP/1.1\r\n", dport=80)


@test("HTTP", "HTTP PATCH request")
def _():
    return tcp_pkt(b"PATCH /users/1 HTTP/1.1\r\n", dport=80)


# ===================================================================
# Modbus TCP
# [WS:modbus]
# MBAP header: txn_id(2) + proto_id(2=0x0000) + length(2) + unit(1)
# ===================================================================


@test("Modbus", "Modbus FC=0x03 read holding registers")
def _():
    return tcp_pkt(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a", dport=502)


@test("Modbus", "Modbus FC=0x05 write single coil")
def _():
    return tcp_pkt(b"\x00\x02\x00\x00\x00\x06\x01\x05\x00\x0a\xff\x00", dport=502)


# ===================================================================
# MQTT
# [WS:mqtt]
# CONNECT: fixed header 0x10, then variable length, then "MQTT"
# PUBLISH: type nibble = 3 (0x3x), SUBSCRIBE=8, etc.
# ===================================================================


@test("MQTT", "MQTT CONNECT with 'MQTT' protocol name")
def _():
    return tcp_pkt(b"\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test", dport=1883)


@test("MQTT", "MQTT CONNECT with 'MQIsdp' (v3.1)")
def _():
    return tcp_pkt(b"\x10\x16\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x06client", dport=1883)


@test("MQTT", "MQTT PUBLISH on known port 1883")
def _():
    return tcp_pkt(b"\x30\x0c\x00\x04test\x48\x65\x6c\x6c\x6f", dport=1883)


# ===================================================================
# PostgreSQL
# [WS:pgsql] [WS:SampleCaptures#postgresql-v3-frontendbackend-protocol]
# Startup: length(4) + version 196608 (0x00030000)
# SSLRequest: length(4)=8 + code 80877103 (0x04D2162F)
# Backend msgs: single-byte tag (R/E/K/S/Z) + length(4)
# ===================================================================


@test("PostgreSQL", "PostgreSQL v3 startup message")
def _():
    msg = b"\x00\x00\x00\x27" + b"\x00\x03\x00\x00" + b"user\x00admin\x00database\x00mydb\x00\x00"
    return tcp_pkt(msg, dport=5432)


@test("PostgreSQL/SSL", "PostgreSQL SSLRequest")
def _():
    return tcp_pkt(b"\x00\x00\x00\x08\x04\xd2\x16\x2f", dport=5432)


@test("PostgreSQL", "PostgreSQL AuthenticationOk (R tag)")
def _():
    return tcp_pkt(b"R\x00\x00\x00\x08\x00\x00\x00\x00", sport=5432, dport=54321)


@test("PostgreSQL", "PostgreSQL ErrorResponse (E tag)")
def _():
    return tcp_pkt(b"E\x00\x00\x00\x30SFATAL\x00C28000\x00Mfailed\x00\x00", sport=5432)


# ===================================================================
# MySQL
# [WS:mysql] [WS:SampleCaptures#mysql-protocol]
# Greeting: proto_ver=0x0a + version_string ("5.7", "8.0", etc.)
# ===================================================================


@test("MySQL", "MySQL 5.7 server greeting")
def _():
    return tcp_pkt(b"\x0a5.7.99-log\x00" + b"\x01" * 20, sport=3306)


@test("MySQL", "MySQL 8.0 server greeting")
def _():
    return tcp_pkt(b"\x0a8.0.32\x00" + b"\x02" * 20, sport=3306)


# ===================================================================
# MSSQL TDS
# [WS:tds] [WS:SampleCaptures#ms-sql-server-protocol---tabular-data-stream-tds]
# Packet type at byte 0: 0x12=pre-login, 0x07=login7, 0x04=response
# ===================================================================


@test("MSSQL/TDS", "TDS pre-login (type 0x12) on port 1433")
def _():
    return tcp_pkt(b"\x12\x01\x00\x2f\x00\x00\x01\x00", dport=1433)


# ===================================================================
# SMB / SMB2
# [WS:smb,smb2] [WS:SampleCaptures#server-message-block-smbcommon-internet-file-system-cifs]
# NetBIOS session header(4) + magic: \xFFSMB (SMB1) or \xFESMB (SMB2)
# ===================================================================


@test("SMB", "SMB1 \\xFFSMB magic")
def _():
    return tcp_pkt(b"\x00\x00\x00\x55\xffSMB\x72\x00\x00\x00\x00", dport=445)


@test("SMB", "SMB2 \\xFESMB magic")
def _():
    return tcp_pkt(b"\x00\x00\x01\x00\xfeSMB\x40\x00\x01\x00", dport=445)


# ===================================================================
# RDP / X.224
# [WS:rdp] [WS:SampleCaptures#credssp]
# TPKT header: version=3 (0x03), reserved=0 (0x00)
# ===================================================================


@test("RDP", "RDP TPKT + X.224 on port 3389")
def _():
    return tcp_pkt(b"\x03\x00\x00\x25\x20\xe0\x00\x00\x00\x00\x00", dport=3389)


# ===================================================================
# Telnet
# [WS:telnet] [WS:SampleCaptures#telnet]
# IAC (0xFF) + command: WILL=0xFB, WONT=0xFC, DO=0xFD, DONT=0xFE
# ===================================================================


@test("Telnet", "Telnet IAC WILL (0xFF 0xFB)")
def _():
    return tcp_pkt(b"\xff\xfb\x01\xff\xfb\x03", dport=23)


@test("Telnet", "Telnet IAC DO (0xFF 0xFD)")
def _():
    return tcp_pkt(b"\xff\xfd\x01\xff\xfd\x1f", dport=23)


# ===================================================================
# FTP
# [WS:ftp] — greeting "220 " on port 21
# ===================================================================


@test("FTP", "FTP server greeting on port 21")
def _():
    return tcp_pkt(b"220 FTP server ready\r\n", sport=21)


# ===================================================================
# SMTP
# [WS:smtp] [WS:SampleCaptures — smtp.pcap]
# Greeting "220 " on port 25/587
# ===================================================================


@test("SMTP", "SMTP server greeting on port 25")
def _():
    return tcp_pkt(b"220 mail.example.com ESMTP Postfix\r\n", sport=25)


# ===================================================================
# VNC
# [WS:vnc] [WS:SampleCaptures — vnc-sample.pcap]
# "RFB " protocol version string
# ===================================================================


@test("VNC", "VNC RFB protocol version")
def _():
    return tcp_pkt(b"RFB 003.008\n", sport=5900)


# ===================================================================
# Oracle TNS
# [WS:tns] [WS:SampleCaptures#oracle-tns--sqlnet--oci--opi]
# TNS: pkt_len(2) + checksum(2) + type(1): 1=Connect, 2=Accept, 4=Refuse
# ===================================================================


@test("Oracle/TNS", "Oracle TNS Connect on port 1521")
def _():
    return tcp_pkt(b"\x00\xfa\x00\x00\x01\x00\x00\x00\x01\x3a", dport=1521)


# ===================================================================
# Java RMI — "JRMI" magic
# ===================================================================


@test("Java-RMI", "Java RMI JRMI magic bytes")
def _():
    return tcp_pkt(b"JRMI\x00\x02K", dport=11099)


# ===================================================================
# S7comm (Siemens)
# [WS:s7comm] [WS:SampleCaptures#s7comm---s7-communication]
# TPKT (0x03 0x00) on port 102
# ===================================================================


@test("S7comm", "S7comm TPKT on port 102")
def _():
    return tcp_pkt(b"\x03\x00\x00\x16\x11\xe0\x00\x00", dport=102)


# ===================================================================
# DNP3
# [WS:dnp3] [WS:SampleCaptures#dnp3]
# Start bytes: 0x05 0x64
# ===================================================================


@test("DNP3", "DNP3 magic 0x05 0x64")
def _():
    return tcp_pkt(b"\x05\x64\x05\xc0\x01\x00\x00\x00", dport=20000)


# ===================================================================
# IEC 60870-5-104
# [WS:iec60870_104] [WS:SampleCaptures#iec-60870-5-104]
# APCI start byte: 0x68, port 2404
# ===================================================================


@test("IEC-104", "IEC-104 APCI on port 2404")
def _():
    return tcp_pkt(b"\x68\x04\x07\x00\x00\x00", dport=2404)


# ===================================================================
# LDAP
# [WS:ldap] [WS:SampleCaptures#lightweight-directory-access-protocol-ldap]
# BER SEQUENCE tag 0x30 on ports 389/636/3268/3269
# ===================================================================


@test("LDAP", "LDAP BER SEQUENCE on port 389")
def _():
    return tcp_pkt(b"\x30\x25\x02\x01\x01\x60\x20", dport=389)


@test("LDAP", "LDAP on Global Catalog port 3268")
def _():
    return tcp_pkt(b"\x30\x25\x02\x01\x01\x60\x20", dport=3268)


# ===================================================================
# SIP
# [WS:sip] [WS:SampleCaptures#sip-and-rtp]
# ===================================================================


@test("SIP", "SIP INVITE over TCP")
def _():
    return tcp_pkt(b"INVITE sip:user@example.com SIP/2.0\r\n", dport=5060)


@test("SIP", "SIP response over TCP")
def _():
    return tcp_pkt(b"SIP/2.0 200 OK\r\n", sport=5060)


# ===================================================================
# DNS over TCP
# [WS:dns] [WS:SampleCaptures — dns.cap]
# 2-byte length prefix + DNS header
# ===================================================================


@test("DNS/TCP", "DNS query over TCP")
def _():
    return tcp_pkt(b"\x00\x1c\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", dport=53)


# ===================================================================
# Redis
# ===================================================================


@test("Redis", "Redis RESP *1 array")
def _():
    return tcp_pkt(b"*1\r\n$4\r\nPING\r\n", dport=6379)


@test("Redis", "Redis inline PING")
def _():
    return tcp_pkt(b"PING\r\n", dport=6379)


# ===================================================================
# TCP flag classification (no payload)
# ===================================================================


@test("TCP/SYN", "SYN scan")
def _():
    return tcp_syn(dport=8080)


@test("TCP/SYN-ACK", "SYN-ACK response")
def _():
    return tcp_synack(sport=443)


@test("TCP", "ACK only (no payload)")
def _():
    return tcp_ack(dport=80)


# ===================================================================
# UDP protocols
# ===================================================================


# [WS:dns]
@test("DNS", "DNS query over UDP")
def _():
    return udp_pkt(b"\xaa\xbb\x01\x00\x00\x01", dport=53)


# [WS:ntp] [WS:SampleCaptures#network-time-protocol]
@test("NTP", "NTP request on port 123")
def _():
    return udp_pkt(b"\x1b" + b"\x00" * 47, dport=123)


# [WS:snmp] [WS:SampleCaptures#snmp]
@test("SNMP", "SNMP GET on port 161")
def _():
    return udp_pkt(b"\x30\x26\x02\x01\x01", dport=161)


# [WS:dhcp]
@test("DHCP", "DHCP Discover (port 67<->68)")
def _():
    return udp_pkt(b"\x01\x01\x06\x00", dport=67, sport=68)


# [WS:syslog]
@test("Syslog", "Syslog on port 514")
def _():
    return udp_pkt(b"<34>Oct 11 syslog message", dport=514)


# [WS:ssdp]
@test("SSDP", "SSDP NOTIFY on port 1900")
def _():
    return udp_pkt(b"NOTIFY * HTTP/1.1\r\n", dport=1900)


# [WS:mdns]
@test("mDNS", "mDNS on port 5353")
def _():
    return udp_pkt(b"\x00\x00\x00\x00", dport=5353)


# [WS:tftp] [WS:SampleCaptures#tftp]
@test("TFTP", "TFTP RRQ on port 69")
def _():
    return udp_pkt(b"\x00\x01test.txt\x00octet\x00", dport=69)


# [WS:bacnet]
@test("BACnet", "BACnet/IP on port 47808")
def _():
    return udp_pkt(b"\x81\x0a\x00\x11", dport=47808)


# [WS:radius] [WS:SampleCaptures#radius-rfc-2865]
@test("RADIUS", "RADIUS Access-Request on port 1812")
def _():
    return udp_pkt(b"\x01\x01\x00\x14" + b"\x00" * 16, dport=1812)


# [WS:stun]
@test("STUN", "STUN on port 3478")
def _():
    return udp_pkt(b"\x00\x01\x00\x00", dport=3478)


# [WS:coap]
@test("CoAP", "CoAP on port 5683")
def _():
    return udp_pkt(b"\x40\x01\x00\x01", dport=5683)


# [WS:vxlan]
@test("VXLAN", "VXLAN on port 4789")
def _():
    return udp_pkt(b"\x08\x00\x00\x00\x00\x00\x7b\x00", dport=4789)


# [WS:isakmp]
@test("IKE", "IKE/ISAKMP on port 500")
def _():
    return udp_pkt(b"\x00" * 16, dport=500)


# [WS:sip]
@test("SIP", "SIP over UDP on port 5060")
def _():
    return udp_pkt(b"INVITE sip:user@ex.com SIP/2.0\r\n", dport=5060)


# [WS:nbns]
@test("NetBIOS", "NetBIOS name service on port 137")
def _():
    return udp_pkt(b"\x00\x01\x00\x00", dport=137)


@test("WireGuard", "WireGuard on port 51820")
def _():
    return udp_pkt(b"\x01\x00\x00\x00", dport=51820)


# ICMP
@test("ICMP", "ICMP Echo Request")
def _():
    return icmp_pkt()


# ===================================================================
# False-positive guards / regression tests
# ===================================================================


@test("TCP", "Random binary payload — should NOT match any protocol")
def _():
    return tcp_pkt(b"\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc", dport=31337)


@test("UDP", "Random binary on high UDP port")
def _():
    return udp_pkt(b"\xab\xcd\xef\x12\x34\x56", dport=31337)


@test("TLS/1.2+", "REGRESSION: 0x16 on port 3443 must be TLS not MQTT")
def _():
    return tcp_pkt(b"\x16\x03\x03\x01\x00\x01\x00\x00\xfc\x03\x03", dport=3443)


@test("TCP", "0x10 on random port without MQTT payload must NOT be MQTT")
def _():
    return tcp_pkt(b"\x10\x05\x00\x03XXX\x04\x02", dport=31337)


@test("TCP", "0x16 without 0x03 second byte must NOT be TLS")
def _():
    return tcp_pkt(b"\x16\x00\x00\x00\x00", dport=443)


@test("TCP", "Bytes 2:4 = 0x0000 but length field invalid — must NOT be Modbus")
def _():
    return tcp_pkt(b"\xff\xff\x00\x00\xff\xff\xff", dport=8080)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def main():
    passed = 0
    failed = 0
    errors = 0
    failures = []

    print("=" * 72)
    print("  Protocol Classifier Test Suite")
    print("  Ref: https://wiki.wireshark.org/SampleCaptures")
    print("=" * 72)
    print()

    for expected, description, fn in TESTS:
        try:
            pkt = fn()
            result = detect_protocol(pkt)
            if result == expected:
                passed += 1
                status = "PASS"
            else:
                failed += 1
                failures.append((description, expected, result))
                status = "FAIL"
            print(f"  {status:4s}  [{expected:16s}]  {description}")
            if status == "FAIL":
                print(f"        >> got: {result}")
        except Exception as exc:
            errors += 1
            failures.append((description, expected, f"ERROR: {exc}"))
            print(f"  ERR   [{expected:16s}]  {description}")
            print(f"        >> {exc}")

    print()
    print("=" * 72)
    total = len(TESTS)
    print(f"  Results:  {passed}/{total} passed,  {failed} failed,  {errors} errors")
    print("=" * 72)

    if failures:
        print()
        print("  FAILURES:")
        for desc, exp, got in failures:
            print(f"    - {desc}")
            print(f"      expected={exp}  got={got}")
        print()

    return 0 if (failed == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
