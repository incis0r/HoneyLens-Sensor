#!/usr/bin/env python3
"""
tools/ics_honeypot_tester.py — ICS/OT Honeypot Verification Tool
=================================================================
Sends protocol-correct probes to each ICS honeypot and verifies responses.
Reports which honeypots are alive, responding correctly, and logging events.

Usage:
    python -m tools.ics_honeypot_tester --target 192.0.2.10
    python -m tools.ics_honeypot_tester --target 192.0.2.10 --protocol modbus
    python -m tools.ics_honeypot_tester --target 192.0.2.10 --all --verbose
    python -m tools.ics_honeypot_tester --target 192.0.2.10 --check-db

Protocols tested:
    modbus (502), s7comm (102), dnp3 (20000), iec104 (2404),
    bacnet (47808/UDP), enip (44818), opcua (4840), fins (9600),
    mqtt (1883)
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import time

# ─── Protocol Test Definitions ───────────────────────────────────────────

PROTOCOLS = {
    "modbus": {
        "port": 502,
        "proto": "tcp",
        "desc": "Modbus TCP — Schneider PM5560",
        "tests": [
            {
                "name": "Read Holding Registers (FC 3)",
                "send": bytes(
                    [
                        0x00,
                        0x01,  # Transaction ID
                        0x00,
                        0x00,  # Protocol ID (Modbus)
                        0x00,
                        0x06,  # Length
                        0x01,  # Unit ID
                        0x03,  # FC 3: Read Holding Registers
                        0x00,
                        0x00,  # Start address
                        0x00,
                        0x0A,  # Quantity (10 registers)
                    ]
                ),
                "expect_min_len": 7,
                "severity": "LOW",
                "attack_type": "ICS_RECON",
            },
            {
                "name": "Read Device ID (FC 43)",
                "send": bytes(
                    [
                        0x00,
                        0x02,
                        0x00,
                        0x00,
                        0x00,
                        0x05,
                        0x01,
                        0x2B,
                        0x0E,
                        0x01,
                        0x00,
                    ]
                ),
                "expect_min_len": 7,
                "severity": "MEDIUM",
                "attack_type": "MODBUS_RECON",
            },
            {
                "name": "Write Single Coil (FC 5) — CRITICAL",
                "send": bytes(
                    [
                        0x00,
                        0x03,
                        0x00,
                        0x00,
                        0x00,
                        0x06,
                        0x01,
                        0x05,
                        0x00,
                        0x00,
                        0xFF,
                        0x00,
                    ]
                ),
                "expect_min_len": 7,
                "severity": "HIGH",
                "attack_type": "ICS_ATTACK",
            },
        ],
    },
    "s7comm": {
        "port": 102,
        "proto": "tcp",
        "desc": "S7comm — Siemens S7-1200",
        "tests": [
            {
                "name": "COTP Connection Request",
                "send": bytes(
                    [
                        0x03,
                        0x00,
                        0x00,
                        0x16,  # TPKT
                        0x11,
                        0xE0,
                        0x00,
                        0x00,  # COTP CR
                        0x00,
                        0x01,
                        0x00,  # src/dst ref
                        0xC0,
                        0x01,
                        0x0A,  # TPDU size
                        0xC1,
                        0x02,
                        0x01,
                        0x00,  # src TSAP
                        0xC2,
                        0x02,
                        0x01,
                        0x02,  # dst TSAP
                    ]
                ),
                "expect_min_len": 4,
                "expect_byte": (0, 0x03),  # TPKT version 3
                "severity": "MEDIUM",
            },
        ],
    },
    "dnp3": {
        "port": 20000,
        "proto": "tcp",
        "desc": "DNP3 — SEL-3530 RTAC",
        "tests": [
            {
                "name": "Read Request (FC 1)",
                "send": bytes(
                    [
                        0x05,
                        0x64,  # Start bytes
                        0x05,  # Length
                        0xC0,  # Control (DIR=1, PRM=1, FCV=0, FC=0)
                        0x01,
                        0x00,  # Destination (1)
                        0x0A,
                        0x00,  # Source (10)
                        0x00,
                        0x00,  # CRC placeholder
                    ]
                ),
                "expect_min_len": 2,
                "severity": "LOW",
                "attack_type": "ICS_RECON",
            },
        ],
    },
    "iec104": {
        "port": 2404,
        "proto": "tcp",
        "desc": "IEC 60870-5-104 — ABB RTU",
        "tests": [
            {
                "name": "STARTDT act (U-frame)",
                "send": bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00]),
                "expect_min_len": 6,
                "expect_bytes": (0, b"\x68"),
                "severity": "MEDIUM",
            },
            {
                "name": "TESTFR act (U-frame)",
                "send": bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00]),
                "expect_min_len": 6,
                "severity": "LOW",
            },
            {
                "name": "Interrogation Command (I-frame, Type 100)",
                "send": bytes(
                    [
                        0x68,
                        0x0E,  # Start, length 14
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Control (I-frame, SSN=0, RSN=0)
                        0x64,  # Type ID 100 = C_IC_NA_1
                        0x01,  # SQ=0, count=1
                        0x06,
                        0x00,  # COT=6 (activation)
                        0x01,
                        0x00,  # Common address
                        0x00,
                        0x00,
                        0x00,  # IOA
                        0x14,  # QOI=20 (station interrogation)
                    ]
                ),
                "expect_min_len": 6,
                "severity": "MEDIUM",
                "attack_type": "ICS_RECON",
            },
        ],
    },
    "bacnet": {
        "port": 47808,
        "proto": "udp",
        "desc": "BACnet/IP — Johnson Controls HVAC",
        "tests": [
            {
                "name": "Who-Is (Broadcast Discovery)",
                "send": bytes(
                    [
                        0x81,  # BVLC Type
                        0x0B,  # Original-Broadcast-NPDU
                        0x00,
                        0x08,  # Length
                        0x01,  # NPDU Version
                        0x00,  # NPDU Control
                        0x10,
                        0x08,  # Unconfirmed Who-Is
                    ]
                ),
                "expect_min_len": 4,
                "severity": "MEDIUM",
                "attack_type": "ICS_RECON",
            },
        ],
    },
    "enip": {
        "port": 44818,
        "proto": "tcp",
        "desc": "EtherNet/IP — Rockwell 1769-L33ER",
        "tests": [
            {
                "name": "ListIdentity",
                "send": bytes(
                    [
                        0x63,
                        0x00,  # Command: ListIdentity (0x0063 LE)
                        0x00,
                        0x00,  # Length: 0
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Session Handle
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Status
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Sender Context
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Options
                    ]
                ),
                "expect_min_len": 24,
                "severity": "MEDIUM",
                "attack_type": "ICS_RECON",
            },
            {
                "name": "RegisterSession",
                "send": bytes(
                    [
                        0x65,
                        0x00,  # RegisterSession (0x0065 LE)
                        0x04,
                        0x00,  # Length: 4
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Session Handle
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # Status
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x01,
                        0x00,  # Protocol version 1
                        0x00,
                        0x00,  # Options flags
                    ]
                ),
                "expect_min_len": 24,
                "severity": "MEDIUM",
            },
        ],
    },
    "opcua": {
        "port": 4840,
        "proto": "tcp",
        "desc": "OPC UA — Siemens S7-1500",
        "tests": [
            {
                "name": "Hello (HEL)",
                "send": (
                    b"HEL"
                    + b"F"
                    + struct.pack("<I", 57)  # Message size
                    + struct.pack("<I", 0)  # Protocol version
                    + struct.pack("<I", 65535)  # ReceiveBufferSize
                    + struct.pack("<I", 65535)  # SendBufferSize
                    + struct.pack("<I", 0)  # MaxMessageSize
                    + struct.pack("<I", 0)  # MaxChunkCount
                    + struct.pack("<I", 25)  # EndpointUrl length
                    + b"opc.tcp://localhost:4840\x00"
                ),
                "expect_min_len": 8,
                "expect_bytes": (0, b"ACK"),
                "severity": "MEDIUM",
                "attack_type": "ICS_RECON",
            },
        ],
    },
    "fins": {
        "port": 9600,
        "proto": "tcp",
        "desc": "FINS/Omron — CJ2M-CPU33",
        "tests": [
            {
                "name": "Node Address Request",
                "send": (
                    b"FINS"
                    + struct.pack(">I", 12)  # Length
                    + struct.pack(">I", 0)  # Command: Node Address Request
                    + struct.pack(">I", 0)  # Error code
                ),
                "expect_min_len": 16,
                "expect_bytes": (0, b"FINS"),
                "severity": "LOW",
            },
        ],
    },
    "mqtt": {
        "port": 1883,
        "proto": "tcp",
        "desc": "MQTT — Mosquitto 2.0.18",
        "tests": [
            {
                "name": "CONNECT",
                "send": bytes(
                    [
                        0x10,
                        0x10,  # CONNECT, remaining=16
                        0x00,
                        0x04,  # Protocol name length
                        0x4D,
                        0x51,
                        0x54,
                        0x54,  # "MQTT"
                        0x04,  # Protocol level 4 (v3.1.1)
                        0x02,  # Connect flags (clean session)
                        0x00,
                        0x3C,  # Keep alive: 60s
                        0x00,
                        0x04,  # Client ID length
                        0x74,
                        0x65,
                        0x73,
                        0x74,  # "test"
                    ]
                ),
                "expect_min_len": 4,
                "expect_byte": (0, 0x20),  # CONNACK
                "severity": "MEDIUM",
                "attack_type": "MQTT_PROBE",
            },
        ],
    },
}


# ─── Test Runner ─────────────────────────────────────────────────────────


def test_tcp(host: str, port: int, payload: bytes, timeout: float = 3.0) -> tuple[bool, bytes, str]:
    """Send TCP payload and return (success, response, error)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        try:
            resp = sock.recv(4096)
        except TimeoutError:
            resp = b""
        sock.close()
        return True, resp, ""
    except ConnectionRefusedError:
        return False, b"", "Connection refused"
    except TimeoutError:
        return False, b"", "Connection timeout"
    except OSError as e:
        return False, b"", str(e)


def test_udp(host: str, port: int, payload: bytes, timeout: float = 3.0) -> tuple[bool, bytes, str]:
    """Send UDP payload and return (success, response, error)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        try:
            resp, _ = sock.recvfrom(4096)
        except TimeoutError:
            resp = b""
        sock.close()
        return True, resp, ""
    except OSError as e:
        return False, b"", str(e)


def run_test(host: str, proto_name: str, proto_def: dict, verbose: bool = False) -> dict:
    """Run all tests for a protocol. Returns result dict."""
    port = proto_def["port"]
    transport = proto_def["proto"]
    desc = proto_def["desc"]
    tests = proto_def["tests"]

    result = {
        "protocol": proto_name,
        "port": port,
        "description": desc,
        "reachable": False,
        "tests": [],
        "passed": 0,
        "failed": 0,
        "total": len(tests),
    }

    for test in tests:
        name = test["name"]
        payload = test["send"]
        expect_len = test.get("expect_min_len", 1)

        if transport == "tcp":
            ok, resp, err = test_tcp(host, port, payload)
        else:
            ok, resp, err = test_udp(host, port, payload)

        test_result = {
            "name": name,
            "sent_bytes": len(payload),
            "response_bytes": len(resp),
            "passed": False,
            "error": err,
            "severity": test.get("severity", ""),
            "attack_type": test.get("attack_type", ""),
        }

        if not ok:
            test_result["error"] = err
            result["failed"] += 1
        elif len(resp) < expect_len:
            if len(resp) == 0:
                test_result["error"] = "No response (timeout)"
                # Connection accepted but no response is still a partial pass
                result["reachable"] = True
            else:
                test_result["error"] = f"Response too short ({len(resp)} < {expect_len})"
            result["failed"] += 1
        else:
            result["reachable"] = True
            # Check expected bytes if specified
            eb = test.get("expect_byte")
            ebs = test.get("expect_bytes")
            if eb and resp[eb[0]] != eb[1]:
                test_result["error"] = (
                    f"Unexpected byte at {eb[0]}: 0x{resp[eb[0]]:02X} != 0x{eb[1]:02X}"
                )
                result["failed"] += 1
            elif ebs and resp[ebs[0] : ebs[0] + len(ebs[1])] != ebs[1]:
                test_result["error"] = f"Unexpected bytes at {ebs[0]}"
                result["failed"] += 1
            else:
                test_result["passed"] = True
                result["passed"] += 1

        if verbose:
            test_result["response_hex"] = resp[:64].hex() if resp else ""

        result["tests"].append(test_result)
        time.sleep(0.1)  # Brief pause between tests

    return result


def check_db_events(host: str, protocols: list) -> dict:
    """Check database for ICS honeypot events (run on sensor)."""
    try:
        from honeylens.database import legacy_get_db as _legacy_get_db

        conn = _legacy_get_db()
        cur = conn.cursor()

        proto_upper = [p.upper() for p in protocols]
        cur.execute(
            """
            SELECT source, protocol, attack_types, COUNT(*),
                   MIN(timestamp)::text AS first, MAX(timestamp)::text AS last
            FROM sensor_events
            WHERE protocol = ANY(%s)
            GROUP BY source, protocol, attack_types
            ORDER BY source, COUNT(*) DESC
        """,
            (proto_upper,),
        )

        results = []
        for r in cur.fetchall():
            results.append(
                {
                    "source": r[0],
                    "protocol": r[1],
                    "attack_types": r[2],
                    "count": r[3],
                    "first_seen": r[4][:19],
                    "last_seen": r[5][:19],
                }
            )

        # Also check attack_patterns
        cur.execute(
            """
            SELECT ap.attack_type, ap.rule_name, COUNT(*)
            FROM attack_patterns ap
            JOIN sensor_events se ON se.event_id = ap.event_id
            WHERE se.protocol = ANY(%s)
            GROUP BY ap.attack_type, ap.rule_name
            ORDER BY COUNT(*) DESC LIMIT 20
        """,
            (proto_upper,),
        )

        patterns = []
        for r in cur.fetchall():
            patterns.append({"attack_type": r[0], "rule_name": r[1], "count": r[2]})

        conn.close()
        return {"events": results, "attack_patterns": patterns}
    except Exception as e:
        return {"error": str(e)}


# ─── Output Formatters ────────────────────────────────────────────────────

_PASS = "\033[92m✓\033[0m"
_FAIL = "\033[91m✗\033[0m"
_WARN = "\033[93m!\033[0m"
_BOLD = "\033[1m"
_RESET = "\033[0m"
_DIM = "\033[90m"
_CYAN = "\033[96m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"


def print_results(results: list[dict], verbose: bool = False):
    """Pretty-print test results."""
    total_pass = sum(r["passed"] for r in results)
    total_fail = sum(r["failed"] for r in results)
    total_tests = sum(r["total"] for r in results)
    reachable = sum(1 for r in results if r["reachable"])

    print(f"\n{_BOLD}═══ ICS/OT Honeypot Test Results ═══{_RESET}\n")

    for r in results:
        icon = _PASS if r["passed"] == r["total"] else (_WARN if r["reachable"] else _FAIL)
        port_str = f"{_DIM}:{r['port']}{_RESET}"
        print(
            f"  {icon} {_BOLD}{r['protocol'].upper()}{_RESET}{port_str}  {_DIM}{r['description']}{_RESET}"
        )

        if not r["reachable"]:
            err = r["tests"][0]["error"] if r["tests"] else "unknown"
            print(f"      {_RED}NOT REACHABLE: {err}{_RESET}")
            continue

        for t in r["tests"]:
            tick = _PASS if t["passed"] else _FAIL
            sev = t.get("severity", "")
            sev_c = {"LOW": _GREEN, "MEDIUM": _YELLOW, "HIGH": _RED, "CRITICAL": _RED}.get(
                sev, _DIM
            )
            print(
                f"      {tick} {t['name']}  {sev_c}{sev}{_RESET}  "
                f"{_DIM}sent:{t['sent_bytes']}B recv:{t['response_bytes']}B{_RESET}"
            )
            if t.get("error"):
                print(f"         {_RED}{t['error']}{_RESET}")
            if verbose and t.get("response_hex"):
                print(f"         {_DIM}resp: {t['response_hex']}{_RESET}")

    print(
        f"\n{_BOLD}Summary:{_RESET} {reachable}/{len(results)} reachable, "
        f"{_GREEN}{total_pass}{_RESET}/{total_tests} tests passed, "
        f"{_RED}{total_fail}{_RESET} failed\n"
    )


def print_db_results(db_data: dict):
    """Pretty-print database check results."""
    if db_data.get("error"):
        print(f"\n{_FAIL} Database check failed: {db_data['error']}")
        return

    events = db_data.get("events", [])
    patterns = db_data.get("attack_patterns", [])

    print(f"\n{_BOLD}═══ Database Event Check ═══{_RESET}\n")

    if events:
        print(f"  {_CYAN}Events by source/protocol:{_RESET}")
        for e in events:
            atk = e.get("attack_types") or "—"
            print(
                f"    {e['source']:20s} {e['protocol']:8s} {atk:15s} "
                f"{_BOLD}{e['count']:>5,}{_RESET} events  "
                f"{_DIM}{e['first_seen']} → {e['last_seen']}{_RESET}"
            )
    else:
        print(f"  {_WARN} No ICS honeypot events in database")

    if patterns:
        print(f"\n  {_CYAN}Attack patterns detected:{_RESET}")
        for p in patterns:
            print(
                f"    {p['attack_type']:15s} {p['rule_name']:35s} {_BOLD}{p['count']:>5,}{_RESET}"
            )
    print()


# ─── Main ────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="ICS/OT Honeypot Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.0.2.10                    # Test all protocols
  %(prog)s --target 192.0.2.10 --protocol modbus  # Test Modbus only
  %(prog)s --target 192.0.2.10 --all --verbose    # Verbose with hex dumps
  %(prog)s --check-db                                # Check DB for events (run on sensor)
        """,
    )
    parser.add_argument(
        "--target", "-t", default="localhost", help="Target IP (default: localhost)"
    )
    parser.add_argument(
        "--protocol", "-p", choices=list(PROTOCOLS.keys()), help="Test specific protocol only"
    )
    parser.add_argument("--all", "-a", action="store_true", help="Test all protocols (default)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show response hex dumps")
    parser.add_argument(
        "--check-db", action="store_true", help="Check database for ICS events (run on sensor)"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3)"
    )
    args = parser.parse_args()

    if args.check_db:
        protos = [args.protocol] if args.protocol else list(PROTOCOLS.keys())
        db_data = check_db_events(args.target, protos)
        if args.json:
            print(json.dumps(db_data, indent=2, default=str))
        else:
            print_db_results(db_data)
        return

    # Select protocols to test
    if args.protocol:
        to_test = {args.protocol: PROTOCOLS[args.protocol]}
    else:
        to_test = PROTOCOLS

    print(f"\n{_BOLD}Testing ICS/OT honeypots on {_CYAN}{args.target}{_RESET}")
    print(f"{_DIM}Protocols: {', '.join(to_test.keys())}{_RESET}\n")

    results = []
    for name, proto_def in to_test.items():
        result = run_test(args.target, name, proto_def, verbose=args.verbose)
        results.append(result)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_results(results, verbose=args.verbose)


if __name__ == "__main__":
    main()
