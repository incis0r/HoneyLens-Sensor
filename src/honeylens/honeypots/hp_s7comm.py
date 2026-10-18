"""
honeypots/hp_s7comm.py — Modular S7comm (Siemens PLC) honeypot service
========================================================================
Emulates a Siemens S7 PLC over TPKT/COTP + S7comm, captures ICS
reconnaissance and exploitation attempts.

Run standalone:
    python -m honeypots.hp_s7comm
    HP_S7COMM_PORT=102 python -m honeypots.hp_s7comm
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# TPKT / COTP constants
TPKT_VERSION = 3
COTP_CR = 0xE0  # Connection Request
COTP_CC = 0xD0  # Connection Confirm

# S7comm constants
S7_PROTOCOL_ID = 0x32
S7_JOB = 0x01
S7_ACK_DATA = 0x03
S7_FUNC_SETUP = 0xF0
S7_FUNC_READ_SZL = 0x44
S7_SUBFUNC_READ_SZL = 0x01


def _build_tpkt(payload: bytes) -> bytes:
    """Wrap payload in a TPKT header (version 3)."""
    length = 4 + len(payload)
    return struct.pack("!BBH", TPKT_VERSION, 0, length) + payload


def _build_cotp_cc(src_ref: int, dst_ref: int) -> bytes:
    """Build a COTP Connection Confirm (CC) packet."""
    # Length=6, CC PDU type, dst_ref, src_ref, class/option=0
    return struct.pack("!BBHHB", 6, COTP_CC, dst_ref, src_ref, 0)


def _build_cotp_dt(payload: bytes) -> bytes:
    """Build COTP Data Transfer (DT) wrapper."""
    # Length=2, DT type=0xF0, TPDU nr + EOT=0x80
    return struct.pack("!BBB", 2, 0xF0, 0x80) + payload


# Function-code classification (used by handle_s7_dt and the 102 dispatcher).
# Write Var (0x05) is a write attempt; Setup Communication, Read Var, and
# diagnostics/SZL are reconnaissance.
S7_WRITE_FUNCS = {0x05}
S7_RECON_FUNCS = {S7_FUNC_SETUP, S7_FUNC_READ_SZL, 0x04, 0x00}


def _build_s7_response(payload: bytes, profile: dict):
    """Build the S7comm response for a single S7 (0x32...) PDU.

    Returns the raw S7 response payload (without COTP/TPKT framing), or None
    when the function code has no canned response. Mirrors the response shapes
    the original handle_connection emitted for Setup Communication and Read SZL.
    """
    if len(payload) < 10 or payload[0] != S7_PROTOCOL_ID:
        return None

    pdu_ref = struct.unpack("!H", payload[4:6])[0]
    param_len = struct.unpack("!H", payload[6:8])[0]
    s7_params = payload[10 : 10 + param_len] if param_len else b""
    func_code = s7_params[0] if s7_params else 0

    if func_code == S7_FUNC_SETUP:
        # Setup Communication — negotiate PDU size.
        # Response: function 0xF0, reserved, max_amq_calling=1,
        # max_amq_called=1, pdu_size=480
        resp_params = struct.pack("!BBHHH", S7_FUNC_SETUP, 0, 1, 1, 480)
        return (
            struct.pack(
                "!BBHHHHH",
                S7_PROTOCOL_ID,
                S7_ACK_DATA,
                0,
                pdu_ref,
                len(resp_params),
                0,
                0,
            )
            + resp_params
        )

    if func_code == S7_FUNC_READ_SZL:
        # Read SZL — return PLC identity from the profile.
        plc_name = profile.get("plc_name", "S7-1200 CPU 1214C")
        module_type = profile.get("module_type", "6ES7 214-1AG40-0XB0")
        serial = profile.get("serial", "S C-L9E87654321")
        firmware = profile.get("firmware", "V4.5.2")
        plant_id = profile.get("plant_id", "WaterTreatment-PLC03")

        identity = (
            f"Order Number: {module_type}\x00"
            f"Serial: {serial}\x00"
            f"PLC Name: {plc_name}\x00"
            f"Firmware: {firmware}\x00"
            f"Plant ID: {plant_id}\x00"
        ).encode()

        # Userdata response: func=0x00, subfunc return_data
        szl_header = struct.pack("!BBB", S7_FUNC_READ_SZL, S7_SUBFUNC_READ_SZL, 0)
        return (
            struct.pack(
                "!BBHHHHH",
                S7_PROTOCOL_ID,
                S7_ACK_DATA,
                0,
                pdu_ref,
                len(szl_header),
                len(identity),
                0,
            )
            + szl_header
            + identity
        )

    return None


def handle_s7_dt(payload: bytes, profile: dict):
    """Process one S7 (0x32...) PDU. Return (response_payload, kind).

    `kind` is one of "write" / "recon" / "enumeration" for the ICS taxonomy.
    `response_payload` is the raw S7 response (caller wraps it in COTP DT +
    TPKT), or None when there is no canned response for this function code.
    """
    if len(payload) < 2 or payload[0] != S7_PROTOCOL_ID:
        return None, "enumeration"
    func = payload[10] if len(payload) > 10 else 0x00
    if func in S7_WRITE_FUNCS:
        kind = "write"
    elif func in S7_RECON_FUNCS:
        kind = "recon"
    else:
        kind = "enumeration"
    resp = _build_s7_response(payload, profile)
    return resp, kind


class S7commHoneypot(BaseHoneypot):
    """Low-interaction S7comm honeypot over TPKT/COTP.

    Handles COTP connection setup, S7 Setup Communication, and
    Read SZL requests, returning fake PLC identity from the profile.
    """

    PROTOCOL = "s7comm"
    DEFAULT_PORT = 102
    TTL_PROFILE = "plc"

    async def handle_connection(self, reader, writer, peer):
        plc_name = self.profile.get("plc_name", "S7-1200 CPU 1214C")
        self.profile.get("module_type", "6ES7 214-1AG40-0XB0")
        self.profile.get("serial", "S C-L9E87654321")
        self.profile.get("firmware", "V4.5.2")
        self.profile.get("plant_id", "WaterTreatment-PLC03")

        self.logger.info("[S7COMM] %s:%d connected", peer[0], peer[1])

        try:
            # --- Phase 1: TPKT + COTP Connection Request ---
            tpkt_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            ver, _, tpkt_len = struct.unpack("!BBH", tpkt_hdr)
            if ver != TPKT_VERSION:
                self.logger.debug("[S7COMM] %s:%d non-TPKT traffic (ver=%d)", peer[0], peer[1], ver)
                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "ics_probe",
                        "message": "Non-TPKT traffic on S7 port",
                        "dst_port": self.port,
                    },
                    attack_type="ICS_ATTACK",
                    severity="MEDIUM",
                )
                return

            cotp_data = await asyncio.wait_for(reader.readexactly(tpkt_len - 4), timeout=10)
            cotp_data[0]
            cotp_type = cotp_data[1] & 0xF0

            if cotp_type != COTP_CR:
                self.logger.debug(
                    "[S7COMM] %s:%d expected CR, got 0x%02x", peer[0], peer[1], cotp_type
                )
                return

            # Parse source/dest references from CR
            struct.unpack("!H", cotp_data[2:4])[0] if len(cotp_data) >= 4 else 0
            src_ref = struct.unpack("!H", cotp_data[4:6])[0] if len(cotp_data) >= 6 else 0

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "cotp_connect",
                    "message": "COTP Connection Request received",
                    "dst_port": self.port,
                },
            )

            # Send Connection Confirm
            cc = _build_cotp_cc(src_ref=0x0001, dst_ref=src_ref)
            writer.write(_build_tpkt(cc))
            await writer.drain()

            # --- Phase 2: S7comm over COTP DT ---
            while True:
                tpkt_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                ver, _, tpkt_len = struct.unpack("!BBH", tpkt_hdr)
                if ver != TPKT_VERSION:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "ics_probe",
                            "message": "Non-S7 traffic after COTP established (possible MMS/IEC 61850)",
                            "dst_port": self.port,
                        },
                        attack_type="ICS_ATTACK",
                        severity="MEDIUM",
                    )
                    return

                pdu_data = await asyncio.wait_for(reader.readexactly(tpkt_len - 4), timeout=10)

                # Skip COTP DT header (3 bytes: length, type 0xF0, tpdu_nr)
                if len(pdu_data) < 4:
                    break
                cotp_hdr_len = pdu_data[0] + 1
                s7_data = pdu_data[cotp_hdr_len:]

                if len(s7_data) < 10 or s7_data[0] != S7_PROTOCOL_ID:
                    self.logger.debug("[S7COMM] %s:%d non-S7 PDU after COTP", peer[0], peer[1])
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "ics_probe",
                            "message": "Non-S7comm PDU after COTP (possible ICS probe)",
                            "dst_port": self.port,
                        },
                        attack_type="ICS_ATTACK",
                        severity="MEDIUM",
                    )
                    return

                param_len = struct.unpack("!H", s7_data[6:8])[0]
                s7_params = s7_data[10 : 10 + param_len] if param_len else b""
                func_code = s7_params[0] if s7_params else 0

                # Delegate per-PDU decision + response building to the reusable
                # handler so the port-102 dispatcher can share the same logic.
                s7_resp, _kind = handle_s7_dt(s7_data, self.profile)

                if func_code == S7_FUNC_SETUP:
                    # Setup Communication — negotiate PDU size
                    self.logger.info("[S7COMM] %s:%d Setup Communication", peer[0], peer[1])
                    writer.write(_build_tpkt(_build_cotp_dt(s7_resp)))
                    await writer.drain()

                elif func_code == S7_FUNC_READ_SZL:
                    # Read SZL — return PLC identity
                    self.logger.info("[S7COMM] %s:%d Read SZL (PLC identity)", peer[0], peer[1])
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "szl_read",
                            "message": "SZL identity request — ICS reconnaissance",
                            "plc_name": plc_name,
                            "dst_port": self.port,
                        },
                        attack_type="ICS_ATTACK",
                        severity="HIGH",
                    )
                    writer.write(_build_tpkt(_build_cotp_dt(s7_resp)))
                    await writer.drain()

                else:
                    self.logger.debug(
                        "[S7COMM] %s:%d unknown S7 function 0x%02x",
                        peer[0],
                        peer[1],
                        func_code,
                    )
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "unknown_s7_func",
                            "function": f"0x{func_code:02x}",
                            "dst_port": self.port,
                        },
                        attack_type="ICS_ATTACK",
                        severity="MEDIUM",
                    )
                    break

        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    S7commHoneypot().run()
