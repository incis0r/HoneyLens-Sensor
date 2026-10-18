#!/usr/bin/env python3
"""
honeypots/hp_iec104.py — IEC 60870-5-104 Honeypot
===================================================
Simulates an IEC 104 RTU/substation gateway. Responds to STARTDT,
TESTFR, interrogation and command ASDUs, logs all ICS-relevant events.

Run: python -m honeypots.hp_iec104
Service: sensor-hp-iec104 (port 2404)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# ---------------------------------------------------------------------------
# ASDU Type ID catalogue
# ---------------------------------------------------------------------------
ASDU_TYPE_NAMES = {
    1: "M_SP_NA_1 Single Point Info",
    3: "M_DP_NA_1 Double Point Info",
    9: "M_ME_NA_1 Measured Normalized",
    11: "M_ME_NB_1 Measured Scaled",
    13: "M_ME_NC_1 Measured Short Float",
    30: "M_SP_TB_1 Single Point w/ CP56",
    45: "C_SC_NA_1 Single Command",
    46: "C_DC_NA_1 Double Command",
    47: "C_RC_NA_1 Regulating Step",
    48: "C_SE_NA_1 Setpoint Normalized",
    49: "C_SE_NB_1 Setpoint Scaled",
    50: "C_SE_NC_1 Setpoint Short Float",
    51: "C_SE_ND_1 Setpoint Normalized w/o QOS",
    100: "C_IC_NA_1 Interrogation Command",
    101: "C_CI_NA_1 Counter Interrogation",
    102: "C_RD_NA_1 Read Command",
    103: "C_CS_NA_1 Clock Sync",
    105: "C_RP_NA_1 Reset Process",
}

# Sets for classification
COMMAND_TYPE_IDS = {45, 46, 47, 48, 49, 50, 51, 105}
RECON_TYPE_IDS = {100, 101, 102}
CLOCK_SYNC_TYPE_IDS = {103}

# U-frame control byte values
STARTDT_ACT = 0x07
STARTDT_CON = 0x0B
STOPDT_ACT = 0x13
STOPDT_CON = 0x23
TESTFR_ACT = 0x43
TESTFR_CON = 0x83

UFRAME_NAMES = {
    STARTDT_ACT: "STARTDT act",
    STARTDT_CON: "STARTDT con",
    STOPDT_ACT: "STOPDT act",
    STOPDT_CON: "STOPDT con",
    TESTFR_ACT: "TESTFR act",
    TESTFR_CON: "TESTFR con",
}

START_BYTE = 0x68
MAX_APDU_LEN = 253


class IEC104Honeypot(BaseHoneypot):
    PROTOCOL = "iec104"
    DEFAULT_PORT = 2404
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.station_name = p.get("station_name", "Substation-Alpha RTU")
        self.vendor = p.get("vendor", "ABB")
        self.ioa_count = int(p.get("ioa_count", 100))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_apdu(control: bytes, asdu: bytes = b"") -> bytes:
        """Build a full APDU: start byte + length + control + optional ASDU."""
        body = control + asdu
        return bytes([START_BYTE, len(body)]) + body

    def _build_uframe(self, ctrl_byte: int) -> bytes:
        """Build a U-frame APDU."""
        return self._build_apdu(bytes([ctrl_byte, 0x00, 0x00, 0x00]))

    def _build_sframe(self, rsn: int) -> bytes:
        """Build an S-frame acknowledging up to rsn."""
        ctrl = struct.pack("<HH", 0x01, rsn << 1)
        return self._build_apdu(ctrl)

    def _build_iframe(self, ssn: int, rsn: int, asdu: bytes) -> bytes:
        """Build an I-frame carrying an ASDU."""
        ctrl = struct.pack("<HH", ssn << 1, rsn << 1)
        return self._build_apdu(ctrl, asdu)

    @staticmethod
    def _frame_type(ctrl: bytes) -> str:
        """Return 'U', 'S', or 'I' based on control field."""
        if ctrl[0] & 0x03 == 0x03:
            return "U"
        if ctrl[0] & 0x03 == 0x01:
            return "S"
        return "I"

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------
    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[IEC104] Connection from %s:%d", peer[0], peer[1])

        ssn = 0  # send sequence number
        rsn = 0  # receive sequence number
        data_transfer_active = False

        try:
            while True:
                # Read start byte
                start = await asyncio.wait_for(reader.readexactly(1), timeout=60)
                if start[0] != START_BYTE:
                    continue

                # Read length
                length_byte = await asyncio.wait_for(reader.readexactly(1), timeout=10)
                apdu_len = length_byte[0]
                if apdu_len < 4 or apdu_len > MAX_APDU_LEN:
                    break

                # Read rest of APDU (control field + optional ASDU)
                body = await asyncio.wait_for(reader.readexactly(apdu_len), timeout=10)
                ctrl = body[0:4]
                asdu_bytes = body[4:] if len(body) > 4 else b""

                ftype = self._frame_type(ctrl)

                # --- U-frame ------------------------------------------------
                if ftype == "U":
                    utype = ctrl[0]
                    uname = UFRAME_NAMES.get(utype, f"U-0x{utype:02X}")

                    event_data = {
                        "dst_port": self.port,
                        "phase": "iec104_uframe",
                        "rule": uname,
                        "payload": f"U-frame {uname}",
                        "frame_type": "U",
                        "ctrl_hex": ctrl.hex(),
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    self.logger.info("[IEC104] %s U-frame: %s", peer[0], uname)

                    # Respond to activation requests
                    if utype == STARTDT_ACT:
                        writer.write(self._build_uframe(STARTDT_CON))
                        await writer.drain()
                        data_transfer_active = True
                    elif utype == TESTFR_ACT:
                        writer.write(self._build_uframe(TESTFR_CON))
                        await writer.drain()
                    elif utype == STOPDT_ACT:
                        writer.write(self._build_uframe(STOPDT_CON))
                        await writer.drain()
                        data_transfer_active = False

                # --- S-frame ------------------------------------------------
                elif ftype == "S":
                    ack_rsn = struct.unpack("<H", ctrl[2:4])[0] >> 1
                    event_data = {
                        "dst_port": self.port,
                        "phase": "iec104_sframe",
                        "rule": "S-frame ACK",
                        "payload": f"S-frame ACK rsn={ack_rsn}",
                        "frame_type": "S",
                        "ctrl_hex": ctrl.hex(),
                        "ack_rsn": ack_rsn,
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    self.logger.debug("[IEC104] %s S-frame ACK rsn=%d", peer[0], ack_rsn)

                # --- I-frame ------------------------------------------------
                elif ftype == "I":
                    tx_ssn = struct.unpack("<H", ctrl[0:2])[0] >> 1
                    tx_rsn = struct.unpack("<H", ctrl[2:4])[0] >> 1
                    rsn = (tx_ssn + 1) & 0x7FFF  # next expected

                    # Parse ASDU header (minimum 7 bytes: TypeID+SQ+COT(2)+CA(2)+IOA(3-byte first))
                    type_id = cot = ca = ioa = None
                    if len(asdu_bytes) >= 6:
                        type_id = asdu_bytes[0]
                        asdu_bytes[1]
                        cot = struct.unpack("<H", asdu_bytes[2:4])[0]
                        ca = struct.unpack("<H", asdu_bytes[4:6])[0]
                        if len(asdu_bytes) >= 9:
                            ioa = asdu_bytes[6] | (asdu_bytes[7] << 8) | (asdu_bytes[8] << 16)

                    type_name = (
                        ASDU_TYPE_NAMES.get(type_id, f"TypeID_{type_id}")
                        if type_id is not None
                        else "unknown"
                    )

                    # Classify
                    attack_type = None
                    severity = None
                    if type_id is not None:
                        if type_id in COMMAND_TYPE_IDS:
                            attack_type = "ICS_ATTACK"
                            severity = "CRITICAL"
                        elif type_id in CLOCK_SYNC_TYPE_IDS:
                            attack_type = "ICS_ATTACK"
                            severity = "MEDIUM"
                        elif type_id in RECON_TYPE_IDS:
                            attack_type = "ICS_RECON"
                            severity = "MEDIUM" if type_id in (100, 101) else "LOW"
                        elif type_id == 1:
                            # Monitor-only, just log
                            severity = "LOW"

                    event_data = {
                        "dst_port": self.port,
                        "phase": "iec104_iframe",
                        "rule": type_name,
                        "payload": (
                            f"I-frame TypeID={type_id} ({type_name}) "
                            f"COT={cot} CA={ca} IOA={ioa} SSN={tx_ssn} RSN={tx_rsn}"
                        ),
                        "frame_type": "I",
                        "ctrl_hex": ctrl.hex(),
                        "asdu_hex": asdu_bytes.hex(),
                        "type_id": type_id,
                        "type_name": type_name,
                        "cot": cot,
                        "common_address": ca,
                        "ioa": ioa,
                        "ssn": tx_ssn,
                        "rsn": tx_rsn,
                    }
                    log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

                    if attack_type == "ICS_ATTACK":
                        self.logger.warning(
                            "[IEC104] %s COMMAND TypeID=%s COT=%s CA=%s IOA=%s",
                            peer[0],
                            type_id,
                            cot,
                            ca,
                            ioa,
                        )
                    elif attack_type == "ICS_RECON":
                        self.logger.info(
                            "[IEC104] %s RECON TypeID=%s COT=%s CA=%s",
                            peer[0],
                            type_id,
                            cot,
                            ca,
                        )
                    else:
                        self.logger.info(
                            "[IEC104] %s I-frame TypeID=%s COT=%s CA=%s",
                            peer[0],
                            type_id,
                            cot,
                            ca,
                        )

                    # Send S-frame acknowledgment
                    writer.write(self._build_sframe(rsn))
                    await writer.drain()

                    # For interrogation commands, send a simple
                    # activation confirmation I-frame back
                    if type_id == 100 and data_transfer_active and len(asdu_bytes) >= 6:
                        # Mirror ASDU with COT = 7 (activation confirmation)
                        resp_asdu = (
                            bytes(
                                [
                                    type_id,
                                    asdu_bytes[1],  # SQ+number
                                ]
                            )
                            + struct.pack("<H", 7)
                            + asdu_bytes[4:]
                        )  # COT=7, rest unchanged
                        writer.write(self._build_iframe(ssn, rsn, resp_asdu))
                        await writer.drain()
                        ssn = (ssn + 1) & 0x7FFF

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    IEC104Honeypot().run()
