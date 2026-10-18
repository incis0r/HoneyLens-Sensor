#!/usr/bin/env python3
"""
honeypots/hp_iec104.py — IEC 60870-5-104 Honeypot
===================================================
Simulates an IEC 104 RTU/substation gateway. Responds to STARTDT,
TESTFR, interrogation and command ASDUs, logs all ICS-relevant events.

A byte stream is IEC-104 only if it is framed as IEC-104 from its first byte. Until
2026-11-19 the loop skipped bytes until it met 0x68 — ASCII ``h`` — and parsed what followed,
so a web scanner's ``Host:`` and a TLS ClientHello's ``http/1.1`` became U-, S- and I-frames,
and 25 handshakes on one sensor became CRITICAL "Double Command" verdicts. ``check_apci`` and
``parse_asdu`` below are the recognition; ``handle_connection`` refuses to resynchronise.

Run: python -m honeypots.hp_iec104
Service: sensor-hp-iec104 (port 2404)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import guess_foreign, preview

# ---------------------------------------------------------------------------
# ASDU Type ID catalogue — the types IEC 60870-5-104 assigns. The 101-only types with a
# CP24Time2a tag (2, 4, 6, ...) and 104/106 are deliberately absent: 104 does not use them,
# so a frame carrying one is not a 104 frame.
# ---------------------------------------------------------------------------
ASDU_TYPE_NAMES = {
    1: "M_SP_NA_1 Single Point Info",
    3: "M_DP_NA_1 Double Point Info",
    5: "M_ST_NA_1 Step Position",
    7: "M_BO_NA_1 Bitstring",
    9: "M_ME_NA_1 Measured Normalized",
    11: "M_ME_NB_1 Measured Scaled",
    13: "M_ME_NC_1 Measured Short Float",
    15: "M_IT_NA_1 Integrated Totals",
    20: "M_PS_NA_1 Packed Single Point",
    21: "M_ME_ND_1 Measured Normalized w/o quality",
    30: "M_SP_TB_1 Single Point w/ CP56",
    31: "M_DP_TB_1 Double Point w/ CP56",
    32: "M_ST_TB_1 Step Position w/ CP56",
    33: "M_BO_TB_1 Bitstring w/ CP56",
    34: "M_ME_TD_1 Measured Normalized w/ CP56",
    35: "M_ME_TE_1 Measured Scaled w/ CP56",
    36: "M_ME_TF_1 Measured Short Float w/ CP56",
    37: "M_IT_TB_1 Integrated Totals w/ CP56",
    38: "M_EP_TD_1 Protection Event w/ CP56",
    39: "M_EP_TE_1 Protection Start Events w/ CP56",
    40: "M_EP_TF_1 Protection Output Circuit w/ CP56",
    45: "C_SC_NA_1 Single Command",
    46: "C_DC_NA_1 Double Command",
    47: "C_RC_NA_1 Regulating Step",
    48: "C_SE_NA_1 Setpoint Normalized",
    49: "C_SE_NB_1 Setpoint Scaled",
    50: "C_SE_NC_1 Setpoint Short Float",
    51: "C_BO_NA_1 Bitstring command",
    58: "C_SC_TA_1 Single Command w/ CP56",
    59: "C_DC_TA_1 Double Command w/ CP56",
    60: "C_RC_TA_1 Regulating Step w/ CP56",
    61: "C_SE_TA_1 Setpoint Normalized w/ CP56",
    62: "C_SE_TB_1 Setpoint Scaled w/ CP56",
    63: "C_SE_TC_1 Setpoint Short Float w/ CP56",
    64: "C_BO_TA_1 Bitstring command w/ CP56",
    70: "M_EI_NA_1 End of Initialization",
    100: "C_IC_NA_1 Interrogation Command",
    101: "C_CI_NA_1 Counter Interrogation",
    102: "C_RD_NA_1 Read Command",
    103: "C_CS_NA_1 Clock Sync",
    105: "C_RP_NA_1 Reset Process",
    107: "C_TS_TA_1 Test Command w/ CP56",
    110: "P_ME_NA_1 Parameter Normalized",
    111: "P_ME_NB_1 Parameter Scaled",
    112: "P_ME_NC_1 Parameter Short Float",
    113: "P_AC_NA_1 Parameter Activation",
    120: "F_FR_NA_1 File Ready",
    121: "F_SR_NA_1 Section Ready",
    122: "F_SC_NA_1 Call Directory / Select File",
    123: "F_LS_NA_1 Last Section",
    124: "F_AF_NA_1 Ack File",
    125: "F_SG_NA_1 Segment",
    126: "F_DR_TA_1 Directory",
    127: "F_SC_NB_1 Query Log",
}

# Sets for classification. 58-64 are 45-51 with a time tag: the same breaker operation, and
# the form a master that keeps its clock synchronised actually sends.
COMMAND_TYPE_IDS = {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64, 105}
PARAMETER_TYPE_IDS = {110, 111, 112, 113}
RECON_TYPE_IDS = {100, 101, 102, 107, 120, 121, 122, 123, 124, 125, 126, 127}
CLOCK_SYNC_TYPE_IDS = {103}

# Bytes of one information element after the 3-byte IOA, for the control-direction types
# whose size the standard fixes. A command ASDU is exactly 6 + n * (3 + size) bytes; this is
# the check that tells a Double Command from a TLS extension that starts with 0x2e.
_ELEMENT_SIZE = {
    45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 4,
    58: 8, 59: 8, 60: 8, 61: 10, 62: 10, 63: 12, 64: 11,
    100: 1, 101: 1, 102: 0, 103: 7, 105: 1, 107: 9,
    110: 3, 111: 3, 112: 5, 113: 1,
}  # fmt: skip

# Causes of transmission the standard defines (6 low bits of the first COT octet).
_VALID_CAUSES = frozenset({*range(1, 14), *range(20, 42), *range(44, 48)})

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
_UFRAME_ACTIVATIONS = frozenset({STARTDT_ACT, STOPDT_ACT, TESTFR_ACT})

START_BYTE = 0x68
MAX_APDU_LEN = 253
# How much of a stream that is not IEC-104 the decoy still reads before it says so.
_FOREIGN_READ = 4096


def check_apci(ctrl: bytes, apdu_len: int) -> tuple[str | None, str | None]:
    """Recognise the control field: ``("I" | "S" | "U", None)``, or ``(None, why not)``.

    IEC 60870-5-104 §5 fixes more than the two low bits the old test looked at. A U-format
    APDU is exactly four octets, one of six function codes, the other three zero. An S-format
    one is exactly ``01 00`` plus a receive number whose bit 0 is clear. An I-format one has
    bit 0 clear in octets 1 and 3 and must carry an ASDU.
    """
    if len(ctrl) < 4:
        return None, "control field shorter than four octets"
    low = ctrl[0] & 0x03
    if low == 0x03:
        if ctrl[0] not in UFRAME_NAMES:
            return None, f"U-format with unassigned function 0x{ctrl[0]:02X}"
        if ctrl[1:4] != b"\x00\x00\x00":
            return None, "U-format with non-zero octets 2-4"
        if apdu_len != 4:
            return None, f"U-format APDU of length {apdu_len}, not 4"
        return "U", None
    if low == 0x01:
        if ctrl[0] != 0x01 or ctrl[1] != 0x00:
            return None, "S-format whose first two octets are not 01 00"
        if ctrl[2] & 0x01:
            return None, "S-format with bit 0 of octet 3 set"
        if apdu_len != 4:
            return None, f"S-format APDU of length {apdu_len}, not 4"
        return "S", None
    if ctrl[0] & 0x01 or ctrl[2] & 0x01:
        return None, "I-format with bit 0 of octet 1 or 3 set"
    if apdu_len <= 4:
        return None, "I-format APDU without an ASDU"
    return "I", None


def parse_asdu(asdu: bytes) -> dict:
    """The ASDU header as the standard lays it out, and whether the ASDU is plausible.

    ``cot`` is the cause alone. It used to be the two COT octets read as one integer, which is
    the cause only while the originator address is zero: a deactivation from originator 104
    was stored as ``COT=26632``.
    """
    out: dict = {
        "type_id": None,
        "type_name": "unknown",
        "sq": None,
        "num_objects": None,
        "cot": None,
        "cot_negative": None,
        "cot_test": None,
        "originator": None,
        "common_address": None,
        "ioa": None,
        "defect": None,
    }
    if len(asdu) < 6:
        out["defect"] = f"ASDU of {len(asdu)} byte(s) ends inside its 6-byte header"
        if asdu:
            out["type_id"] = asdu[0]
            out["type_name"] = ASDU_TYPE_NAMES.get(asdu[0], f"TypeID_{asdu[0]}")
        return out
    type_id = asdu[0]
    out["type_id"] = type_id
    out["type_name"] = ASDU_TYPE_NAMES.get(type_id, f"TypeID_{type_id}")
    out["sq"] = bool(asdu[1] & 0x80)
    out["num_objects"] = n = asdu[1] & 0x7F
    out["cot"] = cause = asdu[2] & 0x3F
    out["cot_negative"] = bool(asdu[2] & 0x40)
    out["cot_test"] = bool(asdu[2] & 0x80)
    out["originator"] = asdu[3]
    out["common_address"] = struct.unpack("<H", asdu[4:6])[0]
    if len(asdu) >= 9:
        out["ioa"] = int.from_bytes(asdu[6:9], "little")

    if type_id not in ASDU_TYPE_NAMES:
        out["defect"] = f"type identification {type_id} is not assigned in IEC 60870-5-104"
    elif n == 0:
        out["defect"] = "variable structure qualifier announces zero information objects"
    elif cause not in _VALID_CAUSES:
        out["defect"] = f"cause of transmission {cause} is not defined"
    elif len(asdu) < 9:
        out["defect"] = "ASDU ends before the information object address"
    elif type_id in _ELEMENT_SIZE:
        size = _ELEMENT_SIZE[type_id]
        want = 6 + (3 + n * size if out["sq"] else n * (3 + size))
        if len(asdu) != want:
            out["defect"] = (
                f"{out['type_name'].split()[0]} with {n} object(s) is {want} bytes, got {len(asdu)}"
            )
    return out


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
    async def _read_apdu(self, reader, first: bool):
        """Read one APDU. Returns ``(consumed, ctrl, asdu, kind, defect)``; ``consumed`` is
        ``b""`` only on a clean end of stream. Never skips a byte to find a start."""
        try:
            start = await asyncio.wait_for(reader.readexactly(1), timeout=60)
        except asyncio.IncompleteReadError:
            return b"", b"", b"", None, None
        consumed = start
        if start[0] != START_BYTE:
            return (
                consumed,
                b"",
                b"",
                None,
                f"byte 0x{start[0]:02X} where the start byte 0x68 belongs",
            )
        try:
            length_byte = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        except asyncio.IncompleteReadError as exc:
            return consumed + exc.partial, b"", b"", None, "stream ends after the start byte"
        consumed += length_byte
        apdu_len = length_byte[0]
        if apdu_len < 4 or apdu_len > MAX_APDU_LEN:
            return consumed, b"", b"", None, f"APDU length {apdu_len} is outside 4..{MAX_APDU_LEN}"
        try:
            body = await asyncio.wait_for(reader.readexactly(apdu_len), timeout=10)
        except asyncio.IncompleteReadError as exc:
            why = f"stream ends {len(exc.partial)} byte(s) into an APDU announced as {apdu_len}"
            return consumed + exc.partial, b"", b"", None, why
        consumed += body
        ctrl, asdu_bytes = body[0:4], body[4:]
        kind, defect = check_apci(ctrl, apdu_len)
        if kind == "I" and first:
            # The two-bit I-format test passes a quarter of all text. A connection that OPENS
            # with an I-format frame whose ASDU is not a 104 ASDU is not a 104 connection.
            asdu_defect = parse_asdu(asdu_bytes)["defect"]
            if asdu_defect:
                return (
                    consumed,
                    ctrl,
                    asdu_bytes,
                    None,
                    f"opens with an I-format frame, but {asdu_defect}",
                )
        return consumed, ctrl, asdu_bytes, kind, defect

    async def _not_iec104(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) IEC-104, then nothing more."""
        try:
            rest = await asyncio.wait_for(reader.read(_FOREIGN_READ), timeout=2)
        except (TimeoutError, ConnectionError):
            rest = b""
        data = consumed + rest
        guess = guess_foreign(data)
        event_data = {
            "dst_port": self.port,
            "defect": defect,
            "foreign_protocol": guess,
            "client_bytes": len(data),
            "preview": preview(data),
            "first_bytes_hex": data[:64].hex(),
        }
        if frames == 0:
            # Not an ICS exchange at all: `ics: False` keeps it out of ics_events, as Fox
            # does for HTTP on 1911.
            event_data.update(
                phase="foreign_on_ics_port",
                ics=False,
                rule=f"not IEC-104: {guess}",
                payload=f"non-IEC-104 traffic on port {self.port}: {guess}, {len(data)} bytes",
            )
            log_event(
                self.PROTOCOL, peer, event_data, "SCANNER", "LOW", raw=data[:MAX_RAW_EVENT_BYTES]
            )
        else:
            # A peer that framed correctly and then stopped: a fuzzer or a broken client.
            event_data.update(
                phase="iec104_desync",
                frames_before=frames,
                rule="malformed frame after a valid session",
                payload=f"IEC-104 framing lost after {frames} frame(s): {defect}",
            )
            log_event(
                self.PROTOCOL, peer, event_data, "ICS_RECON", "LOW", raw=data[:MAX_RAW_EVENT_BYTES]
            )
        self.logger.info("[IEC104] %s not IEC-104 (%s): %s", peer[0], guess, defect)

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[IEC104] Connection from %s:%d", peer[0], peer[1])

        ssn = 0  # send sequence number
        rsn = 0  # receive sequence number
        data_transfer_active = False
        frames = 0  # valid APDUs received on this connection

        try:
            while True:
                consumed, ctrl, asdu_bytes, ftype, defect = await self._read_apdu(
                    reader, first=frames == 0
                )
                if not consumed:
                    return
                if defect:
                    await self._not_iec104(reader, peer, consumed, defect, frames)
                    return
                frames += 1
                # The APCI frame as received. ctrl_hex (kept) is not a key ingest reads, so
                # a U- or S-frame row decoded to nothing; frame_hex is.
                apci = frame_hex(consumed)

                # --- U-frame ------------------------------------------------
                if ftype == "U":
                    utype = ctrl[0]
                    uname = UFRAME_NAMES[utype]

                    event_data = {
                        "dst_port": self.port,
                        "phase": "iec104_uframe",
                        "rule": uname,
                        "payload": f"U-frame {uname}",
                        "frame_type": "U",
                        "ctrl_hex": ctrl.hex(),
                        "frame_hex": apci,
                    }
                    # An activation from the controlling side is someone opening, testing or
                    # stopping a 104 session with an outstation: reconnaissance by itself.
                    # A confirmation is an answer to something this decoy never sends.
                    if utype in _UFRAME_ACTIVATIONS:
                        log_event(self.PROTOCOL, peer, event_data, "ICS_RECON", "LOW")
                    else:
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
                        "frame_hex": apci,
                        "ack_rsn": ack_rsn,
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    self.logger.debug("[IEC104] %s S-frame ACK rsn=%d", peer[0], ack_rsn)

                # --- I-frame ------------------------------------------------
                elif ftype == "I":
                    tx_ssn = struct.unpack("<H", ctrl[0:2])[0] >> 1
                    tx_rsn = struct.unpack("<H", ctrl[2:4])[0] >> 1
                    rsn = (tx_ssn + 1) & 0x7FFF  # next expected

                    asdu = parse_asdu(asdu_bytes)
                    type_id = asdu["type_id"]
                    type_name = asdu["type_name"]
                    cot, ca, ioa = asdu["cot"], asdu["common_address"], asdu["ioa"]

                    # Classify. A verdict that names an operation needs an ASDU that is one:
                    # a command type id over bytes of the wrong shape is not a command.
                    attack_type = None
                    severity = None
                    if asdu["defect"]:
                        attack_type, severity = "ICS_RECON", "LOW"
                    elif type_id in COMMAND_TYPE_IDS:
                        attack_type, severity = "ICS_ATTACK", "CRITICAL"
                    elif type_id in PARAMETER_TYPE_IDS:
                        attack_type, severity = "ICS_ATTACK", "HIGH"
                    elif type_id in CLOCK_SYNC_TYPE_IDS:
                        attack_type, severity = "ICS_ATTACK", "MEDIUM"
                    elif type_id in RECON_TYPE_IDS:
                        attack_type = "ICS_RECON"
                        severity = "MEDIUM" if type_id in (100, 101) else "LOW"
                    elif type_id == 1:
                        # Monitor-only, just log
                        severity = "LOW"

                    event_data = {
                        "dst_port": self.port,
                        "phase": "iec104_iframe",
                        "rule": "malformed ASDU" if asdu["defect"] else type_name,
                        "payload": (
                            f"I-frame TypeID={type_id} ({type_name}) "
                            f"COT={cot} OA={asdu['originator']} CA={ca} IOA={ioa} "
                            f"SSN={tx_ssn} RSN={tx_rsn}"
                        ),
                        "frame_type": "I",
                        "ctrl_hex": ctrl.hex(),
                        "frame_hex": apci,
                        "asdu_hex": asdu_bytes.hex(),
                        "type_id": type_id,
                        "type_name": type_name,
                        "sq": asdu["sq"],
                        "num_objects": asdu["num_objects"],
                        "cot": cot,
                        "cot_negative": asdu["cot_negative"],
                        "cot_test": asdu["cot_test"],
                        "originator": asdu["originator"],
                        "common_address": ca,
                        "ioa": ioa,
                        "ssn": tx_ssn,
                        "rsn": tx_rsn,
                        # A real outstation ignores an I-frame before STARTDT; the sender's
                        # intent is still the event, so it is recorded and flagged.
                        "before_startdt": not data_transfer_active,
                    }
                    if asdu["defect"]:
                        event_data["asdu_defect"] = asdu["defect"]
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
                    if type_id == 100 and data_transfer_active and not asdu["defect"]:
                        # Mirror ASDU with COT = 7 (activation confirmation)
                        # COT=7; the originator address is echoed, as an outstation does.
                        resp_asdu = (
                            bytes([type_id, asdu_bytes[1], 7, asdu_bytes[3]]) + asdu_bytes[4:]
                        )
                        writer.write(self._build_iframe(ssn, rsn, resp_asdu))
                        await writer.drain()
                        ssn = (ssn + 1) & 0x7FFF

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    IEC104Honeypot().run()
