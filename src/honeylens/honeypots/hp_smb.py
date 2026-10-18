"""
honeypots/hp_smb.py — Modular SMB honeypot service
====================================================
Speaks enough SMB2 to capture NTLM authentication attempts (hashes),
share enumeration, and file operation probes.

Run standalone:
    python -m honeypots.hp_smb
    HP_SMB_PORT=445 python -m honeypots.hp_smb
"""

from __future__ import annotations

import asyncio
import os
import struct
from typing import Any, ClassVar

from honeylens.honeypots._base import BaseHoneypot, log_event


class SMBHoneypot(BaseHoneypot):
    """Low-interaction SMB2 honeypot focused on NTLM credential capture."""

    PROTOCOL = "smb"
    DEFAULT_PORT = 445
    TTL_PROFILE = "windows"
    CONNECTION_TIMEOUT = 120

    SMB2_MAGIC = b"\xfeSMB"
    SMB1_MAGIC = b"\xffSMB"
    NTLMSSP_MAGIC = b"NTLMSSP\x00"

    # SMB2 command codes
    CMD_NEGOTIATE = 0x0000
    CMD_SESSION_SETUP = 0x0001
    CMD_TREE_CONNECT = 0x0003
    CMD_CREATE = 0x0005
    CMD_IOCTL = 0x000B

    CMD_NAMES: ClassVar = {
        0x0000: "Negotiate",
        0x0001: "SessionSetup",
        0x0002: "Logoff",
        0x0003: "TreeConnect",
        0x0004: "TreeDisconnect",
        0x0005: "Create",
        0x0006: "Close",
        0x0008: "Read",
        0x0009: "Write",
        0x000B: "IOCTL",
        0x000D: "Echo",
        0x000E: "QueryDirectory",
        0x0010: "QueryInfo",
        0x0011: "SetInfo",
    }

    def __init__(self):
        super().__init__()
        self._ntlm_challenge = os.urandom(8)
        self._session_id = 0x0000000000040000
        self._tree_id = 0x00000001
        self._server_guid = os.urandom(16)
        self._hostname = self.profile.get("hostname", "WIN-SENSOR01")
        self._domain = self.profile.get("domain", "WORKGROUP")
        self._os_version = self.profile.get("os", "Windows Server 2019")
        self._shares = self.profile.get("shares", ["SHARE$", "IPC$"])

    # ---- protocol helpers ---------------------------------------------------

    @staticmethod
    def _nb_header(payload: bytes) -> bytes:
        return b"\x00" + len(payload).to_bytes(3, "big") + payload

    def _smb2_header(
        self, command, status=0, flags=0x00000001, message_id=0, session_id=0, tree_id=0
    ) -> bytes:
        hdr = self.SMB2_MAGIC
        hdr += struct.pack("<H", 64)  # StructureSize
        hdr += struct.pack("<H", 1)  # CreditCharge
        hdr += struct.pack("<I", status)
        hdr += struct.pack("<H", command)
        hdr += struct.pack("<H", 1)  # CreditResponse
        hdr += struct.pack("<I", flags)
        hdr += struct.pack("<I", 0)  # NextCommand
        hdr += struct.pack("<Q", message_id)
        hdr += struct.pack("<I", 0)  # Reserved
        hdr += struct.pack("<I", tree_id)
        hdr += struct.pack("<Q", session_id)
        hdr += b"\x00" * 16  # Signature
        return hdr

    def _negotiate_response(self, msg_id: int) -> bytes:
        hdr = self._smb2_header(self.CMD_NEGOTIATE, message_id=msg_id)
        body = struct.pack("<H", 65)
        body += struct.pack("<H", 0x01)  # SecurityMode
        body += struct.pack("<H", 0x0210)  # Dialect SMB 2.1
        body += struct.pack("<H", 0)  # NegotiateContextCount
        body += self._server_guid
        body += struct.pack("<I", 0x0000002F)  # Capabilities
        body += struct.pack("<I", 1048576) * 3  # Max sizes
        body += struct.pack("<Q", 0) * 2  # Timestamps
        body += struct.pack("<H", 128)  # SecurityBufferOffset
        body += struct.pack("<H", 0)  # SecurityBufferLength
        body += struct.pack("<I", 0)  # NegotiateContextOffset
        return self._nb_header(hdr + body)

    def _ntlm_challenge_msg(self) -> bytes:
        msg = self.NTLMSSP_MAGIC + struct.pack("<I", 2)
        domain_bytes = self._domain.encode("utf-16-le")
        target_offset = 56
        msg += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), target_offset)
        msg += struct.pack("<I", 0x00028233 | 0x00020000 | 0x00008000)
        msg += self._ntlm_challenge
        msg += b"\x00" * 8
        host_bytes = self._hostname.encode("utf-16-le")
        target_info = struct.pack("<HH", 2, len(domain_bytes)) + domain_bytes
        target_info += struct.pack("<HH", 1, len(host_bytes)) + host_bytes
        target_info += struct.pack("<HH", 0, 0)
        ti_offset = target_offset + len(domain_bytes)
        msg += struct.pack("<HHI", len(target_info), len(target_info), ti_offset)
        msg += b"\x00" * max(0, target_offset - len(msg))
        msg += domain_bytes + target_info
        return msg

    def _session_setup_response(self, msg_id, ntlm_token, status=0xC0000016):
        hdr = self._smb2_header(
            self.CMD_SESSION_SETUP, status=status, message_id=msg_id, session_id=self._session_id
        )
        body = struct.pack("<H", 9) + struct.pack("<H", 0)
        body += struct.pack("<H", 72) + struct.pack("<H", len(ntlm_token))
        body += ntlm_token
        return self._nb_header(hdr + body)

    def _tree_connect_response(self, msg_id):
        hdr = self._smb2_header(
            self.CMD_TREE_CONNECT,
            message_id=msg_id,
            session_id=self._session_id,
            tree_id=self._tree_id,
        )
        body = struct.pack("<H", 16) + struct.pack("<BB", 0x01, 0)
        body += struct.pack("<I", 0x00000030) + struct.pack("<I", 0x001F01FF) * 2
        return self._nb_header(hdr + body)

    def _error_response(self, command, msg_id, status=0xC0000022):
        hdr = self._smb2_header(
            command,
            status=status,
            message_id=msg_id,
            session_id=self._session_id,
            tree_id=self._tree_id,
        )
        body = struct.pack("<H", 9) + b"\x00\x00" + struct.pack("<I", 0) + b"\x00"
        return self._nb_header(hdr + body)

    def _parse_header(self, data: bytes) -> dict:
        if len(data) < 64:
            return {}
        return {
            "command": struct.unpack("<H", data[12:14])[0],
            "message_id": struct.unpack("<Q", data[24:32])[0],
            "session_id": struct.unpack("<Q", data[40:48])[0],
            "tree_id": struct.unpack("<I", data[36:40])[0],
        }

    def _extract_ntlm(self, data: bytes) -> dict:
        info: dict[str, Any] = {}
        pos = data.find(self.NTLMSSP_MAGIC)
        if pos < 0:
            return info
        nd = data[pos:]
        if len(nd) < 12:
            return info
        msg_type = struct.unpack("<I", nd[8:12])[0]
        info["ntlm_type"] = msg_type
        if msg_type == 1:
            info["ntlm_phase"] = "negotiate"
        elif msg_type == 3:
            info["ntlm_phase"] = "authenticate"
            try:
                nt_len = struct.unpack("<H", nd[20:22])[0]
                nt_off = struct.unpack("<I", nd[24:28])[0]
                dom_len = struct.unpack("<H", nd[28:30])[0]
                dom_off = struct.unpack("<I", nd[32:36])[0]
                usr_len = struct.unpack("<H", nd[36:38])[0]
                usr_off = struct.unpack("<I", nd[40:44])[0]
                if dom_len and dom_off:
                    info["domain"] = nd[dom_off : dom_off + dom_len].decode(
                        "utf-16-le", errors="replace"
                    )
                if usr_len and usr_off:
                    info["username"] = nd[usr_off : usr_off + usr_len].decode(
                        "utf-16-le", errors="replace"
                    )
                if nt_len > 16 and nt_off:
                    nt_resp = nd[nt_off : nt_off + nt_len]
                    info["nt_proof_str"] = nt_resp[:16].hex()
                    user = info.get("username", "unknown")
                    domain = info.get("domain", "")
                    info["ntlmv2_hash"] = (
                        f"{user}::{domain}:{self._ntlm_challenge.hex()}"
                        f":{nt_resp[:16].hex()}:{nt_resp[16:].hex()}"
                    )
            except (struct.error, IndexError):
                pass  # silent: expected from malformed NTLM frame
        return info

    # ---- connection handler -------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        msg_count = 0
        try:
            while msg_count < 200:
                nb_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=60)
                nb_len = int.from_bytes(nb_hdr[1:4], "big")
                if nb_len > 0x100000 or nb_len < 4:
                    break
                smb_data = await asyncio.wait_for(reader.readexactly(nb_len), timeout=60)

                # SMB1 probe detection
                if smb_data[:4] == self.SMB1_MAGIC:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "smb1_detected",
                            "hex": smb_data[:256].hex(),
                            "dst_port": self.port,
                        },
                        attack_type="SMB_EXPLOIT_PROBE",
                        severity="HIGH",
                    )
                    self.logger.warning("[SMB] %s SMBv1 probe detected", peer[0])
                    break

                if smb_data[:4] != self.SMB2_MAGIC:
                    break

                hdr = self._parse_header(smb_data)
                if not hdr:
                    break
                cmd = hdr["command"]
                msg_id = hdr["message_id"]
                cmd_name = self.CMD_NAMES.get(cmd, f"0x{cmd:04X}")

                if cmd == self.CMD_NEGOTIATE:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "negotiate",
                            "dst_port": self.port,
                        },
                        attack_type="SMB_SCAN",
                        severity="LOW",
                    )
                    self.logger.info("[SMB] %s Negotiate", peer[0])
                    writer.write(self._negotiate_response(msg_id))
                    await writer.drain()

                elif cmd == self.CMD_SESSION_SETUP:
                    ntlm = self._extract_ntlm(smb_data)
                    if ntlm.get("ntlm_phase") == "negotiate":
                        self.logger.info("[SMB] %s NTLM negotiate", peer[0])
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "ntlm_negotiate",
                                "dst_port": self.port,
                            },
                        )
                        writer.write(
                            self._session_setup_response(
                                msg_id, self._ntlm_challenge_msg(), status=0xC0000016
                            )
                        )
                        await writer.drain()
                    elif ntlm.get("ntlm_phase") == "authenticate":
                        self.logger.warning(
                            "[SMB] %s NTLM auth: %s\\%s",
                            peer[0],
                            ntlm.get("domain", "?"),
                            ntlm.get("username", "?"),
                        )
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "phase": "ntlm_auth",
                                "username": ntlm.get("username"),
                                "domain": ntlm.get("domain"),
                                "ntlmv2_hash": ntlm.get("ntlmv2_hash"),
                                "dst_port": self.port,
                            },
                            attack_type="CREDENTIAL_CAPTURE",
                            severity="HIGH",
                        )
                        writer.write(self._session_setup_response(msg_id, b"", status=0x00000000))
                        await writer.drain()
                    else:
                        writer.write(
                            self._session_setup_response(
                                msg_id, self._ntlm_challenge_msg(), status=0xC0000016
                            )
                        )
                        await writer.drain()

                elif cmd == self.CMD_TREE_CONNECT:
                    try:
                        body = smb_data[64:]
                        p_off = struct.unpack("<H", body[4:6])[0]
                        p_len = struct.unpack("<H", body[6:8])[0]
                        share_path = (
                            smb_data[p_off : p_off + p_len].decode("utf-16-le", errors="replace")
                            if p_off
                            else ""
                        )
                    except (struct.error, IndexError):
                        share_path = ""
                    self.logger.info("[SMB] %s TreeConnect %s", peer[0], share_path)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "tree_connect",
                            "share_path": share_path,
                            "dst_port": self.port,
                        },
                        attack_type="SMB_ENUM",
                        severity="MEDIUM",
                    )
                    writer.write(self._tree_connect_response(msg_id))
                    await writer.drain()

                else:
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "smb2_command",
                            "command": cmd_name,
                            "hex": smb_data[:256].hex(),
                            "dst_port": self.port,
                        },
                    )
                    self.logger.info("[SMB] %s %s", peer[0], cmd_name)
                    writer.write(self._error_response(cmd, msg_id))
                    await writer.drain()

                msg_count += 1

        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    SMBHoneypot().run()
