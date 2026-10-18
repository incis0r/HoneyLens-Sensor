#!/usr/bin/env python3
"""
honeypots/hp_opcua.py — OPC UA Binary Honeypot
================================================
Simulates an OPC UA server (e.g. Siemens SIMATIC S7 OPC UA).
Responds to HEL/OPN/MSG/CLO and logs all ICS-relevant events.

Run: python -m honeypots.hp_opcua
Service: sensor-hp-opcua (port 4840)
"""

from __future__ import annotations

import asyncio
import struct
import time

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    read_rest,
)
from honeylens.honeypots.ics.verdict import verdict_for, verdict_for_semantics
from honeylens.ics import decode
from honeylens.ics.opcua import MESSAGE_TYPES, SERVICE_NAMES

HEADER_SIZE = 8
# The largest message this server accepts, as it always has.
MAX_MESSAGE_SIZE = 65535
# MSG may be split into chunks; the connection-level messages are always final.
_CHUNK_TYPES = frozenset({"F", "C", "A"})
_CHUNKED = frozenset({"MSG"})


def check_header(header: bytes, first: bool = True) -> str | None:
    """Why these 8 bytes are not an OPC UA transport header, or None when they are.

    A header is a message type the transport defines, a chunk type, and the size of the
    whole message. ``first`` is True for the first message of a connection, which is HEL.
    """
    if len(header) < HEADER_SIZE:
        return f"{len(header)} byte(s), a transport header is {HEADER_SIZE}"
    kind = header[0:3].decode("ascii", errors="replace")
    chunk = header[3:4].decode("ascii", errors="replace")
    size = struct.unpack("<I", header[4:8])[0]
    if kind not in MESSAGE_TYPES:
        return f"message type {header[0:3]!r} is not one the OPC UA transport defines"
    if chunk not in _CHUNK_TYPES or (chunk != "F" and kind not in _CHUNKED):
        return f"chunk type {header[3:4]!r} is not valid on a {kind} message"
    if not HEADER_SIZE <= size <= MAX_MESSAGE_SIZE:
        return f"message size {size} is outside {HEADER_SIZE}..{MAX_MESSAGE_SIZE}"
    if first and kind != "HEL":
        return f"first message is {kind}, a connection opens with HEL"
    return None


# OPC UA StatusCode: Good
SC_GOOD = b"\x00\x00\x00\x00"
# OPC UA StatusCode: Bad_ServiceUnsupported (0x800A_0000)
SC_BAD_SERVICE = struct.pack("<I", 0x800A0000)


class OpcuaHoneypot(BaseHoneypot):
    PROTOCOL = "opcua"
    DEFAULT_PORT = 4840
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.server_name = p.get("server_name", "Siemens SIMATIC S7 OPC UA Server")
        self.product_uri = p.get("product_uri", "urn:SIMATIC.S7.OPC.UA.Server")
        self.manufacturer = p.get("manufacturer", "Siemens AG")
        self.application_uri = p.get("application_uri", "urn:S7-1500.OPC.UA")

    # ── helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _ua_string(s: str) -> bytes:
        """Encode a UA String (4-byte LE length + UTF-8)."""
        raw = s.encode("utf-8")
        return struct.pack("<i", len(raw)) + raw

    @staticmethod
    def _ua_bytestring(b: bytes) -> bytes:
        """Encode a UA ByteString (4-byte LE length + raw)."""
        return struct.pack("<i", len(b)) + b

    @staticmethod
    def _ua_datetime() -> bytes:
        """Current time as OPC UA DateTime (100-ns ticks since 1601-01-01)."""
        # Offset between 1601 and 1970 in 100-ns intervals
        EPOCH_DIFF = 116444736000000000
        ticks = int(time.time() * 10_000_000) + EPOCH_DIFF
        return struct.pack("<Q", ticks)

    def _build_msg(self, msg_type: bytes, chunk: bytes, body: bytes) -> bytes:
        """Build a complete OPC UA message with header."""
        size = 8 + len(body)
        return msg_type + chunk + struct.pack("<I", size) + body

    # ── message handlers ────────────────────────────────────────────

    def _handle_hel(self, body: bytes) -> tuple[bytes, str | None]:
        """Process HEL, return (ACK message, endpoint_url)."""
        if len(body) < 20:
            return self._build_err(0x80830000, "Bad_TcpMessageTooLarge"), None

        # Parse HEL fields
        struct.unpack("<I", body[0:4])[0]
        recv_buf = struct.unpack("<I", body[4:8])[0]
        send_buf = struct.unpack("<I", body[8:12])[0]
        max_msg = struct.unpack("<I", body[12:16])[0]
        max_chunk = struct.unpack("<I", body[16:20])[0]

        # Extract endpoint URL
        endpoint_url = None
        if len(body) >= 24:
            url_len = struct.unpack("<I", body[20:24])[0]
            if 0 < url_len <= 4096 and len(body) >= 24 + url_len:
                endpoint_url = body[24 : 24 + url_len].decode("utf-8", errors="replace")

        # Build ACK
        ack_body = struct.pack(
            "<IIIII",
            0,  # ProtocolVersion
            min(recv_buf, 65535),  # ReceiveBufferSize
            min(send_buf, 65535),  # SendBufferSize
            min(max_msg, 16777216),  # MaxMessageSize
            min(max_chunk, 4096),  # MaxChunkCount
        )
        return self._build_msg(b"ACK", b"F", ack_body), endpoint_url

    def _build_err(self, status_code: int, reason: str) -> bytes:
        """Build an ERR message."""
        reason_bytes = reason.encode("utf-8")
        body = struct.pack("<I", status_code)
        body += struct.pack("<I", len(reason_bytes)) + reason_bytes
        return self._build_msg(b"ERR", b"F", body)

    def _handle_opn(self, body: bytes) -> bytes:
        """Process OPN request, return OPN response (SecurityMode=None)."""
        # Minimal OPN response body:
        #   SecureChannelId (4) + SecurityTokenId (4) + ...
        # We need to build a proper response header + body

        # Extract secure channel id from request if present
        secure_channel_id = 1
        if len(body) >= 4:
            secure_channel_id = struct.unpack("<I", body[0:4])[0]
            if secure_channel_id == 0:
                secure_channel_id = 1

        # Build asymmetric security header (SecurityMode=None)
        security_policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
        asym_header = self._ua_bytestring(security_policy)
        asym_header += struct.pack("<i", -1)  # SenderCertificate (null)
        asym_header += struct.pack("<i", -1)  # ReceiverCertificateThumbprint (null)

        # Sequence header
        sequence_number = 1
        request_id = 1
        # Try to extract request_id from the incoming message
        # After SecureChannelId(4) + AsymSecurityHeader + SequenceHeader
        # This is complex to parse fully, so we use a simple request_id
        seq_header = struct.pack("<II", sequence_number, request_id)

        # Response body — OpenSecureChannelResponse
        # NodeId encoding: FourByte (0x01), namespace=0, id=449 (OpenSecureChannelResponse)
        node_id = struct.pack("<BBH", 0x01, 0x00, 449)

        # ResponseHeader
        resp_header = self._ua_datetime()  # Timestamp
        resp_header += struct.pack("<I", 0)  # RequestHandle
        resp_header += SC_GOOD  # ServiceResult
        resp_header += struct.pack("<B", 0)  # ServiceDiagnostics (null encoding)
        resp_header += struct.pack("<i", -1)  # StringTable (empty array)
        resp_header += struct.pack("<BBB", 0, 0, 0)  # AdditionalHeader (null)

        # SecurityToken
        token = struct.pack("<I", secure_channel_id)  # ChannelId
        token += struct.pack("<I", 1)  # TokenId
        token += self._ua_datetime()  # CreatedAt
        token += struct.pack("<I", 3600000)  # RevisedLifetime (ms)

        # ServerNonce
        server_nonce = self._ua_bytestring(b"\x00" * 32)

        resp_body = node_id + resp_header + struct.pack("<I", 0) + token + server_nonce

        opn_body = struct.pack("<I", secure_channel_id) + asym_header + seq_header + resp_body
        return self._build_msg(b"OPN", b"F", opn_body)

    def _handle_msg(self, body: bytes, peer: tuple) -> bytes:
        """Process MSG request, identify service, log, and respond."""
        # MSG body layout:
        #   SecureChannelId (4) + TokenId (4) + SequenceNumber (4) + RequestId (4)
        #   + NodeId + RequestHeader + ...
        # One reading of the request: the decoder names the service and says what it does.
        frame = decode("opcua", body)
        attack_type, severity = verdict_for(frame)
        words = {f.name: f.value for f in frame.fields if isinstance(f.value, int)}
        secure_channel_id = words.get("secure_channel_id", 1)
        token_id = words.get("token_id", 1)
        seq_num = words.get("sequence_number", 1)
        request_id = words.get("request_id", 1)
        service_id = frame.code or 0
        if frame.code is None:
            service_name = "Unknown"
        else:
            service_name = SERVICE_NAMES.get(service_id, f"Service_{service_id}")

        event_data = {
            "dst_port": self.port,
            "phase": "opcua_request",
            "rule": service_name,
            "payload": f"service={service_name} id={service_id} chan={secure_channel_id} seq={seq_num}",
            "service_id": service_id,
            "service_name": service_name,
            "secure_channel_id": secure_channel_id,
            "token_id": token_id,
            "sequence_number": seq_num,
            "request_id": request_id,
            "body_hex": body[:128].hex(),
        }

        log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

        if attack_type == "ICS_ATTACK":
            self.logger.warning(
                "[OPC UA] %s %s (id=%d) — %s %s",
                peer[0],
                service_name,
                service_id,
                attack_type,
                severity,
            )
        else:
            self.logger.info("[OPC UA] %s %s (id=%d)", peer[0], service_name, service_id)

        # Build response
        if len(body) < 16:
            return self._build_service_fault(body, 0x80010000)
        if service_id == 428:
            return self._build_get_endpoints_response(
                body, secure_channel_id, token_id, seq_num, request_id
            )
        elif service_id == 422:
            return self._build_find_servers_response(
                body, secure_channel_id, token_id, seq_num, request_id
            )
        else:
            return self._build_service_fault(
                body, 0x800A0000, secure_channel_id, token_id, seq_num, request_id
            )

    def _build_msg_response(
        self,
        secure_channel_id: int,
        token_id: int,
        seq_num: int,
        request_id: int,
        resp_node_id: int,
        resp_body: bytes,
    ) -> bytes:
        """Build a complete MSG response."""
        # Symmetric security header is just TokenId
        header = struct.pack("<I", secure_channel_id)
        header += struct.pack("<I", token_id)
        # Sequence header
        header += struct.pack("<I", seq_num)
        header += struct.pack("<I", request_id)
        # NodeId (FourByte)
        header += struct.pack("<BBH", 0x01, 0x00, resp_node_id)
        # ResponseHeader
        header += self._ua_datetime()  # Timestamp
        header += struct.pack("<I", 0)  # RequestHandle
        header += SC_GOOD  # ServiceResult
        header += struct.pack("<B", 0)  # ServiceDiagnostics (null)
        header += struct.pack("<i", -1)  # StringTable (empty)
        header += struct.pack("<BBB", 0, 0, 0)  # AdditionalHeader (null)

        header += resp_body
        return self._build_msg(b"MSG", b"F", header)

    def _build_get_endpoints_response(
        self, body: bytes, chan: int, tok: int, seq: int, req_id: int
    ) -> bytes:
        """Build GetEndpointsResponse (id=431) with one endpoint."""
        endpoint_url = self._ua_string(f"opc.tcp://0.0.0.0:{self.port}")
        server_app_desc = (
            self._ua_string(self.application_uri)  # ApplicationUri
            + self._ua_string(self.product_uri)  # ProductUri
            +
            # ApplicationName (LocalizedText: encoding=0x02 means text only)
            struct.pack("<B", 0x02)
            + self._ua_string(self.server_name)
            + struct.pack("<I", 0)  # ApplicationType: SERVER
            + self._ua_string("")  # GatewayServerUri
            + self._ua_string("")  # DiscoveryProfileUri
            + struct.pack("<i", -1)  # DiscoveryUrls (empty array)
        )
        # Build single endpoint
        endpoint = (
            endpoint_url
            + server_app_desc
            + struct.pack("<i", -1)  # ServerCertificate (null)
            + struct.pack("<I", 1)  # SecurityMode: None
            + self._ua_string("http://opcfoundation.org/UA/SecurityPolicy#None")
            + struct.pack("<i", -1)  # UserIdentityTokens (empty)
            + self._ua_string("")  # TransportProfileUri
            + struct.pack("<B", 0)  # SecurityLevel
        )
        # Array of 1 endpoint
        resp_body = struct.pack("<i", 1) + endpoint
        return self._build_msg_response(chan, tok, seq, req_id, 431, resp_body)

    def _build_find_servers_response(
        self, body: bytes, chan: int, tok: int, seq: int, req_id: int
    ) -> bytes:
        """Build FindServersResponse (id=425) with one server."""
        server = (
            self._ua_string(self.application_uri)
            + self._ua_string(self.product_uri)
            + struct.pack("<B", 0x02)
            + self._ua_string(self.server_name)
            + struct.pack("<I", 0)  # ApplicationType: SERVER
            + self._ua_string("")  # GatewayServerUri
            + self._ua_string("")  # DiscoveryProfileUri
            +
            # DiscoveryUrls: array of 1
            struct.pack("<i", 1)
            + self._ua_string(f"opc.tcp://0.0.0.0:{self.port}")
        )
        resp_body = struct.pack("<i", 1) + server
        return self._build_msg_response(chan, tok, seq, req_id, 425, resp_body)

    def _build_service_fault(
        self,
        body: bytes,
        status_code: int = 0x800A0000,
        chan: int = 1,
        tok: int = 1,
        seq: int = 1,
        req_id: int = 1,
    ) -> bytes:
        """Build a ServiceFault (id=397) MSG response."""
        header = struct.pack("<I", chan)
        header += struct.pack("<I", tok)
        header += struct.pack("<I", seq)
        header += struct.pack("<I", req_id)
        # NodeId for ServiceFault (397)
        header += struct.pack("<BBH", 0x01, 0x00, 397)
        # ResponseHeader
        header += self._ua_datetime()
        header += struct.pack("<I", 0)  # RequestHandle
        header += struct.pack("<I", status_code)  # ServiceResult (Bad)
        header += struct.pack("<B", 0)  # ServiceDiagnostics (null)
        header += struct.pack("<i", -1)  # StringTable (empty)
        header += struct.pack("<BBB", 0, 0, 0)  # AdditionalHeader (null)

        return self._build_msg(b"MSG", b"F", header)

    # ── main connection loop ────────────────────────────────────────

    async def _unframed(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) OPC UA; no reply."""
        data = await read_rest(reader, consumed)
        if frames == 0:
            event, verdict = foreign_event(self.port, data, "OPC UA", defect), FOREIGN_VERDICT
        else:
            event, verdict = desync_event(self.port, data, "OPC UA", defect, frames), DESYNC_VERDICT
        log_event(self.PROTOCOL, peer, event, *verdict, raw=data[:MAX_RAW_EVENT_BYTES])
        self.logger.info("[OPC UA] %s not OPC UA: %s", peer[0], defect)

    def _transport_event(self, kind: str, message: bytes, payload: str, phase: str) -> dict:
        """The event for a connection-level message. ``message_hex`` is the message as it
        arrived; it is not under a key the frame decoder reads, because that decoder takes
        the body of a MSG chunk and would misread a Hello."""
        return {
            "dst_port": self.port,
            "phase": phase,
            "rule": MESSAGE_TYPES[kind][0],
            "payload": payload,
            "message_hex": frame_hex(message),
        }

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[OPC UA] Connection from %s:%d", peer[0], peer[1])
        frames = 0

        try:
            while True:
                try:
                    raw_header = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=60)
                except asyncio.IncompleteReadError as cut:
                    if cut.partial:
                        defect = (
                            f"stream ends {len(cut.partial)} byte(s) into a "
                            f"{HEADER_SIZE}-byte transport header"
                        )
                        await self._unframed(reader, peer, bytes(cut.partial), defect, frames)
                    return
                except TimeoutError:
                    stalled = await read_rest(reader, b"")
                    if stalled:
                        defect = f"{len(stalled)} byte(s) and then silence, no transport header"
                        await self._unframed(reader, peer, stalled, defect, frames)
                    return

                refused = check_header(raw_header, first=frames == 0)
                if refused:
                    await self._unframed(reader, peer, raw_header, refused, frames)
                    return

                msg_type = raw_header[0:3].decode("ascii")
                msg_size = struct.unpack("<I", raw_header[4:8])[0]

                try:
                    body = await asyncio.wait_for(
                        reader.readexactly(msg_size - HEADER_SIZE), timeout=30
                    )
                except asyncio.IncompleteReadError as cut:
                    got = raw_header + bytes(cut.partial)
                    defect = f"{msg_type} message cut short: {len(got)} of {msg_size} byte(s)"
                    event = desync_event(
                        self.port, got, "OPC UA", defect, frames, phase="opcua_truncated"
                    )
                    log_event(
                        self.PROTOCOL, peer, event, *DESYNC_VERDICT, raw=got[:MAX_RAW_EVENT_BYTES]
                    )
                    return
                frames += 1
                verdict = verdict_for_semantics(MESSAGE_TYPES[msg_type][1], self.PROTOCOL)

                if msg_type == "HEL":
                    ack, endpoint_url = self._handle_hel(body)
                    event = self._transport_event(
                        msg_type,
                        raw_header + body,
                        f"HEL endpoint={endpoint_url or 'N/A'}",
                        "opcua_hello",
                    )
                    event["endpoint_url"] = endpoint_url
                    log_event(self.PROTOCOL, peer, event, *verdict)
                    self.logger.info("[OPC UA] %s HEL endpoint=%s", peer[0], endpoint_url or "N/A")
                    writer.write(ack)
                    await writer.drain()

                elif msg_type == "OPN":
                    event = self._transport_event(
                        msg_type,
                        raw_header + body,
                        f"OPN len={len(body)}",
                        "opcua_open_secure_channel",
                    )
                    log_event(self.PROTOCOL, peer, event, *verdict)
                    self.logger.info("[OPC UA] %s OPN", peer[0])
                    resp = self._handle_opn(body)
                    writer.write(resp)
                    await writer.drain()

                elif msg_type == "MSG":
                    resp = self._handle_msg(body, peer)
                    writer.write(resp)
                    await writer.drain()

                elif msg_type == "CLO":
                    event = self._transport_event(msg_type, raw_header + body, "CLO", "opcua_close")
                    log_event(self.PROTOCOL, peer, event, *verdict)
                    self.logger.info("[OPC UA] %s CLO — closing", peer[0])
                    break

                else:
                    # ACK, ERR and ReverseHello are a server's messages: a peer that sends
                    # one is recorded, and the conversation ends there.
                    event = self._transport_event(
                        msg_type,
                        raw_header + body,
                        f"{msg_type} len={len(body)}",
                        "opcua_peer_message",
                    )
                    log_event(self.PROTOCOL, peer, event, *verdict)
                    self.logger.info("[OPC UA] %s sent %s — closing", peer[0], msg_type)
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    OpcuaHoneypot().run()
