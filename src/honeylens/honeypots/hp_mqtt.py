#!/usr/bin/env python3
"""
honeypots/hp_mqtt.py — MQTT Broker Honeypot
=============================================
Simulates an MQTT broker. Accepts CONNECT, SUBSCRIBE, PUBLISH,
PINGREQ, and DISCONNECT packets. Logs credentials, topics, and payloads.

Run: python -m honeypots.hp_mqtt
Service: sensor-hp-mqtt (port 1883)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

MAX_PDU = 1048576  # 1 MB max MQTT payload


async def _read_remaining_length(reader) -> int:
    """Decode MQTT variable-length remaining-length field."""
    remaining = 0
    shift = 0
    for _ in range(4):
        b = await reader.readexactly(1)
        remaining |= (b[0] & 0x7F) << shift
        shift += 7
        if not (b[0] & 0x80):
            break
    return remaining


class MQTTHoneypot(BaseHoneypot):
    PROTOCOL = "mqtt"
    DEFAULT_PORT = 1883
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 180

    def __init__(self):
        super().__init__()
        p = self.profile
        self.broker_name = p.get("broker_name", "mosquitto")
        self.version = p.get("version", "2.0.18")
        self.topics = p.get("topics", [])

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[MQTT] Connection from %s:%d", peer[0], peer[1])

        try:
            # --- Read first packet (expect CONNECT) ---
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=30)
            pkt_type = (first_byte[0] >> 4) & 0x0F
            remaining = await _read_remaining_length(reader)

            if remaining > MAX_PDU:
                self.logger.warning(
                    "[MQTT] Oversized payload from %s: %d bytes", peer[0], remaining
                )
                return

            payload = await asyncio.wait_for(reader.readexactly(remaining), timeout=30)

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "dst_port": self.port,
                    "phase": "connect",
                    "pkt_type": pkt_type,
                    "payload_hex": payload[:128].hex(),
                },
                attack_type="MQTT_PROBE",
                severity="MEDIUM",
            )

            # Parse CONNECT packet fields
            if pkt_type == 1 and len(payload) > 10:
                idx = 0
                # Protocol name
                if idx + 2 <= len(payload):
                    pname_len = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2 + pname_len
                # Protocol level + connect flags + keep alive
                if idx < len(payload):
                    idx += 1  # protocol level
                connect_flags = payload[idx] if idx < len(payload) else 0
                idx += 1
                idx += 2  # keep alive

                # Client ID
                client_id = ""
                if idx + 2 <= len(payload):
                    cid_len = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    client_id = payload[idx : idx + cid_len].decode(errors="ignore")
                    idx += cid_len
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "client_id",
                            "client_id": client_id,
                        },
                    )

                # Username (bit 7)
                if connect_flags & 0x80 and idx + 2 <= len(payload):
                    ulen = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    username = payload[idx : idx + ulen].decode(errors="ignore")
                    idx += ulen
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "auth",
                            "rule": "mqtt_auth",
                            "username": username,
                        },
                        attack_type="CREDENTIAL_CAPTURE",
                        severity="HIGH",
                    )

                # Password (bit 6)
                if connect_flags & 0x40 and idx + 2 <= len(payload):
                    plen = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    password = payload[idx : idx + plen].decode(errors="ignore")
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "auth_password",
                            "password": password,
                        },
                        attack_type="CREDENTIAL_CAPTURE",
                        severity="HIGH",
                    )

            # Send CONNACK (accepted)
            writer.write(bytes([0x20, 0x02, 0x00, 0x00]))
            await writer.drain()

            # --- Packet loop ---
            while True:
                hdr_byte = await asyncio.wait_for(reader.read(1), timeout=120)
                if not hdr_byte:
                    break

                pkt_type_byte = hdr_byte[0]
                pkt_type_num = (pkt_type_byte >> 4) & 0x0F
                remaining = await _read_remaining_length(reader)
                body = (
                    await asyncio.wait_for(reader.readexactly(remaining), timeout=30)
                    if remaining
                    else b""
                )

                # SUBSCRIBE (8)
                if pkt_type_num == 8 and len(body) >= 2:
                    packet_id = body[0:2]
                    idx, return_codes = 2, []
                    while idx < len(body):
                        if idx + 2 > len(body):
                            break
                        topic_len = (body[idx] << 8) | body[idx + 1]
                        idx += 2
                        if idx + topic_len > len(body):
                            break
                        topic = body[idx : idx + topic_len].decode(errors="ignore")
                        idx += topic_len
                        qos = body[idx] if idx < len(body) else 0
                        idx += 1
                        return_codes.append(min(qos, 2))
                        self.logger.info("[MQTT] %s SUBSCRIBE topic=%s qos=%d", peer[0], topic, qos)
                        # Wildcard subscriptions = enumeration
                        sev = "HIGH" if topic in ("#", "$SYS/#", "+/#") else "MEDIUM"
                        atype = (
                            "MQTT_ENUMERATION"
                            if topic.startswith("$SYS") or topic == "#"
                            else "MQTT_SUBSCRIBE"
                        )
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "dst_port": self.port,
                                "phase": "subscribe",
                                "topic": topic,
                                "qos": qos,
                            },
                            attack_type=atype,
                            severity=sev,
                        )
                    suback = bytes([0x90, 2 + len(return_codes)]) + packet_id + bytes(return_codes)
                    writer.write(suback)
                    await writer.drain()

                # UNSUBSCRIBE (10)
                elif pkt_type_num == 10 and len(body) >= 2:
                    writer.write(bytes([0xB0, 0x02]) + body[0:2])
                    await writer.drain()

                # PUBLISH (3) — PUBACK for QoS 1
                elif pkt_type_num == 3:
                    # Extract topic from PUBLISH payload
                    if len(body) >= 2:
                        topic_len = (body[0] << 8) | body[1]
                        pub_topic = (
                            body[2 : 2 + topic_len].decode(errors="ignore")
                            if 2 + topic_len <= len(body)
                            else ""
                        )
                        pub_payload = (
                            body[2 + topic_len : 2 + topic_len + 200].decode(errors="ignore")
                            if pub_topic
                            else ""
                        )
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "dst_port": self.port,
                                "phase": "publish",
                                "topic": pub_topic,
                                "message": pub_payload[:200],
                            },
                            attack_type="MQTT_INJECT",
                            severity="HIGH",
                        )
                    qos = (pkt_type_byte & 0x06) >> 1
                    if qos == 1 and len(body) >= 4:
                        writer.write(bytes([0x40, 0x02]) + body[2:4])
                        await writer.drain()

                # PINGREQ (12)
                elif pkt_type_num == 12:
                    writer.write(bytes([0xD0, 0x00]))
                    await writer.drain()

                # DISCONNECT (14)
                elif pkt_type_num == 14:
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    MQTTHoneypot().run()
