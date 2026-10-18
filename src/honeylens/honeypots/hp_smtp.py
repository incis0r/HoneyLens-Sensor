"""
honeypots/hp_smtp.py — Modular SMTP honeypot service
======================================================
Emulates an SMTP/ESMTP server to capture relay attempts, credential
brute-force via AUTH, and full message bodies sent by attackers.

Response fidelity:
    All replies follow RFC 5321 grammar — 3-digit reply codes, CRLF
    termination, multi-line responses using `code-` continuations and
    `code ` for the final line. EHLO advertises real ESMTP keywords
    (PIPELINING, SIZE, AUTH, HELP); AUTH LOGIN implements the canonical
    SASL challenge sequence (334 VXNlcm5hbWU6 / 334 UGFzc3dvcmQ6) so
    credential-stuffing scripts walk through the prompts and record
    their base64-encoded creds before the final 535.

    Verified on the wire against Suricata 7.0.13's SMTP parser:
      • banner-only and banner + EHLO + QUIT flows pass cleanly
        (smtp event emitted with `helo` extracted, no anomaly).
      • Flows that carry AUTH trip `INVALID_REPLY` because Suricata
        7.0.13 does not implement the SASL state machine (RFC 4954).
        This affects every RFC-correct SMTP server, including Postfix
        and Sendmail; suppress it on honeypot ports rather than
        bending the response shape.
      • The `APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION` alert is a
        proto-detect artifact for banner-first protocols when the
        client has not sent any byte yet — also not a fidelity issue.

Run standalone:
    python -m honeypots.hp_smtp
    HP_SMTP_PORT=2525 python -m honeypots.hp_smtp
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(text: str) -> str:
    """Strip control characters and null bytes from decoded text."""
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


def _ehlo_response(hostname: str, peer_ip: str) -> bytes:
    """Canonical multi-line EHLO response (RFC 5321 §4.5.3.1).

    Continuation lines use `code-`; the final line uses `code<SP>`. Every
    advertised keyword is a real ESMTP extension so Suricata's SMTP parser
    accepts the response direction. Without this, the parser drops the
    server-side bytes to "junk" status and triggers sid 2220000 ("SMTP
    invalid reply") + sid 2260002 ("Applayer Detect protocol only one
    direction") on every flow.
    """
    return (
        f"250-{hostname} Hello [{peer_ip}], pleased to meet you\r\n"
        f"250-PIPELINING\r\n"
        f"250-SIZE 10485760\r\n"
        f"250-VRFY\r\n"
        f"250-ETRN\r\n"
        f"250-AUTH LOGIN PLAIN\r\n"
        f"250-AUTH=LOGIN PLAIN\r\n"
        f"250-8BITMIME\r\n"
        f"250-DSN\r\n"
        f"250 HELP\r\n"
    ).encode()


def _b64(s: str) -> bytes:
    """Base64-encode an ASCII prompt string for SASL challenges."""
    return base64.b64encode(s.encode("ascii"))


class SMTPHoneypot(BaseHoneypot):
    """Low-interaction SMTP honeypot.

    Presents an ESMTP banner, handles EHLO/HELO, MAIL FROM, RCPT TO,
    DATA, AUTH (LOGIN / PLAIN), STARTTLS, NOOP, RSET, VRFY, EXPN, HELP,
    and QUIT. Captures relay attempts and auth credentials.
    """

    PROTOCOL = "smtp"
    DEFAULT_PORT = 25
    TTL_PROFILE = "linux"

    # ---- helpers -----------------------------------------------------------

    async def _read_line(self, reader, timeout=60):  # noqa: ASYNC109 — API z 0.9
        """Read one CRLF-terminated line; return sanitised text or None on EOF."""
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            return None
        return _sanitize(line.decode(errors="ignore"))

    async def _handle_auth_login(self, reader, writer, peer, raw_command):
        """Walk the canonical SASL LOGIN challenge: 334 Username: / 334
        Password: / 535. Captures the base64-encoded responses and logs
        the decoded credentials.

        Supports the inline-username form `AUTH LOGIN <b64user>` — RFC 4954
        §4 lets clients supply the initial response on the same line.
        """
        username_b64 = ""
        password_b64 = ""

        parts = raw_command.split(None, 2)
        if len(parts) == 3:
            username_b64 = parts[2]
        else:
            writer.write(b"334 " + _b64("Username:") + b"\r\n")
            await writer.drain()
            line = await self._read_line(reader)
            if line is None or line == "*":
                writer.write(b"501 Authentication cancelled\r\n")
                return
            username_b64 = line

        writer.write(b"334 " + _b64("Password:") + b"\r\n")
        await writer.drain()
        line = await self._read_line(reader)
        if line is None or line == "*":
            writer.write(b"501 Authentication cancelled\r\n")
            return
        password_b64 = line

        def _decode(b64s: str) -> str:
            try:
                return base64.b64decode(b64s, validate=False).decode("utf-8", errors="replace")
            except Exception:
                return b64s

        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "auth_login_creds",
                "raw": raw_command,
                "username_b64": username_b64,
                "username": _decode(username_b64),
                "password_b64": password_b64,
                "password": _decode(password_b64),
                "dst_port": self.port,
            },
            attack_type="CREDENTIAL_CAPTURE",
            severity="HIGH",
        )
        self.logger.info(
            "[SMTP] %s:%d AUTH LOGIN user=%s pass=%s",
            peer[0],
            peer[1],
            _decode(username_b64),
            _decode(password_b64),
        )
        writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")

    async def _handle_auth_plain(self, reader, writer, peer, raw_command):
        """SASL PLAIN (RFC 4616) — payload is `\\0<authcid>\\0<password>`.

        Either inline (`AUTH PLAIN <b64>`) or two-step (`AUTH PLAIN` then
        the client sends b64 on the next line after a `334 \\r\\n` prompt).
        """
        parts = raw_command.split(None, 2)
        if len(parts) == 3:
            payload_b64 = parts[2]
        else:
            writer.write(b"334 \r\n")
            await writer.drain()
            line = await self._read_line(reader)
            if line is None or line == "*":
                writer.write(b"501 Authentication cancelled\r\n")
                return
            payload_b64 = line

        username = password = ""
        try:
            payload = base64.b64decode(payload_b64, validate=False).decode(
                "utf-8", errors="replace"
            )
            bits = payload.split("\x00")
            if len(bits) >= 3:
                username = bits[1]
                password = bits[2]
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)

        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "auth_plain_creds",
                "raw": raw_command,
                "payload_b64": payload_b64,
                "username": username,
                "password": password,
                "dst_port": self.port,
            },
            attack_type="CREDENTIAL_CAPTURE",
            severity="HIGH",
        )
        self.logger.info(
            "[SMTP] %s:%d AUTH PLAIN user=%s pass=%s",
            peer[0],
            peer[1],
            username,
            password,
        )
        writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")

    # ---- connection handler ------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        banner = self.profile.get("banner", "ESMTP ready")
        hostname = self.profile.get("hostname", "mail.swifttrans.local")

        # Profile may set `banner` either as a bare text fragment ("ESMTP
        # Postfix (Ubuntu)") or as a full reply line that already includes
        # the 220 code and hostname ("220 mail.example.com ESMTP ..."). Be
        # tolerant of both shapes — emit one canonical 220 line per RFC.
        b = banner.strip()
        if re.match(r"^2\d{2}[\s\-]", b):
            line = b.rstrip("\r\n") + "\r\n"
        else:
            line = f"220 {hostname} {b}\r\n"
        writer.write(line.encode())
        await writer.drain()

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line:
                    break

                raw = _sanitize(line.decode(errors="ignore"))
                upper = raw.upper()

                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "command",
                        "command": raw,
                        "dst_port": self.port,
                    },
                )

                if upper.startswith("EHLO"):
                    self.logger.info("[SMTP] %s:%d %s", peer[0], peer[1], raw)
                    writer.write(_ehlo_response(hostname, peer[0]))

                elif upper.startswith("HELO"):
                    # HELO is the pre-ESMTP single-line form.
                    self.logger.info("[SMTP] %s:%d %s", peer[0], peer[1], raw)
                    writer.write(f"250 {hostname}\r\n".encode())

                elif upper.startswith("MAIL FROM"):
                    self.logger.info("[SMTP] %s:%d %s", peer[0], peer[1], raw)
                    writer.write(b"250 2.1.0 Sender ok\r\n")

                elif upper.startswith("RCPT TO"):
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "relay_attempt",
                            "rcpt": raw,
                            "dst_port": self.port,
                        },
                        attack_type="SMTP_RELAY",
                        severity="MEDIUM",
                    )
                    self.logger.info("[SMTP] %s:%d %s", peer[0], peer[1], raw)
                    writer.write(b"250 2.1.5 Recipient ok\r\n")

                elif upper.startswith("DATA"):
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    body_lines = []
                    while True:
                        dline = await asyncio.wait_for(reader.readline(), timeout=60)
                        text = dline.decode(errors="ignore").rstrip("\r\n")
                        if text == ".":
                            break
                        body_lines.append(text)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "data",
                            "body": "\n".join(body_lines)[:4096],
                            "dst_port": self.port,
                        },
                        attack_type="SMTP_RELAY",
                        severity="MEDIUM",
                    )
                    writer.write(b"250 2.0.0 Ok: queued\r\n")

                elif upper.startswith("AUTH"):
                    # Log the bootstrap, then dispatch on mechanism so the
                    # response track follows RFC 4954 / SASL grammar.
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "auth",
                            "raw": raw,
                            "dst_port": self.port,
                        },
                        attack_type="CREDENTIAL_CAPTURE",
                        severity="HIGH",
                    )
                    self.logger.info("[SMTP] %s:%d AUTH attempt: %s", peer[0], peer[1], raw)

                    mech = ""
                    rest = raw[4:].strip()
                    if rest:
                        mech = rest.split(None, 1)[0].upper()

                    if mech == "LOGIN":
                        await self._handle_auth_login(reader, writer, peer, raw)
                    elif mech == "PLAIN":
                        await self._handle_auth_plain(reader, writer, peer, raw)
                    else:
                        # CRAM-MD5, NTLM, anything else — refuse cleanly with
                        # the right SMTP reply rather than a blanket 535.
                        writer.write(b"504 5.5.4 Unrecognized authentication type\r\n")

                elif upper.startswith("STARTTLS"):
                    # We don't actually upgrade — clients that try will get a
                    # TLS handshake failure, which is honest about the
                    # honeypot's limit. The 220 keeps Suricata happy first.
                    writer.write(b"220 2.0.0 Ready to start TLS\r\n")

                elif upper.startswith("NOOP"):
                    writer.write(b"250 2.0.0 Ok\r\n")

                elif upper.startswith("RSET"):
                    writer.write(b"250 2.0.0 Ok\r\n")

                elif upper.startswith("VRFY") or upper.startswith("EXPN"):
                    writer.write(b"252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery\r\n")

                elif upper.startswith("HELP"):
                    writer.write(
                        b"214-2.0.0 This is the help message\r\n"
                        b"214 2.0.0 Try EHLO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT\r\n"
                    )

                elif upper.startswith("QUIT"):
                    writer.write(f"221 2.0.0 {hostname} closing connection\r\n".encode())
                    await writer.drain()
                    break

                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")

                await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    SMTPHoneypot().run()
