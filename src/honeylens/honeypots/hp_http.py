"""
honeypots/hp_http.py — Modular HTTP honeypot service
=====================================================
Captures HTTP requests, extracts credentials and attack indicators,
returns a realistic response page.

Run standalone:  python -m honeypots.hp_http
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import dataclasses
import logging
import os
import re
import urllib.parse
from typing import ClassVar

# Imported after _base, which puts the project root on sys.path — this module is also
# started as a script, and an import above that bootstrap silently falls back.
from honeylens.b64_shape import add_carriers, b64_shape, decode_b64, request_carriers
from honeylens.honeypots import h2_capture, shell_bait
from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_CAPTURE
from honeylens.honeypots.body_capture import capture as capture_body

# How much of the connection summary travels in the event's ``payload``. Explicit, because
# ``_base.log_event`` otherwise renders ``json.dumps(data)`` into that field and would put
# every kept stream's text into the one greppable column the text rules read — a connection
# is not a request, and a flood's fifth stream must not earn the first one's label.
_H2_PAYLOAD_MAX = 480
_H2_PATH_IN_PAYLOAD = 200

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# One deadline for topping up a connection preface that arrived split across segments.
# Short: the remaining bytes are already in flight or the client is not sending them.
_PREFACE_TOP_UP_SECONDS = 5.0

# `h2_capture` truncates a reason to 500 characters; so do we, for the same column.
_H2_REASON_MAX = 500

# `shell_bait.decide` returns None for "serve the ordinary page", which is fine for a row
# that covers one request but not for one that covers a whole connection: without a token
# of its own, a connection that served stream 1 and refused stream 3 recorded
# ``misdirected`` alone, and the row said we refused when we had also served.
_SERVED_PAGE = "page"

# A SETTINGS payload is a whole number of 6-byte (identifier, value) pairs; anything else
# is not an HTTP2-Settings header we can hand to h2, and a client that sent one was never
# entitled to the 101.
_SETTINGS_ENTRY = 6


class HTTPHoneypot(BaseHoneypot):
    PROTOCOL = "http"
    DEFAULT_PORT = 80
    TTL_PROFILE = "linux"

    def __init__(self):
        super().__init__()
        self.server_header = self.profile.get(
            "server_header", "Apache/2.4.66 (Ubuntu) mod_http2/2.0.32"
        )
        self.powered_by = self.profile.get("powered_by", "PHP/7.4.3")
        self.title = self.profile.get("title", "Welcome")
        self.upgrade = self.profile.get("upgrade", "h2,h2c")

    # ------------------------------------------------------------------ parse
    def _parse_request(self, data: bytes) -> dict:
        """Parse raw HTTP bytes into structured components."""
        result: dict = {
            "method": None,
            "path": None,
            "version": None,
            "headers": {},
            "host_values": [],
            "body": None,
            "body_raw": b"",
            "query_string": None,
        }
        try:
            if b"\r\n\r\n" in data:
                hdr_part, body = data.split(b"\r\n\r\n", 1)
                # No truncation here: body_capture.MAX_CAPTURE is the single ceiling,
                # and it is applied where the event is built. A second, smaller cap in
                # the parser silently cost us everything past 8 KB of a POST.
                result["body"] = body.decode(errors="ignore")
                result["body_raw"] = body
            else:
                hdr_part = data

            lines = hdr_part.decode(errors="ignore").split("\r\n")
            if lines:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    result["method"] = parts[0]
                    result["path"] = parts[1]
                    if "?" in parts[1]:
                        _, qs = parts[1].split("?", 1)
                        result["query_string"] = qs
                if len(parts) >= 3:
                    result["version"] = parts[2]

            # Every value, not the last one, and in order. `host_claims` unions them, so
            # a request that names a foreign domain in its FIRST `Host` and ours in its
            # second is refused — measured, last-wins served the full page and recorded
            # `host='decoy.invalid'`. No 400 is needed for that and none is served: the
            # union ruling already settles it, and the parser was simply throwing the
            # first value away before the union could see it.
            host_values: list[str] = []
            last_name: str | None = None
            for line in lines[1:]:
                if line[:1] in (" ", "\t"):
                    # obs-fold (RFC 9112 §5.2): a line beginning with SP or HTAB continues
                    # the previous field value. Deprecated, and the RFC's own alternative
                    # to rejecting it is to replace the fold with a space before
                    # interpreting the field — which is what this does, because it needs no
                    # persona decision and errs toward seeing the value. Skipping the line
                    # left `Host:\r\n victim.example` with an EMPTY claim list and served
                    # the full page under a foreign name.
                    if last_name is not None:
                        folded = (result["headers"][last_name] + " " + line.strip(" \t")).strip(
                            " \t"
                        )
                        result["headers"][last_name] = folded
                        # Stripped, the same way the claim above is read: a folded
                        # `Host : x` is still a `Host` claim.
                        if last_name.strip(" \t") == "host" and host_values:
                            host_values[-1] = folded
                    continue
                # RFC 9112 §5: `field-line = field-name ":" OWS field-value OWS`, and OWS
                # may be EMPTY. Requiring `": "` dropped every header a client sent without
                # a space after the colon — `Host:victim.example`, which is legal, which
                # httpd accepts, and which is exactly what a hand-rolled
                # `printf 'GET / HTTP/1.1\r\nHost:x\r\n\r\n'` scanner emits. Such a line
                # was skipped *entirely*, so `Authorization:Basic …`, `User-Agent:…` and
                # `Content-Type:…` from any such client were silently absent from every
                # row this decoy ever wrote: evidence we cannot go back and recover. It
                # also left the foreign-host guard with nothing to judge, because the
                # parser decides which header spellings exist before anything downstream
                # sees them.
                #
                # Searched from index 1 so a leading-colon line (`:method: GET`, which
                # malformed clients do send) keeps the name it has always been recorded
                # under rather than becoming nameless and dropped.
                colon = line.find(":", 1)
                if colon < 0:
                    last_name = None
                    continue
                name = line[:colon].lower()
                value = line[colon + 1 :].strip(" \t")
                result["headers"][name] = value
                # The key keeps the whitespace verbatim — `Host : x` still lands under
                # `"host "`, which is evidence of how the request was built — but the
                # CLAIM is read from the stripped name. RFC 9112 §5.1 wants a 400 for
                # whitespace before the colon and this served the full Apache page under
                # a stranger's domain instead, and granted the 101 on the same parse,
                # because the claim set came back empty and a correct resolver refuses
                # nothing when it is told nothing. No 400 is needed to close that: a
                # header whose stripped name is `host` is a `Host` claim, and the 421 we
                # already serve follows — the same resolution obs-fold got.
                if name.strip(" \t") == "host":
                    host_values.append(value)
                last_name = name
            result["host_values"] = host_values
        except Exception as exc:
            result["parse_error"] = str(exc)
        return result

    # -------------------------------------------------------------- classify
    _ATTACK_PATTERNS: ClassVar[list[tuple]] = [
        (r"\.\./|\.\.\\|%2e%2e", "path_traversal", "HIGH"),
        (r"(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*--)", "sql_injection", "HIGH"),
        (r"<script|javascript:|on\w+\s*=", "xss", "MEDIUM"),
        (r"/etc/passwd|/etc/shadow|/proc/self", "lfi", "HIGH"),
        (r"cmd\.exe|/bin/(?:sh|bash)|powershell", "rce_attempt", "CRITICAL"),
        (r"wp-login|wp-admin|xmlrpc\.php", "wordpress_scan", "LOW"),
        (r"\.env|\.git/|config\.php", "info_disclosure", "MEDIUM"),
    ]

    # h2c upgrade recon shapes — an ``Upgrade: h2c``/``h2`` request, or a User-Agent that
    # names an HTTP/2 library or the CVE. Severity is LOW: recon, not exploit; promotion
    # happens via the Suricata SIDs or the AI triage stage seeing the chain across events.
    #
    # Named for what was SEEN, not for a CVE (2026-11-12). These shapes were once labelled
    # as a CVE-2026-23918 verdict, paired with the Server: Apache/2.4.66 bait. The decoy now
    # also speaks HTTP/2 for CVE-2026-119618, and a bare h2c upgrade fits CVE-2026-23918
    # and CVE-2026-119618 at once, so it binds to neither: the repo's rule is that a CVE
    # label needs the affected service, and here the service is ambiguous. The User-Agent
    # branch is weaker still: a value the sender chooses cannot carry a CVE claim, and
    # ``python-h2/x`` is mostly what an honest HTTP/2 client sends into the new path.
    # Rows already stored under the old name stay as they are; Suricata's own 23918 labels
    # are a different producer and untouched.
    #
    # Checked AFTER `_ATTACK_PATTERNS`: a request that carries both an attack path and
    # an upgrade header is an attack, and the recon label must not shadow it.
    #
    # v2 (2026-05-29): removed generic python-(requests|httpx|urllib3) from
    # the UA pattern after day-1 telemetry showed they collide with cloud-
    # secrets hunters, MCP probers, and Elasticsearch enumeration. Kept the
    # h2-library-specific identifiers (python-h2, h2, hyper-h2) plus the
    # CVE-named and Apache-named recon kits.
    _CVE_2026_23918_UA_RE = re.compile(
        r"^(?:python-h2|h2|hyper-h2|"
        r"CVE-?2026-?23918[-_]?\w*|apache[-_]?2[._]?4[._]?66[-_]?\w*)/",
        re.IGNORECASE,
    )

    def _classify(
        self, path: str | None, body: str | None, headers: dict | None = None
    ) -> tuple[str, str] | None:
        """Return (attack_type, severity) for the first matching pattern.

        ``path`` has always been allowed to be ``None`` (an unparseable request line gives
        no path, and `handle_connection` passed it straight through); the signature now
        says so, because `h2_capture.decide` calls this per HTTP/2 stream and a stream
        whose ``:path`` was missing or duplicated has none either.
        """
        text = urllib.parse.unquote(path or "")
        if body:
            text += " " + body
        text_lower = text.lower()
        for pattern, atype, sev in self._ATTACK_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return atype, sev

        # Upgrade recon, after the attack patterns: see the comment above the UA regex.
        # Real browsers do not send an h2c upgrade; the exploit's HTTP/1.1 fallback does.
        if headers:
            # Tokens are stripped like `_h2c_settings` strips them, so every request that
            # decoy upgrades (`Upgrade: websocket, h2` included) is judged as one.
            upgrade = (headers.get("upgrade") or "").lower()
            if "h2c" in upgrade or "h2" in [token.strip() for token in upgrade.split(",")]:
                return "h2c_upgrade_recon", "LOW"
            ua = headers.get("user-agent") or ""
            if self._CVE_2026_23918_UA_RE.match(ua):
                return "h2c_upgrade_recon", "LOW"
        return None

    # -------------------------------------------------------------- creds
    @staticmethod
    def _basic_auth_blob(headers: dict) -> str | None:
        """The raw Base64 blob from an `Authorization: Basic` header, or None."""
        auth = headers.get("authorization", "")
        if not isinstance(auth, str) or not auth.lower().startswith("basic "):
            return None
        return auth.split(" ", 1)[1].strip() if " " in auth else ""

    @staticmethod
    def _basic_auth_shape(headers: dict) -> dict | None:
        """Length and Base64 validity of a Basic blob, recorded whatever it turns out to be.

        CVE-2026-114938 is delivered as a blob that *cannot* be Base64: the over-write happens
        inside `java.util.Base64.decode` while it rejects the input. A blob whose length is
        ``≡ 1 (mod 4)`` is that shape — four characters carry three bytes, so one left over is
        impossible — and the ladder measured on the fleet 2026-11-18 (`31.76.87.52`, four
        sensors) is `QQ==`, `AAA==`, ``"A"*64 + "="`` and ``"A"*128 + "="``.

        Recorded for valid blobs too: a missing field would otherwise be ambiguous between
        "this blob was fine" and "this decoy predates the change".
        """
        blob = HTTPHoneypot._basic_auth_blob(headers)
        shape = b64_shape(blob)
        if shape is None:
            return None
        # The primitive's measurement under this field's original key names. The names are kept
        # because they shipped to 8/8 this morning and the IOC sheet and the hunting queries
        # point at them, and a 30-day retention window means renaming them blanks a dashboard.
        # `b64_carriers` carries the same blob as carrier `basic` with the full shape; this
        # field is redundant once the window has rolled and can go then.
        return {
            "b64_len": shape["len"],
            "b64_mod4": shape["mod4"],
            "b64_valid": shape["decodes"],
        }

    @staticmethod
    def _b64_carriers(
        headers: dict,
        path: str | None = None,
        body: str | None = None,
        *,
        body_truncated: bool = False,
    ) -> list[dict] | None:
        """Every Base64 carrier in this request, each measured by `honeylens.b64_shape`.

        One method, called from both event-building sites. `hp_http` and `honeypot_k8s` each
        grew their own Basic-auth extractor last time and they diverged — the k8s one reduced
        the value to the word `"present"` — which is why the 14 rows the 2026-11-18 actor left
        on four decoy surfaces are stored and can never be labelled. NTLM, SAML and Bearer go
        through one place.

        Called with headers alone from the HTTP/1.1 site, because `body_capture.capture` now
        reads the body and the path for every decoy that captures a body — and this decoy keeps
        the query string inside `path`, so extracting it here as well would store every SAML
        parameter twice. The two sources are disjoint by construction rather than deduplicated
        afterwards. The HTTP/2 upgrade site does pass a path: nothing captures a body there.

        Per-source truncation is handled by `request_carriers`: that ceiling clips the body,
        while headers and the query string arrive whole.
        """
        fields = request_carriers(
            headers=headers or {}, query=path, body=body, body_truncated=body_truncated
        )
        return fields.get("b64_carriers") or None

    @staticmethod
    def _decode_basic_blob(blob: str) -> str | None:
        """Decode a Basic blob, or None if it is not Base64 at all.

        Two things the previous one-liner got wrong, both measured on captured traffic:

        * ``base64.b64decode`` without ``validate=True`` **accepts** the CVE-2026-114938
          trigger: ``"A"*64 + "="`` decodes to 48 NUL bytes, which were then stored as a
          username. Those NULs are also the one byte psycopg refuses to bind.
        * It **rejects** legal *unpadded* Base64 for "Incorrect padding". Two addresses on the
          fleet send a 63-character blob that is a real credential
          (`caldav_public_user@localhost:…`), and we stored nothing for either.

        So: refuse ``len % 4 == 1`` outright, re-pad everything else, and validate.
        """
        # One implementation of "is this Base64", in `honeylens.b64_shape`. The copy that used
        # to live here disagreed with the shape field beside it on a url-alphabet blob:
        # `b64_valid=True` in the row, `None` from the decoder, in the same event.
        raw = decode_b64(blob)
        return None if raw is None else raw.decode(errors="ignore")

    @staticmethod
    def _extract_credentials(headers: dict, body: str | None) -> dict | None:
        """Pull credentials from Basic-Auth header or POST body.

        A blob that is not Base64 is not a credential — it is the CVE-2026-114938 shape, and
        `_basic_auth_shape` records it. Returning a credential with an empty username for it
        put exploit attempts in the credential corpus.
        """
        blob = HTTPHoneypot._basic_auth_blob(headers)
        if blob is not None:
            decoded = HTTPHoneypot._decode_basic_blob(blob)
            if decoded is not None:
                user, _, pw = decoded.partition(":")
                return {"username": user, "password": pw, "source": "basic_auth"}
        if body:
            m = re.search(
                r"(?:user(?:name)?|login)=([^&]+).*?(?:pass(?:word)?|pwd)=([^&]+)", body, re.I
            )
            if m:
                return {
                    "username": urllib.parse.unquote_plus(m.group(1)),
                    "password": urllib.parse.unquote_plus(m.group(2)),
                    "source": "post_body",
                }
        return None

    # -------------------------------------------------------------- response
    def _page(self) -> str:
        return (
            f"<html><head><title>{self.title}</title></head>"
            f"<body><h1>{self.title}</h1>"
            f"<p>It works!</p></body></html>\r\n"
        )

    def _build_response(self) -> bytes:
        html = self._page()
        return (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {self.server_header}\r\n"
            f"X-Powered-By: {self.powered_by}\r\n"
            f"Upgrade: {self.upgrade}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(html)}\r\n"
            f"Connection: close\r\n"
            f"\r\n{html}"
        ).encode()

    # -------------------------------------------------------------- handler
    async def _read_request(self, reader) -> bytes:
        """Read headers, then keep reading until Content-Length is satisfied.

        A single `read()` returns whatever one TCP segment happened to carry, so a
        POST larger than the MTU used to be recorded with its body cut at the packet
        boundary — the bigger the payload, the more of it was lost. Bounded by
        MAX_CAPTURE (plus headers) so a client still cannot make us buffer without
        limit.
        """
        data = await asyncio.wait_for(reader.read(16384), timeout=30)
        if not data:
            return data
        if self._h2_enabled():
            data = await self._complete_preface(reader, data)
        if b"\r\n\r\n" not in data:
            return data

        head, body = data.split(b"\r\n\r\n", 1)
        want = 0
        for line in head.decode(errors="ignore").split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    want = int(line.split(":", 1)[1].strip())
                except ValueError:
                    want = 0
                break

        want = min(want, MAX_CAPTURE)
        while len(body) < want:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(min(65536, want - len(body))), timeout=10
                )
            except TimeoutError:
                break  # a stalled sender still leaves us what did arrive
            if not chunk:
                break
            body += chunk
        return head + b"\r\n\r\n" + body

    async def _complete_preface(self, reader, data: bytes) -> bytes:
        """Top up a connection preface that arrived split across TCP segments.

        The preface carries ``\\r\\n\\r\\n`` at offset 16, so a client that sends it in two
        segments makes the header split in `_read_request` return early with no
        Content-Length to wait for — and the HTTP/2 path, which tests
        ``data.startswith(PREFACE)``, never fires. Measured: one segment yields a full
        ``H2_CONNECTION`` row, the same bytes split at 20 yields ``method=PRI``, split at 1
        yields nothing. One extra ``send()`` is free for an attacker to arrange, so rarity
        is the wrong axis: this is the kind of single attacker-controlled choice that must
        not be able to switch our own analysis off.

        Bounded three ways: only when what arrived is a strict prefix of the preface, never
        past its 24 bytes, and under one deadline for the whole top-up. Whatever did arrive
        is returned either way, so a client that stops mid-preface is recorded as before.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _PREFACE_TOP_UP_SECONDS
        while len(data) < len(h2_capture.PREFACE) and h2_capture.PREFACE.startswith(data):
            left = deadline - loop.time()
            if left <= 0:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(len(h2_capture.PREFACE) - len(data)), left
                )
            except TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        return data

    async def handle_connection(self, reader, writer, peer):
        data = await self._read_request(reader)
        if not data:
            return

        req = self._parse_request(data)
        hdrs = req.get("headers", {})

        # Decided BEFORE the HTTP/2 branches, and carried into the row. `shell_bait`'s
        # foreign-host split "is not a nicety. It is what makes the bait safe to run at
        # all": answering 200 with content under a domain that is not ours manufactures
        # evidence that THEIR site is compromised. Two attacker-controlled headers
        # (`Upgrade: h2c` and `HTTP2-Settings`) must not be able to switch that guard off,
        # and until 2026-11-12 they could — measured, 421 without them and the full Apache
        # page with them. A misdirected request is refused and never upgraded or observed;
        # `bait` proceeds, but every HTTP/2 stream is judged on its own host in
        # `_h2_response_for`, because HTTP/2 carries the host per request.
        #
        # The host claims are resolved by `shell_bait.host_claims`, which is the only
        # place that knows the spellings — this decoy does not reason about hosts itself.
        # The union refuses if ANY claim it is given is foreign.
        #
        # "Given" is the load-bearing word, and an earlier version of this comment left it
        # out: it claimed a spelling this file has never heard of could not launder a
        # foreign name past the guard. It can. **`_parse_request` is the upstream gate** —
        # the resolver can only union what the parser handed it, and the parser decides
        # which header spellings exist at all. That is not hypothetical: requiring `": "`
        # instead of RFC 9112 §5's `field-line = field-name ":" OWS field-value OWS` meant
        # `Host:victim.example` produced an EMPTY claim list, and a correct resolver
        # refused nothing because it was told nothing. A new spelling has to be reachable
        # through the parser before `host_claims` can weigh it.
        claims = shell_bait.host_claims(
            target=req["path"], host_header=req.get("host_values") or hdrs.get("host")
        )
        mode = shell_bait.decide(req["path"], claims)

        if self._h2_enabled() and mode != "misdirected":
            if data.startswith(h2_capture.PREFACE):
                # Prior knowledge: the client opened with the HTTP/2 connection preface.
                # Until now that was parsed as a nonsense HTTP/1.1 request (``PRI``) and
                # hung up on.
                if await self._serve_h2(
                    reader, writer, peer, entry="preface", prefix=data, mode=mode
                ):
                    return
            else:
                settings_header = self._h2c_settings(hdrs)
                # Truthiness, not `is not None`, and the same test in all three places
                # that read this value: here, `_response_modes`, and
                # `h2_capture.observe`'s choice between `initiate_upgrade_connection` and
                # `initiate_connection`. They used to be spelled two ways and agreed only
                # because `_h2c_settings` cannot return `b""` today; a future relaxation
                # that let it would have granted a 101 to a connection the observer then
                # started as a plain one and never answered on stream 1. Aligning all
                # three removes the disagreement instead of documenting it.
                if settings_header:
                    writer.write(self._h2c_switching_protocols())
                    await writer.drain()
                    # Committed, and so `_serve_h2` never hands this connection back: the
                    # 101 is on the wire, so it is an HTTP/2 connection whatever happens
                    # inside the observer. Falling through to the HTTP/1.1 block below
                    # would run `capture_body`, `_extract_credentials` and `_classify` over
                    # the preface and the frames — fabricating credentials out of frame
                    # bytes, which `_h2c_request_record` exists to prevent — and would put
                    # an HTTP/1.1 200 after a 101, which no server emits.
                    #
                    # Whatever followed the request headers is the client's connection
                    # preface, pipelined behind the upgrade in the same read; dropping it
                    # would leave the observation empty on exactly the connections this
                    # path exists for. `_h2c_settings` has ruled out a declared body, so
                    # these bytes are not one.
                    await self._serve_h2(
                        reader,
                        writer,
                        peer,
                        entry="upgrade",
                        prefix=req.get("body_raw") or b"",
                        settings_header=settings_header,
                        # The request that bought the 101 is evidence, not a handshake
                        # token: it carries a method, a path, headers and possibly
                        # credentials, and `h2` never sees any of it.
                        upgrade_req=req,
                        mode=mode,
                        committed=True,
                    )
                    return

        # Named rather than splatted inline: `_b64_carriers` needs this dict's
        # `body_truncated` to know whether a body-derived length means anything.
        body_fields = capture_body(
            req.get("body_raw") or b"", req["path"] or "", hdrs.get("content-type", "")
        )
        event: dict = {
            "phase": "request",
            "method": req["method"],
            "path": req["path"],
            "query_string": req["query_string"],
            "http_version": req["version"],
            "user_agent": hdrs.get("user-agent"),
            "host": hdrs.get("host"),
            "content_type": hdrs.get("content-type"),
            "headers": hdrs,
            "dst_port": self.port,
            # Verbatim, credentials included — the body is the evidence.
            # See honeypots/body_capture.py.
            **body_fields,
        }

        # Additive, and only when the request-target carried an authority: one more claim
        # the request made, recorded verbatim beside the `Host` header rather than
        # replacing it.
        target_host = shell_bait.target_authority(req["path"])
        if target_host is not None:
            event["request_target_host"] = target_host
        # The claim we actually refused for, when we refused. Without it the row read
        # `host='decoy.invalid'` while the foreign name appeared nowhere, and no
        # host-based hunt could find the event.
        foreign = shell_bait.foreign_claim(claims)
        if foreign is not None:
            event["host"] = foreign

        creds = self._extract_credentials(hdrs, req["body"])
        if creds:
            event["credentials"] = creds
        # Recorded whether or not a credential came out of it: a blob that is not Base64 is
        # the CVE-2026-114938 shape, and `credentials` being absent cannot say so on its own.
        shape = self._basic_auth_shape(hdrs)
        if shape:
            event["basic_auth"] = shape
        # Every other carrier that hands attacker Base64 to `java.util.Base64.getDecoder()`
        # pre-auth: NTLM/Negotiate (168 rows from 68 fleet sources), SAMLRequest/SAMLResponse,
        # a SOAP BinarySecurityToken, and a Bearer token's dot-separated segments.
        # Headers only. `body_fields` already carries the body's and the path's carriers from
        # `capture`, and this decoy's `path` includes the query string, so asking for it twice
        # would store every SAML parameter twice.
        add_carriers(event, request_carriers(headers=hdrs))

        attack = self._classify(req["path"], req["body"], hdrs)
        attack_type = attack[0] if attack else None
        severity = attack[1] if attack else None

        # Decided above, before the HTTP/2 branches, so the record says what we served.
        # A shell hunt is only worth answering if we can later tell which reply
        # produced the follow-up request. See honeypots/shell_bait.py.
        if mode:
            event["response_mode"] = mode

        # Keep the bytes only when the payload rides in the body. A GET adds
        # nothing a parsed request does not already carry, and storing raw for
        # every scan would bloat the table for no evidentiary gain.
        log_event(
            self.PROTOCOL,
            peer,
            event,
            attack_type=attack_type,
            severity=severity,
            raw=data if req.get("body_raw") else None,
        )

        self.logger.info(
            "[HTTP] %s:%d %s %s%s%s",
            peer[0],
            peer[1],
            req["method"] or "?",
            (req["path"] or "/")[:80],
            f" [{attack_type}]" if attack_type else "",
            f" -> {mode}" if mode else "",
        )

        writer.write(shell_bait.build(mode, self.server_header) if mode else self._build_response())
        await writer.drain()

    # ---------------------------------------------------------------- http/2
    #
    # The persona has advertised a vulnerable ``mod_http2`` and ``Upgrade: h2,h2c`` for
    # months while speaking only HTTP/1.1, so every client that took the bait was hung up
    # on before it could send a HEADERS frame: 366 connections from 245 sources in 90 days,
    # all answered ``HTTP/1.1 200`` and closed. ``honeypots/h2_capture.py`` holds enough
    # HTTP/2 state to let one finish its sentence; here is where it is reached.
    #
    # **The decoy stays neutral.** It answers like a patched httpd 2.4.71: it does not
    # reflect ``Content-Length: []``, does not crash, does not stall, and does not
    # implement the A/B oracle the reference proof-of-concept uses to fingerprint a target.
    # The version strings are the only bait and the behaviour behind them is honest.
    # (Operator's decision, 2026-11-12.)
    #
    # **Capture is best-effort; serving is not** — the same contract as
    # ``pre_parser_capture.make_capturing_factory``, which returns the stock factory when
    # aiohttp's internals are not the shape it expects. Anything the HTTP/2 path raises
    # costs us the observation, never the connection: it falls back to today's reply.

    #: Set per host by the quadlet generator (``H2_CAPTURE_ENABLED`` at generation time).
    H2_ENV: ClassVar[str] = "HONEYLENS_H2_CAPTURE"

    def _h2_enabled(self) -> bool:
        """Whether this host's operator switched the HTTP/2 path on."""
        return os.environ.get(self.H2_ENV, "").strip().lower() in _TRUTHY

    @staticmethod
    def _h2c_settings(headers: dict) -> bytes | None:
        """The ``HTTP2-Settings`` value to upgrade with, or ``None`` not to upgrade.

        An h2c upgrade carries the client's opening SETTINGS in this header rather than in
        a frame, so without a decodable one there is nothing to start an HTTP/2 connection
        from — such a request keeps today's HTTP/1.1 reply (and with it the
        ``h2c_upgrade_recon`` label `_classify` gives a bare ``Upgrade: h2c``).
        Returned padded, because h2 base64-decodes it strictly and clients do strip the
        padding RFC 7540 told them to.

        A request that declares a body is not upgraded either. RFC 7540 §3.2 requires the
        client to send the whole body before the upgrade takes effect, so the bytes after
        the headers would be that body and not the HTTP/2 preface — and feeding them to
        the observer would trade a captured POST body for a protocol error. The body is
        the evidence; it keeps the HTTP/1.1 path.
        """
        # ``h2c`` is the cleartext token and the only one Apache would honour here; ``h2``
        # is accepted too because the decoy advertises ``Upgrade: h2,h2c`` and we want to
        # see a client follow through on the bait we put out, not grade its RFC reading.
        # The 101 always names ``h2c``, which is what this connection actually is.
        upgrade = (headers.get("upgrade") or "").lower()
        if not {"h2c", "h2"} & {token.strip() for token in upgrade.split(",")}:
            return None
        declared_body = (headers.get("content-length") or "0").strip() not in {"", "0"}
        if declared_body or headers.get("transfer-encoding"):
            return None
        value = (headers.get("http2-settings") or "").strip()
        if not value:
            return None
        padded = value + "=" * (-len(value) % 4)
        try:
            payload = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError) as exc:
            logging.getLogger(__name__).debug("undecodable HTTP2-Settings: %s", exc)
            return None
        if not payload or len(payload) % _SETTINGS_ENTRY:
            return None
        return padded.encode("ascii", "ignore")

    def _h2c_switching_protocols(self) -> bytes:
        return b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"

    def _h2c_request_record(self, req: dict) -> dict:
        """The h2c upgrade request as evidence, not as a handshake token.

        RFC 7540 makes this request stream 1 of the HTTP/2 connection, but its headers
        arrived over HTTP/1.1 and ``h2`` never sees them. Without classifying it here, two
        extra headers would turn our own analysis off: ``GET /etc/passwd`` earns ``lfi``,
        and the same request with ``Upgrade: h2c`` and ``HTTP2-Settings`` would be stored
        with no verdict at all. Attacker input does not gate our analysis — the fifth time
        on this work that one attacker-controlled field could have done exactly that.

        Classified **with** its headers, because this genuinely *is* an HTTP/1.1 request
        and `_classify`'s ``Upgrade``/User-Agent rules are the right ones for it. A path
        attack on it earns its attack verdict, not the upgrade one: `_classify` checks the
        attack patterns first, so the header branch no longer shadows them and no second
        header-less pass is needed. (The per-stream calls inside `h2_capture.decide` stay
        on ``None`` headers: that ruling is unchanged, because an HTTP/2 stream has no
        ``upgrade`` header to judge.)

        **The path and the headers, and never a body — there is no body here.** What
        `_parse_request` put in ``body``/``body_raw`` is the bytes after the blank line,
        and on this path those are the HTTP/2 connection preface and the frames the client
        pipelined behind it: the very bytes `handle_connection` hands to `_serve_h2` as
        ``prefix``. They cannot be both a body and the frame stream, and they are the frame
        stream. `_h2c_settings` has already refused any request that declares a body, so
        there is nothing else they could be. Running text rules over them would be the
        connection-buffer-as-request-evidence defect `pre_parser_capture` documents, twice
        over: those bytes are decoded per stream and judged properly by `decide`, so a
        verdict here would be counted twice against one connection — and a text rule over
        binary HPACK can manufacture one out of noise, a false ``rce_attempt`` from a
        Huffman-coded header value. `_extract_credentials` still earns its place with no
        body: ``authorization: Basic`` lives in the headers, and an attacker choosing to
        send it is real evidence.
        """
        hdrs = req.get("headers") or {}
        record: dict = {
            "method": req.get("method"),
            "path": req.get("path"),
            "query_string": req.get("query_string"),
            "http_version": req.get("version"),
            "user_agent": hdrs.get("user-agent"),
            "host": hdrs.get("host"),
            "content_type": hdrs.get("content-type"),
            "headers": hdrs,
        }
        target_host = shell_bait.target_authority(req.get("path"))
        if target_host is not None:
            # One more claim this request made, beside the `Host` header above.
            record["request_target_host"] = target_host
        # body=None in both calls below, deliberately: see the docstring. The bytes
        # `_parse_request` calls the body are the HTTP/2 connection preface and the frames
        # behind it, not request text — this is not a dropped argument, do not "fix" it.
        creds = self._extract_credentials(hdrs, None)
        if creds:
            record["credentials"] = creds
        shape = self._basic_auth_shape(hdrs)
        if shape:
            record["basic_auth"] = shape
        # Headers and query only, for the same reason the credential call passes body=None
        # above: what `_parse_request` calls the body here is the HTTP/2 preface and its frames.
        carriers = self._b64_carriers(hdrs, path=req.get("path"))
        if carriers:
            record["b64_carriers"] = carriers
        result = self._classify(req.get("path"), None, hdrs)
        record["verdicts"] = [result[0]] if result else []
        record["severity"] = result[1] if result else None
        return record

    def _h2_response(self, mode: str | None = None) -> tuple[list[tuple[str, str]], bytes]:
        """The persona's response for a completed HTTP/2 stream, in `shell_bait`'s ``mode``.

        No ``content-length``: END_STREAM delimits the body, RFC 9113 does not require the
        header, and a reflected ``Content-Length`` is exactly the oracle the 119618
        proof-of-concept reads. No ``upgrade``/``connection`` either — HTTP/2 forbids
        connection-specific headers and h2 refuses to send them.

        The two `shell_bait` modes answer without content, mirroring `shell_bait.build`
        over HTTP/2 rather than letting the protocol launder the guard away: ``421``
        refuses a domain that is not ours to answer for and gives a scanner nothing to act
        on, and the bait's empty ``200`` is what a planted shell returns to a bare GET — no
        banner to fingerprint, but enough for a sweep to record a hit.
        """
        if mode == "misdirected":
            return [(":status", "421"), ("server", self.server_header)], b""
        headers = [(":status", "200"), ("server", self.server_header)]
        if mode == "bait":
            return [*headers, ("content-type", "text/html; charset=UTF-8")], b""
        return [
            *headers,
            ("x-powered-by", self.powered_by),
            ("content-type", "text/html; charset=UTF-8"),
        ], self._page().encode()

    def _h2_response_for(
        self,
        stream: h2_capture.H2Stream | None,
        obs: h2_capture.H2Observation,
        served: list[tuple[str, int]],
    ) -> tuple[list[tuple[str, str]], bytes]:
        """The reply for one HTTP/2 stream, judged on what *that stream* asked for.

        Records what it decided in ``served``, so the row can say what was served. A
        preface connection has no HTTP/1.1 ``Host`` to decide from, so without this its
        ``response_mode`` would read empty on the very connections where the per-stream
        guard did the refusing.

        HTTP/2 carries the host in each stream's ``:authority``, so one connection can ask
        under several names and a connection-level decision cannot stand in for all of
        them. `shell_bait`'s guard is per request; so is this. Without it a bare preface
        with ``:authority victim.example`` was served the full Apache page — measured — and
        that is the one outcome the guard exists to prevent, because it manufactures
        evidence that someone else's site is compromised.

        A stream past ``keep_streams`` was not recorded, so its host is unreadable here and
        the guard **fails closed**: a bodyless ``200``, not the page. A client that
        completes more than five streams on this decoy is not a browser, and serving a
        third party's domain a page must not be the default when we cannot check.
        """
        if stream is None:
            return [(":status", "200"), ("server", self.server_header)], b""
        claims = shell_bait.host_claims(
            target=stream.path,
            host_header=stream.host_values or stream.headers.get("host"),
            authority=stream.authority,
        )
        mode = shell_bait.decide(stream.path, claims)
        # Every reply gets a token, the page included: a connection that served stream 1
        # and refused stream 3 used to record "misdirected" alone, so the row said we
        # refused when we had also served. Appended raw, one per answered stream;
        # `_response_modes` is the single place that de-duplicates, so there is one
        # implementation of that rule rather than two agreeing by luck.
        #
        # Paired with the outbound tally **as it stands now**, before this reply is
        # queued, because we are called before it is flushed: a peer that dies mid-flush
        # left the row claiming `page` with `bytes_out=51` — the handshake alone — and
        # nothing on the wire. `_response_modes` keeps a token only if the tally grew past
        # this mark, which is the only thing that distinguishes a reply that went out from
        # one that was queued onto a peer that had gone. A `bytes_out > 0` gate could not
        # tell them apart, because the handshake already made it non-zero.
        served.append((mode or _SERVED_PAGE, obs.bytes_out))
        return self._h2_response(mode)

    @staticmethod
    def _response_modes(
        obs: h2_capture.H2Observation,
        settings_header: bytes | None,
        mode: str | None,
        served: list[tuple[str, int]],
    ) -> str | None:
        """What this connection actually replied, de-duplicated, for ``response_mode``.

        Stream 1's token cannot be appended by `_h2_response_for`, because on the upgrade
        path the observer answers that stream itself, before any stream completes — so it
        is added here instead, and **only once something actually left for the peer**.
        Seeding it up front stated intent rather than outcome: measured twice, with the
        record build patched to raise after the 101 and with a peer whose second write
        raised, the row read ``response_mode='page'`` while ``bytes_out=0`` showed the
        reply never went out. That is the same mistake as seeding the preface path, which
        was rejected on the grounds that a reset flood answers nothing — the standard has
        to hold on both sides.

        ``bool(settings_header)`` on purpose, which is the exact test `h2_capture.observe`
        uses to decide whether to answer stream 1 at all. The two were spelled differently
        (``is not None`` here) and agreed only because `_h2c_settings` can never return
        ``b""`` today; a future relaxation would have seeded ``page`` onto a connection
        that took the ``initiate_connection()`` branch and answered nothing.

        Each per-stream token carries the outbound tally from just before its reply was
        queued, and is kept only if the tally grew past it — the same standard, applied to
        the side `_h2_response_for` owns. It cannot use ``bytes_out > 0`` the way stream 1
        does: on a preface connection the handshake has already made the tally non-zero,
        so a peer that died mid-flush recorded ``page`` with ``bytes_out=51`` and nothing
        on the wire. Stream 1's own test *is* ``bytes_out > 0``, and exactly for the
        mirror-image reason: there the handshake and that reply are queued together and
        flushed once, so the tally is still 0 if neither got out.

        This is the only place the de-duplication rule lives. It was implemented twice
        once, and two copies agreeing by luck is what makes a mutation of either look dead.
        """
        tokens: list[str] = []
        if settings_header and obs.bytes_out > 0:
            tokens.append(mode or _SERVED_PAGE)
        for token, tally_before in served:
            if obs.bytes_out > tally_before and token not in tokens:
                tokens.append(token)
        return ",".join(tokens) or None

    @staticmethod
    def _h2_payload(
        obs: h2_capture.H2Observation,
        verdicts: list[str],
        upgrade_request: dict | None = None,
    ) -> str:
        """One line: the connection's summary, the h2c upgrade request if there was one,
        and the **first** decoded stream.

        A connection is not a request. Rendering every kept stream here would let a
        flood's fifth stream earn the first one's label — the lesson
        ``pre_parser_capture`` paid for with 61 misattributed verdicts. The upgrade
        request is not a second stream's text: it is this connection's own first request,
        this row holds its verdict, and the greppable field has to be able to show what it
        asked for.
        """
        parts = [
            f"h2 {obs.entry}",
            f"streams={obs.streams_opened}",
            f"headers={obs.headers_frames}",
            f"rst={obs.rst_stream_total}",
            f"shape={obs.shape_matches}",
            f"cont={obs.continuation_frames}",
            f"in={obs.bytes_in}",
            f"out={obs.bytes_out}",
        ]
        if obs.goaway_reason:
            parts.append(f"goaway={obs.goaway_reason}")
        if obs.h2_error:
            parts.append(f"error={obs.h2_error}")
        if verdicts:
            parts.append(f"verdicts={','.join(verdicts)}")
        if upgrade_request:
            path = (upgrade_request.get("path") or "")[:_H2_PATH_IN_PAYLOAD]
            parts.append(f"upgrade={upgrade_request.get('method') or '?'} {path}")
        if obs.streams:
            first = obs.streams[0]
            path = (first.path or "")[:_H2_PATH_IN_PAYLOAD]
            parts.append(f"first=#{first.stream_id} {first.method or '?'} {path}")
        return " ".join(parts)[:_H2_PAYLOAD_MAX]

    def _h2_event(
        self,
        obs: h2_capture.H2Observation,
        verdicts: list[str],
        *,
        incomplete: str | None,
        upgrade_request: dict | None = None,
        response_mode: str | None = None,
    ) -> dict:
        """One event for one HTTP/2 connection — never one per stream.

        A 3456-stream flood is one row. The store holds ~5.1M rows under 30-day retention
        and a per-stream row would let a single attacker own the table.
        """
        event: dict = {
            "event_type": "H2_CONNECTION",
            # log_event derives the attack_patterns rule name from this; without it a
            # verdict lands in the table with nothing to explain itself.
            "rule": verdicts[0] if verdicts else "h2_connection",
            "h2_entry": obs.entry,
            "http_version": "2",
            "dst_port": self.port,
            "h2_verdicts": verdicts,
            "payload": self._h2_payload(obs, verdicts, upgrade_request),
            # The counters that let a reader re-derive the verdict, because the verdict
            # names are a lossy summary: a shaped flood with too few resets reads as a
            # "probe", and a reset flood carrying CONTINUATION reports only the bomb.
            "streams_opened": obs.streams_opened,
            "headers_frames": obs.headers_frames,
            "rst_stream_total": obs.rst_stream_total,
            # Decides nothing (any reset code fires the race); recorded because it says the
            # resets matched the reference capture's code.
            "rst_stream_cancel": obs.rst_stream_cancel,
            "reset_ratio": round(
                obs.rst_stream_total / obs.headers_frames if obs.headers_frames else 0.0, 4
            ),
            "shape_matches": obs.shape_matches,
            "continuation_frames": obs.continuation_frames,
            "data_frames": obs.data_frames,
            "frames_total": obs.frames_total,
            # Reads 1 for a reset flood and varies with TCP segmentation: not a flood
            # signal, kept for the reader.
            "max_concurrent_streams_seen": obs.max_concurrent_streams_seen,
            # The pair that is the amplification ratio, and the reason the outbound budget
            # exists at all.
            "bytes_in": obs.bytes_in,
            "bytes_out": obs.bytes_out,
            "goaway_sent": obs.goaway_sent,
            # A resource label, not an attack signal: do not derive anything from it.
            "goaway_reason": obs.goaway_reason,
            "settings_initial_window_size": obs.settings_initial_window_size,
            "window_update_count": obs.window_update_count,
            "window_update_min_increment": obs.window_update_min_increment,
            "h2_error": obs.h2_error,
            "h2_error_reason": obs.h2_error_reason,
            # Which side of the line that failure fell on, as `h2`'s own exception
            # hierarchy drew it (`h2_capture.is_protocol_error`). `h2_error_reason` is a
            # free-text message and `h2_error` is a class name, so without this a hunt for
            # "the peer broke the protocol" has to match on either -- and the verdict name
            # is a lossy summary, absent whenever something heavier already fired.
            "h2_error_protocol": obs.h2_error_protocol,
            "streams": [dataclasses.asdict(stream) for stream in obs.streams],
        }
        if response_mode:
            # What we served, decided by `shell_bait` before the h2 branches. Without it
            # nobody could tell afterwards whether this connection got the page, the
            # bait's empty 200, or nothing — and the bait is only worth running if a
            # follow-up request can be tied to the reply that caused it.
            event["response_mode"] = response_mode
        if upgrade_request is not None:
            # Under its own key, so a reader never mistakes the HTTP/1.1 request that
            # bought the 101 for one of the decoded HTTP/2 streams. Its verdicts are
            # already merged into `h2_verdicts` and the severity by `_log_h2`.
            event["upgrade_request"] = upgrade_request
            if upgrade_request.get("credentials"):
                event["credentials"] = upgrade_request["credentials"]
        # Credentials a stream posted in its DATA body, read the way the HTTP/1.1 path
        # reads them. Without this an HTTP/2 POST of `login=admin&pwd=hunter2` lost the
        # password outright, where the same bytes over HTTP/1.1 were captured — the
        # classification bypass Goal 5 forbids, in its credential half. The stream that
        # yielded them is named, because a connection can carry several.
        for stream in obs.streams:
            if not stream.body:
                continue
            found = self._extract_credentials(stream.headers, stream.body)
            if found:
                # One guard around BOTH, not a `setdefault` each. Independent
                # `setdefault`s let the second land when the first was a no-op, so an
                # upgrade request's Basic credential was recorded with
                # `credentials_from_stream: 3` while stream 3's own
                # `login=…&pwd=…` never reached the field — the row naming a stream as
                # the source of something it did not send. That is the misattribution
                # `_h2_payload` above cites the 61-verdict lesson for, so it does not get
                # to reappear two screens below it.
                if "credentials" not in event:
                    event["credentials"] = found
                    event["credentials_from_stream"] = stream.stream_id
                break
        if obs.streams:
            first = obs.streams[0]
            # Convenience fields: the FIRST stream's, not the connection's. `streams` and
            # the counters above describe the connection; these name one stream, and
            # `fields_from_stream` says which.
            event["fields_from_stream"] = first.stream_id
            event["method"] = first.method
            event["path"] = first.path
            # The claim we refused for when we refused, and otherwise the host the
            # stream actually named. Taking the first claim instead let an authority
            # parsed out of `:path` outrank the `:authority` the stream really sent, so
            # `:path '//images.php'` recorded `host='images.php'` — a path segment in the
            # one column a host-based hunt reads, on the shape this very diff calls the
            # commonest in shell-sweep traffic. `host_claims` orders target-authority
            # first because that is the order it looks, not an order of authority; only a
            # FOREIGN claim is worth displacing what the stream said about itself.
            stream_claims = shell_bait.host_claims(
                target=first.path,
                host_header=first.host_values or first.headers.get("host"),
                authority=first.authority,
            )
            event["host"] = (
                shell_bait.foreign_claim(stream_claims)
                or first.authority
                or first.headers.get("host")
            )
            event["user_agent"] = first.headers.get("user-agent")
            event["content_type"] = first.content_type
        elif upgrade_request is not None:
            # No stream decoded — the client bought the 101 and then said nothing in
            # HTTP/2. The upgrade request is still what it asked for, so it fills the same
            # fields and `fields_from_upgrade_request` says where they came from.
            event["fields_from_upgrade_request"] = True
            for key in ("method", "path", "query_string", "host", "user_agent", "content_type"):
                event[key] = upgrade_request.get(key)
        if incomplete is None:
            event["duration_ms"] = obs.duration_ms
        else:
            # Cancelled at CONNECTION_TIMEOUT, or the capture broke after the 101 was
            # already on the wire. Either way `duration_ms` and `raw` are assigned after
            # the observer's loop, so on this path they are 0 and empty — not measurements,
            # and omitted rather than reported. The reason says which happened.
            event["h2_incomplete"] = incomplete
        return event

    def _log_h2(
        self,
        peer,
        obs: h2_capture.H2Observation,
        *,
        incomplete: str | None,
        upgrade_request: dict | None = None,
        response_mode: str | None = None,
    ) -> None:
        verdicts, severity = h2_capture.decide(obs, self._classify)
        if upgrade_request is not None:
            # Appended, never re-ordered: `decide`'s precedence is its own and the upgrade
            # request's verdict is one more fact about the same connection, not a reason to
            # re-weight the others. The severity still rises to the heaviest.
            for name in upgrade_request.get("verdicts") or []:
                if name not in verdicts:
                    verdicts.append(name)
            severity = h2_capture.heavier(severity, upgrade_request.get("severity"))
        event = self._h2_event(
            obs,
            verdicts,
            incomplete=incomplete,
            upgrade_request=upgrade_request,
            response_mode=response_mode,
        )
        log_event(
            self.PROTOCOL,
            peer,
            event,
            attack_type=h2_capture.attack_type_field(verdicts, obs.verdict_severities),
            severity=severity,
            raw=obs.raw or None,
        )
        self.logger.info(
            "[HTTP/2] %s:%d %s streams=%d rst=%d shape=%d [%s]%s",
            peer[0],
            peer[1],
            obs.entry,
            obs.streams_opened,
            obs.rst_stream_total,
            obs.shape_matches,
            ",".join(verdicts),
            f" goaway={obs.goaway_reason}" if obs.goaway_reason else "",
        )

    async def _serve_h2(
        self,
        reader,
        writer,
        peer,
        *,
        entry: str,
        prefix: bytes = b"",
        settings_header: bytes | None = None,
        upgrade_req: dict | None = None,
        mode: str | None = None,
        committed: bool = False,
    ) -> bool:
        """Observe one HTTP/2 connection and write exactly one event for it.

        Returns False only when the HTTP/2 path could not run **and** nothing has been
        written that commits the connection to HTTP/2; the caller then serves HTTP/1.1 as
        it always has, so a connection still gets exactly one event, just not this one.
        With ``committed`` — the ``101`` already on the wire — there is no handing back:
        the row is written here and the caller returns. ``observe`` is documented never to
        raise except ``CancelledError``; the ``except Exception`` is there because a decoy
        must not become a new failure surface if that ever stops being true.

        Everything that can run attacker-shaped input through our own code is inside the
        ``try``, including building the upgrade record and the response: the whole point of
        this guard is the failure nobody predicted, and a raise while preparing would
        otherwise kill the connection with no event at all.
        """
        obs: h2_capture.H2Observation | None = None
        record: dict | None = None
        # Each reply a *stream* got, appended by `_h2_response_for` as that stream is
        # answered, de-duplicated and joined into `response_mode` by `_response_modes` —
        # the way `attack_type` already summarises a row covering more than one request.
        # Not seeded: see `_response_modes` for why stream 1's token cannot be added here.
        served: list[tuple[str, int]] = []
        try:
            # Constructed here, so the one thing above it that could raise is this
            # dataclass's own constructor — see the `obs is None` branch below.
            obs = h2_capture.H2Observation(entry=entry)
            record = self._h2c_request_record(upgrade_req) if upgrade_req is not None else None
            headers, body = self._h2_response(mode)
            await h2_capture.observe(
                reader,
                writer,
                entry=entry,
                prefix=prefix,
                settings_header=settings_header,
                # Stream 1 on the upgrade path and the fallback everywhere else; every
                # decoded stream is judged on its own `:authority` by `_h2_response_for`.
                response_headers=headers,
                response_body=body,
                response_for=lambda stream: self._h2_response_for(stream, obs, served),
                # Classified as each stream's HEADERS arrive, so a verdict survives the
                # `keep_streams` ceiling. See `h2_capture.classify_stream`.
                classify=self._classify,
                obs=obs,
            )
        except asyncio.CancelledError:
            # The handler's 60-second timeout. The observation is ours, so everything
            # tallied before the cancellation is still on the record: a client that sends
            # the preface and goes silent gets its event too.
            if obs is not None:
                self._log_h2(
                    peer,
                    obs,
                    incomplete="cancelled",
                    upgrade_request=record,
                    response_mode=self._response_modes(obs, settings_header, mode, served),
                )
            raise
        except Exception as exc:
            self.logger.debug("h2 capture unavailable: %s", exc)
            # ``obs is None`` on the committed path is the ONE route through this decoy
            # that yields no row at all: the 101 is already on the wire so we must not fall
            # back, and there is no observation to build a row from. It is reachable only if
            # `H2Observation(entry=...)` itself raised — a dataclass whose every field has a
            # default, called with a literal from our own code and nothing from the
            # attacker. Deliberately left as is rather than retried in this handler: a
            # second call to the constructor that just failed would raise again, so that
            # "fix" could not work, and a fix that cannot work is worse than a named gap.
            # Everything else — clean close, GOAWAY, every budget, protocol error,
            # cancellation at CONNECTION_TIMEOUT, a broken capture after the 101 — writes
            # exactly one row.
            if not committed or obs is None:
                return False  # serve HTTP/1.1, exactly as before the h2 path existed
            obs.h2_error = obs.h2_error or type(exc).__name__
            obs.h2_error_reason = (
                obs.h2_error_reason or (str(exc) or type(exc).__name__)[:_H2_REASON_MAX]
            )
            # Classified here as well as inside `observe`, because this is the other place
            # an exception becomes a row. The 101 has gone out, so `entry == "upgrade"` and
            # `decide()` withholds the `h2_prior_knowledge` baseline -- an `H2Error`
            # arriving here without this line produces a row carrying no verdict at all.
            obs.h2_error_protocol = obs.h2_error_protocol or h2_capture.is_protocol_error(exc)
            self._log_h2(
                peer,
                obs,
                incomplete="capture_error",
                upgrade_request=record,
                response_mode=self._response_modes(obs, settings_header, mode, served),
            )
            return True
        self._log_h2(
            peer,
            obs,
            incomplete=None,
            upgrade_request=record,
            response_mode=self._response_modes(obs, settings_header, mode, served),
        )
        return True


if __name__ == "__main__":
    HTTPHoneypot().run()
