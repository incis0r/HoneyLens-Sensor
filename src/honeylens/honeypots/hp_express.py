"""
honeypots/hp_express.py — Node/Express JSON API decoy
======================================================
Bait for NODE2SHELL / CVE-2026-111497, the out-of-bounds write in Node's Brotli decoder. The
bug is reachable because Express 5 with body-parser 2 inflates a ``Content-Encoding: br``
request body by default, so an operator who fingerprints before firing needs to believe there
is a Node service here. Measured 2026-10-30 and again 2026-11-01: the fleet has recorded zero
Brotli-encoded request bodies, and it also offers no Node surface at all -- so the zero is a
statement about our bait, not only about the traffic. This decoy is the half of that result we
can change. Option 2 of the 30 Oct NODE2SHELL review §5.

What makes it look like Express, all of it observable in a real `express()` app with no routes:

* ``X-Powered-By: Express`` -- on by default in Express, and the single most-fingerprinted header.
* An Express-shaped 404: ``Cannot GET /path`` in a ``<pre>`` block, with
  ``Content-Security-Policy: default-src 'none'`` and ``X-Content-Type-Options: nosniff``.
  That trio comes from ``finalhandler`` and is hard to fake by accident.
* A weak ``ETag`` (``W/"len-hash"``) on JSON responses, which is Express's default etag mode.
* ``Vary: Accept-Encoding``, and a JSON index that states the API accepts compressed bodies.
* A compressed request body is answered the way a server that inflated it answers: ``200`` with
  a plausible ack, not ``415``. A ``415`` tells a careful operator the body was never inflated,
  and the whole point of the bait is that it looks like it was.

What it deliberately does not do:

* **It never decompresses anything.** The compressed bytes are captured verbatim and stored.
  Decoding attacker input buys nothing here -- the verdict comes from the header -- and running
  any decoder over a payload crafted to break a decoder is not a thing to do on a sensor.
* **It emits no verdict of its own.** A decoy verdict suppresses the central classifier for that
  event entirely (``ingest/honeypot.py::_attack_hits`` -- "neither overridden nor supplemented"),
  which in 2026-10-26 cost twenty PHP2Shell events their PHP2Shell tag because the nginx decoy
  had already answered with its own. The ``node2shell_brotli_request_body`` rule in the central
  registry does the labelling, so everything else in the body still gets classified too.
* **It does not answer like a patched decoder.** Replying ``ERR__ERROR_FORMAT_BLOCK_SWITCH`` to
  a malformed Brotli body would tell the operator they found a Node service and that it is
  patched, which is option 3 of the review -- a deception decision, outside the passive lane,
  and not what was chosen.

Run standalone:  python -m honeylens.honeypots.hp_express
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from email.utils import formatdate

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_CAPTURE
from honeylens.honeypots.body_capture import capture as capture_body

#: Request-body encodings Express 5 + body-parser 2 will inflate. `br` is the one that matters;
#: the others are here so the event says which of them arrived rather than just "compressed".
INFLATED_ENCODINGS = ("br", "gzip", "deflate")


class ExpressHoneypot(BaseHoneypot):
    PROTOCOL = "express"
    DEFAULT_PORT = 3000
    TTL_PROFILE = "linux"

    def __init__(self):
        super().__init__()
        self.powered_by = self.profile.get("powered_by", "Express")
        self.service_name = self.profile.get("service_name", "api")
        self.service_version = self.profile.get("service_version", "1.4.2")

    # ------------------------------------------------------------------ parse
    @staticmethod
    def _parse_request(data: bytes) -> dict:
        """Parse raw HTTP bytes. Headers are decoded as text; the body is kept as bytes, because
        a Brotli-encoded body is not text and decoding it would be the first thing to destroy."""
        out: dict = {
            "method": None,
            "path": None,
            "version": None,
            "headers": {},
            "body_raw": b"",
            "query_string": None,
        }
        head = data
        if b"\r\n\r\n" in data:
            head, out["body_raw"] = data.split(b"\r\n\r\n", 1)

        lines = head.decode("latin-1", "replace").split("\r\n")
        if lines:
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2:
                out["method"], out["path"] = parts[0], parts[1]
                if "?" in parts[1]:
                    out["query_string"] = parts[1].split("?", 1)[1]
            if len(parts) >= 3:
                out["version"] = parts[2]
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                out["headers"][k.lower()] = v
        return out

    @staticmethod
    def declared_encodings(headers: dict) -> list[str]:
        """Which inflatable encodings the request declares on its own body, in header order.

        Only ``Content-Encoding`` counts. ``Accept-Encoding`` is what the client will *accept*
        back and is present on thousands of ordinary requests a day -- reading it as the body's
        encoding is the mistake that turns the whole fleet into a false positive.
        """
        raw = (headers.get("content-encoding") or "").lower()
        if not raw:
            return []
        tokens = [t.strip() for t in raw.split(",")]
        return [t for t in tokens if t in INFLATED_ENCODINGS]

    # -------------------------------------------------------------- response
    @staticmethod
    def _etag(body: bytes) -> str:
        """Express's default weak etag: length in hex, then a base64 digest, as `W/"len-hash"`."""
        # SHA-1 because that is what Express's etag uses. usedforsecurity=False says so to
        # the interpreter and to the scanners: the value is a cache tag we are imitating,
        # not a hash anything trusts.
        digest = hashlib.sha1(body, usedforsecurity=False).digest()
        tag = base64.b64encode(digest)[:27].decode()
        return f'W/"{len(body):x}-{tag}"'

    def _respond(self, status: str, body: bytes, content_type: str, extra: str = "") -> bytes:
        return (
            f"HTTP/1.1 {status}\r\n"
            f"X-Powered-By: {self.powered_by}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Vary: Accept-Encoding\r\n"
            f"ETag: {self._etag(body)}\r\n"
            f"Date: {formatdate(time.time(), usegmt=True)}\r\n"
            f"Connection: keep-alive\r\n"
            f"Keep-Alive: timeout=5\r\n"
            f"{extra}"
            f"\r\n"
        ).encode() + body

    def _index(self) -> bytes:
        body = (
            f'{{"name":"{self.service_name}","version":"{self.service_version}","status":"ok",'
            '"endpoints":["/api/v1/health","/api/v1/events","/api/v1/import"],'
            '"accepts":{"content-encoding":["br","gzip","deflate"],"content-type":'
            f'["application/json"]}},"uptime":{int(time.monotonic())}}}'
        )
        return self._respond("200 OK", body.encode(), "application/json; charset=utf-8")

    def _ack(self, encodings: list[str]) -> bytes:
        """What a server that inflated the body answers. Says nothing about what was in it."""
        body = '{"accepted":true,"encoding":"%s"}' % (encodings[0] if encodings else "identity")
        return self._respond("200 OK", body.encode(), "application/json; charset=utf-8")

    def _not_found(self, method: str | None, path: str | None) -> bytes:
        """finalhandler's 404, including the two headers Express sends with it."""
        shown = (path or "/").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        body = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            "<title>Error</title>\n</head>\n<body>\n"
            f"<pre>Cannot {(method or 'GET').upper()} {shown}</pre>\n"
            "</body>\n</html>\n"
        ).encode()
        return self._respond(
            "404 Not Found",
            body,
            "text/html; charset=utf-8",
            extra="Content-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\n",
        )

    # -------------------------------------------------------------- handler
    #: Ceiling on the header block, so a client cannot make us buffer without limit by never
    #: sending the terminator.
    MAX_HEADER_BYTES = 64 * 1024

    async def _read_request(self, reader) -> bytes:
        """Read until the header terminator, then the declared Content-Length, bounded.

        A single read() returns whatever one TCP segment carried, and this matters twice over.
        A body larger than the MTU arrives in pieces, so stopping at the first read is how a
        decoy records a 20 KB POST as a 1.4 KB one -- the defect found on the honeypotng family
        in October. Less obviously, the *headers* can also be split: if the first segment ends
        mid-header there is no `\\r\\n\\r\\n` yet, and a decoy that gives up there loses the
        entire body, which is exactly what this decoy exists to capture. So the terminator is
        waited for rather than assumed.
        """
        data = b""
        while b"\r\n\r\n" not in data and len(data) < self.MAX_HEADER_BYTES:
            chunk = await asyncio.wait_for(reader.read(16384), timeout=30)
            if not chunk:
                break
            data += chunk
        if not data or b"\r\n\r\n" not in data:
            return data
        head, body = data.split(b"\r\n\r\n", 1)
        want = 0
        for line in head.decode("latin-1", "replace").split("\r\n")[1:]:
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

    async def handle_connection(self, reader, writer, peer):
        data = await self._read_request(reader)
        if not data:
            return

        req = self._parse_request(data)
        hdrs = req["headers"]
        body_raw = req["body_raw"]
        encodings = self.declared_encodings(hdrs)

        event: dict = {
            "phase": "request",
            "method": req["method"],
            "path": req["path"],
            "query_string": req["query_string"],
            "http_version": req["version"],
            "user_agent": hdrs.get("user-agent"),
            "host": hdrs.get("host"),
            "content_type": hdrs.get("content-type"),
            "content_encoding": hdrs.get("content-encoding"),
            "headers": hdrs,
            "dst_port": self.port,
            # Verbatim and undecoded. A Brotli body is binary, so body_capture base64s it.
            **capture_body(body_raw, req["path"] or "", hdrs.get("content-type", "")),
        }
        if encodings:
            # Named explicitly so a hunt does not have to re-parse the header list, and so the
            # event says which encoding arrived rather than merely that one did.
            event["body_encodings"] = encodings
            event["brotli_body"] = "br" in encodings

        # No attack_type from here: a decoy verdict switches the central classifier off for this
        # event, and the rule that names this vector lives in the central registry
        # (node2shell_brotli_request_body). Keep the raw bytes whenever a body arrived -- for a
        # compressed body the bytes ARE the evidence and the parse is not.
        log_event(self.PROTOCOL, peer, event, proto="HTTP", raw=data if body_raw else None)

        self.logger.info(
            "[EXPRESS] %s:%d %s %s%s",
            peer[0],
            peer[1],
            req["method"] or "?",
            (req["path"] or "/")[:80],
            f" body={len(body_raw)}B enc={','.join(encodings)}" if encodings else "",
        )

        path = (req["path"] or "/").split("?", 1)[0]
        if body_raw:
            writer.write(self._ack(encodings))
        elif path in ("/", "/api/v1/health"):
            writer.write(self._index())
        else:
            writer.write(self._not_found(req["method"], req["path"]))
        await writer.drain()


if __name__ == "__main__":
    ExpressHoneypot().run()
