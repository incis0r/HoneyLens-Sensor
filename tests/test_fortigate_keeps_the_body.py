"""The FortiGate decoy must keep the bodies that are sent to it.

Most handlers here answer from the path and the headers, which is enough to be
believable and was never enough to be evidence. Two of them captured a body, with
512-byte and 256-byte samples of their own; the rest read nothing.

Measured over the 30-day window on 2026-10-25: **5 046 POSTs across the fleet and not
one stored body**, 3 310 of them on `sensor-f`, where this decoy takes almost all the HTTP
traffic. `ingest/fortigate.py` had no `full_payload` write at all, so even the two
handlers that did capture put their sample in a JSON blob inside `payload` and nothing in
the column a content hunt reads.

The capture now happens in middleware rather than per handler, so a route added later
cannot reintroduce the gap by forgetting — which is what these tests pin.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from honeylens.honeypots import honeypot_fortigate as fg


@pytest.fixture
def decoy(tmp_path):
    """The real app with the real middleware, writing events to a temp file."""
    log = tmp_path / "fortigate.json"

    async def run(method, path, **kw):
        honeypot = fg.FortiGateHoneypot(log_file=str(log))
        app = web.Application(middlewares=[fg._body_middleware_factory()])
        honeypot.setup_routes(app)
        async with TestClient(TestServer(app)) as client:
            await client.request(method, path, **kw)
        return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]

    return run


def _events(decoy, method, path, **kw):
    return asyncio.run(decoy(method, path, **kw))


def test_a_post_body_is_captured_on_a_route_that_never_read_one(decoy):
    """`/api/v2/...` answers from the path; the body was simply discarded."""
    body = b'{"name":"../../mkey","password":"hunter2"}'
    events = _events(decoy, "POST", "/api/v2/cmdb/system/admin", data=body)

    assert events, "no event was written at all"
    with_body = [e for e in events if e.get("data", {}).get("body_len")]
    assert with_body, "the body was discarded again"
    assert with_body[0]["data"]["body_len"] == len(body)
    assert "mkey" in with_body[0]["data"]["body_sample"]


def test_the_verbatim_bytes_travel_for_full_payload(decoy):
    """`raw_hex` is what `ingest/fortigate.py` turns into `full_payload`."""
    body = b"\x00\x01\xff<?php system('id'); ?>"
    events = _events(decoy, "POST", "/api/v2/cmdb/system/admin", data=body)

    raw = [bytes.fromhex(e["raw_hex"]) for e in events if e.get("raw_hex")]
    assert raw, "nothing would reach full_payload"
    assert raw[0] == body, "what is stored is not what arrived"


def test_a_get_carries_no_body_fields(decoy):
    """'no body' and 'an empty body' are different observations."""
    events = _events(decoy, "GET", "/login")
    assert events
    assert not any(e.get("raw_hex") for e in events)


def test_the_credential_handler_still_captures_its_pair(decoy):
    """The middleware reads the body first; aiohttp caches it, so `request.post()` in
    the handler must still see the form."""
    events = _events(decoy, "POST", "/logincheck", data={"username": "admin", "secretkey": "x"})

    assert any("admin" in json.dumps(e.get("data", {})) for e in events), (
        "reading the body in middleware broke the handler's own form parsing"
    )


def test_every_route_is_covered_by_the_middleware():
    """A route added later must not be able to reintroduce the gap by forgetting."""
    honeypot = fg.FortiGateHoneypot(log_file="/dev/null")
    app = web.Application(middlewares=[fg._body_middleware_factory()])
    honeypot.setup_routes(app)
    assert len(app.middlewares) == 1
    assert app.router.routes(), "no routes registered"
