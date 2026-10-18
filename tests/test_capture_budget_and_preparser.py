"""B12 (per-honeypot capture budget) and E7 (pre-parser rejection capture) coverage."""

from __future__ import annotations

import asyncio

from aiohttp import web

from honeylens.honeypots import body_capture, pre_parser_capture
from honeylens.honeypots import honeypot_netscaler as ns
from honeylens.honeypots import honeypot_sharepoint as sp
from honeylens.honeypots import sink as real_sink


class _CaptureSink:
    def __init__(self):
        self.records: list[dict] = []

    def build_record(self, **kw):
        return real_sink.build_record(**kw)

    def write_record(self, record):
        self.records.append(record)
        return True


# --- B12: per-honeypot capture budget --------------------------------------------------


def test_body_capture_honors_per_call_budget():
    big = b"A" * (200 * 1024)
    default = body_capture.capture(big, "/x", "application/x-www-form-urlencoded")
    assert default["body_truncated"] is True
    assert len(default["body_sample"]) == body_capture.MAX_CAPTURE  # global ceiling

    wide = body_capture.capture(
        big, "/x", "application/x-www-form-urlencoded", max_capture=256 * 1024
    )
    assert wide["body_truncated"] is False
    assert len(wide["body_sample"]) == len(big)  # kept in full under the bigger budget
    assert wide["body_len"] == len(big)  # true length always reported


def test_build_record_honors_raw_capture_bytes():
    raw = b"B" * (200 * 1024)
    default = real_sink.build_record(
        source="x",
        honeypot="x",
        protocol="http",
        peer=("1.2.3.4", 1),
        event={},
        payload="p",
        raw=raw,
    )
    assert len(default["raw_hex"]) == real_sink.MAX_RAW_CAPTURE * 2  # hex = 2 chars/byte

    wide = real_sink.build_record(
        source="x",
        honeypot="x",
        protocol="http",
        peer=("1.2.3.4", 1),
        event={},
        payload="p",
        raw=raw,
        raw_capture_bytes=256 * 1024,
    )
    assert len(wide["raw_hex"]) == len(raw) * 2  # full body retained


def test_sharepoint_budget_covers_stage_two():
    # The ToolShell stage-two (~535 KB) must fit under SharePoint's per-honeypot budget.
    assert sp._RAW_CAPTURE >= 600 * 1024 > real_sink.MAX_RAW_CAPTURE


def test_sharepoint_big_budget_is_gated_to_critical_stage_two():
    # resource-cap-defeat guard: the big budget is reserved for the CRITICAL confirmed stage-two
    # (forged-honeytoken __VIEWSTATE). A lower-severity tag or an untagged flood keeps the 64 KiB
    # default, so an attacker cannot force 768 KiB captures by stuffing a big body with a cheap
    # marker — they'd first need the honeytoken key to produce a CRITICAL.
    assert sp._capture_budget({"severity": "CRITICAL"}) == sp._RAW_CAPTURE
    assert (
        sp._capture_budget({"severity": "HIGH", "matches": [{"behaviour": "x"}]})
        == sp._RAW_CAPTURE_DEFAULT
    )
    assert sp._capture_budget({"matches": []}) == sp._RAW_CAPTURE_DEFAULT
    assert sp._capture_budget({}) == sp._RAW_CAPTURE_DEFAULT
    assert sp._RAW_CAPTURE_DEFAULT <= 64 * 1024 < sp._RAW_CAPTURE


# --- E7: pre-parser rejection capture --------------------------------------------------


def test_make_capturing_factory_falls_back_without_internals():
    sentinel = object()  # no _loop / _kwargs
    assert pre_parser_capture.make_capturing_factory(sentinel, lambda info: None) is sentinel


def test_record_pre_parser_reject_emits_event():
    hp = ns.NetScalerHoneypot()
    cap = _CaptureSink()
    hp._sink = cap
    hp.record_pre_parser_reject(
        {
            "peer": ("203.0.113.9", 55000),
            "status": 400,
            "reason": "Bad status line",
            "raw": b"\x16\x03\x01garbage",
            "dst_port": 50443,
            "scheme": "https",
        }
    )
    assert cap.records, "a pre-parser reject must be emitted"
    rec = cap.records[-1]
    assert rec["event"]["event_type"] == "PRE_PARSER_REJECT"
    assert rec["event"]["reject_status"] == 400
    assert rec["peer_ip"] == "203.0.113.9"
    assert rec["raw_hex"] == b"\x16\x03\x01garbage".hex()  # the offending bytes are kept


def test_pre_parser_reject_recorded_end_to_end():
    """Full path: a malformed request aiohttp rejects before routing is still captured."""
    cap = _CaptureSink()

    async def _main():
        hp = ns.NetScalerHoneypot()
        hp._sink = cap
        app = web.Application()
        hp.setup_routes(app)
        runner = web.AppRunner(app)
        await runner.setup()
        factory = pre_parser_capture.make_capturing_factory(
            runner.server, hp.record_pre_parser_reject
        )
        assert factory is not runner.server, "capturing factory should wrap the server"
        loop = asyncio.get_running_loop()
        server = await loop.create_server(factory, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x16\x03\x01\x00\xff not a valid request line\r\n\r\n")
            await writer.drain()
            await reader.read(200)  # drain the 400 so the server finishes the exchange
            writer.close()
            await asyncio.sleep(0.05)
        finally:
            server.close()
            await server.wait_closed()
            await runner.cleanup()

    asyncio.run(_main())
    assert any(r["event"].get("event_type") == "PRE_PARSER_REJECT" for r in cap.records), (
        "the pre-parser rejection was not recorded"
    )
