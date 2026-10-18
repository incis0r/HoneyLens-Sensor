import asyncio

from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.ics.fox import FoxHoneypot, build_fox_hello
from tests.ics_fakes import FakeReader, FakeWriter


def test_fox_hello_has_identity():
    hello = build_fox_hello(get_profile("fox"), "203.0.113.9")
    assert b"fox hello" in hello
    assert b"app.version=s:4.10.3.36" in hello
    assert b"brandId=s:vykon" in hello
    assert b"hostId=s:Qnx-NPM6E-0000-1A2B-3C4D" in hello
    assert hello.rstrip().endswith(b";;")


def test_fox_connect_sends_hello_and_classifies(monkeypatch):
    events = []
    monkeypatch.setattr(
        "honeylens.honeypots.ics.fox.log_event", lambda *a, **k: events.append((a, k))
    )
    hp = FoxHoneypot()
    r, w = FakeReader(b""), FakeWriter()
    asyncio.run(hp.handle_connection(r, w, w.get_extra_info("peername")))
    assert b"fox hello" in bytes(w.sent)
    assert events and events[0][1].get("attack_type") == "ics_enumeration"
