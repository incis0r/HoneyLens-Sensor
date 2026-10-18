"""The ICS decoys owe the pipeline the frame they actually received.

The defect class: a decoy stores the bytes in a shape its own decoder never sees. The MQTT
decoy read the fixed header and remaining length first and stored only what followed, so a
decoder pointed at ``payload_hex`` met a CONNECT that began at the protocol-name length, and
a credential mask written against full packets was a no-op on every real row while 45 tests
stayed green. So the bar here is not "a ``*_hex`` key exists". It is: the hex a decoy stores,
fed through ``decode_hex`` exactly as ingest feeds it, places fields and reaches a code.

Each driver below pushes real wire bytes through the real decoy class (only ``log_event`` is
replaced) and returns the metadata dicts the decoy emitted.
"""

import asyncio
import struct

import pytest

from honeylens.honeypots.honeypots_config import get_profile
from honeylens.ics import decode_hex, mask_hex
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_bacnet import READ_PROPERTY as BACNET_READ
from tests.test_ics_decode_bacnet import WHO_IS as BACNET_WHO_IS
from tests.test_ics_decode_bacnet import WRITE_PROPERTY as BACNET_WRITE
from tests.test_ics_decode_dnp3 import app as dnp3_app
from tests.test_ics_decode_dnp3 import frame as dnp3_frame
from tests.test_ics_decode_enip import GET_ATTR, READ_TAG, WRITE_TAG, encap, rr_data
from tests.test_ics_decode_fins import CONTROLLER_DATA as FINS_CONTROLLER
from tests.test_ics_decode_fins import MEMORY_READ as FINS_MEMORY_READ
from tests.test_ics_decode_iec104 import SC as IEC104_SC
from tests.test_ics_decode_mms import IDENTIFY as MMS_IDENTIFY
from tests.test_ics_decode_mms import INITIATE as MMS_INITIATE
from tests.test_ics_decode_mms import READ as MMS_READ
from tests.test_ics_decode_mms import SESSION_CONNECT, presentation
from tests.test_ics_decode_mms import WRITE as MMS_WRITE
from tests.test_ics_decode_mms import dt as mms_dt
from tests.test_ics_decode_mqtt import _s, connect, packet
from tests.test_ics_decode_profinet import rpc
from tests.test_ics_decode_s7comm import (
    CR_BODY,
    READ_VAR,
    SETUP,
    SZL,
    WRITE_VAR,
    dt,
    s7_job,
    tpkt,
)

PEER = ("203.0.113.9", 40000)
USER, PASS = b"admin-user", b"s3cr3t-pass"

# Where ingest reads the frame (ingest.honeypot._ICS_HEX_KEYS, first non-empty wins) and the
# key each decoy keeps its own reading of the code under.
_HEX_KEYS = (
    "pdu_hex",
    "asdu_hex",
    "apdu_hex",
    "frame_hex",
    "data_hex",
    "body_hex",
    "app_objects_hex",
    "payload_hex",
)
# SZL userdata; session CONNECT and Initiate; iec104 U-frame and S-frame (no type id)
_CODELESS = {"cotp102_s7": 1, "cotp102_mms": 2, "iec104": 2}
_OWN_CODE = {
    "mqtt": "pkt_type",
    "dnp3": "fc",
    "enip": "command",
    "s7comm": "func_code",
    "modbus": "fc",
    "iec104": "type_id",
    "bacnet": "service",
    "opcua": "service_id",
    "fins": "mrc",
}


def _ingest_hex(md: dict) -> str | None:
    """The same choice ``_ics_frame_hex`` makes, restated so a change there shows up here."""
    for key in _HEX_KEYS:
        value = md.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _stream(monkeypatch, module: str, hp, data: bytes) -> list[dict]:
    events: list[dict] = []
    monkeypatch.setattr(f"{module}.log_event", lambda *a, **k: events.append(a[2]))
    reader, writer = FakeReader(data), FakeWriter(PEER)
    asyncio.run(hp.handle_connection(reader, writer, PEER))
    return events


def _mqtt(mp):
    from honeylens.honeypots.hp_mqtt import MQTTHoneypot

    stream = (
        connect(username=USER, password=PASS)
        + packet(0x82, b"\x00\x01" + _s(b"#") + b"\x00")
        + packet(0x30, _s(b"cmd/valve") + b"open")
        + b"\xc0\x00"
    )
    return "mqtt", _stream(mp, "honeylens.honeypots.hp_mqtt", MQTTHoneypot(), stream), 3


def _dnp3(mp):
    from honeylens.honeypots.hp_dnp3 import DNP3Honeypot

    frames = [
        dnp3_frame(dnp3_app(1, bytes([1, 2, 6]))),
        dnp3_frame(dnp3_app(23)),
        dnp3_frame(dnp3_app(13)),
        dnp3_frame(dnp3_app(5, bytes(range(30)))),  # a second 16-byte block with its own CRC
    ]
    stream = b"".join(frames)
    return "dnp3", _stream(mp, "honeylens.honeypots.hp_dnp3", DNP3Honeypot(), stream), len(frames)


def _enip(mp):
    from honeylens.honeypots.hp_enip import ENIPHoneypot

    frames = [
        encap(0x01),
        encap(0x04),
        encap(0x63),
        encap(0x64),
        encap(0x65, struct.pack("<HH", 1, 0)),
        encap(0x66, session=1),
        encap(0x6F, rr_data(GET_ATTR), session=7),
        encap(0x6F, rr_data(READ_TAG), session=7),
        encap(0x6F, rr_data(WRITE_TAG), session=7),
        encap(0x70, b"\x00" * 8, session=7),
        encap(0x77, b"\xaa\xbb"),
    ]
    stream = b"".join(frames)
    return "enip", _stream(mp, "honeylens.honeypots.hp_enip", ENIPHoneypot(), stream), len(frames)


def _cotp102_s7(mp):
    from honeylens.honeypots.ics.cotp102 import Cotp102Honeypot

    dts = [SETUP, READ_VAR, WRITE_VAR, SZL]
    stream = tpkt(CR_BODY) + b"".join(dt(x) for x in dts)
    return "s7comm", _stream(mp, "honeylens.honeypots.ics.cotp102", Cotp102Honeypot(), stream), 4


def _cotp102_mms(mp):
    from honeylens.honeypots.ics.cotp102 import Cotp102Honeypot

    pdus = [SESSION_CONNECT] + [presentation(x) for x in (MMS_INITIATE, MMS_IDENTIFY, MMS_READ)]
    pdus.append(presentation(MMS_WRITE))
    stream = tpkt(CR_BODY) + b"".join(mms_dt(x) for x in pdus)
    return "mms", _stream(mp, "honeylens.honeypots.ics.cotp102", Cotp102Honeypot(), stream), 5


def _standalone_s7(mp):
    from honeylens.honeypots.hp_s7comm import S7commHoneypot

    stream = tpkt(CR_BODY) + dt(SETUP) + dt(s7_job(bytes([0x44, 0x01]))) + dt(WRITE_VAR)
    return "s7comm", _stream(mp, "honeylens.honeypots.hp_s7comm", S7commHoneypot(), stream), 2


def _profinet(mp):
    from honeylens.honeypots.ics.profinet import ProfinetDatagramProtocol
    from tests.ics_fakes import FakeDatagramTransport

    events: list[dict] = []
    mp.setattr("honeylens.honeypots.ics.profinet.log_event", lambda *a, **k: events.append(a[2]))
    proto = ProfinetDatagramProtocol(profile=get_profile("profinet"))
    proto.connection_made(FakeDatagramTransport())
    datagrams = [rpc(5), rpc(6), rpc(4)]
    for d in datagrams:
        proto.datagram_received(d, PEER)
    return "profinet", events, len(datagrams)


def _modbus(mp):
    from honeylens.honeypots.hp_modbus import ModbusHoneypot

    pdus = [
        bytes.fromhex("030000000a"),
        bytes.fromhex("0600010002"),
        bytes.fromhex("10000100020400010002"),
        bytes.fromhex("5a0020001400000000000002"),
    ]
    stream = b"".join(struct.pack(">HHHB", i, 0, len(p) + 1, 1) + p for i, p in enumerate(pdus))
    return "modbus", _stream(mp, "honeylens.honeypots.hp_modbus", ModbusHoneypot(), stream), 4


def _iec104(mp):
    from honeylens.honeypots.hp_iec104 import IEC104Honeypot

    def apci(body: bytes) -> bytes:
        return bytes([0x68, len(body)]) + body

    frames = [
        apci(bytes.fromhex("07000000")),  # U: STARTDT act
        apci(bytes.fromhex("01000400")),  # S: ack
        bytes.fromhex(IEC104_SC),  # I: C_SC_NA_1
        apci(bytes.fromhex("00000000" + "64010600ffff00000014")),  # I: interrogation
    ]
    stream = b"".join(frames)
    return "iec104", _stream(mp, "honeylens.honeypots.hp_iec104", IEC104Honeypot(), stream), 4


def _fins(mp):
    from honeylens.honeypots.hp_fins import FinsHoneypot

    def tcp(payload: bytes) -> bytes:
        return b"FINS" + struct.pack(">III", len(payload) + 8, 2, 0) + payload

    frames = [bytes.fromhex(FINS_CONTROLLER), bytes.fromhex(FINS_MEMORY_READ)]
    stream = b"".join(tcp(f) for f in frames)
    return "fins", _stream(mp, "honeylens.honeypots.hp_fins", FinsHoneypot(), stream), 2


def _opcua(mp):
    from honeylens.honeypots.hp_opcua import OpcuaHoneypot

    chan = bytes.fromhex("01000000010000000200000003000000")
    # FourByte NodeId ns=0: GetEndpoints 428, Read 631, Write 673
    bodies = [chan + b"\x01\x00" + struct.pack("<H", i) + b"\x00" * 8 for i in (428, 631, 673)]
    stream = b"".join(b"MSGF" + struct.pack("<I", len(b) + 8) + b for b in bodies)
    return "opcua", _stream(mp, "honeylens.honeypots.hp_opcua", OpcuaHoneypot(), stream), 3


def _bacnet(mp):
    from honeylens.honeypots.hp_bacnet import BACnetHoneypot, BACnetProtocol
    from tests.ics_fakes import FakeDatagramTransport

    events: list[dict] = []
    mp.setattr("honeylens.honeypots.hp_bacnet.log_event", lambda *a, **k: events.append(a[2]))
    proto = BACnetProtocol(BACnetHoneypot())
    proto.connection_made(FakeDatagramTransport())
    apdus = [BACNET_READ, BACNET_WRITE, BACNET_WHO_IS]
    for apdu in apdus:
        body = b"\x01\x00" + bytes.fromhex(apdu)
        proto.datagram_received(struct.pack(">BBH", 0x81, 0x0A, len(body) + 4) + body, PEER)
    return "bacnet", events, len(apdus)


DRIVERS = [
    _mqtt,
    _dnp3,
    _enip,
    _cotp102_s7,
    _cotp102_mms,
    _standalone_s7,
    _profinet,
    _modbus,
    _iec104,
    _fins,
    _opcua,
    _bacnet,
]
_IDS = [d.__name__.lstrip("_") for d in DRIVERS]


@pytest.fixture(params=DRIVERS, ids=_IDS)
def run(request, monkeypatch):
    protocol, events, frames_sent = request.param(monkeypatch)
    return request.param.__name__.lstrip("_"), protocol, events, frames_sent


def test_the_drivers_cover_every_ics_decoy_the_brief_names(monkeypatch):
    """A driver list narrower than ``_ICS_HONEYPOTS`` has concealed a real defect twice on this
    plan: first six protocols sat outside the loop, then iec104's ``ctrl_hex`` stayed invisible
    to ingest. A loop that cannot say it is incomplete is the defect, so a new ICS decoy with
    no driver fails here. fox, melsec and coap are exempt: they store no frame by design."""
    from honeylens.ingest.honeypot import _ICS_HONEYPOTS

    driven = {driver(monkeypatch)[0] for driver in DRIVERS}
    assert driven == _ICS_HONEYPOTS - {"fox", "melsec", "coap"}


def test_every_ics_decoy_sends_a_hex_key(run):
    """Defect: s7comm reported ``bytes`` and ``phase`` and nothing else, so the row had no frame."""
    _name, _protocol, events, _n = run
    assert events
    assert any(k.endswith("_hex") for md in events for k in md)


def test_the_stored_hex_decodes_through_the_decoder_ingest_uses(run):
    """Defect class: ``hex exists`` is not ``hex decodes``. Every frame the decoy was sent must
    come back from ``decode_hex`` with fields placed and, where a code exists, a code."""
    name, protocol, events, frames_sent = run
    decoded = [decode_hex(protocol, h) for md in events if (h := _ingest_hex(md))]
    assert len(decoded) >= frames_sent, f"{name}: {len(decoded)} frames decoded of {frames_sent}"
    for f in decoded:
        assert f.fields, (name, f.tail_reason)
    # A session setup or a userdata PDU is a frame the decoder places without a code.
    codeless = sum(f.code is None for f in decoded)
    assert codeless == _CODELESS.get(name, 0), (name, codeless)


def test_where_a_decoy_and_the_decoder_both_read_a_field_they_agree(run):
    """The cheapest detector for the defect class above. ``ics_events.function_code`` comes from
    the decoy's own metadata and never from ``Frame.code``, so these are two independent
    readings of one event. A disagreement means the decoy stored bytes in a shape the decoder
    does not read the way the decoy did.

    The comparison is not allowed to pass by comparing nothing: the number of events where both
    sides spoke is counted and must be positive for every decoy that has an own code."""
    _name, protocol, events, _n = run
    key = _OWN_CODE.get(protocol)
    compared = 0
    for md in events:
        own, h = md.get(key) if key else None, _ingest_hex(md)
        if own is None or h is None:
            continue
        f = decode_hex(protocol, h)
        if f.code is not None:
            assert f.code == own, (protocol, md.get("phase"), f.code, own)
            compared += 1
    if key:
        assert compared, f"{protocol}: no event had both a decoy code and a decoded code"


# ---- decoy-specific: the shapes the brief called out ------------------------------------


def test_mqtt_frame_hex_is_the_whole_packet_and_payload_hex_is_unchanged(monkeypatch):
    """Defect: the stored CONNECT began at the protocol-name length, not at the packet type.
    ``frame_hex`` is the full packet; ``payload_hex`` keeps its old value (the body) so nothing
    reading it moves, and ``pkt_type`` keeps meaning the wire type nibble."""
    _p, events, _n = _mqtt(monkeypatch)
    first = events[0]
    pkt = connect(username=USER, password=PASS)
    body = pkt[2:]
    assert first["frame_hex"] == pkt.hex()
    assert first["payload_hex"] == body.hex()
    assert first["pkt_type"] == 1
    f = decode_hex("mqtt", first["frame_hex"])
    assert f.code == 1 and f.semantics == "enumerate"
    assert next(x for x in f.fields if x.name == "remaining_length").value == len(body)


def test_mqtt_credentials_in_the_new_key_are_covered_by_the_mask(monkeypatch):
    """The full-packet shape carries the username and password too; ``mask_hex`` must cover it."""
    _p, events, _n = _mqtt(monkeypatch)
    for key in ("frame_hex", "payload_hex"):
        masked = bytes.fromhex(mask_hex("mqtt", events[0][key]))
        assert USER not in masked and PASS not in masked, key
        assert len(masked) * 2 == len(events[0][key])


def test_mqtt_later_packets_carry_their_own_frame_and_type(monkeypatch):
    """Defect: SUBSCRIBE and PUBLISH rows had no bytes and no packet type, so they decoded to
    nothing and their ``function_code`` was NULL."""
    _p, events, _n = _mqtt(monkeypatch)
    by_phase = {md["phase"]: md for md in events if "frame_hex" in md}
    assert by_phase["subscribe"]["pkt_type"] == 8
    assert by_phase["publish"]["pkt_type"] == 3
    assert decode_hex("mqtt", by_phase["subscribe"]["frame_hex"]).code == 8


def test_dnp3_frame_hex_is_the_wire_frame_and_places_the_function_code(monkeypatch):
    """Defect: ``app_objects_hex`` began after the function code, so nothing could be decoded
    from it. ``frame_hex`` is the data-link frame as received, block CRCs included."""
    _p, events, _n = _dnp3(monkeypatch)
    wanted = dnp3_frame(dnp3_app(1, bytes([1, 2, 6]))).hex()
    assert events[0]["frame_hex"] == wanted
    f = decode_hex("dnp3", events[0]["frame_hex"])
    assert f.code == 1 and any(x.name == "function_code" for x in f.fields)
    assert events[0]["app_objects_hex"] == "010206"


def test_enip_every_shape_carries_the_encapsulation_frame_and_command(monkeypatch):
    """Defect: ``data_hex`` appeared on 7 of 23 shapes and was only the command data, never the
    header; ``command`` appeared on one. Every logged shape now sends both."""
    _p, events, n = _enip(monkeypatch)
    assert len(events) == n
    sent = [
        encap(0x01).hex(),
        encap(0x04).hex(),
        encap(0x63).hex(),
        encap(0x64).hex(),
        encap(0x65, struct.pack("<HH", 1, 0)).hex(),
        encap(0x66, session=1).hex(),
        encap(0x6F, rr_data(GET_ATTR), session=7).hex(),
        encap(0x6F, rr_data(READ_TAG), session=7).hex(),
        encap(0x6F, rr_data(WRITE_TAG), session=7).hex(),
        encap(0x70, b"\x00" * 8, session=7).hex(),
        encap(0x77, b"\xaa\xbb").hex(),
    ]
    assert [md["frame_hex"] for md in events] == sent
    assert all(isinstance(md["command"], int) for md in events)


def test_s7comm_sends_an_integer_function_code_when_a_job_arrives(monkeypatch):
    """Defect: the function code was logged as ``"0x05"``, a string, on one branch only. A job
    now sends an int; userdata (ROSCTR 7) is not a job, so it sends none rather than a
    made-up 0; a session with no S7 PDU sends none."""
    _p, events, _n = _cotp102_s7(monkeypatch)
    codes = [md.get("func_code") for md in events]
    assert codes == [0xF0, 0x04, 0x05, None]
    assert all(type(c) is int for c in codes[:3])
    assert "function" not in events[2]  # no string spelling beside it on the production path


def test_the_standalone_s7_decoy_sends_integer_codes_too(monkeypatch):
    _p, events, _n = _standalone_s7(monkeypatch)
    by_phase = {md["phase"]: md for md in events}
    assert (
        by_phase["szl_read"]["func_code"] == 0x44 and type(by_phase["szl_read"]["func_code"]) is int
    )
    assert by_phase["unknown_s7_func"]["func_code"] == 0x05
    assert by_phase["unknown_s7_func"]["function"] == "0x05"  # the old string key is kept
    assert decode_hex("s7comm", by_phase["unknown_s7_func"]["frame_hex"]).code == 0x05


def test_cotp102_mms_frames_decode_to_service_numbers(monkeypatch):
    """Defect: the dispatcher logged ``bytes`` only, for MMS as for S7."""
    _p, events, _n = _cotp102_mms(monkeypatch)
    codes = [decode_hex("mms", md["frame_hex"]).code for md in events]
    assert codes == [None, None, 2, 4, 5]


def test_profinet_frame_hex_gives_the_opnum_the_decoy_cannot_read(monkeypatch):
    """The decoy guesses from byte 2; the decoder reads byte 68. The stored hex is what lets
    the second reading exist at all."""
    _p, events, _n = _profinet(monkeypatch)
    assert events[0]["frame_hex"] == rpc(5).hex()
    assert [decode_hex("profinet", md["frame_hex"]).code for md in events] == [5, 6, 4]


def test_a_decoder_is_never_handed_non_hex_and_says_so():
    """The 'not valid hex' path is the decoder's, not the decoys': the decoys write hex() so it
    cannot arise from them. Pinned here so the removed per-frame assertion has a real home."""
    assert "not valid hex" in decode_hex("mqtt", "zz").tail_reason


def test_iec104_u_and_s_frames_are_stored_under_a_key_ingest_reads(monkeypatch):
    """Defect: U- and S-frames kept their bytes only under ``ctrl_hex``, which ingest does not
    read, so those rows decoded to nothing while an 'a hex key exists' test stayed green."""
    _p, events, _n = _iec104(monkeypatch)
    by_phase = {md["phase"]: md for md in events}
    for phase in ("iec104_uframe", "iec104_sframe"):
        md = by_phase[phase]
        assert _ingest_hex(md) == md["frame_hex"]
        assert md["ctrl_hex"]  # kept
        assert decode_hex("iec104", md["frame_hex"]).fields
