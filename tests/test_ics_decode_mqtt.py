"""MQTT decoder: fixed header, CONNECT (credentials withheld), PUBLISH topic, packet-type table."""

import pytest

from honeylens.ics import decode
from honeylens.ics import mqtt as mqtt_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)


def _s(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def packet(first: int, body: bytes) -> bytes:
    return bytes([first]) + _varint(len(body)) + body


def connect(
    client: bytes = b"cli",
    username: bytes | None = None,
    password: bytes | None = None,
    level: int = 4,
    name: bytes = b"MQTT",
    will: tuple[bytes, bytes] | None = None,
) -> bytes:
    flags = 0x02 | (0x80 if username is not None else 0) | (0x40 if password is not None else 0)
    flags |= 0x04 if will else 0
    body = _s(name) + bytes([level, flags]) + b"\x00\x3c"
    if level == 5:
        body += b"\x00"  # no properties
    body += _s(client)
    if will:
        body += (b"\x00" if level == 5 else b"") + _s(will[0]) + _s(will[1])
    if username is not None:
        body += _s(username)
    if password is not None:
        body += _s(password)
    return packet(0x10, body)


def test_connect_is_session_setup_and_fully_placed():
    """The observed pkt_type 1; the client id is shown, the session is an 'enumerate'."""
    raw = connect()
    f = decode("mqtt", raw)
    assert f.code == 1 and f.semantics == "enumerate" and f.tail_offset is None
    by = {x.name: x for x in f.fields}
    assert by["packet_type"].meaning == "CONNECT" and by["protocol_name"].value == "MQTT"
    assert by["protocol_level"].value == 4 and by["keep_alive"].value == 60
    assert by["client_id"].value == "cli" and by["remaining_length"].value == len(raw) - 2
    assert f.sentence == "Opens an MQTT session as client 'cli'"


def test_username_and_password_values_never_appear_but_their_byte_ranges_do():
    """Credentials must not reach a screen: values are withheld, offsets stay for masking."""
    raw = connect(username=b"admin", password=b"s3cr3t-pass")
    f = decode("mqtt", raw)
    by = {x.name: x for x in f.fields}
    assert by["username"].value == "<redacted>" and by["password"].value == "<redacted>"
    dump = repr(f)
    assert "admin" not in dump and "s3cr3t" not in dump and b"s3cr3t".hex() not in dump
    pw = by["password"]
    assert raw[pw.offset + 2 : pw.offset + pw.length] == b"s3cr3t-pass"
    assert pw.offset + pw.length == len(raw) and f.tail_offset is None
    assert "username and password" in f.sentence


def test_credentials_are_withheld_for_every_version_and_with_a_will():
    """Defect class: a layout that skipped the will left username/password in the tail, unmasked."""
    for level in (3, 4, 5):
        name = b"MQIsdp" if level == 3 else b"MQTT"
        raw = connect(level=level, name=name, username=b"u-secret", password=b"p-secret",
                      will=(b"w/topic", b"bye"))  # fmt: skip
        f = decode("mqtt", raw)
        names = [x.name for x in f.fields]
        assert "username" in names and "password" in names and "will_topic" in names, level
        assert f.tail_offset is None
        assert "secret" not in repr(f)


def test_a_connect_cut_inside_the_credentials_never_leaks_them_into_a_field():
    raw = connect(username=b"admin", password=b"hunter2hunter2")
    cut = decode("mqtt", raw[:-5])
    assert "hunter2" not in repr(cut) and cut.tail_offset is not None
    assert "inside the password" in cut.tail_reason
    assert not any(x.name == "password" for x in cut.fields)


def test_a_connect_with_an_unknown_protocol_name_is_not_given_the_layout():
    """Never apply a sub-layout that was not confirmed. The unrecognised name is not echoed
    (a mis-framed length can swallow credentials), only its size."""
    f = decode("mqtt", connect(name=b"XMPP", username=b"u", password=b"p"))
    assert not any(x.name in ("client_id", "username") for x in f.fields)
    assert "XMPP" not in f.tail_reason and "4 byte" in f.tail_reason and f.tail_offset == 8


def test_a_connect_with_an_unknown_protocol_level_names_the_level():
    f = decode("mqtt", connect(level=9))
    assert f.tail_offset is not None and "level 9" in f.tail_reason
    assert not any(x.name == "client_id" for x in f.fields)


def test_publish_is_a_write_and_places_topic_but_not_the_payload():
    """The payload of a PUBLISH starts after MQTT 5 properties on a version-5 connection, and a
    PUBLISH does not carry the version, so it is reported as unplaced rather than guessed."""
    body = _s(b"plant/valve1/set") + b"open"
    raw = packet(0x30, body)
    f = decode("mqtt", raw)
    assert f.code == 3 and f.semantics == "write"
    by = {x.name: x for x in f.fields}
    assert by["topic"].value == "plant/valve1/set"
    assert f.tail_offset == len(raw) - 4 and "version" in f.tail_reason
    assert f.sentence == "Publishes to topic 'plant/valve1/set'"


def test_publish_qos_one_places_the_packet_identifier_and_qos_three_is_an_anomaly():
    raw = packet(0x32, _s(b"t") + b"\x00\x07" + b"x")
    f = decode("mqtt", raw)
    by = {x.name: x for x in f.fields}
    assert by["packet_identifier"].value == 7 and "QoS 1" in by["packet_type"].meaning
    bad = decode("mqtt", packet(0x36, _s(b"t") + b"\x00\x07"))
    assert bad.semantics == "anomaly" and bad.code == 3 and "QoS 3" in bad.tail_reason


def test_subscribe_is_a_read_and_its_filters_stay_in_the_tail():
    """The filter layout depends on the MQTT version, which SUBSCRIBE does not carry."""
    raw = packet(0x82, b"\x00\x0a" + _s(b"#") + b"\x00")
    f = decode("mqtt", raw)
    assert f.code == 8 and f.semantics == "read"
    assert next(x for x in f.fields if x.name == "packet_identifier").value == 10
    assert f.tail_offset == 4 and "version" in f.tail_reason


def test_pingreq_and_disconnect_are_fully_placed_without_semantics():
    for first in (0xC0, 0xE0):
        f = decode("mqtt", bytes([first, 0]))
        assert f.semantics is None and f.tail_offset is None and f.sentence


def test_type_zero_is_an_anomaly_and_server_to_client_types_are_anomalies_as_requests():
    """Type 0 is reserved; CONNACK/SUBACK/UNSUBACK/PINGRESP are sent only by a server."""
    zero = decode("mqtt", bytes([0x00, 0]))
    assert zero.semantics == "anomaly" and "reserved" in zero.sentence
    for first in (0x20, 0x90, 0xB0, 0xD0):
        f = decode("mqtt", bytes([first, 0]))
        assert f.semantics == "anomaly", hex(first)
        assert "server" in f.sentence


def test_type_fifteen_is_not_called_out_of_specification():
    """Defect class: 'not in the specification' for a type MQTT 5 defines (AUTH)."""
    f = decode("mqtt", bytes([0xF0, 0]))
    assert f.code == 15 and f.semantics is None
    assert "AUTH" in f.sentence


def test_a_frame_cut_before_and_inside_a_field():
    """Defect class: 'inside' written where no byte of the field was present."""
    raw = connect(username=b"admin")
    inside_len = decode("mqtt", raw[:3])  # fixed header, remaining length, one byte of the name
    assert "inside the protocol_name" in inside_len.tail_reason
    before = decode("mqtt", raw[:1])
    assert before.tail_offset == 1 and "before the remaining_length" in before.tail_reason
    assert before.code == 1 and before.sentence == "CONNECT (frame cut short)"
    assert decode("mqtt", raw[:2]).sentence == "CONNECT (frame cut short)"


def test_a_remaining_length_that_never_ends_is_reported_not_followed():
    f = decode("mqtt", bytes([0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]))
    assert f.code == 3 and f.semantics == "anomaly"
    assert "remaining length" in f.tail_reason and f.tail_offset == 5
    assert next(x for x in f.fields if x.name == "remaining_length").length == 4


def test_bytes_after_the_packet_are_in_the_tail():
    raw = bytes([0xC0, 0]) + bytes([0xC0, 0])
    f = decode("mqtt", raw)
    assert f.tail_offset == 2 and "after the remaining length" in f.tail_reason


_TYPES = {
    1: "enumerate", 3: "write", 8: "read", 0: "anomaly", 2: "anomaly", 9: "anomaly",
    11: "anomaly", 13: "anomaly", 4: None, 5: None, 6: None, 7: None, 10: None, 12: None,
    14: None, 15: None,
}  # fmt: skip


@pytest.mark.parametrize("ptype", sorted(_TYPES))
def test_packet_type_table_on_full_length_frames(ptype):
    """MITRE keys off this mapping; all sixteen nibble values are pinned."""
    body = {1: connect()[2:], 3: _s(b"t"), 8: b"\x00\x01"}.get(ptype, b"")
    first = (ptype << 4) | (0x02 if ptype in (6, 8, 10) else 0)
    raw = packet(first, body)
    f = mqtt_module.decode(raw)
    assert f.code == ptype and f.semantics == _TYPES[ptype]
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    """Defect: the flags byte was read before checking it existed, so a CONNECT cut right
    after the protocol level raised IndexError."""
    for raw in (
        connect(username=b"a", password=b"b", will=(b"t", b"m")),
        connect(level=5, username=b"a", password=b"b", will=(b"t", b"m")),
        packet(0x32, _s(b"topic") + b"\x00\x01" + b"zz"),
        packet(0x82, b"\x00\x01" + _s(b"x") + b"\x00"),
    ):
        assert_every_prefix_is_sane(mqtt_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [
        decode("mqtt", x)
        for x in (
            connect(),
            connect(username=b"u", password=b"p"),
            connect(level=5),
            packet(0x30, _s(b"t")),
            packet(0x30, _s(b"a-much-longer-topic-name")),
            packet(0x82, b"\x00\x01"),
        )
    ]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("mqtt", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: mqtt.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        mqtt_module.decode,
        1883,
        (b"", b"\x10", b"\x10\x20", connect()[:12], b"\x30\x10", b"\x82\x08\x00\x01"),
    )


def test_an_out_of_spec_type_is_an_anomaly_even_when_the_remaining_length_is_cut():
    """Defect: the anomaly was decided after the remaining length, so a one-byte probe of
    an undefined QoS was reported as a 'write'."""
    for first, code in ((0x00, 0), (0x20, 2), (0x90, 9), (0x36, 3)):
        f = decode("mqtt", bytes([first]))
        assert f.code == code and f.semantics == "anomaly", hex(first)
        g = decode("mqtt", bytes([first, 0]))
        assert g.semantics == "anomaly", hex(first)


def test_a_remaining_length_that_never_ends_is_an_anomaly():
    f = decode("mqtt", bytes([0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]))
    assert f.code == 1 and f.semantics == "anomaly" and "forbids" in f.tail_reason


def test_sentences_clip_attacker_text_to_a_fixed_budget():
    """Defect: a 20 KB topic produced a 20 KB 'one plain-language line'."""
    f = decode("mqtt", packet(0x30, _s(b"t" * 20000)))
    assert f.semantics == "write" and len(f.sentence) < 200 and f.sentence.endswith("...'")
    big_client = decode("mqtt", connect(client=b"c" * 20000))
    assert len(big_client.sentence) < 200 and big_client.tail_offset is None
    assert next(x for x in big_client.fields if x.name == "client_id").length == 20002
