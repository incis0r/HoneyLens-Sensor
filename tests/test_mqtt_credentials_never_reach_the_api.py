"""MQTT CONNECT credentials: the hex a consumer serves must not carry them.

The defect: the decoder withheld username/password from the Field values, but the stored
``payload_hex`` is the whole CONNECT packet, so the credentials sat in it in the clear and
the key-based ``redact_structure`` could not see them. ``mask_hex`` closes that in the decoder
layer. The end-to-end API test belongs to the endpoint's own task; this pins mask_hex.
"""

import itertools

import pytest

from honeylens.ics import MASKERS, decode, mask_hex
from tests.test_ics_decode_mqtt import _s, connect, packet

USER, PASS = b"admin-user", b"s3cr3t-pass"
WILL = (b"will/topic", b"will-body")


def _hides(out: bytes, *secrets: bytes) -> None:
    """No 3-byte window of any secret survives, so a mask that is two bytes off is caught."""
    for secret in secrets:
        for i in range(len(secret) - 2):
            assert secret[i : i + 3] not in out, (secret, i)


def _masked(raw: bytes) -> bytes:
    out = mask_hex("mqtt", raw.hex())
    assert len(out) == len(raw) * 2
    return bytes.fromhex(out)


@pytest.mark.parametrize("level,name", [(3, b"MQIsdp"), (4, b"MQTT"), (5, b"MQTT")])
@pytest.mark.parametrize("will", [None, WILL])
def test_credential_bytes_appear_nowhere_in_the_masked_hex(level, name, will):
    """Defect: username and password were in payload_hex in the clear."""
    raw = connect(username=USER, password=PASS, level=level, name=name, will=will)
    out = mask_hex("mqtt", raw.hex())
    for secret in (USER, PASS):
        assert secret.hex() not in out
    _hides(bytes.fromhex(out), USER, PASS)


@pytest.mark.parametrize("level,name", [(3, b"MQIsdp"), (4, b"MQTT"), (5, b"MQTT")])
def test_masking_preserves_length_and_every_byte_outside_the_credentials(level, name):
    """Only the username and password bodies change; their 2-byte length prefixes stay. The
    expected ranges come from the packet as built here (the credentials are its last two
    strings), not from the Frame."""
    raw = connect(username=USER, password=PASS, level=level, name=name, will=WILL)
    pw_start = len(raw) - len(_s(PASS))
    user_start = pw_start - len(_s(USER))
    expected = raw[:user_start] + _s(bytes(len(USER))) + _s(bytes(len(PASS)))
    out = _masked(raw)
    assert out == expected
    assert out[:user_start] == raw[:user_start] and WILL[0] in out and WILL[1] in out


def test_a_username_without_a_password_and_a_password_without_a_username():
    for kwargs in ({"username": USER}, {"password": PASS}):
        raw = connect(**kwargs)
        out = mask_hex("mqtt", raw.hex())
        assert USER.hex() not in out and PASS.hex() not in out
        assert len(out) == len(raw) * 2


@pytest.mark.parametrize("name,level", [(b"XXXX", 4), (b"MQTT", 9), (b"MQIsdp", 4), (b"MQTT", 0)])
def test_a_connect_with_an_unrecognised_protocol_leaves_no_credentials_in_the_tail(name, level):
    """Defect: an unknown protocol name/level stops the decoder, so the credentials sit in
    the tail and no field range covers them."""
    raw = connect(username=USER, password=PASS, level=level, name=name, will=WILL)
    out = _masked(raw)
    _hides(out, USER, PASS)
    name_ok = name in (b"MQTT", b"MQIsdp")
    keep = (1 + 1) + (2 + len(name) + 1 if name_ok else 0)  # fixed header, then name and level
    assert out[:keep] == raw[:keep]
    assert out[keep:] == bytes(len(raw) - keep)


def test_a_connect_cut_inside_the_credentials_leaks_no_partial_credential():
    raw = connect(username=USER, password=PASS)
    for cut in range(1, len(raw)):
        out = _masked(raw[:cut])
        _hides(out, USER, PASS)


def test_bytes_trailing_a_connect_are_masked_too():
    """Over-masking is the right failure direction: a tail after the payload may hold
    credentials the layout did not account for."""
    raw = connect(username=USER, password=PASS) + b"trailing-" + PASS
    out = _masked(raw)
    _hides(out, USER, PASS)


def test_the_screen_still_learns_that_a_password_was_offered():
    raw = connect(username=b"admin", password=b"x")
    pw = next(x for x in decode("mqtt", raw).fields if x.name == "password")
    assert pw.value == "<redacted>" and pw.length == 3
    out = bytes.fromhex(mask_hex("mqtt", raw.hex()))
    assert out[pw.offset : pw.offset + 2] == raw[pw.offset : pw.offset + 2]  # prefix stays
    assert out[pw.offset + 2 : pw.offset + pw.length] == bytes(pw.length - 2)  # body zeroed


def test_only_positively_confirmed_non_connect_shapes_pass_through_unhinted():
    """Defect: a blanket pass-through of anything that was not a recognised CONNECT leaked
    every real (headerless) row. Pass-through needs a complete packet of another type."""
    pub = packet(0x30, _s(b"a/b") + b"payload")
    assert mask_hex("mqtt", pub.hex()) == pub.hex()
    assert mask_hex("mqtt", packet(0xC0, b"").hex()) == "c000"
    for unconfirmed in (b"\x30\x20ab", pub + b"x", b"\x40" + USER + PASS, b"\x00\x01" + PASS):
        assert set(mask_hex("mqtt", unconfirmed.hex())) == {"0"}
    # protocols without a hook are not touched
    assert mask_hex("modbus", "0001000000060103000a0001") == "0001000000060103000a0001"
    assert mask_hex("no-such-protocol", "abcd") == "abcd"


@pytest.mark.parametrize("bad", [None, "", "abc", "zz", "10 0", "0x10", "\x00", "10" * 3 + "g"])
@pytest.mark.parametrize("protocol", ["mqtt", "modbus", "nope"])
def test_mask_hex_never_raises_and_returns_a_string(protocol, bad):
    assert isinstance(mask_hex(protocol, bad), str)


def test_malformed_mqtt_hex_is_never_echoed_back():
    """An odd-length CONNECT is not decodable, but echoing it would still leak: it is dropped."""
    odd = (connect(username=USER, password=PASS).hex())[:-1]
    assert mask_hex("mqtt", odd) == ""
    assert mask_hex("mqtt", None) == ""


def test_a_hook_that_fails_masks_everything(monkeypatch):
    def boom(raw: bytes) -> bytes:
        raise RuntimeError("x")

    monkeypatch.setitem(MASKERS, "mqtt", boom)
    assert mask_hex("mqtt", "10aabb") == "000000"


def test_every_prefix_of_every_variant_hides_the_credentials():
    for level, will in itertools.product((3, 4, 5), (None, WILL)):
        name = b"MQIsdp" if level == 3 else b"MQTT"
        raw = connect(username=USER, password=PASS, level=level, name=name, will=will)
        for cut in range(len(raw) + 1):
            out = mask_hex("mqtt", raw[:cut].hex())
            assert USER.hex() not in out and PASS.hex() not in out


# ---- the shape the decoy actually stores -------------------------------------------------
# hp_mqtt reads the type byte and remaining length separately and stores only
# payload[:128].hex(): the body, with NO fixed header. The first 45 tests above all used
# full packets, a shape no decoy writes, so the mask was a silent no-op on every real row.

REAL_ROW = "00044d5154540400000a000643454e535953"  # verbatim from sensor-a, client "CENSYS"


def _body(raw: bytes) -> bytes:
    """What the decoy stores for a full packet: everything after the fixed header."""
    i = 1
    while raw[i] & 0x80:
        i += 1
    return raw[i + 1 :]


def test_a_real_stored_row_is_recognised_as_a_connect_and_survives_intact():
    """Defect: a headerless row has no type nibble; it must not be mistaken for anything else."""
    out = mask_hex("mqtt", REAL_ROW)
    assert out == REAL_ROW  # no credentials in it, nothing to zero
    assert out != "00" * len(REAL_ROW)


@pytest.mark.parametrize("level,name", [(3, b"MQIsdp"), (4, b"MQTT"), (5, b"MQTT")])
@pytest.mark.parametrize("will", [None, WILL])
def test_a_headerless_connect_body_carries_no_credentials_out(level, name, will):
    """Defect: the mask was a no-op on the headerless bodies the decoy stores."""
    body = _body(connect(username=USER, password=PASS, level=level, name=name, will=will))
    assert body[0] == 0  # the shape really is headerless
    out = bytes.fromhex(mask_hex("mqtt", body.hex()))
    assert len(out) == len(body)
    _hides(out, USER, PASS)
    assert out != body
    assert out.startswith(body[: 2 + len(name) + 1])  # name, level survive


def test_the_real_row_with_credentials_added_is_masked():
    body = bytes.fromhex(REAL_ROW)[:7] + b"\xc0" + bytes.fromhex(REAL_ROW)[8:]
    body += _s(USER) + _s(PASS)
    out = bytes.fromhex(mask_hex("mqtt", body.hex()))
    assert USER not in out and PASS not in out and len(out) == len(body)


def test_every_prefix_of_a_headerless_body_hides_the_credentials():
    """The decoy truncates at 128 bytes, so any cut can occur."""
    for level, will in itertools.product((3, 4, 5), (None, WILL)):
        name = b"MQIsdp" if level == 3 else b"MQTT"
        body = _body(connect(username=USER, password=PASS, level=level, name=name, will=will))
        for cut in range(len(body) + 1):
            out = bytes.fromhex(mask_hex("mqtt", body[:cut].hex()))
            assert len(out) == cut
            for secret in (USER, PASS):
                for n in range(3, len(secret) + 1):
                    assert secret[:n] not in out, (level, will, cut, n)


def test_a_headerless_connect_with_an_unknown_level_is_masked_from_the_level_on():
    body = _body(connect(username=USER, password=PASS, level=9))
    out = bytes.fromhex(mask_hex("mqtt", body.hex()))
    assert USER not in out and PASS not in out


@pytest.mark.parametrize(
    "raw",
    [
        b"\x00\x04XXXX\x04\xc0\x00\x0a" + _s(USER) + _s(PASS),  # unknown protocol name
        b"\x00\x05MQTT" + USER + PASS,  # a name length that is not ours
        b"\x00" + USER + PASS,
        b"\x30\x00" + USER + PASS,  # looks like a PUBLISH but does not parse as one cleanly
        b"\xff\xff\xff\xff" + USER + PASS,
    ],
)
def test_bytes_that_are_not_confirmed_as_another_packet_are_zeroed(raw):
    """Fail closed: an unrecognised shape is exactly when the content is unknown."""
    out = bytes.fromhex(mask_hex("mqtt", raw.hex()))
    assert out == bytes(len(raw))


def test_a_complete_non_connect_packet_still_passes_through():
    for raw in (packet(0xC0, b""), packet(0xE0, b""), packet(0x30, _s(b"a/b") + b"payload")):
        assert mask_hex("mqtt", raw.hex()) == raw.hex()


# ---- the packet-type hint: buys back pass-through, never a skipped mask ---------------------
# Defect: failing closed zeroed non-credential evidence, e.g. an HTTP request spoken at the
# MQTT port, which the decoy stores under pkt_type 4 (the wire byte decides it).
HTTP_ROW = "54202f20485454502f312e310d0a486f73743a20"  # verbatim sensor-a row prefix, pkt_type 4


def test_an_http_probe_stored_under_another_packet_type_stays_readable():
    assert mask_hex("mqtt", HTTP_ROW, pkt_type=4) == HTTP_ROW
    assert set(mask_hex("mqtt", HTTP_ROW)) == {"0"}  # no hint: fail closed


@pytest.mark.parametrize("hint", [4, 3, 8, 15])
@pytest.mark.parametrize("level,name", [(3, b"MQIsdp"), (4, b"MQTT"), (5, b"MQTT")])
def test_a_forged_packet_type_cannot_unmask_a_connect_shaped_body(hint, level, name):
    """The evasion: a non-CONNECT fixed-header byte with a CONNECT body carrying credentials.
    The body's own shape is checked before the hint is consulted."""
    body = _body(connect(username=USER, password=PASS, level=level, name=name, will=WILL))
    out = bytes.fromhex(mask_hex("mqtt", body.hex(), pkt_type=hint))
    assert USER not in out and PASS not in out and len(out) == len(body)
    full = connect(username=USER, password=PASS, level=level, name=name)
    out = bytes.fromhex(mask_hex("mqtt", full.hex(), pkt_type=hint))
    assert USER not in out and PASS not in out


@pytest.mark.parametrize("hint", [None, 0, 1, 16, -1, True, "4"])
def test_a_hint_that_is_not_a_known_non_connect_type_buys_nothing(hint):
    assert set(mask_hex("mqtt", HTTP_ROW, pkt_type=hint)) == {"0"}


# ---- mis-framed CONNECTs and MQTT 5 authentication data ---------------------------------------


def _misframed() -> bytes:
    """A protocol-name length prefix that swallows the rest of the packet."""
    body = b"\x00\x05" + USER + b"\x00\x0b" + PASS
    inner = bytes([0x00, len(body)]) + body
    return bytes([0x10, len(inner)]) + inner


def test_a_connect_whose_protocol_name_length_swallows_the_credentials_is_masked():
    """Defect: the name consumed the whole packet, the tail started at its end and no
    credential field was placed, so nothing was masked and the Field value held the secret."""
    raw = _misframed()
    out = _masked(raw)
    _hides(out, USER, PASS)
    assert out == raw[:2] + bytes(len(raw) - 2)
    assert out != raw
    frame = decode("mqtt", raw)
    assert "admin" not in repr(frame) and "s3cr3t" not in repr(frame)
    headerless = raw[2:]
    _hides(bytes.fromhex(mask_hex("mqtt", headerless.hex(), pkt_type=1)), USER, PASS)


def test_a_protocol_name_other_than_the_two_real_ones_is_never_stored_in_a_field():
    for name in (b"XXXX", b"AMQPXX", USER + b"\x00\x0b" + PASS):
        frame = decode("mqtt", connect(name=name, username=USER, password=PASS))
        assert not any(isinstance(f.value, str) and "admin" in f.value for f in frame.fields)
        assert name.decode("latin-1") not in repr(frame)
    ok = decode("mqtt", connect())
    assert next(f for f in ok.fields if f.name == "protocol_name").value == "MQTT"


def test_a_client_id_that_swallows_the_credentials_is_withheld_from_field_and_hex():
    """The same class one field later: a client id length covering username and password."""
    swallow = _s(b"cid" + b"\x00\x0a" + USER + b"\x00\x0b" + PASS)
    body = _s(b"MQTT") + bytes([4, 0xC2]) + b"\x00\x3c" + swallow
    raw = packet(0x10, body)
    out = _masked(raw)
    _hides(out, USER, PASS)
    frame = decode("mqtt", raw)
    assert "admin" not in repr(frame) and "s3cr3t" not in repr(frame)
    assert next(f for f in frame.fields if f.name == "client_id").value == "<redacted>"


def _v5(properties: bytes) -> bytes:
    body = _s(b"MQTT") + bytes([5, 0xC2]) + b"\x00\x3c" + _varint_prop(properties)
    body += _s(b"cli") + _s(USER) + _s(PASS)
    return packet(0x10, body)


def _varint_prop(properties: bytes) -> bytes:
    return bytes([len(properties)]) + properties


def test_mqtt5_authentication_data_is_a_password_and_the_method_is_not():
    """Defect: property 0x16 is the password of enhanced authentication, and the whole
    properties blob was one hex Field and sat in the hex untouched."""
    props = b"\x15" + _s(b"PLAIN") + b"\x16" + _s(PASS)
    raw = _v5(props)
    out = _masked(raw)
    _hides(out, PASS, USER)
    assert b"PLAIN" in out  # the mechanism name stays visible
    frame = decode("mqtt", raw)
    blob = next(f for f in frame.fields if f.name == "properties")
    assert PASS.hex() not in blob.value and PASS.hex()[:6] not in str(blob.value)
    assert b"PLAIN".hex() in blob.value
    assert PASS.hex() not in repr(frame)


def test_mqtt5_properties_that_cannot_be_walked_are_zeroed_whole():
    props = b"\x15" + _s(b"PLAIN") + b"\xfe" + PASS  # unknown property id
    out = _masked(_v5(props))
    _hides(out, PASS, USER)
    assert b"PLAIN" not in out


def test_mqtt5_other_properties_are_zeroed_but_keep_their_place():
    props = b"\x26" + _s(b"k") + _s(PASS) + b"\x15" + _s(b"PLAIN") + b"\x11\x00\x00\x00\x09"
    raw = _v5(props)
    out = _masked(raw)
    _hides(out, PASS)
    assert len(out) == len(raw) and b"PLAIN" in out


def test_a_failing_hook_is_logged_not_silent(monkeypatch, caplog):
    def boom(raw: bytes) -> bytes:
        raise RuntimeError("x")

    monkeypatch.setitem(MASKERS, "mqtt", boom)
    with caplog.at_level("WARNING"):
        assert mask_hex("mqtt", "10aabb") == "000000"
    assert any("mqtt" in r.getMessage() for r in caplog.records)


# ---- the properties header is walked by the reader's own rules --------------------------------


def _v5_raw_props(header: bytes, props: bytes) -> bytes:
    body = _s(b"MQTT") + bytes([5, 0xC2]) + b"\x00\x3c" + header + props
    return packet(0x10, body + _s(b"cli") + _s(USER) + _s(PASS))


@pytest.mark.parametrize(
    "header,props",
    [
        (b"\x80\x80\x80\x80", b""),  # four continuation bytes: the reader stops at four
        (b"\x80\x80\x80\x80\x80\x80", b"\x15" + _s(b"PLAIN")),
        (b"\x80" * 40, b""),  # a continuation run that extends past the whole field
        (b"\x85", b"\x15" + _s(b"PLAIN")),  # header and size disagree
    ],
)
def test_a_properties_header_the_walk_and_the_reader_could_disagree_on(header, props):
    """Defect (defence in depth): the mask recomputed the varint header length with no
    four-byte cap, so on a continuation run its boundary could differ from the reader's and
    restore raw bytes over a zeroed region. A disagreement must zero the blob."""
    raw = _v5_raw_props(header, props)
    out = _masked(raw)
    assert len(out) == len(raw)
    _hides(out, USER, PASS)
    assert PASS.hex() not in mask_hex("mqtt", raw.hex())


def test_the_varint_header_walk_returns_none_on_any_disagreement():
    from honeylens.ics.mqtt import _varint_header

    assert _varint_header(b"\x80\x80\x80\x80\x00", 0, 5) is None
    assert _varint_header(b"\x80" * 10, 0, 3) is None
    assert _varint_header(b"\x02ab", 0, 3) == (1, 2)


def _layout(frame):
    return [(f.name, f.offset, f.length) for f in frame.fields], frame.tail_offset


@pytest.mark.parametrize("level,name", [(3, b"MQIsdp"), (4, b"MQTT"), (5, b"MQTT")])
@pytest.mark.parametrize("will", [None, WILL])
@pytest.mark.parametrize(
    "creds",
    [
        {"username": USER, "password": PASS},
        {"username": USER},
        {"password": PASS},
        {},
        {"username": b"", "password": b""},
    ],
)
def test_the_masked_packet_decodes_to_the_same_layout_as_the_original(level, name, will, creds):
    """Defect: the mask zeroed each credential field whole, length prefix included, so the
    masked bytes re-decoded with the username/password collapsed to two bytes and a fabricated
    'N byte(s) after the CONNECT payload' tail, on every credential-bearing CONNECT. The screen
    decodes the masked bytes, so masked and unmasked must place every byte identically."""
    raw = connect(level=level, name=name, will=will, **creds)
    masked = _masked(raw)
    assert _layout(decode("mqtt", masked)) == _layout(decode("mqtt", raw))
    assert decode("mqtt", masked).tail_offset is None
