"""PROFINET decoder: the DCE/RPC datagram header (80 bytes) and the PNIO device opnum.

The decoy's own offset (byte 2 as an opnum) is deliberately not reproduced: the opnum is
read from byte 68 of the connectionless header, in the byte order the header's data
representation declares.
"""

import struct

import pytest

from honeylens.ics import decode
from honeylens.ics import profinet as profinet_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)

# DEA00001-6C97-11D1-8271-00A02442DF7D, the PROFINET IO device interface, little-endian on the wire.
PNIO_DEVICE = bytes.fromhex("01 00 a0 de 97 6c d1 11 82 71 00 a0 24 42 df 7d".replace(" ", ""))
OTHER_IF = bytes.fromhex("08 83 af e1 1f 5d c9 11 91 a4 08 00 2b 14 a0 fa")  # endpoint mapper


def rpc(
    opnum: int, ptype: int = 0, interface: bytes = PNIO_DEVICE, body: bytes = b"", little=True
) -> bytes:
    """A connectionless DCE/RPC datagram: 80 header bytes, then the body."""
    e = "<" if little else ">"
    drep = bytes([0x10 if little else 0x00, 0, 0])
    return (
        bytes([4, ptype, 0x20, 0]) + drep + b"\x00"
        + bytes(range(16)) + interface + bytes(range(16, 32))
        + struct.pack(e + "III", 0x1234, 1, 7)
        + struct.pack(e + "HHHHH", opnum, 0xFFFF, 0xFFFF, len(body), 0)
        + b"\x00\x00" + body
    )  # fmt: skip


def test_header_is_eighty_bytes_and_the_opnum_sits_at_byte_68():
    assert len(rpc(2)) == 80 and struct.unpack_from("<H", rpc(2), 68)[0] == 2


def test_read_request_is_a_read_and_names_the_interface():
    raw = rpc(2, body=b"\x00" * 12)
    f = decode("profinet", raw)
    by = {x.name: x for x in f.fields}
    assert f.code == 2 and f.semantics == "read"
    assert by["interface_uuid"].value == "dea00001-6c97-11d1-8271-00a02442df7d"
    assert by["interface_uuid"].meaning == "PROFINET IO device interface"
    assert by["opnum"].offset == 68 and by["opnum"].meaning == "Read"
    assert by["packet_type"].meaning == "request" and by["sequence_number"].value == 7
    assert f.tail_offset == 80 and "12 byte(s)" in f.tail_reason


def test_the_decoy_offset_is_not_used():
    """Defect pinned: the decoy read byte 2 as the opnum. In a real datagram byte 2 is flags1,
    and a write opnum (3) placed there must change nothing."""
    raw = bytearray(rpc(2))
    raw[2] = 0x06  # what the decoy would have called a Write
    f = decode("profinet", bytes(raw))
    assert f.code == 2 and f.semantics == "read"
    raw2 = bytearray(rpc(3))
    raw2[2] = 0x00
    assert decode("profinet", bytes(raw2)).semantics == "write"


def test_big_endian_data_representation_is_honoured():
    """The header declares its byte order; ignoring it reads opnum 2 as 512."""
    be = rpc(2, little=False)
    # the UUID is big-endian too, so write the interface in that order
    swapped = bytearray(be)
    swapped[24:40] = bytes.fromhex("dea000016c9711d1827100a02442df7d")
    f = decode("profinet", bytes(swapped))
    assert f.code == 2 and f.semantics == "read"
    assert (
        next(x for x in f.fields if x.name == "interface_uuid").value
        == "dea00001-6c97-11d1-8271-00a02442df7d"
    )


@pytest.mark.parametrize(
    ("opnum", "semantics"),
    [
        (0, None),
        (1, None),
        (2, "read"),
        (3, "write"),
        (4, "control"),
        (5, "enumerate"),
        (6, "anomaly"),
        (7, "anomaly"),
        (255, "anomaly"),
        (65535, "anomaly"),
    ],
)
def test_opnum_table_on_full_length_datagrams(opnum, semantics):
    """MITRE keys off this; opnums 0-5 are defined on the device interface, 6 and up are not."""
    raw = rpc(opnum)
    f = profinet_module.decode(raw)
    assert f.semantics == semantics and f.code == opnum
    assert_frame_sane(f, raw)


def test_an_opnum_on_another_interface_is_not_given_pnio_meaning():
    """Never apply a sub-layout that was not confirmed: the interface UUID selects the meaning."""
    f = decode("profinet", rpc(3, interface=OTHER_IF, body=b"\x01\x02"))
    assert f.code is None and f.semantics is None
    assert "e1af8308-5d1f-11c9-91a4-08002b14a0fa" in f.tail_reason
    bare = decode("profinet", rpc(3, interface=OTHER_IF))
    assert bare.tail_offset is None and "e1af8308-5d1f-11c9-91a4-08002b14a0fa" in bare.sentence
    assert next(x for x in f.fields if x.name == "opnum").meaning is None


def test_a_response_packet_type_is_defined_but_carries_no_request_meaning():
    f = decode("profinet", rpc(2, ptype=2))
    assert f.semantics is None and f.code is None
    assert next(x for x in f.fields if x.name == "packet_type").meaning == "response"


def test_a_connection_oriented_packet_type_is_an_anomaly_in_a_datagram():
    f = decode("profinet", rpc(2, ptype=11))
    assert f.semantics == "anomaly" and "connection-oriented" in f.sentence


def test_an_undefined_packet_type_is_worded_differently():
    f = decode("profinet", rpc(2, ptype=99))
    assert f.semantics == "anomaly" and "connection-oriented" not in f.sentence


def test_a_datagram_that_is_not_dce_rpc_is_reported_not_guessed():
    """Defect class: the decoy treated any UDP payload as DCE/RPC. Version 4 is required."""
    f = decode("profinet", bytes([0x05, 0x00, 0x06]) + b"\x00" * 80)
    assert f.fields == () and f.tail_offset == 0 and "version 5" in f.tail_reason


def test_a_datagram_cut_before_and_inside_a_field():
    """Defect class: 'inside' for a field of which no byte was present."""
    raw = rpc(2)
    before = decode("profinet", raw[:68])
    assert before.tail_offset == 68 and "before the opnum" in before.tail_reason
    assert before.code is None and before.sentence is None
    inside = decode("profinet", raw[:69])
    assert inside.tail_offset == 68 and "inside the opnum" in inside.tail_reason
    late = decode("profinet", raw[:78])
    assert late.code == 2 and late.semantics == "read" and late.sentence == "Read (frame cut short)"
    assert late.tail_offset == 78 and "before the auth_proto" in late.tail_reason
    assert "inside the fragment_number" in decode("profinet", raw[:77]).tail_reason


def test_value_types_do_not_depend_on_length():
    frames = [
        decode("profinet", rpc(2)),
        decode("profinet", rpc(3, body=b"abc")),
        decode("profinet", rpc(0, little=False)),
    ]
    assert_value_types_are_stable(frames)
    assert {type(x.value) for f in frames for x in f.fields if x.name.endswith("uuid")} == {str}


def test_a_datagram_cut_at_every_length_is_a_sane_frame():
    for raw in (rpc(2, body=b"abcd"), rpc(0, little=False), rpc(9, ptype=11)):
        assert_every_prefix_is_sane(profinet_module.decode, raw)


def test_empty_frame_is_undecodable():
    f = decode("profinet", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: profinet.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        profinet_module.decode, 34964, (b"", b"\x04", rpc(2)[:30], rpc(2)[:70], rpc(2))
    )
