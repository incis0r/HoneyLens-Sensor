"""MMS (IEC 61850) decoder: TPKT, COTP, ISO session, presentation, then the MMS PDU.

The three entry points are told apart by their first bytes, because the decoys store
different slices of the stream: a TPKT frame (``03 00 ..``), a COTP TPDU, or the session
layer payload (the COTP data the port-102 dispatcher sees).

The layers are walked in order. The decoy finds its service tag by searching the first eight
bytes; this decoder does not: each layer's expected byte is checked, and a frame that departs
from the layering is reported unparsed, with the byte that broke it in the tail reason.

``Frame.code`` is the confirmed-service number (4 read, 5 write, 2 identify). An initiate
request, a session CONNECT and a COTP connection request are session setups: semantics
``enumerate`` with no code. Only the first confirmed request in the PDU is decoded.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_COTP_TYPES = {
    0xE0: "Connection Request",
    0xD0: "Connection Confirm",
    0xF0: "Data",
    0x80: "Disconnect Request",
    0xC0: "Disconnect Confirm",
    0x70: "TPDU Error",
}
_SESSION_TYPES = {
    0x01: "DATA TRANSFER",
    0x0D: "CONNECT",
    0x0E: "ACCEPT",
    0x09: "FINISH",
    0x0A: "DISCONNECT",
    0x19: "ABORT",
}
_MMS_PDUS = {
    0: "confirmed-RequestPDU",
    1: "confirmed-ResponsePDU",
    2: "confirmed-ErrorPDU",
    3: "unconfirmed-PDU",
    4: "rejectPDU",
    5: "cancel-RequestPDU",
    6: "cancel-ResponsePDU",
    7: "cancel-ErrorPDU",
    8: "initiate-RequestPDU",
    9: "initiate-ResponsePDU",
    10: "initiate-ErrorPDU",
    11: "conclude-RequestPDU",
    12: "conclude-ResponsePDU",
    13: "conclude-ErrorPDU",
}

# confirmed service number -> (name, semantics). Numbers not listed carry no name here.
_SERVICES: dict[int, tuple[str, Semantics | None]] = {
    0: ("status", "enumerate"),
    1: ("getNameList", "enumerate"),
    2: ("identify", "enumerate"),
    3: ("rename", "write"),
    4: ("read", "read"),
    5: ("write", "write"),
    6: ("getVariableAccessAttributes", "enumerate"),
    7: ("defineNamedVariable", "write"),
    8: ("defineScatteredAccess", "write"),
    9: ("getScatteredAccessAttributes", "enumerate"),
    10: ("deleteVariableAccess", "write"),
    11: ("defineNamedVariableList", "write"),
    12: ("getNamedVariableListAttributes", "enumerate"),
    13: ("deleteNamedVariableList", "write"),
    14: ("defineNamedType", "write"),
    15: ("getNamedTypeAttributes", "enumerate"),
    16: ("deleteNamedType", "write"),
    17: ("input", None),
    18: ("output", None),
    19: ("takeControl", None),
    20: ("relinquishControl", None),
    26: ("initiateDownloadSequence", "write"),
    27: ("downloadSegment", "write"),
    28: ("terminateDownloadSequence", "write"),
    29: ("initiateUploadSequence", "read"),
    30: ("uploadSegment", "read"),
    31: ("terminateUploadSequence", "read"),
    32: ("requestDomainDownload", "write"),
    33: ("requestDomainUpload", "read"),
    34: ("loadDomainContent", "write"),
    35: ("storeDomainContent", None),
    36: ("deleteDomain", "write"),
    37: ("getDomainAttributes", "enumerate"),
    38: ("createProgramInvocation", "control"),
    39: ("deleteProgramInvocation", "control"),
    40: ("start", "control"),
    41: ("stop", "control"),
    42: ("resume", "control"),
    43: ("reset", "control"),
    44: ("kill", "control"),
    45: ("getProgramInvocationAttributes", "enumerate"),
    46: ("obtainFile", None),
    63: ("getAlarmSummary", "enumerate"),
    64: ("getAlarmEnrollmentSummary", "enumerate"),
    65: ("readJournal", "read"),
    66: ("writeJournal", "write"),
    71: ("getCapabilityList", "enumerate"),
    72: ("fileOpen", "read"),
    73: ("fileRead", "read"),
    74: ("fileClose", None),
    75: ("fileRename", "write"),
    76: ("fileDelete", "write"),
    77: ("fileDirectory", "enumerate"),
}
# Services 0-77 are all defined by MMS; the rest are not.
_DEFINED = range(0, 78)


class _Stop(Exception):
    """A field ends before it is complete."""

    def __init__(self, name: str, where: str) -> None:
        super().__init__(name)
        self.name = name
        self.where = where


class _Unplaced(Exception):
    """The next layer is not the one expected; the reason names what was seen."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _State:
    def __init__(self) -> None:
        self.code: int | None = None
        self.semantics: Semantics | None = None
        self.sentence: str | None = None
        self.outer: tuple[int, str] | None = None


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.pos = 0
        self.end = len(raw)
        self.fields: list[Field] = []

    def need(self, n: int, name: str) -> None:
        if self.pos + n > self.end:
            raise _Stop(name, "before" if self.pos >= self.end else "inside")

    def peek(self, name: str) -> int:
        self.need(1, name)
        return self.raw[self.pos]

    def uint(self, name: str, label: str, n: int, meaning: str | None = None) -> int:
        self.need(n, name)
        value = int.from_bytes(self.raw[self.pos : self.pos + n], "big")
        self.fields.append(Field(name, label, self.pos, n, value, meaning))
        self.pos += n
        return value

    def hexed(self, name: str, label: str, n: int) -> str:
        self.need(n, name)
        value = self.raw[self.pos : self.pos + n].hex()
        self.fields.append(Field(name, label, self.pos, n, value, None))
        self.pos += n
        return value

    def ber_header(self, name: str, label: str) -> tuple[int, int, int]:
        """A BER tag and length as one field; value is the content length.

        Returns (first tag byte, tag number, content length). Tag numbers of 31 and above use
        the two-byte form, with the number below 128 in the second byte.
        """
        start = self.pos
        self.need(1, name)
        first = self.raw[start]
        number, pos = first & 0x1F, start + 1
        if number == 0x1F:
            if pos >= self.end:
                raise _Stop(name, "inside")
            number, pos = self.raw[pos], pos + 1
            if number >= 0x80:
                raise _Unplaced(
                    f"the tag at byte {start} uses a multi-byte tag number, which is not decoded"
                )
        if pos >= self.end:
            raise _Stop(name, "inside")
        length = self.raw[pos]
        pos += 1
        if length >= 0x80:
            extra = length & 0x7F
            if length == 0x80 or extra > 2:
                raise _Unplaced(
                    f"the BER length form 0x{length:02x} at byte {pos - 1} is not decoded"
                )
            if pos + extra > self.end:
                raise _Stop(name, "inside")
            length = int.from_bytes(self.raw[pos : pos + extra], "big")
            pos += extra
        meaning = _header_meaning(name, first, number)
        self.fields.append(Field(name, label, start, pos - start, length, meaning))
        self.pos = pos
        return first, number, length


def _integer(r: _Reader, name: str, label: str) -> int:
    """A BER INTEGER (tag 0x02) of one to four bytes, as one field covering tag, length and value."""
    seen = r.peek(name)
    if seen != 0x02:
        raise _Unplaced(f"expected tag 0x02 for the {name} field, found 0x{seen:02x}")
    start = r.pos
    width = r.ber_header(name, label)[2]
    r.fields.pop()
    if not 1 <= width <= 4:
        r.pos = start
        raise _Unplaced(f"the {name} field has an INTEGER length of {width}, which is not decoded")
    if r.pos + width > r.end:
        r.pos = start
        raise _Stop(name, "inside")
    value = int.from_bytes(r.raw[r.pos : r.pos + width], "big")
    r.pos += width
    r.fields.append(Field(name, label, start, r.pos - start, value, None))
    return value


def _header_meaning(name: str, first: int, number: int) -> str | None:
    if name == "presentation_pdu":
        return "fully-encoded-data"
    if name == "mms_pdu" and first >> 6 == 2:
        return _MMS_PDUS.get(number)
    if name == "service":
        known = _SERVICES.get(number)
        return known[0] if known else None
    return None


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("mms", 0, "empty frame: no TPKT, COTP or session bytes")
    r = _Reader(raw)
    st = _State()
    try:
        if raw[0] == 0x03 and len(raw) > 1 and raw[1] == 0x00:
            _tpkt(r, st)
            return _cotp(r, st)
        if len(raw) > 1 and raw[1] in _COTP_TYPES:
            return _cotp(r, st)
        if raw[0] in _SESSION_TYPES:
            return _session(r, st)
    except _Stop as stop:
        return _cut(raw, r, st, stop)
    except _Unplaced as unplaced:
        return _frame(raw, r.fields, None, None, None, r.pos, unplaced.reason)
    seen = raw[:2].hex()
    return undecodable(
        "mms",
        len(raw),
        f"the first bytes are 0x{seen}, which are not TPKT, COTP or an ISO session SPDU",
    )


def _tpkt(r: _Reader, st: _State) -> None:
    r.uint("tpkt_version", "TPKT version", 1)
    r.uint("tpkt_reserved", "TPKT reserved", 1)
    total = r.uint("tpkt_length", "TPKT length", 2)
    if 4 <= total < len(r.raw):
        r.end = total
        st.outer = (total, f"{len(r.raw) - total} byte(s) after the TPKT length of {total}")


def _cotp(r: _Reader, st: _State) -> Frame:
    li = r.uint("cotp_length", "COTP length indicator", 1)
    ptype = r.uint("cotp_pdu_type", "COTP PDU type", 1)
    kind = ptype & 0xF0
    old = r.fields[-1]
    r.fields[-1] = Field(
        old.name, old.label, old.offset, old.length, old.value, _COTP_TYPES.get(kind)
    )
    if kind == 0xF0:
        if li != 2:
            why = (
                f"the COTP length indicator is {li}, not 2, so the Data TPDU layout is not applied"
            )
            return _done(r, st, None, None, None, why)
        r.uint("tpdu_number_eot", "TPDU number and end-of-transmission", 1)
        return _session(r, st)
    if kind == 0xE0:
        st.semantics, st.sentence = "enumerate", "COTP connection request (frame cut short)"
        r.uint("destination_reference", "Destination reference", 2)
        r.uint("source_reference", "Source reference", 2)
        r.uint("class_option", "Class and options", 1)
        why = "the COTP connection parameters (TSAPs, TPDU size) are not decoded here"
        return _done(
            r, st, "enumerate", None, "Opens an ISO session (COTP connection request)", why
        )
    why = f"a COTP {_COTP_TYPES.get(kind, 'TPDU')} carries no MMS data, so the bytes after it are not placed"
    return _done(r, st, None, None, None, why)


def _session(r: _Reader, st: _State) -> Frame:
    first = r.peek("session_type")
    if first == 0x01:
        seen = r.raw[r.pos : r.pos + 4]
        if len(seen) == 4 and seen != b"\x01\x00\x01\x00":
            raise _Unplaced(
                f"the session data SPDUs are 0x{seen.hex()}, not give-tokens and data-transfer 0x01000100"
            )
        r.hexed("session_spdus", "Session give-tokens and data-transfer SPDUs", 4)
        return _presentation(r, st)
    if first in (0x0D, 0x0E, 0x09, 0x0A, 0x19):
        r.uint("session_type", "Session SPDU type", 1, _SESSION_TYPES[first])
        r.uint("session_length", "Session SPDU length", 1)
        if first == 0x0D:
            why = "the session connect parameters and the presentation and ACSE layers are not decoded here"
            return _done(
                r, st, "enumerate", None, "Opens an ISO session (association request)", why
            )
        why = f"a session {_SESSION_TYPES[first]} SPDU carries no MMS request, so the bytes after it are not placed"
        return _done(r, st, None, None, None, why)
    seen_hex = f"0x{first:02x}"
    raise _Unplaced(
        f"the data after COTP starts with {seen_hex}, not an ISO session SPDU, so no presentation or MMS layout is applied"
    )


def _expect(r: _Reader, name: str, label: str, tag: int) -> int:
    seen = r.peek(name)
    if seen != tag:
        raise _Unplaced(f"expected tag 0x{tag:02x} for the {name} field, found 0x{seen:02x}")
    return r.ber_header(name, label)[2]


def _presentation(r: _Reader, st: _State) -> Frame:
    _expect(r, "presentation_pdu", "Presentation PDU", 0x61)
    _expect(r, "pdv_list", "PDV list", 0x30)
    _integer(r, "presentation_context_id", "Presentation context ID")
    _expect(r, "single_asn1_type", "Single ASN.1 type", 0xA0)
    return _mms(r, st)


def _mms(r: _Reader, st: _State) -> Frame:
    tag = r.peek("mms_pdu")
    _, number, _ = r.ber_header("mms_pdu", "MMS PDU")
    if tag >> 6 != 2 or number not in _MMS_PDUS:
        why = f"tag 0x{tag:02x} is not a context tag 0-13 of the MMSpdu CHOICE, so its content is not placed"
        sentence = f"Sends tag 0x{tag:02x}, which is not in the MMS PDU CHOICE"
        return _done(r, st, "anomaly", None, sentence, why)
    name = _MMS_PDUS[number]
    if number == 8:
        why = "the initiate request parameters are not decoded here"
        return _done(r, st, "enumerate", None, "Opens an MMS association (initiate request)", why)
    if number == 11:
        return _done(
            r,
            st,
            None,
            None,
            "Asks to end the MMS association (conclude request)",
            "the conclude request content is not decoded here",
        )
    if number == 5:
        return _done(
            r,
            st,
            None,
            None,
            "Cancels an outstanding MMS request",
            "the cancel request content is not decoded here",
        )
    if number != 0:
        why = f"{name} is a response or notification that MMS defines for the server to send, and its content is not decoded here"
        return _done(r, st, None, None, f"Sends a {name}", why)
    return _confirmed_request(r, st)


def _confirmed_request(r: _Reader, st: _State) -> Frame:
    invoke = _integer(r, "invoke_id", "Invoke ID")

    tag = r.peek("service")
    if tag >> 6 != 2:
        raise _Unplaced(
            f"the next tag 0x{tag:02x} is not a context-class service tag, so no service is placed"
        )
    # The service number is known from the tag bytes alone, before the length is read.
    number = tag & 0x1F
    if number == 0x1F:
        r.need(2, "service")
        number = r.raw[r.pos + 1]
    st.code = number
    known = _SERVICES.get(number)
    st.semantics = known[1] if known else None
    label = known[0] if known else f"service {number}"
    st.sentence = f"{label} (frame cut short)"
    r.ber_header("service", "Service")
    if number not in _DEFINED:
        why = f"service number {number} is not one MMS defines (0-77), so its parameters are not placed"
        return _done(
            r,
            st,
            "anomaly",
            number,
            f"Sends service number {number}, which MMS does not define",
            why,
        )
    sentence = f"Sends the MMS {label} request (invoke ID {invoke})"
    why = f"the parameters of the {label} request are not decoded here"
    return _done(r, st, known[1] if known else None, number, sentence, why)


def _done(
    r: _Reader,
    st: _State,
    semantics: Semantics | None,
    code: int | None,
    sentence: str | None,
    reason: str,
) -> Frame:
    if r.pos >= len(r.raw):
        return _frame(r.raw, r.fields, semantics, code, sentence, None, None)
    if st.outer is not None and r.pos == st.outer[0]:
        reason = st.outer[1]
    return _frame(r.raw, r.fields, semantics, code, sentence, r.pos, reason)


def _cut(raw: bytes, r: _Reader, st: _State, stop: _Stop) -> Frame:
    layer = "the declared length" if r.end < len(raw) else "the frame"
    why = f"{layer} ends {stop.where} the {stop.name} field"
    return _frame(raw, r.fields, st.semantics, st.code, st.sentence, r.pos, why)


def _frame(
    raw: bytes,
    fields: list[Field],
    semantics: Semantics | None,
    code: int | None,
    sentence: str | None,
    tail_offset: int | None,
    tail_reason: str | None,
) -> Frame:
    if tail_offset is None:
        tail_reason = None
    return Frame(
        protocol="mms",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["mms"] = decode
