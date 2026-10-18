"""S7comm decoder: TPKT, COTP, then the S7 header and the job function or userdata subfunction.

The three layers are told apart by their first bytes, because the decoys store different
slices of the same stream: a TPKT frame (``03 00 ..``), a COTP TPDU (length indicator, then a
PDU type byte), or a bare S7 PDU (``32 ..``, the COTP payload the port-102 dispatcher sees).

A COTP connection request is a session setup: semantics ``enumerate`` with no code and no
function field, because no S7 job was sent. ``Frame.code`` is the job function code
(0x04 read variable, 0x05 write variable, 0xF0 setup communication). A userdata PDU
(ROSCTR 7) carries a function group and subfunction instead of a function code, so it has
semantics and no code.

S7comm has no public closed specification; a function code outside the table is reported
without semantics, never as an anomaly.
"""

from __future__ import annotations

from collections.abc import Callable

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_COTP_TYPES = {
    0xE0: "Connection Request",
    0xD0: "Connection Confirm",
    0xF0: "Data",
    0x80: "Disconnect Request",
    0xC0: "Disconnect Confirm",
    0x70: "TPDU Error",
}
_TSAP = {
    0xC0: ("tpdu_size", "TPDU size"),
    0xC1: ("calling_tsap", "Calling TSAP"),
    0xC2: ("called_tsap", "Called TSAP"),
}

_ROSCTR = {1: "Job", 2: "Ack", 3: "Ack_Data", 7: "Userdata"}

# job function code -> (name, semantics)
_JOBS: dict[int, tuple[str, Semantics | None]] = {
    0x00: ("CPU services", None),
    0xF0: ("Setup Communication", "enumerate"),
    0x04: ("Read Var", "read"),
    0x05: ("Write Var", "write"),
    0x1A: ("Request Download", "write"),
    0x1B: ("Download Block", "write"),
    0x1C: ("Download Ended", "write"),
    0x1D: ("Start Upload", "read"),
    0x1E: ("Upload", "read"),
    0x1F: ("End Upload", "read"),
    0x28: ("PI Service", "control"),
    0x29: ("PLC Stop", "control"),
}
_JOB_SENTENCES = {
    0xF0: "Negotiates the S7 session (Setup Communication)",
    0x1A: "Starts a program download to the PLC",
    0x1B: "Sends a program block to the PLC",
    0x1C: "Ends a program download to the PLC",
    0x1D: "Starts a program upload from the PLC",
    0x1E: "Uploads a program block from the PLC",
    0x1F: "Ends a program upload from the PLC",
    0x28: "Starts or stops a program on the PLC (PI service)",
    0x29: "Stops the PLC",
}
_AREAS = {
    0x81: "inputs",
    0x82: "outputs",
    0x83: "flags",
    0x84: "DB",
    0x1C: "counters",
    0x1D: "timers",
}
_GROUPS = {
    1: "Push",
    2: "Cyclic data",
    3: "Block functions",
    4: "CPU functions",
    5: "Security",
    7: "Time functions",
}
# (function group, subfunction) -> (semantics, sentence)
_USERDATA: dict[tuple[int, int], tuple[Semantics, str]] = {
    (4, 1): ("enumerate", "Reads the PLC's system status list (identity and configuration)"),
    (3, 1): ("enumerate", "Lists the blocks stored on the PLC"),
    (3, 2): ("enumerate", "Lists the blocks of one type stored on the PLC"),
    (3, 3): ("enumerate", "Reads the details of a block stored on the PLC"),
    (7, 1): ("read", "Reads the PLC's clock"),
    (7, 2): ("command", "Sets the PLC's clock"),
    (7, 4): ("command", "Sets the PLC's clock"),
}


class _Stop(Exception):
    """The bytes allowed to a field end before it is complete."""

    def __init__(self, name: str, where: str) -> None:
        super().__init__(name)
        self.name = name
        self.where = where


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.pos = 0
        self.end = len(raw)
        self.fields: list[Field] = []

    def uint(
        self,
        name: str,
        label: str,
        n: int,
        meaning: str | None = None,
        show: Callable[[int], tuple[int, str | None]] | None = None,
    ) -> int:
        """Read a big-endian integer. `show` maps it to the (value, meaning) the field displays."""
        if self.pos + n > self.end:
            raise _Stop(name, "before" if self.pos >= self.end else "inside")
        value = int.from_bytes(self.raw[self.pos : self.pos + n], "big")
        shown, meant = show(value) if show else (value, meaning)
        self.fields.append(Field(name, label, self.pos, n, shown, meant))
        self.pos += n
        return value

    def hexed(self, name: str, label: str, n: int) -> str:
        if self.pos + n > self.end:
            raise _Stop(name, "before" if self.pos >= self.end else "inside")
        value = self.raw[self.pos : self.pos + n].hex()
        self.fields.append(Field(name, label, self.pos, n, value, None))
        self.pos += n
        return value

    def relabel(self, index: int, meaning: str | None) -> None:
        old = self.fields[index]
        self.fields[index] = Field(old.name, old.label, old.offset, old.length, old.value, meaning)


class _State:
    """What is known about the frame so far, for a frame that ends before it is complete."""

    def __init__(self) -> None:
        self.code: int | None = None
        self.semantics: Semantics | None = None
        self.sentence: str | None = None
        self.tail_reason: str | None = None
        self.outer: tuple[int, str] | None = None
        self.data_from: int | None = None  # where the S7 data section begins


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("s7comm", 0, "empty frame: no TPKT, COTP or S7 bytes")
    r = _Reader(raw)
    st = _State()
    try:
        if raw[0] == 0x03 and len(raw) > 1 and raw[1] == 0x00:
            _tpkt(r, st)
            return _cotp(r, st)
        if raw[0] == 0x32:
            return _s7(r, st)
        if len(raw) > 1 and raw[1] in _COTP_TYPES:
            return _cotp(r, st)
    except _Stop as stop:
        return _cut(raw, r, st, stop)
    seen = raw[:2].hex()
    return undecodable(
        "s7comm", len(raw), f"the first bytes are 0x{seen}, which are not TPKT, COTP or S7"
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
    cotp_end = r.pos + li
    ptype = r.uint("cotp_pdu_type", "COTP PDU type", 1)
    kind = ptype & 0xF0
    r.relabel(len(r.fields) - 1, _COTP_TYPES.get(kind))
    if kind == 0xF0:
        if li != 2:
            why = (
                f"the COTP length indicator is {li}, not 2, so the Data TPDU layout is not applied"
            )
            return _done(r, st, None, None, None, why)
        r.uint("tpdu_number_eot", "TPDU number and end-of-transmission", 1)
        return _s7(r, st)
    if kind in (0xE0, 0xD0):
        if kind == 0xE0:
            st.semantics, st.sentence = "enumerate", "COTP connection request (frame cut short)"
        r.uint("destination_reference", "Destination reference", 2)
        r.uint("source_reference", "Source reference", 2)
        r.uint("class_option", "Class and options", 1)
        while r.pos < min(cotp_end, r.end):
            code = r.raw[r.pos]
            known = _TSAP.get(code)
            if known is None:
                why = f"COTP parameter 0x{code:02x} is not decoded here"
                return _done(r, st, _setup(kind), None, _setup_sentence(kind), why)
            if r.pos + 2 > r.end:
                raise _Stop(known[0], "inside")
            length = r.raw[r.pos + 1]
            if r.pos + 2 + length > r.end:
                raise _Stop(known[0], "inside")
            r.fields.append(
                Field(
                    known[0],
                    known[1],
                    r.pos,
                    2 + length,
                    r.raw[r.pos + 2 : r.pos + 2 + length].hex(),
                    None,
                )
            )
            r.pos += 2 + length
        if r.pos < cotp_end:
            raise _Stop("cotp_parameter", "before")
        return _done(r, st, _setup(kind), None, _setup_sentence(kind), None)
    why = f"a COTP {_COTP_TYPES.get(kind, 'TPDU')} carries no S7 job, so the bytes after it are not placed"
    return _done(r, st, None, None, None, why)


def _setup(kind: int) -> Semantics | None:
    return "enumerate" if kind == 0xE0 else None


def _setup_sentence(kind: int) -> str:
    if kind == 0xE0:
        return "Opens an S7 session (COTP connection request) and sends no S7 job"
    return "Sends a COTP Connection Confirm, which a server sends in answer to a request"


def _s7(r: _Reader, st: _State) -> Frame:
    if r.pos >= r.end or r.raw[r.pos] != 0x32:
        seen = f"0x{r.raw[r.pos]:02x}" if r.pos < len(r.raw) else "nothing"
        why = f"the data after COTP starts with {seen}, not the S7 protocol id 0x32, so no S7 layout is applied"
        return _done(r, st, None, None, None, why)
    r.uint("protocol_id", "Protocol ID", 1)
    rosctr = r.uint("rosctr", "Message type (ROSCTR)", 1, None)
    r.relabel(len(r.fields) - 1, _ROSCTR.get(rosctr))
    r.uint("reserved", "Reserved", 2)
    r.uint("pdu_reference", "PDU reference", 2)
    param_len = r.uint("parameter_length", "Parameter length", 2)
    r.uint("data_length", "Data length", 2)
    if rosctr in (2, 3):
        r.uint("error_class", "Error class", 1)
        r.uint("error_code", "Error code", 1)
        why = f"a {_ROSCTR[rosctr]} PDU is a response the PLC sends, and its layout is not decoded here"
        return _done(r, st, None, None, None, why)
    if rosctr not in (1, 7):
        why = (
            f"message type {rosctr} is not one this decoder knows, so the parameters are not placed"
        )
        return _done(r, st, None, None, None, why)

    param_end = min(r.end, r.pos + param_len)
    st.data_from = param_end
    saved_end = r.end
    r.end = param_end
    if rosctr == 7:
        frame = _userdata(r, st)
    else:
        frame = _job(r, st)
    r.end = saved_end
    return frame


def _job(r: _Reader, st: _State) -> Frame:
    code = r.uint("function_code", "Function code", 1)
    known = _JOBS.get(code)
    st.code = code
    if known is None:
        st.sentence = f"S7 function 0x{code:02x} (frame cut short)"
        why = f"function code 0x{code:02x} is not one this decoder knows, so its parameters are not placed"
        return _done(r, st, None, code, None, why)
    name, semantics = known
    st.semantics = semantics
    st.sentence = f"{name} (frame cut short)"
    r.relabel(len(r.fields) - 1, name)
    if code in (0x04, 0x05):
        return _variable_access(r, st, code, name, semantics)
    sentence = _JOB_SENTENCES.get(code, f"Sends the S7 {name} job")
    why = f"the parameters of {name} are not decoded here"
    return _done(r, st, semantics, code, sentence, why)


def _variable_access(
    r: _Reader, st: _State, code: int, name: str, semantics: Semantics | None
) -> Frame:
    count = r.uint("item_count", "Item count", 1)
    verb = "Reads" if code == 0x04 else "Writes"
    sentence = f"{verb} {count} item(s) on the PLC"
    if count == 0:
        return _done(r, st, semantics, code, sentence, None)
    expected = (0x12, 0x0A, 0x10)
    present = r.raw[r.pos : min(r.end, r.pos + 3)]
    for i, byte in enumerate(present):  # compare the bytes that are there, one by one
        if byte != expected[i]:
            why = (
                f"item byte {i} is 0x{byte:02x}, not 0x{expected[i]:02x} of the S7ANY address "
                "0x12 0x0a 0x10, so the item is not placed"
            )
            return _done(r, st, semantics, code, sentence, why)
    r.uint("item_variable_spec", "Variable specification", 1)
    r.uint("item_address_length", "Address length", 1)
    r.uint("item_syntax_id", "Syntax ID", 1)
    r.uint("item_transport_size", "Transport size", 1)
    r.uint("item_length", "Item length", 2)
    db = r.uint("db_number", "DB number", 2)
    area = r.uint("area", "Area", 1, show=lambda v: (v, _AREAS.get(v)))
    address = r.uint("address", "Bit address", 3)
    where = _AREAS.get(area, f"area 0x{area:02x}")
    place = f"DB {db}" if area == 0x84 else where
    sentence = f"{verb} {count} item(s) {'from' if code == 0x04 else 'to'} the PLC, the first {'from' if code == 0x04 else 'to'} {place} at byte {address >> 3}"
    left = count - 1
    if left:
        return _done(r, st, semantics, code, sentence, f"{left} further item(s) are not decoded")
    return _done(r, st, semantics, code, sentence, None)


def _userdata(r: _Reader, st: _State) -> Frame:
    head = r.hexed("userdata_head", "Parameter head", 3)
    if head != "000112":
        why = f"the userdata parameter head is 0x{head}, not 0x000112, so the subfunction layout is not applied"
        return _done(r, st, None, None, None, why)
    plen = r.uint("userdata_length", "Userdata parameter length", 1)
    if plen != 4:
        why = f"the userdata parameter length is {plen}, not 4, so the subfunction layout is not applied"
        return _done(r, st, None, None, None, why)
    r.uint("method", "Method", 1)
    tg = r.uint(
        "function_group",
        "Function group",
        1,
        show=lambda v: (v & 0x0F, _GROUPS.get(v & 0x0F)),
    )
    group, kind = tg & 0x0F, tg >> 4
    sub = r.uint("subfunction", "Subfunction", 1)
    r.uint("sequence_number", "Sequence number", 1)
    known = _USERDATA.get((group, sub)) if kind == 4 else None
    if known is None:
        why = (
            f"function group {group} subfunction {sub} (type {kind}) is not one this "
            "decoder assigns a meaning to"
        )
        return _done(r, st, None, None, "Sends an S7 userdata PDU", why)
    return _done(r, st, known[0], None, known[1], None)


def _done(
    r: _Reader,
    st: _State,
    semantics: Semantics | None,
    code: int | None,
    sentence: str | None,
    reason: str | None,
) -> Frame:
    """The frame is understood as far as it goes; whatever remains is the tail."""
    if r.pos >= len(r.raw):
        return _frame(r.raw, r.fields, semantics, code, sentence, None, None)
    why = reason
    if why is None:
        if st.outer is not None and r.pos == st.outer[0]:
            why = st.outer[1]
        elif r.pos == st.data_from:
            why = "the S7 data section after the parameters is not decoded"
        else:
            why = "bytes after the decoded fields"
    return _frame(r.raw, r.fields, semantics, code, sentence, r.pos, why)


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
        protocol="s7comm",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["s7comm"] = decode
