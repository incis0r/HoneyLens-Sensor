"""OPC UA decoder: the secure-channel header and the request type of a MSG body.

The input is the body of a MSG chunk as the decoy captures it (``body_hex``), so the
8-byte transport header is not part of it: SecureChannelId, TokenId, SequenceNumber and
RequestId (four little-endian words), then the NodeId of the request type. That NodeId is
the DefaultBinary encoding id of the service request (428 is GetEndpointsRequest).
The request header and the request body stay in the tail.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_HEADER: tuple[tuple[str, str], ...] = (
    ("secure_channel_id", "Secure channel ID"),
    ("token_id", "Security token ID"),
    ("sequence_number", "Sequence number"),
    ("request_id", "Request ID"),
)

# DefaultBinary encoding id -> (service request, semantics), namespace 0.
_SERVICES: dict[int, tuple[str, Semantics | None]] = {
    422: ("FindServersRequest", "enumerate"),
    428: ("GetEndpointsRequest", "enumerate"),
    446: ("OpenSecureChannelRequest", None),
    452: ("CloseSecureChannelRequest", None),
    461: ("CreateSessionRequest", None),
    467: ("ActivateSessionRequest", None),
    473: ("CloseSessionRequest", None),
    479: ("CancelRequest", None),
    488: ("AddNodesRequest", "write"),
    494: ("AddReferencesRequest", "write"),
    500: ("DeleteNodesRequest", "write"),
    506: ("DeleteReferencesRequest", "write"),
    527: ("BrowseRequest", "enumerate"),
    533: ("BrowseNextRequest", "enumerate"),
    554: ("TranslateBrowsePathsToNodeIdsRequest", "enumerate"),
    560: ("RegisterNodesRequest", None),
    566: ("UnregisterNodesRequest", None),
    631: ("ReadRequest", "read"),
    664: ("HistoryReadRequest", "read"),
    673: ("WriteRequest", "write"),
    700: ("HistoryUpdateRequest", "write"),
    712: ("CallRequest", "command"),
    751: ("CreateMonitoredItemsRequest", "read"),
    763: ("ModifyMonitoredItemsRequest", None),
    769: ("SetMonitoringModeRequest", None),
    775: ("SetTriggeringRequest", None),
    781: ("DeleteMonitoredItemsRequest", None),
    787: ("CreateSubscriptionRequest", None),
    793: ("ModifySubscriptionRequest", None),
    799: ("SetPublishingModeRequest", None),
    826: ("PublishRequest", None),
    832: ("RepublishRequest", None),
    841: ("TransferSubscriptionsRequest", None),
    847: ("DeleteSubscriptionsRequest", None),
}

_ENCODINGS = {0: "Two-byte NodeId", 1: "Four-byte NodeId", 2: "Numeric NodeId"}
_OTHER_ENCODINGS = {3: "String NodeId", 4: "GUID NodeId", 5: "ByteString NodeId"}
# encoding -> (namespace field length or 0, id field length)
_NUMERIC_LAYOUT = {0: (0, 1), 1: (1, 2), 2: (2, 4)}


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("opcua", 0, "empty frame: no secure channel header")
    fields: list[Field] = []
    pos = 0
    for name, label in _HEADER:
        if pos + 4 > len(raw):
            return _cut(raw, fields, pos, name)
        fields.append(
            Field(name, label, pos, 4, int.from_bytes(raw[pos : pos + 4], "little"), None)
        )
        pos += 4

    if pos >= len(raw):
        return _cut(raw, fields, pos, "type_node_encoding")
    encoding = raw[pos]
    kind = encoding & 0x3F  # bits 6 and 7 flag a namespace URI or server index on the NodeId
    fields.append(
        Field(
            "type_node_encoding",
            "Request type NodeId encoding",
            pos,
            1,
            encoding,
            _ENCODINGS.get(kind) or _OTHER_ENCODINGS.get(kind),
        )
    )
    pos += 1

    if kind not in _NUMERIC_LAYOUT:
        if kind in _OTHER_ENCODINGS:
            why = (
                f"the request type NodeId uses encoding 0x{encoding:02x} "
                f"({_OTHER_ENCODINGS[kind]}), which names no numeric service, "
                "so the bytes after it are not placed"
            )
            return _frame(raw, fields, None, None, None, _after(raw, pos), why)
        why = (
            f"NodeId encoding 0x{encoding:02x} is not defined by the OPC UA specification, "
            "so the bytes after it are not placed"
        )
        sentence = f"Sends a request type with the undefined NodeId encoding 0x{encoding:02x}"
        return _frame(raw, fields, "anomaly", None, sentence, _after(raw, pos), why)

    if encoding & 0xC0:
        why = (
            f"NodeId encoding 0x{encoding:02x} carries a namespace-URI or server-index flag "
            "whose extra fields are not decoded here, so the bytes after it are not placed"
        )
        return _frame(raw, fields, None, None, None, _after(raw, pos), why)

    ns_len, id_len = _NUMERIC_LAYOUT[kind]
    namespace = 0
    if ns_len:
        if pos + ns_len > len(raw):
            return _cut(raw, fields, pos, "type_namespace")
        namespace = int.from_bytes(raw[pos : pos + ns_len], "little")
        fields.append(
            Field("type_namespace", "Request type namespace", pos, ns_len, namespace, None)
        )
        pos += ns_len
    if pos + id_len > len(raw):
        return _cut(raw, fields, pos, "type_id")
    service = int.from_bytes(raw[pos : pos + id_len], "little")
    known = _SERVICES.get(service) if namespace == 0 else None
    fields.append(
        Field("type_id", "Request type ID", pos, id_len, service, known[0] if known else None)
    )
    pos += id_len

    if namespace != 0:
        why = (
            f"the request type NodeId is in namespace {namespace}, so its id {service} "
            "has no meaning here, and the request header and body are not decoded"
        )
        return _frame(raw, fields, None, None, None, _after(raw, pos), why)
    why = "the request header and the request body are not decoded here"
    if known is None:
        why = f"service id {service} is not one this decoder knows; " + why
        return _frame(raw, fields, None, service, None, _after(raw, pos), why)
    name, semantics = known
    return _frame(
        raw, fields, semantics, service, f"Sends the OPC UA {name}", _after(raw, pos), why
    )


def _after(raw: bytes, pos: int) -> int | None:
    return pos if pos < len(raw) else None


def _cut(raw: bytes, fields: list[Field], pos: int, name: str) -> Frame:
    # `pos` is where the field would start: "before" if no byte of it is present.
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the {name} field"
    # No service id has been read on any path here, so there is no sentence.
    return _frame(raw, fields, None, None, None, pos, why)


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
        protocol="opcua",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["opcua"] = decode
