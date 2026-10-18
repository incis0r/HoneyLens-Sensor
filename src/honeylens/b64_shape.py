"""The single Base64 shape measurement, shared by every decoy and every carrier extractor.

CVE-2026-114938 ("Java4Shell") is delivered as a blob that *cannot* be Base64: the over-write
happens inside `java.util.Base64.decode` while it rejects the input, before it throws. So the
evidence is the blob's **shape**, and the shape has to be measured where the blob still exists.

Why this is one module and not a method on each decoy: `hp_http` and `honeypot_k8s` each grew
their own Basic-auth extractor, and the k8s one reduced the value to the word `"present"` before
anything could measure it. The 14 rows the 2026-11-18 actor left on four decoy surfaces are
stored and cannot be labelled, because the evidence was gone by the time it reached the
database. NTLM, SAML and Bearer go through this function instead.

Two measured findings from the PoC (the internal Java4Shell case notes) bound what may be
claimed:

* **F4** (`AdjProbe16`): `basic sig9a=32`, `url=0`, `mime=0`. Only `Base64.getDecoder()` takes
  the vulnerable intrinsic. A token that distinguishes the base64url alphabet therefore cannot
  reach it through a conformant decoder — so `alphabet` is reported, not assumed, and a token
  that distinguishes nothing is reported as `"either"` rather than silently called standard.
* **F5** (`AdjProbe8/9`): only the exact 64+1 = 65-character shape fires on that build; 129,
  193 and 259 with every malformed tail measured zero. So `len` is exact and the caller decides
  what to make of it.
"""

import base64
import logging
import re
from typing import Any
from urllib.parse import unquote

_STD_ONLY = frozenset("+/")
_URL_ONLY = frozenset("-_")
_TO_STD = str.maketrans("-_", "+/")
#: Every character that can appear in either Base64 alphabet, padding included.
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")

log = logging.getLogger(__name__)


def _alphabet(token: str) -> str:
    """Which Base64 variant the token's own characters rule in or out.

    `"either"` is not a failure to decide: a token of plain alphanumerics and padding is legal
    in both alphabets, and naming one would be an unsupported claim about which decoder the
    receiving application would use. `"mixed"` is legal in neither and is itself a signal, and
    `"invalid"` means the value is not a Base64 token in the first place.
    """
    chars = set(token)
    # Asked first, because `mod4` and padding only mean anything in a field that is Base64.
    # A query parameter is percent-decoded before it is measured and what comes back is not
    # guaranteed to be a token at all: one real fleet value decoded to a 19-byte string with an
    # interior `=` and characters from no alphabet, and it was being graded as an exploit.
    if not chars <= _B64_CHARS:
        return "invalid"
    std = bool(chars & _STD_ONLY)
    url = bool(chars & _URL_ONLY)
    if std and url:
        return "mixed"
    if std:
        return "std"
    if url:
        return "url"
    return "either"


def decode_b64(token: str | None) -> bytes | None:
    """The bytes a token decodes to, in the variant its own characters allow, or `None`.

    This is the **only** implementation of "is this Base64" in the codebase, and `decodes` in
    the shape below is defined as "this returned something". There used to be a second copy in
    `hp_http._decode_basic_blob`, and the copies disagreed: for a url-alphabet blob the shape
    recorded `b64_valid=True` while the decoder returned `None`, so one field of a stored row
    contradicted the next.

    `len % 4 == 1` is refused outright rather than re-padded: four characters carry three bytes
    and no bit pattern leaves one over, so no amount of padding makes it legal. Python's
    `b64decode` without `validate=True` *accepts* `"A"*64 + "="` and hands back 48 NUL bytes,
    which is how the trigger was first stored as a username.
    """
    if not token or len(token) % 4 == 1:
        return None
    alphabet = _alphabet(token)
    if alphabet in ("mixed", "invalid"):
        return None
    candidate = token.translate(_TO_STD) if alphabet == "url" else token
    try:
        return base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=True)
    except Exception as exc:  # malformed input is the normal case here, not an error
        log.debug("not base64: %s", exc)
        return None


def _shape_without_decode(token: str, truncated: bool) -> dict[str, Any]:
    """Every field `shape_verdict` reads, and not the one it never does.

    `shape_verdict` applies lengths, padding positions and an alphabet check — it never looks
    at `decodes`. So a verdict can be computed **exactly** without decoding anything, which is
    what lets the record budget be spent on candidates that will actually be labelled instead
    of on an approximation of them.
    """
    stripped = token.rstrip("=")
    return {
        "len": len(token),
        "mod4": len(token) % 4,
        "alphabet": _alphabet(token),
        "pad_count": token.count("="),
        # `=` anywhere but the tail is illegal in every variant, and it is invisible to `mod4`:
        # `AAA=AAAA` is a clean multiple of four. This is the shape the Basic-auth length rules
        # could not see.
        "pad_interior": "=" in stripped,
        "truncated": truncated,
    }


def b64_shape(token: str | None, *, truncated: bool = False) -> dict[str, Any] | None:
    """Measure one Base64-carrying token. `None` in, `None` out; `""` is a shape, not an absence.

    ``truncated`` is the caller's fact to state and is never inferred. Real `SAMLRequest` values
    on this fleet reach 7,660 characters and `SAMLResponse` is larger, so any capture budget
    that clips the field makes `len` — and with it `mod4` — independent of what the sender sent.
    A clipped field can manufacture `mod4 == 1` out of a perfectly valid token. Only the code
    that clipped it knows, so it passes ``truncated=True`` and every consumer can discount the
    shape instead of believing it.
    """
    if token is None:
        return None
    return {**_shape_without_decode(token, truncated), "decodes": decode_b64(token) is not None}


# =========================================================================
# Carrier extractors
# =========================================================================
# Every one of these goes through `b64_shape` above. The point of collecting them in one place
# is that the per-decoy copies diverged last time and the divergence destroyed evidence.
#
# Ranked by what the fleet carries (30 days to 2026-11-18, own validation sources excluded):
# NTLM/Negotiate 168 rows from 68 sources, SAMLRequest 87 from ~58, SAMLResponse 13 from 12,
# Bearer JWT 16 from 3. NTLM and SAML are standard padded Base64 and reach
# `Base64.getDecoder()`; the JWT path measured safe (F4), so Bearer is extracted to be graded
# down, not to be alarmed on.

_AUTH_HEADERS = ("authorization", "proxy-authorization")
_HEADER_SCHEMES = ("basic", "ntlm", "negotiate", "bearer")
_SAML_PARAMS = {"SAMLRequest": "saml_request", "SAMLResponse": "saml_response"}
_BST_NAME = "binarysecuritytoken"
#: How much of one element's start tag is searched for the name. A real token element carries
#: `EncodingType` and `ValueType` and stays under ~300 characters; this bound is only here so a
#: single enormous "tag" cannot turn one iteration into a long substring search.
_BST_TAG_SCAN = 1024
#: The name itself, found case-insensitively in one pass. The scan is driven by this rather
#: than by tag positions, which is what makes padding free: a `>` or a `<` that is not near an
#: occurrence costs nothing, and cannot hide an element behind it either.
_BST_PRESENT_RE = re.compile(_BST_NAME, re.IGNORECASE)
_WS_RE = re.compile(r"\s+")

#: A JWT has three dot-separated segments and a JWE has five. Past that the value is not a
#: token being parsed, and the count is the sender's to choose: a `Bearer` header with 20,000
#: dots produced 20,000 shape dicts in one event, measured.
MAX_BEARER_SEGMENTS = 5
#: Records one request may contribute. A 68 KB SOAP body of 1,200 `BinarySecurityToken`
#: elements produced 1,200 of them. Same reasoning `body_capture` already applies to `payload`:
#: an attacker-chosen length is a way to fill the disk.
MAX_CARRIERS = 16
#: How many body elements are listed as candidates. A **backstop**, not a budget: it is applied
#: in document order, before anything is ranked, so whatever it drops is dropped blindly. At
#: 4,096 that made it the last place to hide evidence — the SharePoint decoy retains up to
#: 768 KB for a confirmed stage-two `__VIEWSTATE`, a minimal token element is 28 characters, so
#: that body holds 28,086 of them, and 5,000 harmless ones ahead of the real one already
#: dropped it (measured). It is now above what any configured budget can hold, with
#: `test_the_listing_cap_is_not_reachable_under_any_configured_budget` guarding the
#: relationship, and exists only so the code cannot be driven unbounded if a budget is raised.
#: The price of not capping below that is linear and measured: 5.4 ms at 64 KB, 45.7 ms at
#: 535 KB, for a body made of nothing but token elements.
MAX_BODY_CANDIDATES = 65536


def _params(blob: str, name: str) -> list[tuple[str, bool]]:
    """**Every** value this parameter has, percent-decoded and nothing else.

    Every, not the first: reading one value was a bypass. `SAMLRequest=QQ%3D%3D` followed by
    `SAMLRequest=<trigger>` missed the trigger, and which value the receiving application uses
    is not ours to guess — Tomcat takes the first, other stacks take the last, some
    concatenate. The one that reaches `java.util.Base64` is whichever the server picks.

    `+` is deliberately NOT translated to a space. The HTML form rule says it should be, but in
    a Base64-valued parameter `+` is one of the 64 characters, and translating it changes the
    token's length and therefore its `mod4`. A conformant sender percent-encodes a literal `+`
    as `%2B`, where both readings agree; a sender who does not is handing us Base64, not prose.
    """
    pattern = re.compile(r"(?:^|[?&;])" + re.escape(name) + r"=([^&;#]*)", re.IGNORECASE)
    out: list[tuple[str, bool]] = []
    for match in pattern.finditer(blob):
        if len(out) >= MAX_BODY_CANDIDATES:
            break
        # A value that ends where the captured text ends has no separator after it, so the
        # capture ceiling may have cut it. One that is followed by `&`, `;` or `#` is whole,
        # whatever the ceiling did to the rest of the body.
        out.append((unquote(match[1]), match.end() >= len(blob)))
    return out


def _header_carriers(headers: dict) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in _AUTH_HEADERS:
        value = lowered.get(name)
        if not isinstance(value, str):
            continue
        # Any whitespace, not a single space. RFC 7235 writes `1*SP`, so `Basic\t<blob>` is
        # non-conformant — but whether Tomcat's `BasicAuthenticator` accepts one is not
        # something this code can know, and the asymmetry is not close: being more permissive
        # than the server costs a carrier whose own shape then decides whether it means
        # anything, while being less permissive costs a bypass. Both a tab and an obs-folded
        # continuation recorded nothing before this, measured.
        parts = value.split(None, 1)
        if len(parts) < 2:
            continue
        scheme = parts[0].lower()
        if scheme not in _HEADER_SCHEMES:
            continue
        token = parts[1].strip()
        if not token:
            continue
        if scheme != "bearer":
            out.append({"carrier": scheme, "token": token})
            continue
        # A JWT is dot-separated and each segment is decoded separately, so a `mod4` over the
        # whole token is meaningless. An opaque Bearer splits into one segment and gets its own
        # carrier name, because RFC 6750's `b64token` is a syntax for an opaque string rather
        # than an encoding: its length says nothing, and 46 rows on this fleet would have been
        # labelled on it. See `LENGTH_GRADED_CARRIERS`.
        segments = token.split(".")
        carrier = "bearer" if len(segments) > 1 else "bearer_opaque"
        for index, segment in enumerate(segments[:MAX_BEARER_SEGMENTS]):
            out.append({"carrier": carrier, "segment": index, "token": segment})
    return out


def _param_carriers(blob: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, carrier in _SAML_PARAMS.items():
        out += [
            {"carrier": carrier, "token": token, "maybe_cut": cut}
            for token, cut in _params(blob, name)
        ]
    # `Signature=` is only a carrier inside a SAML exchange. On its own it is too generic —
    # `X-Amz-Signature=` is a hex SigV4 value — and the gate is the parameter list, which an
    # extractor has and a text rule does not. That is the whole reason this lives here.
    if out:
        out += [
            {"carrier": "saml_signature", "token": t, "maybe_cut": cut}
            for t, cut in _params(blob, "Signature")
        ]
    return out


def _bst_tokens(body: str) -> list[tuple[str, bool]]:
    """Every `BinarySecurityToken` element's raw text, with whether it may have been cut.

    Four earlier shapes of this function each failed on an input the one before it did not try,
    and the pattern in the failures is the lesson: every bound added against a cost became a
    place to hide evidence.

    1. ``<[^<>]*BinarySecurityToken[^<>]*>([^<]*)<`` was **quadratic on repeated exact
       matches** — ``"<" + "BinarySecurityToken" * N`` measured 0.17 ms at N=50 against
       41.23 ms at N=800, extrapolating to ~760 ms at the 64 KB ceiling. Near-miss bodies are
       linear, which is why measuring only those gave the wrong verdict.
    2. Walking `<` positions re-searched for the same `>` from each: 67.76 ms on
       ``"<" * 65536 + ">"``. Caching it left 14.7 ms of loop overhead on ``"><" * 32768``.
    3. Capping the walk at 2,048 tags bounded that and **dropped a real element hidden behind
       the padding** — zero carriers, measured.
    4. Driving from the name fixed all of those and left a bounded forward search for `>`,
       which was the same mistake once more: **1,100 characters of attributes hid the
       element**, where 1,000 did not.

    So the forward search is unbounded, and linear by a monotonic cache: name occurrences
    arrive in order, so a cached `>` already past the current name is still the first one after
    it, and a fresh search always begins after the cached position — the scans never overlap.

    The backward search stays bounded, and that is correct rather than a remaining hole: XML
    allows nothing between `<` and the element name, so a name further than a tag's length from
    its `<` is an attribute name. A Java XML parser would not see an element there either.
    """
    out: list[tuple[str, bool]] = []
    gt = -1
    skip_to = 0
    for match in _BST_PRESENT_RE.finditer(body):
        if len(out) >= MAX_BODY_CANDIDATES:
            break
        at = match.start()
        # Occurrences inside an element already recorded: a second copy of the name in the same
        # start tag used to produce a second identical record, three for three and sixteen for
        # fifty. One element, one record.
        if at < skip_to:
            continue
        lt = body.rfind("<", max(0, at - _BST_TAG_SCAN), at)
        if lt < 0 or ">" in body[lt:at]:
            continue
        # A closing tag carries the same name and is not an element. The original regex matched
        # those too and then hid it by consuming the following `<`, so it reported one candidate
        # per *pair* and looked right by accident.
        if body[lt + 1 : lt + 2] == "/":
            continue
        if gt <= at:
            gt = body.find(">", match.end())
            if gt < 0:
                break
        end = body.find("<", gt + 1)
        # The element's whole text. There is no clip here and there must not be: the token is
        # never stored — only its shape is — so a clip bounded shaping work and nothing else,
        # while setting `truncated` and suppressing the grading. Measured: 16,000 spaces of
        # legal MIME folding after the 65-character trigger still graded and 20,000 did not.
        # The work is proportional to the element's text, and elements do not overlap.
        # No closing `<` means the element's text ran to the end of what was captured, so the
        # ceiling may have cut it. One that found its terminator is whole.
        out.append((body[gt + 1 :], True) if end < 0 else (body[gt + 1 : end], False))
        skip_to = gt + 1
    return out


def _body_carriers(body: str) -> list[dict[str, Any]]:
    out = _param_carriers(body)
    for raw, maybe_cut in _bst_tokens(body):
        # XML character data may be folded across lines, so whitespace here is transport, not
        # token. Collapsing it cannot turn a valid token malformed — it restores the original.
        out.append(
            {
                "carrier": "binary_security_token",
                "token": _WS_RE.sub("", raw),
                "maybe_cut": maybe_cut,
            }
        )
    return out


def _candidates(headers: dict | None, query: str | None, body: str | None) -> list[dict[str, Any]]:
    """The tokens one request offers, before any of them is measured.

    Separated from the shaping so the caps can be applied to the *candidate* list: building
    20,000 shape dictionaries and then throwing away 19,984 of them is the cost the cap exists
    to avoid.
    """
    found: list[dict[str, Any]] = []
    if headers:
        found += _header_carriers(headers)
    if query:
        found += _param_carriers(query)
    if body:
        found += _body_carriers(body)
    return found


def fair_slice(items: list[dict[str, Any]], limit: int = MAX_CARRIERS) -> list[dict[str, Any]]:
    """At most ``limit`` records, round-robin by carrier so no carrier can crowd out another.

    First-come-first-served was a working detection bypass, measured: 1,200 harmless
    `BinarySecurityToken` elements in a body filled all 16 slots in arrival order, the `basic`
    carrier holding the real 65-character trigger was dropped, and the event lost its
    `CVE_2026_114938` label entirely — while the same header with an ordinary body was
    labelled. Ranking headers above bodies would have closed that one case and left the next
    one, a stuffed body against a stuffed query string, wide open.

    Carriers keep their first-appearance order, and with nine possible carrier names against a
    limit of sixteen, every carrier present is guaranteed a slot.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        groups.setdefault(str(item.get("carrier", "")), []).append(item)
    out: list[dict[str, Any]] = []
    depth = 0
    while len(out) < limit:
        progressed = False
        for bucket in groups.values():
            if depth < len(bucket):
                out.append(bucket[depth])
                progressed = True
                if len(out) >= limit:
                    break
        if not progressed:
            break
        depth += 1
    return out


def _candidate_rank(item: dict[str, Any], truncated: bool) -> int:
    """0 for the shape that fires, 1 for any other verdict, 2 for a token with no verdict.

    This is `shape_verdict` itself rather than a cheap imitation of it. The imitation said yes
    to anything with `mod4 == 1`, and `shape_verdict` says no to a token whose characters are
    not Base64 at all — so 20 elements holding `!!!!!` filled the budget and dropped the real
    one, measured. Exact is also affordable: no decode is needed, because none of the gates
    reads `decodes`.
    """
    cut = truncated and bool(item.get("maybe_cut", False))
    verdict = shape_verdict(_shape_without_decode(str(item.get("token") or ""), cut))
    if verdict is None:
        return 2
    return 0 if verdict == VERDICT_FIRES else 1


def _shape_candidates(
    found: list[dict[str, Any]], truncated: bool, limit: int = MAX_CARRIERS
) -> list[dict[str, Any]]:
    # Graded candidates first. Spending the budget in arrival order was the last way to hide
    # evidence and the cheapest to reach: 20 harmless `BinarySecurityToken` elements ahead of
    # the real one dropped it, measured, and `fair_slice` could not help because the siblings
    # were the same carrier. Priority, not exclusivity — the ordinary records fill what is left,
    # because the shape of a valid token is evidence too.
    tiers: tuple[list[dict[str, Any]], ...] = ([], [], [])
    for item in found:
        tiers[_candidate_rank(item, truncated)].append(item)
    chosen: list[dict[str, Any]] = []
    for tier in tiers:
        if len(chosen) >= limit:
            break
        chosen += fair_slice(tier, limit - len(chosen))
    records = []
    for item in chosen:
        item = dict(item)
        # Per token, not per body. A truncated body used to discount every carrier it held,
        # which made "trigger first, then 100 KB of padding" the cheapest bypass in the set: the
        # token was captured whole, its length was exact, and the grading was suppressed anyway.
        maybe_cut = bool(item.pop("maybe_cut", False))
        shape = b64_shape(item.pop("token"), truncated=truncated and maybe_cut)
        records.append({**item, "shape": shape})
    return records


def carrier_shapes(
    headers: dict | None = None,
    query: str | None = None,
    body: str | None = None,
    *,
    truncated: bool = False,
) -> list[dict[str, Any]]:
    """Every Base64-carrying token in one request, each measured by `b64_shape`, capped.

    Returns a list of ``{"carrier": str, "shape": dict}``, with ``"segment"`` added for the
    dot-separated parts of a Bearer token. A list rather than a dict because one request can
    carry several segments of one carrier, and because the order is the order we found them.
    At most `MAX_CARRIERS`; use `request_carriers` when the caller needs to know what was
    dropped.

    ``truncated`` applies to every shape the call produces: if any field reaching this function
    was clipped by a capture budget, no shape from it can be trusted on length.
    """
    return _shape_candidates(_candidates(headers, query, body), truncated)


# =========================================================================
# Grading
# =========================================================================

#: The shape that fires on the build the PoC measured (F5: `AdjProbe8/9` — 129, 193 and 259
#: with every malformed tail measured zero fires). Scored critical.
VERDICT_FIRES = "java4shell_b64_fires_65"
#: Impossible Base64 at some other length: the sweep that decides whether to send the real one.
VERDICT_SWEEP = "java4shell_b64_malformed_length"
#: `=` before a non-`=` character, or more than two pad characters. Illegal in every variant and
#: invisible to `mod4` — `AAA=AAAA` is a clean multiple of four.
VERDICT_PADDING = "java4shell_b64_illegal_padding"

_FIRING_LENGTH = 65

#: Carriers whose value is Base64 **by specification**, so its length modulo 4 is evidence.
#: `bearer` here means one dot-separated segment of a JWT, which is base64url by definition —
#: measured across all 21 segments of the 7 distinct real JWTs on this fleet, `mod4` is 0, 2 or
#: 3 and never 1. `bearer_opaque` is deliberately absent: RFC 6750's `b64token` is a syntax for
#: an opaque string, not an encoding, so its length carries nothing. Measured: 46 fleet rows of
#: opaque Bearer values are `mod4 == 1`, and grading them would have labelled every one.
LENGTH_GRADED_CARRIERS = frozenset(
    {
        "basic",
        "ntlm",
        "negotiate",
        "bearer",
        "saml_request",
        "saml_response",
        "saml_signature",
        "binary_security_token",
    }
)


def shape_verdict(shape: dict[str, Any] | None, carrier: str | None = None) -> str | None:
    """Grade one measured shape, or `None` if there is nothing to say about it.

    The grading lives here rather than in the rule set because two of the four carriers arrive
    transport-encoded — `SAMLRequest` percent-encodes `=` as `%3D`, `BinarySecurityToken` folds
    across lines — and a text rule counting characters on the wire form measures the encoding
    instead of the token. On this fleet that is not hypothetical: 52 SAMLRequest rows from 29
    sources read `mod4 == 2` purely because of `%3D`, and an attacker who writes padding that
    way reads back as `mod4 == 0`.

    The length gates are suppressed for two kinds of field and the padding gates are not. A
    clipped field, because clipping decides the length; and a field whose value is not Base64
    by specification, named by ``carrier`` and checked against `LENGTH_GRADED_CARRIERS` — an
    opaque Bearer token has no reason to be a multiple of four and 46 fleet rows prove it.
    Passing no ``carrier`` asserts that the caller knows the field is Base64.

    For clipping the asymmetry is not a compromise: clipping removes a tail, so it can only lower `pad_count`
    and can never move a `=` into the interior. An illegal pad that survived clipping is one
    the sender sent. A length, once clipped, says nothing about the sender at all.
    """
    if not isinstance(shape, dict) or not shape:
        return None
    if shape.get("alphabet") == "invalid":
        return None
    # Read with `.get`, not `[]`: this dict round-trips through a decoy's JSON log and the
    # ingest queue before it gets here, so a missing key is a malformed record to ignore and
    # not an exception to raise inside classification.
    if shape.get("pad_interior") or (shape.get("pad_count") or 0) >= 3:
        return VERDICT_PADDING
    if shape.get("truncated"):
        return None
    if carrier is not None and carrier not in LENGTH_GRADED_CARRIERS:
        return None
    if shape.get("mod4") == 1:
        return VERDICT_FIRES if shape.get("len") == _FIRING_LENGTH else VERDICT_SWEEP
    return None


def request_carriers(
    headers: dict | None = None,
    query: str | None = None,
    body: str | None = None,
    *,
    body_truncated: bool = False,
) -> dict[str, Any]:
    """The fields describing one request's Base64 carriers, ready to splat into an event.

    The single entry point for a decoy, and the reason it exists is that the truncation flag is
    **per source**. A body ceiling clips the body; headers and the query string arrive whole.
    Marking a header shape truncated would discard a sound length, and marking a clipped body
    shape sound would invent one — so the two are measured in separate calls and joined here.

    Returns `{}` when the request carries nothing, so an ordinary request gains no field. When
    the cap drops records, `b64_carriers_dropped` says how many: silently keeping 16 of 1,200
    would make the row read like a request that carried 16.

    That count is a **lower bound**: listing candidates is itself bounded, by
    `MAX_BODY_CANDIDATES` elements per body and `MAX_BEARER_SEGMENTS` segments per Bearer
    value, so the number is what was listed minus what was kept. It cannot over-report, which
    is the direction that matters — a row never claims to have dropped more than it saw.
    """
    found = _candidates(headers, query, None)
    records = _shape_candidates(found, truncated=False)
    body_found: list[dict[str, Any]] = _candidates(None, None, body) if body else []
    # `limit=`, not a prefix slice. Slicing the candidate list here cut the real element off
    # the end before `_shape_candidates` could prefer it: 300 harmless siblings ahead of it
    # were enough, measured end to end through `body_capture.capture`.
    remaining = max(0, MAX_CARRIERS - len(records))
    records += _shape_candidates(body_found, truncated=body_truncated, limit=remaining)
    if not records:
        return {}
    out: dict[str, Any] = {"b64_carriers": records}
    dropped = (len(found) + len(body_found)) - len(records)
    if dropped > 0:
        out["b64_carriers_dropped"] = dropped
    return out


def add_carriers(event: dict[str, Any], fields: dict[str, Any]) -> None:
    """Merge one `request_carriers` result into an event that may already carry some.

    Exists because `event.update(a); event.update(b)` loses `a`'s carriers to `b`'s, and two
    producers per event is the normal case rather than the exception: a decoy gets the body and
    the path from `body_capture.capture` and the headers from its own header dict. The k8s
    decoy had exactly that bug for the length of one edit — the body's `saml_response` vanished
    behind the header's `basic` — which is why the merge is a named function and not a line
    repeated at each call site.

    Adds nothing when there is nothing, so an ordinary request gains no field. The cap applies
    to the merged list and the dropped counts add up, because a row that says it carried 16
    when 1,201 arrived is a row that misreports the request.
    """
    if not fields:
        return
    merged = [*event.get("b64_carriers", []), *fields.get("b64_carriers", [])]
    if not merged:
        return
    # `fair_slice`, not a prefix: merging in arrival order let a stuffed body spend the
    # headers' budget and drop the evidence.
    kept = fair_slice(merged)
    event["b64_carriers"] = kept
    dropped = (
        event.get("b64_carriers_dropped", 0)
        + fields.get("b64_carriers_dropped", 0)
        + (len(merged) - len(kept))
    )
    if dropped:
        event["b64_carriers_dropped"] = dropped
