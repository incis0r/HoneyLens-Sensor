"""Caps on what one request can make us shape and store, and no raw blob anywhere.

All three pinned here came out of a security review of the carrier work, and two of them were
measured rather than argued:

* A `Bearer` value with 20,000 dots produced **20,000 shape dicts in one event** (20 ms of
  shaping), and a 68 KB body of 1,200 `BinarySecurityToken` elements produced 1,200 records.
  Both lengths are the attacker's to choose. `body_capture` already carries the same reasoning
  for `payload`: "a decoy that writes an attacker-chosen string of unbounded length is a way to
  fill the disk".
* The `BinarySecurityToken` pattern was reported as a ReDoS and is not one — measured linear,
  0.12 ms at 8 KB against 1.05 ms at 65 KB on the worst near-match body. The real gap was that
  the cost test contained no `<` at all, so it exercised nothing. It does now.
"""

import time

from honeylens.b64_shape import (
    MAX_BEARER_SEGMENTS,
    MAX_CARRIERS,
    carrier_shapes,
    request_carriers,
    shape_verdict,
)


def test_a_bearer_token_cannot_make_us_shape_twenty_thousand_segments():
    token = ".".join(["AAAA"] * 20000)
    records = carrier_shapes(headers={"authorization": f"Bearer {token}"})
    assert len(records) <= MAX_BEARER_SEGMENTS
    # A JWT has 3 segments and a JWE has 5. Anything past that is not a token being parsed.
    assert MAX_BEARER_SEGMENTS == 5


def test_a_soap_body_cannot_make_us_store_a_record_per_element():
    body = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>" * 1200
    assert len(carrier_shapes(body=body)) <= MAX_CARRIERS


def test_the_total_is_capped_and_the_drop_is_stated():
    """`b64_carriers_dropped` is a **lower bound**, and that is the honest reading.

    Listing candidates is itself bounded, by `MAX_BODY_CANDIDATES` per body, so the count
    reports what was listed minus what was kept. It cannot over-report, which is the direction
    that matters: a row never claims to have dropped more than it saw. A body of 1,200
    elements is well inside that bound, so here the count is exact.
    """
    body = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>" * 1200
    fields = request_carriers(body=body)
    assert len(fields["b64_carriers"]) == MAX_CARRIERS
    assert fields["b64_carriers_dropped"] == 1200 - MAX_CARRIERS
    # Silently keeping 16 and saying nothing would make the row read like a request that
    # carried 16.
    assert fields["b64_carriers_dropped"] > 0


def test_nothing_is_dropped_when_nothing_overflows():
    fields = request_carriers(headers={"authorization": "Basic QQ=="})
    assert len(fields["b64_carriers"]) == 1
    assert "b64_carriers_dropped" not in fields


def test_a_huge_token_is_measured_at_its_real_length():
    """Superseded the 8 KB clip, which was a bypass in two directions.

    The token is never stored — only its shape is — so the clip bounded shaping work and
    nothing else, and that work is proportional to the element text, which is bounded by the
    body. Reporting a length we chose, and setting `truncated` for it, threw away a sound
    measurement: `truncated` now means only what it says, that the **body** was clipped and the
    sender's length is therefore unknown.
    """
    huge = "<wsse:BinarySecurityToken>" + "A" * 60000 + "</wsse:BinarySecurityToken>"
    shape = carrier_shapes(body=huge)[0]["shape"]
    assert shape["len"] == 60000
    assert shape["truncated"] is False


def test_the_binary_security_token_scan_is_linear_on_an_adversarial_body():
    """The bodies that were claimed to be quadratic. Doubling the input must not more than
    roughly double the time; a return to quadratic shows up as orders of magnitude."""
    timings = {}
    for size in (8192, 65536):
        body = "<" + "B" * size  # the worst near-match prefix: every backtrack starts with 'B'
        start = time.perf_counter()
        carrier_shapes(body=body)
        timings[size] = time.perf_counter() - start
    assert timings[65536] < 0.25
    # 8x the input, far less than 8^2 the time.
    assert timings[65536] < max(timings[8192], 1e-4) * 24


def test_a_body_of_almost_matching_tags_is_bounded():
    body = ("<x:BinarySecurityTokez" + "a" * 500) * 120
    start = time.perf_counter()
    carrier_shapes(body=body)
    assert (time.perf_counter() - start) < 0.25


# ------------------------------------------------- merging, because two sources per event is
# ------------------------------------------------- the normal case and `dict.update` loses one


def test_merging_keeps_both_sources():
    """A decoy with a body and a header dict calls two different producers, and
    `ev.update(a); ev.update(b)` silently drops `a`'s carriers — measured on the k8s decoy,
    where the body's `saml_response` disappeared behind the header's `basic`."""
    from honeylens.b64_shape import add_carriers

    event: dict = {}
    add_carriers(event, request_carriers(body=f"SAMLResponse={'A' * 64}="))
    add_carriers(event, request_carriers(headers={"authorization": f"Basic {'A' * 64}="}))
    assert [r["carrier"] for r in event["b64_carriers"]] == ["saml_response", "basic"]


def test_merging_respects_the_cap_and_sums_the_drops():
    from honeylens.b64_shape import add_carriers

    body = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>" * 1200
    event: dict = {}
    add_carriers(event, request_carriers(body=body))
    add_carriers(event, request_carriers(headers={"authorization": "Basic QQ=="}))
    assert len(event["b64_carriers"]) == MAX_CARRIERS
    # 1,200 body candidates plus the one header carrier, of which MAX_CARRIERS survive.
    assert event["b64_carriers_dropped"] == 1201 - MAX_CARRIERS


def test_merging_nothing_adds_nothing():
    from honeylens.b64_shape import add_carriers

    event: dict = {"method": "GET"}
    add_carriers(event, request_carriers(headers={"user-agent": "curl/8.5.0"}))
    assert event == {"method": "GET"}


# ------------------------------------------------- the cap turned into an evasion, and the
# ------------------------------------------------- "not a ReDoS" verdict was measured wrong


def test_a_stuffed_body_cannot_push_the_header_evidence_out():
    """A working bypass, measured: 1,200 harmless `BinarySecurityToken` elements in the body
    filled all 16 slots in arrival order, the `basic` carrier holding the real 65-character
    trigger was dropped, and the event lost its `CVE_2026_114938` label entirely. The control
    — the same header with an ordinary body — was labelled.

    So the cap cannot be first-come-first-served. It is round-robin by carrier: one
    attacker-chosen source cannot spend another's budget, whatever order the decoy merges them
    in. Ranking headers above bodies would have fixed this one case and left the next one
    (a stuffed body against a stuffed query string) open.
    """
    from honeylens.b64_shape import add_carriers
    from honeylens.classification.attack_classifier import classify_event_row

    trigger = "A" * 64 + "="
    stuffing = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>" * 1200
    event: dict = {}
    add_carriers(event, request_carriers(body=stuffing))
    add_carriers(event, request_carriers(headers={"authorization": f"Basic {trigger}"}))

    carriers = [r["carrier"] for r in event["b64_carriers"]]
    assert "basic" in carriers, "the body spent the header's budget"
    hits = classify_event_row("POST /api/v1/pods", "HTTP", event)
    assert "CVE_2026_114938" in {t for t, _r, _s in hits}


def test_every_carrier_present_keeps_at_least_one_slot():
    from honeylens.b64_shape import add_carriers

    event: dict = {}
    add_carriers(event, request_carriers(body="<x:BinarySecurityToken>QQ==</x:B><" * 40))
    add_carriers(event, request_carriers(query="SAMLRequest=QQ%3D%3D&Signature=QUJD"))
    add_carriers(event, request_carriers(headers={"authorization": "NTLM QQ=="}))
    kept = {r["carrier"] for r in event["b64_carriers"]}
    assert {"binary_security_token", "saml_request", "saml_signature", "ntlm"} <= kept


def test_the_binary_security_token_scan_is_linear_on_repeated_exact_matches():
    """The input the first cost test missed, and the reason its verdict was wrong.

    Near-miss bodies are linear and were measured as such. **Repeated exact matches with no
    closing `>` were quadratic**: with the old pattern, `'<' + 'BinarySecurityToken' * N`
    measured 0.17 ms at N=50, 0.65 at 100, 2.60 at 200, 10.12 at 400 and 41.23 ms at 800 —
    4x the time for 2x the input, which extrapolates to roughly 760 ms per request at the
    64 KB capture ceiling, on the event loop, with the attacker choosing N.
    """
    timings = {}
    for n in (200, 800):
        body = "<" + "BinarySecurityToken" * n
        start = time.perf_counter()
        carrier_shapes(body=body)
        timings[n] = time.perf_counter() - start
    assert timings[800] < 0.05
    # 4x the input. Quadratic would be ~16x the time; allow 8x for noise on a small base.
    assert timings[800] < max(timings[200], 1e-5) * 8


def test_the_scan_is_bounded_at_the_capture_ceiling():
    from honeylens.honeypots.body_capture import MAX_CAPTURE

    body = "<" + "BinarySecurityToken" * (MAX_CAPTURE // 19)
    start = time.perf_counter()
    carrier_shapes(body=body)
    assert (time.perf_counter() - start) < 0.1


def test_a_closing_tag_is_not_an_element():
    """The index scan counts start tags. `</wsse:BinarySecurityToken>` carries the same name,
    and the regex this replaced matched those too — then hid it by consuming the following `<`,
    so it reported one candidate per *pair* and looked correct by accident."""
    one = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    assert len(carrier_shapes(body=one)) == 1
    assert len(carrier_shapes(body=one * 3)) == 3


# ------------------------------------------------- round three: the index scan had its own two
# ------------------------------------------------- problems, and one was a one-character bypass


def test_lowercasing_the_whole_body_shifted_the_indices():
    """A one-character detection bypass, measured.

    `str.lower()` is not length-preserving in Unicode: `'\\u0130'` (LATIN CAPITAL LETTER I WITH
    DOT ABOVE) lowercases to two code points. The scan took indices from `body` and read them
    out of `body.lower()`, so a single such character anywhere earlier in the body shifted
    every later window by one and the tag name fell outside it — one carrier became zero.

    The window is now lowercased on its own, from `body`'s own indices, and nothing does index
    arithmetic on a case-folded string.
    """
    element = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    assert len(carrier_shapes(body=element)) == 1
    for prefix in ["İ", "İ" * 3, "ıİ", "İ<x>"]:
        assert len(carrier_shapes(body=prefix + element)) == 1, repr(prefix)


def test_the_tag_name_is_still_matched_whatever_its_case():
    for tag in [
        "BinarySecurityToken",
        "binarysecuritytoken",
        "BINARYSECURITYTOKEN",
        "BinarySecurityTOKEN",
    ]:
        body = f"<wsse:{tag}>QQ==</wsse:{tag}>"
        assert len(carrier_shapes(body=body)) == 1, tag


def test_a_body_of_unclosed_tags_does_not_restart_the_scan():
    """`'<' * N + '>'` re-searched for the same `>` from every `<`. Measured before the fix:
    0.78 ms at N=2,000 against 21.37 ms at N=32,000 — 16x the input for 27x the time."""
    timings = {}
    for n in (4000, 32000):
        body = "<" * n + ">"
        start = time.perf_counter()
        carrier_shapes(body=body)
        timings[n] = time.perf_counter() - start
    assert timings[32000] < 0.01
    # 8x the input; measured 14x before the fix, and quadratic would be ~64x.
    assert timings[32000] < max(timings[4000], 1e-5) * 10


def test_the_unclosed_tag_body_is_bounded_at_the_capture_ceiling():
    from honeylens.honeypots.body_capture import MAX_CAPTURE

    start = time.perf_counter()
    carrier_shapes(body="<" * MAX_CAPTURE + ">")
    # 67.76 ms when every `<` re-searched for the same `>`; 14.7 ms once that was cached but the
    # loop still visited all 65,536 of them; and only the **last** `<` before a `>` can open a
    # tag, so one `rfind` settles the whole body. On the event loop, length attacker-chosen.
    assert (time.perf_counter() - start) < 0.005


def test_a_body_without_the_name_is_not_walked_at_all():
    """Driving the scan by `>` left one body costly: `"><" * 32768` measured 14.67 ms, one
    loop iteration per `>`. Nothing in it can match, and a single case-insensitive literal
    search settles that before the walk starts."""
    body = "><" * 32768
    start = time.perf_counter()
    assert carrier_shapes(body=body) == []
    assert (time.perf_counter() - start) < 0.004


def test_padding_tags_cannot_bury_a_real_element():
    """A ceiling on tags walked was my own second cap-turned-evasion: bounding it at 2,048
    start tags meant `"><" * 32768` ahead of a real token element dropped it — 0 carriers,
    measured — trading a 14.7 ms body for a trivial bypass. On a honeypot that is the wrong
    way round; detection is the product.

    So the scan is driven by the **name** instead of by the tag count: occurrences are found in
    one pass and each one is resolved by bounded local search, so padding that does not contain
    the name costs nothing and cannot hide anything behind it.
    """
    body = "><" * 32768 + "<wsse:BinarySecurityToken>" + "A" * 64 + "=</wsse:B>"
    start = time.perf_counter()
    records = carrier_shapes(body=body)
    elapsed = time.perf_counter() - start
    assert [r["carrier"] for r in records] == ["binary_security_token"]
    assert records[0]["shape"]["len"] == 65
    assert elapsed < 0.01


def test_a_token_element_inside_a_realistic_soap_envelope_is_still_found():
    envelope = (
        '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soap:Header><wsse:Security><wsu:Timestamp><wsu:Created>2026-11-18T18:00:00Z</wsu:Created>"
        "</wsu:Timestamp><wsse:BinarySecurityToken EncodingType='...#Base64Binary' "
        "ValueType='...#X509v3'>" + "A" * 64 + "=</wsse:BinarySecurityToken></wsse:Security>"
        "</soap:Header><soap:Body><ns:Ping/></soap:Body></soap:Envelope>"
    )
    records = carrier_shapes(body=envelope)
    assert [r["carrier"] for r in records] == ["binary_security_token"]
    assert records[0]["shape"]["len"] == 65


# ------------------------------------------------- round four: the bounded forward search was
# ------------------------------------------------- itself the hiding place I said I'd removed


def test_a_long_attribute_list_cannot_hide_the_element():
    """Measured: 1,000 characters of attributes kept the element, **1,100 dropped it** — the
    `>` fell outside the bounded forward search and the carrier vanished. One line to build.

    The previous commit's own conclusion was "no ceiling to hide behind", and this was a
    ceiling to hide behind. The `>` search is unbounded now, kept linear by a monotonic cache:
    occurrences arrive in order, so a cached `>` that is already past the current name is still
    the first one after it, and a fresh search always starts after the cached position.
    """
    trigger = "A" * 64 + "="
    for pad in (0, 500, 1000, 1100, 2000, 20000):
        body = f"<wsse:BinarySecurityToken {'x' * pad}>{trigger}</wsse:B>"
        records = carrier_shapes(body=body)
        assert [r["carrier"] for r in records] == ["binary_security_token"], pad
        assert records[0]["shape"]["len"] == 65, pad


def test_the_backward_search_stays_bounded_and_that_is_correct():
    """The other direction needs no such fix. XML does not allow whitespace or anything else
    between `<` and the element name, so a name more than a tag's length after its `<` is an
    *attribute* name and not an element — a Java XML parser would not see an element there
    either, so neither do we."""
    body = "<a " + "z" * 5000 + " BinarySecurityToken>QQ==<"
    assert carrier_shapes(body=body) == []


def test_the_same_name_inside_one_tag_is_one_element():
    """Measured: three occurrences in one start tag produced three identical records, and at
    fifty they filled the cap. Each name hit was resolved independently instead of each
    element being recorded once."""
    trigger = "A" * 64 + "="
    for k in (1, 3, 50):
        body = "<a " + "BinarySecurityToken " * k + f">{trigger}<"
        assert len(carrier_shapes(body=body)) == 1, k


def test_the_repeated_name_body_is_bounded_at_the_ceiling():
    from honeylens.honeypots.body_capture import MAX_CAPTURE

    body = "<a " + "BinarySecurityToken " * (MAX_CAPTURE // 20) + ">QQ==<"
    start = time.perf_counter()
    records = carrier_shapes(body=body)
    assert (time.perf_counter() - start) < 0.02
    assert len(records) == 1


def test_legal_whitespace_padding_cannot_suppress_the_grading():
    """Round five, and the sixth time one of my own bounds suppressed evidence.

    Whitespace inside Base64 is legal — MIME folding puts it there, and XML character data may
    carry it — so the collapse was always right. But the raw span was clipped at 16 KB and the
    clip set `truncated`, which `shape_verdict` reads as "this length is not the sender's".
    Measured: 16,000 spaces after the 65-character trigger still graded, **20,000 did not** —
    the shape read `len=65 mod4=1` and returned no verdict at all.

    The clip is gone. The collapse runs over the element's whole text, which is bounded by the
    body, and `truncated` comes only from the body's own ceiling.
    """
    trigger = "A" * 64 + "="
    for spaces in (0, 1000, 16000, 20000, 60000):
        body = f"<wsse:BinarySecurityToken>{trigger}{' ' * spaces}</wsse:B>"
        shape = carrier_shapes(body=body)[0]["shape"]
        assert (shape["len"], shape["mod4"]) == (65, 1), spaces
        assert shape["truncated"] is False, spaces
        assert shape_verdict(shape) == "java4shell_b64_fires_65", spaces


def test_tokens_that_can_never_be_labelled_do_not_take_slots():
    """The triage said yes to anything with `mod4 == 1`, and `shape_verdict` says no to a token
    whose characters are not Base64 at all. Measured: 20 elements holding `!!!!!` — five
    characters, `mod4 == 1`, ungradeable — filled the budget and dropped the real one.

    The triage is now `shape_verdict` itself, run on a shape computed without decoding. That is
    exact rather than approximate because **`shape_verdict` never reads `decodes`**: every gate
    it applies is a length, a padding position or an alphabet check.
    """
    trigger = "A" * 64 + "="
    junk = "<wsse:BinarySecurityToken>!!!!!</wsse:BinarySecurityToken>"
    real = f"<wsse:BinarySecurityToken>{trigger}</wsse:BinarySecurityToken>"
    for n in (5, 20, 100, 1000):
        lens = [r["shape"]["len"] for r in carrier_shapes(body=junk * n + real)]
        assert 65 in lens, n


def test_the_firing_shape_outranks_the_sweep_for_a_scarce_slot():
    """Within the graded group the budget is still finite, so order by what the verdict is
    worth: the one shape F5 measured as firing goes ahead of the rungs that cannot."""
    trigger = "A" * 64 + "="
    sweep = "<wsse:BinarySecurityToken>" + "A" * 128 + "=</wsse:BinarySecurityToken>"
    real = f"<wsse:BinarySecurityToken>{trigger}</wsse:BinarySecurityToken>"
    lens = [r["shape"]["len"] for r in carrier_shapes(body=sweep * 200 + real)]
    assert 65 in lens


# ------------------------------------------------- the last hiding place: the record budget
# ------------------------------------------------- itself, spent on harmless siblings


def test_a_real_element_cannot_be_buried_among_harmless_siblings():
    """The last bound that could hide evidence, and the cheapest to reach: **20 harmless
    `BinarySecurityToken` elements ahead of the real one dropped it** — measured, label gone —
    because the 16 record slots were spent in arrival order on siblings of the same carrier.
    `fair_slice` protects carriers from each other and did nothing within one carrier.

    So the budget goes to candidates that would be graded, first. The triage is cheap on
    purpose — length modulo four and where the `=` characters sit, no decode — and it only
    sets priority, so over-selecting costs a slot and never a verdict.
    """
    trigger = "A" * 64 + "="
    harmless = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    real = f"<wsse:BinarySecurityToken>{trigger}</wsse:BinarySecurityToken>"
    for n in (5, 20, 100, 1000):
        records = carrier_shapes(body=harmless * n + real)
        assert 65 in [r["shape"]["len"] for r in records], n


def test_the_same_holds_for_the_malformed_shapes_that_are_not_the_firing_one():
    harmless = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    for token, why in [
        ("AAA==", "the short rung"),
        ("AAA=AAAA", "interior padding"),
        ("AAAA====", "four pad characters"),
    ]:
        body = harmless * 500 + f"<wsse:BinarySecurityToken>{token}</wsse:B>"
        kept = [r["shape"] for r in carrier_shapes(body=body)]
        assert any(s["len"] == len(token) for s in kept), why


def test_a_buried_element_is_still_labelled_end_to_end():
    from honeylens.classification.attack_classifier import classify_event_row
    from honeylens.honeypots.body_capture import capture

    trigger = "A" * 64 + "="
    harmless = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    body = (harmless * 300 + f"<wsse:BinarySecurityToken>{trigger}</wsse:B>").encode()
    fields = capture(body, "/_vti_bin/webs.asmx", "text/xml")
    hits = classify_event_row("POST /_vti_bin/webs.asmx", "HTTP", fields)
    assert "java4shell_b64_fires_65" in {r for _t, r, _s in hits}


def test_priority_does_not_starve_the_ordinary_records():
    """Graded candidates go first, not exclusively: a request whose carriers are all ordinary
    still records them, because the shape of a valid token is evidence too."""
    harmless = "<wsse:BinarySecurityToken>QQ==</wsse:BinarySecurityToken>"
    assert len(carrier_shapes(body=harmless * 3)) == 3
    mixed = carrier_shapes(body=harmless * 3 + "<wsse:BinarySecurityToken>AAA==</wsse:B>")
    assert len(mixed) == 4


# ------------------------------------------------- and one level up: the listing cap itself,
# ------------------------------------------------- applied in document order before ranking


def test_the_listing_cap_is_not_reachable_under_any_configured_budget():
    """`MAX_BODY_CANDIDATES` was 4,096 and applied in **document order**, before any ranking —
    so on the decoy with the largest capture budget it was the last place to hide evidence.

    Measured: the SharePoint decoy retains up to 768 KB for a confirmed stage-two
    `__VIEWSTATE`, a minimal token element is 28 characters, so that body holds 28,086 of them.
    5,000 harmless elements ahead of the real one already dropped it.

    The cap stays, as a backstop so the code cannot be driven unbounded if a budget is raised,
    but it is set above what any configured budget can hold. This test is the guard on that
    relationship: raise a budget past it and this fails rather than the detection failing
    quietly.
    """
    from honeylens.b64_shape import MAX_BODY_CANDIDATES
    from honeylens.honeypots.body_capture import MAX_CAPTURE
    from honeylens.honeypots.honeypot_cms import capture_budget
    from honeylens.honeypots.honeypot_sharepoint import _RAW_CAPTURE, _RAW_CAPTURE_DEFAULT

    largest = max(MAX_CAPTURE, _RAW_CAPTURE, _RAW_CAPTURE_DEFAULT, capture_budget(None))
    minimal_element = len("<a:BinarySecurityToken>QQ==<")
    assert MAX_BODY_CANDIDATES > largest // minimal_element, (
        f"a {largest} byte budget holds {largest // minimal_element} elements, which the "
        f"{MAX_BODY_CANDIDATES} listing cap would silently drop"
    )


def test_thousands_of_harmless_siblings_cannot_bury_the_element():
    trigger = "A" * 64 + "="
    harmless = "<a:BinarySecurityToken>QQ==<"
    real = f"<a:BinarySecurityToken>{trigger}<"
    for n in (1000, 5000, 20000):
        records = carrier_shapes(body=harmless * n + real)
        verdicts = [shape_verdict(r["shape"]) for r in records]
        assert "java4shell_b64_fires_65" in verdicts, n


def test_the_largest_configured_body_stays_bounded():
    """768 KB of nothing but token elements. The listing is linear and this is the price of not
    having a cap that hides things: measured 5.4 ms at 64 KB and 45.7 ms at 535 KB."""
    from honeylens.honeypots.honeypot_sharepoint import _RAW_CAPTURE

    harmless = "<a:BinarySecurityToken>QQ==<"
    body = harmless * (_RAW_CAPTURE // len(harmless))
    start = time.perf_counter()
    carrier_shapes(body=body)
    assert (time.perf_counter() - start) < 0.25


# ------------------------------------------------- the simplest bypass of all: make the body
# ------------------------------------------------- ceiling fire and let it suppress everything


def test_padding_after_a_complete_token_cannot_suppress_it():
    """Found by probing, not by a review, and the cheapest bypass in the whole set: put the
    trigger first and append padding until the body ceiling fires.

    Measured before the fix: the element plus 100 KB of padding read `body_truncated=True`,
    which propagated to **every** carrier from that body, so a token captured whole with an
    exact `len=65` was not labelled. The same worked for a SAML parameter.

    `truncated` now means what it says about *that token*: a token is complete when its own
    terminator was found inside the captured sample — the element's closing `<`, or the
    parameter's `&`. Only a token that runs to the boundary can have been cut, and only that
    one has its length discounted.
    """
    from honeylens.classification.attack_classifier import classify_event_row
    from honeylens.honeypots.body_capture import capture

    trigger = "A" * 64 + "="
    element = f"<wsse:BinarySecurityToken>{trigger}</wsse:BinarySecurityToken>"
    for pad_kb in (0, 10, 100, 500):
        fields = capture((element + "x" * (pad_kb * 1024)).encode(), "/_vti_bin/webs.asmx", "")
        shape = fields["b64_carriers"][0]["shape"]
        assert (shape["len"], shape["truncated"]) == (65, False), pad_kb
        hits = classify_event_row("POST /x", "HTTP", fields)
        assert "CVE_2026_114938" in {t for t, _r, _s in hits}, pad_kb


def test_the_same_for_a_saml_parameter():
    from honeylens.classification.attack_classifier import classify_event_row
    from honeylens.honeypots.body_capture import capture

    trigger = "A" * 64 + "="
    for pad_kb in (0, 100, 500):
        body = (f"SAMLResponse={trigger}&x=" + "y" * (pad_kb * 1024)).encode()
        fields = capture(body, "/saml/login", "")
        shape = fields["b64_carriers"][0]["shape"]
        assert (shape["len"], shape["truncated"]) == (65, False), pad_kb
        hits = classify_event_row("POST /saml/login", "HTTP", fields)
        assert "CVE_2026_114938" in {t for t, _r, _s in hits}, pad_kb


def test_a_token_that_runs_to_the_boundary_is_still_discounted():
    """The flag still does its real job. A token with no terminator inside the sample may have
    been cut by the ceiling, so its length is not the sender's and must not be graded."""
    from honeylens.honeypots.body_capture import MAX_CAPTURE, capture

    # The element's text runs past the ceiling: no closing `<` is captured.
    body = ("<wsse:BinarySecurityToken>" + "A" * (MAX_CAPTURE + 100)).encode()
    fields = capture(body, "/_vti_bin/webs.asmx", "")
    assert fields["body_truncated"] is True
    assert fields["b64_carriers"][0]["shape"]["truncated"] is True

    # And the same for a parameter with no `&` after it.
    body = (f"SAMLResponse={'A' * (MAX_CAPTURE + 100)}").encode()
    fields = capture(body, "/saml/login", "")
    assert fields["b64_carriers"][0]["shape"]["truncated"] is True


def test_repeated_parameters_stay_bounded_at_the_largest_budget():
    from honeylens.honeypots.honeypot_sharepoint import _RAW_CAPTURE

    one = "SAMLRequest=QQ%3D%3D&"
    body = one * (_RAW_CAPTURE // len(one))
    start = time.perf_counter()
    carrier_shapes(body=body)
    # Measured 110.8 ms for 37,450 parameters in 768 KB; the bound catches a change of shape.
    assert (time.perf_counter() - start) < 0.4
