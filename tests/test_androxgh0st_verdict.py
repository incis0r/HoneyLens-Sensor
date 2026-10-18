"""AndroxGh0st's twenty-byte probe gets a verdict, and it is reconnaissance.

B4b. The internal AndroxGh0st IOC notes: AndroxGh0st (CISA AA24-016A) opens against a new address
with a single `POST /` carrying a twenty-byte constant body — `0x%5B%5D=androxgh0st`, which is
`0x[]=androxgh0st` URL-encoded, a PHP array-parameter trick that tests whether the target parses the
body as PHP input. Over 30 days the fleet took **1,402 of them from 20+ addresses and every single
row has an empty `attack_types`**: sensor-a 732, sensor-b 645, sensor-c 22, sensor-e 3, labelled 0,
0, 0, 0. It arrived four times in the 24 hours before the sheet was written.

Two rules, because the sheet's §5 asks for two detections and they are not the same claim:

* the byte-identical constant is the fingerprint — a 20-byte literal that cannot false-positive;
* the botnet's name anywhere in a body or query is the fallback, and on its own it says only
  that the name went past, which is reconnaissance and nothing more.

The exact probe satisfies both, so it comes back `ANDROXGH0ST,RECON` exactly as the sheet
specifies, and the fallback alone comes back `RECON`.

**Low, not high.** Nothing in that body executes anything: §5.3 names the mistake to avoid as the
`sp-webshell-aspx` one — a HIGH verdict claiming more than the evidence carries. The probe also
arrives alone on this fleet; no `.env` sweep follows from the same address in the same minute,
because our decoys do not answer like a PHP app.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import get_severity

# §4 — byte-identical on every capture, no padding, no variation, no parameters.
PROBE_BODY = "0x%5B%5D=androxgh0st"
PROBE_BODY_DECODED = "0x[]=androxgh0st"

# §4 — the full request, as the decoys receive it. The UA is a stale Chrome 81 on Linux and is
# a weak secondary at best, so no rule keys on it.
PROBE_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/81.0.4044.129 Safari/537.36"
)


def _decoy_row(body: str, *, port: int = 443, path: str = "/", method: str = "POST"):
    meta = {
        "method": method,
        "path": path,
        "port": port,
        "headers": {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
            "user-agent": PROBE_UA,
            "accept-encoding": "gzip, deflate",
        },
        "body_sample": body,
        "body_len": len(body),
        "user_agent": PROBE_UA,
    }
    payload = f"{method} {path} body_len={len(body)}\n{body}"
    return classify_event_row(payload, "http", meta)


def _raw_row(body: str):
    head = (
        "POST / HTTP/1.1\r\nAccept: */*\r\nConnection: keep-alive\r\n"
        f"User-Agent: {PROBE_UA}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nAccept-Encoding: gzip, deflate\r\n\r\n{body}"
    )
    return classify_event_row(head, "http", {"dst_port": 443})


def _types(hits) -> set[str]:
    return {h[0] for h in hits}


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


# ---------------------------------------------------------------------------
# The fingerprint
# ---------------------------------------------------------------------------


def test_the_twenty_byte_probe_is_named():
    """1,402 rows across four sensors, every one of them with an empty `attack_types`."""
    hits = _decoy_row(PROBE_BODY)

    assert "ANDROXGH0ST" in _types(hits)
    assert "androxgh0st_probe_body" in _rules(hits)


def test_the_verdict_is_the_pair_the_sheet_specifies():
    """§5.1: `ANDROXGH0ST,RECON`. The name is what it is; recon is what it did."""
    assert {"ANDROXGH0ST", "RECON"} <= _types(_decoy_row(PROBE_BODY))


def test_the_decoded_form_is_the_same_probe():
    """`0x[]=androxgh0st` — the classifier decodes bodies, and a sender may not encode."""
    assert "ANDROXGH0ST" in _types(_decoy_row(PROBE_BODY_DECODED))


def test_the_probe_is_reconnaissance_not_exploitation():
    """§5.3. Nothing in a twenty-byte body executes anything, and claiming otherwise is the
    `sp-webshell-aspx` error: a HIGH verdict on a bare GET of a path."""
    assert get_severity("ANDROXGH0ST", "androxgh0st_probe_body") == "low"


def test_the_capture_path_sees_the_same_probe():
    """sensor-a and sensor-b have Suricata; sensor-c and sensor-e have only the decoy row."""
    assert "ANDROXGH0ST" in _types(_raw_row(PROBE_BODY))


@pytest.mark.parametrize("port", [80, 443, 8080, 8888])
def test_the_probe_is_not_port_gated(port):
    """netscaler and http on sensor-a, netscaler on sensor-b, sharepoint on its alternate HTTP port on sensor-c and sensor-e."""
    assert "ANDROXGH0ST" in _types(_decoy_row(PROBE_BODY, port=port))


# ---------------------------------------------------------------------------
# The fallback claims less
# ---------------------------------------------------------------------------


def test_the_name_alone_is_recon_and_not_the_fingerprint():
    """§5.2 asks for the substring as a fallback. It is a weaker claim and must stay weaker:
    seeing the name is not seeing the twenty-byte probe."""
    hits = _decoy_row("tool=androxgh0st&target=x")

    assert "RECON" in _types(hits)
    assert "androxgh0st_named_token" in _rules(hits)
    assert "ANDROXGH0ST" not in _types(hits)


def test_the_name_in_a_query_string_counts():
    hits = _decoy_row("x=1", path="/index.php?mode=androxgh0st", method="GET")

    assert "RECON" in _types(hits)


def test_the_fallback_is_case_insensitive():
    assert "RECON" in _types(_decoy_row("AndroxGh0st=1"))


# ---------------------------------------------------------------------------
# Nothing else moves
# ---------------------------------------------------------------------------


def test_a_php_array_parameter_on_its_own_is_not_this_botnet():
    """`0x[]=` is a PHP array-parameter trick, not a signature. Without the name it says
    nothing about who sent it."""
    hits = _decoy_row("0x%5B%5D=1")

    assert "ANDROXGH0ST" not in _types(hits)
    assert "androxgh0st_named_token" not in _rules(hits)


def test_an_ordinary_form_post_is_untouched():
    assert _decoy_row("page=2&sort=date") == []


def test_the_stale_chrome_user_agent_is_not_a_verdict():
    """§4 calls it a weak secondary. Chrome 81 on Linux is also what a lot of real traffic
    claims, so no rule keys on it."""
    hits = _decoy_row("page=2")

    assert "ANDROXGH0ST" not in _types(hits)


# ---------------------------------------------------------------------------
# The dashboard can place it
# ---------------------------------------------------------------------------


def test_the_verdict_is_mitre_mapped_to_reconnaissance():
    mapping = get_mitre_mapping("ANDROXGH0ST", "")

    assert mapping, "ANDROXGH0ST has no MITRE mapping"
    assert {m["tactic"] for m in mapping} == {"reconnaissance"}
