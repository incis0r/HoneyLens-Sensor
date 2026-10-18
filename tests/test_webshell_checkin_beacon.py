"""A check-in is not a scan, and the fleet had no verdict that said so.

B4c. The internal beacon IOC notes: since 2026-11-01 one sender, `154.12.18.42`, has sent
a single `POST /k7f3a9` every three hours on the hour, to a path that exists in no product,
carrying a constant 28-hex key in an `X-K` header and a four-command host-profiling body — `id;
nproc; hostname; uname -m`. Identity, core count, name, architecture: the questions a mining or
proxy operator asks, not a data thief. The operator either believes a webshell of theirs is
installed there or is holding the option open.

What it carried instead: `RCE` on every row — correct in class, because the body is a shell
command list, and silent about everything that matters. No rule of ours named the family.

The 4 Oct-4 Nov fleet review §5.1 then showed the beacon is half of a fixed eight-second
sequence repeated on the same three-hour cycle:

    01:03:35   POST /v3/kv/put   -> etcd decoy      :2379
    01:03:36   POST /k7f3a9      -> netscaler decoy :80
    01:03:42   POST /k7f3a9      -> honeypotng      :8080

The beacon's body and an etcd write are the same shopping list: find compute, then persist. So
this file asserts both halves — the etcd half is B2's `k8s_etcd_kv_write`, and a regression there
would break the pair just as surely.

**Four detections, in the shape the sheet asks for, with one deliberate relaxation.** Its item 4
wants the generalised family as path AND header AND body together. Requiring all three means one
missing element loses the verdict, and each element is already distinctive on its own: a POST to a
hex-only path with a shell-command body is named, and a single-letter `X-*` header carrying a long
hex string is named, independently. Both are HIGH; an event carrying both carries both rows.

**Nothing here answers it.** The decoys return their static page, which is the right behaviour: a
reply shaped like command output would tell the operator a shell exists at that address. The
canary stays passive by rule.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import get_severity

BEACON_PATH = "/k7f3a9"
BEACON_KEY = "8fc060100e7354cfc881a8abde61"
BEACON_BODY = "id; nproc; hostname; uname -m"


def _decoy_row(path: str, body: str = "", *, method: str = "POST", port: int = 80, headers=None):
    """The beacon as a decoy stores it. No user-agent: §3 records the header as absent."""
    meta = {
        "method": method,
        "path": path,
        "port": port,
        "headers": {"host": "sensor.example", "connection": "close", **(headers or {})},
    }
    if body:
        meta["body_sample"] = body
        meta["body_len"] = len(body)
    summary = f"{method} {path} body_len={len(body)}"
    payload = f"{summary}\n{body}" if body else summary
    return classify_event_row(payload, "http", meta)


def _raw_row(path: str, body: str = "", *, method: str = "POST", headers=None):
    lines = {"Host": "sensor.example", "Connection": "close", "Content-Length": str(len(body))}
    lines.update(headers or {})
    head = "\r\n".join(f"{k}: {v}" for k, v in lines.items())
    return classify_event_row(
        f"{method} {path} HTTP/1.1\r\n{head}\r\n\r\n{body}", "http", {"dst_port": 80}
    )


def _types(hits) -> set[str]:
    return {h[0] for h in hits}


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


# ---------------------------------------------------------------------------
# The beacon itself
# ---------------------------------------------------------------------------


def test_the_beacon_is_named_as_a_check_in():
    """Every row of it carried `RCE` and nothing that said what it was."""
    hits = _decoy_row(BEACON_PATH, BEACON_BODY, headers={"x-k": BEACON_KEY})

    assert "WEBSHELL_CHECKIN" in _types(hits)


def test_the_path_alone_is_enough():
    """§4.1: regardless of method or body. No product uses this path, and the operator asking
    for it at all is the finding."""
    hits = _decoy_row(BEACON_PATH, method="GET")

    assert "WEBSHELL_CHECKIN" in _types(hits)


def test_the_check_in_is_high():
    assert get_severity("WEBSHELL_CHECKIN", "webshell_checkin_known_path") == "high"


def test_the_key_header_is_named_separately():
    """§4.2: a single-letter-plus-dash header carrying 28 hex characters is a shell key, not a
    cache hint — and the key is the OPERATOR's, constant across every sensor and all 72 hours,
    which makes it the one indicator that is not the victim's."""
    hits = _decoy_row("/", headers={"x-k": BEACON_KEY})

    assert "WEBSHELL_KEY" in _types(hits)
    assert get_severity("WEBSHELL_KEY", "webshell_hex_key_header") == "high"


def test_the_key_header_is_seen_on_both_ingest_paths():
    """sensor-a and sensor-b have Suricata; sensor-c has only the decoy row."""
    assert "WEBSHELL_KEY" in _types(_decoy_row("/", headers={"x-k": BEACON_KEY}))
    assert "WEBSHELL_KEY" in _types(_raw_row("/", headers={"X-K": BEACON_KEY}))


def test_an_ordinary_custom_header_is_not_a_shell_key():
    """`X-Request-Id` and friends are everywhere. The rule is about a one-letter name carrying
    a long hex string, which is a credential shape."""
    hits = _decoy_row("/", headers={"x-request-id": "8fc060100e7354cfc881a8abde61"})

    assert "WEBSHELL_KEY" not in _types(hits)


def test_a_short_hex_value_is_not_a_key():
    """A one-letter header with four hex characters could be anything."""
    assert "WEBSHELL_KEY" not in _types(_decoy_row("/", headers={"x-k": "8fc0"}))


def test_the_body_is_named_as_host_profiling():
    """§4.3. The four commands are the inventory question: who am I running as, how many cores,
    what name, what architecture."""
    hits = _decoy_row(BEACON_PATH, BEACON_BODY)

    assert "HOST_PROFILING" in _types(hits)
    assert get_severity("HOST_PROFILING", "shell_host_profiling_chain") == "medium"


def test_host_profiling_is_not_claimed_from_one_command():
    """A single `id` in a body is a word. The tell is commands CHAINED, which is a script."""
    assert "HOST_PROFILING" not in _types(_decoy_row("/x", "id"))


def test_host_profiling_generalises_past_this_operator_s_four_commands():
    hits = _decoy_row("/abc123", "whoami; uname -a; uptime")

    assert "HOST_PROFILING" in _types(hits)


# ---------------------------------------------------------------------------
# The family, not one path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/a1b2c", "/deadbeef", "/0f0f0f0f", "/abc12"])
def test_a_post_to_a_hex_only_path_with_a_shell_body_is_the_same_family(path):
    """§4.4 asks for the family rather than the one path: the next key will be a different six
    characters, and the one thing the operator cannot change is that it is asking a shell to
    report back."""
    hits = _decoy_row(path, BEACON_BODY)

    assert "WEBSHELL_CHECKIN" in _types(hits)
    assert "webshell_checkin_hex_path_shell_body" in _rules(hits)


def test_this_operator_s_own_path_is_not_hex_and_that_is_why_it_is_listed_literally():
    """`k7f3a9` has a `k` in it — §3 calls the path "six lowercase hex-ish chars", not hex. The
    generalised family rule therefore does not cover this operator's own path, which is exactly
    why the sheet keeps the literal as its own detection instead of only the family."""
    hits = _decoy_row(BEACON_PATH, BEACON_BODY)

    assert "webshell_checkin_known_path" in _rules(hits)
    assert "webshell_checkin_hex_path_shell_body" not in _rules(hits)
    assert "WEBSHELL_CHECKIN" in _types(hits)


def test_the_family_rule_sees_the_capture_path_too():
    assert "WEBSHELL_CHECKIN" in _types(_raw_row("/a1b2c3", BEACON_BODY))


def test_a_hex_path_without_a_shell_body_is_not_a_check_in():
    """A short hex path on its own is a URL shape — commit hashes, short links, cache keys. The
    claim needs the second half."""
    hits = _decoy_row("/a1b2c3", "name=value")

    assert "WEBSHELL_CHECKIN" not in _types(hits)


def test_a_shell_body_on_an_ordinary_path_is_not_a_check_in():
    """It is still host profiling, and that is what gets said about it."""
    hits = _decoy_row("/api/v1/run", BEACON_BODY)

    assert "WEBSHELL_CHECKIN" not in _types(hits)
    assert "HOST_PROFILING" in _types(hits)


def test_a_longer_hex_path_is_not_the_family():
    """`^/[0-9a-f]{5,8}$` is the shape; a 32-character hex path is a hash in a URL, which is
    how plenty of real applications route."""
    hits = _decoy_row("/8fc060100e7354cfc881a8abde61beef", BEACON_BODY)

    assert "WEBSHELL_CHECKIN" not in _types(hits)


# ---------------------------------------------------------------------------
# The path has to be visible for any of this to work
# ---------------------------------------------------------------------------


def test_the_path_is_classified_even_when_only_metadata_carries_it():
    """Found by checking this beacon against the live store: 33 of 66 rows on sensor-b came back
    with no check-in verdict. The netscaler decoy replaces `payload` with the captured body
    when there is one, so the path existed only in `metadata["path"]` — and `path` was not in
    the list of metadata keys the classifier scans. No path rule could fire on any such row.

    Measured over 7 days: 1,534 rows on sensor-a and 682 on sensor-b carry a path that is not in
    their payload, 780 and 124 of them with no verdict at all. It is concentrated exactly
    where exploitation lives: requests with a body."""
    hits = classify_event_row(
        BEACON_BODY,  # what the decoy stores as the payload: the body, and only the body
        "http",
        {"method": "POST", "path": BEACON_PATH, "port": 80, "body_sample": BEACON_BODY},
    )

    assert "WEBSHELL_CHECKIN" in _types(hits)


def test_an_ordinary_path_in_metadata_still_classifies_as_before():
    """The new target is additive: a traversal in `metadata["path"]` was invisible too."""
    hits = classify_event_row(
        "x=1", "http", {"method": "POST", "path": "/../../../../etc/passwd", "port": 80}
    )

    assert "LFI" in _types(hits)


# ---------------------------------------------------------------------------
# Both halves of the three-hourly sequence
# ---------------------------------------------------------------------------


def test_the_etcd_write_half_of_the_sequence_is_still_named():
    """§5.1: `POST /v3/kv/put` at 01:03:35 and `POST /k7f3a9` one second later are the same
    actor on the same cycle. B2 named the etcd write; if that regresses, this pair stops being
    legible even though the beacon rule still fires."""
    hits = _decoy_row("/v3/kv/put", '{"key":"Zm9v","value":"YmFy"}', port=2379)

    assert "k8s_etcd_kv_write" in _rules(hits)
    assert get_severity("K8S_ATTACK", "k8s_etcd_kv_write") == "critical"


def test_the_two_halves_carry_different_verdicts():
    """Persisting into a cluster store and polling for a shell are different acts; the pair is
    read from two rows, not from one blended verdict."""
    beacon = _types(_decoy_row(BEACON_PATH, BEACON_BODY, headers={"x-k": BEACON_KEY}))
    etcd = _types(_decoy_row("/v3/kv/put", '{"key":"Zm9v"}', port=2379))

    assert "WEBSHELL_CHECKIN" in beacon
    assert "WEBSHELL_CHECKIN" not in etcd
    assert "K8S_ATTACK" in etcd


# ---------------------------------------------------------------------------
# Nothing else moves
# ---------------------------------------------------------------------------


def test_an_ordinary_request_is_untouched():
    assert _decoy_row("/index.html", method="GET") == []


def test_a_bare_slash_post_is_not_a_check_in():
    assert "WEBSHELL_CHECKIN" not in _types(_decoy_row("/", "page=2"))


# ---------------------------------------------------------------------------
# The dashboard can place it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attack_type", ["WEBSHELL_CHECKIN", "WEBSHELL_KEY", "HOST_PROFILING"])
def test_every_new_verdict_is_mitre_mapped(attack_type):
    mapping = get_mitre_mapping(attack_type, "")

    assert mapping, f"{attack_type} has no MITRE mapping"
    assert all(m["technique"].startswith("T") for m in mapping), mapping


def test_the_check_in_is_mapped_to_persistence_and_command_and_control():
    """It is not reconnaissance: the operator is polling something they expect to own."""
    tactics = {m["tactic"] for m in get_mitre_mapping("WEBSHELL_CHECKIN", "")}

    assert "persistence" in tactics
    assert "command-and-control" in tactics


def test_host_profiling_is_mapped_to_discovery():
    tactics = {m["tactic"] for m in get_mitre_mapping("HOST_PROFILING", "")}

    assert tactics == {"discovery"}
