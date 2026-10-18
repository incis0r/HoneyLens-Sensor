"""A proxy header our own edge sets is not an attack, and a word is not a Redis command.

Three corrections that fall out of making header and path targets visible to the classifier
(B4c). Each is measured against the live store on a 4,000-row random sample per sensor.

**`rate_limit_bypass_headers` fired on our own real-IP attribution.** It matched the mere
PRESENCE of `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP` or
`X-Originating-IP`. The fleet's edge sets `X-Real-IP` on every forwarded request -- that is how
real-IP attribution works here, and the internal real-IP spoofing IOC notes §5 measured `gap=0`
on six sensors because of it. With headers newly visible on decoy rows, 1,133 of 4,000 sampled
rows on `sensor-b` would have been labelled `API_ABUSE`, against 0 stored today, and 399 distinct
values in those headers were ordinary public client addresses. The sheet's own item 2 is the
honest predicate: the CLAIMED VALUE is unroutable as a client -- loopback, `0.0.0.0`, `::1`,
`localhost` or RFC1918. That is intent, not a misconfigured client. Measured in the same sample:
`X-Client-IP: 172.16.0.1`, `True-Client-IP: 127.0.0.1` and `X-Originating-IP: 192.168.1.1` all
occur, so the real signal survives.

Item 1 of that sheet -- the header arriving from a peer that is not the configured proxy -- is
NOT implementable here: classification never sees the peer, only the claimed value. It belongs
where the peer is known, which is the same place B5b's PTR lookup belongs.

**`rate_limit_bypass_origin` had the same shape** for `X-Forwarded-Host`, which the edge also
sets: 247 of the 255 occurrences on `sensor-b` were the bypass value `localhost`, and the other 8
were our own front's hostname. `X-Original-URL` keeps the presence test -- it overrides the
routed path, all 8 occurrences carried attacker paths, and nothing of ours sends it.

**`redis_dangerous_cmd` called PHPUnit Redis.** Its `EVAL` alternative is case-insensitive and
bounded only by `\\b`, so it matched the word inside
`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` -- the CVE-2017-9841 probe. 57 of 4,000
sampled rows on `sensor-b` would have been labelled a Redis attack for asking after a PHP file.
Redis takes `EVAL <script> <numkeys>`, so requiring whitespace or a quote after the verb keeps
every real form and drops the English word.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row


def _row(headers=None, path="/", body="", method="GET", port=443):
    meta = {"method": method, "path": path, "port": port}
    if headers:
        meta["headers"] = {"host": "sensor.example", **headers}
    if body:
        meta["body_sample"] = body
        meta["body_len"] = len(body)
    payload = f"{method} {path} body_len={len(body)}" + (f"\n{body}" if body else "")
    return classify_event_row(payload, "http", meta)


def _rules(hits) -> set[str]:
    return {h[1] for h in hits}


# ---------------------------------------------------------------------------
# Our own edge is not an attacker
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claimed",
    ["45.61.178.105", "213.209.159.175", "8.132.93.29"],
    ids=["top_sender", "second_sender", "third_sender"],
)
def test_a_public_address_in_a_real_ip_header_is_not_a_bypass_attempt(claimed):
    """These are the three most common values measured in `X-Real-IP` on sensor-b. They are the
    senders' own addresses, written there by our edge so attribution works."""
    hits = _row({"x-real-ip": claimed})

    assert "rate_limit_bypass_headers" not in _rules(hits)


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("x-client-ip", "172.16.0.1"),
        ("true-client-ip", "127.0.0.1"),
        ("x-originating-ip", "192.168.1.1"),
        ("cf-connecting-ip", "127.0.0.1"),
        ("x-real-ip", "0.0.0.0"),
        ("x-remote-addr", "localhost"),
        ("x-real-ip", "::1"),
        ("x-client-ip", "10.0.0.1"),
    ],
)
def test_an_unroutable_claim_is_still_named(header, value):
    """Every one of these pairs was measured in the sample. A client cannot reach us FROM
    loopback or from private space, so the claim is intent."""
    assert "rate_limit_bypass_headers" in _rules(_row({header: value}))


def test_the_wire_dialect_works_too():
    """A capture row carries wire-form headers, a decoy row carries a dict."""
    raw = "GET / HTTP/1.1\r\nHost: x\r\nX-Client-IP: 127.0.0.1\r\n\r\n"

    assert "rate_limit_bypass_headers" in _rules(classify_event_row(raw, "http", {"dst_port": 80}))


def test_our_own_forwarded_host_is_not_an_attack():
    """8 of 255 occurrences: the front's own hostname, which the edge sets."""
    hits = _row({"x-forwarded-host": "front.example.net"})

    assert "rate_limit_bypass_origin" not in _rules(hits)


def test_a_localhost_forwarded_host_is_named():
    """247 of 255 occurrences on sensor-b."""
    assert "rate_limit_bypass_origin" in _rules(_row({"x-forwarded-host": "localhost"}))


def test_an_overridden_request_path_keeps_the_presence_test():
    """`X-Original-URL` reroutes the request inside the application. Nothing of ours sends it,
    and all 8 measured occurrences carried attacker paths."""
    assert "rate_limit_bypass_origin" in _rules(_row({"x-original-url": "/press/"}))


def test_the_forwarded_for_rule_is_unchanged():
    """It already tested the value rather than the presence, which is why it only fired 4 times
    in the same sample where the presence rule fired 1,133."""
    assert "rate_limit_bypass_xff" in _rules(_row({"x-forwarded-for": "127.0.0.1"}))
    assert "rate_limit_bypass_xff" not in _rules(_row({"x-forwarded-for": "45.61.178.105"}))


# ---------------------------------------------------------------------------
# A word is not a Redis command
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/phpunit/Util/PHP/eval-stdin.php",
        "/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ],
)
def test_the_phpunit_probe_is_not_a_redis_attack(path):
    """57 of 4,000 sampled rows on sensor-b. It is a real probe -- CVE-2017-9841, a development
    file left in `vendor/` that executes a POSTed body as PHP -- but it is not someone sending
    Redis `EVAL`, and the wrong label was the ONLY label it had: removing it left the probe with
    no verdict at all, so `phpunit_eval_stdin_probe` arrives in the same change."""
    hits = _row(path=path)

    assert "redis_dangerous_cmd" not in _rules(hits)
    assert "phpunit_eval_stdin_probe" in _rules(hits)


def test_the_phpunit_probe_is_recon_and_not_the_cve():
    """Asking for the path achieves nothing. The same reasoning made `sp-webshell-aspx` a RECON
    verdict after 87 sources sent one bare GET each."""
    from honeylens.classification.scoring import get_severity

    hits = _row(path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")

    assert {h[0] for h in hits} == {"RECON"}
    assert get_severity("RECON", "phpunit_eval_stdin_probe") == "low"


def test_a_posted_php_body_is_still_named_as_execution():
    """The exploited case needs no new rule: `rce_eval_exec` and `php_opening_tag` have always
    named a PHP body, so this rule never has to claim the RCE itself."""
    hits = _row(
        path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        body="<?php system('id');?>",
        method="POST",
    )

    assert "RCE" in {h[0] for h in hits}
    assert "RECON" in {h[0] for h in hits}


@pytest.mark.parametrize(
    "payload",
    ['EVAL "return 1" 0', "eval 'redis.call(\"set\",KEYS[1],1)' 1 x", "EVAL\t'x' 0"],
)
def test_a_real_redis_eval_is_still_named(payload):
    """Redis takes `EVAL <script> <numkeys>`, so a separator always follows the verb."""
    assert "redis_dangerous_cmd" in _rules(classify_event_row(payload, "tcp", {"dst_port": 6379}))


@pytest.mark.parametrize("payload", ["FLUSHALL", "CONFIG SET dir /var/spool/cron", "SLAVEOF x 1"])
def test_the_other_redis_commands_are_untouched(payload):
    assert "redis_dangerous_cmd" in _rules(classify_event_row(payload, "tcp", {"dst_port": 6379}))
