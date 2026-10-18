"""A PTR is set by whoever owns the address, so matching it is only half the check.

`crawler_claim` returned `CLAIM_GENUINE` on `ptr.endswith('.googlebot.com')` alone, and the
module's own comment claimed "the check is the one those operators themselves document". It is
not: Google documents **forward-confirmed** reverse DNS -- resolve the PTR back and require the
original address in the answer. Reverse DNS is a record the address's owner publishes, and a VPS
provider will happily let a tenant set `crawl-1-2-3-4.googlebot.com` on a rented address.

So the one-directional check disarmed exactly the detection this module exists for: the forged
Googlebot asking for `/.env` and `/.git/config` (7,833 `SENSITIVE_FILE` plus 7,472 `SCANNER`
rows). An attacker who reads our own source and sets a PTR goes from `FORGED_CRAWLER` to
`genuine`, which is worse than having no check -- it launders the claim.

**A failure to confirm is never a forgery.** The forward query is a network call on the same
loaded resolver as the reverse one, and the reasoning that kept `CLAIM_UNPROVEN` for a missing
PTR applies unchanged in the forward direction: a timeout must not make us accuse a real
crawler. Only a PTR that does not match the operator's suffix at all is a contradiction, and
that is the owner's own record disagreeing with the claim, not a resolver having a bad minute.
"""

from __future__ import annotations

import pytest

from honeylens.intelligence import scanner_exclusions as sx

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

REAL = "66.249.66.1"  # what a genuine crawler address behaves like
FORGER = "198.51.100.77"  # a rented address whose owner set a Google-looking PTR


@pytest.fixture(autouse=True)
def _clean_caches():
    sx.reset_ptr_cache()
    yield
    sx.reset_ptr_cache()


def _reverse(mapping):
    return lambda ip: mapping.get(ip, "")


def _forward(mapping):
    return lambda name: tuple(mapping.get(name, ()))


# ---------------------------------------------------------------------------
# The claim itself
# ---------------------------------------------------------------------------


def test_a_ptr_that_resolves_back_to_the_address_is_genuine():
    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        REAL,
        resolver=_reverse({REAL: "crawl-66-249-66-1.googlebot.com"}),
        forward_resolver=_forward({"crawl-66-249-66-1.googlebot.com": (REAL,)}),
    )

    assert claim == sx.CLAIM_GENUINE


def test_a_google_looking_ptr_that_does_not_resolve_back_is_not_genuine():
    """The forgery this module exists to catch: the PTR is the attacker's to publish."""
    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        FORGER,
        resolver=_reverse({FORGER: "crawl-198-51-100-77.googlebot.com"}),
        forward_resolver=_forward({"crawl-198-51-100-77.googlebot.com": ("66.249.66.1",)}),
    )

    assert claim != sx.CLAIM_GENUINE
    assert claim == sx.CLAIM_UNPROVEN


def test_a_forward_lookup_that_answers_nothing_is_unproven_not_forged():
    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        FORGER,
        resolver=_reverse({FORGER: "crawl-198-51-100-77.googlebot.com"}),
        forward_resolver=_forward({}),
    )

    assert claim == sx.CLAIM_UNPROVEN


def test_a_forward_resolver_that_raises_is_unproven_not_forged():
    """The busiest hours are when the resolver is slowest; a honeypot under load must not
    start accusing real crawlers in either direction."""

    def _boom(_name):
        raise OSError("resolver is having a bad minute")

    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        FORGER,
        resolver=_reverse({FORGER: "crawl-198-51-100-77.googlebot.com"}),
        forward_resolver=_boom,
    )

    assert claim == sx.CLAIM_UNPROVEN


def test_a_ptr_contradicting_the_claim_is_still_forged():
    """Unchanged: the owner's own record disagreeing with the claim is a contradiction, and
    needs no forward query to establish."""
    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        FORGER,
        resolver=_reverse({FORGER: "ip-58-82.superbithost.com"}),
        forward_resolver=_forward({}),
    )

    assert claim == sx.CLAIM_FORGED


def test_no_ptr_at_all_is_still_unproven():
    claim = sx.crawler_claim(
        GOOGLEBOT_UA, FORGER, resolver=_reverse({}), forward_resolver=_forward({})
    )

    assert claim == sx.CLAIM_UNPROVEN


def test_an_address_in_the_answer_counts_however_it_is_written():
    """The forward answer comes from the system resolver, so the comparison is between
    addresses, not between strings."""
    claim = sx.crawler_claim(
        GOOGLEBOT_UA,
        "2001:db8::1",
        resolver=_reverse({"2001:db8::1": "crawl-v6.googlebot.com"}),
        forward_resolver=_forward({"crawl-v6.googlebot.com": ("2001:0db8:0000::0001",)}),
    )

    assert claim == sx.CLAIM_GENUINE


# ---------------------------------------------------------------------------
# The stored-hostname path takes the same confirmation
# ---------------------------------------------------------------------------


def test_a_stored_hostname_is_confirmed_too():
    """`crawler_claim_with_hostname` exists to save a lookup, not to skip the check: the
    enrichment's PTR was published by the same owner."""
    claim = sx.crawler_claim_with_hostname(
        GOOGLEBOT_UA,
        FORGER,
        "crawl-198-51-100-77.googlebot.com",
        forward_resolver=_forward({"crawl-198-51-100-77.googlebot.com": ("66.249.66.1",)}),
    )

    assert claim == sx.CLAIM_UNPROVEN


def test_a_stored_hostname_that_confirms_is_genuine():
    claim = sx.crawler_claim_with_hostname(
        GOOGLEBOT_UA,
        REAL,
        "crawl-66-249-66-1.googlebot.com",
        forward_resolver=_forward({"crawl-66-249-66-1.googlebot.com": (REAL,)}),
    )

    assert claim == sx.CLAIM_GENUINE


# ---------------------------------------------------------------------------
# What the profiler ends up tagging
# ---------------------------------------------------------------------------


def test_the_forger_is_tagged_unverified_rather_than_laundered():
    tags = sx.crawler_tags(
        [GOOGLEBOT_UA],
        FORGER,
        "crawl-198-51-100-77.googlebot.com",
        forward_resolver=_forward({"crawl-198-51-100-77.googlebot.com": ("66.249.66.1",)}),
    )

    assert tags == ["CRAWLER_CLAIM_UNVERIFIED"]


def test_a_genuine_crawler_gets_no_tag():
    tags = sx.crawler_tags(
        [GOOGLEBOT_UA],
        REAL,
        "crawl-66-249-66-1.googlebot.com",
        forward_resolver=_forward({"crawl-66-249-66-1.googlebot.com": (REAL,)}),
    )

    assert tags == []
