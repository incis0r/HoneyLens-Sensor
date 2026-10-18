"""Google does not request dotfiles.

B5b, open item 6 of the 4 Oct-4 Nov fleet review §5.4. A forged Googlebot is the single
busiest user-agent in the fleet's secrets sweep: **7,833 `SENSITIVE_FILE` and 7,472 `SCANNER`
requests** claim `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` while
asking for `/.env` and `/.git/config`.

**Why this is not a text rule, and the design constraint the plan states.** The detection is "the
claimed agent does not match the PTR", and a PTR lookup is a network call. At 15,305 rows it
cannot live in `classify_event_row`: that would be 15,305 DNS lookups on the ingest path. So it
lives beside `_reverse_dns` in `intelligence/scanner_exclusions.py`, cached once per ADDRESS, and
the profiler — which has already resolved the address — consumes it and tags the profile.

**The fourth outcome is the point.** A claim resolves to genuine, forged, or *unproven*, and
unproven is never tagged. The resolver is slowest exactly when the fleet is busiest, and a
honeypot under load that starts accusing real crawlers has made its own evidence worthless.
Absence of proof is not proof.

The same section asks for the opposite case as a standing exclusion: `l9explore/1.2.2` (1,204
requests) and `WebSiphon/next-0.1` (2,210) identify themselves honestly, which is the cheapest
possible exclusion. That is a separate predicate on purpose — one is a lie about who you are, the
other is the truth — and it is **informational only**. The first draft put it inside
`is_known_scanner`, which is the function that gates hunting and deep AI analysis: a sender who
wrote `User-Agent: l9explore/1.2.2` would have switched off our own follow-up work on themselves.
A header is the sender's to choose; an ASN and a PTR are not, and a real Censys or Shodan node is
already excluded by those — so the header would have added the bypass and nothing else.
"""

from __future__ import annotations

import pytest

from honeylens.intelligence import scanner_exclusions as se

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture(autouse=True)
def _clear_cache():
    se.reset_ptr_cache()
    yield
    se.reset_ptr_cache()


class _CountingResolver:
    """A stubbed resolver that records how often it was asked."""

    def __init__(self, answer: str = "", raises: bool = False):
        self.answer = answer
        self.raises = raises
        self.calls: list[str] = []

    def __call__(self, ip: str, *_args, **_kwargs) -> str:
        self.calls.append(ip)
        if self.raises:
            raise OSError("resolver down")
        return self.answer


# ---------------------------------------------------------------------------
# The claim against the PTR
# ---------------------------------------------------------------------------


def test_a_googlebot_claim_from_a_foreign_ptr_is_forged():
    """7,833 SENSITIVE_FILE and 7,472 SCANNER requests on the fleet."""
    resolver = _CountingResolver("vps-4213.cheaphost.example")

    assert se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver) == se.CLAIM_FORGED


@pytest.mark.parametrize(
    "ptr",
    [
        "crawl-66-249-66-1.googlebot.com",
        "rate-limited-proxy-66-249-64-1.google.com",
        "crawl-66-249-66-1.googlebot.com.",
        "CRAWL-66-249-66-1.GOOGLEBOT.COM",
    ],
)
def test_a_genuine_googlebot_is_not_flagged(ptr):
    """Google publishes these suffixes and this is the check Google itself documents. A
    trailing dot and upper case are both ordinary PTR forms."""
    resolver = _CountingResolver(ptr)

    assert se.crawler_claim(GOOGLEBOT_UA, "66.249.66.1", resolver) == se.CLAIM_GENUINE


def test_a_resolver_with_no_answer_proves_nothing():
    """Not forged. An address with no PTR is extremely common and says nothing about the
    claim."""
    resolver = _CountingResolver("")

    assert se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver) == se.CLAIM_UNPROVEN


def test_a_resolver_that_fails_proves_nothing():
    """The busiest hours are when the resolver is slowest. A timeout must never accuse a real
    crawler — which is why this returns `unproven` rather than raising or guessing."""
    resolver = _CountingResolver(raises=True)

    assert se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver) == se.CLAIM_UNPROVEN


def test_a_request_claiming_nothing_is_not_judged():
    """No claim, no lookup. Most traffic is in this case, so it must cost nothing."""
    resolver = _CountingResolver("whatever.example")

    assert se.crawler_claim("curl/8.5.0", "198.51.100.7", resolver) == se.CLAIM_NONE
    assert resolver.calls == [], "a non-claim must not touch the resolver"


def test_the_resolver_is_called_once_per_address_not_once_per_event():
    """The whole reason this is not a text rule. 15,305 forged-Googlebot rows must cost one
    lookup, not 15,305."""
    resolver = _CountingResolver("vps-4213.cheaphost.example")

    for _ in range(50):
        se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver)

    assert resolver.calls == ["198.51.100.7"]


def test_each_address_is_resolved_on_its_own():
    resolver = _CountingResolver("vps-4213.cheaphost.example")

    se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver)
    se.crawler_claim(GOOGLEBOT_UA, "198.51.100.8", resolver)
    se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver)

    assert resolver.calls == ["198.51.100.7", "198.51.100.8"]


@pytest.mark.parametrize(
    ("ua", "ptr", "expected"),
    [
        ("bingbot/2.0", "msnbot-157-55-39-1.search.msn.com", "genuine"),
        ("bingbot/2.0", "vps.example", "forged"),
        ("YandexBot/3.0", "spider-5-45-207-1.yandex.com", "genuine"),
        ("Baiduspider/2.0", "baiduspider-123-125-71-1.crawl.baidu.com", "genuine"),
        ("DuckDuckBot/1.1", "duckduckbot.duckduckgo.com", "genuine"),
        ("Applebot/0.1", "17-58-98-1.applebot.apple.com", "genuine"),
        ("PetalBot", "petalbot-114-119-1-1.petalsearch.com", "genuine"),
    ],
)
def test_the_other_operators_publish_their_suffixes_too(ua, ptr, expected):
    """Googlebot is the one that was measured; the mechanism is identical for the rest, and a
    table beats seven copies of the same check."""
    resolver = _CountingResolver(ptr)

    assert se.crawler_claim(ua, "198.51.100.7", resolver) == expected


def test_a_lookalike_domain_does_not_pass():
    """`googlebot.com.evil.example` ends with neither published suffix, and a substring test
    would have let it through."""
    resolver = _CountingResolver("crawl.googlebot.com.evil.example")

    assert se.crawler_claim(GOOGLEBOT_UA, "198.51.100.7", resolver) == se.CLAIM_FORGED


# ---------------------------------------------------------------------------
# Using the PTR the enrichment already stored
# ---------------------------------------------------------------------------


def test_a_stored_ptr_costs_no_lookup():
    """The profiler has usually resolved the address before this runs."""
    resolver = _CountingResolver("should-not-be-called.example")

    claim = se.crawler_claim_with_hostname(
        GOOGLEBOT_UA, "198.51.100.7", "vps-4213.cheaphost.example", resolver
    )

    assert claim == se.CLAIM_FORGED
    assert resolver.calls == []


def test_an_empty_stored_ptr_falls_through_to_the_resolver():
    """`osint-enrichment-empty`: asn, org and hostname come back empty on this fleet's
    profilers far more often than not, so the fallback is the normal path."""
    resolver = _CountingResolver("crawl-66-249-66-1.googlebot.com")

    claim = se.crawler_claim_with_hostname(GOOGLEBOT_UA, "66.249.66.1", "", resolver)

    assert claim == se.CLAIM_GENUINE
    assert resolver.calls == ["66.249.66.1"]


def test_no_claim_means_no_work_even_with_a_stored_ptr():
    resolver = _CountingResolver("x.example")

    assert se.crawler_claim_with_hostname("curl/8.5.0", "1.2.3.4", "x.example", resolver) == "none"


# ---------------------------------------------------------------------------
# What the profiler puts on the address
# ---------------------------------------------------------------------------


def test_a_forged_claim_tags_the_profile():
    """`internal_tags` on `attacker_profiles` already has a GIN index, so the tag is queryable
    the day it is written and needs no migration."""
    resolver = _CountingResolver("vps-4213.cheaphost.example")

    tags = se.crawler_tags([GOOGLEBOT_UA, "curl/8.5.0"], "198.51.100.7", "", resolver)

    assert tags == ["FORGED_CRAWLER"]


def test_an_unproven_claim_is_named_as_unproven_not_as_a_forgery():
    """The measurement that corrects the review's premise. Resolving every Googlebot claimant
    from the sensors on 2026-11-05: on sensor-a, 7,564 rows from 41 sources and NOT ONE could be
    contradicted — every one of those addresses has no PTR at all. On sensor-b, 601 of 1,192 rows
    were positively forged (`ip-58-82.superbithost.com` accounts for 600) and the rest were
    unproven.

    So the "three-line reverse-DNS detection" would have been right about 601 rows and wrong by
    construction about 7,564 if a missing PTR were read as a forgery. Two tags, because they are
    two different statements."""
    resolver = _CountingResolver("")

    assert se.crawler_tags([GOOGLEBOT_UA], "198.51.100.7", "", resolver) == [
        "CRAWLER_CLAIM_UNVERIFIED"
    ]


def test_a_contradicted_claim_outranks_an_unverified_one():
    """One address, two claims: if either is contradicted, that is what the address is tagged
    with. The weaker tag would otherwise bury the stronger finding."""
    resolver = _CountingResolver("ip-58-82.superbithost.example")

    tags = se.crawler_tags([GOOGLEBOT_UA, "bingbot/2.0"], "198.51.100.7", "", resolver)

    assert tags == ["FORGED_CRAWLER"]


def test_a_genuine_crawler_tags_nothing():
    resolver = _CountingResolver("crawl-66-249-66-1.googlebot.com")

    assert se.crawler_tags([GOOGLEBOT_UA], "66.249.66.1", "", resolver) == []


def test_an_address_can_be_both():
    """One address can run an honest scanner and a forged crawler; the tags are independent and
    their order is fixed so a query can rely on it."""
    resolver = _CountingResolver("vps-4213.cheaphost.example")

    tags = se.crawler_tags([GOOGLEBOT_UA, "l9explore/1.2.2"], "198.51.100.7", "", resolver)

    assert tags == ["FORGED_CRAWLER", "SELF_IDENTIFYING_SCANNER"]


def test_an_address_with_no_crawler_claim_gets_no_crawler_tag():
    """Most traffic claims nothing, and `CRAWLER_CLAIM_UNVERIFIED` must not become a tag on
    every address that happens to have no PTR."""
    resolver = _CountingResolver("")

    assert se.crawler_tags(["curl/8.5.0"], "198.51.100.7", "", resolver) == []


def test_an_address_with_no_recorded_agents_is_not_tagged():
    assert se.crawler_tags(None, "198.51.100.7", "") == []
    assert se.crawler_tags([], "198.51.100.7", "") == []
    assert se.crawler_tags([None, ""], "198.51.100.7", "") == []


def test_the_profiler_calls_it_with_what_it_has():
    """A guard against the signature drifting apart from its one caller: the profiler passes
    the address's claimed agents, the address, and the PTR enrichment already stored."""
    import inspect

    from honeylens.analysis import attacker_profiler

    src = inspect.getsource(attacker_profiler.profile_ip)

    assert "crawler_tags(" in src
    assert 'ip_info.get("user_agents")' in src
    assert 'extracted.get("hostname")' in src


def test_the_profiler_asks_the_store_for_those_agents():
    """And the query that fills `user_agents` has to exist, or the tag can never fire."""
    import inspect

    from honeylens.analysis import attacker_profiler

    src = inspect.getsource(attacker_profiler.fetch_ip_info)

    assert "user_agents" in src
    assert "metadata->>'user_agent'" in src


# ---------------------------------------------------------------------------
# The honest half: scanners that name themselves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ua",
    [
        "l9explore/1.2.2",
        "WebSiphon/next-0.1",
        "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
        "masscan/1.3",
        "Mozilla/5.0 (compatible; InternetMeasurement/1.0; +https://internet-measurement.com/)",
    ],
)
def test_a_self_identifying_scanner_is_recognised(ua):
    """§5.4: 1,204 requests from l9explore and 2,210 from WebSiphon. No lookup, no enrichment,
    just the string they chose to send."""
    assert se.is_self_identifying_scanner(ua) is True


def test_a_forged_crawler_is_not_a_self_identifying_scanner():
    """The two predicates must not be confused. Something claiming Googlebot while asking for
    `/.env` is the opposite of a scanner identifying itself honestly."""
    assert se.is_self_identifying_scanner(GOOGLEBOT_UA) is False


def test_an_ordinary_browser_is_not_recognised():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0"

    assert se.is_self_identifying_scanner(ua) is False


def test_a_user_agent_cannot_switch_off_hunting():
    """The gate `routes/hunting.py` consults is `is_known_scanner`, and it must not take a
    header: a sender who wrote `User-Agent: l9explore/1.2.2` would otherwise have excluded
    themselves from profiling and deep AI analysis. A real scanner is caught by its ASN and its
    PTR, which it does not choose, so the header adds nothing there but the bypass."""
    import inspect

    assert "user_agent" not in inspect.signature(se.is_known_scanner).parameters
    assert "user_agent_substrings" not in inspect.getsource(se.is_known_scanner)


def test_the_honest_scanner_still_earns_a_profile_tag():
    """Informational is not the same as discarded: §5.4 is right that honest
    self-identification is cheap signal, so it lands where a human or a query can use it."""
    assert se.crawler_tags(["l9explore/1.2.2"], "198.51.100.7", "x.example") == [
        "SELF_IDENTIFYING_SCANNER"
    ]
