"""country + city must come from one geolocation source (no BG/Lelystad pairs)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.analysis.attacker_profiler import reconcile_geo


def test_stale_city_cleared_when_geo_has_no_city():
    # the reported bug: registry country BG + stale ip-api city Lelystad
    fields = {"country": "BG", "city": "Lelystad"}
    reconcile_geo(fields, {"country_code": "BG", "city": ""})
    assert fields["country"] == "BG"
    assert fields["city"] == ""  # stale mismatched city dropped


def test_geo_country_and_city_taken_as_a_pair():
    fields = {"country": "BG", "city": "Lelystad"}  # registry said BG
    reconcile_geo(fields, {"country_code": "NL", "city": "Amsterdam"})
    assert fields["country"] == "NL"  # geolocation wins for the pair
    assert fields["city"] == "Amsterdam"


def test_unknown_geo_keeps_osint_country_but_clears_city():
    fields = {"country": "US", "city": "Somewhere"}
    reconcile_geo(fields, {"country_code": "??", "city": ""})
    assert fields["country"] == "US"  # keep OSINT country when geo blank
    assert fields["city"] == ""


def test_private_geo_does_not_override_country():
    fields = {"country": "US", "city": "x"}
    reconcile_geo(fields, {"country_code": "LAN", "city": ""})
    assert fields["country"] == "US"
    assert fields["city"] == ""


def test_none_geo_is_safe():
    fields = {"country": "DE", "city": "Berlin"}
    reconcile_geo(fields, None)
    assert fields["country"] == "DE"
    assert fields["city"] == ""
