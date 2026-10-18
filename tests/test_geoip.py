"""core.geoip — address classification, TTL cache, ip-api rate limit, flags."""

from __future__ import annotations

from pathlib import Path

import pytest

from honeylens import geoip


@pytest.mark.parametrize(
    ("ip", "private"),
    [
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("172.32.0.1", False),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("169.254.1.2", True),
        ("8.8.8.8", False),
        ("not-an-ip", False),
        ("1.2.3", False),
        ("", False),
    ],
)
def test_is_private_ip(ip: str, private: bool) -> None:
    assert geoip.is_private_ip(ip) is private


def test_is_valid_public_ip() -> None:
    assert geoip.is_valid_public_ip("8.8.8.8")
    assert not geoip.is_valid_public_ip("10.0.0.1")
    assert not geoip.is_valid_public_ip("")
    assert not geoip.is_valid_public_ip("999.1.1.1")


@pytest.mark.parametrize(
    ("code", "flag"),
    [
        ("US", "🇺🇸"),
        ("pl", "🇵🇱"),
        ("LAN", "🏠"),
        ("PIRATE", "🏴‍☠️"),
        ("??", "🏴"),
        ("", "🏴"),
        ("USA", "🏴"),
    ],
)
def test_country_flag(code: str, flag: str) -> None:
    assert geoip.country_flag(code) == flag


def test_lookup_private_and_tester_do_not_touch_backends(monkeypatch) -> None:
    monkeypatch.setattr(geoip, "_lookup_maxmind", lambda ip: pytest.fail("backend called"))
    monkeypatch.setattr(geoip, "_lookup_ipapi", lambda ip: pytest.fail("backend called"))
    assert geoip.lookup_ip("192.168.0.9")["country_code"] == "LAN"
    monkeypatch.setitem(geoip.TESTER_IPS, "203.0.113.5", "Red Team")
    got = geoip.lookup_ip("203.0.113.5")
    assert got["country_code"] == "PIRATE" and got["city"] == "Red Team" and got["is_tester"]
    assert geoip.lookup_ip("")["country_code"] == "??"


def test_lookup_uses_cache_within_ttl(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(geoip, "_lookup_maxmind", lambda ip: None)
    monkeypatch.setattr(
        geoip,
        "_lookup_ipapi",
        lambda ip: (
            calls.append(ip)
            or {"ip": ip, "country_code": "PL", "country": "Poland", "source": "ip-api"}
        ),
    )
    clock = [1_000_000.0]
    monkeypatch.setattr(geoip, "_now", lambda: clock[0])
    geoip._geo_cache.clear()
    assert geoip.lookup_ip("203.0.113.77")["country_code"] == "PL"
    assert geoip.lookup_ip("203.0.113.77")["country_code"] == "PL"
    assert calls == ["203.0.113.77"]
    clock[0] += geoip.CACHE_TTL + 1
    geoip.lookup_ip("203.0.113.77")
    assert calls == ["203.0.113.77"] * 2


def test_cache_evicts_oldest_tenth_when_full(monkeypatch) -> None:
    geoip._geo_cache.clear()
    monkeypatch.setattr(geoip, "CACHE_SIZE", 20)
    for i in range(20):
        geoip._put_in_cache(f"1.1.1.{i}", {"i": i})
    geoip._put_in_cache("9.9.9.9", {"i": 99})
    assert len(geoip._geo_cache) == 19
    assert "1.1.1.0" not in geoip._geo_cache and "1.1.1.19" in geoip._geo_cache


def test_final_fallback_when_all_backends_fail(monkeypatch) -> None:
    geoip._geo_cache.clear()
    monkeypatch.setattr(geoip, "_lookup_maxmind", lambda ip: None)
    monkeypatch.setattr(geoip, "_lookup_ipapi", lambda ip: None)
    assert geoip.lookup_ip("203.0.113.9") == {
        "ip": "203.0.113.9",
        "country": "Unknown",
        "country_code": "??",
        "source": "none",
    }


def test_ipapi_rejects_non_ip_before_building_a_url(monkeypatch) -> None:
    monkeypatch.setattr(geoip, "_http_get_json", lambda url: pytest.fail("network called"))
    assert geoip._lookup_ipapi("8.8.8.8/../../etc") is None


def test_ipapi_rate_limit_is_per_minute_window(monkeypatch) -> None:
    """0.9 reset the counter only after 60 s of SILENCE: under continuous traffic the limit
    blocked forever."""
    clock = [5000.0]
    monkeypatch.setattr(geoip, "_now", lambda: clock[0])
    monkeypatch.setattr(
        geoip,
        "_http_get_json",
        lambda url: {"status": "success", "countryCode": "PL", "country": "Poland"},
    )
    geoip._rate_reset()
    for _ in range(geoip.IP_API_RATE_LIMIT):
        assert geoip._lookup_ipapi("203.0.113.1") is not None
        clock[0] += 1.0
    assert geoip._lookup_ipapi("203.0.113.1") is None  # the 46th within this minute
    clock[0] += 61.0
    assert geoip._lookup_ipapi("203.0.113.1") is not None


def test_tester_ips_from_env_and_file(tmp_path: Path) -> None:
    f = tmp_path / "testers.txt"
    f.write_text("# comment\n203.0.113.10 Red Team Alice\n203.0.113.11\n\n")
    got = geoip.load_tester_ips("1.2.3.4, 5.6.7.8", f)
    assert got == {
        "1.2.3.4": "Tester (env)",
        "5.6.7.8": "Tester (env)",
        "203.0.113.10": "Red Team Alice",
        "203.0.113.11": "Tester",
    }
    assert geoip.load_tester_ips("", tmp_path / "missing") == {}
