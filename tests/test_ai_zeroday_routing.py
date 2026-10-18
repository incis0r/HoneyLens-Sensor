#!/usr/bin/env python3
"""Tests for the 0-day vs high-novelty split (routes/ai.py + AI subnav)."""

import pytest


def test_ai_subnav_has_high_novelty_and_candidates():
    from honeylens.webui.dashboard_ai import AI_SUBNAV

    keys = {k for k, _url, _label in AI_SUBNAV}
    urls = {url for _k, url, _label in AI_SUBNAV}
    assert "candidates" in keys and "/ai/zero-days" in urls
    assert "highnov" in keys and "/ai/high-novelty" in urls


def test_zd_colour_bands():
    from honeylens.routes.ai import _zd_colour

    assert _zd_colour(95) == "#ef4444"  # >=90 critical
    assert _zd_colour(75) == "#f97316"  # >=70 high
    assert _zd_colour(55) == "#eab308"  # >=50 medium
    assert _zd_colour(10) == "#22c55e"  # low


def test_nov_colour_mapping():
    from honeylens.routes.ai import _nov_colour

    assert _nov_colour(10) == "#ef4444"
    assert _nov_colour(6) == "#22c55e"
    assert _nov_colour(0) == "#94a3b8"  # below the surface
    assert _nov_colour(None) == "#94a3b8"


class _FakeReq:
    def __init__(self, accept="", fmt=None):
        self.headers = {"accept": accept}
        self.query_params = {"format": fmt} if fmt else {}


@pytest.mark.parametrize(
    "accept,fmt,expect_html",
    [
        ("*/*", None, False),  # fetch()/XHR/curl -> JSON (dashboard data)
        ("", None, False),  # header-less internal fake req -> JSON
        ("text/html,application/xhtml+xml", None, True),  # page navigation -> HTML
        ("application/json", None, False),  # API client -> JSON
        ("application/json,text/html", None, False),  # JSON-first Accept -> JSON
        ("text/html", "json", False),  # ?format=json wins
        ("application/json", "html", True),  # ?format=html wins
    ],
)
def test_wants_html_only_for_page_navigation(accept, fmt, expect_html):
    """HTML only for explicit text/html navigation (or ?format=html). Everything
    else — notably Accept */* from fetch()/XHR — gets JSON, so the dashboards'
    own data widgets keep working."""
    from honeylens.routes._helpers import wants_html

    assert wants_html(_FakeReq(accept, fmt)) is expect_html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
