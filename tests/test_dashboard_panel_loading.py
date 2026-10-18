"""Dashboard: the main panels must not be gated behind an earlier await.

`refresh()` loaded the panels in two steps: first `await Promise.all([loadKPIs(),
loadBadgeData()])`, and only then the main panels (scanners, MITM, honeypots, attacks,
events). `await fetchJSON` does not reject a hung request — so a single slow or hanging
KPI/badge fetch (e.g. over a slow link to the sensor) left ALL the main panels on
"Loading...", because their fetch never started. The symptom seen in production: five
panels on "Loading..." with healthy, fast endpoints.

The fix: the main panels load independently (one Promise.all together with loadKPIs), and
the badge data catches up in the background. This test makes sure the regression does not
come back.
"""

from __future__ import annotations

import re

from honeylens.webui.dashboard_main import render_dashboard

HTML = render_dashboard()


def test_main_panels_are_not_gated_behind_a_prior_await():
    # The old pattern: a separate await on KPIs+badges BEFORE the main panels.
    assert "await Promise.all([loadKPIs(), loadBadgeData()]);" not in HTML, (
        "the main panels must not wait on a separate KPI+badge await — it freezes the dashboard"
    )


def test_kpis_and_main_panels_load_in_one_concurrent_group():
    # loadKPIs and loadScanners must start in the same Promise.all so that neither
    # blocks the other.
    # find the group that contains loadScanners
    groups = re.findall(r"Promise\.all\(\[([^\]]*)\]\)", HTML)
    main_group = next((g for g in groups if "loadScanners()" in g), "")
    assert main_group, "no Promise.all group with the main panels"
    for fn in (
        "loadKPIs()",
        "loadScanners()",
        "loadEvents()",
        "loadMitmStatus()",
        "loadHoneypotStatus()",
    ):
        assert fn in main_group, f"{fn} must be in the same concurrent group as the rest"


def test_badge_data_does_not_block_main_panels():
    # loadBadgeData is meant to run in the background (no await before the main panels).
    assert "loadBadgeData().then(" in HTML, (
        "badges are meant to catch up in the background, not block"
    )
