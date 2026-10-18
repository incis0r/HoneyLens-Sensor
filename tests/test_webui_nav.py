"""WebUI IA phase 1 — grouped navigation, a11y landmarks, air-gap wrapper."""

from honeylens import config
from honeylens.webui import shared

# --- navigation taxonomy ----------------------------------------------------


def test_every_nav_link_is_in_exactly_one_group():
    grouped = [k for _a, _l, keys in shared.NAV_GROUPS for k in keys]
    link_keys = [e[0] for e in shared.NAV_LINKS]
    assert sorted(grouped) == sorted(link_keys), "every NAV_LINKS key in exactly one group"
    assert len(grouped) == len(set(grouped)), "no key in two groups"


def test_group_keys_reference_real_links():
    link_keys = {e[0] for e in shared.NAV_LINKS}
    for _a, _l, keys in shared.NAV_GROUPS:
        for k in keys:
            assert k in link_keys, f"group references unknown nav key {k}"


# --- grouped nav rendering (WEBUI_NEW_SHELL on) -----------------------------


def test_grouped_nav_is_a_primary_landmark_with_all_destinations(monkeypatch):
    monkeypatch.setattr(config, "WEBUI_NEW_SHELL", True, raising=False)
    html = shared.nav_bar_html("hunting")
    assert '<nav class="topbar" aria-label="Primary">' in html
    for _a, label, _keys in shared.NAV_GROUPS:
        assert f">{label}</summary>" in html  # every area rendered (<details> disclosure)
    for _k, href, _label in [tuple(e[:3]) for e in shared.NAV_LINKS]:
        assert f'href="{href}"' in html  # every destination present


def test_active_link_and_area_are_marked(monkeypatch):
    monkeypatch.setattr(config, "WEBUI_NEW_SHELL", True, raising=False)
    html = shared.nav_bar_html("hunting")
    assert 'aria-current="page"' in html  # active leaf
    assert "nav-area active" in html  # active area (Investigate)
    assert 'action="/logout"' in html  # logout always present


# --- flat fallback (WEBUI_NEW_SHELL off) ------------------------------------


def test_flat_nav_fallback_when_flag_off(monkeypatch):
    monkeypatch.setattr(config, "WEBUI_NEW_SHELL", False, raising=False)
    html = shared.nav_bar_html("dashboard")
    assert "topbar-nav" in html
    assert "nav-areas" not in html
    assert 'action="/logout"' in html


# --- air-gap + accessibility (U9, U12) --------------------------------------


def test_html_page_has_no_external_internet_assets():
    html = shared.html_page("Test", "<p>hi</p>", "dashboard")
    for host in ("googleapis.com", "gstatic.com", "cdnjs", "cloudflare"):
        assert host not in html, f"shared wrapper must not load {host} (air-gap)"


def test_html_page_has_skip_link_and_main_landmark():
    html = shared.html_page("Test", "<p>hi</p>", "dashboard")
    assert 'class="skip-link" href="#main-content"' in html
    assert 'id="main-content"' in html


# --- shared page header / subnav --------------------------------------------


def test_page_header_escapes_untrusted_text():
    html = shared.page_header_html(
        "<script>alert(1)</script>", description="<img src=x onerror=1>", eyebrow="Investigate"
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "Investigate" in html


def test_main_dashboard_template_migrated():
    """Main dashboard (phase 2): no Google Fonts (U12), no duplicated top-bar CSS
    (U4), no redundant 'Dashboards' chip strip (U2)."""
    from honeylens.webui import dashboard_main as dm

    t = dm.DASHBOARD_HTML
    assert "googleapis" not in t
    assert "Dashboards:</span>" not in t
    assert '<div class="api-links"' not in t
    assert "Shared topbar styles" not in t


def test_subnav_marks_active_and_is_section_landmark():
    html = shared.subnav_html(
        [("ov", "/ai/stats", "Overview"), ("rules", "/ai/rules", "Rules")], active="rules"
    )
    assert 'aria-label="Section"' in html
    assert 'aria-current="page"' in html
    assert 'href="/ai/rules"' in html


# ---------------------------------------------------------------------------
# AI Canary page (Idea 52)
# ---------------------------------------------------------------------------


def test_canary_page_is_in_the_deception_area():
    from honeylens.webui.shared import NAV_GROUPS, NAV_LINKS

    assert any(k == "canary" for k, _href, *_ in NAV_LINKS)
    deception = next(g for g in NAV_GROUPS if g[0] == "deception")
    assert "canary" in deception[2]


def test_canary_page_renders_with_the_shared_shell():
    from honeylens.webui.dashboard_canary import CANARY_DASHBOARD_HTML as H

    assert H.startswith("<!DOCTYPE html>") and H.rstrip().endswith("</html>")
    assert "AI Canary" in H
    # pulls its own data as JSON, not through the HTML branch
    assert "/canary/stats?format=json" in H
    # the finding the page exists to show: answered-from vs read-by
    assert "Called back from" in H and "Read by" in H
    assert "origin_src_ip !== r.callback_src_ip" in H.replace("&&", "&&")


def test_canary_page_escapes_untrusted_fields():
    """User-Agent and paths come from attackers, so nothing may be interpolated raw."""
    from honeylens.webui.dashboard_canary import CANARY_DASHBOARD_HTML as H

    for field in (
        "a.user_agent",
        "r.user_agent",
        "r.origin_path",
        "r.callback_src_ip",
        "r.origin_src_ip",
    ):
        # may be wrapped in a fallback, e.g. esc(r.origin_path || '—')
        assert "esc(" + field in H
    assert "innerHTML" in H and "+ r.user_agent" not in H  # nothing raw
