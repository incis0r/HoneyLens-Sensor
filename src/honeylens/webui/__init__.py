"""
webui — Hybrid Intelligence Sensor Web Dashboard Package
=========================================================
Provides unified HTML dashboards for the sensor API.

All dashboards share:
  - CSS variables (ICS/OT dark theme)
  - Navigation bar with active page highlighting
  - Event detail drawer with 6 action buttons
  - CSP nonce-based inline script security
  - CSRF token validation for state-changing operations
  - Input sanitisation via html.escape()

Usage in api.py:
    from honeylens.webui import register_webui_routes
    register_webui_routes(app)

Compatible with Python 3.9+.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_webui_routes(app: "FastAPI") -> None:
    """
    Register all WebUI HTML dashboard routes on the FastAPI app.
    Called from api.py after the app is created and middleware is attached.
    """
    # Import and register each dashboard module
    from honeylens.webui.dashboard_ai import register_routes as reg_ai
    from honeylens.webui.dashboard_archive import register_routes as reg_archive
    from honeylens.webui.dashboard_classifier import register_routes as reg_classifier
    from honeylens.webui.dashboard_hunting import register_routes as reg_hunting
    from honeylens.webui.dashboard_ics import register_routes as reg_ics
    from honeylens.webui.dashboard_ja4 import register_routes as reg_ja4
    from honeylens.webui.dashboard_main import register_routes as reg_main
    from honeylens.webui.dashboard_mitm import register_routes as reg_mitm
    from honeylens.webui.dashboard_mitre import register_routes as reg_mitre
    from honeylens.webui.endpoint_generic import register_routes as reg_generic

    # Order matters for FastAPI route matching:
    # Static paths before parameterised paths
    reg_main(app)
    reg_ics(app)
    reg_ai(app)
    reg_hunting(app)
    reg_mitm(app)
    reg_classifier(app)
    reg_mitre(app)
    reg_ja4(app)
    reg_archive(app)
    reg_generic(app)
