"""
webui/dashboard_archive.py — Archive Dashboard
================================================
Routes at /archive/* for archived event tables, search, stats.
HTML rendering is handled by api.py using endpoint_generic functions.
Compatible with Python 3.9+.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    """Archive routes are served by api.py — this is a placeholder for future
    dedicated archive dashboard HTML."""
    pass
