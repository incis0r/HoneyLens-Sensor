"""HoneyLens plugin ABI — type definitions.

A plugin imports the Plugin and HoneyLensCore Protocols from this module,
declares its own Plugin class implementing the protocol, and is loaded by
core/plugins.py at sensor-api startup.

API VERSIONING
--------------
The HoneyLensCore.api_version string follows semver. Bump the major when
removing a method or changing a method signature in a backwards-
incompatible way; bump the minor when adding a method. Plugins declare
their target API_VERSION; the loader rejects plugins built against an
incompatible major.

CURRENT API VERSION: "1.0"
"""

import logging
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

# The single source of truth for the current API version.
CURRENT_API_VERSION = "1.0"


@runtime_checkable
class HoneyLensCore(Protocol):
    """The narrow ABI a plugin is allowed to call."""

    api_version: str  # e.g. "1.0"

    # Detection extension points
    def register_fingerprinter(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a fingerprinter function under a stable name.

        ``name`` is the wire-protocol identifier (e.g. "ja4s", "ja4h").
        Callers retrieve the fingerprinter via core.get_fingerprinter(name)
        and skip the call when get_fingerprinter returns None.
        """
        ...

    def get_fingerprinter(self, name: str) -> Callable[..., Any] | None:
        """Return the registered fingerprinter for ``name`` or None.

        Used by ingest paths to graceful-degrade when a plugin isn't loaded.
        """
        ...

    # Routing extension points
    def register_route_module(self, prefix: str, module: Any) -> None:
        """Mount a FastAPI APIRouter (the module must expose ``router``).

        Plugin's routes appear under the given prefix.
        """
        ...

    # Detection-rule and schema extension points
    def register_rules_from(self, yaml_path: str) -> None:
        """Append rules from a YAML file the plugin ships."""
        ...

    def register_schema_migration(self, sql_path: str) -> None:
        """Register a SQL migration the plugin needs applied at startup."""
        ...

    # Dashboard extension point
    def register_dashboard_widget(self, slot: str, render_fn: Callable[..., str]) -> None:
        """Attach a dashboard widget to a named slot.

        Slots known to OSS HoneyLens 1.0:
          - "ja4_variants"   (under the JA4 tab)
          - "scoring_extra"  (under the Profile page)
        """
        ...

    # Resource accessors plugins may need
    def get_db(self) -> Any:
        """Return the shared psycopg2 connection from core.database.get_db()."""
        ...

    def get_logger(self, name: str) -> logging.Logger:
        """Return a logger namespaced under the plugin name."""
        ...

    def get_config(self, key: str, default: Any = None) -> Any:
        """Read a value from config.py (returns ``default`` if unset)."""
        ...


@runtime_checkable
class Plugin(Protocol):
    """The Plugin contract.

    Each plugin module exports a ``Plugin`` class with ``NAME``, ``VERSION``,
    ``API_VERSION`` class attributes and a ``register(core)`` method.

    Example:

        class Plugin:
            NAME = "ja4_plus"
            VERSION = "1.0.0"
            API_VERSION = "1.0"
            def register(self, core: HoneyLensCore) -> None:
                core.register_fingerprinter("ja4s", parse_ja4s)
                core.register_route_module("/api/v2/ja4plus", routes)
                core.register_rules_from("rules/ja4_plus.yaml")
    """

    NAME: str
    VERSION: str
    API_VERSION: str

    def register(self, core: HoneyLensCore) -> None: ...
