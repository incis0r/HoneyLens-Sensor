"""Plugin loader and ``HoneyLensCore`` adapter.

Loaded once at sensor-api startup. The adapter implements the ``HoneyLensCore`` protocol
from the public ``honeylens_plugin_api`` ABI (package name unchanged since 0.9, because
external plugins import it directly); the loader iterates ``config.ENABLED_PLUGINS`` and
calls each plugin's ``register(core)``.

Failure isolation: a plugin that raises in import, constructor or ``register()`` is
logged and skipped; sensor-api keeps running.
"""

import importlib
import logging
from collections.abc import Callable
from typing import Any

from honeylens_plugin_api import CURRENT_API_VERSION, HoneyLensCore

logger = logging.getLogger("honeylens.plugins")


def _api_compatible(plugin_api: str | None, core_api: str | None) -> bool:
    """Compatible = same major version."""
    if not plugin_api or not core_api:
        return False
    return plugin_api.split(".", 1)[0] == core_api.split(".", 1)[0]


class HoneyLensCoreAdapter:
    """Concrete ``HoneyLensCore`` implementation passed to ``plugin.register()``."""

    api_version = CURRENT_API_VERSION

    def __init__(self, fastapi_app: Any | None = None) -> None:
        self._fastapi_app = fastapi_app
        self._fingerprinters: dict[str, Callable[..., Any]] = {}
        self._dashboard_widgets: dict[str, list[Callable[..., str]]] = {}
        self._pending_migrations: list[str] = []
        self._pending_rule_files: list[str] = []

    # --- detection ---------------------------------------------------------
    def register_fingerprinter(self, name: str, fn: Callable[..., Any]) -> None:
        if name in self._fingerprinters:
            logger.warning("fingerprinter %r already registered, overwriting", name)
        self._fingerprinters[name] = fn

    def get_fingerprinter(self, name: str) -> Callable[..., Any] | None:
        return self._fingerprinters.get(name)

    # --- routing -----------------------------------------------------------
    def register_route_module(self, prefix: str, module: Any) -> None:
        if self._fastapi_app is None:
            logger.warning(
                "register_route_module(%r) called but no FastAPI app bound — skipping", prefix
            )
            return
        router = getattr(module, "router", None)
        if router is None:
            raise ValueError(f"register_route_module: {module!r} has no 'router' attribute")
        self._fastapi_app.include_router(router, prefix=prefix)

    # --- rules and schema --------------------------------------------------
    def register_rules_from(self, yaml_path: str) -> None:
        # The consumer (the rule loader in classification) collects them via get_pending_rule_files().
        self._pending_rule_files.append(yaml_path)

    def register_schema_migration(self, sql_path: str) -> None:
        self._pending_migrations.append(sql_path)

    def get_pending_rule_files(self) -> list[str]:
        return list(self._pending_rule_files)

    def get_pending_migrations(self) -> list[str]:
        return list(self._pending_migrations)

    # --- dashboard ---------------------------------------------------------
    def register_dashboard_widget(self, slot: str, render_fn: Callable[..., str]) -> None:
        self._dashboard_widgets.setdefault(slot, []).append(render_fn)

    def get_dashboard_widgets(self, slot: str) -> list[Callable[..., str]]:
        return list(self._dashboard_widgets.get(slot, ()))

    # --- resources ---------------------------------------------------------
    def get_db(self) -> Any:
        from honeylens.database import get_db

        return get_db()

    def get_logger(self, name: str) -> logging.Logger:
        return logging.getLogger(f"plugins.{name}")

    def get_config(self, key: str, default: Any = None) -> Any:
        from honeylens import config

        return getattr(config, key, default)

    @property
    def fingerprinter_names(self) -> list[str]:
        return sorted(self._fingerprinters)


def load_plugins(core: HoneyLensCore, enabled: list[str]) -> list[str]:
    """Load every plugin in ``enabled``; return the names of those that succeeded.

    Each stage (import, constructor, API compatibility, ``register``) is isolated
    separately: ``except Exception`` is intentional here, because plugin code is foreign
    and may raise anything, and one bad plugin must not stop the sensor.
    """
    loaded: list[str] = []
    for name in enabled:
        module_name = f"honeylens_{name}"
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:
            logger.error("plugin %s: import %s failed: %s", name, module_name, exc)
            continue

        plugin_cls = getattr(mod, "Plugin", None)
        if plugin_cls is None:
            logger.error("plugin %s: module %s has no Plugin class", name, module_name)
            continue

        try:
            plugin = plugin_cls()
        except Exception as exc:
            logger.error("plugin %s: Plugin() failed: %s", name, exc)
            continue

        plugin_api = getattr(plugin, "API_VERSION", None)
        if not _api_compatible(plugin_api, core.api_version):
            logger.error(
                "plugin %s targets API %s, core is %s — skipping",
                name,
                plugin_api,
                core.api_version,
            )
            continue

        try:
            plugin.register(core)
        except Exception as exc:
            logger.error("plugin %s: register() raised %s — skipping", name, exc)
            continue

        logger.info(
            "plugin loaded: %s v%s (API %s)",
            getattr(plugin, "NAME", name),
            getattr(plugin, "VERSION", "?"),
            plugin_api,
        )
        loaded.append(name)
    return loaded
