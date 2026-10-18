"""core.plugins — loader wtyczek i adapter HoneyLensCore. Port 1:1 z 0.9 tests/test_plugin_loader.py."""

from __future__ import annotations

import sys
import types

import pytest

from honeylens.plugins import HoneyLensCoreAdapter, _api_compatible, load_plugins

# ---------------------------------------------------------------------------
# _api_compatible
# ---------------------------------------------------------------------------


class TestApiCompatible:
    def test_same_major_minor(self):
        assert _api_compatible("1.0", "1.0")

    def test_same_major_different_minor(self):
        assert _api_compatible("1.5", "1.0")
        assert _api_compatible("1.0", "1.5")

    def test_different_major_rejected(self):
        assert not _api_compatible("2.0", "1.0")
        assert not _api_compatible("1.0", "2.0")

    def test_none_or_empty_rejected(self):
        assert not _api_compatible(None, "1.0")
        assert not _api_compatible("", "1.0")
        assert not _api_compatible("1.0", "")


# ---------------------------------------------------------------------------
# HoneyLensCoreAdapter
# ---------------------------------------------------------------------------


class TestAdapter:
    def test_fingerprinter_register_and_get(self):
        c = HoneyLensCoreAdapter()
        f = lambda x: x  # noqa: E731
        c.register_fingerprinter("ja4s", f)
        assert c.get_fingerprinter("ja4s") is f
        assert c.get_fingerprinter("ja4h") is None

    def test_fingerprinter_overwrite_logs_warning(self, caplog):
        c = HoneyLensCoreAdapter()
        c.register_fingerprinter("ja4s", lambda x: 1)
        with caplog.at_level("WARNING"):
            c.register_fingerprinter("ja4s", lambda x: 2)
        assert any("already registered" in r.message for r in caplog.records)

    def test_dashboard_widgets_list_per_slot(self):
        c = HoneyLensCoreAdapter()
        c.register_dashboard_widget("ja4_variants", lambda: "<a/>")
        c.register_dashboard_widget("ja4_variants", lambda: "<b/>")
        c.register_dashboard_widget("scoring_extra", lambda: "<c/>")
        assert len(c.get_dashboard_widgets("ja4_variants")) == 2
        assert len(c.get_dashboard_widgets("scoring_extra")) == 1
        assert c.get_dashboard_widgets("nonexistent") == []

    def test_pending_collections(self):
        c = HoneyLensCoreAdapter()
        c.register_rules_from("/tmp/rules.yaml")
        c.register_schema_migration("/tmp/0001.sql")
        assert "/tmp/rules.yaml" in c._pending_rule_files
        assert "/tmp/0001.sql" in c._pending_migrations

    def test_register_route_module_no_app_warns(self, caplog):
        c = HoneyLensCoreAdapter(fastapi_app=None)
        with caplog.at_level("WARNING"):
            c.register_route_module("/api/v2/x", types.SimpleNamespace())
        assert any("no FastAPI app bound" in r.message for r in caplog.records)

    def test_register_route_module_missing_router_attr_raises(self):
        # Use a fake app to get past the "no app" warning.
        fake_app = types.SimpleNamespace(include_router=lambda *a, **k: None)
        c = HoneyLensCoreAdapter(fastapi_app=fake_app)
        with pytest.raises(ValueError, match="no 'router' attribute"):
            c.register_route_module("/api/v2/x", types.SimpleNamespace())


# ---------------------------------------------------------------------------
# load_plugins — failure-isolation contract
# ---------------------------------------------------------------------------


def _install_fake_plugin_module(name: str, plugin_cls):
    """Inject a fake honeylens_<name> module into sys.modules for the test."""
    mod_name = f"honeylens_{name}"
    mod = types.ModuleType(mod_name)
    mod.Plugin = plugin_cls
    sys.modules[mod_name] = mod


class _GoodPlugin:
    NAME = "good"
    VERSION = "1.0.0"
    API_VERSION = "1.0"
    registered = False

    def register(self, core):
        type(self).registered = True


class _IncompatiblePlugin:
    NAME = "incompat"
    VERSION = "0.1.0"
    API_VERSION = "2.0"  # major mismatch with core

    def register(self, core):
        raise AssertionError("should never be called")


class _RaisesAtConstruct:
    NAME = "rs"
    VERSION = "0.1.0"
    API_VERSION = "1.0"

    def __init__(self):
        raise RuntimeError("constructor blew up")

    def register(self, core):
        pass


class _RaisesAtRegister:
    NAME = "rr"
    VERSION = "0.1.0"
    API_VERSION = "1.0"

    def register(self, core):
        raise RuntimeError("register blew up")


class TestLoadPlugins:
    def setup_method(self):
        # Ensure a clean class-level state for _GoodPlugin between tests
        _GoodPlugin.registered = False

    def test_empty_list_loads_nothing(self):
        c = HoneyLensCoreAdapter()
        assert load_plugins(c, []) == []

    def test_unknown_module_skipped(self, caplog):
        c = HoneyLensCoreAdapter()
        # Make sure no real package exists
        sys.modules.pop("honeylens_doesnotexist", None)
        with caplog.at_level("ERROR"):
            assert load_plugins(c, ["doesnotexist"]) == []
        assert any("import honeylens_doesnotexist failed" in r.message for r in caplog.records)

    def test_good_plugin_loads(self):
        _install_fake_plugin_module("good", _GoodPlugin)
        c = HoneyLensCoreAdapter()
        assert load_plugins(c, ["good"]) == ["good"]
        assert _GoodPlugin.registered

    def test_incompatible_api_skipped(self, caplog):
        _install_fake_plugin_module("incompat", _IncompatiblePlugin)
        c = HoneyLensCoreAdapter()
        with caplog.at_level("ERROR"):
            assert load_plugins(c, ["incompat"]) == []
        assert any("targets API 2.0" in r.message for r in caplog.records)

    def test_constructor_failure_skipped(self, caplog):
        _install_fake_plugin_module("rs", _RaisesAtConstruct)
        c = HoneyLensCoreAdapter()
        with caplog.at_level("ERROR"):
            assert load_plugins(c, ["rs"]) == []
        assert any("Plugin() failed" in r.message for r in caplog.records)

    def test_register_failure_skipped_other_plugins_still_load(self, caplog):
        _install_fake_plugin_module("rr", _RaisesAtRegister)
        _install_fake_plugin_module("good", _GoodPlugin)
        c = HoneyLensCoreAdapter()
        with caplog.at_level("ERROR"):
            loaded = load_plugins(c, ["rr", "good"])
        assert loaded == ["good"]  # rr skipped, good loaded
        assert _GoodPlugin.registered
