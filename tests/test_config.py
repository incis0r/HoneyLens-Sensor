"""honeylens.config — traffic filters and parsers for .env values; constants read via env()."""

from __future__ import annotations

import pytest

from honeylens import config


def test_parse_src_host_ports_keeps_pairs_and_drops_garbage() -> None:
    got = config.parse_src_host_ports(
        "192.0.2.50:5432, 192.0.2.50:9090,198.51.100.0/24:161, bad, :5, h:0, h:70000, h:x"
    )
    assert got == {"192.0.2.50": {5432, 9090}, "198.51.100.0/24": {161}}


def test_parse_src_host_ports_survives_ipv6() -> None:
    assert config.parse_src_host_ports("2001:db8::5:5432") == {"2001:db8::5": {5432}}


def test_parse_siem_config_accepts_only_a_json_list() -> None:
    assert config.parse_siem_config("") == []
    assert config.parse_siem_config("{}") == []
    assert config.parse_siem_config("not json") == []
    assert config.parse_siem_config('[{"type":"syslog"}]') == [{"type": "syslog"}]


def test_parse_list() -> None:
    assert config.parse_list("") == []
    assert config.parse_list(" a, b ,,c ") == ["a", "b", "c"]


def test_should_ignore_traffic_management_ports(monkeypatch) -> None:
    monkeypatch.setattr(config, "IGNORE_PORTS", [62222])
    assert config.should_ignore_traffic(dst_port=62222)
    assert not config.should_ignore_traffic(dst_port=22)


def test_should_ignore_traffic_high_ports_unless_always_captured(monkeypatch) -> None:
    monkeypatch.setattr(config, "IGNORE_PORTS", [])
    monkeypatch.setattr(config, "IGNORE_DST_PORT_ABOVE", 30000)
    monkeypatch.setattr(config, "ALWAYS_CAPTURE_PORTS", [8443])
    assert config.should_ignore_traffic(dst_port=40000)
    assert not config.should_ignore_traffic(dst_port=8443)
    assert not config.should_ignore_traffic(dst_port=443)
    monkeypatch.setattr(config, "IGNORE_DST_PORT_ABOVE", 0)
    assert not config.should_ignore_traffic(dst_port=40000)


def test_should_ignore_traffic_local_sources_by_network(monkeypatch) -> None:
    monkeypatch.setattr(config, "IGNORE_PORTS", [])
    monkeypatch.setattr(config, "IGNORE_LOCAL_SOURCES", ["198.51.100.0/24", "garbage"])
    assert config.should_ignore_traffic(src_ip="198.51.100.10")
    assert not config.should_ignore_traffic(src_ip="10.1.6.10")
    assert not config.should_ignore_traffic(src_ip="not-an-ip")


def test_should_ignore_traffic_src_host_port_pair_only(monkeypatch) -> None:
    """A scalpel: one host on one port; the same host on another port stays visible."""
    monkeypatch.setattr(config, "IGNORE_PORTS", [])
    monkeypatch.setattr(config, "IGNORE_LOCAL_SOURCES", [])
    monkeypatch.setattr(
        config, "IGNORE_SRC_HOST_PORTS", {"192.0.2.50": {5432}, "198.51.100.0/24": {161}}
    )
    assert config.should_ignore_traffic(src_ip="192.0.2.50", dst_port=5432)
    assert not config.should_ignore_traffic(src_ip="192.0.2.50", dst_port=22)
    assert not config.should_ignore_traffic(src_ip="192.0.2.51", dst_port=5432)
    assert config.should_ignore_traffic(src_ip="198.51.100.77", dst_port=161)
    assert not config.should_ignore_traffic(src_ip="bad", dst_port=161)


def test_get_port_filter_sql(monkeypatch) -> None:
    monkeypatch.setattr(config, "IGNORE_DST_PORT_ABOVE", 30000)
    monkeypatch.setattr(config, "ALWAYS_CAPTURE_PORTS", [22, 443])
    assert config.get_port_filter_sql() == "(dst_port <= 30000 OR dst_port IN (22,443))"
    assert config.get_port_filter_sql("p") == "(p <= 30000 OR p IN (22,443))"
    monkeypatch.setattr(config, "IGNORE_DST_PORT_ABOVE", 0)
    assert config.get_port_filter_sql() == "TRUE"


def test_get_sensor_interfaces(monkeypatch) -> None:
    monkeypatch.delenv("SENSOR_INTERFACES", raising=False)
    monkeypatch.setattr(config, "INTERFACE", "eth0")
    assert config.get_sensor_interfaces() == ["eth0"]
    monkeypatch.setenv("SENSOR_INTERFACES", "eth0, eth1,")
    assert config.get_sensor_interfaces() == ["eth0", "eth1"]


def test_fortigate_config_ports_fall_back_to_defaults(monkeypatch) -> None:
    monkeypatch.setattr(
        config, "env", lambda k, d=None, cast=None: {"FORTIGATE_PORTS": "x,,"}.get(k, d)
    )
    assert config.get_fortigate_config()["ports"] == list(config.FORTIGATE_PORTS)


def test_db_config_has_a_connect_timeout() -> None:
    """Without it, importing text_rules hangs on an unreachable host for the full TCP timeout."""
    assert config.DB_CONFIG["connect_timeout"] >= 1


def test_paths_hang_off_sensor_home() -> None:
    assert str(config.PCAP_DIR).startswith(str(config.SENSOR_HOME))
    assert str(config.TLS_CERT_DIR).startswith(str(config.SENSOR_HOME))


@pytest.mark.parametrize(
    "name",
    [
        "DB_CONFIG",
        "SESSION",
        "BLOG",
        "ATTACKER_PROFILING",
        "SIEM_FORWARDERS",
        "ENABLED_PLUGINS",
        "SENSOR_HOSTNAME",
        "EBPF_DISSECTION_PORTS",
    ],
)
def test_public_constants_exist(name: str) -> None:
    assert hasattr(config, name)


def test_no_duplicate_definitions_in_config_source() -> None:
    """0.9 defined EVENTS_JSON, PCAP_DIR, HONEYPOTNG_GLOB and HONEYPOT_LOG_GLOBS twice; the
    second one was the 'effective' one and somebody already lost K8s events to that once."""
    import re
    from pathlib import Path

    src = Path(config.__file__).read_text()
    names = re.findall(r"^([A-Z][A-Z0-9_]+)\s*(?::\s*[^=]+)?=", src, flags=re.M)
    dupes = {n for n in names if names.count(n) > 1}
    assert dupes == set()
