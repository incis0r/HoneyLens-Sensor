"""The manifest is the only source of truth for what a honeypot is — so it must be true.

Every entry has to resolve to real code, every honeypot in the tree has to be in it
(a decoy left out of the manifest is a decoy nobody can deploy), and what the
generator writes has to be the runtime we measured: rootless, pasta, UTC,
identity on a volume, the protocol port inside the container.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

from honeylens.honeypots import cli, manifest
from honeylens.honeypots._base import BaseHoneypot

HONEYPOTS_DIR = Path(manifest.__file__).parent

# In the tree but deliberately not deployed: hp_s7comm was replaced by ics.cotp102 under
# the same PROTOCOL and unit name in 0.9 (sensor-hp-s7comm.service).
NOT_DEPLOYED = {"honeylens.honeypots.hp_s7comm"}


def test_every_entry_resolves_to_a_class_or_a_main():
    for hp in manifest.HONEYPOTS:
        module = importlib.import_module(hp.module)
        target = getattr(module, hp.entry)
        if inspect.isclass(target):
            assert issubclass(target, BaseHoneypot), hp.name
            assert target.DEFAULT_PORT == hp.ports[0], f"{hp.name}: manifest port != DEFAULT_PORT"
        else:
            assert callable(target), hp.name


def test_every_base_honeypot_in_the_tree_is_in_the_manifest():
    in_manifest = {hp.module for hp in manifest.HONEYPOTS}
    missing = []
    for path in HONEYPOTS_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text())
        has_base = any(
            isinstance(n, ast.ClassDef)
            and any(getattr(b, "id", None) == "BaseHoneypot" for b in n.bases)
            for n in ast.walk(tree)
        )
        if not has_base:
            continue
        rel = path.relative_to(HONEYPOTS_DIR.parent.parent).with_suffix("")
        modname = ".".join(rel.parts)
        if modname not in in_manifest and modname not in NOT_DEPLOYED:
            missing.append(modname)
    assert not missing, f"BaseHoneypot subclasses not in the manifest: {missing}"


def test_names_are_unique_and_ports_are_sane():
    names = [hp.name for hp in manifest.HONEYPOTS]
    assert len(names) == len(set(names))
    for hp in manifest.HONEYPOTS:
        assert hp.ports, hp.name
        assert len(set(hp.ports)) == len(hp.ports), hp.name
        for bound, public in hp.port_map:
            assert 1 <= public <= 65535
            assert 1024 <= bound <= 65535, f"{hp.name}: bound port {bound} needs root"
            if hp.port_block:
                assert bound == hp.port_block + public
            elif public < 1024 or public in manifest.HOST_RESERVED_PORTS:
                # < 1024 without root; a host-reserved port (5432 = the sensor's own
                # Postgres) without colliding with the database — both go high and via DNAT.
                assert bound == 30000 + public, f"{hp.name}: {public} must bind high"
            else:
                assert bound == public


def test_translated_ports_are_pinned_through_env_not_code():
    """A base honeypot reads HP_<PROTO>_PORT; the manifest gives it the high port and the
    map back to the protocol port, so the process needs no privilege and the database
    still sees 502."""
    modbus = manifest.get("modbus")
    assert modbus.runtime_env == {"HP_MODBUS_PORT": "30502", "HONEYLENS_PORT_MAP": "30502:502"}
    assert "HONEYLENS_PORT_MAP" not in manifest.get("redis").runtime_env
    mono = manifest.get("honeypot").runtime_env
    assert "40022:ssh" in mono["HONEYPOTNG_SERVICES"]
    assert "8443" not in mono["HONEYPOTNG_SERVICES"], "8080/8443 belong to Flask in the monolith"
    assert mono["HONEYWEB_PORT"] == "48080" and mono["HONEYWEB_TLS_PORT"] == "48443"
    assert "40022:22" in mono["HONEYLENS_PORT_MAP"] and "48443:8443" in mono["HONEYLENS_PORT_MAP"]
    assert manifest.get("llm-tls").runtime_env["LLM_HONEYPOT_PORT"] == "30443"


def test_decoys_never_bind_directly_on_ports_the_sensor_host_owns():
    """5432 (the sensor's Postgres) and 60443 (the API) belong to the host. A decoy with such
    a protocol port must bind high (30000+) and rely on DNAT — otherwise it collides with the
    sensor's own database. Measured on a 1.0 sensor: hp-postgres in a restart loop, because
    5432 was held by the real PostgreSQL 13. This is the case on every 1.0 sensor."""
    from honeylens.honeypots.manifest import HOST_RESERVED_PORTS, bind_port

    for hp in manifest.HONEYPOTS:
        for bound, _proto in hp.port_map:
            assert bound not in HOST_RESERVED_PORTS, (
                f"{hp.name} binds a host-reserved port directly: {bound}"
            )
    assert bind_port(5432) == 35432
    pg = manifest.get("postgres")
    assert pg.port_map == [(35432, 5432)], "the event must see 5432, the bind is 35432"
    assert pg.runtime_env["HP_POSTGRES_PORT"] == "35432"
    assert pg.runtime_env["HONEYLENS_PORT_MAP"] == "35432:5432"


def test_udp_honeypots_are_the_datagram_ones():
    udp = {hp.name for hp in manifest.HONEYPOTS if hp.udp}
    assert udp == {"bacnet", "profinet"}


# ------------------------------------------------------------------ the launcher


def test_run_starts_a_base_honeypot_through_its_class(monkeypatch):
    from honeylens.honeypots import hp_modbus

    monkeypatch.delenv("HP_MODBUS_PORT", raising=False)
    started = []
    monkeypatch.setattr(hp_modbus.ModbusHoneypot, "run", lambda self: started.append(self.port))
    assert cli.run("modbus") == 0
    assert started == [30502], "bound high: no root needed inside the container"


def test_run_pins_the_manifest_env_and_makes_the_identity(monkeypatch, tmp_path):
    from honeylens.honeypots import hp_nginx

    monkeypatch.setenv("HONEYLENS_IDENTITY_DIR", str(tmp_path))
    monkeypatch.delenv("HP_NGINX_CERT", raising=False)
    seen = {}
    monkeypatch.setattr(hp_nginx, "main", lambda: seen.update(dict(os.environ)) or 0)
    import os

    assert cli.run("nginx") == 0
    assert seen["HP_NGINX_PORT"] == "8443"
    assert seen["HP_NGINX_CERT"] == str(tmp_path / "nginx.crt")
    assert (tmp_path / "nginx.crt").exists() and (tmp_path / "nginx.key").exists()
    assert (tmp_path / "nginx.key").stat().st_mode & 0o777 == 0o600


def test_run_clears_argv_so_the_honeypot_parser_sees_no_stray_name(monkeypatch):
    """`honeylens-hp paloalto` leaves 'paloalto' in sys.argv; a honeypot main() with its
    own argparse (paloalto, fortigate) then died on 'unrecognized arguments: paloalto'.
    run() must reset argv before dispatching so the parser falls back to env/defaults."""
    import argparse
    import sys

    from honeylens.honeypots import hp_wago

    monkeypatch.setattr(sys, "argv", ["honeylens-hp", "wago"])

    seen_argv = []

    def fake_main():
        # exactly what paloalto's main() does: its own argparse reads sys.argv[1:]
        parser = argparse.ArgumentParser(prog="honeylens-hp")
        parser.add_argument("--port")
        parser.parse_args()  # raises SystemExit if argv still carries "wago"
        seen_argv.append(list(sys.argv))
        return 0

    monkeypatch.setattr(hp_wago, "main", fake_main)
    assert cli.run("wago") == 0
    assert seen_argv and "wago" not in seen_argv[0][1:]


def test_operator_env_outranks_the_manifest(monkeypatch, tmp_path):
    from honeylens.honeypots import hp_wago

    monkeypatch.setenv("HONEYLENS_IDENTITY_DIR", str(tmp_path))
    monkeypatch.setenv("HP_WAGO_PORT", "18090")
    seen = {}
    import os

    monkeypatch.setattr(hp_wago, "main", lambda: seen.update(dict(os.environ)) or 0)
    cli.run("wago")
    assert seen["HP_WAGO_PORT"] == "18090"


def test_a_self_signed_identity_is_made_once(tmp_path):
    cert, key = tmp_path / "a.crt", tmp_path / "a.key"
    assert cli.ensure_self_signed(cert, key, "x") is True
    first = cert.read_bytes()
    assert cli.ensure_self_signed(cert, key, "x") is False
    assert cert.read_bytes() == first, "a regenerated certificate is a changed fingerprint"


def test_unknown_name_is_an_error():
    with pytest.raises(KeyError):
        manifest.get("nope")


# ------------------------------------------------------------------ the quadlets


def test_quadlets_encode_the_measured_runtime(tmp_path):
    written = cli.write_quadlets(
        tmp_path, state_dir="/var/lib/honeylens", image_tag="1.0.0", registry="localhost"
    )
    assert len(written) == len(manifest.HONEYPOTS) + 1
    modbus = (tmp_path / "hp-modbus.container").read_text()
    assert "Network=pasta" in modbus
    assert "UserNS=keep-id:uid=1000,gid=1000" in modbus
    assert "PublishPort=30502:30502\n" in modbus
    assert "Environment=HP_MODBUS_PORT=30502" in modbus
    assert "Environment=HONEYLENS_PORT_MAP=30502:502" in modbus
    assert "AddCapability" not in modbus and "DropCapability=ALL" in modbus
    assert "Environment=TZ=UTC" in modbus
    assert "Image=localhost/honeylens/hp-modbus:1.0.0" in modbus
    assert "Volume=/var/lib/honeylens/hp-logs:/opt/logs:z" in modbus
    assert "identity" not in modbus.split("[Container]")[1].split("ReadOnly")[0].replace(
        "/var/lib/honeylens/hp-logs", ""
    )
    bacnet = (tmp_path / "hp-bacnet.container").read_text()
    assert "PublishPort=47808:47808/udp" in bacnet
    nginx = (tmp_path / "hp-nginx.container").read_text()
    assert "Volume=/var/lib/honeylens/identity/nginx:/var/lib/honeylens/identity:Z" in nginx
    assert "Environment=HP_NGINX_CERT=/var/lib/honeylens/identity/nginx.crt" in nginx
    k8s = (tmp_path / "hp-k8s.container").read_text()
    assert "Environment=K8S_HONEYPOT_LOG_FILE=/opt/logs/honeypotng/honeypot_k8s.json" in k8s
    mono = (tmp_path / "hp-honeypot.container").read_text()
    assert "AddCapability" not in mono
    assert "PublishPort=40021:40021\n" in mono and "PublishPort=48080:48080\n" in mono
    fw = (tmp_path / "firewalld-forwards.sh").read_text()
    assert "port=502:proto=tcp:toport=30502" in fw
    # 5432 is the sensor's own Postgres: the decoy binds 35432, DNAT delivers (HOST_RESERVED_PORTS)
    assert "port=5432:proto=tcp:toport=35432" in fw
    # redis 6379: bound directly and not served by the monolith — the only port with no DNAT
    assert "port=6379" not in fw, "no DNAT where host and container port are the same"


def test_the_two_paloalto_decoys_share_one_identity():
    assert manifest.get("paloalto").identity == manifest.get("paloalto-ssh").identity


def test_the_monolith_stands_beside_the_hp_decoys():
    """The monolith lives in its own 40000+ block and nginx moved its cleartext listener
    to 8000 (Dariusz, 2026-09-20), so no two units claim one host port any more."""
    assert cli.port_conflicts(manifest.HONEYPOTS) == []


# ------------------------------------------------------ eBPF TTL deception (layer 8)


def test_every_ttl_profile_has_a_definition():
    """The eBPF loader builds its port->profile map from these values (layer 8); a
    profile a honeypot carries but config.DECEPTION_PROFILES does not define would be
    silently dropped from the BPF map at load time."""
    from honeylens import config

    for hp in manifest.HONEYPOTS:
        assert hp.ttl_profile in config.DECEPTION_PROFILES, (
            f"{hp.name}: ttl_profile {hp.ttl_profile!r} is not in DECEPTION_PROFILES"
        )


def test_ics_decoys_carry_the_plc_fingerprint():
    """The OT/ICS honeypots must not leak the native Linux TTL/window — that is the whole
    point of the deception layer. WINDOWS for the Windows-facing services, plc for OT."""
    plc = {hp.name for hp in manifest.HONEYPOTS if hp.ttl_profile == "plc"}
    windows = {hp.name for hp in manifest.HONEYPOTS if hp.ttl_profile == "windows"}
    assert plc == {
        "modbus",
        "dnp3",
        "iec104",
        "enip",
        "opcua",
        "fins",
        "s7comm",
        "bacnet",
        "fox",
        "profinet",
    }
    assert windows == {"ldap", "rdp", "smb", "sharepoint"}


def test_the_loader_map_keys_on_protocol_ports():
    """The map the loader hands the BPF program is keyed on the protocol port (what TC
    egress sees after NAT reversal), not the 30000+ bound host port."""
    from honeylens.ebpf.ebpf_ttl_loader import load_config

    port_profiles = load_config()["port_profiles"]
    assert port_profiles[502] == "plc"  # modbus, protocol port — not 30502
    assert port_profiles[445] == "windows"  # smb
    assert 30502 not in port_profiles
    # linux (no-op default) is never populated
    assert all(prof != "linux" for prof in port_profiles.values())
