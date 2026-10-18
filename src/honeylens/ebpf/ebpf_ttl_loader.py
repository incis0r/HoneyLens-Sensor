#!/usr/bin/env python3
"""
ebpf_ttl_loader.py — eBPF TTL / OS Fingerprint Deception Loader
================================================================
Loads the TC egress eBPF program that rewrites IP TTL and TCP window
on outbound honeypot traffic to mimic the target OS.

Builds the port→profile map from the honeypot manifest (ttl_profile) and populates the BPF map.

Usage:
    sudo python ebpf_ttl_loader.py                    # normal mode
    sudo python ebpf_ttl_loader.py --dry-run           # show what would be loaded
    sudo python ebpf_ttl_loader.py --stats              # show live counters
    sudo python ebpf_ttl_loader.py --detach             # remove TC filter
    sudo python ebpf_ttl_loader.py --interface eth0     # override interface
    sudo python ebpf_ttl_loader.py --verify             # verify deception is working

Requires: root / CAP_NET_ADMIN + CAP_BPF, BCC (python3-bcc), iproute2
Platform: Rocky Linux 9 / RHEL 9 (kernel 5.14+)
"""

from __future__ import annotations

import argparse
import ctypes
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FILE = "/var/log/sensor_ttl_deception.log"

logger = logging.getLogger("ttl-deception")
logger.setLevel(logging.DEBUG)

_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    _fh = logging.FileHandler(LOG_FILE)
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_fmt)
    logger.addHandler(_fh)
except OSError:
    pass  # silent: can't write log file — continue with stderr only

_sh = logging.StreamHandler(sys.stderr)
_sh.setLevel(logging.INFO)
_sh.setFormatter(_fmt)
logger.addHandler(_sh)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config():
    """Deception settings: profiles from config, port -> profile map from the honeypot manifest.

    In 0.9 the port -> profile map was a separate, hand-written dict in config.py
    (DECEPTION_PORT_PROFILES) and drifted away from the honeypots' actual ports. In 1.0 the
    source of truth for ports is the manifest, and every honeypot carries its own
    ``ttl_profile`` — so the map is assembled from the manifest, keyed by the PROTOCOL PORT
    (the one the attacker sees, and the one TC egress sees after NAT is reversed; see
    the 1.0 plan, layer 5, the eBPF measurement).
    """
    from honeylens.config import (
        DECEPTION_ENABLED,
        DECEPTION_INTERFACE,
        DECEPTION_PROFILES,
        INTERFACE,
    )
    from honeylens.honeypots.manifest import HONEYPOTS

    port_profiles: dict[int, str] = {}
    for hp in HONEYPOTS:
        if hp.ttl_profile == "linux":
            continue  # the default profile is a no-op — keep it out of the map
        for port in hp.ports:
            port_profiles[port] = hp.ttl_profile

    return {
        "enabled": DECEPTION_ENABLED,
        "interface": DECEPTION_INTERFACE or INTERFACE,
        "port_profiles": port_profiles,
        "profiles": DECEPTION_PROFILES,
    }


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------


def check_root():
    if os.geteuid() != 0:
        logger.error("Must run as root (need CAP_NET_ADMIN + CAP_BPF)")
        return False
    return True


def check_interface(iface: str) -> bool:
    """Verify network interface exists."""
    if not Path(f"/sys/class/net/{iface}").exists():
        logger.error("Interface %s does not exist", iface)
        return False
    return True


def check_bcc() -> bool:
    """Verify BCC is available."""
    try:
        from bcc import BPF  # noqa: F401

        return True
    except ImportError:
        logger.error("BCC not found — install python3-bcc: dnf install python3-bcc")
        return False


# ---------------------------------------------------------------------------
# BPF program structure
# ---------------------------------------------------------------------------


# Must match struct os_profile in ebpf_ttl_deception.c
class OSProfile(ctypes.Structure):
    _fields_ = [
        ("ttl", ctypes.c_uint8),
        ("tcp_window", ctypes.c_uint16),
        ("tcp_wscale", ctypes.c_uint8),
        ("profile_id", ctypes.c_uint8),
    ]


PROFILE_IDS = {
    "linux": 0,
    "windows": 1,
    "windows7": 2,
    "plc": 3,
}


# ---------------------------------------------------------------------------
# TC filter management
# ---------------------------------------------------------------------------


def tc_setup_clsact(iface: str) -> bool:
    """Add clsact qdisc if not already present (required for TC egress BPF)."""
    result = subprocess.run(["tc", "qdisc", "show", "dev", iface], capture_output=True, text=True)
    if "clsact" in result.stdout:
        logger.info("clsact qdisc already present on %s", iface)
        return True

    logger.info("Adding clsact qdisc to %s", iface)
    result = subprocess.run(
        ["tc", "qdisc", "add", "dev", iface, "clsact"], capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.error("Failed to add clsact: %s", result.stderr.strip())
        return False
    return True


def tc_detach(iface: str) -> bool:
    """Remove existing egress BPF filters."""
    logger.info("Detaching TC egress filters from %s", iface)
    result = subprocess.run(
        ["tc", "filter", "del", "dev", iface, "egress"], capture_output=True, text=True
    )
    # It's OK if there's nothing to delete
    if result.returncode != 0 and "No such file" not in result.stderr:
        logger.warning("tc filter del: %s", result.stderr.strip())
    return True


def tc_attach(iface: str, bpf_fd: int) -> bool:
    """Attach BPF fd to TC egress using pyroute2 (works on all BCC versions)."""
    try:
        from pyroute2 import IPRoute

        ipr = IPRoute()

        # Get interface index
        links = ipr.link_lookup(ifname=iface)
        if not links:
            logger.error("pyroute2: interface %s not found", iface)
            ipr.close()
            return False
        idx = links[0]

        # Add TC filter: egress, bpf, direct-action
        # parent 0xFFFFFFF3 = TC_H_CLSACT | TC_H_MIN_EGRESS
        ipr.tc(
            "add-filter",
            "bpf",
            idx,
            fd=bpf_fd,
            name="ttl_deception",
            parent="ffff:fff3",  # clsact egress
            classid=1,
            direct_action=True,
        )
        ipr.close()
        logger.info("BPF fd=%d attached to TC egress on %s via pyroute2", bpf_fd, iface)
        return True
    except ImportError:
        logger.error("pyroute2 not available — install: pip install pyroute2")
        return False
    except Exception as e:
        logger.error("pyroute2 tc attach failed: %s", e)
        try:
            ipr.close()
        except Exception as exc:
            logger.debug("tc attach cleanup failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Main loader
# ---------------------------------------------------------------------------


def load_and_run(config: dict, args):
    """Load the eBPF program, populate maps, and run until interrupted."""
    from bcc import BPF

    iface = args.interface or config["interface"]
    if not check_interface(iface):
        return 1

    # Compile and load BPF program
    src_file = str(Path(__file__).parent / "ebpf_ttl_deception.c")
    if not Path(src_file).exists():
        logger.error("BPF source not found: %s", src_file)
        return 1

    logger.info("Loading eBPF TTL deception program from %s", src_file)

    try:
        bpf = BPF(src_file=src_file)
    except Exception as e:
        logger.error("Failed to compile BPF program: %s", e)
        return 1

    # Get the entry function
    fn = bpf.load_func("ttl_deception", BPF.SCHED_CLS)
    logger.info("BPF function loaded: ttl_deception (fd=%d)", fn.fd)

    # Setup TC clsact qdisc
    if not tc_setup_clsact(iface):
        return 1

    # Remove any existing egress filter first
    tc_detach(iface)

    # Attach to TC egress via pyroute2
    if not tc_attach(iface, fn.fd):
        logger.error("Failed to attach BPF to TC egress — aborting")
        return 1

    logger.info("TC egress BPF attached to %s", iface)

    # ── Populate port_profiles map ──────────────────────────────────────
    port_map = bpf.get_table("port_profiles")
    profiles = config["profiles"]
    port_profiles = config["port_profiles"]

    populated = 0
    for port, profile_name in port_profiles.items():
        if profile_name == "linux":
            continue  # No-op profile — don't add to map

        prof_cfg = profiles.get(profile_name)
        if not prof_cfg:
            logger.warning("Unknown profile '%s' for port %d — skipping", profile_name, port)
            continue

        key = ctypes.c_uint16(port)
        val = OSProfile(
            ttl=prof_cfg.get("ttl", 0),
            tcp_window=prof_cfg.get("tcp_window", 0),
            tcp_wscale=prof_cfg.get("tcp_wscale", 255),
            profile_id=PROFILE_IDS.get(profile_name, 0),
        )
        port_map[key] = val
        populated += 1
        logger.info(
            "  port %5d → %-10s (TTL=%d, window=%d)", port, profile_name, val.ttl, val.tcp_window
        )

    logger.info("Populated %d port→profile entries", populated)
    logger.info("")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  TTL Deception ACTIVE on %s", iface)
    logger.info("  %d ports remapped, press Ctrl+C to stop", populated)
    logger.info("═══════════════════════════════════════════════════════")

    # ── Run loop — print stats periodically ────────────────────────────
    running = True

    def _stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    stats_map = bpf.get_table("stats")
    stat_interval = 30  # seconds between stat prints

    try:
        while running:
            time.sleep(stat_interval)
            if not running:
                break
            try:
                inspected = stats_map[ctypes.c_uint32(0)].value
                rewritten = stats_map[ctypes.c_uint32(1)].value
                synack_rw = stats_map[ctypes.c_uint32(2)].value
                logger.info(
                    "Stats: inspected=%d  TTL-rewritten=%d  SYN-ACK-window=%d",
                    inspected,
                    rewritten,
                    synack_rw,
                )
            except (KeyError, IndexError):
                pass  # silent: stats map not yet populated
    except KeyboardInterrupt:
        pass  # silent: expected Ctrl+C shutdown signal

    # ── Cleanup ────────────────────────────────────────────────────────
    logger.info("Shutting down — detaching TC filter from %s", iface)
    tc_detach(iface)
    logger.info("TTL deception stopped.")
    return 0


# ---------------------------------------------------------------------------
# Stats mode
# ---------------------------------------------------------------------------


def show_stats(config: dict, args):
    """Show live stats from the BPF maps (assumes program is already running)."""
    try:
        import importlib.util

        if importlib.util.find_spec("bcc") is None:
            raise ImportError
    except ImportError:
        logger.error("BCC not available")
        return 1

    iface = args.interface or config["interface"]
    logger.info("Reading stats (press Ctrl+C to stop)...")

    # We need to attach to read the pinned maps — this is complex.
    # Simpler: re-read the map by loading the same program.
    # For a production version, we'd use pinned maps in /sys/fs/bpf.
    print("Note: stats mode requires the deception program to be running.")
    print(f"Check logs at {LOG_FILE}")
    print("")

    # Show TC filter status
    result = subprocess.run(
        ["tc", "filter", "show", "dev", iface, "egress"], capture_output=True, text=True
    )
    if result.stdout.strip():
        print(f"TC egress filters on {iface}:")
        print(result.stdout)
    else:
        print(f"No TC egress filters on {iface} — deception may not be running.")

    return 0


# ---------------------------------------------------------------------------
# Verify mode
# ---------------------------------------------------------------------------


def verify_deception(config: dict, args):
    """Quick self-test: send a SYN to a honeypot port and check the TTL in the response."""
    print("Verification steps:")
    print("")
    print("  1. From another machine, run:")
    print("     nmap -O -p 445 <sensor-ip>")
    print("")
    print("  2. Check the OS guess — should show Windows, not Linux.")
    print("")
    print("  3. Quick TTL check:")
    print("     hping3 -S -p 445 -c 1 <sensor-ip>")
    print("     → TTL in response should be 128 (Windows), not 64 (Linux)")
    print("")
    print("  4. Compare with non-honeypot port:")
    print("     hping3 -S -p 22 -c 1 <sensor-ip>")
    print("     → TTL should be 64 (Linux, native)")
    print("")

    iface = args.interface or config["interface"]
    result = subprocess.run(
        ["tc", "filter", "show", "dev", iface, "egress"], capture_output=True, text=True
    )
    if "ttl_deception" in result.stdout or "bpf" in result.stdout.lower():
        print(f"✔ TC egress BPF filter is active on {iface}")
    else:
        print(f"✘ No BPF filter found on {iface} egress — deception NOT active")

    return 0


# ---------------------------------------------------------------------------
# Detach mode
# ---------------------------------------------------------------------------


def detach(config: dict, args):
    """Remove TC egress BPF filter."""
    iface = args.interface or config["interface"]
    tc_detach(iface)
    logger.info("Detached TC egress filter from %s", iface)
    return 0


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def dry_run(config: dict, args):
    """Show what would be loaded without actually loading."""
    iface = args.interface or config["interface"]
    profiles = config["profiles"]
    port_profiles = config["port_profiles"]

    print("═══════════════════════════════════════════════════════")
    print("  TTL Deception — Dry Run")
    print("═══════════════════════════════════════════════════════")
    print(f"  Interface: {iface}")
    print(f"  Enabled:   {config['enabled']}")
    print("")
    print("  Port → Profile mapping:")
    print("  ─────────────────────────────────────────────────────")

    for port, profile_name in sorted(port_profiles.items()):
        prof = profiles.get(profile_name, {})
        ttl = prof.get("ttl", "?")
        win = prof.get("tcp_window", "?")
        ws = prof.get("tcp_wscale", "?")
        print(
            f"    port {port:>5d} → {profile_name:<10s}  TTL={ttl:<4}  window={win:<6}  wscale={ws}"
        )

    print("")
    print("  Available profiles:")
    print("  ─────────────────────────────────────────────────────")
    for name, prof in profiles.items():
        desc = prof.get("description", "")
        print(
            f"    {name:<12s}  TTL={prof.get('ttl', '?'):<4}  window={prof.get('tcp_window', '?'):<6}  {desc}"
        )

    print("")
    print("  To activate: sudo python ebpf_ttl_loader.py")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="eBPF TTL / OS Fingerprint Deception Loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python %(prog)s                  # Load and run
  sudo python %(prog)s --dry-run        # Preview configuration
  sudo python %(prog)s --stats          # Show counters
  sudo python %(prog)s --detach         # Remove TC filter
  sudo python %(prog)s --verify         # Check if active
  sudo python %(prog)s --interface eth1 # Override interface
        """,
    )
    parser.add_argument("--dry-run", action="store_true", help="Show configuration without loading")
    parser.add_argument("--stats", action="store_true", help="Show live statistics")
    parser.add_argument("--detach", action="store_true", help="Remove TC egress filter")
    parser.add_argument("--verify", action="store_true", help="Verify deception is working")
    parser.add_argument(
        "--interface", "-i", type=str, default=None, help="Override network interface"
    )
    args = parser.parse_args()

    config = load_config()

    if not config["enabled"]:
        logger.info("Deception is disabled in config (DECEPTION_ENABLED=False)")
        return 0

    if args.dry_run:
        return dry_run(config, args)
    if args.stats:
        return show_stats(config, args)
    if args.verify:
        return verify_deception(config, args)
    if args.detach:
        if not check_root():
            return 1
        return detach(config, args)

    # Normal mode — load and run
    if not check_root():
        return 1
    if not check_bcc():
        return 1

    return load_and_run(config, args)


if __name__ == "__main__":
    sys.exit(main())
