#!/usr/bin/env python3
"""
ttl_profiler.py — OS Fingerprint Profiler for Deception Profiles
================================================================
Captures real TCP/IP stack characteristics from live hosts to create
custom OS deception profiles for the eBPF TTL deception system.

Modes:
  1. PROBE  — Send SYN probes to a real host and capture its fingerprint
  2. SNIFF  — Passively sniff traffic from a host on the local network
  3. NMAP   — Parse an existing Nmap OS detection XML output
  4. EXPORT — Export captured profiles to config.py-compatible Python dict

Use cases:
  - Profile a real Windows Server to get exact TTL/window/options values
  - Profile a real Siemens S7-1200 PLC on port 102
  - Profile a real FortiGate to clone its TCP stack for the honeypot
  - Import Nmap fingerprint scans as deception profiles

Usage:
    # Probe a real Windows box
    sudo python ttl_profiler.py probe 192.168.1.50 --ports 445,3389,135

    # Probe a real PLC
    sudo python ttl_profiler.py probe 10.0.1.100 --ports 102,502

    # Passive sniff (watch traffic from a host)
    sudo python ttl_profiler.py sniff --host 192.168.1.50 --interface eth0 --duration 30

    # Import Nmap OS detection results
    sudo python ttl_profiler.py nmap scan_results.xml

    # List saved profiles
    python ttl_profiler.py list

    # Export profile for config.py
    python ttl_profiler.py export windows-server-2022

    # Export all profiles
    python ttl_profiler.py export --all

    # Delete a profile
    python ttl_profiler.py delete windows-server-2022

Requires: root (for probe/sniff), scapy
Install:  pip install scapy
Profiles: stored in ./profiles/ttl_profiles.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Profile storage
# ---------------------------------------------------------------------------

PROFILE_DIR = Path(__file__).parent / "profiles"
PROFILE_FILE = PROFILE_DIR / "ttl_profiles.json"


def _load_profiles() -> dict[str, dict]:
    """Load saved profiles from disk."""
    if not PROFILE_FILE.exists():
        return {}
    try:
        with open(PROFILE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_profiles(profiles: dict[str, dict]):
    """Save profiles to disk."""
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    with open(PROFILE_FILE, "w") as f:
        json.dump(profiles, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    ORANGE = "\033[38;5;208m"
    PURPLE = "\033[38;5;141m"


# ---------------------------------------------------------------------------
# TCP option parsing
# ---------------------------------------------------------------------------

TCP_OPT_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "WScale",
    4: "SAckOK",
    5: "SAck",
    8: "Timestamp",
    14: "AltChkSum",
    15: "AltChkSumOpt",
    28: "UTO",
    34: "TFO",
    254: "Experiment",
}


def parse_tcp_options(opts) -> list[dict]:
    """Parse scapy TCP options into structured list."""
    result: list[dict[str, Any]] = []
    if not opts:
        return result
    for opt in opts:
        if isinstance(opt, tuple):
            kind_name = (
                opt[0]
                if isinstance(opt[0], str)
                else TCP_OPT_NAMES.get(opt[0], f"Unknown({opt[0]})")
            )
            entry: dict[str, Any] = {"kind": kind_name}
            if len(opt) > 1 and opt[1] is not None:
                val = opt[1]
                if kind_name == "MSS":
                    entry["value"] = int(val)
                elif kind_name == "WScale":
                    entry["value"] = int(val)
                elif kind_name == "Timestamp":
                    if isinstance(val, (tuple, list)) and len(val) >= 2:
                        entry["value"] = {"tsval": val[0], "tsecr": val[1]}
                    else:
                        entry["value"] = val
                elif kind_name == "SAckOK":
                    entry["value"] = True
                else:
                    entry["value"] = repr(val)
            result.append(entry)
        else:
            result.append({"kind": str(opt)})
    return result


def options_order_string(opts: list[dict]) -> str:
    """Get the TCP options order as a compact string."""
    return ",".join(o["kind"] for o in opts)


# ---------------------------------------------------------------------------
# OS guessing
# ---------------------------------------------------------------------------


def guess_os_from_fingerprint(fp: dict) -> str:
    """Heuristic OS guess from captured fingerprint."""
    ttl = fp.get("ttl", 0)
    window = fp.get("tcp_window", 0)
    wscale = fp.get("tcp_wscale")
    mss = fp.get("mss")
    opts_order = fp.get("options_order", "")

    # Windows signatures
    if 120 <= ttl <= 128:
        if window == 65535 and wscale == 8:
            return "Windows 10/11 / Server 2019+"
        elif window == 8192:
            return "Windows 7 / Server 2008"
        elif window == 65535:
            return "Windows (modern)"
        return "Windows (generic)"

    # Linux signatures
    elif 60 <= ttl <= 64:
        if wscale == 7 and window in range(28000, 30000):
            return "Linux 5.x/6.x (modern)"
        elif wscale == 7:
            return "Linux (modern kernel)"
        elif wscale == 6:
            return "Linux 4.x"
        elif "Timestamp" in opts_order:
            return "Linux (generic)"
        return "Linux / Unix"

    # Embedded / PLC
    elif 25 <= ttl <= 32:
        if mss and mss < 1000:
            return "Embedded / PLC (small MSS)"
        return "Embedded / PLC / IoT"

    # BSD
    elif ttl == 255:
        return "Solaris / AIX / HP-UX"

    # Cisco / networking gear
    elif ttl == 255 or ttl == 64:
        if window and window < 4096:
            return "Network device (switch/router)"

    return f"Unknown (TTL={ttl})"


# ---------------------------------------------------------------------------
# PROBE mode — active SYN fingerprinting
# ---------------------------------------------------------------------------


def probe_host(target: str, ports: list[int], timeout: float = 5.0, verbose: bool = False) -> dict:
    """
    Send SYN probes to target and capture fingerprint from SYN-ACK responses.
    Returns a profile dict.
    """
    from scapy.all import IP, TCP, RandShort, conf, sr1

    conf.verb = 0
    results = {}

    print(f"\n  {C.BOLD}Probing {C.CYAN}{target}{C.RESET} ({len(ports)} ports, timeout={timeout}s)")
    print()

    for port in ports:
        sport = int(RandShort())
        # Craft SYN with standard options (mimic a real OS)
        pkt = IP(dst=target, ttl=64) / TCP(
            sport=sport,
            dport=port,
            flags="S",
            seq=1000,
            window=65535,
            options=[
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (int(time.time()), 0)),
                ("NOP", None),
                ("WScale", 7),
            ],
        )

        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        rtt = (time.time() - t0) * 1000

        if resp is None:
            print(f"    port {port:>5d}  {C.DIM}no response (filtered/closed){C.RESET}")
            continue

        if not resp.haslayer(TCP):
            print(f"    port {port:>5d}  {C.DIM}non-TCP response{C.RESET}")
            continue

        tcp = resp[TCP]
        ip = resp[IP]

        if tcp.flags != 0x12:  # Not SYN-ACK
            flags_str = str(tcp.flags) if hasattr(tcp.flags, "__str__") else hex(tcp.flags)
            print(f"    port {port:>5d}  {C.DIM}flags={flags_str} (not SYN-ACK){C.RESET}")
            # Still capture TTL from RST
            if tcp.flags & 0x04:  # RST
                results[port] = {
                    "port": port,
                    "open": False,
                    "ttl": ip.ttl,
                    "rtt_ms": round(rtt, 1),
                }
            # Send RST
            rst = IP(dst=target) / TCP(sport=sport, dport=port, flags="R", seq=1001)
            sr1(rst, timeout=0.5, verbose=0)
            continue

        # Parse SYN-ACK
        opts = parse_tcp_options(tcp.options)
        wscale = None
        mss = None
        ts_rate = None
        for o in opts:
            if o["kind"] == "WScale":
                wscale = o.get("value")
            elif o["kind"] == "MSS":
                mss = o.get("value")
            elif o["kind"] == "Timestamp" and isinstance(o.get("value"), dict):
                ts_rate = o["value"].get("tsval")

        fp = {
            "port": port,
            "open": True,
            "ttl": ip.ttl,
            "tcp_window": tcp.window,
            "tcp_wscale": wscale,
            "mss": mss,
            "df": bool(ip.flags.DF) if hasattr(ip.flags, "DF") else bool(ip.flags & 0x2),
            "ip_id": ip.id,
            "options": opts,
            "options_order": options_order_string(opts),
            "timestamp_val": ts_rate,
            "rtt_ms": round(rtt, 1),
        }

        results[port] = fp

        # Display
        os_g = guess_os_from_fingerprint(fp)
        ttl_c = C.CYAN if ip.ttl >= 120 else (C.ORANGE if ip.ttl <= 32 else C.DIM)
        print(
            f"    port {port:>5d}  "
            f"TTL={ttl_c}{ip.ttl:<4d}{C.RESET}  "
            f"window={tcp.window:<6d}  "
            f"wscale={wscale if wscale is not None else '—':<4}  "
            f"MSS={mss if mss else '—':<5}  "
            f"DF={'Y' if fp['df'] else 'N'}  "
            f"opts=[{fp['options_order']}]  "
            f"→ {C.BOLD}{os_g}{C.RESET}"
        )

        if verbose:
            print(f"             IP.id={ip.id}  TS.val={ts_rate}  RTT={rtt:.1f}ms")

        # Send RST to close
        rst = IP(dst=target) / TCP(sport=sport, dport=port, flags="R", seq=1001)
        sr1(rst, timeout=0.5, verbose=0)
        time.sleep(0.1)

    return results


def build_profile_from_probes(name: str, target: str, results: dict, description: str = "") -> dict:
    """Build a deception profile from probe results."""
    # Find the most common TTL/window across open ports
    open_fps = [r for r in results.values() if r.get("open")]
    if not open_fps:
        print(f"\n  {C.RED}No open ports found — cannot build profile{C.RESET}")
        return {}

    # Use majority values
    ttls = [r["ttl"] for r in open_fps]
    windows = [r["tcp_window"] for r in open_fps]
    wscales = [r.get("tcp_wscale") for r in open_fps if r.get("tcp_wscale") is not None]
    msses = [r.get("mss") for r in open_fps if r.get("mss") is not None]

    from collections import Counter

    most_common_ttl = Counter(ttls).most_common(1)[0][0]
    most_common_win = Counter(windows).most_common(1)[0][0]
    most_common_ws = Counter(wscales).most_common(1)[0][0] if wscales else None

    os_guess = guess_os_from_fingerprint(
        {
            "ttl": most_common_ttl,
            "tcp_window": most_common_win,
            "tcp_wscale": most_common_ws,
            "mss": msses[0] if msses else None,
            "options_order": open_fps[0].get("options_order", ""),
        }
    )

    profile = {
        "name": name,
        "description": description or f"Profiled from {target} — {os_guess}",
        "ttl": most_common_ttl,
        "tcp_window": most_common_win,
        "tcp_wscale": most_common_ws if most_common_ws is not None else 255,
        "mss": msses[0] if msses else 1460,
        "os_guess": os_guess,
        "source": {
            "method": "probe",
            "target": target,
            "ports_probed": list(results.keys()),
            "ports_open": [p for p, r in results.items() if r.get("open")],
            "timestamp": datetime.now(UTC).isoformat(),
        },
        "per_port": {},
    }

    # Store per-port details for ports that differ from the majority
    for port, fp in results.items():
        if not fp.get("open"):
            continue
        port_entry = {
            "ttl": fp["ttl"],
            "tcp_window": fp["tcp_window"],
            "tcp_wscale": fp.get("tcp_wscale"),
            "mss": fp.get("mss"),
            "df": fp.get("df"),
            "options_order": fp.get("options_order", ""),
        }
        profile["per_port"][str(port)] = port_entry

    return profile


# ---------------------------------------------------------------------------
# SNIFF mode — passive fingerprinting
# ---------------------------------------------------------------------------


def sniff_host(host: str, interface: str, duration: int = 30, verbose: bool = False) -> dict:
    """Passively sniff SYN-ACK packets from a target host."""
    from scapy.all import IP, TCP, conf
    from scapy.all import sniff as scapy_sniff

    conf.verb = 0
    results = {}

    print(
        f"\n  {C.BOLD}Sniffing traffic from {C.CYAN}{host}{C.RESET} on {interface} for {duration}s"
    )
    print(f"  {C.DIM}(generate traffic to the host to capture SYN-ACK responses){C.RESET}")
    print()

    def process_pkt(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]

        # We want packets FROM the target host (SYN-ACK responses)
        if ip.src != host:
            return
        if tcp.flags != 0x12:  # SYN-ACK only
            return

        port = tcp.sport
        opts = parse_tcp_options(tcp.options)
        wscale = None
        mss = None
        for o in opts:
            if o["kind"] == "WScale":
                wscale = o.get("value")
            elif o["kind"] == "MSS":
                mss = o.get("value")

        fp = {
            "port": port,
            "open": True,
            "ttl": ip.ttl,
            "tcp_window": tcp.window,
            "tcp_wscale": wscale,
            "mss": mss,
            "df": bool(ip.flags & 0x2),
            "options": opts,
            "options_order": options_order_string(opts),
        }

        if port not in results:
            results[port] = fp
            os_g = guess_os_from_fingerprint(fp)
            print(
                f"    Captured port {port:>5d}  "
                f"TTL={ip.ttl:<4d}  window={tcp.window:<6d}  "
                f"wscale={wscale if wscale is not None else '—':<4}  "
                f"→ {C.BOLD}{os_g}{C.RESET}"
            )

    bpf_filter = f"src host {host} and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"

    try:
        scapy_sniff(
            iface=interface,
            filter=bpf_filter,
            prn=process_pkt,
            timeout=duration,
            store=False,
        )
    except PermissionError:
        print(f"  {C.RED}Permission denied — run as root{C.RESET}")
    except OSError as e:
        print(f"  {C.RED}Sniff error: {e}{C.RESET}")

    print(f"\n  Captured {len(results)} unique port fingerprints")
    return results


# ---------------------------------------------------------------------------
# NMAP mode — parse Nmap OS detection XML
# ---------------------------------------------------------------------------


def parse_nmap_xml(xml_file: str) -> list[dict]:
    """Parse Nmap XML output with OS detection results.

    Uses defusedxml to neutralise XXE / billion-laughs / external-entity
    attacks even though the input is operator-supplied — defence in depth.
    """
    import defusedxml.ElementTree as ET

    profiles: list[dict[str, Any]] = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"  {C.RED}Failed to parse {xml_file}: {e}{C.RESET}")
        return profiles

    for host in root.findall(".//host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        # Get OS matches
        os_elem = host.find("os")
        if os_elem is None:
            continue

        os_matches = os_elem.findall("osmatch")
        if not os_matches:
            continue

        best_match = os_matches[0]  # Highest accuracy
        os_name = best_match.get("name", "Unknown OS")
        accuracy = best_match.get("accuracy", "?")

        # Get fingerprint details from osclass
        osclass = best_match.find("osclass")
        os_family = osclass.get("osfamily", "") if osclass is not None else ""
        os_gen = osclass.get("osgen", "") if osclass is not None else ""

        # Get open port info for TTL extraction
        ports_elem = host.find("ports")
        port_details = {}
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    portid = int(port_elem.get("portid", 0))
                    port_details[portid] = {
                        "port": portid,
                        "protocol": port_elem.get("protocol", "tcp"),
                        "service": "",
                    }
                    svc = port_elem.find("service")
                    if svc is not None:
                        port_details[portid]["service"] = svc.get("name", "")

        # Guess TTL from OS family
        if "windows" in os_family.lower():
            ttl = 128
            window = 65535
            wscale = 8
        elif "linux" in os_family.lower():
            ttl = 64
            window = 29200
            wscale = 7
        elif any(k in os_name.lower() for k in ["siemens", "plc", "scada", "embedded"]):
            ttl = 30
            window = 2048
            wscale = 0
        else:
            ttl = 64
            window = 29200
            wscale = 7

        safe_name = os_name.lower().replace(" ", "-").replace("/", "-")[:40]
        profile = {
            "name": f"nmap-{safe_name}",
            "description": f"{os_name} (Nmap {accuracy}% confidence) from {ip}",
            "ttl": ttl,
            "tcp_window": window,
            "tcp_wscale": wscale,
            "os_guess": os_name,
            "source": {
                "method": "nmap",
                "file": xml_file,
                "target": ip,
                "accuracy": accuracy,
                "os_family": os_family,
                "os_generation": os_gen,
                "ports_open": list(port_details.keys()),
                "timestamp": datetime.now(UTC).isoformat(),
            },
        }
        profiles.append(profile)

        print(
            f"    {C.CYAN}{ip}{C.RESET}  "
            f"{C.BOLD}{os_name}{C.RESET} ({accuracy}%)  "
            f"TTL={ttl}  family={os_family}  "
            f"ports={list(port_details.keys())}"
        )

    return profiles


# ---------------------------------------------------------------------------
# LIST / EXPORT / DELETE commands
# ---------------------------------------------------------------------------


def cmd_list(args):
    """List all saved profiles."""
    profiles = _load_profiles()

    if not profiles:
        print(f"\n  {C.DIM}No saved profiles. Create one with:{C.RESET}")
        print(f"    sudo python {sys.argv[0]} probe <target> --ports 445,3389")
        return 0

    print(f"\n  {C.BOLD}Saved Profiles ({len(profiles)}){C.RESET}")
    print(f"  {'─' * 78}")
    print(
        f"  {C.BOLD}{'Name':<25s}  {'TTL':>4s}  {'Window':>7s}  {'WScale':>6s}  "
        f"{'OS Guess':<30s}{C.RESET}"
    )
    print(f"  {'─' * 78}")

    for name, prof in sorted(profiles.items()):
        ttl = prof.get("ttl", "?")
        win = prof.get("tcp_window", "?")
        ws = prof.get("tcp_wscale", "?")
        os_g = prof.get("os_guess", prof.get("description", ""))[:30]
        method = prof.get("source", {}).get("method", "?")

        if isinstance(ttl, int) and ttl >= 120:
            c = C.CYAN
        elif isinstance(ttl, int) and ttl <= 32:
            c = C.ORANGE
        else:
            c = C.DIM

        print(
            f"  {name:<25s}  {c}{ttl:>4}{C.RESET}  {win:>7}  {ws:>6}  "
            f"{os_g:<30s}  {C.DIM}[{method}]{C.RESET}"
        )

    print(f"  {'─' * 78}")
    print()
    return 0


def cmd_export(args):
    """Export profiles as config.py-compatible Python dict."""
    profiles = _load_profiles()

    if args.name == "--all" or args.all:
        to_export = profiles
    else:
        if args.name not in profiles:
            print(f"  {C.RED}Profile '{args.name}' not found{C.RESET}")
            print(f"  Available: {', '.join(profiles.keys())}")
            return 1
        to_export = {args.name: profiles[args.name]}

    print("\n# ── Paste into config.py DECEPTION_PROFILES ──")
    print()

    for name, prof in to_export.items():
        safe_name = name.replace("-", "_").replace(" ", "_")
        print(f'    "{safe_name}": {{')
        print(f'        "ttl": {prof["ttl"]},')
        print(f'        "tcp_window": {prof["tcp_window"]},')
        ws = prof.get("tcp_wscale")
        print(f'        "tcp_wscale": {ws if ws is not None else 255},')
        desc = prof.get("description", prof.get("os_guess", name))
        print(f'        "description": "{desc}",')
        print("    },")
        print()

    # Also show port mapping suggestion
    print("# ── Suggested DECEPTION_PORT_PROFILES entries ──")
    print()
    for name, prof in to_export.items():
        safe_name = name.replace("-", "_").replace(" ", "_")
        ports_open = prof.get("source", {}).get("ports_open", [])
        if ports_open:
            for p in ports_open:
                print(f'    {p}: "{safe_name}",')
    print()

    return 0


def cmd_delete(args):
    """Delete a saved profile."""
    profiles = _load_profiles()
    if args.name not in profiles:
        print(f"  {C.RED}Profile '{args.name}' not found{C.RESET}")
        return 1

    del profiles[args.name]
    _save_profiles(profiles)
    print(f"  {C.GREEN}Deleted profile '{args.name}'{C.RESET}")
    return 0


# ---------------------------------------------------------------------------
# PROBE command
# ---------------------------------------------------------------------------


def cmd_probe(args):
    """Probe a target and save the fingerprint as a profile."""
    try:
        from scapy.all import conf  # noqa: F401
    except ImportError:
        print(f"  {C.RED}scapy required — pip install scapy{C.RESET}")
        return 1

    if os.geteuid() != 0:
        print(f"  {C.RED}Must run as root (raw sockets){C.RESET}")
        return 1

    ports = [int(p.strip()) for p in args.ports.split(",")]
    results = probe_host(args.target, ports, timeout=args.timeout, verbose=args.verbose)

    if not any(r.get("open") for r in results.values()):
        print(f"\n  {C.RED}No open ports found on {args.target}{C.RESET}")
        return 1

    # Build profile
    name = args.name or f"probe-{args.target.replace('.', '-')}"
    profile = build_profile_from_probes(name, args.target, results, args.description or "")

    if not profile:
        return 1

    # Display summary
    print(f"\n  {C.BOLD}{'═' * 60}{C.RESET}")
    print(f"  {C.BOLD}Profile: {C.CYAN}{name}{C.RESET}")
    print(f"  {C.BOLD}{'═' * 60}{C.RESET}")
    print(f"    OS Guess:    {C.BOLD}{profile['os_guess']}{C.RESET}")
    print(f"    TTL:         {profile['ttl']}")
    print(f"    TCP Window:  {profile['tcp_window']}")
    print(f"    TCP WScale:  {profile['tcp_wscale']}")
    print(f"    MSS:         {profile.get('mss', '—')}")
    print(f"    Ports open:  {profile['source']['ports_open']}")

    # Save
    if not args.no_save:
        profiles = _load_profiles()
        if name in profiles and not args.force:
            print(
                f"\n  {C.YELLOW}Profile '{name}' already exists. Use --force to overwrite.{C.RESET}"
            )
            return 1
        profiles[name] = profile
        _save_profiles(profiles)
        print(f"\n  {C.GREEN}Profile saved as '{name}'{C.RESET}")
        print(f"  {C.DIM}Export with: python {sys.argv[0]} export {name}{C.RESET}")
    else:
        print(f"\n  {C.DIM}(not saved — use without --no-save to persist){C.RESET}")

    return 0


# ---------------------------------------------------------------------------
# SNIFF command
# ---------------------------------------------------------------------------


def cmd_sniff(args):
    """Passively sniff and build profile."""
    try:
        from scapy.all import conf  # noqa: F401
    except ImportError:
        print(f"  {C.RED}scapy required — pip install scapy{C.RESET}")
        return 1

    if os.geteuid() != 0:
        print(f"  {C.RED}Must run as root{C.RESET}")
        return 1

    results = sniff_host(
        args.host,
        args.interface,
        duration=args.duration,
        verbose=args.verbose,
    )

    if not results:
        print(
            f"\n  {C.YELLOW}No SYN-ACK packets captured. "
            f"Make sure traffic is flowing to/from {args.host}.{C.RESET}"
        )
        return 1

    name = args.name or f"sniff-{args.host.replace('.', '-')}"
    profile = build_profile_from_probes(name, args.host, results, args.description or "")

    if profile and not args.no_save:
        profiles = _load_profiles()
        profiles[name] = profile
        _save_profiles(profiles)
        print(f"\n  {C.GREEN}Profile saved as '{name}'{C.RESET}")

    return 0


# ---------------------------------------------------------------------------
# NMAP command
# ---------------------------------------------------------------------------


def cmd_nmap(args):
    """Import profiles from Nmap XML."""
    if not Path(args.xml_file).exists():
        print(f"  {C.RED}File not found: {args.xml_file}{C.RESET}")
        return 1

    print(f"\n  {C.BOLD}Parsing Nmap OS detection from {args.xml_file}{C.RESET}\n")

    imported = parse_nmap_xml(args.xml_file)

    if not imported:
        print(f"\n  {C.YELLOW}No OS fingerprints found in XML{C.RESET}")
        return 1

    if not args.no_save:
        profiles = _load_profiles()
        for prof in imported:
            name = prof["name"]
            profiles[name] = prof
        _save_profiles(profiles)
        print(f"\n  {C.GREEN}Imported {len(imported)} profiles{C.RESET}")

    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="OS Fingerprint Profiler — capture real TCP/IP characteristics "
        "for eBPF TTL deception profiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    # probe
    p_probe = sub.add_parser("probe", help="Actively probe a host to capture its fingerprint")
    p_probe.add_argument("target", help="Target IP address")
    p_probe.add_argument(
        "--ports", "-p", required=True, help="Comma-separated ports to probe (e.g. 445,3389,135)"
    )
    p_probe.add_argument("--name", "-n", default=None, help="Profile name (default: probe-<ip>)")
    p_probe.add_argument("--description", default="", help="Profile description")
    p_probe.add_argument(
        "--timeout", "-t", type=float, default=5.0, help="Timeout per probe (default: 5s)"
    )
    p_probe.add_argument("--verbose", "-v", action="store_true")
    p_probe.add_argument("--no-save", action="store_true", help="Don't save profile to disk")
    p_probe.add_argument("--force", "-f", action="store_true", help="Overwrite existing profile")

    # sniff
    p_sniff = sub.add_parser("sniff", help="Passively sniff traffic from a host")
    p_sniff.add_argument("--host", required=True, help="Host IP to capture from")
    p_sniff.add_argument("--interface", "-i", default="eth0", help="Capture interface")
    p_sniff.add_argument(
        "--duration", "-d", type=int, default=30, help="Capture duration in seconds (default: 30)"
    )
    p_sniff.add_argument("--name", "-n", default=None, help="Profile name")
    p_sniff.add_argument("--description", default="", help="Profile description")
    p_sniff.add_argument("--verbose", "-v", action="store_true")
    p_sniff.add_argument("--no-save", action="store_true")

    # nmap
    p_nmap = sub.add_parser("nmap", help="Import from Nmap OS detection XML")
    p_nmap.add_argument("xml_file", help="Nmap XML output file (nmap -O -oX)")
    p_nmap.add_argument("--no-save", action="store_true")

    # list
    sub.add_parser("list", help="List saved profiles")

    # export
    p_export = sub.add_parser("export", help="Export profile as config.py snippet")
    p_export.add_argument(
        "name", nargs="?", default="--all", help="Profile name to export (or --all)"
    )
    p_export.add_argument("--all", action="store_true", help="Export all profiles")

    # delete
    p_del = sub.add_parser("delete", help="Delete a saved profile")
    p_del.add_argument("name", help="Profile name to delete")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "probe": cmd_probe,
        "sniff": cmd_sniff,
        "nmap": cmd_nmap,
        "list": cmd_list,
        "export": cmd_export,
        "delete": cmd_delete,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
