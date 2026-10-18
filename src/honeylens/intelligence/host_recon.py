#!/usr/bin/env python3
"""
intelligence/host_recon.py — Host Reconnaissance via System Tools
=================================================================
Uses dig, host, whois, and traceroute to gather accurate IP intelligence
without relying on rate-limited OSINT APIs.

Data collected:
  - Reverse DNS (PTR record)
  - Forward DNS validation
  - Whois: NetName, OrgName, Country, CIDR, abuse contact, registration dates
  - ASN from whois
  - Hostname patterns (cloud provider, ISP, datacenter detection)

Usage:
    python -m intelligence.host_recon 45.142.193.233
    python -m intelligence.host_recon --batch ips.txt
    python -m intelligence.host_recon --enrich   # enrich attacker_profiles

Run: python -m intelligence.host_recon
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import subprocess  # nosec B404 — fixed system commands (dig, whois, ip, tcpdump), args as a list, no shell
import time
from typing import Any

from honeylens.database import legacy_get_db

# The hostname from the PTR record is controlled by the reverse-DNS owner, and it reaches
# dig's arguments — only DNS-name characters and no leading dash (so it is not treated as an option).
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")

logger = logging.getLogger("host-recon")

# ─── DNS Lookups ─────────────────────────────────────────────────────────


def reverse_dns(ip: str, timeout: int = 5) -> str | None:
    """Get PTR record for IP via dig."""
    ipaddress.ip_address(ip)  # ValueError before anything reaches the process arguments
    try:
        r = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, args as a list, no shell
            ["dig", "+short", "-x", ip, "+time=3", "+tries=1"],  # noqa: S607 # nosec B607 — dig z PATH
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ptr = r.stdout.strip().rstrip(".")
        return ptr if ptr and ";" not in ptr and "timed out" not in ptr.lower() else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def forward_dns(hostname: str, timeout: int = 5) -> list[str]:
    """Resolve hostname to IPs via dig."""
    if not _HOSTNAME_RE.match(hostname or ""):
        return []
    try:
        r = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, args as a list
            ["dig", "+short", hostname, "+time=3", "+tries=1"],  # noqa: S607 # nosec B607
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return [
            line.strip()
            for line in r.stdout.strip().split("\n")
            if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line.strip())
        ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def dns_txt(domain: str, timeout: int = 5) -> list[str]:
    """Get TXT records for domain (SPF, DKIM etc.)."""
    if not _HOSTNAME_RE.match(domain or ""):
        return []
    try:
        r = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, args as a list
            ["dig", "+short", "TXT", domain, "+time=3", "+tries=1"],  # noqa: S607 # nosec B607
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return [
            line.strip().strip('"')
            for line in r.stdout.strip().split("\n")
            if line.strip() and line.strip() != '""'
        ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


# ─── Whois Parsing ───────────────────────────────────────────────────────


def whois_lookup(ip: str, timeout: int = 10) -> dict[str, str]:
    """Parse whois output for IP address."""
    result = {}
    ipaddress.ip_address(ip)
    try:
        r = subprocess.run(["whois", ip], capture_output=True, timeout=timeout)  # noqa: S603, S607 # nosec B603 B607
        text = r.stdout.decode("utf-8", errors="replace")

        # Key patterns to extract (case-insensitive)
        patterns = {
            "netname": r"(?:NetName|netname):\s*(.+)",
            "org_name": r"(?:OrgName|org-name|organisation|Organization):\s*(.+)",
            "country": r"(?:Country|country):\s*([A-Z]{2})",
            "cidr": r"(?:CIDR|inetnum|route):\s*(.+)",
            "asn": r"(?:OriginAS|origin):\s*(?:AS)?(\d+)",
            "abuse_email": r"(?:OrgAbuseEmail|abuse-mailbox|e-mail):\s*(\S+@\S+)",
            "descr": r"(?:OrgTechName|descr|Description):\s*(.+)",
            "city": r"(?:City|city):\s*(.+)",
            "state": r"(?:StateProv|state):\s*(.+)",
            "address": r"(?:Address|address):\s*(.+)",
            "reg_date": r"(?:RegDate|created):\s*(.+)",
            "updated": r"(?:Updated|last-modified|changed):\s*(.+)",
            "ref": r"(?:Ref|source):\s*(https?://\S+|RIPE|ARIN|APNIC|LACNIC|AFRINIC)",
        }

        # Parse all matches — take the LAST one (RIPE/regional block comes after ARIN referral)
        for key, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Filter out junk values
                valid = [
                    m.strip()
                    for m in matches
                    if m.strip() and m.strip() != "***" and "Administered by" not in m
                ]
                if valid:
                    result[key] = valid[-1]  # Last match = most specific (regional RIR block)

        # Extract all route/CIDR entries
        cidrs = re.findall(r"(?:CIDR|route|inetnum):\s*(.+)", text, re.IGNORECASE)
        if cidrs:
            result["all_cidrs"] = [c.strip() for c in cidrs[:5]]

        # Extract RIR (Regional Internet Registry)
        for rir in ["RIPE", "ARIN", "APNIC", "LACNIC", "AFRINIC"]:
            if rir in text:
                result["rir"] = rir
                break

        # Raw whois length for reference
        result["whois_length"] = len(text)

    except subprocess.TimeoutExpired:
        result["error"] = "whois timeout"
    except FileNotFoundError:
        result["error"] = "whois not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Hostname Pattern Analysis ───────────────────────────────────────────

# Cloud/hosting provider patterns in reverse DNS
_PROVIDER_PATTERNS = {
    # Major clouds
    r"\.amazonaws\.com$": ("AWS", "cloud"),
    r"\.compute\.google(apis)?\.com$": ("GCP", "cloud"),
    r"\.azure\.com$": ("Azure", "cloud"),
    r"\.cloudapp\.azure\.com$": ("Azure", "cloud"),
    r"\.digitalocean\.com$": ("DigitalOcean", "cloud"),
    r"\.vultr\.com$": ("Vultr", "cloud"),
    r"\.linode\.com$": ("Linode", "cloud"),
    r"\.hetzner\.com$": ("Hetzner", "hosting"),
    r"\.contabo\.net$": ("Contabo", "hosting"),
    r"\.ovh\.\w+$": ("OVH", "hosting"),
    r"\.scaleway\.com$": ("Scaleway", "cloud"),
    r"\.oracle(cloud)?\.com$": ("Oracle Cloud", "cloud"),
    # VPN/Proxy services
    r"\.nordvpn\.com$": ("NordVPN", "vpn"),
    r"\.expressvpn\.com$": ("ExpressVPN", "vpn"),
    r"\.mullvad\.net$": ("Mullvad", "vpn"),
    r"\.protonvpn\.ch$": ("ProtonVPN", "vpn"),
    r"tor-exit": ("Tor Exit", "tor"),
    r"\.torservers\.": ("Tor", "tor"),
    # Bulletproof / suspicious
    r"\.shodan\.io$": ("Shodan", "scanner"),
    r"\.censys\.io$": ("Censys", "scanner"),
    r"\.shadowserver\.org$": ("Shadowserver", "scanner"),
    # ISP patterns
    r"\.comcast\.net$": ("Comcast", "isp"),
    r"\.verizon\.net$": ("Verizon", "isp"),
    r"\.rr\.com$": ("Spectrum", "isp"),
    r"dsl|adsl|pppoe|dhcp|pool|dynamic|dial": ("Dynamic IP", "residential"),
}

_COUNTRY_TLD = {
    "pl": "PL",
    "de": "DE",
    "fr": "FR",
    "nl": "NL",
    "uk": "GB",
    "co.uk": "GB",
    "ru": "RU",
    "cn": "CN",
    "jp": "JP",
    "br": "BR",
    "ar": "AR",
    "in": "IN",
    "au": "AU",
    "ca": "CA",
    "it": "IT",
    "es": "ES",
    "se": "SE",
    "no": "NO",
    "fi": "FI",
    "dk": "DK",
    "be": "BE",
    "ch": "CH",
    "at": "AT",
    "cz": "CZ",
    "ro": "RO",
    "bg": "BG",
    "hu": "HU",
    "sk": "SK",
    "hr": "HR",
    "ua": "UA",
    "kr": "KR",
    "tw": "TW",
    "sg": "SG",
    "hk": "HK",
    "my": "MY",
    "th": "TH",
    "id": "ID",
    "ph": "PH",
    "vn": "VN",
    "za": "ZA",
    "mx": "MX",
    "co": "CO",
    "cl": "CL",
    "pe": "PE",
    "tr": "TR",
    "il": "IL",
    "ae": "AE",
    "sa": "SA",
    "ir": "IR",
    "eg": "EG",
    "ng": "NG",
    "ke": "KE",
}


def analyze_hostname(hostname: str) -> dict[str, str]:
    """Extract intelligence from reverse DNS hostname."""
    if not hostname:
        return {}

    result: dict[str, Any] = {}
    hn = hostname.lower()

    # Provider detection
    for pattern, (provider, category) in _PROVIDER_PATTERNS.items():
        if re.search(pattern, hn):
            result["provider"] = provider
            result["host_category"] = category
            break

    # Country from TLD
    parts = hn.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        tld2 = ".".join(parts[-2:])
        cc = _COUNTRY_TLD.get(tld2) or _COUNTRY_TLD.get(tld)
        if cc:
            result["country_from_rdns"] = cc

    # IP embedded in hostname (common for residential/dynamic)
    ip_in_host = re.search(r"(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})", hn)
    if ip_in_host:
        result["ip_in_hostname"] = True
        result["host_category"] = result.get("host_category", "residential")

    # Datacenter indicators
    dc_patterns = ["vps", "server", "dedicated", "cloud", "host", "colo"]
    if any(p in hn for p in dc_patterns):
        result["host_category"] = result.get("host_category", "datacenter")

    result["rdns"] = hostname
    return result


# ─── Full Recon ──────────────────────────────────────────────────────────


def recon_ip(ip: str) -> dict:
    """Run full reconnaissance on an IP address."""
    start = time.time()
    result: dict[str, Any] = {"ip": ip, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}

    # 1. Reverse DNS
    ptr = reverse_dns(ip)
    result["rdns"] = ptr

    # 2. Forward validation (does PTR resolve back to this IP?)
    if ptr:
        fwd = forward_dns(ptr)
        result["rdns_validated"] = ip in fwd
        result["rdns_forward_ips"] = fwd

    # 3. Hostname analysis
    if ptr:
        host_info = analyze_hostname(ptr)
        result.update(host_info)

    # 4. Whois
    whois_data = whois_lookup(ip)
    result["whois"] = whois_data

    # Extract key fields from whois
    if whois_data.get("country"):
        result["country_whois"] = whois_data["country"]
    if whois_data.get("org_name"):
        result["org_whois"] = whois_data["org_name"]
    if whois_data.get("netname"):
        result["netname"] = whois_data["netname"]
    if whois_data.get("asn"):
        result["asn_whois"] = int(whois_data["asn"])
    if whois_data.get("abuse_email"):
        result["abuse_email"] = whois_data["abuse_email"]
    if whois_data.get("cidr"):
        result["cidr"] = whois_data["cidr"]
    if whois_data.get("rir"):
        result["rir"] = whois_data["rir"]
    if whois_data.get("city"):
        result["city_whois"] = whois_data["city"]
    if whois_data.get("reg_date"):
        result["registration_date"] = whois_data["reg_date"]

    # 5. Best-guess country (whois > rdns TLD > existing)
    result["country_best"] = result.get("country_whois") or result.get("country_from_rdns") or "??"

    result["elapsed_ms"] = int((time.time() - start) * 1000)
    return result


# ─── Database Enrichment ────────────────────────────────────────────────


def enrich_profiles(limit: int = 50, force: bool = False):
    """Enrich attacker_profiles with host_recon data."""
    conn = legacy_get_db()
    cur = conn.cursor()

    # Find profiles missing rdns or with stale data
    if force:
        cur.execute(
            """
            SELECT host(ip) FROM attacker_profiles
            ORDER BY total_events DESC LIMIT %s
        """,
            (limit,),
        )
    else:
        cur.execute(
            """
            SELECT host(ip) FROM attacker_profiles
            WHERE (as_org IS NULL OR as_org = '' OR country IS NULL OR country = '')
            ORDER BY total_events DESC LIMIT %s
        """,
            (limit,),
        )

    ips = [r[0] for r in cur.fetchall()]
    logger.info("Enriching %d profiles", len(ips))

    enriched = 0
    for ip in ips:
        try:
            data = recon_ip(ip)

            updates = {}
            # Update country if whois has better data
            if data.get("country_whois"):
                updates["country"] = data["country_whois"]
            # Update city if whois has it
            if data.get("city_whois"):
                updates["city"] = data["city_whois"]
            # Update org if whois has it
            if data.get("org_whois") and not data["org_whois"].startswith("***"):
                updates["as_org"] = data["org_whois"]
            # Update ASN if whois found it
            if data.get("asn_whois"):
                updates["asn"] = data["asn_whois"]

            if updates:
                set_clause = ", ".join(f"{k} = %s" for k in updates.keys())
                vals = [*list(updates.values()), ip]
                cur.execute(
                    f"UPDATE attacker_profiles SET {set_clause}, updated_at = NOW() WHERE host(ip) = %s",  # noqa: S608 # nosec B608 — columns from a fixed set in code, values as parameters
                    vals,
                )
                enriched += 1
                logger.info("  %s → %s", ip, json.dumps(updates, default=str))

            # Rate limit: 1 whois per second
            time.sleep(1)

        except Exception as e:
            logger.warning("  %s: error: %s", ip, e)

    conn.commit()
    conn.close()
    logger.info("Enriched %d/%d profiles", enriched, len(ips))


# ─── CLI ─────────────────────────────────────────────────────────────────


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(
        description="Host Reconnaissance via System Tools (dig, whois)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ip", nargs="?", help="IP address to investigate")
    parser.add_argument("--batch", "-b", help="File with one IP per line")
    parser.add_argument("--enrich", action="store_true", help="Enrich attacker_profiles in DB")
    parser.add_argument(
        "--force", action="store_true", help="Re-enrich all profiles (not just empty)"
    )
    parser.add_argument(
        "--limit", "-l", type=int, default=50, help="Max profiles to enrich (default: 50)"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.enrich:
        enrich_profiles(limit=args.limit, force=args.force)
        return

    if args.batch:
        with open(args.batch) as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = []
        for ip in ips:
            r = recon_ip(ip)
            results.append(r)
            if not args.json:
                _print_result(r)
            time.sleep(1)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        return

    if not args.ip:
        parser.print_help()
        return

    result = recon_ip(args.ip)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_result(result)


def _print_result(r: dict):
    """Pretty-print a recon result."""
    B = "\033[1m"
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    D = "\033[90m"
    N = "\033[0m"

    print(f"\n{B}═══ {C}{r['ip']}{N} {B}═══{N}  {D}({r.get('elapsed_ms', 0)}ms){N}")

    # RDNS
    ptr = r.get("rdns")
    validated = r.get("rdns_validated")
    if ptr:
        v = f" {G}✓ validated{N}" if validated else f" {R}✗ not validated{N}"
        print(f"  {B}RDNS:{N}     {C}{ptr}{N}{v}")
    else:
        print(f"  {B}RDNS:{N}     {D}— no PTR record{N}")

    # Provider / category
    if r.get("provider"):
        cat = r.get("host_category", "")
        cat_c = R if cat in ("tor", "vpn") else Y if cat == "scanner" else G
        print(f"  {B}Provider:{N} {cat_c}{r['provider']}{N} ({cat})")

    # Country
    cw = r.get("country_whois", "")
    cr = r.get("country_from_rdns", "")
    cb = r.get("country_best", "??")
    sources = []
    if cw:
        sources.append(f"whois:{cw}")
    if cr:
        sources.append(f"rdns:{cr}")
    print(f"  {B}Country:{N}  {G}{cb}{N}  {D}({', '.join(sources)}){N}")

    # City
    if r.get("city_whois"):
        print(f"  {B}City:{N}     {r['city_whois']}")

    # Org / Netname
    if r.get("org_whois"):
        print(f"  {B}Org:{N}      {r['org_whois']}")
    if r.get("netname"):
        print(f"  {B}NetName:{N}  {r['netname']}")

    # ASN
    if r.get("asn_whois"):
        print(f"  {B}ASN:{N}      AS{r['asn_whois']}")

    # CIDR
    if r.get("cidr"):
        print(f"  {B}CIDR:{N}     {r['cidr']}")

    # RIR
    if r.get("rir"):
        print(f"  {B}RIR:{N}      {r['rir']}")

    # Abuse contact
    if r.get("abuse_email"):
        print(f"  {B}Abuse:{N}    {Y}{r['abuse_email']}{N}")

    # Registration date
    if r.get("registration_date"):
        print(f"  {B}Reg Date:{N} {r['registration_date']}")

    # Hostname features
    if r.get("ip_in_hostname"):
        print(f"  {B}Note:{N}     {Y}IP embedded in hostname (likely residential/dynamic){N}")

    print()


if __name__ == "__main__":
    main()
