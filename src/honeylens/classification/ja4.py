"""
ja4.py — JA4 TLS Client Fingerprinting (BSD)
==============================================
Implements the BASE JA4 fingerprint as defined by FoxIO, distributed
under BSD 3-Clause:
    https://github.com/FoxIO-LLC/ja4

JA4 Format (a_b_c):
    a = Protocol(q/t/d) + TLS_Version + SNI(d/i) + CipherCount + ExtCount + ALPN
    b = Truncated SHA256 of sorted cipher suites (12 chars)
    c = Truncated SHA256 of sorted extensions + signature algorithms (12 chars)

Example: t13d1516h2_8daaf6152771_02713d6af862

NOTE on JA4+ variants
---------------------
The JA4+ variant suite (JA4S, JA4H, JA4X, JA4SSH, JA4T) is licensed under
the FoxIO Licence 1.1 — non-commercial use only. Those parsers are NOT
shipped with this OSS distribution. Operators who need them can either
build their own implementations or install the separate enterprise
plugin (honeylens_ja4_plus).

When the plugin is loaded the registry returns the variant fingerprinters;
when it isn't, ingest paths skip the variant computation and the
ja4_fingerprints table simply contains rows of fingerprint_type='ja4'
only. No schema migration is needed to upgrade.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from typing import Any

logger = logging.getLogger("honeylens.classifier.ja4")

# ===========================================================================
# GREASE Values (RFC 8701)
# ===========================================================================

GREASE_VALUES: set[int] = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


def is_grease(value: int) -> bool:
    """Check if a value is a GREASE value (should be filtered)."""
    return value in GREASE_VALUES


# ===========================================================================
# TLS Version Mapping for JA4
# ===========================================================================

TLS_VERSION_MAP: dict[int, str] = {
    0x0300: "s3",  # SSL 3.0
    0x0301: "10",  # TLS 1.0
    0x0302: "11",  # TLS 1.1
    0x0303: "12",  # TLS 1.2
    0x0304: "13",  # TLS 1.3
}

# For display purposes
TLS_VERSION_NAMES: dict[int, str] = {
    0x0300: "SSL3.0",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}


def tls_version_to_ja4(version: int) -> str:
    """Convert TLS version to JA4 format (2 chars)."""
    return TLS_VERSION_MAP.get(version, "00")


def get_highest_tls_version(versions: list[int]) -> int:
    """Get highest supported TLS version from list, ignoring GREASE."""
    valid = [v for v in versions if not is_grease(v)]
    return max(valid) if valid else 0x0303


# ===========================================================================
# ALPN Protocol Mapping
# ===========================================================================

ALPN_MAP: dict[str, str] = {
    "http/1.1": "h1",
    "http/1.0": "h1",
    "h2": "h2",
    "h2c": "h2",
    "h3": "h3",
    "spdy/3.1": "sp",
    "http/2": "h2",
    "grpc": "gr",
    "imap": "im",
    "pop3": "po",
    "ftp": "ft",
    "stun.turn": "st",
    "stun.nat-discovery": "sn",
    "webrtc": "wr",
    "c-webrtc": "cw",
    "mqtt": "mq",
    "dns": "dn",
    "dot": "dt",  # DNS over TLS
    "doq": "dq",  # DNS over QUIC
}


def alpn_to_ja4(alpn: str | None) -> str:
    """Convert ALPN to JA4 format (first+last char or mapped value)."""
    if not alpn:
        return "00"

    # Check mapping first
    alpn_lower = alpn.lower()
    if alpn_lower in ALPN_MAP:
        return ALPN_MAP[alpn_lower]

    # Use first and last character
    if len(alpn) >= 2:
        return alpn[0] + alpn[-1]
    elif len(alpn) == 1:
        return alpn[0] + alpn[0]

    return "00"


# ===========================================================================
# Known JA4 Fingerprints Database
# ===========================================================================

KNOWN_JA4: dict[str, str] = {
    # Browsers
    "t13d1516h2_8daaf6152771_02713d6af862": "Chrome (TCP)",
    "q13d0312h3_55b375c5d22e_06cda9e17597": "Chrome (QUIC)",
    "t13d1517h2_8daaf6152771_b0da82dd1658": "Chrome (PSK)",
    "t13d1517h2_8daaf6152771_b1ff8ab2d16f": "Chrome (no key)",
    # Malware
    "t13d201100_2b729b4bf6f3_9e7b989ebec8": "IcedID Malware",
    "t13d190900_9dc949149365_97f8aa674fd9": "Sliver Malware",
    "t13d880900_fcb5b95cb75a_b0d3b4ac2a14": "SoftEther VPN Client",
    "t13d191000_9dc949149365_e7c285222651": "Evilginx",
    # Tools
    "t12d0700h1_000000000000_000000000000": "curl (basic)",
    "t13d1307h2_9dc949149365_cd08e31494d8": "Python requests",
}


def identify_ja4(ja4_hash: str) -> str | None:
    """Look up JA4 hash in known fingerprints database."""
    return KNOWN_JA4.get(ja4_hash)


# ===========================================================================
# JA4: TLS Client Fingerprinting
# ===========================================================================


def parse_tls_client_hello_ja4(data: bytes) -> dict[str, Any] | None:
    """
    Parse TLS ClientHello and generate JA4 fingerprint.

    Args:
        data: Raw TLS ClientHello bytes (starting at record layer)

    Returns:
        Dict with ja4, ja4_r (raw), and parsed components, or None on error
    """
    try:
        if len(data) < 5:
            return None

        # TLS Record Layer
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            return None

        _record_version = struct.unpack(">H", data[1:3])[0]
        record_length = struct.unpack(">H", data[3:5])[0]

        if len(data) < 5 + record_length:
            return None

        # Handshake layer
        pos = 5
        handshake_type = data[pos]
        if handshake_type != 0x01:  # ClientHello
            return None

        pos += 1
        _handshake_length = struct.unpack(">I", b"\x00" + data[pos : pos + 3])[0]
        pos += 3

        # ClientHello version
        client_version = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        cipher_suites_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        cipher_suites = []
        cipher_end = pos + cipher_suites_len
        while pos < cipher_end:
            cs = struct.unpack(">H", data[pos : pos + 2])[0]
            if not is_grease(cs):
                cipher_suites.append(cs)
            pos += 2

        # Compression Methods
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions
        extensions = []
        signature_algorithms = []
        sni = None
        alpn = None
        supported_versions = []

        if pos + 2 <= len(data):
            extensions_len = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            ext_end = pos + extensions_len

            while pos + 4 <= ext_end and pos + 4 <= len(data):
                ext_type = struct.unpack(">H", data[pos : pos + 2])[0]
                ext_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
                ext_data = data[pos + 4 : pos + 4 + ext_len]

                # Skip GREASE extensions
                if not is_grease(ext_type):
                    extensions.append(ext_type)

                    # Parse specific extensions
                    if ext_type == 0x0000:  # SNI
                        if len(ext_data) > 5:
                            name_len = struct.unpack(">H", ext_data[3:5])[0]
                            sni = ext_data[5 : 5 + name_len].decode("ascii", errors="ignore")

                    elif ext_type == 0x0010:  # ALPN
                        if len(ext_data) > 2:
                            alpn_list_len = struct.unpack(">H", ext_data[0:2])[0]
                            alpn_pos = 2
                            while alpn_pos < 2 + alpn_list_len and alpn_pos < len(ext_data):
                                alpn_str_len = ext_data[alpn_pos]
                                if alpn_pos + 1 + alpn_str_len <= len(ext_data):
                                    alpn_val = ext_data[
                                        alpn_pos + 1 : alpn_pos + 1 + alpn_str_len
                                    ].decode("ascii", errors="ignore")
                                    if alpn is None:
                                        alpn = alpn_val  # First ALPN value
                                alpn_pos += 1 + alpn_str_len

                    elif ext_type == 0x000D:  # Signature Algorithms
                        if len(ext_data) >= 2:
                            sig_len = struct.unpack(">H", ext_data[0:2])[0]
                            sig_pos = 2
                            while sig_pos + 2 <= 2 + sig_len and sig_pos + 2 <= len(ext_data):
                                sig = struct.unpack(">H", ext_data[sig_pos : sig_pos + 2])[0]
                                if not is_grease(sig):
                                    signature_algorithms.append(sig)
                                sig_pos += 2

                    elif ext_type == 0x002B:  # Supported Versions
                        if len(ext_data) >= 1:
                            sv_len = ext_data[0]
                            sv_pos = 1
                            while sv_pos + 2 <= 1 + sv_len and sv_pos + 2 <= len(ext_data):
                                sv = struct.unpack(">H", ext_data[sv_pos : sv_pos + 2])[0]
                                if not is_grease(sv):
                                    supported_versions.append(sv)
                                sv_pos += 2

                pos += 4 + ext_len

        # Determine TLS version (use supported_versions if available)
        if supported_versions:
            tls_version = get_highest_tls_version(supported_versions)
        else:
            tls_version = client_version

        # Build JA4 fingerprint
        # Part a: Protocol + Version + SNI + CipherCount + ExtCount + ALPN
        protocol = "t"  # TCP TLS (use "q" for QUIC, "d" for DTLS)
        version_str = tls_version_to_ja4(tls_version)
        sni_indicator = "d" if sni else "i"  # d=domain, i=IP/none
        cipher_count = min(len(cipher_suites), 99)
        ext_count = min(len(extensions), 99)
        alpn_str = alpn_to_ja4(alpn)

        ja4_a = f"{protocol}{version_str}{sni_indicator}{cipher_count:02d}{ext_count:02d}{alpn_str}"

        # Part b: Truncated SHA256 of sorted cipher suites
        sorted_ciphers = sorted(cipher_suites)
        cipher_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

        # Part c: Truncated SHA256 of sorted extensions (minus SNI/ALPN) + signature algorithms
        # Remove SNI (0x0000) and ALPN (0x0010) from extensions for part c
        ext_for_c = [e for e in extensions if e not in (0x0000, 0x0010)]
        sorted_ext = sorted(ext_for_c)
        ext_str = ",".join(f"{e:04x}" for e in sorted_ext)
        sig_str = ",".join(f"{s:04x}" for s in signature_algorithms)

        if sig_str:
            combined = ext_str + "_" + sig_str
        else:
            combined = ext_str

        ja4_c = hashlib.sha256(combined.encode()).hexdigest()[:12]

        ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

        # Raw fingerprint (for detailed analysis)
        ja4_r = f"{ja4_a}_{cipher_str}_{ext_str}"
        if sig_str:
            ja4_r += f"_{sig_str}"

        return {
            "ja4": ja4,
            "ja4_r": ja4_r,
            "ja4_a": ja4_a,
            "ja4_b": ja4_b,
            "ja4_c": ja4_c,
            "tls_version": tls_version,
            "tls_version_str": TLS_VERSION_NAMES.get(tls_version, f"0x{tls_version:04x}"),
            "sni": sni,
            "alpn": alpn,
            "cipher_suites": cipher_suites,
            "cipher_count": len(cipher_suites),
            "extensions": extensions,
            "extension_count": len(extensions),
            "signature_algorithms": signature_algorithms,
            "identified": identify_ja4(ja4),
        }

    except (
        Exception
    ) as exc:  # last net over bytes from the attacker; the parser itself has a narrower except
        logger.debug("TLS parse aborted: %s", exc)
        return None


# ===========================================================================
# PCAP Processing
# ===========================================================================


def ja4_from_pcap(pcap_path: str) -> list[dict[str, Any]]:
    """
    Extract JA4+ fingerprints from a PCAP file.

    Requires scapy to be installed.

    Args:
        pcap_path: Path to PCAP file

    Returns:
        List of fingerprint results
    """
    try:
        from scapy.all import IP, TCP, Raw, rdpcap
    except ImportError:
        return []

    results = []

    try:
        packets = rdpcap(pcap_path)

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue

            tcp = pkt[TCP]

            # Check for TLS ClientHello
            if tcp.haslayer(Raw):
                payload = bytes(tcp[Raw].load)

                # TLS Handshake (0x16) + version
                if len(payload) > 5 and payload[0] == 0x16:
                    # Check for ClientHello (0x01) or ServerHello (0x02)
                    if len(payload) > 9 and payload[5] == 0x01:
                        result = parse_tls_client_hello_ja4(payload)
                        if result:
                            result["src_ip"] = pkt[IP].src if pkt.haslayer(IP) else None
                            result["dst_ip"] = pkt[IP].dst if pkt.haslayer(IP) else None
                            result["src_port"] = tcp.sport
                            result["dst_port"] = tcp.dport
                            result["type"] = "ja4"
                            results.append(result)

    except Exception as e:
        logger.debug("JA4 parse error: %s", e)

    return results


# ===========================================================================
# CLI / Testing
# ===========================================================================


def _self_test():
    """Run self-tests on base JA4 implementation."""
    print("JA4 Self-Test")
    print("=" * 60)

    # Test known fingerprint lookup
    print("\n[Database] Known Fingerprints")
    test_ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
    ident = identify_ja4(test_ja4)
    print(f"  {test_ja4}: {ident or 'Unknown'}")

    print("\n" + "=" * 60)
    print("Self-test complete!")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        _self_test()
    elif len(sys.argv) > 1:
        # Process PCAP file
        results = ja4_from_pcap(sys.argv[1])
        for r in results:
            fp_type = r.get("type", "unknown")
            if fp_type == "ja4":
                print(f"JA4: {r['ja4']}")
                if r.get("identified"):
                    print(f"  Identified: {r['identified']}")
                print(f"  SNI: {r.get('sni')}")
    else:
        print("Usage: python ja4.py [--test | pcap_file]")
        print("\nJA4 TLS Client Fingerprinting (BSD)")
        print("  --test     Run self-tests")
        print("  pcap_file  Extract JA4 from PCAP file")
