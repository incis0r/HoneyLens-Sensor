"""
ja3.py — JA3/JA3S TLS Fingerprint Calculator
=============================================
Calculates JA3 (client) and JA3S (server) fingerprints from TLS handshake data.

JA3 fingerprints identify TLS clients based on their ClientHello message,
regardless of IP address. This is useful for:
  - Identifying malware/botnets by their TLS fingerprint
  - Detecting suspicious clients using uncommon cipher suites
  - Correlating traffic from the same tool across different IPs

Reference: https://github.com/salesforce/ja3
Paper: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

JA3 Format:
    MD5(SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats)

JA3S Format (server fingerprint):
    MD5(SSLVersion,CipherSuite,Extensions)

Usage:
    from ja3 import parse_client_hello, parse_server_hello, ja3_from_pcap

    # From raw bytes
    ja3_info = parse_client_hello(client_hello_bytes)
    print(ja3_info["ja3_hash"])

    # From PCAP file
    results = ja3_from_pcap("/path/to/capture.pcap")

Requires: Python >= 3.9
Optional: scapy (for PCAP parsing)
"""

from __future__ import annotations

import hashlib
import logging
import struct

logger = logging.getLogger("honeylens.classifier.ja3")

# ===========================================================================
# GREASE Values (RFC 8701)
# ===========================================================================
# GREASE (Generate Random Extensions And Sustain Extensibility) values
# are random padding values that should be filtered from JA3 fingerprints
# to ensure consistent fingerprinting across implementations.

GREASE_VALUES = frozenset(
    {
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
)


def is_grease(value: int) -> bool:
    """Check if a value is a GREASE value (should be filtered from JA3)."""
    return value in GREASE_VALUES


# ===========================================================================
# TLS Version Mapping
# ===========================================================================

TLS_VERSIONS = {
    0x0300: "SSL3.0",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
    # Draft versions
    0x7F00: "TLS1.3-draft",
}


def tls_version_str(version: int) -> str:
    """Convert TLS version number to human-readable string."""
    return TLS_VERSIONS.get(version, f"0x{version:04x}")


# ===========================================================================
# Known JA3 Fingerprints Database
# ===========================================================================
# Common JA3 hashes for identification. This is a small subset;
# see https://ja3er.com for a comprehensive database.

KNOWN_JA3 = {
    # Browsers
    "e7d705a3286e19ea42f587b344ee6865": "Chrome/Windows",
    "b32309a26951912be7dba376398abc3b": "Firefox/Windows",
    "9e10692f1b7f78228b2d4e424db3a98c": "Safari/macOS",
    "ada70206e40642a3e4461f35503241d5": "Chrome/macOS",
    # Malware / Tools
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (HTTPS)",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "Metasploit",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Emotet",
    "51c64c77e60f3980eea90869b68c58a8": "IcedID",
    "c12f54a3f91dc7bafd92cb59fe009a35": "BazarLoader",
    # Scanners / Tools
    "b386946a5a44d1ddcc843bc75336dfce": "curl/OpenSSL",
    "3e9b20610098f02403a37a7f32da0e04": "wget/GnuTLS",
    "e058e223e0a7c8b2f485b6a00fa0c4b1": "Nmap SSL scan",
    "36f7277af969a6947a61ae0b815907a1": "Qualys SSL Labs",
    "9b7ffb92e5d4a1a9f41e3e33aadc2d55": "Python/requests",
    "b9db79e16f8f2a40d943d8392d819f31": "Go net/http",
    # Bots
    "473cd7cb9faa642487833865d516e578": "Googlebot",
    "cd08e31494f9531f560d64c695473da9": "Bingbot",
}


def identify_ja3(ja3_hash: str) -> str | None:
    """Look up a JA3 hash in the known fingerprints database."""
    return KNOWN_JA3.get(ja3_hash)


# ===========================================================================
# ClientHello Parser (JA3)
# ===========================================================================


def parse_client_hello(data: bytes) -> dict | None:
    """
    Parse a TLS ClientHello message and extract JA3 components.

    Args:
        data: Raw bytes containing the TLS ClientHello record.
              Can be the full TLS record or just the handshake message.

    Returns:
        Dictionary with:
            - tls_version: int (e.g., 0x0303 for TLS 1.2)
            - tls_version_str: str (e.g., "TLS1.2")
            - cipher_suites: list[int]
            - extensions: list[int]
            - elliptic_curves: list[int] (from supported_groups extension)
            - ec_point_formats: list[int]
            - sni: str (Server Name Indication if present)
            - ja3_string: str (raw JA3 string before hashing)
            - ja3_hash: str (MD5 hash of ja3_string)
            - ja3_identified: str or None (known client if matched)

        Returns None if parsing fails.
    """
    try:
        if len(data) < 5:
            return None

        pos = 0

        # Check if this starts with TLS record header
        if data[0] == 0x16:  # Handshake content type
            # TLS record header: type(1) + version(2) + length(2)
            _record_version = struct.unpack(">H", data[1:3])[0]
            record_length = struct.unpack(">H", data[3:5])[0]
            pos = 5

            if len(data) < pos + record_length:
                return None

        # Handshake header
        if len(data) <= pos:
            return None

        handshake_type = data[pos]
        if handshake_type != 0x01:  # ClientHello
            return None

        # Handshake length (3 bytes, big-endian)
        _handshake_length = struct.unpack(">I", b"\x00" + data[pos + 1 : pos + 4])[0]
        pos += 4

        # Client version (2 bytes) - this is the "legacy" version in TLS 1.3
        client_version = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID (variable length)
        if pos >= len(data):
            return None
        session_id_length = data[pos]
        pos += 1 + session_id_length

        # Cipher suites (2-byte length + list)
        if pos + 2 > len(data):
            return None
        cipher_suites_length = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        cipher_suites = []
        for i in range(0, cipher_suites_length, 2):
            if pos + i + 2 > len(data):
                break
            cs = struct.unpack(">H", data[pos + i : pos + i + 2])[0]
            if not is_grease(cs):
                cipher_suites.append(cs)
        pos += cipher_suites_length

        # Compression methods (1-byte length + list)
        if pos >= len(data):
            return None
        compression_length = data[pos]
        pos += 1 + compression_length

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni = None
        supported_versions = []

        if pos + 2 <= len(data):
            extensions_length = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            extensions_end = pos + extensions_length

            while pos + 4 <= extensions_end and pos + 4 <= len(data):
                ext_type = struct.unpack(">H", data[pos : pos + 2])[0]
                ext_length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
                ext_data = data[pos + 4 : pos + 4 + ext_length]

                if not is_grease(ext_type):
                    extensions.append(ext_type)

                # Parse specific extensions
                if ext_type == 0x0000 and ext_length > 5:  # SNI
                    try:
                        # SNI list: list_length(2) + type(1) + name_length(2) + name
                        sni_length = struct.unpack(">H", ext_data[3:5])[0]
                        sni = ext_data[5 : 5 + sni_length].decode("ascii", errors="ignore")
                    except (struct.error, IndexError, ValueError):
                        logger.debug("malformed TLS extension 0x%04x", ext_type)

                elif ext_type == 0x000A and ext_length >= 2:  # Supported Groups (elliptic_curves)
                    try:
                        curves_length = struct.unpack(">H", ext_data[0:2])[0]
                        for i in range(2, min(2 + curves_length, len(ext_data)), 2):
                            curve = struct.unpack(">H", ext_data[i : i + 2])[0]
                            if not is_grease(curve):
                                elliptic_curves.append(curve)
                    except (struct.error, IndexError, ValueError):
                        logger.debug("malformed TLS extension 0x%04x", ext_type)

                elif ext_type == 0x000B and ext_length >= 1:  # EC Point Formats
                    try:
                        formats_length = ext_data[0]
                        for i in range(1, min(1 + formats_length, len(ext_data))):
                            ec_point_formats.append(ext_data[i])
                    except (struct.error, IndexError, ValueError):
                        logger.debug("malformed TLS extension 0x%04x", ext_type)

                elif ext_type == 0x002B and ext_length >= 1:  # Supported Versions (TLS 1.3)
                    try:
                        versions_length = ext_data[0]
                        for i in range(1, min(1 + versions_length, len(ext_data)), 2):
                            ver = struct.unpack(">H", ext_data[i : i + 2])[0]
                            if not is_grease(ver):
                                supported_versions.append(ver)
                    except (struct.error, IndexError, ValueError):
                        logger.debug("malformed TLS extension 0x%04x", ext_type)

                pos += 4 + ext_length

        # Build JA3 string
        # Format: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_parts = [
            str(client_version),
            "-".join(str(c) for c in cipher_suites),
            "-".join(str(e) for e in extensions),
            "-".join(str(c) for c in elliptic_curves),
            "-".join(str(f) for f in ec_point_formats),
        ]
        ja3_string = ",".join(ja3_parts)
        ja3_hash = hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()

        # Determine actual TLS version
        actual_version = supported_versions[0] if supported_versions else client_version

        return {
            "tls_version": client_version,
            "tls_version_actual": actual_version,
            "tls_version_str": tls_version_str(actual_version),
            "cipher_suites": cipher_suites,
            "cipher_suites_count": len(cipher_suites),
            "extensions": extensions,
            "extensions_count": len(extensions),
            "elliptic_curves": elliptic_curves,
            "ec_point_formats": ec_point_formats,
            "supported_versions": supported_versions,
            "sni": sni,
            "ja3_string": ja3_string,
            "ja3_hash": ja3_hash,
            "ja3_identified": identify_ja3(ja3_hash),
        }

    except (
        Exception
    ) as exc:  # last net over bytes from the attacker; the parser itself has a narrower except
        logger.debug("TLS parse aborted: %s", exc)
        return None


# ===========================================================================
# ServerHello Parser (JA3S)
# ===========================================================================


def parse_server_hello(data: bytes) -> dict | None:
    """
    Parse a TLS ServerHello message and extract JA3S components.

    Args:
        data: Raw bytes containing the TLS ServerHello record.

    Returns:
        Dictionary with:
            - tls_version: int
            - tls_version_str: str
            - cipher_suite: int (single cipher chosen by server)
            - extensions: list[int]
            - ja3s_string: str
            - ja3s_hash: str (MD5)

        Returns None if parsing fails.
    """
    try:
        if len(data) < 5:
            return None

        pos = 0

        # Check for TLS record header
        if data[0] == 0x16:
            pos = 5  # Skip record header

        # Handshake header
        handshake_type = data[pos]
        if handshake_type != 0x02:  # ServerHello
            return None

        _handshake_length = struct.unpack(">I", b"\x00" + data[pos + 1 : pos + 4])[0]
        pos += 4

        # Server version
        server_version = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        session_id_length = data[pos]
        pos += 1 + session_id_length

        # Cipher suite (2 bytes - single cipher chosen)
        cipher_suite = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        # Compression method (1 byte)
        pos += 1

        # Extensions
        extensions = []

        if pos + 2 <= len(data):
            extensions_length = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            extensions_end = pos + extensions_length

            while pos + 4 <= extensions_end and pos + 4 <= len(data):
                ext_type = struct.unpack(">H", data[pos : pos + 2])[0]
                ext_length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]

                if not is_grease(ext_type):
                    extensions.append(ext_type)

                pos += 4 + ext_length

        # Build JA3S string
        # Format: SSLVersion,CipherSuite,Extensions
        ja3s_parts = [
            str(server_version),
            str(cipher_suite),
            "-".join(str(e) for e in extensions),
        ]
        ja3s_string = ",".join(ja3s_parts)
        ja3s_hash = hashlib.md5(ja3s_string.encode(), usedforsecurity=False).hexdigest()

        return {
            "tls_version": server_version,
            "tls_version_str": tls_version_str(server_version),
            "cipher_suite": cipher_suite,
            "extensions": extensions,
            "ja3s_string": ja3s_string,
            "ja3s_hash": ja3s_hash,
        }

    except (
        Exception
    ) as exc:  # last net over bytes from the attacker; the parser itself has a narrower except
        logger.debug("TLS parse aborted: %s", exc)
        return None


# ===========================================================================
# PCAP Parsing (requires scapy)
# ===========================================================================


def ja3_from_pcap(pcap_path: str) -> list[dict]:
    """
    Extract JA3 fingerprints from all TLS ClientHello messages in a PCAP file.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        List of dicts, each containing:
            - src_ip, src_port, dst_ip, dst_port
            - ja3_hash, ja3_string, sni
            - All fields from parse_client_hello()

    Requires: scapy
    """
    try:
        from scapy.all import IP, TCP, IPv6, rdpcap
    except ImportError:
        raise ImportError("scapy is required for PCAP parsing: pip install scapy") from None

    results = []
    packets = rdpcap(pcap_path)

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        payload = bytes(tcp.payload)

        if len(payload) < 6:
            continue

        # Check for TLS ClientHello
        if payload[0] == 0x16 and payload[5] == 0x01:
            ja3_info = parse_client_hello(payload)

            if ja3_info:
                # Add connection info
                if pkt.haslayer(IP):
                    ja3_info["src_ip"] = pkt[IP].src
                    ja3_info["dst_ip"] = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    ja3_info["src_ip"] = pkt[IPv6].src
                    ja3_info["dst_ip"] = pkt[IPv6].dst

                ja3_info["src_port"] = tcp.sport
                ja3_info["dst_port"] = tcp.dport

                results.append(ja3_info)

    return results


# ===========================================================================
# Command-line Interface
# ===========================================================================


def main():
    """CLI for JA3 fingerprinting."""
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ja3.py <pcap_file>        Extract JA3 from PCAP")
        print("  python ja3.py --hex <hex_string> Parse hex-encoded ClientHello")
        print("  python ja3.py --lookup <ja3_hash> Look up known fingerprint")
        sys.exit(1)

    if sys.argv[1] == "--hex" and len(sys.argv) >= 3:
        data = bytes.fromhex(sys.argv[2])
        result = parse_client_hello(data)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("Failed to parse ClientHello")
            sys.exit(1)

    elif sys.argv[1] == "--lookup" and len(sys.argv) >= 3:
        ja3_hash = sys.argv[2].lower()
        identified = identify_ja3(ja3_hash)
        if identified:
            print(f"{ja3_hash}: {identified}")
        else:
            print(f"{ja3_hash}: Unknown")

    else:
        # Assume PCAP file
        pcap_path = sys.argv[1]
        try:
            results = ja3_from_pcap(pcap_path)
            for r in results:
                print(
                    f"{r.get('src_ip')}:{r.get('src_port')} -> "
                    f"{r.get('dst_ip')}:{r.get('dst_port')}"
                )
                print(f"  JA3: {r.get('ja3_hash')}")
                print(f"  SNI: {r.get('sni', '-')}")
                if r.get("ja3_identified"):
                    print(f"  Identified: {r.get('ja3_identified')}")
                print()
        except ImportError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"File not found: {pcap_path}")
            sys.exit(1)


if __name__ == "__main__":
    main()
