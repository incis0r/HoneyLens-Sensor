#!/usr/bin/env python3
"""
ingest/suricata.py — Suricata EVE JSON Alert Ingestion
========================================================
Reads Suricata EVE JSON alerts and inserts into sensor_events +
attack_patterns. Events classified by Suricata are marked so the
AI pipeline can skip them (known attacks don't need Claude).

Usage:
    python -m ingest.suricata              # Process new alerts
    python -m ingest.suricata --all        # Reprocess all
    python -m ingest.suricata --dry-run    # Test without inserting
    python -m ingest.suricata --stats      # Show Suricata stats

Cron:
    * * * * * sensor cd /opt/sensor && flock -xn /tmp/ingest_suricata.lock \
        /opt/sensor/venv/bin/python -m ingest.suricata >> /opt/sensor/logs/ingest_suricata.log 2>&1
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys

import psycopg2

from honeylens.config import should_ignore_traffic
from honeylens.database import legacy_get_db
from honeylens.ingest import state

logger = logging.getLogger("honeylens.ingest.suricata")

EVE_LOG = os.environ.get("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
# Offset now lives in ingest/state.py — /var/run was root-owned and the
# ingest runs as `sensor`, so it was never written. See that module.
_POS_NAME = "suricata"

# Suricata category → HoneyLens attack_type mapping
CATEGORY_MAP = {
    "Attempted Administrator Privilege Gain": "RCE",
    "Attempted User Privilege Gain": "PRIV_ESCALATION",
    "Web Application Attack": "WEB_EXPLOIT",
    "A Network Trojan was Detected": "MALWARE",
    "Potentially Bad Traffic": "ANOMALY",
    "Misc Attack": "EXPLOIT",
    "Generic Protocol Command Decode": "PROTO_ABUSE",
    "Attempted Denial of Service": "DOS",
    "Attempted Information Leak": "INFO_DISCLOSURE",
    "Detection of a Non-Standard Protocol or Event": "PROTO_ANOMALY",
    "Misc activity": "SCANNER",
    "Not Suspicious Traffic": "BENIGN",
    "Potential Corporate Privacy Violation": "POLICY",
    "A suspicious filename was detected": "MALWARE",
    "A suspicious string was detected": "SUSPICIOUS",
    "Decode of an RPC Query": "RPC_PROBE",
    "Executable Code was Detected": "SHELLCODE",
    "Exploit Kit Activity Detected": "EXPLOIT_KIT",
    "Domain Observed Used for C2 Detected": "C2",
    "Malware Command and Control Activity Detected": "C2",
}

# Signature-name overrides — checked BEFORE the coarse CATEGORY_MAP, because the
# ET signature *name* is far more specific than the classtype/category. Ordered;
# first match wins. This fixes systemic mislabels where the classtype is coarse:
#   * "ET SCAN LibSSH ... BruteForce" (classtype attempted-admin → category
#     "Attempted Administrator Privilege Gain") was mislabelled RCE;
#   * reputation-list hits ("ET DROP Dshield", "ET CINS Poor Reputation IP",
#     "Spamhaus DROP", classtype misc-attack → category "Misc Attack") were
#     mislabelled EXPLOIT.
# Patterns are deliberately high-precision to avoid introducing new mislabels.
SIGNATURE_RULES = [
    # Suricata's own engine events, not signatures of attacker behaviour. Everything the
    # engine emits itself is prefixed `SURICATA `; ET and GPL rules never are, which is
    # what makes the prefix safe to key on.
    #
    # Their classtype is "Generic Protocol Command Decode", so the coarse map called them
    # PROTO_ABUSE — a name that reads as "someone is abusing a protocol" when the actual
    # meaning is "the capture saw a stream it could not reassemble cleanly". They fire on
    # asymmetric routing, packet loss, NAT, or simply starting capture mid-connection.
    #
    # The scale is the problem: 24k such events on PROD and 44k on sensor-a over 30 days, the
    # third-largest attack type on the fleet. One file download from GitHub produced 2,845
    # of them in eight minutes against a baseline of ~40 an hour. Kept rather than dropped
    # — invalid checksums and excessive retransmissions are genuine capture-quality
    # signals — but named honestly and scored `info` so they stop drowning real findings.
    (re.compile(r"^SURICATA\s", re.I), "ENGINE_ANOMALY"),
    (
        re.compile(
            r"dshield|spamhaus|\bcins\b|poor reputation|block[\s-]?listed|"
            r"drop listed|blocklist|known compromised|abuse\.ch",
            re.I,
        ),
        "REPUTATION",
    ),
    (re.compile(r"known tor|tor exit node|tor relay|tor node", re.I), "TOR"),
    (
        re.compile(r"brute[\s-]?force|password guess(?:ing)?|credential stuffing", re.I),
        "BRUTE_FORCE",
    ),
    (
        re.compile(
            r"\bscan\b|\bnmap\b|masscan|zmap|sipvicious|\brecon(?:naissance)?\b|"
            r"probing|frequent .*connection",
            re.I,
        ),
        "SCANNER",
    ),
    (re.compile(r"\bddos\b|denial of service", re.I), "DOS"),
    (re.compile(r"exploit kit", re.I), "EXPLOIT_KIT"),
    (
        re.compile(r"coin[\s-]?miner|crypto[\s-]?miner|cryptocurrency mining|xmrig", re.I),
        "CRYPTOMINING",
    ),
    (re.compile(r"\btrojan\b|\bbotnet\b|\bransomware\b", re.I), "MALWARE"),
]


def classify_attack(signature: str, category: str) -> str:
    """Map a Suricata alert to a HoneyLens attack_type.

    The signature name is authoritative when it clearly states the behaviour
    (reputation / brute-force / scan / DoS / malware); otherwise fall back to
    the coarse category classtype map, then a generic label.
    """
    sig = signature or ""
    for rx, at in SIGNATURE_RULES:
        if rx.search(sig):
            return at
    return CATEGORY_MAP.get(category, "SURICATA_ALERT")


# Suricata severity → HoneyLens severity
SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

# Minimum severity to forward to configured SIEM destinations.
# DEV 2026-05-08: ingest.suricata was posting 31.5 M HTTP POSTs / 41.9 GB
# to Loki over 2.83 days (~200-440 push/sec) — overwhelming the receiver
# and producing per-alert noise in the dashboards. By default we now only
# forward CRITICAL (sev=1) + HIGH (sev=2) events to SIEM. Override via env
# var SIEM_SURICATA_MIN_SEVERITY (1=CRITICAL only, 2=HIGH+, 3=MEDIUM+, 4=all).
# DB writes are unaffected — every alert is still INSERTed locally.
try:
    SIEM_SURICATA_MIN_SEVERITY = int(os.environ.get("SIEM_SURICATA_MIN_SEVERITY", "2"))
except (TypeError, ValueError):
    SIEM_SURICATA_MIN_SEVERITY = 2


def get_connection():
    conn = legacy_get_db()
    conn.autocommit = True
    return conn


def get_position(log_path: str | None = None) -> int:
    return state.read_position(_POS_NAME, log_path)


def save_position(pos: int):
    state.save_position(_POS_NAME, pos)


def generate_event_id(alert: dict) -> str:
    """Deterministic event ID from Suricata alert."""
    unique = "{}-{}-{}-{}-{}-{}".format(
        alert.get("timestamp", ""),
        alert.get("src_ip", ""),
        alert.get("src_port", ""),
        alert.get("dest_ip", ""),
        alert.get("dest_port", ""),
        alert.get("alert", {}).get("signature_id", ""),
    )
    return "sur_" + hashlib.sha256(unique.encode()).hexdigest()[:28]


def process_alert(conn, alert: dict, dry_run: bool = False) -> bool:
    """Process a single Suricata EVE alert and insert into DB."""
    if alert.get("event_type") != "alert":
        return False

    al = alert.get("alert", {})
    if not al:
        return False

    sid = al.get("signature_id", 0)
    signature = al.get("signature", "")
    category = al.get("category", "")
    sev_num = al.get("severity", 3)

    event_id = generate_event_id(alert)
    src_ip = alert.get("src_ip", "")
    src_port = alert.get("src_port", 0)
    dst_port = alert.get("dest_port", 0)
    proto = alert.get("proto", "TCP").upper()
    ts = alert.get("timestamp", "")

    # Skip alerts whose source IP is in IGNORE_LOCAL_SOURCES (LAN/infra traffic)
    if should_ignore_traffic(src_ip=src_ip):
        return False

    # Map to HoneyLens types — signature name first, then coarse category.
    attack_type = classify_attack(signature, category)
    severity = SEVERITY_MAP.get(sev_num, "MEDIUM")

    # Extract CVEs from metadata if available.
    #
    # A HUNTING rule's declared CVE is NOT a claim that this request exploited it. Measured on
    # sensor-a 2026-10-30: six sources sent a byte-identical 302-byte probe whose body is
    # `PHP_SESSION_UPLOAD_PROGRESS=internet-census` with `filename="internet-census.txt"` and
    # the content `1` -- an exposure census carrying no code at all -- and every one was stored
    # as `EXPLOIT,CVE_2026_109619`. The verdict came from `ET HUNTING PHP Generic Upload
    # Progress Session Manipulation` (sid 2072555), which fires on cookie + multipart + the
    # field name and declares `cve CVE_2026_109619` in its metadata. The paired `ET EXPLOIT ...
    # Code Injection in Filename` rule (2072554) is the one that actually asserts exploitation.
    #
    # So six research scanners were counted as CVE exploitation in three successive threat
    # reviews, and `track_cve` fed the CVE dashboard from them too. The ET feed is third party,
    # so this cannot be fixed in the rule -- a local edit is overwritten on the next update. The
    # attack_type still lands, and the signature text is still stored verbatim; only the
    # positive CVE claim is withheld.
    cve = ""
    cve_ids = []  # normalized CVE-YYYY-NNNN format for CIRCL enrichment
    is_hunting = "hunting" in (signature or "").lower()
    metadata = al.get("metadata", {})
    if metadata and not is_hunting:
        cve_list = metadata.get("cve", [])
        if cve_list:
            if not isinstance(cve_list, list):
                cve_list = [str(cve_list)]
            cve = cve_list[0]
            for c in cve_list:
                # Suricata uses CVE_YYYY_NNNN, normalize to CVE-YYYY-NNNN
                normalized = str(c).replace("_", "-")
                if not normalized.startswith("CVE-"):
                    normalized = "CVE-" + normalized.lstrip("CVE")
                cve_ids.append(normalized)

    # Build payload with Suricata context
    payload = json.dumps(
        {
            "suricata_sid": sid,
            "signature": signature,
            "category": category,
            "severity": sev_num,
            "cve": cve,
            # What the rule declared, kept even when it was not promoted to a verdict above:
            # a hunting hit on a CVE pattern is still evidence, it is just not a finding.
            "cve_declared": (metadata or {}).get("cve", []),
            "hunting": is_hunting,
            "metadata": metadata,
            "proto": proto,
            "app_proto": alert.get("app_proto", ""),
        }
    )

    attack_types_str = attack_type
    if cve:
        attack_types_str += "," + cve.replace("-", "_")

    if dry_run:
        logger.info(
            "[DRY-RUN] SID:%s %s → %s:%s | %s | %s",
            sid,
            src_ip,
            alert.get("dest_ip", ""),
            dst_port,
            category,
            signature[:60],
        )
        return True

    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO sensor_events (
                event_id, timestamp, src_ip, src_port, dst_port,
                protocol, source, payload, attack_types,
                suricata_sid, suricata_signature
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s
            ) ON CONFLICT (event_id) DO NOTHING
        """,
            (
                event_id,
                ts,
                src_ip,
                src_port,
                dst_port,
                proto,
                "suricata",
                payload,
                attack_types_str,
                sid,
                signature[:500],
            ),
        )
        # Fan-out to configured SIEM forwarders (no-op if none configured).
        # Severity gate: skip MEDIUM/LOW alerts unless operator overrides.
        # See SIEM_SURICATA_MIN_SEVERITY comment near top of module.
        if sev_num <= SIEM_SURICATA_MIN_SEVERITY:
            try:
                from honeylens.siem import forward_event_dict as _fwd_siem

                _fwd_siem(
                    {
                        "event_id": event_id,
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "source": "suricata",
                        "severity": severity,
                        "payload": payload,
                        "attack_types": attack_types_str,
                        "metadata": {
                            "suricata_sid": sid,
                            "signature": signature[:500],
                            "severity": severity,
                            "severity_num": sev_num,
                            "category": category,
                        },
                    }
                )
            except Exception as exc:
                logger.debug("optional metadata skipped: %s", exc)

        # Insert attack pattern
        rule_name = f"suricata_sid_{sid}"
        cur.execute(
            """
            INSERT INTO attack_patterns (
                event_id, attack_type, rule_name, severity, confidence,
                matched_text
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id, attack_type, rule_name) DO NOTHING
        """,
            (
                event_id,
                attack_type,
                rule_name,
                severity,
                "high",
                signature[:500],
            ),
        )

        # Enrich CVE dashboard with Suricata-detected CVEs
        if cve_ids:
            try:
                from honeylens.intelligence.circl_enricher import track_cve

                for cid in cve_ids:
                    track_cve(cid, conn)
            except Exception as e:
                logger.debug("CVE tracking error: %s", e)

        return True
    except psycopg2.Error as e:
        logger.debug("Insert error: %s", e)
        return False


def process_log(eve_log: str, conn, process_all: bool = False, dry_run: bool = False):
    """Process Suricata EVE JSON log file."""
    if not os.path.exists(eve_log):
        logger.warning("EVE log not found: %s", eve_log)
        return 0, 0

    start_pos = 0 if process_all else get_position(eve_log)
    processed = 0
    inserted = 0

    with open(eve_log) as f:
        f.seek(start_pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            if alert.get("event_type") != "alert":
                continue

            processed += 1
            if process_alert(conn, alert, dry_run):
                inserted += 1

        if not dry_run:
            save_position(f.tell())

    return processed, inserted


def show_stats(conn):
    """Show Suricata ingestion statistics."""
    cur = conn.cursor()
    print("\n=== Suricata Ingestion Statistics ===\n")

    cur.execute("""
        SELECT COUNT(*), COUNT(DISTINCT src_ip),
               MIN(timestamp)::date, MAX(timestamp)::date
        FROM sensor_events WHERE source = 'suricata'
    """)
    r = cur.fetchone()
    print("Events: {}, Unique IPs: {}, First: {}, Last: {}".format(*r))

    print("\nTop Suricata rules:")
    cur.execute("""
        SELECT suricata_sid, suricata_signature, COUNT(*) as hits
        FROM sensor_events WHERE source = 'suricata' AND suricata_sid IS NOT NULL
        GROUP BY suricata_sid, suricata_signature
        ORDER BY hits DESC LIMIT 15
    """)
    for r in cur.fetchall():
        print(f"  SID:{r[0]:<8} {r[2]:5d} hits  {(r[1] or '')[:60]}")

    print("\nAttack type breakdown:")
    cur.execute("""
        SELECT attack_type, COUNT(*) FROM attack_patterns
        WHERE rule_name LIKE 'suricata_sid_%%'
        GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 10
    """)
    for r in cur.fetchall():
        print(f"  {r[0]:<25} {r[1]}")


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="Ingest Suricata EVE JSON alerts")
    parser.add_argument(
        "--all", "-a", action="store_true", help="Process all alerts from beginning"
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Test without inserting")
    parser.add_argument("--stats", action="store_true", help="Show ingestion statistics")
    parser.add_argument("--eve-log", default=EVE_LOG, help=f"EVE log path (default: {EVE_LOG})")
    args = parser.parse_args()

    try:
        conn = get_connection()
    except psycopg2.Error as e:
        logger.error("DB connection failed: %s", e)
        sys.exit(1)

    if args.stats:
        show_stats(conn)
        conn.close()
        sys.exit(0)

    logger.info("Suricata EVE ingest starting (log: %s)", args.eve_log)
    if args.dry_run:
        logger.info("DRY RUN — no changes")

    processed, inserted = process_log(
        args.eve_log,
        conn,
        process_all=args.all,
        dry_run=args.dry_run,
    )

    logger.info("Processed: %d alerts, Inserted: %d new", processed, inserted)
    conn.close()


if __name__ == "__main__":
    main()
