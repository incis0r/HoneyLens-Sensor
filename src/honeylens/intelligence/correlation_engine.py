"""
correlation_engine.py — Attacker Fingerprint Correlation (Idea 28)
===================================================================
Groups IPs that share rare fingerprints into clusters.
Runs periodically (cron or daemon, every 15 minutes).

Usage:
    python correlation_engine.py              # Run once
    python correlation_engine.py --daemon     # Run continuously

Compatible with Python 3.9+.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

from honeylens.config import FINGERPRINT_CORRELATION
from honeylens.database import legacy_get_db

logger = logging.getLogger("honeylens.correlation")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


# Defaults
_CFG: dict[str, Any] = {
    "enabled": True,
    "interval_minutes": 15,
    "max_ips_per_fingerprint": 20,
    "min_cluster_size": 2,
    "min_cluster_confidence": 0.5,
    "botnet_confidence_threshold": 0.9,
    "max_clusters": 500,
}
_CFG.update(FINGERPRINT_CORRELATION)

# Fingerprint type weights — how strongly each type indicates same operator
WEIGHTS = {
    "http_ua_hash": 0.3,
    "http_lib": 0.6,
    "http_header_order": 0.7,
    "ssh_client": 0.8,
    "ssh_lib": 0.7,
    "ja4": 0.9,
    "cred_hash": 0.85,
    "http_accept_lang": 0.2,
    "uri_sequence": 0.75,
    "port_sequence": 0.5,
}


def _get_db():
    conn = legacy_get_db()
    conn.autocommit = True
    return conn


# ---------------------------------------------------------------------------
# Cluster Detection
# ---------------------------------------------------------------------------


def find_shared_fingerprints(conn: Any) -> list[dict]:
    """
    Find fingerprints shared by 2+ IPs but fewer than MAX threshold.
    Returns list of {type, hash, value, ips, count, detail}.
    """
    max_ips = _CFG["max_ips_per_fingerprint"]
    min_size = _CFG["min_cluster_size"]

    cur = conn.cursor()
    cur.execute(
        """
        SELECT fingerprint_type, fingerprint_hash, fingerprint_value,
               ARRAY_AGG(DISTINCT host(ip)) AS ips,
               COUNT(DISTINCT ip) AS ip_count,
               SUM(event_count) AS total_events
        FROM attacker_fingerprints
        GROUP BY fingerprint_type, fingerprint_hash, fingerprint_value
        HAVING COUNT(DISTINCT ip) >= %s AND COUNT(DISTINCT ip) <= %s
        ORDER BY COUNT(DISTINCT ip) DESC
        LIMIT 1000
    """,
        (min_size, max_ips),
    )

    results = []
    for r in cur.fetchall():
        results.append(
            {
                "type": r[0],
                "hash": r[1],
                "value": r[2],
                "ips": r[3],
                "ip_count": r[4],
                "total_events": r[5],
            }
        )

    return results


def calculate_cluster_confidence(shared_fp: dict, max_ips: int) -> float:
    """Calculate confidence for a single fingerprint cluster."""
    fp_type = shared_fp["type"]
    ip_count = shared_fp["ip_count"]
    total_events = shared_fp["total_events"]

    weight = WEIGHTS.get(fp_type, 0.3)
    rarity_score = 1.0 - (ip_count / max(max_ips, 1))
    consistency = min((total_events / max(ip_count, 1)) / 3.0, 1.0)

    return round(weight * rarity_score * max(consistency, 0.3), 3)


def merge_multi_fingerprint_clusters(clusters: list[dict]) -> list[dict]:
    """
    Merge clusters where the same set of IPs appears across multiple
    fingerprint types. Boost confidence for multi-fingerprint overlap.
    """
    # Group by IP set (frozen set of IPs)
    ip_groups: dict[frozenset, list[dict]] = {}
    for c in clusters:
        key = frozenset(c["ips"])
        if key not in ip_groups:
            ip_groups[key] = []
        ip_groups[key].append(c)

    merged = []
    for ip_set, group in ip_groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Multi-fingerprint overlap — combine confidences
        # P(same operator) = 1 - product(1 - confidence_i)
        combined_conf = 1.0
        for g in group:
            combined_conf *= 1.0 - g["confidence"]
        combined_conf = round(1.0 - combined_conf, 3)

        types = [g["type"] for g in group]
        values = [g["value"][:60] for g in group]

        merged_cluster = {
            "type": "multi:" + "+".join(sorted(set(types))),
            "hash": group[0]["hash"],
            "value": " | ".join(values[:3]),
            "ips": list(ip_set),
            "ip_count": len(ip_set),
            "confidence": combined_conf,
            "fingerprints": [
                {"type": g["type"], "value": g["value"], "confidence": g["confidence"]}
                for g in group
            ],
            "is_multi": True,
        }
        merged.append(merged_cluster)

    return merged


def generate_cluster_tag(cluster: dict, idx: int) -> str:
    """Generate a human-readable cluster tag."""
    fp_type = cluster.get("type", "")
    conf = cluster.get("confidence", 0)

    if conf >= _CFG["botnet_confidence_threshold"] or cluster.get("is_multi"):
        return f"BOTNET_{idx}"

    value = cluster.get("value", "")[:30]
    # Clean value for tag use
    import re

    clean = re.sub(r"[^a-zA-Z0-9._/-]", "_", value)[:25]

    type_prefix = {
        "http_lib": "LIB",
        "http_ua_hash": "UA",
        "http_header_order": "HDR",
        "ssh_client": "SSH",
        "ssh_lib": "SSH_LIB",
        "ja4": "JA4",
        "cred_hash": "CRED",
    }
    prefix = type_prefix.get(fp_type, "FP")

    return f"CLUSTER_{prefix}_{clean}_{idx}"


# ---------------------------------------------------------------------------
# Main correlation run
# ---------------------------------------------------------------------------


def run_correlation() -> dict[str, Any]:
    """
    Main correlation run.
    1. Find shared fingerprints
    2. Calculate confidence
    3. Merge multi-fingerprint clusters
    4. Generate cluster tags
    5. Update attacker_profiles
    6. Store in fingerprint_clusters
    """
    if not _CFG.get("enabled", True):
        logger.info("Fingerprint correlation disabled")
        return {"status": "disabled"}

    conn = _get_db()
    cur = conn.cursor()

    # Check table exists
    cur.execute("""
        SELECT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_name = 'attacker_fingerprints')
    """)
    if not cur.fetchone()[0]:
        conn.close()
        logger.warning("attacker_fingerprints table not found — run setup_db.py")
        return {"status": "table_missing"}

    logger.info("Running fingerprint correlation...")
    t0 = time.time()

    # 1. Find shared fingerprints
    shared = find_shared_fingerprints(conn)
    logger.info("Found %d shared fingerprints across IPs", len(shared))

    if not shared:
        conn.close()
        return {"status": "no_clusters", "shared_fingerprints": 0}

    # 2. Calculate confidence for each
    max_ips = _CFG["max_ips_per_fingerprint"]
    min_conf = _CFG["min_cluster_confidence"]

    clusters = []
    for s in shared:
        conf = calculate_cluster_confidence(s, max_ips)
        if conf >= min_conf:
            s["confidence"] = conf
            clusters.append(s)

    logger.info("%d clusters above confidence threshold %.2f", len(clusters), min_conf)

    # 3. Merge multi-fingerprint clusters
    clusters = merge_multi_fingerprint_clusters(clusters)

    # 4. Limit
    clusters = clusters[: _CFG["max_clusters"]]

    # 5. Generate tags and store
    cluster_count = 0
    tagged_ips: set[str] = set()

    for idx, c in enumerate(clusters, 1):
        tag = generate_cluster_tag(c, idx)
        c["tag"] = tag

        # Store/update fingerprint_clusters
        try:
            ips_array = c["ips"]
            cur.execute(
                """
                INSERT INTO fingerprint_clusters
                    (cluster_tag, fingerprint_type, fingerprint_hash, fingerprint_value,
                     ip_count, confidence, ips, first_seen, last_seen, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::inet[], NOW(), NOW(), NOW())
                ON CONFLICT (cluster_tag) DO UPDATE SET
                    ip_count = EXCLUDED.ip_count,
                    confidence = EXCLUDED.confidence,
                    ips = EXCLUDED.ips,
                    last_seen = NOW(),
                    updated_at = NOW()
            """,
                (
                    tag,
                    c["type"],
                    c["hash"],
                    c["value"][:512],
                    c["ip_count"],
                    c["confidence"],
                    ips_array,
                ),
            )
            cluster_count += 1
        except Exception as exc:
            logger.debug("Failed to store cluster %s: %s", tag, exc)
            continue

        # Tag each IP in attacker_profiles
        for ip in c["ips"]:
            try:
                # Add cluster tag if not already present
                cur.execute(
                    """
                    UPDATE attacker_profiles
                    SET internal_tags = CASE
                            WHEN internal_tags IS NULL THEN ARRAY[%s]
                            WHEN %s = ANY(internal_tags) THEN internal_tags
                            ELSE array_append(internal_tags, %s)
                        END,
                        cluster_tags = CASE
                            WHEN cluster_tags IS NULL THEN ARRAY[%s]
                            WHEN %s = ANY(cluster_tags) THEN cluster_tags
                            ELSE array_append(cluster_tags, %s)
                        END,
                        updated_at = NOW()
                    WHERE host(ip) = %s
                """,
                    (tag, tag, tag, tag, tag, tag, ip),
                )
                tagged_ips.add(ip)
            except Exception as exc:
                logger.debug("Failed to tag IP %s with %s: %s", ip, tag, exc)

    elapsed = time.time() - t0
    conn.close()

    result = {
        "status": "completed",
        "elapsed_ms": int(elapsed * 1000),
        "shared_fingerprints": len(shared),
        "clusters_detected": cluster_count,
        "ips_tagged": len(tagged_ips),
        "clusters": [
            {
                "tag": c["tag"],
                "type": c["type"],
                "ip_count": c["ip_count"],
                "confidence": c["confidence"],
                "value": c["value"][:60],
            }
            for c in clusters[:20]
        ],
    }

    logger.info(
        "Correlation complete: %d clusters, %d IPs tagged (%dms)",
        cluster_count,
        len(tagged_ips),
        int(elapsed * 1000),
    )

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()

    daemon = "--daemon" in sys.argv

    if daemon:
        interval = _CFG.get("interval_minutes", 15) * 60
        logger.info("Correlation engine daemon starting (interval: %ds)", interval)
        while True:
            try:
                result = run_correlation()
                logger.info("Run result: %s", result.get("status"))
            except Exception as e:
                logger.error("Correlation run failed: %s", e)
            time.sleep(interval)
    else:
        result = run_correlation()
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
