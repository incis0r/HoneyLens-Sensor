#!/usr/bin/env python3
"""NetScaler honeypot threat-intel report generator.

Dumps the facts behind a NetScaler-decoy review straight from a sensor's database:
who hit the decoy, from where, what they sent, and which Citrix CVEs they aimed at.
Read-only.

Run it on a sensor host (it reuses the sensor's own DB config):

    HONEYLENS_ENV_FILE=~/honeylens-state/.env .venv/bin/python \
        scripts/examples/netscaler_honeypot_report.py [--days N] [--source netscaler]

NetScaler events are the rows with source='netscaler'. Enrichment (country, hostname,
ai/claude verdicts) is a LEFT JOIN on attacker_profiles, so it degrades gracefully when a
source IP has not been profiled yet. RFC1918 / internal addresses (the gateway doing the
DNAT, health checks) are reported separately from external actors so they do not distort
the "who" picture.
"""

from __future__ import annotations

import argparse

from honeylens.database import legacy_get_db

# Citrix NetScaler decoy's own attack tags (set by honeypot_netscaler._detect).
NS_TAG_LIKE = "ns-%%"  # %% — psycopg2 reads a lone % in the SQL text as a parameter mark


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", default="netscaler", help="sensor_events.source value")
    ap.add_argument("--days", type=int, default=0, help="limit to the last N days (0 = all)")
    ap.add_argument("--top", type=int, default=25, help="rows per ranked section")
    args = ap.parse_args()

    conn = legacy_get_db()
    cur = conn.cursor()
    src = args.source
    window = ""
    wargs: tuple = (src,)
    if args.days:
        window = " AND timestamp > now() - (%s || ' days')::interval"
        wargs = (src, str(args.days))

    def q(title, sql, args_=None):
        print(f"\n##### {title}")
        try:
            cur.execute(sql, args_ if args_ is not None else wargs)
            for r in cur.fetchall():
                print(" | ".join("" if v is None else str(v) for v in r))
            conn.commit()
        except Exception as e:  # one failed section must not abort the rest
            conn.rollback()
            print(f"(error: {e})")

    q(
        "VOLUME (events | distinct ips | first | last)",
        f"SELECT count(*), count(distinct src_ip), min(timestamp), max(timestamp) "
        f"FROM sensor_events WHERE source=%s{window}",
    )
    q(
        "PER_DAY (day | events | ips)",
        f"SELECT timestamp::date d, count(*), count(distinct src_ip) "
        f"FROM sensor_events WHERE source=%s{window} GROUP BY d ORDER BY d",
    )
    q(
        "DST_PORTS (port | proto | events)",
        f"SELECT dst_port, protocol, count(*) FROM sensor_events WHERE source=%s{window} "
        f"GROUP BY dst_port, protocol ORDER BY 3 DESC",
    )
    q(
        f"TOP_EXTERNAL_IPS (ip | events | country | hostname | ai_threat | intent) — RFC1918 excluded, top {args.top}",
        f"SELECT e.src_ip, count(*) c, p.country, p.hostname, p.ai_threat_level, left(p.ai_intent,50) "
        f"FROM sensor_events e LEFT JOIN attacker_profiles p ON p.ip=e.src_ip "
        f"WHERE e.source=%s{window} AND NOT (e.src_ip <<= inet '10.0.0.0/8' "
        f"OR e.src_ip <<= inet '192.168.0.0/16' OR e.src_ip <<= inet '172.16.0.0/12') "
        f"GROUP BY e.src_ip, p.country, p.hostname, p.ai_threat_level, p.ai_intent "
        f"ORDER BY c DESC LIMIT {args.top}",
    )
    q(
        "INTERNAL_IPS (RFC1918 — infra, not actors)",
        f"SELECT src_ip, count(*) FROM sensor_events e WHERE source=%s{window} "
        f"AND (src_ip <<= inet '10.0.0.0/8' OR src_ip <<= inet '192.168.0.0/16' "
        f"OR src_ip <<= inet '172.16.0.0/12') GROUP BY src_ip ORDER BY 2 DESC",
    )
    q(
        "TOP_COUNTRIES",
        f"SELECT coalesce(p.country,'?'), count(distinct e.src_ip), count(*) "
        f"FROM sensor_events e LEFT JOIN attacker_profiles p ON p.ip=e.src_ip "
        f"WHERE e.source=%s{window} GROUP BY 1 ORDER BY 3 DESC LIMIT 15",
    )
    q(
        "ATTACK_TYPES (summary)",
        f"SELECT attack_types, count(*) FROM sensor_events WHERE source=%s{window} "
        f"AND attack_types IS NOT NULL AND attack_types<>'' GROUP BY 1 ORDER BY 2 DESC LIMIT 30",
    )
    q(
        "RULE_HITS (attack_type | rule | events | ips)",
        f"SELECT p.attack_type, p.rule_name, count(*) c, count(distinct e.src_ip) "
        f"FROM attack_patterns p JOIN sensor_events e ON e.event_id=p.event_id "
        f"WHERE e.source=%s{window} GROUP BY 1,2 ORDER BY c DESC LIMIT 40",
    )
    q(
        "CITRIX_CVE_ACTORS (ip | tag | cve-rule | events | country | hostname | ai_threat)",
        f"SELECT e.src_ip, p.attack_type, p.rule_name, count(*) c, pr.country, pr.hostname, pr.ai_threat_level "
        f"FROM sensor_events e JOIN attack_patterns p ON p.event_id=e.event_id "
        f"LEFT JOIN attacker_profiles pr ON pr.ip=e.src_ip "
        f"WHERE e.source=%s{window} AND p.attack_type LIKE '{NS_TAG_LIKE}' "
        f"GROUP BY e.src_ip, p.attack_type, p.rule_name, pr.country, pr.hostname, pr.ai_threat_level "
        f"ORDER BY c DESC",
    )
    q(
        "REQUEST_LINES (first request line | events | ips)",
        f"SELECT substring(payload from '^[A-Z]+ [^\\r\\n ]+'), count(*) c, count(distinct src_ip) "
        f"FROM sensor_events WHERE source=%s{window} AND payload IS NOT NULL "
        f"GROUP BY 1 ORDER BY c DESC LIMIT 30",
    )
    q(
        "HIGH_CRITICAL_ACTORS (ip | threat | cve | summary)",
        f"SELECT DISTINCT e.src_ip, pr.ai_threat_level, pr.claude_cve, left(pr.claude_summary,220) "
        f"FROM sensor_events e JOIN attacker_profiles pr ON pr.ip=e.src_ip "
        f"WHERE e.source=%s{window} AND pr.ai_threat_level IN ('HIGH','CRITICAL') "
        f"ORDER BY pr.ai_threat_level DESC, e.src_ip LIMIT 30",
    )
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
