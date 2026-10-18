#!/usr/bin/env python3
"""
blog_diag.py — Blog Publisher Diagnostic Tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Run on the sensor to verify all DB schemas match blog_publisher.py expectations.

Usage:
    python blog_diag.py
    python blog_diag.py --ip 202.142.151.6    # also test queries for a real IP
"""

import argparse
import sys

import psycopg2.extras

try:
    from honeylens.database import legacy_get_db
except ImportError:
    print("[!] Cannot import core.database from config.py — are you in /opt/sensor/?")
    sys.exit(1)

# ── What blog_publisher.py expects ──────────────────────────────────────

EXPECTED = {
    "attacker_profiles": [
        "ip",
        "country",
        "asn",
        "as_org",
        "abuse_score",
        "open_ports",
        "hostname",
        "city",
        "is_vpn",
        "is_noise",
        "os_guess",
        "ai_summary",
        "ai_intent",
        "ai_threat_level",
        "hunt_status",
        "finish_notes",
        "internal_tags",
        "cluster_tags",
        "mitre_techniques",
        "apt_candidates",
        "claude_verdict",
        "claude_summary",
        "claude_technique",
        "claude_cve",
        "claude_threat_actor",
        "total_events",
        "total_attacks",
        "attack_types",
        "first_seen",
        "last_seen",
        "osint_data",
    ],
    "sensor_events": [
        "event_id",
        "src_ip",
        "dst_port",
        "protocol",
        "timestamp",
    ],
    "ai_analysis": [
        "event_id",
        "timestamp",
        "triage_class",
        "triage_confidence",
        "triage_reasoning",
        "novelty_score",
        "known_cve",
        "deep_model",
        "deep_analysis",
        "zero_day_score",
        "suggested_rule_name",
        "suggested_mitre",
        "claude_verdict",
        "claude_confidence",
        "claude_attack_type",
        "claude_technique",
        "claude_tactic",
        "claude_cve",
        "claude_zero_day_prob",
        "claude_threat_actor",
        "claude_kill_chain",
        "claude_summary",
        "claude_iocs",
        "claude_recommendations",
    ],
    "attack_patterns": [
        "event_id",
        "attack_type",
        "rule_name",
        "severity",
    ],
    "threat_scores": [
        "event_id",
        "score",
        "severity",
        "hit_count",
    ],
}

# ── Test queries (same as blog_publisher.py) ────────────────────────────

TEST_QUERIES = {
    "attacker_profiles": """
        SELECT ip, country, asn, as_org, abuse_score,
               open_ports, hostname, city,
               is_vpn, is_noise, os_guess,
               ai_summary, ai_intent, ai_threat_level,
               hunt_status, finish_notes,
               internal_tags, cluster_tags,
               mitre_techniques, apt_candidates,
               claude_verdict, claude_summary,
               claude_technique, claude_cve, claude_threat_actor,
               total_events, total_attacks, attack_types,
               first_seen, last_seen,
               osint_data
        FROM attacker_profiles
        WHERE host(ip) = %s
    """,
    "ai_analysis": """
        SELECT
            a.event_id,
            a.triage_class, a.triage_confidence, a.triage_reasoning,
            a.novelty_score, a.known_cve,
            a.deep_model, a.deep_analysis, a.zero_day_score,
            a.suggested_rule_name, a.suggested_mitre,
            a.claude_verdict, a.claude_confidence, a.claude_attack_type,
            a.claude_technique, a.claude_tactic, a.claude_cve,
            a.claude_zero_day_prob, a.claude_threat_actor, a.claude_kill_chain,
            a.claude_summary, a.claude_iocs, a.claude_recommendations
        FROM ai_analysis a
        JOIN sensor_events se ON se.event_id = a.event_id
        WHERE host(se.src_ip) = %s
        ORDER BY a.timestamp DESC
        LIMIT 1
    """,
    "sensor_events_agg": """
        SELECT
            COUNT(*)                       AS event_count,
            MIN(timestamp)                 AS first_seen,
            MAX(timestamp)                 AS last_seen,
            COUNT(DISTINCT dst_port)       AS unique_ports,
            array_agg(DISTINCT dst_port)   AS ports,
            array_agg(DISTINCT protocol)   AS protocols
        FROM sensor_events
        WHERE host(src_ip) = %s
    """,
    "attack_patterns": """
        SELECT ap.attack_type, ap.rule_name, ap.severity,
               COUNT(*) AS hit_count
        FROM attack_patterns ap
        JOIN sensor_events se ON se.event_id = ap.event_id
        WHERE host(se.src_ip) = %s
        GROUP BY ap.attack_type, ap.rule_name, ap.severity
        ORDER BY hit_count DESC
        LIMIT 20
    """,
    "threat_scores": """
        SELECT MAX(ts.score) AS max_score,
               MAX(ts.severity) AS max_severity,
               COUNT(*) AS scored_events,
               SUM(ts.hit_count) AS total_hits
        FROM threat_scores ts
        JOIN sensor_events se ON se.event_id = ts.event_id
        WHERE host(se.src_ip) = %s
    """,
}


def get_table_columns(cur, table):
    """Get actual columns for a table."""
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = %s
        ORDER BY ordinal_position
    """,
        (table,),
    )
    return [row["column_name"] for row in cur.fetchall()]


def main():
    parser = argparse.ArgumentParser(description="Blog Publisher Diagnostics")
    parser.add_argument("--ip", help="Test queries against a real IP")
    args = parser.parse_args()

    print("=" * 70)
    print("BLOG PUBLISHER — DIAGNOSTIC REPORT")
    print("=" * 70)

    try:
        conn = legacy_get_db()
        conn.cursor_factory = psycopg2.extras.RealDictCursor
    except Exception as e:
        print("\n[FAIL] Cannot connect to database: %s" % e)
        sys.exit(1)

    print("\n[OK] Database connection successful")
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ── Phase 1: Schema validation ──────────────────────────────────────

    print("\n" + "-" * 70)
    print("PHASE 1: SCHEMA VALIDATION")
    print("-" * 70)

    all_ok = True
    for table, expected_cols in EXPECTED.items():
        actual_cols = get_table_columns(cur, table)

        if not actual_cols:
            print("\n[WARN] Table '%s' not found (may be optional)" % table)
            continue

        missing = [c for c in expected_cols if c not in actual_cols]
        extra = [c for c in actual_cols if c not in expected_cols]

        if missing:
            all_ok = False
            print("\n[FAIL] %s — MISSING columns that blog_publisher expects:" % table)
            for m in missing:
                print("         - %s" % m)
        else:
            print("\n[OK]   %s — all %d expected columns present" % (table, len(expected_cols)))

        if extra:
            print("       Extra columns (not used by publisher): %s" % ", ".join(extra[:10]))
            if len(extra) > 10:
                print("       ... and %d more" % (len(extra) - 10))

    # ── Phase 2: Query execution ────────────────────────────────────────

    if args.ip:
        print("\n" + "-" * 70)
        print("PHASE 2: QUERY TESTS (IP: %s)" % args.ip)
        print("-" * 70)

        for name, query in TEST_QUERIES.items():
            try:
                cur.execute(query, (args.ip,))
                rows = cur.fetchall()
                row_count = len(rows)

                if row_count > 0:
                    row = dict(rows[0])
                    # Truncate long values for display
                    display = {}
                    for k, v in row.items():
                        sv = str(v)
                        display[k] = sv[:80] + "..." if len(sv) > 80 else sv
                    print("\n[OK]   %s — %d row(s)" % (name, row_count))
                    for k, v in display.items():
                        print("         %s: %s" % (k, v))
                else:
                    print("\n[WARN] %s — 0 rows (no data for this IP)" % name)
            except Exception as e:
                all_ok = False
                conn.rollback()
                err = str(e).strip().split("\n")
                print("\n[FAIL] %s — QUERY ERROR:" % name)
                for line in err[:5]:
                    print("         %s" % line)
    else:
        print("\n[INFO] Skipping query tests (use --ip X.X.X.X to test)")

    # ── Phase 3: Config check ───────────────────────────────────────────

    print("\n" + "-" * 70)
    print("PHASE 3: BLOG CONFIG CHECK")
    print("-" * 70)

    try:
        from honeylens.config import BLOG

        print("\n[OK]   BLOG config found in config.py")
        print("         enabled:     %s" % BLOG.get("enabled"))
        print("         blog_url:    %s" % BLOG.get("blog_url"))
        print("         api_key:     %s***" % (BLOG.get("api_key", "")[:8] or "NOT SET"))
        print("         basic_user:  %s" % BLOG.get("basic_user"))
        print("         basic_pass:  %s" % ("***set***" if BLOG.get("basic_pass") else "NOT SET"))
        print("         verify_tls:  %s" % BLOG.get("verify_tls"))
        print("         publishing:  manual only (operator-triggered from hunting)")

        if not BLOG.get("enabled"):
            print("\n[WARN] BLOG.enabled is False — publishing is disabled")
        if not BLOG.get("api_key") or BLOG["api_key"].startswith("sk_blog_CHANGE"):
            print("\n[WARN] API key appears to be the default placeholder — change it!")
        if not BLOG.get("basic_pass") or BLOG["basic_pass"] == "CHANGE_THIS_TO_A_STRONG_PASSWORD":
            print("\n[WARN] Basic password appears to be the default — change it!")
    except ImportError:
        print("\n[FAIL] No BLOG section found in config.py")
        all_ok = False

    # ── Phase 4: Ollama check ───────────────────────────────────────────

    print("\n" + "-" * 70)
    print("PHASE 4: OLLAMA CHECK")
    print("-" * 70)

    try:
        from honeylens.config import OLLAMA_DEEP_MODEL, OLLAMA_URL

        print("\n         URL:   %s" % OLLAMA_URL)
        print("         Model: %s" % OLLAMA_DEEP_MODEL)

        import requests

        try:
            r = requests.get("%s/api/tags" % OLLAMA_URL.rstrip("/"), timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if OLLAMA_DEEP_MODEL in models or any(OLLAMA_DEEP_MODEL in m for m in models):
                    print("[OK]   Ollama reachable, model '%s' available" % OLLAMA_DEEP_MODEL)
                else:
                    print("[WARN] Ollama reachable but model '%s' not found" % OLLAMA_DEEP_MODEL)
                    print("         Available: %s" % ", ".join(models[:5]))
            else:
                print("[WARN] Ollama returned HTTP %d" % r.status_code)
        except Exception as e:
            print("[WARN] Cannot reach Ollama: %s" % e)
            print("         (fallback template content will be used)")
    except ImportError:
        print("\n[WARN] OLLAMA_URL / OLLAMA_DEEP_MODEL not in config.py")

    # ── Summary ─────────────────────────────────────────────────────────

    print("\n" + "=" * 70)
    if all_ok:
        print("RESULT: ALL CHECKS PASSED")
    else:
        print("RESULT: ISSUES FOUND — fix the [FAIL] items above")
    print("=" * 70)

    conn.close()


if __name__ == "__main__":
    main()
