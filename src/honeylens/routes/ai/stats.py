"""AI routes — stats feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    Request,
    _ai_dashboard_html,
    _ai_not_configured_html,
    db,
    logger,
    logging,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/stats")
def ai_stats(request: Request):
    """AI Analysis Dashboard — triage stats, flagged events, full analysis log."""
    conn = db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'ai_analysis'
        """)
        if not cur.fetchone():
            conn.close()
            if wants_html(request):
                return HTMLResponse(_ai_not_configured_html())
            return {"error": "ai_analysis table not found"}

        # ── Summary counters ────────────────────────────────────────────
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE triage_class = 'NOISE') AS noise,
                COUNT(*) FILTER (WHERE triage_class = 'KNOWN') AS known,
                COUNT(*) FILTER (WHERE triage_class = 'SUSPICIOUS') AS suspicious,
                COUNT(*) FILTER (WHERE triage_class = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE deep_analysis IS NOT NULL) AS deep_analysed,
                COUNT(*) FILTER (WHERE zero_day_score >= 70) AS zero_day_candidates,
                COUNT(*) FILTER (WHERE analyst_reviewed = FALSE
                                 AND triage_class IN ('SUSPICIOUS', 'CRITICAL')) AS pending_review,
                ROUND(AVG(triage_duration_ms)::numeric, 0) AS avg_triage_ms,
                ROUND(AVG(novelty_score)::numeric, 1) AS avg_novelty,
                MAX(novelty_score) AS max_novelty,
                MAX(timestamp) AS last_analysis,
                COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '24 hours') AS last_24h,
                COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '1 hour') AS last_1h,
                COUNT(*) FILTER (WHERE suggested_rule_regex IS NOT NULL) AS suggested_rules
            FROM ai_analysis
        """)
        s = cur.fetchone()

        summary = dict(
            total=s[0] or 0,
            noise=s[1] or 0,
            known=s[2] or 0,
            suspicious=s[3] or 0,
            critical=s[4] or 0,
            deep_analysed=s[5] or 0,
            zero_day_candidates=s[6] or 0,
            pending_review=s[7] or 0,
            avg_triage_ms=float(s[8]) if s[8] else 0,
            avg_novelty=float(s[9]) if s[9] else 0,
            max_novelty=s[10] or 0,
            last_analysis=s[11].isoformat() if s[11] else None,
            last_24h=s[12] or 0,
            last_1h=s[13] or 0,
            suggested_rules=s[14] or 0,
        )

        # ── By class distribution ───────────────────────────────────────
        by_class = {
            "NOISE": summary["noise"],
            "KNOWN": summary["known"],
            "SUSPICIOUS": summary["suspicious"],
            "CRITICAL": summary["critical"],
        }

        # ── Novelty distribution ────────────────────────────────────────
        cur.execute("""
            SELECT novelty_score, COUNT(*)
            FROM ai_analysis WHERE novelty_score IS NOT NULL
            GROUP BY novelty_score ORDER BY novelty_score
        """)
        novelty_dist = [{"score": r[0], "count": r[1]} for r in cur.fetchall()]

        # ── Recent flagged (SUSPICIOUS/CRITICAL) ────────────────────────
        cur.execute("""
            SELECT a.event_id, a.triage_class, a.novelty_score, a.triage_confidence,
                   a.triage_reasoning, a.known_cve, a.zero_day_score, a.timestamp,
                   a.deep_model, a.suggested_rule_name, a.triage_model,
                   a.triage_duration_ms, a.analyst_reviewed,
                   se.src_ip::text, se.protocol, se.dst_port
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            WHERE a.triage_class IN ('SUSPICIOUS', 'CRITICAL')
            ORDER BY a.timestamp DESC LIMIT 50
        """)
        flagged = [
            dict(
                event_id=r[0],
                triage_class=r[1],
                novelty_score=r[2],
                confidence=r[3],
                reasoning=r[4],
                known_cve=r[5],
                zero_day_score=r[6],
                timestamp=r[7].isoformat() if r[7] else None,
                deep_model=r[8],
                suggested_rule=r[9],
                model=r[10],
                duration_ms=r[11],
                reviewed=r[12],
                src_ip=r[13],
                protocol=r[14],
                dst_port=r[15],
            )
            for r in cur.fetchall()
        ]

        # ── Full analysis log (last 200) ────────────────────────────────
        cur.execute("""
            SELECT a.event_id, a.triage_class, a.triage_confidence,
                   a.novelty_score, a.triage_reasoning, a.known_cve,
                   a.zero_day_score, a.triage_model, a.triage_duration_ms,
                   a.deep_model, a.suggested_rule_name, a.suggested_rule_regex,
                   a.suggested_mitre, a.analyst_reviewed, a.timestamp,
                   se.protocol, se.src_ip::text, se.dst_port, se.attack_types
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            ORDER BY a.timestamp DESC LIMIT 200
        """)
        events = [
            dict(
                event_id=r[0],
                triage_class=r[1],
                confidence=r[2],
                novelty=r[3],
                reasoning=r[4],
                cve=r[5],
                zero_day=r[6],
                model=r[7],
                duration_ms=r[8],
                deep_model=r[9],
                suggested_rule=r[10],
                suggested_regex=r[11],
                suggested_mitre=r[12],
                reviewed=r[13],
                timestamp=r[14].isoformat() if r[14] else None,
                protocol=r[15],
                src_ip=r[16],
                dst_port=r[17],
                attack_types=r[18],
            )
            for r in cur.fetchall()
        ]

    except Exception as e:
        conn.close()
        logging.error(f"attacker_hunting error: {e}")
        if wants_html(request):
            return HTMLResponse("<h2>Error: An internal error occurred</h2>")
        return {"error": "An internal error occurred"}

    # ── Check which src_ips are already hunted (have attacker_profiles) ──
    hunted_ips = set()
    try:
        all_ips = set()
        for f in flagged:
            if f.get("src_ip"):
                all_ips.add(
                    f["src_ip"].split("/")[0]
                    if "/" in (f.get("src_ip") or "")
                    else f.get("src_ip", "")
                )
        for ev in events:
            if ev.get("src_ip"):
                all_ips.add(
                    ev["src_ip"].split("/")[0]
                    if "/" in (ev.get("src_ip") or "")
                    else ev.get("src_ip", "")
                )
        if all_ips:
            conn2 = db()
            cur2 = conn2.cursor()
            cur2.execute(
                "SELECT host(ip) FROM attacker_profiles WHERE host(ip) = ANY(%s)", (list(all_ips),)
            )
            hunted_ips = {r[0] for r in cur2.fetchall()}
            conn2.close()
    except Exception as e:
        logger.debug("attacker_profiles lookup failed: %s", e)  # silent: optional table

    conn.close()

    result: dict[str, Any] = dict(
        summary=summary,
        by_class=by_class,
        novelty_dist=novelty_dist,
        flagged=flagged,
        events=events,
        hunted_ips=list(hunted_ips),
    )

    # ── Claude cost stats ─────────────────────────────────────────────
    try:
        conn3 = db()
        cur3 = conn3.cursor()
        cur3.execute("""
            SELECT
                COUNT(*) AS total_calls,
                COALESCE(SUM(estimated_cost_usd), 0) AS total_cost,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                COALESCE(AVG(elapsed_ms), 0) AS avg_elapsed_ms,
                COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '24 hours') AS calls_24h,
                COALESCE(SUM(estimated_cost_usd) FILTER (WHERE created_at >= NOW()-INTERVAL '24 hours'), 0) AS cost_24h,
                COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '1 hour') AS calls_1h,
                COALESCE(SUM(estimated_cost_usd) FILTER (WHERE created_at >= NOW()-INTERVAL '1 hour'), 0) AS cost_1h,
                MAX(created_at) AS last_call,
                COUNT(DISTINCT src_ip) AS unique_ips,
                COUNT(DISTINCT verdict) AS verdict_types,
                COUNT(*) FILTER (WHERE verdict = 'CRITICAL') AS critical_verdicts,
                COUNT(*) FILTER (WHERE verdict = 'HIGH') AS high_verdicts,
                COUNT(*) FILTER (WHERE cve IS NOT NULL AND cve != '') AS with_cve,
                COUNT(*) FILTER (WHERE threat_actor IS NOT NULL AND threat_actor != '') AS with_actor
            FROM claude_analysis_log
        """)
        cr = cur3.fetchone()
        result["claude_stats"] = {
            "total_calls": cr[0] or 0,
            "total_cost": round(float(cr[1] or 0), 4),
            "total_input_tokens": cr[2] or 0,
            "total_output_tokens": cr[3] or 0,
            "avg_elapsed_ms": int(cr[4] or 0),
            "calls_24h": cr[5] or 0,
            "cost_24h": round(float(cr[6] or 0), 4),
            "calls_1h": cr[7] or 0,
            "cost_1h": round(float(cr[8] or 0), 4),
            "last_call": cr[9].isoformat() if cr[9] else None,
            "unique_ips": cr[10] or 0,
            "critical": cr[12] or 0,
            "high": cr[13] or 0,
            "with_cve": cr[14] or 0,
            "with_actor": cr[15] or 0,
        }

        # Per-model breakdown
        cur3.execute("""
            SELECT model,
                   COUNT(*) AS calls,
                   COALESCE(SUM(estimated_cost_usd), 0) AS cost,
                   COALESCE(SUM(input_tokens), 0) AS input_tok,
                   COALESCE(SUM(output_tokens), 0) AS output_tok,
                   COALESCE(AVG(elapsed_ms), 0) AS avg_ms
            FROM claude_analysis_log
            WHERE model IS NOT NULL
            GROUP BY model
            ORDER BY calls DESC
        """)
        models = []
        for mr in cur3.fetchall():
            models.append(
                {
                    "model": mr[0] or "unknown",
                    "calls": mr[1] or 0,
                    "cost": round(float(mr[2] or 0), 4),
                    "input_tokens": mr[3] or 0,
                    "output_tokens": mr[4] or 0,
                    "avg_ms": int(mr[5] or 0),
                }
            )
        result["claude_stats"]["by_model"] = models

        # Model comparison: verdict distribution per model
        cur3.execute("""
            SELECT model, verdict, COUNT(*) AS cnt
            FROM claude_analysis_log
            WHERE model IS NOT NULL AND verdict IS NOT NULL
            GROUP BY model, verdict
            ORDER BY model, cnt DESC
        """)
        model_verdicts: dict[str, Any] = {}
        for mr in cur3.fetchall():
            m = mr[0] or "unknown"
            if m not in model_verdicts:
                model_verdicts[m] = {}
            model_verdicts[m][mr[1]] = mr[2]
        result["claude_stats"]["model_verdicts"] = model_verdicts

        # Per-IP cost breakdown (top 20 most expensive IPs)
        cur3.execute("""
            SELECT src_ip, COUNT(*) AS calls,
                   COALESCE(SUM(estimated_cost_usd), 0) AS total_cost,
                   COALESCE(SUM(input_tokens), 0) AS tokens,
                   MAX(verdict) AS top_verdict,
                   MAX(created_at) AS last_call
            FROM claude_analysis_log
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY total_cost DESC
            LIMIT 20
        """)
        ip_costs = [
            {
                "ip": r[0],
                "calls": r[1],
                "cost": round(float(r[2] or 0), 4),
                "tokens": r[3] or 0,
                "top_verdict": r[4],
                "last_call": r[5].isoformat() if r[5] else None,
            }
            for r in cur3.fetchall()
        ]
        result["claude_stats"]["ip_costs"] = ip_costs

        conn3.close()
    except Exception as e:
        logger.debug("claude_stats query failed: %s", e)
        result["claude_stats"] = None

    if wants_html(request):
        return HTMLResponse(content=_ai_dashboard_html(result))
    return result
