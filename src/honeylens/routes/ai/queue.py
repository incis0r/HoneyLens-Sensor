"""AI routes — queue feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    Request,
    db,
    html_response,
    logger,
    psycopg2,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/queue")
def ai_queue(request: Request):
    """Events pending analyst review (SUSPICIOUS/CRITICAL, not yet reviewed)."""
    conn = db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT a.event_id, a.triage_class, a.novelty_score,
                   a.triage_confidence, a.triage_reasoning, a.known_cve,
                   a.zero_day_score, a.suggested_rule_name,
                   a.suggested_rule_regex, a.timestamp,
                   a.deep_analysis
            FROM ai_analysis a
            WHERE a.analyst_reviewed = FALSE
              AND a.triage_class IN ('SUSPICIOUS', 'CRITICAL')
            ORDER BY
                CASE a.triage_class WHEN 'CRITICAL' THEN 0 ELSE 1 END,
                a.novelty_score DESC
            LIMIT 50
        """)
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
    except Exception as e:
        logger.debug("AI analysis queue query failed: %s", e)
        rows = []
    conn.close()
    if wants_html(request):
        return html_response("AI Analysis Queue", rows, request, "auto")
    return {"queue": rows, "count": len(rows)}
