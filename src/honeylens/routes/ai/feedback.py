"""AI routes — feedback feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    _EVENT_ID_RE,
    HTTPException,
    Request,
    db_cursor,
)

router = APIRouter(tags=["AI Analysis"])


@router.post("/ai/feedback/{event_id}")
async def ai_feedback(event_id: str, request: Request):
    """Mark an AI analysis as true positive or false positive.
    Body: {"feedback": "tp" or "fp"}
    Updates ai_analysis.analyst_reviewed and rule_statistics TP/FP counts."""
    body = await request.json()
    feedback = body.get("feedback", "").lower()
    if feedback not in ("tp", "fp"):
        return {"error": "feedback must be 'tp' or 'fp'"}
    if not _EVENT_ID_RE.match(event_id):
        raise HTTPException(400, "Invalid event_id")
    try:
        with db_cursor() as cur:
            # Mark as reviewed
            cur.execute(
                """
                UPDATE ai_analysis SET analyst_reviewed = TRUE
                WHERE event_id = %s
            """,
                (event_id,),
            )
            # Update rule_statistics TP/FP counters for matched rules
            cur.execute(
                """
                SELECT rule_name FROM attack_patterns WHERE event_id = %s
            """,
                (event_id,),
            )
            rules = [r[0] for r in cur.fetchall()]
            col = "confirmed_true" if feedback == "tp" else "confirmed_false"
            for rn in rules:
                cur.execute(
                    f"""
                    UPDATE rule_statistics SET {col} = {col} + 1, updated_at = NOW()
                    WHERE rule_name = %s
                """,  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
                    (rn,),
                )
        return {
            "status": "ok",
            "event_id": event_id,
            "feedback": feedback,
            "rules_updated": len(rules),
        }
    except Exception as e:
        return {"error": str(e)}
