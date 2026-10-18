"""AI routes — rules feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from typing import ClassVar, cast

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    HTTPException,
    JSONResponse,
    Request,
    _ai_rules_html,
    _infer_attack_type,
    _severity_from_triage,
    ai_subnav,
    db,
    html_response,
    json,
    logger,
    psycopg2,
    re,
    valid_event_id,
    validate_rule,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/rules/suggested")
async def ai_suggested_rules(request: Request):
    """List AI-suggested classifier rules pending review."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT a.event_id, a.suggested_rule_name, a.suggested_rule_regex,
                   a.suggested_mitre, a.triage_class, a.triage_confidence,
                   a.claude_verdict, a.claude_attack_type,
                   a.timestamp, a.analyst_reviewed
            FROM ai_analysis a
            WHERE a.suggested_rule_name IS NOT NULL
              AND a.suggested_rule_name != ''
            ORDER BY a.analyst_reviewed ASC NULLS FIRST, a.timestamp DESC
            LIMIT 100
        """)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
        conn.close()

        if wants_html(request):
            from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

            html = f"""<!DOCTYPE html><html><head><title>Suggested Rules</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("rules")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:16px">AI-Suggested Classifier Rules ({len(rows)})</h2>
<table><thead><tr><th>Rule Name</th><th>Regex</th><th>MITRE</th><th>Verdict</th><th>Confidence</th><th>Reviewed</th><th>Actions</th></tr></thead><tbody>"""
            import html as _h

            for r in rows:
                reviewed = "Yes" if r.get("analyst_reviewed") else "No"
                rev_color = "#22c55e" if r.get("analyst_reviewed") else "#f97316"
                regex = _h.escape((r.get("suggested_rule_regex") or "")[:60])
                rule_name = _h.escape(str(r.get("suggested_rule_name") or "?"))
                mitre = _h.escape(str(r.get("suggested_mitre") or ""))
                verdict = _h.escape(str(r.get("claude_verdict") or r.get("triage_class") or ""))
                confidence = _h.escape(str(r.get("triage_confidence") or ""))
                eid = _h.escape(str(r.get("event_id") or ""))
                html += f"""<tr>
<td style="font-weight:600;color:#22d3ee">{rule_name}</td>
<td><code style="font-size:10px">{regex}</code></td>
<td>{mitre}</td>
<td>{verdict}</td>
<td>{confidence}</td>
<td style="color:{rev_color}">{reviewed}</td>
<td>
<button onclick="fetch('/ai/rules/{eid}/approve',{{method:'POST'}}).then(()=>location.reload())"
 style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:10px">Approve</button>
<button onclick="fetch('/ai/rules/{eid}/reject',{{method:'POST'}}).then(()=>location.reload())"
 style="background:#ef444422;color:#ef4444;border:1px solid #ef4444;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:10px;margin-left:4px">Reject</button>
</td></tr>"""
            html += f"</tbody></table><script>{sortable_table_js()}</script></div></body></html>"
            return HTMLResponse(html)

        return {"rules": rows, "count": len(rows)}
    except Exception as e:
        conn.close()
        return {"error": str(e)}


@router.post("/ai/rules/{event_id}/approve")
async def ai_rule_approve(event_id: str, request: Request):
    """Approve an AI-suggested rule — mark as reviewed."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE ai_analysis
            SET analyst_reviewed = TRUE, analyst_verdict = 'APPROVED',
                analyst_notes = 'Approved via WebUI on ' || NOW()::text
            WHERE event_id = %s AND suggested_rule_name IS NOT NULL
        """,
            (event_id,),
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
        if updated == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "approved", "event_id": event_id}
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/ai/rules/{event_id}/reject")
async def ai_rule_reject(event_id: str, request: Request):
    """Reject an AI-suggested rule — mark as reviewed + rejected."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE ai_analysis
            SET analyst_reviewed = TRUE, analyst_verdict = 'REJECTED',
                analyst_notes = 'Rejected via WebUI on ' || NOW()::text
            WHERE event_id = %s AND suggested_rule_name IS NOT NULL
        """,
            (event_id,),
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
        if updated == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "rejected", "event_id": event_id}
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/ai/rules/all")
def ai_rules_all():
    """Combined endpoint: AI-suggested + approved custom rules in one response."""

    # Build a fake request that always wants JSON (not HTML)
    class _FakeReq:
        headers: ClassVar[dict[str, str]] = {"accept": "application/json"}
        query_params: ClassVar[dict[str, str]] = {}

    fake = cast(Request, _FakeReq())
    suggested = _pending_suggested_rules(fake)
    custom = ai_custom_rules_list(fake)
    sug_data = suggested if isinstance(suggested, dict) else {"rules": [], "count": 0}
    cust_data = custom if isinstance(custom, dict) else {"rules": [], "count": 0}
    return {"suggested": sug_data, "custom": cust_data}


def _pending_suggested_rules(request):
    """AI-suggested rules not yet approved (novelty-ordered) — JSON helper for /ai/rules/all.

    NOT a route: GET /ai/rules/suggested is served by the async ai_suggested_rules
    above (the analyst review page). This is the data-only variant used to compose
    the combined /ai/rules/all response.
    """
    conn = db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Check if ai_custom_rules table exists for the LEFT JOIN
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'ai_custom_rules'
            )
        """)
        has_custom_table = cur.fetchone()["exists"]

        if has_custom_table:
            cur.execute("""
                SELECT a.event_id, a.suggested_rule_name, a.suggested_rule_regex,
                       a.triage_class, a.novelty_score, a.triage_reasoning, a.timestamp,
                       a.suggested_mitre,
                       se.protocol, host(se.src_ip) AS src_ip, se.attack_types,
                       FALSE AS already_approved
                FROM ai_analysis a
                LEFT JOIN sensor_events se ON se.event_id = a.event_id
                LEFT JOIN ai_custom_rules cr ON cr.rule_name = a.suggested_rule_name
                WHERE a.suggested_rule_name IS NOT NULL
                  AND a.suggested_rule_regex IS NOT NULL
                  AND cr.rule_name IS NULL
                ORDER BY a.novelty_score DESC
                LIMIT 50
            """)
        else:
            cur.execute("""
                SELECT a.event_id, a.suggested_rule_name, a.suggested_rule_regex,
                       a.triage_class, a.novelty_score, a.triage_reasoning, a.timestamp,
                       a.suggested_mitre,
                       se.protocol, host(se.src_ip) AS src_ip, se.attack_types,
                       FALSE AS already_approved
                FROM ai_analysis a
                LEFT JOIN sensor_events se ON se.event_id = a.event_id
                WHERE a.suggested_rule_name IS NOT NULL
                  AND a.suggested_rule_regex IS NOT NULL
                ORDER BY a.novelty_score DESC
                LIMIT 50
            """)

        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
    except Exception as e:
        logger.error("Error loading suggested rules: %s", e)
        rows = []
    conn.close()
    if wants_html(request):
        return html_response("Suggested Rules", rows, request, "auto")
    return {"rules": rows, "count": len(rows)}


@router.get("/ai/rules/custom")
def ai_custom_rules_list(request: Request):
    """List all approved AI-generated custom rules."""
    conn = db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Check if table exists first
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'ai_custom_rules'
            )
        """)
        if not cur.fetchone()["exists"]:
            conn.close()
            return {
                "rules": [],
                "count": 0,
                "note": "ai_custom_rules table not created yet. Run: python setup_db.py",
            }

        cur.execute("""
            SELECT id, rule_name, attack_type, regex_pattern, severity,
                   mitre_technique, description, enabled,
                   source_event_id, ai_reasoning, ai_novelty, ai_triage_class,
                   approved_by, approved_at, created_at
            FROM ai_custom_rules
            ORDER BY created_at DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            for k in ("approved_at", "created_at"):
                if r.get(k):
                    r[k] = r[k].isoformat()
    except Exception as e:
        logger.error("Error loading custom rules: %s", e)
        rows = []
    conn.close()
    if wants_html(request):
        return html_response("Custom Rules", rows, request, "auto")
    return {"rules": rows, "count": len(rows)}


@router.get("/ai/rules/export")
def ai_rules_export(request: Request, include_disabled: bool = False):
    """Export custom rules as a signed JSON bundle (Idea 42)."""
    import hashlib as _hl
    import socket as _sock

    from honeylens.version import VERSION as _ver

    conn = db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    sql = "SELECT * FROM ai_custom_rules"
    if not include_disabled:
        sql += " WHERE enabled = TRUE"
    sql += " ORDER BY rule_name"
    try:
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.debug("AI rules query failed: %s", e)
        rows = []
    conn.close()

    rules = []
    for r in rows:
        rules.append(
            {
                "rule_name": r.get("rule_name", ""),
                "rule_regex": r.get("rule_regex") or r.get("regex_pattern", ""),
                "rule_category": r.get("rule_category") or r.get("attack_type", "UNKNOWN"),
                "rule_severity": r.get("rule_severity") or r.get("severity", "MEDIUM"),
                "rule_description": r.get("rule_description") or r.get("description", ""),
                "mitre_technique": r.get("mitre_technique", ""),
                "source_model": r.get("source_model", ""),
                "enabled": bool(r.get("enabled", True)),
                "tags": r.get("tags") or [],
            }
        )

    rules_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    sha = _hl.sha256(rules_json.encode()).hexdigest()

    bundle = {
        "honeylens_rule_bundle": {
            "version": 1,
            "format": "honeylens-rules-v1",
            "exported_at": __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .isoformat(),
            "exported_from": {
                "sensor_id": f"sensor-{_sock.gethostname()}",
                "sensor_version": _ver,
                "hostname": _sock.gethostname(),
            },
            "rule_count": len(rules),
            "sha256": sha,
        },
        "rules": rules,
    }

    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="honeylens_rules_{sha[:8]}.json"'},
    )


@router.post("/ai/rules/approve")
async def ai_approve_rule(request: Request):
    """
    Approve an AI-suggested rule — adds it to ai_custom_rules.
    Body JSON: {event_id, rule_name?, attack_type?, severity?, description?}
    """
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        body = await request.json()
    except Exception as e:
        logger.debug("JSON parse error for rule suggestion: %s", e)
        raise HTTPException(status_code=400, detail="JSON body required: {event_id}") from e

    event_id = body.get("event_id")
    if not event_id or not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Valid event_id required")

    conn = db()
    cur = conn.cursor()

    # Ensure ai_custom_rules table exists
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'ai_custom_rules'
        )
    """)
    if not cur.fetchone()[0]:
        conn.close()
        raise HTTPException(
            status_code=503, detail="ai_custom_rules table not found. Run: python setup_db.py"
        )

    # Fetch the AI suggestion
    cur.execute(
        """
        SELECT suggested_rule_name, suggested_rule_regex, suggested_mitre,
               triage_class, novelty_score, triage_reasoning
        FROM ai_analysis WHERE event_id = %s
    """,
        (event_id,),
    )
    ai_row = cur.fetchone()
    if not ai_row:
        conn.close()
        raise HTTPException(status_code=404, detail="No AI analysis found for this event")
    if not ai_row[0] or not ai_row[1]:
        conn.close()
        raise HTTPException(status_code=400, detail="No rule suggestion in this AI analysis")

    rule_name = body.get("rule_name") or ai_row[0]
    regex_pattern = body.get("regex_pattern") or ai_row[1]
    mitre = body.get("mitre_technique") or ai_row[2]
    triage_class = ai_row[3]
    novelty = ai_row[4]
    reasoning = ai_row[5]

    # Analyst can override these — always normalize to UPPERCASE
    attack_type = (body.get("attack_type") or _infer_attack_type(rule_name)).upper()
    severity = body.get("severity") or _severity_from_triage(triage_class, novelty)
    description = body.get("description") or (reasoning[:200] if reasoning else None)

    # Guardrail: reject fantasy/over-broad/benign-matching rules before they
    # ever enter ai_custom_rules (root cause of the 2026-07-23 false-ICS wave).
    if validate_rule is not None:
        ok, reason = validate_rule(rule_name, attack_type, regex_pattern)
        if not ok:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Rule rejected by guardrail: {reason}")
    else:
        # minimal fallback if the validator module is unavailable
        try:
            re.compile(regex_pattern)
        except re.error as e:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Invalid regex: {str(e)[:100]}") from e

    # Sanitize rule_name
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", rule_name)[:128]

    try:
        cur.execute(
            """
            INSERT INTO ai_custom_rules (
                rule_name, attack_type, regex_pattern, severity,
                mitre_technique, description, enabled,
                source_event_id, ai_reasoning, ai_novelty, ai_triage_class
            ) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s)
            ON CONFLICT (rule_name) DO UPDATE SET
                regex_pattern = EXCLUDED.regex_pattern,
                severity = EXCLUDED.severity,
                mitre_technique = EXCLUDED.mitre_technique,
                description = EXCLUDED.description,
                enabled = TRUE,
                disabled_at = NULL
            RETURNING id, rule_name
        """,
            (
                clean_name,
                attack_type,
                regex_pattern,
                severity,
                mitre,
                description,
                event_id,
                reasoning,
                novelty,
                triage_class,
            ),
        )
        result = cur.fetchone()
        conn.commit()
        conn.close()
        return {
            "status": "approved",
            "rule_id": result[0],
            "rule_name": result[1],
            "attack_type": attack_type,
            "severity": severity,
            "regex": regex_pattern,
        }
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)[:200]}") from e


@router.post("/ai/rules/reject")
async def ai_reject_rule(request: Request):
    """
    Reject/dismiss an AI-suggested rule — clears the suggestion from ai_analysis.
    Body JSON: {event_id}
    """
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        body = await request.json()
    except Exception as e:
        logger.debug("JSON parse error for rule delete: %s", e)
        raise HTTPException(status_code=400, detail="JSON body required: {event_id}") from e

    event_id = body.get("event_id")
    if not event_id or not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Valid event_id required")

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE ai_analysis SET
                suggested_rule_name = NULL,
                suggested_rule_regex = NULL,
                suggested_mitre = NULL
            WHERE event_id = %s
            RETURNING event_id
        """,
            (event_id,),
        )
        row = cur.fetchone()
        conn.commit()
        conn.close()
        if row:
            return {"status": "rejected", "event_id": event_id}
        else:
            raise HTTPException(status_code=404, detail="No AI analysis found for this event")
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)[:200]}") from e


@router.post("/ai/rules/custom/{rule_id}/toggle")
def ai_toggle_custom_rule(rule_id: int, request: Request):
    """Enable/disable a custom rule."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE ai_custom_rules
            SET enabled = NOT enabled,
                disabled_at = CASE WHEN enabled THEN NOW() ELSE NULL END
            WHERE id = %s
            RETURNING id, rule_name, enabled
        """,
            (rule_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.commit()
        conn.close()
        return {"rule_id": row[0], "rule_name": row[1], "enabled": row[2]}
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


@router.delete("/ai/rules/custom/{rule_id}")
def ai_delete_custom_rule(rule_id: int):
    """Permanently delete a custom rule."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM ai_custom_rules WHERE id = %s RETURNING rule_name", (rule_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.commit()
        conn.close()
        return {"deleted": row[0]}
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


@router.get("/ai/rules", response_class=HTMLResponse)
async def ai_rules_dashboard(request: Request):
    """AI Rule Management dashboard — review suggestions, approve, manage custom rules."""
    if not wants_html(request):
        from starlette.responses import JSONResponse as _JSONResp

        return _JSONResp(
            {
                "suggested": "/ai/rules/suggested",
                "custom": "/ai/rules/custom",
                "all": "/ai/rules/all",
                "approve": "POST /ai/rules/approve",
            }
        )
    return HTMLResponse(content=_ai_rules_html())


@router.post("/ai/rules/reload")
async def ai_rules_reload(request: Request):
    """Hot-reload custom rules into the attack classifier without restart."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        from honeylens.classification.attack_classifier import (
            get_custom_rule_names,
            reload_custom_rules,
        )

        count = reload_custom_rules()
        names = sorted(get_custom_rule_names())
        return {"status": "reloaded", "custom_rules_loaded": count, "rule_names": names}
    except ImportError:
        # Fallback to standalone loader module
        try:
            from honeylens.classification.custom_rules_loader import get_custom_rule_names as _names
            from honeylens.classification.custom_rules_loader import reload_custom_rules as _reload

            count = _reload()
            return {
                "status": "reloaded",
                "custom_rules_loaded": count,
                "rule_names": sorted(_names()),
            }
        except ImportError:
            return {
                "status": "error",
                "detail": "Neither attack_classifier nor custom_rules_loader available",
            }
    except Exception as e:
        return {"status": "error", "detail": str(e)[:200]}
