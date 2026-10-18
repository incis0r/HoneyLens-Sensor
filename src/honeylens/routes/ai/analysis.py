"""AI routes — analysis feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    HTTPException,
    Request,
    _analysis_detail_html,
    _attacker_hunting_tables_exist,
    db,
    is_known_scanner,
    logger,
    psycopg2,
    valid_event_id,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/analysis/{event_id}")
def ai_analysis_detail(event_id: str, request: Request):
    """Full AI analysis result for a specific event (HTML for browsers, JSON API)."""
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id")

    conn = db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    row = event = None
    try:
        cur.execute("SELECT * FROM ai_analysis WHERE event_id = %s", (event_id,))
        row = cur.fetchone()
        cur.execute(
            """SELECT protocol, host(src_ip) AS src_ip, dst_port,
                              attack_types, LEFT(payload, 2000) AS payload
                       FROM sensor_events WHERE event_id = %s""",
            (event_id,),
        )
        event = cur.fetchone()
    except Exception as e:
        logger.debug("AI analysis detail query failed: %s", e)
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="No AI analysis for this event")

    result = dict(row)
    if result.get("timestamp"):
        result["timestamp"] = result["timestamp"].isoformat()

    if wants_html(request):
        return HTMLResponse(_analysis_detail_html(event_id, result, dict(event) if event else {}))
    return result


@router.post("/ai/analyze/{event_id}")
async def ai_analyze_trigger(event_id: str, request: Request):
    """Manually trigger AI analysis for a specific event. Returns the result."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id")

    # Check if ai_analysis table exists
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'ai_analysis'
    """)
    if not cur.fetchone():
        conn.close()
        raise HTTPException(
            status_code=503,
            detail="AI analysis not configured. Run: python ai_analyzer.py --test-ollama",
        )

    # Check if event exists
    cur.execute(
        """
        SELECT event_id, timestamp, protocol, src_ip::text, src_port,
               dst_ip::text, dst_port, payload, attack_types, scan_score
        FROM sensor_events WHERE event_id = %s
    """,
        (event_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Event not found")

    cols = [
        "event_id",
        "timestamp",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "payload",
        "attack_types",
        "scan_score",
    ]
    event = dict(zip(cols, row, strict=False))
    event["timestamp"] = event["timestamp"].isoformat() if event["timestamp"] else None
    event["severity"] = "HIGH"  # Force analysis

    # Skip known research scanners (unless force query param)
    src_ip_raw = (event.get("src_ip") or "").split("/")[0]
    force_param = request.query_params.get("force", "") if hasattr(request, "query_params") else ""
    # Operator can pick the deep-analysis backend per request:
    #   engine=local -> Ollama (on-box, free)   engine=cloud -> Claude (deeper, paid)
    requested_engine = (
        request.query_params.get("engine", "") if hasattr(request, "query_params") else ""
    ).lower()
    if src_ip_raw and is_known_scanner(ip=src_ip_raw) and force_param != "true":
        conn.close()
        raise HTTPException(
            status_code=422,
            detail=f"Skipped: {src_ip_raw} is a known research scanner. Add ?force=true to override.",
        )

    # Check for existing analysis
    cur.execute(
        "SELECT triage_class, novelty_score, triage_reasoning, "
        "zero_day_score, deep_analysis FROM ai_analysis WHERE event_id = %s",
        (event_id,),
    )
    existing = cur.fetchone()
    conn.close()

    # Use the configured backend. ``engine=local`` remains an explicit Ollama
    # override; the default and ``engine=cloud`` use the same dispatcher as the
    # background analyzer (Nous/OpenAI/Claude/Ollama).
    try:
        from honeylens.analysis.ai_analyzer import (
            AnalysisEngine,
            OllamaClient,
            _build_engine,
            ensure_ai_tables,
        )
        from honeylens.config import OLLAMA_TIMEOUT, OLLAMA_URL

        ollama = None
        backend_name = None
        if requested_engine == "local":
            ollama = OllamaClient(OLLAMA_URL, OLLAMA_TIMEOUT)
            if ollama.is_available():
                engine = AnalysisEngine(ollama)
                backend_name = "ollama"
            else:
                ollama.close()
                engine = None
        else:
            engine, backend_name = _build_engine()

        if engine is None:
            if existing:
                return {
                    "status": "cached",
                    "event_id": event_id,
                    "triage_class": existing[0],
                    "novelty_score": existing[1],
                    "reasoning": existing[2],
                    "zero_day_score": existing[3],
                    "deep_analysis": existing[4],
                    "message": "Configured AI backend unavailable — returning cached analysis",
                }
            raise HTTPException(status_code=503, detail="Configured AI backend is unavailable")

        ensure_ai_tables()
        triage = engine.triage_event(event)

        deep = None
        # A manual request runs deep even for benign triage so the operator gets
        # the complete result shown by the event preview.
        _want_deep = requested_engine in ("local", "cloud") or triage.get("classification") in (
            "SUSPICIOUS",
            "CRITICAL",
        )
        if _want_deep:
            deep = engine.deep_analyze(event, triage)

        if ollama is not None:
            ollama.close()

        result = {
            "status": "analysed",
            "event_id": event_id,
            "triage_class": triage.get("classification"),
            "confidence": triage.get("confidence"),
            "novelty_score": triage.get("novelty_score"),
            "reasoning": triage.get("reasoning"),
            "known_cve": triage.get("known_cve"),
            "iocs": triage.get("iocs", []),
        }
        if requested_engine:
            result["requested_engine"] = requested_engine
        result["backend"] = backend_name
        if deep:
            result["deep_analysis"] = deep
            result["deep_engine"] = backend_name
            result["zero_day_score"] = deep.get("zero_day_probability")
            rule = deep.get("suggested_rule") or {}
            result["suggested_rule"] = (
                rule.get("rule_name") if isinstance(rule, dict) else deep.get("suggested_rule_name")
            )

        # Auto-hunt the source IP after AI analysis
        src_ip_raw = (event.get("src_ip") or "").split("/")[0]
        if src_ip_raw:
            try:
                from honeylens.analysis.attacker_profiler import (
                    fetch_ip_info,
                    get_db_connection,
                    profile_ip,
                )
                from honeylens.config import ATTACKER_PROFILING
                from honeylens.intelligence.osint_providers import build_providers

                if ATTACKER_PROFILING and _attacker_hunting_tables_exist():
                    hunt_conn = db()
                    hunt_cur = hunt_conn.cursor()
                    hunt_cur.execute(
                        "SELECT 1 FROM attacker_profiles WHERE host(ip) = %s", (src_ip_raw,)
                    )
                    if not hunt_cur.fetchone():
                        hunt_conn.close()
                        providers = build_providers(ATTACKER_PROFILING)
                        # 0.9 called profile_ip(ip, conn, providers, mitre_data=…) — wrong
                        # signature and an unawaited coroutine: auto-hunt from the API never
                        # started (the same bug as in claude_analyzer, layer 4).
                        db_conn = get_db_connection()
                        try:
                            await profile_ip(
                                src_ip_raw,
                                fetch_ip_info(db_conn, src_ip_raw),
                                db_conn,
                                providers,
                                ATTACKER_PROFILING,
                            )
                        finally:
                            db_conn.close()
                        logger.info("Auto-hunted %s after AI analysis", src_ip_raw)
                    else:
                        hunt_conn.close()
            except Exception as hunt_err:
                logger.debug("Auto-hunt skipped for %s: %s", src_ip_raw, hunt_err)

        return result

    except ImportError:
        if existing:
            return {
                "status": "cached",
                "event_id": event_id,
                "triage_class": existing[0],
                "novelty_score": existing[1],
                "reasoning": existing[2],
                "zero_day_score": existing[3],
                "deep_analysis": existing[4],
                "message": "ai_analyzer module not available — returning cached analysis",
            }
        raise HTTPException(
            status_code=503, detail="ai_analyzer.py not found. Deploy Phase 1 AI files."
        ) from None
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis error: {e!s}") from e
