"""AI prompt-injection canary metrics (Idea 52 Phase B).

`/canary/stats` reports issued canaries vs. AI-agent callbacks (correlation rate,
latency, top agents). The callback ingress itself is served by the honeypot on its
own port (see honeypot_k8s), NOT here — this is a read-only dashboard endpoint.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request

from honeylens.routes._helpers import db, wants_html

logger = logging.getLogger("api")
router = APIRouter(tags=["AI Canary"])


def _render(request, result):
    """JSON for API/fetch callers, the dashboard page for a browser."""
    if wants_html(request):
        from fastapi.responses import HTMLResponse

        from honeylens.webui.dashboard_canary import CANARY_DASHBOARD_HTML

        return HTMLResponse(CANARY_DASHBOARD_HTML)
    return result


def _from_registry(request, window, registry, rows):
    """Shape the response from registry rows (the fast, authoritative path)."""
    delays: list[Any] = []
    agents: dict[str, Any] = {}
    recent: list[Any] = []
    for ts, cb_ip, origin_ip, proto, path, ua, delay in rows:
        if delay is not None:
            delays.append(int(delay))
        key = ua or "?"
        agents[key] = agents.get(key, 0) + 1
        if len(recent) < 20:
            recent.append(
                {
                    "timestamp": ts.isoformat() if ts else None,
                    "callback_src_ip": cb_ip,
                    "origin_src_ip": origin_ip,
                    "origin_path": " ".join(x for x in (proto, path) if x) or None,
                    "user_agent": key,
                    "correlated": bool(path),
                    "delay_ms": int(delay) if delay is not None else None,
                }
            )
    return _render(
        request,
        {
            "window": window,
            "source": "registry",
            "issued": registry["issued"],
            "callbacks": registry["answered"],
            "correlated": registry["correlated"],
            "avg_latency_ms": round(sum(delays) / len(delays)) if delays else None,
            "top_agents": sorted(
                ({"user_agent": k, "count": v} for k, v in agents.items()),
                key=lambda x: -x["count"],
            )[:10],
            "recent": recent,
        },
    )


@router.get("/canary/stats")
def canary_stats(request: Request, window: str = "30 days"):
    """Issued vs. callback metrics for the AI prompt-injection canary."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SET statement_timeout='20s'")
        # The registry is the authority once populated: it survives honeypot
        # restarts, spans processes, and — the practical reason this whole branch
        # exists — it is small and indexed. Deriving the same numbers from events
        # means joining attack_patterns to sensor_events, which on a busy sensor
        # (~500k rows) blows the statement timeout and the page shows nothing.
        registry = None
        try:
            cur.execute(
                """SELECT count(*), count(callback_at),
                          count(*) FILTER (WHERE callback_at IS NOT NULL
                                             AND origin_path IS NOT NULL)
                     FROM ai_prompt_canaries
                    WHERE issued_at > NOW() - INTERVAL %s""",
                (window,),
            )
            issued_reg, answered_reg, correlated_reg = cur.fetchone()
            if issued_reg:
                registry = {
                    "issued": issued_reg,
                    "answered": answered_reg,
                    "correlated": correlated_reg,
                }
        except Exception:
            conn.rollback()
            cur = conn.cursor()
            cur.execute("SET statement_timeout='20s'")

        if registry is not None:
            cur.execute(
                """SELECT callback_at, host(callback_src_ip), host(origin_src_ip),
                          origin_protocol, origin_path, callback_user_agent,
                          EXTRACT(EPOCH FROM (callback_at - issued_at)) * 1000
                     FROM ai_prompt_canaries
                    WHERE callback_at IS NOT NULL AND issued_at > NOW() - INTERVAL %s
                    ORDER BY callback_at DESC LIMIT 500""",
                (window,),
            )
            return _from_registry(request, window, registry, cur.fetchall())

        # The honeypot event dict (canary_nonce, canary_correlated, origin_*,
        # user_agent, callback_delay_ms) lands in the jsonb `metadata` column —
        # `payload` only holds the request line ("GET /canary/ai/..").
        #
        # Issued canaries: any honeypot response that embedded a nonce. Source is
        # NOT constrained to honeypot_k8s — the K8s secret read logs protocol
        # 'https' so the ingest labels it 'honeypotng', and the LLM honeypot issues
        # canaries too. The callback rows also carry canary_nonce, so exclude them.
        cur.execute(
            """SELECT count(*) FROM sensor_events
                WHERE timestamp > NOW() - INTERVAL %s
                  AND metadata ? 'canary_nonce'
                  AND COALESCE(metadata->>'action','') <> 'ai_canary_callback'""",
            (window,),
        )
        issued = cur.fetchone()[0]

        cur.execute(
            """SELECT se.metadata, host(se.src_ip), se.timestamp
               FROM sensor_events se JOIN attack_patterns ap ON ap.event_id = se.event_id
               WHERE ap.attack_type = 'AI_AGENT_CALLBACK' AND se.timestamp > NOW() - INTERVAL %s
               ORDER BY se.timestamp DESC LIMIT 500""",
            (window,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    correlated = 0
    delays: list[Any] = []
    agents: dict[str, Any] = {}
    recent: list[Any] = []
    for meta, ip, ts in rows:
        # psycopg2 decodes jsonb to a dict; be defensive about NULL/str.
        if isinstance(meta, dict):
            d = meta
        elif isinstance(meta, str):
            try:
                d = json.loads(meta)
            except (ValueError, TypeError):
                d = {}
        else:
            d = {}
        if d.get("canary_correlated"):
            correlated += 1
        if isinstance(d.get("callback_delay_ms"), int):
            delays.append(d["callback_delay_ms"])
        ua = d.get("user_agent") or "?"
        agents[ua] = agents.get(ua, 0) + 1
        if len(recent) < 20:
            recent.append(
                {
                    "timestamp": ts.isoformat() if ts else None,
                    "callback_src_ip": ip,
                    "origin_src_ip": d.get("origin_src_ip"),
                    "origin_path": d.get("origin_path"),
                    "user_agent": ua,
                    "correlated": bool(d.get("canary_correlated")),
                    "delay_ms": d.get("callback_delay_ms"),
                }
            )

    # Reached only when the registry is empty — an older sensor, or one that has
    # not issued a canary yet.
    result = {
        "window": window,
        "source": "events",
        "issued": issued,
        "callbacks": len(rows),
        "correlated": correlated,
        "avg_latency_ms": round(sum(delays) / len(delays)) if delays else None,
        "top_agents": sorted(
            ({"user_agent": k, "count": v} for k, v in agents.items()), key=lambda x: -x["count"]
        )[:10],
        "recent": recent,
    }
    return _render(request, result)
