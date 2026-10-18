"""
routes/classifier.py — Attack Classifier & Knowledge Base Routes
=================================================================
Extracted from api.py (Phase 1 refactor).
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from honeylens.database import db_cursor
from honeylens.geoip import get_country_code
from honeylens.intelligence.whitelist import is_whitelisted
from honeylens.routes._helpers import (
    EXCLUDED_SUBNETS,
    db,
    html_response,
    strip_cidr,
    valid_event_id,
    valid_protocol,
    wants_html,
)


def _get_country(ip):
    if not ip:
        return "??"
    if is_whitelisted(ip):
        return "PIRATE"
    return get_country_code(ip)


logger = logging.getLogger("api")

router = APIRouter(tags=["Attack Classifier"])

# 1.0: the attack_types column and the attack_patterns table come from migrations 0001/0002,
# which honeylens-migrate runs before the API — no probing of the database at module import.
_HAS_ATTACK_COL = True
_HAS_ATTACK_TBL = True


def _classifier_html_page(title, content):
    from honeylens.webui.dashboard_classifier import _classifier_html_page

    return _classifier_html_page(title, content)


def _attack_kb_list_html(data):
    from honeylens.webui.dashboard_attack_kb import attack_kb_list_html

    return attack_kb_list_html(data)


def _attack_kb_detail_html(*args, **kwargs):
    from honeylens.webui.dashboard_attack_kb import attack_kb_detail_html

    return attack_kb_detail_html(*args, **kwargs)


# Routes — Attack Classifier Stats & Management (Idea 12)
# ---------------------------------------------------------------------------


@router.get("/classifier/stats")
def classifier_stats(request: Request):
    """
    Get statistics about the attack classifier.

    Returns rule counts by type and severity, version info.
    """
    try:
        from honeylens.classification.attack_classifier import get_classifier_stats

        stats = get_classifier_stats()

        if wants_html(request):
            try:
                from honeylens.webui.dashboard_classifier import classifier_dashboard_html

                # Fetch threats and rules data
                _fake_scope = {
                    "type": "http",
                    "method": "GET",
                    "path": "/",
                    "query_string": b"",
                    "headers": [],
                }
                _fake_req = Request(_fake_scope)
                threats_data = classifier_top_threats(request=_fake_req)
                rules_data = classifier_rules(request=_fake_req)
                threats_list = (
                    threats_data.get("threats", []) if isinstance(threats_data, dict) else []
                )
                rules_by_type = (
                    rules_data.get("rules_by_type", {}) if isinstance(rules_data, dict) else {}
                )

                # Rule performance metrics from rule_statistics + attack_patterns
                rule_perf = []
                rule_trend = []
                try:
                    with db_cursor() as cur:
                        # Performance: top rules by hits with TP/FP rates
                        cur.execute("""
                            SELECT rs.rule_name, rs.attack_type, rs.severity,
                                   rs.total_hits, rs.confirmed_true, rs.confirmed_false,
                                   rs.last_hit, rs.enabled, rs.avg_score
                            FROM rule_statistics rs
                            ORDER BY rs.total_hits DESC
                            LIMIT 50
                        """)
                        for r in cur.fetchall():
                            total = r[3] or 0
                            tp = r[4] or 0
                            fp = r[5] or 0
                            reviewed = tp + fp
                            rule_perf.append(
                                {
                                    "rule_name": r[0],
                                    "attack_type": r[1],
                                    "severity": r[2],
                                    "total_hits": total,
                                    "confirmed_true": tp,
                                    "confirmed_false": fp,
                                    "fp_rate": round(fp / reviewed * 100, 1) if reviewed else None,
                                    "tp_rate": round(tp / reviewed * 100, 1) if reviewed else None,
                                    "last_hit": r[6].isoformat() if r[6] else None,
                                    "enabled": r[7],
                                    "avg_score": r[8],
                                }
                            )

                        # Trend: attack patterns per day (last 30 days)
                        cur.execute("""
                            SELECT created_at::date AS day,
                                   COUNT(*) AS total_detections,
                                   COUNT(DISTINCT rule_name) AS unique_rules,
                                   COUNT(DISTINCT attack_type) AS unique_types,
                                   COUNT(DISTINCT event_id) AS unique_events
                            FROM attack_patterns
                            WHERE created_at >= NOW() - INTERVAL '30 days'
                            GROUP BY day ORDER BY day DESC
                        """)
                        for r in cur.fetchall():
                            rule_trend.append(
                                {
                                    "day": str(r[0]),
                                    "total": r[1],
                                    "unique_rules": r[2],
                                    "unique_types": r[3],
                                    "unique_events": r[4],
                                }
                            )
                except Exception as e:
                    logger.debug("Rule perf query: %s", e)

                return HTMLResponse(
                    content=classifier_dashboard_html(
                        stats,
                        threats_list,
                        rules_by_type,
                        rule_perf=rule_perf,
                        rule_trend=rule_trend,
                    )
                )
            except Exception as exc:
                logger.warning("Classifier dashboard error: %s", exc)
                return HTMLResponse(
                    content=_classifier_html_page(
                        "Classifier Stats",
                        f"<p>Dashboard render error: {html.escape(str(exc))}</p>",
                    )
                )

        return stats

    except Exception as e:
        logger.error("classifier_stats error: %s", e)
        return {"error": "An internal error occurred"}


@router.get("/classifier/rules")
def classifier_rules(request: Request, attack_type: str | None = None, severity: str | None = None):
    """
    List all detection rules, grouped by attack type.
    Optional filters: attack_type, severity
    """
    try:
        from collections import defaultdict

        from honeylens.classification.attack_classifier import (
            _RULES,
            get_classifier_stats,
            get_severity,
        )

        # Group rules by attack type
        rules_by_type = defaultdict(list)
        total_rules = 0

        for atype, rname, regex in _RULES:
            if attack_type and atype != attack_type:
                continue
            rule_sev = get_severity(atype, rname)
            if severity and rule_sev != severity:
                continue

            rules_by_type[atype].append(
                {
                    "rule_name": rname,
                    "severity": rule_sev,
                    "pattern": regex.pattern[:120] + "..."
                    if len(regex.pattern) > 120
                    else regex.pattern,
                }
            )
            total_rules += 1

        if wants_html(request):
            stats = get_classifier_stats()

            # Filters bar
            filter_html = '<div style="display:flex;gap:15px;margin-bottom:16px;padding:12px;background:var(--bg2);border-radius:8px;border:1px solid var(--border);flex-wrap:wrap;align-items:center">'
            filter_html += (
                '<label style="font-size:12px;color:var(--text2)">Filter by Type:</label>'
            )
            filter_html += '<select style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px" '
            filter_html += "onchange=\"if(this.value) window.location='/classifier/rules?attack_type='+this.value; else window.location='/classifier/rules';\">"
            filter_html += '<option value="">All Types</option>'
            for atype in sorted(rules_by_type.keys()):
                selected = "selected" if atype == attack_type else ""
                filter_html += f'<option value="{atype}" {selected}>{atype} ({len(rules_by_type[atype])})</option>'
            filter_html += "</select>"
            filter_html += (
                '<label style="font-size:12px;color:var(--text2)">Filter by Severity:</label>'
            )
            filter_html += '<select style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px" '
            filter_html += "onchange=\"if(this.value) window.location='/classifier/rules?severity='+this.value; else window.location='/classifier/rules';\">"
            filter_html += '<option value="">All Severities</option>'
            for sev in ["critical", "high", "medium", "low", "info"]:
                selected = "selected" if sev == severity else ""
                sev_count = sum(
                    1 for rules in rules_by_type.values() for r in rules if r["severity"] == sev
                )
                filter_html += f'<option value="{sev}" {selected}>{sev} ({sev_count})</option>'
            filter_html += f'</select><div style="margin-left:auto;color:var(--text2);font-size:12px">Showing <span style="color:var(--accent)">{total_rules}</span> rules</div></div>'

            # Rules table
            content = f'<p style="margin-bottom:12px"><b>Total Rules:</b> {stats["total_rules"]} | <b>Types:</b> {stats["attack_types"]}</p>'
            content += filter_html
            for atype in sorted(rules_by_type.keys()):
                type_rules = rules_by_type[atype]
                content += f'<details style="margin-bottom:8px"><summary style="cursor:pointer;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;font-size:13px;font-weight:600;color:var(--accent)">{html.escape(atype)} <span style="color:var(--text2);font-weight:400">({len(type_rules)} rules)</span></summary>'
                content += '<table class="events-table" style="margin:8px 0"><thead><tr><th>Rule Name</th><th>Severity</th><th>Pattern</th></tr></thead><tbody>'
                for rule in type_rules:
                    sev = rule["severity"]
                    sev_color = {
                        "critical": "var(--red)",
                        "high": "var(--orange)",
                        "medium": "var(--yellow)",
                        "low": "var(--green)",
                        "info": "var(--accent)",
                    }.get(sev, "var(--text2)")
                    pattern_escaped = html.escape(rule["pattern"])
                    content += f'<tr><td style="font-family:var(--mono);font-size:12px">{html.escape(rule["rule_name"])}</td>'
                    content += f'<td><span style="color:{sev_color};font-weight:600;font-size:11px">{sev}</span></td>'
                    content += f'<td style="font-family:var(--mono);font-size:10px;color:var(--text2);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{pattern_escaped}">{pattern_escaped}</td></tr>'
                content += "</tbody></table></details>"

            content += """
<script>
// Collapse all if more than 10 types
document.addEventListener('DOMContentLoaded', function() {
  var details = document.querySelectorAll('details');
  if (details.length <= 10) { details.forEach(function(d) { d.open = true; }); }
});
</script>"""

            return HTMLResponse(content=_classifier_html_page("Detection Rules", content))

        # JSON response
        return {
            "rules_by_type": {k: v for k, v in sorted(rules_by_type.items())},
            "total_rules": total_rules,
            "types_count": len(rules_by_type),
        }

    except Exception as e:
        logger.error("classifier_rules error: %s", e)
        return {"error": "An internal error occurred"}


@router.get("/classifier/analyze")
def classifier_analyze(request: Request, payload: str):
    """
    Analyze a payload and return detections with severity scoring.

    Query param: payload (URL-encoded)
    """
    try:
        import urllib.parse

        # 0.9 imported this from attack_classifier, where the function does not exist —
        # /classifier/analyze ended with ImportError on every call.
        from honeylens.classification.scoring import classify_with_severity

        decoded = urllib.parse.unquote(payload)
        result = classify_with_severity(decoded)

        if wants_html(request):
            rows = ["<h3>Payload Analysis</h3>"]
            rows.append(f"<p><b>Input:</b> <code>{html.escape(decoded[:200])}</code></p>")
            rows.append(f"<p><b>Threat Score:</b> {result['score']}/100</p>")

            sev_color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#28a745",
                "info": "#17a2b8",
                "none": "#6c757d",
            }.get(result["severity"], "#6c757d")
            rows.append(
                f"<p><b>Severity:</b> <span style='color:{sev_color};font-weight:bold'>{result['severity'].upper()}</span></p>"
            )

            if result["attack_types"]:
                rows.append(f"<p><b>Attack Types:</b> {', '.join(result['attack_types'])}</p>")

            if result["chains"]:
                rows.append("<h4>Attack Chains Detected</h4>")
                for chain in result["chains"]:
                    rows.append(
                        f"<p>⚠️ <b>{html.escape(chain['chain'])}</b>: {html.escape(chain['description'])}</p>"
                    )

            if result["hits"]:
                rows.append("<h4>Detections</h4>")
                rows.append(
                    '<table class="events-table"><thead><tr><th>Type</th><th>Rule</th><th>Severity</th><th>Match</th></tr></thead><tbody>'
                )
                for hit in result["hits_with_severity"]:
                    color = {
                        "critical": "var(--red)",
                        "high": "var(--orange)",
                        "medium": "var(--yellow)",
                        "low": "var(--green)",
                        "info": "var(--accent)",
                    }.get(hit[3], "var(--text2)")
                    rows.append(
                        f"<tr><td style='color:var(--accent)'>{html.escape(str(hit[0]))}</td>"
                        f"<td style='font-family:var(--mono);font-size:12px'>{html.escape(str(hit[1]))}</td>"
                        f"<td><span style='color:{color};font-weight:600'>{hit[3]}</span></td>"
                        f"<td><code>{html.escape(str(hit[2])[:60])}</code></td></tr>"
                    )
                rows.append("</tbody></table>")
            else:
                rows.append("<p>No attacks detected.</p>")

            content = "\n".join(rows)
            return HTMLResponse(content=_classifier_html_page("Payload Analysis", content))

        return result

    except Exception as e:
        logger.error("classifier_analyze error: %s", e)
        return {"error": "An internal error occurred"}


@router.get("/classifier/severity/{severity}")
def classifier_by_severity(request: Request, severity: str, hours: int = 24):
    """
    Get events filtered by severity level.
    """
    valid_severities = ["critical", "high", "medium", "low", "info"]
    if severity not in valid_severities:
        return {"error": f"Invalid severity. Use: {', '.join(valid_severities)}"}

    try:
        from honeylens.classification.attack_classifier import ATTACK_TYPE_SEVERITY

        # Get attack types that match this severity
        matching_types = [atype for atype, sev in ATTACK_TYPE_SEVERITY.items() if sev == severity]

        conn = db()
        cur = conn.cursor()

        # Build query for matching attack types
        if matching_types:
            type_conditions = " OR ".join(["attack_types LIKE %s" for _ in matching_types])
            type_params = [f"%{t}%" for t in matching_types]
            query = (
                """
                SELECT event_id, timestamp, src_ip, dst_port, protocol, attack_types, payload_sample
                FROM sensor_events
                WHERE ("""  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
                + type_conditions
                + """)
                  AND timestamp >= NOW() - INTERVAL '%s hours'
                ORDER BY timestamp DESC
                LIMIT 200
            """
            )
            cur.execute(query, [*type_params, hours])
        else:
            return {"events": [], "severity": severity, "count": 0}

        events = []
        for row in cur.fetchall():
            events.append(
                {
                    "event_id": row[0],
                    "timestamp": row[1].isoformat() if row[1] else None,
                    "src_ip": row[2],
                    "dst_port": row[3],
                    "protocol": row[4],
                    "attack_types": row[5],
                    "payload_sample": row[6][:100] if row[6] else None,
                }
            )

        if wants_html(request):
            color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#28a745",
                "info": "#17a2b8",
            }.get(severity, "#6c757d")
            rows = [
                f"<h3>Events with <span style='color:{color}'>{html.escape(severity).upper()}</span> Severity</h3>"
            ]
            rows.append(f"<p>Last {hours} hours | {len(events)} events</p>")
            rows.append(
                '<table class="events-table"><thead><tr><th>Time</th><th>Source</th><th>Port</th><th>Attack Types</th></tr></thead><tbody>'
            )
            for e in events[:100]:
                rows.append(
                    f"<tr><td style='font-size:11px'>{e['timestamp'][:19] if e['timestamp'] else '-'}</td>"
                    f"<td style='font-family:var(--mono);color:var(--accent)'>{e['src_ip']}</td><td>{e['dst_port']}</td>"
                    f"<td style='font-size:11px'>{html.escape(str(e['attack_types'] or ''))}</td></tr>"
                )
            rows.append("</tbody></table>")
            content = "\n".join(rows)
            return HTMLResponse(content=_classifier_html_page(f"Severity: {severity}", content))

        return {"events": events, "severity": severity, "count": len(events)}

    except Exception as e:
        logger.error("classifier_by_severity error: %s", e)
        return {"error": "An internal error occurred"}


@router.post("/classifier/test")
async def classifier_test(request: Request):
    """Test the attack classifier against a sample payload.
    Body: {"payload": "...", "protocol": "HTTP", "dst_port": 80}
    Returns: {"hits": [[attack_type, rule_name, matched_text], ...]}
    """
    try:
        from honeylens.classification.attack_classifier import classify_event_row

        body = await request.json()
        payload = body.get("payload", "")
        protocol = body.get("protocol", "TCP")
        dst_port = body.get("dst_port", 0)
        if not payload:
            return {"hits": [], "error": "Empty payload"}
        metadata = {"dst_port": dst_port} if dst_port else {}
        hits = classify_event_row(payload=payload, protocol=protocol, metadata=metadata)
        return {"hits": hits, "protocol": protocol, "rules_matched": len(hits)}
    except Exception as e:
        return {"error": str(e), "hits": []}


@router.get("/classifier/top-threats")
def classifier_top_threats(request: Request, hours: int = 24, limit: int = 20):
    """
    Get top threats by severity and frequency.
    """
    try:
        from honeylens.classification.attack_classifier import (
            ATTACK_TYPE_SEVERITY,
            SEVERITY_WEIGHTS,
        )

        conn = db()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT UPPER(attack_types) AS attack_types, COUNT(*) as count
            FROM sensor_events
            WHERE attack_types IS NOT NULL
              AND attack_types != ''
              AND timestamp >= NOW() - INTERVAL '%s hours'
            GROUP BY UPPER(attack_types)
            ORDER BY count DESC
        """,
            (hours,),
        )

        # Aggregate and score
        type_counts: dict[str, Any] = {}
        for row in cur.fetchall():
            if row[0]:
                for attack_type in row[0].split(","):
                    attack_type = _normalize_attack_type(attack_type)
                    if attack_type:
                        type_counts[attack_type] = type_counts.get(attack_type, 0) + row[1]

        # Add severity scores
        threats = []
        for atype, count in type_counts.items():
            severity = ATTACK_TYPE_SEVERITY.get(atype, "medium")
            weight = SEVERITY_WEIGHTS.get(severity, 50)
            threats.append(
                {
                    "attack_type": atype,
                    "count": count,
                    "severity": severity,
                    "threat_score": count * weight // 10,  # Weighted score
                }
            )

        # Sort by threat score
        threats.sort(key=lambda x: x["threat_score"], reverse=True)
        threats = threats[:limit]

        if wants_html(request):
            from honeylens.webui.dashboard_classifier import threats_dashboard_html

            return HTMLResponse(content=threats_dashboard_html(threats, hours))

        return {"threats": threats, "hours": hours}

    except Exception as e:
        logger.error("classifier_top_threats error: %s", e)
        return {"error": "An internal error occurred"}


# ---------------------------------------------------------------------------

# --- Attack routes (extracted from api.py) ---
# ---------------------------------------------------------------------------


@router.get("/attack/rules_grouped")
def attack_rules_grouped(request: Request):
    """Get all attack rules grouped by attack type for dropdown menus."""
    from honeylens.classification.attack_classifier import get_all_rules

    rules = get_all_rules()

    # Sort attack types and rules within each type
    result = {}
    for attack_type in sorted(rules.keys()):
        result[attack_type] = sorted(rules[attack_type], key=lambda x: x["rule_name"])

    if wants_html(request):
        return html_response("Attack Rules by Type", result, request, "record")
    return result


@router.get("/attack/rule/{rule_name}")
def events_by_rule(rule_name: str, request: Request, limit: int = 100):
    """Get events matching a specific rule name via attack_patterns table."""
    # SECURITY: Validate and sanitize rule_name
    # Allow alphanumeric, underscore, hyphen, dot only (max 100 chars)
    if not rule_name or len(rule_name) > 100:
        raise HTTPException(status_code=400, detail="Invalid rule name length")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", rule_name):
        raise HTTPException(status_code=400, detail="Invalid rule name format")

    limit = min(max(limit, 1), 1000)  # Clamp limit

    conn = db()
    cur = conn.cursor()

    # Search in attack_patterns table which stores actual rule names
    cur.execute(
        """
        SELECT DISTINCT se.event_id, se.timestamp, se.src_ip::text, se.dst_port,
               se.protocol, se.attack_types, ap.rule_name, ap.matched_text
        FROM sensor_events se
        JOIN attack_patterns ap ON ap.event_id = se.event_id
        WHERE ap.rule_name ILIKE %s
        ORDER BY se.timestamp DESC
        LIMIT %s
    """,
        (f"%{rule_name}%", limit),
    )

    rows = cur.fetchall()
    conn.close()

    result = [
        {
            "event_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "src_ip": r[2],
            "dst_port": r[3],
            "protocol": r[4],
            "attack_types": r[5],
            "rule_name": r[6],
            "matched_text": r[7],
        }
        for r in rows
    ]

    if wants_html(request):
        return html_response(f"Events with rule: {rule_name}", result, request, "events")
    return result


# Classifier categories and vendor slugs both occur in stored attack patterns.
_ATTACK_TYPE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{1,63}")


def _valid_attack_type(name: str) -> bool:
    return bool(_ATTACK_TYPE_RE.fullmatch(name))


def _normalize_attack_type(name: str) -> str:
    """Fold a label to one spelling for *grouping and severity lookup* (see the threat
    summary). Do NOT use this to build a database lookup — use ``_attack_type_candidates``.
    """
    name = name.strip()
    # Some summary views uppercase labels; NetScaler stores lowercase slugs.
    if name.lower().startswith("ns-"):
        return name.lower()
    return name if "-" in name else name.upper()


def _attack_type_candidates(name: str) -> list[str]:
    """Every spelling a stored ``attack_type`` might have, for an exact-match lookup.

    ``attack_type`` is not stored in one consistent case. The classifier writes uppercase
    categories (``CREDENTIAL``, ``ICS_RECON``), lowercase underscore slugs
    (``info_disclosure``, ``wordpress_scan``, ``ics_recon_function_code``) and hyphenated
    lowercase ones (``ns-path-traversal``) side by side.

    The case used to be *guessed*: anything without a hyphen was upper-cased. That made every
    lowercase underscore tag unreachable from the UI — ``/attack/types`` lists the stored
    spelling verbatim, so the dropdown offered ``ics_recon_function_code``, the drill-down
    upper-cased it to ``ICS_RECON_FUNCTION_CODE``, and the exact match returned nothing. On
    a live sensor that silently hid seven types, ``info_disclosure`` among them with 2,284 events.

    Matching a candidate set rather than ``LOWER(attack_type) = LOWER(%s)`` keeps the
    comparison an equality, so ``idx_ap_type_created`` is still usable on a table that runs
    to tens of millions of rows.
    """
    name = name.strip()
    out: list[str] = []
    for candidate in (name, name.upper(), name.lower()):
        if candidate and candidate not in out:
            out.append(candidate)
    return out


@router.get("/attack/types")
def list_attack_types(request: Request):
    """
    List all distinct attack types with event counts.
    Returns attack types sorted by event count descending.
    """
    if not _HAS_ATTACK_TBL:
        return html_response("Attack Types", [], request, "stats")
    conn = db()
    cur = conn.cursor()

    # Two-stage query — the original 14-day GROUP BY + COUNT DISTINCT +
    # MODE() WITHIN GROUP timed out under load on a 30M-row / 17 GB
    # attack_patterns on DEV (2026-05-08). The expensive aggregates are
    # MODE() and COUNT(DISTINCT rule_name) — both force a sort over every
    # matched row per group. We split into:
    #   stage 1 (cheap, runs in <100ms with idx_ap_created_at): event_count,
    #           first_seen, last_seen for the last 14 days. UPPER() dropped
    #           because attack_type is already stored uppercase by the
    #           classifier's normalisation step.
    #   stage 2 (only run on top-N from stage 1): MODE() and COUNT DISTINCT
    #           for the top 30 attack_types. With the long tail filtered
    #           out, the per-group sort is bounded.
    cur.execute("""
        SELECT
            attack_type,
            COUNT(*) AS event_count,
            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen
        FROM attack_patterns
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY attack_type
        ORDER BY event_count DESC
        LIMIT 30
    """)
    summary = cur.fetchall()

    # Stage 2: enrich top-N with rule_count + top_rule (best-effort; if
    # this query times out we still return summary with placeholders).
    enrichment = {}
    if summary:
        try:
            top_types = [r[0] for r in summary]
            cur.execute(
                """
                SELECT attack_type,
                       COUNT(DISTINCT rule_name) AS rule_count,
                       MODE() WITHIN GROUP (ORDER BY rule_name) AS top_rule
                FROM attack_patterns
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                  AND attack_type = ANY(%s)
                GROUP BY attack_type
            """,
                (top_types,),
            )
            enrichment = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        except Exception as exc:
            logger.debug("attack-types stage-2 enrichment failed: %s", exc)

    conn.close()
    result = [
        {
            "attack_type": r[0],
            "event_count": r[1],
            "hit_count": r[1],  # alias kept for backward-compat with the
            # dashboard JS that reads both names
            "first_seen": r[2].isoformat() if r[2] else None,
            "last_seen": r[3].isoformat() if r[3] else None,
            "rule_count": enrichment.get(r[0], (0, "—"))[0],
            "top_rule": enrichment.get(r[0], (0, "—"))[1] or "—",
        }
        for r in summary
    ]
    return html_response("Attack Types", result, request, "attacks")


# ---------------------------------------------------------------------------
# Attack Knowledge Base (Idea 27)
# ---------------------------------------------------------------------------


def _has_attack_kb():
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'attack_definitions')"
        )
        result = cur.fetchone()[0]
        conn.close()
        return result
    except Exception as e:
        logger.debug("attack_definitions table check failed: %s", e)
        return False


_HAS_ATTACK_KB = _has_attack_kb()


@router.get("/attack/kb")
def attack_kb_list(request: Request):
    """List all attack types in the Knowledge Base."""
    if not _HAS_ATTACK_KB:
        if wants_html(request):
            return HTMLResponse(content=_attack_kb_list_html([]))
        return []
    with db_cursor(dict_cursor=True) as cur:
        cur.execute("""
            SELECT attack_type, display_name, short_description, category,
                   default_severity, observed_count, observed_unique_ips,
                   first_observed, last_observed, trend_7d, trend_30d,
                   analyst_reviewed, updated_at
            FROM attack_definitions
            ORDER BY observed_count DESC NULLS LAST
        """)
        rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        for k in ("first_observed", "last_observed", "updated_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    if wants_html(request):
        return HTMLResponse(content=_attack_kb_list_html(rows))
    return rows


@router.get("/attack/info/{attack_type}")
def attack_kb_detail(attack_type: str, request: Request):
    """Full knowledge base entry for an attack type."""
    if not _HAS_ATTACK_KB:
        raise HTTPException(
            status_code=404,
            detail="Knowledge Base not populated. Run: python -m tools.attack_kb_builder",
        )
    attack_type = attack_type.strip()
    if not _valid_attack_type(attack_type):
        raise HTTPException(status_code=400, detail="Invalid attack type")

    with db_cursor(dict_cursor=True) as cur:
        # Main definition. Matched against the candidate spellings, then `attack_type` is
        # replaced by whatever the row actually stores — every lookup and comparison below
        # keeps using a single exact value, as before.
        cur.execute(
            "SELECT * FROM attack_definitions WHERE attack_type = ANY(%s)",
            (_attack_type_candidates(attack_type),),
        )
        defn = cur.fetchone()
        if defn and defn.get("attack_type"):
            attack_type = defn["attack_type"]
        if not defn:
            raise HTTPException(
                status_code=404,
                detail=f"No KB entry for {attack_type}. Run: python -m tools.attack_kb_builder --type {attack_type}",
            )

        defn = dict(defn)

        # Rule definitions (if populated)
        rules = []
        try:
            cur.execute(
                """
                SELECT rule_name, severity, hit_count, last_hit, description
                FROM attack_rule_definitions
                WHERE attack_type = %s
                ORDER BY hit_count DESC NULLS LAST
            """,
                (attack_type,),
            )
            rules = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.debug("attack_rule_definitions query failed: %s", e)

        # If no rule_definitions yet, get rule names from classifier
        if not rules:
            try:
                from honeylens.classification.attack_classifier import _RULES, get_severity

                for at, rname, _ in _RULES:
                    if at == attack_type:
                        rules.append(
                            {
                                "rule_name": rname,
                                "severity": get_severity(at, rname),
                                "hit_count": 0,
                                "last_hit": None,
                                "description": None,
                            }
                        )
            except Exception as e:
                logger.debug("Classifier rule fallback failed: %s", e)

        # CVE links
        cves = []
        try:
            cur.execute(
                """
                SELECT cve_id, cve_name, product, cvss_score, description, in_cisa_kev, ms_bulletin_id
                FROM attack_cve_links
                WHERE attack_type = %s
                ORDER BY cvss_score DESC NULLS LAST
            """,
                (attack_type,),
            )
            cves = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.debug("attack_cve_links query failed: %s", e)

    # Serialize timestamps
    for k in ("first_observed", "last_observed", "created_at", "updated_at"):
        if defn.get(k):
            defn[k] = defn[k].isoformat()

    if wants_html(request):
        return HTMLResponse(content=_attack_kb_detail_html(defn, rules, cves))
    return {"definition": defn, "rules": rules, "cves": cves}


@router.get("/attack/type/{attack_type}")
def events_by_attack_type_v2(
    attack_type: str, request: Request, limit: int = 500, protocol: str | None = None
):
    """
    Events matching a specific attack type.
    Optional protocol filter (e.g. ?protocol=HTTP to filter HTTP events only).
    """
    if not _HAS_ATTACK_TBL:
        return html_response(f"Attack Type: {attack_type}", [], request, "events")
    attack_type = attack_type.strip()
    if not _valid_attack_type(attack_type):
        raise HTTPException(
            status_code=400,
            detail="Invalid attack type format (letters, digits, underscores and hyphens only)",
        )
    candidates = _attack_type_candidates(attack_type)
    limit = min(max(limit, 1), 2000)

    conn = db()
    cur = conn.cursor()

    # Build column list
    base_cols = """
        se.event_id, se.source, se.src_ip::text, se.src_port,
        se.protocol, se.dst_port,
        EXTRACT(EPOCH FROM se.timestamp)::double precision,
        se.scan_score, se.port_entropy,
        se.payload
    """
    if _HAS_ATTACK_COL:
        base_cols += ", se.attack_types"

    # Build query with optional protocol filter
    query = f"""
        SELECT DISTINCT {base_cols}
        FROM sensor_events se
        JOIN attack_patterns ap ON ap.event_id = se.event_id
        WHERE ap.attack_type = ANY(%s)
          AND NOT (se.src_ip <<= ANY(%s::inet[]))
          AND ap.created_at >= NOW() - INTERVAL '90 days'
    """  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters

    params: list[Any] = [candidates, EXCLUDED_SUBNETS]

    if protocol:
        if not valid_protocol(protocol):
            raise HTTPException(status_code=400, detail="Invalid protocol name")
        query += " AND LOWER(se.protocol) LIKE LOWER(%s)"
        params.append(f"%{protocol}%")

    query += " ORDER BY 7 DESC LIMIT %s"
    params.append(limit)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        src_ip = strip_cidr(r[2])
        result.append(
            {
                "event_id": r[0],
                "source": r[1],
                "src_ip": src_ip,
                "src_port": r[3],
                "protocol": r[4],
                "dst_port": r[5],
                "timestamp": r[6],
                "scan_score": r[7],
                "port_entropy": r[8],
                "payload_preview": (r[9][:200] + "...") if r[9] and len(r[9]) > 200 else r[9],
                "attack_types": r[10] if _HAS_ATTACK_COL else None,
                "country_code": _get_country(src_ip),
            }
        )

    title = f"Attack Type: {attack_type}"
    if protocol:
        title += f" (Protocol: {protocol})"
    return html_response(title, result, request, "events")


@router.get("/attack/type/{attack_type}/http")
def http_events_by_attack_type(attack_type: str, limit: int = 500):
    """
    HTTP-related events matching a specific attack type.
    Filters to events where protocol is HTTP or dst_port is 80/443/8080/8443.
    """
    if not _HAS_ATTACK_TBL:
        return []
    attack_type = attack_type.strip()
    if not _valid_attack_type(attack_type):
        raise HTTPException(status_code=400, detail="Invalid attack type format")
    candidates = _attack_type_candidates(attack_type)
    limit = min(max(limit, 1), 2000)

    conn = db()
    cur = conn.cursor()

    # Build query - use explicit column list to avoid %% escaping issues
    base_cols = """
        se.event_id, se.source, se.src_ip::text, se.src_port,
        se.protocol, se.dst_port,
        EXTRACT(EPOCH FROM se.timestamp)::double precision,
        se.scan_score, se.port_entropy,
        se.payload
    """
    if _HAS_ATTACK_COL:
        base_cols += ", se.attack_types"

    query = f"""
        SELECT DISTINCT {base_cols}
        FROM sensor_events se
        JOIN attack_patterns ap ON ap.event_id = se.event_id
        WHERE ap.attack_type = ANY(%s)
          AND NOT (se.src_ip <<= ANY(%s::inet[]))
          AND ap.created_at >= NOW() - INTERVAL '90 days'
          AND (
            LOWER(se.protocol) LIKE %s
            OR se.dst_port IN (80, 443, 8080, 8443, 8000, 3000, 10443, 20443)
            OR se.source IN ('honeypotng', 'k8s-honeypot', 'fortigate-honeypot')
          )
        ORDER BY 7 DESC
        LIMIT %s
    """  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters

    cur.execute(query, (candidates, EXCLUDED_SUBNETS, "%http%", limit))
    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        src_ip = strip_cidr(r[2])
        result.append(
            {
                "event_id": r[0],
                "source": r[1],
                "src_ip": src_ip,
                "src_port": r[3],
                "protocol": r[4],
                "dst_port": r[5],
                "timestamp": r[6],
                "scan_score": r[7],
                "port_entropy": r[8],
                "payload_preview": (r[9][:200] + "...") if r[9] and len(r[9]) > 200 else r[9],
                "attack_types": r[10] if _HAS_ATTACK_COL else None,
                "country_code": _get_country(src_ip),
            }
        )
    return result


@router.get("/attack_rules")
def attack_rules(request: Request):
    """Per-rule breakdown: how many times each rule fired."""
    if not _HAS_ATTACK_TBL:
        return html_response("Attack Rules", [], request, "stats")
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            UPPER(attack_type) AS attack_type,
            rule_name,
            COUNT(*) AS hit_count,
            COUNT(*) AS event_count
        FROM attack_patterns
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY UPPER(attack_type), rule_name
        ORDER BY hit_count DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    conn.close()
    result = [
        {
            "attack_type": r[0],
            "rule_name": r[1],
            "hit_count": r[2],
            "event_count": r[3],
        }
        for r in rows
    ]
    return html_response("Attack Rules Breakdown", result, request, "stats")


@router.get("/attack_event/{event_id}")
def attack_event_detail(event_id: str, request: Request):
    """All attack pattern hits for a specific event."""
    if not _HAS_ATTACK_TBL:
        return html_response(f"Attack Details: {event_id}", [], request)
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT attack_type, rule_name, matched_text, created_at::text
        FROM attack_patterns
        WHERE event_id = %s
        ORDER BY created_at
    """,
        (event_id,),
    )
    rows = cur.fetchall()
    conn.close()
    result = [
        {
            "attack_type": r[0],
            "rule_name": r[1],
            "matched_text": r[2],
            "created_at": r[3],
        }
        for r in rows
    ]
    return html_response(
        f"Attack Patterns for Event: {event_id[:12]}...", result, request, "attacks"
    )
