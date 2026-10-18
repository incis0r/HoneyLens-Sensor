#!/usr/bin/env python3
"""classification_tunning.py — surface wrong attack classifications for review.

Reviews recent events and their assigned ``attack_types`` and raises the ones that look
mis-classified, so the central rule can be fixed (after which
:mod:`honeylens.tools.auto_backfill` re-tags the stored events). It does NOT modify data.

Heuristic (cheap, rule-independent): a binary/ICS wire-protocol tag (SMB, RDP, MODBUS,
S7, …) on an HTTP/HTTPS event is almost always a false positive — you will not find the
SMB protocol inside an HTTP body. Each suspect carries the rule_name that produced it, so
the report points straight at the rule to fix.

LLM sieve (optional): suspects are then confirmed by an LLM — the **deep** model when one
is available, otherwise the **triage** model. If no LLM backend is reachable the script
still runs and reports every heuristic suspect, flagged as NOT LLM-vetted.

    honeylens-classification-tunning                 # last 7 days, LLM-vet if available
    honeylens-classification-tunning --days 30 --limit 100
    honeylens-classification-tunning --no-llm        # heuristic only
    honeylens-classification-tunning --json out.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("classification-tunning")

# Attack-type labels that denote a binary/ICS wire protocol — they cannot legitimately
# appear inside an HTTP(S) text request, so seeing them on HTTP traffic is a misfire.
BINARY_PROTOCOL_ATTACKS = {
    "SMB",
    "SMB2",
    "RDP",
    "VNC",
    "MODBUS",
    "S7",
    "S7COMM",
    "DNP3",
    "ENIP",
    "BACNET",
    "OPCUA",
    "IEC104",
    "FINS",
    "ORACLE_TNS",
    "MSSQL",
    "MYSQL",
    "CASSANDRA",
    "MEMCACHED",
}


# --------------------------------------------------------------------------- LLM judge


def _build_judge():
    """Return (judge, label) where judge(system, prompt) -> str, or (None, reason).

    Prefers the deep model; falls back to the triage model; returns None if no LLM
    backend is reachable (the caller then reports suspects unsieved).
    """
    try:
        from honeylens.analysis.ai_analyzer import AnalysisEngine, OllamaClient, _build_engine
        from honeylens.config import OLLAMA_DEEP_MODEL, OLLAMA_TRIAGE_MODEL
    except Exception as exc:  # import/path problems must not break the script
        return None, f"analyzer import failed: {exc}"

    try:
        engine, _tag = _build_engine()
    except Exception as exc:
        return None, f"no backend: {exc}"
    if engine is None:
        return None, "no LLM backend configured/reachable"

    def _call(target, model, system, prompt) -> str:
        if isinstance(target, OllamaClient):
            return target.generate(model, system, prompt)[0]
        # OpenAI / Nous backend engine
        if hasattr(target, "triage_model") and target.__class__.__name__ == "OpenAIBackendEngine":
            from honeylens.analysis import openai_analyzer

            return openai_analyzer._call_openai(model, system, prompt, 512, stage="deep")[0]
        # Claude backend engine
        import honeylens.analysis.claude_analyzer as ca

        client = ca._get_client()
        msg = client.messages.create(
            model=model,
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(getattr(b, "text", "") for b in msg.content)

    # Pick target + model: deep if available, else triage.
    if isinstance(engine, AnalysisEngine):
        if engine.deep_backend is not None:
            target, model, which = engine.deep_backend, engine.deep_model, "deep"
        elif engine.ollama.has_model(OLLAMA_DEEP_MODEL):
            target, model, which = engine.ollama, OLLAMA_DEEP_MODEL, "deep"
        else:
            target, model, which = engine.ollama, OLLAMA_TRIAGE_MODEL, "triage"
    else:  # cloud primary (OpenAI/Nous/Claude) runs both stages on the cloud
        target, model, which = engine, engine.deep_model or engine.triage_model, "deep"

    def judge(system: str, prompt: str) -> str:
        return _call(target, model, system, prompt)

    return judge, f"{which}:{model}"


_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_verdict(text: str) -> dict:
    m = _JSON_RE.search(text or "")
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:
        return {}


# --------------------------------------------------------------------------- DB scan


def _find_suspects(days: int, scan_limit: int) -> list[dict]:
    """Events whose binary/ICS tag sits on HTTP(S) traffic (the misfire class)."""
    from honeylens.classification.text_rules import _HTTP_PORTS
    from honeylens.database import legacy_get_db

    conn = legacy_get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT e.event_id, e.protocol, e.dst_port, e.attack_types,
                   p.attack_type, p.rule_name, left(e.payload, 1000)
            FROM sensor_events e
            JOIN attack_patterns p ON p.event_id = e.event_id
            WHERE e.timestamp > now() - (%s || ' days')::interval
              AND p.attack_type = ANY(%s)
              AND ( e.protocol ILIKE 'http%%' OR e.dst_port = ANY(%s) )
            ORDER BY e.timestamp DESC
            LIMIT %s
            """,
            (days, sorted(BINARY_PROTOCOL_ATTACKS), sorted(_HTTP_PORTS), scan_limit),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "event_id": r[0],
            "protocol": r[1],
            "dst_port": r[2],
            "attack_types": r[3],
            "suspect_tag": r[4],
            "rule_name": r[5],
            "payload": r[6] or "",
        }
        for r in rows
    ]


_SYSTEM = (
    "You are a network-security analyst auditing honeypot event classifications. A "
    "protocol-specific tag (SMB, RDP, MODBUS, S7, …) on an HTTP/HTTPS request is almost "
    "always a false positive — that binary protocol cannot appear inside an HTTP body. "
    "Respond in JSON only."
)


def _judge_prompt(s: dict) -> str:
    return (
        f"Protocol: {s['protocol']}\nPort: {s['dst_port']}\n"
        f"All tags: {s['attack_types']}\nSuspect tag: {s['suspect_tag']} "
        f"(from rule {s['rule_name']})\nPayload (truncated):\n{s['payload'][:800]}\n\n"
        "Is the suspect tag a correct classification for this traffic? "
        'Respond JSON: {"wrong": true|false, "reason": "short", "suggested": "tag or NONE"}'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--days", type=int, default=7, help="look back this many days")
    parser.add_argument("--scan-limit", type=int, default=5000, help="max suspect rows to scan")
    parser.add_argument("--limit", type=int, default=40, help="max events to LLM-vet")
    parser.add_argument("--no-llm", action="store_true", help="skip the LLM sieve")
    parser.add_argument("--json", metavar="PATH", help="write findings as JSON")
    args = parser.parse_args()

    suspects = _find_suspects(args.days, args.scan_limit)
    if not suspects:
        logger.info("no binary/ICS tags on HTTP traffic in the last %s days — clean", args.days)
        return 0
    logger.info("found %s suspect tags (binary/ICS attack on HTTP traffic)", len(suspects))

    judge, label = (None, "disabled") if args.no_llm else _build_judge()
    if judge:
        logger.info("LLM sieve: %s", label)
    else:
        logger.warning("no LLM sieve (%s) — reporting heuristic suspects unvetted", label)

    # LLM-vet distinct events up to --limit; rule-level counts cover everything scanned.
    vetted = 0
    for s in suspects:
        if judge and vetted < args.limit:
            try:
                v = _parse_verdict(judge(_SYSTEM, _judge_prompt(s)))
                s["llm_wrong"] = v.get("wrong")
                s["llm_reason"] = v.get("reason")
                s["llm_suggested"] = v.get("suggested")
            except Exception as exc:
                s["llm_wrong"] = None
                s["llm_reason"] = f"llm error: {exc}"
            vetted += 1
        else:
            s["llm_wrong"] = None

    # Roll up by the rule that produced the tag — this is what you fix centrally.
    by_rule: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"count": 0, "llm_wrong": 0, "examples": []}
    )
    for s in suspects:
        g = by_rule[(s["suspect_tag"], s["rule_name"])]
        g["count"] += 1
        if s.get("llm_wrong") is True:
            g["llm_wrong"] += 1
        if len(g["examples"]) < 3:
            g["examples"].append(
                {"event_id": s["event_id"], "protocol": s["protocol"], "port": s["dst_port"]}
            )

    print("\n=== classification_tunning: suspected mis-classifications ===")
    print(f"window={args.days}d  suspects={len(suspects)}  llm={label}\n")
    print(f"{'ATTACK':12} {'RULE':34} {'COUNT':>6} {'LLM-WRONG':>9}")
    for (tag, rule), g in sorted(by_rule.items(), key=lambda kv: -kv[1]["count"]):
        wrong = "-" if not judge else str(g["llm_wrong"])
        print(f"{tag:12} {rule:34} {g['count']:>6} {wrong:>9}")
    print(
        "\nFix: tighten/exclude the offending rule in classification/rules/, then "
        "`honeylens-auto-backfill --force` re-tags stored events.\n"
        "LLM-WRONG is '-' when not vetted (no LLM / --no-llm); treat every row as a candidate then."
    )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "window_days": args.days,
                    "llm": label,
                    "by_rule": {f"{t}/{r}": g for (t, r), g in by_rule.items()},
                    "suspects": suspects,
                },
                f,
                indent=2,
                default=str,
            )
        logger.info("wrote %s", args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
