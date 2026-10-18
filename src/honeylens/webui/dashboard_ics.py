"""
webui/dashboard_ics.py — ICS/OT Operator Console
================================================
A triage console built around three operator questions:

    1. "Am I under attack?"          -> the status verdict + live event stream
    2. "Who was it?"                 -> active-attackers panel + IP focus
    3. "Related events for this IP?" -> IP focus drawer (/ics/ip/<ip>)

Split view: LEFT = last events (live, filterable), RIGHT = last attacks
(write/command attempts) + active attackers. Click any IP for the full actor
profile; click any event for detail. Inline Ack / False-positive / Trust.

Robustness (this file has burned us before):
  * All interactivity is wired with ONE delegated addEventListener reading
    data-act attributes — no inline onclick that a sanitizer/CSP can strip.
  * window.onerror paints a visible banner, so a runtime fault is never silent.
  * The data payload is injected as JSON with <, U+2028, U+2029 escaped so an
    attack string in the data can never break the inline <script>.
Requires Python 3.11+ (datetime.UTC).
"""

from __future__ import annotations

import html as _html
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

# Rows written before this instant carry fewer facts: no stored frame bytes, no semantics,
# no technique. Any figure computed across it has to say so.
_CUTOVER = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
_CUTOVER_LABEL = "25 Oct 2026 12:00 UTC"

# Compared in UTC, in SQL. `timestamp` is timestamptz, so the comparison itself is
# instant-safe, but one sensor's database runs Etc/UTC and every other Europe/Warsaw, and the
# offset changed on 25 October itself: converting both sides to a naive UTC timestamp makes
# the answer independent of the session's TimeZone. Counted over the whole table, the same
# scope as the summary and the funnel the banner sits above. {fp_and} is the false-positive gate.
_CUTOVER_SQL = """
    SELECT COUNT(*) FILTER (
               WHERE timestamp AT TIME ZONE 'UTC' < %(cut)s::timestamptz AT TIME ZONE 'UTC'),
           COUNT(*) FILTER (
               WHERE timestamp AT TIME ZONE 'UTC' >= %(cut)s::timestamptz AT TIME ZONE 'UTC')
    FROM ics_events
    WHERE TRUE{fp_and}
"""


def _esc(v: Any) -> str:
    return _html.escape("" if v is None else str(v), quote=True)


def _render_cutover_marker(cutover: dict | None) -> str:
    """The banner that qualifies every figure on a page whose window reaches back past the
    cutover. Empty when no row in the window predates it, so a window that does not cross
    carries no qualifier it does not need."""
    if not cutover:
        return ""
    before = int(cutover.get("before") or 0)
    if before <= 0:
        return ""
    after = int(cutover.get("after") or 0)
    return (
        '<div class="cutover-marker" data-cut="1" role="note">'
        f"<b>These figures cross {_CUTOVER_LABEL}.</b> "
        f"{before:,} of the {before + after:,} events counted here were recorded "
        "before that moment, when the decoys kept fewer facts: no stored bytes, no meaning, "
        "no technique. An empty or &ldquo;unknown&rdquo; field on those rows is not evidence "
        "that nothing happened."
        "</div>"
    )


_PK_PALETTE = 8


def _byte_range(f: dict) -> tuple[int, int]:
    try:
        o, n = int(f.get("offset") or 0), int(f.get("length") or 0)
    except (TypeError, ValueError):
        return 0, 0
    return o, max(n, 0)


def _tail_from(tail: dict) -> int:
    try:
        return int(tail.get("offset") or 0)
    except (TypeError, ValueError):
        return 0


def _fmt_value(v: Any) -> str:
    if v is None:
        return "&mdash;"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return _esc(", ".join(str(x) for x in v))
    return _esc(v)


def _pk_state(d: dict, hex_s: str, fields: list, tail: dict | None) -> tuple[str, str]:
    """(state, sentence): which of the honesty states this block is in, said in words.

    Three different sentences, because three different things went wrong, and one empty pane
    for all of them hides which: nothing was stored; something was stored and could not be
    read; or it was read and part of it has no field."""
    reason = (tail or {}).get("reason") or ""
    if not d.get("hex_key") and not hex_s:
        why = f" ({_esc(reason)})" if reason else ""
        return (
            "nobytes",
            "<b>No bytes were stored for this event.</b> Nothing was decoded, and nothing is "
            f"implied about what was sent{why}.",
        )
    if not fields:
        why = _esc(reason) if reason else "the decoder gave no reason"
        return (
            "undecodable",
            f"<b>Bytes were stored but could not be decoded:</b> {why}.",
        )
    if tail is not None:
        try:
            off = int(tail.get("offset") or 0)
        except (TypeError, ValueError):
            off = 0
        raw_len = d.get("raw_len")
        why = _esc(reason) or "no reason given"
        if isinstance(raw_len, int) and raw_len <= off:
            # nothing exists at or after the offset: the frame simply ended
            return (
                "tail",
                f"<b>Decoded as far as the frame goes; it ended before the next field "
                f"could be read (offset {off}):</b> {why}.",
            )
        left = f"{raw_len - off} byte(s) from " if isinstance(raw_len, int) else "the bytes from "
        return (
            "tail",
            f"<b>Decoded, but {left}offset {off} are not placed in any field:</b> {why}.",
        )
    return "clean", "<b>Decoded to the last byte.</b> Every stored byte belongs to a field."


def _render_hex(hex_s: str, fields: list, tail_from: int | None) -> str:
    n = len(hex_s) // 2
    spans = [_byte_range(f) for f in fields]
    out = []
    for row in range(0, n, 16):
        cells = []
        for i in range(row, min(row + 16, n)):
            cls = "by"
            for k, (o, ln) in enumerate(spans):
                if o <= i < o + ln:
                    cls += f" fc{k % _PK_PALETTE}"
                    break
            else:
                if tail_from is not None and i >= tail_from:
                    cls += " tl"
            cells.append(
                f'<span class="{cls}" data-i="{i}">{_esc(hex_s[2 * i : 2 * i + 2])}</span>'
            )
        out.append(f'<div class="hr"><span class="of">{row:04x}</span> {" ".join(cells)}</div>')
    if len(hex_s) % 2:  # an odd trailing nibble is shown, not dropped
        out.append(f'<div class="hr"><span class="by tl">{_esc(hex_s[-1])}</span></div>')
    return "".join(out)


def _render_readings(d: dict, recorded: Any) -> str:
    """The two function codes: one the decoy wrote, one the decoder read from the bytes.

    They are independent and can legitimately differ; neither is preferred. s7comm stores no
    function code on purpose (its meaning is a job/function pair), which is not a gap."""
    proto = str(d.get("protocol") or "").lower()
    code = d.get("code")
    shown_dec = "&mdash;" if code is None else _esc(code)
    if recorded is None:
        note = (
            "not recorded (by design for s7comm)"
            if proto == "s7comm"
            else "not recorded for this row"
        )
        shown_rec = f'<span class="muted">{note}</span>'
        differ = False
    else:
        shown_rec = _esc(recorded)
        differ = code is not None and str(code) != str(recorded)
    flag = (
        ' <span class="pk-differ">The two readings differ; both are shown, neither is '
        "preferred.</span>"
        if differ
        else ""
    )
    return (
        '<div class="pk-readings">Function code '
        f'<span class="rd">recorded by the decoy: <b>{shown_rec}</b></span> '
        f'<span class="rd">read by the decoder from these bytes: <b>{shown_dec}</b></span>'
        f"{flag}</div>"
    )


_UNSET: Any = object()


def _render_packet_view(decoded: dict, recorded_code: Any = _UNSET) -> str:
    """Hex on the left, the field breakdown on the right, the plain sentence under them.

    Everything shown comes from the block the API sent, which has already masked credentials
    from the hex and the field values. Nothing is rebuilt from another source and every value
    is escaped: this function must not be a path around that masking."""
    from honeylens.ingest.ics_helpers import semantics_to_mitre

    d = decoded or {}
    hex_s = str(d.get("hex") or "")
    fields = [f for f in (d.get("fields") or []) if isinstance(f, dict)]
    tail = d.get("tail") if isinstance(d.get("tail"), dict) else None
    state, state_html = _pk_state(d, hex_s, fields, tail)

    notes = []
    if d.get("hex_truncated"):
        notes.append(
            f"Showing the first {len(hex_s) // 2} bytes of {_esc(d.get('raw_len'))}; "
            "the rest is not sent to the page."
        )
    if d.get("capture_truncated"):
        notes.append("The decoy captured only part of this frame.")

    head = [f'<div class="pk-state st-{state}" data-state="{state}">{state_html}</div>']
    if notes:
        head.append(f'<div class="pk-note">{" ".join(notes)}</div>')
    if recorded_code is not _UNSET:
        head.append(_render_readings(d, recorded_code))

    if hex_s:
        hex_html = _render_hex(hex_s, fields, _tail_from(tail) if (tail and fields) else None)
    elif state == "nobytes":
        hex_html = '<div class="pk-empty">No bytes to show: none were stored.</div>'
    else:
        hex_html = (
            '<div class="pk-empty">No printable bytes were kept; the reason is stated above.</div>'
        )

    if fields:
        rows = []
        for k, f in enumerate(fields):
            o, ln = _byte_range(f)
            rng = f"{o}" if ln <= 1 else f"{o}&ndash;{o + ln - 1}"
            meaning = (
                f' <span class="muted">{_esc(f.get("meaning"))}</span>' if f.get("meaning") else ""
            )
            rows.append(
                f'<tr class="fld fc{k % _PK_PALETTE}" data-offset="{o}" data-length="{ln}">'
                f"<td>{_esc(f.get('label') or f.get('name'))}</td>"
                f"<td>{_fmt_value(f.get('value'))}{meaning}</td>"
                f'<td class="muted">byte {rng}</td></tr>'
            )
        fields_html = (
            '<table class="t pk-t"><thead><tr><th>Field</th><th>Value</th><th>Where</th></tr>'
            f"</thead><tbody>{''.join(rows)}</tbody></table>"
        )
    else:
        fields_html = '<div class="pk-empty">No fields: the bytes were not decoded.</div>'

    sentence = d.get("sentence")
    sent_html = (
        f'<p class="pk-sentence">{_esc(sentence)}</p>'
        if sentence
        else '<p class="pk-sentence muted">No plain-language reading: the frame was not decoded.</p>'
    )

    sem = d.get("semantics")
    tech, tactic = semantics_to_mitre(sem)
    if tech:
        link = (
            f'<a class="tl-link" target="_blank" rel="noopener" '
            f'href="https://attack.mitre.org/techniques/{_esc(tech)}/">{_esc(tech)}</a>'
        )
        mitre_html = (
            f'<div class="pk-mitre">MITRE ATT&amp;CK for ICS, from what the frame means ({_esc(sem)}): '
            f'{link} <span class="muted">{_esc(tactic)}</span></div>'
        )
    elif sem == "anomaly":
        mitre_html = (
            '<div class="pk-mitre">No technique is asserted: a function code outside the '
            "specification is a finding in itself, not a technique.</div>"
        )
    else:
        mitre_html = '<div class="pk-mitre">No technique is asserted: what these bytes mean is not known.</div>'

    return (
        '<div class="pk">'
        + "".join(head)
        + f'<div class="pk-cols"><div class="pk-hex">{hex_html}</div>'
        + f'<div class="pk-fields">{fields_html}</div></div>'
        + sent_html
        + mitre_html
        + "</div>"
    )


def register_routes(app: FastAPI) -> None:
    """HTML routes are served by routes/ics.py; this module renders only."""
    pass


def _ics_not_configured_html() -> str:
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>ICS/OT</title>'
        "<style>body{background:#0f172a;color:#e2e8f0;font-family:monospace;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh}</style>"
        '</head><body><div style="text-align:center">'
        '<div style="font-size:3rem">&#x1F3ED;</div>'
        '<h2 style="color:#f87171;margin:16px 0">ICS/OT Detection Not Configured</h2>'
        '<p style="color:#94a3b8">Run <code>python setup_db.py</code> to create ICS tables.</p>'
        '<a href="/" style="color:#38bdf8">&#8592; Back to Dashboard</a>'
        "</div></body></html>"
    )


def _ics_dashboard_html(data: dict) -> str:
    import json as _json

    from honeylens.classification.mitre_mapping import TACTICS_ICS
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html

    tactic_map = {
        slug: f"{info.get('name', slug)} ({info.get('id', '')})"
        for slug, info in (TACTICS_ICS or {}).items()
    }

    def _safe(obj):
        s = _json.dumps(obj, default=str)
        return s.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    doc = _TEMPLATE
    doc = doc.replace("/*__SHARED_CSS__*/", SHARED_CSS)
    doc = doc.replace("<!--__NAV__-->", nav_bar_html("ics"))
    doc = doc.replace("/*__PAGE_DATA__*/", _safe(data))
    doc = doc.replace("/*__TACTIC_MAP__*/", _safe(tactic_map))
    doc = doc.replace("/*__CUT_MS__*/0", str(int(_CUTOVER.timestamp() * 1000)))
    doc = doc.replace("/*__CUT_LABEL__*/", _CUTOVER_LABEL)
    doc = doc.replace("<!--__CUTOVER__-->", _render_cutover_marker(data.get("cutover")))
    return doc


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ICS/OT Console — HoneyLens</title>
<style>
/*__SHARED_CSS__*/
:root{--ic:#22d3ee}
*{box-sizing:border-box}
.jserr{display:none;position:fixed;top:0;left:0;right:0;z-index:9999;background:#ef4444;color:#fff;
  padding:8px 16px;font:12px/1.4 monospace}
.bar{display:flex;gap:10px;align-items:center;padding:8px 20px;background:var(--bg2);border-bottom:1px solid var(--border);flex-wrap:wrap}
.bar .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.verdict{margin:14px 20px;border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:18px;border:1px solid}
.verdict .big{font-size:22px;font-weight:800;letter-spacing:.5px}
.verdict .sub{font-size:13px;opacity:.9}
.verdict .vk{margin-left:auto;display:flex;gap:22px;text-align:center}
.verdict .vk div .n{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums}
.verdict .vk div .l{font-size:9px;text-transform:uppercase;letter-spacing:.5px;opacity:.75}
.grid{display:grid;grid-template-columns:1.4fr 1fr;gap:14px;padding:0 20px 24px;align-items:start}
@media(max-width:1100px){.grid{grid-template-columns:1fr}}
.card{background:var(--bg1);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.card+.card{margin-top:14px}
.ch{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:700}
.ch .c{font-size:10px;color:var(--text3);font-weight:500}
.ch .right{margin-left:auto;display:flex;gap:6px;align-items:center}
.flt{display:flex;gap:7px;flex-wrap:wrap;align-items:center;padding:9px 12px;border-bottom:1px solid var(--border)}
.flt input,.flt select{background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:5px 8px;font:11px monospace}
.flt input{flex:1;min-width:130px}
.scroll{max-height:64vh;overflow:auto}
.scroll.sm{max-height:40vh}
.ev{display:grid;grid-template-columns:auto auto 1fr auto;gap:9px;align-items:center;padding:8px 13px;border-bottom:1px solid var(--border);cursor:pointer}
.ev:hover{background:var(--bg2)}
.ev .m{min-width:0}
.ev .ln{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev .sb{font-size:10px;color:var(--text3)}
.ev .rt{display:flex;gap:5px;align-items:center;opacity:0;transition:opacity .1s}
.ev:hover .rt{opacity:1}
.atk{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;padding:8px 13px;border-bottom:1px solid var(--border);cursor:pointer}
.atk:hover{background:var(--bg2)}
.empty{padding:24px;text-align:center;color:var(--text3);font-size:12px}
.pill{display:inline-block;padding:2px 7px;border-radius:10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle}
.chip{display:inline-block;padding:1px 7px;border-radius:5px;font-size:10px;font-weight:700;border:1px solid transparent;cursor:pointer}
.chip:hover{border-color:currentColor}
.ipl{color:var(--ic);text-decoration:none;cursor:pointer}
.ipl:hover{text-decoration:underline}
.b{padding:3px 8px;font:700 10px monospace;border-radius:5px;border:1px solid var(--border);background:var(--bg2);color:var(--text2);cursor:pointer}
.b:hover{border-color:var(--ic);color:var(--text)}
.b.ack:hover{border-color:#22c55e;color:#22c55e}.b.fp:hover{border-color:#ef4444;color:#ef4444}
.b.trust:hover{border-color:#a855f7;color:#a855f7}
.tabs{display:flex;gap:0;flex-wrap:wrap;padding:0 20px;border-bottom:2px solid var(--border)}
.tb{padding:8px 14px;background:none;border:none;color:var(--text3);font:600 12px monospace;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px}
.tb:hover{color:var(--text)}.tb.on{color:var(--ic);border-bottom-color:var(--ic)}
.pane{display:none;padding:14px 20px}.pane.on{display:block}
table.t{width:100%;border-collapse:collapse;font-size:11px}
table.t th{text-align:left;padding:6px 9px;color:var(--text3);font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap}
table.t td{padding:5px 9px;border-bottom:1px solid var(--border);white-space:nowrap}
table.t tbody tr:hover{background:var(--bg2)}
.dw{position:fixed;top:0;right:-760px;width:720px;max-width:96vw;height:100vh;background:var(--bg1);border-left:1px solid var(--border);z-index:91;transition:right .2s;overflow:auto;box-shadow:-8px 0 24px #0006}
.dw.open{right:0}
.dw .h{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border)}
.dw .bd{padding:14px 16px}
.dtabs{display:flex;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg1);z-index:2}
.dtb{flex:1;padding:9px 8px;background:none;border:none;border-bottom:2px solid transparent;color:var(--text3);font:600 12px monospace;cursor:pointer;text-align:center}
.dtb small{display:block;font-weight:400;font-size:9px;opacity:.8}
.dtb:hover{color:var(--text)}.dtb.on{color:var(--ic);border-bottom-color:var(--ic)}
@media(min-width:1250px){body.dwopen main{padding-right:720px}}
.ev.sel,.atk.sel{background:var(--bg2);box-shadow:inset 3px 0 0 var(--ic)}
.funnel{display:flex;gap:8px;flex-wrap:wrap;align-items:stretch;margin:0 20px 14px}
.funnel .ft{flex:1 0 100%;font-size:12px;color:var(--text2)}
.funnel .ft b{font-size:16px;color:var(--text)}
.fb{flex:1 1 120px;border-radius:8px;padding:8px 10px;cursor:pointer;border:1px solid var(--fc);background:color-mix(in srgb,var(--fc) 10%,transparent)}
.fb:hover{background:color-mix(in srgb,var(--fc) 20%,transparent)}
.fb .n{font-size:20px;font-weight:800;color:var(--fc);font-variant-numeric:tabular-nums}
.fb .pl{font-size:11px;color:var(--text)}.fb .id{font-size:9px;text-transform:uppercase;letter-spacing:.5px;color:var(--fc)}
.fb[data-b=anomaly]{border-width:2px;background:color-mix(in srgb,var(--fc) 22%,transparent)}
.fb[data-b=anomaly]:hover{background:color-mix(in srgb,var(--fc) 34%,transparent)}
.fb[data-b=unknown]{border-style:dashed;background:transparent}
.fb[data-b=unknown]:hover{background:color-mix(in srgb,var(--fc) 14%,transparent)}
.fb[data-b=unknown] .n{color:var(--text3)}
[data-cut]{margin:0 20px 14px;padding:9px 13px;border:1px solid #eab30899;border-left:4px solid #eab308;border-radius:7px;background:#eab30814;font-size:12px;line-height:1.5}
.pill.pu{background:transparent;border:1px dashed #94a3b8;color:#94a3b8}
.pill.pa{background:#d946ef;color:#fff}
.pk{font-size:12px}
.pk-state{padding:8px 11px;border-radius:7px;border:1px solid var(--border);margin-bottom:8px;line-height:1.5}
.pk-state.st-nobytes{border-style:dashed;color:var(--text2)}
.pk-state.st-undecodable{border-color:#f97316;background:#f9731614}
.pk-state.st-tail{border-color:#eab308;background:#eab30814}
.pk-state.st-clean{border-color:#22c55e55;background:#22c55e10}
.pk-note,.pk-readings{font-size:11px;color:var(--text2);margin-bottom:8px;line-height:1.6}
.pk-readings .rd{display:inline-block;margin-right:12px}
.pk-differ{color:#f97316;font-weight:700}
.pk-cols{display:grid;grid-template-columns:minmax(200px,1fr) 1.3fr;gap:12px;align-items:start}
@media(max-width:700px){.pk-cols{grid-template-columns:1fr}}
.pk-hex{font:11px/1.9 monospace;background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:8px;overflow-x:auto}
.pk-hex .of{color:var(--text3);margin-right:6px}
.pk-hex .by{display:inline-block;padding:0 2px;border-radius:3px;cursor:default}
.pk-hex .by.tl{background:repeating-linear-gradient(45deg,#eab30833 0 3px,transparent 3px 6px);color:#eab308}
.pk-empty{color:var(--text3);padding:6px;line-height:1.5}
.pk-t td{white-space:normal;word-break:break-word}
.pk-sentence{margin:12px 0 4px;font-size:14px;font-weight:600;line-height:1.5}
.pk-mitre{font-size:11px;color:var(--text2)}
.pk .tl-link{color:#f87171}
.fc0{--pc:#38bdf8}.fc1{--pc:#f472b6}.fc2{--pc:#a3e635}.fc3{--pc:#fbbf24}
.fc4{--pc:#c084fc}.fc5{--pc:#2dd4bf}.fc6{--pc:#fb923c}.fc7{--pc:#94a3b8}
.pk .by[class*=fc]{background:color-mix(in srgb,var(--pc) 28%,transparent);color:var(--text)}
.pk tr.fld td:first-child{box-shadow:inset 3px 0 0 var(--pc)}
.pk .by.hl{background:var(--pc);color:#0f172a;font-weight:700}
.pk tr.fld.hl td{background:color-mix(in srgb,var(--pc) 22%,transparent)}
.kv{display:flex;gap:10px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}
.kv .k{width:130px;color:var(--text3)}.kv .v{flex:1;word-break:break-all}
.mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin:6px 0 12px}
.mini .x{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:8px}
.mini .x .n{font-size:17px;font-weight:800}.mini .x .l{font-size:9px;color:var(--text3);text-transform:uppercase}
.toast{position:fixed;bottom:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast .t{background:var(--bg1);border:1px solid var(--border);border-left:3px solid #22c55e;border-radius:7px;padding:9px 13px;font:12px monospace;box-shadow:0 6px 20px #0008}
.toast .t.e{border-left-color:#ef4444}
.muted{color:var(--text3)}
a.tl{color:#f87171;text-decoration:none}a.tl:hover{text-decoration:underline}
</style>
</head><body>
<a class="skip-link" href="#main-content">Skip to content</a>
<div class="jserr" id="jserr"></div>
<!--__NAV__-->
<main id="main-content">

<div class="bar">
  <strong>&#x1F3ED; ICS / OT Threat Console</strong>
  <span id="modeBadge" class="muted" style="font-size:11px"></span>
  <div class="right">
    <label class="muted" style="font-size:11px;display:flex;gap:5px;align-items:center;cursor:pointer">
      <input type="checkbox" id="showFp" data-act="showfp"> show false-positives</label>
    <button class="btn" data-act="refresh">&#x27F3; Refresh</button>
  </div>
</div>

<div class="verdict" id="verdict"></div>

<!--__CUTOVER__-->

<!-- What the events ARE, six buckets that are never summed into each other. -->
<div class="funnel" id="funnel">
  <div class="ft"><b id="kpi-total">0</b> ICS events, split by what they are &mdash; a command is never counted as a read, and &ldquo;not known&rdquo; is not &ldquo;quiet&rdquo;</div>
  <div class="fb" style="--fc:#ef4444" data-b="command" data-act="filter" data-intent="command" title="An attempt to order a device (command or control)"><div class="n" id="kpi-command">0</div><div class="pl">Orders to a device attempted</div><div class="id">command</div></div>
  <div class="fb" style="--fc:#f97316" data-b="write" data-act="filter" data-intent="write" title="An attempt to change a value or setting"><div class="n" id="kpi-write">0</div><div class="pl">Changes to values or settings attempted</div><div class="id">write</div></div>
  <div class="fb" style="--fc:#eab308" data-b="recon" data-act="filter" data-intent="recon" title="Values were read, or hosts and ports were scanned"><div class="n" id="kpi-recon">0</div><div class="pl">Values read, and host/port scans</div><div class="id">recon</div></div>
  <div class="fb" style="--fc:#22c55e" data-b="enumeration" data-act="filter" data-intent="enumeration" title="Asked what the device is or what it has"><div class="n" id="kpi-enumeration">0</div><div class="pl">Asked what is there</div><div class="id">enumeration</div></div>
  <div class="fb" style="--fc:#d946ef" data-b="anomaly" data-act="filter" data-intent="anomaly" title="A code or frame the protocol specification does not define or does not allow here: a finding"><div class="n" id="kpi-anomaly">0</div><div class="pl">&#9888; Does not fit the specification</div><div class="id">anomaly</div></div>
  <div class="fb" style="--fc:#94a3b8" data-b="unknown" data-act="filter" data-intent="unknown" title="What this was is not known: the bytes were not kept, or could not be understood"><div class="n" id="kpi-unknown">0</div><div class="pl">Not known (not recorded or not understood)</div><div class="id">unknown</div></div>
</div>

<div class="grid">
  <!-- LEFT: last events (live, filterable) -->
  <div class="card">
    <div class="ch">&#x1F4E1; Last events <span class="c" id="evCount"></span>
      <div class="right"><span class="c" id="evNote"></span></div></div>
    <div class="flt">
      <input id="q" placeholder="search ip / rule / function / protocol…">
      <select id="fIntent"><option value="">intent</option><option value="command">command</option><option value="write">write</option><option value="recon">recon</option><option value="enumeration">enumeration</option><option value="anomaly">anomaly (outside spec)</option><option value="unknown">unknown (not known)</option></select>
      <select id="fSev"><option value="">severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
      <select id="fProto"><option value="">protocol</option></select>
      <button class="b" data-act="clearf">reset</button>
    </div>
    <div class="scroll" id="evList"></div>
  </div>

  <!-- RIGHT: attacks + who -->
  <div>
    <div class="card">
      <div class="ch" style="color:#f97316">&#x26A1; Write / command attempts
        <span class="c">— safety-critical</span></div>
      <div class="scroll sm" id="atkList"></div>
    </div>
    <div class="card">
      <div class="ch" style="color:#f472b6">&#x1F575; Active attackers <span class="c">click an IP for the full profile</span></div>
      <div class="scroll sm" id="whoList"></div>
    </div>
  </div>
</div>

<!-- secondary analytics -->
<div class="tabs" id="tabs">
  <button class="tb on" data-act="tab" data-v="protocols">&#x1F310; Protocols</button>
  <button class="tb" data-act="tab" data-v="targets">&#x1F3AF; Targets</button>
  <button class="tb" data-act="tab" data-v="mitre">&#x1F6E1; MITRE ICS</button>
  <button class="tb" data-act="tab" data-v="funccodes">&#x2699; Function codes</button>
  <button class="tb" data-act="tab" data-v="advisories">&#x26A0; Advisories</button>
</div>
<div class="pane on" id="pane-protocols"><table class="t"><thead><tr><th>Protocol</th><th>Total</th><th>Writes</th><th>Controls</th><th>Discovery</th><th>High+</th><th>Last seen</th></tr></thead><tbody id="tb-proto"></tbody></table></div>
<div class="pane" id="pane-targets"><table class="t"><thead><tr><th>Target IP</th><th>Port</th><th>Events</th><th>Writes</th><th>Protocols</th></tr></thead><tbody id="tb-dst"></tbody></table></div>
<div class="pane" id="pane-mitre"><table class="t"><thead><tr><th>Technique</th><th>Tactic</th><th>Count</th><th>High+</th><th>Last seen</th></tr></thead><tbody id="tb-mitre"></tbody></table></div>
<div class="pane" id="pane-funccodes"><table class="t"><thead><tr><th>Protocol</th><th>FC</th><th>Function</th><th>Total</th><th>Write/Ctrl</th><th>Sources</th><th>Max sev</th></tr></thead><tbody id="tb-fc"></tbody></table></div>
<div class="pane" id="pane-advisories"><table class="t"><thead><tr><th>CVE</th><th>CVSS</th><th>Vendor</th><th>Product</th><th>Protocols</th><th>Title</th></tr></thead><tbody id="tb-adv"></tbody></table></div>

<aside class="dw" id="dw" role="dialog" aria-label="Incident detail" aria-hidden="true">
  <div class="h"><strong id="dwTitle">Incident</strong><span id="dwSev"></span><span class="muted" style="font-size:10px">Esc closes &middot; &#8593;&#8595; walks the list</span><button class="btn" style="margin-left:auto" data-act="closedrawer" aria-label="Close">&#x2715;</button></div>
  <div class="dtabs" role="tablist">
    <button class="dtb on" role="tab" data-act="dtab" data-v="event">Event<small>what was sent</small></button>
    <button class="dtb" role="tab" data-act="dtab" data-v="address">Address<small>who sent it</small></button>
    <button class="dtb" role="tab" data-act="dtab" data-v="honeypot">Honeypot<small>this decoy on this sensor</small></button>
  </div>
  <div class="bd" id="dwBody"></div>
</aside>

<div class="toast" id="toast"></div>

<script>
window.onerror=function(m,s,l){var b=document.getElementById('jserr');if(b){b.style.display='block';b.textContent='⚠ ICS console JS error: '+m+'  (line '+l+') — please send this text';}return false;};

var DATA=/*__PAGE_DATA__*/;
var TMAP=/*__TACTIC_MAP__*/;
DATA.events=DATA.events||[];DATA.needs_attention=DATA.needs_attention||[];DATA.write_ops=DATA.write_ops||[];DATA.top_src=DATA.top_src||[];

var SEVC={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'};
var BUCKETS=['command','write','recon','enumeration','anomaly','unknown'];
// Six buckets. anomaly = a code or frame the specification does not define or allow here (a finding);
// unknown = semantics is NULL: bytes not kept (every row before the cutover) or not understood. They must not look alike.
var INTENT={command:{l:'COMMAND',c:'#ef4444',p:'an attempt to order a device (command or control)'},write:{l:'WRITE',c:'#f97316',p:'an attempt to change a value or setting'},recon:{l:'RECON',c:'#eab308',p:'values read, or hosts and ports scanned'},enumeration:{l:'ENUM',c:'#22c55e',p:'asked what the device is or what it has'},anomaly:{l:'\u26A0 OUT OF SPEC',c:'#d946ef',p:'a code or frame the protocol specification does not define or does not allow here',k:'pa'},unknown:{l:'NOT KNOWN',c:'#94a3b8',p:'what this was is not known: the bytes were not kept, or could not be understood',k:'pu'}};
var CUT_MS=/*__CUT_MS__*/0;var CUT_LABEL='/*__CUT_LABEL__*/';
var PROTOC={modbus:'#f97316',dnp3:'#8b5cf6',s7comm:'#3b82f6',enip:'#06b6d4',bacnet:'#84cc16',opcua:'#ec4899',iec104:'#f59e0b',mqtt:'#10b981',fox:'#14b8a6',profinet:'#a855f7',mms:'#fb7185',melsec:'#f43f5e',fins:'#0ea5e9'};
function esc(v){if(v==null)return '';return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function ipS(i){return i?String(i).split('/')[0]:'';}
function sevc(s){return SEVC[String(s||'').toUpperCase()]||'#94a3b8';}
function proc(p){return PROTOC[String(p||'').toLowerCase()]||'#94a3b8';}
function intm(i){return INTENT[i]||{l:String(i||'?').toUpperCase(),c:'#94a3b8'};}
function tname(s){if(!s)return '';return TMAP[s]||String(s).replace(/-ics$/,'').replace(/-/g,' ');}
function ago(iso){if(!iso)return '';var d=(Date.now()-new Date(iso).getTime())/1000;if(isNaN(d))return '';if(d<60)return Math.max(0,Math.floor(d))+'s';if(d<3600)return Math.floor(d/60)+'m';if(d<86400)return Math.floor(d/3600)+'h';return Math.floor(d/86400)+'d';}
function tshort(iso){if(!iso)return '';return String(iso).replace('T',' ').slice(5,19);}
function within(iso,sec){if(!iso)return false;var d=(Date.now()-new Date(iso).getTime())/1000;return !isNaN(d)&&d<sec;}
function ipill(i){var m=intm(i);if(m.k)return '<span class="pill '+m.k+'" title="'+esc(m.p)+'">'+m.l+'</span>';return '<span class="pill" title="'+esc(m.p||'')+'" style="background:'+m.c+'22;color:'+m.c+'">'+m.l+'</span>';}
function preCut(iso){var t=Date.parse(iso);return !isNaN(t)&&t<CUT_MS;}
function sdot(s){return '<span class="dot" title="'+esc(s)+'" style="background:'+sevc(s)+'"></span>';}
function pchip(p){if(!p)return '';return '<span class="chip" style="color:'+proc(p)+'" data-act="filter" data-proto="'+esc(p)+'">'+esc(p)+'</span>';}
function iplink(ip){var i=ipS(ip);if(!i)return '<span class="muted">—</span>';return '<a class="ipl" data-act="ipfocus" data-ip="'+esc(i)+'">'+esc(i)+'</a>';}
function mlink(t){if(!t)return '<span class="muted">—</span>';return '<a class="tl" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/'+esc(String(t).replace('.','/'))+'/">'+esc(t)+'</a>';}
function toast(m,e){var w=document.getElementById('toast');var d=document.createElement('div');d.className='t'+(e?' e':'');d.textContent=m;w.appendChild(d);setTimeout(function(){d.remove();},3400);}
function showErr(m){toast(m,true);}

// ── Verdict: am I under attack? ──────────────────────────────────────────────
function renderVerdict(){
  var ev1h=(DATA.events||[]).filter(function(e){return within(e.timestamp,3600);});
  var by=function(k){return ev1h.filter(function(e){return e.intent===k;}).length;};
  var cmd=by('command'),wr=by('write'),rec=by('recon')+by('enumeration'),an=by('anomaly'),unk=by('unknown');
  var src1h=new Set(ev1h.map(function(e){return ipS(e.src_ip);})).size;
  var st,col,sub;
  if(cmd||wr){st='UNDER ATTACK';col='#ef4444';sub=cmd+' command(s) and '+wr+' write(s) against ICS services in the last hour';}
  else if(rec||an){st='ACTIVE PROBING';col='#f59e0b';sub=rec+' recon (reads, scans) or enumeration event(s)'+(an?' and '+an+' that do not fit the specification':'')+' in the last hour — no control attempts yet';}
  else if(unk){st='UNCLASSIFIED';col='#94a3b8';sub=unk+' event(s) in the last hour whose meaning is not known (bytes not kept or not understood) — this is not the same as quiet';}
  else {st='QUIET';col='#22c55e';sub='No ICS events in the last hour';}
  var s=DATA.summary||{};
  var el=document.getElementById('verdict');
  el.style.background=col+'14';el.style.borderColor=col+'55';
  el.innerHTML='<div><div class="big" style="color:'+col+'">'+st+'</div><div class="sub muted">'+esc(sub)+'</div></div>'+
    '<div class="vk">'+
    kk(ev1h.length,'events 1h')+kk(cmd,'command 1h','#ef4444')+kk(wr,'write 1h','#f97316')+kk(src1h,'sources 1h','#f472b6')+
    kk((s.critical||0),'critical','#ef4444')+kk((s.new_src_24h||0),'new src 24h','#f472b6')+
    kk((s.false_positives||0),'false-pos','#64748b')+'</div>';
  var t=document.getElementById('kpi-total');if(t)t.textContent=Number(s.total||0).toLocaleString();
  BUCKETS.forEach(function(b){var c=document.getElementById('kpi-'+b);if(c)c.textContent=Number(s['intent_'+b]||0).toLocaleString();});
}
function kk(n,l,c){return '<div><div class="n" style="color:'+(c||'#e2e8f0')+'">'+Number(n).toLocaleString()+'</div><div class="l">'+l+'</div></div>';}

// ── Left: last events (server-backed when filtered) ─────────────────────────
var VIEW=[];var _seq=0;
function gv(id){return (document.getElementById(id).value||'').trim();}
function curF(){return {q:gv('q'),intent:gv('fIntent'),severity:gv('fSev'),protocol:gv('fProto')};}
function anyF(f){return !!(f.q||f.intent||f.severity||f.protocol);}
function loadEvents(){
  var f=curF();
  if(!anyF(f)){VIEW=DATA.events||[];paintEvents(VIEW,'showing '+VIEW.length+' most-recent — filter to search full history');return;}
  var p=new URLSearchParams();p.set('limit','500');
  if(document.getElementById('showFp').checked)p.set('include_fp','1');
  if(f.q)p.set('q',f.q);if(f.intent)p.set('intent',f.intent);if(f.severity)p.set('severity',f.severity);if(f.protocol)p.set('protocol',f.protocol);
  document.getElementById('evList').innerHTML='<div class="empty">searching full history…</div>';
  var seq=++_seq;
  fetch('/ics/events?'+p.toString(),{headers:{Accept:'application/json'}}).then(function(r){if(!r.ok)throw new Error('events HTTP '+r.status);return r.json();})
    .then(function(d){if(seq!==_seq)return;VIEW=d.events||[];paintEvents(VIEW,VIEW.length+' of '+(d.count!=null?d.count:VIEW.length)+' matched (full history)');})
    .catch(function(e){if(seq!==_seq)return;document.getElementById('evList').innerHTML='<div class="empty">Failed: '+esc(e.message)+'</div>';});
}
function paintEvents(rows,note){
  document.getElementById('evCount').textContent='· '+rows.length;
  document.getElementById('evNote').textContent=note||'';
  var b=document.getElementById('evList');
  if(!rows.length){b.innerHTML='<div class="empty">No matching events.</div>';return;}
  b.innerHTML=rows.slice(0,400).map(function(e){
    var tgt=ipS(e.dst_ip)+(e.dst_port?(':'+e.dst_port):'');
    return '<div class="ev" data-act="event" data-eid="'+esc(e.event_id)+'">'+
      '<div>'+ipill(e.intent)+'</div><div>'+sdot(e.severity)+'</div>'+
      '<div class="m"><div class="ln">'+pchip(e.protocol)+' '+iplink(e.src_ip)+' <span class="muted">&#8594; '+esc(tgt)+'</span> '+esc(e.function_name||e.attack_type||'')+'</div>'+
      '<div class="sb">'+esc(e.rule_name||'')+' · '+ago(e.timestamp)+' ago</div></div>'+
      '<div class="rt"><button class="b ack" data-act="ack" data-eid="'+esc(e.event_id)+'">Ack</button>'+
      '<button class="b fp" data-act="fp" data-eid="'+esc(e.event_id)+'">FP</button></div></div>';
  }).join('');
}

// ── Right: attacks + who ─────────────────────────────────────────────────────
function renderAttacks(){
  var w=(DATA.write_ops||[]);
  var b=document.getElementById('atkList');
  if(!w.length){b.innerHTML='<div class="empty">&#x2705; No write/command attempts recorded.</div>';return;}
  b.innerHTML=w.slice(0,40).map(function(e){
    var tgt=ipS(e.dst_ip)+(e.dst_port?(':'+e.dst_port):'');
    return '<div class="atk" data-act="event" data-eid="'+esc(e.event_id)+'">'+
      '<div><div class="ln" style="font-size:12px">'+sdot(e.severity)+' '+pchip(e.protocol)+' <b>'+esc(e.function_name||'')+'</b></div>'+
      '<div class="sb muted" style="font-size:10px">'+iplink(e.src_ip)+' &#8594; '+esc(tgt)+' · '+ago(e.timestamp)+' ago</div></div>'+
      '<div>'+mlink(e.mitre_technique)+'</div></div>';
  }).join('');
}
function renderWho(){
  var s=(DATA.top_src||[]);
  var b=document.getElementById('whoList');
  if(!s.length){b.innerHTML='<div class="empty">No sources.</div>';return;}
  b.innerHTML=s.map(function(a){
    var pr=(a.protocols||[]).map(pchip).join(' ');
    var wc=a.writes_controls||0;
    return '<div class="atk" data-act="ipfocus" data-ip="'+esc(ipS(a.ip))+'">'+
      '<div><div class="ln" style="font-size:12px">'+iplink(a.ip)+' <span class="muted">'+a.total+' events</span>'+
      (wc?' <span class="pill" style="background:#f9731622;color:#f97316">'+wc+' W/C</span>':'')+(a.critical?' <span class="pill" style="background:#ef444422;color:#ef4444">'+a.critical+' crit</span>':'')+'</div>'+
      '<div class="sb" style="font-size:10px">'+pr+'</div></div>'+
      '<div><button class="b trust" data-act="trust" data-ip="'+esc(ipS(a.ip))+'">Trust</button></div></div>';
  }).join('');
}

// ── Secondary tables ─────────────────────────────────────────────────────────
function fill(id,html){var el=document.getElementById(id);if(el)el.innerHTML=html;}
function renderTables(){
  fill('tb-proto',(DATA.by_protocol||[]).map(function(p){return '<tr><td><span class="chip" style="color:'+proc(p.protocol)+'" data-act="filter" data-proto="'+esc(p.protocol)+'">'+esc(p.protocol)+'</span></td><td>'+p.total+'</td><td style="color:#f97316">'+(p.writes||0)+'</td><td style="color:#ef4444">'+(p.controls||0)+'</td><td class="muted">'+(p.discovery||0)+'</td><td>'+(p.high_sev||0)+'</td><td class="muted">'+tshort(p.last_seen)+'</td></tr>';}).join('')||'<tr><td colspan=7 class="empty">none</td></tr>');
  fill('tb-dst',(DATA.top_dst||[]).map(function(d){return '<tr><td>'+iplink(d.ip)+'</td><td class="muted">'+esc(d.port)+'</td><td>'+d.total+'</td><td style="color:#f97316">'+(d.writes||0)+'</td><td>'+(d.protocols||[]).map(pchip).join(' ')+'</td></tr>';}).join('')||'<tr><td colspan=5 class="empty">none</td></tr>');
  fill('tb-mitre',(DATA.by_technique||[]).map(function(t){return '<tr><td>'+mlink(t.technique)+'</td><td class="muted">'+esc(tname(t.tactic))+'</td><td>'+t.count+'</td><td style="color:#f97316">'+(t.high_sev||0)+'</td><td class="muted">'+tshort(t.last_seen)+'</td></tr>';}).join('')||'<tr><td colspan=5 class="empty">none</td></tr>');
  fill('tb-fc',(DATA.by_function||[]).map(function(f){return '<tr><td>'+pchip(f.protocol)+'</td><td class="muted">'+esc(f.function_code)+'</td><td>'+esc(f.function_name||'')+'</td><td>'+f.total+'</td><td style="color:#f97316">'+((f.writes||0)+(f.controls||0))+'</td><td>'+(f.unique_src||0)+'</td><td>'+sdot(f.max_severity)+' '+esc(f.max_severity||'')+'</td></tr>';}).join('')||'<tr><td colspan=7 class="empty">none</td></tr>');
  fill('tb-adv',(DATA.advisories||[]).slice(0,40).map(function(a){var kev=a.is_kev?' <span class="pill" style="background:#ef4444;color:#fff">KEV</span>':'';return '<tr><td><a class="tl" target="_blank" rel="noopener" href="https://vulnerability.circl.lu/cve/'+esc(a.cve_id)+'">'+esc(a.cve_id)+'</a>'+kev+'</td><td style="color:'+sevc(a.cvss_severity)+';font-weight:700">'+esc(a.cvss_score||'')+'</td><td>'+esc(a.vendor||'')+'</td><td>'+esc(a.product||'')+'</td><td style="color:#22d3ee">'+esc((a.protocols||[]).join(', '))+'</td><td>'+esc((a.title||'').slice(0,60))+'</td></tr>';}).join('')||'<tr><td colspan=6 class="empty">no cached advisories</td></tr>');
  var sel=document.getElementById('fProto');var cur=sel.value;
  sel.innerHTML='<option value="">protocol</option>'+(DATA.by_protocol||[]).map(function(p){return '<option value="'+esc(p.protocol)+'">'+esc(p.protocol)+' ('+p.total+')</option>';}).join('');
  sel.value=cur;
}
function showTab(name){
  document.querySelectorAll('.tb').forEach(function(t){t.classList.toggle('on',t.getAttribute('data-v')===name);});
  document.querySelectorAll('.pane').forEach(function(p){p.classList.remove('on');});
  var el=document.getElementById('pane-'+name);if(el)el.classList.add('on');
}

// ── Drawer: one incident, three tabs (event / address / honeypot) ─────────────
var CUR={eid:null,ip:null,proto:null,tab:'event'};
var PKT={},IPC={};
function findE(eid){var f=function(a){return (a||[]).find(function(x){return x.event_id===eid;});};return f(VIEW)||f(DATA.events)||f(DATA.write_ops)||f(DATA.needs_attention)||(window._IPV&&f(window._IPV.events));}
function kv(k,v){if(v==null||v==='')return '';return '<div class="kv"><div class="k">'+esc(k)+'</div><div class="v">'+v+'</div></div>';}
function drawerOpen(){return document.getElementById('dw').classList.contains('open');}
function showDrawer(){var d=document.getElementById('dw');d.classList.add('open');d.setAttribute('aria-hidden','false');document.body.classList.add('dwopen');}
function setTab(t){CUR.tab=t;document.querySelectorAll('.dtb').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-v')===t);});paintDrawer();}
function markSel(){document.querySelectorAll('.ev.sel,.atk.sel').forEach(function(n){n.classList.remove('sel');});
  if(!CUR.eid)return;document.querySelectorAll('#evList .ev').forEach(function(n){if(n.getAttribute('data-eid')===CUR.eid)n.classList.add('sel');});}
function openEvent(eid,tab){
  var e=findE(eid);if(!e){showErr('event not found');return;}
  CUR.eid=eid;CUR.ip=ipS(e.src_ip);CUR.proto=e.protocol||null;CUR.tab=tab||CUR.tab||'event';
  document.getElementById('dwTitle').textContent=(e.protocol||'ICS')+' · '+(e.function_name||e.attack_type||'event');
  document.getElementById('dwSev').innerHTML='<span class="pill" style="background:'+sevc(e.severity)+'22;color:'+sevc(e.severity)+'">'+esc(e.severity||'')+'</span> '+ipill(e.intent);
  showDrawer();markSel();setTab(CUR.tab);
}
function openIp(ip,eid){
  ip=ipS(ip);if(!ip)return;
  var e=eid?findE(eid):null;
  if(e){CUR.eid=eid;CUR.proto=e.protocol||null;document.getElementById('dwTitle').textContent=(e.protocol||'ICS')+' · '+(e.function_name||e.attack_type||'event');
    document.getElementById('dwSev').innerHTML='<span class="pill" style="background:'+sevc(e.severity)+'22;color:'+sevc(e.severity)+'">'+esc(e.severity||'')+'</span> '+ipill(e.intent);}
  else{CUR.eid=null;CUR.proto=null;document.getElementById('dwTitle').textContent='Source '+ip;document.getElementById('dwSev').innerHTML='';}
  CUR.ip=ip;CUR.tab='address';showDrawer();markSel();setTab('address');
}
function paintDrawer(){
  var b=document.getElementById('dwBody');
  if(CUR.tab==='event')paintEventTab(b);
  else if(CUR.tab==='address')paintAddressTab(b);
  else paintHoneypotTab(b);
}
function noInc(what){return '<div class="empty">Pick an event from the list to see '+what+'.</div>';}
function paintEventTab(b){
  var e=CUR.eid?findE(CUR.eid):null;if(!e){b.innerHTML=noInc('the event');return;}
  var eid=CUR.eid;
  var tgt=ipS(e.dst_ip)+(e.dst_port?(':'+e.dst_port):'');
  var cut=preCut(e.timestamp)?'<div class="cutnote" data-cut="1">Recorded before '+CUT_LABEL+': the decoy kept fewer facts then, so &ldquo;unknown&rdquo; here means <b>not recorded</b>, not harmless.</div>':'';
  // plain-language facts first; identifiers (technique id, rule, event id) after
  var h=cut+kv('What',esc(e.function_name||e.attack_type||''))+kv('Kind',ipill(e.intent)+' <span class="muted">'+esc((intm(e.intent).p)||'')+'</span>')+
    kv('From',iplink(e.src_ip)+(e.src_port?' :'+e.src_port:''))+kv('To',esc(tgt))+kv('When',esc(e.timestamp))+
    kv('Protocol',pchip(e.protocol))+
    kv('Function code, recorded by the decoy',e.function_code!=null?esc(e.function_code):'<span class="muted">not recorded'+(String(e.protocol).toLowerCase()==='s7comm'?' (by design for s7comm)':'')+'</span>')+
    kv('Register',e.register_start!=null?esc(e.register_start)+(e.register_count?(' &times;'+e.register_count):''):'')+
    kv('Data value',esc(e.data_value))+kv('Attack type',esc(e.attack_type))+kv('Rule',esc(e.rule_name))+
    kv('MITRE, as stored',mlink(e.mitre_technique)+(e.mitre_tactic?' · '+esc(tname(e.mitre_tactic)):''))+kv('Event ID',esc(e.event_id));
  h+='<div class="ch" style="border-top:1px solid var(--border);margin-top:12px">Packet</div><div id="pktBox"><div class="empty">loading the packet…</div></div>';
  h+='<div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">'+
    '<button class="b ack" data-act="ack" data-eid="'+esc(eid)+'">&#x2713; Acknowledge</button>'+
    '<button class="b fp" data-act="fp" data-eid="'+esc(eid)+'">&#x2716; False-positive</button>'+
    '<button class="b trust" data-act="ipfocus" data-ip="'+esc(ipS(e.src_ip))+'">&#x1F50D; Who is '+esc(ipS(e.src_ip))+'?</button></div>';
  h+='<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;align-items:center">'+
    '<span class="muted" style="font-size:11px">Analyse event:</span>'+
    '<button class="b" style="border-color:#22d3ee55" data-act="ai" data-eid="'+esc(eid)+'" data-engine="local">&#x1F9E0; Local AI</button>'+
    '<button class="b" style="border-color:#a855f755" data-act="ai" data-eid="'+esc(eid)+'" data-engine="cloud">&#x2601; Cloud AI</button></div>';
  h+='<div id="aiResult" style="margin-top:12px"></div>';
  b.innerHTML=h;
  loadPacket(eid);
}
// The packet is rendered by the server (escaped, from the API's already-masked block); the
// script only places it.
function loadPacket(eid){
  var put=function(html){var box=document.getElementById('pktBox');if(box&&CUR.eid===eid&&CUR.tab==='event')box.innerHTML=html;};
  if(PKT[eid]){put(PKT[eid]);return;}
  fetch('/ics/event/'+encodeURIComponent(eid)+'/packet',{headers:{Accept:'text/html'}}).then(function(r){if(!r.ok)throw new Error('packet HTTP '+r.status);return r.text();})
    .then(function(t){PKT[eid]=t;put(t);}).catch(function(err){put('<div class="empty">The packet could not be loaded: '+esc(err.message)+'</div>');});
}
function paintAddressTab(b){
  if(!CUR.ip){b.innerHTML=noInc('who sent it');return;}
  var ip=CUR.ip;
  if(IPC[ip]){b.innerHTML=ipHtml(IPC[ip]);return;}
  b.innerHTML='<div class="empty">loading profile…</div>';
  var u='/ics/ip/'+encodeURIComponent(ip)+(document.getElementById('showFp').checked?'?include_fp=1':'');
  fetch(u,{headers:{Accept:'application/json'}}).then(function(r){if(!r.ok)throw new Error('profile HTTP '+r.status);return r.json();})
    .then(function(d){IPC[ip]=d;window._IPV=d;if(CUR.ip===ip&&CUR.tab==='address')b.innerHTML=ipHtml(d);})
    .catch(function(e){if(CUR.ip===ip&&CUR.tab==='address')b.innerHTML='<div class="empty">Failed: '+esc(e.message)+'</div>';});
}
function bucketCell(k,n){var m=intm(k);var st=k==='unknown'?'border:1px dashed '+m.c+';background:transparent':k==='anomaly'?'border:2px solid '+m.c+';background:'+m.c+'33':'border:1px solid '+m.c+'44;background:'+m.c+'1a';
  return '<div style="flex:1;'+st+';border-radius:6px;padding:6px;text-align:center" title="'+esc(m.p||'')+'"><div style="color:'+m.c+';font-weight:800">'+(n||0)+'</div><div class="l" style="font-size:9px;color:'+m.c+'">'+m.l+'</div></div>';}
function ipHtml(d){
  var it=d.intent||{},sv=d.severity||{};
  var tags=(d.is_trusted?'<span class="pill" style="background:#a855f722;color:#a855f7">TRUSTED</span> ':'')+(sv.CRITICAL?'<span class="pill" style="background:#ef444422;color:#ef4444">'+sv.CRITICAL+' crit</span>':'');
  var mini='<div class="mini">'+
    mx(d.total,'total events')+mx(d.last_1h||0,'last 1h','#f59e0b')+mx(d.last_24h||0,'last 24h')+
    mx(d.writes_controls||0,'write/cmd','#f97316')+mx(d.unique_targets||0,'targets')+mx(d.unique_protocols||0,'protocols')+'</div>';
  var seen='<div class="muted" style="font-size:11px;margin-bottom:10px">'+tags+' first seen '+esc(tshort(d.first_seen))+' · last seen '+esc(tshort(d.last_seen))+' ('+ago(d.last_seen)+' ago)</div>';
  var funnel='<div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">'+BUCKETS.map(function(k){return bucketCell(k,it[k]);}).join('')+'</div>';
  var prow=function(t,rows){return '<div class="ch" style="border-top:1px solid var(--border)">'+t+'</div>'+rows;};
  var tg=(d.targets||[]).slice(0,12).map(function(t){return '<div class="kv"><div class="k">'+esc(ipS(t.dst_ip))+':'+esc(t.dst_port)+'</div><div class="v muted">'+t.count+' events</div></div>';}).join('')||'<div class="empty">—</div>';
  var fn=(d.functions||[]).slice(0,12).map(function(f){return '<div class="kv"><div class="k">'+pchip(f.protocol)+'</div><div class="v">'+esc(f.function_name||'')+' <span class="muted">&times;'+f.count+'</span> '+sdot(f.max_severity)+'</div></div>';}).join('')||'<div class="empty">—</div>';
  var evs='<div class="scroll sm" style="border-top:1px solid var(--border)">'+(d.events||[]).slice(0,120).map(function(e){var tgt=ipS(e.dst_ip)+(e.dst_port?(':'+e.dst_port):'');return '<div class="ev" data-act="event" data-eid="'+esc(e.event_id)+'"><div>'+ipill(e.intent)+'</div><div>'+sdot(e.severity)+'</div><div class="m"><div class="ln">'+pchip(e.protocol)+' '+esc(e.function_name||e.attack_type||'')+' <span class="muted">&#8594; '+esc(tgt)+'</span></div><div class="sb">'+esc(e.rule_name||'')+' · '+ago(e.timestamp)+' ago</div></div><div></div></div>';}).join('')+'</div>';
  var acts='<div style="display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap">'+
    '<button class="b trust" data-act="trust" data-ip="'+esc(d.ip)+'">&#x1F6E1; Trust this source</button>'+
    '<button class="b fp" data-act="fpsrc" data-ip="'+esc(d.ip)+'">&#x2716; Mark all FP</button>'+
    '<a class="b" style="text-decoration:none" target="_blank" href="/events_ip/'+encodeURIComponent(d.ip)+'">Full host view &#8594;</a></div>';
  return '<div style="font-size:13px;margin-bottom:8px">Source <b>'+esc(d.ip)+'</b></div>'+mini+seen+acts+'<b style="font-size:12px">What this address did</b>'+funnel+
    prow('Targets hit',tg)+prow('Functions used',fn)+prow('Recent events ('+(d.events||[]).length+')',evs);
}
// "Honeypot" = this decoy on this sensor, from the per-protocol breakdown /ics/stats already
// serves. Cross-sensor figures do not exist here and are not implied.
function paintHoneypotTab(b){
  var p=CUR.proto;if(!p){b.innerHTML=noInc('which decoy it hit');return;}
  var row=(DATA.by_protocol||[]).find(function(x){return String(x.protocol).toLowerCase()===String(p).toLowerCase();});
  var h='<div style="font-size:13px;margin-bottom:6px">This decoy on this sensor: '+pchip(p)+'</div>'+
    '<div class="muted" style="font-size:11px;margin-bottom:10px">Counts come from this sensor only. They say nothing about the same decoy elsewhere in the fleet.</div>';
  if(!row){b.innerHTML=h+'<div class="empty">No per-protocol figures for '+esc(p)+' in this page.</div>';return;}
  h+='<div class="mini">'+mx(row.total,'events')+mx(row.writes||0,'writes','#f97316')+mx(row.controls||0,'commands','#ef4444')+mx(row.discovery||0,'discovery / enumeration')+mx(row.high_sev||0,'high+','#f97316')+'</div>'+
    '<div class="muted" style="font-size:11px;margin-bottom:10px">Counted from the meaning of the bytes; rows whose meaning is not known count as unknown, not as writes. Last seen '+esc(tshort(row.last_seen))+' ('+ago(row.last_seen)+' ago).</div>';
  var fns=(DATA.by_function||[]).filter(function(f){return String(f.protocol).toLowerCase()===String(p).toLowerCase();}).slice(0,15);
  h+='<div class="ch" style="border-top:1px solid var(--border)">Functions seen on this decoy</div>'+(fns.map(function(f){return '<div class="kv"><div class="k">fc '+esc(f.function_code)+'</div><div class="v">'+esc(f.function_name||'')+' <span class="muted">&times;'+f.total+' · '+(f.unique_src||0)+' source(s)</span> '+sdot(f.max_severity)+'</div></div>';}).join('')||'<div class="empty">—</div>');
  var dst=(DATA.top_dst||[]).filter(function(x){return (x.protocols||[]).map(function(q){return String(q).toLowerCase();}).indexOf(String(p).toLowerCase())>=0;}).slice(0,10);
  h+='<div class="ch" style="border-top:1px solid var(--border)">Targets of this decoy</div>'+(dst.map(function(t){return '<div class="kv"><div class="k">'+esc(ipS(t.ip))+':'+esc(t.port)+'</div><div class="v muted">'+t.total+' events</div></div>';}).join('')||'<div class="empty">—</div>');
  b.innerHTML=h;
}
function mx(n,l,c){return '<div class="x"><div class="n" style="color:'+(c||'#e2e8f0')+'">'+Number(n).toLocaleString()+'</div><div class="l">'+l+'</div></div>';}
function closeAll(){var d=document.getElementById('dw');d.classList.remove('open');d.setAttribute('aria-hidden','true');document.body.classList.remove('dwopen');CUR.eid=null;markSel();}
// Arrow keys walk the visible list with the drawer open, keeping the tab the reader is on.
function walk(dir){
  var rows=Array.prototype.slice.call(document.querySelectorAll('#evList .ev'));if(!rows.length)return;
  var i=rows.findIndex(function(n){return n.getAttribute('data-eid')===CUR.eid;});
  var n=i<0?(dir>0?0:rows.length-1):Math.min(rows.length-1,Math.max(0,i+dir));
  var tab=CUR.tab;openEvent(rows[n].getAttribute('data-eid'),tab);rows[n].scrollIntoView({block:'nearest'});
}

// ── Per-event AI analysis (local Ollama / cloud Claude) ─────────────────────
function aiField(l,v){if(v==null||v===''||(Array.isArray(v)&&!v.length))return '';return '<div style="margin:4px 0"><span class="muted">'+esc(l)+':</span> '+esc(Array.isArray(v)?v.join(', '):(typeof v==='object'?JSON.stringify(v):v))+'</div>';}
function renderAI(r){
  var cls=r.triage_class||'—';
  var col=cls==='CRITICAL'?'#ef4444':cls==='SUSPICIOUS'?'#f97316':cls==='BENIGN'?'#22c55e':'#94a3b8';
  var eng=r.deep_engine||(r.requested_engine==='cloud'?'claude':'ollama');
  var d=r.deep_analysis||{};
  var verdict=r.claude_verdict||d.verdict||'';
  var summary=r.claude_summary||d.summary||d.reasoning||'';
  var zd=(r.zero_day_score!=null)?r.zero_day_score:d.zero_day_probability;
  var h='<div class="card" style="border-color:'+col+'66">'+
    '<div class="ch" style="color:'+col+'">&#x1F9E0; AI verdict: '+esc(cls)+
      ' <span class="c">via '+esc(eng)+(r.confidence?(' &middot; '+esc(r.confidence)):'')+'</span></div>'+
    '<div style="padding:11px 14px;font-size:12px;line-height:1.65">';
  if(r.status==='cached')h+='<div class="muted" style="margin-bottom:6px">(cached &mdash; AI backend offline)</div>';
  if(r.engine_note)h+='<div style="color:#eab308;margin-bottom:7px">&#9888; '+esc(r.engine_note)+'</div>';
  if(r.reasoning)h+='<div style="margin-bottom:8px">'+esc(r.reasoning)+'</div>';
  h+=aiField('Verdict',verdict)+aiField('Summary',summary)+aiField('Known CVE',r.known_cve)+
     aiField('Novelty',r.novelty_score)+aiField('Zero-day score',zd)+
     aiField('Suggested rule',r.suggested_rule)+aiField('IOCs',r.iocs);
  h+='</div></div>';
  return h;
}
function analyzeEvent(eid,engine){
  var box=document.getElementById('aiResult');if(!box)return;
  var label=engine==='cloud'?'Cloud (Claude)':'Local (Ollama)';
  box.innerHTML='<div class="empty">&#x1F9E0; Analysing with '+label+' AI&hellip; (this can take a few seconds)</div>';
  post('/ai/analyze/'+encodeURIComponent(eid)+'?engine='+engine+'&force=true',{})
    .then(function(r){box.innerHTML=renderAI(r);})
    .catch(function(e){box.innerHTML='<div class="empty" style="color:#ef4444">AI analysis failed: '+esc(e.message)+'</div>';});
}

// ── Triage ───────────────────────────────────────────────────────────────────
function post(path,body){return fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){if(r.status===403)throw new Error('admin access required');if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});}
function ackEvents(ids){ids=ids.filter(Boolean);if(!ids.length)return;post('/ics/triage/ack',{event_ids:ids}).then(function(r){toast('Acknowledged '+(r.acknowledged||ids.length));softReload();}).catch(function(e){showErr(e.message);});}
function fpEvents(ids){ids=ids.filter(Boolean);if(!ids.length)return;var n=prompt('Mark '+ids.length+' event(s) false-positive. Optional note:','');if(n===null)return;post('/ics/triage/false-positive',{event_ids:ids,note:n||null}).then(function(r){toast('Marked '+(r.marked||ids.length)+' FP');softReload();}).catch(function(e){showErr(e.message);});}
function fpSrc(ip){ip=ipS(ip);if(!ip)return;if(!confirm('Mark ALL events from '+ip+' as false-positive?'))return;post('/ics/triage/false-positive',{src_ip:ip,note:'operator: source not an attacker'}).then(function(r){toast('Marked '+(r.marked||0)+' FP from '+ip);hardReload();}).catch(function(e){showErr(e.message);});}
function trustSrc(ip){ip=ipS(ip);if(!ip)return;if(!confirm('Trust '+ip+'? Its events get acknowledged.'))return;post('/ics/triage/trust-source',{src_ip:ip}).then(function(r){toast('Trusted '+ip+' ('+(r.acknowledged||0)+' acked)');hardReload();}).catch(function(e){showErr(e.message);});}
function softReload(){loadEvents();}
function hardReload(){setTimeout(function(){location.reload();},700);}
function toggleFp(){var on=document.getElementById('showFp').checked;var u=new URL(location.href);if(on)u.searchParams.set('include_fp','1');else u.searchParams.delete('include_fp');location.href=u.toString();}

// ── Delegated events (robust: one listener, no inline handlers) ──────────────
document.addEventListener('click',function(ev){
  var el=ev.target.closest('[data-act]');if(!el)return;var a=el.getAttribute('data-act');
  try{
    if(a==='tab')showTab(el.getAttribute('data-v'));
    else if(a==='ipfocus'){ev.preventDefault();var row=el.closest('[data-eid]');openIp(el.getAttribute('data-ip'),row?row.getAttribute('data-eid'):null);}
    else if(a==='dtab')setTab(el.getAttribute('data-v'));
    else if(a==='event')openEvent(el.getAttribute('data-eid'),drawerOpen()?CUR.tab:'event');
    else if(a==='ai')analyzeEvent(el.getAttribute('data-eid'),el.getAttribute('data-engine'));
    else if(a==='ack')ackEvents([el.getAttribute('data-eid')]);
    else if(a==='fp')fpEvents([el.getAttribute('data-eid')]);
    else if(a==='fpsrc')fpSrc(el.getAttribute('data-ip'));
    else if(a==='trust')trustSrc(el.getAttribute('data-ip'));
    else if(a==='filter'){var d=el.dataset;if(d.proto!==undefined)document.getElementById('fProto').value=d.proto;if(d.intent!==undefined)document.getElementById('fIntent').value=d.intent;if(d.sev!==undefined)document.getElementById('fSev').value=d.sev;loadEvents();window.scrollTo({top:0,behavior:'smooth'});}
    else if(a==='clearf'){['q','fIntent','fSev','fProto'].forEach(function(id){document.getElementById(id).value='';});loadEvents();}
    else if(a==='closedrawer')closeAll();
    else if(a==='refresh')location.reload();
    else if(a==='showfp')toggleFp();
  }catch(e){showErr(e.message);}
});

// ── Packet view: hovering a field lights its bytes, hovering bytes lights the field ─
// The link is by byte range (data-offset/data-length on a field row, data-i on a byte), so
// it works both ways from the same two numbers.
function pkClear(pk){pk.querySelectorAll('.hl').forEach(function(n){n.classList.remove('hl');});}
function pkLight(pk,row){
  var o=+row.getAttribute('data-offset'),l=+row.getAttribute('data-length');row.classList.add('hl');
  pk.querySelectorAll('.by').forEach(function(by){var i=+by.getAttribute('data-i');if(i>=o&&i<o+l)by.classList.add('hl');});
}
function pkHover(ev){
  var pk=ev.target.closest&&ev.target.closest('.pk');
  if(!pk){document.querySelectorAll('.pk .hl').forEach(function(n){n.classList.remove('hl');});return;}
  pkClear(pk);if(ev.type==='mouseout')return;
  var row=ev.target.closest('tr.fld'),by=ev.target.closest('.by');
  if(row)pkLight(pk,row);
  else if(by){var i=+by.getAttribute('data-i');
    var rows=Array.prototype.slice.call(pk.querySelectorAll('tr.fld'));
    for(var k=0;k<rows.length;k++){var o=+rows[k].getAttribute('data-offset'),l=+rows[k].getAttribute('data-length');if(i>=o&&i<o+l){pkLight(pk,rows[k]);break;}}}
}

// ── Init ─────────────────────────────────────────────────────────────────────
(function(){
  function safe(fn){try{fn();}catch(e){window.onerror(e.message,'',0);}}
  if(new URL(location.href).searchParams.get('include_fp'))document.getElementById('showFp').checked=true;
  safe(renderVerdict);safe(renderTables);safe(renderAttacks);safe(renderWho);safe(loadEvents);
  var qt=null;document.getElementById('q').addEventListener('input',function(){clearTimeout(qt);qt=setTimeout(loadEvents,350);});
  ['fIntent','fSev','fProto'].forEach(function(id){document.getElementById(id).addEventListener('change',loadEvents);});
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'){closeAll();return;}
    if(!drawerOpen()||(e.key!=='ArrowDown'&&e.key!=='ArrowUp'))return;
    var t=e.target&&e.target.tagName;if(t==='INPUT'||t==='SELECT'||t==='TEXTAREA')return;
    e.preventDefault();walk(e.key==='ArrowDown'?1:-1);
  });
  document.addEventListener('mouseover',pkHover);document.addEventListener('mouseout',pkHover);
})();
</script>
</main>
</body></html>"""
