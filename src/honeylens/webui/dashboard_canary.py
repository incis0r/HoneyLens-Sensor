"""AI prompt-injection canary dashboard (Idea 52).

Reads /canary/stats?format=json. The story the page has to tell is narrow but
specific: how many canaries went out, how many were answered, and — the finding —
whether the address that answered is the same one that read the honeypot output.
An agent calling back from different infrastructure than the client that harvested
the credential is exactly what this feature exists to surface.
"""

from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html

_CANARY_CSS = """
.cgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:14px}
.kpi{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px}
.kpi-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3)}
.kpi-val{font-size:22px;font-weight:600;margin-top:4px}
.kpi-val.hit{color:var(--red)}
.kpi-sub{font-size:10px;color:var(--text3);margin-top:2px}
table.canary{width:100%;border-collapse:collapse;font-size:11px}
table.canary th{text-align:left;padding:6px 8px;color:var(--text3);font-weight:500;
  border-bottom:1px solid var(--border);white-space:nowrap}
table.canary td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left}
table.canary tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.split{color:var(--red);font-weight:600}
.same{color:var(--text3)}
.wrapcell{max-width:320px;overflow-wrap:anywhere}
.empty{padding:14px;color:var(--text3);font-size:11px}
"""

CANARY_DASHBOARD_HTML = (
    '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    '<meta name="referrer" content="strict-origin-when-cross-origin">\n'
    "<title>AI Canary — Hybrid Intelligence Sensor</title>\n"
    "<style>" + SHARED_CSS + _CANARY_CSS + "</style>\n"
    "</head>\n<body>\n"
    '<a href="#main-content" class="skip-link">Skip to main content</a>\n'
    + nav_bar_html("canary")
    + '<div class="page" id="main-content">\n'
    + page_header_html(
        "AI Canary",
        eyebrow="Deception",
        description="Benign instructions planted in credential-like honeypot responses. "
        "An AI agent that obeys one makes a harmless callback we record.",
        metadata=("Window: 30 days",),
    )
    + r"""
<div class="cgrid">
  <div class="kpi">
    <div class="kpi-lbl">Canaries Issued</div>
    <div class="kpi-val" id="issued">—</div>
    <div class="kpi-sub" id="issuedSrc">&nbsp;</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Agent Callbacks</div>
    <div class="kpi-val" id="callbacks">—</div>
    <div class="kpi-sub">instructions actually obeyed</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Correlated</div>
    <div class="kpi-val" id="correlated">—</div>
    <div class="kpi-sub">tied back to what was read</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Average Latency</div>
    <div class="kpi-val" id="latency">—</div>
    <div class="kpi-sub">read &rarr; callback</div>
  </div>
</div>

<div class="panel" style="margin-bottom:14px">
  <div class="panel-hdr">Callback Clients</div>
  <div id="agents" class="empty">Loading...</div>
</div>

<div class="panel">
  <div class="panel-hdr">Recent Callbacks</div>
  <div id="recent" class="empty">Loading...</div>
</div>

<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

fetch('/canary/stats?format=json', {credentials:'same-origin'})
  .then(function(r){return r.json();})
  .then(function(d){
    document.getElementById('issued').textContent = d.issued != null ? d.issued : '—';
    document.getElementById('issuedSrc').textContent =
      d.source === 'registry' ? 'from the canary registry' : 'counted from events';
    var cb = d.callbacks || 0;
    var cbEl = document.getElementById('callbacks');
    cbEl.textContent = cb;
    if (cb > 0) cbEl.className = 'kpi-val hit';
    document.getElementById('correlated').textContent = d.correlated != null ? d.correlated : '—';
    document.getElementById('latency').textContent =
      d.avg_latency_ms != null ? d.avg_latency_ms + ' ms' : '—';

    var ag = d.top_agents || [];
    document.getElementById('agents').innerHTML = ag.length
      ? '<table class="canary"><tr><th>User-Agent</th><th>Callbacks</th></tr>' +
        ag.map(function(a){return '<tr><td class="mono wrapcell">' + esc(a.user_agent) +
          '</td><td>' + esc(a.count) + '</td></tr>';}).join('') + '</table>'
      : '<div class="empty">No agent has taken the bait yet.</div>';

    var rc = d.recent || [];
    document.getElementById('recent').innerHTML = rc.length
      ? '<table class="canary"><tr><th>Time</th><th>Called back from</th><th>Read by</th>' +
        '<th>Artefact</th><th>User-Agent</th><th>Delay</th></tr>' +
        rc.map(function(r){
          // The interesting case: the agent answers from somewhere other than the
          // client that read the honeypot output.
          var split = r.origin_src_ip && r.callback_src_ip &&
                      r.origin_src_ip !== r.callback_src_ip;
          return '<tr><td class="mono">' + esc((r.timestamp||'').replace('T',' ').slice(0,19)) +
            '</td><td class="mono ' + (split ? 'split' : '') + '">' + esc(r.callback_src_ip) +
            '</td><td class="mono ' + (split ? 'split' : 'same') + '">' +
              esc(r.origin_src_ip || '—') +
            '</td><td class="mono wrapcell">' + esc(r.origin_path || '—') +
            '</td><td class="mono wrapcell">' + esc(r.user_agent) +
            '</td><td>' + (r.delay_ms != null ? esc(r.delay_ms) + ' ms' : '—') +
            '</td></tr>';
        }).join('') + '</table>' +
        (rc.some(function(r){return r.origin_src_ip && r.callback_src_ip &&
                                    r.origin_src_ip !== r.callback_src_ip;})
          ? '<div class="empty">Highlighted rows answered from a different address than the one that read the output.</div>'
          : '')
      : '<div class="empty">No callbacks recorded in this window.</div>';
  })
  .catch(function(){
    document.getElementById('recent').innerHTML =
      '<div class="empty">Could not load canary statistics.</div>';
  });
</script>
"""
    + "</div>\n</body>\n</html>"
)
