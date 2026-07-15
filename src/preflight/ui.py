"""Judge/browser-facing HTML surfaces.

The API stays machine-first (JSON). Browsers hitting GET / get a small,
self-contained landing page (no CDNs, no build step); GET /audit/{id}?format=html
returns a shareable server-rendered report. All user-controlled text is escaped
server-side, and the landing page builds DOM via textContent only.
"""

from __future__ import annotations

import html

from .models import AuditReport, Severity
from .scoring import VERDICT_AT_RISK, VERDICT_READY

_CSS = """
:root{--bg:#0a1220;--panel:#111b2e;--panel2:#0e1626;--ink:#e8eef7;--muted:#93a4bc;
--line:#22304a;--teal:#2dd4bf;--teal-ink:#04211c;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#12233f 0%,var(--bg) 55%);
color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;min-height:100vh}
a{color:var(--teal)}
header{display:flex;align-items:center;gap:.6rem;padding:1.1rem clamp(1rem,4vw,2.5rem);border-bottom:1px solid var(--line)}
.brand{font-weight:700;letter-spacing:.02em}
header nav{margin-left:auto;font-size:.9rem}
main{max-width:880px;margin:0 auto;padding:2.2rem clamp(1rem,4vw,2rem) 4rem}
h1{font-size:clamp(1.7rem,4.5vw,2.6rem);line-height:1.15;margin:.2rem 0 .6rem}
.accent{color:var(--teal)}
.sub{color:var(--muted);max-width:62ch;margin:0 0 1.6rem}
form{display:grid;gap:.9rem;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1.2rem}
label{font-size:.85rem;color:var(--muted)}
input{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:9px;
color:var(--ink);padding:.7rem .8rem;font-family:var(--mono);font-size:.95rem}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--teal);outline-offset:2px}
button.primary{background:var(--teal);color:var(--teal-ink);font-weight:700;border:0;border-radius:9px;
padding:.75rem 1.1rem;font-size:1rem;cursor:pointer}
button.primary[disabled]{opacity:.55;cursor:wait}
.chips{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.9rem 0 0;color:var(--muted);font-size:.85rem}
.chip{background:transparent;border:1px solid var(--line);color:var(--ink);border-radius:999px;
padding:.35rem .8rem;font-size:.82rem;cursor:pointer}
.chip:hover{border-color:var(--teal)}
#status{margin:1.2rem 0 0;color:var(--muted);min-height:1.4rem}
.pulse::after{content:"…";animation:p 1.2s infinite}
@keyframes p{0%{opacity:.2}50%{opacity:1}100%{opacity:.2}}
.banner{font-size:1.25rem;font-weight:800;letter-spacing:.03em;padding:.85rem 1.1rem;border-radius:11px;margin:1.4rem 0 .6rem}
.v-ready{background:rgba(46,164,79,.14);color:#5fe08a;border:1px solid rgba(46,164,79,.5)}
.v-risk{background:rgba(210,153,34,.12);color:#e8b64f;border:1px solid rgba(210,153,34,.5)}
.v-fail{background:rgba(207,34,46,.12);color:#ff7b87;border:1px solid rgba(207,34,46,.55)}
.meta{color:var(--muted);font-size:.9rem;margin:.2rem 0 1rem;overflow-wrap:anywhere}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1.1rem 1.2rem;margin:1rem 0}
.card h2{margin:.1rem 0 .7rem;font-size:1.05rem}
ol.fixes{margin:0;padding-left:1.2rem}
ol.fixes li{margin:.35rem 0}
.finding{display:grid;grid-template-columns:auto 1fr;gap:.6rem;padding:.55rem 0;border-top:1px solid var(--line)}
.finding:first-child{border-top:0}
.sev{font-family:var(--mono);font-size:.72rem;font-weight:700;border-radius:6px;padding:.15rem .45rem;
height:fit-content;white-space:nowrap;text-transform:uppercase}
.s-critical{background:rgba(207,34,46,.28);color:#ff8d97}
.s-fail{background:rgba(207,34,46,.14);color:#ff8d97}
.s-warn{background:rgba(210,153,34,.16);color:#e8b64f}
.s-info{background:rgba(147,164,188,.15);color:var(--muted)}
.s-pass{background:rgba(46,164,79,.15);color:#5fe08a}
.f-title{font-weight:600}
.f-detail{color:var(--muted);font-size:.88rem;overflow-wrap:anywhere}
.f-fix{color:var(--teal);font-size:.88rem}
code,pre{font-family:var(--mono)}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:.8rem 1rem;
overflow-x:auto;font-size:.83rem}
footer{border-top:1px solid var(--line);color:var(--muted);padding:1.4rem clamp(1rem,4vw,2.5rem);font-size:.9rem}
.badgebox{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
"""

_MARK_SVG = (
    '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M3 17 9 11l4 4 8-8" stroke="#2DD4BF" stroke-width="2.4" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    '<path d="M15 7h6v6" stroke="#2DD4BF" stroke-width="2.4" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)

_FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E"
    "%3Crect width='24' height='24' rx='5' fill='%230a1220'/%3E"
    "%3Cpath d='M4 17 9.5 11.5l4 4L21 8' stroke='%232DD4BF' stroke-width='2.4' fill='none' "
    "stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E"
)

LANDING_HTML = (
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Preflight — pass OKX.AI review the first time</title>
<meta name="description" content="Paste any agent-service endpoint and get a graded OKX.AI readiness report in about 30 seconds: protocol, x402 payment challenge, robustness, security.">
<link rel="icon" href=\""""
    + _FAVICON
    + """\">
<style>"""
    + _CSS
    + """</style>
</head>
<body>
<header>"""
    + _MARK_SVG
    + """<span class="brand">Preflight</span>
<nav><a href="/docs">API docs</a></nav>
</header>
<main>
<h1>Pass OKX.AI review <span class="accent">the first time</span>.</h1>
<p class="sub">Paste any agent-service endpoint. Preflight runs 20+ deterministic checks —
reachability, protocol, field-by-field x402 payment-challenge validation, robustness,
security — and returns a graded readiness verdict with a fix for every failure.
No LLM verdicts. Nothing to install.</p>

<form id="f">
  <div>
    <label for="url">Endpoint URL</label>
    <input id="url" name="url" type="url" required placeholder="https://your-asp.example.com/api/service" autocomplete="off" spellcheck="false">
  </div>
  <div>
    <label for="price">Listing price in USDT (optional — checks it matches the x402 challenge)</label>
    <input id="price" name="price" inputmode="decimal" placeholder="0.05" autocomplete="off">
  </div>
  <button id="go" class="primary" type="submit">Run preflight</button>
</form>

<div class="chips">Try it:
  <button class="chip" type="button" data-url="/demo/broken-x402">a deliberately broken endpoint</button>
  <button class="chip" type="button" data-url="/">Preflight auditing itself</button>
</div>

<p id="status" role="status" aria-live="polite"></p>
<section id="result" hidden aria-live="polite"></section>

<div class="card">
<h2>Use it from your agent</h2>
<pre><code id="curl"></code></pre>
<p class="meta">Free quick check at <code>POST /check</code> · deep audit at <code>POST /audit</code> (x402 on X Layer) ·
reports at <code>GET /audit/{id}</code> (json · md · html) · live badge at <code>GET /audit/{id}/badge.svg</code></p>
</div>
</main>
<footer>Preflight is itself an OKX.AI Agent Service Provider. It audits public HTTPS endpoints only,
never follows redirects, and refuses private-network targets by design.</footer>
<script>
(function(){
"use strict";
var $=function(s){return document.querySelector(s)};
var form=$('#f'),urlIn=$('#url'),priceIn=$('#price'),go=$('#go'),status=$('#status'),result=$('#result');
$('#curl').textContent="curl -s -X POST "+location.origin+"/check -H 'content-type: application/json' -d '{\\"url\\":\\"https://your-endpoint/api\\"}'";
document.querySelectorAll('.chip').forEach(function(c){
  c.addEventListener('click',function(){urlIn.value=location.origin+c.dataset.url;priceIn.value='';form.requestSubmit();});
});
function el(tag,cls,text){var n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;}
function verdictClass(v){return v==='READY'?'v-ready':v==='AT RISK'?'v-risk':'v-fail';}
function showError(msg){status.classList.remove('pulse');status.textContent=msg;go.disabled=false;}
form.addEventListener('submit',function(e){
  e.preventDefault();
  go.disabled=true;result.hidden=true;result.textContent='';
  status.textContent='Running 20+ deterministic checks';status.classList.add('pulse');
  var body={url:urlIn.value.trim()};
  var p=priceIn.value.trim();if(p)body.declared_price=p;
  fetch('/audit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})
  .then(function(r){
    if(r.status===402){
      status.textContent='Deep audit is a paid OKX.AI service — running the free quick check instead';
      return fetch('/check',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:body.url})})
        .then(function(r2){
          if(r2.status===429){throw new Error('Rate limit reached — try again in a minute.');}
          if(!r2.ok){throw new Error('That does not look like a valid public https:// URL.');}
          return r2.json().then(function(rep){rep._quick=true;return rep;});
        });
    }
    if(r.status===429){throw new Error('Rate limit reached — try again in a minute.');}
    if(!r.ok){throw new Error('That does not look like a valid public https:// URL.');}
    return r.json();
  })
  .then(render)
  .catch(function(err){showError(err.message||'Network error.');});
});
function render(rep){
  status.classList.remove('pulse');go.disabled=false;
  if(!rep._quick)status.textContent='';
  result.textContent='';
  result.appendChild(el('div','banner '+verdictClass(rep.verdict),rep.verdict));
  var meta='Grade '+rep.grade+' · '+rep.score+'/100 · '+rep.endpoint_kind+
    (rep.duration_ms!==undefined?' · '+Math.round(rep.duration_ms)+' ms':'')+
    (rep.target_url?' · '+rep.target_url:'');
  result.appendChild(el('p','meta',meta));
  if(rep.summary&&!rep.findings)result.appendChild(el('p','meta',rep.summary));
  if(rep.fixes&&rep.fixes.length){
    var fc=el('div','card');fc.appendChild(el('h2',null,'Fix first'));
    var ol=el('ol','fixes');
    rep.fixes.forEach(function(f){ol.appendChild(el('li',null,f));});
    fc.appendChild(ol);result.appendChild(fc);
  }
  var findings=rep.findings||(rep.top_issues||[]).map(function(t){return{severity:t.severity,title:t.title,fix:t.fix};});
  var order=['critical','fail','warn','info','pass'];
  var card=el('div','card');card.appendChild(el('h2',null,rep.findings?'All findings ('+findings.length+')':'Top issues ('+findings.length+')'));
  order.forEach(function(sev){
    findings.filter(function(f){return f.severity===sev;}).forEach(function(f){
      var row=el('div','finding');
      row.appendChild(el('span','sev s-'+sev,sev));
      var b=el('div');
      b.appendChild(el('div','f-title',f.title));
      if(f.detail)b.appendChild(el('div','f-detail',f.detail));
      if(f.fix&&(sev==='critical'||sev==='fail'||sev==='warn'))b.appendChild(el('div','f-fix','Fix: '+f.fix));
      row.appendChild(b);card.appendChild(row);
    });
  });
  result.appendChild(card);
  var share=el('div','card');share.appendChild(el('h2',null,'Share it'));
  var box=el('div','badgebox');
  var img=document.createElement('img');img.src=rep.badge_url;img.alt='Preflight badge: '+rep.verdict;
  box.appendChild(img);
  var a=el('a',null,'Open shareable report');a.href='/audit/'+rep.report_id+'?format=html';
  box.appendChild(a);
  share.appendChild(box);
  var snip=el('pre');snip.appendChild(el('code',null,'![Preflight]('+rep.badge_url+')'));
  share.appendChild(snip);
  result.appendChild(share);
  result.hidden=false;
}
})();
</script>
</body>
</html>"""
)

_SEV_ORDER = [Severity.CRITICAL, Severity.FAIL, Severity.WARN, Severity.INFO, Severity.PASS]


def report_html(report: AuditReport, base_url: str) -> str:
    base = base_url.rstrip("/")
    badge_url = f"{base}/audit/{report.report_id}/badge.svg"
    verdict_class = (
        "v-ready"
        if report.verdict == VERDICT_READY
        else "v-risk" if report.verdict == VERDICT_AT_RISK else "v-fail"
    )
    rows = []
    for severity in _SEV_ORDER:
        for finding in report.findings:
            if finding.severity is not severity:
                continue
            detail = (
                f'<div class="f-detail">{html.escape(finding.detail)}</div>' if finding.detail else ""
            )
            fix = (
                f'<div class="f-fix">Fix: {html.escape(finding.fix)}</div>'
                if finding.fix and severity in (Severity.CRITICAL, Severity.FAIL, Severity.WARN)
                else ""
            )
            rows.append(
                f'<div class="finding"><span class="sev s-{severity.value}">{severity.value}</span>'
                f'<div><div class="f-title">{html.escape(finding.title)}</div>{detail}{fix}</div></div>'
            )
    fixes = ""
    if report.fixes:
        items = "".join(f"<li>{html.escape(fix)}</li>" for fix in report.fixes)
        fixes = f'<div class="card"><h2>Fix first</h2><ol class="fixes">{items}</ol></div>'
    latency = (
        f" · median latency {report.latency.median_ms:.0f} ms" if report.latency else ""
    )
    return (
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Preflight report — """
        + html.escape(report.verdict)
        + """</title>
<link rel="icon" href=\""""
        + _FAVICON
        + """\">
<style>"""
        + _CSS
        + """</style>
</head>
<body>
<header>"""
        + _MARK_SVG
        + f"""<span class="brand">Preflight</span>
<nav><a href="{base}/">Run your own audit</a></nav>
</header>
<main>
<div class="banner {verdict_class}">{html.escape(report.verdict)}</div>
<p class="meta">Grade <strong>{report.grade}</strong> · {report.score}/100 ·
{html.escape(report.endpoint_kind)} · checked {report.checked_at.strftime("%Y-%m-%d %H:%M UTC")}
· <code>{html.escape(report.target_url)}</code>{latency}</p>
<p class="sub">{html.escape(report.summary)}</p>
<div class="card"><h2>Live badge</h2>
<div class="badgebox"><img src="{badge_url}" alt="Preflight badge: {html.escape(report.verdict)}"></div>
<pre><code>![Preflight]({badge_url})</code></pre></div>
{fixes}
<div class="card"><h2>All findings ({len(report.findings)})</h2>{"".join(rows)}</div>
<p class="meta"><a href="{base}/audit/{report.report_id}">JSON</a> ·
<a href="{base}/audit/{report.report_id}?format=md">Markdown</a></p>
</main>
<footer>Generated by Preflight — deterministic conformance auditing for agent services.</footer>
</body>
</html>"""
    )
