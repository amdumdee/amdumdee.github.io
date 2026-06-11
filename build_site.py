#!/usr/bin/env python3
"""build_site.py — Global Threat Intelligence site generator for amdumdee.com

Reads every threat-report YAML in the repo (named YYYY-MM-DD-*.yaml) plus any
rollups, and bakes them into a single self-contained docs/index.html.

Run from the repo root:  python3 build_site.py
Then enable GitHub Pages on the /docs folder (or move index.html to root).

Pattern mirrors the proven ruwgxo.com book-site builder: one fast static file,
content baked in at build time, client-side nav/search, no runtime fetches.
"""

import glob, json, re, yaml
from pathlib import Path
from html import escape

REPO_ROOT = Path('_data/global-threat-intel')
OUT_DIR   = Path('threat-intel')

# ── YAML loader ───────────────────────────────────────────────────────────────

def load_yaml(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        raw = f.read()
    try:
        docs = list(yaml.safe_load_all(raw))
        merged = {}
        for d in docs:
            if isinstance(d, dict):
                merged.update(d)
        return merged
    except Exception:
        return {}

# ── File discovery ────────────────────────────────────────────────────────────

DATE_RE   = re.compile(r'(\d{4})-(\d{2})-(\d{2})-(.+)\.ya?ml$')
ROLLUP_RE = re.compile(r'(\d{4})-(Q[1-4]|H[12]|\d{2}|annual)-rollup\.ya?ml$', re.IGNORECASE)

def discover():
    """Return (reports, rollups) as sorted lists of dicts."""
    reports, rollups = [], []
    for p in REPO_ROOT.rglob('*.y*ml'):
        # skip the framework / config files
        if 'framework' in p.name.lower() or p.name.startswith('.'):
            continue
        name = p.name
        rm = ROLLUP_RE.search(name)
        if rm:
            rollups.append({'path': p, 'year': rm.group(1), 'period': rm.group(2).upper()})
            continue
        dm = DATE_RE.search(name)
        if dm:
            y, mo, d, slug = dm.groups()
            reports.append({
                'path': p, 'date': f'{y}-{mo}-{d}',
                'year': y, 'month': mo, 'slug': slug,
            })
    reports.sort(key=lambda r: r['date'], reverse=True)   # newest first
    rollups.sort(key=lambda r: (r['year'], r['period']), reverse=True)
    return reports, rollups

# ── Helpers ───────────────────────────────────────────────────────────────────

def nice_label(key):
    key = str(key)
    stop = {'a','an','the','and','or','of','in','on','at','to','for','vs','via'}
    words = key.replace('_', ' ').split()
    return ' '.join(w.capitalize() if i == 0 or w not in stop else w
                    for i, w in enumerate(words))

def first_str(doc, *path, default=''):
    """Dig nested dict by a path of keys; return first string found."""
    cur = doc
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur.strip() if isinstance(cur, str) else default

def deep_find(d, target):
    """Find first value for `target` key anywhere in nested structure."""
    if isinstance(d, dict):
        if target in d:
            return d[target]
        for v in d.values():
            r = deep_find(v, target)
            if r is not None:
                return r
    elif isinstance(d, list):
        for it in d:
            r = deep_find(it, target)
            if r is not None:
                return r
    return None

MONTHS = {'01':'January','02':'February','03':'March','04':'April','05':'May',
          '06':'June','07':'July','08':'August','09':'September','10':'October',
          '11':'November','12':'December'}

def pretty_date(iso):
    try:
        y, m, d = iso.split('-')
        return f'{MONTHS.get(m, m)} {int(d)}, {y}'
    except Exception:
        return iso

SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

# ── Block extraction (prose / list / code / subheadings) ──────────────────────

SKIP_KEYS = {
    'report_date', 'threat_id', 'rollup_id', 'severity_business',
    'severity_technical', 'last_updated', 'rollup_date', 'author',
    'confidence_level', 'period', 'period_type', 'rollup_type',
    'reports_synthesized', 'period_covered', 'post_metadata',
    'schema_version', 'version',
}

def is_code_text(text):
    if not isinstance(text, str):
        return False
    lines = text.strip().splitlines()
    if not lines:
        return False
    pats = ('import ', 'from ', 'def ', 'class ', '# ', '>>> ', '$ ')
    n = sum(1 for l in lines if any(l.lstrip().startswith(p) for p in pats)
            or l.startswith('    ') or l.startswith('\t'))
    return n >= 3

def extract(d, depth=0):
    out = []
    if isinstance(d, str):
        t = d.strip()
        if len(t) >= 30:
            out.append({'type': 'code' if is_code_text(t) else 'prose', 'text': t, 'level': depth})
        return out
    if isinstance(d, list):
        # list of dicts with name/impact (affected orgs, decisions, sources)
        structured = [x for x in d if isinstance(x, dict)]
        if structured:
            for item in structured:
                # decision-style
                if 'decision' in item:
                    pr = item.get('priority', '')
                    head = f"{pr}: {item['decision']}" if pr else item['decision']
                    out.append({'type': 'subheading', 'text': head.strip(), 'level': depth})
                    for kk in ('business_justification', 'cost_estimate', 'action_horizon'):
                        if item.get(kk):
                            out.append({'type': 'prose',
                                        'text': f'{nice_label(kk)}: {item[kk].strip()}',
                                        'level': depth + 1})
                # name/impact-style (affected orgs)
                elif 'name' in item and 'impact' in item:
                    out.append({'type': 'kv', 'k': item['name'].strip(),
                                'v': item['impact'].strip(), 'level': depth})
                # pattern-style (rollups)
                elif 'pattern' in item:
                    out.append({'type': 'subheading', 'text': item['pattern'].strip(), 'level': depth})
                    if item.get('frequency'):
                        out.append({'type': 'prose', 'text': item['frequency'].strip(), 'level': depth + 1})
                    if item.get('significance'):
                        out.append({'type': 'prose', 'text': item['significance'].strip(), 'level': depth + 1})
                else:
                    out.extend(extract(item, depth + 1))
            return out
        bullets = [str(x).strip() for x in d if isinstance(x, str) and str(x).strip()]
        if bullets:
            out.append({'type': 'list', 'text': bullets, 'level': depth})
        return out
    if isinstance(d, dict):
        for k, v in d.items():
            if k in SKIP_KEYS:
                continue
            label = nice_label(k)
            if isinstance(v, str):
                if len(v.strip()) < 20:
                    continue
                out.append({'type': 'subheading', 'text': label, 'level': depth})
                out.append({'type': 'code' if is_code_text(v) else 'prose',
                            'text': v.strip(), 'level': depth})
            elif isinstance(v, (list, dict)):
                sub = extract(v, depth + 1)
                if sub:
                    out.append({'type': 'subheading', 'text': label, 'level': depth})
                    out.extend(sub)
    return out

# ── Source rendering (the credibility layer) ──────────────────────────────────

def render_sources(doc):
    srcs = deep_find(doc, 'source_articles')
    if not isinstance(srcs, list):
        return ''
    rows = []
    for s in srcs:
        if not isinstance(s, dict):
            continue
        title = escape(str(s.get('title', '')).strip())
        url   = str(s.get('url', '')).strip()
        date  = escape(str(s.get('date', '')).strip())
        contrib = escape(str(s.get('key_contribution', '')).strip())
        if not title:
            continue
        link = (f'<a href="{escape(url)}" target="_blank" rel="noopener">{title} ↗</a>'
                if url and url.lower().startswith('http') else title)
        meta = ' · '.join(x for x in (date, contrib) if x)
        rows.append(f'<li><div class="src-t">{link}</div>'
                    + (f'<div class="src-m">{meta}</div>' if meta else '') + '</li>')
    if not rows:
        return ''
    return ('<div class="sources"><div class="box-label">Sources — every claim traced</div>'
            '<ul class="src-list">' + ''.join(rows) + '</ul></div>')

# ── Render one report ─────────────────────────────────────────────────────────

GITHUB_BLOB = 'https://github.com/AmDumDee/global-threat-intel/blob/main'

def render_report(entry, is_rollup=False):
    doc = load_yaml(entry['path'])
    H = escape
    # path of this YAML relative to the data repo root → GitHub source link
    try:
        rel = entry['path'].relative_to(REPO_ROOT).as_posix()
        source_url = f'{GITHUB_BLOB}/{rel}'
    except Exception:
        source_url = ''

    if is_rollup:
        summ = doc.get('rollup_summary', {})
        title = first_str(summ, 'title') or entry['path'].stem
        rid   = first_str(summ, 'rollup_id')
        ptype = first_str(summ, 'period_type') or first_str(summ, 'rollup_type')
        period = first_str(summ, 'period')
        badge = ' · '.join(x for x in ['ROLLUP', ptype.title() if ptype else '', period] if x)
        exec_sum = first_str(summ, 'executive_summary')
        body_root = {k: v for k, v in doc.items() if k != 'rollup_summary'}
    else:
        summ = doc.get('threat_summary', {})
        title = first_str(summ, 'title') or entry['path'].stem
        rid   = first_str(summ, 'threat_id')
        sev_b = first_str(summ, 'severity_business')
        sev_t = first_str(summ, 'severity_technical')
        date  = pretty_date(entry['date'])
        parts = [date]
        if sev_b: parts.append(f'Business: {sev_b}')
        if sev_t: parts.append(f'Technical: {sev_t}')
        badge = ' · '.join(parts)
        exec_sum = first_str(summ, 'executive_summary')
        body_root = {k: v for k, v in doc.items() if k != 'threat_summary'}

    html = ['<article>']
    html.append('<header class="rep-header">')
    cls = 'badge rollup-badge' if is_rollup else 'badge'
    html.append(f'<div class="{cls}">{H(badge)}</div>')
    html.append(f'<h1>{H(title)}</h1>')
    if rid:
        html.append(f'<div class="rid">{H(rid)}</div>')
    if source_url:
        html.append(f'<a class="src-link" href="{H(source_url)}" target="_blank" rel="noopener">View raw analysis on GitHub ↗</a>')
    html.append('</header>')

    if exec_sum:
        html.append('<div class="box exec"><div class="box-label">Executive Summary</div>')
        for para in exec_sum.split('\n\n'):
            p = para.strip()
            if p:
                html.append(f'<p class="prose">{H(p)}</p>')
        html.append('</div>')

    # main body blocks
    blocks = extract(body_root)
    seen = set()
    for b in blocks:
        t = b['type']
        lvl = b.get('level', 0)
        if t == 'subheading':
            txt = b['text']
            sig = ('SH', txt[:60])
            if sig in seen:
                continue
            seen.add(sig)
            tag = 'h2' if lvl <= 1 else 'h3' if lvl <= 3 else 'h4'
            html.append(f'<{tag} class="sh{min(lvl,3)}">{H(txt)}</{tag}>')
        elif t == 'prose':
            txt = b['text']
            sig = ('P', txt[:60])
            if sig in seen:
                continue
            seen.add(sig)
            html.append(f'<p class="prose">{H(txt)}</p>')
        elif t == 'code':
            html.append(f'<pre class="code"><code>{H(b["text"])}</code></pre>')
        elif t == 'kv':
            html.append(f'<div class="kv"><span class="kv-k">{H(b["k"])}</span>'
                        f'<span class="kv-v">{H(b["v"])}</span></div>')
        elif t == 'list':
            if isinstance(b['text'], list):
                html.append('<ul class="blist">')
                for it in b['text']:
                    html.append(f'<li>{H(str(it))}</li>')
                html.append('</ul>')

    # sources last (only on daily reports; rollups point to archive)
    if not is_rollup:
        html.append(render_sources(doc))

    html.append('</article>')
    return '\n'.join(html), title

# ── HTML shell (CSS + JS) ─────────────────────────────────────────────────────

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#ffffff;--bg2:#f6f8fa;--bg3:#eceff3;
  --txt:#16191d;--txt2:#444b54;--txt3:#8a929c;
  --border:#e1e5ea;--acc:#b3261e;--acc-bg:#fdeceb;
  --crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4a6;
  --code-bg:#1e1e2e;--code-txt:#cdd6f4;
  --serif:Georgia,'Times New Roman',serif;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'SFMono-Regular',Consolas,'Liberation Mono',monospace;
  --sidebar:300px;--max-prose:720px;
}
@media(prefers-color-scheme:dark){
  :root{
    --bg:#121417;--bg2:#1a1d21;--bg3:#202327;
    --txt:#e6e9ed;--txt2:#a8b0ba;--txt3:#6b7280;
    --border:#2a2e34;--acc:#f87171;--acc-bg:#2a1514;
    --code-bg:#0d0d16;
  }
}
html,body{height:100%;background:var(--bg3);color:var(--txt);font-family:var(--sans);
  -webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}

.shell{display:flex;height:100vh;overflow:hidden}
.sidebar{width:var(--sidebar);min-width:var(--sidebar);background:var(--bg);
  border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.main{flex:1;overflow-y:auto;background:var(--bg3)}

.s-top{padding:1.2rem 1.1rem .9rem;border-bottom:1px solid var(--border);flex-shrink:0}
.s-brand{font-size:15px;font-weight:700;color:var(--txt);letter-spacing:-.01em}
.s-tag{font-size:11px;color:var(--txt3);margin-top:3px;line-height:1.4}
.s-search{padding:9px 11px;border-bottom:1px solid var(--border);flex-shrink:0}
.s-search input{width:100%;padding:7px 10px;font-size:12.5px;border:1px solid var(--border);
  border-radius:7px;background:var(--bg2);color:var(--txt);outline:none}
.s-search input:focus{border-color:var(--acc)}
.s-scroll{flex:1;overflow-y:auto;padding:6px 0}
.s-foot{padding:.7rem 1.1rem;border-top:1px solid var(--border);flex-shrink:0;
  display:flex;flex-direction:column;gap:5px}
.s-foot a{font-size:11px;color:var(--txt3)}

.nav-sec{padding:.5rem 1.1rem .25rem;font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--txt3)}
.nav-item{width:100%;padding:.5rem 1.1rem;font-size:12.5px;color:var(--txt2);
  background:none;border:none;border-left:2px solid transparent;cursor:pointer;
  text-align:left;line-height:1.4;display:block}
.nav-item:hover{background:var(--bg2);color:var(--txt)}
.nav-item.active{border-left-color:var(--acc);color:var(--acc);background:var(--acc-bg)}
.nav-date{font-size:10px;color:var(--txt3);margin-bottom:1px}
.nav-item.active .nav-date{color:var(--acc)}
.nav-roll{font-weight:600}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;
  vertical-align:middle}
.dot.critical{background:var(--crit)}.dot.high{background:var(--high)}
.dot.medium{background:var(--med)}.dot.low{background:var(--low)}

#rbar{height:2px;background:var(--acc);position:fixed;top:0;left:var(--sidebar);
  z-index:100;pointer-events:none;transition:width .15s}

.c-outer{max-width:calc(var(--max-prose) + 4rem);margin:0 auto;padding:2.5rem 2.2rem 8rem}

.rep-header{margin-bottom:1.8rem;padding-bottom:1.4rem;border-bottom:1px solid var(--border)}
.badge{display:inline-block;font-size:11px;color:var(--txt3);font-weight:600;
  text-transform:uppercase;letter-spacing:.05em;margin-bottom:.6rem;font-family:var(--sans)}
.rollup-badge{color:var(--acc)}
h1{font-family:var(--serif);font-size:2.05rem;font-weight:400;line-height:1.18;
  color:var(--txt);letter-spacing:-.015em}
.rid{font-family:var(--mono);font-size:11px;color:var(--txt3);margin-top:.6rem}
.src-link{display:inline-block;margin-top:.7rem;font-family:var(--sans);font-size:12px;
  font-weight:600;color:var(--txt3);border:1px solid var(--border);border-radius:6px;
  padding:4px 10px}
.src-link:hover{color:var(--acc);border-color:var(--acc);text-decoration:none}

.box{background:var(--bg2);border:1px solid var(--border);border-radius:11px;
  padding:1.2rem 1.4rem;margin-bottom:1.8rem}
.exec{border-left:3px solid var(--acc)}
.box-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  color:var(--txt3);margin-bottom:.7rem;font-family:var(--sans)}

.sh0,.sh1{font-family:var(--serif);font-size:1.4rem;font-weight:400;color:var(--txt);
  margin:2.2rem 0 .8rem;padding-top:1.4rem;border-top:1px solid var(--border)}
.sh2{font-family:var(--sans);font-size:1.02rem;font-weight:600;color:var(--txt);
  margin:1.6rem 0 .5rem}
.sh3{font-family:var(--sans);font-size:.88rem;font-weight:600;color:var(--txt2);
  margin:1.2rem 0 .4rem;text-transform:uppercase;letter-spacing:.04em}
.prose{font-family:var(--serif);font-size:17px;line-height:1.8;color:var(--txt);
  margin-bottom:1.1rem;white-space:pre-wrap;word-break:break-word}
.box .prose:last-child{margin-bottom:0}
.code{background:var(--code-bg);color:var(--code-txt);font-family:var(--mono);
  font-size:13px;line-height:1.6;padding:1.1rem 1.3rem;border-radius:8px;
  overflow-x:auto;margin:1rem 0 1.5rem;white-space:pre}
.blist{margin:0 0 1.2rem 1.3rem}
.blist li{font-family:var(--sans);font-size:15px;line-height:1.65;color:var(--txt2);
  padding:.22rem 0}
.kv{display:flex;flex-direction:column;gap:2px;padding:.6rem .9rem;margin:.5rem 0;
  background:var(--bg2);border:1px solid var(--border);border-radius:8px}
.kv-k{font-family:var(--sans);font-size:13.5px;font-weight:600;color:var(--txt)}
.kv-v{font-family:var(--sans);font-size:13.5px;line-height:1.55;color:var(--txt2)}

.sources{margin-top:2.5rem;padding-top:1.6rem;border-top:2px solid var(--border)}
.src-list{list-style:none}
.src-list li{padding:.55rem 0;border-bottom:1px solid var(--border)}
.src-list li:last-child{border-bottom:none}
.src-t{font-family:var(--sans);font-size:14px;line-height:1.5;color:var(--txt)}
.src-m{font-family:var(--sans);font-size:11.5px;color:var(--txt3);margin-top:2px}

.welcome{padding:3rem 2.2rem}
.welcome h1{font-size:2.5rem;margin-bottom:.5rem}
.w-tag{font-family:var(--serif);font-size:1.15rem;color:var(--txt2);font-style:italic;
  margin-bottom:2rem}
.w-meta{font-size:13px;color:var(--txt3);display:flex;flex-wrap:wrap;gap:1rem;
  margin-bottom:2rem;font-family:var(--sans)}
.w-meta span+span::before{content:'·';margin-right:1rem}
.w-body{font-family:var(--serif);font-size:16px;line-height:1.8;color:var(--txt2);
  max-width:560px;margin-bottom:1.8rem}
.start{display:inline-block;padding:.7rem 1.5rem;background:var(--acc);color:#fff;
  border-radius:7px;font-size:14px;font-weight:500;cursor:pointer;border:none;
  font-family:var(--sans)}

.menu-fab{display:none;position:fixed;bottom:1rem;right:1rem;z-index:200;
  padding:9px 15px;background:var(--bg);border:1px solid var(--border);
  border-radius:9px;font-size:13px;color:var(--txt2);cursor:pointer;
  box-shadow:0 2px 12px rgba(0,0,0,.18)}
@media(max-width:768px){
  .sidebar{position:fixed;left:0;top:0;height:100%;z-index:150;
    transform:translateX(-110%);transition:transform .2s;width:290px}
  .sidebar.open{transform:translateX(0)}
  #rbar{left:0}
  .menu-fab{display:block}
  .c-outer{padding:1.6rem 1.1rem 6rem}
  h1{font-size:1.6rem}
  .prose{font-size:15.5px}
}
"""

JS = """
const REPORTS=__REPORTS__;
const ROLLUPS=__ROLLUPS__;
const DOCS=__DOCS__;
let active=null;

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function buildNav(){
  const el=document.getElementById('nav');
  if(ROLLUPS.length){
    const h=document.createElement('div');h.className='nav-sec';h.textContent='Rollups';el.appendChild(h);
    ROLLUPS.forEach(r=>{
      const b=document.createElement('button');b.className='nav-item nav-roll';b.dataset.id=r.id;
      b.innerHTML=`${esc(r.label)}`;
      b.addEventListener('click',()=>{load(r.id);closeMobile();});
      el.appendChild(b);
    });
  }
  const h2=document.createElement('div');h2.className='nav-sec';h2.textContent='Daily Reports';el.appendChild(h2);
  REPORTS.forEach(r=>{
    const b=document.createElement('button');b.className='nav-item';b.dataset.id=r.id;
    const sev=(r.sev||'').toLowerCase();
    b.innerHTML=`<div class="nav-date">${esc(r.datePretty)}</div>`+
      `<span class="dot ${sev}"></span>${esc(r.title)}`;
    b.addEventListener('click',()=>{load(r.id);closeMobile();});
    el.appendChild(b);
  });
}

function load(id){
  const html=DOCS[id];
  if(!html)return;
  document.getElementById('content').innerHTML='<div class="c-outer">'+html+'</div>';
  document.getElementById('main').scrollTop=0;
  if(active)active.classList.remove('active');
  const btn=document.querySelector('.nav-item[data-id="'+CSS.escape(id)+'"]');
  if(btn){btn.classList.add('active');active=btn;btn.scrollIntoView({block:'nearest'});}
  document.getElementById('rbar').style.width='0';
  location.hash=id;
}

document.getElementById('main').addEventListener('scroll',function(){
  const pct=this.scrollTop/(this.scrollHeight-this.clientHeight)||0;
  document.getElementById('rbar').style.width=Math.round(pct*100)+'%';
});

document.getElementById('search').addEventListener('input',function(){
  const q=this.value.toLowerCase();
  document.querySelectorAll('.nav-item').forEach(b=>{
    b.style.display=!q||b.textContent.toLowerCase().includes(q)?'':'none';
  });
});

function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');}
function closeMobile(){if(window.innerWidth<=768)document.getElementById('sidebar').classList.remove('open');}

buildNav();
// deep link
if(location.hash){const id=location.hash.slice(1);if(DOCS[id])load(id);}
"""

SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Global Threat Intelligence — AmDumDee</title>
<meta name="description" content="Daily executive cybersecurity threat intelligence. Original analysis translating real threats into board-level business decisions. Every report sourced.">
<meta name="author" content="Am Dum Dee">
<meta name="keywords" content="threat intelligence, cybersecurity, CISO, board governance, cyber risk, executive briefing">
<meta property="og:title" content="Global Threat Intelligence — AmDumDee">
<meta property="og:description" content="Daily executive threat intelligence. Original analysis, business-translated, every source cited.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://amdumdee.com">
<style>__CSS__</style>
</head>
<body>
<div id="rbar"></div>
<button class="menu-fab" onclick="toggleSidebar()">☰ Reports</button>
<div class="shell">
  <nav class="sidebar" id="sidebar">
    <div class="s-top">
      <div class="s-brand">Global Threat Intelligence</div>
      <div class="s-tag">Executive cyber risk, translated. Daily. Every source cited.</div>
    </div>
    <div class="s-search"><input id="search" type="search" placeholder="Search reports…"></div>
    <div class="s-scroll" id="nav"></div>
    <div class="s-foot">
      <a href="/">← amdumdee.com</a>
      <a href="https://github.com/AmDumDee/global-threat-intel" target="_blank">GitHub ↗</a>
      <a href="https://linkedin.com/in/amdumdee" target="_blank">LinkedIn ↗</a>
    </div>
  </nav>
  <main class="main" id="main">
    <div id="content">
      <div class="c-outer welcome">
        <h1>Global Threat Intelligence</h1>
        <p class="w-tag">Executive cyber risk, translated — daily.</p>
        <div class="w-meta">
          <span>__COUNT__ reports</span>
          <span>Business-focused</span>
          <span>Original analysis</span>
          <span>Every source cited</span>
        </div>
        <p class="w-body">Cybersecurity threats explained for the people who make the decisions — CISOs, CTOs, and boards. Not CVE scores. Not vendor pitches. Just what each threat means for revenue, liability, and governance, with every claim traced to its source.</p>
        <button class="start" onclick="load((ROLLUPS[0]||REPORTS[0]).id)">Read the latest →</button>
      </div>
    </div>
  </main>
</div>
<script>
__JS__
</script>
</body>
</html>"""

# ── Build ─────────────────────────────────────────────────────────────────────

def main():
    OUT_DIR.mkdir(exist_ok=True)
    reports, rollups = discover()
    print(f"Found {len(reports)} reports, {len(rollups)} rollups")

    docs = {}
    rep_nav, roll_nav = [], []
    errors = []

    for entry in reports:
        rid = entry['date'] + '-' + re.sub(r'[^a-z0-9]+', '-', entry['slug'].lower())[:40]
        try:
            html, title = render_report(entry, is_rollup=False)
            docs[rid] = html
            doc = load_yaml(entry['path'])
            sev = first_str(doc.get('threat_summary', {}), 'severity_business') or \
                  (deep_find(doc, 'severity_business') or '')
            rep_nav.append({'id': rid, 'title': title, 'date': entry['date'],
                            'datePretty': pretty_date(entry['date']),
                            'sev': sev if isinstance(sev, str) else ''})
        except Exception as e:
            errors.append((entry['path'].name, str(e)))

    for entry in rollups:
        rid = f"rollup-{entry['year']}-{entry['period']}".lower()
        try:
            html, title = render_report(entry, is_rollup=True)
            docs[rid] = html
            label = f"{entry['year']} {entry['period']}"
            roll_nav.append({'id': rid, 'label': label, 'title': title})
        except Exception as e:
            errors.append((entry['path'].name, str(e)))

    reports_json = json.dumps(rep_nav, separators=(',', ':'))
    rollups_json = json.dumps(roll_nav, separators=(',', ':'))
    docs_json = json.dumps(docs, separators=(',', ':'))

    js = (JS.replace('__REPORTS__', reports_json)
            .replace('__ROLLUPS__', rollups_json)
            .replace('__DOCS__', docs_json))
    html = (SHELL.replace('__CSS__', CSS)
                 .replace('__JS__', js)
                 .replace('__COUNT__', str(len(reports))))


    # ── sitemap.xml (root-level, covers landing + all reports) ──
    base = 'https://amdumdee.com'
    urls = [f'{base}/', f'{base}/threat-intel/']
    for r in rep_nav:
        urls.append(f"{base}/threat-intel/#{r['id']}")
    for r in roll_nav:
        urls.append(f"{base}/threat-intel/#{r['id']}")
    sm = ['<?xml version="1.0" encoding="UTF-8"?>',
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        sm.append(f'  <url><loc>{u}</loc></url>')
    sm.append('</urlset>')
    Path('sitemap.xml').write_text('\n'.join(sm), encoding='utf-8')

    # ── llms.txt (AI-readable summary, aids citation) ──
    newest = rep_nav[:15]
    lines = [
        '# AmDumDee — Global Threat Intelligence',
        '',
        '> Executive cybersecurity threat intelligence. Original analysis that translates',
        '> current threats into board-level business decisions for CISOs, CTOs, and board',
        '> members. No CVE scores, no vendor pitches. Every report cites its sources.',
        '',
        'Site: https://amdumdee.com',
        'Threat intel archive: https://amdumdee.com/threat-intel/',
        'Source repository: https://github.com/AmDumDee/global-threat-intel',
        f'Total reports: {len(rep_nav)}',
        '',
        '## How to cite',
        'Reports are identified by threat_id (e.g. TI-20260604-001). When referencing,',
        'attribute to "AmDumDee Global Threat Intelligence" with the report title and date.',
        '',
        '## Most recent reports',
    ]
    for r in newest:
        lines.append(f"- {r['datePretty']}: {r['title']} (https://amdumdee.com/threat-intel/#{r['id']})")
    lines.append('')
    Path('llms.txt').write_text('\n'.join(lines), encoding='utf-8')
    print(f"  + sitemap.xml ({len(urls)} urls), llms.txt")

    out = OUT_DIR / 'index.html'
    out.write_text(html, encoding='utf-8')
    kb = out.stat().st_size // 1024
    print(f"\n✓ {out} — {kb} KB, {len(docs)} pages, {len(errors)} errors")
    for n, e in errors[:8]:
        print(f"  ! {n}: {e}")

if __name__ == '__main__':
    main()
