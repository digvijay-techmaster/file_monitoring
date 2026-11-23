"""Dashboard + JSON API.   python main.py api   ->   http://127.0.0.1:8000"""
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

# File names can contain anything (even <script>), so the page only ever uses textContent, never innerHTML.
PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>File Access Monitor</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#6b7280;--card:#f3f4f6;--line:#e5e7eb;--low:#0891b2;--medium:#d97706;--high:#dc2626;--critical:#7f1d1d}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e5e7eb;--mut:#9ca3af;--card:#1b2027;--line:#2a313a;--low:#22d3ee;--medium:#fbbf24;--high:#f87171;--critical:#fca5a5}}
body{margin:0;padding:20px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:24px 0 8px}
.sub{color:var(--mut);margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.card{background:var(--card);border-radius:8px;padding:10px 12px}.card b{display:block;font-size:22px}
.card span{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:500;font-size:12px}td.path{word-break:break-all;font-family:ui-monospace,monospace;font-size:12px}
.low{color:var(--low)}.medium{color:var(--medium)}.high{color:var(--high)}.critical{color:var(--critical);font-weight:700}
.ok{color:#16a34a}.bad{color:var(--high);font-weight:700}
.wrap{overflow-x:auto}
</style></head><body>
<h1>File Access Monitor</h1>
<div class="sub" id="status">loading...</div>
<div class="cards" id="cards"></div>
<h2>Alerts</h2><div class="wrap"><table id="alerts"></table></div>
<h2>Recent file events</h2><div class="wrap"><table id="events"></table></div>
<h2>Most changed files</h2><div class="wrap"><table id="top"></table></div>
<script>
const $ = id => document.getElementById(id);
function el(tag, text, cls){const e=document.createElement(tag); e.textContent=text==null?'':text; if(cls)e.className=cls; return e;}
function table(id, head, rows){
  const t=$(id); t.replaceChildren();
  const hr=document.createElement('tr'); head.forEach(h=>hr.appendChild(el('th',h))); t.appendChild(hr);
  rows.forEach(r=>{const tr=document.createElement('tr'); r.forEach(c=>tr.appendChild(el('td',c[0],c[1]))); t.appendChild(tr);});
}
const when = ts => (ts||'').replace('T',' ').slice(0,19);
async function load(){
  try{
    const [s,a,e,v]=await Promise.all(['summary','alerts?limit=30','events?limit=40','verify'].map(x=>fetch('/api/'+x).then(r=>r.json())));
    const sev=s.alerts_by_severity||{};
    $('cards').replaceChildren(...[['Alerts',s.alerts],['Critical',sev.critical||0],['High',sev.high||0],['Medium',sev.medium||0],['Events',s.events]].map(([k,n])=>{
      const d=document.createElement('div'); d.className='card'; d.appendChild(el('b',n)); d.appendChild(el('span',k)); return d;}));
    const chainOk=v.events.ok&&v.alerts.ok;
    const st=$('status'); st.replaceChildren(el('span','storage: '+s.storage+'   |   log integrity: '),
      el('span',chainOk?'OK (hash chain intact)':'BROKEN - logs were tampered with!',chainOk?'ok':'bad'),
      el('span','   |   monitor heartbeat: '+(s.heartbeat_age_sec==null?'never':s.heartbeat_age_sec+'s ago')));
    table('alerts',['Time','Severity','Rule','Message','Who','MITRE'],a.map(x=>[[when(x.ts)],[x.severity,x.severity],[x.rule],[x.message,'path'],[(x.user||'?')+(x.exe?' / '+x.exe:'')],[x.mitre||'']]));
    table('events',['Time','Action','Path','Who','Severity'],e.map(x=>[[when(x.ts)],[x.action],[x.path,'path'],[(x.user||'?')+(x.exe?' / '+x.exe:'')],[x.severity,x.severity]]));
    table('top',['File','Events'],s.top_paths.map(p=>[[p[0],'path'],[p[1]]]));
  }catch(err){$('status').textContent='cannot reach the API: '+err;}
}
load(); setInterval(load,3000);
</script></body></html>"""


def create_app(store):
    app = FastAPI(title="File Access Monitor")

    @app.get("/api/summary")
    def summary():
        return store.summary()

    @app.get("/api/alerts")
    def alerts(limit: int = Query(50, ge=1, le=500)):
        return store.recent("alerts", limit)

    @app.get("/api/events")
    def events(limit: int = Query(100, ge=1, le=1000)):
        return store.recent("events", limit)

    @app.get("/api/verify")
    def verify():
        out = {}
        for c in ("events", "alerts"):
            ok, n, msg = store.verify(c)
            out[c] = {"ok": ok, "checked": n, "detail": msg}
        return out

    @app.get("/", response_class=HTMLResponse)
    def home():
        return PAGE

    return app
