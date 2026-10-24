"""Desktop-style GUI — a local web app served by the program itself.

    aishield gui [--port 8770]

Same idea as the settings page, grown into the full app: a
Hermes-desktop-style interface (sidebar + panels) that runs every
front door the CLI/MCP expose — dashboard, scan, patch, latest CVEs,
CVE lookup, settings. It is served from 127.0.0.1 by the stdlib HTTP
server and opened in the machine's own browser, so the SAME gui works
on Windows, macOS and Linux with no extra program, no build step and
no dependencies. Local-only by design: it can apply patches, so it
never binds beyond loopback.
"""
import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, ai, config as cfgmod, cvenow, engine, feeds
from . import inventory, patch, report as reportmod, transport


# ------------------------------------------------------------------ API
def api_status():
    kev_map, kev_date = feeds.kev()
    cfg = cfgmod.load()
    try:
        cvenow.list_feed(filter=["critical"], limit=1)
        cve_ok = True
    except Exception:
        cve_ok = False
    return {
        "version": __version__,
        "kev_count": len(kev_map), "kev_date": kev_date,
        "cvenow_reachable": cve_ok,
        "server_url": cfg["server"]["url"],
        "triage_configured": cfg["roles"]["triage"]["model"],
        "triage_resolved": ai.triage_model(),
        "decision": cfg["roles"]["decision"],
        "targets": inventory.targets(),
        "local_enabled": transport.local_enabled(),
        "local_kind": inventory.local_kind(),
        "hosts": transport.hosts(),
        "models_loaded": ai.loaded_models(),
    }


def api_latest(source, limit=20, ecosystem=None):
    if source == "kev":
        feed = cvenow.list_feed(name="kev", limit=limit)
    elif source == "all":
        feed = cvenow.list_feed(name="all", ecosystem=ecosystem, limit=limit)
    else:
        feed = cvenow.list_feed(filter=["critical"], ecosystem=ecosystem,
                                limit=limit)
    items = (feed.get("items") or feed.get("entries")
             or feed.get("vulnerabilities") or [])
    out = []
    for it in items:
        if isinstance(it, dict):
            out.append({
                "id": it.get("id") or it.get("cve_id") or it.get("cveID"),
                "summary": (it.get("summary") or it.get("title") or "")[:220],
                "severity": it.get("severity") or it.get("cvss") or "",
                "published": it.get("published") or it.get("date") or "",
            })
    return {"items": out}


def api_cve(cve_id):
    out = {"cve_id": cve_id, "found": False, "cvenow": None, "kev": None,
           "nvd": None}
    try:
        out["cvenow"] = cvenow.get_vulnerability(cve_id)
    except Exception:
        out["cvenow"] = None
    kev_map, _ = feeds.kev()
    out["kev"] = kev_map.get(cve_id.upper())
    try:
        out["nvd"] = feeds.nvd_cve(cve_id)
    except Exception:
        out["nvd"] = None
    out["found"] = bool(out["cvenow"] or out["kev"] or out["nvd"])
    return out


def api_scan(body):
    target = body.get("target") or "local"
    result = engine.run_scan(
        target, program=body.get("program") or None,
        use_ai=bool(body.get("ai")), adjudicate_apps=True)
    result["report_text"] = engine.format_report(result)
    return result


def api_patch_plan(body):
    result = engine.run_scan(body.get("target") or "local",
                             program=body.get("program") or None)
    return {"target": result["target"],
            "findings_count": len(result["findings"]),
            "plan": result["plan"]}


def api_patch_apply(body):
    if body.get("confirm") != "PATCH":
        return {"error": "type PATCH in the confirm box to apply"}
    target = body.get("target") or "local"
    before = engine.run_scan(target, program=body.get("program") or None)
    outcome = patch.apply_plan(before["plan"], confirm="PATCH")
    after = engine.run_scan(target, program=body.get("program") or None)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf = reportmod.write_run_report(base, target, before, outcome, after)
    return {"outcome": outcome, "report_pdf": pdf,
            "findings_before": len(before["findings"]),
            "findings_after": len([f for f in after["findings"]
                                   if f["confidence"] != "error"])}


def api_config_get():
    cfg = cfgmod.load()
    srv = dict(cfg["server"])
    srv["api_key_set"] = bool(srv.pop("api_key", None))
    return {"server": srv, "roles": cfg["roles"],
            "local_enabled": transport.local_enabled(),
            "hosts": transport.hosts()}


def api_config_save(body):
    cfg = cfgmod.load()
    srv = body.get("server") or {}
    if srv.get("url"):
        cfg["server"]["url"] = str(srv["url"]).rstrip("/")
    if srv.get("api_key"):
        cfg["server"]["api_key"] = srv["api_key"]
    if srv.get("proxy_mode"):
        cfg["server"]["proxy_mode"] = srv["proxy_mode"]
        try:
            cfg["server"]["proxy_port"] = int(srv.get("proxy_port"))
        except (TypeError, ValueError):
            pass
    else:
        cfg["server"].pop("proxy_mode", None)
        cfg["server"].pop("proxy_port", None)
    cfg["roles"]["triage"]["model"] = body.get("triage") or None
    cfg["roles"]["decision"]["model"] = body.get("decision") or None
    cfg["roles"]["decision"]["fallback"] = body.get("decision_fallback") or None
    if body.get("endpoint"):
        cfg["roles"]["decision"]["endpoint"] = body["endpoint"]
    cfgmod.save(cfg)
    entries = {}
    for h in body.get("hosts") or []:
        name = (h.get("name") or "").strip()
        if name and h.get("host") and h.get("user"):
            entry = {"os": h.get("os") or "linux", "host": h["host"],
                     "user": h["user"], "enabled": bool(h.get("enabled"))}
            try:
                entry["port"] = int(h.get("port") or 22)
            except (TypeError, ValueError):
                entry["port"] = 22
            if h.get("proxy"):
                entry["proxy"] = h["proxy"]
            entries[name] = entry
    transport.save_all_hosts(entries,
                             local_enabled=bool(body.get("local_enabled")))
    return {"saved": True, "targets": inventory.targets()}


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        try:
            if u.path == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if u.path == "/api/status":
                return self._send(200, api_status())
            if u.path == "/api/models":
                return self._send(200, ai.loaded_models())
            if u.path == "/api/config":
                return self._send(200, api_config_get())
            if u.path == "/api/latest":
                q = parse_qs(u.query)
                return self._send(200, api_latest(
                    (q.get("source") or ["critical"])[0],
                    limit=int((q.get("limit") or ["20"])[0])))
            if u.path.startswith("/api/cve/"):
                return self._send(200, api_cve(u.path.rsplit("/", 1)[-1]))
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)[:400]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        try:
            if self.path == "/api/scan":
                return self._send(200, api_scan(body))
            if self.path == "/api/patch/plan":
                return self._send(200, api_patch_plan(body))
            if self.path == "/api/patch/apply":
                return self._send(200, api_patch_apply(body))
            if self.path == "/api/config":
                return self._send(200, api_config_save(body))
            return self._send(404, {"error": "not found"})
        except RuntimeError as e:
            return self._send(200, {"error": str(e)[:400]})
        except Exception as e:
            return self._send(500, {"error": str(e)[:400]})


def serve(port=8770, open_browser=True):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"AI Shield GUI: {url}  (Ctrl-C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGUI stopped")
    return 0


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Shield</title>
<style>
 :root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2a3242;--txt:#e6ebf2;--dim:#8b94a7;--acc:#3fb68b;--warn:#e3b341;--bad:#f47067}
 *{box-sizing:border-box} body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--txt);display:flex;min-height:100vh}
 nav{width:215px;background:var(--panel);border-right:1px solid var(--line);padding:1rem .7rem;flex:none;display:flex;flex-direction:column;gap:.25rem}
 nav .logo{font-size:1.15rem;font-weight:700;padding:.3rem .6rem 1rem}
 nav button{background:none;border:0;color:var(--dim);text-align:left;padding:.55rem .6rem;border-radius:7px;font:inherit;cursor:pointer}
 nav button.on{background:var(--panel2);color:var(--txt)}
 nav button:hover{color:var(--txt)}
 nav .foot{margin-top:auto;color:var(--dim);font-size:.8rem;padding:.6rem}
 main{flex:1;padding:1.4rem 1.6rem;max-width:1060px}
 h1{font-size:1.3rem;margin:.1rem 0 1rem} h2{font-size:1.05rem;margin:1.4rem 0 .6rem}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem}
 .card b{font-size:1.35rem;display:block} .card span{color:var(--dim);font-size:.85rem}
 table{width:100%;border-collapse:collapse;font-size:.92rem}
 th,td{border-bottom:1px solid var(--line);padding:.45rem .5rem;text-align:left;vertical-align:top}
 th{color:var(--dim);font-weight:600}
 .badge{border-radius:5px;padding:.05rem .45rem;font-size:.78rem;background:var(--panel2);border:1px solid var(--line)}
 .kev{background:#4a2320;border-color:#7a352c;color:#ffb4ab} .crit{color:var(--bad)} .ok{color:var(--acc)}
 input,select,textarea{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:.45rem;font:inherit}
 button.act{background:var(--acc);color:#06251a;border:0;border-radius:6px;padding:.5rem 1.1rem;font:inherit;font-weight:600;cursor:pointer}
 button.ghost{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:.5rem 1rem;font:inherit;cursor:pointer}
 label{display:block;margin:.65rem 0 .2rem;font-weight:600}
 .row{display:flex;gap:.8rem;flex-wrap:wrap;align-items:end} .row>div{flex:1;min-width:160px}
 pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.8rem;white-space:pre-wrap;font-size:.85rem}
 .dim{color:var(--dim)} .spin{color:var(--warn)} .host{border:1px solid var(--line);border-radius:8px;padding:.7rem;margin:.5rem 0;background:var(--panel)}
 .view{display:none} .view.on{display:block}
</style></head><body>
<nav>
 <div class="logo">🛡️ AI Shield</div>
 <button data-v="dash" class="on">Dashboard</button>
 <button data-v="scan">Scan</button>
 <button data-v="patch">Patch</button>
 <button data-v="latest">Latest CVEs</button>
 <button data-v="cve">CVE lookup</button>
 <button data-v="settings">Settings</button>
 <div class="foot" id="ver"></div>
</nav>
<main>
 <section id="v-dash" class="view on"><h1>Dashboard</h1><div class="cards" id="cards"></div>
  <h2>Targets</h2><div id="targets"></div>
  <p class="dim">The shield is designed to run on each machine itself — remote machines scan only when you enable them in Settings.</p></section>
 <section id="v-scan" class="view"><h1>Scan</h1>
  <div class="row"><div><label>Target</label><select id="scan-target"></select></div>
  <div><label>Program filter (optional)</label><input id="scan-program" placeholder="e.g. chrome"></div>
  <div><label><input type="checkbox" id="scan-ai" style="width:auto"> AI brief</label></div>
  <div><button class="act" id="scan-go">Run scan</button></div></div>
  <p id="scan-state" class="dim"></p><div id="scan-out"></div></section>
 <section id="v-patch" class="view"><h1>Patch</h1>
  <div class="row"><div><label>Target</label><select id="patch-target"></select></div>
  <div><button class="ghost" id="plan-go">Dry-run plan</button></div></div>
  <div id="plan-out"></div>
  <h2>Apply</h2><p class="dim">Held steps (lifelines, decision holds, unconfirmed matches) never auto-apply. A PDF report is written to data/reports/.</p>
  <div class="row"><div><label>Type PATCH to confirm</label><input id="apply-confirm" placeholder="PATCH"></div>
  <div><button class="act" id="apply-go">Apply patch plan</button></div></div>
  <pre id="apply-out" style="display:none"></pre></section>
 <section id="v-latest" class="view"><h1>Latest CVEs</h1>
  <div class="row"><div><label>Source</label><select id="latest-src"><option value="critical">critical (CVE Now)</option><option value="kev">known-exploited (KEV)</option><option value="all">all</option></select></div>
  <div><button class="ghost" id="latest-go">Load</button></div></div><div id="latest-out"></div></section>
 <section id="v-cve" class="view"><h1>CVE lookup</h1>
  <div class="row"><div><label>CVE id</label><input id="cve-id" placeholder="CVE-2026-111497"></div>
  <div><button class="ghost" id="cve-go">Look up</button></div></div><pre id="cve-out" style="display:none"></pre></section>
 <section id="v-settings" class="view"><h1>Settings</h1><div id="settings-out"></div></section>
</main>
<script>
const $=s=>document.querySelector(s), $$=s=>document.querySelectorAll(s);
async function api(p,o){const r=await fetch(p,o);return r.json();}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
let STATUS=null;
$$('nav button').forEach(b=>b.onclick=()=>{$$('nav button').forEach(x=>x.classList.remove('on'));b.classList.add('on');$$('.view').forEach(v=>v.classList.remove('on'));$('#v-'+b.dataset.v).classList.add('on');if(b.dataset.v==='settings')loadSettings();});
async function loadStatus(){
 STATUS=await api('/api/status');
 $('#ver').textContent='v'+STATUS.version+' · local '+(STATUS.local_enabled?'on':'off');
 $('#cards').innerHTML=[['KEV catalog',STATUS.kev_count],['KEV released',(STATUS.kev_date||'').slice(0,10)],['CVE Now',STATUS.cvenow_reachable?'reachable':'unreachable'],['Main model',STATUS.triage_resolved||'offline'],['Decision model',STATUS.decision.model||'main model'],['Targets',STATUS.targets.join(', ')||'none']].map(c=>`<div class="card"><b>${esc(c[1])}</b><span>${esc(c[0])}</span></div>`).join('');
 $('#targets').innerHTML='<table><tr><th>Target</th><th>Kind</th><th>Detail</th></tr>'+STATUS.targets.map(t=>{const h=STATUS.hosts[t];return `<tr><td>${esc(t)}</td><td>${h?esc(h.os):esc(STATUS.local_kind)}</td><td>${h?esc(h.user+'@'+h.host):'this machine'}</td></tr>`;}).join('')+'</table>';
 const opts=STATUS.targets.map(t=>`<option>${esc(t)}</option>`).join('');
 $('#scan-target').innerHTML=opts; $('#patch-target').innerHTML=opts;
}
$('#scan-go').onclick=async()=>{
 const body={target:$('#scan-target').value,program:$('#scan-program').value,ai:$('#scan-ai').checked};
 $('#scan-state').innerHTML='<span class="spin">scanning… (can take a minute on a cold cache)</span>';$('#scan-out').innerHTML='';
 const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 if(r.error){$('#scan-state').textContent='error: '+r.error;return;}
 $('#scan-state').textContent=`${r.inventory_count} items · ${r.findings.length} findings · ${r.elapsed_s}s`;
 const rows=r.findings.map(f=>`<tr><td>${esc(f.name)} ${esc(f.version)}</td><td>${(f.cve_ids||[]).map(esc).join('<br>')}</td><td>${f.known_exploited?'<span class="badge kev">KEV</span> ':''}<span class="badge">${esc(f.severity||'')}</span></td><td>${esc((f.fixed_versions||[]).join(', '))}</td><td class="dim">${esc(f.confidence)}</td></tr>`).join('');
 $('#scan-out').innerHTML=(r.warnings&&r.warnings.length?`<p class="spin">⚠ ${r.warnings.map(esc).join('<br>')}</p>`:'')+`<table><tr><th>Package</th><th>CVEs</th><th>Severity</th><th>Fixed in</th><th>Confidence</th></tr>${rows||'<tr><td colspan=5 class="ok">no findings</td></tr>'}</table>`+(r.ai_brief?`<h2>AI brief (${esc(r.ai_model||'')})</h2><pre>${esc(r.ai_brief)}</pre>`:'');
};
$('#plan-go').onclick=async()=>{
 $('#plan-out').innerHTML='<span class="spin">planning…</span>';
 const r=await api('/api/patch/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value})});
 if(r.error){$('#plan-out').textContent='error: '+r.error;return;}
 const rows=(r.plan.steps||[]).map(s=>`<tr><td>${esc(s.name)}</td><td class="dim">${esc(s.command||s.note||'')}</td><td>${s.auto?'<span class="ok">auto</span>':'held/manual'}</td><td>${esc(s.decision||'')}${s.decision_reason?' — '+esc(s.decision_reason):''}</td></tr>`).join('');
 $('#plan-out').innerHTML=`<p>${r.findings_count} findings → ${(r.plan.steps||[]).length} steps</p><table><tr><th>Package</th><th>Command / note</th><th>Mode</th><th>Decision</th></tr>${rows}</table>`;
};
$('#apply-go').onclick=async()=>{
 const out=$('#apply-out');out.style.display='block';out.textContent='applying…';
 const r=await api('/api/patch/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value,confirm:$('#apply-confirm').value})});
 out.textContent=r.error?('error: '+r.error):JSON.stringify(r,null,1);
};
$('#latest-go').onclick=async()=>{
 $('#latest-out').innerHTML='<span class="spin">loading…</span>';
 const r=await api('/api/latest?source='+$('#latest-src').value);
 $('#latest-out').innerHTML='<table><tr><th>CVE</th><th>Severity</th><th>Summary</th></tr>'+(r.items||[]).map(i=>`<tr><td>${esc(i.id)}</td><td>${esc(i.severity)}</td><td>${esc(i.summary)}</td></tr>`).join('')+'</table>';
};
$('#cve-go').onclick=async()=>{
 const out=$('#cve-out');out.style.display='block';out.textContent='looking up…';
 const r=await api('/api/cve/'+encodeURIComponent($('#cve-id').value.trim()));
 out.textContent=r.found?JSON.stringify(r,null,1):'not found in CVE Now, KEV or NVD';
};
async function loadSettings(){
 const c=await api('/api/config');
 const hostRows=Object.entries(c.hosts).map(([n,h])=>hostRow({name:n,...h})).join('');
 $('#settings-out').innerHTML=`
 <h2>Model provider</h2>
 <label>Server base URL</label><input id="s-url" value="${esc(c.server.url)}" style="width:100%">
 <label>API key ${c.server.api_key_set?'(saved — blank keeps it)':'(blank = none)'}</label><input id="s-key" type="password" style="width:100%">
 <div class="row"><div><label>Main model (blank = auto)</label><input id="s-triage" list="s-models" value="${esc(c.roles.triage.model||'')}"></div>
 <div><label>Decision model (optional)</label><input id="s-decision" list="s-models" value="${esc(c.roles.decision.model||'')}"></div></div>
 <datalist id="s-models">${(await api('/api/models')).map(m=>`<option value="${esc(m)}">`).join('')}</datalist>
 <div class="row"><div><label>Decision fallback</label><input id="s-fb" value="${esc(c.roles.decision.fallback||'')}"></div>
 <div><label>Decision endpoint</label><input id="s-ep" value="${esc(c.roles.decision.endpoint||'/v1/systemone')}"></div></div>
 <h2>Machines</h2>
 <label style="font-weight:400"><input type="checkbox" id="s-local" ${c.local_enabled?'checked':''} style="width:auto"> <b>This device</b> — scan this machine (recommended; it's how antivirus-style tools work)</label>
 <p class="dim">Remote machines scan only with their “scan enabled” box checked.</p>
 <div id="s-hosts">${hostRows}</div>
 <button class="ghost" onclick="addHostRow()">+ add machine</button>
 <p><button class="act" id="s-save">Save settings</button> <span id="s-msg" class="ok"></span></p>`;
 $('#s-save').onclick=saveSettings;
}
function hostRow(h){
 return `<div class="host"><div class="row">
 <div><label>Name</label><input class="h-name" value="${esc(h.name||'')}"></div>
 <div><label>OS</label><select class="h-os">${['linux','macos','windows'].map(o=>`<option ${h.os===o?'selected':''}>${o}</option>`).join('')}</select></div>
 <div><label>Host</label><input class="h-host" value="${esc(h.host||'')}"></div></div>
 <div class="row"><div><label>User</label><input class="h-user" value="${esc(h.user||'')}"></div>
 <div><label>Port</label><input class="h-port" value="${esc(h.port||22)}"></div>
 <div><label>Proxy</label><input class="h-proxy" value="${esc(h.proxy||'')}" placeholder="none / env / env:3130"></div>
 <div><label>Scan enabled</label><input type="checkbox" class="h-enabled" ${h.enabled?'checked':''} style="width:auto"></div></div></div>`;
}
function addHostRow(){$('#s-hosts').insertAdjacentHTML('beforeend',hostRow({}));}
async function saveSettings(){
 const hosts=$$('#s-hosts .host').map(el=>({name:el.querySelector('.h-name').value,os:el.querySelector('.h-os').value,host:el.querySelector('.h-host').value,user:el.querySelector('.h-user').value,port:el.querySelector('.h-port').value,proxy:el.querySelector('.h-proxy').value,enabled:el.querySelector('.h-enabled').checked}));
 const body={server:{url:$('#s-url').value,api_key:$('#s-key').value},triage:$('#s-triage').value,decision:$('#s-decision').value,decision_fallback:$('#s-fb').value,endpoint:$('#s-ep').value,local_enabled:$('#s-local').checked,hosts};
 const r=await api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 $('#s-msg').textContent=r.saved?'saved ✓ targets: '+r.targets.join(', '):'error';
 loadStatus();
}
loadStatus();
</script></body></html>"""
