"""Settings page — a tiny built-in web UI for changing configuration
later, without re-running the wizard or hand-editing YAML.

    aishield settings [--port 8765]

Serves ONE self-contained page (stdlib http.server, no dependencies,
no external assets) bound to 127.0.0.1 only. It edits the same
untracked local config the wizard writes: config/models.local.yaml and
config/hosts.local.yaml. Local-only by design: anyone who can reach
the page can change the settings, so it never binds beyond loopback.
"""
import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from . import ai, config as cfgmod, inventory, transport

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Shield — settings</title>
<style>
 body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:760px;padding:0 1rem;color:#1c2333}
 h1{font-size:1.4rem} h2{font-size:1.05rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}
 label{display:block;margin:.7rem 0 .2rem;font-weight:600}
 input,select{width:100%;padding:.45rem;border:1px solid #b9c0cf;border-radius:6px;font:inherit}
 .row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
 .host{border:1px solid #dde1ea;border-radius:8px;padding:.8rem;margin:.6rem 0}
 .host .row{grid-template-columns:1fr 1fr 1fr}
 button{background:#1450a0;color:#fff;border:0;border-radius:6px;padding:.55rem 1.1rem;font:inherit;cursor:pointer}
 button.secondary{background:#e8ecf3;color:#1c2333}
 .saved{background:#e5f4e5;border:1px solid #9cc79c;padding:.6rem .8rem;border-radius:6px}
 .hint{color:#5a6376;font-size:.88rem}
</style></head><body>
<h1>🛡️ AI Shield — settings</h1>
<p class="hint">Changes save to this install's untracked local config
(<code>config/models.local.yaml</code>, <code>config/hosts.local.yaml</code>)
and apply to the next scan. This page is served on 127.0.0.1 only.</p>
__SAVED__
<form method="post" action="/save">
<h2>Model provider</h2>
<label for="server_url">Server base URL</label>
<input id="server_url" name="server_url" value="__SERVER_URL__" placeholder="http://localhost:1234">
<p class="hint">Any OpenAI-compatible server: LM Studio, Ollama
(http://localhost:11434/v1), llama.cpp, vLLM, OpenAI…</p>
<label for="api_key">API key</label>
<input id="api_key" name="api_key" type="password" value="" placeholder="__KEY_HINT__">
<label for="proxy_mode">Model-server proxy</label>
<select id="proxy_mode" name="proxy_mode">
 <option value="">none</option>
 <option value="env-connect" __PROXY_SEL__>env-connect (sandbox CONNECT proxy)</option>
</select>
<label for="proxy_port">Proxy port (env-connect only)</label>
<input id="proxy_port" name="proxy_port" value="__PROXY_PORT__" placeholder="3130">
<h2>Models</h2>
<div class="row"><div>
<label for="triage">Main model</label>
<input id="triage" name="triage" list="models" value="__TRIAGE__" placeholder="blank = auto-pick strongest">
</div><div>
<label for="decision">Decision model (optional)</label>
<input id="decision" name="decision" list="models" value="__DECISION__" placeholder="blank = use main model">
</div></div>
<datalist id="models">__MODEL_OPTIONS__</datalist>
<button type="button" class="secondary" onclick="refreshModels()">Refresh model list from server</button>
<div class="row"><div>
<label for="decision_fallback">Decision fallback model</label>
<input id="decision_fallback" name="decision_fallback" value="__DECISION_FALLBACK__">
</div><div>
<label for="endpoint">Decision endpoint path (systemone wire)</label>
<input id="endpoint" name="endpoint" value="__ENDPOINT__">
<label for="protocol">Decision protocol</label>
<select id="protocol" name="protocol">
 <option value="auto" __PROTO_AUTO__>auto — /v1/decisions, then /v1/systemone</option>
 <option value="decisions" __PROTO_DECISIONS__>/v1/decisions (OpenAI-compatible)</option>
 <option value="systemone" __PROTO_SYSTEMONE__>/v1/systemone (Jev wire)</option>
 <option value="chat" __PROTO_CHAT__>chat only — no typed endpoint</option>
</select>
</div></div>
<h2>Machines to scan</h2>
<label><input type="checkbox" name="local_enabled" __LOCAL_CHECKED__ style="width:auto">
<b>This device</b> — scan the machine the shield itself runs on (recommended)</label>
<p class="hint">The shield is designed to run on each machine itself.
Remote machines are scanned only when you check their
<b>scan enabled</b> box — they're off by default.</p>
<div id="hosts">__HOST_ROWS__</div>
<button type="button" class="secondary" onclick="addHost()">+ add machine</button>
<p style="margin-top:1.6rem"><button type="submit">Save settings</button></p>
</form>
<script>
function hostRow(h){
 const d=document.createElement('div'); d.className='host';
 d.innerHTML=`<div class="row">
  <div><label>Name</label><input name="h_name" value="${h.name||''}" placeholder="workstation"></div>
  <div><label>OS</label><select name="h_os">
    <option ${h.os=='linux'?'selected':''}>linux</option>
    <option ${h.os=='macos'?'selected':''}>macos</option>
    <option ${h.os=='windows'?'selected':''}>windows</option></select></div>
  <div><label>Host</label><input name="h_host" value="${h.host||''}" placeholder="192.0.2.10"></div></div>
 <div class="row">
  <div><label>User</label><input name="h_user" value="${h.user||''}"></div>
  <div><label>Port</label><input name="h_port" value="${h.port||22}"></div>
  <div><label>Proxy</label><input name="h_proxy" value="${h.proxy||''}" placeholder="none / env / env:3130"></div></div>
 <div><label>Scan enabled</label>
 <input type="hidden" name="h_enabled" value="${h.enabled?1:0}">
 <input type="checkbox" ${h.enabled?'checked':''} style="width:auto"
   onchange="this.previousElementSibling.value=this.checked?1:0"></div>
 <p><button type="button" class="secondary" onclick="this.closest('.host').remove()">remove</button></p>`;
 return d;}
function addHost(){document.getElementById('hosts').appendChild(hostRow({}));}
async function refreshModels(){
 const r=await fetch('/api/models'); const ids=await r.json();
 const dl=document.getElementById('models');
 dl.innerHTML=ids.map(m=>`<option value="${m}">`).join('');
 alert(ids.length? ids.length+' models loaded into the list' : 'server listed no models');}
</script></body></html>"""


def _esc(v):
    return html.escape(str(v or ""), quote=True)


def render(saved=False):
    cfg = cfgmod.load()
    srv, roles = cfg["server"], cfg["roles"]
    hosts = transport.hosts()
    rows = "".join(
        "<script>document.getElementById('hosts').appendChild(hostRow(%s));</script>"
        % json.dumps({"name": name, **entry})
        for name, entry in sorted(hosts.items()))
    try:
        models = ai.loaded_models()
    except Exception:
        models = []
    page = PAGE
    for token, value in (
            ("__SAVED__", '<p class="saved">Saved. New settings apply to the '
                          'next scan.</p>' if saved else ""),
            ("__SERVER_URL__", _esc(srv.get("url"))),
            ("__KEY_HINT__", "saved — leave blank to keep it" if srv.get("api_key")
             else "blank = none (most local servers need none)"),
            ("__PROXY_SEL__", "selected" if srv.get("proxy_mode") == "env-connect" else ""),
            ("__PROXY_PORT__", _esc(srv.get("proxy_port") or "")),
            ("__TRIAGE__", _esc(roles["triage"].get("model"))),
            ("__DECISION__", _esc(roles["decision"].get("model"))),
            ("__DECISION_FALLBACK__", _esc(roles["decision"].get("fallback"))),
            ("__ENDPOINT__", _esc(roles["decision"].get("endpoint") or "/v1/systemone")),
            ("__PROTO_AUTO__", "selected" if (roles["decision"].get("protocol") or "auto") == "auto" else ""),
            ("__PROTO_DECISIONS__", "selected" if roles["decision"].get("protocol") == "decisions" else ""),
            ("__PROTO_SYSTEMONE__", "selected" if roles["decision"].get("protocol") == "systemone" else ""),
            ("__PROTO_CHAT__", "selected" if roles["decision"].get("protocol") == "chat" else ""),
            ("__MODEL_OPTIONS__", "".join(f'<option value="{_esc(m)}">' for m in models)),
            ("__LOCAL_CHECKED__", "checked" if transport.local_enabled() else ""),
            ("__HOST_ROWS__", rows)):
        page = page.replace(token, value)
    return page


def _save(form):
    def one(name):
        return (form.get(name) or [""])[0].strip()
    cfg = cfgmod.load()
    cfg["server"]["url"] = one("server_url").rstrip("/") or cfg["server"]["url"]
    if one("api_key"):
        cfg["server"]["api_key"] = one("api_key")
    mode = one("proxy_mode")
    if mode:
        cfg["server"]["proxy_mode"] = mode
        try:
            cfg["server"]["proxy_port"] = int(one("proxy_port"))
        except ValueError:
            pass
    else:
        cfg["server"].pop("proxy_mode", None)
        cfg["server"].pop("proxy_port", None)
    cfg["roles"]["triage"]["model"] = one("triage") or None
    cfg["roles"]["decision"]["model"] = one("decision") or None
    cfg["roles"]["decision"]["fallback"] = one("decision_fallback") or None
    cfg["roles"]["decision"]["endpoint"] = one("endpoint") or "/v1/systemone"
    cfg["roles"]["decision"]["protocol"] = one("protocol") or "auto"
    cfgmod.save(cfg)
    entries = {}
    names = form.get("h_name") or []
    for i, name in enumerate(names):
        name = name.strip()
        if not name:
            continue
        def col(key):
            vals = form.get(key) or []
            return vals[i].strip() if i < len(vals) else ""
        entry = {"os": col("h_os") or "linux", "host": col("h_host"),
                 "user": col("h_user")}
        try:
            entry["port"] = int(col("h_port") or 22)
        except ValueError:
            entry["port"] = 22
        if col("h_proxy"):
            entry["proxy"] = col("h_proxy")
        entry["enabled"] = col("h_enabled") == "1"
        if entry["host"] and entry["user"]:
            entries[name] = entry
    transport.save_all_hosts(entries,
                             local_enabled=("local_enabled" in form))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/models":
            body = json.dumps(ai.loaded_models()).encode()
            ctype = "application/json"
        else:
            body = render(saved=(self.path.startswith("/?saved"))).encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        _save(form)
        self.send_response(303)
        self.send_header("Location", "/?saved=1")
        self.end_headers()


def serve(port=8765):
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"AI Shield settings: http://127.0.0.1:{port}/  (Ctrl-C to stop)")
    print(f"targets: {', '.join(inventory.targets())}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nsettings server stopped")
    return 0
