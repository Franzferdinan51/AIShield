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
import time
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
    except Exception:
        pass  # the verdict comes from LAST below, cache or not
    cst = cvenow.last_status()
    cve_ok = bool(cst.get("ok"))
    if cve_ok:
        cve_note = "reachable"
    elif cst.get("cache_entries"):
        import time as _t
        age_h = max(0.0, (_t.time() - (cst.get("cache_newest_ts") or 0)) / 3600)
        cve_note = ("unreachable — serving cache (%.1fh old)" % age_h)
    else:
        cve_note = "unreachable, no cache yet"
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        extra = _dash_extra(base, kev_map)
    except Exception:
        extra = {}
    return {**extra,
        "version": __version__,
        "kev_count": len(kev_map), "kev_date": kev_date,
        "cvenow_reachable": cve_ok, "cvenow_note": cve_note,
        "server_url": cfg["server"]["url"],
        "triage_configured": cfg["roles"]["triage"]["model"],
        "triage_resolved": ai.triage_model(),
        "decision": cfg["roles"]["decision"],
        "targets": inventory.targets(),
        "local_enabled": transport.local_enabled(),
        "local_kind": inventory.local_kind(),
        "hosts": transport.hosts(),
        "models_loaded": ai.loaded_models(),
        "proxy_mode": cfg["server"].get("proxy_mode"),
        "proxy_port": cfg["server"].get("proxy_port"),
        "api_key_set": bool(cfg["server"].get("api_key")),
    }



def _dash_extra(base, kev_map):
    """Cheap local detail for the dashboard: system facts, patch-log
    stats, newest reports, newest KEV entries. No network, no scans."""
    import glob
    import platform
    import socket
    recent_kev = sorted(kev_map.values(),
                        key=lambda e: e.get("dateAdded") or "",
                        reverse=True)[:6]
    stats = {"applied": 0, "failed": 0, "recent": [], "last_run": None}
    log_path = os.path.join(base, "data", "patch-log.jsonl")
    if os.path.exists(log_path):
        with open(log_path) as f:
            lines = f.readlines()[-400:]
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        stats["applied"] = sum(1 for e in entries if e.get("rc") == 0)
        stats["failed"] = sum(1 for e in entries if e.get("rc") not in (0, None))
        stats["recent"] = [
            {"ts": e.get("ts"), "target": e.get("target"),
             "name": e.get("name"), "rc": e.get("rc"),
             "command": (e.get("command") or "")[:90]}
            for e in entries[-8:]][::-1]
        if entries:
            stats["last_run"] = entries[-1].get("ts")
    reports = []
    for p in sorted(glob.glob(os.path.join(base, "data", "reports", "*.pdf")),
                    key=os.path.getmtime, reverse=True)[:5]:
        reports.append({
            "name": os.path.basename(p),
            "interactive": os.path.exists(p[:-4] + ".json"),
            "mtime": time.strftime("%Y-%m-%d %H:%M",
                                   time.localtime(os.path.getmtime(p)))})
    return {
        "system": {"platform": platform.system(),
                   "release": platform.release(),
                   "python": platform.python_version(),
                   "host": socket.gethostname()},
        "patch_stats": stats,
        "reports": reports,
        "kev_recent": [{"id": e.get("cveID"), "vendor": e.get("vendorProject"),
                        "product": e.get("product"),
                        "name": (e.get("vulnerabilityName") or "")[:90],
                        "added": e.get("dateAdded")} for e in recent_kev],
    }


def _kev_items(limit):
    kev_map, _ = feeds.kev()
    entries = sorted(kev_map.values(),
                     key=lambda e: e.get("dateAdded") or "",
                     reverse=True)[:limit]
    return [{"id": e.get("cveID"),
             "summary": ("%s %s — %s" % (e.get("vendorProject") or "",
                                         e.get("product") or "",
                                         e.get("vulnerabilityName") or ""))[:220],
             "severity": "KEV",
             "published": e.get("dateAdded") or ""} for e in entries]


def api_latest(source, limit=20, ecosystem=None):
    # KEV comes from the program's own local catalog — it must work
    # even where the CVE Now service is unreachable.
    if source == "kev":
        return {"items": _kev_items(limit), "source": "local KEV catalog"}
    warning = None
    try:
        if source == "all":
            feed = cvenow.list_feed(name="all", ecosystem=ecosystem,
                                    limit=limit)
        else:
            feed = cvenow.list_feed(filter=["critical"],
                                    ecosystem=ecosystem, limit=limit)
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
        if out:
            return {"items": out, "source": "CVE Now"}
        warning = "CVE Now returned no items"
    except Exception as e:
        warning = "CVE Now unreachable from this machine (%s)" % type(e).__name__
    return {"items": _kev_items(limit), "source": "local KEV catalog",
            "warning": warning + " — showing the local known-exploited "
                                 "catalog instead"}


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


def api_reports():
    import glob
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = []
    pdfs = sorted(glob.glob(os.path.join(base, "data", "reports", "*.pdf")),
                  key=os.path.getmtime, reverse=True)[:20]
    for p in pdfs:
        entry = {"name": os.path.basename(p),
                 "mtime": time.strftime("%Y-%m-%d %H:%M",
                                        time.localtime(os.path.getmtime(p))),
                 "interactive": False}
        jp = p[:-4] + ".json"
        if os.path.exists(jp):
            try:
                with open(jp) as f:
                    d = json.load(f)
                entry.update(interactive=True,
                             json_name=os.path.basename(jp),
                             target=d.get("target"), ts=d.get("ts"),
                             summary=d.get("summary"))
            except Exception:
                pass
        out.append(entry)
    return {"reports": out}


def _explain_cache():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(base, "data", "explain-cache.json")
    try:
        with open(p) as f:
            return p, json.load(f)
    except Exception:
        return p, {}


def api_explain(body):
    cve_id = (body.get("cve_id") or "").strip()
    if not cve_id:
        return {"error": "cve_id required"}
    installed = None
    if body.get("name"):
        installed = {"name": body["name"], "version": body.get("version") or ""}
    key = cve_id.upper() + "|" + (
        "%s@%s" % (installed["name"], installed["version"]) if installed else "")
    p, cache = _explain_cache()
    if key in cache:
        return {"explanation": cache[key]["text"], "cached": True}
    kev_map, _ = feeds.kev()
    kev_entry = kev_map.get(cve_id.upper())
    vuln = None
    try:
        vuln = cvenow.get_vulnerability(cve_id)
    except Exception:
        vuln = None
    text = ai.explain_cve(cve_id, kev_entry=kev_entry, vuln=vuln,
                          installed=installed)
    if not text:
        return {"error": "no chat model available on the configured server"}
    cache[key] = {"ts": time.time(), "text": text}
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass
    return {"explanation": text, "cached": False}


def api_report_summary(body):
    name = os.path.basename(body.get("json_name") or "")
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(base, "data", "reports", name)
    if not name.endswith(".json") or not os.path.exists(p):
        return {"error": "no such report"}
    with open(p) as f:
        run = json.load(f)
    if run.get("ai_summary"):
        return {"summary": run["ai_summary"], "cached": True}
    text = ai.summarize_run(run)
    if not text:
        return {"error": "no chat model available on the configured server"}
    run["ai_summary"] = text
    try:
        with open(p, "w") as f:
            json.dump(run, f, indent=1, default=str)
    except Exception:
        pass
    return {"summary": text, "cached": False}


def api_ask(body):
    q = (body.get("question") or "").strip()
    if not q:
        return {"error": "question required"}
    parts = []
    scan = body.get("scan")
    if isinstance(scan, dict) and scan.get("findings") is not None:
        fs = [{"name": f.get("name"), "version": f.get("version"),
               "cves": f.get("cve_ids"), "kev": f.get("known_exploited"),
               "confidence": f.get("confidence")}
              for f in scan.get("findings") or []][:60]
        parts.append("LAST SCAN of %s: %s items, %s findings: %s" % (
            scan.get("target"), scan.get("inventory_count"),
            len(scan.get("findings") or []), json.dumps(fs, default=str)))
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        extra = _dash_extra(base, feeds.kev()[0])
        parts.append("PATCH LOG: %s" % json.dumps(extra["patch_stats"], default=str)[:1500])
        parts.append("RECENT REPORTS: %s" % json.dumps(extra["reports"], default=str))
    except Exception:
        pass
    text = ai.ask(q, "\n".join(parts) or "(no shield data available)")
    if not text:
        return {"error": "no chat model available on the configured server"}
    return {"answer": text}


def api_approvals(body):
    from . import approvals
    return approvals.set_approval(body.get("target"), body.get("name"),
                                  body.get("manager"),
                                  body.get("cve_ids") or [],
                                  body.get("action") or "")


def api_swarm():
    from . import swarm as swarmmod
    data = swarmmod.census()
    data["incidents"] = swarmmod.incidents(8)
    return data


def api_swarm_assess(body):
    from . import swarm as swarmmod
    return swarmmod.assess()


def api_swarm_action(body):
    from . import swarm as swarmmod
    return swarmmod.act(int(body.get("pid") or 0),
                        body.get("action") or "",
                        body.get("confirm") or "")


def api_swarm_mark(body):
    from . import swarm as swarmmod
    return swarmmod.mark(int(body.get("pid") or 0),
                         body.get("kind") or "")


def api_policy_get():
    from . import policy as policymod
    return {"policy": policymod.load(), "file": policymod.PATH}


def api_policy_save(body):
    from . import policy as policymod
    pol = policymod.load()
    for k in ("enabled", "auto_apply", "require_decision_allow",
              "allow_candidates"):
        if k in body:
            pol[k] = bool(body[k])
    if isinstance(body.get("targets"), list):
        pol["targets"] = [str(t) for t in body["targets"]]
    if body.get("scan_interval_hours"):
        pol["scan_interval_hours"] = float(body["scan_interval_hours"])
    return {"policy": policymod.save(pol)}


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
    if "decisions_endpoint" in body:
        cfg["roles"]["decision"]["decisions_endpoint"] = \
            body["decisions_endpoint"] or "/v1/decisions"
    if body.get("protocol"):
        cfg["roles"]["decision"]["protocol"] = body["protocol"]
    cfgmod.save(cfg)
    entries = {}
    existing = transport.hosts()
    for h in body.get("hosts") or []:
        name = (h.get("name") or "").strip()
        if name and h.get("host") and h.get("user"):
            # start from the stored entry so fields the form does not
            # render (identity, ...) survive a GUI save
            entry = dict(existing.get(name) or {})
            entry.update({"os": h.get("os") or "linux", "host": h["host"],
                          "user": h["user"], "enabled": bool(h.get("enabled"))})
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
            if u.path == "/api/policy":
                return self._send(200, api_policy_get())
            if u.path == "/api/swarm":
                return self._send(200, api_swarm())
            if u.path == "/api/reports":
                return self._send(200, api_reports())
            if u.path.startswith("/api/report-data/"):
                name = os.path.basename(u.path.rsplit("/", 1)[-1])
                base = os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))
                p = os.path.join(base, "data", "reports", name)
                if name.endswith(".json") and os.path.exists(p):
                    with open(p) as f:
                        return self._send(200, json.load(f))
                return self._send(404, {"error": "no such report data"})
            if u.path == "/api/latest":
                q = parse_qs(u.query)
                return self._send(200, api_latest(
                    (q.get("source") or ["critical"])[0],
                    limit=int((q.get("limit") or ["20"])[0])))
            if u.path.startswith("/api/report/"):
                name = os.path.basename(u.path.rsplit("/", 1)[-1])
                base = os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))
                p = os.path.join(base, "data", "reports", name)
                if name.endswith(".pdf") and os.path.exists(p):
                    with open(p, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                return self._send(404, {"error": "no such report"})
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
            if self.path == "/api/explain":
                return self._send(200, api_explain(body))
            if self.path == "/api/report-summary":
                return self._send(200, api_report_summary(body))
            if self.path == "/api/ask":
                return self._send(200, api_ask(body))
            if self.path == "/api/approvals":
                return self._send(200, api_approvals(body))
            if self.path == "/api/policy":
                return self._send(200, api_policy_save(body))
            if self.path == "/api/swarm/assess":
                return self._send(200, api_swarm_assess(body))
            if self.path == "/api/swarm/action":
                return self._send(200, api_swarm_action(body))
            if self.path == "/api/swarm/mark":
                return self._send(200, api_swarm_mark(body))
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
 :root{
  --ink:#070a12; --txt:#eef2fb; --dim:#9aa7c2; --cyan:#38e1ff; --violet:#8b7cff;
  --teal:#3fe0a8; --warn:#ffc44d; --bad:#ff7a6b;
  --glass:linear-gradient(155deg,rgba(255,255,255,.06),rgba(255,255,255,.02) 55%,rgba(255,255,255,.03));
  --stroke:rgba(255,255,255,.14);
  --shadow:0 14px 34px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.08);
 }
 *{box-sizing:border-box}
 html{scrollbar-color:rgba(255,255,255,.22) transparent}
 body{margin:0;font-family:"Avenir Next","Segoe UI",system-ui,-apple-system,sans-serif;color:var(--txt);
  display:flex;min-height:100vh;background:
  radial-gradient(1100px 700px at 85% -10%,rgba(139,124,255,.10),transparent 60%),
  radial-gradient(900px 650px at -10% 110%,rgba(56,225,255,.06),transparent 55%),
  radial-gradient(700px 500px at 55% 120%,rgba(63,224,168,.04),transparent 60%),
  var(--ink)}
 .orb{position:fixed;border-radius:50%;filter:blur(90px);pointer-events:none;z-index:0;opacity:.22}
 .orb.a{width:420px;height:420px;right:-120px;top:-140px;background:radial-gradient(circle at 35% 35%,#8d84d8,#4a3fa0 70%)}
 .orb.b{width:360px;height:360px;left:-120px;bottom:-140px;background:radial-gradient(circle at 35% 35%,#5ec8d8,#0f5a70 70%)}
 /* ---------- sidebar ---------- */
 nav{position:relative;z-index:1;width:228px;flex:none;display:flex;flex-direction:column;gap:.3rem;
  padding:1.1rem .8rem;margin:14px 0 14px 14px;border-radius:22px;background:var(--glass);
  border:1px solid var(--stroke);box-shadow:var(--shadow);backdrop-filter:blur(16px) saturate(150%)}
 nav .logo{display:flex;align-items:center;gap:.6rem;font-size:1.08rem;font-weight:650;letter-spacing:.02em;padding:.2rem .4rem 1rem}
 nav .logo .bub{width:38px;height:38px;flex:none;display:grid;place-items:center;font-size:1.15rem;border-radius:13px;
  background:linear-gradient(150deg,#6fd4e8,#54749e 55%,#6f5fae);box-shadow:inset 0 1px 2px rgba(255,255,255,.28),inset 0 -5px 9px rgba(0,0,40,.3),0 6px 14px rgba(79,124,255,.22)}
 nav button{position:relative;background:transparent;border:1px solid transparent;color:var(--dim);text-align:left;
  padding:.6rem .7rem;border-radius:13px;font:inherit;font-weight:500;cursor:pointer;transition:all .18s ease}
 nav button:hover{color:var(--txt);background:rgba(255,255,255,.05)}
 nav button.on{color:#fff;background:linear-gradient(120deg,rgba(56,225,255,.13),rgba(139,124,255,.15));
  border-color:rgba(255,255,255,.13);box-shadow:inset 0 1px 0 rgba(255,255,255,.12)}
 nav .foot{margin-top:auto;color:var(--dim);font-size:.78rem;padding:.6rem .4rem 0}
 /* ---------- layout / views ---------- */
 main{position:relative;z-index:1;flex:1;padding:1.7rem 1.9rem;max-width:1120px}
 .view{display:none} .view.on{display:block;animation:rise .35s ease both}
 @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
 h1{font-size:1.35rem;font-weight:600;margin:.1rem 0 1.1rem;letter-spacing:.01em}
 h1::after{content:"";display:block;width:64px;height:4px;border-radius:4px;margin-top:.45rem;
  background:linear-gradient(90deg,rgba(56,225,255,.55),rgba(139,124,255,.55))}
 h2{font-size:1.05rem;margin:1.5rem 0 .7rem;color:#dbe4f7}
 /* ---------- bubbles / cards ---------- */
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.9rem}
 .card{position:relative;overflow:hidden;border-radius:19px;padding:1rem 1.1rem;background:var(--glass);
  border:1px solid var(--stroke);box-shadow:var(--shadow);backdrop-filter:blur(12px) saturate(140%);
  transition:transform .18s ease, box-shadow .18s ease}
 .card::before{content:"";position:absolute;inset:0 0 55% 0;border-radius:19px 19px 50% 50%/19px 19px 26px 26px;
  background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,0));pointer-events:none}
 .card:hover{transform:translateY(-2px);box-shadow:0 18px 40px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.1)}
 .card b{font-size:1.3rem;font-weight:600;display:block;letter-spacing:.01em}
 .card span{color:var(--dim);font-size:.82rem;font-weight:500;text-transform:uppercase;letter-spacing:.06em}
 /* ---------- tables as glass strips ---------- */
 table{width:100%;border-collapse:separate;border-spacing:0 .45rem;font-size:.92rem}
 th{color:var(--dim);font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.06em;padding:0 .7rem .1rem;text-align:left}
 td{background:rgba(255,255,255,.045);padding:.6rem .7rem;border-top:1px solid rgba(255,255,255,.07);border-bottom:1px solid rgba(255,255,255,.07);vertical-align:top}
 td:first-child{border-left:1px solid rgba(255,255,255,.07);border-radius:13px 0 0 13px}
 td:last-child{border-right:1px solid rgba(255,255,255,.07);border-radius:0 13px 13px 0}
 tr:hover td{background:rgba(255,255,255,.075)}
 .badge{display:inline-block;border-radius:999px;padding:.14rem .6rem;font-size:.76rem;font-weight:600;
  background:linear-gradient(160deg,rgba(255,255,255,.14),rgba(255,255,255,.05));border:1px solid var(--stroke);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.1)}
 .kev{background:linear-gradient(160deg,rgba(255,90,70,.35),rgba(255,90,70,.14));border-color:rgba(255,122,107,.5);color:#ffd9d3}
 .crit{color:var(--bad);font-weight:600} .ok{color:var(--teal);font-weight:550} .dim{color:var(--dim)}
 /* ---------- controls ---------- */
 input,select,textarea{width:100%;background:linear-gradient(180deg,rgba(0,0,0,.32),rgba(0,0,0,.18));
  border:1px solid var(--stroke);color:var(--txt);border-radius:12px;padding:.55rem .7rem;font:inherit;
  box-shadow:inset 0 2px 6px rgba(0,0,0,.35);outline:none;transition:border-color .15s, box-shadow .15s}
 input:focus,select:focus,textarea:focus{border-color:rgba(56,225,255,.45);box-shadow:inset 0 2px 6px rgba(0,0,0,.35),0 0 0 3px rgba(56,225,255,.1)}
 select option{background:#141a29;color:var(--txt)}
 label{display:block;margin:.65rem 0 .3rem;font-weight:550;font-size:.86rem;color:#cfdaf2}
 .row{display:flex;gap:.9rem;flex-wrap:wrap;align-items:end} .row>div{flex:1;min-width:160px}
 button.act{background:linear-gradient(140deg,#3ecb9e,#1ea87e 60%,#178a66);color:#051a11;
  border:1px solid rgba(255,255,255,.2);border-radius:13px;padding:.6rem 1.25rem;font:inherit;font-weight:600;cursor:pointer;
  box-shadow:inset 0 1px 1px rgba(255,255,255,.22),0 6px 14px rgba(25,185,138,.18);transition:all .15s}
 button.act:hover{filter:brightness(1.05)} button.act:active{transform:translateY(1px)}
 button.ghost{background:var(--glass);color:var(--txt);border:1px solid var(--stroke);border-radius:13px;
  padding:.6rem 1.1rem;font:inherit;font-weight:550;cursor:pointer;box-shadow:inset 0 1px 0 rgba(255,255,255,.09);transition:all .15s}
 button.ghost:hover{border-color:rgba(56,225,255,.35)}
 #apply-go{background:linear-gradient(140deg,#eec25e,#e8893f 55%,#d6542f);color:#2a1000;
  box-shadow:inset 0 1px 1px rgba(255,255,255,.25),0 6px 14px rgba(244,100,60,.18)}
 /* toggle switches (all checkboxes) */
 input[type=checkbox]{appearance:none;-webkit-appearance:none;width:46px!important;height:26px;flex:none;vertical-align:-7px;
  border-radius:999px;padding:0;cursor:pointer;position:relative;outline:none;
  background:linear-gradient(180deg,rgba(0,0,0,.45),rgba(0,0,0,.25));border:1px solid var(--stroke);
  box-shadow:inset 0 2px 5px rgba(0,0,0,.5);transition:all .18s}
 input[type=checkbox]::before{content:"";position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#ffffff,#c7d2e8 65%,#93a3c0);box-shadow:0 2px 5px rgba(0,0,0,.45);transition:left .18s}
 input[type=checkbox]:checked{background:linear-gradient(140deg,#2fa8c4,#4f6bd8 60%,#7158c4);border-color:rgba(255,255,255,.25);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.18)}
 input[type=checkbox]:checked::before{left:22px}
 /* ---------- panels ---------- */
 pre{background:linear-gradient(165deg,rgba(10,14,24,.85),rgba(10,14,24,.65));border:1px solid var(--stroke);
  border-radius:16px;padding:.9rem 1rem;white-space:pre-wrap;font-size:.85rem;box-shadow:var(--shadow);backdrop-filter:blur(10px)}
 .host{border:1px solid var(--stroke);border-radius:17px;padding:.85rem 1rem;margin:.6rem 0;background:var(--glass);
  box-shadow:var(--shadow);backdrop-filter:blur(12px)}
 .spin{color:var(--warn);font-weight:550}
 .kv{display:flex;justify-content:space-between;gap:1rem;padding:.32rem 0;border-bottom:1px solid rgba(255,255,255,.06)}
 .kv:last-child{border-bottom:0} .kv span{color:var(--dim)} .kv b{font-weight:550;text-align:right;word-break:break-all}
 .chips{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.35rem}
 .clickable{cursor:pointer} .clickable:hover td{background:rgba(56,225,255,.08)}
 #scan-state:empty{display:none}
 @media (max-width:820px){body{flex-direction:column} nav{width:auto;margin:10px 10px 0;flex-direction:row;flex-wrap:wrap;align-items:center}
  nav .logo{padding-bottom:.2rem} nav .foot{display:none} main{padding:1.1rem}}
</style></head><body>
<div class="orb a"></div><div class="orb b"></div>
<nav>
 <div class="logo"><span class="bub">🛡️</span> AI Shield</div>
 <button data-v="dash" class="on">📊&ensp;Dashboard</button>
 <button data-v="scan">🔍&ensp;Scan</button>
 <button data-v="patch">🩹&ensp;Patch</button>
 <button data-v="reports">📄&ensp;Reports</button>
 <button data-v="ask">💬&ensp;Ask</button>
 <button data-v="latest">🆕&ensp;Latest CVEs</button>
 <button data-v="cve">🔎&ensp;CVE lookup</button>
 <button data-v="swarm">🐝&ensp;Swarm</button>
 <button data-v="settings">⚙️&ensp;Settings</button>
 <div class="foot" id="ver"></div>
</nav>
<main>
 <section id="v-dash" class="view on"><h1>Dashboard</h1><div class="cards" id="cards"></div>
  <div class="row" style="margin-top:1rem;align-items:stretch">
   <div class="host" style="flex:1.25"><h2 style="margin-top:.2rem">AI layer</h2><div id="dash-ai"></div></div>
   <div class="host" style="flex:1"><h2 style="margin-top:.2rem">Feeds &amp; system</h2><div id="dash-feeds"></div></div>
  </div>
  <h2>Targets</h2><div id="targets"></div>
  <div class="row" style="align-items:stretch">
   <div class="host" style="flex:1.25"><h2 style="margin-top:.2rem">Recent patch activity</h2><div id="dash-activity"></div></div>
   <div class="host" style="flex:1"><h2 style="margin-top:.2rem">Newest known-exploited</h2><div id="dash-kev"></div></div>
  </div>
  <div class="host"><h2 style="margin-top:.2rem">Latest reports</h2><div id="dash-reports"></div></div>
  <p class="dim">The shield is designed to run on each machine itself — remote machines scan only when you enable them in Settings.</p></section>
 <section id="v-scan" class="view"><h1>Scan</h1>
  <div class="row"><div><label>Target</label><select id="scan-target"></select></div>
  <div><label>Program filter (optional)</label><input id="scan-program" placeholder="e.g. chrome"></div>
  <div><label><input type="checkbox" id="scan-ai"> AI brief</label></div>
  <div><button class="act" id="scan-go">Run scan</button></div></div>
  <p id="scan-state" class="dim"></p>
  <div class="row" id="scan-filter-row" style="display:none"><div><label>Filter results</label><input id="scan-filter" placeholder="package or CVE…"></div>
  <div><label><input type="checkbox" id="scan-kev"> KEV only</label></div></div>
  <div id="scan-out"></div></section>
  <section id="v-patch" class="view"><h1>Patch</h1>
  <p class="dim">See exactly what can be patched on a machine, then patch it. Anything the shield can't safely run itself is listed separately with the reason — nothing is hidden, and nothing runs until you say so.</p>
  <div class="row"><div><label>Target</label><select id="patch-target"></select></div>
  <div><button class="act" id="plan-go">See what can be patched</button></div></div>
  <div id="plan-out"></div>
  <div id="apply-zone"></div>
  <div id="apply-out" style="margin-top:1rem"></div></section>
<section id="v-reports" class="view"><h1>Reports</h1>
  <div id="reports-list"></div><div id="report-detail"></div></section>
 <section id="v-ask" class="view"><h1>Ask your shield</h1>
  <p class="dim">Answers come only from your shield's own data — the last scan in this session, the patch log and your reports. If it isn't in the data, it will say so.</p>
  <div class="row"><div><label>Question</label><input id="ask-q" placeholder="e.g. what couldn't be patched automatically, and why?"></div>
  <div><button class="act" id="ask-go">Ask</button></div></div>
  <pre id="ask-out" style="display:none"></pre></section>
 <section id="v-latest" class="view"><h1>Latest CVEs</h1>
  <div class="row"><div><label>Source</label><select id="latest-src"><option value="critical">critical (CVE Now)</option><option value="kev">known-exploited (KEV)</option><option value="all">all</option></select></div>
  <div><button class="ghost" id="latest-go">Load</button></div></div><div id="latest-out"></div></section>
 <section id="v-cve" class="view"><h1>CVE lookup</h1>
  <div class="row"><div><label>CVE id</label><input id="cve-id" placeholder="CVE-2026-111497"></div>
  <div><button class="ghost" id="cve-go">Look up</button></div></div><div id="cve-explain"></div><pre id="cve-out" style="display:none"></pre></section>
 <section id="v-swarm" class="view"><h1>Rogue agent swarm — detection &amp; defense</h1>
<p class="dim">A census of this machine: agent-like processes, what they're connected to, and which ones move together. Your own agents are <b>friendly</b> (allowlist in config/swarm.local.yaml). Defense is yours to fire — freeze is reversible, kill is not — and every action snapshots the census as evidence and lands in the incident log. Nothing here reaches out to another machine.</p>
<div style="margin:.4rem 0"><button class="act" id="sw-scan">🛰️ Run census</button> <button id="sw-assess">🤖 Assess with AI</button> <span id="sw-msg" class="dim"></span></div>
<div id="sw-out"></div><div id="sw-assess-out"></div></section>
<section id="v-settings" class="view"><h1>Settings</h1><div id="settings-out"></div><div id="policy-out"></div></section>
</main>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
async function api(p,o){const r=await fetch(p,o);return r.json();}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
let STATUS=null;
function go(v){$$('nav button').forEach(x=>x.classList.toggle('on',x.dataset.v===v));$$('.view').forEach(x=>x.classList.remove('on'));$('#v-'+v).classList.add('on');if(v==='settings')loadSettings();if(v==='swarm')loadSwarm();if(v==='reports')loadReports();if(v==='patch')loadPlan();}
$$('nav button').forEach(b=>b.onclick=()=>go(b.dataset.v));
async function loadStatus(){
 STATUS=await api('/api/status');
 $('#ver').textContent='v'+STATUS.version+' · local '+(STATUS.local_enabled?'on':'off');
 const ps=STATUS.patch_stats||{applied:0,failed:0,recent:[]};
 $('#cards').innerHTML=[['KEV catalog',STATUS.kev_count],['KEV released',(STATUS.kev_date||'').slice(0,10)],['CVE Now',STATUS.cvenow_reachable?'reachable':(STATUS.cvenow_note&&STATUS.cvenow_note.indexOf('cache')>=0?'cached':'unreachable')],['Main model',STATUS.triage_resolved||'offline'],['Decision model',(STATUS.decision||{}).model||'main model'],['Models loaded',(STATUS.models_loaded||[]).length],['Patches applied',ps.applied],['Last patch run',ps.last_run?String(ps.last_run).slice(0,10):'never']].map(c=>`<div class="card"><b>${esc(c[1])}</b><span>${esc(c[0])}</span></div>`).join('');
 const kv=(k,v)=>`<div class="kv"><span>${esc(k)}</span><b>${esc(v)}</b></div>`;
 const d=STATUS.decision||{};
 $('#dash-ai').innerHTML=kv('Provider',STATUS.server_url)+kv('Main model',(STATUS.triage_resolved||'—')+(STATUS.triage_configured?'':' (auto)'))+kv('Decision model',d.model||'same as main')+kv('Decision fallback',d.fallback||'—')+kv('Decision protocol',d.protocol||'auto')+kv('Decisions endpoint',d.decisions_endpoint||'/v1/decisions')+kv('SystemOne endpoint',d.endpoint||'/v1/systemone')+kv('Proxy',STATUS.proxy_mode?(STATUS.proxy_mode+' :'+(STATUS.proxy_port||'')):'none')+kv('API key',STATUS.api_key_set?'saved':'not set')+`<div class="chips">${(STATUS.models_loaded||[]).slice(0,14).map(m=>`<span class="badge">${esc(m)}</span>`).join('')}</div>`;
 const sy=STATUS.system||{};
 $('#dash-feeds').innerHTML=kv('KEV catalog',STATUS.kev_count+' entries')+kv('KEV released',(STATUS.kev_date||'').slice(0,10))+kv('CVE Now',STATUS.cvenow_note||(STATUS.cvenow_reachable?'reachable':'unreachable from here'))+kv('This device',STATUS.local_enabled?'scanning on':'off')+kv('Machine',(sy.host||'')+' · '+(sy.platform||'')+' '+(sy.release||''))+kv('Python',sy.python||'')+kv('Shield version','v'+STATUS.version)+kv('Patch failures (logged)',ps.failed);
 const rowsT=[`<tr><td>local</td><td>${esc(STATUS.local_kind)}</td><td>this machine</td><td>${STATUS.local_enabled?'<span class="badge">enabled</span>':'<span class="badge kev">off</span>'}</td></tr>`]
  .concat(Object.entries(STATUS.hosts||{}).map(([n,h])=>`<tr><td>${esc(n)}</td><td>${esc(h.os)}</td><td>${esc(h.user+'@'+h.host)}</td><td>${h.enabled?'<span class="badge">enabled</span>':'<span class="badge kev">off</span>'}</td></tr>`));
 $('#targets').innerHTML='<table><tr><th>Target</th><th>Kind</th><th>Detail</th><th>Scan</th></tr>'+rowsT.join('')+'</table>';
 $('#dash-activity').innerHTML=ps.recent&&ps.recent.length?'<table><tr><th>When</th><th>Target</th><th>Package</th><th>Result</th></tr>'+ps.recent.map(e=>`<tr><td class="dim">${esc(String(e.ts||'').slice(5,16))}</td><td>${esc(e.target)}</td><td>${esc(e.name)}</td><td>${e.rc===0?'<span class="ok">applied</span>':'<span class="crit">rc '+esc(e.rc)+'</span>'}</td></tr>`).join('')+'</table>':'<p class="dim">no patch runs logged yet — head to <a href="#" onclick="go(\'patch\');return false">Patch</a></p>';
 $('#dash-kev').innerHTML=(STATUS.kev_recent||[]).length?'<table><tr><th>CVE</th><th>Product</th><th>Added</th></tr>'+STATUS.kev_recent.map(e=>`<tr class="clickable" onclick="lookupCve('${esc(e.id)}')"><td>${esc(e.id)}</td><td>${esc((e.vendor||'')+' '+(e.product||''))}</td><td class="dim">${esc(e.added||'')}</td></tr>`).join('')+'</table>':'<p class="dim">KEV catalog not loaded</p>';
 $('#dash-reports').innerHTML=(STATUS.reports||[]).length?STATUS.reports.map(r=>`<div class="kv"><span>📄 ${esc(r.name)}</span><b>${r.interactive?'<a href="#" onclick="go(\'reports\');return false">read in app</a> · ':''}<a href="/api/report/${esc(r.name)}" target="_blank">PDF</a> · ${esc(r.mtime)}</b></div>`).join(''):'<p class="dim">no reports yet — patch runs write one here</p>';
 const opts=STATUS.targets.map(t=>`<option>${esc(t)}</option>`).join('');
 $('#scan-target').innerHTML=opts; $('#patch-target').innerHTML=opts;
}
function lookupCve(id){go('cve');$('#cve-id').value=id;$('#cve-go').click();}
let LASTSCAN=null;
$('#scan-go').onclick=async()=>{
 const body={target:$('#scan-target').value,program:$('#scan-program').value,ai:$('#scan-ai').checked};
 $('#scan-state').innerHTML='<span class="spin">scanning… (can take a minute on a cold cache)</span>';$('#scan-out').innerHTML='';
 const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 if(r.error){$('#scan-state').textContent='error: '+r.error;return;}
 LASTSCAN=r;
 $('#scan-state').textContent=`${r.inventory_count} items · ${r.findings.length} findings · ${r.elapsed_s}s`;
 $('#scan-filter-row').style.display='flex';
 renderScan();
};
function renderScan(){
 const r=LASTSCAN; if(!r)return;
 const q=($('#scan-filter').value||'').toLowerCase(), kevOnly=$('#scan-kev').checked;
 const fs=r.findings.filter(f=>(!kevOnly||f.known_exploited)&&(!q||(f.name+' '+(f.cve_ids||[]).join(' ')).toLowerCase().includes(q)));
 const rows=fs.map(f=>`<tr><td>${esc(f.name)} ${esc(f.version)}</td><td class="clickable" onclick="lookupCve('${esc((f.cve_ids||[])[0]||'')}')">${(f.cve_ids||[]).map(esc).join('<br>')}</td><td>${f.known_exploited?'<span class="badge kev">KEV</span> ':''}<span class="badge">${esc(f.severity||'')}</span></td><td>${esc((f.fixed_versions||[]).join(', '))}</td><td class="dim">${esc(f.confidence)}${f.ai_era?` <span class="badge">ai era: ${esc(f.ai_era.verdict)}</span>`:''}</td><td>${(f.cve_ids||[]).length?`<button class="ghost" onclick="explainFinding('${esc((f.cve_ids||[])[0])}','${esc(f.name)}','${esc(f.version)}')">explain</button>`:''}</td></tr>`).join('');
 $('#scan-out').innerHTML=(r.warnings&&r.warnings.length?`<p class="spin">⚠ ${r.warnings.map(esc).join('<br>')}</p>`:'')+(r.cleared&&r.cleared.length?`<p class="ok">✓ cleared by version check (installed is outside the CVE's affected range): ${r.cleared.map(c=>esc(c.name)+' '+esc(c.version)+' · '+esc(c.cve)).join(' &nbsp; ')}</p>`:'')+(r.changes&&r.changes.since?`<p class=\"dim\">since last scan (${esc(r.changes.since)}): <b>${(r.changes.new||[]).length} new</b>, <b>${(r.changes.resolved||[]).length} resolved</b>${(r.changes.resolved||[]).length?' — resolved: '+r.changes.resolved.map(f=>esc(f.name)).join(', '):''}</p>`:'')+`<table><tr><th>Package</th><th>CVEs</th><th>Severity</th><th>Fixed in</th><th>Confidence</th><th></th></tr>${rows||'<tr><td colspan=6 class="ok">no findings match</td></tr>'}</table><div id="explain-box"></div>`+(r.ai_brief?`<h2>AI brief (${esc(r.ai_model||'')})</h2><pre>${esc(r.ai_brief)}</pre>`:'');
}
$('#scan-filter').addEventListener('input',renderScan);
$('#scan-kev').addEventListener('change',renderScan);
async function approveAct(btn,action){
 const d=btn.dataset;
 await api('/api/approvals',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value,name:d.name,manager:d.manager,cve_ids:d.cves?d.cves.split(','):[],action})});
 loadPlan();
}
const MGR_ACTION={brew:'Homebrew upgrade',pip:'pip upgrade',apt:'system package upgrade',npm:'npm update',winget:'winget upgrade',macapp:'in-app update',app:'in-app update'};
function actsHtml(x){
 const attrs=`data-name="${esc(x.name)}" data-manager="${esc(x.manager)}" data-cves="${esc((x.cve_ids||[]).join(','))}"`;
 if(x.acknowledged)return `<div style="margin-top:.5rem"><span class="badge">✓ acknowledged by you</span> <button class="ghost" onclick="approveAct(this,'revoke')" ${attrs}>undo</button></div>`;
 if(x.approved)return `<div style="margin-top:.5rem"><span class="badge">approved by you</span> <button class="ghost" onclick="approveAct(this,'revoke')" ${attrs}>undo</button></div>`;
 const patchable=['brew','npm','apt'].includes(x.manager)||x.decision==='hold';
 return `<div style="margin-top:.5rem">${x.approval_blocked?`<span class="crit">⛔ approval won't work here: ${esc(x.approval_blocked)}</span> `:(patchable?`<button class="act" onclick="approveAct(this,'patch')" ${attrs}>✓ Approve &amp; patch</button> `:'')}<button class="ghost" onclick="approveAct(this,'acknowledge')" ${attrs}>Acknowledge</button></div>`;
}
async function loadPlan(){
 $('#plan-out').innerHTML='<span class="spin">checking what can be patched…</span>';
 $('#apply-zone').innerHTML='';$('#apply-out').innerHTML='';
 const target=$('#patch-target').value;
 const r=await api('/api/patch/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
 if(r.error){$('#plan-out').innerHTML=`<p class="crit">${esc(r.error)}</p>`;return;}
 const auto=(r.plan||[]).filter(x=>x.auto),manual=(r.plan||[]).filter(x=>!x.auto);const manualActive=manual.filter(x=>!x.acknowledged);
 const card=x=>`<div class="host"><div class="kv"><span><b>${esc(x.name)}</b> ${esc(x.version||'')}${x.auto?` → ${esc((x.fixed_versions||[])[0]||'latest')}`:''}</span><b>${x.auto?'<span class="ok">ready to patch</span>':'<span class="crit">needs you</span>'}</b></div>${x.auto?`<div class="dim">${esc(MGR_ACTION[x.manager]||(x.manager+' update'))}${x.decision?' · AI safety check: '+esc(x.decision):''}</div><div class="dim" style="font-family:monospace;font-size:.82rem;word-break:break-all">${esc(x.command||'')}</div>`+(x.approved?actsHtml(x):''):`<div>${esc(x.note||'manual step')}</div>`+actsHtml(x)}</div>`;
 $('#plan-out').innerHTML=`<h2>${auto.length} ready to patch · ${manualActive.length} need${manualActive.length===1?'s':''} you</h2><p class="dim">from ${r.findings_count} findings on ${esc(target)}</p>`+(auto.length?`<h3>✅ The shield can patch these</h3>`+auto.map(card).join(''):'')+(manual.length?`<h3>✋ These need you — here's why</h3>`+manual.map(card).join(''):'');
 const zone=$('#apply-zone');
 if(auto.length){
  zone.innerHTML=`<div style="margin-top:1rem"><button class="act" id="patch-now" style="font-size:1.05rem;padding:.75rem 1.5rem">⚡ Patch ${auto.length} item${auto.length===1?'':'s'} now</button> <span class="dim">runs the exact commands listed above on ${esc(target)}; a report is saved either way</span></div>`;
  $('#patch-now').onclick=()=>{
   zone.innerHTML=`<div class="host"><b>Last check</b> — this really runs those upgrades on <b>${esc(target)}</b>.<div class="row" style="margin-top:.6rem"><div><label>Type PATCH to arm</label><input id="apply-confirm" placeholder="PATCH"></div><div><button class="act" id="apply-go">Confirm — patch now</button></div><div><button class="ghost" id="apply-cancel">Cancel</button></div></div></div>`;
   $('#apply-cancel').onclick=()=>loadPlan();
   $('#apply-go').onclick=applyPatch;
  };
 }else{
  zone.innerHTML=`<div class="host" style="margin-top:1rem"><b>Nothing here can be patched automatically right now.</b><div class="dim">${manual.length?'The items above need a manual update — each one says why.':'This machine is fully patched against everything the shield can check.'}</div></div>`;
 }
}
async function applyPatch(){
 const out=$('#apply-out');out.innerHTML='<span class="spin">patching…</span>';
 const r=await api('/api/patch/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value,confirm:$('#apply-confirm').value})});
 if(r.error){out.innerHTML=`<p class="crit">${esc(r.error)}</p>`;return;}
 const steps=((r.outcome||{}).applied||[]);
 const counts={};steps.forEach(st=>{counts[st.result]=(counts[st.result]||0)+1;});
 const icon=res=>res==='applied'?'✅':(String(res).indexOf('blocked')===0?'⛔':(res==='skipped-manual'?'✋':'✗'));
 const rows=steps.map(st=>`<div class="host"><div class="kv"><span>${icon(st.result)} <b>${esc(st.name)}</b></span><b>${esc(st.result)}</b></div>${st.ai_diagnosis&&st.ai_diagnosis.cause?`<div class="dim">🤖 ${esc(st.ai_diagnosis.cause)}${st.ai_diagnosis.next?' → '+esc(st.ai_diagnosis.next):''}</div>`:''}</div>`).join('');
 const pdf=r.report_pdf?String(r.report_pdf).split('/').pop():'';
 out.innerHTML=`<h2>Done — findings ${r.findings_before} → ${r.findings_after}</h2><p class="dim">${Object.entries(counts).map(([k,v])=>v+' '+k).join(' · ')||'no steps ran'}</p>${rows}${pdf?`<p><a href="/api/report/${encodeURIComponent(pdf)}" target="_blank">Open the PDF report</a></p>`:''}<details><summary class="dim" style="cursor:pointer">raw details</summary><pre>${esc(JSON.stringify(r,null,1))}</pre></details>`;
 $('#apply-zone').innerHTML='';
 loadPlan();
}
$('#plan-go').onclick=loadPlan;
$('#latest-go').onclick=async()=>{
 $('#latest-out').innerHTML='<span class="spin">loading…</span>';
 const r=await api('/api/latest?source='+$('#latest-src').value);
 $('#latest-out').innerHTML=(r.warning?`<p class="spin">⚠ ${esc(r.warning)}</p>`:'')+(r.error?`<p class="crit">${esc(r.error)}</p>`:'')+'<table><tr><th>CVE</th><th>Severity</th><th>Summary</th></tr>'+(r.items||[]).map(i=>`<tr><td>${esc(i.id)}</td><td>${esc(i.severity)}</td><td>${esc(i.summary)}</td></tr>`).join('')+'</table>';
};
$('#cve-go').onclick=async()=>{
 const out=$('#cve-out');out.style.display='block';out.textContent='looking up…';
 const id=$('#cve-id').value.trim();
 const r=await api('/api/cve/'+encodeURIComponent(id));
 out.textContent=r.found?JSON.stringify(r,null,1):'not found in CVE Now, KEV or NVD';
 const ex=$('#cve-explain'); ex.innerHTML='<p class="spin">asking the model…</p>';
 const e=await api('/api/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cve_id:id})});
 ex.innerHTML=e.error?`<p class="crit">${esc(e.error)}</p>`:`<div class="host"><h2 style="margin-top:.2rem">In plain English ${e.cached?'<span class="dim">(cached)</span>':''}</h2><p style="white-space:pre-wrap">${esc(e.explanation)}</p></div>`;
};
let RUNS=[];
async function loadReports(){
 const r=await api('/api/reports'); RUNS=r.reports||[];
 $('#reports-list').innerHTML=RUNS.length?'<table><tr><th>When</th><th>Target</th><th>Findings</th><th>Results</th><th></th></tr>'+RUNS.map((x,i)=>`<tr><td>${esc(x.mtime)}</td><td>${esc(x.target||((x.name||'').split('-')[1]||''))}</td><td>${x.summary?esc(x.summary.findings_before)+' → '+esc(x.summary.findings_after):'<span class="dim">PDF only</span>'}</td><td>${x.summary?esc(Object.entries(x.summary.results||{}).map(([k,v])=>k+' '+v).join(' · ')):'—'}</td><td>${x.interactive?`<button class="ghost" onclick="openRun(${i})">Read</button> `:''}<a href="/api/report/${esc(x.name)}" target="_blank">PDF</a></td></tr>`).join('')+'</table>':'<p class="dim">no reports yet — every patch run writes one</p>';
 const first=RUNS.findIndex(x=>x.interactive);
 if(first>=0&&!$('#report-detail').innerHTML)openRun(first);
}
async function openRun(i){
 const x=RUNS[i]; if(!x||!x.json_name)return;
 const d=await api('/api/report-data/'+encodeURIComponent(x.json_name));
 renderRun(d);
}
function findingsTable(fs){
 return '<table><tr><th>Package</th><th>CVEs</th><th>Severity</th><th>Confidence</th></tr>'+(fs.map(f=>`<tr><td>${esc(f.name)} ${esc(f.version||'')}</td><td>${(f.cve_ids||[]).map(esc).join('<br>')}</td><td>${f.known_exploited?'<span class="badge kev">KEV</span> ':''}<span class="badge">${esc(f.severity||'')}</span></td><td class="dim">${esc(f.confidence||'')}</td></tr>`).join('')||'<tr><td colspan=4 class="ok">none</td></tr>')+'</table>';
}
function renderRun(d){
 const sm=d.summary||{}; const steps=(d.outcome&&d.outcome.applied)||[];
 const chip=r=>r==='applied'?'<span class="badge">applied</span>':`<span class="badge kev">${esc(r||'')}</span>`;
 $('#report-detail').innerHTML=`<h2>Run — ${esc(d.target||'')} · ${esc(d.ts||'')}</h2>
 <div class="host"><h2 style="margin-top:.2rem">AI summary</h2>${d.ai_summary?`<p style="white-space:pre-wrap">${esc(d.ai_summary)}</p>`:`<button class="ghost" onclick="genSummary('${esc(d.pdf||'')}')">Generate AI summary</button><span id="sum-msg" class="dim"></span>`}</div>
 <div class="cards">${[['Findings before',sm.findings_before],['Findings after',sm.findings_after],['Steps',sm.steps],['Applied',(sm.results||{}).applied||0]].map(c=>`<div class="card"><b>${esc(c[1])}</b><span>${esc(c[0])}</span></div>`).join('')}</div>
 <h2>Steps</h2>`+(steps.map(st=>`<div class="host"><div class="kv"><span><b>${esc(st.name)}</b> ${esc(st.version||'')} · ${esc(st.manager||'')}</span><b>${chip(st.result)}${st.decision?' · decision: '+esc(st.decision):''}</b></div>${st.command?`<div class="dim" style="font-family:monospace;font-size:.82rem;word-break:break-all">${esc(st.command)}</div>`:''}${st.note?`<div class="dim">${esc(st.note)}</div>`:''}${st.ai_diagnosis&&st.ai_diagnosis.cause?`<div class=\"dim\">🤖 ${esc(st.ai_diagnosis.cause)}${st.ai_diagnosis.next?' → '+esc(st.ai_diagnosis.next):''}</div>`:''}${st.output_tail?`<details><summary class="dim" style="cursor:pointer">output</summary><pre>${esc(st.output_tail)}</pre></details>`:''}</div>`).join('')||'<p class="dim">no steps</p>')
 +`<h2>Still present after (${(d.findings_after||[]).length})</h2>`+findingsTable(d.findings_after||[]);
}
async function explainFinding(cveId,name,version){
 const box=$('#explain-box'); if(!box)return;
 box.innerHTML='<p class="spin">asking the model…</p>';
 const r=await api('/api/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cve_id:cveId,name,version})});
 box.innerHTML=r.error?`<p class="crit">${esc(r.error)}</p>`:`<div class="host"><h2 style="margin-top:.2rem">${esc(cveId)} — in plain English ${r.cached?'<span class="dim">(cached)</span>':''}</h2><p style="white-space:pre-wrap">${esc(r.explanation)}</p></div>`;
}
$('#ask-go').onclick=async()=>{
 const out=$('#ask-out'); out.style.display='block'; out.textContent='thinking…';
 const body={question:$('#ask-q').value,scan:LASTSCAN?{target:LASTSCAN.target,inventory_count:LASTSCAN.inventory_count,findings:LASTSCAN.findings}:null};
 const r=await api('/api/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 out.textContent=r.error?('error: '+r.error):r.answer;
};
$('#ask-q').addEventListener('keydown',e=>{if(e.key==='Enter')$('#ask-go').click();});
async function genSummary(pdfName){
 const m=$('#sum-msg'); if(m)m.textContent=' asking the model…';
 const x=RUNS.find(r=>r.name===pdfName);
 if(!x||!x.json_name){if(m)m.textContent=' (no data file for this run)';return;}
 const r=await api('/api/report-summary',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({json_name:x.json_name})});
 if(r.error){if(m)m.textContent=' error: '+r.error;return;}
 const d=await api('/api/report-data/'+encodeURIComponent(x.json_name));
 renderRun(d);
}
let SWARM=null, SWCONFIRM=null;
function swRow(e){
 const chip=e.class==='enemy'?'<span class="chip bad" style="font-size:.95rem;padding:.25rem .6rem">☠ ENEMY</span>':e.class==='friendly'?'<span class="chip ok" style="font-size:.95rem;padding:.25rem .6rem">✓ FRIENDLY</span>':'<span class="chip warn" style="font-size:.95rem;padding:.25rem .6rem">? UNKNOWN</span>';
 const marks=e.class==='friendly'
   ? `<button data-mark="hostile" data-pid="${e.pid}">✖ Mark hostile</button>`
   : `<button data-mark="friendly" data-pid="${e.pid}">✓ It's mine</button> <button data-mark="hostile" data-pid="${e.pid}">✖ Mark hostile</button>`;
 const acts=`<button data-act="freeze" data-pid="${e.pid}">❄️ Freeze</button> <button data-act="resume" data-pid="${e.pid}">▶ Resume</button> <button data-act="kill" data-pid="${e.pid}">☠️ Kill</button>`;
 return `<tr style="border-left:6px solid ${e.class==='enemy'?'#e5534b':e.class==='friendly'?'#3fb950':'#d29922'}"><td>${chip}</td><td>${e.pid}</td><td style="max-width:24rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.cmd)}">${esc(e.cmd)}</td><td>${e.cpu}% / ${e.mem}%</td><td><b>${esc(e.why||'')}</b><br><span class="dim">${esc((e.signals||[]).join('; ')||'')}</span></td><td class="dim">${esc((e.endpoints||[]).join(', ')||'—')}</td><td style="white-space:nowrap">${marks}<br>${acts}</td></tr>`;
}
function swTable(list){
 return `<table><tr><th>verdict</th><th>pid</th><th>process</th><th>cpu/mem</th><th>why — in plain words</th><th>talking to</th><th>your call</th></tr>${list.map(swRow).join('')}</table>`;
}
async function loadSwarm(){
 const out=$('#sw-out');
 const _a=$('#sw-scan'); if(_a)_a.onclick=loadSwarm; const _b=$('#sw-assess'); if(_b)_b.onclick=swAssess;
 out.innerHTML='<p class="dim">running census…</p>';
 const d=await api('/api/swarm'); SWARM=d;
 if(d.error){out.innerHTML=`<p>⚠️ ${esc(d.error)}</p>`;return;}
 const swarms=(d.swarms||[]).map(sw=>`<div class="host" style="border-color:#e5534b"><b>⚠ moving together — ${esc(sw.kind)}</b> · ${esc(sw.key)}<br>${esc(sw.reason)}<br><span class="dim">members: ${sw.members.join(', ')}</span></div>`).join('');
 const inc=(d.incidents||[]).map(i=>`<div class="kv"><span>${esc(i.ts)}</span><b>${esc(i.action)} pid ${i.pid}</b></div><div class="dim" style="margin:-.3rem 0 .4rem">${esc(i.cmd||'')}</div>`).join('');
 const sec=(title,color,list,empty)=>list.length?`<h2 style="border-left:8px solid ${color};padding-left:.5rem">${title} — ${list.length}</h2>${swTable(list)}`:`<h2 style="border-left:8px solid ${color};padding-left:.5rem">${title} — 0</h2><p class="dim">${empty}</p>`;
 out.innerHTML=`<div class="cards" style="margin:.6rem 0">
  <div class="card" style="border-color:#e5534b"><b style="color:#e5534b">${(d.enemy||[]).length}</b><span>☠ ENEMY</span></div>
  <div class="card" style="border-color:#d29922"><b style="color:#d29922">${(d.unknown||[]).length}</b><span>? UNKNOWN</span></div>
  <div class="card" style="border-color:#3fb950"><b style="color:#3fb950">${(d.friendly||[]).length}</b><span>✓ FRIENDLY — yours</span></div>
  <div class="card"><b>${(d.swarms||[]).length}</b><span>clusters moving together</span></div>
  <div class="card"><b>${d.total_processes}</b><span>processes scanned</span></div></div>
 <p class="dim">three verdicts, nothing in between: <b style="color:#3fb950">FRIENDLY</b> = identified as yours · <b style="color:#d29922">UNKNOWN</b> = agent-like, no owner match — teach the shield with <i>✓ It's mine</i> or <i>✖ Mark hostile</i> and it remembers the program · <b style="color:#e5534b">ENEMY</b> = marked hostile by you, talking to a blocked endpoint, or judged rogue by the AI.</p>
 ${swarms}
 ${sec('☠ ENEMY','#e5534b',d.enemy||[],'nothing hostile detected.')}
 ${sec('? UNKNOWN — not yours that we know of, not proven hostile','#d29922',d.unknown||[],'no unidentified agent-like processes.')}
 ${sec('✓ FRIENDLY — your agents','#3fb950',d.friendly||[],'no friendly agents detected.')}
 ${inc?`<h2>Incident log</h2>${inc}`:''}
 <div id="sw-confirm"></div>`;
 $$('#sw-out [data-act]').forEach(b=>b.onclick=()=>swAsk(b.dataset.act,+b.dataset.pid));
 $$('#sw-out [data-mark]').forEach(b=>b.onclick=async()=>{
  const r=await api('/api/swarm/mark',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:+b.dataset.pid,kind:b.dataset.mark})});
  if(r.ok){$('#sw-msg').textContent=`remembered: ${r.prog} → ${r.kind}`;loadSwarm();}
  else $('#sw-msg').textContent='⚠️ '+(r.error||'mark failed');
 });
}
function swAsk(action,pid){
 SWCONFIRM={action,pid};
 $('#sw-confirm').innerHTML=`<div class="host" style="border-color:#e5534b"><b>${esc(action)} pid ${pid}?</b> ${action==='freeze'?'It stops in place (SIGSTOP) — reversible with Resume.':action==='kill'?'It gets SIGTERM — this ends the process.':'It resumes (SIGCONT).'} A census snapshot is saved as evidence and the action is logged.<br>
 type <b>DEFEND</b> to confirm: <input id="sw-conf-in" style="width:8rem"> <button class="act" id="sw-conf-go">Confirm — ${esc(action)}</button> <button id="sw-conf-no">Cancel</button></div>`;
 $('#sw-conf-no').onclick=()=>{$('#sw-confirm').innerHTML='';};
 $('#sw-conf-go').onclick=async()=>{
  const r=await api('/api/swarm/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid,action,confirm:$('#sw-conf-in').value})});
  $('#sw-confirm').innerHTML=`<p>${r.ok?('✅ '+esc(action)+' fired on pid '+pid+' — logged'+(r.snapshot?' with an evidence snapshot':'')):('⚠️ '+esc(r.error||'failed'))}</p>`;
  if(r.ok)setTimeout(loadSwarm,800);
 };
}
async function swAssess(){
 $('#sw-assess-out').innerHTML='<p class="dim">assessing… (census + models)</p>';
 const r=await api('/api/swarm/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
 setTimeout(loadSwarm,400);
 $('#sw-assess-out').innerHTML=`<div class="host"><h2 style="margin-top:.2rem">🤖 AI assessment</h2>${r.verdict&&r.verdict.probability!==undefined?`<p><b>rogue-swarm verdict:</b> ${esc(r.verdict.verdict)} — p=${esc(r.verdict.probability)} on cluster “${esc(r.verdict.cluster||'')}” <span class="dim">(${esc(r.verdict.model||'')})</span></p>`:''}<div style="white-space:pre-wrap">${esc(r.assessment||'(no narrative model answered)')}</div></div>`;
}
async function loadPolicy(){
 const el=$('#policy-out'); if(!el)return;
 const r=await api('/api/policy');
 const p=r.policy||{};
 const tlist=(STATUS&&STATUS.targets)||[];
 const tbox=tlist.map(t=>`<label style="display:inline-block;margin-right:1rem"><input type="checkbox" class="pol-target" value="${esc(t)}" ${((p.targets||[]).includes(t))?'checked':''}> ${esc(t)}</label>`).join('');
 el.innerHTML=`<div class="host" style="margin-top:1.2rem"><h2 style="margin-top:.2rem">Automation policy — for agents</h2>
 <p class="dim">Scans are always free for any agent (MCP or CLI). <b>Patching without you in the loop</b> happens only inside this policy — it governs the MCP <i>auto_defend</i> tool, <i>aishield watch</i>, and any agent you connect (e.g. LM Studio). Lifelines never auto-patch under any policy, and your per-item approvals always count.</p>
 <div class="kv"><span>Enable automation</span><input type="checkbox" id="pol-enabled" ${p.enabled?'checked':''}></div>
 <div class="kv"><span>Let agents auto-patch</span><input type="checkbox" id="pol-apply" ${p.auto_apply?'checked':''}></div>
 <div class="kv"><span>Covered targets</span><span>${tbox||'<span class="dim">none configured</span>'}</span></div>
 <div class="kv"><span>Require the AI safety check to say "allow"</span><input type="checkbox" id="pol-req" ${p.require_decision_allow?'checked':''}></div>
 <div class="kv"><span>Let name-match findings auto-patch</span><input type="checkbox" id="pol-cand" ${p.allow_candidates?'checked':''}></div>
 <div class="kv"><span>Watch interval (hours)</span><input id="pol-interval" type="number" min="1" step="1" value="${esc(p.scan_interval_hours||24)}" style="width:5rem"></div>
 <div style="margin-top:.7rem"><button class="act" id="pol-save">Save policy</button> <span id="pol-msg" class="dim"></span></div>
 <p class="dim">stored in ${esc(r.file||'config/policy.local.yaml')} — never shipped anywhere; a fresh install defaults to fully off.</p></div>`;
 $('#pol-save').onclick=async()=>{
  const body={enabled:$('#pol-enabled').checked,auto_apply:$('#pol-apply').checked,require_decision_allow:$('#pol-req').checked,allow_candidates:$('#pol-cand').checked,scan_interval_hours:parseFloat($('#pol-interval').value)||24,targets:$$('.pol-target').filter(x=>x.checked).map(x=>x.value)};
  const rr=await api('/api/policy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  $('#pol-msg').textContent=rr.policy?'saved ✓':'error';
 };
}
async function loadSettings(){
 loadPolicy();
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
 <div><label>Decision endpoint (systemone wire)</label><input id="s-ep" value="${esc(c.roles.decision.endpoint||'/v1/systemone')}"></div></div>
 <div class="row"><div><label>Decisions endpoint (OpenAI wire)</label><input id="s-decisions" value="${esc(c.roles.decision.decisions_endpoint||'/v1/decisions')}"></div>
 <div><label>Model-server proxy</label><select id="s-proxymode"><option value="" ${!c.server.proxy_mode?'selected':''}>none</option><option value="env-connect" ${c.server.proxy_mode==='env-connect'?'selected':''}>env-connect (sandbox CONNECT proxy)</option></select></div>
 <div><label>Proxy port (env-connect only)</label><input id="s-proxyport" value="${esc(c.server.proxy_port||'')}" placeholder="3130"></div></div>
 <div class="row"><div><label>Decision protocol</label><select id="s-proto">${['auto','decisions','systemone','chat'].map(p=>`<option value="${p}" ${((c.roles.decision.protocol||'auto')===p)?'selected':''}>${p==='auto'?'auto — /v1/decisions, then /v1/systemone':p}</option>`).join('')}</select></div></div>
 <h2>Machines</h2>
 <label style="font-weight:400"><input type="checkbox" id="s-local" ${c.local_enabled?'checked':''}> <b>This device</b> — scan this machine (recommended; it's how antivirus-style tools work)</label>
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
 <div><label>Scan enabled</label><input type="checkbox" class="h-enabled" ${h.enabled?'checked':''} style="width:auto"></div>
 <div><label>&nbsp;</label><button class="ghost" onclick="this.closest('.host').remove()">✕ remove</button></div></div></div>`;
}
function addHostRow(){$('#s-hosts').insertAdjacentHTML('beforeend',hostRow({}));}
async function saveSettings(){
 const hosts=$$('#s-hosts .host').map(el=>({name:el.querySelector('.h-name').value,os:el.querySelector('.h-os').value,host:el.querySelector('.h-host').value,user:el.querySelector('.h-user').value,port:el.querySelector('.h-port').value,proxy:el.querySelector('.h-proxy').value,enabled:el.querySelector('.h-enabled').checked}));
 const body={server:{url:$('#s-url').value,api_key:$('#s-key').value,proxy_mode:$('#s-proxymode').value,proxy_port:$('#s-proxyport').value},triage:$('#s-triage').value,decision:$('#s-decision').value,decision_fallback:$('#s-fb').value,endpoint:$('#s-ep').value,decisions_endpoint:$('#s-decisions').value,protocol:$('#s-proto').value,local_enabled:$('#s-local').checked,hosts};
 try{
 const r=await api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 $('#s-msg').textContent=r.saved?'saved ✓ targets: '+r.targets.join(', '):'error: '+JSON.stringify(r);
 }catch(e){$('#s-msg').textContent='error: '+e.message;}
 loadStatus();
}
loadStatus();
</script></body></html>"""
