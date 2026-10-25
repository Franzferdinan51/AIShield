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
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, ai, config as cfgmod, cvenow, engine, feeds
from . import inventory, netwatch, patch
from . import report as reportmod, transport


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


def api_latest(source, limit=20, ecosystem=None):
    # One shared implementation for every surface (engine.latest):
    # CVE Now first, the local KEV catalog with an honest warning
    # when the service is unreachable.
    return engine.latest(source=source, limit=limit, ecosystem=ecosystem)


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


_JOBS = {}
_JOBS_LOCK = threading.Lock()


def _job_log(job, line):
    job["lines"].append(line)
    try:
        with open(job["logfile"], "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _run_patch_job(job, program):
    target = job["target"]
    try:
        _job_log(job, f"[{time.strftime('%H:%M:%S')}] scanning {target}…")
        before = engine.run_scan(target, program=program)
        _job_log(job, f"plan ready: {len(before['plan'])} step(s) from "
                      f"{len(before['findings'])} finding(s)")
        outcome = patch.apply_plan(before["plan"], confirm="PATCH",
                                   log=lambda line: _job_log(job, line))
        _job_log(job, "rescanning to verify what actually changed…")
        after = engine.run_scan(target, program=program)
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf = reportmod.write_run_report(base, target, before, outcome,
                                         after)
        job["outcome"] = outcome
        job["report_pdf"] = pdf
        job["findings_before"] = len(before["findings"])
        job["findings_after"] = len([f for f in after["findings"]
                                      if f["confidence"] != "error"])
        _job_log(job, f"done — findings {job['findings_before']} → "
                      f"{job['findings_after']}"
                      + (f" · report: {pdf}" if pdf else ""))
        job["state"] = "done"
    except Exception as e:
        job["error"] = str(e)[:400]
        _job_log(job, f"run failed: {job['error']}")
        job["state"] = "error"


def api_patch_start(body):
    if body.get("confirm") != "PATCH":
        return {"error": "type PATCH in the confirm box to apply"}
    with _JOBS_LOCK:
        for j in _JOBS.values():
            if j["state"] == "running":
                return {"error": "a patch run is already in progress — "
                                 "watch it in the live log",
                        "job_id": j["id"]}
        job_id = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        logdir = os.path.join(base, "data", "patch-jobs")
        os.makedirs(logdir, exist_ok=True)
        job = {"id": job_id, "target": body.get("target") or "local",
               "state": "running", "lines": [], "outcome": None,
               "report_pdf": None, "findings_before": None,
               "findings_after": None, "error": None,
               "started": time.strftime("%Y-%m-%d %H:%M:%S"),
               "logfile": os.path.join(logdir, job_id + ".log")}
        _JOBS[job_id] = job
    threading.Thread(target=_run_patch_job,
                     args=(job, body.get("program") or None),
                     daemon=True).start()
    return {"job_id": job_id, "state": "running"}


def api_patch_job(job_id=None):
    with _JOBS_LOCK:
        if job_id and job_id in _JOBS:
            job = _JOBS[job_id]
        elif _JOBS:
            job = _JOBS[max(_JOBS)]
        else:
            return {"job": None}
        return {"job": {k: job[k] for k in
                        ("id", "target", "state", "lines", "outcome",
                         "report_pdf", "findings_before",
                         "findings_after", "error", "started")}}


_NW_CACHE = {}


def api_netwatch(hours=24, target="local"):
    hit = _NW_CACHE.get(target)
    if hit and time.time() - hit["at"] < 300:
        return hit["data"]
    data = netwatch.census(hours=hours, target=target)
    _NW_CACHE[target] = {"at": time.time(), "data": data}
    return data


def api_netwatch_block(body):
    if body.get("confirm") != "BLOCK":
        return {"error": "confirm with BLOCK to block a source"}
    target = body.get("target") or "local"
    if target == "local":
        out = netwatch.block(body.get("ip") or "", actor="owner (GUI)")
    else:
        out = netwatch.block_remote(target, body.get("ip") or "",
                                    actor="owner (GUI)")
    _NW_CACHE.pop(target, None)
    return out


def api_netwatch_unblock(body):
    out = netwatch.unblock(body.get("ip") or "", actor="owner (GUI)")
    _NW_CACHE.pop("local", None)
    return out


def api_netwatch_assess(body=None):
    target = (body or {}).get("target") or "local"
    out = netwatch.assess(api_netwatch(target=target))
    return out


def api_netwatch_sampler():
    import sys as _sys
    if getattr(_sys, "frozen", False):
        argv = [_sys.executable]
    elif os.path.exists(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "bin", "aishield")):
        argv = [os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "bin", "aishield")]
    else:
        return {"error": "no runnable shield entry found for the "
                         "sampler"}
    sysname = __import__("platform").system()
    if sysname == "Darwin":
        plist = os.path.expanduser(
            "~/Library/LaunchAgents/com.aishield.netwatch.plist")
        os.makedirs(os.path.dirname(plist), exist_ok=True)
        with open(plist, "w") as f:
            f.write(netwatch.sampler_plist(argv))
        import subprocess as _sp
        _sp.run(["launchctl", "unload", plist], capture_output=True)
        _sp.run(["launchctl", "load", plist], capture_output=True)
        return {"installed": True,
                "detail": "LaunchAgent com.aishield.netwatch — a "
                          "connection snapshot every 60 seconds"}
    return {"error": f"sampler auto-install is macOS-only for now; "
                     f"run `aishield netwatch --sample` from cron/"
                     f"Task Scheduler on {sysname}"}


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
        if ai.triage_model():
            return {"error": "the chat model did not answer — "
                             "try again in a moment"}
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
        if ai.triage_model():
            return {"error": "the chat model did not answer — "
                             "try again in a moment"}
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
        if ai.triage_model():
            return {"error": "the chat model did not answer — "
                             "try again in a moment"}
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
    try:
        pid = int(body.get("pid") or 0)
    except (TypeError, ValueError):
        return {"error": "pid must be an integer"}
    return swarmmod.act(pid, body.get("action") or "",
                        body.get("confirm") or "")


def api_swarm_mark(body):
    from . import swarm as swarmmod
    try:
        pid = int(body.get("pid") or 0)
    except (TypeError, ValueError):
        return {"error": "pid must be an integer"}
    return swarmmod.mark(pid, body.get("kind") or "")


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
        try:
            pol["scan_interval_hours"] = float(body["scan_interval_hours"])
        except (TypeError, ValueError):
            pass  # garbage interval: keep the stored value
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
            if u.path == "/api/patch/job":
                q = parse_qs(u.query)
                return self._send(200, api_patch_job(
                    (q.get("id") or [None])[0]))
            if u.path.startswith("/api/patch/log/"):
                jid = os.path.basename(u.path.rsplit("/", 1)[-1])
                base = os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))
                lp = os.path.join(base, "data", "patch-jobs",
                                  jid + ".log")
                if os.path.exists(lp):
                    with open(lp, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="patch-{jid}.log"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                return self._send(404, {"error": "no such patch log"})
            if u.path == "/api/netwatch":
                q = parse_qs(u.query)
                try:
                    hours = int((q.get("hours") or ["24"])[0])
                except (TypeError, ValueError):
                    hours = 24
                return self._send(200, api_netwatch(
                    hours, (q.get("target") or ["local"])[0]))
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
                try:
                    limit = int((q.get("limit") or ["20"])[0])
                except (TypeError, ValueError):
                    limit = 20
                return self._send(200, api_latest(
                    (q.get("source") or ["critical"])[0], limit=limit))
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
            if self.path == "/api/patch/start":
                return self._send(200, api_patch_start(body))
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
            if self.path == "/api/netwatch/block":
                return self._send(200, api_netwatch_block(body))
            if self.path == "/api/netwatch/unblock":
                return self._send(200, api_netwatch_unblock(body))
            if self.path == "/api/netwatch/assess":
                return self._send(200, api_netwatch_assess(body))
            if self.path == "/api/netwatch/sampler":
                return self._send(200, api_netwatch_sampler())
            return self._send(404, {"error": "not found"})
        except RuntimeError as e:
            return self._send(200, {"error": str(e)[:400]})
        except Exception as e:
            return self._send(500, {"error": str(e)[:400]})


def serve(port=8770, open_browser=True):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        from . import netwatch as _nw
        _nw.start_canaries()
        print("netwatch canaries listening on %s "
              "(accept-and-log only, never speak; hits land in the "
              "Netwatch tab)" % ", ".join(str(p) for p in sorted(
                  _nw.CANARY_PORTS)))
    except Exception:
        pass
    threading.Thread(target=lambda: api_netwatch(24, "local"),
                     daemon=True).start()
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
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
 :root{
  --bg:#0a0e16; --panel:#101623; --panel2:#0d1320; --line:rgba(148,170,205,.14);
  --line2:rgba(148,170,205,.22); --txt:#e9eef8; --dim:#8d9bb5; --faint:#64718c;
  --acc:#4cc3e6; --acc2:#8b7cff; --teal:#3ecf9a; --warn:#f2b544; --bad:#f2785f;
  --r:14px; --shadow:0 10px 30px rgba(0,0,0,.35);
 }
 *{box-sizing:border-box}
 html{scrollbar-color:rgba(148,170,205,.3) transparent}
 body{margin:0;color:var(--txt);display:flex;min-height:100vh;background:var(--bg);
  font-family:"Avenir Next","Segoe UI",system-ui,-apple-system,sans-serif;
  font-size:15px;line-height:1.45;-webkit-font-smoothing:antialiased}
 ::selection{background:rgba(76,195,230,.32)}
 :focus-visible{outline:2px solid rgba(76,195,230,.55);outline-offset:2px;border-radius:6px}
 /* ---------- sidebar ---------- */
 nav{width:224px;flex:none;display:flex;flex-direction:column;gap:2px;padding:18px 12px;
  background:var(--panel2);border-right:1px solid var(--line);position:sticky;top:0;height:100vh}
 nav .logo{display:flex;align-items:center;gap:.6rem;font-size:1.02rem;font-weight:600;
  letter-spacing:.01em;padding:.1rem .5rem .9rem}
 nav .logo .bub{width:34px;height:34px;flex:none;display:grid;place-items:center;font-size:1.05rem;
  border-radius:10px;background:linear-gradient(150deg,#2b4a63,#1d2f4a);border:1px solid var(--line2)}
 .navlbl{font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.11em;
  color:var(--faint);padding:.85rem .6rem .3rem}
 nav button{position:relative;background:transparent;border:0;color:var(--dim);text-align:left;
  padding:.52rem .65rem .52rem .8rem;border-radius:9px;font:inherit;font-size:.93rem;font-weight:500;
  cursor:pointer;transition:background .15s,color .15s;width:100%}
 nav button:hover{color:var(--txt);background:rgba(148,170,205,.07)}
 nav button.on{color:#fff;background:rgba(76,195,230,.12)}
 nav button.on::before{content:"";position:absolute;left:0;top:20%;bottom:20%;width:3px;
  border-radius:3px;background:var(--acc)}
 nav .foot{margin-top:auto;color:var(--faint);font-size:.76rem;padding:.7rem .5rem 0;
  border-top:1px solid var(--line)}
 /* ---------- layout / topbar / views ---------- */
 main{flex:1;padding:0 2rem 2.4rem;max-width:1180px;min-width:0}
 #topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:1rem;
  padding:.85rem 0 .8rem;background:linear-gradient(180deg,var(--bg) 78%,transparent);
  border-bottom:1px solid var(--line);margin-bottom:1.4rem}
 #crumb{font-size:.95rem;font-weight:600;letter-spacing:.01em}
 .tb-right{margin-left:auto;display:flex;gap:.5rem;align-items:center}
 .pill{display:inline-flex;align-items:center;gap:.42rem;border:1px solid var(--line2);
  border-radius:999px;padding:.22rem .7rem;font-size:.78rem;color:var(--dim);background:var(--panel)}
 .pill .dot{width:7px;height:7px;border-radius:50%;background:var(--teal);flex:none}
 .view{display:none} .view.on{display:block;animation:rise .28s ease both}
 @keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
 h1{font-size:1.28rem;font-weight:600;margin:.2rem 0 1rem;letter-spacing:.01em}
 h2{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.09em;
  color:var(--dim);margin:1.6rem 0 .7rem}
 /* ---------- cards / panels ---------- */
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:.8rem}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:.95rem 1.05rem;box-shadow:var(--shadow)}
 .card b{font-size:1.45rem;font-weight:600;display:block;letter-spacing:.01em;
  font-variant-numeric:tabular-nums}
 .card span{color:var(--dim);font-size:.74rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em}
 .host{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:.9rem 1.05rem;margin:.6rem 0;box-shadow:var(--shadow)}
 /* ---------- tables ---------- */
 table{width:100%;border-collapse:collapse;font-size:.92rem}
 th{color:var(--faint);font-weight:600;text-transform:uppercase;font-size:.7rem;
  letter-spacing:.07em;padding:.45rem .7rem;text-align:left;border-bottom:1px solid var(--line2);
  position:sticky;top:0;background:var(--panel)}
 td{padding:.55rem .7rem;border-bottom:1px solid var(--line);vertical-align:top}
 tr:last-child td{border-bottom:0}
 tbody tr{transition:background .12s} tr:hover td{background:rgba(148,170,205,.05)}
 .badge{display:inline-block;border-radius:999px;padding:.13rem .58rem;font-size:.74rem;
  font-weight:600;background:rgba(148,170,205,.12);border:1px solid var(--line2);color:var(--txt)}
 .kev{background:rgba(242,120,95,.16);border-color:rgba(242,120,95,.45);color:#ffc9bc}
 .crit{color:var(--bad);font-weight:600} .ok{color:var(--teal);font-weight:550} .dim{color:var(--dim)}
 .kv{display:flex;justify-content:space-between;gap:1rem;padding:.34rem 0;border-bottom:1px solid var(--line)}
 .kv:last-child{border-bottom:0} .kv span{color:var(--dim)} .kv b{font-weight:550;text-align:right;word-break:break-all}
 .chips{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.35rem}
 .clickable{cursor:pointer} .clickable:hover td{background:rgba(76,195,230,.07)}
 /* ---------- controls ---------- */
 input,select,textarea{width:100%;background:var(--panel2);border:1px solid var(--line2);
  color:var(--txt);border-radius:10px;padding:.55rem .7rem;font:inherit;outline:none;
  transition:border-color .15s, box-shadow .15s}
 input:focus,select:focus,textarea:focus{border-color:rgba(76,195,230,.55);
  box-shadow:0 0 0 3px rgba(76,195,230,.13)}
 select option{background:var(--panel);color:var(--txt)}
 label{display:block;margin:.6rem 0 .3rem;font-weight:550;font-size:.83rem;color:#c3cfe2}
 .row{display:flex;gap:.9rem;flex-wrap:wrap;align-items:end} .row>div{flex:1;min-width:160px}
 button{font:inherit}
 button.act{background:#1d9e77;color:#eafff6;border:1px solid rgba(255,255,255,.14);
  border-radius:10px;padding:.58rem 1.2rem;font-weight:600;cursor:pointer;transition:filter .15s, transform .1s}
 button.act:hover{filter:brightness(1.1)} button.act:active{transform:translateY(1px)}
 button.act:disabled{opacity:.55;cursor:default;filter:none}
 button.ghost{background:transparent;color:var(--txt);border:1px solid var(--line2);
  border-radius:10px;padding:.58rem 1.05rem;font-weight:550;cursor:pointer;transition:all .15s}
 button.ghost:hover{border-color:rgba(76,195,230,.5);background:rgba(76,195,230,.06)}
 #apply-go{background:#d97a2b;color:#fff5e8;border-color:rgba(255,255,255,.16)}
 #apply-go:hover{filter:brightness(1.08)}
 input[type=checkbox]{appearance:none;-webkit-appearance:none;width:44px!important;height:25px;flex:none;
  vertical-align:-7px;border-radius:999px;padding:0;cursor:pointer;position:relative;outline:none;
  background:#232f47;border:1px solid var(--line2);transition:all .18s}
 input[type=checkbox]::before{content:"";position:absolute;top:2px;left:2px;width:19px;height:19px;
  border-radius:50%;background:#c9d4e8;transition:left .18s}
 input[type=checkbox]:checked{background:#2b7ea8;border-color:rgba(255,255,255,.2)}
 input[type=checkbox]:checked::before{left:21px;background:#fff}
 /* ---------- panels, log, map, toasts ---------- */
 pre{background:#0a0f1a;border:1px solid var(--line);border-radius:12px;padding:.9rem 1rem;
  white-space:pre-wrap;font-size:.85rem}
 #patch-log{background:#070b12;border:1px solid var(--line);border-radius:10px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;line-height:1.5}
 #patch-live{border-left:3px solid var(--acc)}
 #nw-map{border:1px solid var(--line);box-shadow:none}
 .leaflet-container{font:inherit;background:#0a0f1a}
 .spin{color:var(--warn);font-weight:550}
 .spin::before{content:"◌ ";animation:rot 1s linear infinite;display:inline-block}
 @keyframes rot{to{transform:rotate(360deg)}}
 #scan-state:empty{display:none}
 #toasts{position:fixed;right:18px;bottom:18px;z-index:99;display:flex;flex-direction:column;gap:.5rem;max-width:360px}
 .toast{background:var(--panel);border:1px solid var(--line2);border-left:3px solid var(--teal);
  border-radius:12px;padding:.7rem .95rem;font-size:.9rem;box-shadow:0 16px 40px rgba(0,0,0,.5);
  animation:rise .25s ease both}
 .toast.warn{border-left-color:var(--warn)} .toast.err{border-left-color:var(--bad)}
 @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
 @media (max-width:860px){body{flex-direction:column} nav{width:auto;height:auto;position:static;
  flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--line)}
  .navlbl{display:none} nav .logo{padding-bottom:.1rem} nav .foot{display:none}
  nav button{width:auto} nav button.on::before{display:none} main{padding:0 1.1rem 2rem}}
</style></head><body>
<nav>
 <div class="logo"><span class="bub">🛡️</span> AI Shield</div>
 <div class="navlbl">Overview</div>
 <button data-v="dash" class="on">📊&ensp;Dashboard</button>
 <div class="navlbl">Defend</div>
 <button data-v="scan">🔍&ensp;Scan</button>
 <button data-v="patch">🩹&ensp;Patch</button>
 <div class="navlbl">Intel</div>
 <button data-v="reports">📄&ensp;Reports</button>
 <button data-v="ask">💬&ensp;Ask</button>
 <button data-v="latest">🆕&ensp;Latest CVEs</button>
 <button data-v="cve">🔎&ensp;CVE lookup</button>
 <div class="navlbl">Watch</div>
 <button data-v="swarm">🐝&ensp;Swarm</button>
 <button data-v="netwatch">🌐&ensp;Netwatch</button>
 <div class="navlbl">System</div>
 <button data-v="settings">⚙️&ensp;Settings</button>
 <div class="foot" id="ver"></div>
</nav>
<main>
 <div id="topbar"><span id="crumb">Dashboard</span><span class="tb-right"><span class="pill" id="tb-pill"><span class="dot"></span><span id="tb-status">shield starting…</span></span></span></div>
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
  <div id="patch-live" class="card" style="display:none;margin-top:1rem">
    <div class="kv"><b id="patch-live-title">Patch run</b><span id="patch-live-actions"></span></div>
    <pre id="patch-log" style="max-height:320px;overflow:auto;margin:.6rem 0 0"></pre>
    <div id="patch-live-results"></div>
  </div>
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
 <section id="v-netwatch" class="view"><h1>Netwatch — who's probing this machine</h1>
<p class="dim">Sources caught pinging, scanning or trying to log in to this machine's services — tracked from auth logs, live connections and the sampler, located on the map, and blockable at the firewall. Your own fleet (tailnet / local network) is listed separately and can never be blocked.</p>
<div class="row"><div><label>Machine</label><select id="nw-target"></select></div>
<div><button class="act" id="nw-scan">🌐 Refresh watch</button></div>
<div><button id="nw-assess">🤖 Assess with AI</button></div>
<div><button class="ghost" id="nw-sampler">⏱️ Enable 24/7 watch (this machine)</button></div></div>
<div style="margin:.2rem 0"><span id="nw-msg" class="dim"></span></div>
<div id="nw-out"></div><div id="nw-assess-out"></div></section>
<section id="v-settings" class="view"><h1>Settings</h1><div id="settings-out"></div><div id="policy-out"></div></section>
</main>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
async function api(p,o){const r=await fetch(p,o);return r.json();}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
let STATUS=null;
const TITLES={dash:'Dashboard',scan:'Scan',patch:'Patch',reports:'Reports',ask:'Ask the shield',latest:'Latest CVEs',cve:'CVE lookup',swarm:'Swarm',netwatch:'Netwatch',settings:'Settings'};
function go(v){const _c=$('#crumb');if(_c)_c.textContent=TITLES[v]||v;$$('nav button').forEach(x=>x.classList.toggle('on',x.dataset.v===v));$$('.view').forEach(x=>x.classList.remove('on'));$('#v-'+v).classList.add('on');if(v==='settings')loadSettings();if(v==='swarm')loadSwarm();if(v==='netwatch')loadNetwatch();if(v==='reports')loadReports();if(v==='patch')loadPlan();}
$$('nav button').forEach(b=>b.onclick=()=>go(b.dataset.v));
async function loadStatus(){
 STATUS=await api('/api/status');
 $('#ver').textContent='v'+STATUS.version+' · local '+(STATUS.local_enabled?'on':'off');
 const _tb=$('#tb-status'); if(_tb)_tb.textContent='v'+STATUS.version+' · '+(STATUS.targets||[]).length+' target'+((STATUS.targets||[]).length===1?'':'s')+' · KEV '+(STATUS.kev_date||'').slice(0,10);
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
 const _keep={}; for(const _id of ['scan-target','patch-target','nw-target']){const _e=document.getElementById(_id); if(_e&&_e.value)_keep[_id]=_e.value;}
 $('#scan-target').innerHTML=opts; $('#patch-target').innerHTML=opts; const _nwt=$('#nw-target'); if(_nwt)_nwt.innerHTML=opts;
 for(const _id of ['scan-target','patch-target','nw-target']){const _e=document.getElementById(_id); if(_e&&_keep[_id]&&STATUS.targets.includes(_keep[_id]))_e.value=_keep[_id];}
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
 const rows=fs.map(f=>`<tr><td>${esc(f.name)} ${esc(f.version)}</td><td class="clickable" onclick="lookupCve('${esc((f.cve_ids||[])[0]||'')}')">${(f.cve_ids||[]).map(esc).join('<br>')}</td><td>${f.known_exploited?'<span class="badge kev">KEV</span> ':''}<span class="badge">${esc(f.cvss ?? f.severity_label ?? '')}</span></td><td>${esc((f.fixed_versions||[]).join(', '))}</td><td class="dim">${esc(f.confidence)}${f.ai_era?` <span class="badge">ai era: ${esc(f.ai_era.verdict)}</span>`:''}</td><td>${(f.cve_ids||[]).length?`<button class="ghost" onclick="explainFinding('${esc((f.cve_ids||[])[0])}','${esc(f.name)}','${esc(f.version)}')">explain</button>`:''}</td></tr>`).join('');
 $('#scan-out').innerHTML=(r.warnings&&r.warnings.length?`<p class="spin">⚠ ${r.warnings.map(esc).join('<br>')}</p>`:'')+(r.cleared&&r.cleared.length?`<p class="ok">✓ cleared by version check (installed is outside the CVE's affected range): ${r.cleared.map(c=>esc(c.name)+' '+esc(c.version)+' · '+esc(c.cve)).join(' &nbsp; ')}</p>`:'')+(r.changes&&r.changes.since?`<p class=\"dim\">since last scan (${esc(r.changes.since)}): <b>${(r.changes.new||[]).length} new</b>, <b>${(r.changes.resolved||[]).length} resolved</b>${(r.changes.resolved||[]).length?' — resolved: '+r.changes.resolved.map(f=>esc(f.name)).join(', '):''}</p>`:'')+`<table><tr><th>Package</th><th>CVEs</th><th>Severity</th><th>Fixed in</th><th>Confidence</th><th></th></tr>${rows||'<tr><td colspan=6 class="ok">no findings match</td></tr>'}</table><div id="explain-box"></div>`+(r.ai_brief?`<h2>AI brief (${esc(r.ai_model||'')})</h2><pre>${esc(r.ai_brief)}</pre>`:'');
}
$('#scan-filter').addEventListener('input',renderScan);
$('#patch-target').addEventListener('change',()=>{loadPlan();});
$('#scan-target').addEventListener('change',()=>{LASTSCAN=null;$('#scan-out').innerHTML='';$('#scan-filter-row').style.display='none';$('#scan-state').textContent='target changed — press Scan';});
$('#scan-kev').addEventListener('change',renderScan);
async function approveAct(btn,action){
 const d=btn.dataset;
 await api('/api/approvals',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value,name:d.name,manager:d.manager,cve_ids:d.cves?d.cves.split(','):[],action})});
 loadPlan();
}
const MGR_ACTION={brew:'Homebrew upgrade',pip:'pip upgrade',apt:'system package upgrade',npm:'npm update',winapp:'winget upgrade',macapp:'in-app update',app:'in-app update',binary:'manual update'};
const isHold=x=>x.decision==='hold',isLife=x=>((x.decision_detail||{}).via==='lifeline-rule');
const runnable=x=>x.auto&&(!isHold(x)||x.approved_override);
function actsHtml(x){
 const attrs=`data-name="${esc(x.name)}" data-manager="${esc(x.manager)}" data-cves="${esc((x.cve_ids||[]).join(','))}"`;
 if(x.acknowledged)return `<div style="margin-top:.5rem"><span class="badge">✓ acknowledged by you</span> <button class="ghost" onclick="approveAct(this,'revoke')" ${attrs}>undo</button></div>`;
 if(x.approved)return `<div style="margin-top:.5rem"><span class="badge">approved by you</span> <button class="ghost" onclick="approveAct(this,'revoke')" ${attrs}>undo</button></div>`;
 const patchable=(['brew','npm','apt','pip'].includes(x.manager)||isHold(x)||(x.manager==='winapp'&&x.winget_id))&&!isLife(x);
 return `<div style="margin-top:.5rem">${x.approval_blocked?`<span class="crit">⛔ approval won't work here: ${esc(x.approval_blocked)}</span> `:(patchable?`<button class="act" onclick="approveAct(this,'patch')" ${attrs}>✓ Approve &amp; patch</button> `:'')}<button class="ghost" onclick="approveAct(this,'acknowledge')" ${attrs}>Acknowledge</button></div>`;
}
async function loadPlan(){
 $('#plan-out').innerHTML='<span class="spin">checking what can be patched…</span>';
 $('#apply-zone').innerHTML='';
 checkPatchJob();
 const target=$('#patch-target').value;
 const r=await api('/api/patch/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
 if(r.error){$('#plan-out').innerHTML=`<p class="crit">${esc(r.error)}</p>`;return;}
 const auto=(r.plan||[]).filter(runnable),manual=(r.plan||[]).filter(x=>!runnable(x));const manualActive=manual.filter(x=>!x.acknowledged);
 const holdLine=x=>isLife(x)?`<div>⛔ lifeline package — the shield never auto-patches these (kernel / SSH / package-manager class); update it yourself during maintenance.</div>`:((isHold(x)&&!x.approved_override)?`<div class="dim">AI safety check: hold${x.decision_detail&&x.decision_detail.via?' via '+esc(x.decision_detail.via):''} — approving below is your explicit override.</div>`:'');
 const card=x=>{const rd=runnable(x);return `<div class="host"><div class="kv"><span><b>${esc(x.name)}</b> ${esc(x.version||'')}${rd?` → ${esc((x.fixed_versions||[])[0]||'latest')}`:''}</span><b>${rd?'<span class="ok">ready to patch</span>':'<span class="crit">needs you</span>'}</b></div>${rd?`<div class="dim">${esc(MGR_ACTION[x.manager]||(x.manager+' update'))}${x.decision?' · AI safety check: '+esc(x.decision):''}</div><div class="dim" style="font-family:monospace;font-size:.82rem;word-break:break-all">${esc(x.command||'')}</div>`+(x.approved?actsHtml(x):''):holdLine(x)+`<div>${esc(x.note||'manual step')}</div>`+actsHtml(x)}</div>`;};
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
 const live=$('#patch-live');live.style.display='block';
 $('#patch-live-title').textContent='Patch run — starting…';
 $('#patch-live-actions').innerHTML='';
 $('#patch-log').textContent='';
 $('#patch-live-results').innerHTML='';
 const r=await api('/api/patch/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('#patch-target').value,confirm:$('#apply-confirm').value})});
 if(r.error&&!r.job_id){$('#patch-log').textContent='error: '+r.error;return;}
 $('#apply-zone').innerHTML='';
 pollPatchJob(r.job_id,0);
}
let PATCH_POLL=null;
async function checkPatchJob(){
 try{
  const r=await api('/api/patch/job');
  if(!r.job)return;
  const j=r.job;
  $('#patch-live').style.display='block';
  renderPatchLog(j,0);
  if(j.state==='running'){pollPatchJob(j.id,(j.lines||[]).length);}
  else{renderPatchOutcome(j);}
 }catch(e){}
}
function pollPatchJob(id,seen){
 if(PATCH_POLL)clearInterval(PATCH_POLL);
 PATCH_POLL=setInterval(async()=>{
  const r=await api('/api/patch/job?id='+encodeURIComponent(id));
  if(!r.job){clearInterval(PATCH_POLL);return;}
  const j=r.job;
  seen=renderPatchLog(j,seen);
  if(j.state!=='running'){clearInterval(PATCH_POLL);PATCH_POLL=null;renderPatchOutcome(j);loadPlanSoft();const _done=((j.outcome||{}).applied||[]);const _ok=_done.every(e=>!e.result||String(e.result).indexOf('applied')===0||e.result==='skipped-manual'||e.result==='held-by-decision');toast(_ok?'✓ patch run finished on '+j.target:'patch run finished on '+j.target+' — some steps need attention',_ok?'':'warn');}
 },1500);
}
function renderPatchLog(j,seen){
 const pre=$('#patch-log');const lines=j.lines||[];
 for(let i=seen;i<lines.length;i++){pre.textContent+=(i?'\n':'')+lines[i];}
 if(lines.length>seen){pre.scrollTop=pre.scrollHeight;}
 $('#patch-live-title').textContent=(j.state==='running'?'⚙️ Patching '+j.target+'…':'Patch run · '+j.target+' · '+j.started);
 return lines.length;
}
function renderPatchOutcome(j){
 const box=$('#patch-live-results');
 const pdf=j.report_pdf?String(j.report_pdf).split('/').pop():'';
 $('#patch-live-actions').innerHTML=`<a class="ghost" style="padding:.3rem .7rem;text-decoration:none" href="/api/patch/log/${encodeURIComponent(j.id)}">⬇ Download log</a>`+(pdf?` <a class="ghost" style="padding:.3rem .7rem;text-decoration:none" href="/api/report/${encodeURIComponent(pdf)}" target="_blank">📄 PDF report</a>`:'');
 if(j.state==='error'){box.innerHTML=`<p class="crit">✗ this run failed: ${esc(j.error||'unknown error')} — the log above has the details.</p>`;return;}
 const steps=((j.outcome||{}).applied||[]);
 const counts={};steps.forEach(st=>{counts[st.result]=(counts[st.result]||0)+1;});
 const icon=res=>String(res||'').indexOf('applied')===0?'✅':(String(res).indexOf('blocked')===0?'⛔':((res==='skipped-manual'||res==='held-by-decision')?'✋':'✗'));
 const rows=steps.map(st=>`<div class="host"><div class="kv"><span>${icon(st.result)} <b>${esc(st.name)}</b></span><b>${esc(st.result)}</b></div>${st.ai_diagnosis&&st.ai_diagnosis.cause?`<div class="dim">🤖 ${esc(st.ai_diagnosis.cause)}${st.ai_diagnosis.next?' → '+esc(st.ai_diagnosis.next):''}</div>`:''}</div>`).join('');
 box.innerHTML=`<h2 style="margin:.8rem 0 .2rem">✓ Patch run finished — findings ${j.findings_before} → ${j.findings_after}</h2><p class="dim">${Object.entries(counts).map(([k,v])=>v+' '+k).join(' · ')||'no steps ran'}</p>${rows}`;
}
async function loadPlanSoft(){
 const cur=$('#patch-target').value;
 const r=await api('/api/patch/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:cur})});
 if(r.error||!r.plan)return;
 const auto=(r.plan||[]).filter(runnable);
 $('#plan-out').insertAdjacentHTML('afterbegin',`<p class="ok">plan refreshed after the run: ${auto.length} step(s) still patchable on ${esc(cur)}</p>`);
}
let NW_MAP=null,NW_LAYER=null;
let NW_TARGET='local';
async function loadNetwatch(){
 const _a=$('#nw-scan'); if(_a)_a.onclick=loadNetwatch;
 const _b=$('#nw-assess'); if(_b)_b.onclick=nwAssess;
 const _c=$('#nw-sampler'); if(_c)_c.onclick=nwSampler;
 const _t=$('#nw-target'); if(_t){NW_TARGET=_t.value||'local';_t.onchange=loadNetwatch;}
 $('#nw-out').innerHTML='<span class="spin">watching '+esc(NW_TARGET)+'… (a cold log history can take a moment)</span>';
 const r=await api('/api/netwatch?hours=24&target='+encodeURIComponent(NW_TARGET));
 if(r.error){$('#nw-out').innerHTML=`<p class="crit">${esc(r.error)}</p>`;return;}
 const t=r.totals||{};
 const geo=a=>{const g=a.geo||{};return [g.city,g.region,g.country].filter(Boolean).join(', ')||(g.label||'—');};
 const org=a=>{const g=a.geo||{};return g.org||g.isp||'';};
 const row=a=>`<tr><td><b>${esc(a.ip)}</b>${a.live_connected?' <span class="badge kev">connected now</span>':''}<br><span class="dim">${esc(geo(a))}</span><br><span class="dim">${esc(org(a))}</span></td><td><span class="badge" style="${a.level==='high'?'background:rgba(255,90,80,.25)':(a.level==='medium'?'background:rgba(255,190,60,.22)':'')}">${esc(a.level)}</span></td><td>${a.attempts||0} failed logins<br><span class="dim">${a.sampled_events||0} connection events</span></td><td class="dim">${esc((a.users||[]).slice(0,6).join(', ')||'—')}</td><td class="dim">${esc((a.services||[]).join(', ')||'—')}</td><td class="dim">${esc(a.first_seen||'')} → ${esc(a.last_seen||'')}</td><td>${a.blocked?'<span class="badge">⛔ blocked by you</span>':`<button class="act" data-ip="${esc(a.ip)}" onclick="nwBlock(this)">⛔ Block</button>`}</td></tr>`;
 const krow=a=>`<tr><td><b>${esc(a.ip)}</b><br><span class="dim">${esc((a.geo||{}).label||a.class)}</span></td><td class="dim">${esc((a.services||[]).join(', ')||'—')}</td><td>${a.attempts||0} failed<br><span class="dim">${a.sampled_events||0} events</span></td><td class="dim">${esc((a.sources||[]).join(', '))}</td></tr>`;
 $('#nw-out').innerHTML=`
 <div class="cards">
  <div class="card"><b>${t.public_sources||0}</b><span>public sources tracked</span></div>
  <div class="card"><b>${t.attempts||0}</b><span>failed login attempts (24h)</span></div>
  <div class="card"><b>${t.connected_now||0}</b><span>connected right now</span></div>
  <div class="card"><b>${t.blocked||0}</b><span>blocked by you</span></div>
 </div>
 ${r.note?`<p class="spin">⚠ ${esc(r.note)}</p>`:''}
 ${r.sampler_active?'':'<p class="dim">the 24/7 sampler is not installed yet — history builds from logs + live checks only. “Enable 24/7 watch” adds a snapshot every minute.</p>'}
 <div id="nw-map" style="height:340px;border-radius:14px;margin:.6rem 0;background:rgba(255,255,255,.04)"></div>
 <h3>🌍 Public sources — attackers &amp; probers</h3>
 <table><tr><th>Source</th><th>Risk</th><th>Activity</th><th>Users tried</th><th>Services</th><th>First → last seen</th><th></th></tr>${(r.attackers||[]).map(row).join('')||'<tr><td colspan=7 class="ok">no public attackers tracked in the last 24h — quiet network</td></tr>'}</table>
 ${(r.known_sources||[]).length?`<h3>🏠 Your own network (can never be blocked)</h3><table><tr><th>Source</th><th>Services</th><th>Activity</th><th>Seen via</th></tr>${(r.known_sources||[]).map(krow).join('')}</table>`:''}
 ${(NW_TARGET==='local'&&(r.blocked_list||[]).length)?`<h3>⛔ Blocklist (this machine)</h3><p>${(r.blocked_list||[]).map(ip=>`<span class="badge" style="margin-right:.4rem">${esc(ip)} <a href="#" onclick="nwUnblock(event,'${esc(ip)}')" style="color:inherit">✕ unblock</a></span>`).join('')}</p><p class="dim">blocks live in the shield's list immediately; the firewall copy applies via the generated script in the data folder (the result message after blocking says exactly how).</p>`:''}`;
 drawNwMap(r.attackers||[]);
}
function drawNwMap(attackers){
 const el=$('#nw-map'); if(!el)return;
 if(typeof L==='undefined'){el.innerHTML='<p class="dim" style="padding:1rem">map tiles need an internet connection (OpenStreetMap) — the table below has every location in text.</p>';return;}
 if(!NW_MAP){NW_MAP=L.map('nw-map').setView([30,0],2);L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:18,attribution:'© OpenStreetMap'}).addTo(NW_MAP);NW_LAYER=L.layerGroup().addTo(NW_MAP);}
 NW_LAYER.clearLayers();
 const pts=[];
 attackers.forEach(a=>{const g=a.geo||{};if(g.lat==null||g.lon==null)return;pts.push([g.lat,g.lon]);
  const color=a.level==='high'?'#ff5040':(a.level==='medium'?'#ffb02e':'#38e1ff');
  L.circleMarker([g.lat,g.lon],{radius:a.level==='high'?10:7,color,fillColor:color,fillOpacity:.55}).addTo(NW_LAYER)
   .bindPopup(`<b>${esc(a.ip)}</b><br>${esc([g.city,g.country].filter(Boolean).join(', '))}<br>${esc(g.org||g.isp||'')}<br>${a.attempts} failed attempts · risk ${a.level}${a.blocked?'<br>⛔ blocked':''}`);});
 if(pts.length)NW_MAP.fitBounds(pts,{padding:[30,30],maxZoom:5});
 setTimeout(()=>NW_MAP&&NW_MAP.invalidateSize(),80);
}
async function nwBlock(btn){
 const ip=btn.dataset.ip;
 if(btn.dataset.armed){btn.textContent='blocking…';
  const r=await api('/api/netwatch/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,confirm:'BLOCK',target:NW_TARGET})});
  if(r.error){$('#nw-msg').textContent='error: '+r.error;btn.textContent='⛔ Block';delete btn.dataset.armed;return;}
  if(r.applied)toast('⛔ '+ip+' blocked at the firewall');
  $('#nw-msg').textContent=r.applied?`${ip} blocked AND applied at the firewall.`:(NW_TARGET==='local'?`${ip} is on the blocklist. To apply at the firewall: ${r.how||''}`:`block on ${NW_TARGET} didn't apply: ${r.how||r.error||''}`);
  loadNetwatch();return;}
 btn.dataset.armed='1';btn.textContent='Really block '+ip+'?';
 setTimeout(()=>{if(btn.isConnected){delete btn.dataset.armed;btn.textContent='⛔ Block';}},5000);
}
async function nwUnblock(ev,ip){ev.preventDefault();
 const r=await api('/api/netwatch/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
 if(r.error){$('#nw-msg').textContent='error: '+r.error;return;}
 $('#nw-msg').textContent=`${ip} unblocked in the list — re-run the apply script to lift the firewall rule: ${r.how||''}`;
 loadNetwatch();}
async function nwAssess(){
 $('#nw-assess-out').innerHTML='<span class="spin">asking the model…</span>';
 const r=await api('/api/netwatch/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:NW_TARGET})});
 $('#nw-assess-out').innerHTML=r.error?`<p class="crit">${esc(r.error)}</p>`:`<div class="host"><h2 style="margin-top:.2rem">🤖 Netwatch assessment <span class="dim">(${esc(r.model||'')})</span></h2><p style="white-space:pre-wrap">${esc(r.assessment||'')}</p></div>`;
}
async function nwSampler(){
 const r=await api('/api/netwatch/sampler',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
 $('#nw-msg').textContent=r.error?('sampler: '+r.error):('✓ '+r.detail);
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
 return '<table><tr><th>Package</th><th>CVEs</th><th>Severity</th><th>Confidence</th></tr>'+(fs.map(f=>`<tr><td>${esc(f.name)} ${esc(f.version||'')}</td><td>${(f.cve_ids||[]).map(esc).join('<br>')}</td><td>${f.known_exploited?'<span class="badge kev">KEV</span> ':''}<span class="badge">${esc(f.cvss ?? f.severity_label ?? '')}</span></td><td class="dim">${esc(f.confidence||'')}</td></tr>`).join('')||'<tr><td colspan=4 class="ok">none</td></tr>')+'</table>';
}
function renderRun(d){
 const sm=d.summary||{}; const steps=(d.outcome&&d.outcome.applied)||[];
 const chip=r=>String(r||'').indexOf('applied')===0?'<span class="badge">applied</span>':`<span class="badge kev">${esc(r||'')}</span>`;
 $('#report-detail').innerHTML=`<h2>Run — ${esc(d.target||'')} · ${esc(d.ts||'')}</h2>
 <div class="host"><h2 style="margin-top:.2rem">AI summary</h2>${d.ai_summary?`<p style="white-space:pre-wrap">${esc(d.ai_summary)}</p>`:`<button class="ghost" onclick="genSummary('${esc(d.pdf||'')}')">Generate AI summary</button><span id="sum-msg" class="dim"></span>`}</div>
 <div class="cards">${[['Findings before',sm.findings_before],['Findings after',sm.findings_after],['Steps',sm.steps],['Applied',Object.entries(sm.results||{}).filter(([k])=>k.indexOf('applied')===0).reduce((a,[,v])=>a+v,0)]].map(c=>`<div class="card"><b>${esc(c[1])}</b><span>${esc(c[0])}</span></div>`).join('')}</div>
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
 if(rr.policy)toast('automation policy saved');
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
 if(r.saved)toast('settings saved');
 }catch(e){$('#s-msg').textContent='error: '+e.message;}
 loadStatus();
}
loadStatus();
function toast(msg,kind){const box=$('#toasts')||(()=>{const d=document.createElement('div');d.id='toasts';document.body.appendChild(d);return d;})();const t=document.createElement('div');t.className='toast'+(kind?' '+kind:'');t.textContent=msg;box.appendChild(t);setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .4s';setTimeout(()=>t.remove(),420);},5200);}
</script></body></html>"""
