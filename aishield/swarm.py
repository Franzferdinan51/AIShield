"""Rogue-agent swarm detection and defense (local machine).

Detection is a census, not a guess: enumerate processes, read their
established connections, and score agent-like behavior — agent
frameworks in the command line, browser automation, many children,
many distinct endpoints, calls to LLM API endpoints, worker pools
with identical command lines. Processes that share rare endpoints,
a parent, or an identical command line cluster into candidate
swarms. The owner's own agents (Hermes, the shield, LM Studio, …)
are recognized as friendly via an allowlist the owner controls in
config/swarm.local.yaml.

Defense is on-machine only, and owner-fired: freeze (SIGSTOP,
reversible), resume (SIGCONT), kill (SIGTERM), an endpoint blocklist
that turns any process talking to a blocked endpoint hostile, and
an evidence snapshot + incident log for every action. System
processes and the shield itself are protected and can never be
acted on. No action here reaches out to another machine.
"""
import json
import os
import platform
import signal
import socket
import subprocess
import time

import yaml

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG_PATH = os.path.join(HERE, "config", "swarm.local.yaml")
LOG_PATH = os.path.join(HERE, "data", "swarm-log.jsonl")
INC_DIR = os.path.join(HERE, "data", "swarm-incidents")

FRAMEWORKS = ["langchain", "autogen", "crewai", "openai-agents",
              "agentops", "smolagents", "langgraph", "mcp-server",
              "mcp_server", "fastmcp", "playwright", "chromedriver",
              "puppeteer", "selenium", "openclaw", "hermes"]
RUNTIMES = ["python", "node", "deno", "bun"]
LLM_DOMAINS = ["api.openai.com", "api.anthropic.com", "openrouter.ai",
               "api.mistral.ai", "generativelanguage.googleapis.com",
               "api.cohere.com", "api.x.ai", "api.deepseek.com",
               "api.groq.com", "api.together.xyz", "api.perplexity.ai"]
LOCAL_MODEL_PORTS = {"1234", "11434", "8080", "8000"}
DEFAULT_FRIENDLY = ["hermes", "aishield", "lm studio", "lmstudio",
                    "systemone"]
PROTECTED = ["kernel_task", "launchd", "windowserver", "loginwindow",
             "opendirectoryd", "configd", "mds", "mds_stores", "sshd",
             "systemd", "init", "kthreadd", "dock", "finder",
             "controlcenter", "notificationcenter", "tccd", "cfprefsd",
             "distnoted", "userEventAgent".lower(), "coreaudiod",
             "bluetoothd", "airportd", "syspolicyd", "amfid"]


def load_cfg():
    cfg = {"friendly": list(DEFAULT_FRIENDLY), "blocklist": [],
           "hostile": []}
    try:
        with open(CFG_PATH) as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            if isinstance(data.get("friendly"), list):
                cfg["friendly"] = [str(x).lower() for x in data["friendly"]]
            if isinstance(data.get("blocklist"), list):
                cfg["blocklist"] = [str(x).lower() for x in data["blocklist"]]
            if isinstance(data.get("hostile"), list):
                cfg["hostile"] = [str(x).lower() for x in data["hostile"]]
    except Exception:
        pass
    return cfg


def _run(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def _processes():
    out = _run(["ps", "-axo", "pid=,ppid=,pcpu=,pmem=,etime=,command="])
    procs = []
    for line in out.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            cpu, mem = float(parts[2]), float(parts[3])
        except ValueError:
            continue
        procs.append({"pid": pid, "ppid": ppid, "cpu": cpu, "mem": mem,
                      "etime": parts[4], "cmd": parts[5]})
    return procs


def _connections():
    """pid -> set of remote 'ip:port' (established only)."""
    conns = {}
    system = platform.system()
    if system == "Darwin":
        out = _run(["lsof", "-iTCP", "-sTCP:ESTABLISHED", "-P", "-n"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            name = parts[8]
            if "->" in name:
                conns.setdefault(pid, set()).add(name.split("->", 1)[1])
    else:
        out = _run(["ss", "-tnp", "state", "established"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            remote = parts[4]
            pid = None
            if "pid=" in line:
                try:
                    pid = int(line.split("pid=", 1)[1].split(",", 1)[0]
                              .split(")", 1)[0])
                except ValueError:
                    pid = None
            if pid:
                conns.setdefault(pid, set()).add(remote)
    return conns


def _llm_ips():
    ips = {}
    for d in LLM_DOMAINS:
        try:
            ips[socket.gethostbyname(d)] = d
        except Exception:
            pass
    return ips


VERDICTS_PATH = os.path.join(HERE, "data", "swarm-verdicts.json")


def _prog_key(cmd):
    """A stable identity for a program across runs: runtime + the
    module/script it runs. Two workers of the same program share a
    key, so one owner mark covers the fleet."""
    toks = cmd.split()
    if not toks:
        return cmd.lower()[:110]
    base = os.path.basename(toks[0]).lower()
    rest = toks[1:]
    for i, t in enumerate(rest):
        if t == "-m" and i + 1 < len(rest):
            return f"{base} -m {rest[i + 1]}".lower()[:110]
        if t.startswith("-"):
            continue
        return f"{base} {t}".lower()[:110]
    return base


def _verdicts():
    try:
        with open(VERDICTS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_verdict(prog, verdict, p, cluster):
    allv = _verdicts()
    allv[prog] = {"verdict": verdict, "p": p, "cluster": cluster,
                  "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
    os.makedirs(os.path.dirname(VERDICTS_PATH), exist_ok=True)
    with open(VERDICTS_PATH, "w") as f:
        json.dump(allv, f, indent=1)


def classify(procs, conns, cfg, llm_ips):
    by_pid = {p["pid"]: p for p in procs}
    children = {}
    for p in procs:
        children.setdefault(p["ppid"], []).append(p["pid"])
    friendly_pats = cfg["friendly"]
    blocked = set(cfg["blocklist"])
    hostile_pats = cfg.get("hostile") or []
    verdicts = _verdicts()
    by_pid_full = {p["pid"]: p for p in procs}

    def owner_of(proc):
        """Whose process is this? Its own allowlist/path identity, or
        inherited from an ancestor (a worker under Hermes is Hermes')."""
        chain = [proc]
        seen, cur = set(), proc
        for _ in range(6):
            parent = by_pid_full.get(cur["ppid"])
            if parent is None or parent["pid"] in seen:
                break
            seen.add(parent["pid"])
            chain.append(parent)
            cur = parent
        for node in chain:
            nlow = node["cmd"].lower()
            for f in friendly_pats:
                if f in nlow:
                    return f
            if "/applications/" in nlow:
                seg = nlow.split("/applications/", 1)[1].split(".app", 1)[0]
                if seg and any(f in seg for f in friendly_pats):
                    return seg + " (app)"
            if "/.hermes/" in nlow:
                return "hermes"
            if "/aishield/" in nlow:
                return "aishield"
        return None

    out = []
    for p in procs:
        cmd = p["cmd"]
        low = cmd.lower()
        base = os.path.basename(cmd.split()[0]).lower() if cmd.split() else ""
        eps = sorted(conns.get(p["pid"], set()))
        ep_hosts = {e.rsplit(":", 1)[0].strip("[]") for e in eps}
        ep_ports = {e.rsplit(":", 1)[-1] for e in eps}
        signals, score = [], 0
        if any(f in low for f in FRAMEWORKS):
            signals.append("agent framework/automation in command line")
            score += 3
        if base in RUNTIMES or any(r in base for r in RUNTIMES):
            score += 1
        if " agent" in low or low.rstrip().endswith("agent") \
                or "--agent" in low:
            signals.append("names itself an agent")
            score += 2
        kids = len(children.get(p["pid"], []))
        if kids >= 4:
            signals.append(f"fan-out: {kids} child processes")
            score += 2
        elif kids >= 2:
            score += 1
        llm_hits = [llm_ips[h] for h in ep_hosts if h in llm_ips]
        if llm_hits:
            signals.append("talks to LLM API: " + ", ".join(sorted(set(llm_hits))))
            score += 3
        if ep_ports & LOCAL_MODEL_PORTS:
            signals.append("talks to a local model server")
            score += 1
        if len(ep_hosts) >= 6:
            signals.append(f"many distinct endpoints ({len(ep_hosts)})")
            score += 2
        if p["cpu"] >= 60:
            signals.append(f"heavy CPU ({p['cpu']:.0f}%)")
            score += 1
        blocked_hits = [h for h in ep_hosts
                        if h in blocked or any(b in h for b in blocked if b)]
        prog = _prog_key(cmd)
        entry = {"pid": p["pid"], "ppid": p["ppid"], "cpu": p["cpu"],
                 "mem": p["mem"], "etime": p["etime"],
                 "cmd": cmd[:220], "prog": prog, "score": score,
                 "signals": signals, "endpoints": eps[:12],
                 "children": kids, "in_cluster": None}
        vm = verdicts.get(prog)
        owner = owner_of(p)
        if any(pat in low for pat in PROTECTED) or p["pid"] <= 1:
            entry["class"] = "protected"
            entry["why"] = "system process — never listed for action"
        elif prog in hostile_pats or any(h in low for h in hostile_pats):
            entry["class"] = "enemy"
            entry["why"] = "ENEMY — you marked this program hostile"
        elif blocked_hits:
            entry["class"] = "enemy"
            entry["why"] = ("ENEMY — talks to a blocked endpoint: "
                             + ", ".join(sorted(set(blocked_hits))))
        elif prog in friendly_pats or owner:
            entry["class"] = "friendly"
            entry["why"] = f"yours — identity: {owner}"
        elif vm and vm.get("verdict") == "rogue":
            entry["class"] = "enemy"
            entry["why"] = (f"ENEMY — the AI judged this program rogue "
                            f"(p={vm.get('p')}, {vm.get('ts', '')[:10]}, "
                            f"cluster: {vm.get('cluster')})")
        elif score >= 3:
            entry["class"] = "unknown"
            entry["why"] = ("unknown — agent-like, no owner match"
                            + ("; the AI cleared this program once "
                               f"(p={vm.get('p')})"
                               if vm and vm.get("verdict") == "benign"
                               else ""))
        else:
            continue  # ordinary process — not part of the census report
        out.append(entry)
    return out, by_pid


def cluster(entries, conns):
    """Group suspects/hostiles into candidate swarms: shared rare
    endpoints, one parent fanning out, identical command lines."""
    sus = [e for e in entries if e["class"] in ("unknown", "enemy")]
    swarms, used = [], set()
    by_ep = {}
    for e in sus:
        for ep in e["endpoints"]:
            by_ep.setdefault(ep, []).append(e["pid"])
    for ep, pids in sorted(by_ep.items()):
        members = [p for p in set(pids) if p not in used]
        if len(members) >= 2:
            swarms.append({"kind": "shared-endpoint", "key": ep,
                           "members": sorted(members),
                           "reason": f"{len(members)} agent-like processes "
                                     f"share endpoint {ep} — coordination "
                                     f"or a common controller"})
            used.update(members)
    by_parent = {}
    for e in sus:
        if e["pid"] not in used:
            by_parent.setdefault(e["ppid"], []).append(e["pid"])
    for ppid, pids in sorted(by_parent.items()):
        if len(pids) >= 3:
            swarms.append({"kind": "fan-out", "key": f"parent {ppid}",
                           "members": sorted(pids),
                           "reason": f"{len(pids)} agent-like processes "
                                     f"spawned under one parent (pid {ppid})"})
            used.update(pids)
    by_cmd = {}
    for e in sus:
        if e["pid"] not in used:
            by_cmd.setdefault(e["cmd"][:80], []).append(e["pid"])
    for cmd, pids in sorted(by_cmd.items()):
        if len(pids) >= 3:
            swarms.append({"kind": "worker-pool", "key": cmd[:60],
                           "members": sorted(pids),
                           "reason": f"{len(pids)} processes run an identical "
                                     f"command line — a worker pool"})
            used.update(pids)
    for e in sus:
        if e["pid"] in used:
            e["in_cluster"] = next(
                (sw["kind"] for sw in swarms if e["pid"] in sw["members"]),
                None)
            if e["class"] == "unknown":
                e["why"] += f"; in a {e['in_cluster']} cluster"
    return swarms


def census():
    if platform.system() == "Windows":
        return {"error": "local swarm census supports macOS/Linux in "
                          "this build"}
    cfg = load_cfg()
    procs = _processes()
    conns = _connections()
    entries, _ = classify(procs, conns, cfg, _llm_ips())
    swarms = cluster(entries, conns)
    return {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "os": platform.system(),
            "total_processes": len(procs),
            "friendly": [e for e in entries if e["class"] == "friendly"],
            "enemy": [e for e in entries if e["class"] == "enemy"],
            "unknown": [e for e in entries if e["class"] == "unknown"],
            "suspects": [e for e in entries
                         if e["class"] in ("unknown", "enemy")],
            "swarms": swarms,
            "blocklist": cfg["blocklist"],
            "note": "three verdicts only: friendly = identified as "
                    "yours (allowlist, owner process tree, or app path); "
                    "unknown = agent-like with no owner match; enemy = "
                    "marked hostile by you, talking to a blocked "
                    "endpoint, or judged rogue by the AI. Protected "
                    "(system/shield) are never listed for action."}


def _log(entry):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def mark(pid, kind):
    """The owner teaches the shield: this program is mine (friendly)
    or hostile (enemy). Persisted in config/swarm.local.yaml by
    program key, so future runs classify instantly."""
    if kind not in ("friendly", "hostile"):
        return {"error": f"unknown mark {kind}"}
    procs = _processes()
    target = next((x for x in procs if x["pid"] == pid), None)
    if target is None:
        return {"error": f"pid {pid} no longer exists"}
    low = target["cmd"].lower()
    if any(pat in low for pat in PROTECTED) or pid <= 1 \
            or pid == os.getpid():
        return {"error": "protected process — cannot be marked"}
    prog = _prog_key(target["cmd"])
    data = {}
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            data = {}
    for k in ("friendly", "hostile"):
        if not isinstance(data.get(k), list):
            data[k] = list(DEFAULT_FRIENDLY) if k == "friendly" else []
    other = "hostile" if kind == "friendly" else "friendly"
    data[other] = [x for x in data[other] if x != prog]
    if prog not in data[kind]:
        data[kind] = list(data[kind]) + [prog]
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    os.replace(tmp, CFG_PATH)
    _log({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
          "action": f"mark-{kind}", "pid": pid, "cmd": prog})
    return {"ok": True, "prog": prog, "kind": kind}


def act(pid, action, confirm):
    """Owner-fired defense. confirm must be 'DEFEND'."""
    if confirm != "DEFEND":
        return {"error": "actions require confirm='DEFEND'"}
    if action not in ("freeze", "resume", "kill"):
        return {"error": f"unknown action {action}"}
    cfg = load_cfg()
    procs = _processes()
    target = next((p for p in procs if p["pid"] == pid), None)
    if target is None:
        return {"error": f"pid {pid} no longer exists"}
    low = target["cmd"].lower()
    if any(pat in low for pat in PROTECTED) or pid <= 1 \
            or pid == os.getpid() or "aishield" in low and "gui" in low:
        return {"error": "protected process — the shield never acts on "
                         "system processes or itself"}
    sig = {"freeze": signal.SIGSTOP, "resume": signal.SIGCONT,
           "kill": signal.SIGTERM}[action]
    try:
        os.kill(pid, sig)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    snap = None
    if action in ("freeze", "kill"):
        os.makedirs(INC_DIR, exist_ok=True)
        snap = os.path.join(INC_DIR, "census-%s.json"
                            % time.strftime("%Y%m%d-%H%M%S"))
        try:
            with open(snap, "w") as f:
                json.dump(census(), f, indent=1)
        except Exception:
            snap = None
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "action": action,
             "pid": pid, "cmd": target["cmd"][:220], "snapshot": snap}
    _log(entry)
    return {"ok": True, **entry}


def incidents(limit=10):
    out = []
    try:
        with open(LOG_PATH) as f:
            lines = f.readlines()[-limit:]
        for line in lines:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass
    return list(reversed(out))


def assess(data=None):
    """AI read of a census: narrative assessment + a typed verdict on
    the largest cluster. Advisory only — the owner fires actions."""
    from . import ai
    data = data or census()
    if data.get("error"):
        return data
    out = {"census_ts": data["ts"]}
    model = ai._narrative_model()
    lines = [f"machine census: {data['total_processes']} processes, "
             f"{len(data['friendly'])} friendly agents, "
             f"{len(data['suspects'])} suspects, "
             f"{len(data['swarms'])} clusters"]
    for s in data["swarms"][:4]:
        lines.append(f"cluster ({s['kind']}): {s['reason']}; members "
                     f"{s['members']}")
    for e in data["suspects"][:8]:
        lines.append(f"suspect pid {e['pid']} score {e['score']}: "
                     f"{e['cmd'][:110]} | signals: {'; '.join(e['signals'])}")
    if model:
        text = ai._narrate(
            "You are the defensive analyst inside AI Shield. Assess "
            "this census for ROGUE AGENT SWARM activity — agent "
            "processes the owner did not install or approve, possibly "
            "coordinating. Data:\n" + "\n".join(lines) +
            "\nWrite: (1) verdict — is there evidence of a rogue swarm, "
            "and how strong; (2) what looks benign and why; (3) the "
            "concrete countermeasures you recommend from this playbook "
            "only: freeze the workers, kill the parent, block the "
            "coordinator endpoint, watch and re-census. Be specific, "
            "name pids. Say plainly when the evidence is thin.",
            model, 1500)
        if text:
            out["assessment"] = text
            out["model"] = model
    if data["swarms"]:
        top = max(data["swarms"], key=lambda s: len(s["members"]))
        members = [e for e in data["suspects"]
                   if e["pid"] in top["members"]]
        state = ("cluster: " + top["reason"] + " | processes: " +
                 "; ".join(f"pid {e['pid']} {e['cmd'][:80]} "
                           f"signals {', '.join(e['signals'])}"
                           for e in members[:5]))
        try:
            verdict, p, m = ai.decide_noul(
                state,
                "Decide whether this statement is true: these processes "
                "form a coordinated agent swarm that the machine's "
                "owner did not knowingly install or approve.")
            out["verdict"] = {"statement": "rogue swarm",
                              "verdict": verdict, "probability": p,
                              "model": m, "cluster": top["key"]}
            if verdict in ("yes", "no"):
                stored = "rogue" if verdict == "yes" else "benign"
                for e in members:
                    _save_verdict(e["prog"], stored, p, top["key"])
                out["verdict"]["remembered_for"] = [e["prog"]
                                                    for e in members]
        except Exception as e:
            out["verdict"] = {"error": str(e)[:160]}
    return out
