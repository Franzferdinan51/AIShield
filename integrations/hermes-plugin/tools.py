"""AI Shield tool schemas and handlers.

Handlers take (args, **kwargs) and always return a JSON string. They
drive the installed AI Shield CLI (bin/aishield) as a subprocess, so
the plugin works with whatever shield version is installed and never
imports the shield into the Hermes venv.

Locate the shield: $AISHIELD_HOME, then ~/aishield, then `aishield`
on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

MAX_FINDINGS = 50


def _shield_cmd() -> list[str] | None:
    home = os.environ.get("AISHIELD_HOME")
    if home and (Path(home) / "bin" / "aishield").exists():
        return [str(Path(home) / "bin" / "aishield")]
    local = Path.home() / "aishield" / "bin" / "aishield"
    if local.exists():
        return [str(local)]
    found = shutil.which("aishield")
    return [found] if found else None


def _run(argv: list[str], timeout: int = 1500) -> tuple[int, str, str]:
    cmd = _shield_cmd()
    if cmd is None:
        return 127, "", ("AI Shield is not installed (or not found). "
                         "Install it from https://github.com/Franzferdinan51/AIShield "
                         "or set AISHIELD_HOME to its install directory.")
    try:
        p = subprocess.run(cmd + argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"aishield {' '.join(argv)} timed out after {timeout}s"
    except Exception as e:  # never raise into the agent loop
        return 127, "", f"{type(e).__name__}: {e}"


def _json_out(text: str):
    """Parse the first JSON document in text (some shield commands
    print a JSON block followed by human-readable lines)."""
    try:
        obj, _ = json.JSONDecoder().raw_decode((text or "").lstrip())
        return obj
    except Exception:
        return None


def _err(msg: str) -> str:
    return json.dumps({"error": msg})


# ---------------------------------------------------------------- tools

def status(args, **kwargs) -> str:
    rc, out, err = _run(["--version"], timeout=30)
    if rc != 0:
        return _err(err.strip() or "aishield not responding")
    version = out.strip()
    rc, hosts_out, _ = _run(["hosts"], timeout=30)
    rc2, models_out, _ = _run(["models"], timeout=30)
    models = _json_out(models_out) or {}
    roles = models.get("roles") or {}
    server = dict(models.get("server") or {})
    if server.get("api_key") and not str(server["api_key"]).startswith("set ("):
        # never hand an agent the raw key (this plugin also drives
        # older shield versions whose `models` output is unmasked)
        server["api_key"] = "set (…%s)" % str(server["api_key"])[-4:]
    return json.dumps({
        "version": version,
        "server": server,
        "triage_model": (roles.get("triage") or {}).get("model") or "auto",
        "decision_model": (roles.get("decision") or {}).get("model"),
        "decision_protocol": (roles.get("decision") or {}).get("protocol") or "auto",
        "hosts": _json_out(hosts_out) or hosts_out.strip()[:500],
    })


def scan(args, **kwargs) -> str:
    target = (args.get("target") or "local").strip()
    argv = ["scan", target, "--json"]
    if args.get("program"):
        argv += ["--program", str(args["program"])]
    if args.get("ai"):
        argv += ["--ai"]
    if args.get("adjudicate") is False:
        argv += ["--no-adjudicate"]
    rc, out, err = _run(argv)
    if rc != 0:
        return _err((err or out).strip()[:800] or f"scan failed rc={rc}")
    data = _json_out(out)
    if data is None:
        return _err("scan returned unparseable output")
    findings = data.get("findings") or []
    return json.dumps({
        "target": data.get("target"),
        "inventory_count": data.get("inventory_count"),
        "findings_count": len(findings),
        "findings": findings[:MAX_FINDINGS],
        "findings_truncated": len(findings) > MAX_FINDINGS,
        "plan_steps": len(data.get("plan") or []),
        "warnings": data.get("warnings") or [],
        "ai_brief": data.get("ai_brief"),
    })


def patch_plan(args, **kwargs) -> str:
    target = (args.get("target") or "local").strip()
    argv = ["scan", target, "--json"]
    if args.get("program"):
        argv += ["--program", str(args["program"])]
    rc, out, err = _run(argv)
    if rc != 0:
        return _err((err or out).strip()[:800] or f"plan failed rc={rc}")
    data = _json_out(out)
    if data is None:
        return _err("plan returned unparseable output")
    return json.dumps({
        "target": data.get("target"),
        "findings_count": len(data.get("findings") or []),
        "plan": data.get("plan") or [],
    })


def patch_apply(args, **kwargs) -> str:
    if args.get("confirm") != "PATCH":
        return _err("patch_apply requires confirm='PATCH' — nothing was run. "
                    "Show the user the plan (aishield_patch_plan) and apply "
                    "only when they explicitly agree.")
    target = (args.get("target") or "local").strip()
    argv = ["patch", target, "--apply"]
    if args.get("program"):
        argv += ["--program", str(args["program"])]
    rc, out, err = _run(argv, timeout=3600)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"apply failed rc={rc}")
    applied = data.get("applied") or {}
    steps = applied.get("applied") or []
    rescan, report = None, None
    for line in (out or "").splitlines():
        if line.startswith("post-patch rescan:"):
            rescan = line.partition(":")[2].strip()
        elif line.startswith("report:"):
            report = line.partition(":")[2].strip()
    return json.dumps({
        "target": data.get("target"),
        "steps": [{"name": s.get("name"), "result": s.get("result"),
                   "rc": s.get("rc"), "decision": s.get("decision"),
                   "note": s.get("note")} for s in steps],
        "env_warnings": applied.get("env_warnings") or [],
        "rescan": rescan,
        "report_pdf": report,
    })


def policy(args, **kwargs) -> str:
    rc, out, err = _run(["policy", "--json"], timeout=60)
    if rc != 0:
        return _err((err or out).strip()[:800])
    data = _json_out(out)
    return json.dumps(data if data is not None else {"raw": out.strip()[:2000]})


def auto_defend(args, **kwargs) -> str:
    target = (args.get("target") or "local").strip()
    argv = ["watch", "--once", "--json", target]
    rc, out, err = _run(argv, timeout=3600)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"auto_defend failed rc={rc}")
    return json.dumps(data)


def swarm_scan(args, **kwargs) -> str:
    argv = ["swarm", "--json"]
    if args.get("assess"):
        argv.append("--assess")
    rc, out, err = _run(argv, timeout=900)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"swarm failed rc={rc}")
    return json.dumps(data)


def swarm_act(args, **kwargs) -> str:
    if args.get("confirm") != "DEFEND":
        return _err("swarm_act requires confirm='DEFEND' — freeze/resume/"
                    "kill only on the user's direction or a clear "
                    "hostile case, and report it to the user immediately.")
    try:
        pid = int(args.get("pid") or 0)
    except (TypeError, ValueError):
        return _err("pid must be an integer")
    action = (args.get("action") or "").strip()
    rc, out, err = _run(["swarm", "--act", f"{action}:{pid}",
                         "--confirm", "DEFEND"], timeout=300)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"swarm_act failed rc={rc}")
    return json.dumps(data)


def swarm_mark(args, **kwargs) -> str:
    if args.get("kind") == "friendly":
        return _err("refused: only the owner can mark a program friendly "
                    "(GUI Swarm tab). Report it to the user instead.")
    if args.get("confirm") != "DEFEND":
        return _err("swarm_mark requires confirm='DEFEND'")
    try:
        pid = int(args.get("pid") or 0)
    except (TypeError, ValueError):
        return _err("pid must be an integer")
    rc, out, err = _run(["swarm", "--mark", f"hostile:{pid}"], timeout=120)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"swarm_mark failed rc={rc}")
    return json.dumps(data)


def netwatch_scan(args, **kwargs) -> str:
    try:
        hours = int(args.get("hours") or 24)
    except (TypeError, ValueError):
        return _err("hours must be an integer")
    argv = ["netwatch", "--json", "--hours", str(hours), "--target",
            (args.get("target") or "local")]
    if args.get("assess"):
        argv.append("--assess")
    rc, out, err = _run(argv, timeout=900)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"netwatch failed rc={rc}")
    return json.dumps(data)


def netwatch_block(args, **kwargs) -> str:
    if args.get("confirm") != "BLOCK":
        return _err("netwatch_block requires confirm='BLOCK' — blocking "
                    "is reversible by the owner, and you must report "
                    "the block to the user immediately, in full.")
    ip = (args.get("ip") or "").strip()
    rc, out, err = _run(["netwatch", "--block", ip, "--confirm", "BLOCK",
                         "--target", (args.get("target") or "local")],
                        timeout=300)
    data = _json_out(out)
    if data is None:
        return _err((err or out).strip()[:1200] or f"netwatch_block failed rc={rc}")
    return json.dumps(data)


def latest(args, **kwargs) -> str:
    source = (args.get("source") or "kev").strip()
    # the schema speaks kev|cvenow; the CLI speaks kev|critical|all
    source = {"cvenow": "critical"}.get(source, source)
    if source not in ("kev", "critical", "all"):
        return _err(f"unknown source '{source}' (want kev or cvenow)")
    try:
        limit = int(args.get("limit") or 10)
    except (TypeError, ValueError):
        return _err("limit must be an integer")
    rc, out, err = _run(["latest", "--source", source, "--limit", str(limit)],
                        timeout=120)
    if rc != 0:
        return _err((err or out).strip()[:800])
    return json.dumps({"source": source, "items_text": out.strip()[:4000]})


def cve(args, **kwargs) -> str:
    cid = (args.get("id") or "").strip()
    if not cid:
        return _err("id is required")
    rc, out, err = _run(["cve", cid], timeout=120)
    if rc != 0:
        return _err((err or out).strip()[:800])
    data = _json_out(out)
    return json.dumps(data if data is not None else {"raw": out.strip()[:4000]})


# ---------------------------------------------------------------- schemas

_TARGET = {"type": "string",
           "description": "Machine to scan: 'local' (this machine) or a name from the shield's machine list. Default 'local'."}
_PROGRAM = {"type": "string",
            "description": "Optional: only consider packages/apps whose name contains this text."}

STATUS = {
    "name": "aishield_status",
    "description": "AI Shield status: version, model server, triage/decision models and protocol, and the configured machines. Call this first if you are unsure the shield is installed or how it is configured.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

SCAN = {
    "name": "aishield_scan",
    "description": ("Scan a machine for known vulnerabilities. Matching is deterministic (OSV version ranges, CVE Now cross-check, CISA KEV overlay); app findings are name-match candidates adjudicated by the decision model when enabled. Set ai=true for a written triage brief (slower). Full scans can take a few minutes on a cold cache. Returns findings (capped at 50) with CVE ids, fixed versions and match confidence."),
    "parameters": {"type": "object", "properties": {
        "target": _TARGET, "program": _PROGRAM,
        "ai": {"type": "boolean", "description": "Also produce an AI triage brief."},
        "adjudicate": {"type": "boolean", "description": "Adjudicate app name-matches with the decision model (default true)."},
    }, "required": []},
}

PATCH_PLAN = {
    "name": "aishield_patch_plan",
    "description": "Build the patch plan for a machine WITHOUT applying anything: one step per vulnerable package to its highest fixed version, each marked auto or held/manual with the decision outcome. Always show this to the user before aishield_patch_apply.",
    "parameters": {"type": "object", "properties": {
        "target": _TARGET, "program": _PROGRAM}, "required": []},
}

PATCH_APPLY = {
    "name": "aishield_patch_apply",
    "description": ("Apply the auto steps of the patch plan. SAFETY: requires confirm='PATCH' — pass it only when the user has seen the plan and explicitly agreed. Lifeline packages (kernel, SSH, package manager, container runtimes) are held by rule before any AI decision and are never auto-applied. The result includes a post-patch rescan (the source of truth, not exit codes) and the path of a PDF report. Can take a long time when apt metadata refreshes."),
    "parameters": {"type": "object", "properties": {
        "target": _TARGET, "program": _PROGRAM,
        "confirm": {"type": "string", "description": "Must be exactly 'PATCH', and only when the user explicitly approved applying."},
    }, "required": ["confirm"]},
}

LATEST = {
    "name": "aishield_latest",
    "description": "The latest published vulnerabilities: source 'kev' (CISA known-exploited catalog) or 'cvenow' (the CVE Now feed).",
    "parameters": {"type": "object", "properties": {
        "source": {"type": "string", "enum": ["kev", "cvenow"]},
        "limit": {"type": "integer", "description": "How many entries (default 10)."},
    }, "required": []},
}

POLICY = {
    "name": "aishield_policy",
    "description": "Read the owner's automation policy for agents: whether auto-patching is enabled, which targets it covers, and its guardrails (safety-check requirement, candidate handling, watch interval). Check this before any unattended patching.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

AUTO_DEFEND = {
    "name": "aishield_auto_defend",
    "description": ("Run ONE automated-defense cycle for a target: scan, apply only what the owner's automation policy allows, rescan, write a report. Refuses with the reason when the policy is off or doesn't cover the target. This is the ONLY unattended patch path — never use it to bypass asking the user; the policy itself is the user's standing instruction. Report applied / withheld / remaining to the user in detail afterwards."),
    "parameters": {"type": "object", "properties": {
        "target": _TARGET}, "required": []},
}

SWARM_SCAN = {
    "name": "aishield_swarm_scan",
    "description": "Rogue-agent swarm census of this machine (read-only): every agent-like process verdicted FRIENDLY (identified as the owner's — allowlist, owner process lineage, app path), UNKNOWN (agent-like, no owner match) or ENEMY (marked hostile, blocked-endpoint talker, or AI-judged rogue), each with a plain-language why, plus clusters of processes moving together. CONFIDENTIAL owner data — report to the owner only. assess=true adds the AI assessment + cluster verdict (verdicts are remembered per program).",
    "parameters": {"type": "object", "properties": {
        "assess": {"type": "boolean", "description": "Add AI assessment (slower)."},
    }, "required": []},
}

SWARM_ACT = {
    "name": "aishield_swarm_act",
    "description": ("Swarm defense: freeze (reversible — prefer it), resume, or kill a process by pid. Requires confirm='DEFEND'. The shield refuses protected processes and refuses agent kills of FRIENDLY-classified processes. Every action snapshots the census as evidence and is incident-logged. Report any action to the user immediately with pid, program and reason."),
    "parameters": {"type": "object", "properties": {
        "pid": {"type": "integer", "description": "Process id from aishield_swarm_scan."},
        "action": {"type": "string", "enum": ["freeze", "resume", "kill"]},
        "confirm": {"type": "string", "description": "Must be exactly 'DEFEND'."},
    }, "required": ["pid", "action", "confirm"]},
}

SWARM_MARK = {
    "name": "aishield_swarm_mark",
    "description": "Mark a program HOSTILE in the swarm census (remembered per program). Marking friendly is refused — trust declarations are the owner's alone. Requires confirm='DEFEND'.",
    "parameters": {"type": "object", "properties": {
        "pid": {"type": "integer"},
        "kind": {"type": "string", "enum": ["hostile"]},
        "confirm": {"type": "string", "description": "Must be exactly 'DEFEND'."},
    }, "required": ["pid", "kind", "confirm"]},
}

NETWATCH_SCAN = {
    "name": "aishield_netwatch_scan",
    "description": "Netwatch census of this machine (read-only): public sources probing/attacking its services — failed logins from auth logs, live inbound connections, sampler history — tracked, geolocated, risk-rated. The owner's own network (tailnet/LAN) appears separately as known_sources and can never be blocked. CONFIDENTIAL owner security data — report to the owner only. assess=true adds the AI assessment.",
    "parameters": {"type": "object", "properties": {
        "hours": {"type": "integer", "description": "Look-back window (default 24)."},
        "target": {"type": "string", "description": "Machine to watch: 'local' (default) or a configured target name."},
        "assess": {"type": "boolean", "description": "Add AI assessment (slower)."},
    }, "required": []},
}

NETWATCH_BLOCK = {
    "name": "aishield_netwatch_block",
    "description": ("Block a PUBLIC attacker IP in the Netwatch blocklist. Requires confirm='BLOCK'. Private/tailnet/loopback IPs are refused by the shield. The result states whether the firewall rule applied live or what the owner runs once. You MUST report the block to the user immediately with the IP, the evidence, and the applied state."),
    "parameters": {"type": "object", "properties": {
        "ip": {"type": "string", "description": "Public source IP from aishield_netwatch_scan."},
        "target": {"type": "string", "description": "Machine to block it on: 'local' (default) or the target it attacked."},
        "confirm": {"type": "string", "description": "Must be exactly 'BLOCK'."},
    }, "required": ["ip", "confirm"]},
}

CVE = {
    "name": "aishield_cve",
    "description": "Look up one CVE id across CVE Now and NVD: summary, severity, references, exploitation status.",
    "parameters": {"type": "object", "properties": {
        "id": {"type": "string", "description": "e.g. CVE-2026-111497"},
    }, "required": ["id"]},
}


def make_handlers():
    return (status, scan, patch_plan, patch_apply, latest, cve,
            policy, auto_defend, swarm_scan, swarm_act, swarm_mark,
            netwatch_scan, netwatch_block)
