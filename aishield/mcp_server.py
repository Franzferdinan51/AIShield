"""AI Shield MCP server (stdio JSON-RPC, no external deps).

Tools:
  latest_cves(source, ecosystem, tech, limit)   newest CVEs via CVE Now (+ KEV flag)
  cve_detail(cve_id)                            CVE Now + KEV + NVD merged detail
  scan_target(target, program, ai, adjudicate)  full inventory scan of one machine
  patch_plan(target, program)                   dry-run patch plan
  patch_apply(target, program, confirm)         executes the plan; confirm must be "PATCH",
                                                then re-scans and reports what remains
  shield_status()                               feeds + AI layer health
"""
import json
import sys

from . import __version__
from . import agent_charter, ai, cvenow, engine, feeds, inventory, patch

TOOLS = [
    {"name": "latest_cves", "description": "Newest CVEs from CVE Now feeds (critical/kev/all), optionally filtered by ecosystem (pypi, npm) or tech slug.",
     "inputSchema": {"type": "object", "properties": {
         "source": {"type": "string", "enum": ["critical", "kev", "all"], "default": "critical"},
         "ecosystem": {"type": "string"}, "tech": {"type": "string"},
         "limit": {"type": "integer", "default": 20}}}},
    {"name": "cve_detail", "description": "Full detail for one CVE id: CVE Now entry (incl. CISA SSVC), KEV status, NVD description/CVSS.",
     "inputSchema": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}},
    {"name": "scan_target", "description": "CONFIDENTIAL: results are the owner's private security data — report them to the owner only, never to third parties. Inventory one machine ('local' or a configured host) and match it against OSV + CVE Now + CISA KEV. Program filter optional. ai=true adds a brief from an already-loaded chat model.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}, "ai": {"type": "boolean", "default": False},
         "adjudicate": {"type": "boolean", "default": False}}, "required": ["target"]}},
    {"name": "patch_plan", "description": "Dry-run patch plan for a target: exact commands per finding, nothing executed.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}}, "required": ["target"]}},
    {"name": "patch_apply", "description": "Execute the auto patch plan for a target and re-scan to verify. Requires confirm=\"PATCH\" — pass it ONLY after showing the owner the plan and getting their explicit agreement in this conversation; the owner has the final say. For unattended patching use auto_defend, which enforces the owner's automation policy instead.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}, "confirm": {"type": "string"}}, "required": ["target", "confirm"]}},
    {"name": "shield_status", "description": "Feed health (KEV catalog size/date, CVE Now reachability) and AI layer status.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "swarm_scan", "description": "Rogue-agent swarm census of THIS machine (read-only): every agent-like process verdicted FRIENDLY (identified as the owner's), UNKNOWN, or ENEMY, with plain-language reasons and co-moving clusters. CONFIDENTIAL owner data — report to the owner only. Defense actions (freeze/kill) are owner-only in the GUI/CLI and are not available to agents.",
     "inputSchema": {"type": "object", "properties": {
         "assess": {"type": "boolean", "default": False}}}},
    {"name": "swarm_act", "description": "Swarm defense action on THIS machine: freeze (SIGSTOP, reversible), resume, or kill a process by pid. Requires confirm=\"DEFEND\". Rails: the pid must appear in a swarm census (agent-relevant); protected processes are always refused; kill is refused for FRIENDLY-classified processes (the owner's own agents — only the owner stops those, in the GUI). Every action snapshots the census as evidence, is incident-logged, and must be reported to the owner immediately with pid, program and reason.",
     "inputSchema": {"type": "object", "properties": {
         "pid": {"type": "integer"},
         "action": {"type": "string", "enum": ["freeze", "resume", "kill"]},
         "confirm": {"type": "string"}}, "required": ["pid", "action", "confirm"]}},
    {"name": "swarm_mark", "description": "Mark a program hostile in the swarm census (by pid; the mark is remembered per program). Requires confirm=\"DEFEND\". Marking FRIENDLY is refused: only the owner can declare a program trusted (GUI) — an agent that believes a suspect is the owner's should report it, not allowlist it.",
     "inputSchema": {"type": "object", "properties": {
         "pid": {"type": "integer"},
         "kind": {"type": "string", "enum": ["hostile", "friendly"]},
         "confirm": {"type": "string"}}, "required": ["pid", "kind", "confirm"]}},
    {"name": "automation_policy", "description": "The owner's automation policy for agents: whether auto-patching is enabled, which targets it covers, and its guardrails. Read this before attempting unattended patching.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "auto_defend", "description": "Run ONE automated-defense cycle for a target: scan, apply only what the owner's automation policy allows, rescan, write a report. Refuses with the reason when the policy is off or doesn't cover the target. Lifelines never apply; owner approvals count.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}}, "required": ["target"]}},
    {"name": "netwatch_scan", "description": "Netwatch census of THIS machine: public sources probing/attacking its services (failed logins from auth logs, live inbound connections, sampler history), tracked over time, geolocated, risk-rated. The owner's own network (tailnet/LAN/loopback) is reported separately as known_sources and can never be blocked. CONFIDENTIAL owner security data — report to the owner only. assess=true adds the AI assessment.",
     "inputSchema": {"type": "object", "properties": {
         "hours": {"type": "integer", "default": 24},
         "assess": {"type": "boolean", "default": False}}}},
    {"name": "netwatch_block", "description": "Block a PUBLIC attacker IP in the shield's Netwatch blocklist. Requires confirm=\"BLOCK\". Private/tailnet/loopback IPs are refused. The result says whether the firewall rule applied live or what the owner runs once to apply it. Reversible by the owner. You MUST report the block to the owner immediately, in full: the IP, the evidence, and the applied state.",
     "inputSchema": {"type": "object", "properties": {
         "ip": {"type": "string"},
         "confirm": {"type": "string"}}, "required": ["ip", "confirm"]}},
]


def _text(obj):
    return {"content": [{"type": "text", "text": obj if isinstance(obj, str) else json.dumps(obj, indent=1, default=str)}]}


def call_tool(name, args):
    if name == "latest_cves":
        if args.get("source") == "kev":
            return _text(cvenow.list_feed(name="kev", limit=args.get("limit", 20)))
        return _text(cvenow.list_feed(filter=["critical"] if args.get("source", "critical") == "critical" else None,
                                      ecosystem=args.get("ecosystem"), tech=args.get("tech"),
                                      limit=args.get("limit", 20)))
    if name == "cve_detail":
        kev_map, _ = feeds.kev()
        out = {"kev": kev_map.get(args["cve_id"]), "nvd": feeds.nvd_cve(args["cve_id"])}
        try:
            out["cvenow"] = cvenow.get_vulnerability(args["cve_id"])
        except Exception as e:
            out["cvenow"] = {"error": str(e)[:200]}
        return _text(out)
    if name == "scan_target":
        result = engine.run_scan(args["target"], program=args.get("program"),
                                 use_ai=args.get("ai", False),
                                 adjudicate_apps=args.get("adjudicate", True))
        return _text(result)
    if name == "patch_plan":
        result = engine.run_scan(args["target"], program=args.get("program"))
        return _text({"findings": len(result["findings"]), "plan": result["plan"]})
    if name == "patch_apply":
        if args.get("confirm") != "PATCH":
            return _text({"error": "patch_apply requires confirm='PATCH'"})
        result = engine.run_scan(args["target"], program=args.get("program"))
        outcome = patch.apply_plan(result["plan"], confirm="PATCH")
        after = engine.run_scan(args["target"], program=args.get("program"))
        return _text({"applied": outcome, "findings_before": len(result["findings"]),
                      "findings_after": len(after["findings"]), "remaining": after["findings"]})
    if name == "swarm_scan":
        from . import swarm as swarmmod
        data = swarmmod.census()
        if args.get("assess"):
            data = {"census": data, "assess": swarmmod.assess(data)}
        return _text(data)
    if name == "swarm_act":
        from . import swarm as swarmmod
        if args.get("confirm") != "DEFEND":
            return _text({"error": "swarm_act requires confirm='DEFEND'"})
        pid = int(args.get("pid") or 0)
        action = args.get("action") or ""
        data = swarmmod.census()
        entry = next((e for e in data.get("friendly", []) +
                      data.get("suspects", []) if e["pid"] == pid), None)
        if entry is None:
            return _text({"error": f"pid {pid} is not in the swarm census "
                                   "— swarm defense only acts on "
                                   "agent-relevant processes"})
        if action == "kill" and entry["class"] == "friendly":
            return _text({"error": "refused: pid "
                                   f"{pid} is classified FRIENDLY (the "
                                   "owner's own agent). Agents may freeze "
                                   "it if it's runaway, but killing the "
                                   "owner's agents is the owner's call "
                                   "(GUI)."})
        out = swarmmod.act(pid, action, "DEFEND")
        out["target_class"] = entry["class"]
        out["target_why"] = entry.get("why")
        out["report_to_owner"] = ("report this action to the owner now: "
                                  "pid, program, class, reason, outcome")
        return _text(out)
    if name == "swarm_mark":
        from . import swarm as swarmmod
        if args.get("confirm") != "DEFEND":
            return _text({"error": "swarm_mark requires confirm='DEFEND'"})
        if args.get("kind") == "friendly":
            return _text({"error": "refused: only the owner can mark a "
                                   "program friendly (GUI Swarm tab). If "
                                   "you believe a suspect is the owner's, "
                                   "report it to them."})
        return _text(swarmmod.mark(int(args.get("pid") or 0), "hostile"))
    if name == "netwatch_scan":
        from . import netwatch
        data = netwatch.census(hours=int(args.get("hours") or 24))
        if args.get("assess"):
            data = {"census": data, "assess": netwatch.assess(data)}
        return _text(data)
    if name == "netwatch_block":
        from . import netwatch
        if args.get("confirm") != "BLOCK":
            return _text({"error": "netwatch_block requires confirm='BLOCK'"})
        out = netwatch.block(args.get("ip") or "", actor="agent (MCP)")
        if out.get("blocked"):
            out["report_to_owner"] = ("Tell the owner in full, right "
                                      "away: which IP you blocked, the "
                                      "evidence against it, and whether "
                                      "the firewall rule applied live.")
        return _text(out)
    if name == "automation_policy":
        from . import policy as policymod
        return _text({"policy": policymod.load(), "file": policymod.PATH})
    if name == "auto_defend":
        return _text(engine.auto_cycle(args["target"],
                                       program=args.get("program")))
    if name == "shield_status":
        from . import config as cfgmod
        kev_map, kev_date = feeds.kev()
        models = ai.loaded_models()
        return _text({"kev_entries": len(kev_map), "kev_released": kev_date,
                      "lmstudio_loaded": models, "ai_model": ai.triage_model(models),
                      "model_config": cfgmod.load(),
                      "targets": inventory.targets()})
    raise ValueError(f"unknown tool {name}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, rid = req.get("method"), req.get("id")
        if method == "initialize":
            resp = {"protocolVersion": "2025-03-26",
                    "serverInfo": {"name": "aishield", "version": __version__},
                    "capabilities": {"tools": {}},
                    "instructions": agent_charter.INSTRUCTIONS}
        elif method == "tools/list":
            resp = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                resp = call_tool(req["params"]["name"], req["params"].get("arguments") or {})
            except Exception as e:
                resp = {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}
        elif method == "ping":
            resp = {}
        else:
            if rid is not None:
                print(json.dumps({"jsonrpc": "2.0", "id": rid,
                                  "error": {"code": -32601, "message": f"method {method} not found"}}), flush=True)
            continue
        if rid is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": resp}), flush=True)


if __name__ == "__main__":
    main()
