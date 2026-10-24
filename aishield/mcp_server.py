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

from . import __version__, ai, cvenow, engine, feeds, inventory, patch

TOOLS = [
    {"name": "latest_cves", "description": "Newest CVEs from CVE Now feeds (critical/kev/all), optionally filtered by ecosystem (pypi, npm) or tech slug.",
     "inputSchema": {"type": "object", "properties": {
         "source": {"type": "string", "enum": ["critical", "kev", "all"], "default": "critical"},
         "ecosystem": {"type": "string"}, "tech": {"type": "string"},
         "limit": {"type": "integer", "default": 20}}}},
    {"name": "cve_detail", "description": "Full detail for one CVE id: CVE Now entry (incl. CISA SSVC), KEV status, NVD description/CVSS.",
     "inputSchema": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}},
    {"name": "scan_target", "description": "Inventory one machine ('local' or a configured host) and match it against OSV + CVE Now + CISA KEV. Program filter optional. ai=true adds a brief from an already-loaded chat model.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}, "ai": {"type": "boolean", "default": False},
         "adjudicate": {"type": "boolean", "default": False}}, "required": ["target"]}},
    {"name": "patch_plan", "description": "Dry-run patch plan for a target: exact commands per finding, nothing executed.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}}, "required": ["target"]}},
    {"name": "patch_apply", "description": "Execute the auto patch plan for a target and re-scan to verify. Requires confirm=\"PATCH\".",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "enum": inventory.targets()},
         "program": {"type": "string"}, "confirm": {"type": "string"}}, "required": ["target", "confirm"]}},
    {"name": "shield_status", "description": "Feed health (KEV catalog size/date, CVE Now reachability) and AI layer status.",
     "inputSchema": {"type": "object", "properties": {}}},
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
                    "capabilities": {"tools": {}}}
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
