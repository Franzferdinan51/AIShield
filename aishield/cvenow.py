"""CVE Now client — talks to the public cve.now MCP server (stateless JSON-RPC over HTTPS).

Tools used:
  - list_feed(name|filter|tech|ecosystem, limit)  -> newest CVEs
  - get_vulnerability(id)                          -> one CVE/GHSA/OSV entry (+ CISA SSVC)
  - check_stack(packages=[{ecosystem,name,version}]) -> matches for exact versions
"""
import json
import requests

URL = "https://mcp.cve.now/mcp"
HEADERS = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}
_id = [0]


def _call(tool, arguments, timeout=60):
    _id[0] += 1
    payload = {"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}}
    r = requests.post(URL, json=payload, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"cve.now error: {data['error']}")
    result = data.get("result", {})
    # MCP tool results carry text content blocks; cve.now returns JSON text.
    for block in result.get("content", []):
        if block.get("type") == "text":
            try:
                return json.loads(block["text"])
            except json.JSONDecodeError:
                return {"text": block["text"]}
    return result


def list_feed(name=None, filter=None, tech=None, ecosystem=None, limit=20):
    args = {"limit": limit}
    if name:
        args["name"] = name
    if filter:
        args["filter"] = filter if isinstance(filter, list) else [filter]
    if tech:
        args["tech"] = tech if isinstance(tech, list) else [tech]
    if ecosystem:
        args["ecosystem"] = ecosystem if isinstance(ecosystem, list) else [ecosystem]
    return _call("list_feed", args)


def get_vulnerability(vuln_id):
    return _call("get_vulnerability", {"id": vuln_id})


def check_stack(packages, timeout=120):
    """packages: list of {ecosystem, name, version}. Returns cve.now's match report."""
    return _call("check_stack", {"packages": packages}, timeout=timeout)
