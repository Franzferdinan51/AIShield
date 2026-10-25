"""CVE Now client — talks to the public cve.now MCP server (stateless JSON-RPC over HTTPS).

Tools used:
  - list_feed(name|filter|tech|ecosystem, limit)  -> newest CVEs
  - get_vulnerability(id)                          -> one CVE/GHSA/OSV entry (+ CISA SSVC)
  - check_stack(packages=[{ecosystem,name,version}]) -> matches for exact versions
"""
import hashlib
import json
import os
import time

import requests

URL = "https://mcp.cve.now/mcp"
HEADERS = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}
_id = [0]


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_PATH = os.path.join(_ROOT, "data", "cvenow-cache.json")
_cache = None
# Last live attempt outcome, for honest status reporting: a cached
# answer must never masquerade as a reachable service.
LAST = {"ok": None, "ts": 0, "error": None}


def _cache_key(tool, arguments):
    raw = json.dumps({"tool": tool, "args": arguments},
                     sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _cache_read():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH) as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    return _cache


def _cache_write(key, result):
    c = _cache_read()
    c[key] = {"ts": time.time(), "result": result}
    if len(c) > 300:  # evict oldest — a cache, not an archive
        for k in sorted(c, key=lambda k: c[k].get("ts", 0))[:len(c) - 300]:
            del c[k]
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(c, f)
        os.replace(tmp, CACHE_PATH)
    except Exception:
        pass


def last_status():
    c = _cache_read()
    return {**LAST, "cache_entries": len(c),
            "cache_newest_ts": max((v.get("ts", 0) for v in c.values()),
                                   default=0)}


def _call(tool, arguments, timeout=60):
    key = _cache_key(tool, arguments)
    try:
        result = _call_live(tool, arguments, timeout=timeout)
    except Exception as e:
        LAST.update(ok=False, ts=time.time(),
                    error=("%s: %s" % (type(e).__name__, e))[:200])
        hit = _cache_read().get(key)
        if hit is not None:
            return hit["result"]  # stale beats dead
        raise
    LAST.update(ok=True, ts=time.time(), error=None)
    _cache_write(key, result)
    return result


def _call_live(tool, arguments, timeout=60):
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
