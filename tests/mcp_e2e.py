#!/usr/bin/env python3
"""End-to-end MCP test: drives the stdio server like a real client."""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
proc = subprocess.Popen([sys.executable, "-m", "aishield.mcp_server"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        text=True, cwd=ROOT)


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def recv():
    return json.loads(proc.stdout.readline())


fails = []


def check(label, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + label + (f"  {extra}" if extra else ""))
    if not cond:
        fails.append(label)


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
r = recv()
check("initialize", r.get("result", {}).get("serverInfo", {}).get("name") == "aishield")
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
r = recv()
tools = [t["name"] for t in r["result"]["tools"]]
check("tools/list", tools == ["latest_cves", "cve_detail", "scan_target",
                              "patch_plan", "patch_apply", "shield_status"],
      str(tools))

send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
      "params": {"name": "shield_status", "arguments": {}}})
r = recv()
txt = r["result"]["content"][0]["text"]
check("shield_status", "model_config" in txt and "kev_entries" in txt)

send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
      "params": {"name": "latest_cves", "arguments": {"limit": 3}}})
r = recv()
check("latest_cves", "items" in r["result"]["content"][0]["text"])

send({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
      "params": {"name": "cve_detail", "arguments": {"cve_id": "CVE-2026-48710"}}})
r = recv()
check("cve_detail real", "48710" in r["result"]["content"][0]["text"])

send({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
      "params": {"name": "nope_tool", "arguments": {}}})
r = recv()
check("unknown tool -> error, server alive",
      "error" in r or r.get("result", {}).get("isError"), json.dumps(r)[:120])

send({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
      "params": {"name": "patch_apply",
                 "arguments": {"target": "local", "program": "brotli"}}})
r = recv()
ok = ("error" in r) or ("PATCH" in json.dumps(r))
check("patch_apply without confirm refused cleanly", ok, json.dumps(r)[:160])

send({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
      "params": {"name": "scan_target",
                 "arguments": {"target": "local", "program": "openssl"}}})
r = recv()
txt = r.get("result", {}).get("content", [{}])[0].get("text", "")
check("scan_target still works after errors", "findings" in txt)

send({"jsonrpc": "2.0", "id": 9, "method": "bogus/method", "params": {}})
r = recv()
check("unknown method -> error", "error" in r, json.dumps(r)[:120])

proc.stdin.close()
proc.wait(timeout=10)
print("RESULT:", "ALL PASS" if not fails else f"FAILURES: {fails}")
sys.exit(1 if fails else 0)
