"""AI Shield for Hermes: CVE scanning, gated patching, swarm
defense and netwatch as agent tools."""

from __future__ import annotations

from pathlib import Path

from . import tools

TOOLSET = "aishield"

_TOOLS = [
    ("aishield_status", "STATUS", "AI Shield status and configuration"),
    ("aishield_scan", "SCAN", "Scan a machine for known CVEs"),
    ("aishield_patch_plan", "PATCH_PLAN", "Patch plan (dry-run)"),
    ("aishield_patch_apply", "PATCH_APPLY",
     "Apply patches (requires confirm='PATCH')"),
    ("aishield_latest", "LATEST", "Latest KEV / CVE Now entries"),
    ("aishield_cve", "CVE", "Look up one CVE"),
    ("aishield_policy", "POLICY", "The owner's automation policy"),
    ("aishield_auto_defend", "AUTO_DEFEND",
     "One policy-gated auto-defense cycle"),
    ("aishield_swarm_scan", "SWARM_SCAN", "Rogue-agent swarm census"),
    ("aishield_swarm_act", "SWARM_ACT",
     "Swarm defense action (requires confirm='DEFEND')"),
    ("aishield_swarm_mark", "SWARM_MARK", "Mark a program hostile"),
    ("aishield_netwatch_scan", "NETWATCH_SCAN",
     "Netwatch: sources probing/attacking this machine"),
    ("aishield_netwatch_block", "NETWATCH_BLOCK",
     "Block a public attacker IP (requires confirm='BLOCK')"),
]


def register(ctx) -> None:
    handlers = tools.make_handlers()
    by_fn = {fn.__name__: fn for fn in handlers}
    for name, schema_name, desc in _TOOLS:
        fn_name = name[len("aishield_"):]
        ctx.register_tool(name=name, toolset=TOOLSET,
                          schema=getattr(tools, schema_name),
                          handler=by_fn[fn_name], description=desc,
                          emoji="🛡️")
    skill = Path(__file__).parent / "skills" / "aishield" / "SKILL.md"
    if skill.exists():
        ctx.register_skill("aishield", skill)
