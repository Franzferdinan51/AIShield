"""AI Shield for Hermes: CVE scanning and gated patching as agent tools."""

from __future__ import annotations

from pathlib import Path

from . import tools

TOOLSET = "aishield"


def register(ctx) -> None:
    status, scan, patch_plan, patch_apply, latest, cve = tools.make_handlers()
    ctx.register_tool(name="aishield_status", toolset=TOOLSET, schema=tools.STATUS,
                      handler=status, description="AI Shield status and configuration",
                      emoji="🛡️")
    ctx.register_tool(name="aishield_scan", toolset=TOOLSET, schema=tools.SCAN,
                      handler=scan, description="Scan a machine for known CVEs",
                      emoji="🛡️")
    ctx.register_tool(name="aishield_patch_plan", toolset=TOOLSET, schema=tools.PATCH_PLAN,
                      handler=patch_plan, description="Patch plan (dry-run)",
                      emoji="🛡️")
    ctx.register_tool(name="aishield_patch_apply", toolset=TOOLSET, schema=tools.PATCH_APPLY,
                      handler=patch_apply, description="Apply patches (requires confirm='PATCH')",
                      emoji="🛡️")
    ctx.register_tool(name="aishield_latest", toolset=TOOLSET, schema=tools.LATEST,
                      handler=latest, description="Latest KEV / CVE Now entries",
                      emoji="🛡️")
    ctx.register_tool(name="aishield_cve", toolset=TOOLSET, schema=tools.CVE,
                      handler=cve, description="Look up one CVE",
                      emoji="🛡️")

    skill = Path(__file__).parent / "skills" / "aishield" / "SKILL.md"
    if skill.exists():
        ctx.register_skill("aishield", skill)
