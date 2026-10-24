"""Scan orchestration shared by the CLI and the MCP server."""
import time

from . import ai, feeds, inventory, match, patch


def _dedupe(findings):
    """Merge duplicate records for the same package+CVE (OSV returns GHSA and
    PYSEC records that alias to one CVE). Unions sources/fixes, keeps max CVSS."""
    merged = {}
    for f in findings:
        key = (f["target"], f["name"].lower(), f["manager"],
               tuple(f["cve_ids"]) if f["cve_ids"] else (f["vuln_id"],))
        if key not in merged:
            merged[key] = {**f, "vuln_ids": [f["vuln_id"]]}
            continue
        m = merged[key]
        m["vuln_ids"].append(f["vuln_id"])
        m["sources"] = sorted(set(m["sources"]) | set(f["sources"]))
        m["fixed_versions"] = sorted(set(m["fixed_versions"]) | set(f["fixed_versions"]))
        try:
            if float(str(f["cvss"]).split(":")[-1].split()[0]) > float(str(m["cvss"]).split(":")[-1].split()[0]):
                m["cvss"] = f["cvss"]
        except Exception:
            pass
        if len(f["summary"]) > len(m["summary"]):
            m["summary"] = f["summary"]
    return list(merged.values())


def run_scan(target, program=None, use_ai=False, adjudicate_apps=True):
    started = time.time()
    items = inventory.collect(target)
    if program:
        items = [it for it in items if program.lower() in it["name"].lower()]
    kev_map, kev_date = feeds.kev()
    findings = match.scan_packages(items, kev_map)
    findings += match.scan_apps(items, kev_map)
    # Feed failures ride along as confidence="error" pseudo-findings; they
    # are warnings, not findings — keep them out of counts, plans, reports.
    warnings = [f["summary"] for f in findings if f.get("confidence") == "error"]
    findings = [f for f in findings if f.get("confidence") != "error"]
    if adjudicate_apps:
        kept = []
        for f in findings:
            if f["confidence"].startswith("name-match"):
                verdict, detail = ai.adjudicate(f["name"], f["version"], f["kev"])
                if detail.get("via") != "none":
                    f["ai_verdict"] = verdict
                    f["ai_detail"] = detail
                    if verdict == "no":
                        continue
                    if verdict == "yes":
                        f["confidence"] = ("name-match, confirmed by "
                                           f"{detail.get('via')} model")
            kept.append(f)
        findings = kept
    findings = match.rank(_dedupe(findings))
    result = {
        "target": target, "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "inventory_count": len(items), "program_filter": program,
        "kev_catalog_date": kev_date,
        "findings": findings, "warnings": warnings,
        "plan": patch.build_plan(findings, decide=True),
        "elapsed_s": round(time.time() - started, 1),
    }
    if use_ai:
        model = ai.triage_model()
        result["ai_model"] = model
        if model:
            result["ai_brief"] = ai.triage(findings, target, model=model)
    return result


def format_report(result):
    lines = [f"AI SHIELD — {result['target']} — {result['scanned_at']}",
             f"inventory: {result['inventory_count']} items | "
             f"findings: {len(result['findings'])} | KEV catalog: {result['kev_catalog_date']}"]
    if not result["findings"]:
        lines.append("clean — nothing matched known-vulnerable ranges or KEV products.")
    for f in result["findings"]:
        kev_tag = " [KNOWN-EXPLOITED]" if f["known_exploited"] else ""
        fix = f" -> fixed in {', '.join(f['fixed_versions'])}" if f.get("fixed_versions") else ""
        verdict = ""
        det = f.get("ai_detail") or {}
        if f.get("ai_verdict"):
            verdict = f" [ai: {f['ai_verdict']}" + \
                      (f" p={det['p_yes']}" if det.get("p_yes") is not None else "") + "]"
        lines.append(f"- {f['name']} {f['version']} ({f['ecosystem']}/{f['manager']}) "
                     f"{','.join(f['cve_ids']) or f['vuln_id']}{kev_tag}: "
                     f"{f['summary'][:110]}{fix} [{f['confidence']}; via {','.join(f['sources'])}]{verdict}")
    auto = [p for p in result["plan"] if p["auto"]]
    manual = [p for p in result["plan"] if not p["auto"]]
    if auto:
        lines.append("patch plan (auto):")
        for p in auto:
            dec = ""
            if p.get("decision"):
                probs = (p.get("decision_detail") or {}).get("probabilities") or {}
                top = max(probs.values()) if probs else None
                dec = f"  [decision: {p['decision']}" + (f" p={top}" if top else "") + \
                      f" via {p.get('decision_detail', {}).get('via', '?')}]"
            lines.append(f"  $ {p['command']}   # {p['name']} {p['version']}{dec}")
    if manual:
        lines.append("patch plan (manual):")
        for p in manual:
            lines.append(f"  {p['name']}: {p['note']}")
    if result.get("ai_brief"):
        lines.append(f"\nAI brief ({result.get('ai_model')}):\n{result['ai_brief']}")
    for w in result.get("warnings") or []:
        lines.append(f"warning: a feed cross-check was unavailable ({w[:120]})")
    return "\n".join(lines)
