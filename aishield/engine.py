"""Scan orchestration shared by the CLI and the MCP server."""
import os
import time

from . import ai, disclosures, feeds, inventory, match, patch


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
    app_findings, cleared = match.scan_apps(items, kev_map)
    findings += app_findings
    disc_advisories, disc_meta = disclosures.advisories()
    disc_findings, disc_cleared = match.scan_disclosures(items, disc_advisories)
    findings += disc_findings
    cleared += disc_cleared
    pwn_incidents, pwn_generated = feeds.pwnwatch()
    match.pwnwatch_overlay(findings, pwn_incidents)
    pwn_findings, pwn_cleared = match.scan_pwnwatch(items, pwn_incidents,
                                                    findings)
    findings += pwn_findings
    cleared += pwn_cleared
    # Feed failures ride along as confidence="error" pseudo-findings; they
    # are warnings, not findings — keep them out of counts, plans, reports.
    warnings = [f["summary"] for f in findings if f.get("confidence") == "error"]
    findings = [f for f in findings if f.get("confidence") != "error"]
    if disc_meta.get("stale"):
        warnings.append("a disclosure source page changed since it was "
                        "curated — re-check it for CVE assignments or "
                        "vendor fixes (see result['disclosures'])")
    if not pwn_incidents:
        warnings.append("pwn.watch incident index unreachable and no "
                        "cache — live-incident overlay skipped this scan")
    if adjudicate_apps:
        kept = []
        for f in findings:
            if f["confidence"].startswith("name-match") and f.get("kev"):
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
    # Advisory era stamps for name-matches with NO published version
    # data anywhere (deterministic sources already had their say at
    # match time; these are the residue). The stamp never clears or
    # confirms anything — it tells the human how plausible the match
    # is, so stale noise is recognizable at a glance.
    try:
        for f in findings:
            if (f.get("sources") == ["kev"] and not f.get("fixed_versions")
                    and str(f.get("confidence", "")).startswith("name-match")):
                cve = (f.get("cve_ids") or [None])[0]
                if not cve:
                    continue
                wins = feeds.nvd_windows(feeds.nvd_cve_raw(cve))
                bnds = feeds.cve_fixed_bounds(feeds.osv_vuln_detail(cve))
                if not wins and not bnds:
                    era = ai.era_check(f["name"], f.get("version"), cve,
                                       f.get("kev"))
                    if era:
                        f["ai_era"] = era
    except Exception:
        pass
    findings = match.rank(_dedupe(findings))
    result = {
        "target": target, "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "inventory_count": len(items), "program_filter": program,
        "kev_catalog_date": kev_date, "disclosures": disc_meta,
        "pwnwatch": {"generated_at": pwn_generated,
                     "incidents": len(pwn_incidents),
                     "live": sum(1 for i in pwn_incidents
                                 if i.get("status") == "live")},
        "findings": findings, "warnings": warnings, "cleared": cleared,
        "plan": patch.build_plan(findings, decide=True),
        "elapsed_s": round(time.time() - started, 1),
    }
    result["changes"] = _scan_history(result)
    if use_ai:
        model = ai.triage_model()
        result["ai_model"] = model
        if model:
            result["ai_brief"] = ai.triage(findings, target, model=model)
    return result


def _scan_history(result):
    """Persist the scan (data/scans/) and diff it against the previous
    scan of the same target: what is new, what resolved. Deterministic;
    returns the changes block (also stored on the result)."""
    import glob as _glob
    import json as _json
    base = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "data", "scans")
    try:
        os.makedirs(base, exist_ok=True)
        prev_files = sorted(_glob.glob(os.path.join(
            base, "scan-%s-*.json" % result["target"])))
        prev = None
        if prev_files:
            with open(prev_files[-1]) as fh:
                prev = _json.load(fh)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        slim = {k: result.get(k) for k in
                ("target", "scanned_at", "inventory_count", "findings",
                 "cleared", "kev_catalog_date")}
        with open(os.path.join(base, "scan-%s-%s.json"
                               % (result["target"], stamp)), "w") as fh:
            _json.dump(slim, fh, indent=1, default=str)
        for old in prev_files[:-19]:
            try:
                os.remove(old)
            except Exception:
                pass
        if not prev:
            return {"since": None, "new": [], "resolved": []}
        key = lambda f: (str(f.get("name", "")).lower(),
                         f.get("vuln_id") or "")
        now_map = {key(f): f for f in result["findings"]}
        prev_map = {key(f): f for f in prev.get("findings") or []}
        brief = lambda f: {"name": f.get("name"),
                           "version": f.get("version"),
                           "cve_ids": f.get("cve_ids") or []}
        return {"since": prev.get("scanned_at"),
                "new": [brief(now_map[k]) for k in now_map
                        if k not in prev_map],
                "resolved": [brief(prev_map[k]) for k in prev_map
                             if k not in now_map]}
    except Exception:
        return {"since": None, "new": [], "resolved": []}


def format_report(result):
    lines = [f"AI SHIELD — {result['target']} — {result['scanned_at']}",
             f"inventory: {result['inventory_count']} items | "
             f"findings: {len(result['findings'])} | KEV catalog: {result['kev_catalog_date']}"]
    if not result["findings"]:
        lines.append("clean — nothing matched known-vulnerable ranges or KEV products.")
    for c in result.get("cleared") or []:
        lines.append(f"cleared: {c['name']} {c['version']} — installed version is "
                     f"outside the published affected range for {c['cve']} "
                     f"(KEV name-match, version-checked)")
    for f in result["findings"]:
        kev_tag = " [KNOWN-EXPLOITED]" if f["known_exploited"] else ""
        fix = f" -> fixed in {', '.join(f['fixed_versions'])}" if f.get("fixed_versions") else ""
        verdict = ""
        det = f.get("ai_detail") or {}
        if f.get("ai_verdict"):
            verdict = f" [ai: {f['ai_verdict']}" + \
                      (f" p={det['p_yes']}" if det.get("p_yes") is not None else "") + "]"
        era = ""
        if f.get("ai_era"):
            era = (f" [ai era: {f['ai_era'].get('verdict')} — "
                   f"{f['ai_era'].get('reason', '')}]")
        lines.append(f"- {f['name']} {f['version']} ({f['ecosystem']}/{f['manager']}) "
                     f"{','.join(f['cve_ids']) or f['vuln_id']}{kev_tag}: "
                     f"{f['summary'][:110]}{fix} [{f['confidence']}; via {','.join(f['sources'])}]{verdict}{era}")
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
    ch = result.get("changes") or {}
    if ch.get("since"):
        lines.append(f"changes since last scan ({ch['since']}): "
                     f"{len(ch.get('new') or [])} new, "
                     f"{len(ch.get('resolved') or [])} resolved")
        for f in ch.get("resolved") or []:
            lines.append(f"  resolved: {f['name']} {f['version']} "
                         f"{','.join(f['cve_ids'])}")
        for f in ch.get("new") or []:
            lines.append(f"  NEW: {f['name']} {f['version']} "
                         f"{','.join(f['cve_ids'])}")
    if result.get("ai_brief"):
        lines.append(f"\nAI brief ({result.get('ai_model')}):\n{result['ai_brief']}")
    for w in result.get("warnings") or []:
        lines.append(f"warning: a feed cross-check was unavailable ({w[:120]})")
    return "\n".join(lines)


def auto_cycle(target, program=None):
    """One automated-defense cycle for a target: scan, filter the plan
    through the owner's automation policy, apply what's allowed,
    rescan, write the usual report. Refuses (with the reason) when
    the policy doesn't cover this target — agents and watch mode
    both run through here, so the rules live in exactly one place."""
    from . import policy as policymod
    from . import report as _report
    pol = policymod.load()
    if not pol.get("enabled") or not pol.get("auto_apply"):
        return {"target": target, "ran": False,
                "reason": "automation policy is off — the owner has not "
                          "enabled agent auto-patching (Settings → "
                          "Automation policy, or config/policy.local.yaml)"}
    if target not in (pol.get("targets") or []):
        return {"target": target, "ran": False,
                "reason": "target %r is not covered by the automation "
                          "policy" % target}
    before = run_scan(target, program=program)
    allowed, withheld = policymod.filter_plan(before["plan"], pol)
    outcome = patch.apply_plan(allowed, confirm="PATCH")
    after = run_scan(target, program=program)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf = _report.write_run_report(base, target, before, outcome, after)
    return {"target": target, "ran": True,
            "findings_before": len(before["findings"]),
            "findings_after": len([f for f in after["findings"]
                                   if f["confidence"] != "error"]),
            "applied": [{"name": r.get("name"), "result": r.get("result")}
                        for r in outcome.get("applied") or []],
            "withheld": withheld, "report": pdf}
