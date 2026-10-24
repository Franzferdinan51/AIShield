"""Patch planner + executor.

Safety model: planning is always free; applying requires an explicit
confirm token at the call site (CLI --apply flag / MCP confirm="PATCH").
Every apply is logged, and the caller re-scans to verify. Commands run
where the software lives, through the program's own transport.
"""
import json
import os
import subprocess
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(HERE, "data", "patch-log.jsonl")



def target_opts(target):
    """Per-target options from config/targets.yaml, overridden by the
    untracked config/targets.local.yaml; the '_all_' entry merges into
    every target."""
    opts = {}
    try:
        import yaml
        for name in ("targets.yaml", "targets.local.yaml"):
            path = os.path.join(HERE, "config", name)
            if not os.path.exists(path):
                continue
            with open(path) as f:
                doc = yaml.safe_load(f) or {}
            merged = dict(doc.get("_all_") or {})
            merged.update(doc.get(target) or {})
            for k, v in merged.items():
                if k == "lifeline_extra":
                    opts[k] = list(opts.get(k) or []) + list(v or [])
                else:
                    opts[k] = v
    except Exception:
        pass
    return opts


def plan_for(finding):
    """Return {auto: bool, command: str|None, note: str} for one finding."""
    conf = str(finding.get("confidence", ""))
    confirmed = finding.get("ai_verdict") == "yes" or "confirmed" in conf
    if conf.startswith("name-match") and not confirmed:
        return {"auto": False, "command": None,
                "note": "unconfirmed product name-match — verify it's the KEV product "
                        "before patching (scan with adjudication to auto-check)"}
    mgr, name = finding["manager"], finding["name"]
    fixed = (finding.get("fixed_versions") or [None])[0]
    if mgr == "apt":
        install = finding.get("install_name") or name
        return {"auto": True, "command": f"sudo apt-get install -y --only-upgrade {install}",
                "note": f"apt upgrades {install} to the distro's fixed build (backports included)"}
    if mgr == "pip":
        # Use the interpreter the collector inventoried (findings carry it);
        # a bare `python3` here could resolve to a different environment
        # than the one that was scanned.
        py = finding.get("python") or "python3"
        spec = f"'{name}>={fixed}'" if fixed else f"-U {name}"
        cmd = f"{py} -m pip install -U {spec}" if fixed else f"{py} -m pip install {spec}"
        if target_opts(finding["target"]).get("pip_break_system_packages"):
            cmd += " --break-system-packages"
        return {"auto": True, "command": cmd,
                "note": f"pip upgrade to >={fixed}" if fixed else "pip upgrade to latest"}
    if mgr == "npm":
        spec = f"{name}@{fixed}" if fixed else f"{name}@latest"
        return {"auto": True, "command": f"npm install -g {spec}", "note": f"npm global -> {spec}"}
    if mgr == "brew":
        return {"auto": True, "command": f"brew upgrade {name}",
                "note": "Homebrew upgrade to latest fixed build"}
    if mgr == "winapp":
        wid = finding.get("winget_id")
        if wid:
            import base64 as _b64
            ps = (f"winget upgrade --id {wid} --exact --silent "
                  f"--accept-package-agreements "
                  f"--accept-source-agreements --disable-interactivity")
            enc = _b64.b64encode(ps.encode("utf-16-le")).decode()
            avail = finding.get("winget_available")
            return {"auto": True,
                    "command": f"powershell -NoProfile -EncodedCommand {enc}",
                    "note": f"winget upgrade {wid}"
                            + (f" → {avail}" if avail else " → latest")}
        return {"auto": False, "command": None,
                "note": "no winget package id matched this app — update "
                        "it with its vendor updater"}
    if mgr == "macapp":
        return {"auto": False, "command": None,
                "note": "App-store/vendor updater — update inside the app or its vendor site"}
    if mgr == "binary":
        return {"auto": False, "command": None,
                "note": "Standalone binary — reinstall from vendor (or its package manager)"}
    return {"auto": False, "command": None, "note": f"No patch route for manager '{mgr}'"}


def _ver(v):
    try:
        from packaging.version import Version
        return (0, Version(str(v)), "")
    except Exception:
        return (1, None, str(v))


# Packages a patch run must never auto-apply: the machine's lifelines —
# boot/kernel, remote access, the package managers themselves, container
# runtimes. A deterministic rule: it fires before (and regardless of)
# any AI decision. Users extend it per target with lifeline_extra.
LIFELINES = ("linux-image", "linux-headers", "linux-generic", "openssh",
             "openssh-server", "docker", "containerd", "apt", "dpkg",
             "rpm", "dnf", "grub", "systemd", "libc6", "glibc")


def lifeline_hold(name, target=None):
    n = (name or "").lower()
    extra = target_opts(target).get("lifeline_extra") or [] if target else []
    return any(tok in n for tok in list(LIFELINES) + [str(e).lower() for e in extra])


def build_plan(findings, decide=False):
    """One step per (target, package, manager): when several CVEs hit one
    package, patch once to the highest fixed version. With decide=True, each
    auto step gets a safety decision: lifeline rule first, then the
    configured decision model (fail-open: no answer = no decision field)."""
    steps = {}
    for f in findings:
        p = plan_for({**f, "fixed_versions": sorted(f.get("fixed_versions") or [],
                                                    key=_ver, reverse=True)})
        key = (f["target"], f["name"].lower(), f["manager"])
        step = {**{k: f.get(k) for k in ("target", "name", "version", "ecosystem",
                                         "manager", "cve_ids", "fixed_versions",
                                         "known_exploited", "ai_verdict",
                                         "winget_id", "winget_available")}, **p}
        if key not in steps:
            steps[key] = step
        else:
            s = steps[key]
            s["cve_ids"] = sorted(set(s["cve_ids"]) | set(step["cve_ids"]))
            s["known_exploited"] = s["known_exploited"] or step["known_exploited"]
            new_fixed = step["fixed_versions"][0] if step["fixed_versions"] else None
            old_fixed = s["fixed_versions"][0] if s["fixed_versions"] else None
            if new_fixed and (not old_fixed or _ver(new_fixed) > _ver(old_fixed)):
                s["command"], s["note"], s["auto"] = step["command"], step["note"], step["auto"]
                s["fixed_versions"] = step["fixed_versions"]
    plan = list(steps.values())
    if decide:
        from . import ai
        checked = 0
        for s in plan:
            if not s.get("auto"):
                continue
            if lifeline_hold(s["name"], s.get("target")):
                s["decision"] = "hold"
                s["decision_detail"] = {"via": "lifeline-rule"}
                continue
            if checked >= 80:
                break
            checked += 1
            decision, detail = ai.decide_patch_step(s)
            if decision:
                s["decision"] = decision
                s["decision_detail"] = detail
    _apply_approvals(plan, decide=decide)
    return plan


def _approved_command(s):
    name = s.get("name") or ""
    if s.get("manager") == "winapp" and s.get("winget_id"):
        return plan_for({"manager": "winapp",
                         "winget_id": s["winget_id"],
                         "winget_available": s.get("winget_available"),
                         "name": name, "confidence": "confirmed",
                         "fixed_versions": s.get("fixed_versions")})["command"]
    if s.get("manager") == "brew":
        return "brew upgrade %s" % name
    if s.get("manager") == "npm":
        fix = (s.get("fixed_versions") or ["latest"])[0]
        return "npm install -g %s@%s" % (name, fix)
    if s.get("manager") == "apt":
        return "sudo apt-get install -y --only-upgrade %s" % name
    return None


def _apply_approvals(plan, decide=False):
    """Owner approvals (aishield/approvals.py) meet the plan:
    'acknowledge' just stamps the step; 'patch' promotes a held step
    into the plan — except lifelines, which no approval can lift, and
    app-store items, which have no patch command to run. A promoted
    candidate still faces the AI safety check; an approved step that
    was ALREADY held by that check is the owner's override."""
    from . import approvals
    store = approvals.load()
    if not store:
        return
    for s in plan:
        action = approvals.lookup(s, store)
        if not action:
            continue
        if action == "acknowledge":
            s["acknowledged"] = True
            continue
        # action == "patch"
        if lifeline_hold(s["name"], s.get("target")):
            s["approval_blocked"] = "lifeline — never auto-patched"
            continue
        if s.get("auto") and s.get("decision") == "hold":
            s["approved"] = True
            s["approved_override"] = True
            continue
        if s.get("auto"):
            s["approved"] = True
            continue
        cmd = s.get("command") or _approved_command(s)
        if not cmd:
            s["approval_blocked"] = ("no patch command exists for this "
                                     "kind of item (vendor/app-store)")
            continue
        s["command"] = cmd
        s["approved"] = True
        if decide:
            from . import ai
            decision, detail = ai.decide_patch_step(s)
            if decision:
                s["decision"] = decision
                s["decision_detail"] = detail
                if decision == "hold":
                    s["note"] = ((s.get("note") or "") +
                                 " [you approved this, but the safety "
                                 "check still holds it]").strip()
                    continue  # stays manual: auto remains False
        s["auto"] = True


def _exec(target, command, timeout=600):
    """Run a patch command through the program's own transport."""
    from . import transport
    try:
        out, err, rc = transport.run(target, command, timeout=timeout)
    except Exception as e:
        # A timeout or transport failure is a FAILED STEP with the
        # reason recorded — never an exception that kills the whole
        # run silently (v0.8.2's apt update hit the 600 s cap on a
        # slow mirror and the run died with no steps, log or report).
        return 127, "", f"{type(e).__name__}: {e}"[:1000]
    return rc, (out or "")[-2000:], (err or "")[-1000:]


def apply_plan(plan, confirm, log=None):
    """Execute the auto entries of a plan. confirm must be the string
    'PATCH'. `log`, when given, is called with one line at a time so a
    UI can stream the run live."""
    say = log or (lambda line: None)
    if confirm != "PATCH":
        return {"error": "apply requires confirm='PATCH' — nothing was run"}
    auto_n = sum(1 for s in plan if s.get("auto") and s.get("command"))
    say(f"applying {auto_n} step(s); "
        f"{len(plan) - auto_n} manual/held step(s) stay for the owner")
    # refresh apt metadata once per target before any apt step (a fresh
    # machine's package lists may be empty — "Unable to locate package")
    apt_targets = sorted({s["target"] for s in plan
                          if s.get("auto") and s.get("manager") == "apt"})
    update_warnings = []
    for t in apt_targets:
        say(f"[{t}] refreshing apt package lists…")
        rc, out, err = _exec(t, "sudo apt-get update -qq", timeout=1800)
        if rc != 0:
            update_warnings.append(
                {"target": t, "apt_update_failed":
                 (out + err)[-400:] or f"rc={rc}"})
    results = []
    for step in plan:
        if not step.get("auto") or not step.get("command"):
            results.append({**step, "result": "skipped-manual"})
            continue
        if step.get("decision") == "hold" \
                and not step.get("approved_override"):
            results.append({**step, "result": "held-by-decision"})
            say(f"■ held by the safety decision: {step['name']} "
                f"({step['target']})")
            continue
        say(f"→ {step['name']} ({step['target']}): {step.get('note') or step['manager']}")
        rc, out, err = _exec(step["target"], step["command"])
        pep668_retry = False
        if rc != 0 and step.get("manager") == "pip" \
                and "--break-system-packages" not in step["command"] \
                and ("externally-managed" in (out + err) or "PEP 668" in (out + err)):
            # PEP 668 refusal: this run exists only because a person
            # explicitly confirmed it (confirm="PATCH"), so retry once
            # with the override instead of failing the step.
            pep668_retry = True
            say("  pip refused (PEP 668 externally-managed) — retrying "
                "once with --break-system-packages")
            rc, out, err = _exec(step["target"],
                                 step["command"] + " --break-system-packages")
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "target": step["target"],
                 "name": step["name"], "from_version": step["version"],
                 "command": step["command"], "rc": rc,
                 "pep668_retry": pep668_retry}
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        result = "applied" if rc == 0 else "failed"
        if rc == 0:
            say(f"  ✓ {step['name']} — command succeeded")
        else:
            tail = ((out + err).strip().splitlines() or [""])[-1][:160]
            say(f"  ✗ {step['name']} — rc={rc}: {tail}")
        if rc != 0 and ("no RECORD file" in (out + err)
                        or "installed by brew" in (out + err)):
            # pip cannot uninstall a copy Homebrew installed (no pip
            # metadata) — that copy updates with brew, not pip.
            result = "blocked-brew-owned"
        results.append({**step, "result": result,
                        "rc": rc, "pep668_retry": pep668_retry,
                        "output_tail": (out + err)[-400:]})
    # Post-apply consistency check: if any pip step ran, ask that same
    # interpreter whether the environment still resolves (catches the case
    # where an upgrade overshoots another package's exact pin).
    checks = {}
    for s in plan:
        if s.get("manager") == "pip" and s.get("auto") and s.get("command"):
            py = s["command"].split(" -m pip")[0]
            checks.setdefault((s["target"], py), None)
    warnings = []
    for (target, py) in checks:
        rc, out, err = _exec(target, f"{py} -m pip check")
        text = (out + err).strip()
        if rc != 0 and text:
            warnings.append({"target": target, "python": py,
                             "pip_check": text[:600]})
    # AI diagnosis for anything that didn't apply — advice stamped
    # onto the step, never a change to what was attempted.
    try:
        from . import ai as _ai
        for r in results:
            if r.get("result") in ("failed",) or str(
                    r.get("result", "")).startswith("blocked"):
                diag = _ai.diagnose_failure(r, r.get("output_tail") or "")
                if diag:
                    r["ai_diagnosis"] = diag
                    say(f"  AI diagnosis for {r['name']}: {diag}")
    except Exception:
        pass
    done_n = sum(1 for r in results if r.get("result") == "applied")
    say(f"apply phase done: {done_n} applied, "
        f"{len(results) - done_n} not applied (see step cards)")
    return {"applied": results,
            "env_warnings": update_warnings + warnings}
