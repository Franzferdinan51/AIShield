"""Patch planner + executor.

Safety model (fleet law): planning is always free; applying requires an explicit
confirm token at the call site (CLI --apply flag / MCP confirm="PATCH"). Every
apply is logged with before/after versions, and the caller re-scans to verify.
Commands run where the software lives: locally for the VM, over the ssh
wrappers for mac/batman/grievous.
"""
import json
import os
import subprocess
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(HERE, "data", "patch-log.jsonl")
SSH = {"mac": "~/bin/mac-ssh", "batman": "~/bin/batman-ssh", "grievous": "~/bin/grievous-ssh"}


def target_opts(target):
    try:
        import yaml
        with open(os.path.join(HERE, "config", "targets.yaml")) as f:
            return (yaml.safe_load(f) or {}).get(target, {}) or {}
    except Exception:
        return {}


def plan_for(finding):
    """Return {auto: bool, command: str|None, note: str} for one finding."""
    if str(finding.get("confidence", "")).startswith("name-match") and \
            "AI-confirmed" not in str(finding.get("confidence", "")):
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
        spec = f"'{name}>={fixed}'" if fixed else f"-U {name}"
        cmd = f"python3 -m pip install -U {spec}" if fixed else f"python3 -m pip install {spec}"
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
    if mgr in ("macapp", "winapp"):
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


def build_plan(findings):
    """One step per (target, package, manager): when several CVEs hit one
    package, patch once to the highest fixed version."""
    steps = {}
    for f in findings:
        p = plan_for({**f, "fixed_versions": sorted(f.get("fixed_versions") or [],
                                                    key=_ver, reverse=True)})
        key = (f["target"], f["name"].lower(), f["manager"])
        step = {**{k: f.get(k) for k in ("target", "name", "version", "ecosystem",
                                         "manager", "cve_ids", "fixed_versions",
                                         "known_exploited")}, **p}
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
    return list(steps.values())


def _exec(target, command, timeout=600):
    if target == "vm":
        p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
    else:
        wrapper = os.path.expanduser(SSH[target])
        p = subprocess.run([wrapper, command], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "")[-2000:], (p.stderr or "")[-1000:]


def apply_plan(plan, confirm):
    """Execute the auto entries of a plan. confirm must be the string 'PATCH'."""
    if confirm != "PATCH":
        return {"error": "apply requires confirm='PATCH' — nothing was run"}
    # refresh apt metadata once per target before any apt step (a fresh
    # machine's package lists may be empty — "Unable to locate package")
    apt_targets = sorted({s["target"] for s in plan
                          if s.get("auto") and s.get("manager") == "apt"})
    for t in apt_targets:
        _exec(t, "sudo apt-get update -qq")
    results = []
    for step in plan:
        if not step.get("auto") or not step.get("command"):
            results.append({**step, "result": "skipped-manual"})
            continue
        rc, out, err = _exec(step["target"], step["command"])
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "target": step["target"],
                 "name": step["name"], "from_version": step["version"],
                 "command": step["command"], "rc": rc}
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        results.append({**step, "result": "applied" if rc == 0 else "failed",
                        "rc": rc, "output_tail": (out + err)[-400:]})
    return {"applied": results}
