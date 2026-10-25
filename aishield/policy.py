"""Automation policy — the owner's standing orders for agents.

Scans are always free for any caller (CLI, MCP, an AI in LM Studio).
PATCHING without a human in the loop is different: it happens only
inside the policy the owner set in config/policy.local.yaml:

  enabled: false            master switch (default off)
  targets: [local]          machines the policy covers
  auto_apply: false         agents/watch may apply patches
  require_decision_allow: true
                            an auto step needs the AI safety check's
                            'allow' (or an owner approval) — a missing
                            or held decision withholds the step
  allow_candidates: false   name-match findings (KEV products matched
                            by name, AI-confirmed) may auto-apply
  scan_interval_hours: 24   watch-mode cadence

Lifelines are never auto-applied under any policy. Owner approvals
(approvals.py) always count: an approved step is the human's word,
recorded ahead of time.
"""
import os

import yaml

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(HERE, "config", "policy.local.yaml")

DEFAULTS = {"enabled": False, "targets": ["local"], "auto_apply": False,
            "require_decision_allow": True, "allow_candidates": False,
            "scan_interval_hours": 24}


def load():
    pol = dict(DEFAULTS)
    try:
        with open(PATH) as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            pol.update({k: data[k] for k in DEFAULTS if k in data})
    except Exception:
        pass
    return pol


def save(pol):
    clean = {k: pol.get(k, DEFAULTS[k]) for k in DEFAULTS}
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    tmp = PATH + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(clean, f, sort_keys=False)
    os.replace(tmp, PATH)
    return clean


def covers(pol, target):
    return bool(pol.get("enabled") and pol.get("auto_apply")
                and target in (pol.get("targets") or []))


def filter_plan(plan, pol):
    """Split a plan into (allowed, withheld) under the policy. Every
    withheld step carries its reason — an agent (or a report) can say
    exactly what wasn't done and why."""
    allowed, withheld = [], []
    for s in plan:
        name = s.get("name")
        if not s.get("auto") or not s.get("command"):
            withheld.append({"name": name, "reason": "not an auto step "
                             "(manual/held)"})
            continue
        detail = s.get("decision_detail") or {}
        if detail.get("via") == "lifeline-rule":
            withheld.append({"name": name, "reason": "lifeline — never "
                             "auto-patched"})
            continue
        if s.get("approved"):
            allowed.append(s)
            continue
        if pol.get("require_decision_allow") and s.get("decision") != "allow":
            withheld.append({"name": name, "reason": "no safety-check "
                             "'allow' on record (decision: %s)"
                             % (s.get("decision") or "none")})
            continue
        if not pol.get("allow_candidates") and s.get("ai_verdict") is not None:
            withheld.append({"name": name, "reason": "name-match finding "
                             "— policy keeps candidates manual"})
            continue
        allowed.append(s)
    return allowed, withheld
