"""Owner approvals for held patch steps.

The shield holds some steps back on purpose (unconfirmed product
name-matches, AI safety holds). The owner can overrule two ways,
recorded here per finding (target + package + manager + CVE set):

  "patch"       — yes, patch it: the step joins the plan (still
                  safety-checked; lifelines are never overridable)
  "acknowledge" — I know about it; stop listing it as needing me

Approvals live in data/approvals.json on the machine running the
shield. They never create a patch command for app-store software
(there isn't one) and never lift a lifeline hold.
"""
import json
import os
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(HERE, "data", "approvals.json")


def key(target, name, manager, cve_ids):
    return "|".join([target or "", (name or "").lower(), manager or "",
                     ",".join(sorted(cve_ids or []))])


def load():
    try:
        with open(PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def lookup(step, store=None):
    store = store if store is not None else load()
    rec = store.get(key(step.get("target"), step.get("name"),
                        step.get("manager"), step.get("cve_ids")))
    return rec.get("action") if rec else None


def set_approval(target, name, manager, cve_ids, action):
    store = load()
    k = key(target, name, manager, cve_ids)
    if action == "revoke":
        store.pop(k, None)
    elif action in ("patch", "acknowledge"):
        store[k] = {"action": action, "target": target, "name": name,
                    "manager": manager, "cve_ids": cve_ids or [],
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    else:
        return {"error": "action must be patch, acknowledge or revoke"}
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    tmp = PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(store, f, indent=1)
    os.replace(tmp, PATH)
    return {"ok": True, "key": k, "action": action}
