"""AI layer: two swappable roles, both configured in config/models.yaml
(or env) — never hardcoded in code.

  triage    — a chat model (OpenAI-compatible /v1/chat/completions) that
              writes prose briefs. Uses only models ALREADY LOADED on the
              server; never triggers a load. Unset = auto-pick strongest.
  decision  — a decision model on the SystemOne wire (POST /v1/systemone):
              typed questions (noul / choice) answered with calibrated
              probabilities, no generated text. Fail-open: if it doesn't
              answer, scans proceed without decisions.

Fleet law: AI never decides whether a package version is vulnerable —
deterministic feed data does that. AI decides identity, priority, and
patch safety, and explains.
"""
import json
import os

import requests

from . import config as cfgmod

YES_AT = 0.75   # noul P(yes) at/above -> "yes"
NO_AT = 0.30    # noul P(yes) at/below -> "no"; between -> "unsure"


def server_url():
    return cfgmod.load()["server"]["url"]


def _proxies():
    """Route non-localhost model servers through the fleet tunnel proxy."""
    url = server_url()
    if "localhost" in url or "127.0.0.1" in url:
        return None
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if https_proxy and ":" in https_proxy:
        tunnel = https_proxy.rsplit(":", 1)[0] + ":3130"
        return {"http": tunnel, "https": tunnel}
    return None


# ------------------------------------------------------------------ triage (chat)
def loaded_models():
    try:
        r = requests.get(server_url() + "/v1/models", proxies=_proxies(), timeout=10)
        r.raise_for_status()
        return [m["id"] for m in r.json().get("data", [])]
    except Exception:
        return []


def triage_model(models=None):
    configured = cfgmod.load()["roles"]["triage"]["model"]
    if configured:
        return configured
    models = models if models is not None else loaded_models()
    chat = [m for m in models if "embed" not in m.lower()
            and not m.lower().startswith("d1")]
    if not chat:
        return None
    def score(m):
        s = 0
        for tag, pts in (("35b", 50), ("27b", 45), ("12b", 35), ("9b", 30),
                         ("7b", 15)):
            if tag in m.lower():
                s = max(s, pts)
        return s
    return sorted(chat, key=score, reverse=True)[0]


# backwards-compatible alias
pick_model = triage_model


def chat(messages, model=None, max_tokens=1200, timeout=180):
    model = model or triage_model()
    if not model:
        return None
    r = requests.post(server_url() + "/v1/chat/completions",
                      json={"model": model, "messages": messages,
                            "max_tokens": max_tokens, "temperature": 0.2},
                      proxies=_proxies(), timeout=timeout)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


SYSTEM = ("You are the reasoning layer of AI Shield, a defensive CVE scanner for a "
          "small home fleet (Linux VM, Mac Studio, two Windows PCs). Be precise and "
          "concrete. Never invent CVE details beyond what you are given. Plain "
          "language, no hype: say what is exposed, how bad it is, and the exact fix.")


def triage(findings, target, model=None):
    if not findings:
        return "No findings to triage."
    slim = [{k: f.get(k) for k in ("name", "version", "ecosystem", "cve_ids",
                                   "summary", "cvss", "known_exploited",
                                   "fixed_versions", "confidence")}
            for f in findings[:40]]
    prompt = ("Here are verified vulnerability findings for target "
              f"'{target}' (JSON). Write a short defensive brief: "
              "1) overall exposure in 2 sentences, 2) the top risks ranked, with "
              "for each: what's exposed, what an attacker gets, the exact fix, "
              "3) what can wait. Keep it tight.\n\n" + json.dumps(slim, indent=1))
    return chat([{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": prompt}], model=model, max_tokens=1600)


# ------------------------------------------------------------------ decision (SystemOne wire)
def decision_answers(state, questions, timeout=20):
    """POST the configured decision endpoint. Returns answers dict or None.
    Tries the configured decision model, then its configured fallback."""
    cfg = cfgmod.load()["roles"]["decision"]
    endpoint = cfg.get("endpoint") or "/v1/systemone"
    for model in [cfg.get("model"), cfg.get("fallback")]:
        if not model:
            continue
        try:
            r = requests.post(server_url() + endpoint,
                              json={"model": model, "state": state,
                                    "questions": questions},
                              proxies=_proxies(), timeout=timeout)
            if r.status_code != 200:
                continue
            answers = r.json().get("answers")
            if isinstance(answers, dict) and answers:
                return {"answers": answers, "model": model}
        except Exception:
            continue
    return None


def decide_noul(state, instructions):
    """Binary decision. Returns (verdict, p_yes, model) — verdict in
    yes/no/unsure; (None, None, None) if the decision layer is silent."""
    out = decision_answers(state, {"q": {"type": "noul", "instructions": instructions}})
    if not out:
        return None, None, None
    ans = out["answers"].get("q") or {}
    p = ans.get("noul")
    if not isinstance(p, (int, float)):
        return None, None, None
    verdict = "yes" if p >= YES_AT else "no" if p <= NO_AT else "unsure"
    return verdict, round(float(p), 3), out["model"]


def decide_choice(state, instructions, criteria):
    """Multi-way decision. criteria: {label: description}.
    Returns (label, probabilities, model) or (None, {}, None)."""
    out = decision_answers(state, {"q": {"type": "choice",
                                         "instructions": instructions,
                                         "criteria": criteria}})
    if not out:
        return None, {}, None
    ans = out["answers"].get("q") or {}
    label = ans.get("choice")
    probs = ans.get("probabilities") or {}
    if label not in criteria:
        return None, {}, None
    return label, {k: round(float(v), 3) for k, v in probs.items()
                   if isinstance(v, (int, float))}, out["model"]


def adjudicate(app_name, app_version, kev_entry):
    """Is this installed app the KEV-listed product?
    Decision model first (typed, probabilistic); chat model as fallback.
    Returns (verdict, detail) — verdict yes/no/unsure."""
    state = (f"Installed application: \"{app_name}\" version {app_version}. "
             f"CISA KEV entry: vendor \"{kev_entry.get('vendorProject')}\", "
             f"product \"{kev_entry.get('product')}\", vulnerability "
             f"\"{kev_entry.get('vulnerabilityName')}\" ({kev_entry.get('cveID')}).")
    instructions = ("Decide whether the installed application is the same product "
                    "the CISA KEV entry refers to. 'yes' means: it is the same "
                    "product. 'no' means: a different product that merely shares "
                    "a name or a word.")
    verdict, p, model = decide_noul(state, instructions)
    if verdict:
        return verdict, {"p_yes": p, "model": model, "via": "decision"}
    out = chat([{"role": "system", "content": SYSTEM},
                {"role": "user", "content": state + "\nIs the installed application "
                 "the same product the KEV entry refers to? Answer with exactly "
                 "one word: yes, no, or unsure."}], max_tokens=8, timeout=120)
    if not out:
        return "unsure", {"via": "none"}
    word = out.strip().lower().split()[0].strip(".,")
    return (word if word in ("yes", "no", "unsure") else "unsure"), {"via": "chat"}


def decide_patch_step(step):
    """Safety decision for one auto patch step. Returns (decision, detail)
    with decision in allow/hold, or (None, {}) if the layer is silent."""
    state = (f"Proposed patch on target '{step['target']}': run "
             f"`{step['command']}` to upgrade {step['name']} from "
             f"{step['version']} (fixes {', '.join(step.get('cve_ids') or []) or 'known CVEs'}"
             f"{', KNOWN-EXPLOITED in the wild' if step.get('known_exploited') else ''}).")
    criteria = {
        "allow": "a routine, reversible package upgrade of a userland library or "
                 "tool; safe to apply without a human watching",
        "hold": "touches a system-critical component, a network/remote-access "
                "lifeline, a database or stateful service, the package manager "
                "itself, or anything where a bad upgrade could lock the owner "
                "out of the machine — a human should apply it",
    }
    label, probs, model = decide_choice(
        state,
        "Decide whether this patch step may be auto-applied or must be held "
        "for a human. When in doubt, hold.", criteria)
    if not label:
        return None, {}
    return label, {"probabilities": probs, "model": model, "via": "decision"}
