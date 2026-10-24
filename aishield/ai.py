"""AI layer: two swappable roles, both configured in config/models.yaml
(or env) — never hardcoded in code.

  triage    — a chat model (OpenAI-compatible /v1/chat/completions) that
              writes prose briefs. Uses only models ALREADY LOADED on the
              server; never triggers a load. Unset = auto-pick strongest.
  decision  — typed decisions (noul / choice) with calibrated
              probabilities from an optional decision endpoint:
              /v1/decisions (OpenAI-compatible; LM Studio 0.4.26+)
              or /v1/systemone (Jev wire; LM Studio / Ollama),
              selected by config protocol (auto = decisions first),
              falling back to the triage chat model in prose.
              Fail-open: if nothing answers, scans proceed without
              decisions.

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


def _headers():
    key = cfgmod.load()["server"].get("api_key") or os.environ.get("AISHIELD_API_KEY")
    return {"Authorization": f"Bearer {key}"} if key else {}


def _proxies():
    """Optional proxying for the model server, opt-in via config
    (server.proxy_mode: 'env-connect' + server.proxy_port): route
    through the HTTPS_PROXY host on a different port — for sandboxed
    runners whose model server is reachable only through a CONNECT
    proxy. Default: no explicit proxies (requests' environment
    defaults apply)."""
    srv = cfgmod.load()["server"]
    if srv.get("proxy_mode") != "env-connect":
        return None
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    port = srv.get("proxy_port")
    if not https_proxy or not port:
        return None
    from urllib.parse import urlparse, urlunparse
    u = urlparse(https_proxy)
    netloc = f"{u.hostname}:{port}"
    if u.username:
        netloc = f"{u.username}:{u.password or ''}@{netloc}"
    tunnel = urlunparse((u.scheme or "http", netloc, "", "", "", ""))
    return {"http": tunnel, "https": tunnel}


# ------------------------------------------------------------------ triage (chat)
def loaded_models():
    try:
        r = requests.get(server_url() + "/v1/models", proxies=_proxies(),
                         headers=_headers(), timeout=10)
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
                      proxies=_proxies(), headers=_headers(), timeout=timeout)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


SYSTEM = ("You are the reasoning layer of AI Shield, a defensive CVE scanner "
          "people run on their own machines. Be precise and concrete. Never "
          "invent CVE details beyond what you are given. Plain language, no "
          "hype: say what is exposed, how bad it is, and the exact fix.")


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
    try:
        return chat([{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}], model=model,
                    max_tokens=1600)
    except Exception as e:
        # The brief is optional garnish — never let it kill a scan.
        return f"(AI brief unavailable: {str(e)[:120]})"


# ------------------------------------------------- decision (typed endpoint)
import time as _time

_decision_dead_until = 0.0
_last_via = 'decision'


def _post_decisions(model, endpoint, state, questions, timeout):
    """OpenAI-compatible decisions wire (LM Studio 0.4.26+): questions
    as an ARRAY; noul -> predicate; answers keyed by name."""
    qlist = []
    for name, q in questions.items():
        item = {"name": name, "instructions": q["instructions"]}
        if q["type"] == "noul":
            item["type"] = "predicate"
        elif q["type"] == "choice":
            item["type"] = "choice"
            item["choices"] = [{"value": v, "description": d}
                                for v, d in (q.get("criteria") or {}).items()]
        else:
            item["type"] = q["type"]
        qlist.append(item)
    r = requests.post(server_url() + endpoint,
                      json={"model": model, "input": state, "questions": qlist},
                      proxies=_proxies(), headers=_headers(), timeout=timeout)
    if r.status_code != 200:
        return None
    answers = {}
    for a in r.json().get("answers") or []:
        name = a.get("name")
        if a.get("type") == "predicate" and isinstance(a.get("probability"), (int, float)):
            answers[name] = {"noul": a["probability"]}
        elif a.get("type") == "choice":
            probs = {p["value"]: p["probability"]
                     for p in a.get("probabilities") or []
                     if isinstance(p.get("probability"), (int, float))}
            answers[name] = {"choice": a.get("choice"), "probabilities": probs}
    return answers or None


def _post_systemone(model, endpoint, state, questions, timeout):
    """Jev / SystemOne wire: questions as a MAP; noul/choice types."""
    r = requests.post(server_url() + endpoint,
                      json={"model": model, "state": state,
                            "questions": questions},
                      proxies=_proxies(), headers=_headers(), timeout=timeout)
    if r.status_code != 200:
        return None
    answers = r.json().get("answers")
    return answers if isinstance(answers, dict) and answers else None


def decision_answers(state, questions, timeout=20):
    """Ask the configured decision protocol. Returns
    {"answers": {...}, "model": id, "via": protocol} or None.

    Protocols (config roles.decision.protocol):
      decisions — POST /v1/decisions (OpenAI-compatible; LM Studio
                  0.4.26+ serves it natively for decision models)
      systemone — POST /v1/systemone (Jev wire; LM Studio 0.4.26+ and
                  Ollama serve it; the legacy path, being superseded
                  by /v1/decisions upstream)
      auto      — decisions first, then systemone (default)
      chat      — no typed endpoint; callers fall back to the chat model
    Tries the configured decision model, then its fallback. Circuit
    breaker: a connection failure mutes the layer for 60 s so a down
    server can't tax every candidate/step in a scan with timeouts."""
    global _decision_dead_until, _last_via
    if _time.time() < _decision_dead_until:
        return None
    cfg = cfgmod.load()["roles"]["decision"]
    protocol = (cfg.get("protocol") or "auto").lower()
    if protocol == "chat":
        return None
    wires = {"decisions": (_post_decisions, cfg.get("decisions_endpoint") or "/v1/decisions"),
             "systemone": (_post_systemone, cfg.get("endpoint") or "/v1/systemone")}
    order = ["decisions", "systemone"] if protocol == "auto" else [protocol]
    for model in [cfg.get("model"), cfg.get("fallback")]:
        if not model:
            continue
        for name in order:
            fn, endpoint = wires[name]
            try:
                answers = fn(model, endpoint, state, questions, timeout)
            except Exception:
                _decision_dead_until = _time.time() + 60
                return None
            if answers:
                _last_via = name
                return {"answers": answers, "model": model, "via": name}
    return None


def decision_typed_models():
    """Models the server itself types as 'decision' (LM Studio's
    /api/v1/models), best-effort — [] on any other server."""
    try:
        r = requests.get(server_url() + "/api/v1/models",
                         proxies=_proxies(), headers=_headers(), timeout=8)
        if r.status_code != 200:
            return []
        return [m["key"] for m in r.json().get("models") or []
                if m.get("type") == "decision" and m.get("key")]
    except Exception:
        return []


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
        return verdict, {"p_yes": p, "model": model, "via": _last_via}
    try:
        out = chat([{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": state + "\nIs the installed application "
                     "the same product the KEV entry refers to? Answer with exactly "
                     "one word: yes, no, or unsure."}], max_tokens=8, timeout=30)
    except Exception:
        out = None
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
    if label:
        return label, {"probabilities": probs, "model": model, "via": _last_via}
    # Chat fallback: any loaded chat model can make the same call in
    # prose. Strict one-word answer; anything unclear means no decision
    # (the caller treats silence as fail-open, and lifelines already
    # fired deterministically before this layer).
    try:
        out = chat([{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": state + "\nMay this patch step be "
                     "auto-applied, or must it be held for a human? Answer with "
                     "exactly one word: allow or hold."}], max_tokens=8, timeout=30)
    except Exception:
        out = None
    if not out:
        return None, {}
    word = out.strip().lower().split()[0].strip(".,")
    if word in ("allow", "hold"):
        return word, {"via": "chat"}
    return None, {}
