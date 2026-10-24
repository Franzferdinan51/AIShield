"""LM Studio reasoning layer.

Rules (fleet law): use ONLY models already loaded in LM Studio — never trigger
a fresh load. If nothing suitable is loaded, the shield runs fine without AI.
Endpoint: Mac LM Studio via the tailnet tunnel proxy (port 3130).
"""
import json
import os

import requests

# LM Studio endpoint. Set AISHIELD_LM_URL to your own instance (never commit
# a private/tailnet address). Through the fleet tunnel proxy, non-localhost
# http targets are routed via the :3130 tailnet proxy automatically.
MAC_LM = os.environ.get("AISHIELD_LM_URL", "http://localhost:1234")


def _proxies():
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if https_proxy and ":" in https_proxy:
        tunnel = https_proxy.rsplit(":", 1)[0] + ":3130"
        return {"http": tunnel, "https": tunnel}
    return None


def loaded_models():
    try:
        r = requests.get(MAC_LM + "/v1/models", proxies=_proxies(), timeout=10)
        r.raise_for_status()
        return [m["id"] for m in r.json().get("data", [])]
    except Exception:
        return []


def pick_model(models=None):
    """Prefer a strong already-loaded chat model; skip embedders/tiny models."""
    models = models if models is not None else loaded_models()
    chat = [m for m in models if "embed" not in m.lower() and "d1-" not in m.lower()]
    if not chat:
        return None
    def score(m):
        s = 0
        for tag, pts in (("35b", 50), ("27b", 45), ("12b", 35), ("9b", 30),
                         ("da7d", 20), ("7b", 15)):
            if tag in m.lower():
                s = max(s, pts)
        return s
    return sorted(chat, key=score, reverse=True)[0]


def chat(messages, model=None, max_tokens=1200, timeout=180):
    model = model or pick_model()
    if not model:
        return None
    r = requests.post(MAC_LM + "/v1/chat/completions",
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


def adjudicate(app_name, app_version, kev_entry, model=None):
    """Is this installed app the KEV-listed product? Returns 'yes'|'no'|'unsure'."""
    prompt = (f"Installed application: \"{app_name}\" version {app_version}.\n"
              f"CISA KEV entry: vendor/project \"{kev_entry.get('vendorProject')}\", "
              f"product \"{kev_entry.get('product')}\", vulnerability "
              f"\"{kev_entry.get('vulnerabilityName')}\" ({kev_entry.get('cveID')}).\n"
              "Is the installed application the same product the KEV entry refers to? "
              "Answer with exactly one word: yes, no, or unsure.")
    out = chat([{"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt}], model=model, max_tokens=8, timeout=120)
    if not out:
        return "unsure"
    word = out.strip().lower().split()[0].strip(".,")
    return word if word in ("yes", "no", "unsure") else "unsure"
