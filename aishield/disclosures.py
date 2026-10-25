"""Disclosure feeds: vulnerabilities published WITHOUT CVE assignment —
researcher disclosures, vendor pre-CVE advisories, incident reports.

Philosophy (same as the rest of the shield): verdicts stay deterministic.
An advisory here is curated, structured data — product, the EXACT versions
the source tested, severity as stated by the source, the precondition the
source states, and the source's operator mitigations. The matcher fires
only on a version the source actually tested; any other version is
reported as unproven, never as safe and never as vulnerable. There is no
CVE and no vendor fix for these by definition, so the patch planner must
never offer an upgrade for a disclosure finding (see patch.plan_for).

Feed #1: TAILWORM — Erica Windisch / Cyberdione Labs' security assessment
of Tailscale v1.104.2 and headscale v0.29.5 (testing 2026-10-22..24),
published 2026-10-25 WITHOUT coordinated disclosure: 11 findings, no CVE
IDs assigned, unpatched at publication. Source: https://tailworm.com/
(no llms.txt / machine-readable edition exists on the site — checked
2026-10-25 — so the advisories below are curated from the report text).
A page-hash watch flags when the report changes after curation, so a
human re-checks for CVE assignments or vendor fixes.
"""
import hashlib
import json
import os
import time

import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "data")

TAILWORM_URL = "https://tailworm.com/"
TAILWORM_CURATED = "2026-10-25"

# id, product, tested versions, severity (as stated), title,
# precondition (as stated / implied by the finding), operator mitigation
TAILWORM = [
    ("TAILWORM-1", "tailscale", ["1.104.2"], "High",
     "Tailscale SSH: ssh -L unix-socket forwarding dials as root",
     "Tailscale SSH server enabled",
     "Disable Tailscale SSH (or SSH forwarding); keep SSH grants per-pair, never identity/tag-wide."),
    ("TAILWORM-2", "tailscale", ["1.104.2"], "High",
     "Tailscale SSH: ssh -R unix-socket forwarding replaces root-owned sockets",
     "Tailscale SSH server enabled",
     "Disable Tailscale SSH (or SSH forwarding); keep SSH grants per-pair, never identity/tag-wide."),
    ("TAILWORM-3", "tailscale", ["1.104.2"], "High",
     "Tailscale SSH: TOCTOU race defeats the unix-socket path allowlist",
     "Tailscale SSH server enabled",
     "Disable Tailscale SSH (or SSH forwarding); firewalls do not stop this race."),
    ("TAILWORM-4", "tailscale", ["1.104.2"], "High",
     "conn25 app connector: a user entitlement confers unrestricted egress selection",
     "App connector (conn25) in use",
     "Enforce connector destinations with an egress allowlist at the firewall; drop cloud metadata and internal ranges by default."),
    ("TAILWORM-5", "tailscale", ["1.104.2"], "High",
     "Tailscale SSH: gliderssh session pin causes a root-tailscaled OOM loop",
     "Tailscale SSH server enabled",
     "Disable Tailscale SSH until the upstream gliderlabs/ssh fix ships in tailscaled."),
    ("TAILWORM-6", "headscale", ["0.29.5"], "Medium-High",
     "headscale: embedded DERP / noise auth cache memory exhaustion",
     "Running headscale (embedded DERP)",
     "Put memory limits and restart supervision on headscale; throttle registration rate."),
    ("TAILWORM-7", "tailscale", ["1.104.2"], "High",
     "serve --tcp forward to the localapi socket: remote permit-write access to localapi",
     "A serve TCP forward to a unix socket (e.g. localapi) is configured",
     "Audit serve config; remove TCP forwards to the agent's own or other privileged sockets."),
    ("TAILWORM-8", "tailscale", ["1.104.2"], "Medium",
     "serve unix-proxy socket guard is config-time-only (TOCTOU)",
     "A serve unix-socket proxy is configured",
     "Avoid serve unix-socket proxies to privileged sockets until fixed."),
    ("TAILWORM-9", "tailscale", ["1.104.2"], "Medium",
     "funnel entitlement is peer-capability + local config only (node attribute is CLI-only)",
     "Tailscale Funnel in use",
     "Keep Funnel off unless it is actively needed; it is a public-internet exposure."),
    ("TAILWORM-10", "tailscale", ["1.104.2"], "Configuration note",
     "TS_SERVE_ALLOW_ALL_INTERFACES exposes serve outside the tunnel bind",
     "TS_SERVE_ALLOW_ALL_INTERFACES set (non-default knob)",
     "Do not set TS_SERVE_ALLOW_ALL_INTERFACES."),
    ("TAILWORM-11", "tailscale", ["1.104.2"], "Medium",
     "serve web handler: shared-context race bleeds capabilities across mounts (authorization bypass)",
     "tailscale serve with header-based authorization across mounts",
     "Avoid relying on per-mount header authorization in serve until fixed."),
]

FEEDS = [
    {"name": "tailworm", "url": TAILWORM_URL, "curated": TAILWORM_CURATED,
     "advisories": TAILWORM},
]


def advisories():
    """Returns (advisory dicts, feed meta). Advisory dict shape:
    {id, product, versions, severity, title, precondition, mitigation,
     feed, url, curated}."""
    out, meta = [], {"feeds": []}
    for feed in FEEDS:
        for (vid, product, versions, severity, title, pre, mit) in feed["advisories"]:
            out.append({"id": vid, "product": product, "versions": versions,
                        "severity": severity, "title": title,
                        "precondition": pre, "mitigation": mit,
                        "feed": feed["name"], "url": feed["url"],
                        "curated": feed["curated"]})
        meta["feeds"].append({"name": feed["name"], "url": feed["url"],
                              "curated": feed["curated"],
                              "count": len(feed["advisories"])})
    meta["stale"] = _tailworm_stale()
    return out, meta


def _tailworm_stale():
    """True when the live TAILWORM report page differs from the page as
    curated. The first successful fetch sets the baseline; an unreachable
    page is not 'stale', just unchecked (returns False)."""
    path = os.path.join(DATA, "tailworm-baseline.json")
    fresh = os.path.exists(path) and (time.time() - os.path.getmtime(path)) < 12 * 3600
    if fresh:
        try:
            with open(path) as f:
                return bool(json.load(f).get("stale"))
        except Exception:
            return False
    try:
        r = requests.get(TAILWORM_URL, timeout=30,
                         headers={"User-Agent": "aishield"})
        r.raise_for_status()
        digest = hashlib.sha256(r.content).hexdigest()
    except Exception:
        return False
    stale = False
    try:
        with open(path) as f:
            stale = json.load(f).get("sha256") != digest
    except Exception:
        stale = False  # no baseline yet — this fetch becomes it
    try:
        os.makedirs(DATA, exist_ok=True)
        with open(path, "w") as f:
            json.dump({"sha256": digest, "stale": stale,
                       "checked_at": time.strftime("%Y-%m-%d %H:%M:%S %Z")}, f)
    except Exception:
        pass
    return stale
