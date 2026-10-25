"""Feed layer: CISA KEV (known-exploited), OSV (package vulns + fixed versions),
NVD (CVE detail/CVSS enrichment). All cached under data/ with TTLs."""
import json
import os
import time

import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "data")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fresh(path, ttl_hours):
    return os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl_hours * 3600


# ---------------------------------------------------------------- KEV
def kev(refresh=False):
    """Returns {cveID: entry} for the full CISA Known Exploited Vulnerabilities catalog."""
    path = os.path.join(DATA, "kev.json")
    if refresh or not _fresh(path, 12):
        try:
            r = requests.get(KEV_URL, timeout=60)
            r.raise_for_status()
            os.makedirs(DATA, exist_ok=True)
            with open(path, "w") as f:
                f.write(r.text)
        except Exception:
            if not os.path.exists(path):
                raise  # no cache at all — the caller must know
    with open(path) as f:
        doc = json.load(f)
    return {v["cveID"]: v for v in doc["vulnerabilities"]}, doc.get("dateReleased")


# ---------------------------------------------------------------- OSV


def kev_items(limit=20):
    """Newest KEV entries as {id, summary, severity, published} items —
    the local catalog, so it works with no network at all. Shared by
    the GUI/CLI/MCP 'latest' paths as the CVE Now fallback."""
    kev_map, _ = kev()
    entries = sorted(kev_map.values(),
                     key=lambda e: e.get("dateAdded") or "",
                     reverse=True)[:limit]
    return [{"id": e.get("cveID"),
             "summary": ("%s %s — %s" % (e.get("vendorProject") or "",
                                         e.get("product") or "",
                                         e.get("vulnerabilityName") or ""))[:220],
             "severity": "KEV",
             "published": e.get("dateAdded") or ""} for e in entries]


def osv_query_batch(packages):
    """packages: [{ecosystem, name, version}] -> list parallel to input of [vuln summaries].
    OSV does the version-range matching server-side — deterministic, authoritative."""
    queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                "version": p["version"]} for p in packages]
    out = []
    for i in range(0, len(queries), 500):
        chunk = queries[i:i + 500]
        r = requests.post(OSV_BATCH, json={"queries": chunk}, timeout=120)
        r.raise_for_status()
        out.extend(r.json().get("results", []))
    return out


def osv_vuln_detail(vuln_id):
    """Detail record with a 24 h on-disk cache (vuln records change slowly)."""
    cache = os.path.join(DATA, "osv-cache")
    os.makedirs(cache, exist_ok=True)
    path = os.path.join(cache, vuln_id.replace("/", "_") + ".json")
    if _fresh(path, 24):
        with open(path) as f:
            return json.load(f)
    r = requests.get(OSV_VULN + vuln_id, timeout=30)
    r.raise_for_status()
    doc = r.json()
    with open(path, "w") as f:
        json.dump(doc, f)
    return doc


def osv_details_parallel(vuln_ids, workers=10):
    from concurrent.futures import ThreadPoolExecutor
    def fetch(vid):
        try:
            return vid, osv_vuln_detail(vid)
        except Exception:
            return vid, None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(ex.map(fetch, vuln_ids))


def fixed_versions(detail, ecosystem, name):
    """Extract fixed versions for a package from an OSV vuln detail record."""
    fixes = set()
    for aff in detail.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    v = str(ev["fixed"])
                    # OSV sometimes records a fix commit hash instead of a
                    # version — useless for patching, drop it.
                    if len(v) >= 32 and all(c in "0123456789abcdef" for c in v.lower()):
                        continue
                    if v and (v[0].isdigit() or v[0] in "vV"):
                        fixes.add(v)
    return sorted(fixes)


def cvss_of(detail):
    for sev in detail.get("severity", []):
        if sev.get("type", "").startswith("CVSS"):
            return sev.get("score")
    return None


# ---------------------------------------------------------------- pwn.watch
PWNWATCH_URL = "https://pwn.watch/incidents.json"


def pwnwatch(refresh=False):
    """pwn.watch incident index: live security incidents with CVEs,
    patch status and affected/fixed versions as published (plain static
    JSON, no auth). Returns (incidents, generatedAt). Cached 6 h.
    This is an overlay/candidate source, never a sole verdict source —
    and it must never break a scan: on failure with no cache at all it
    returns ([], None) and the caller notes the gap as a warning."""
    path = os.path.join(DATA, "pwnwatch.json")
    if refresh or not _fresh(path, 6):
        try:
            r = requests.get(PWNWATCH_URL, timeout=60,
                             headers={"User-Agent": "aishield"})
            r.raise_for_status()
            os.makedirs(DATA, exist_ok=True)
            with open(path, "w") as f:
                f.write(r.text)
        except Exception:
            if not os.path.exists(path):
                return [], None
    try:
        with open(path) as f:
            doc = json.load(f)
        return doc.get("incidents", []), doc.get("generatedAt")
    except Exception:
        return [], None


# ---------------------------------------------------------------- NVD
def nvd_cve(cve_id):
    """CVE detail from NVD: description, CVSS base score, weaknesses. Best-effort."""
    try:
        r = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=30,
                         headers={"User-Agent": "aishield"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return {}
        c = vulns[0]["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score = None
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"].get("baseScore")
                break
        return {"description": desc, "cvss": score,
                "published": c.get("published"), "lastModified": c.get("lastModified")}
    except Exception:
        return {}


def cve_fixed_bounds(detail):
    """(package_name, fixed_version) pairs from an OSV vuln record's
    affected ranges — the only machine-readable 'fixed in' data that
    exists for KEV-catalog CVEs (the catalog itself has none)."""
    out = []
    for aff in (detail or {}).get("affected") or []:
        pkg = (aff.get("package") or {}).get("name", "")
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    out.append((pkg, str(ev["fixed"])))
    return out


def nvd_cve_raw(cve_id):
    """Full NVD record for a CVE (24 h on-disk cache). {} on failure."""
    cache = os.path.join(DATA, "nvd-cache")
    os.makedirs(cache, exist_ok=True)
    path = os.path.join(cache, cve_id.replace("/", "_") + ".json")
    if _fresh(path, 24):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    try:
        r = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=30,
                         headers={"User-Agent": "aishield"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        c = vulns[0]["cve"] if vulns else {}
        with open(path, "w") as f:
            json.dump(c, f)
        return c
    except Exception:
        return {}


def nvd_windows(cve_obj):
    """(product, start_incl, end_excl, end_incl) windows from an NVD
    record's CPE configurations — the affected version ranges KEV
    itself doesn't publish. Exact-version CPEs become [v, v] windows."""
    out = []

    def walk(node):
        for m in node.get("cpeMatch", []) or []:
            if not m.get("vulnerable"):
                continue
            parts = (m.get("criteria") or "").split(":")
            if len(parts) < 6:
                continue
            product = parts[4]
            start = m.get("versionStartIncluding")
            endx = m.get("versionEndExcluding")
            endi = m.get("versionEndIncluding")
            if not (start or endx or endi) and parts[5] not in ("*", "-"):
                start = endi = parts[5]
            out.append((product, start, endx, endi))
        for ch in node.get("children", []) or []:
            walk(ch)

    for cfg in (cve_obj or {}).get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            walk(node)
    return out


def nvd_windows_parallel(cve_ids, workers=4):
    from concurrent.futures import ThreadPoolExecutor

    def fetch(cid):
        try:
            return cid, nvd_windows(nvd_cve_raw(cid))
        except Exception:
            return cid, []

    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cid, wins in ex.map(fetch, cve_ids):
            out[cid] = wins
    return out
