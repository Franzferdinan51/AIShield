"""Matching engine: inventory x (OSV + CVE Now check_stack + CISA KEV).

Deterministic verdicts come from OSV's server-side version-range matching and
CVE Now's synced catalog (also OSV-backed). KEV overlays known-exploited status.
Apps (non-package software) are name-matched against KEV products as candidates.
"""
import re

from . import cvenow, feeds

OSV_ECOSYSTEMS = {"PyPI", "npm", "Ubuntu", "crates.io", "Go", "NuGet",
                  "RubyGems", "Packagist", "Maven", "Debian", "Alpine"}


def _norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _cve_ids(vuln):
    ids = [vuln.get("id", "")]
    ids += vuln.get("aliases", []) or []
    return sorted({i for i in ids if i.startswith("CVE-")})


def scan_packages(items, kev_map, use_cvenow=True):
    """items: inventory records with OSV ecosystems. Returns findings."""
    pkgs = [it for it in items if it["ecosystem"] in OSV_ECOSYSTEMS and it["version"]]
    findings = []
    if not pkgs:
        return findings
    results = feeds.osv_query_batch(pkgs)
    unique_ids = sorted({v["id"] for res in results for v in (res.get("vulns") or [])})
    detail_cache = feeds.osv_details_parallel(unique_ids) if unique_ids else {}
    for item, res in zip(pkgs, results):
        for v in res.get("vulns", []) or []:
            vid = v["id"]
            detail = detail_cache.get(vid) or v
            cves = _cve_ids(detail) or _cve_ids(v)
            kev_hits = [kev_map[c] for c in cves if c in kev_map]
            findings.append({
                "target": item["target"], "name": item["name"],
                "version": item["version"], "ecosystem": item["ecosystem"],
                "manager": item["manager"], "vuln_id": vid, "cve_ids": cves,
                "python": item.get("python"),
                "winget_id": item.get("winget_id"),
                "winget_available": item.get("winget_available"),
                "install_name": item.get("install_name"),
                "summary": detail.get("summary") or v.get("summary", ""),
                "cvss": feeds.cvss_of(detail),
                "known_exploited": bool(kev_hits),
                "kev": kev_hits[0] if kev_hits else None,
                "fixed_versions": feeds.fixed_versions(detail, item["ecosystem"], item["name"]),
                "sources": ["osv"], "confidence": "version-range match",
            })
    if use_cvenow:
        try:
            # cve.now check_stack only accepts package-registry ecosystems;
            # distro ecosystems (Ubuntu/Debian/Alpine) are OSV-only there.
            eco_map = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo",
                       "Go": "go", "RubyGems": "rubygems", "NuGet": "nuget",
                       "Packagist": "packagist", "Maven": "maven"}
            stack = [{"ecosystem": eco_map[p["ecosystem"]], "name": p["name"],
                      "version": p["version"]} for p in pkgs if p["ecosystem"] in eco_map]
            report = {"affected": []}
            for i in range(0, len(stack), 200):
                part = cvenow.check_stack(stack[i:i + 200])
                if isinstance(part, dict) and isinstance(part.get("affected"), list):
                    report["affected"].extend(part["affected"])
                elif isinstance(part, dict) and "text" in part:
                    raise RuntimeError(str(part["text"])[:160])
            seen = {(f["name"].lower(), tuple(f["cve_ids"])) for f in findings}
            for m in _iter_cvenow_matches(report):
                key = (m["name"].lower(), tuple(m["cve_ids"]))
                if key not in seen:
                    base = next((p for p in pkgs if p["name"].lower() == m["name"].lower()), None)
                    if base:
                        cves = m["cve_ids"]
                        kev_hits = [kev_map[c] for c in cves if c in kev_map]
                        findings.append({
                            "target": base["target"], "name": base["name"],
                            "version": base["version"], "ecosystem": base["ecosystem"],
                            "manager": base["manager"], "vuln_id": m["vuln_id"],
                            "python": base.get("python"),
                            "winget_id": base.get("winget_id"),
                            "winget_available": base.get("winget_available"),
                            "install_name": base.get("install_name"),
                            "cve_ids": cves, "summary": m.get("summary", ""),
                            "cvss": m.get("cvss"), "known_exploited": bool(kev_hits),
                            "kev": kev_hits[0] if kev_hits else None,
                            "fixed_versions": m.get("fixed_versions", []),
                            "sources": ["cve.now"], "confidence": "version-range match"})
                else:
                    for f in findings:
                        if (f["name"].lower(), tuple(f["cve_ids"])) == key:
                            if "cve.now" not in f["sources"]:
                                f["sources"].append("cve.now")
                            if isinstance(m.get("cvss"), (int, float)):
                                f["cvss"] = m["cvss"]
        except Exception as e:
            raw = str(e)
            if any(t in raw for t in ("SSLError", "Connection", "Max retries",
                                      "timed out", "NameResolution")):
                raw = ("CVE Now unreachable from this machine — version "
                       "cross-check skipped; OSV + KEV verdicts still apply")
            findings.append({"target": items[0]["target"] if items else "?",
                             "name": "(cve.now check_stack unavailable)",
                             "version": "", "ecosystem": "", "manager": "",
                             "vuln_id": "", "cve_ids": [], "summary": raw[:200],
                             "cvss": None, "known_exploited": False, "kev": None,
                             "fixed_versions": [], "sources": ["error"],
                             "confidence": "error"})
    return findings


def _iter_cvenow_matches(report):
    """Normalize cve.now check_stack output into match dicts.
    Live shape: {coverage, checked, affected: [{id, title, severity:{cvss},
    url, package:{ecosystem, name, version}}]}."""
    out = []
    matches = []
    if isinstance(report, dict):
        for key in ("affected", "matches", "vulnerable", "results", "findings"):
            if isinstance(report.get(key), list):
                matches = report[key]
                break
        if not matches and report.get("packages"):
            matches = report["packages"]
    elif isinstance(report, list):
        matches = report
    for m in matches:
        if not isinstance(m, dict):
            continue
        pkg = m.get("package") or {}
        if pkg.get("name") and (m.get("id") or "").startswith("CVE-"):
            sev = m.get("severity") or {}
            out.append({"name": pkg["name"], "vuln_id": m["id"],
                        "cve_ids": [m["id"]], "summary": m.get("title", ""),
                        "cvss": sev.get("cvss"), "fixed_versions": []})
    for m in matches:
        if not isinstance(m, dict):
            continue
        pkg = m.get("package", m)
        name = pkg.get("name") or m.get("name")
        vulns = m.get("vulns") or m.get("vulnerabilities") or ([m] if m.get("id") else [])
        for v in vulns:
            if not isinstance(v, dict):
                continue
            ids = [v.get("id", "")] + (v.get("aliases") or [])
            cves = sorted({i for i in ids if i.startswith("CVE-")})
            if name and cves:
                out.append({"name": name, "vuln_id": v.get("id", ""), "cve_ids": cves,
                            "summary": v.get("summary", ""), "cvss": None,
                            "fixed_versions": v.get("fixed_versions", [])})
    return out


def _squash(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower()).removeprefix("lib")


def _names_align(osv_pkg, installed):
    a, b = _squash(osv_pkg), _squash(installed)
    return len(a) >= 3 and len(b) >= 3 and (a == b or a in b or b in a)


def _v(text):
    from packaging.version import InvalidVersion, Version
    try:
        return Version(str(text).replace("_", ".").replace("-", "."))
    except (InvalidVersion, Exception):
        return None


def _past_fix(installed_version, bounds, installed_name, windows=()):
    """True when the installed version provably sits OUTSIDE every
    published affected range for this CVE on a name-aligned product.
    Sources: NVD CPE version windows (primary) and OSV 'fixed' events.
    Conservative: no aligned data, an unparsable version anywhere, or
    one covering window all keep the finding."""
    inst = _v(installed_version)
    if inst is None:
        return False
    aligned = [w for w in windows if _names_align(w[0], installed_name)]
    if aligned:
        for _prod, start, endx, endi in aligned:
            lo = _v(start) if start else None
            if start and lo is None:
                return False
            if lo is not None and inst < lo:
                continue  # below this window
            if endx:
                hi = _v(endx)
                if hi is None or inst < hi:
                    return False  # inside [lo, endx)
                continue
            if endi:
                hi = _v(endi)
                if hi is None or inst <= hi:
                    return False  # inside [lo, endi]
                continue
            return False  # open-ended window covers it
        return True
    fixed = []
    for pkg, fv in bounds:
        if not _names_align(pkg, installed_name):
            continue
        fv2 = _v(fv)
        if fv2 is not None:
            fixed.append(fv2)
    return bool(fixed) and all(inst >= f for f in fixed)


def scan_apps(items, kev_map):
    """Name-match installed apps against KEV vendor/product. Candidates
    only — the AI layer (or a human) adjudicates whether it's the same
    product. Returns (findings, cleared): a candidate whose installed
    version is provably at/past the CVE's published fix (OSV ranges)
    is not a finding at all — it lands in `cleared` so the scan can
    say so instead of crying wolf on every rescan."""
    kev_products = []
    for cve, entry in kev_map.items():
        prod = _norm(entry.get("product", ""))
        vend = _norm(entry.get("vendorProject", ""))
        if prod:
            kev_products.append((prod.split(), vend.split(), cve, entry))
    findings = []
    matched = []
    for it in items:
        if it["ecosystem"] != "app":
            continue
        n = _norm(it["name"])
        if len(n) < 3:
            continue
        n_tokens = n.split()
        n_set = set(n_tokens)
        for p_tokens, v_tokens, cve, entry in kev_products:
            if not p_tokens:
                continue
            p_set = set(p_tokens)
            # token-sequence containment either way (never raw substring:
            # "rust" in "trust" and "nss" in "openssl" are not matches)
            def _subseq(small, big):
                return any(big[i:i + len(small)] == small
                           for i in range(len(big) - len(small) + 1))
            match = _subseq(p_tokens, n_tokens) or _subseq(n_tokens, p_tokens)
            if match and len(n_tokens) == 1 and len(p_tokens) >= 2:
                # lone generic word ("node") must be the product's first or
                # last token — not a middle word ("Network Node Manager")
                if n_tokens[0] not in (p_tokens[0], p_tokens[-1]):
                    match = False
            if not match and len(n_tokens) == 1 and len(n) >= 6 and n in p_set:
                match = True
            if not match and p_set <= n_set and len(p_tokens) >= 2:
                match = True
            if match and len(p_tokens) == 1:
                # one-word products ("Runtime", "CLI", "Git") match only the
                # exact app name, or a name that also carries the vendor token
                if n_tokens != p_tokens and not (set(v_tokens) & n_set):
                    match = False
            if match and p_tokens == v_tokens and n_tokens != p_tokens:
                # product adds nothing beyond the vendor ("Microsoft") —
                # exact name equality only
                match = False
            if match:
                matched.append((it, cve, entry))
                break
    cleared = []
    if matched:
        details, winmap = {}, {}
        uniq = sorted({cve for _, cve, _ in matched})
        try:
            details = feeds.osv_details_parallel(uniq)
        except Exception:
            details = {}
        try:
            winmap = feeds.nvd_windows_parallel(uniq)
        except Exception:
            winmap = {}
        for it, cve, entry in matched:
            bounds = feeds.cve_fixed_bounds(details.get(cve))
            if _past_fix(it["version"], bounds, it["name"],
                         winmap.get(cve) or ()):
                cleared.append({"name": it["name"], "version": it["version"],
                                "cve": cve})
                continue
            findings.append({
                "target": it["target"], "name": it["name"], "version": it["version"],
                "ecosystem": "app", "manager": it["manager"], "vuln_id": cve,
                "cve_ids": [cve],
                "summary": entry.get("vulnerabilityName", ""),
                "cvss": None, "known_exploited": True, "kev": entry,
                "winget_id": it.get("winget_id"),
                "winget_available": it.get("winget_available"),
                "fixed_versions": [], "sources": ["kev"],
                "confidence": "name-match candidate (KEV product)"})
    return findings, cleared


def rank(findings):
    def key(f):
        cvss = 0.0
        raw = f.get("cvss")
        if isinstance(raw, (int, float)):
            cvss = float(raw)
        elif raw:
            try:
                cvss = float(str(raw).split()[0])
            except Exception:
                cvss = 0.0
        return (0 if f["known_exploited"] else 1, -cvss, f["name"])
    return sorted(findings, key=key)
