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
    rejected = []
    for it in items:
        if it["ecosystem"] != "app":
            continue
        n = _norm(it["name"])
        if len(n) < 3:
            continue
        n_tokens = n.split()
        n_set = set(n_tokens)
        near = []
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
                elif n_tokens[0] == p_tokens[0] and n_tokens[0] != p_tokens[-1]:
                    # A lone word matching only the product's FIRST token
                    # is usually the modifier, not the product: "ruby"
                    # in "Ruby on Rails" is the language — the product
                    # is Rails. It stands only with vendor corroboration
                    # (the vendor shares the token: "docker" the app vs
                    # Docker Desktop, vendor Docker). Otherwise it's a
                    # different product that shares a word — record it
                    # as cleared so the scan can say why it's silent.
                    if n_tokens[0] not in set(v_tokens):
                        match = False
                        near.append({
                            "name": it["name"], "version": it["version"],
                            "cve": cve,
                            "reason": "different product — '%s' is only "
                                      "the modifier in '%s' (vendor: %s)"
                                      % (n, entry.get("product", ""),
                                         entry.get("vendorProject", ""))})
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
        rejected.extend(near)
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
    return findings, cleared + rejected


def _pwn_product_names(product):
    """Name variants for a pwn.watch product string: the head segment
    ('Postiz' from 'Postiz (gitroomhq/postiz-app), self-hosted') plus
    the parenthetical path basename ('postiz-app')."""
    head = re.split(r"[,(]", product or "")[0].strip()
    names = [head] if head else []
    m = re.search(r"\(([^)]+)\)", product or "")
    if m:
        base = m.group(1).strip().rstrip("/").split("/")[-1]
        if base and base.lower() not in (h.lower() for h in names):
            names.append(base)
    return names


def _pwn_fixed_pairs(incident):
    """(prefix, version) pairs parsed from an incident's fixedVersions
    strings: 'PyPI Brotli 1.2.1' -> ('PyPI Brotli', '1.2.1'), a bare
    '24.22.1' -> (incident product, '24.22.1'), and continuation segments
    of a slash list inherit the first segment's prefix ('Envoy 1.40.0 /
    1.39.3'). Used ONLY for the conservative at/past-fix clearance —
    never to assert that a machine is affected."""
    pairs = []
    product = _pwn_product_names(incident.get("product", ""))
    for s in incident.get("fixedVersions") or []:
        segs = [x.strip() for x in re.split(r"[,/]", str(s)) if x.strip()]
        first_prefix = None
        for seg in segs:
            m = re.search(r"(\d+(?:\.\d+)+)\s*$", seg)
            if not m:
                continue
            prefix = seg[:m.start()].strip()
            if first_prefix is None:
                first_prefix = prefix
            if not prefix:
                prefix = first_prefix or (product[0] if product else "")
            pairs.append((prefix, m.group(1)))
    return pairs


def _pwn_at_fix(item, incident):
    """The fixed version (same major line) the installed version is
    provably at/past, per pwn.watch's published fixedVersions — or None."""
    core = _version_core(item["version"])
    inst = _v(core)
    if inst is None:
        return None
    best = None
    for prefix, fv in _pwn_fixed_pairs(incident):
        if prefix and not _names_align(prefix, item["name"]):
            continue
        fvv = _v(fv)
        if fvv is not None and fvv.major == inst.major and inst >= fvv:
            if best is None or fvv > _v(best):
                best = fv
    return best


def _pwn_incident_names(incident):
    """All name variants an incident can match against: its product
    string, plus the product prefixes inside its affected/fixed strings
    (incidents bundle co-products — the Node.js incident also covers
    Bun and PyPI Brotli). Each prefix contributes itself, its last word,
    and its path basename."""
    names = list(_pwn_product_names(incident.get("product", "")))

    def add(text):
        text = (text or "").strip()
        if not text:
            return
        cands = [text, text.split()[-1]]
        if "/" in text:
            cands.append(text.rstrip("/").split("/")[-1])
        for c in cands:
            if c and c.lower() not in (n.lower() for n in names):
                names.append(c)

    for prefix, _fv in _pwn_fixed_pairs(incident):
        add(prefix)
    for s in incident.get("affectedVersions") or []:
        for seg in str(s).split(","):
            m = re.match(r"\s*([^0-9<>]+?)(?=\s*(?:>=|<=|<|>|=|\d)|\s*$)", seg)
            if m:
                add(m.group(1))
    return names


def scan_pwnwatch(items, incidents, existing=()):
    """pwn.watch candidates: name-aligned incidents (patch + supply-chain
    categories) against installed items. CANDIDATES, not verdicts — the
    feed's affected-version data is prose, so an item is only ever
    CLEARED deterministically (provably at/past the published fix, same
    major line) or reported as a name-match candidate carrying the
    incident's own affected/fixed text for a human or the brief.
    Items already carrying a proven finding for one of the incident's
    CVEs are skipped — pwnwatch_overlay stamps those instead."""
    proven = {}
    for f in existing:
        for c in f.get("cve_ids") or []:
            proven.setdefault((f["target"], _norm(f["name"])), set()).add(c)
    import time as _time
    cutoff = _time.strftime("%Y-%m-%d",
                            _time.gmtime(_time.time() - 120 * 86400))
    findings, cleared = [], []
    for it in items:
        for inc in incidents:
            if inc.get("category") not in ("patch", "supply-chain"):
                continue
            if inc.get("status") == "closed" and inc.get("patchStatus") == "patched":
                # Long-closed, fully patched incidents whose prose ranges
                # can't prove clearance are candidate noise (a 2023
                # libwebp incident vs every Chrome install, forever).
                # Live, unpatched, partial, and recent incidents still
                # surface; the overlay stamps proven findings at any age.
                when = str(inc.get("closedAt") or inc.get("startedAt") or "")
                if when and when[:10] < cutoff:
                    continue
            names = _pwn_incident_names(inc)
            if not any(_names_align(n, it["name"]) for n in names):
                continue
            cves = [c for c in inc.get("cveIds") or [] if c.startswith("CVE-")]
            if proven.get((it["target"], _norm(it["name"])), set()) & set(cves):
                continue
            fixed_at = _pwn_at_fix(it, inc)
            if fixed_at:
                cleared.append({
                    "name": it["name"], "version": it["version"],
                    "cve": ", ".join(cves) or inc.get("slug", ""),
                    "reason": "at/past the pwn.watch fixed version %s "
                              "(incident %s)" % (fixed_at, inc.get("slug"))})
                continue
            affected = "; ".join(inc.get("affectedVersions") or [])[:300]
            fixed = "; ".join(inc.get("fixedVersions") or [])[:200]
            findings.append({
                "target": it["target"], "name": it["name"],
                "version": it["version"], "ecosystem": it["ecosystem"],
                "manager": it["manager"], "vuln_id": inc.get("slug", ""),
                "cve_ids": cves,
                "python": it.get("python"),
                "winget_id": it.get("winget_id"),
                "winget_available": it.get("winget_available"),
                "install_name": it.get("install_name"),
                "summary": "%s | pwn.watch affected: %s | fixed: %s"
                           % (inc.get("title", ""), affected, fixed),
                "cvss": None, "severity_label": inc.get("severity"),
                "known_exploited": False, "kev": None,
                "live_incident": inc.get("status") == "live",
                "patch_status": inc.get("patchStatus"),
                "fixed_versions": [], "sources": ["pwn.watch"],
                "confidence": "name-match candidate (pwn.watch incident)"})
    return findings, cleared


def pwnwatch_overlay(findings, incidents):
    """Corroboration stamp: a proven finding whose CVE appears in a
    pwn.watch incident gains the source + the incident's live/patch
    status, so the report shows when a finding is a live incident."""
    by_cve = {}
    for inc in incidents:
        for c in inc.get("cveIds") or []:
            by_cve.setdefault(c, []).append(inc)
    for f in findings:
        hits = [inc for c in f.get("cve_ids") or []
                for inc in by_cve.get(c, [])]
        if not hits:
            continue
        pick = next((i for i in hits if i.get("status") == "live"), hits[0])
        if "pwn.watch" not in f["sources"]:
            f["sources"].append("pwn.watch")
        f["pwnwatch"] = {"slug": pick.get("slug"),
                         "status": pick.get("status"),
                         "patch_status": pick.get("patchStatus"),
                         "url": pick.get("url")}


def _version_core(text):
    """Leading dotted-numeric core of a version string ('1.104.2-tabc'
    -> '1.104.2'), or '' when the string doesn't start with a version."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", str(text or "").strip())
    return m.group(1) if m else ""


def scan_disclosures(items, advisories):
    """Match installed apps against curated disclosure advisories
    (aishield/disclosures.py — vulnerabilities published with no CVE and
    no fix). Deterministic and conservative: a finding fires ONLY when
    the installed version is one the source actually tested. A product
    installed at any other version lands in `cleared` with the reason
    stated plainly — unproven, NOT declared safe."""
    by_product = {}
    for adv in advisories:
        by_product.setdefault(adv["product"], []).append(adv)
    findings, cleared = [], []
    for it in items:
        tokens = _norm(it["name"]).split()
        product = next((p for p in by_product if p in tokens), None)
        if not product:
            continue
        core = _version_core(it["version"])
        advs = by_product[product]
        tested = sorted({v for a in advs for v in a["versions"]})
        if core not in tested:
            cleared.append({
                "name": it["name"], "version": it["version"],
                "cve": ", ".join(sorted({a["id"] for a in advs})),
                "reason": "installed version %s is not a version the %s "
                          "disclosure tested (%s) — status unproven, "
                          "not cleared as safe"
                          % (it["version"] or "?", advs[0]["feed"],
                             ", ".join(tested))})
            continue
        for a in advs:
            if core not in a["versions"]:
                continue
            findings.append({
                "target": it["target"], "name": it["name"],
                "version": it["version"], "ecosystem": it["ecosystem"],
                "manager": it["manager"], "vuln_id": a["id"], "cve_ids": [],
                "python": it.get("python"),
                "winget_id": it.get("winget_id"),
                "winget_available": it.get("winget_available"),
                "install_name": it.get("install_name"),
                "summary": "%s — precondition: %s. Mitigation: %s "
                           "(source: %s, curated %s)"
                           % (a["title"], a["precondition"],
                              a["mitigation"], a["url"], a["curated"]),
                "cvss": None, "severity_label": a["severity"],
                "known_exploited": False, "kev": None,
                "fixed_versions": [],
                "sources": ["disclosure:" + a["feed"]],
                "confidence": "disclosure match (version-exact, unpatched)"})
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
