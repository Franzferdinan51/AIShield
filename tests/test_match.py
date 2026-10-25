"""Matching-engine tests: every KEV product match is reported (a
cleared first match must not hide an affecting later one), and feed
outages degrade to warnings instead of killing the scan.
Run: python3 tests/test_match.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aishield import feeds, match


def _kev(cve, product="Sample Product"):
    return {cve: {"product": product, "vendorProject": "Sample",
                  "vulnerabilityName": "test vuln " + cve}}


def _app(name="Sample Product", version="1.0"):
    return {"target": "local", "name": name, "version": version,
            "ecosystem": "app", "manager": "macapp", "python": None,
            "winget_id": None, "winget_available": None,
            "install_name": None}


def _pkg(name="brotli", version="1.1.0"):
    return {"target": "local", "name": name, "version": version,
            "ecosystem": "PyPI", "manager": "pip", "python": None,
            "winget_id": None, "winget_available": None,
            "install_name": None}


def test_apps_report_every_kev_match():
    kev_map = dict(_kev("CVE-2026-0001"))
    kev_map.update(_kev("CVE-2026-0002"))
    old_det, old_win = feeds.osv_details_parallel, feeds.nvd_windows_parallel
    feeds.osv_details_parallel = lambda ids: {}
    feeds.nvd_windows_parallel = lambda ids: {}
    try:
        findings, cleared = match.scan_apps([_app()], kev_map)
    finally:
        feeds.osv_details_parallel, feeds.nvd_windows_parallel = \
            old_det, old_win
    cves = sorted(f["vuln_id"] for f in findings)
    assert cves == ["CVE-2026-0001", "CVE-2026-0002"], (cves, cleared)


def test_osv_outage_warns_instead_of_killing_scan():
    def boom(pkgs):
        raise ConnectionError("HTTPSConnectionPool: Max retries exceeded "
                              "(Failed to establish a connection)")
    old = feeds.osv_query_batch
    feeds.osv_query_batch = boom
    try:
        findings = match.scan_packages([_pkg()], {}, use_cvenow=False)
    finally:
        feeds.osv_query_batch = old
    assert len(findings) == 1, findings
    assert findings[0]["confidence"] == "error"
    assert "OSV unreachable" in findings[0]["summary"], findings[0]


def test_cvenow_outage_warns_instead_of_killing_scan():
    old_batch, old_stack = feeds.osv_query_batch, match.cvenow.check_stack
    feeds.osv_query_batch = lambda pkgs: [{} for _ in pkgs]
    match.cvenow.check_stack = lambda pkgs, timeout=120: (_ for _ in ()).throw(
        ConnectionError("HTTPSConnectionPool: Max retries exceeded "
                        "(Failed to establish a connection)"))
    try:
        findings = match.scan_packages([_pkg()], {})
    finally:
        feeds.osv_query_batch, match.cvenow.check_stack = \
            old_batch, old_stack
    assert len(findings) == 1, findings
    assert findings[0]["confidence"] == "error"
    assert "CVE Now unreachable" in findings[0]["summary"], findings[0]


def test_short_fragments_do_not_align():
    assert match._names_align("cli", "cliclick") is False
    assert match._names_align("aom", "aomei") is False
    assert match._names_align("npm", "npm") is True  # exact still matches
    assert match._names_align("brotli", "PyPI Brotli") is True
    assert match._names_align("Node.js", "node") is True


def test_incident_names_drop_generic_fragments():
    inc = {"product": "@subql/common (npm) and downstream @subql/* packages",
           "affectedVersions": ["@subql/common 5.8.3",
                                "e.g. @subql/cli 6.6.3, @subql/query 2.25.0",
                                "Downstream ranges that resolve to 5.8.3"],
           "fixedVersions": ["@subql/common 5.8.2 (npm 'latest')"]}
    names = match._pwn_incident_names(inc)
    low = [n.lower() for n in names]
    assert "cli" not in low and "query" not in low and "to" not in low
    inc2 = {"product": "OVHcloud CLI (GitHub releases)",
            "affectedVersions": ["v0.11.0 to v0.15.0",
                                 "run the installer 2.0"],
            "fixedVersions": []}
    low2 = [n.lower() for n in match._pwn_incident_names(inc2)]
    assert "installer" not in low2, low2
    assert "ovhcloud cli" in low2  # the real product stays
    assert not any(len(n.split()) > 4 for n in names), names
    assert "@subql/cli" in names  # full identifiers still match exactly
    assert "@subql/common" in names


def main():
    test_apps_report_every_kev_match()
    test_osv_outage_warns_instead_of_killing_scan()
    test_cvenow_outage_warns_instead_of_killing_scan()
    test_short_fragments_do_not_align()
    test_incident_names_drop_generic_fragments()
    print("test_match: ALL PASS")


if __name__ == "__main__":
    main()
