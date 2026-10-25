"""pwn.watch tests: candidates are name-matches only, clearance is
major-line-aware and provable-only, breach category never scans, and
proven findings get the overlay instead of a duplicate candidate.
Run: python3 tests/test_pwnwatch.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aishield import match

NODE_INCIDENT = {
    "slug": "nodejs-test-incident", "product": "Node.js",
    "category": "patch", "status": "live", "patchStatus": "patched",
    "severity": "critical", "title": "Node.js test security release",
    "cveIds": ["CVE-2026-000001", "CVE-2026-000002"],
    "affectedVersions": ["22.x before 22.23.4, 24.x before 24.22.1, "
                         "26.x before 26.12.1",
                         "PyPI Brotli 1.0.3 to 1.2.0"],
    "fixedVersions": ["22.23.4", "24.22.1", "26.12.1", "PyPI Brotli 1.2.1"],
    "url": "https://pwn.watch/i/nodejs-test-incident",
}
BREACH = dict(NODE_INCIDENT, slug="some-breach", category="breach",
              product="Node.js")


def item(name, version, target="local", ecosystem="app", manager="brew"):
    return {"target": target, "name": name, "version": version,
            "ecosystem": ecosystem, "manager": manager, "python": None,
            "winget_id": None, "winget_available": None,
            "install_name": None}


def main():
    inc = [NODE_INCIDENT, BREACH]

    # At the published fix for its line -> cleared, no candidate.
    f, c = match.scan_pwnwatch([item("Node.js", "26.12.1")], inc)
    assert f == [] and len(c) == 1 and "26.12.1" in c[0]["reason"], (f, c)
    f, c = match.scan_pwnwatch([item("node", "24.22.1")], inc)
    assert f == [] and len(c) == 1, (f, c)

    # Below the fix on its line -> candidate (NOT cleared by a higher
    # major line's fix: 24.22.0 must not be cleared by 26.12.1).
    f, c = match.scan_pwnwatch([item("Node.js", "24.22.0")], inc)
    assert len(f) == 1 and c == [], (f, c)
    assert f[0]["sources"] == ["pwn.watch"] and f[0]["live_incident"]
    assert f[0]["confidence"].startswith("name-match")

    # Prefixed co-products in the same incident align independently:
    # Brotli 1.1.0 is below the PyPI Brotli fix -> candidate; 1.2.1 clears.
    f, c = match.scan_pwnwatch(
        [item("brotli", "1.1.0", ecosystem="PyPI", manager="pip")], inc)
    assert len(f) == 1 and c == [], (f, c)
    f, c = match.scan_pwnwatch(
        [item("brotli", "1.2.1", ecosystem="PyPI", manager="pip")], inc)
    assert f == [] and len(c) == 1, (f, c)

    # Unrelated product -> nothing. Breach category alone -> nothing.
    f, c = match.scan_pwnwatch([item("Firefox", "140.0")], inc)
    assert f == [] and c == []
    f, c = match.scan_pwnwatch([item("Node.js", "24.22.0")], [BREACH])
    assert f == [] and c == []

    # Proven finding for an incident CVE: overlay stamps it, and the
    # candidate pass skips the duplicate.
    proven = [{"target": "local", "name": "Node.js", "version": "24.22.0",
               "ecosystem": "app", "manager": "brew",
               "cve_ids": ["CVE-2026-000001"], "sources": ["osv"]}]
    match.pwnwatch_overlay(proven, inc)
    assert proven[0]["sources"] == ["osv", "pwn.watch"], proven
    assert proven[0]["pwnwatch"]["slug"] == "nodejs-test-incident"
    f, c = match.scan_pwnwatch([item("Node.js", "24.22.0")], inc, proven)
    assert f == [] and c == [], (f, c)

    print("test_pwnwatch: ALL PASS")


if __name__ == "__main__":
    main()
