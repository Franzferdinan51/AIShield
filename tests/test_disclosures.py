"""Disclosure-feed tests: version-exact matching only, unproven != safe,
and the patch planner must never offer an upgrade for an unpatched
advisory. Run: python3 tests/test_disclosures.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aishield import disclosures, match, patch


def item(name, version, target="local"):
    return {"target": target, "name": name, "version": version,
            "ecosystem": "app", "manager": "macapp", "python": None,
            "winget_id": None, "winget_available": None,
            "install_name": None}


def main():
    advs, meta = disclosures.advisories()
    assert len(advs) == 11, len(advs)
    assert meta["feeds"][0]["name"] == "tailworm"

    # Mac case: Tailscale at the exact tested version -> 10 findings
    # (TAILWORM-6 is headscale-only).
    f, c = match.scan_disclosures([item("Tailscale", "1.104.2")], advs)
    assert len(f) == 10, [x["vuln_id"] for x in f]
    assert all(x["sources"] == ["disclosure:tailworm"] for x in f)
    assert all(x["fixed_versions"] == [] and not x["known_exploited"] for x in f)
    assert {x["vuln_id"] for x in f} == {"TAILWORM-%d" % i for i in
                                         (1, 2, 3, 4, 5, 7, 8, 9, 10, 11)}
    assert not c

    # Windows case: 1.102.4 was NOT tested -> no findings, one
    # 'unproven' cleared note (never 'safe').
    f, c = match.scan_disclosures([item("Tailscale", "1.102.4")], advs)
    assert f == [] and len(c) == 1 and "unproven" in c[0]["reason"], c

    # headscale at the tested version -> exactly its one finding.
    f, c = match.scan_disclosures([item("headscale", "0.29.5")], advs)
    assert [x["vuln_id"] for x in f] == ["TAILWORM-6"], f

    # Long-form version strings still core-match; unrelated apps ignored.
    f, _ = match.scan_disclosures(
        [item("Tailscale", "1.104.2-tc3430f0d2-g598b63867"),
         item("Firefox", "1.104.2")], advs)
    assert len(f) == 10, len(f)

    # The planner must refuse to 'patch' a disclosure finding even when
    # the manager would normally auto-upgrade (brew).
    brew_finding = dict(f[0], manager="brew")
    plan = patch.plan_for(brew_finding)
    assert plan["auto"] is False and plan["command"] is None, plan
    assert "no vendor fix" in plan["note"], plan

    print("test_disclosures: ALL PASS")


if __name__ == "__main__":
    main()
