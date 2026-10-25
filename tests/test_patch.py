"""Patch-planner shell-safety tests: ordinary packages produce
exactly the same commands as before, while names/versions/interpreters
carrying shell metacharacters become manual steps — never commands.
Run: python3 tests/test_patch.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aishield import patch


def _finding(manager, name="brotli", fixed="1.2.1", **kw):
    f = {"target": "local", "name": name, "version": "1.1.0",
         "manager": manager, "confidence": "version-range match",
         "sources": ["osv"], "fixed_versions": [fixed] if fixed else [],
         "python": kw.pop("python", "python3"),
         "install_name": kw.pop("install_name", None),
         "winget_id": kw.pop("winget_id", None),
         "winget_available": kw.pop("winget_available", None)}
    f.update(kw)
    return f


EVIL = ["x; touch /tmp/pwned", "x$(touch /tmp/pwned)", "x`id`",
        "x | tee /tmp/pwned", "a b", "-rf", "x&calc", "x%PATH%",
        "x\necho pwned", "~root/x", "x\\u001b[0m"]


def test_normal_commands_unchanged():
    assert patch.plan_for(_finding("pip"))["command"] == \
        "python3 -m pip install -U 'brotli>=1.2.1'"
    assert patch.plan_for(_finding("brew"))["command"] == \
        "brew upgrade brotli"
    assert patch.plan_for(_finding("npm"))["command"] == \
        "npm install -g brotli@1.2.1"
    assert patch.plan_for(_finding("apt", install_name="libfoo"))[
        "command"] == "sudo apt-get install -y --only-upgrade libfoo"
    w = patch.plan_for(_finding("winapp", winget_id="7zip.7zip",
                                winget_available="26.0"))
    assert w["auto"] and w["command"].startswith(
        "powershell -NoProfile -EncodedCommand ")
    # real-world punctuation still passes the guard
    assert patch.plan_for(
        _finding("npm", name="@scope/tool"))["auto"] is True
    assert patch.plan_for(
        _finding("pip", name="python-dateutil"))["auto"] is True
    assert patch.plan_for(_finding(
        "apt", name="libc6", install_name="libc6"))["auto"] is True


def test_evil_names_never_become_commands():
    for mgr in ("pip", "brew", "npm", "apt"):
        for name in EVIL:
            p = patch.plan_for(_finding(mgr, name=name))
            assert p["auto"] is False and p["command"] is None, (mgr, name, p)


def test_evil_versions_and_paths_never_become_commands():
    for bad in ("1.2.1; touch /tmp/pwned", "1.0 | tee x", "-1"):
        p = patch.plan_for(_finding("pip", fixed=bad))
        assert p["auto"] is False and p["command"] is None, (bad, p)
    for bad in ("/tmp/x; id", "python$(id)", "C:\\tools\\evil & calc"):
        p = patch.plan_for(_finding("pip", python=bad))
        assert p["auto"] is False and p["command"] is None, (bad, p)
    p = patch.plan_for(_finding("apt", install_name="x; id"))
    assert p["auto"] is False and p["command"] is None, p
    p = patch.plan_for(_finding("winapp", winget_id='7zip.7zip"; evil #'))
    assert p["auto"] is False and p["command"] is None, p


def test_brew_owner_refuses_evil_without_executing():
    calls = []
    old = patch._exec
    patch._exec = lambda *a, **k: calls.append(a) or (0, "", "")
    try:
        assert patch.brew_owner("local", "x; id") is None
        assert patch.brew_owner("local", "brotli",
                                python="/tmp/x; id") is None
    finally:
        patch._exec = old
    assert calls == [], calls


def test_approved_command_refuses_evil():
    s = {"manager": "brew", "name": "x; id", "target": "local"}
    assert patch._approved_command(s) is None
    s = {"manager": "winapp", "name": "x", "target": "local",
         "winget_id": "a; b"}
    assert patch._approved_command(s) is None


def test_approved_command_rebuilds_routes():
    # an approved pip candidate gains the real route (with the
    # inventoried interpreter); brew/npm/apt/winapp too
    s = {"manager": "pip", "name": "brotli", "target": "local",
         "python": "/usr/local/bin/python3",
         "fixed_versions": ["1.2.1"], "sources": ["osv"]}
    assert patch._approved_command(s) == \
        "/usr/local/bin/python3 -m pip install -U 'brotli>=1.2.1'"
    s = {"manager": "brew", "name": "brotli", "target": "local",
         "sources": ["osv"]}
    assert patch._approved_command(s) == "brew upgrade brotli"
    s = {"manager": "apt", "name": "libc6", "target": "local",
         "install_name": "libc6", "sources": ["osv"]}
    assert patch._approved_command(s) == \
        "sudo apt-get install -y --only-upgrade libc6"
    # disclosures never gain an upgrade offer, even approved
    s = {"manager": "macapp", "name": "Tailscale", "target": "local",
         "sources": ["disclosure:tailworm"]}
    assert patch._approved_command(s) is None
    s = {"manager": "pip", "name": "x", "target": "local",
         "sources": ["disclosure:tailworm"]}
    assert patch._approved_command(s) is None


def main():
    test_normal_commands_unchanged()
    test_evil_names_never_become_commands()
    test_evil_versions_and_paths_never_become_commands()
    test_brew_owner_refuses_evil_without_executing()
    test_approved_command_refuses_evil()
    test_approved_command_rebuilds_routes()
    print("test_patch: ALL PASS")


if __name__ == "__main__":
    main()
