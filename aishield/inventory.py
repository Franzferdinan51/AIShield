"""Inventory collectors. Every collector returns uniform records:
{name, version, ecosystem, manager, target}
ecosystem = OSV ecosystem string (PyPI, npm, crates.io, Go, ...) or "app"
for installed applications that need name-based watching (KEV product match).
"""
import base64
import json
import os
import platform
import subprocess

SSH = {"mac": ["~/bin/mac-ssh"], "batman": ["~/bin/batman-ssh"], "grievous": ["~/bin/grievous-ssh"]}


def this_host():
    """Which fleet target THIS machine is, when the shield runs on one of
    them: the Mac runs macOS, the sandbox VM runs Linux. A target that is
    this host must be collected locally — the ssh wrappers point AWAY
    from here and don't exist on the host itself."""
    system = platform.system()
    if system == "Darwin":
        return "mac"
    if system == "Linux":
        return "vm"
    return None


def _run(cmd, timeout=180):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                       text=True, timeout=timeout)
    return p.stdout, p.stderr, p.returncode


def _remote(target, command, timeout=300):
    """Run a collector script on a target. Self-targets run locally;
    remote targets go through the fleet ssh wrappers (script passed as
    ONE argv element, real newlines preserved through ssh)."""
    if target == this_host():
        out, err, rc = _run(command, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"{target} collector failed: {(err or '').strip()[:300]}")
        return out
    wrapper = os.path.expanduser(SSH[target][0])
    if not os.path.exists(wrapper):
        raise RuntimeError(
            f"collecting '{target}' needs {SSH[target][0]}, which doesn't exist "
            f"on this machine ({platform.system()}) — run aishield from the VM "
            "or the Mac, where the fleet wrappers live")
    p = subprocess.run([wrapper, command], capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"{target} collector failed: {(p.stderr or '').strip()[:300]}")
    return p.stdout


# ------------------------------------------------------------------ local linux
def inv_linux_local(target="vm"):
    items = []
    out, _, _ = _run("dpkg-query -W -f='${Package} ${Version} ${Source}\\n' 2>/dev/null")
    seen_src = set()
    for line in out.splitlines():
        parts = line.split(" ")
        if len(parts) >= 2:
            binary, full_version = parts[0], parts[1]
            source = parts[2] if len(parts) >= 3 and parts[2] else binary
            key = (source, full_version)
            if key in seen_src:
                continue
            seen_src.add(key)
            # OSV's Ubuntu index is keyed by SOURCE package + FULL distro version
            items.append({"name": source, "version": full_version,
                          "install_name": binary, "ecosystem": "Ubuntu",
                          "manager": "apt", "target": target})
    out, _, _ = _run("python3 -m pip list --format=json 2>/dev/null")
    try:
        for p in json.loads(out or "[]"):
            items.append({"name": p["name"], "version": p["version"],
                          "ecosystem": "PyPI", "manager": "pip", "target": target})
    except json.JSONDecodeError:
        pass
    out, _, _ = _run("npm ls -g --depth=0 --json 2>/dev/null")
    try:
        for name, info in (json.loads(out or "{}").get("dependencies") or {}).items():
            items.append({"name": name, "version": info.get("version", ""),
                          "ecosystem": "npm", "manager": "npm", "target": target})
    except json.JSONDecodeError:
        pass
    out, _, _ = _run("node --version 2>/dev/null")
    if out.strip():
        items.append({"name": "node", "version": out.strip().lstrip("v"),
                      "ecosystem": "app", "manager": "binary", "target": target})
    return items


# ------------------------------------------------------------------ macOS (remote)
MAC_COLLECT = r'''
export PATH=/opt/homebrew/bin:$PATH
echo "===BREW==="
brew list --versions 2>/dev/null
echo "===PIP==="
python3 -m pip list --format=json 2>/dev/null
echo "===NPM==="
npm ls -g --depth=0 --json 2>/dev/null
echo "===APPS==="
for a in /Applications/*.app; do
  n=$(basename "$a" .app)
  v=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$a/Contents/Info.plist" 2>/dev/null)
  [ -n "$v" ] && echo "$n|$v"
done
echo "===END==="
'''


def inv_mac(target="mac"):
    raw = _remote(target, MAC_COLLECT)
    items, section = [], None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("==="):
            section = line.strip("=")
            continue
        if not line:
            continue
        if section == "BREW":
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                items.append({"name": parts[0], "version": parts[1],
                              "ecosystem": "app", "manager": "brew", "target": target})
        elif section == "PIP":
            try:
                for p in json.loads(line):
                    items.append({"name": p["name"], "version": p["version"],
                                  "ecosystem": "PyPI", "manager": "pip", "target": target})
            except json.JSONDecodeError:
                pass
        elif section == "NPM":
            try:
                for name, info in (json.loads(line).get("dependencies") or {}).items():
                    items.append({"name": name, "version": info.get("version", ""),
                                  "ecosystem": "npm", "manager": "npm", "target": target})
            except json.JSONDecodeError:
                pass
        elif section == "APPS":
            if "|" in line:
                n, v = line.rsplit("|", 1)
                items.append({"name": n, "version": v, "ecosystem": "app",
                              "manager": "macapp", "target": target})
    return items


# ------------------------------------------------------------------ windows (remote)
WIN_COLLECT = r'''
$apps = @()
foreach ($root in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
  $apps += Get-ItemProperty $root -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    ForEach-Object { [PSCustomObject]@{ name = $_.DisplayName; version = "$($_.DisplayVersion)" } }
}
$apps | ConvertTo-Json -Compress
'''


_JUNK_TOKENS = {"x64", "x86", "arm64", "win64", "win32", "edition", "bit",
                "64bit", "32bit"}


def _clean_win_name(name):
    """Registry DisplayNames append versions/editions ("7-Zip 26.04 (x64
    edition)") — strip version-ish tokens so product matching sees the name."""
    import re
    toks = re.sub(r"[^a-z0-9.+-]+", " ", name.lower()).split()
    kept = [t for t in toks
            if not re.fullmatch(r"\d+(\.\d+)*", t) and t not in _JUNK_TOKENS]
    return " ".join(kept) if kept else name


def inv_windows(target):
    enc = base64.b64encode(WIN_COLLECT.encode("utf-16-le")).decode()
    raw = _remote(target, f"powershell -NoProfile -EncodedCommand {enc}")
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("[") or line.startswith("{"):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    data = [data]
                for a in data:
                    if a.get("name"):
                        items.append({"name": _clean_win_name(a["name"]),
                                      "raw_name": a["name"],
                                      "version": a.get("version", ""),
                                      "ecosystem": "app", "manager": "winapp",
                                      "target": target})
            except json.JSONDecodeError:
                pass
    return items


COLLECTORS = {"vm": inv_linux_local, "mac": inv_mac,
              "batman": inv_windows, "grievous": inv_windows}
TARGETS = ["vm", "mac", "batman", "grievous"]


def collect(target):
    return COLLECTORS[target](target)
