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

from . import transport


def _run(cmd, timeout=180):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                       text=True, timeout=timeout)
    return p.stdout, p.stderr, p.returncode


def _remote(target, command, timeout=300):
    """Run a collector script on a target through the program's own
    transport (local for self-targets, its built-in ssh otherwise)."""
    out, err, rc = transport.run(target, command, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"{target} collector failed: {(err or '').strip()[:300]}")
    return out


def parse_brew_line(line):
    """`brew list --versions` prints every installed version per line
    ('brotli 1.2.0 1.2.1', oldest first) — the name is the FIRST token
    and the installed version the LAST. Splitting off only the last
    token corrupts the name with stale versions."""
    parts = line.split()
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return None


def _parse_npm_json(text, items, target):
    """`npm ls --json` is pretty-printed multi-line JSON (unlike pip's
    single line), so the NPM section is buffered whole and parsed
    once — parsing it line-by-line silently yields zero packages."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return
    if not isinstance(doc, dict):
        return
    for name, info in (doc.get("dependencies") or {}).items():
        if isinstance(info, dict):
            items.append({"name": name,
                          "version": info.get("version") or "",
                          "ecosystem": "npm", "manager": "npm",
                          "target": target})


# ------------------------------------------------------------------ linux
LINUX_COLLECT = r'''
echo "===DPKG==="
dpkg-query -W -f='${Package} ${Version} ${Source}\n' 2>/dev/null
echo "===PYEXE==="
python3 -c 'import sys; print(sys.executable)' 2>/dev/null
echo "===PIP==="
python3 -m pip list --format=json 2>/dev/null
echo "===NPM==="
npm ls -g --depth=0 --json 2>/dev/null
echo "===NODE==="
node --version 2>/dev/null
echo "===END==="
'''


def inv_linux(target):
    raw = _remote(target, LINUX_COLLECT)
    items, section = [], None
    pyexe = None
    npm_buf = []
    seen_src = set()
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("==="):
            section = line.strip("=")
            continue
        if not line:
            continue
        if section == "PYEXE":
            pyexe = line
        elif section == "DPKG":
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
        elif section == "PIP":
            try:
                for p in json.loads(line):
                    items.append({"name": p["name"], "version": p["version"],
                                  "ecosystem": "PyPI", "manager": "pip",
                                  "target": target, "python": pyexe})
            except json.JSONDecodeError:
                pass
        elif section == "NPM":
            npm_buf.append(line)
        elif section == "NODE":
            items.append({"name": "node", "version": line.lstrip("v"),
                          "ecosystem": "app", "manager": "binary",
                          "target": target})
    _parse_npm_json("\n".join(npm_buf), items, target)
    return items


# ------------------------------------------------------------------ macOS (remote)
MAC_COLLECT = r'''
export PATH=/opt/homebrew/bin:$PATH
echo "===PYEXE==="
python3 -c 'import sys; print(sys.executable)' 2>/dev/null
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
    pyexe = None
    npm_buf = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("==="):
            section = line.strip("=")
            continue
        if not line:
            continue
        if section == "PYEXE":
            # The interpreter the collector's pip belongs to. Patch steps
            # MUST use this exact interpreter — the caller's shell python
            # can be a different environment entirely (learned the hard
            # way: caller's login python was an agent venv with pins).
            pyexe = line
        elif section == "BREW":
            parsed = parse_brew_line(line)
            if parsed:
                items.append({"name": parsed[0], "version": parsed[1],
                              "ecosystem": "app", "manager": "brew",
                              "target": target})
        elif section == "PIP":
            try:
                for p in json.loads(line):
                    items.append({"name": p["name"], "version": p["version"],
                                  "ecosystem": "PyPI", "manager": "pip",
                                  "target": target, "python": pyexe})
            except json.JSONDecodeError:
                pass
        elif section == "NPM":
            npm_buf.append(line)
        elif section == "APPS":
            if "|" in line:
                n, v = line.rsplit("|", 1)
                items.append({"name": n, "version": v, "ecosystem": "app",
                              "manager": "macapp", "target": target})
    _parse_npm_json("\n".join(npm_buf), items, target)
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
"WINGETLIST"
try { winget list --accept-source-agreements --disable-interactivity 2>$null } catch {}
"WINGETUP"
try { winget upgrade --accept-source-agreements --disable-interactivity 2>$null } catch {}
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


def _parse_winget_table(lines):
    """winget's fixed-width tables: column starts come from the header
    row (Name/Id/Version/Available/Source). Returns row dicts."""
    rows = []
    header_at = None
    for i, line in enumerate(lines):
        if line.startswith("Name") and " Id" in line and "Version" in line:
            header_at = i
            break
    if header_at is None:
        return rows
    header = lines[header_at]
    cols = {}
    for col in ("Name", "Id", "Version", "Available", "Source"):
        at = header.find(" " + col) if col != "Name" else 0
        if at >= 0:
            cols[col] = at if col == "Name" else at + 1
    order = sorted(cols.items(), key=lambda kv: kv[1])
    for line in lines[header_at + 1:]:
        if not line.strip() or set(line.strip()) <= set("- "):
            continue
        row = {}
        for j, (col, start) in enumerate(order):
            end = order[j + 1][1] if j + 1 < len(order) else None
            row[col.lower()] = line[start:end].strip() if end else line[start:].strip()
        if row.get("id"):
            rows.append(row)
    return rows


def inv_windows(target):
    enc = base64.b64encode(WIN_COLLECT.encode("utf-16-le")).decode()
    raw = _remote(target, f"powershell -NoProfile -EncodedCommand {enc}",
                  timeout=600)
    items = []
    section = "apps"
    winget_lines, up_lines = [], []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped == "WINGETLIST":
            section = "winget"
            continue
        if stripped == "WINGETUP":
            section = "up"
            continue
        if section == "winget":
            winget_lines.append(line)
            continue
        if section == "up":
            up_lines.append(line)
            continue
        line = stripped
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
    # attach winget identity: registry names and winget names differ
    # in decoration, so match on cleaned names, both directions.
    by_clean = {}
    for row in _parse_winget_table(winget_lines):
        # only real winget packages can be upgraded by id — the list
        # also carries ARP/MSIX pseudo-ids that winget cannot service
        if (row.get("source") or "").lower() != "winget":
            continue
        by_clean[_clean_win_name(row.get("name", ""))] = row
    up_by_id = {r["id"]: r for r in _parse_winget_table(up_lines)}
    for it in items:
        row = by_clean.get(it["name"]) or by_clean.get(
            _clean_win_name(it.get("raw_name", "")))
        if row:
            it["winget_id"] = row["id"]
            up = up_by_id.get(row["id"])
            if up and up.get("available"):
                it["winget_available"] = up["available"]
    return items


COLLECTORS = {"linux": inv_linux, "macos": inv_mac, "windows": inv_windows}


def local_kind():
    return {"Linux": "linux", "Darwin": "macos",
            "Windows": "windows"}.get(platform.system(), "linux")


def target_kind(target):
    """What OS a target runs: 'local' is this machine; any other target
    is a machine the user defined in the hosts config, with its os."""
    if target == "local":
        return local_kind()
    entry = transport.hosts().get(target)
    if entry is None:
        raise RuntimeError(
            f"unknown target '{target}' — targets are 'local' plus the "
            "machines defined in config/hosts.local.yaml (see `aishield hosts`)")
    kind = (entry.get("os") or "").lower()
    if kind not in COLLECTORS:
        raise RuntimeError(
            f"target '{target}' needs an os (linux|macos|windows) in its "
            "hosts config entry")
    return kind


def targets():
    """Enabled scan targets. 'local' (this machine) is enabled unless
    the user unchecked it; remote machines are OPT-IN — an entry only
    counts when its hosts config carries enabled: true. The shield is
    designed to run on each machine itself, not to sweep remotes."""
    out = ["local"] if transport.local_enabled() else []
    out += sorted(name for name, entry in transport.hosts().items()
                  if entry.get("enabled"))
    return out


# Backwards-compatible alias for callers that read a static list.
TARGETS = targets()


def collect(target):
    return COLLECTORS[target_kind(target)](target)
