"""Built-in fleet transport — the program reaches its targets itself.

No wrapper scripts, no companion programs: remote targets are reached
with the operating system's own ssh, driven by the program's host
config (config/hosts.yaml, overridden by the untracked
config/hosts.local.yaml and AISHIELD_HOST_<TARGET> env vars).

A host entry: {host, user, port, identity, proxy}
  proxy: "none" (default) or "env" — build an HTTP CONNECT ProxyCommand
  from the HTTPS_PROXY environment variable (for sandboxed runners
  whose only egress is a proxy). Machines on a normal network use none.
Self-targets (this machine) run locally with no ssh at all.
"""
import os
import subprocess
from urllib.parse import urlparse

import yaml

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENTRY_DEFAULTS = {"port": 22, "identity": "~/.ssh/id_ed25519",
                  "proxy": "none"}


def _load_file(name):
    path = os.path.join(BASE, "config", name)
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def hosts():
    """User-defined machines from config/hosts.yaml + hosts.local.yaml.
    The program ships with NO built-in targets: an entry counts only
    when it names a host and a user (the committed template's empty
    example sections don't)."""
    cfg = {}
    for name in ("hosts.yaml", "hosts.local.yaml"):
        for target, entry in (_load_file(name) or {}).items():
            if isinstance(entry, dict):
                merged = dict(ENTRY_DEFAULTS)
                merged.update(cfg.get(target) or {})
                merged.update({k: v for k, v in entry.items()
                               if v is not None})
                cfg[target] = merged
    cfg = {t: e for t, e in cfg.items()
           if t != "local" and e.get("host") and e.get("user")}
    for target in cfg:
        env = os.environ.get("AISHIELD_HOST_" + target.upper())
        if env:  # user@host[:port]
            userhost = env
            if ":" in env.rsplit("@", 1)[-1]:
                userhost, _, port = env.rpartition(":")
                cfg[target]["port"] = int(port)
            if "@" in userhost:
                cfg[target]["user"], cfg[target]["host"] = userhost.split("@", 1)
            else:
                cfg[target]["host"] = userhost
    return cfg


def describe():
    return hosts()


def local_enabled():
    """Whether 'local' (this machine) is a scan target. Stored as a
    reserved 'local' entry in hosts.local.yaml ({enabled: bool});
    default True — running on the machine itself is the recommended
    way to use the shield."""
    for name in ("hosts.local.yaml", "hosts.yaml"):
        doc = _load_file(name) or {}
        entry = doc.get("local")
        if isinstance(entry, dict) and "enabled" in entry:
            return bool(entry["enabled"])
    return True


def _write_hosts(doc):
    path = os.path.join(BASE, "config", "hosts.local.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)
    os.replace(tmp, path)
    return path


def save_local_enabled(enabled):
    path = os.path.join(BASE, "config", "hosts.local.yaml")
    doc = {}
    if os.path.exists(path):
        with open(path) as f:
            doc = yaml.safe_load(f) or {}
    entry = dict(doc.get("local") or {})
    entry["enabled"] = bool(enabled)
    doc["local"] = entry
    return _write_hosts(doc)


def save_host(name, entry):
    """Add/replace one machine in the untracked hosts.local.yaml."""
    path = os.path.join(BASE, "config", "hosts.local.yaml")
    doc = {}
    if os.path.exists(path):
        with open(path) as f:
            doc = yaml.safe_load(f) or {}
    doc[name] = entry
    return _write_hosts(doc)


def save_all_hosts(entries, local_enabled=None):
    """Replace the untracked hosts.local.yaml wholesale (settings page).
    The reserved 'local' entry (this-device flag) is preserved/carried
    separately from the machine entries."""
    doc = dict(entries or {})
    if local_enabled is None:
        existing = _load_file("hosts.local.yaml") or {}
        if "local" in existing:
            doc["local"] = existing["local"]
    else:
        doc["local"] = {"enabled": bool(local_enabled)}
    return _write_hosts(doc)


def _proxy_command(port_override=None):
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy:
        return None
    u = urlparse(proxy)
    if not u.hostname:
        return None
    port = port_override or u.port
    if not port:
        return None
    auth = ""
    if u.username:
        auth = f" -P {u.username}:{u.password or ''}"
    return f"nc -X connect -x {u.hostname}:{port}{auth} %h %p"


def ssh_argv(target, command):
    entry = hosts()[target]
    if not entry.get("host") or not entry.get("user"):
        raise RuntimeError(
            f"target '{target}' is not configured — set its host/user in "
            "config/hosts.local.yaml (see config/hosts.yaml) or the "
            f"AISHIELD_HOST_{target.upper()} env var")
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(entry.get("port") or 22)]
    identity = entry.get("identity")
    if identity:
        argv += ["-o", "IdentitiesOnly=yes",
                 "-i", os.path.expanduser(identity)]
    proxy = str(entry.get("proxy") or "none")
    if proxy.startswith("env"):
        # "env" or "env:<port>" — some environments split their plain
        # HTTP proxy and their CONNECT proxy across ports; the override
        # lives in the untracked local config, not in shipped defaults.
        override = None
        if ":" in proxy:
            try:
                override = int(proxy.split(":", 1)[1])
            except ValueError:
                override = None
        pc = _proxy_command(override)
        if pc:
            argv += ["-o", f"ProxyCommand={pc}"]
    argv.append(f"{entry['user']}@{entry['host']}")
    argv.append(command)
    return argv


def run(target, command, timeout=300):
    """Run `command` on `target`; returns (stdout, stderr, rc).
    'local' runs in this machine's shell; any other target goes over
    ssh with the command as ONE argument (parsed once, remotely)."""
    if target == "local":
        # A service-launched process (GUI server, plugin host) often
        # inherits a minimal PATH without Homebrew — the collectors
        # probe with an augmented PATH, so local command execution
        # must too, or `brew upgrade ...` dies with rc 127.
        env = dict(os.environ)
        parts = (env.get("PATH") or "/usr/bin:/bin").split(":")
        for extra in ("/opt/homebrew/bin", "/usr/local/bin"):
            if extra not in parts:
                parts.insert(0, extra)
        env["PATH"] = ":".join(parts)
        p = subprocess.run(command, shell=True, capture_output=True,
                           text=True, timeout=timeout, env=env)
        return p.stdout, p.stderr, p.returncode
    p = subprocess.run(ssh_argv(target, command), capture_output=True,
                       text=True, timeout=timeout)
    return p.stdout, p.stderr, p.returncode
