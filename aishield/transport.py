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
import platform
import subprocess
from urllib.parse import urlparse

import yaml

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    "mac": {"host": "", "user": "", "port": 22,
            "identity": "~/.ssh/id_ed25519", "proxy": "none"},
    "batman": {"host": "", "user": "", "port": 22,
               "identity": "~/.ssh/id_ed25519", "proxy": "none"},
    "grievous": {"host": "", "user": "", "port": 22,
                 "identity": "~/.ssh/id_ed25519", "proxy": "none"},
}


def this_host():
    """Which fleet target THIS machine is (macOS -> mac, Linux -> vm).
    Windows machines report None: they are targets, reached over ssh."""
    system = platform.system()
    if system == "Darwin":
        return "mac"
    if system == "Linux":
        return "vm"
    return None


def _load_file(name):
    path = os.path.join(BASE, "config", name)
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def hosts():
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    for name in ("hosts.yaml", "hosts.local.yaml"):
        for target, entry in (_load_file(name) or {}).items():
            if target in cfg and isinstance(entry, dict):
                cfg[target].update({k: v for k, v in entry.items()
                                    if v is not None})
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
    Self-targets run locally in a shell; remote targets over ssh with
    the command as ONE argument (the remote shell parses it once)."""
    if target == this_host():
        p = subprocess.run(command, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    if target not in hosts():
        raise RuntimeError(
            f"target '{target}' can only be scanned from the machine "
            "itself (no remote transport is configured for it)")
    p = subprocess.run(ssh_argv(target, command), capture_output=True,
                       text=True, timeout=timeout)
    return p.stdout, p.stderr, p.returncode
