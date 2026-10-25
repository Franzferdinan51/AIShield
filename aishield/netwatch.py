"""Netwatch — network intrusion watch for the local machine.

Catches sources that probe or attack this machine's network
services, tracks them over time, locates them, and lets the owner
block them:

- attack evidence from the platform's own logs (sshd failures on
  Linux auth logs / macOS unified log where visible / Windows
  OpenSSH + Security event channels),
- a connection sensor: point-in-time inbound pressure per source
  IP per service port (netstat/ss), plus an optional 60-second
  sampler (LaunchAgent / systemd timer / scheduled task) that
  accumulates history into data/netwatch-samples.jsonl,
- GeoIP (ip-api.com, cached in data/geo-cache.json; public IPs
  only — private/tailnet sources are classified, never looked up
  and never blockable),
- a blocklist (config/netwatch.local.yaml) with a generated
  platform apply script (pf anchor on macOS, iptables on Linux,
  Windows Firewall rules). Applying at the firewall needs admin
  rights the shield doesn't hold, so block() records the block,
  writes the exact apply script, tries a non-interactive apply
  where the platform allows, and says plainly what remains.

Only PUBLIC source IPs can be attackers or be blocked: tailnet
(100.64/10), LAN and loopback sources are the owner's own fleet.
"""

import base64
import ipaddress
import json
import os
import platform
import re
import subprocess
import time

from . import config as cfgmod

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG_PATH = os.path.join(HERE, "config", "netwatch.local.yaml")
DATA = os.path.join(HERE, "data")
SAMPLES = os.path.join(DATA, "netwatch-samples.jsonl")
PROBES = os.path.join(DATA, "netwatch-probes.jsonl")
CANARY_HEARTBEAT = os.path.join(DATA, "netwatch-canary.json")
GEOCACHE = os.path.join(DATA, "geo-cache.json")
LOG = os.path.join(DATA, "netwatch-log.jsonl")

SERVICE_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 139: "SMB",
                 5900: "VNC", 1234: "LM Studio", 11434: "Ollama",
                 8770: "AI Shield", 8766: "agent shim", 80: "HTTP",
                 443: "HTTPS", 8080: "HTTP", 8188: "ComfyUI",
                 9000: "service", 32400: "Plex", 8081: "HTTP",
                 # the owner's actually-exposed local services —
                 # pressure on these is what "being attacked" means
                 # on this fleet (added 0.17.5)
                 3444: "node service", 8765: "Hermes tools",
                 8799: "drama server", 8895: "Command Center",
                 8899: "RAG visualizer", 8901: "service",
                 8930: "Hermes Town", 8940: "Town Lives",
                 9010: "BrowserOS", 9011: "BrowserOS",
                 9119: "Hermes dashboard"}

# Canary listeners: ports nothing legitimate uses. ANY connection is
# a probe by definition — the sensor that sees scans the socket
# tables can't (a SYN to a closed port leaves no socket behind).
CANARY_PORTS = {2222: "SSH (canary)", 13389: "RDP (canary)",
                5901: "VNC (canary)"}
_TAILNET = ipaddress.ip_network("100.64.0.0/10")


def ip_class(ip):
    """own-fleet classes vs public — the block/geo rail."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr in _TAILNET:
        return "tailnet"
    if addr.is_private or addr.is_link_local or addr.is_reserved \
            or addr.is_multicast or addr.is_unspecified:
        return "lan"
    return "public"


def _run(argv, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


# ---------------------------------------------------------------- logs
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_RE_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+)? ?from " + _IP)
_RE_INVALID = re.compile(r"Invalid user (\S+) from " + _IP)
_RE_MAXAUTH = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+)? ?from " + _IP)
_RE_DISCO = re.compile(r"Disconnected from authenticating user (\S+) " + _IP)


def _feed(records, ip, user, ts, service="SSH"):
    if not ip:
        return
    r = records.setdefault(ip, {"ip": ip, "attempts": 0, "users": set(),
                                 "first_seen": ts, "last_seen": ts,
                                 "services": set()})
    r["attempts"] += 1
    if user:
        r["users"].add(user)
    if ts:
        r["first_seen"] = min(r["first_seen"] or ts, ts)
        r["last_seen"] = max(r["last_seen"] or ts, ts)
    r["services"].add(service)


def _parse_sshd_lines(lines, records, ts_of=None):
    for line in lines:
        m = _RE_FAIL.search(line) or _RE_MAXAUTH.search(line)
        if m:
            _feed(records, m.group(2), m.group(1),
                  ts_of(line) if ts_of else "")
            continue
        m = _RE_INVALID.search(line)
        if m:
            _feed(records, m.group(2), m.group(1),
                  ts_of(line) if ts_of else "")


def _linux_ts_of(line):
    m = re.match(r"(\w{3})\s+(\d+) (\d+):(\d+):(\d+)", line)
    if not m:
        return ""
    months = {m_: i + 1 for i, m_ in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
         "Aug", "Sep", "Oct", "Nov", "Dec"])}
    try:
        import datetime
        now = datetime.datetime.now()
        dt = datetime.datetime(now.year, months[m.group(1)],
                               int(m.group(2)), int(m.group(3)),
                               int(m.group(4)))
        if dt.timestamp() > now.timestamp() + 86400:
            dt = dt.replace(year=now.year - 1)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _log_attackers(hours):
    """{ip: record} from the platform's auth logs + a note."""
    records = {}
    sysname = platform.system()
    if sysname == "Darwin":
        out = _run(["log", "show", "--last", f"{hours}h", "--style",
                    "compact", "--predicate", 'process == "sshd"'],
                   timeout=25)
        _parse_sshd_lines(out.splitlines(), records)
        note = None if records else (
            "macOS does not expose root sshd log entries to user "
            "sessions — the connection sensor and sampler below "
            "carry the watch on this platform")
        return records, note
    if sysname == "Windows":
        return _log_attackers_windows(hours)
    # Linux: auth logs, then journald
    import glob as _glob
    cutoff = time.time() - hours * 3600
    files = [f for f in ("/var/log/auth.log", "/var/log/secure",
                         "/var/log/auth.log.1", "/var/log/secure.1")
             if os.path.exists(f)]
    hit = False
    for path in files:
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
        except Exception:
            continue
        hit = True
        _parse_sshd_lines(lines, records, _linux_ts_of)
    if not hit:
        out = _run(["journalctl", "-u", "ssh", "-u", "sshd",
                    "--since", f"-{hours}h", "--no-pager"], timeout=60)
        _parse_sshd_lines(out.splitlines(), records)
    return records, None


_WIN_PS = r'''
$out = @()
$since = (Get-Date).AddHours(-__HOURS__)
try {
  Get-WinEvent -FilterHashtable @{LogName="OpenSSH/Operational"; StartTime=$since} -MaxEvents 4000 -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Message -match "Failed password|Invalid user|maximum authentication") {
      $out += [PSCustomObject]@{ ts = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"); msg = $_.Message.Substring(0, [Math]::Min(220, $_.Message.Length)); svc = "SSH" }
    }
  }
} catch {}
try {
  Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$since} -MaxEvents 2000 -ErrorAction SilentlyContinue | ForEach-Object {
    [xml]$x = $_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_."#text" }
    if ($d.IpAddress -and $d.IpAddress -ne "-") {
      $out += [PSCustomObject]@{ ts = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"); ip4625 = $d.IpAddress; user = $d.TargetUserName; svc = "Logon" }
    }
  }
} catch {}
$out | ConvertTo-Json -Compress
'''


def _parse_winevents(raw):
    records = {}
    for line in raw.splitlines():
        line = line.strip()
        if not (line.startswith("[") or line.startswith("{")):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            data = [data]
        for e in data:
            if e.get("ip4625"):
                _feed(records, e["ip4625"], e.get("user"),
                      e.get("ts", ""), e.get("svc", "Logon"))
            elif e.get("msg"):
                _parse_sshd_lines([e["msg"]], records,
                                  lambda _l, t=e.get("ts", ""): t)
    return records


def _win_ps_command(hours):
    ps = _WIN_PS.replace("__HOURS__", str(int(hours)))
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -EncodedCommand {enc}"


def _log_attackers_windows(hours):
    raw = _run(["powershell", "-NoProfile", "-EncodedCommand",
                _win_ps_command(hours).split("EncodedCommand ", 1)[1]],
               timeout=120)
    return _parse_winevents(raw), None


def _log_attackers_remote(target, kind, hours):
    """Log evidence fetched from a remote target over the shield's
    SSH transport."""
    from . import transport
    if kind == "windows":
        out, err, rc = transport.run(target, _win_ps_command(hours),
                                     timeout=300)
        return _parse_winevents(out), None
    if kind == "linux":
        out, err, rc = transport.run(
            target,
            "grep -hE 'Failed password|Invalid user|maximum "
            "authentication' /var/log/auth.log /var/log/secure "
            "2>/dev/null | tail -3000", timeout=120)
        records = {}
        _parse_sshd_lines(out.splitlines(), records, _linux_ts_of)
        return records, None
    return {}, ("remote macOS targets don't expose sshd logs over "
                "SSH either — the live sensor still applies")


# ------------------------------------------------------------- sensor
def live_snapshot():
    """Inbound pressure right now: {ip: {port: {established,
    syn_recv, time_wait}}} for service ports, all sources."""
    sysname = platform.system()
    out = ""
    if sysname == "Darwin":
        out = _run(["netstat", "-an", "-p", "tcp"], timeout=20)
    elif sysname == "Windows":
        out = _run(["netstat", "-an", "-p", "TCP"], timeout=20)
    else:
        out = _run(["ss", "-tan"], timeout=20) or _run(
            ["netstat", "-an", "-p", "tcp"], timeout=20)
    return _live_from_text(out, sysname)


def _live_from_text(out, sysname):
    snap = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[-1].upper()
        if state not in ("ESTABLISHED", "SYN_RECV", "SYN_RCVD",
                         "TIME_WAIT", "TIME-WAIT"):
            continue
        if sysname == "Windows":
            local, foreign = parts[1], parts[2]
            if ":" not in local or ":" not in foreign:
                continue
            lip, lport = local.rsplit(":", 1)
            fip = foreign.rsplit(":", 1)[0].strip("[]")
        elif out and "Recv-Q" in line:
            continue
        else:
            # netstat (mac) uses addr.port; ss uses addr:port
            local, foreign = parts[3], parts[4]
            if sysname == "Linux" and ":" in local:
                lip, lport = local.rsplit(":", 1)
                fip = foreign.rsplit(":", 1)[0].strip("[]")
            else:
                if "." not in local or "." not in foreign:
                    continue
                lip, lport = local.rsplit(".", 1)
                fip = foreign.rsplit(".", 1)[0]
        try:
            port = int(lport)
        except ValueError:
            continue
        if port not in SERVICE_PORTS or ip_class(fip) == "loopback":
            continue
        if fip == lip:
            continue
        key = "established" if state == "ESTABLISHED" else (
            "syn_recv" if state.startswith("SYN") else "time_wait")
        snap.setdefault(fip, {}).setdefault(port, {}).setdefault(
            key, 0)
        snap[fip][port][key] += 1
    return snap


def sample_once():
    """One sensor snapshot appended to the history file."""
    snap = live_snapshot()
    os.makedirs(DATA, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "snap": snap}
    with open(SAMPLES, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def _sampled_events(hours):
    """{ip: events} aggregated from the sampler history window."""
    events = {}
    if not os.path.exists(SAMPLES):
        return events
    cutoff = time.time() - hours * 3600
    try:
        with open(SAMPLES) as f:
            lines = f.readlines()[-4000:]
    except Exception:
        return events
    for line in lines:
        try:
            rec = json.loads(line)
            ts = time.mktime(time.strptime(rec["ts"],
                                           "%Y-%m-%d %H:%M:%S"))
        except Exception:
            continue
        if ts < cutoff:
            continue
        for ip, ports in (rec.get("snap") or {}).items():
            n = sum(sum(c.values()) for c in ports.values())
            events[ip] = events.get(ip, 0) + n
    return events


# ------------------------------------------------------------- probes
def _probe_events(hours):
    """Probe/scan evidence per source IP: {ip: {..., flagged}}.

    Two signals the plain sensor misses:
    - scan shape in the sampler history: one source touching many
      distinct service ports, or piling up SYN_RECV half-opens;
    - canary hits: a connection to a canary port is a probe by
      definition (nothing legitimate uses those ports).
    """
    out = {}
    cutoff = time.time() - hours * 3600

    def slot(ip):
        return out.setdefault(ip, {"ports": set(), "syn_recv": 0,
                                   "canary_ports": set(),
                                   "canary_hits": 0, "samples": 0})

    if os.path.exists(SAMPLES):
        try:
            with open(SAMPLES) as f:
                lines = f.readlines()[-4000:]
        except Exception:
            lines = []
        for line in lines:
            try:
                rec = json.loads(line)
                ts = time.mktime(time.strptime(
                    rec["ts"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if ts < cutoff:
                continue
            for ip, ports in (rec.get("snap") or {}).items():
                s = slot(ip)
                s["samples"] += 1
                for port, counts in (ports or {}).items():
                    s["ports"].add(int(port))
                    s["syn_recv"] += counts.get("syn_recv", 0)
    if os.path.exists(PROBES):
        try:
            with open(PROBES) as f:
                lines = f.readlines()[-4000:]
        except Exception:
            lines = []
        for line in lines:
            try:
                rec = json.loads(line)
                ts = time.mktime(time.strptime(
                    rec["ts"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if ts < cutoff:
                continue
            s = slot(rec.get("ip", ""))
            s["canary_ports"].add(int(rec.get("port", 0)))
            s["canary_hits"] += 1
    for ip, s in out.items():
        s["ports"] = sorted(s["ports"])
        s["canary_ports"] = sorted(s["canary_ports"])
        kinds = []
        if s["canary_hits"]:
            kinds.append("canary")
        if len(s["ports"]) >= 4 or s["syn_recv"] >= 10:
            kinds.append("scan")
        s["kinds"] = kinds
        s["flagged"] = bool(kinds)
    return out


def start_canaries():
    """Bind the canary listeners (called by the long-lived GUI
    process). A hit appends to the probes file and is closed at
    once — the canary never speaks. Returns the ports bound."""
    import socket
    import threading

    bound = []

    def serve(port):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(16)
        except Exception:
            return
        bound.append(port)
        while True:
            try:
                conn, addr = srv.accept()
            except Exception:
                return
            try:
                os.makedirs(DATA, exist_ok=True)
                with open(PROBES, "a") as f:
                    f.write(json.dumps({
                        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "ip": addr[0], "port": port}) + "\n")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    for p in CANARY_PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()

    def heartbeat():
        while True:
            try:
                os.makedirs(DATA, exist_ok=True)
                with open(CANARY_HEARTBEAT, "w") as f:
                    json.dump({"ts": time.strftime(
                        "%Y-%m-%d %H:%M:%S"), "ports": bound}, f)
            except Exception:
                pass
            time.sleep(60)

    threading.Thread(target=heartbeat, daemon=True).start()
    return bound


def canary_status():
    try:
        with open(CANARY_HEARTBEAT) as f:
            hb = json.load(f)
        ts = time.mktime(time.strptime(hb["ts"], "%Y-%m-%d %H:%M:%S"))
        return {"active": (time.time() - ts) < 180,
                "ports": hb.get("ports") or []}
    except Exception:
        return {"active": False, "ports": []}


# ---------------------------------------------------------------- geo
def geo(ip):
    cls = ip_class(ip)
    if cls != "public":
        return {"class": cls, "label": {"tailnet": "your tailnet",
                                        "lan": "local network",
                                        "loopback": "this machine"
                                        }.get(cls, cls)}
    cache = {}
    if os.path.exists(GEOCACHE):
        try:
            with open(GEOCACHE) as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    if ip in cache:
        return cache[ip]
    out = {"class": "public"}
    try:
        import requests
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,lat,lon,"
                              "isp,org,as,query"},
            timeout=6)
        d = r.json()
        if d.get("status") == "success":
            out = {"class": "public", "country": d.get("country"),
                   "region": d.get("regionName"), "city": d.get("city"),
                   "lat": d.get("lat"), "lon": d.get("lon"),
                   "isp": d.get("isp"), "org": d.get("org"),
                   "as": d.get("as")}
    except Exception as e:
        out = {"class": "public", "error": type(e).__name__}
    cache[ip] = out
    os.makedirs(DATA, exist_ok=True)
    try:
        with open(GEOCACHE, "w") as f:
            json.dump(cache, f, indent=1)
    except Exception:
        pass
    return out


# ------------------------------------------------------------ blocklist
def _load_blocked():
    if os.path.exists(CFG_PATH):
        try:
            import yaml
            with open(CFG_PATH) as f:
                data = yaml.safe_load(f) or {}
            return list(data.get("blocked") or [])
        except Exception:
            return []
    return []


def _save_blocked(ips):
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    import yaml
    with open(CFG_PATH, "w") as f:
        f.write("# AI Shield Netwatch blocklist — the owner's list.\n"
                "# Apply at the firewall with data/netwatch-apply.*\n")
        yaml.safe_dump({"blocked": sorted(set(ips))}, f)


def _log_event(entry):
    os.makedirs(DATA, exist_ok=True)
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
    with open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _apply_artifacts(ips):
    """Write the platform firewall script + rules from the list.
    Returns {script, how}."""
    os.makedirs(DATA, exist_ok=True)
    sysname = platform.system()
    if sysname == "Darwin":
        with open(os.path.join(DATA, "netwatch-blocked.txt"),
                  "w") as f:
            f.write("\n".join(ips) + ("\n" if ips else ""))
        anchor = os.path.join(DATA, "netwatch-pf-anchor.txt")
        with open(anchor, "w") as f:
            f.write('table <aishield_blocked> persist file '
                    '"/etc/aishield-blocked.txt"\n'
                    'block drop in quick from <aishield_blocked> '
                    'to any\n')
        script = os.path.join(DATA, "netwatch-apply.sh")
        with open(script, "w") as f:
            f.write("#!/bin/bash\n"
                    "# AI Shield Netwatch — apply the blocklist to pf.\n"
                    "set -e\n"
                    f'cp "{os.path.join(DATA, "netwatch-blocked.txt")}"'
                    " /etc/aishield-blocked.txt\n"
                    f'cp "{anchor}" /etc/pf.anchors/aishield\n'
                    "grep -q 'anchor \"aishield\"' /etc/pf.conf || {\n"
                    "  cp /etc/pf.conf /etc/pf.conf.aishield-backup\n"
                    "  printf '\\nanchor \"aishield\"\\nload anchor "
                    "\"aishield\" from \"/etc/pf.anchors/aishield\"\\n'"
                    " >> /etc/pf.conf\n"
                    "}\n"
                    "pfctl -E -f /etc/pf.conf 2>/dev/null || true\n"
                    "pfctl -a aishield -f /etc/pf.anchors/aishield\n"
                    "echo \"netwatch blocklist applied: "
                    "$(wc -l < /etc/aishield-blocked.txt) IP(s)\"\n")
        os.chmod(script, 0o755)
        return {"script": script,
                "how": f"run once in Terminal: sudo bash {script} "
                       f"(re-run after changing the list)"}
    if sysname == "Windows":
        script = os.path.join(DATA, "netwatch-apply.ps1")
        with open(script, "w") as f:
            f.write("# AI Shield Netwatch — apply the blocklist to "
                    "Windows Firewall (run elevated)\n")
            f.write("Get-NetFirewallRule -DisplayName 'AIShield-*' "
                    "-ErrorAction SilentlyContinue | "
                    "Remove-NetFirewallRule\n")
            for ip in ips:
                f.write(f"New-NetFirewallRule -DisplayName "
                        f"'AIShield-Block-{ip}' -Direction Inbound "
                        f"-RemoteAddress {ip} -Action Block\n")
            f.write(f"Write-Host 'netwatch blocklist applied: "
                    f"{len(ips)} IP(s)'\n")
        return {"script": script,
                "how": f"run elevated in PowerShell: {script}"}
    script = os.path.join(DATA, "netwatch-apply.sh")
    with open(script, "w") as f:
        f.write("#!/bin/bash\n# AI Shield Netwatch — apply the "
                "blocklist with iptables.\nset -e\n")
        for ip in ips:
            f.write(f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null "
                    f"|| iptables -I INPUT -s {ip} -j DROP\n")
        f.write(f"echo 'netwatch blocklist applied: {len(ips)} "
                "IP(s)'\n")
    os.chmod(script, 0o755)
    return {"script": script,
            "how": f"run once in a terminal: sudo bash {script} "
                   f"(re-run after changing the list)"}


def block(ip, actor="owner"):
    """Add a public source IP to the blocklist. Fleet/private IPs are
    refused — blocking your own network is never the right move."""
    cls = ip_class(ip)
    if cls == "invalid":
        return {"error": f"'{ip}' is not an IP address"}
    if cls != "public":
        return {"error": f"{ip} is {cls} — your own network is never "
                         f"blocked"}
    ips = _load_blocked()
    if ip not in ips:
        ips.append(ip)
        _save_blocked(ips)
    art = _apply_artifacts(ips)
    applied = False
    if platform.system() == "Windows":
        try:
            out = _run(["powershell", "-NoProfile", "-ExecutionPolicy",
                        "Bypass", "-File", art["script"]], timeout=60)
            applied = "applied" in out
        except Exception:
            applied = False
    else:
        probe = subprocess.run(["sudo", "-n", "true"],
                               capture_output=True)
        if probe.returncode == 0:
            out = _run(["sudo", "-n", "bash", art["script"]], timeout=60)
            applied = "applied" in out
    _log_event({"action": "block", "ip": ip, "actor": actor,
                "applied": applied})
    return {"blocked": True, "ip": ip, "applied": applied,
            "script": art["script"],
            "how": None if applied else art["how"]}


def block_remote(target, ip, actor="owner"):
    """Block a public attacker ON a remote machine: a Windows
    Firewall rule (or iptables) written over the shield's SSH
    transport. Public IPs only — the same rail as local."""
    cls = ip_class(ip)
    if cls == "invalid":
        return {"error": f"'{ip}' is not an IP address"}
    if cls != "public":
        return {"error": f"{ip} is {cls} — your own network is never "
                         f"blocked"}
    from . import inventory as _inv
    from . import transport as _transport
    kind = _inv.target_kind(target)
    if kind == "windows":
        ps = (f"if (Get-NetFirewallRule -DisplayName "
              f"'AIShield-Block-{ip}' -ErrorAction SilentlyContinue) "
              f"{{ 'already' }} else {{ New-NetFirewallRule "
              f"-DisplayName 'AIShield-Block-{ip}' -Direction Inbound "
              f"-RemoteAddress {ip} -Action Block | Out-Null; "
              f"'created' }}")
        enc = base64.b64encode(ps.encode("utf-16-le")).decode()
        out, err, rc = _transport.run(
            target, f"powershell -NoProfile -EncodedCommand {enc}",
            timeout=120)
        ok = "created" in out or "already" in out
        _log_event({"action": "block-remote", "target": target,
                    "ip": ip, "actor": actor, "applied": ok})
        return {"blocked": ok, "ip": ip, "target": target,
                "applied": ok,
                "how": None if ok else
                       "the firewall rule could not be created over "
                       "SSH (the remote session may lack elevation) — "
                       f"output: {(out + err)[-200:]}"}
    if kind == "linux":
        out, err, rc = _transport.run(
            target,
            f"sudo -n iptables -C INPUT -s {ip} -j DROP 2>/dev/null "
            f"|| sudo -n iptables -I INPUT -s {ip} -j DROP",
            timeout=60)
        ok = rc == 0
        _log_event({"action": "block-remote", "target": target,
                    "ip": ip, "actor": actor, "applied": ok})
        return {"blocked": ok, "ip": ip, "target": target,
                "applied": ok,
                "how": None if ok else
                       "iptables over SSH needs passwordless sudo on "
                       "the target"}
    return {"error": f"remote blocking isn't supported for "
                     f"{kind} targets yet"}


def unblock(ip, actor="owner"):
    ips = [x for x in _load_blocked() if x != ip]
    _save_blocked(ips)
    art = _apply_artifacts(ips)
    _log_event({"action": "unblock", "ip": ip, "actor": actor})
    return {"unblocked": True, "ip": ip, "script": art["script"],
            "how": art["how"]}


# --------------------------------------------------------------- census
def census(hours=24, with_geo=True, target="local"):
    """Merge log evidence + sampler history + the live sensor into
    one tracked-sources report. Remote targets are watched over the
    shield's SSH transport: their auth logs + live connections
    (no sampler runs there, so history is the log window)."""
    if target == "local":
        logs, note = _log_attackers(hours)
        sampled = _sampled_events(hours)
        live = live_snapshot()
        probes = _probe_events(hours)
        blocked = set(_load_blocked())
    else:
        from . import inventory as _inv
        from . import transport as _transport
        kind = _inv.target_kind(target)
        logs, note = _log_attackers_remote(target, kind, hours)
        sampled = {}
        if kind == "windows":
            raw, _e, _r = _transport.run(target, "netstat -an -p TCP",
                                         timeout=60)
            live = _live_from_text(raw, "Windows")
        elif kind == "linux":
            raw, _e, _r = _transport.run(target, "ss -tan", timeout=60)
            live = _live_from_text(raw, "Linux")
        else:
            raw, _e, _r = _transport.run(
                target, "netstat -an -p tcp", timeout=60)
            live = _live_from_text(raw, "Darwin")
        blocked = set()
        probes = {}
        note = ((note + " · " if note else "") +
                "remote watch: auth logs + live connections only — "
                "no sampler runs on that machine")
    ips = set(logs) | set(sampled) | set(live) | {
        ip for ip, p in probes.items() if p.get("flagged")}
    attackers, known = [], []
    for ip in ips:
        cls = ip_class(ip)
        lr = logs.get(ip) or {}
        entry = {
            "ip": ip, "class": cls,
            "attempts": lr.get("attempts", 0),
            "users": sorted(lr.get("users") or []),
            "first_seen": lr.get("first_seen") or "",
            "last_seen": lr.get("last_seen") or "",
            "services": sorted(lr.get("services") or []),
            "sampled_events": sampled.get(ip, 0),
            "live": live.get(ip, {}),
            "blocked": ip in blocked,
            "sources": [s for s, on in
                        (("auth log", ip in logs),
                         ("sampler", ip in sampled),
                         ("live connections", ip in live),
                         ("canary", bool((probes.get(ip) or {})
                                         .get("canary_hits"))),
                         ("probe sensor", bool((probes.get(ip) or {})
                                               .get("flagged")))) if on],
        }
        pr = probes.get(ip) or {}
        if pr.get("flagged"):
            entry["probe"] = {"kinds": pr["kinds"],
                              "ports": pr["ports"],
                              "syn_recv": pr["syn_recv"],
                              "canary_ports": pr["canary_ports"],
                              "canary_hits": pr["canary_hits"]}
        live_services = set()
        for port, counts in (live.get(ip) or {}).items():
            live_services.add(SERVICE_PORTS.get(int(port), str(port)))
            if counts.get("established"):
                entry["live_connected"] = True
        entry["services"] = sorted(set(entry["services"]) |
                                   live_services)
        score = entry["attempts"] + entry["sampled_events"]
        if entry.get("live_connected") and cls == "public":
            score += 30
        if pr.get("flagged"):
            score += 40 if "canary" in pr["kinds"] else 25
        entry["risk"] = score
        entry["level"] = ("high" if score >= 100 or
                          (cls == "public" and entry.get("live_connected")
                           and entry["attempts"] >= 5)
                          else "medium" if score >= 10 else "low")
        if pr.get("flagged") and cls == "public":
            if "canary" in pr["kinds"]:
                entry["level"] = "high"
            elif entry["level"] == "low":
                entry["level"] = "medium"
        entry["geo"] = geo(ip) if with_geo else {"class": cls}
        (attackers if cls == "public" else known).append(entry)
    attackers.sort(key=lambda e: -e["risk"])
    known.sort(key=lambda e: -e["risk"])
    return {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "hours": hours,
            "target": target, "note": note,
            "sampler_active": os.path.exists(SAMPLES),
            "totals": {"public_sources": len(attackers),
                       "attempts": sum(a["attempts"] for a in attackers),
                       "blocked": sum(1 for a in attackers
                                      if a["blocked"]),
                       "connected_now": sum(1 for a in attackers
                                            if a.get("live_connected")),
                       "probing_sources": sum(
                           1 for p in probes.values()
                           if p.get("flagged")),
                       "canary_hits": sum(
                           p.get("canary_hits", 0)
                           for p in probes.values())},
            "canary": (canary_status() if target == "local"
                       else {"active": False, "ports": []}),
            "attackers": attackers, "known_sources": known,
            "blocked_list": sorted(blocked)}


def assess(data=None):
    """AI read of the tracked sources — grounded in the census,
    recommendations stay inside the blocklist playbook."""
    from . import ai
    data = data or census(hours=24)
    rows = []
    for a in data["attackers"][:15]:
        g = a.get("geo") or {}
        where = ", ".join(x for x in (g.get("city"), g.get("region"),
                                      g.get("country")) if x) or "unknown"
        rows.append(f"- {a['ip']} ({where}; {g.get('org') or g.get('isp') or 'unknown network'}): "
                    f"{a['attempts']} failed attempts, users tried: "
                    f"{', '.join(a['users'][:8]) or '—'}, services: "
                    f"{', '.join(a['services']) or '—'}, "
                    f"risk {a['level']}, "
                    f"{'BLOCKED already' if a['blocked'] else 'not blocked'}"
                    f"{', connected right now' if a.get('live_connected') else ''}"
                    f"{', PROBE ' + '/'.join(a['probe']['kinds']) + ' across ports ' + ','.join(map(str, a['probe']['ports'] + a['probe']['canary_ports'])) if a.get('probe') else ''}")
    prompt = (
        "You are the AI layer of AI Shield's Netwatch, writing for the "
        "machine's owner. Below are the public sources tracked "
        "probing or attacking this machine in the last 24 hours. "
        "Assess: which look like automated botnet scanning vs "
        "targeted attempts, what the username patterns say, and "
        "which IPs you recommend blocking (the owner blocks with one "
        "click; the blocklist applies at the firewall). Be direct "
        "and specific. If the list is empty, say the network looks "
        "quiet and what the sensor is watching.\n\n"
        + ("\n".join(rows) if rows else "(no public attackers tracked)"))
    return {"assessment": ai._narrate(prompt, ai.triage_model()),
            "model": ai.triage_model(), "census_ts": data["ts"]}


# ------------------------------------------------------------- sampler
def sampler_plist(exe_argv):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.aishield.netwatch</string>
  <key>ProgramArguments</key>
  <array>
{chr(10).join(f"    <string>{a}</string>" for a in exe_argv)}
    <string>netwatch</string><string>--sample</string>
  </array>
  <key>StartInterval</key><integer>60</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>{os.path.join(DATA, "netwatch-sampler.log")}</string>
  <key>StandardErrorPath</key><string>{os.path.join(DATA, "netwatch-sampler.log")}</string>
</dict>
</plist>
'''
