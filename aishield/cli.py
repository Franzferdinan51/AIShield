"""AI Shield CLI.

  aishield latest [--source kev|critical|all] [--ecosystem pypi] [--limit 20]
  aishield scan <target> [--program NAME] [--ai] [--adjudicate] [--json]
  aishield patch <target> [--program NAME] [--apply] [--json]
  aishield cve <CVE-ID>
  aishield status
Targets: 'local' (this machine) plus any machines defined in
config/hosts.local.yaml — see `aishield hosts`. 'all' scans every target.
"""
import argparse
import json
import os
import sys

from . import ai, config as cfgmod, cvenow, engine, feeds, inventory, match, patch, transport


def cmd_latest(args):
    if args.source == "kev":
        feed = cvenow.list_feed(name="kev", limit=args.limit)
    elif args.source == "critical":
        feed = cvenow.list_feed(filter=["critical"], ecosystem=args.ecosystem, limit=args.limit)
    else:
        feed = cvenow.list_feed(name="all", ecosystem=args.ecosystem, limit=args.limit)
    items = feed.get("items") or feed.get("entries") or feed.get("vulnerabilities") or []
    if args.json:
        print(json.dumps(feed, indent=1))
        return
    for it in items:
        if isinstance(it, dict):
            cid = it.get("id") or it.get("cve_id") or it.get("cveID") or "?"
            summ = (it.get("summary") or it.get("title") or "")[:100]
            sev = it.get("severity") or it.get("cvss") or ""
            print(f"{cid}  {sev}  {summ}")
    if not items:
        print(json.dumps(feed)[:800])


def cmd_scan(args):
    targets = inventory.targets() if args.target == "all" else [args.target]
    failed = False
    for t in targets:
        try:
            result = engine.run_scan(t, program=args.program, use_ai=args.ai,
                                     adjudicate_apps=args.adjudicate)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            failed = True
            continue
        if args.json:
            print(json.dumps(result, indent=1, default=str))
        else:
            print(engine.format_report(result))
            print()
    if failed and len(targets) == 1:
        sys.exit(2)


def cmd_patch(args):
    try:
        result = engine.run_scan(args.target, program=args.program)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    if not args.apply:
        print(engine.format_report(result))
        print("\n(dry run — re-run with --apply to execute the auto patch plan)")
        return
    plan = result["plan"]
    if getattr(args, "policy", False):
        from . import policy as policymod
        pol = policymod.load()
        plan, withheld = policymod.filter_plan(plan, pol)
        for w in withheld:
            print(f"withheld by policy: {w['name']} — {w['reason']}")
    outcome = patch.apply_plan(plan, confirm="PATCH")
    print(json.dumps(outcome, indent=1, default=str))
    after = engine.run_scan(args.target, program=args.program)
    still = [f for f in after["findings"] if f["confidence"] != "error"]
    print(f"\npost-patch rescan: {len(still)} findings remain "
          f"(was {len(result['findings'])})")
    from . import report as _report
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf = _report.write_run_report(base, args.target, result, outcome, after)
    print(f"report: {pdf}")


def cmd_mcp(args):
    from . import mcp_server
    mcp_server.main()


def cmd_swarm(args):
    from . import swarm as swarmmod
    if args.act:
        action, _, pid = args.act.partition(":")
        out = swarmmod.act(int(pid), action, args.confirm or "")
        print(json.dumps(out, indent=1))
        return
    if args.mark:
        kind, _, pid = args.mark.partition(":")
        out = swarmmod.mark(int(pid), kind)
        print(json.dumps(out, indent=1))
        return
    data = swarmmod.census()
    if args.assess:
        data = {"census": data, "assess": swarmmod.assess(data)}
    if args.json:
        print(json.dumps(data, indent=1, default=str))
        return
    if data.get("error"):
        print(data["error"])
        return
    print(f"swarm census {data['ts']} — {data['total_processes']} "
          f"processes · {len(data['friendly'])} friendly · "
          f"{len(data['enemy'])} enemy · {len(data['unknown'])} unknown · "
          f"{len(data['swarms'])} clusters")
    for sw in data["swarms"]:
        print(f"\n⚠ cluster [{sw['kind']}] {sw['key']}: {sw['reason']}")
    for e in data["enemy"]:
        print(f"  ☠ ENEMY pid {e['pid']} score {e['score']} "
              f"{e['cmd'][:90]}\n      {e.get('why', '')}")
    for e in data["unknown"]:
        print(f"  ? UNKNOWN pid {e['pid']} score {e['score']} "
              f"{e['cmd'][:90]}\n      {e.get('why', '')}")
        for sig in e["signals"]:
            print(f"      · {sig}")
    for e in data["friendly"]:
        print(f"  ✓ friendly pid {e['pid']} {e['cmd'][:90]} "
              f"— {e.get('why', '')}")
    inc = swarmmod.incidents(5)
    if inc:
        print("\nrecent defense actions:")
        for i in inc:
            print(f"  {i.get('ts')} {i.get('action')} pid "
                  f"{i.get('pid')} {i.get('cmd', '')[:70]}")
    if args.assess:
        a = data.get("assess") or {}
        if a.get("assessment"):
            print("\nAI assessment:\n" + a["assessment"])
        if a.get("verdict"):
            print("verdict:", a["verdict"])


def cmd_charter(args):
    from . import agent_charter
    print(agent_charter.CHARTER)


def cmd_policy(args):
    from . import policy as policymod
    pol = policymod.load()
    if args.json:
        print(json.dumps({"policy": pol, "file": policymod.PATH}, indent=1))
        return
    print(f"automation policy ({policymod.PATH}):")
    for k, v in pol.items():
        print(f"  {k}: {v}")
    if not pol["enabled"]:
        print("\npolicy is OFF — agents can scan freely, but nothing "
              "auto-patches until the owner enables it (GUI Settings → "
              "Automation policy).")


def cmd_watch(args):
    import time as _time
    from . import policy as policymod
    pol = policymod.load()
    targets = [args.target] if args.target else list(pol.get("targets") or [])
    if not pol.get("enabled") or not pol.get("auto_apply"):
        msg = {"ran": False, "reason": "automation policy is off — "
               "enable it in GUI Settings → Automation policy or "
               "config/policy.local.yaml"}
        print(json.dumps(msg, indent=1) if args.json else msg["reason"])
        return
    targets = [t for t in targets if t in (pol.get("targets") or [])]
    if not targets:
        msg = {"ran": False, "reason": "no requested target is covered "
               "by the policy"}
        print(json.dumps(msg, indent=1) if args.json else msg["reason"])
        return
    interval = (args.interval or pol.get("scan_interval_hours") or 24) * 3600
    while True:
        for t in targets:
            out = engine.auto_cycle(t)
            if args.json:
                print(json.dumps(out, indent=1, default=str))
            elif out.get("ran"):
                print(f"[{t}] findings {out['findings_before']} → "
                      f"{out['findings_after']} · applied "
                      f"{len(out['applied'])} · withheld "
                      f"{len(out['withheld'])} · report {out['report']}")
            else:
                print(f"[{t}] {out.get('reason')}")
        if args.once:
            return
        _time.sleep(interval)


def cmd_cve(args):
    out = {"cvenow": None, "kev": None, "nvd": None}
    try:
        out["cvenow"] = cvenow.get_vulnerability(args.cve_id)
    except Exception as e:
        out["cvenow"] = {"error": str(e)[:200]}
    kev_map, _ = feeds.kev()
    out["kev"] = kev_map.get(args.cve_id)
    out["nvd"] = feeds.nvd_cve(args.cve_id)
    found = bool(out["kev"]) or bool(out["nvd"]) or (
        isinstance(out["cvenow"], dict) and out["cvenow"]
        and "error" not in out["cvenow"] and out["cvenow"].get("id"))
    out["found"] = found
    print(json.dumps(out, indent=1, default=str))
    if not found:
        print(f"note: {args.cve_id} not found in CVE Now, KEV, or NVD "
              "(check the id — or it may be reserved/unpublished)")


def cmd_status(args):
    from . import __version__
    kev_map, kev_date = feeds.kev()
    models = ai.loaded_models()
    cfg = cfgmod.load()
    print(f"AI Shield v{__version__}")
    print(f"KEV catalog: {len(kev_map)} entries, released {kev_date}")
    print(f"model server: {cfg['server']['url']}")
    print(f"loaded models: {models or 'none reachable'}")
    print(f"triage role: {cfg['roles']['triage']['model'] or 'auto'} "
          f"-> {ai.triage_model(models) or 'offline'}")
    dec = cfg["roles"]["decision"]
    print(f"decision role: {dec['model']} (fallback {dec.get('fallback')}) "
          f"protocol {dec.get('protocol') or 'auto'}")
    verdict, p, used = ai.decide_noul(
        "A test probe: the sky is blue on a clear day.",
        "Is the sky blue on a clear day? 'yes' means it is blue.")
    probe = (f"answering as {used} (p_yes={p})" if verdict
             else "not answering (fail-open)")
    print(f"decision probe: {probe}")
    try:
        cvenow.list_feed(filter=["critical"], limit=1)
        print("CVE Now: reachable")
    except Exception as e:
        print(f"CVE Now: unreachable ({str(e)[:120]})")
    print(f"targets: {', '.join(inventory.targets())}")


def cmd_gui(args):
    from . import gui
    return gui.serve(port=args.port, open_browser=not args.no_open)


def cmd_settings(args):
    from . import settings
    return settings.serve(port=args.port)


def cmd_hosts(args):
    print(json.dumps(transport.describe(), indent=1))
    print("'local' (this machine): enabled =", transport.local_enabled(),
          "| kind:", inventory.local_kind())
    print("remote machines scan only when their entry has enabled: true")
    print("config: config/hosts.yaml + config/hosts.local.yaml (untracked)")


def cmd_models(args):
    cfg = cfgmod.load()
    print(json.dumps(cfg, indent=1))
    print(f"config files: {cfgmod.MODELS_YAML} + {cfgmod.MODELS_LOCAL_YAML} (untracked, wins)")
    print("env overrides: AISHIELD_LM_URL, AISHIELD_TRIAGE_MODEL, "
          "AISHIELD_DECISION_MODEL")


def _ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def _pick(title, options, default_idx=0):
    """options: [(value, label)]. Returns the chosen value."""
    print(title)
    for i, (_, label) in enumerate(options):
        mark = " *" if i == default_idx else ""
        print(f"  {i + 1}. {label}{mark}")
    raw = input(f"choice [1-{len(options)}, Enter={default_idx + 1}]: ").strip()
    if not raw:
        return options[default_idx][0]
    try:
        return options[int(raw) - 1][0]
    except (ValueError, IndexError):
        print("invalid choice, keeping default")
        return options[default_idx][0]


PROVIDERS = [
    ("lmstudio", "LM Studio (local)", "http://localhost:1234"),
    ("ollama", "Ollama (local)", "http://localhost:11434/v1"),
    ("llamacpp", "llama.cpp server (local)", "http://localhost:8080/v1"),
    ("vllm", "vLLM (local / self-hosted)", "http://localhost:8000/v1"),
    ("openai", "OpenAI API", "https://api.openai.com/v1"),
    ("custom", "Custom OpenAI-compatible URL", None),
]


def _parse_ssh_target(raw):
    """'user@host[:port]' -> (user, host, port)."""
    raw = raw.strip()
    port = 22
    if "@" in raw:
        user, _, hostport = raw.partition("@")
    else:
        user, hostport = "", raw
    if ":" in hostport:
        hostport, _, p = hostport.rpartition(":")
        try:
            port = int(p)
        except ValueError:
            pass
    return user, hostport, port


def cmd_setup(args):
    cfg = cfgmod.load()
    provider_urls = {k: u for k, _, u in PROVIDERS if u}
    if getattr(args, "provider", None) and not args.server:
        cfg["server"]["url"] = provider_urls[args.provider]
    if args.server:
        cfg["server"]["url"] = args.server.rstrip("/")
    if getattr(args, "api_key", None) is not None:
        cfg["server"]["api_key"] = args.api_key or None
    if args.triage is not None:
        cfg["roles"]["triage"]["model"] = args.triage or None
    if args.decision is not None:
        cfg["roles"]["decision"]["model"] = args.decision or None
    if args.decision_fallback is not None:
        cfg["roles"]["decision"]["fallback"] = args.decision_fallback or None
    if getattr(args, "decision_protocol", None):
        cfg["roles"]["decision"]["protocol"] = args.decision_protocol
    for spec in (getattr(args, "add_host", None) or []):
        # name:os:user@host[:port]
        try:
            name, osname, ssh = spec.split(":", 2)
            user, host, port = _parse_ssh_target(ssh)
            transport.save_host(name, {"os": osname, "host": host,
                                       "user": user, "port": port,
                                       "enabled": True})
            print(f"host saved: {name} ({osname}, {user}@{host}:{port})")
        except Exception as e:
            print(f"could not parse --add-host '{spec}': {e}")
    if not args.yes:
        print("AI Shield setup — connect a model provider, pick the models,")
        print("and (optionally) add machines to scan. Everything is saved to")
        print("untracked local config; re-run setup any time to change it.\n")
        cur_url = cfg["server"]["url"]
        default_idx = next((i for i, (_, _, u) in enumerate(PROVIDERS)
                            if u == cur_url), 0)
        pkey = _pick("model provider:", [(k, f"{label} — {u or 'you enter the URL'}")
                                         for k, label, u in PROVIDERS],
                     default_idx)
        if pkey == "custom":
            cfg["server"]["url"] = _ask("model server base URL", cur_url).rstrip("/")
        else:
            cfg["server"]["url"] = _ask("model server base URL",
                                        provider_urls[pkey]).rstrip("/")
        have_key = bool(cfg["server"].get("api_key"))
        key = _ask("API key (blank = none; local servers usually need none"
                   + (", Enter keeps the saved one" if have_key else "") + ")")
        if key:
            cfg["server"]["api_key"] = key
        os.environ["AISHIELD_LM_URL"] = cfg["server"]["url"]
        if cfg["server"].get("api_key"):
            os.environ["AISHIELD_API_KEY"] = cfg["server"]["api_key"]
        loaded = ai.loaded_models()
        if loaded:
            print(f"\nconnected — the server lists {len(loaded)} model(s).")
            chat_opts = [(None, "auto — strongest chat model on the server")]
            chat_opts += [(m, m) for m in loaded
                          if "embed" not in m.lower()]
            chat_opts.append(("__custom__", "type a model id manually"))
            cur = cfg["roles"]["triage"]["model"]
            di = next((i for i, (v, _) in enumerate(chat_opts) if v == cur), 0)
            choice = _pick("main model (writes briefs; also the fallback for "
                           "decisions):", chat_opts, di)
            if choice == "__custom__":
                choice = _ask("main model id") or None
            cfg["roles"]["triage"]["model"] = choice
            print("\nThe decision model makes the safety calls (is this app the")
            print("vulnerable product? may this patch run unattended?). If your")
            print("server exposes a typed decision endpoint, name its model;")
            print("otherwise skip — decisions fall back to the main model.")
            typed = ai.decision_typed_models()
            dec_opts = [(None, "none — use the main model for decisions")]
            dec_opts += [(m, f"{m}  (decision model)") for m in typed]
            dec_opts += [(m, m) for m in loaded if m not in typed]
            dec_opts.append(("__custom__", "type a model id manually"))
            cur = cfg["roles"]["decision"]["model"]
            di = next((i for i, (v, _) in enumerate(dec_opts) if v == cur), 0)
            choice = _pick("decision model (optional):", dec_opts, di)
            if choice == "__custom__":
                choice = _ask("decision model id") or None
            cfg["roles"]["decision"]["model"] = choice
            if choice:
                fb = _ask("decision fallback model (blank = none)",
                          cfg["roles"]["decision"].get("fallback") or "")
                cfg["roles"]["decision"]["fallback"] = fb or None
                proto = _pick("decision protocol:", [
                    ("auto", "auto — /v1/decisions first, then /v1/systemone (recommended)"),
                    ("decisions", "/v1/decisions — OpenAI-compatible (LM Studio 0.4.26+)"),
                    ("systemone", "/v1/systemone — Jev wire (LM Studio / Ollama)"),
                    ("chat", "chat only — no typed endpoint")],
                    ["auto", "decisions", "systemone", "chat"].index(
                        cfg["roles"]["decision"].get("protocol") or "auto"))
                cfg["roles"]["decision"]["protocol"] = proto
        else:
            print("\nserver not reachable right now — that's fine, save now")
            print("and the shield picks models up when the server is up.")
            tri = _ask("main model id (blank = auto)",
                       cfg["roles"]["triage"]["model"] or "")
            cfg["roles"]["triage"]["model"] = tri or None
            dec = _ask("decision model id (blank = use main model)",
                       cfg["roles"]["decision"]["model"] or "")
            cfg["roles"]["decision"]["model"] = dec or None
            if dec:
                fb = _ask("decision fallback model (blank = none)",
                          cfg["roles"]["decision"].get("fallback") or "")
                cfg["roles"]["decision"]["fallback"] = fb or None
                proto = _pick("decision protocol:", [
                    ("auto", "auto — /v1/decisions first, then /v1/systemone (recommended)"),
                    ("decisions", "/v1/decisions — OpenAI-compatible (LM Studio 0.4.26+)"),
                    ("systemone", "/v1/systemone — Jev wire (LM Studio / Ollama)"),
                    ("chat", "chat only — no typed endpoint")],
                    ["auto", "decisions", "systemone", "chat"].index(
                        cfg["roles"]["decision"].get("protocol") or "auto"))
                cfg["roles"]["decision"]["protocol"] = proto
        print("\nMachines to scan. The shield is designed to run on each")
        print("machine itself — remote scanning is optional and off unless")
        print("you enable it per machine.")
        here = _ask("scan THIS device? (y/n)", "y")
        transport.save_local_enabled(here.lower().startswith("y"))
        while True:
            name = _ask("add a machine? its short name (blank to finish)")
            if not name:
                break
            osname = _pick(f"os for '{name}':",
                           [("linux", "linux"), ("macos", "macos"),
                            ("windows", "windows")], 0)
            ssh = _ask("ssh target (user@host[:port])")
            user, host, port = _parse_ssh_target(ssh)
            if not host or not user:
                print("  need user@host — skipped")
                continue
            en = _ask(f"enable scanning for '{name}'? (y/n)", "n")
            path = transport.save_host(
                name, {"os": osname, "host": host, "user": user,
                       "port": port, "enabled": en.lower().startswith("y")})
            print(f"  saved {name} -> {user}@{host}:{port} ({osname}, "
                  f"{'enabled' if en.lower().startswith('y') else 'disabled'}) in {path}")
    path = cfgmod.save(cfg)
    print(f"\nmodel config saved: {path}")
    print(json.dumps(cfg, indent=1))
    print(f"targets now: {', '.join(inventory.targets())}")
    tri = ai.triage_model() or "offline (no chat model reachable)"
    print(f"main model: {tri}")
    if cfg["roles"]["decision"]["model"]:
        verdict, p, used = ai.decide_noul(
            "A test probe: the sky is blue on a clear day.",
            "Is the sky blue on a clear day? 'yes' means it is blue.")
        layer = (f"answering as {used} (p_yes={p})" if verdict
                 else "not answering (fail-open — scans still work)")
        print(f"decision layer: {layer}")
    else:
        print("decision layer: main model (chat fallback)")


BANNER = "🛡️  AI Shield — CVE Now + KEV + OSV scanner/patcher"
USAGE = """usage: aishield <command> [options]

  status                 feeds + model server + AI layer health
  latest                 newest CVEs from CVE Now (--source kev|critical|all)
  cve <CVE-ID>           full detail on one CVE
  scan <target>          scan local|<configured host>|all (--program X, --ai)
  patch <target>         dry-run patch plan; --apply executes (held steps stay held)
  models                 show the model configuration
  setup                  wizard: set the model server + models
  settings               settings page in your browser (models + machines)
  gui                    full desktop-style GUI in your browser (all platforms)

Models are swappable — config/models.yaml or env vars; nothing is hardcoded."""


def main(argv=None):
    from . import __version__
    ap = argparse.ArgumentParser(prog="aishield")
    ap.add_argument("--version", action="version",
                    version=f"aishield {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("latest")
    p.add_argument("--source", choices=["kev", "critical", "all"], default="critical")
    p.add_argument("--ecosystem", default=None)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_latest)
    p = sub.add_parser("scan")
    p.add_argument("target", choices=inventory.targets() + ["all"])
    p.add_argument("--program", default=None)
    p.add_argument("--ai", action="store_true")
    p.add_argument("--adjudicate", action=argparse.BooleanOptionalAction,
                   default=True, help="decision-model checks of app candidates")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("patch")
    p.add_argument("target", choices=inventory.targets())
    p.add_argument("--program", default=None)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--policy", action="store_true",
                   help="with --apply: run only what the automation "
                        "policy allows")
    p.set_defaults(fn=cmd_patch)
    p = sub.add_parser("mcp")
    p.set_defaults(fn=cmd_mcp)
    p = sub.add_parser("swarm")
    p.add_argument("--json", action="store_true")
    p.add_argument("--assess", action="store_true",
                   help="add the AI assessment + cluster verdict")
    p.add_argument("--act", default=None,
                   help="freeze:PID | resume:PID | kill:PID")
    p.add_argument("--mark", default=None,
                   help="friendly:PID | hostile:PID — teach the shield "
                        "a program's verdict (remembered per program)")
    p.add_argument("--confirm", default=None,
                   help="actions require --confirm DEFEND")
    p.set_defaults(fn=cmd_swarm)
    p = sub.add_parser("charter")
    p.set_defaults(fn=cmd_charter)
    p = sub.add_parser("policy")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_policy)
    p = sub.add_parser("watch")
    p.add_argument("target", nargs="?", default=None,
                   choices=inventory.targets() + [None])
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=float, default=None,
                   help="hours between cycles (default: policy value)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_watch)
    p = sub.add_parser("cve")
    p.add_argument("cve_id")
    p.set_defaults(fn=cmd_cve)
    p = sub.add_parser("status")
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("models")
    p.set_defaults(fn=cmd_models)
    p = sub.add_parser("hosts")
    p.set_defaults(fn=cmd_hosts)
    p = sub.add_parser("gui")
    p.add_argument("--port", type=int, default=8770,
                   help="port for the local GUI (127.0.0.1 only)")
    p.add_argument("--no-open", action="store_true",
                   help="don't open the GUI in a browser")
    p.set_defaults(fn=cmd_gui)
    p = sub.add_parser("settings")
    p.add_argument("--port", type=int, default=8765,
                   help="port for the local settings page (127.0.0.1 only)")
    p.set_defaults(fn=cmd_settings)
    p = sub.add_parser("setup")
    p.add_argument("--server", default=None, help="model server base URL")
    p.add_argument("--triage", default=None, help="triage model id ('' = auto)")
    p.add_argument("--decision", default=None, help="decision model id")
    p.add_argument("--decision-fallback", default=None)
    p.add_argument("--provider", default=None,
                   choices=["lmstudio", "ollama", "llamacpp", "vllm", "openai", "custom"],
                   help="provider preset for the model server URL")
    p.add_argument("--decision-protocol", default=None,
                   choices=["auto", "decisions", "systemone", "chat"],
                   help="decision wire: auto tries /v1/decisions then /v1/systemone")
    p.add_argument("--api-key", default=None,
                   help="API key for the model server ('' clears it)")
    p.add_argument("--add-host", action="append", default=None,
                   metavar="name:os:user@host[:port]",
                   help="define a machine to scan (repeatable)")
    p.add_argument("--yes", action="store_true",
                   help="non-interactive: save given values without prompts")
    p.set_defaults(fn=cmd_setup)
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        # Bare `aishield` in a terminal: banner + live status + usage.
        print(BANNER)
        try:
            cmd_status(args)
        except Exception as e:
            print(f"(status unavailable: {str(e)[:100]})")
        print()
        print(USAGE)
        return
    args.fn(args)


if __name__ == "__main__":
    main()
