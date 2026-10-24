"""AI Shield CLI.

  aishield latest [--source kev|critical|all] [--ecosystem pypi] [--limit 20]
  aishield scan <target> [--program NAME] [--ai] [--adjudicate] [--json]
  aishield patch <target> [--program NAME] [--apply] [--json]
  aishield cve <CVE-ID>
  aishield status
Targets: vm (this machine), mac, batman, grievous, all
"""
import argparse
import json
import sys

from . import ai, config as cfgmod, cvenow, engine, feeds, inventory, match, patch


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
    targets = inventory.TARGETS if args.target == "all" else [args.target]
    for t in targets:
        result = engine.run_scan(t, program=args.program, use_ai=args.ai,
                                 adjudicate_apps=args.adjudicate)
        if args.json:
            print(json.dumps(result, indent=1, default=str))
        else:
            print(engine.format_report(result))
            print()


def cmd_patch(args):
    result = engine.run_scan(args.target, program=args.program)
    if not args.apply:
        print(engine.format_report(result))
        print("\n(dry run — re-run with --apply to execute the auto patch plan)")
        return
    outcome = patch.apply_plan(result["plan"], confirm="PATCH")
    print(json.dumps(outcome, indent=1, default=str))
    after = engine.run_scan(args.target, program=args.program)
    still = [f for f in after["findings"] if f["confidence"] != "error"]
    print(f"\npost-patch rescan: {len(still)} findings remain "
          f"(was {len(result['findings'])})")


def cmd_cve(args):
    out = {"cvenow": None, "kev": None, "nvd": None}
    try:
        out["cvenow"] = cvenow.get_vulnerability(args.cve_id)
    except Exception as e:
        out["cvenow"] = {"error": str(e)[:200]}
    kev_map, _ = feeds.kev()
    out["kev"] = kev_map.get(args.cve_id)
    out["nvd"] = feeds.nvd_cve(args.cve_id)
    print(json.dumps(out, indent=1, default=str))


def cmd_status(args):
    kev_map, kev_date = feeds.kev()
    models = ai.loaded_models()
    cfg = cfgmod.load()
    print(f"KEV catalog: {len(kev_map)} entries, released {kev_date}")
    print(f"model server: {cfg['server']['url']}")
    print(f"loaded models: {models or 'none reachable'}")
    print(f"triage role: {cfg['roles']['triage']['model'] or 'auto'} "
          f"-> {ai.triage_model(models) or 'offline'}")
    dec = cfg["roles"]["decision"]
    print(f"decision role: {dec['model']} (fallback {dec.get('fallback')}) "
          f"via {dec.get('endpoint')}")
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
    print(f"targets: {', '.join(inventory.TARGETS)}")


def cmd_models(args):
    cfg = cfgmod.load()
    print(json.dumps(cfg, indent=1))
    print(f"config file: {cfgmod.MODELS_YAML}")
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


def cmd_setup(args):
    cfg = cfgmod.load()
    if args.server:
        cfg["server"]["url"] = args.server.rstrip("/")
    if args.triage is not None:
        cfg["roles"]["triage"]["model"] = args.triage or None
    if args.decision is not None:
        cfg["roles"]["decision"]["model"] = args.decision or None
    if args.decision_fallback is not None:
        cfg["roles"]["decision"]["fallback"] = args.decision_fallback or None
    if not args.yes:
        print("AI Shield setup — pick the model server and the models for "
              "each role.\nEverything is swappable later: edit "
              "config/models.yaml, re-run setup, or use env vars.\n")
        cfg["server"]["url"] = _ask("model server URL (LM Studio or any "
                                    "OpenAI-compatible server)",
                                    cfg["server"]["url"]).rstrip("/")
        import aishield.ai as _ai  # probe with the new URL in-process
        os_url = cfg["server"]["url"]
        import os as _os
        _os.environ["AISHIELD_LM_URL"] = os_url
        loaded = _ai.loaded_models()
        if loaded:
            print(f"server reachable — {len(loaded)} models loaded")
            chat_opts = [(None, "auto — strongest loaded chat model")]
            chat_opts += [(m, m) for m in loaded if not m.lower().startswith("d1")
                          and "embed" not in m.lower()]
            chat_opts.append(("__custom__", "type a model id manually"))
            choice = _pick("triage model (writes the briefs):", chat_opts, 0)
            if choice == "__custom__":
                choice = _ask("triage model id") or None
            cfg["roles"]["triage"]["model"] = choice
            dec_opts = [(m, m) for m in loaded if m.lower().startswith("d1")]
            dec_opts += [(m, m) for m in loaded if not m.lower().startswith("d1")]
            dec_opts.append(("__custom__", "type a model id manually"))
            dec_opts.append((None, "none — disable the decision layer"))
            cur = cfg["roles"]["decision"]["model"]
            default_idx = next((i for i, (v, _) in enumerate(dec_opts)
                                if v == cur), 0)
            choice = _pick("decision model (typed checks via /v1/systemone):",
                           dec_opts, default_idx)
            if choice == "__custom__":
                choice = _ask("decision model id") or None
            cfg["roles"]["decision"]["model"] = choice
            fb = _ask("decision fallback model (blank = none)",
                      cfg["roles"]["decision"].get("fallback") or "")
            cfg["roles"]["decision"]["fallback"] = fb or None
        else:
            print("server not reachable right now — saving anyway; "
                  "you can set model ids by name.")
            tri = _ask("triage model id (blank = auto)",
                       cfg["roles"]["triage"]["model"] or "")
            cfg["roles"]["triage"]["model"] = tri or None
            dec = _ask("decision model id (blank = disable)",
                       cfg["roles"]["decision"]["model"] or "")
            cfg["roles"]["decision"]["model"] = dec or None
    path = cfgmod.save(cfg)
    print(f"\nsaved: {path}")
    print(json.dumps(cfg, indent=1))
    verdict, p, used = ai.decide_noul(
        "A test probe: the sky is blue on a clear day.",
        "Is the sky blue on a clear day? 'yes' means it is blue.")
    layer = (f"answering as {used} (p_yes={p})" if verdict
             else "not answering (fail-open — scans still work)")
    print(f"decision layer: {layer}")
    tri = ai.triage_model() or "offline (no chat model loaded)"
    print(f"triage layer: {tri}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aishield")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("latest")
    p.add_argument("--source", choices=["kev", "critical", "all"], default="critical")
    p.add_argument("--ecosystem", default=None)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_latest)
    p = sub.add_parser("scan")
    p.add_argument("target", choices=inventory.TARGETS + ["all"])
    p.add_argument("--program", default=None)
    p.add_argument("--ai", action="store_true")
    p.add_argument("--adjudicate", action=argparse.BooleanOptionalAction,
                   default=True, help="decision-model checks of app candidates")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("patch")
    p.add_argument("target", choices=inventory.TARGETS)
    p.add_argument("--program", default=None)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_patch)
    p = sub.add_parser("cve")
    p.add_argument("cve_id")
    p.set_defaults(fn=cmd_cve)
    p = sub.add_parser("status")
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("models")
    p.set_defaults(fn=cmd_models)
    p = sub.add_parser("setup")
    p.add_argument("--server", default=None, help="model server base URL")
    p.add_argument("--triage", default=None, help="triage model id ('' = auto)")
    p.add_argument("--decision", default=None, help="decision model id")
    p.add_argument("--decision-fallback", default=None)
    p.add_argument("--yes", action="store_true",
                   help="non-interactive: save given values without prompts")
    p.set_defaults(fn=cmd_setup)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
