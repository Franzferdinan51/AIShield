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

from . import ai, cvenow, engine, feeds, inventory, match, patch


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
    print(f"KEV catalog: {len(kev_map)} entries, released {kev_date}")
    print(f"LM Studio loaded models: {models or 'none reachable'}")
    print(f"AI layer: {ai.pick_model(models) or 'offline (no suitable model loaded)'}")
    try:
        feed = cvenow.list_feed(filter=["critical"], limit=1)
        print("CVE Now: reachable")
    except Exception as e:
        print(f"CVE Now: unreachable ({str(e)[:120]})")
    print(f"targets: {', '.join(inventory.TARGETS)}")


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
    p.add_argument("--adjudicate", action="store_true")
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
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
