# AI Shield 🛡️

A defensive CVE scanner + patcher for a small home fleet (Linux VM, Mac Studio,
two Windows PCs), built around **CVE Now** for the latest vulnerabilities,
**CISA KEV** for known-exploited status, **OSV** for deterministic
version-range matching and fixed versions, and a **local LLM in LM Studio**
as the reasoning layer. Ships as a CLI and an MCP server.

## Why it's built this way

- **Verdicts are deterministic.** Whether you're affected is decided by OSV's
  version-range data and CVE Now's synced catalog — never by the LLM. The AI
  explains, prioritizes, and adjudicates fuzzy product matches; it does not
  guess at affectedness.
- **Three independent sources, cross-checked.** CVE Now (`check_stack`),
  OSV (`querybatch`), and the CISA KEV catalog. A finding lists its sources.
- **Apps are watched against KEV by product name**, with token-precise
  matching (no substring false positives) and optional AI adjudication.
  Unconfirmed name matches never enter the auto patch plan.
- **Patching is gated.** Plans are dry-run by default. Applying requires an
  explicit confirm (`--apply` / `confirm="PATCH"`), every action is logged
  with before/after versions, and a re-scan verifies the fix landed.
- **The AI layer never loads a model.** It uses whatever is already loaded
  in LM Studio; if nothing suitable is loaded, the shield runs without it. Point it at your instance with `AISHIELD_LM_URL` (default `http://localhost:1234`).

## Quick start

```sh
bin/aishield status                      # feeds + AI layer health
bin/aishield latest --source critical    # newest critical CVEs (CVE Now)
bin/aishield latest --source kev         # newest known-exploited (KEV feed)
bin/aishield cve CVE-2026-111497         # merged detail: CVE Now + KEV + NVD
bin/aishield scan vm                     # scan this machine
bin/aishield scan mac --ai               # scan the Mac + LM Studio brief
bin/aishield scan mac --program chrome   # one program only
bin/aishield scan all                    # the whole fleet
bin/aishield patch mac                   # dry-run patch plan
bin/aishield patch mac --apply           # execute the auto plan, then re-scan
```

Targets: `vm` (local), `mac`, `batman`, `grievous` (over the fleet's SSH
wrappers). Collectors cover apt (by source package, full distro versions —
that's what OSV's Ubuntu index is keyed on), pip, npm, Homebrew, macOS apps,
and Windows installed programs (registry).

## MCP server

```sh
python3 -m aishield.mcp_server   # stdio JSON-RPC
```

Tools: `latest_cves`, `cve_detail`, `scan_target`, `patch_plan`,
`patch_apply` (requires `confirm="PATCH"`), `shield_status`.

Register it with Hermes / any MCP client as a stdio server with
command `python3 -m aishield.mcp_server` and cwd set to this repo.

## Layout

- `aishield/cvenow.py` — CVE Now MCP client (stateless JSON-RPC over HTTPS)
- `aishield/feeds.py` — KEV catalog, OSV batch + cached details, NVD enrichment
- `aishield/inventory.py` — per-OS collectors (local + SSH)
- `aishield/match.py` — matching engine (packages + KEV app watch)
- `aishield/ai.py` — LM Studio reasoning layer (loaded models only)
- `aishield/patch.py` — patch plans, gated apply, patch log
- `aishield/engine.py` — scan orchestration + report formatting
- `aishield/cli.py`, `aishield/mcp_server.py` — the two front doors
- `data/` — KEV cache, OSV detail cache, patch log

## Known limits (v0.1)

- OSV distro indexes are keyed by source package; a handful of binary-only
  packages can be missed.
- KEV carries no version ranges, so app findings are *candidates* — the
  installed version may already be fixed. Adjudication (`--adjudicate`)
  uses the local model to confirm product identity.
- Windows patching is report-only in v0.1 (inventory + findings work;
  winget automation is on the roadmap).
