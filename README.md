# AI Shield 🛡️

A defensive CVE scanner + patcher you run on your own machines, built
around **CVE Now** for the latest vulnerabilities, **CISA KEV** for
known-exploited status, **OSV** for deterministic version-range matching
and fixed versions, and a **local (or any OpenAI-compatible) LLM** as
the reasoning layer. One self-contained program: a CLI and an MCP server
that install, scan, patch, and report with no companion tools.

## Install

```sh
git clone <this repo> && cd AIShield
pip install -e .          # registers the `aishield` command
# — or run it in place:  bin/aishield
aishield setup            # connect your model provider + pick models
aishield scan local       # scan this machine — works with zero config
```

## Desktop GUI (all platforms)

```sh
aishield gui        # opens the app in your browser
```

A Hermes-desktop-style interface — sidebar, dashboard, scan, patch,
latest CVEs, CVE lookup, settings — served by the program itself from
127.0.0.1 and opened in the machine's own browser. Same program, same
config, no extra install and no build step, so the identical GUI works
on **Windows, macOS and Linux**. The CLI and MCP server remain fully
supported front doors.

## Setup wizard

`aishield setup` walks you through it:

1. **Provider** — LM Studio, Ollama, llama.cpp, vLLM, OpenAI, or any
   custom OpenAI-compatible base URL. Optional API key for providers
   that need one (most local servers need none).
2. **Main model** — picked from the models your server actually lists
   (or `auto`). Writes the scan briefs and serves as the decision
   fallback.
3. **Decision model** (optional) — if your server exposes a typed
   decision endpoint (`POST /v1/systemone`-style calibrated answers),
   name its model; otherwise decisions use the main model.
4. **Machines** — `local` is always included; add more machines
   (name, OS, `user@host`) to scan them over ssh.

Settings save to untracked local config (`config/models.local.yaml`,
`config/hosts.local.yaml`) — API keys and private addresses never land
in version control.

**Later changes:** `aishield settings` serves a settings page on
http://127.0.0.1:8765 — edit the provider, API key, main/decision
models (with a live model list from your server) and the machine list
in your browser; it writes the same local config files. `aishield
models` and `aishield hosts` show the current configuration in the
terminal. Scripted setups work too:
`aishield setup --provider ollama --triage <model> --yes`, and every
value has an env override (`AISHIELD_LM_URL`, `AISHIELD_API_KEY`,
`AISHIELD_TRIAGE_MODEL`, `AISHIELD_DECISION_MODEL`,
`AISHIELD_HOST_<NAME>=user@host[:port]`).

## Why it's built this way

- **Verdicts are deterministic.** Whether you're affected is decided by
  OSV's version-range data and CVE Now's synced catalog — never by the
  LLM. The AI explains, prioritizes, and adjudicates fuzzy product
  matches; it does not guess at affectedness.
- **Three independent sources, cross-checked.** CVE Now (`check_stack`),
  OSV (`querybatch`), and the CISA KEV catalog. A finding lists its
  sources; a feed outage degrades to a warning, never a fake finding.
- **Apps are watched against KEV by product name**, with token-precise
  matching (no substring false positives) and optional AI adjudication.
  Unconfirmed name matches never enter the auto patch plan.
- **Patching is gated.** Plans are dry-run by default. Applying requires
  an explicit confirm (`--apply` / `confirm="PATCH"`), every action is
  logged, a re-scan verifies the fix landed, and a **PDF report** of the
  run is written to `data/reports/`.
- **Nothing about models is hardcoded.** No model names ship in the
  code or the committed config. Swap models by re-running the wizard or
  editing one file.
- **The AI layer never loads a model.** It uses models your server
  already serves; if none are reachable, the shield runs without it
  (fail-open).
- **Safety decisions while scanning.** The decision layer adjudicates
  app candidates and safety-checks every auto patch step.
  Deterministic lifeline rules (kernel/boot, SSH, the package manager,
  container runtimes — extensible per target via `lifeline_extra`) hold
  critical packages before the AI is even asked, and a held step is
  never auto-applied.
- **Targets are yours — and local by default.** The program ships with
  no built-in machines. A **this device** checkbox (wizard + settings
  page) controls scanning the machine the shield runs on, and remote
  machines are opt-in per machine: the shield is designed to run on
  each machine itself, not to sweep remotes. Collectors are per-OS
  (Linux, macOS, Windows) and run locally or over the program's own
  ssh transport.

## Quick start

```sh
aishield status                      # feeds + AI layer health
aishield latest --source critical    # newest critical CVEs (CVE Now)
aishield latest --source kev         # newest known-exploited (KEV feed)
aishield cve CVE-2026-111497         # merged detail: CVE Now + KEV + NVD
aishield scan local                  # scan this machine
aishield scan local --ai             # + an AI brief of the findings
aishield scan workstation            # a machine from your hosts config
aishield scan all                    # local + every configured machine
aishield patch local                 # dry-run patch plan
aishield patch local --apply         # execute the auto plan, re-scan, PDF report
aishield models                      # current model configuration
aishield hosts                       # current target configuration
```

Collectors cover apt (by source package, full distro versions — that's
what OSV's Ubuntu index is keyed on), pip (patch steps use the exact
interpreter that was inventoried), npm, Homebrew, macOS apps, and
Windows installed programs (registry).

## MCP server

```sh
python3 -m aishield.mcp_server   # stdio JSON-RPC
```

Tools: `latest_cves`, `cve_detail`, `scan_target`, `patch_plan`,
`patch_apply` (requires `confirm="PATCH"`), `shield_status`.

Register it with any MCP client as a stdio server with command
`python3 -m aishield.mcp_server` and cwd set to this repo.

## Layout

- `aishield/cvenow.py` — CVE Now MCP client (stateless JSON-RPC over HTTPS)
- `aishield/feeds.py` — KEV catalog, OSV batch + cached details, NVD enrichment
- `aishield/transport.py` — built-in target transport (local + ssh)
- `aishield/inventory.py` — per-OS collectors
- `aishield/match.py` — matching engine (packages + KEV app watch)
- `aishield/ai.py` — reasoning layer (triage + decision roles)
- `aishield/patch.py` — patch plans, gated apply, patch log
- `aishield/report.py` — dependency-free PDF run reports
- `aishield/engine.py` — scan orchestration + report formatting
- `aishield/gui.py` — the desktop-style GUI (local web app, stdlib only)
- `aishield/settings.py` — the local settings page (stdlib only)
- `aishield/cli.py`, `aishield/mcp_server.py` — the two front doors
- `config/` — committed templates + your untracked `*.local.yaml`
- `data/` — KEV cache, OSV detail cache, patch log, PDF reports

## Known limits

- OSV distro indexes are keyed by source package; a handful of
  binary-only packages can be missed.
- KEV carries no version ranges, so app findings are *candidates* —
  the installed version may already be fixed. Adjudication uses the
  configured models to confirm product identity.
- Windows patching is report-only (inventory + findings work; winget
  automation is on the roadmap).

## Changelog

- **0.7.0** — desktop GUI: `aishield gui` serves a Hermes-style web
  app (dashboard, scan, patch with gated apply + PDF reports, latest
  CVEs, CVE lookup, full settings) on 127.0.0.1 and opens it in the
  machine's browser — one program, every platform (Windows/macOS/
  Linux), no dependencies beyond the stdlib.
- **0.6.1** — scan-target checkboxes: 'this device' toggle plus a
  per-machine enable flag (remote scanning is opt-in, off by default)
  in the wizard and the settings page; config saves are atomic.
- **0.6.0** — works for anyone: no built-in fleet, no baked-in models.
  Targets are user-defined machines (name + OS) in local config;
  collectors dispatch by OS. The setup wizard covers providers
  (LM Studio, Ollama, llama.cpp, vLLM, OpenAI, custom), API keys, main
  + decision model selection from the server's live model list, and
  adding machines. A `aishield settings` web page (127.0.0.1) edits
  the same config later. Decisions fall back to the main chat model
  when no typed decision endpoint exists. Lifeline list is generic and
  extensible per target. All personal/deployment settings live in
  untracked `*.local.yaml` files.
- **0.5.0** — one self-contained program: built-in transport reaches
  targets over the OS ssh from the program's own host config; external
  wrapper scripts removed from every code path.
- **0.4.3** — every `patch --apply` run writes a PDF summary report to
  `data/reports/` (dependency-free writer).
- **0.4.2** — collector/patcher interpreter agreement: pip patch steps
  use the exact interpreter that was inventoried; `pip check` runs
  after applies and surfaces pin conflicts.
- **0.4.1** — self-host fix: scanning/patching the machine the shield
  runs on works locally instead of routing through remote wrappers.
- **0.4.0** — `aishield` terminal command: bare run shows banner +
  live status + usage; pyproject packaging with a console entry point.
- **0.3.0** — end-to-end hardening: decision-layer circuit breaker,
  fail-soft AI fallbacks, explicit not-found for unknown CVEs, MCP
  end-to-end test in `tests/mcp_e2e.py`.
- **0.2.0** — swappable AI roles (config + setup wizard + env
  overrides); decision-model checks during scans.
- **0.1.0** — initial release: KEV + OSV + CVE Now scanning, gated
  patching, CLI + MCP.
