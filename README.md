# AI Shield 🛡️

A defensive CVE scanner + patcher for a small home fleet (Linux VM, Mac Studio,
two Windows PCs), built around **CVE Now** for the latest vulnerabilities,
**CISA KEV** for known-exploited status, **OSV** for deterministic
version-range matching and fixed versions, and a **local LLM in LM Studio**
as the reasoning layer. Ships as a CLI and an MCP server.

## Install

```sh
git clone https://github.com/Franzferdinan51/AIShield && cd AIShield
ln -s "$PWD/bin/aishield" /opt/homebrew/bin/aishield   # macOS; or ~/.local/bin on Linux
# — or, from the clone:  pip install -e .   (registers the `aishield` command)
aishield            # bare run: banner + live status + usage
aishield setup      # point it at your model server + models
```

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
  in LM Studio; if nothing suitable is loaded, the shield runs without it.
- **Every AI role is swappable — nothing is hardcoded.** A setup wizard
  (`aishield setup`) lets you point the shield at any model server
  (LM Studio or any OpenAI-compatible endpoint) and pick the model for
  each role; choices live in `config/models.yaml` and can be overridden
  by env vars (`AISHIELD_LM_URL`, `AISHIELD_TRIAGE_MODEL`,
  `AISHIELD_DECISION_MODEL`). Upgrade or replace a model by editing one
  file — no code changes.
- **A decision model checks while scanning.** The `decision` role (any
  model family served on the SystemOne wire, `POST /v1/systemone` —
  typed noul/choice questions with calibrated probabilities) adjudicates
  app name-match candidates and safety-checks every auto patch step.
  Deterministic lifeline rules (kernel, SSH, Tailscale, Docker, the
  package manager…) hold critical packages before the AI is even asked,
  and a held step is never auto-applied. The decision layer fails open:
  no answer, no decisions — scans still work. Point it at your instance with `AISHIELD_LM_URL` (default `http://localhost:1234`).

## Quick start

```sh
bin/aishield setup                       # wizard: set model server + models
bin/aishield models                      # show current model configuration
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

## Changelog

- **0.3.0** — end-to-end hardening pass: decision-layer circuit breaker
  (a down model server no longer taxes scans), fail-soft AI brief and
  adjudication fallbacks, `cve` reports an explicit not-found, version
  surfaced in status/MCP, wizard warns before saving a private server
  address, MCP end-to-end test in `tests/mcp_e2e.py`.
- **0.2.0** — swappable AI roles (`config/models.yaml` + `aishield setup`
  wizard + env overrides); decision-model checks during scans
  (candidate adjudication + patch-step safety decisions + lifeline holds).
- **0.1.0** — initial release: KEV + OSV + CVE Now scanning, gated patching,
  CLI + MCP.
- **0.4.0** — `aishield` is now the terminal command: bare run shows banner +
  live status + usage, `--version` added, pyproject packaging with a
  console entry point (`pip install -e .` registers `aishield` on PATH).
- **0.4.1** — self-host fix: scanning/patching the machine the shield itself
  runs on (e.g. `aishield scan mac` on the Mac, which is also what Batman's
  launcher reaches) no longer routes through the VM-side ssh wrappers that
  don't exist there; self-targets collect and patch locally, missing
  wrappers produce a clean error instead of a traceback.
- **0.4.2** — collector/patcher interpreter agreement: pip findings now
  carry the exact interpreter that was inventoried, and patch steps use
  it (a bare `python3` at patch time could resolve to a different
  environment — e.g. an agent's pinned venv — than the one scanned).
  `apply` also runs `pip check` afterwards and reports pin conflicts.
- **0.4.3** — every `patch --apply` run now writes a PDF summary report
  (scan before, applied/held/manual steps, pip-check result, post-patch
  rescan) to `data/reports/`, rendered by a small dependency-free PDF
  writer (`aishield/report.py`).
