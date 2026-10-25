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

## How it works

One engine, three front doors (CLI, GUI, MCP server) — they all run
the same pipeline:

1. **Inventory.** Per-OS collectors list what's installed: apt/dpkg
   (by *source* package with full distro versions), pip (recording the
   exact interpreter each environment belongs to), npm globals,
   Homebrew formulas/casks, macOS `/Applications`, and Windows
   installed programs from the registry. Collection runs on the
   machine itself for `local`, or over the built-in ssh transport for
   enabled remote machines.
2. **Matching (deterministic).** Packages are matched server-side
   against **OSV** version ranges (`querybatch`, chunked), cross-checked
   with **CVE Now** `check_stack`, and overlaid with the **CISA KEV**
   catalog (known-exploited). Installed apps, which have no package
   ecosystem, are name-matched against KEV with token-precise rules —
   never substring matching — so "7-Zip" can't false-positive on
   unrelated names. Two more AI-friendly sources ride along:
   **pwn.watch** live incidents (stamped onto proven findings, plus
   name-match candidates that clear only at/past the published fix
   on the same major line) and curated **disclosure advisories**
   for vulnerabilities published with no CVE and no vendor fix
   (a finding fires only on a version the source actually tested;
   the planner never offers an upgrade for one). Every finding
   cites its sources; a feed outage degrades to a *warning on the
   scan*, never a fake finding.
3. **Ranking.** Known-exploited first, then severity and fix
   availability, deduplicated across sources.
4. **Patch planning.** One step per package to the highest fixed
   version, with the correct route per manager (apt upgrade, pip via
   the *inventoried* interpreter, `brew upgrade`, vendor/app-store
   notes for the rest). Plans are dry-run by default.
5. **Gated apply.** Applying needs an explicit confirm (`--apply`,
   `confirm="PATCH"`, or typing PATCH in the GUI). Order of authority:
   deterministic **lifeline rules** hold critical packages (kernel,
   SSH, package manager, container runtimes) before anything else is
   consulted; the **decision layer** then safety-checks each remaining
   auto step; held steps are never auto-applied. Every action is
   logged, a post-patch **re-scan verifies** the fix landed (the
   rescan, not the exit code, is the source of truth), `pip check`
   surfaces pin conflicts, and a **PDF report** of the run lands in
   `data/reports/`.

## Hermes plugin

Hermes agents can drive the shield through the plugin in
`integrations/hermes-plugin/` — see its README for install
(`hermes plugins install … --enable`). It exposes `aishield_status`,
`aishield_scan`, `aishield_patch_plan`, `aishield_patch_apply`
(gated by the same `PATCH` confirmation), `aishield_latest` and
`aishield_cve`, and registers a skill with the safety rules
(scan before patching, never invent the confirmation, trust the
rescan).

## How the AI works

The AI is a reasoning layer over the deterministic results — it
**never decides whether a version is vulnerable**. That is always
OSV/CVE Now data. It has two swappable roles, both configured (never
hardcoded) via the wizard, the settings page/GUI, config files, or
env vars:

- **Main (triage) model** — any chat model on your OpenAI-compatible
  server. Writes the scan brief (`--ai` / GUI): what is exposed, what
  an attacker gets, the exact fix, what can wait. Also serves as the
  decision fallback (below).
- **Decision model** (optional) — makes the two judgment calls a scan
  needs:
  1. *Adjudication:* app findings start as name-match **candidates**
     (KEV has no version ranges). The decision layer answers "is this
     installed app the product the KEV entry refers to?" — unconfirmed
     candidates never enter the auto patch plan.
  2. *Patch-step safety:* each auto step gets allow/hold. When in
     doubt, hold.

  Three ways to answer, picked by the `protocol` setting (default
  `auto`): **`/v1/decisions`** — the OpenAI-compatible decisions
  endpoint (LM Studio 0.4.26+ serves it natively for decision-typed
  models; questions are `predicate`/`choice`, answers carry
  probabilities, zero output tokens); **`/v1/systemone`** — the Jev
  wire (LM Studio 0.4.26+ and Ollama serve it; `{model, state,
  questions}` → calibrated probabilities, thresholds yes ≥ 0.75 /
  no ≤ 0.30; upstream is superseding it with `/v1/decisions`, so
  `auto` tries decisions first); otherwise the same questions go to
  the **main chat model** with a strict one-word answer format.

Safety properties: the layer is **fail-open** (no answer → no
decisions, scans proceed; a circuit breaker mutes it for 60 s after a
connection failure so a down server can't tax every step), lifeline
holds fire **before and regardless of** any AI answer, and the shield
**never loads a model** — it only uses models your server already
serves. Prompts carry only the finding data, and they go only to the
server *you* configured.

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

## Swarm tab — rogue agent detection & defense

The desktop GUI's **Swarm** tab runs a census of the local machine:
agent-like processes scored by signals (agent frameworks, browser
automation, child fan-out, distinct endpoints, LLM-API traffic),
clustered into candidate swarms (shared endpoints, one parent,
identical worker command lines), with the owner's own agents
recognized via an allowlist (`config/swarm.local.yaml`). The AI
layer writes an assessment and a typed verdict on the largest
cluster. Defense is owner-fired and on-machine only: **freeze**
(SIGSTOP, reversible), **resume**, **kill**, an endpoint blocklist
that marks talkers hostile, evidence snapshots and an incident log.
System processes and the shield itself are protected. CLI:
`aishield swarm [--assess]`; agents can read the census via the
MCP `swarm_scan` tool — actions stay with the owner.

## For agents (MCP / CLI / plugins)

Scans are free for any agent. Patching is governed, on purpose:

- **The agent charter** ships with the shield and binds any agent
  using it: owner has the final say, patching needs the owner's
  explicit approval (or their automation policy), and **all shield
  data is the owner's confidential security data — reported to the
  owner only, never shared with third parties**. Full text:
  `aishield charter` or docs/AGENT-CHARTER.md. The MCP server sends
  the charter to every client in its `initialize` response.
- **Automation policy** (GUI Settings → Automation policy, or
  `config/policy.local.yaml`; template in
  `config/policy.example.yaml`, defaults fully off): when the owner
  enables it, agents may run `auto_defend` (MCP) / `aishield watch`
  cycles that scan and apply only what the policy allows —
  safety-check `allow` required, name-match candidates withheld
  unless allowed, lifelines never — writing the usual report every
  cycle.
- **LM Studio**: add to `mcp.json`:
  `{"mcpServers": {"aishield": {"command": "python3", "args": ["-m",
  "aishield.mcp_server"], "cwd": "/path/to/aishield"}}}` — or simply
  `"command": "/path/to/aishield/bin/aishield", "args": ["mcp"]`.

## MCP server

```sh
python3 -m aishield.mcp_server   # stdio JSON-RPC
```

Tools (13): `latest_cves`, `cve_detail`, `scan_target`, `patch_plan`,
`patch_apply` (requires `confirm="PATCH"`), `shield_status`,
`swarm_scan`, `swarm_act` / `swarm_mark` (require `confirm="DEFEND"`),
`automation_policy`, `auto_defend`, `netwatch_scan`,
`netwatch_block` (requires `confirm="BLOCK"`).

Register it with any MCP client as a stdio server with command
`python3 -m aishield.mcp_server` and cwd set to this repo.

## Layout

- `aishield/cvenow.py` — CVE Now MCP client (stateless JSON-RPC over HTTPS)
- `aishield/feeds.py` — KEV catalog, OSV batch + cached details, NVD enrichment, pwn.watch incidents
- `aishield/disclosures.py` — curated advisories for vulnerabilities with no CVE (version-exact)
- `aishield/transport.py` — built-in target transport (local + ssh)
- `aishield/inventory.py` — per-OS collectors
- `aishield/match.py` — matching engine (packages + KEV app watch + pwn.watch + disclosures)
- `aishield/ai.py` — reasoning layer (triage + decision roles)
- `aishield/patch.py` — patch plans, gated apply, patch log
- `aishield/report.py` — dependency-free PDF run reports
- `aishield/engine.py` — scan orchestration + report formatting
- `aishield/gui.py` — the desktop-style GUI (local web app, stdlib only)
- `aishield/settings.py` — the local settings page (stdlib only)
- `aishield/swarm.py` — rogue-agent census + owner-fired defense
- `aishield/netwatch.py` — network intrusion watch (sensors, canaries, blocklist)
- `aishield/policy.py`, `aishield/approvals.py` — automation policy + owner approvals
- `aishield/agent_charter.py` — the rules binding any agent using the shield
- `aishield/cli.py`, `aishield/mcp_server.py` — the two front doors
- `tests/` — runnable suites (`python3 tests/test_*.py`) + MCP end-to-end (`tests/mcp_e2e.py`)
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

- **0.17.6 (dev)** — hardening & fix pass: `latest` (CLI/MCP/GUI) shares
  one implementation with KEV fallback when CVE Now is unreachable;
  OSV outages degrade to a scan warning instead of killing the scan;
  every KEV product match is reported and version-checked on its own
  (a cleared old CVE no longer hides an affecting new one); npm
  globals and multi-version brews are actually collected (both
  parsers silently dropped them); pwn.watch candidates stop
  false-positive matching on 3-letter and generic fragments
  ("cli" flagged every *-cli tool); patch commands refuse shell
  metacharacters (hostile names become manual steps); API keys are
  masked everywhere agents can see them; owner-specific netwatch
  ports and swarm names moved out of shipped source into untracked
  local config; six runnable test suites, all green, MCP E2E 9/9.
- **0.17.3–0.17.5 (dev)** — new sources + netwatch sensors: pwn.watch
  live-incident overlay on proven findings plus name-match
  candidates with same-major-line clearance; curated disclosure
  advisories for vulnerabilities with no CVE and no fix
  (version-exact matches only, never a patch offer); netwatch
  probe sensors — scan-shape detection over sampler history,
  canary listeners, widened service ports — with tests.
- **0.17.2 (dev)** — GUI target pickers keep their selection across
  refreshes; changing the patch target reloads the plan, changing
  the scan target resets the scan state.
- **0.17.1 (dev)** — KEV name-matches stop mismatching modifiers: a
  lone word matching only the product's first token ("ruby" in
  "Ruby on Rails") stands only with vendor corroboration, otherwise
  it's recorded as cleared with the reason stated.
- **0.17.0 (dev)** — GUI overhaul: grouped sidebar navigation,
  a status topbar (version · targets · KEV date), a calmer flat
  design system (softer contrast, denser tables, no glare),
  toast notifications for patch completions, blocks and saves,
  and full keyboard-focus + reduced-motion support. Every view
  and control from before, restyled.
- **0.16.2 (dev)** — Homebrew-owned packages patch too: plan
  building detects pip packages that Homebrew actually owns
  (pip can't update them — no RECORD) and turns them into
  `brew upgrade <formula>` steps; an apply-time rescue retries
  via brew if a step still lands blocked. Netwatch went remote
  in 0.16.1 (watch/block on any target over SSH; faster local
  census).
- **0.16.0 (dev)** — remote patching that actually patches +
  Netwatch. Windows targets patch for real now: scans collect
  winget package ids (and available versions), so confirmed Windows
  findings become winget upgrade steps the Patch page / CLI / MCP
  can run over SSH — previously every Windows app was manual-only.
  The Patch page runs patches as a background job with a **live
  streaming log**, a persistent result banner, a **downloadable
  log**, and a PDF — no more silent blocking request that wiped
  its own confirmation. New **Netwatch** tab: sources probing or
  attacking the machine, tracked from auth logs, live connections
  and an optional 60-second sampler, geolocated and plotted on a
  map (OpenStreetMap), blockable at the firewall from a shield
  blocklist (pf / iptables / Windows Firewall scripts generated;
  your own tailnet/LAN can never be blocked). AI assessment
  included. MCP + Hermes plugin gain `netwatch_scan` /
  `netwatch_block` (13 tools), the agent charter gains the
  Netwatch rules, and the Hermes plugin registration is rewritten
  (it silently dropped every tool past the original six).
- **0.15.2 (dev)** — swarm defense for agents: MCP `swarm_act` /
  `swarm_mark` and Hermes plugin equivalents join the read-only
  census. Rails: confirm DEFEND; census members only; agents can't
  kill FRIENDLY processes or mark anything friendly (trust is the
  owner's declaration); charter gains a swarm-defense section.
- **0.15.1 (dev)** — Swarm verdicts made unmissable: exactly three
  classes — **FRIENDLY** (identified as yours: allowlist, owner
  process lineage, app path), **UNKNOWN** (agent-like, no owner
  match), **ENEMY** (you marked it hostile, it talks to a blocked
  endpoint, or the AI judged the program rogue — verdicts are
  remembered per program). Every row says why in plain words, and
  *It's mine* / *Mark hostile* buttons teach the shield per program.
- **0.15.0 (dev)** — Swarm tab: rogue agent swarm detection
  (process/network census, signal scoring, clustering, friendly
  allowlist, endpoint blocklist) and defense (freeze/resume/kill
  behind a DEFEND confirm, evidence snapshots, incident log) +
  AI assessment with a typed cluster verdict. MCP `swarm_scan`
  (read-only for agents), `aishield swarm` CLI.

- **0.14.0** — automation policy for agents (owner's standing
  orders: GUI Settings editor, `aishield policy`, config template;
  MCP `auto_defend` / `aishield watch` cycles apply only what the
  policy allows, every withheld step explained; defaults off) +
  the agent charter (privacy: shield data to the owner only;
  approval protocol; owner-final-say; detailed reporting) shipped
  in docs, `aishield charter`, the MCP initialize instructions and
  the Hermes plugin skill. MCP grows to 8 tools; `aishield mcp`
  subcommand added.

- **0.13.0** — owner approvals for held steps. Every "needs you"
  item in the Patch page now offers **Approve & patch** (when a
  patch command exists for it) or **Acknowledge** (stop listing it
  as needing you). Approvals are recorded per finding
  (data/approvals.json) and honored by every surface — GUI, CLI and
  MCP all build plans through the same code. An approved candidate
  still faces the AI safety check; approving a step the check
  already held is the owner's explicit override. Two things no
  approval can do: lift a lifeline hold, or invent a patch command
  for app-store software. Every approval can be undone.

- **0.12.2** — the Patch page reads like a patch page now: it opens
  with "N ready to patch · M need you", plain-language cards (what,
  from → to, how, the exact command), one big **Patch now** button
  with the typed PATCH as a framed last check, and card-style results
  (with AI diagnoses and the report link) instead of a raw JSON dump.
  The plan loads itself when the page opens.
- **0.12.1** — hardening of the 0.12.0 AI paths: flat-object JSON
  parsing for model replies, verdict normalization, transient-error
  tolerance in narrative calls, and a missing-import fix.
- **0.12.0** — AI in the backend, not just the glass: patch runs
  generate their narrative summary inside the report writer itself
  (PDF, sidecar, GUI and MCP all carry the same text); failed or
  blocked patch steps get an **AI diagnosis** (cause + next action,
  from the step's own output) stamped into the outcome, the log and
  the report; scans are **persisted and diffed** (data/scans/ —
  every scan reports what's new and what resolved since the last
  one); and KEV name-matches with no published version data anywhere
  get an advisory **AI era stamp** (likely-stale / plausible /
  unknown) so stale noise is recognizable — the stamp never clears
  or confirms a finding.

- **0.11.2** — narrative AI calls (explain / summary / ask) retry
  with a larger token budget when a reasoning model spends the first
  budget thinking and returns empty content.
- **0.11.1** — name-matches stop crying wolf: a KEV candidate whose
  installed version is provably outside the CVE's published affected
  range (NVD CPE version windows, OSV fixed versions as fallback) is
  cleared at scan time and reported as cleared, instead of reappearing
  after every patch forever. Patch reports now annotate each remaining
  finding (patched in this run / held / blocked / not in plan) and say
  why patched items can still be listed. AI narrative calls fall back
  to the configured main model when no chat model is loaded.
- **0.11.0** — AI woven through the app (grounded, never in charge):
  per-finding **Explain** buttons and an automatic plain-English
  panel on CVE lookup (cached; fed only the KEV/CVE Now record and
  what's installed, and it calls out likely stale name-matches);
  **AI run summaries** in Reports (generated once, stored with the
  run); and a new **Ask** view — questions answered strictly from
  your shield's own data (last scan, patch log, reports), with an
  explicit "not in the data" when it isn't. Matching and patching
  stay deterministic, exactly as before.
- **0.10.5** — Interactive reports: every patch run now writes a
  structured JSON twin next to its PDF, and the GUI gains a Reports
  view — browse runs, read findings-before/after, per-step results
  with expandable command output, all in the app (PDF still linked).
  Scan results are filterable (text + KEV-only) and click through
  to CVE lookup; the patch apply output leads with a human summary
  line instead of raw JSON.
- **0.10.4** — Caching so a dead feed stops breaking pages: every
  CVE Now call (feed, lookup, stack check) is cached on disk and an
  outage serves the last cached answer instead of an exception; the
  KEV catalog likewise falls back to its stale file when a refresh
  fails. Status reporting stays honest — the dashboard distinguishes
  reachable / unreachable-but-cached / unreachable-no-cache, and the
  one warning a scan still prints is a human sentence, not a raw
  HTTP stack trace.
- **0.10.3** — Dashboard rebuilt with real detail (AI-layer panel,
  feeds & system panel, per-target scan states, recent patch
  activity from the log, newest KEV entries that click through to
  lookup, downloadable PDF reports). Latest CVEs: KEV now comes
  from the local catalog, and the CVE Now sources fall back to it
  with a visible warning when the service is unreachable (on some
  networks the page was simply empty). Local command execution now
  augments PATH with the Homebrew locations — a service-launched
  shield could collect brew packages but not run `brew upgrade`
  (rc 127). Pip copies installed by Homebrew are reported as
  blocked-brew-owned instead of a generic failure.
- **0.10.2** — "when I tell it to patch, it patches": plan_for gated
  adjudicated findings on a marker string ("AI-confirmed") that the
  adjudicator never writes (it writes "confirmed by <via> model"), so
  every AI-confirmed app/brew finding was held as manual forever.
  The gate now reads the structured verdict. And a pip step refused
  by PEP 668 (externally-managed environment) retries once with
  --break-system-packages — an apply only runs under an explicit
  human PATCH confirmation, which is the authorization for the
  override; the retry is stamped in the step result and the log.
- **0.10.1** — GUI settings fixes: the Save button was dead in the
  browser (a NodeList has no .map — the API worked, the page's save
  handler threw before posting; found by using the page, not the
  API). Settings gained the missing fields the standalone settings
  page already had (decisions endpoint, model-server proxy), host
  rows can be removed, saves preserve per-host fields the form
  doesn't render (e.g. identity), and a failed save now shows its
  error instead of failing silently.
- **0.10.0** — GUI redesign: glassmorphism theme — glossy bubble
  cards with sheen, gradient orbs, pill navigation with glow,
  glass-strip tables, toggle switches for every checkbox, gloss
  sweep buttons (the Apply button gets its own caution gradient).
  Same engine, same APIs, no dependencies.
- **0.9.1** — launcher hardening: `bin/aishield` now probes for the
  first Python that can import the shield's dependencies instead of
  trusting `python3` (sanitized environments — agent plugin hosts,
  cron, launchd — can resolve a bare interpreter without them; the
  Hermes plugin's first live agent call caught exactly that).
  `AISHIELD_PYTHON` overrides the choice.
- **0.9.0** — Hermes plugin (`integrations/hermes-plugin/`): six
  `aishield_*` agent tools (status, scan, patch plan, gated apply,
  latest, CVE lookup) plus a bundled skill with the safety rules.
  The plugin drives the installed CLI as a subprocess; applying
  still requires the explicit `PATCH` confirmation.
- **0.8.3** — patch-run hardening: a command timeout or transport
  failure is now a recorded failed step, never a silent run-killer
  (a 600 s `apt-get update` on a slow mirror once ended a run with
  no steps, log or report); the apt metadata refresh gets 1800 s
  and its failure surfaces in `env_warnings`.
- **0.8.2** — wizard consistency: the server-unreachable (manual
  entry) path now asks for the decision fallback and protocol too,
  not just the connected path.
- **0.8.1** — GUI fix: the Patch view read `plan.steps`, but the plan
  is a list — it rendered "0 steps" for every plan. Caught by an
  end-to-end pass over every surface.
- **0.8.0** — LM Studio decision endpoints: the decision layer speaks
  `/v1/decisions` (OpenAI-compatible, LM Studio 0.4.26+) in addition
  to the `/v1/systemone` Jev wire, selected by a new `protocol`
  setting (auto/decisions/systemone/chat) in the wizard, settings
  page and GUI; decision-typed models from the server's catalog are
  floated first in the wizard's picker.
- **0.7.1** — README: full "How it works" pipeline walkthrough and
  "How the AI works" section (roles, adjudication, decision
  thresholds, fail-open rules).
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
