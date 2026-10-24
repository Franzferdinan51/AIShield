# Research notes — what the field does, and what AI Shield took from it

Surveyed 2026-10-24 (GitHub + vendor docs): Vuls, Grype, Trivy, osv-scanner,
OpenSCAP, Lynis, Wazuh, patchman, plus the CVE data APIs.

## The consensus architecture (which we follow)

- **Match packages against per-ecosystem / per-distro feeds, not raw NVD.**
  Grype/Trivy are accurate because their DBs are built from distro security
  trackers (Ubuntu USN, Debian Security Tracker, Alpine secdb) + GHSA.
  Raw NVD CPE matching without distro data produces backport false positives
  — the classic failure mode. AI Shield queries OSV's Ubuntu index with the
  *source* package name and *full distro version*, which is that same distro
  data, so fixed-version comparisons are backport-aware.
- **NVD is an enrichment source, not a matcher.** We use it (and CVE Now's
  SSVC fields) for description/CVSS context only.
- **Nobody credible auto-patches blindly.** The tools that remediate
  (Wazuh+Ansible, Vuls' companion workflows) gate on approval, snapshot, and
  verify after. AI Shield: dry-run plans by default, explicit confirm token,
  patch log with before/after versions, automatic post-patch re-scan.
- **osv-scanner proved the OSV `querybatch` pattern** (one call, whole
  inventory, server-side range matching). We use it as the primary matcher.
- **KEV + EPSS-style prioritization beats raw CVSS.** CVE Now exposes CISA
  SSVC decision points; KEV membership is our top sort key.

## Adopted in v0.1

- OSV querybatch for package ecosystems + distro indexes (Ubuntu by source
  package + full version) — deterministic verdicts, fixed versions included.
- CVE Now as a first-class source: `list_feed` for latest CVEs,
  `get_vulnerability` for SSVC-rich detail, `check_stack` as an independent
  second matcher (chunked; distro ecosystems excluded — it rejects them).
- KEV overlay for known-exploited ranking + app/product watching.
- A reasoning layer restricted to models the user's server already
  serves: triage briefs, product-identity adjudication for name-match
  candidates. The LLM never decides affectedness for packages.
- Gated patching with rescan verification (above).

## On the roadmap (from the research)

- Trivy/Grype cross-check mode for container images and language lockfiles
  (Grype's `relatedVulnerabilities`/match-type data is a good confidence
  signal). Note: verify scanner provenance before trusting one.
- EPSS scores in ranking alongside KEV.
- Snapshot/rollback integration (Timeshift/APFS/Restore Points) before apply.
- Winget-based patching for Windows apps.
- Scheduled scans with report delivery.
