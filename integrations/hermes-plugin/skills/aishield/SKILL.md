---
name: aishield
description: Use AI Shield to scan machines for CVEs and patch them safely.
---

# AI Shield

AI Shield is the vulnerability scanner/patcher installed on this
machine (CLI: `aishield`). The `aishield_*` tools wrap it.

## Rules

- **Scan before patching.** Run `aishield_scan` (or
  `aishield_patch_plan`) and show the user the findings and the plan
  before any apply.
- **Applying needs the user's explicit go-ahead.** Only call
  `aishield_patch_apply` with `confirm="PATCH"` after the user has
  seen the plan and agreed. Never invent the confirmation.
- **Held is by design.** Lifeline packages (kernel, SSH, package
  managers, container runtimes) and unconfirmed app name-matches are
  held or manual — report them, don't try to force them.
- **Trust the rescan.** After an apply, the post-patch rescan count
  is the truth about what got fixed, not any single exit code.
- **Local first.** `local` (this machine) is the default target;
  remote machines only appear when the user enabled them in the
  shield's config.
- Scans can take a few minutes on a cold cache; patch applies can
  take longer (apt metadata refresh). That's normal — wait for the
  tool result.
