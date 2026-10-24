# AI Shield — Hermes plugin

Gives Hermes agents the `aishield_*` tools (status, scan, patch
plan, gated patch apply, latest CVEs, CVE lookup) plus an
`aishield` skill with the safety rules.

The plugin drives the installed AI Shield CLI as a subprocess, so
[install AI Shield](https://github.com/Franzferdinan51/AIShield)
first. It finds the shield via `$AISHIELD_HOME`, then `~/aishield`,
then `aishield` on PATH.

## Install

```sh
hermes plugins install https://github.com/Franzferdinan51/AIShield/tree/main/integrations/hermes-plugin --enable
```

or copy this directory to `~/.hermes/plugins/aishield/` and run
`hermes plugins enable aishield`. Restart Hermes (or start a new
session) so the tools register.
