# Sample policies — BYOP templates

> **Status: templates, not live policy.** Transit does not load
> user-supplied policies yet — Bring Your Own Policy ships in phases
> (see the scoped vendor policy and byop design notes (not included in this repository): Phase 2a
> adds the user policy directory for shipped vendors, Phase 2b adds
> custom vendors like the ones in this folder). Until then these files
> are documentation: vetted starting points for the vendors Transit
> doesn't ship, and worked examples of the policy schema.
>
> The runtime loader reads `policies/*.yaml` only and skips this
> subdirectory — pinned by `loader::tests::load_dir_ignores_subdirectories`
> (a dev build resolves the policies dir to this repo checkout, so a
> loadable file here would otherwise break startup). The release bundle
> glob (`tauri.conf.json` `bundle.resources`) likewise excludes it.

## Schema crash course

```yaml
mode: gated            # or `unrestricted` (modal-only; needs `warning:`)
precedence: block-wins # tiebreak when BOTH lists match (default-safe)
canonicalization:
  aliases: {}          # first-token contractions the CLI accepts
allowed: []            # head-command regexes (anchor with ^)
blocked: []            # head-command regexes — config/write/shell-escape
pipe_allowed: []       # per-stage regexes for `cmd | stage | stage`
pipe_blocked: []       # any stage that writes/escapes
```

Rules the gate applies (`transit_policy::engine`):

- **Default-deny.** A command matching nothing is refused. You only
  need `blocked:` for things that would otherwise match an `allowed:`
  pattern — and for high-value explicit denials you want named in the
  deny reason.
- **Canonicalization before matching:** trim → Unicode NFC → lowercase
  → first-token alias expansion. **Aliases are load-bearing**: if the
  CLI accepts `conf` for `config`, a `^config` block without a
  `conf: config` alias is a bypass (CLAUDE.md §7 step 2).
- **Pipes are block-wins always**: every stage must match
  `pipe_allowed` and no stage may match `pipe_blocked`. Empty
  `pipe_allowed` means any piped command is refused.
- The per-command **approval modal always runs** regardless of policy
  (Inviolable Rule 3) — the gate is damage control, not the only line.

## Before you use one of these

Review every pattern against your environment and your vendor's
firmware version. These are conservative read-only baselines written
from the vendor's documented command surface; they cannot know about
your custom scripts, restricted shells, or third-party packages.
Specific risk notes live as comments next to each pattern.

| File | Vendor | Notes |
|---|---|---|
| `fortios.yaml` | Fortinet FortiGate (FortiOS 7.x CLI) | `execute`/`config`/`diagnose` trees; prefix-abbreviation aliases |
| `routeros.yaml` | MikroTik RouterOS v7 | slash-path + verb grammar; no alias support for mid-line abbreviations |
| `hp_procurve.yaml` | HP ProCurve / Aruba (legacy ProVision CLI) | `configure`/`copy`/`write`/`erase` block set; Cisco-style pipe filters |
