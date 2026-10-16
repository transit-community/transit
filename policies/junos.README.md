# Junos command policy — design rationale

This policy gates **every** AI-proposed command against a Juniper
Junos device. It is the gate side of Inviolable Rule 3 (every
proposed command runs through both the policy gate AND the UI
approval modal — see `CLAUDE.md` §3).

## Intent

Junos devices in scope for Transit are network-engineering targets
under investigation, not lab machines we own outright. The gate's
job is to **make the AI structurally incapable of mutating the
device** even when the user has clicked through approval. The
allowlist permits operational-status commands (`show`, `ping`,
`traceroute`, `monitor`, `file list`, `op`, `help`); the blocklist
denies anything that writes config, drops to shell, restarts a
process, or performs file I/O on the device.

If a network engineer wants to `commit` a change after the AI
diagnoses a problem, they do it themselves at their own CLI. The
agent never gets to.

## Precedence: `block-wins`

When a command matches both an `allowed` and a `blocked` regex (e.g.
a hypothetical future allowlist entry that overlaps an existing
blocklist), the deny wins. This is belt-and-suspenders: any future
maintainer expanding the allowlist won't accidentally re-enable
something the blocklist explicitly refused.

`allow-wins` exists in the schema for the rare case where the
blocklist is intentionally over-broad and an allowlist carves a
narrow exception. Junos doesn't use that pattern in v1.

## Pipe-stage policy

Junos pipes (`show route | match BGP | count`) let you filter and
format output. Each stage has its own side-effect surface:

- `match` / `except` / `find` are pure filters — allowed.
- `display set`/`xml`/`json` are pure formatters — allowed.
- `count` / `last N` / `no-more` / `trim` are pure transforms — allowed.
- `save <path>` writes to local-device file — **blocked**.
- `compare` (at config-mode prompts) is intentionally never reached
  from operational mode — **blocked** belt-and-suspenders.
- `commit` and `request` are CLI verbs that should NEVER appear in
  a pipe stage — **blocked**.

Any pipe stage NOT matching the allow list default-denies. Adding a
new safe stage means adding a regex to `pipe_allowed`; adding a new
unsafe stage means adding to `pipe_blocked` AND writing a corpus
test that demonstrates the new pattern is rejected.

## How the canonicalization aliases were chosen

Junos accepts contracted verbs natively (`sh int br` → `show
interfaces brief`). Without alias expansion, an attacker could write
`sho version` and bypass `^show( |$)` by missing the canonical form.
The alias map normalizes the head before regex matching.

v1 covers single-word first-token aliases only. Multi-word aliases
(like `sh int br` → `show interfaces brief` as a unit) would require
a more capable canonicalizer; deferred. In the meantime, `sh int
br` aliases the head `sh` → `show` and the rest passes through —
which still routes through `^show( |$)` correctly.

## Verification: cargo-mutants

When changing this file (or `transit_policy::engine::evaluate`), run
the mutation-testing pass:

```bash
cd src-tauri
cargo install cargo-mutants
cargo mutants --package transit_policy
```

Every mutant of `evaluate` must be killed by an existing test. If
one survives, add a test that distinguishes the original from the
mutant. Common surviving-mutant patterns:

- Replacing `is_match` with `true`: add a test where the regex
  doesn't match and the command default-denies.
- Replacing `Decision::Allow` with the deny constructor: covered
  by every allow-path test in `engine.rs::tests`.
- Removing the `pipe_blocked` check: covered by
  `pipe_stage_blocked_denies_even_with_allowed_head` in
  `engine.rs::tests`.

## Known false-positives

(None in v1. Add as encountered.)
