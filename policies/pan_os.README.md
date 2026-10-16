# Palo Alto PAN-OS command policy — design rationale

Companion to `policies/pan_os.yaml`. Same intent as the Junos /
Cisco / Arista policies: gate every AI-proposed command so the
agent is structurally incapable of mutating a PAN-OS firewall,
even after user approval. See `policies/junos.README.md` for the
broader rationale (Inviolable Rule 3, default-deny, block-wins
precedence, cargo-mutants verification loop).

## Why PAN-OS is its own policy

PAN-OS shares the operational-mode/configuration-mode split with
Junos (and the Cisco family), but the verbs are distinct enough
that aliasing to either would either over-block (Junos's
`commit confirmed` doesn't exist on PAN-OS) or under-block
(PAN-OS's `debug software shell` doesn't exist on Cisco).
Separate file keeps the verbs honest.

## The critical block: `debug software shell`

PAN-OS firewalls run on a Linux underlay. `debug software shell`
drops the operator into a root Linux shell, full bypass of the
gate. Once in the shell, the attacker has direct access to:
- the configuration files on disk,
- the routing table,
- packet capture,
- the certificate store,
- anything the firewall's Linux root can do.

THE single most important block on PAN-OS. Matched as a prefix
so any future `debug software shell ARGS` variant is caught.

## Adjacent shell-adjacent blocks

- **`debug system `** prefix covers `debug system maint-mode`
  (reboots into maintenance mode where loadcfg can replace the
  running config), `debug system loadcfg`, `debug system
  disk-image`, and other system-state mutators.
- **`request restart` / `request shutdown`** — power-cycle and
  shutdown verbs.
- **`request system `** — license imports, certificate imports,
  software update operations. All outside the read-only
  contract.
- **`request platform-software `** — image management.
- **`request high-availability `** — HA failover, sync override.
- **`request password-hash `** — generates a password hash from
  a plaintext input. Surfacing the hash to the agent (even
  redacted) is a path we don't need to enable; PAN-OS engineers
  do this at their own CLI when changing local admin passwords.

## Configuration-model blocks

PAN-OS uses a candidate-config / running-config model similar to
Junos. The mutator verbs:

- **`configure`** enters config mode. Block at entry.
- **`edit`** navigates within config. Block.
- **`set`** is the universal config mutator (with carve-outs
  below). Block as a prefix.
- **`delete`** removes config nodes.
- **`commit` / `commit-all` / `commit-force`** push the candidate
  to running. Block all three prefixes via `^commit`.
- **`load` / `save` / `revert`** swap candidate config from file
  / save current to file / revert candidate. All persistence
  operations.
- **`rename` / `move`** reorganize config nodes — write
  operations even though they don't change values.
- **`copy`** copies files (running-config -> startup, etc.).

## `set` handling — default-deny rather than block-wins carve-out

The natural design — `^set ` as a head block plus three
allow-list carve-outs (`set cli pager`, `set cli terminal`,
`set cli timeout`) — doesn't work under PAN-OS's `block-wins`
precedence: any command matching both lists gets denied, so the
carve-outs lose to the broad block.

Cleaner: don't block `^set ` at the head at all. Allow exactly
the three operational-only forms; everything else with a `set`
head falls through to default-deny.

- **`set cli pager off|on`** — pager control. No device state.
- **`set cli terminal type|width|height`** — terminal cosmetic
  controls. No device state.
- **`set cli timeout <minutes>`** — CLI idle timeout for THIS
  session only. No persisted state.

Config-mode `set` commands (`set deviceconfig`, `set network`,
`set rulebase`, …) match no allow regex, so default-deny rejects
them. Adding a new `^set cli ...` carve-out means appending to
the allowlist + a corpus row; no blocklist edit needed. This
keeps `block-wins` consistent across all five gated vendors and
moves the precision into the allowlist where it belongs.

## Grammar-anchored viewers (`less` / `tail` / `find` / `grep`)

These four heads are PAN-OS-native read-only commands, but their
GNU namesakes exist in every Linux shell — and the original
patterns (`^less `, `^tail `, `^find `, `^grep `) accepted *any*
argument shape, GNU forms included (`less /etc/passwd`,
`find / -exec rm {} \;`). Under today's default-deny +
block-wins posture that was latent rather than live, but it
provided zero protection for a device that is NOT actually a
PAN-OS box (mislabeled inventory) and would turn into a real
bypass under any future allow-wins loosening.

The v1.0.1 patterns anchor each head to grammar only PAN-OS
accepts:

- **`less` / `tail` / `grep`** must name a log *area* token —
  `mp-log`, `dp-log`, `appweb-log`, … — matched as
  `[a-z0-9._-]+-log`. `/` is deliberately outside the character
  class, so no filesystem path can satisfy the pattern. `tail`
  additionally admits its two option forms (`follow yes|no`,
  `lines <n>`) in any order; `grep` admits its `word value`
  option pairs (`count yes`, `context 5`, …) before the area.
- **`find`** must be the literal `find command` (PAN-OS's
  command-help search) — GNU `find`'s path-first grammar can't
  match.

An attacker-controlled filename that *ends* in `-log` still
matches (`grep x-log …`) — harmless: on a real PAN-OS box grep
only reads log areas anyway, and on a mislabeled GNU box the
worst case is a read of a file literally named `*-log`, with the
per-command approval modal still in front of it (Rule 3).

## Alias canonicalization

PAN-OS engineers ubiquitously contract `show` to `sh` and
`delete` to `del`. We alias `sh`/`sho`/`shw` -> `show` so the
allowlist's `^show( |$)` catches the contracted form.

We deliberately do NOT alias `del` -> `delete`: aliasing would
let `del-this-thing` flow through as `delete-this-thing` and
accidentally trip the blocklist on a non-delete command. The
blocklist's `^delete ` catches the contracted form fine because
PAN-OS itself doesn't accept `del` — typing `del config-thing`
returns "Unknown command", so an attacker can't use the
contraction to bypass the gate.

## Pipe-stage policy

PAN-OS pipe verbs split into:

- **Pure filters** — `match`, `except`, `count`. Allowed.
- **File writers** — `redirect`, `tee`. Blocked.

Any pipe stage NOT matching the allow list default-denies.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test pan_os_corpus
cargo mutants --package transit_policy --in-place \
    --test-package transit_policy
```

See `policies/junos.README.md` §"Verification" for the
cargo-mutants `--in-place` rationale.
