# Cisco NX-OS command policy — design rationale

Companion to `policies/nxos.yaml`. NX-OS (Nexus 5k/7k/9k data-center
switches) shares Cisco grammar with IOS but has a substantially
different command surface for image management, feature gating, and
shell escape. Same intent as the Junos / IOS policies: gate every
AI-proposed command so the agent cannot mutate state. See
`policies/junos.README.md` for the broader rationale.

## NX-OS-specific blocks

### `feature` / `no feature`

NX-OS gates many capabilities behind `feature` toggles — `feature
bgp`, `feature interface-vlan`, `feature ssh`, etc. Enabling a
feature mutates device state and can change forwarding behavior
silently. Disabling a feature can drop in-flight protocol
adjacencies. **Both forms blocked.**

### `install all` / `install`

NX-OS image upgrade flow. Multi-step, mutates everything. **Always
blocked.**

### Shell / scripting escapes

NX-OS exposes several full-bypass vectors:

- `run bash` — drops the user into the underlying Linux shell.
- `python` — embedded Python interpreter (NX-OS ships Python
  natively). Can `import os; os.system(...)`.
- `run python` — same.
- `source <bootflash:path>` — runs a script file from local
  storage.
- `tclsh` — Tcl interpreter, same risk as on IOS.

All blocked. The `^run bash` and `^python` regexes catch the bare
forms; the YAML's `allowed:` list does NOT include these tokens
elsewhere, so default-deny would catch them too — block-list entry
is belt-and-suspenders.

### `scheduler` / `event manager`

NX-OS's built-in cron and EEM. Both allow arbitrary actions to be
scheduled/triggered. **Blocked.**

## Pipe-stage policy

NX-OS has more UNIX-flavored pipe verbs than IOS (`grep`, `head`,
`sort`, `wc` etc.). All filter-only and allowed.

The dangerous pipe verbs:

- `redirect` / `tee` / `append` — file writers, blocked.
- `vsh` — virtual shell escape inside the pipe context, blocked.
- `run-script` — runs a script file mid-pipe, blocked.

## Why `^python` is in the head blocklist, not the pipe list

Python on NX-OS is a top-level command (`python` at the
operational prompt drops to the interpreter). It's NOT a valid
pipe verb on stock NX-OS. We list it under head-blocked, not
pipe-blocked. If a future NX-OS version exposes `| python ...` as
a pipe verb, add to `pipe_blocked` then.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test nxos_corpus
cargo mutants --package transit_policy
```
