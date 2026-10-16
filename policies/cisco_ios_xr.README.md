# Cisco IOS-XR command policy — design rationale

Companion to `policies/cisco_ios_xr.yaml`. IOS-XR is Cisco's carrier-grade
OS (ASR 9000 / NCS / CRS / XRv). It shares classic IOS's grammar for the
read-only `show` surface but diverges sharply in its config model and its
shell-escape vectors. Same intent as the Junos / IOS policies: gate every
AI-proposed command so the agent cannot mutate state. See
`policies/junos.README.md` for the broader rationale.

The `allowed` lane mirrors `cisco_ios.yaml` (read-only `show` / `ping` /
`traceroute` / `dir` / `more` / `terminal`). Everything below is the
XR-specific delta.

## Two-stage commit config model

IOS-XR uses a candidate-config + commit model (like Junos/PAN-OS), not
classic IOS's imperative write. `configure [terminal|exclusive|private]`
enters a candidate; `commit` applies it to running. There is **no `write`
verb** on XR — so, unlike `cisco_ios.yaml`, this policy carries no
`wr` → `write` alias. **`^configure`, `^conf t`, and `^commit` are
blocked.** Blocking config entry makes commit unreachable in practice;
`^commit` is listed anyway for legibility and defense-in-depth.

## Shell / scripting escapes

IOS-XR exposes several full-bypass vectors that do not exist (or differ)
on classic IOS. All blocked at the head:

- `run` — on classic 32-bit IOS-XR (QNX) drops to the underlying task
  shell. Blocked via `^run( |$)`. **This is the subtlest entry:**
  `show running-config` abbreviates to `sh run`, but the gate matches the
  *head* (text before the first `|`) and the `sh` → `show` alias rewrites
  only the first token, so `sh run` canonicalizes to head `show run`
  (read-only) and never collides with `^run`. Bare `run` is the shell.
- `bash` — on 64-bit IOS-XR (eXR, Linux/Wind River underlay) drops to a
  Linux root shell. **The single highest-value block on modern XR.**
  `^bash` catches `bash`, `bash -c …`, `bash sudo …`.
- `script` — IOS-XR 7.x on-box automation: `script run <name>` executes
  an operator/EEM/config/process script (Python or bash) from
  `harddisk:/mirror/script-mgmt/`. A direct arbitrary-code path. Blocked
  via `^script( |$)`.
- `attach` — `attach location <node>` attaches to a specific node on XR's
  distributed control plane and can drop to that node's shell. Blocked.
- `admin` — enters the System Admin VM (sysadmin plane), which has its own
  config and its own `run`/`bash` into the sysadmin Linux shell. Blocked.
- `tclsh` — Tcl interpreter, same risk as on IOS.

The `allowed:` list does not surface any of these tokens, so default-deny
would catch them too — the block-list entries are belt-and-suspenders and
make the intent legible to the LLM via the policy summary.

### `^admin` over-block is accepted

`^admin` also blocks `admin show …` (running a show inside the sysadmin
plane). That is intentional over-blocking: sysadmin-plane visibility is
outside the read-only **network**-plane mandate, and the same card/chassis
data is reachable via the XR-plane `show platform` / `show inventory`.

### Verbs deliberately NOT blocked

`python`, `source`, `event manager run`, and `ksh` are blocked on NX-OS,
but they are **not standalone IOS-XR exec verbs** — on XR those vectors are
reached only via the already-blocked `run` / `bash` / `script` / `attach`.
Listing them here would imply commands XR does not have; default-deny
covers any that a future release introduces. If a future XR build exposes a
bare `python` / `source` exec verb, add `^python` / `^source` then.

## Image / process / hardware mutation

`install` (add/activate/commit/replace/rollback/remove), `reload`
(router or `reload location <node>`), `process` (restart/shutdown/start),
`hw-module` (line-card reset/shutdown/reload), `clear`, `crypto`, and the
file ops (`copy`/`delete`/`rmdir`/`mkdir`/`format`/`move`) are all blocked.
`show install …` stays allowed — its head is `show`, not `install`.

## `show tech-support` file-write hardening

Bare `show tech-support [component]` dumps read-only to the terminal and is
allowed. The **file-writing forms are blocked**: an explicit `file <dest>`
keyword, or a filesystem / transfer-URL destination token
(`disk0:` / `harddisk:` / `bootflash:` / `nvram:` / `tftp:` / `ftp:` /
`scp:` / `sftp:` / `rcp:` / `http(s):`). block-wins precedence makes this
single `blocked` regex override the broad `^show` allow.

**Backport status: DONE.** The sibling Cisco policies (`cisco_ios.yaml`,
`cisco_ios_xe.yaml`, `nxos.yaml`) now carry an equivalent guard — each
blocks the `file`/filesystem/transfer-URL forms of `show tech-support`
while allowing the bare read-only dump, so the write-a-techfile residual
this section originally TODO'd is closed across the whole Cisco family.
(Even unguarded it was low-severity — a written tech-support file is not
exfiltrable without `copy`/`scp`, both of which are blocked.)

## Pipe-stage policy

IOS-XR output modifiers:

- `include` / `exclude` / `begin` / `count` — pure read-only filters,
  allowed.
- `file` / `redirect` — write output to a file/URL — blocked.
- `utility <tool>` — bridges output to underlying Linux utilities
  (`egrep`, `sed`, `wc`, …); a real processing/escape bridge — blocked.
  Use `| include` / `| exclude` for filtering instead.
- `tee` / `append` — IOS-classic file writers; blocked defensively (kept
  even though XR may not expose them — harmless and consistent with the
  Cisco family).

A pipe stage matching no `pipe_allowed` regex is default-denied, so any
unlisted future verb fails safe.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test cisco_ios_xr_corpus
cargo mutants --package transit_policy --in-place --test-package transit_policy
```
