# Arista EOS command policy — design rationale

Companion to `policies/arista_eos.yaml`. Same intent as the other
vendor policies: gate every AI-proposed command so the agent is
structurally incapable of mutating an Arista EOS device, even after
user approval. See `policies/junos.README.md` for the broader
rationale (Inviolable Rule 3, default-deny, block-wins precedence,
cargo-mutants verification loop).

## Why EOS is its own policy (not aliased to Cisco IOS)

Arista chose a Cisco-style CLI on purpose — network engineers
move between vendors fluently when the verbs match. The
operational surface (`show`, `ping`, `enable`, `configure`,
`write`, `copy`, `reload`, `clear`) is ~90% identical to IOS.

The 10% that *isn't* Cisco-style is dangerous: EOS runs on a
Fedora userland, so it exposes shell + scripting vectors that
don't exist on a classic IOS image. The dedicated policy file
forces those Arista-specific blocks to live next to the canonical
allow set, where a future maintainer adding a new `show` variant
also sees `^bash` and `^python` two lines below.

## Shell-escape blocks (the security-load-bearing section)

EOS exposes three direct gate-bypass routes from the operational
CLI:

- **`bash`** — drops the user into the underlying Fedora root
  shell. From there: `/etc/shadow`, `ip link`, anything the
  switch's Linux root can do. THE single most critical block on
  Arista. We match `^bash` as a prefix so `bash sudo` and
  `bash -c '...'` are also caught.
- **`python` / `python2` / `python3`** — the embedded Python
  interpreters can `import os; os.system(...)` to reach the same
  surface as `bash`. All three forms exist on modern EOS images;
  blocking only one leaves a trivial workaround. Matched with
  `(  |$)` boundary so `python ` and bare `python` (interactive
  REPL) are both denied.
- **`event-handler`** — Arista's analog to Cisco's
  `event manager`. Defining a handler stores a script to run on
  CLI events; invoking one runs the stored script. Both ends
  blocked under `^event-handler `.

Three more entry points are Arista-specific but less commonly
abused:

- **`agent `** — TerminAttr (the state-streaming gRPC agent)
  and related agents are controlled via this command. Restarting
  or reconfiguring an agent isn't a CLI-shell escape per se but
  is well outside the read-only contract.
- **`daemon `** — launches arbitrary user-defined daemons that
  ship as scripts on flash. Direct exec vector.
- **`bash sudo`** — covered by the `^bash` prefix above; called
  out here because EOS engineers often type this form rather
  than dropping to bash and then running sudo.

## Why `enable` is blocked

Bare `enable` doesn't mutate state — it just elevates to
privileged EXEC. Same reasoning as Cisco: once elevated, the next
input has `write` / `copy` / `reload` access. The agent's contract
is read-only across the entire session, and opening that door
violates the contract even if no specific write follows.

## Why `wr` aliases to `write`

Same muscle memory as Cisco IOS — Arista engineers contract
`write` to `wr` and run `wr mem` (or just `wr`) to save running-
config. Without alias expansion, an attacker could write `wr mem`
and bypass `^write`. The alias map normalizes the head before
regex matching.

EOS does auto-save by default, so `wr mem` is functionally a
no-op on a typical box — but we block it anyway for defense in
depth and so the policy reads identically to IOS.

## Pipe-stage policy

EOS pipe verbs split into:

- **Pure filters** — `include`, `exclude`, `begin`, `section`,
  `count`. Allowed (same set as Cisco).
- **EOS-specific output formats** — `json`, `format`. JSON output
  is the Arista signature feature engineers use heavily for
  scripted automation; allow.
- **File writers** — `redirect`, `tee`, `append`. All write to
  local file or remote URL. Blocked.
- **Arbitrary script** — `awk`. The `system()` builtin can spawn
  subshells, and `print >"/path"` writes files. Blocked.

Any pipe stage NOT matching the allow list default-denies. Adding
a new safe verb means adding a regex to `pipe_allowed`; adding a
new unsafe verb means adding to `pipe_blocked` AND writing a
corpus test that demonstrates the new pattern is rejected.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test arista_eos_corpus
cargo mutants --package transit_policy --in-place \
    --test-package transit_policy
```

See `policies/junos.README.md` §"Verification" for the
cargo-mutants `--in-place` rationale (cargo-mutants's default
temp-dir copy excludes `policies/` since it sits outside the
cargo workspace).
