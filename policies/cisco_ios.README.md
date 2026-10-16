# Cisco IOS command policy — design rationale

Companion to `policies/cisco_ios.yaml`. Same intent as the Junos
policy: gate every AI-proposed command so the agent is structurally
incapable of mutating a Cisco IOS device, even after user approval.
See `policies/junos.README.md` for the broader rationale (Inviolable
Rule 3, default-deny, block-wins precedence, cargo-mutants
verification loop).

## Why `enable` is blocked

Bare `enable` doesn't mutate state — it just elevates to privileged
EXEC. We block it anyway because once elevated, the next user input
in the same session has access to `write`, `copy`, `reload`, etc.
The agent's contract is read-only across the entire session;
opening the door to write commands violates that contract even if
no specific write follows.

If a network engineer wants to escalate to do something the agent
proposed, they do `enable` themselves at their own CLI — outside
the gate.

## Why `wr` aliases to `write`

Cisco engineers contract `write` to `wr` ubiquitously (`wr mem` to
save running-config to NVRAM is muscle memory). Without alias
expansion, an attacker could write `wr mem` and bypass `^write` by
missing the canonical form. The alias map normalizes the head
before regex matching.

## Pipe-stage policy

Cisco IOS pipe verbs split into:

- **Pure filters** — `include`, `exclude`, `begin`, `section`,
  `count`. Allowed.
- **File writers** — `redirect`, `tee`, `append`. All write to
  local file or remote URL. Blocked.

Any pipe stage NOT matching the allow list default-denies. Adding a
new safe verb means adding a regex to `pipe_allowed`; adding a new
unsafe verb means adding to `pipe_blocked` AND writing a corpus
test that demonstrates the new pattern is rejected.

## Tcl shell

`tclsh` drops the user into IOS's built-in Tcl interpreter, which
can run arbitrary Tcl including `exec` and file I/O. Full bypass
of the gate. Always blocked. Companion `event manager run` lets
EEM applets (which can be defined to run arbitrary actions) be
triggered manually — also blocked.

## Maintained alongside `cisco_ios_xe.yaml`

IOS-XE shares ~95% of the surface but adds shell-escape vectors
(`guestshell`, `app-hosting`) that don't exist in classic IOS.
When adding a NEW safe verb to one file, add it to both unless
it's platform-specific.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test cisco_ios_corpus
cargo mutants --package transit_policy
```

See `policies/junos.README.md` for the cargo-mutants runbook.
