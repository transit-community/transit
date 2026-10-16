# Generic Linux/Unix command policy — design rationale

Companion to `policies/linux.yaml`. This is the first **unrestricted-
mode** policy: the regex gate doesn't run, the per-command modal
takes over.

## Why no regex gate

Every other vendor in `policies/` enumerates a finite operational
CLI: `show ...` allowed, `configure / write / reload` blocked, plus
~20 shell-escape verbs we know exist. The blocklist is short and
honest. Adding a new IOS verb means thinking about three cases.

For a Linux server, the operational CLI is the entire UNIX command
space. `ls`, `cat`, `grep`, `ps`, `df`, `netstat`, `ss`, `ip`,
`systemctl status`, `journalctl`, `top`, `htop`, `tail`, `less`,
`awk`, `sed`, `find`, `tcpdump`, `dig`, `nslookup`, every Python /
shell one-liner an engineer might type — all read-only. And every
write surface — `rm`, `mv`, `chmod`, `chown`, `dd`, `mkfs`,
`systemctl restart`, `apt`, `dnf`, package managers, `pkill`,
`kill`, redirection (`> /etc/...`), `iptables`, `ufw`, `sudo
anything`, `bash -c` with a destructive body — is equally infinite.

A regex blocklist for Linux either:

1. **Lists ten things and pretends to gate.** Catches `rm -rf /`,
   misses `find / -delete`. False confidence is worse than no gate.
2. **Lists hundreds of things and rots.** Maintenance burden that
   doesn't track the user's actual environment, plus still misses
   the eleventh destructive verb someone invents.

Neither helps. The honest framing: **Linux is the user's
responsibility**. The agent's role is to propose. The user's role
is to read every command before approving.

## How the unrestricted carve-out preserves Rule 3

Rule 3 (CLAUDE.md §3) says: *every `propose_command` runs the
policy gate AND the UI modal*. With `mode: unrestricted`:

- The gate **runs** — it just always returns `AllowUnrestricted {
  warning }` instead of `Allow` / `Deny`. The Decision enum forces
  every consumer to handle this variant explicitly, so a future
  refactor can't silently treat unrestricted as plain Allow.
- The per-command modal **runs** every time. The
  `ApprovalDispatcher` skips the always-allow shortcut for this
  decision shape, so the user types Approve once per command,
  every command, no exceptions.
- The warning is rendered verbatim in the modal banner. Every
  approval is informed.

Compared to the other vendors, the unrestricted carve-out trades
the gate's safety net for honest user awareness. The structural
properties — per-step approval, no shortcuts, visible mode — are
what make the trade acceptable.

## What this policy doesn't cover

- **Network OSes that happen to run Linux** (Cumulus, SONiC,
  VyOS). These ship with structured CLIs (`net add interface`,
  `vtysh`, `set interfaces`) that DO have an enumerable safe
  surface. They get their own gated policies when added — they
  do NOT default to the unrestricted path.
- **macOS / BSD servers**. Same reasoning as Linux applies. We
  ship a single `linux.yaml` covering all generic Unix systems.
  The label may evolve to `unix.yaml` if the scope grows.

## Verification

The unrestricted decision shape is exercised by:

```bash
cd src-tauri
cargo test -p transit_policy --lib unrestricted_mode_short_circuits
cargo test -p transit_app --lib agent_dispatch
```

The agent_dispatch tests pin both the "modal still runs" and the
"always-allow refused" invariants. Removing either is a Rule 3
regression and the build fails.
