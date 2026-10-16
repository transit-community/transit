# Ubiquiti UniFi command policy — design rationale

Companion to `policies/unifi.yaml`. Shipped in **v6.1.0**, promoted from
`policies/samples/unifi.yaml` after the command surface was confirmed on
real gear.

## The thing that makes this policy different

Every other **gated** vendor in `policies/` — Junos, IOS, IOS-XE, IOS-XR,
NX-OS, EOS, PAN-OS — enumerates a *finite vendor CLI*. `show ...` is a
closed set of reads; `configure` / `write` / `reload` is a closed set of
writes; a couple of dozen documented shell escapes complete the picture.

**A UniFi device gives you busybox.** The AP and switch CLIs are a Linux
shell with a handful of Ubiquiti binaries (`info`, `wstalist`,
`athstats`, `swctrl`, `mca-cli-op`) on the path; the UniFi OS gateways
are Debian underneath. So this policy sits between the two existing
shapes:

- It is **not** `linux.yaml`'s `mode: unrestricted`, because unlike a
  general-purpose server there *is* a small, real set of commands an
  engineer runs on an AP, and enumerating it is worth doing.
- It is **not** IOS-shaped either, because the allow list can never be
  complete and the arguments — not the verb — decide whether `ip`, `cat`
  or `tc` reads or writes.

Two consequences follow, and both are deliberate.

### 1. The allow list is argument-anchored, not verb-anchored

`^ip (-[a-z0-9]+ )*(addr|address|link|route|neigh|neighbour|rule|maddress)( |$)`
allows the read subcommands of `ip` and nothing else; `ip link set`
matches no allow pattern (there is no `set` in the list) and so
default-denies. `cat` is scoped to `/proc`, `/sys` and `/var/log` — a
`^cat /data/...` never matches, which matters because on a UniFi OS
console `/data` holds the credential store, the WLAN PSK and RADIUS
databases, Protect footage metadata and Access door credentials. None of
that is reliably secret-*shaped*, so the redaction filter could not save
us; the scoping is what does.

### 2. There is a shell-grammar armor layer

`;`, `&`, `<`, `>`, backtick, `$(`, and `..` are blocked **unanchored**,
so they match anywhere in the line. This is the block list that has no
counterpart on a vendor-CLI policy, and it is the one doing the heaviest
work: without it, every allowed head is a launch pad —
`uptime; reboot`, `dmesg > /tmp/x`, `ping $(cat /etc/passwd)`,
`cat /proc/../data/unifi-core/config/unifi-core.key`. Pinned by
`unifi_shell_grammar_cannot_smuggle_a_write_behind_an_allowed_head`.

`precedence: block-wins` means a line matching both lists is refused.

## Why the always-allow shortcut is refused for this vendor

`agent_dispatch` computes `refuse_always_allow` from three conditions:
an unrestricted vendor, a custom (BYOP) vendor, and — new in v6.1.0 —
a **shell-backed** vendor, which today means UniFi.

The reasoning is that "has a shipped read-only floor" and "is safe to
auto-approve against" are different properties, and this is the first
vendor where they come apart. The floor is worth having: a bad command
is refused before a human ever sees it. But the floor's completeness
rests on a judgement about a shell rather than on an enumerable command
tree, and a regex that auto-approves *future* commands unseen is a much
stronger bet than a floor that refuses known-bad ones. So the
per-command modal stays mandatory here. Threat-model T47.

Any future shell-over-SSH vendor belongs in the same bucket.

## Canonicalization gotcha, found while promoting this policy

The gate canonicalizes before matching: trim → NFC → **lowercase** →
first-token alias expansion. That last-but-one step is load-bearing here
in a way it is not for a vendor CLI.

The sample allowed `^ethtool (-[iSgkamcT] )?[a-z0-9.]+$`. Two problems:

1. The upper-case letters in that class could never match a folded
   command, so the flag form was dead — it failed *closed*, but silently.
2. Fixing it by lowercasing the class would have been worse. Every
   ethtool read flag has an upper-case **mutating** twin that becomes
   indistinguishable once folded: `-S` (show stats) vs `-s` (set
   settings), `-k`/`-K` (offload), `-g`/`-G` (ring), `-a`/`-A` (pause),
   `-c`/`-C` (coalesce). The `$` anchor happens to reject the mutating
   forms because they require trailing arguments — but resting a
   write-block on an anchor is far too subtle to defend.

So flags are refused wholesale and only `^ethtool [a-z0-9.]+$` is
allowed. **A read was traded away to avoid admitting a write**, which is
the right direction for a default-deny gate. The general lesson for any
future policy: never write an allow pattern whose safety depends on
letter case.

## Maintenance

New rows for commands hit in the field belong in
`crates/transit_policy/tests/unifi_corpus.rs`, allowed and blocked
alike. Run `cargo mutants --package transit_policy --in-place
--test-package transit_policy` after editing the YAML — `policies/` lives
outside the cargo workspace, so `--in-place` is required or the corpus
tests see no policy at all.
