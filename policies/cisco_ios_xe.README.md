# Cisco IOS-XE command policy — design rationale

Companion to `policies/cisco_ios_xe.yaml`. IOS-XE inherits IOS's
command surface but adds vectors specific to its Linux underlay.
This document covers the IOS-XE-specific blocks; for the shared
rationale (default-deny, block-wins, why `enable` is blocked, why
`wr` aliases to `write`), see `policies/cisco_ios.README.md`.

## IOS-XE-specific blocks

### `guestshell`

IOS-XE ships a Linux container ("guest shell") for running
admin scripts. `guestshell run <cmd>` and `guestshell` (interactive)
both drop the user into a full bash environment that can read
device internals and reach the network. Equivalent to Junos `start
shell` or NX-OS `run bash`. **Always blocked.**

### `app-hosting`

IOS-XE supports running third-party Docker-style containers on
the device. `app-hosting install`, `app-hosting activate`, etc.
mutate device state and can introduce arbitrary code. **Always
blocked.**

### `request platform software`

The IOS-XE image-management surface — software upgrades, package
install/uninstall. **Always blocked.**

## Pipe-stage policy

Identical to classic IOS. Filter verbs (include/exclude/begin/
section/count) allowed; writer verbs (redirect/tee/append) blocked.

## Maintained alongside `cisco_ios.yaml`

When adding a new safe verb that exists in BOTH IOS and IOS-XE,
add to both files. When adding an IOS-XE-specific verb (something
that doesn't exist in classic IOS), add only here.

## Verification

```bash
cd src-tauri
cargo test -p transit_policy --test cisco_ios_xe_corpus
cargo mutants --package transit_policy
```
