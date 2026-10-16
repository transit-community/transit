---
name: transit-agent-firewall-test
description: Run the architectural firewall check on the Transit codebase. Verifies that transit_agent does not depend on transit_auth, keyring, transit_api, transit_files, transit_localpty, or transit_pcap (directly or via dep graph), that the agent tool enum has exactly 6 variants, and that release builds pass the no-phone-home scan (no hosted-infrastructure hostname or client symbol). Run before merging any PR that touches transit_agent/, transit_auth/, deny.toml, or Cargo.toml.
---

# Transit agent firewall test

This skill verifies the load-bearing architectural invariants of the
Transit agent firewall. Run it on demand or as part of a PR review.

## What it checks

1. **`transit_agent → transit_auth` dependency is absent.**
   - Read `src-tauri/crates/transit_agent/Cargo.toml`. Assert `transit_auth`
     does not appear under `[dependencies]` or `[dev-dependencies]`.
   - Also assert `keyring` is absent there (BYOM v3.0.0: the local
     clients take config + bearer tokens BY VALUE from transit_app —
     transit_agent itself must stay keychain-blind; the deny.toml
     `keyring` wrappers list pins this too).
   - Also assert `transit_api`, `transit_files`, `transit_localpty` and
     `transit_pcap` are absent there. The first three are HUMAN-surface
     transports — the API key injector (v4.0.0), the SFTP/local-filesystem
     engine behind the Files pane (v5.0.0), and the local OS shell
     (v4.4.0). A dependency on any of them would be the agent acquiring a
     controller credential, a filesystem, or unrestricted local execution.
   - `transit_pcap` (v6.0.0) is the odd one out and the reason for it is
     worth understanding rather than pattern-matching: the agent CAN see
     the PCaps surface — that is the point of the feature. What it must
     not do is reach the ENGINE. Visibility is granted through the
     `CaptureSource` trait that `transit_agent` owns and `transit_app`
     implements, exactly as scrollback works. The ban is what keeps the
     three capabilities deliberately left off that trait — raw packet
     bytes, flow reassembly, and export — unreachable by adding a
     dependency and calling the engine directly.
   - Each of the four has a matching `deny.toml` ban (check 3).
   - Run `cargo deny check bans` from `src-tauri/`. Assert it exits 0.

2. **The agent tool enum has exactly six variants.**
   - Read `src-tauri/crates/transit_agent/src/tools.rs` (when it exists).
   - Locate the `ToolCall` enum (the canonical tool surface) and count
     its variants; cross-check the compile-time
     `const_assert_eq!(TOOL_CALL_VARIANT_COUNT, 6)` in the same file
     (the build breaks if the enum and the constant disagree).
   - Assert the count is **exactly 6**: `ListOpenSessions`,
     `ReadScrollback`, `ProposeCommand`, `AskUser`, `ProposeApiCall`,
     `QueryCapture`.
     (`ProposeApiCall` is the v4.0.0 GET-only API-investigation tool —
     its input carries NO `method` field, so the agent structurally
     cannot request a non-GET; the executor injects the key + pins the
     host in `transit_app`, never in `transit_agent`.
     `QueryCapture` is the v6.0.0 PCaps tool, signed off by the maintainer on
     2026-08-06. It reads a local capture file the user opened, changes
     nothing anywhere, and is metadata-only BY CONSTRUCTION: its
     `CaptureQueryWire` enum has no payload/bytes/raw variant, so a
     request for wire payload does not deserialize. Note that `List` and
     `Overview` are empty STRUCT variants (`List {}`), not unit variants
     — serde ignores unknown fields on unit variants of an internally
     tagged enum even under `deny_unknown_fields`, so a unit variant
     would let `{"kind":"overview","payload":true}` parse. If either
     ever becomes a unit variant again, that is a regression worth
     flagging.
     A SEVENTH variant is the next deliberate expansion and requires
     this count to move to 7 in lockstep.)
   - If the file does not yet exist (Phase 5a not landed), report
     "tools enum not yet implemented; firewall check passes vacuously"
     and continue.

3. **`deny.toml` has the bans rules.**
   - Read `deny.toml`. Assert a `[[bans.deny]]` block exists with
     `name = "transit_auth"` and `wrappers = ["transit_app", "transit_ssh"]`
     (or a strict subset thereof).
   - Assert the `name = "keyring"` ban exists (wrappers a subset of
     `["transit_app", "transit_auth"]`).
   - Assert the `name = "transit_api"` ban exists (v4.0.0 — the
     API-transport half of the firewall; `transit_api` injects the
     `X-API-KEY` + pins the host, so the agent must not reach it).
     Wrappers must be a subset of `["transit_app"]`.
   - Assert the `name = "transit_files"` ban exists (v5.0.0 — the
     file-transfer half; `transit_files` is the SFTP browse/transfer
     engine plus the local-filesystem ops behind the Files pane, i.e.
     the one place Transit reads and writes device files and the user's
     own disk. File transfer is a HUMAN surface: the agent cannot list,
     browse, read, or transfer files). Wrappers must be a subset of
     `["transit_app"]`.
   - Assert the `name = "transit_localpty"` ban exists (v4.4.0 surface,
     ban added v5.0.0 — a local shell is unrestricted execution on the
     user's machine). Wrappers must be a subset of `["transit_app"]`.
   - Assert the `name = "transit_pcap"` ban exists (v6.0.0 — the packet
     capture engine. Unlike the others this backs an agent-VISIBLE
     surface; the ban keeps the raw-bytes / reassembly / export
     capabilities off the agent's reach by making the engine
     undependable-on, so metadata-only stays an absence rather than a
     policy). Wrappers must be a subset of `["transit_app"]`.
   - If `transit_agent` ever appears in ANY of these wrappers lists,
     that is a **hard fail**.

4. **No `tauri::command` returns a secret.**
   - Grep `src-tauri/src/` for `#[tauri::command]` (the `transit_app`
     binary's source lives at the workspace root, not under `crates/`).
   - For each command, inspect the return type. Flag any return type
     that contains `SecretString`, `SecretBox`, or types from
     `transit_auth` whose internals could leak credentials.

5. **Release builds pass the no-phone-home scan.**
   - Build: `cargo build --release --manifest-path src-tauri/Cargo.toml --bin transit_app`.
   - Run `./scripts/no-phone-home-scan.sh src-tauri/target/release/transit_app`.
   - It must report clean: no hosted-infrastructure hostname string, no
     `TransitCloud*` / updater / deep-link symbol. `api.anthropic.com`,
     `api.openai.com` and `127.0.0.1:11434` are EXPECTED (the direct
     provider clients and Ollama are the point of this edition) — never
     widen the scan to ban them.

6. **CSP `connect-src` lists no provider hostnames.**
   - Read `src-tauri/tauri.conf.json` `app.security.csp`.
   - Assert `connect-src` does NOT list `api.anthropic.com` or
     `api.openai.com`. The only allowed AI-bound hostname is
     the user's configured hosts.

## How to invoke

When a developer asks you to "run the firewall test," "check the
agent firewall," or "verify the four-tools rule," step through each
of the six checks above. Report a summary like:

```
Transit agent firewall — 6 checks
  [PASS] transit_agent → transit_auth / keyring / transit_api /
         transit_files / transit_localpty / transit_pcap all absent
  [PASS] tool enum variant count: 6
  [PASS] deny.toml bans + wrappers (6 bans)
  [PASS] no tauri::command leaks SecretString
  [SKIP] no release build for the no-phone-home scan
  [PASS] CSP connect-src has no provider hostnames

All firewall invariants hold.
```

Exit non-zero (or report `FAIL` clearly) on any violation. A FAIL is
not a "minor issue" — it represents a security regression that
requires explicit user acknowledgement before merge.

## When to invoke this skill

- Auto: any PR that touches `crates/transit_agent/`,
  `crates/transit_auth/`, `deny.toml`, `src-tauri/Cargo.toml`,
  `src-tauri/tauri.conf.json`, or `crates/transit_tls/`.
- Manual: before a release; after a major refactor.
- In CI: as a step in `.github/workflows/ci.yml` (Phase 5a or later
  when the tool enum exists).
