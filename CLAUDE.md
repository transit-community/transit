# CLAUDE.md — Transit Community Edition contributor manual

> Read this first when entering the codebase. The rules here are not
> preferences. Verify a decision hasn't already changed in the code
> (`git log`, `Cargo.toml`, `tauri.conf.json`, `deny.toml`,
> `docs/security/`) before relying on the leanings here.

## 1. Project identity

Transit Community Edition is an **open-source (Apache-2.0)**
cross-platform GUI SSH client with an embedded agentic AI for read-only
investigation of network gear. The AI runs on the user's own Anthropic /
OpenAI key, sent **directly** to that provider, or on models the user
hosts (Ollama / OpenAI-compatible endpoints). There is no account, no
hosted service, no telemetry and no updater. The binary contacts only the
devices, endpoints and providers the user configures.

Forked from the proprietary Transit client at 6.5.9. The fork's design
record, including what was removed and why, is
[`docs/design/2026-09-19-community-edition-plan.md`](docs/design/2026-09-19-community-edition-plan.md).

## 2. Architecture map

```
src-tauri/                                   (Cargo workspace)
├── Cargo.toml                               (workspace root + transit_app binary)
├── tauri.conf.json                          (CSP + security; load-bearing)
├── capabilities/default.json                (Tauri permissions; load-bearing)
├── src/                                     (transit_app: main + lib)
└── crates/
    ├── transit_core/                        types, parsing, log redaction
    ├── transit_auth/                        SOLE secret holder (device credentials)
    ├── transit_policy/                      per-vendor command gate
    ├── transit_ssh/                         russh PTY transport + TOFU + jump hosts
    ├── transit_agent/                       LLM clients, tools, redaction, agent loop
    ├── transit_tls/                         the ONE TLS trust-anchor builder (OS store vs webpki; cert pins)
    ├── transit_console/                     USB-to-serial transport
    ├── transit_api/                         read-only REST transport + agent GET-gate
    ├── transit_localpty/                    local OS shell (PTY) transport (§20)
    ├── transit_files/                       SFTP browse/transfer engine (§21)
    └── transit_pcap/                        packet capture + analysis engine (§22)
```

**The one-way dependency rule:** `transit_agent` MUST NOT depend on
`transit_auth` or `keyring` (nor on `transit_api`, `transit_files`,
`transit_localpty`, `transit_pcap`). Enforced by `deny.toml` `[[bans.deny]]`
and the `transit-agent-firewall-test` skill. This makes the agent
firewall a property of the type system, not a comment.

## 3. The Three Inviolable Rules

### Rule 1. No secret crosses Tauri IPC except enrollment.

No `tauri::command` returns a value containing a credential. The
commands that ACCEPT a secret are write-only: `enroll_secret` (device
credentials), `enroll_api_session_secret`, `submit_kbi_answers`
(keyboard-interactive, nothing persisted), `provider_key_set` (the
user's Anthropic/OpenAI key → OS keychain), and
`local_endpoint_set_token`. Status commands return booleans only. After
enrollment, every use reads the secret in-process.

### Rule 2. The agent's tool surface is exactly six tools.

`transit_agent::tools` has exactly six variants: `ListOpenSessions`,
`ReadScrollback`, `ProposeCommand`, `AskUser`, `ProposeApiCall` (GET-only;
its input carries **no `method` field**, so the agent structurally cannot
request a mutation), and `QueryCapture` (read-only queries against an
open packet capture; its `CaptureQueryWire` enum has **no payload/bytes/raw
variant**). The count is pinned at compile time
(`static_assertions::const_assert_eq!(TOOL_CALL_VARIANT_COUNT, 6)`). A
seventh is a deliberate scope expansion — see §8.

### Rule 3. Every `propose_command` runs the policy gate AND the UI modal.

Both, not either. No "trusted" commands skip the modal. No "approved
once" commands skip the gate. The "always allow regex for this
chat+session" affordance only suppresses the modal *for commands the gate
already permits*; the gate still runs every time. Pinned by
`agent_dispatch::tests::always_allow_does_not_skip_policy_gate`.

`propose_api_call` applies the same discipline: its gate is the
structural GET + host-pinned path confinement (`transit_api::evaluate_agent_get`),
then the approval modal (per-call by default; a chat may opt in to
auto-approving GETs — safe because a GET cannot mutate, and the gate
still runs). `run_get` re-gates after the modal. Threat model T39.

`Vendor::Linux` (unrestricted) has no enumerable safe-command surface, so
`policies/linux.yaml` declares `mode: unrestricted` and the gate returns
`Decision::AllowUnrestricted { warning }`; the per-command modal stays
mandatory and the always-allow shortcut is structurally refused. T21.

## 4. The Fourth Rule (network)

**The binary contacts nothing the user did not configure.** The only
outbound HTTP is (a) `api.anthropic.com` / `api.openai.com` from the
direct provider clients (`transit_agent::llm::direct`) when the user
enrolled a key or signed in with ChatGPT, (b) `auth.openai.com` for the
Sign in with ChatGPT round-trip (`src/chatgpt_auth.rs`: the authorize
page opens in the system browser, the token exchange runs from Rust —
only on the user's click, T55), (c) the local-model endpoint the user
configured (`llm::ollama`, `llm::openai_compat`, URL rules in
`llm::transport`), (d) REST controllers in the inventory (`transit_api`),
plus SSH to inventory devices. There is no update check, no crash reporter, no
usage ping, and no hosted service of ours.

Made checkable by `scripts/no-phone-home-scan.sh`, which fails a release
build if any hosted-infrastructure hostname or client symbol is present.
It runs on the Linux CI leg and on every release leg. Adding an outbound
host is a Fourth-Rule event: it needs a threat-model entry and a scan
allowance in the same PR.

**Provider keys** live only in the OS keychain (`transit_app::provider_keys`,
service `transit-ce-provider-keys`); `transit_app` reads the key per send
and hands it to the client as a `SecretString`. The client uses
`transit_tls::build_http_client(strict)`: OS-store (or webpki-only) chain
verification, 10 s connect timeout, **no redirects**, **no ambient
proxy**. Threat model T54 (T_DIRECT_KEY).

**Model lists are discovered, not hard-coded.** `DirectAnthropic` /
`DirectOpenAI::list_models` (`GET /v1/models` on the same host, same
credential) feed the `provider_models_list` IPC → `useProviderModels`
(24 h stale, mirrored into `preferences.cachedModels` so the picker is
populated offline). OpenAI's list is filtered heuristically
(`OPENAI_EXCLUDE`); *Additional model ids* stays the escape hatch. The
default for a new chat is `PREFERRED_DEFAULTS` in `providerModels.ts`,
first id present in the offered list.

**Sign in with ChatGPT (preview, OpenAI only).** `[providers]
openai_method = "api_key" | "chatgpt"` picks ONE credential for the
OpenAI side. The plan path is PKCE OAuth on a one-shot `127.0.0.1`
listener; the refresh token lives in the keychain
(`transit-ce-provider-keys` / `openai-chatgpt-refresh`), the access
token in memory, neither crosses IPC. `DirectOpenAI::new(OpenAiAuth::
ChatGptPlan(..))` omits `max_output_tokens` (the preview rejects it) and
maps the `subscription_sharing_*` codes to the `plan_*` markers.
Sign-out REVOKES at `auth.openai.com/api/accounts/oauth/revoke` (RFC
7009, bounded retries) before clearing local state. Personal Plus/Pro
only: a workspace tenant (Business/Enterprise) denies open-source apps at
consent (`3p_delegated_access_policy_denied`) and its Admin Console
allow-list cannot hold a dynamically-registered app — verified
2026-10-15 on the Transit AI Business tenant; do not retread.
Anthropic has no plan path: consumer-plan OAuth in third-party apps is
prohibited by Anthropic's terms (research record in
`docs/design/2026-10-15-dynamic-models-and-subscription-auth.md`).

**Local models** are free: the only gate is `[local_models] enabled`.
Their clients call ONLY user-configured endpoints (plain http
loopback-only; https elsewhere against the OS trust store), carry no
credential of ours, never honor `HTTP_PROXY`, never follow redirects.
Local models price at zero internally (`Pricing::LOCAL_ZERO`; the rounds
checkpoint bounds the loop). Threats T33–T35.

## 5. Build / test / run

Prerequisites:
- Rust via `rustup` — the toolchain is **pinned in `rust-toolchain.toml`**;
  `src-tauri/Cargo.toml`'s `rust-version` is the separate *floor*.
- **Node 22+**. Frontend: Vite 8, Vitest 4, TypeScript 6, ESLint 10, Tailwind 4.
- Tauri 2 system deps for your platform. Linux:
  `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libdbus-1-dev`.
- `gitleaks`.

Dev: `npm install` then `npm run tauri dev`.

Test: `cargo test --workspace --manifest-path src-tauri/Cargo.toml` + `npm run test`.

Audit: `cargo deny check` (in `src-tauri/`) + `npm audit --audit-level=high`
+ `npm run license:check` + `gitleaks detect --source . --no-banner`.

CI (`.github/workflows/ci.yml`) runs all of the above on GitHub-hosted
Ubuntu/macOS/Windows runners. Releases (`release.yml`) build unsigned
bundles on a `v*.*.*` tag and publish them to GitHub Releases with
`SHA256SUMS.txt`; the no-phone-home scan runs on every leg.

## 6. Adding a secret backend (runbook)

1. Implement `transit_auth::SecretBackend` for the new variant.
2. Add detection helpers (available on this platform? configured?).
3. Add a `SecretRef` variant (`transit_core::inventory::types`) and route it
   via the backend's `supports()` — `SecretRegistry::find_backend` is
   first-match-wins. A **value** backend returns the credential from
   `resolve_value` → `SecretString`. A **sign-capable** backend
   (`ssh_agent`, `ssh_key`) returns `Unsupported` from `resolve_value` and
   exposes an inherent `SecretRegistry` method that hands `transit_ssh` a
   ready-to-use credential, so raw key bytes never enter the 60 s cache.
4. Write mock-backend unit tests (no real keystore access needed).
5. Write a real-backend integration test behind a feature flag. Linux CI
   coverage runs inside `ci/keyring-linux/` — see `docs/security/secrets.md`.
6. Update `transit.toml.example`, `docs/security/secrets.md` §"Backends",
   and `docs/security/licenses.md` for new direct deps.
7. `transit-security-audit` fires on `transit_auth/` changes — let it review.

## 7. Adding a vendor policy (runbook)

Shipped gated vendors: Junos, Cisco IOS, IOS-XE, IOS-XR, NX-OS, Arista
EOS, Palo Alto PAN-OS; plus generic Linux in `mode: unrestricted`.

1. **Add the `Vendor` variant** in `transit_core::inventory::types`
   (`Vendor::from_tag` is the single string→Vendor source of truth; also
   `as_str`). Add the label to the frontend's `VENDOR_OPTIONS`
   (`src/lib/schemas.ts`). *(A user-supplied **custom** vendor needs none
   of this — it is `Vendor::Custom` automatically.)*
2. **Create `policies/<vendor>.yaml`** (schema in `transit_policy::loader`):
   `precedence:`, `canonicalization.aliases:` (first-token contractions —
   without these an alias bypasses the head-block list), `allowed:` /
   `blocked:` head-command regexes, `pipe_allowed:` / `pipe_blocked:`
   per-stage regexes (block any stage that writes to file or changes mode).
3. **Identify shell-escape vectors** and add them to `blocked:` — the
   highest-value adds (Junos `^start shell`; IOS `^tclsh`; IOS-XE
   `^guestshell `; NX-OS `^run bash`, `^python`).
4. **Build corpus tests** at `crates/transit_policy/tests/<vendor>_corpus.rs`
   — allowed corpus (every read-only command an engineer uses) and blocked
   corpus (every config/write/shell-escape verb, aliased forms included).
5. **Document design choices** in `policies/<vendor>.README.md`.
5a. **Seed the `phrasebook:`** — 5–20 canonical gate-ALLOWED command forms
   (≤60 chars) rendered into the agent's cached prompt as "Known-good
   forms". `tests/phrasebook_gate.rs` fails the build if any entry is
   gate-denied; there is no test for an EMPTY phrasebook — this step is
   the reminder.
6. **Run cargo-mutants** so no mutation of the gate survives:
   `cargo mutants --package transit_policy --in-place --test-package transit_policy`.
   `--in-place` is required because `policies/` lives outside the cargo
   workspace.
7. **Update the proptest blocklist** in `tests/proptest_blocked.rs`.
8. The agent's system prompt picks up the new vendor automatically
   (`chat.rs::collect_policy_summaries` enumerates `PolicyEngine::vendors()`);
   add the variant to `policy_pointer_present_for_each_open_session_vendor`
   in `transit_agent::system_prompt::tests`.

**BYOP — user policy layer + custom vendors.** Users may supply their own
policies, layered over the bundled set, via `$TRANSIT_USER_POLICIES` (or
`config.toml` `[policy] user_dir`); `PolicyEngine::from_layers` builds the
layered engine. Two invariants: the **read-only floor** (a user layer may
ADD allowed patterns to a shipped vendor but never punch through a shipped
block — `evaluate` runs the bundled policy first and a `DenyKind::Blocked`
is terminal) and **custom vendors** (`Vendor::Custom(Arc<str>)`, no shipped
floor, so the dispatcher refuses the always-allow shortcut). Design:
the threat model, T26.
Samples in `policies/samples/` (templates — never loaded).

## 8. Adding an agent tool (RUNBOOK WITH WARNINGS)

> The tool surface is exactly six (Rule 2). A seventh is a deliberate
> scope expansion requiring maintainer sign-off in the PR.

1. **Stop. Document purpose, inputs, outputs, blast radius** in the PR.
2. Add the variant to `transit_agent::tools` (the `const_assert_eq!` breaks
   the build until you bump the count).
3. Implement dispatch in `transit_app::commands::agent_dispatch`
   (`DefaultDispatcher` if pure read-only, else `ApprovalDispatcher`).
4. Bump the `transit-agent-firewall-test` skill's expected count 6→7.
5. **Redaction review.** Any output the tool returns to the LLM passes the
   redaction filter — new patterns / proptest generators? Update
   `transit_agent::redaction`.
6. **Policy review.** If it can write to a device, stop. If it only reads,
   does its read need filtering?
7. **Approval flow.** If it can change persistent state, the UI must
   require explicit per-call approval.
8. **Session resolution.** A session-taking tool MUST resolve its session
   input through the chat's alias ledger before any trust decision (§15).
9. Update `docs/security/threat-model.md`, this file, both skills, and
   `tests/prompt_injection_corpus.rs`; reset the `tool_schemas` insta snapshot.

If any step looks skippable, you haven't understood the firewall — re-read
`docs/security/threat-model.md`.

## 9. Files to never edit casually

Security-load-bearing. Edits require a security-review pass:

- `crates/transit_auth/src/*` — the sole secret holder.
- `crates/transit_agent/src/tools.rs` — Rule 2 surface (`const_assert_eq! = 6`).
- `crates/transit_agent/src/redaction/` — the device-output → LLM boundary.
  **Output capping + context pruning MUST run strictly AFTER `redact()`.**
- `crates/transit_agent/src/system_prompt.rs` — cache-aware prompt (§13).
- `crates/transit_agent/src/capture.rs` — the `CaptureSource` seam. What is
  ON this trait is the whole of what the agent can do with a capture. T45.
- `crates/transit_agent/src/llm/direct.rs` — the two provider hosts and the
  key's only exposure point. T54.
- `crates/transit_agent/src/llm/transport.rs` — the BYOM URL rules +
  hardened no-proxy/no-redirect client builders. T35.
- `crates/transit_tls/src/lib.rs` — the centralized TLS trust builder for
  every outbound HTTPS client. Strict TLS is a swap of trust anchors,
  never a `danger_accept_invalid_certs` path. T27, T40.
- `crates/transit_pcap/src/live.rs` — builds the command line that runs as
  root; `validate_bpf` is the charset gate in front of the macOS `osascript`
  path. T44. `crates/transit_pcap/src/sanitize.rs` — the wire-string boundary. T45.
- `src/provider_keys.rs` — keychain service + write-only IPC. Rule 1.
- `src/chatgpt_auth.rs` — the Sign in with ChatGPT boundary: PKCE +
  `state`, the one-shot loopback listener, keychain refresh token,
  memory-only access token, dead-grant clearing. T55.
- `src/chat_history.rs` (T50), `src/chat_snippet.rs` (T51) — disk boundaries.
- `tauri.conf.json` `app.security.csp` — `connect-src 'self' ipc: http://ipc.localhost`
  only: the webview reaches no network host at all.
- `capabilities/*.json` — Tauri permission surface. The opener allow-list
  is pinned to the public repository URL + `https://auth.openai.com/*`.
- `deny.toml` — license allowlist + agent firewall bans.
- `scripts/no-phone-home-scan.sh` — the Fourth Rule made checkable.
- `eslint.config.js` (`no-console` outside tests), `.husky/pre-commit`.

## 10. Logging policy

Use `tracing` via `transit_core::log::init()`. Never log: credentials
(wrap in `secrecy::SecretString`, whose `Debug` emits `[REDACTED]`); host
keys; prompt/completion content with device data; provider keys. Log the
**fact** of operations, not their values:

```
GOOD:  info!(device = %device.id, "connecting");
BAD:   info!(?prompt, "sending to LLM");
```

**The diagnostic log** (Settings → Developers) is an opt-in rolling file
sink, off by default. It adds a SINK, never a statement: the file receives
the same events stderr gets, so everything above stays out of it. The
verbosity ceiling is a CLAMP applied where the value is used
(`resolve_file_logging`), not a UI convention.

## 11. State management (frontend)

- **TanStack Query** owns server-state (anything over Tauri IPC). Never
  `useEffect(() => invoke(...))`.
- **Zustand** (`src/stores/`) owns UI state + cross-component coordination.
  **No server data in Zustand.**
- **Plain `useState`** for component-local ephemeral state.

## 12. Inventory + config locations

Single canonical inventory path:
1. `$TRANSIT_INVENTORY` (explicit override).
2. Debug builds: `<project_root>/transit.toml`.
3. Release builds: `dirs::config_dir()/TransitCommunity/transit.toml`.

`config.toml` (Strict TLS, policy user dir, local models, agent-chat
options, pcap dir, developer log) sits beside it; env overrides are
`TRANSIT_*`. In-app inventory edits flow through
`transit_core::inventory::mutator` (atomic write + revalidation); adding a
mutation: add the op (MUST call `revalidate`), unit-test every error path,
wire a `tauri::command` via `with_writable_doc`, add the `api.ts` wrapper +
`mutations.ts` hook.

## 13. Prompt structure + caching

`transit_agent::system_prompt::build` returns ordered `PromptSection`s;
`cache_after` flags become provider cache annotations (Anthropic: up to 4
`cache_control` blocks; OpenAI: longest-prefix auto-detection). Section
ordering invariant:

```
ToolSchema → ReadOnlyMandate → AcceptableUseGuard → InjectionGuard
→ PolicySummary (vendors of OPEN sessions only) → OpenSessions (volatile, LAST)
```

Moving a volatile field into a cached section makes every conversation
pay a cache invalidation on the next session open/close. Adding a section:
decide cache stability, add a `SectionKind`, update `build()` and the
ordering tests, re-snapshot `tests/system_prompt.rs`.

## 14. Agent loop

`transit_agent::AgentLoop` owns a `Conversation`, drives turns via
`LlmClient`, dispatches `ToolCall`s through `ApprovalDispatcher`.
Bounds: `checkpoint_rounds` (50) and `checkpoint_cost_microdollars`
(internal, never surfaced) pause for a one-click Continue;
`stream_timeout` 90 s per turn (600 s for local models). The UI shows
rounds · elapsed · tokens — **never a cost figure**.

**Provider routing** (`chat.rs::DirectClientFactory`): `ollama:` /
`endpoint:` ids → the local clients; otherwise `provider_keys::Provider::for_model`
(`claude` in the id → Anthropic, else OpenAI) → the key from the keychain →
`DirectAnthropic` / `DirectOpenAI`. No key → a client whose first call
fails with `LlmError::MissingKey`, mapped to "add your key in Settings →
API keys". Errors carry stable markers (`missing_provider_key`,
`provider_key_rejected`, `rate_limit_exceeded`, `provider_overloaded`,
`tls_trust`) that `chat.rs` string-matches after the loop flattens them.

Cancellation: `chat_cancel` notifies an `Arc<Notify>`, aborts the task,
drains pending modals. Always-allow regex lives in-memory on the chat
session, cleared when the chat is destroyed, never persisted.

## 15. Session aliases + per-chat scope

The agent's session vocabulary is a short per-chat alias (`s1`, `s2`, …).
Allocation happens ONLY inside `ScopedScrollbackSource::list` (after the
scope filter, so out-of-scope sessions never get an alias); resolution
happens at the TOP of every session-taking handler before any trust
decision. Per-chat device scope (`chat_set_scope`) is enforced
structurally by `scoped_session_view.rs`, never by UI filtering;
out-of-scope refusals are byte-identical to closed sessions. T31.

## 16. Connecting to a device

`connect_device` → resolve device + auth profile → `Connection::connect`
(strict cipher allowlist) → `check_server_key` vs `HostKeyStore` (unseen:
TOFU prompt; mismatch: changed-key modal, T11) → authenticate via
`SecretRegistry` → persist the pin → `Session::open`. A strict-handshake
failure offers the weak-crypto opt-in (T20), never auto-granted. Jump
hosts tunnel through `connect_over_stream` so TOFU/auth run end-to-end
(T52); agent forwarding is per-device opt-in and REJECTS unless opted in
(T53). Bulk connect is **strictly sequential** because the TOFU /
weak-crypto responders are single-slot per `(host, port)`.

## 17. Terminal pane

xterm.js on the PTY IPC contract. OSC 52 is consumed (removing it re-opens
T12). Multi-line pastes go through an editable confirmation dialog. Any
controlled Radix `AlertDialog` opened without a trigger MUST return focus
to the terminal in `onCloseAutoFocus`. Radix dismiss callbacks may run a
stale closure — read live state through a ref.

## 18. Release

1. `node scripts/bump-version.mjs X.Y.Z`.
2. Move `CHANGELOG.md` `[Unreleased]` into `## [X.Y.Z] - <date>`.
3. Merge to main, then `git tag -a vX.Y.Z && git push origin vX.Y.Z`.

`release.yml` asserts tag == `tauri.conf.json` version and a non-empty
changelog section, builds unsigned bundles for macOS (arm64 + x86_64),
Windows, Linux (`.deb` + `.rpm`, x86_64 + aarch64), runs the no-phone-home
scan on each, and publishes a GitHub Release with `SHA256SUMS.txt`.
Artifacts are renamed to the names GitHub serves (each space becomes `.`)
before they are checksummed, and the publish job uploads nothing unless
every name is one GitHub keeps unchanged and `SHA256SUMS.txt` lists exactly
the uploaded files and passes `sha256sum --check`. If a new character in an
artifact name trips it, map that character in the rename rather than
widening the check. There is no updater: users install the next release by
hand.

## 19. Model list

`MODEL_REGISTRY` in `src/components/ChatPanel.tsx` is the picker's
built-in list (display name + level); order matters — the first entry
whose provider has a key is the default. A model that ships after a
release is added by the user under Settings → API keys → *Additional
model ids* (`preferences.customModelIds`, rendered under "Other"). Adding
a registry entry is a frontend-only change; `usage::pricing_for_model`
(internal checkpoint only) infers cost from the `opus`/`sonnet`/`haiku`/`gpt`
substring.

## 20. Local OS terminal

`transit_localpty` (portable-pty) spawns a local shell. **HUMAN input —
NOT an agent surface**: it is deliberately not composed into the agent's
`UnifiedScrollbackSource` / `UnifiedSessionExecutor`. Do NOT add a
`LocalPtyState` argument to any agent-side seam. `Vendor::LocalShell`
default-denies. `[terminal] enabled` is the MDM off-switch. T42.

## 21. Files pane (SFTP)

`transit_files` is a transport-agnostic engine; `FilesState` joins NO
agent seam and NO shared transport dispatch (`files_*` IPC is disjoint).
`deny.toml` bans `transit_files` outside `transit_app`. Upload is a
structured human device write owned in T43. `[files] enabled` is the
DLP off-switch. Anything touching `transit_files::sanitize` or the
transfer engine's path joins → security review.

## 22. PCaps

The first agent-visible surface, through a **trait**
(`transit_agent::capture::CaptureSource`) rather than a dependency
(`transit_pcap` is banned outside `transit_app`). The model receives the
~1,500-token digest, never packets. `query_capture` is served by
`DefaultDispatcher` (read-only, no device, no modal). Live capture drives
the OS's own `tcpdump` / `pktmon`; `[pcap] enabled` and `[pcap]
agent_access` are the off-switches. Anything that would put packet
payload within the agent's reach is a Rule 2 / §8 event. Windows-`cfg`
code must be linted with `cargo clippy --target x86_64-pc-windows-gnu`.
T44/T45.

## 23. Commit / PR checklist

> External contributors: the process (issue first, `Closes #` in the PR,
> DCO `Signed-off-by` on every commit, tests performed) is in
> `CONTRIBUTING.md`; this list is the mechanical half of its checklist.

- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`.
- [ ] `npm run lint`, `npm run format:check`, `npm run test`, `npm run build`, `npm audit --audit-level=high`, `npm run license:check`.
- [ ] `gitleaks detect` clean.
- [ ] README + `CHANGELOG.md` `[Unreleased]` updated for user-visible changes.
- [ ] Sensitive-path diffs (§9): `transit-security-audit` skill. Agent-touching diffs: `transit-agent-firewall-test` skill + `cargo test -p transit_agent --test prompt_injection_corpus` + `--lib agent_loop`.
- [ ] New deps → `docs/security/licenses.md`; new threats → `docs/security/threat-model.md`.
- [ ] New `tauri::command`, capability, or outbound host: justified in the PR; the no-phone-home scan still passes.
- [ ] New third-party GitHub Action references SHA-pinned with the tag as a trailing comment.

## 24. Glossary

- **Policy gate** — `transit_policy::PolicyEngine`. Default-deny per-vendor regex list with explicit precedence + pipe-stage handling.
- **Approval modal** — the dialog requiring an explicit click before a proposed command runs; cannot be dismissed by Enter/Escape/focus-loss.
- **Redaction filter** — `transit_agent::redaction::RedactionFilter`. Strips PEM blocks, encrypted-password lines, keys, JWTs and other secret-shaped tokens before scrollback reaches the model.
- **The agent firewall** — the architectural property that the agent has no code path to a credential, enforced by the workspace dependency graph.
- **TOFU** — trust on first use; first connect records the host key, a later mismatch triggers the changed-key modal.
- **BYOP / BYOM** — bring your own policy / bring your own model.
- **Capture digest** — the size-independent summary the agent reads instead of packets.
- **No-phone-home scan** — `scripts/no-phone-home-scan.sh`; the Fourth Rule as a build gate.
