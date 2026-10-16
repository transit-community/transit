# Transit Community Edition — scope + plan

> **Status (2026-09-19):** steps 1–6 of §8 are IMPLEMENTED in this working
> tree (all Rust + frontend gates green; release binary passes
> `scripts/no-phone-home-scan.sh`). NOT done, by instruction: step 7 — no
> orphan commit, no remote, nothing pushed. Also not yet done: a manual
> smoke against real provider keys, and the per-platform release builds
> (`release.yml` is written but has never run). Q5/Q6 proceeded on the
> stated assumptions. Decisions Q1–Q4 in §10.
>
> **Identifier sweep (2026-09-21):** a second pass over every tracked file,
> comments included, removed the remaining personal, customer, vendor and
> lab identifiers (people's names, a customer ISP and its locale, an
> attorney and firm, lab IP ranges → TEST-NET, a personal-brand theme and
> its domain, image XMP/C2PA metadata, private-repo names, commit refs,
> the proprietary-edition pentest vendor). The app data directory is now
> `TransitCommunity` in code as well as docs, so the edition never reads
> or writes a proprietary install's files. What remains by design: the
> product name "Transit", the maintainer's name in `NOTICE`, the two
> provider hostnames, and this record.
>
> **Design docs removed (2026-10-14):** the sixteen historical design
> documents §3.3 kept were deleted after review; code comments that cited
> them now say so. This file is the only design record that ships.
>
> **Dependency train ported (2026-10-06):** the proprietary 6.5.9 train
> (russh 0.63.3 + host-certificate refusal, Tauri 2.12, React 19.3,
> Vitest 5, rustls 0.23.45, npm `overrides` pins) is applied here, so the
> fork base is now 6.5.9. Deferred upstream and deferred here for the same
> reasons: TypeScript 7, react-resizable-panels 4, age 0.12, portable-pty
> 0.9, dirs 7, sha2 0.11, fontdb 0.24, happy-dom > 20.12.0.
>
> **Purpose (Knox, 2026-09-19):** a wind-down contingency. If Transit AI
> ever closes, this edition is what gets published so the app survives
> its infrastructure. Every design choice below therefore assumes
> **Transit Cloud, Clerk, Stripe, the downloads host, and the update
> manifest no longer exist** — not merely that they are unused. The
> patent impact is understood and accepted (Knox, same day).

## 1. Goal and non-goals

**Goal.** An open-source build of the Transit desktop app that:

1. Contains **no reference to Transit AI infrastructure** — no hostname,
   no token, no signing key, no CI secret name, no update endpoint, no
   deep-link OAuth scheme. Verified by a build-time scan (the inverse of
   today's Rule 4 scan).
2. Has **BYOK unlocked and direct**: the user's Anthropic or OpenAI key
   is stored in the OS keychain and sent **only to that provider**, over
   TLS verified against the OS trust store. No proxy, no metering, no
   entitlement check.
3. Has **BYOM unlocked**: the Ollama / OpenAI-compatible local path
   works with no sign-in, no "local pass", no tier.
4. Keeps **every device-side security property unchanged**: Rule 1 (no
   secret over IPC), Rule 2 (exactly six agent tools), Rule 3 (gate AND
   modal), redaction, TOFU, policy gate, agent firewall. Those are
   properties of the desktop and lose nothing when the cloud goes.
5. Ships **no telemetry, no phone-home of any kind**. The only outbound
   HTTP the binary can make is to (a) the provider the user configured,
   (b) the local model endpoint the user configured, (c) devices in the
   user's inventory.

**Non-goals.** Keeping paid-tier concepts (tiers, budgets, overage, trial,
spend-pause, notices) in any form. Preserving auto-update. Keeping
private planning documents. Code signing.

## 2. What the copy already did (step 0, done)

`rsync` of `transit-app/` → `transit-app-community/`, excluding
`node_modules/`, `src-tauri/target/` (158 GB), `dist/`,
`.claude/worktrees/`, `*.tsbuildinfo`, and the two user-local config
files (`transit-config.toml`, `transit.toml`). Result: 46 MB, of which
29 MB is `.git`.

`gitleaks detect` over all 509 commits of the copied history: **no leaks
found.** That is necessary but not sufficient — see §3.1.

## 3. Repository hygiene (the repo itself, before any code change)

### 3.1 History must be reset — even though gitleaks is clean

gitleaks finds *secret-shaped strings*. It does not find the things
that actually make this history unpublishable:

- `plans/` — Stripe integration, enterprise accounts, billing flow,
  prod cutover, D1 backup, GitHub audit-log archive, free-trial legal
  draft, customer-email builds, attribution/UTM. 171 partner/vendor
  hits in the enterprise-accounts plan alone. Business-confidential.
- `pentest/pentest_prop.pdf` — a vendor's proposal. Their confidential
  document, not ours to publish. `attack-coverage.md` names the vendor.
- `docs/privacy-policy-input.md` — counsel input, owner email, data-flow
  detail for a product whose cloud will not exist.
- `.claude/skills/build-release-artifact/SKILL.md` — SSL.com username,
  notarization key paths, Team ID shape, 1Password item names.
- `CLAUDE.md` (108 KB) — "closed-source commercial", Knox's name and lab,
  cloud runbooks (§19), model rollout (§23), billing tiers. Every §
  referencing the cloud describes infrastructure that must not be
  described in a public repo, and the whole file is an internal
  operating manual.
- `CHANGELOG.md` (116 KB) — tier names, prices, customer-shaped
  requests, cloud version pins.
- Commit messages and PR references across 509 commits.

**Action:** publish from a **fresh root commit** (orphan branch or
`git init`), after the deletions in §3.2 land. Keep the private copy's
`.git` locally for provenance; never push it. Set `origin` to the new
public repo (today it still points at `<the private origin repo>`).

### 3.2 Delete outright

| Path | Why |
|---|---|
| `plans/*` except the design docs listed in §3.3 | business/infra planning |
| `pentest/` | vendor-confidential |
| `docs/privacy-policy-input.md` | counsel input |
| `.claude/skills/build-release-artifact/` | signing/notarization procedure + personal identifiers |
| `.github/CODEOWNERS` | names `@AiKnox` and a review structure that won't exist |
| `.github/workflows/release-dev.yml`, `release-prod.yml`, `release-pentest.yml`, `release-build.yml` | R2, Apple, SSL.com, updater-signing secrets (17 `secrets.*` names) |
| `scripts/build-updater-manifest.mjs`, `update-manifest.mjs`, `sign-windows.mjs`, `register-deeplink-macos.sh`, `release-symbol-scan.sh` | updater manifest, R2 versions.json, SSL.com CodeSignTool, deep-link OAuth, Rule 4 scan (replaced, §6.3) |
| `src-tauri/crates/transit_cloud_client/` (except `tls.rs`, §4.1) | the cloud client: auth, tokens, `/me`, entitlements, revision tracker, local pass |
| `src-tauri/src/cloud.rs`, `channel.rs`, `network.rs` | sign-in/deep-link, compile-time cloud URLs, reachability probe of `CLOUD_HOST` |
| `src-tauri/crates/transit_net/` | its only consumer is the cloud reachability probe (offline banner) |
| `src-tauri/crates/transit_agent/src/llm/dev.rs` | promoted, not deleted — becomes `direct.rs` (§4.2) |
| Frontend: `SignInDialog`, `AccountChip`, `TermsGate`, `TrialBanner`, `BudgetBanner`, `SpendPauseBanner`, `NoticeBanner`, `SubscriptionRequiredPanel`, `UpdateBanner`, `OfflineBanner`, `lib/cloud.ts`, `lib/updater.ts` + their tests | every one is a cloud/billing/updater surface |

### 3.3 Keep, but review line-by-line

| Path | Action |
|---|---|
| `plans/` design docs that explain *desktop* architecture: scoped-vendor-policy-and-byop, connection-import, tls-inspection-trust, ssh-key-file-auth, broadcast-input-bar, chat-device-scope, byom-local-models, local-terminal-surface, files-pane-sftp, pcaps-surface, interactive-keyboard-auth, agent-session-aliases, netbox-integration, agent-chat, jump-hosts, device-scoped-host-key-pins | Keep as `docs/design/`; strip "Knox decided", tier references, cloud dependencies. `byom-local-models` needs its entitlement section removed. |
| `docs/security/threat-model.md` | Remove cloud threats T9, T13–T17 (cloud leak, tenant isolation, provider training, spend runaway, refresh reuse), T29 (trial abuse), T30 (BYOK model unlock), T32 (local pass). Rewrite T27 (TLS inspection) for provider hosts. Add T_DIRECT_KEY (§4.2). Everything device-side stays. |
| `docs/security/secrets.md`, `licenses.md` | Remove cloud-token keyring entries; update dependency list. |
| `CHANGELOG.md` | Start fresh at `## [Unreleased]` with a "forked from Transit 6.5.8" note. The old file is business history. |
| `README.md` | Rewrite: what it is, what it is NOT (no account, no cloud), how to add a key, build instructions. Drop `## Status` (tier/cloud content), drop `## License` proprietary text. |
| `CLAUDE.md` | Rewrite as a contributor guide (~20 KB not 108): the Three Rules, the crate map, runbooks §6–§8, §15–§18, §20, §24–§27 (all desktop-side). Drop §4 (cloud), §19, §21–§23. Remove the user/lab paragraph. |
| `ARCHITECTURE.md`, `CODE_REVIEW.md` | Remove cloud sections; keep the rest. |
| `SECURITY.md` | Replace `security@<the company domain>` + URL with the new repo's advisory process (GitHub private vulnerability reporting). |
| `.github/workflows/ci.yml` | Keep; remove the release-symbol-scan step (replaced), remove any channel-feature matrix. |
| `.github/workflows/win-probe.yml` | Keep (it is the pcap Windows probe, not release infra). |
| `.claude/skills/transit-agent-firewall-test`, `transit-security-audit` | Keep; remove `transit_cloud_client` and channel references from both. |
| `deny.toml` | Remove `transit_cloud_client` from the `keyring` wrappers; add `transit_tls`. License block: swap `LicenseRef-Proprietary` for the chosen license (§9 Q2). |
| `transit.toml.example` | Fine as-is (device inventory only). |
| `policies/`, `src/lib/collections/`, `scripts/gen-*-collection.mjs` | Fine — vendor policy YAML and generated API collections from public docs. |
| `src/assets/fonts/` | Fine — OFL, licence files already bundled. |

### 3.4 Residue scan (run after everything above)

```bash
grep -rIn --exclude-dir=.git --exclude-dir=node_modules -iE \
  'transitai|clerk|stripe|the dev cloud|downloads\.|hobbyist|operator tier|entitle|local.?pass|trial|overage|spend.?pause|knox' .
```
Must return zero hits in code, config, and docs before the orphan commit.

## 4. Rust changes

### 4.1 New crate `transit_tls` (extracted, not written)

`transit_cloud_client/src/tls.rs` (415 lines) is the one part of the
cloud crate that is **not** about the cloud: it is the OS-trust-store
TLS builder (`build_http_client(strict)`, `os_store_tls_config`,
`PinStore` / `PinAwareVerifier` for the controller cert-pin TOFU). It
already has three non-cloud consumers:

- `transit_api::client` (controller REST + cert pinning, T40)
- `transit_agent::llm::transport` (BYOM custom endpoints, T35)
- `set_strict_tls` in `commands.rs` (`[network] strict_tls`, T27)

Move it verbatim to `crates/transit_tls/`, retarget the three
consumers, carry its tests (`tests/tls_trust.rs`). The §9 protection
("a regression could silently relax verification") transfers to the new
path. `[network] strict_tls` now governs provider calls instead of
cloud calls — same semantics, same UI row.

### 4.2 `transit_agent::llm` — direct providers become production

Today: `TransitCloudAnthropic` / `TransitCloudOpenAI` post to the proxy
with optional `_byok` body fields; `DevAnthropic` / `DevOpenAI`
(`dev.rs`, 165 lines, `#[cfg(debug_assertions)]`) post to the providers
directly and already reuse the same body builders and stream parsers.

Change:

1. `dev.rs` → `direct.rs`, production-compiled, renamed
   `DirectAnthropic` / `DirectOpenAI`. Constructors take
   `SecretString` only; `from_env()` is removed (the keychain is the
   single key source — an env-var path is a second, weaker one).
2. HTTP client comes from `transit_tls::build_http_client(strict)`, not
   `reqwest::Client::new()`, so strict-TLS applies and the trust anchor
   is the OS store. Decide whether to honour `HTTP_PROXY` — see §9 Q5.
   No redirects (a 3xx must never carry the key elsewhere).
3. Delete `TransitCloudAnthropic` / `TransitCloudOpenAI` and the
   `byok: Option<...>` parameter of `build_anthropic_body` /
   `build_openai_body` (the `_byok` / `_byok_key` fields with it).
   `anthropic.rs` / `openai.rs` keep their body builders, cache-control
   annotation, and SSE parsers — the bulk of both files.
4. `LlmError::Cloud(transit_cloud_client::Error)` → new variants:
   `Http(reqwest::Error)`, `Status { status, body }`, `MissingKey
   { provider }`, `AuthRejected` (401/403 from the provider: the key is
   wrong or revoked). `chat.rs::user_facing_provider_error` maps these
   to plain copy: 401 → "Anthropic rejected the key — Settings → API
   keys"; 429 → rate-limited; 529/503 → overloaded. Drop the
   `model_requires_byok` / `model_not_allowed` branches.
5. Remove `transit_cloud_client` from `transit_agent/Cargo.toml`. The
   firewall (`deny.toml`) is unaffected: `transit_agent` still cannot
   see `transit_auth` or `keyring`; the key is constructed by
   `transit_app` (which reads `byok.rs`'s keychain entry) and handed
   in as a `SecretString`, exactly as the BYOK path does today.
6. `tests/smoke_messages_stream.rs` — retarget to the direct clients
   behind the same env-var opt-in.
7. Threat model **T_DIRECT_KEY**: the provider key now leaves the
   machine, to one host, over OS-verified TLS, in a header. Mitigations:
   keychain-only storage; write-only IPC (`byok_set_key` unchanged);
   `SecretString` throughout (`Debug` = `[REDACTED]`); no redirect
   following; strict-TLS opt-in; the residue scan guarantees the binary
   knows no other host.

### 4.3 `transit_app` (`src-tauri/src/`)

- **`lib.rs`** — drop `default_client`, `CloudState`, the deep-link
  handler, `tauri_plugin_deep_link`, `tauri_plugin_single_instance`
  (only needed to forward deep-link URLs; if a second instance is still
  undesirable keep it without the `deep-link` feature),
  `tauri_plugin_updater`, `tauri_plugin_process`. Remove the eleven
  `cloud::*` commands from `generate_handler!`.
- **`chat.rs`** — `ChatState::new(cloud)` loses the parameter.
  `provider_route` becomes: `is_local_model` → Ollama/compat (unchanged);
  else model prefix `claude-` → `DirectAnthropic` with the keychain key;
  `gpt-`/`o` → `DirectOpenAI`; no key → `MissingKey`.
  `ensure_local_send_allowed(enabled, signed_in, pass_valid,
  entitled_online)` → `ensure_local_send_allowed(enabled)`; the 12-case
  test table shrinks to two rows. Remove `last_known_local_models_entitled`,
  `local_pass_status` reads, entitlement-revision events.
- **`byok.rs`** — keep the keychain store (`transit-byok` service; rename
  per §9 Q3). `byok_set_use` / `read_use_byok` go — there is no
  "cloud-resident" alternative to toggle against. Keep `byok_status`
  (booleans only, Rule 1). Consider renaming the module `provider_keys`
  since "bring your own" implies an alternative.
- **`commands.rs`** — `resolve_strict_tls` stays (now provider TLS).
  Remove any `[local_models]` entitlement checks; `enabled` is the only
  gate. Remove `TRANSIT_*` env overrides that referenced the cloud
  (none found — the config surface is already local-only).
- **`local_models.rs`** — `local_models_status` drops entitlement
  fields (`entitled`, `pass_valid`).
- **`agent_loop` bounds** — `checkpoint_cost_microdollars` still works
  (pricing is inferred from the model id, never shown). Keep it: it is a
  loop bound, not billing. Confirm `usage::pricing_for_model` has no
  cloud dependency (it does not).
- **Cargo features** — delete `dev-channel` / `prod-channel` and their
  `compile_error!` guards; the build has one shape.

### 4.4 Tauri config + capabilities

`tauri.conf.json`:
- `csp.connect-src` → `'self' ipc: http://ipc.localhost`. (All LLM and
  device HTTP is Rust-side; the webview never needed the provider hosts,
  and Clerk goes.)
- Remove `plugins.deep-link`, `plugins.updater` (endpoint + minisign
  pubkey `<the updater key id>` — that pubkey identifies Transit's signing key;
  remove it, do not leave it as a comment).
- Remove `bundle.windows.signCommand`.
- `identifier` / `productName` — see §9 Q3.

`capabilities/default.json`:
- Remove `deep-link:default`, `updater:*`, `process:allow-restart`.
- `opener:allow-open-url` allow-list: remove all `<the company domain>`,
  `<the billing portal>`, `mailto:support@<the company domain>` entries. Keep the
  permission only if the app still opens any URL (e.g. the GitHub repo
  from Settings → About); otherwise remove it entirely.

## 5. Frontend changes

- **`App.tsx` / `MainArea.tsx`** — remove `useMe`, `TermsGate`,
  `SignInDialog`, `TrialBanner`, `NoticeBanner`, `UpdateBanner`,
  `OfflineBanner`, `AccountChip`.
- **`ChatPanel.tsx`** — the model picker no longer reads
  `me.entitlements.allowed_models` / `byok_models`. Source becomes:
  `MODEL_REGISTRY` (static, already present with display names and
  levels) filtered by "key present for this provider" (from
  `byokStatus`), plus the dynamic Local group (unchanged), plus a
  free-text custom model id (new model ids ship without an app
  release, matching today's §23 forward-compat intent). Default =
  first model whose provider has a key, else first local. The
  `SubscriptionRequiredPanel` branch becomes a "no key, no local model"
  empty state pointing at Settings → API keys / Local models.
- **`SettingsDialog.tsx`** (105 hits — the largest single edit) — remove
  tabs `account`, `billing`, `updates`. Rename `byok` → **API keys**,
  always enabled, copy rewritten ("your key is stored in the OS keychain
  and sent only to Anthropic / OpenAI"). `local-models` tab loses its
  entitlement banner. `network` keeps Strict TLS with rewritten copy.
  `about` links to the public repo.
- **`lib/api.ts`** — remove the eleven `cloud*` wrappers and `MeResponse`
  / entitlement types; keep `byok*`.
- **`lib/localModels.ts`** — drop `LOCAL_PASS_QUERY_KEY`,
  `cloudLocalPassStatus`, the `cloud:entitlement-revision-changed`
  listener.
- **`uiStore.ts`** — remove sign-in dialog state, notice dismissals,
  update-skip state.
- **Tests** — delete the tests of deleted components; rewrite
  `ChatPanel.test`, `SettingsDialog.test`, `chat.test` for the
  key-present gating; `KeyboardInteractiveDialog` and `FileListPane`
  show incidental hits (word "tier"/"terms" in copy) — check, likely
  no-ops.

## 6. Build, release, and the new guarantee

### 6.1 CI
`ci.yml` stays the gate: fmt, clippy `-D warnings`, `cargo test
--workspace`, `cargo deny`, eslint/prettier/vitest, `npm audit`,
`license:check`, gitleaks. Drop the release-symbol-scan step and the
channel feature matrix.

### 6.2 Release
One `release.yml` on tag `v*`: **unsigned** macOS (aarch64 + x86_64),
Windows NSIS/MSI, Linux `.deb`/`.rpm` (x86_64 + aarch64), published to
GitHub Releases with `SHA256SUMS.txt`. No Apple, SSL.com, R2, or
minisign secrets exist in this repo. Document the unsigned-install
steps (macOS `xattr -d com.apple.quarantine`, Windows SmartScreen
"more info → run anyway") in the README. `bump-version.mjs` and
`extract-changelog.mjs` stay.

### 6.3 The inverse symbol scan (`scripts/no-phone-home-scan.sh`)
Rule 4's scan banned `api.anthropic.com` / `api.openai.com` from release
binaries. The community build inverts it: the release binary must
contain **no** `<the company domain>`, `clerk`, `stripe`, `the dev cloud`,
`downloads.` string, and no `TransitCloud*` / `Clerk*` symbol. Run on
every release leg. This scan *is* the "no phone-home" promise, made
checkable — it belongs in the README.

## 7. Verification checklist (before the first public tag)

- [ ] §3.4 residue grep = 0 hits.
- [ ] `cargo deny check` passes with the new license + `transit_tls`.
- [ ] `transit-agent-firewall-test`: variant count still 6;
      `transit_agent` depends on neither `transit_auth`, `keyring`, nor
      the (now-deleted) cloud client.
- [ ] `cargo test -p transit_agent --test prompt_injection_corpus` and
      `--lib agent_loop` green (loop-touching diff).
- [ ] §6.3 scan clean on all release binaries.
- [ ] Manual: fresh machine, no key → chat shows the empty state; add
      Anthropic key → streams; wrong key → 401 copy; add OpenAI key →
      streams; Ollama model → works with no sign-in; Strict TLS on →
      still works against public PKI.
- [ ] `strings <binary> | grep -i transitai` = nothing.
- [ ] Fresh orphan commit; `git log --oneline | wc -l` = 1;
      `git remote -v` points at the new public repo only.

## 8. Sequencing (PR-sized steps)

1. Hygiene deletions + doc rewrites (§3) — no code, reviewable as text.
2. `transit_tls` extraction; retarget the three consumers; build green.
3. `direct.rs` + `LlmError` reshape in `transit_agent`; drop the cloud
   dep; unit tests.
4. `transit_app`: remove `cloud.rs`/`channel.rs`/`network.rs`, rewire
   `chat.rs` routing and the local gate, plugins, capabilities, CSP.
5. Frontend removals + `ChatPanel`/`SettingsDialog` rewrite + tests.
6. `release.yml` + `no-phone-home-scan.sh`; first unsigned build on all
   OSes; manual verification (§7).
7. Orphan commit; push to the public repo — **only when Knox says so**.

Rough size: ~5k lines deleted (cloud crate 3.2k, `cloud.rs`, ten
components + tests), ~600 written (`direct.rs`, error mapping, picker
logic, release workflow, scan), plus doc rewrites. Steps 1–6 are a
solid week of focused work; step 7 is a decision, not work.

## 9. Open decisions (blocking — Knox)

**Q1. Fork now, or generate the fork from `main`?** A one-time fork made
today is stale by the time it is needed; every release touches
`chat.rs` and `SettingsDialog.tsx`, so merging `main` forward means
recurring conflicts in exactly the files this plan rewrites. The
alternative is a `community` Cargo feature (+ a `VITE_EDITION` flag) in
the **main** repo — the direct clients compile in, cloud compiles out —
with `transit-app-community` produced by an export script that strips
§3.2 and rewrites the docs. Then the wind-down step is "run the script,
push". Cost: two code paths in `chat.rs` routing and the Settings tabs,
and the Rule 4 scan runs only on the non-community build.
*Recommendation: feature-in-main + export script.* The copy made today
becomes the first export target either way.

**Q2. License.** Apache-2.0 carries an explicit patent grant to users —
given the provisional (64/112,268) and the wind-down intent, that is
probably what you want, but it is a legal call. MIT has no patent
language. AGPL-3.0 would prevent a closed relaunch by someone else.
*Recommendation: Apache-2.0, after a word with counsel.*

**Q3. Name and identity.** Keep "Transit" (+ icons, `com.transit.app`,
`transit://`, keychain services `transit-byok` / `transit-local-endpoint`,
config dir `Transit`) or rename ("Transit Community", identifier
`app.transit.community`, config dir `TransitCommunity`)? A distinct
identifier lets the two editions install side-by-side and keeps their
keychains and inventories apart — which matters for testing *now*, not
only at wind-down. The wordmark (serials 99867089 / 99885967) is yours
to license or abandon; the icons are also brand assets.
*Recommendation: rename identifier + config dir now; keep the product
name "Transit Community Edition" for recognition.*

**Q4. Update mechanism.** (a) None — zero outbound hosts beyond
providers; users watch GitHub Releases. (b) An opt-in "Check for
updates" button hitting the GitHub Releases API (adds `api.github.com`
as an outbound host, no auto-install). (c) Full `tauri-plugin-updater`
against GitHub Releases — requires a minisign keypair someone must
hold, which contradicts the wind-down premise.
*Recommendation: (a) now, (b) only if users ask.*

**Q5. Proxy behaviour for direct provider calls.** BYOM clients refuse
`HTTP_PROXY` (T35: a proxy is an egress channel). For Anthropic/OpenAI
calls a corporate proxy is a legitimate need — but honouring it means
the key transits the proxy. *Recommendation: refuse proxies by default,
add `[network] provider_proxy_url` as an explicit opt-in that the
Settings → Network tab surfaces with a warning.*

**Q6. Companion repos.** `transit-web` docs referenced from the app, the
`transit-downloads` Worker, the Homebrew tap and `install.sh` — none
ship in this repo, but the README should point somewhere. Are docs
for the community edition a `docs/` folder here, or nothing?

## 10. Decisions (Knox, 2026-09-19)

| Q | Decision | Consequence for the plan |
|---|---|---|
| Q1 fork model | **One-time fork, frozen** on today's 6.5.8 copy. No `community` feature in main, no forward-merges. | Steps 1–6 run once against this copy. Drift is accepted; if the wind-down comes years later, re-running §3–§6 against the then-current main is the refresh procedure — this document is that runbook. |
| Q2 license | **Apache-2.0.** | `LICENSE` = Apache-2.0 text; `workspace.package.license = "Apache-2.0"`; `package.json` `license`; `deny.toml` `[licenses]` unchanged otherwise (Apache-2.0 already allowed for deps). Add `NOTICE` naming the fork origin. Counsel should still see it before publication. |
| Q3 identity | **Rename identifier + config dir; keep the name "Transit Community Edition".** | `tauri.conf.json`: `productName` "Transit Community Edition", `identifier` `app.transit.community`. `dirs::config_dir()/TransitCommunity/` for `transit.toml`, `config.toml`, `known_hosts.toml`, chat history, captures. Keychain services `transit-byok` → `transit-ce-provider-keys`, `transit-local-endpoint` → `transit-ce-local-endpoint`, `transit-cloud` deleted. `bundle/transit.desktop` → `transit-community.desktop`. The `transit://` scheme is gone with deep-link anyway. Icons stay as-is for now (brand call deferred). |
| Q4 updates | **None.** | Remove `tauri-plugin-updater`, `tauri-plugin-process`, `updater.ts`, `UpdateBanner`, the Settings → Updates tab, and the `plugins.updater` block (incl. the minisign pubkey). README points at GitHub Releases. The §6.3 scan additionally bans `github.com` API strings so no update check creeps back in. |
| Q5 proxy | *Assumed:* refuse `HTTP_PROXY` by default; `[network] provider_proxy_url` opt-in with a Settings warning. | Reuses the T35 transport rules; one new config key. |
| Q6 docs | *Assumed:* README + `docs/` in this repo only; no companion sites referenced. | README carries install (unsigned), key setup, local-model setup, the Three Rules, and the no-phone-home scan. |
