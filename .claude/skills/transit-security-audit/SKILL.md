---
name: transit-security-audit
description: Project-specific security audit for diffs touching Transit's secret-handling, agent firewall, IPC commands, capabilities, CSP, file-transfer surface, or the direct-provider / TLS code. Narrower than the built-in security-review skill; checks the Transit-specific Inviolable Rules. Run on any PR diff that touches src-tauri/crates/transit_auth/, transit_agent/, transit_tls/, transit_files/, src-tauri/src/files.rs, src-tauri/capabilities/, src-tauri/tauri.conf.json, or transit.toml parsing.
---

# Transit security audit

A narrower sibling to the built-in `security-review` skill. This skill
audits a diff (or a commit, or a working tree) against the
**Transit-specific** Inviolable Rules. Use it when the broad
`security-review` skill is overkill but you still want a security
review on a sensitive area.

## When to invoke

Auto-trigger on any diff that touches:

- `src-tauri/crates/transit_auth/` — the sole secret holder
- `src-tauri/crates/transit_agent/` — the agent firewall surface
  (incl. the BYOM local clients `llm/ollama.rs`,
  `llm/openai_compat.rs`, and the transport-policy module
  `llm/transport.rs` — T35)
- `src-tauri/crates/transit_tls/` — the one TLS trust-anchor builder
  (T27, T40); `transit_agent/src/llm/direct.rs` — the two provider
  clients and the key's only exposure point (T54)
- `src-tauri/src/local_models.rs` + the `[local_models]` parsing in
  `src-tauri/src/commands.rs` — endpoint registry + keychain tokens
- `src-tauri/crates/transit_files/` + `src-tauri/src/files.rs` — the
  Files (SFTP) surface: remote-name sanitization boundary, the
  local-filesystem ops, and the `files_*` IPC (T43)
- `src-tauri/crates/transit_pcap/` + `src-tauri/src/pcap.rs` +
  `src-tauri/crates/transit_agent/src/capture.rs` — the PCaps surface:
  the `CaptureSource` seam, the wire-string sanitizer, the command line
  that runs as root (`live.rs`), and the `pcap_*` IPC (T44/T45)
- `src-tauri/capabilities/*.json` — Tauri permission surface
- `src-tauri/tauri.conf.json` — CSP, security config
- Any `transit.toml` parsing code in `transit_core::inventory`
- `deny.toml` — license / advisory / ban posture
- `.husky/`, `lint-staged.config.js`, `eslint.config.js` — review-bypass risk

Manual invocation: "run the security audit" or "audit this diff."

## Checklist

Walk the diff line-by-line against this list. Report each finding as
**PASS / WARN / FAIL** with a one-line justification.

### A. Secret hygiene (rules from `feedback_secret_types`,
### `feedback_logging_redaction`, `feedback_no_secrets_to_frontend`)

1. Any new credential-bearing struct: does it use `secrecy::SecretString`
   or `SecretBox<T>`? Has it `#[derive(ZeroizeOnDrop)]` (or manual
   equivalent)? Does its `Debug` impl emit `[REDACTED]`?
2. Any new `#[tauri::command]`: does it return anything that contains a
   secret-shaped type? (Should be **never** except `enroll_secret`.)
3. Any new `info!`, `warn!`, `error!` call: does the format string or
   structured fields include a value that might be a secret? Even if
   the type is `SecretString` (whose `Debug` redacts), prefer logging
   the *fact* not the *value* — `device = %device.id` not `?auth`.
4. Any new `Serialize` derive on a struct with a secret-bearing field?
   That's a regression — `secrecy` is built without its `serde` feature
   so `SecretString`/`SecretBox` can't be serialized; flag any wrapper
   type that re-adds a `Serialize` path around a secret.

### B. Agent firewall (rules from `feedback_four_tools_only`,
### `feedback_agent_auth_dependency`, `feedback_redaction_boundary`)

5. Any change to `transit_agent/Cargo.toml` adding a new dep — is it
   `transit_auth`? (HARD FAIL.)
6. Any change to `transit_agent/src/tools.rs` adding a variant? Tool
   count is **6** as of v6.0.0 (`propose_api_call` — GET-only, no
   `method` field; `query_capture` — read-only, metadata-only, no
   payload/bytes/raw variant). Any further change must be deliberate and
   accompanied by updates to the `transit-agent-firewall-test` skill's
   expected count AND the `const_assert_eq!(TOOL_CALL_VARIANT_COUNT, …)`.
7. Any change to the redaction filter (`transit_agent::redaction`) —
   are the new patterns paired with proptest generators? Are the
   fixture corpora updated?
8. Any new code path that delivers scrollback bytes to the LLM
   without going through the redaction filter? FAIL.

### C. Policy gate (rules from `feedback_policy_and_modal`,
### `feedback_default_deny`)

9. Any change to `transit_policy::PolicyEngine` — is default-deny
   preserved on no-match? Any new "permissive mode" or "default
   permit" toggle is a HARD FAIL.
10. Any change to the agent loop that bypasses either the policy
    gate or the UI approval modal? FAIL.

### D. IPC + capabilities (rules from `feedback_no_secrets_to_frontend`)

11. Any change to `src-tauri/capabilities/*.json` adding a permission
    — what does it grant? Is it justified inline / in CLAUDE.md? Is
    `core:fs:*` or `core:shell:*` being added? (Strong WARN; needs
    explicit justification.)
12. Any change to `src-tauri/tauri.conf.json` `app.security.csp`:
    - Adding a new `connect-src` host? If it's a provider hostname
      (api.anthropic.com, api.openai.com), HARD FAIL — production
      reaches providers only through `llm::direct` with a keychain-sourced `SecretString`.
    - Loosening any directive (`*`, `'unsafe-eval'`)? FAIL.

### E. Provider keys + outbound hosts (Fourth Rule, T54)

14. Every outbound HTTP client is built by `transit_tls::build_http_client`
    or `llm::transport` (no redirects, no ambient proxy, OS-store or
    webpki trust). A bare `reqwest::Client::new()` on a path that carries
    a key is a HARD FAIL.
15. The provider key is read ONLY in `transit_app` (`provider_keys.rs`)
    and handed to `DirectAnthropic` / `DirectOpenAI` as `SecretString`.
    Any `expose_secret()` outside the auth-header site in `direct.rs` is
    a HARD FAIL. No env-var or config-file path for the key may exist.
16. No new outbound hostname anywhere in the tree unless the PR adds a
    threat-model entry AND `scripts/no-phone-home-scan.sh` still passes.
    An update check, crash reporter or usage ping is a HARD FAIL.
17. `provider_keys_status` returns booleans only; no IPC returns a key.
### E2. BYOM local models (threat-model T33–T35)

23. `chat_send_message`'s BYOM send-gate (`ensure_local_send_allowed`)
    must run for every `is_local_model` id BEFORE the factory builds a
    client; its ONLY input is `[local_models] enabled` (there is no
    sign-in or entitlement in this edition). Removing the gate, or
    making it depend on anything the agent can influence, is a FAIL.
24. Transport policy: the loopback pin on the zero-config path and
    the https-off-loopback rule for endpoints live ONLY in
    `llm/transport.rs` and must be consulted by BOTH the config layer
    and the clients. A second, divergent URL check is a WARN; removing
    a re-check is a FAIL.
25. Endpoint bearer tokens: write-only IPC (set/clear), keychain
    storage, attached only as `Authorization` to that endpoint. Any
    read-back IPC is a HARD FAIL (Rule 1).
26. The `:cloud`-tag exclusion in `ollama::probe`/`probe_with` must
    keep cloud-proxied models out of every selectable list (T33).
27. The T34 truncation guard: the pre-send estimate must run before
    any HTTP on both local clients, and `pricing_for_model` /
    `LoopBounds::for_model` / factory routing must all consult the
    single `is_local_model` predicate (a divergence zero-prices a
    cloud model — see `pricing_predicate_matches_local_routing`).

### E3. Files surface (v5.0.0; threat-model T43)

28. The Files surface must stay **agent-blind and Rule 1-clean**: no
    `files_*` command returns anything but session ids / paths / entry
    metadata / transfer counts (never a credential); `FilesState` (or a
    `FilesSession`) is passed to NO agent-side seam — it must appear in
    neither `UnifiedScrollbackSource` nor `UnifiedSessionExecutor` in
    `chat.rs`, nor in `scoped_session_view`, and Files sessions must join
    no shared transport dispatch (`send_input` / `resize_pty` /
    `clear_scrollback` / `disconnect_session` / `list_open_sessions` /
    `session_log` / `session_export` / `capture`); the `transit_files`
    `[[bans.deny]]` entry stays with `wrappers = ["transit_app"]`. Any of
    those is a HARD FAIL. Also confirm the `transit_files::sanitize`
    boundary still rejects remote-supplied names that are `.`/`..`, empty,
    or contain a separator BEFORE any local path join, that the recursive
    walker still refuses remote symlinked directories, and that the
    `[files] enabled` off-switch is still enforced in `files_connect`,
    `files_reconnect`, and every `files_local_*` command.

### E4. PCaps surface (v6.0.0; threat-model T44/T45)

29. **The `CaptureSource` trait is the whole of the agent's reach.** Any
    new method on `transit_agent::capture::CaptureSource`, or any new
    variant of `CaptureQueryKind` / `CaptureQueryWire`, is a **Rule 2 /
    §8 event** even without a new `ToolCall` variant — it widens what the
    model can ask for. A variant or field that would return packet
    payload, reassembled stream bytes, or a file path is a **HARD FAIL**:
    wire payload is the densest credential surface a capture holds, and
    it stays out of the model's context by being unaskable, not by being
    filtered. Confirm `List`/`Overview` remain empty STRUCT variants
    (serde ignores unknown fields on unit variants of an internally
    tagged enum, so a unit variant would let
    `{"kind":"overview","payload":true}` parse).
30. **The three human-only capabilities stay human-only.**
    `pcap_packet_bytes`, flow reassembly, and export must appear in the
    `pcap_*` IPC and **never** on `CaptureSource` or in `PcapCaptureSource`'s
    `query` match. HARD FAIL otherwise.
31. **Redact-before-trim on the capture path.** The `QueryCapture` arm in
    `dispatcher_impl.rs` must run `ConversationRedactor::redact` on the
    engine's answer BEFORE `cap_head_tail`, and frame the result
    `<capture id="…">`. Reordering those, or dropping the framing, is a
    FAIL — a pre-redaction trim can shear a secret past its matcher, and
    unframed content loses the injection guard.
32. **`live.rs` is the only place a Transit string reaches a shell.**
    Any new command construction must build an argv, not a shell string.
    The macOS `osascript` path must keep both escaping layers
    (`shell_quote` then `applescript_quote`), and `validate_bpf` must run
    before any filter string is used, on every platform. Loosening the
    charset allowlist to admit `$`, backtick, `;`, quotes, backslash or
    newline is a HARD FAIL.
33. **Windows filters are refused, never widened.** `bpf_to_pktmon` must
    return `Err` for anything outside its translatable subset. A change
    that makes an untranslatable filter fall back to an empty filter
    list, or to `--comp nics`, is a **HARD FAIL** — it silently records
    the whole segment when the user asked for one host.
34. **Bounded by construction.** `preflight` must keep refusing an
    interface we did not enumerate, a zero rotation ceiling, and an
    insufficient-disk start. Removing any of those is a FAIL.
35. **Both off-switches stay enforced per call.** `[pcap] enabled` gates
    every `pcap_*` command except `pcap_close`; `[pcap] agent_access`
    gates BOTH `list` and `query` on `PcapCaptureSource`. Caching either
    (reading once at startup) is a FAIL — a DLP-locked deployment must
    not be circumventable through an already-open tab.
36. **`transit_pcap` stays out of `transit_agent`.** The `[[bans.deny]]`
    entry keeps `wrappers = ["transit_app"]`. The agent sees captures
    through a trait, never the engine.
37. **Wire strings stay sanitized.** `transit_pcap::sanitize` is the one
    door: `Field::text` / `Field::long_text` are the only constructors
    for a string field, and `Ctx::set_info` sanitizes the info line.
    Adding a second path that builds a `FieldValue::Str` or assigns
    `Dissection::info` directly is a FAIL.

### F. License + supply chain (rules from `docs/security/licenses.md`)

17. Any new dep added: is it on the license allowlist? If MPL-2.0,
    is it tracked in the licenses doc?
18. Any new git remote in `deny.toml` `[sources].allow-git`? Strong
    WARN; needs explicit justification.
19. Any RustSec advisory ignore added to `deny.toml`? Has it a
    one-line justification? A remove-by checkpoint?

### G. Review-bypass risk

20. Any change to pre-commit hooks, `eslint.config.js`,
    `.prettierrc.json`, `lint-staged.config.js`, or
    `.github/workflows/ci.yml` that disables a check? Strong WARN;
    requires written justification.

## Output format

```
Transit security audit — N checks across 7 categories
  Section A (secret hygiene): N/N pass
  Section B (agent firewall): N/N pass
  ...

Findings:
  [PASS] item 1 description
  [WARN] item 11: capability X added — justification: ...
  [FAIL] item 14: reqwest::Client::new() on the provider path in
         transit_agent/src/llm/direct.rs:71 — must be built by
         transit_tls::build_http_client (no redirects, no proxy). Route via
         the proxy.

Action: 1 FAIL must be resolved before merge. 1 WARN should be
acknowledged in the PR description.
```

## When to escalate to the broad `security-review` skill

- The diff touches code outside the auto-trigger list above and you
  see something that looks security-relevant.
- The diff is large or restructures a security-load-bearing crate.
- A FAIL above hints at a deeper issue (not just the surface
  violation).

In those cases, run the broader `security-review` skill **after**
this one to get a second pass.
