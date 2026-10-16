# Dynamic model discovery + subscription sign-in — research and plan

> **Status (2026-10-15, later the same day):** **both parts built** —
> see `transit_agent::llm::direct` (`list_models`, `OpenAiAuth`),
> `src-tauri/src/chatgpt_auth.rs`, `src/lib/providerModels.ts`,
> `src/lib/chatgpt.ts`, threat-model T55, CLAUDE.md §4/§9. The text
> below is the research record as written before implementation; where
> the build diverged, the code and T55 are authoritative (notably: the
> chat picker labels the plan source with a group note rather than a
> separate group, and the error banner's shortcut opens Settings → AI
> providers for every credential-shaped error). Original status:
> researched, not built. Two asks from the first
> local smoke of the Community Edition: (1) stop hard-coding the model list
> so a model released after a build (Opus 5.5 today) is simply there; (2)
> let a user sign in with a consumer subscription instead of a platform
> API key. Part 1 is feasible for both providers. Part 2 is feasible and
> officially supported for OpenAI, and explicitly prohibited for
> Anthropic.

## Part 1 — Dynamic model discovery

### What the providers offer

| | Anthropic | OpenAI (API key) |
|---|---|---|
| Endpoint | `GET https://api.anthropic.com/v1/models` (`x-api-key`, `anthropic-version: 2023-06-01`) | `GET https://api.openai.com/v1/models` (`Authorization: Bearer`) |
| Per-model fields | `id`, `display_name`, `created_at`, `max_input_tokens`, `max_tokens`, `capabilities` (nested `{supported: bool}` tree: thinking types, effort levels, image input, structured outputs, …) | `id`, `created`, `owned_by`, `shutdown_date` — no display name, no capabilities |
| Noise | None: every entry is a chat model | Heavy: embeddings, TTS, transcription, realtime, image, moderation, dated snapshots all share the list |

Both are plain GETs to the two hosts the direct clients already know, so
the Fourth Rule and the no-phone-home scan are untouched; the key is the
same keychain key, exposed in the same header. Threat model T54 needs no
new entry.

### Design

**Rust (`transit_agent::llm::direct`).** Add `list_models()` to both
clients, built on the same `transit_tls` client (no redirects, no proxy).
Each returns `Vec<ProviderModel { id, display_name, created, level,
context_window: Option<u32> }>`:

- Anthropic: take `display_name` verbatim; `created` from `created_at`;
  `level` from the id family (`haiku` → easy, `sonnet` → medium, `opus`
  / `fable` → advanced); `context_window` from `max_input_tokens`. When
  `capabilities` is present, drop models where no thinking type and no
  structured output is supported (none today, but it is the right hook).
- OpenAI: keep `owned_by` ∈ {`openai`, `system`}; keep ids matching
  `^(gpt-|o[0-9])`; drop ids containing any of `audio`, `realtime`,
  `tts`, `transcribe`, `embedding`, `image`, `dall-e`, `whisper`,
  `moderation`, `search`, `instruct`, `computer-use`; collapse a dated
  snapshot (`-YYYY-MM-DD` suffix) when its bare id is also listed; drop
  anything with a past `shutdown_date`. `display_name` is a title-cased
  transform of the id (`gpt-5.6-sol` → `GPT-5.6 Sol`); `level`: `nano`
  / `mini` → easy, `pro` → advanced, else medium. The filter list is a
  `const` with a unit test per rule; a model the filter wrongly hides is
  still reachable through *Additional model ids*.

Both sort newest-first by `created`.

**Tauri shell.** One IPC, `provider_models_list(provider)`, in
`provider_keys.rs`: reads the key in-process, calls `list_models`, returns
the typed list. Nothing but model metadata crosses IPC (Rule 1). Errors
map through the existing markers (`provider_key_rejected`, `tls_trust`).

**Frontend.** A `useProviderModels(provider)` query per enrolled key,
`staleTime` 24 h, `refetchOnWindowFocus: false`, with the last successful
list mirrored into `preferences.cachedModels[provider]` so the picker is
populated instantly on launch and keeps working offline. Settings → API
keys shows "N models · refreshed <time> · Refresh" per provider. The chat
picker's source becomes `discovered ∪ customModelIds`, grouped by `level`
as today. `MODEL_REGISTRY` shrinks to a *preference order* used only to
pick the default for a new chat (first preferred id that the discovered
list contains, else the newest medium-level model, else the newest of
anything); it no longer gates what is shown.

**Caveats.** A network failure or a 401 at list time falls back to the
cached list, then to the registry — never an empty picker while a key is
enrolled. OpenAI's filter is heuristic by construction; the manual id
field stays as the escape hatch.

**Effort.** About a day: two parsers with wiremock tests, one IPC, one
query hook, picker rewrite, Settings row, tests for the default-model
rule.

## Part 2 — Sign in with a consumer subscription

### Anthropic: not permitted

Anthropic's documentation, updated 2026-02-19 after enforcement began on
2026-01-09, states that OAuth tokens from Free, Pro and Max plans are for
Claude Code and Claude.ai only; using them in any other product, tool or
service violates the Consumer Terms, and third-party developers may not
offer claude.ai login or route requests through a user's plan "unless
previously approved". Apps that reused the Claude Code OAuth client were
blocked and users' accounts suspended. The sanctioned path for software
that calls Claude is an API key from the Console.

**Decision:** do not build an Anthropic subscription path. Do not embed
the Claude Code client id. The only route is Anthropic's partner approval,
which does not fit an unmaintained open-source project. The Anthropic
side of this edition stays API-key only; the Part 1 model list makes that
path as good as it can be.

### OpenAI: officially supported for open-source local apps (preview)

"Sign in with ChatGPT" expanded at DevDay (2026-09-29) to let ChatGPT
Plus and Pro users spend their plan allowance inside third-party apps.
Commercial and hosted apps go through an interest form; **open-source,
locally running apps self-serve** through dynamic client registration.
Transit Community Edition is exactly that shape. Users set a weekly cap
per app in ChatGPT settings; when it is hit, requests stop rather than
falling over to another bill.

What the documented flow requires, and how it maps onto this codebase:

| Requirement | Mapping |
|---|---|
| Authorization Code + PKCE (S256) at `https://auth.openai.com/api/accounts/authorize`, token exchange at `POST https://auth.openai.com/api/accounts/oauth/token`, no client secret | New `transit_app::chatgpt_auth` module. The browser is opened with the opener plugin; the exchange runs in Rust on the `transit_tls` client. |
| First run: `client_id=dynamic_agent_client` + `agent_name_hint=<app name>`; the callback returns an issued `client_id` (`oaiapp_…`) to reuse | Persist the issued client id in `config.toml` (it is not a secret). |
| A stable per-installation `ext_agent_host_id` (recommended `urn:uuid:…`) | Generated once, stored beside the client id. |
| Scopes `openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`, `resource=https://api.openai.com/v1` | Constants, pinned by test. |
| Loopback redirect `http://127.0.0.1:<port>/auth/callback` (literal `127.0.0.1`, listener started before the browser opens) | A one-shot `tokio` TCP listener on an ephemeral port, accepting exactly one request, checking `state`, then closing. No deep-link plugin, no custom URL scheme — nothing the proprietary edition's sign-in needed comes back. |
| Access token 1 h; refresh token 30 d, rotated on every refresh | Access token held in memory only; refresh token in the OS keychain under `transit-ce-provider-keys` / `openai-chatgpt-refresh`. Refresh on 401 or when within 5 min of expiry. Rule 1: no token ever crosses IPC; the status command returns booleans plus the signed-in email. |
| Inference: `POST https://api.openai.com/v1/responses` with `Authorization: Bearer`, `store:false`, `stream:true`, `input` as an array; **omit** `max_output_tokens`, `temperature`, `top_p`, `truncation`, `user`, `metadata`, `prompt_cache_retention` and the other listed fields; hosted tools unsupported, function tools fine | `DirectOpenAI` gains an auth mode enum `{ApiKey, ChatGptPlan}`. `build_openai_body` already sets `store:false` and `stream:true`; in plan mode it skips `max_output_tokens` (the per-turn token ceiling then applies only through the loop's own accounting). Our tools are function tools, so the agent loop is unchanged. |
| Model list: `GET /v1/models` with the plan token returns a `models[]` array with `slug`, `display_name`, `visibility`; show `visibility: "list"` entries, send the `slug` | A second parser in Part 1's `list_models`, keyed on auth mode (the API-key shape is `data[]` with `id`). |
| Errors: `subscription_sharing_usage_limit_exceeded` (429, per-app or account cap), `subscription_sharing_user_not_eligible` (403), `subscription_sharing_invalid_user` (401, re-auth), `subscription_sharing_unsupported_capability` (400), refresh failures `invalid_grant` / `refresh_token_expired` / `refresh_token_reused` (clear and re-run OAuth) | New `LlmError` variants with stable markers (`plan_cap_reached`, `plan_not_eligible`, `plan_reauth_required`) and chat copy that links to ChatGPT's usage settings rather than to Settings → API keys. |

**Fourth Rule impact.** This adds one outbound host, `auth.openai.com`,
for the authorize redirect (opened in the system browser) and the token
exchange (from Rust). It is a user-initiated action with no key or
telemetry of ours, so it is within the rule's spirit, but it is a new
host: it needs a threat-model entry (T55 — the refresh token is a
standing credential to the user's ChatGPT plan, scoped to inference,
stored like the provider keys), an addition to the opener capability
allow-list, and a deliberate allowance in `scripts/no-phone-home-scan.sh`
(the scan keeps banning every other host).

**UI.** Settings → API keys becomes Settings → AI providers. The OpenAI
card offers two mutually exclusive methods: "API key" (today) and "Sign
in with ChatGPT" (a button that opens the browser and shows the signed-in
email, plan usage note, and Sign out). The chat picker groups plan models
under "ChatGPT plan" and marks the usage source so the user knows which
bill a chat lands on. When the weekly cap is hit, the chat shows the cap
message with a link to ChatGPT's usage settings, and the picker still
offers API-key and local models.

**Preview risks.** The flow is a preview: endpoints, scopes and the
omitted-field list can change, and OpenAI can withdraw open-source
self-serve. Mitigation: isolate everything plan-specific in
`chatgpt_auth.rs` plus the auth-mode branch in `direct.rs`, so a change
upstream is one module's edit, and keep the API-key path as the default.

**Effort.** Three to four days: the OAuth module with a loopback listener
and wiremock-tested exchange and refresh, keychain storage, the auth-mode
branch and body-shape tests, the second model parser, the error mapping,
the Settings card, picker grouping, the threat-model entry, and the scan
allowance.

## Sequencing

1. **Part 1 first.** Small, independent, and it is the piece Part 2's
   model list builds on.
2. **Part 2 (OpenAI only).** Behind nothing — once it ships it is simply
   the second method on the OpenAI card.
3. Anthropic subscription sign-in: closed, for the policy reason above.
   Revisit only if Anthropic opens a third-party program.

## Sources

- Anthropic Models API fields: the `claude-api` skill's model catalogue
  (`capabilities`, `max_input_tokens`, `max_tokens` since March 2026).
- OpenAI `GET /v1/models` shape: developers.openai.com API reference.
- OpenAI Sign in with ChatGPT for open-source apps:
  developers.openai.com/siwc/token-sharing-open-source (overview,
  sign-in, models-and-inference, token-reference, errors-and-recovery,
  preview-limitations) and the cookbook article; DevDay 2026-09-29
  coverage (The New Stack, xenospectrum, explainx).
- Anthropic policy on consumer-plan OAuth in third-party apps: Agent SDK
  overview on platform.claude.com; coverage of the 2026-02-19
  documentation update (WinBuzzer, GIGAZINE).
