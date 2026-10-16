# Secret-handling rules

> Read this before touching `transit_auth`, any `tauri::command` that
> handles credentials, or anything log-related. These are not preferences.

## What counts as a secret

Anything that authenticates a user or device, or that an attacker
could replay to do so:

- Device passwords, SSH key passphrases, raw private keys.
- The user's provider API keys (Anthropic, OpenAI) — stored in the OS
  keychain by `transit_app::provider_keys`; they cross the IPC boundary
  once, inbound, at enrollment (`provider_key_set`), and leave the
  machine only in a request header to that provider's own host
  (threat-model T54).
- Local-endpoint bearer tokens (`transit_app::local_models`), same shape.

Hostnames and usernames are **not** secrets — they live in
`transit.toml` and may be safely logged or shipped in error reports.

## On-disk

- **`transit.toml` holds zero secret values** — only references like
  `secret = { backend = "keyring", key = "transit/lab-pw" }`. The
  loader in `transit_core::inventory` rejects inline secret-shaped
  values (`password = "..."`, `private_key = "-----BEGIN..."`) with a
  parse error pointing to file:line.
- **No file holds a provider key.** The application reads no provider
  key from the environment or from any config file; the only source is
  the OS keychain (`.env.example` documents the few non-secret dev
  overrides).
- Inventory files outside the project root are refused.
- Symlinks pointing outside the project root are refused.

## Backends (priority order)

1. **`ssh_agent`** — `SSH_AUTH_SOCK`. Covers 1Password SSH Agent
   transparently; the key never enters Transit's process. Touch ID /
   Windows Hello / Linux PAM unlock is handled by 1Password.
2. **`ssh_key`** — a private key file on disk (OpenSSH / PEM / PuTTY
   `.ppk`). `path` references the key; an optional nested `passphrase`
   (a `keyring` ref) holds the passphrase for an encrypted key. Loaded +
   decoded in-process and handed to russh as a sign-ready `PrivateKey`,
   never returned as a value.
3. **`op`** — 1Password CLI: `op read op://Vault/Item/field`.
   Biometric via 1Password's CLI integration.
4. **`keyring`** — OS keystore (Keychain / Credential Manager /
   Secret Service).
5. **`env`** — environment variable. Headless / CI use only.
6. **`encrypted_file`** — `age`-encrypted file unlocked by a startup
   passphrase. Last-resort fallback for minimal Linux installs
   without Secret Service. **Deferred to Phase 2a.1.**

The backend selection happens at startup in
`transit_auth::SecretRegistry`. Backends not available on the current
platform are silently skipped, but each `SecretRef` in `transit.toml`
explicitly names its backend, so a missing backend = parse error.

### Operations matrix

The `SecretBackend` trait splits **value-returning** backends from
**signer** backends. `resolve_value` returns `SecretString`;
`resolve_signer` returns `Arc<dyn Signer>` that signs auth challenges
without exposing the underlying key. Backends return
`BackendError::Unsupported` for the methods they don't implement.

| Backend          | resolve_value | open_ssh_agent_session | enroll | Source        |
|------------------|:-------------:|:----------------------:|:------:|---------------|
| `keyring`        | ✓             |                        | ✓      | OS keystore   |
| `op`             | ✓             |                        |        | 1Password CLI |
| `env`            | ✓             |                        |        | Process env   |
| `ssh_agent`      |               | ✓                      |        | SSH agent     |
| `ssh_key`        |               |                        |        | key file¹     |
| `encrypted_file` | ✓ (Phase 2a.1)|                        | ✓ (2a.1)| age file      |

¹ `ssh_key` is loaded via `SecretRegistry::load_ssh_key` — an inherent
method like `open_ssh_agent_session`, not a trait method — which reads +
decodes the file in-process, resolves any nested `passphrase` from
`keyring`/`op`/`env`, and returns a sign-ready russh `PrivateKey` (never a
`SecretString`). Its top-level `SecretRef::SshKey` is `Unsupported` for
`resolve_value`/`enroll`; the optional passphrase enrolls into its nested
`keyring` ref (the `enroll_secret` command routes there via
`lookup_profile_secret`).

**Phase 2b update**: the `Signer` trait + `resolve_signer` shipped
in Phase 2a have been removed. `ssh_agent` now produces an
[`SshAgentSession`] — a connected `russh::keys::agent::client::AgentClient`
plus the selected identity — that transit_ssh hands to russh's own
`auth::Signer` impl on `AgentClient`. The session resolves the
identity by matching the auth profile's
`public_key_fingerprint` pin (SHA256 of the OpenSSH public key, in
the same format `ssh-keygen -lf` emits). On no match, the error
lists the loaded identities' fingerprints so the user can fix the
pin without spelunking.

[`SshAgentSession`]: ../src-tauri/crates/transit_auth/src/agent.rs

`enroll` is callable only via the `enroll_secret` Tauri command (Rule
1: the only secret-bearing IPC). For backends that can't enroll
(`op` — managed in 1Password; `env` — shell owns it; `ssh_agent` —
agent owns key lifecycle), the auth-profile dialog hides the
"Set value..." button and the user manages the credential out of
band.

### Per-backend availability detection

`SecretRegistry::standard()` runs a per-backend preflight at startup
and exposes a snapshot via `secret_backend_availability()`. Frontend
reads it once at app mount via TanStack Query; the auth-profile
dialog renders an inline amber banner under the backend select when
the user picks a `NeedsInstall` backend.

| Backend     | Probe                                                    | NeedsInstall hint                                                 |
|-------------|----------------------------------------------------------|-------------------------------------------------------------------|
| `keyring`   | write+read+delete a sentinel via the keyring crate       | Linux: `sudo apt install gnome-keyring`; macOS/Windows: rare      |
| `op`        | `which op` + 1Password.app presence (fs check)           | Tristate hint: install op CLI / install both / Ready              |
| `ssh_agent` | `$SSH_AUTH_SOCK` connectable (Unix) or named pipe exists | macOS/Windows: start an agent or enable 1Password's. Linux: see §"Linux: agent contention" — do NOT `eval $(ssh-agent -s)` |
| `env`       | (always Ready)                                           | n/a                                                               |

## Troubleshooting `ssh_agent` auth failures

The single most common SSH auth problem Transit users hit is this:
the auth profile pins a fingerprint, but Transit reports
`no agent identity matches pin "SHA256:..."`. The fingerprint exists
in your 1Password (or wherever you keep keys), but Transit can't see
it. Almost always, the cause is environmental — not a Transit bug or
a 1Password misconfiguration.

### Symptom

A connect attempt fails with an error like:

```
authentication failed for user 'admin': resolve failed:
no agent identity matches pin "SHA256:/n6mIl3rb000x73pLHH18Aecse681Bxgmw8Ce3PBk20".
Loaded identities: [SHA256:aDL1cChx..., SHA256:zFzk3Hg9...].
Either fix the auth profile's fingerprint or `ssh-add` the missing key.
```

The "Loaded identities" list is short or doesn't include the key you
expect, but 1Password shows the key exists and has the SSH agent
enabled for it.

### Diagnostic recipe

Multiple SSH agents can run on the same machine — macOS ships a
legacy `ssh-agent` via launchd that starts on login, and 1Password's
SSH agent runs in parallel on its own socket. The shell environment
variable `SSH_AUTH_SOCK` points at exactly one of them, and the
default on a fresh macOS install is the launchd agent, **not**
1Password. Every SSH client (Transit, OpenSSH, git) follows
`SSH_AUTH_SOCK` blindly.

Compare what your shell sees vs. what 1Password is actually serving:

```bash
# 1. What SSH_AUTH_SOCK currently points to:
echo "$SSH_AUTH_SOCK"
ls -la "$SSH_AUTH_SOCK"

# 2. What 1Password's SSH agent is serving:
ONEP_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
SSH_AUTH_SOCK="$ONEP_SOCK" ssh-add -L

# 3. What your shell's default agent is serving:
ssh-add -L
```

If steps (2) and (3) return different lists, your shell is reading
from the wrong socket. The key you want is at the 1Password socket
(step 2) but Transit / OpenSSH / git / etc. only see what step (3)
returns.

### Fix

Add this line to `~/.zshrc` (or your shell's equivalent rc file):

```bash
export SSH_AUTH_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
```

This is the canonical 1Password SSH agent setup, documented at
<https://developer.1password.com/docs/ssh/agent/>. Open a new
terminal (or `source ~/.zshrc`), then verify:

```bash
ssh-add -L | wc -l   # should match the count in 1Password's SSH Keys panel
```

Reload Transit and retry the connect. The fingerprint pin will match
and auth will succeed.

### Linux: agent contention (strictly worse than macOS)

On a stock Ubuntu/GNOME/Wayland desktop, **three** systemd *user* units
race to own `SSH_AUTH_SOCK`, and each claims it by actively pushing its
own path into the session environment:

- `gcr-ssh-agent.socket` — GNOME Keyring
  (`ExecStartPost=… set-environment SSH_AUTH_SOCK=%t/gcr/ssh`). Wins by
  default, and commonly holds **zero** keys.
- `ssh-agent.socket` — plain OpenSSH agent
  (`… SSH_AUTH_SOCK=%t/openssh_agent`).
- `gpg-agent-ssh.socket` — gpg's agent, when `enable-ssh-support` is on.

Two consequences that are not guessable:

1. **Masking the socket is not enough.** `gcr-ssh-agent.service` is
   wanted by `graphical-session-pre.target`, so it restarts at next
   login even with its socket masked. And `ssh-agent.socket` starts at
   `sockets.target` — *before* GNOME Shell — so it silently overwrites a
   `~/.config/environment.d/` value that looked correct when written.
   The durable fix is to mask **all** the competing units, then set the
   1Password socket in `environment.d`:

   ```bash
   systemctl --user mask --now gcr-ssh-agent.socket gcr-ssh-agent.service \
     ssh-agent.socket ssh-agent.service gpg-agent-ssh.socket
   mkdir -p ~/.config/environment.d
   printf 'SSH_AUTH_SOCK=%s/.1password/agent.sock\n' "$HOME" \
     > ~/.config/environment.d/10-1password-ssh.conf
   ```

2. **A re-login is mandatory, and Wayland makes it a full logout.** GUI
   apps inherit `gnome-shell`'s environment, which is fixed at session
   start — a running Transit keeps the stale socket no matter what a
   new terminal says (`Alt+F2` → `r` is X11-only). Until you log out,
   launching Transit *from a terminal* is the only way to pick up the
   change, which makes the problem look intermittent: works from the
   CLI, broken from the dash.

Diagnostic one-liner (compare who owns the env vs. what 1Password
serves):

```bash
echo "$SSH_AUTH_SOCK"; SSH_AUTH_SOCK="$HOME/.1password/agent.sock" ssh-add -L
```

Do **not** run `eval $(ssh-agent -s)` on a Linux desktop — it starts a
*fourth* agent and hides the real problem for the lifetime of that one
shell. (Transit's own detection hint says the same since v6.3.0.)

Note: for auth profiles that **pin a fingerprint**, Transit already
falls back to 1Password's well-known socket when the `SSH_AUTH_SOCK`
agent doesn't hold the pinned key (macOS group container or
`~/.1password/agent.sock`) — so a pinned profile can keep working even
on a contended box. Unpinned profiles, git signing, and plain `ssh`
have no such fallback, which is why fixing the environment properly
still matters.

### Other `ssh_agent` failure modes

- **Empty identities list** — the agent is running but no keys are
  loaded. In 1Password: open the SSH key item and ensure "Use with
  SSH agent" is enabled. In a legacy `ssh-agent`: run
  `ssh-add ~/.ssh/your-key` to load.
- **Touch ID / biometric not prompting** — 1Password's agent requires
  the 1Password desktop app to be running. If you've quit 1Password,
  agent requests will hang or return empty until you relaunch.
- **Stale fingerprint pin after regenerating a key** — fingerprints
  change every time you regenerate the key. Update
  `public_key_fingerprint` in the auth profile to match, OR remove
  the pin entirely (Transit picks the first loaded identity and
  traces a warning).
- **Windows** — `SSH_AUTH_SOCK` doesn't apply; named pipes do.
  1Password's pipe is `\\.\pipe\openssh-ssh-agent`. The same
  diagnostic logic applies: if OpenSSH's default pipe and 1Password's
  pipe disagree, you'll see fewer identities than expected.

## In-memory

- Use `secrecy::SecretString` for any string-shaped secret. Its `Debug`
  + `Display` emit `[REDACTED]` and it zeroizes its inner buffer on drop.
- Use `secrecy::SecretBox<T>` + `zeroize::ZeroizeOnDrop` for non-string
  shapes (`Vec<u8>`, structured types).
- **No `Serialize` on any secret-bearing struct**, ever. `secrecy` is
  built **without** its `serde` feature (workspace `Cargo.toml`), so
  `SecretString`/`SecretBox` simply do not implement `Serialize` — the
  type system, not a separate test, is what keeps secrets off IPC.
- Don't `clone()` secrets unnecessarily. Pass `&SecretString` or
  move ownership.
- Don't `.expose()` and assign to `String`; use the `&str` only for
  the immediate operation (e.g., russh's auth call) and let it drop.
- Don't pass secrets across an `await` point — they end up in the
  task state, which can survive longer than expected. Authenticate
  fully, then drop.

## Across the IPC boundary (Tauri commands)

- **No `tauri::command` returns a secret to the frontend.** This is
  the Second Inviolable Rule (see `CLAUDE.md`). If a new command needs
  access to credentials, it stays in the backend; the frontend gets a
  handle (session id, device id), not a value.
- **One write-only command** crosses the boundary with a secret:
  `enroll_secret(profile_id, value: SecretString)`. The frontend's
  enrollment UI runs in a dedicated Tauri window that closes
  immediately on submit. Backend persists the secret to the
  appropriate backend, drops the in-memory copy, returns `Ok`.
- After enrollment, every connect fetches from the backend
  in-process — secrets never cross IPC again.

## In logs

- Use `tracing` via `transit_core::log`. `secrecy::SecretString`
  formats as `[REDACTED]`.
- Never `info!("connecting with password={:?}", pw)` even with a
  `SecretString` — log the *fact* of the connection, not the
  credential reference. `info!(device = %device.id, "connecting")` is
  fine; `info!(?auth, "connecting")` is fine *only* because `auth`'s
  `Debug` redacts.
- `tracing` event values are dropped at the log layer, but they pass
  through subscriber chains; assume any `Debug`-formatted value can
  reach disk or stdout. Apply the redaction discipline regardless.
- Provider API keys and endpoint tokens are similarly never logged —
  they are `SecretString`s whose `Debug` is `[REDACTED]`.

## In error reports / panics

- `expect("...")` and `unwrap()` on a `SecretString`-bearing path
  must include a message that does **not** include the value. Prefer
  `?` propagation over `.unwrap()` in production paths.
- macOS / Windows OS-level crash reports may capture process memory.
  This is outside our control; mitigated by `zeroize` clearing
  buffers on drop. Documented as accepted residual risk in the
  threat model.

## Adding a new backend

See `CLAUDE.md` §"Adding a secret backend" for the runbook. In
short: implement `SecretBackend`, add detection helpers, write
mock-backend unit tests, write a real-backend integration test
behind a feature flag, update this doc and `licenses.md`.

## Adding a new credential type

If you find yourself wanting to store a new kind of secret (an OAuth
refresh token, a TOTP seed, an API key for a vendor management
plane), it goes through the same `transit_auth` crate. Do not invent
a parallel storage path. If `SecretRegistry` doesn't support the
shape, extend it — don't bypass it.

## Inline-secret pre-scan in `transit.toml`

Source: `transit_core::inventory::loader`.

Before TOML parsing, the loader scans the raw file content for
patterns that strongly indicate a literal secret pasted into the
inventory file. A match aborts loading with `InventoryError::InlineSecret`
pointing at `file:line` and the matched pattern label. The frontend
shows this as a banner in the sidebar.

Current catalog (best-effort; this is the **first** boundary, not the
last):

  - `password = "..."`
  - `passphrase = "..."`
  - `private_key = "..."`
  - `api_key = "..."`
  - `token = "..."`
  - `secret = "..."` — note: `secret = { backend = ... }` is valid;
    only literal-string values are rejected.
  - `-----BEGIN [A-Z ]+ PRIVATE KEY-----` PEM blocks (anywhere in
    the file, even inside a comment — paste hygiene).

Why pre-scan instead of relying on TOML structural validation?
`serde(deny_unknown_fields)` only catches keys we don't recognize;
a user could legitimately add a `password` field to a struct we
later extend, or write a comment containing a literal secret. The
pre-scan is a coarse but reliable second-net.

This catalog is **not** the comprehensive secret-shape catalog. The
exhaustive set lives in `transit_agent::redaction` (Phase 5a) which
filters scrollback before it reaches the LLM. The inventory pre-scan
focuses on top-of-file inline values; the redaction filter covers
device-output bytes that may contain unfamiliar shapes.

Adding a new pattern:
  1. Add the regex + human-readable label to
     `transit_core::inventory::loader::inline_secret_patterns`.
  2. Add a fixture `bad_inline_<name>.toml` under
     `crates/transit_core/tests/fixtures/inventory/` with header
     `# expect: Err::InlineSecret`.
  3. Add a unit test if line-number assertions are warranted.

## Inventory mutations also run the pre-scan

Source: `transit_core::inventory::mutator`.

The in-app "+ New device" / Edit / Delete / Rename group flow goes
through `transit_core::inventory::mutator`. After every structural
edit the mutated `DocumentMut` is serialized and re-validated through
the **same** `parse_and_validate` chain that the loader uses — inline-
secret pre-scan included. A mutation that would write a file the
loader would reject (e.g. an auth-profile shape that somehow grew a
`password = "..."` field at the IPC boundary) returns
`InventoryError::InlineSecret` and the dialog surfaces it inline; the
file on disk is not touched.

This makes the pre-scan a **two-way** invariant: nothing the GUI
writes can defeat it, and nothing a power user pastes into the file
by hand can defeat it either. Atomic writes (tempfile + rename in the
same parent dir) ensure no half-written file is ever visible to a
concurrent reader.

## Linux CI keyring image

Source: `ci/keyring-linux/`.

GitHub Actions' headless Ubuntu runner can't reach a Secret Service
collection out of the box (no XDG runtime dir, no logged-in user,
gnome-keyring-daemon's GTK prompter dies with `cannot open display`
on first-run unlock). Phase 2d closes the gap with a CI-only Docker
image that pre-installs `gnome-keyring`, `dbus`, `libsecret-1-dev`,
`libdbus-1-dev`, the Rust toolchain, and an entrypoint that:

1. Creates `$XDG_RUNTIME_DIR` with mode 0700.
2. Wraps the rest in a fresh `dbus-run-session`.
3. Starts `gnome-keyring-daemon --replace --daemonize --components=secrets --unlock`
   with a known **non-empty** password piped in. Empty-password
   unlock falls through to the GTK prompter on Ubuntu 22.04 +
   gnome-keyring 40 — non-empty bypasses it. Password strength is
   moot; the keyring is ephemeral inside the container.
4. Sanity-checks the daemon via `secret-tool` round-trip before
   handing off to `cargo test`.

The CI step (`.github/workflows/ci.yml` → `cargo test (Linux
integration via Docker)`) builds the image inline on every run. No
GHCR push, no separate registry — `docker build` uses the runner's
local layer cache so subsequent runs reuse the apt + rustup layers
unchanged.

### When to rebuild

Edit `ci/keyring-linux/Dockerfile` and push. The CI step rebuilds
on every run, so a Dockerfile change takes effect on the next
push. Reasons to bump:
- libsecret / gnome-keyring CVE.
- Ubuntu base image major version (22.04 → 24.04).
- New Rust toolchain feature needed by the workspace.

### Running the same tests locally

```bash
docker build -t transit-keyring-ci ci/keyring-linux/
docker run --rm \
    -v "$(pwd):/workspace" -w /workspace \
    transit-keyring-ci \
    cargo test --manifest-path src-tauri/Cargo.toml \
    -p transit_auth --features integration-tests \
    --test keyring_round_trip -- --test-threads=1
```

Useful when iterating on the keyring backend itself, or
investigating a CI-only failure.

### Why not run on the host

Earlier iterations tried `dbus-launch` + `gnome-keyring-daemon
--unlock` directly on the Ubuntu runner. Three iterations failed:
the runner has no XDG_RUNTIME_DIR set, `dbus-send` doesn't fluently
construct the variant dict that the SSS `CreateCollection` method
expects, and the daemon's GTK prompter still gets invoked because
the host has no logged-in user state. The container approach owns
the entire daemon lifecycle deterministically — same build, same
state, every run.
