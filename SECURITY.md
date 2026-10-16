# Security policy

Transit Community Edition is a desktop SSH client with an embedded
read-only AI agent. The properties we treat as security invariants are
documented in [`CLAUDE.md`](CLAUDE.md) §3 (the Three Inviolable Rules)
and [`docs/security/threat-model.md`](docs/security/threat-model.md).

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** on this repository
(Security → Report a vulnerability). Do not open a public issue for a
security bug.

Include what you found, how to reproduce it, and which invariant it
breaks (a credential crossing IPC, the agent reaching a device without
the policy gate and the approval modal, a redaction bypass, an outbound
connection to a host the user did not configure, …).

## Scope

In scope: everything in this repository — the Rust workspace under
`src-tauri/`, the React frontend under `src/`, the bundled vendor
policies under `policies/`, and the build/release workflows.

Out of scope: the devices, local model endpoints and AI providers you
point the app at; the OS keychain; the operating system's TLS trust
store.
