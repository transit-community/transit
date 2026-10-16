//! `transit_api` — the read-only-capable REST transport that backs
//! Transit's **API sessions** (UniFi first; Fortinet / Meraki / Datto
//! reuse it). It is the HTTP-world sibling of `transit_ssh` /
//! `transit_console`.
//!
//! ## Two actors, two permission models, one session
//!
//! An API session is driven by two actors with deliberately different
//! authority — mirroring how the SSH terminal treats human keystrokes
//! vs. agent-proposed commands (the policy gate is *agent-only*; human
//! input is never gated):
//!
//! - **The human**, through the Postman-style UI, may issue ANY method
//!   (GET / POST / PUT / DELETE). This is exactly like typing
//!   `configure` at a terminal — the operator has always been able to
//!   mutate their own gear. These calls skip [`gate`] entirely and go
//!   straight through [`Endpoint::confine`] + [`ApiClient::send`].
//! - **The AI agent** may issue **GET only** — investigate-only. Every
//!   agent request passes [`gate::evaluate_agent_get`] first, so a GET
//!   cannot become a mutation and cannot leave the controller.
//!
//! ## The invariant both actors share: host pinning
//!
//! Neither actor ever chooses the host. Callers name an [`Endpoint`]
//! (resolved from the session's stored controller config) plus a
//! *path*; [`Endpoint::confine`] joins them and refuses anything that
//! would leave the endpoint's origin or climb above its API path prefix
//! — so a crafted path can neither reach an internal host (SSRF) nor
//! smuggle the injected `X-API-KEY` to a foreign server.
//!
//! ## Firewall
//!
//! This crate performs HTTP and receives the resolved API key by value.
//! It is owned by `transit_app` and MUST NOT be reachable from
//! `transit_agent` — the agent only ever emits a typed tool call, and
//! `transit_app` executes it here. See CLAUDE.md §2 / §3 and
//! `deny.toml`.

mod auth;
mod client;
mod endpoint;
mod error;
pub mod gate;

pub use auth::AppliedAuth;
pub use client::{ApiClient, ApiResponse};
pub use endpoint::{Endpoint, EndpointKind};
pub use error::ApiError;
pub use gate::{evaluate_agent_get, ApiDecision};
