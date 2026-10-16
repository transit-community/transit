//! `ssh_agent` backend — talks to `$SSH_AUTH_SOCK` (Unix) or the
//! OpenSSH named pipe (Windows).
//!
//! Unlike the other backends, this one does not return a value
//! through [`SecretBackend::resolve_value`]; the credential never
//! leaves the agent. Instead, it produces an [`SshAgentSession`]
//! (live wire-protocol client + selected identity) that transit_ssh
//! hands to russh's `authenticate_publickey_with`.
//!
//! The legacy `Phase2bStubSigner` (Phase 2a placeholder) and the
//! `Signer` trait it implemented have been removed; russh's own
//! `auth::Signer` impl on `AgentClient` is what completes the SSH
//! signing handshake.

use async_trait::async_trait;
use secrecy::SecretString;
use transit_core::inventory::SecretRef;

use crate::agent::SshAgentSession;
use crate::{BackendAvailability, BackendError, SecretBackend};

const KIND: &str = "ssh_agent";

pub(crate) struct SshAgentBackend {
    availability: BackendAvailability,
}

impl SshAgentBackend {
    pub(crate) fn new() -> Self {
        Self {
            availability: detect_agent(),
        }
    }

    pub(crate) fn availability(&self) -> BackendAvailability {
        self.availability.clone()
    }

    /// Open a live agent session and select the identity matching the
    /// reference's `public_key_fingerprint` pin. Used by the SSH
    /// connect flow (transit_ssh) and by the `test_secret_resolve`
    /// IPC's reachability probe.
    pub(crate) async fn open_session(
        &self,
        refp: &SecretRef,
    ) -> Result<SshAgentSession, BackendError> {
        let SecretRef::SshAgent {
            public_key_fingerprint,
        } = refp
        else {
            return Err(BackendError::unsupported(KIND, "open_session (wrong kind)"));
        };
        if let BackendAvailability::NeedsInstall { hint } = &self.availability {
            return Err(BackendError::Unavailable {
                backend: KIND,
                hint: hint.clone(),
            });
        }
        SshAgentSession::open(public_key_fingerprint.as_deref()).await
    }
}

/// Platform-appropriate "how do I get a working agent" guidance, shared
/// by the availability probe (both failure arms) and `connect_dynamic`'s
/// resolve-failure path so they can never diverge again — v6.3.0 review
/// finding: the resolve path kept recommending `eval $(ssh-agent -s)` on
/// Linux after the probe hint had already retracted it. On Linux that
/// command starts a FOURTH competing agent (GNOME Keyring's gcr,
/// systemd's ssh-agent.socket, and gpg-agent-ssh.socket already race to
/// own `$SSH_AUTH_SOCK`); the durable fix is masking the competitors +
/// environment.d — see docs/security/secrets.md §"Linux: agent
/// contention".
///
/// `#[cfg(unix)]`: every caller (the probe's two unix arms +
/// `connect_dynamic`'s unix variant) is unix-gated — the Windows arms
/// carry their own named-pipe guidance — so on Windows this would be
/// dead code and fail clippy's `-D warnings`.
#[cfg(unix)]
pub(crate) fn agent_recovery_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "On Linux desktops several agents compete for $SSH_AUTH_SOCK (GNOME \
         Keyring, systemd's ssh-agent.socket, gpg-agent). If you use the \
         1Password agent: mask the competing user units, set SSH_AUTH_SOCK \
         to ~/.1password/agent.sock in ~/.config/environment.d/, then log \
         out and back in — running apps keep the old value until re-login. \
         If you use another agent, make sure ITS socket wins the same way. \
         See docs/security/secrets.md \"Linux: agent contention\". Avoid \
         `eval $(ssh-agent -s)`: it starts yet another agent."
    }
    #[cfg(not(target_os = "linux"))]
    {
        "Start one with `eval $(ssh-agent -s)` and `ssh-add` your key, or \
         enable the SSH agent in 1Password (Settings → Developer)."
    }
}

/// Detection: is `$SSH_AUTH_SOCK` set and is the socket connectable?
/// On Windows the agent uses a named pipe `\\.\pipe\openssh-ssh-agent`;
/// we check pipe existence rather than the env var.
fn detect_agent() -> BackendAvailability {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let Ok(sock) = std::env::var("SSH_AUTH_SOCK") else {
            return BackendAvailability::NeedsInstall {
                hint: format!(
                    "No $SSH_AUTH_SOCK in Transit's environment. {}",
                    agent_recovery_hint()
                ),
            };
        };
        match UnixStream::connect(&sock) {
            Ok(_) => BackendAvailability::Ready,
            Err(e) => BackendAvailability::NeedsInstall {
                hint: format!(
                    "SSH agent socket at {sock} not connectable: {e}. {}",
                    agent_recovery_hint()
                ),
            },
        }
    }

    #[cfg(windows)]
    {
        let pipe = r"\\.\pipe\openssh-ssh-agent";
        if std::path::Path::new(pipe).exists() {
            BackendAvailability::Ready
        } else {
            BackendAvailability::NeedsInstall {
                hint: "OpenSSH agent service not running. Start it with \
                       `Start-Service ssh-agent` (PowerShell as Administrator) \
                       or enable the SSH agent in 1Password."
                    .into(),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        BackendAvailability::Unsupported
    }
}

#[async_trait]
impl SecretBackend for SshAgentBackend {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn supports(&self, refp: &SecretRef) -> bool {
        matches!(refp, SecretRef::SshAgent { .. })
    }

    async fn resolve_value(&self, _refp: &SecretRef) -> Result<SecretString, BackendError> {
        Err(BackendError::unsupported(KIND, "resolve_value"))
    }

    async fn enroll(&self, _refp: &SecretRef, _value: SecretString) -> Result<(), BackendError> {
        // The agent owns key lifecycle. User adds keys via 1Password
        // or `ssh-add`, not via Transit's UI. The auth-profile dialog
        // reflects this: ssh_agent profiles have no "Set value" button.
        Err(BackendError::unsupported(KIND, "enroll"))
    }
}
