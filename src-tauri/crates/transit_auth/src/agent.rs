//! `SshAgentSession` — connected agent client + the selected
//! identity, ready to be handed to russh's
//! `authenticate_publickey_with`.
//!
//! This is transit_auth's only direct russh consumer. Every other
//! credential boundary stays a value-oriented abstraction
//! (`SecretString`); the agent is the exception because the
//! credential never leaves the agent process — what crosses the
//! boundary is a connected wire-protocol session, not the key.

use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::ssh_key::{Fingerprint as SshKeyFingerprint, HashAlg, PublicKey};

use crate::BackendError;

/// Boxed agent stream so the type is the same on Unix (UnixStream)
/// and Windows (NamedPipeClient). Constructed via
/// [`AgentClient::dynamic`].
pub type DynAgentClient = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

/// Raw bidirectional byte stream to the PRIMARY SSH agent — what
/// [`open_agent_byte_stream`] hands to transit_ssh's agent-forwarding
/// pump (v6.5.0, T53). `AgentStream: AsyncRead + AsyncWrite`, so the
/// box plugs straight into `tokio::io::copy_bidirectional`; the box
/// also erases the per-OS transport (unix socket vs named pipe), which
/// keeps the pump cfg-free.
pub type AgentByteStream = Box<dyn AgentStream + Send + Unpin + 'static>;

/// Live SSH agent connection plus the identity selected per the
/// user's pin. Handed to transit_ssh's Connection layer, which
/// passes the inner [`DynAgentClient`] to russh's
/// `authenticate_publickey_with`.
pub struct SshAgentSession {
    client: DynAgentClient,
    identity: PublicKey,
}

impl SshAgentSession {
    /// Open an SSH agent, list identities, and select the one whose
    /// SHA256 fingerprint matches `pin`. With no pin, returns the first
    /// identity (and traces a warning so production logs flag
    /// implicit-first-identity selection).
    ///
    /// Two agents are tried, in order:
    ///
    /// 1. The agent named by `SSH_AUTH_SOCK` (Unix) / the OpenSSH named
    ///    pipe (Windows).
    /// 2. **1Password fallback (Unix, pinned only):** if the *pinned*
    ///    key wasn't found in agent 1 — including when agent 1 was
    ///    unreachable — and 1Password's well-known agent socket exists,
    ///    it is tried next. The trigger is "pinned key not found", NOT
    ///    "no socket": on macOS `SSH_AUTH_SOCK` is *always* set to
    ///    Apple's built-in agent, so without this a 1Password key would
    ///    never resolve from a GUI launch. Scoped to the pinned case so
    ///    searching a second agent for a specific fingerprint stays
    ///    deterministic, and only when 1Password's socket is present so
    ///    non-1Password users keep agent 1's error verbatim.
    ///
    /// Errors are pre-classified so the UI can render an actionable
    /// banner without further branching.
    pub(crate) async fn open(pin: Option<&str>) -> Result<Self, BackendError> {
        // 1. Primary: the agent named by SSH_AUTH_SOCK / the named pipe.
        let primary = match connect_dynamic().await {
            Ok(client) => Self::select(client, pin, AgentOrigin::Env).await,
            Err(e) => Err(e),
        };
        if primary.is_ok() {
            return primary;
        }

        // 2. 1Password fallback — see the doc comment for why the trigger
        //    is "pinned key not found", not "SSH_AUTH_SOCK unset".
        #[cfg(unix)]
        if pin.is_some() {
            if let Some(path) = onepassword_socket_path() {
                return match AgentClient::connect_uds(&path).await {
                    Ok(client) => {
                        tracing::info!(
                            "pinned key not in the SSH_AUTH_SOCK agent; resolving via the \
                             1Password SSH agent socket"
                        );
                        Self::select(client.dynamic(), pin, AgentOrigin::OnePassword).await
                    }
                    Err(e) => Err(BackendError::Unavailable {
                        backend: "ssh_agent",
                        hint: format!(
                            "the pinned key was not in the SSH_AUTH_SOCK agent, and the \
                             1Password SSH agent at {} could not be reached ({e}). Turn it on \
                             in 1Password → Settings → Developer → \"Use the SSH agent\", and \
                             make sure 1Password is running and unlocked.",
                            path.display()
                        ),
                    }),
                };
            }
        }

        primary
    }

    /// List a connected agent's identities and select one by `pin` (or
    /// the first, with a warning, when unpinned). Shared by the primary
    /// and 1Password-fallback paths so both apply identical matching and
    /// error shapes; `origin` only tailors the no-identities hint.
    async fn select(
        mut client: DynAgentClient,
        pin: Option<&str>,
        origin: AgentOrigin,
    ) -> Result<Self, BackendError> {
        let identities =
            client
                .request_identities()
                .await
                .map_err(|e| BackendError::ResolveFailed {
                    detail: format!("agent identity list failed: {e}"),
                })?;

        if identities.is_empty() {
            return Err(BackendError::ResolveFailed {
                detail: origin.empty_hint(),
            });
        }

        let identity = match pin {
            Some(p) => find_by_fingerprint(&identities, p)?,
            None => {
                tracing::warn!(
                    "ssh_agent SecretRef has no public_key_fingerprint pin; \
                     using the first identity ({} of {} loaded). Pin a \
                     fingerprint in the auth profile to make this deterministic.",
                    1,
                    identities.len()
                );
                identities[0].public_key().into_owned()
            }
        };

        Ok(Self { client, identity })
    }

    /// Public key of the identity selected by [`Self::open`]. Used
    /// by transit_ssh to start the russh handshake.
    pub fn public_key(&self) -> &PublicKey {
        &self.identity
    }

    /// Tear down the session into the bare AgentClient. The caller
    /// (transit_ssh) hands this to russh's
    /// `authenticate_publickey_with` as a `&mut` borrow.
    pub fn into_inner(self) -> DynAgentClient {
        self.client
    }
}

/// Which agent a [`SshAgentSession::select`] attempt is talking to —
/// drives the no-identities hint so the user gets agent-appropriate
/// guidance (generic `ssh-add` advice vs. a 1Password-specific cause).
#[derive(Clone, Copy)]
enum AgentOrigin {
    Env,
    #[cfg(unix)]
    OnePassword,
}

impl AgentOrigin {
    fn empty_hint(self) -> String {
        match self {
            AgentOrigin::Env => "ssh agent has no identities loaded. Run \
                 `ssh-add ~/.ssh/<key>` or, in 1Password, enable the SSH agent \
                 and turn on the key."
                .into(),
            #[cfg(unix)]
            AgentOrigin::OnePassword => "the 1Password SSH agent is reachable but \
                 serving no keys — 1Password is locked, or the key isn't authorized \
                 for the agent. Unlock 1Password and confirm the key is enabled."
                .into(),
        }
    }
}

/// The well-known 1Password SSH agent socket for this platform, but
/// only when it exists on disk. `None` when 1Password's agent isn't
/// present — so the primary agent's error stands unchanged and a
/// non-1Password user is never told to "enable 1Password".
#[cfg(unix)]
fn onepassword_socket_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = onepassword_socket_for_home(std::path::Path::new(&home));
    path.exists().then_some(path)
}

/// Pure path construction (no filesystem touch) so it's unit-testable.
/// The macOS Group-Container path uses 1Password's fixed Apple Team ID
/// (`2BUA8C4S2C`); Linux uses the desktop app's `~/.1password` socket.
#[cfg(unix)]
fn onepassword_socket_for_home(home: &std::path::Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".1password/agent.sock")
    }
}

#[cfg(unix)]
async fn connect_dynamic() -> Result<DynAgentClient, BackendError> {
    AgentClient::connect_env()
        .await
        .map(|c| c.dynamic())
        .map_err(|e| BackendError::Unavailable {
            backend: "ssh_agent",
            // Same platform split as detect_agent's hint: on Linux,
            // `eval $(ssh-agent -s)` starts a FOURTH competing agent and
            // hides the real contention problem (v6.3.0 review finding —
            // this sibling arm shipped the retracted advice the probe
            // hint had already dropped).
            hint: format!(
                "could not connect to SSH agent via $SSH_AUTH_SOCK: {e}. {}",
                crate::backends::ssh_agent::agent_recovery_hint()
            ),
        })
}

#[cfg(windows)]
async fn connect_dynamic() -> Result<DynAgentClient, BackendError> {
    // OpenSSH's named-pipe path on Windows. 1Password's agent
    // shadows this when its agent is enabled.
    const PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
    AgentClient::connect_named_pipe(PIPE)
        .await
        .map(|c| c.dynamic())
        .map_err(|e| BackendError::Unavailable {
            backend: "ssh_agent",
            hint: format!(
                "could not connect to OpenSSH agent at {PIPE}: {e}. \
                 Start the agent (`Start-Service ssh-agent` as Administrator) \
                 or enable 1Password's SSH agent."
            ),
        })
}

#[cfg(not(any(unix, windows)))]
async fn connect_dynamic() -> Result<DynAgentClient, BackendError> {
    Err(BackendError::Unavailable {
        backend: "ssh_agent",
        hint: "SSH agent is unsupported on this platform.".into(),
    })
}

/// Dial the primary SSH agent and hand back the raw byte stream, for
/// agent forwarding's per-channel pump (v6.5.0, T53).
///
/// "Primary" deliberately matches OpenSSH `ForwardAgent yes` semantics:
/// `$SSH_AUTH_SOCK` on unix, the OpenSSH named pipe on Windows (which
/// 1Password shadows when its agent is on). The 1Password FALLBACK
/// sockets used by pinned-key auth do NOT apply here — that fallback
/// triggers on "pinned key not found", and forwarding has no pin. A
/// macOS/Linux 1P user who wants 1P keys forwarded points
/// `SSH_AUTH_SOCK` at the 1P socket, exactly as with stock OpenSSH.
/// Reuses [`connect_dynamic`]'s per-OS dialing and pre-classified
/// error hints; the extra box hop from `into_inner` is one pointer
/// indirection on a local, low-throughput stream.
pub async fn open_agent_byte_stream() -> Result<AgentByteStream, BackendError> {
    Ok(connect_dynamic().await?.into_inner())
}

/// Match an identity by its SHA256 fingerprint
/// (`SHA256:<base64-no-pad>`). Pin format must match what
/// `ssh-keygen -lf` emits — that's how users will discover their
/// own pins.
fn find_by_fingerprint(
    identities: &[russh::keys::agent::AgentIdentity],
    pin: &str,
) -> Result<PublicKey, BackendError> {
    let target: SshKeyFingerprint = pin.parse().map_err(|_| BackendError::ResolveFailed {
        detail: format!(
            "auth profile pin {pin:?} is not a valid OpenSSH fingerprint \
             (expected `SHA256:<base64>`)"
        ),
    })?;

    let hash_alg = match target {
        SshKeyFingerprint::Sha256(_) => HashAlg::Sha256,
        SshKeyFingerprint::Sha512(_) => HashAlg::Sha512,
        _ => HashAlg::Sha256,
    };

    let matched = identities.iter().find(|i| {
        let key = i.public_key();
        key.fingerprint(hash_alg) == target
    });

    match matched {
        Some(id) => Ok(id.public_key().into_owned()),
        None => {
            let loaded: Vec<String> = identities
                .iter()
                .map(|i| i.public_key().fingerprint(hash_alg).to_string())
                .collect();
            Err(BackendError::ResolveFailed {
                detail: format!(
                    "no agent identity matches pin {pin:?}. \
                     Loaded identities: [{}]. \
                     Either fix the auth profile's fingerprint or `ssh-add` \
                     the missing key.",
                    loaded.join(", ")
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::agent::AgentIdentity;
    use russh::keys::ssh_key::PublicKey;

    /// Test fixture: same Ed25519 public key used in
    /// `transit_ssh::host_key` tests. Throwaway.
    const TEST_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeWGarXFCkY8zX2GTR2H7M311S6iLXWv7AyA9AN5Tgu \
         transit-host-key-test";
    /// `ssh-keygen -lf` output for the above key.
    const KNOWN_FINGERPRINT: &str = "SHA256:TB9yfs7U9suPXvdMryrKA/UG1ZJrp3DXaZWulMipLoM";

    fn fixture_identity() -> AgentIdentity {
        let key = PublicKey::from_openssh(TEST_PUBKEY).expect("test pubkey parses");
        AgentIdentity::PublicKey {
            key,
            comment: "test".into(),
        }
    }

    #[test]
    fn find_by_fingerprint_matches_known_pin() {
        let ids = vec![fixture_identity()];
        let pk = find_by_fingerprint(&ids, KNOWN_FINGERPRINT).expect("match");
        let actual_pin = pk.fingerprint(HashAlg::Sha256).to_string();
        assert_eq!(actual_pin, KNOWN_FINGERPRINT);
    }

    #[test]
    fn find_by_fingerprint_errors_on_no_match() {
        let ids = vec![fixture_identity()];
        let res = find_by_fingerprint(&ids, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(matches!(res, Err(BackendError::ResolveFailed { .. })));
    }

    #[test]
    fn find_by_fingerprint_rejects_garbage_pin() {
        let ids = vec![fixture_identity()];
        let res = find_by_fingerprint(&ids, "not-a-fingerprint");
        match res {
            Err(BackendError::ResolveFailed { detail }) => {
                assert!(
                    detail.contains("not a valid OpenSSH fingerprint"),
                    "expected explanatory detail, got {detail}"
                );
            }
            other => panic!("expected ResolveFailed, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn onepassword_socket_path_is_the_macos_group_container() {
        let p = onepassword_socket_for_home(std::path::Path::new("/Users/alex"));
        assert_eq!(
            p,
            std::path::PathBuf::from(
                "/Users/alex/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
            )
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn onepassword_socket_path_is_the_linux_dotdir() {
        let p = onepassword_socket_for_home(std::path::Path::new("/home/alex"));
        assert_eq!(
            p,
            std::path::PathBuf::from("/home/alex/.1password/agent.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn agent_origin_hints_are_distinct_and_actionable() {
        let env = AgentOrigin::Env.empty_hint();
        let op = AgentOrigin::OnePassword.empty_hint();
        assert!(env.contains("ssh-add"), "env hint: {env}");
        assert!(op.contains("1Password is locked"), "1p hint: {op}");
        assert_ne!(env, op);
    }
}
