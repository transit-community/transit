//! SSH agent forwarding — the client half (v6.5.0, threat model T53).
//!
//! When a device opts in (`forward_agent = true`), the PTY session
//! requests `auth-agent-req@openssh.com` before the shell starts
//! (`session::writer_loop`), and the server may then open
//! `auth-agent@openssh.com` channels back at us. Each accepted channel
//! is pumped byte-for-byte to the LOCAL primary SSH agent
//! (`$SSH_AUTH_SOCK` on unix, the OpenSSH named pipe on Windows —
//! which 1Password shadows when its agent is enabled) via
//! `transit_auth::open_agent_byte_stream`.
//!
//! Security posture, in order of importance:
//! - The accept/reject verdict lives in `ConnectHandler`
//!   (`server_channel_open_agent_forward`), fixed at connect time.
//!   Disabled → explicit reject. russh's default would ACCEPT.
//! - The agent DIAL runs here, in a spawned task — never on the
//!   session event loop (a stall there freezes the whole connection's
//!   keystrokes, and russh's Windows named-pipe dial can retry
//!   `ERROR_PIPE_BUSY` without bound). The server legally parks on
//!   the channel-open reply until we decide.
//! - An unreachable/dead agent REJECTS the open (`ConnectFailed`),
//!   matching OpenSSH: the remote `ssh` reports "agent unavailable"
//!   cleanly instead of EOFing mid-agent-protocol.
//! - Pump tasks are detached and untracked: channel EOF, agent EOF,
//!   and connection drop (session-loop death ⇒ sender drop ⇒ EOF) all
//!   end the copy. Dropping the channel stream itself sends
//!   channel-close. The honest edge (adversarial review): a hostile
//!   opted-in server can hold a channel HALF-OPEN — never sending,
//!   never closing — and that pump parks until the connection ends.
//!   There is deliberately NO idle timeout: 1Password's per-use
//!   authorization can hold a legitimate signature request for as long
//!   as the human takes, and killing that flow is the worse trade. The
//!   semaphore cap bounds the park to [`MAX_AGENT_PUMPS`] tasks and
//!   idle agent connections per SSH connection, reclaimed at
//!   disconnect.
//! - Concurrency is bounded by a per-connection semaphore
//!   ([`MAX_AGENT_PUMPS`]) so a hostile server can't fd-exhaust us by
//!   spraying opens; excess opens reject with `ResourceShortage`.

use std::time::Duration;

use russh::client::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio::sync::OwnedSemaphorePermit;

/// Ceiling on concurrent pump tasks per connection. Interactive use is
/// one or two (an `ssh`/`git` invocation each); the cap only exists to
/// bound hostility.
pub(crate) const MAX_AGENT_PUMPS: usize = 8;

/// How long the local agent has to answer the dial before we reject
/// the server's channel open. Local sockets answer in microseconds;
/// the timeout exists for wedged agents and the Windows busy-pipe
/// retry loop.
pub(crate) const AGENT_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Dial the local agent, then accept-and-pump (or reject) one inbound
/// agent-forward channel. Runs as its own task; `permit` bounds the
/// per-connection pump count and releases on any exit path.
pub(crate) async fn handle_inbound_channel(
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
    permit: OwnedSemaphorePermit,
    host: String,
    port: u16,
) {
    let _permit = permit;

    let agent = match tokio::time::timeout(
        AGENT_DIAL_TIMEOUT,
        transit_auth::open_agent_byte_stream(),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::warn!(
                host = %host,
                port,
                error = %e,
                "agent forwarding: local agent unreachable; rejecting the server's channel"
            );
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        }
        Err(_) => {
            tracing::warn!(
                host = %host,
                port,
                timeout_s = AGENT_DIAL_TIMEOUT.as_secs(),
                "agent forwarding: local agent dial timed out; rejecting the server's channel"
            );
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        }
    };

    reply.accept().await;

    let mut agent = agent;
    let mut channel_stream = channel.into_stream();
    match tokio::io::copy_bidirectional(&mut channel_stream, &mut agent).await {
        Ok((from_remote, from_agent)) => {
            tracing::debug!(
                host = %host,
                port,
                from_remote,
                from_agent,
                "agent-forward channel closed"
            );
        }
        Err(e) => {
            // Routine on teardown races (one side vanishes mid-copy);
            // never worth more than debug.
            tracing::debug!(host = %host, port, error = %e, "agent-forward pump ended with error");
        }
    }
}
