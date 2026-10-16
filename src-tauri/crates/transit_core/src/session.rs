//! Transport-agnostic terminal-session trait.
//!
//! Both `transit_ssh::Session` and `transit_console::Session` impl
//! [`TerminalSession`] so callers in `transit_app` (the Tauri side)
//! and `transit_agent` can hold one `Arc<dyn TerminalSession>` per
//! open session without branching on transport. The trait covers the
//! common shape of an interactive remote shell: live output stream,
//! keystroke channel, scrollback ring, vendor, opened-at, and an
//! ended-notify signal.
//!
//! Phase 7b C16 lands the trait + impls only. A follow-up PR
//! unifies the Tauri-side session table behind `Arc<dyn
//! TerminalSession>` (today there are still per-transport
//! `SshState.sessions` + `ConsoleState.sessions` maps that the
//! commands explicitly fall through between). Adopting incrementally
//! keeps each commit small and reviewable.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use time::OffsetDateTime;
use tokio::sync::{broadcast, Notify};

use crate::inventory::Vendor;
use crate::scrollback::ScrollbackRing;

/// Common surface shared by every interactive terminal-style
/// transport. New transports (telnet, rsh, raw TCP, …) only need to
/// implement this trait to plug into the agent's read_scrollback,
/// propose_command, and the frontend's TerminalPane wiring.
///
/// **Method colors:**
///   - `subscribe`, `scrollback`, `vendor`, `opened_at`,
///     `ended_notify`, `transport_label` are sync. They read from
///     already-built state (broadcast handles, Arc<Notify>, copied
///     metadata) and never await.
///   - `send_input` is async because both impls funnel through an
///     mpsc-backed writer task whose channel send is async.
#[async_trait]
pub trait TerminalSession: Send + Sync {
    /// Subscribe to live output. Each subscriber gets every byte
    /// produced after the subscription was created; history before
    /// that is in [`Self::scrollback`].
    fn subscribe(&self) -> broadcast::Receiver<Bytes>;

    /// Queue keystrokes / paste bytes to the device. Returns an
    /// opaque error string on failure — concrete error types stay in
    /// the transport crates so callers can map them at the IPC
    /// boundary without needing a unified error enum here.
    async fn send_input(&self, bytes: Bytes) -> Result<(), String>;

    /// Handle to the "session ended" signal. Fires when the
    /// underlying transport reports the remote went away (SSH:
    /// channel close, console: cable unplug or port error).
    fn ended_notify(&self) -> Arc<Notify>;

    /// Shared scrollback ring. Both transports use the same type so
    /// this returns it directly — agent's `read_scrollback`
    /// snapshots, frontend's tab attach reads from here.
    fn scrollback(&self) -> Arc<ScrollbackRing>;

    /// Vendor declared at connect time. Drives `transit_policy`'s
    /// per-vendor allow/block adjudication.
    fn vendor(&self) -> Vendor;

    /// When the session was opened — UTC, used for sorting in the
    /// `list_open_sessions` tool surface.
    fn opened_at(&self) -> OffsetDateTime;

    /// Short transport tag for logging / debug formatting:
    /// `"ssh"`, `"console"`, etc. Not user-visible by default;
    /// the frontend renders session labels from
    /// `SessionTab.customLabel` instead.
    fn transport_label(&self) -> &'static str;
}
