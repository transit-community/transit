//! USB-to-serial (console cable) transport.
//!
//! Phase 7b. Companion to [`transit_ssh`]: the SSH crate handles
//! authenticated remote shells, this crate handles the cable a network
//! engineer plugs into a switch's console port when the management
//! plane is unreachable. Both crates expose a session API with the
//! same shape (reader/writer task split, `subscribe`, `send_input`,
//! `ended_notify`) so the Tauri layer treats them uniformly.
//!
//! # Concurrency
//!
//! Opening a port spawns two background tasks that share ownership of
//! a [`tokio_serial::SerialStream`] via `tokio::io::split`:
//!
//! - **Reader** — drives `AsyncReadExt::read`, pushes bytes into the
//!   shared [`ScrollbackRing`], broadcasts to live subscribers. Exits
//!   on read error (cable unplugged / port closed) and notifies
//!   `ended` so subscribers learn the session went away.
//! - **Writer** — owns the write half, processes
//!   [`SessionCmd::Data`] / [`SessionCmd::Close`] commands FIFO
//!   through a single `mpsc`.
//!
//! No PTY allocation, no resize, no auth: the cable IS the connection.
//!
//! # What this crate intentionally doesn't do
//!
//! - **Hot-plug discovery.** Lives in `hotplug.rs` (Phase 7b C17). The
//!   sidebar's auto-populated cable list is fed from a separate
//!   watcher; this module just opens whatever port-path it's given.
//! - **Paging init.** SSH sessions send `terminal length 0` for
//!   Cisco-family vendors right after the shell is up (so agent
//!   quiescence capture sees no `--More--`). For a console cable
//!   we have no reliable post-auth checkpoint — the user usually
//!   lands at a login prompt, where the paging-init bytes would
//!   produce stray "unknown command" lines. The agent's first
//!   `propose_command` may need to paginate manually until we add
//!   a post-login hook.
//! - **Vendor policy.** [`SessionMeta::vendor`] is plumbed through so
//!   `transit_app::ApprovalDispatcher` can adjudicate
//!   `propose_command` against `transit_policy`, identical to the
//!   SSH path. This crate just stores the value; it never reads it.

mod driver_status;
mod error;
mod hotplug;
mod session;
mod types;

pub use driver_status::{status as driver_status, DriverStatus, MissingDriver};
pub use error::ConsoleError;
pub use hotplug::{start as start_hotplug, HotplugEvent, HotplugWatcher};
pub use session::{
    list_available_ports, Session, SessionMeta, INPUT_CHANNEL_SIZE, OUTPUT_CHANNEL_SIZE,
};
pub use types::{
    ConnectParams, DataBits, FlowControl, Parity, SerialPortInfo, StopBits, UsbPortDetails,
    DEFAULT_BAUD,
};
