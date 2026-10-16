use thiserror::Error;

/// Failure modes for opening / driving a local shell session. The
/// variants are user-actionable — the Tauri layer renders one of these
/// into a launcher banner or toast.
#[derive(Error, Debug)]
pub enum LocalPtyError {
    /// The pseudo-terminal itself couldn't be allocated (rare — the OS
    /// refused an `openpty` / ConPTY handle).
    #[error("failed to open a pseudo-terminal for {program}: {detail}")]
    OpenFailed { program: String, detail: String },

    /// The shell couldn't be spawned. The common cause is a program
    /// name that doesn't resolve on `PATH`, isn't executable, or a
    /// working directory that doesn't exist.
    #[error("failed to spawn shell {program}: {detail}")]
    SpawnFailed { program: String, detail: String },

    /// I/O while wiring up the reader/writer halves or the background
    /// threads. Kept distinct from open/spawn so the UI can tell
    /// "couldn't start it" apart from "started, then a plumbing error".
    #[error("local pty I/O: {detail}")]
    Io { detail: String },

    /// [`crate::Session::send_input`] / [`crate::Session::resize`] after
    /// the shell already exited. The caller should treat the tab as
    /// ended (the "process exited — press Enter" affordance) rather than
    /// surface an error.
    #[error("session is closed")]
    SessionClosed,
}
