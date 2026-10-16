use thiserror::Error;

/// Failure modes for opening / driving a serial-console session. The
/// variants are user-actionable — the Tauri layer renders one of these
/// into a sidebar banner or toast.
#[derive(Error, Debug)]
pub enum ConsoleError {
    /// The OS port path (e.g. `/dev/cu.usbserial-A99BCXAG` on macOS,
    /// `COM3` on Windows) couldn't be opened. The most common cause is
    /// another process already holding the port — most platforms make
    /// serial-port opens exclusive.
    #[error("failed to open serial port {path}: {detail}")]
    OpenFailed { path: String, detail: String },

    /// Configuration was rejected at open time — e.g. requested baud
    /// not supported by the chip, or unsupported parity / flow combo.
    /// Separated from [`Self::OpenFailed`] so the UI can offer a
    /// "use defaults" recovery action.
    #[error("invalid port configuration for {path}: {detail}")]
    InvalidConfig { path: String, detail: String },

    /// Underlying I/O during read or write. Wraps `std::io::Error`
    /// so callers can pattern-match on `ErrorKind` if needed (e.g.
    /// `BrokenPipe` after USB unplug).
    #[error("serial I/O on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `Session::send_input` was called after the writer task already
    /// exited (cable unplugged, port closed). The caller should drop
    /// the `Session` and present the user with the disconnect.
    #[error("session is closed")]
    SessionClosed,

    /// Generic wrapper for failures that don't fit a more specific
    /// classification. Keep this rare — every new failure shape that
    /// is user-actionable should get a dedicated variant so the UI
    /// can render a useful message.
    #[error("console error: {detail}")]
    Other { detail: String },
}
