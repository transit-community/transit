//! Errors for the capture engine.
//!
//! Two rules shape this enum:
//!
//! 1. **A malformed capture is a normal outcome, not a panic.** Every
//!    parse path returns `Result`; the reader tolerates a truncated tail
//!    (the file may still be being written) and reports how far it got.
//! 2. **Nothing here carries packet bytes.** Error text reaches logs, the
//!    UI, and — via a refused `query_capture` — the model. A message that
//!    echoed the offending bytes would be a redaction bypass, so errors
//!    carry offsets, lengths, and static reasons only.

use std::path::PathBuf;

/// Failures opening or reading a capture file.
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a pcap or pcapng file (unrecognized magic)")]
    UnknownFormat,

    #[error("capture header is malformed: {0}")]
    BadHeader(&'static str),

    /// The file ends mid-record. Expected while a live capture is still
    /// running — the indexer stops here and resumes on the next tick.
    #[error("capture truncated at byte {at}")]
    Truncated { at: u64 },

    #[error("capture file is empty")]
    Empty,

    #[error("capture file is {size} bytes, over the {limit}-byte ceiling")]
    TooLarge { size: u64, limit: u64 },

    #[error("could not decompress {path}: {reason}")]
    Gunzip { path: PathBuf, reason: String },

    #[error("no capture is open with id {0}")]
    UnknownCapture(String),

    #[error("packet {0} is not in this capture")]
    UnknownPacket(u64),

    /// A pcapng block type we index but cannot re-read individually
    /// (anything that is not an Enhanced or Simple Packet Block).
    #[error("packet {0} cannot be re-read individually from this file")]
    PacketNotAddressable(u64),

    #[error("filter error: {0}")]
    Filter(#[from] crate::filter::FilterError),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, PcapError>;
