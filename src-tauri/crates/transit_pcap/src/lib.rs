//! Packet-capture engine for Transit's **PCaps** surface (v6.0.0).
//!
//! Reads pcap / pcapng / `.pcap.gz`, dissects, indexes, analyses, and
//! answers filtered queries. Live capture is driven by the operating
//! system's own capture binary (`tcpdump` on macOS/Linux, `pktmon` on
//! Windows) — this crate supervises the process and owns the file, and
//! ships no capture driver of its own.
//!
//! # Where this sits relative to the agent firewall
//!
//! PCaps is the first Transit surface the AI agent can *see*. That is the
//! whole point of it — a packet analyzer whose analysis the assistant
//! cannot read is Wireshark with worse dissectors. It does not weaken the
//! firewall, because visibility is granted the same way scrollback is:
//!
//! - `transit_agent` owns a **trait** (`CaptureSource`) and the
//!   agent-facing answer types. It depends on the *shape* of an answer,
//!   never on this crate.
//! - `transit_app` owns this engine, implements that trait over it, and
//!   hands the resulting `Arc<dyn CaptureSource>` to the per-turn
//!   dispatcher — exactly how `SshScrollbackSource` works today.
//! - **`deny.toml` bans `transit_pcap` outside `transit_app`.** A
//!   `transit_pcap = …` line in `transit_agent`'s manifest fails
//!   `cargo deny` rather than building.
//!
//! So the sentence still holds: *the AI loop has no code path to the
//! capture engine, the raw file, or the OS capture process.* It has a
//! path to one narrow, typed, read-only query interface that
//! `transit_app` chose to expose. Three capabilities are deliberately
//! left off that interface and reachable only from human IPC — raw
//! packet bytes, flow reassembly, and export. Metadata-only is an
//! absence, not a policy.
//!
//! # Untrusted input, twice over
//!
//! A capture file is untrusted: every length field in it is chosen by
//! whoever produced the file. And the *contents* are untrusted in a wider
//! way than anything else Transit reads — a device's CLI output at least
//! requires the attacker to have compromised that device, whereas anyone
//! who can put a frame on the monitored segment can plant text in a
//! capture. Two boundaries answer that:
//!
//! - [`reader`] bounds every allocation against both the declared length
//!   and an absolute ceiling, and never panics on any byte sequence.
//! - [`sanitize`] is the single gate every wire-derived string passes
//!   before it reaches the UI or the model.
//!
//! See `docs/security/threat-model.md` T44 (T_PCAP_CAPTURE) and T45
//! (T_PCAP_AGENT).

pub mod analysis;
pub mod dissect;
pub mod error;
pub mod filter;
pub mod index;
pub mod live;
pub mod reader;
pub mod sanitize;
pub mod types;
pub mod writer;

pub use dissect::{
    dissect, Detail, Dissection, Field, FieldValue, Layer, Proto, ProtoSet, Summary,
};
pub use error::{PcapError, Result};
pub use filter::{Filter, FilterError};
pub use index::{build as build_index, CaptureIndex, FlowSort, IndexLimits, PacketRecord};
pub use reader::{CaptureFile, Fetcher, Interface, OwnedPacket, ScanSummary, Scanner};
pub use types::{CaptureFileMeta, CaptureFormat, Endian, IpProto, LinkType, Ports, RawPacket};
pub use writer::PcapWriter;
