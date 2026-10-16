//! Packet-capture access boundary.
//!
//! `CaptureSource` is to the PCaps surface what [`crate::scrollback::
//! ScrollbackSource`] is to SSH sessions: the seam between this crate and
//! an engine that lives downstream of it. `transit_app` owns
//! `transit_pcap` and implements this trait over it; `transit_agent`
//! depends on the *shape* of an answer and never on the engine, the
//! capture file, or the OS capture process.
//!
//! # This is the first surface the agent can see, and it costs the
//! firewall nothing
//!
//! Terminal (T42) and Files (T43) are structurally agent-blind. PCaps is
//! the opposite — the assistant reading a capture *is* the feature, since
//! a packet analyzer whose analysis the assistant cannot read is
//! Wireshark with worse dissectors.
//!
//! Visibility is still granted the same way scrollback's is, through a
//! trait rather than a dependency, and `deny.toml` bans `transit_pcap`
//! outside `transit_app` to keep that a dep-graph property. What the ban
//! buys is the three capabilities deliberately left **off** this trait —
//! raw packet bytes, flow reassembly, and export. They are reachable only
//! from human IPC. Metadata-only is an absence, not a policy: a model
//! cannot ask for wire payload because there is no shape in which to ask.
//!
//! # Everything crossing this boundary is untrusted
//!
//! A capture's strings are chosen by whoever put a frame on the monitored
//! segment — not by the user, not by a device the user administers, by
//! *anyone on the wire*. The engine sanitizes at its own boundary; the
//! dispatcher redacts and frames on this side. See
//! `docs/security/threat-model.md` T45.

/// Metadata for one open capture.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureMeta {
    /// Stable id the model uses to name this capture.
    pub capture_id: String,
    /// Display name — the file's own name, never a full path. A path
    /// carries a username and would reach the model for no benefit.
    pub name: String,
    pub packets: u64,
    /// Wire bytes across the capture.
    pub bytes: u64,
    /// Human duration, e.g. `00:14:22.418`.
    pub duration: String,
    /// True while a live capture is still being written.
    pub live: bool,
}

/// What the model asked for.
///
/// Note what is not here: there is no variant carrying packet payload,
/// and no field that would return raw bytes. That is the structural half
/// of "metadata only" — the same move that makes `propose_api_call`
/// GET-only by having no `method` field.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureQueryKind {
    /// Enumerate open captures.
    List,
    /// The precomputed digest: protocol mix, talkers, conversations, TCP
    /// health, per-protocol summaries and findings. O(1) in packet count.
    Overview,
    /// Packet rows matching a view filter, paginated.
    Packets {
        filter: Option<String>,
        offset: u32,
        limit: u32,
    },
    /// The conversation table.
    Conversations { by: String, limit: u32 },
    /// One conversation's story: counters, health, and its packets.
    Flow { flow_id: u32 },
    /// One packet's dissected field tree. Fields only — the bytes pane is
    /// a human surface and is not reachable from here.
    Packet { number: u64 },
    /// The deterministic findings list.
    Findings {
        severity: Option<String>,
        limit: u32,
    },
    /// Time-bucketed counters, for rate and throughput questions.
    Timeline {
        bucket_ms: u32,
        filter: Option<String>,
    },
}

/// One capture's answer to a query.
///
/// `text` is a compact, column-aligned table rather than JSON: JSON would
/// restate every field name on every row and cost roughly 40% more tokens
/// for identical information.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureAnswer {
    /// The rendered answer. **Not yet redacted** — the dispatcher runs
    /// `ConversationRedactor` over this before the model sees it, on the
    /// same redact-before-trim contract as scrollback.
    pub text: String,
    /// How many rows matched in total, when the query is row-shaped.
    /// Reported so the model is always told what it did not see; a
    /// silently truncated answer reads as the whole picture.
    pub total_matched: Option<u64>,
    /// How many rows this answer actually carries.
    pub returned: Option<u32>,
    /// True when a limit elided rows.
    pub truncated: bool,
}

impl CaptureAnswer {
    /// An answer with no row semantics (the digest, a packet's fields).
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            total_matched: None,
            returned: None,
            truncated: false,
        }
    }
}

/// Why a query could not be answered.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CaptureQueryError {
    #[error("no capture is open with id `{0}`")]
    UnknownCapture(String),
    /// Raised when `capture_id` was omitted and the choice is ambiguous.
    /// Names the options so the model's next call can be right.
    #[error("{0}")]
    Ambiguous(String),
    #[error("no captures are open")]
    NoCaptures,
    #[error("filter error: {0}")]
    BadFilter(String),
    #[error("{0}")]
    NotFound(String),
    /// `[pcap] agent_access = false`. A deployment can keep the Explorer
    /// and sever the assistant's view of it.
    #[error("the assistant's access to packet captures is disabled on this installation")]
    AccessDisabled,
}

/// The seam. Implemented in `transit_app` over the capture engine.
pub trait CaptureSource: Send + Sync {
    /// Open captures, in the order they were opened.
    fn list(&self) -> Vec<CaptureMeta>;

    /// Answer one query.
    ///
    /// `capture_id` is optional: with exactly one capture open, omitting
    /// it is unambiguous and saves the model a round trip. With several,
    /// the error names them.
    fn query(
        &self,
        capture_id: Option<&str>,
        kind: &CaptureQueryKind,
    ) -> Result<CaptureAnswer, CaptureQueryError>;
}

/// Resolve an optional capture id against a list, with an error that
/// tells the model what to do next.
///
/// Shared here rather than in the implementation so the mock and the real
/// source cannot drift on the one piece of behaviour a model will
/// actually trip over.
pub fn resolve_capture_id(
    requested: Option<&str>,
    open: &[CaptureMeta],
) -> Result<String, CaptureQueryError> {
    match requested {
        Some(id) => {
            if open.iter().any(|c| c.capture_id == id) {
                Ok(id.to_string())
            } else {
                Err(CaptureQueryError::UnknownCapture(id.to_string()))
            }
        }
        None => match open {
            [] => Err(CaptureQueryError::NoCaptures),
            [only] => Ok(only.capture_id.clone()),
            many => {
                let ids: Vec<String> = many
                    .iter()
                    .map(|c| format!("{} ({})", c.capture_id, c.name))
                    .collect();
                Err(CaptureQueryError::Ambiguous(format!(
                    "several captures are open — name one with capture_id: {}",
                    ids.join(", ")
                )))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, name: &str) -> CaptureMeta {
        CaptureMeta {
            capture_id: id.into(),
            name: name.into(),
            packets: 10,
            bytes: 1000,
            duration: "00:00:01.000".into(),
            live: false,
        }
    }

    #[test]
    fn one_open_capture_needs_no_id() {
        let open = vec![meta("c1", "lab.pcap")];
        assert_eq!(resolve_capture_id(None, &open).unwrap(), "c1");
    }

    #[test]
    fn several_open_captures_name_the_options() {
        let open = vec![meta("c1", "a.pcap"), meta("c2", "b.pcap")];
        let err = resolve_capture_id(None, &open).unwrap_err();
        let msg = err.to_string();
        // The model has to be able to fix this on the next call without
        // guessing, so both the ids and the names appear.
        assert!(msg.contains("c1") && msg.contains("c2"), "{msg}");
        assert!(msg.contains("a.pcap") && msg.contains("b.pcap"), "{msg}");
        assert!(msg.contains("capture_id"), "{msg}");
    }

    #[test]
    fn an_unknown_id_is_named() {
        let open = vec![meta("c1", "a.pcap")];
        assert_eq!(
            resolve_capture_id(Some("nope"), &open),
            Err(CaptureQueryError::UnknownCapture("nope".into()))
        );
    }

    #[test]
    fn no_open_captures_is_its_own_error() {
        assert_eq!(
            resolve_capture_id(None, &[]),
            Err(CaptureQueryError::NoCaptures)
        );
    }
}
