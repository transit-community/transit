//! Scrollback access boundary.
//!
//! `ScrollbackSource` is the seam between `transit_agent` and the SSH
//! session manager that owns the actual scrollback rings. The agent
//! reads device output through this trait; production wiring (in
//! `transit_app`, deferred to Phase 5d/6) provides an impl backed by
//! `transit_ssh::ScrollbackRing` snapshots; tests use
//! [`crate::testing::MockScrollbackSource`].
//!
//! This trait deliberately exposes ONLY snapshot reads. The agent has
//! no path to send keystrokes, no path to open new sessions, no path
//! to read raw bytes the SSH layer has already redacted via
//! [`crate::redaction::ConversationRedactor`]. The redaction is done
//! by the dispatcher *between* this source's bytes and what the LLM
//! sees — see [`crate::DefaultDispatcher`].

use transit_core::inventory::Vendor;

#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Raw scrollback text — the FULL current contents of the
    /// session ring, UTF-8. NOT yet redacted; the dispatcher feeds
    /// this through `ConversationRedactor::redact` before applying
    /// any size windowing and returning it as a `read_scrollback`
    /// tool result.
    pub text: String,
    /// True when the ring has already evicted older output (its
    /// capacity was exceeded), i.e. `text` is not the complete
    /// session history. The dispatcher ORs this with its own
    /// post-redaction trims before surfacing `truncated` to the
    /// model.
    pub truncated: bool,
    /// v4.1.0 — true when `text` is a structured API (JSON) response
    /// rather than terminal/CLI output. The dispatcher then redacts via
    /// `ConversationRedactor::redact_json`, which skips the bare-hex
    /// identifier catch-all so a UniFi hostId/consoleId survives (real
    /// secrets stay redacted — they're key-labeled). Only the API
    /// scrollback source sets this; SSH/console leave it `false`. See
    /// `docs/security/threat-model.md` T_API_READ_REDACTION.
    pub json: bool,
}

/// Transport kind of an open session — the fact tool choice depends on.
///
/// `propose_api_call`'s contract says "use this for API/controller
/// sessions; use `propose_command` for SSH/console sessions", and vendor
/// cannot stand in for transport (a UniFi gateway is reachable over SSH
/// *and* as a controller REST API — one vendor string, two transports,
/// two different correct tools). Each production `ScrollbackSource`
/// knows unambiguously what it is building, so the kind is set at
/// construction and rendered in both the prompt roster and the
/// `list_open_sessions` output. There is deliberately no `LocalShell`
/// variant: local shells are agent-blind (T42) and never enter a roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Ssh,
    Console,
    Api,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::Ssh => "ssh",
            SessionKind::Console => "console",
            SessionKind::Api => "api",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub session_id: String,
    pub device_id: String,
    pub vendor: Vendor,
    /// Transport kind (`ssh` / `console` / `api`) — how this session is
    /// reached, and therefore which propose tool fits it. Surfaced to the
    /// model because vendor alone cannot disambiguate (see [`SessionKind`]).
    pub kind: SessionKind,
    /// RFC3339 timestamp.
    pub opened_at: String,
    /// `(name, path)` GET endpoints available on this controller's collection,
    /// surfaced to the agent so it knows what it can propose without guessing
    /// (the #12 known-endpoints "404-killer"). Empty for SSH/console sessions
    /// and for controllers with no collection.
    pub api_endpoints: Vec<(String, String)>,
    /// v6.1.1 — short per-chat session alias (`s1`, `s2`, …) allocated by the
    /// app-side scoped view. When present it is what the model sees as THE
    /// session id (roster, `list_open_sessions`, result envelopes); the
    /// registry UUID stays app-side. `None` outside a chat-scoped view (raw
    /// sources, unit tests) — renderers then fall back to `session_id`.
    pub alias: Option<String>,
    /// v6.1.1 — how many commands have EXECUTED on this session in this
    /// chat: `propose_command` runs AND `propose_api_call` GETs (gate-
    /// denied / user-denied don't count). Populated by the app-side
    /// scoped view from the chat's ledger; rendered in the prompt's
    /// OpenSessions roster so the model doesn't have to keep a narrative
    /// ledger. `None` outside a chat-scoped view.
    pub commands_run: Option<u32>,
    /// v6.1.x — how many bytes the session's scrollback ring currently
    /// holds, so the roster can say whether `read_scrollback` is worth
    /// calling before any tool round. `None` when the source doesn't
    /// track a ring (API sessions) or the ring was contended at listing
    /// time; the roster omits the field then.
    pub scrollback_bytes: Option<usize>,
}

impl SessionMeta {
    /// The session id AS THE MODEL SHOULD SEE IT: the chat's alias when
    /// the scoped view allocated one, the raw registry id otherwise
    /// (unscoped sources, unit tests). Every renderer MUST use this —
    /// a renderer that reads `session_id` directly reintroduces the
    /// 36-char registry UUID v6.1.1 exists to keep out of the prompt.
    pub fn agent_facing_id(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.session_id)
    }

    /// Numeric ordinal of the alias (`s7` → 7). The alias grammar is
    /// `s{n}` — written by the app-side ledger allocator; this parser
    /// is its one counterpart, kept next to the field so the pair
    /// can't drift apart silently.
    pub fn alias_ordinal(&self) -> Option<u32> {
        self.alias.as_deref()?.strip_prefix('s')?.parse().ok()
    }
}

pub trait ScrollbackSource: Send + Sync {
    /// FULL current ring contents for the named session, or `None`
    /// if the session is unknown / closed. Deliberately takes no
    /// byte budget: the `read_scrollback` `max_bytes` window is
    /// applied by the dispatcher strictly AFTER redaction, as a
    /// tail-keep trim on already-redacted text. A pre-redaction
    /// head-drop here could cut a multi-line PEM block mid-body —
    /// the decapitated tail (no `-----BEGIN`) would then sail past
    /// the PEM matcher and reach the LLM verbatim.
    fn snapshot(&self, session_id: &str) -> Option<Snapshot>;

    /// All currently-open sessions. Order is implementation-defined;
    /// callers that need a stable order should sort.
    fn list(&self) -> Vec<SessionMeta>;
}
