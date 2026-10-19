//! Runtime state for API (controller) sessions — the request/response
//! history the agent reads via `read_scrollback` + `list_open_sessions`.
//!
//! An `[[api_session]]` (a UniFi controller) is inventory, not a live
//! connection: the human's request pane sends stateless `api_send_request`
//! calls (`commands.rs`). To let the AGENT see + read a controller the way
//! it sees an SSH session, a per-controller scrollback ring is created when
//! the controller becomes an OPEN session — either the moment its API tab
//! opens ([`ApiSessionState::open`] via `register_api_session`, so the agent
//! can propose the first GET itself) or on the first human send ([`record_exchange`]),
//! whichever comes first. Every send appends to that ring — the same
//! [`ScrollbackRing`] the SSH + console transports use. The ring stores RAW
//! bytes; redaction is the agent boundary, applied by the dispatcher (never
//! at store time), and the human path renders the response raw regardless.
//!
//! [`record_exchange`]: ApiSessionState::record_exchange

use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::SecretString;
use time::OffsetDateTime;
use transit_core::inventory::Vendor;
use transit_core::scrollback::ScrollbackRing;

/// One controller used this session (lazily created on its first
/// `api_send_request`). Keyed by the inventory `ApiSession.id`, which is also
/// the agent-visible session id and the human-visible connection name.
pub struct ApiSessionEntry {
    /// Inventory id == agent session_id == connection name.
    pub api_session_id: String,
    /// Display name (the controller's `name`).
    pub name: String,
    pub vendor: Vendor,
    pub opened_at: OffsetDateTime,
    /// Framed request/response log; RAW bytes (redaction is downstream, at
    /// the agent boundary — the SSH/console rings are raw too).
    pub ring: ScrollbackRing,
    /// `(name, path)` GET endpoints from this controller's collection, pushed
    /// down by the frontend on register (#12 Phase 2b). Surfaced to the agent
    /// so it knows what it can propose without guessing. Not a secret — just
    /// endpoint shapes; may be empty (no collection / not yet sent).
    pub known_endpoints: Vec<(String, String)>,
    /// The auth header the HUMAN last sent on this controller, replayed on
    /// the AGENT's GETs so it can ride the session the human established
    /// (`(header name, value)`).
    ///
    /// Why this exists: `ApiClient::get` sends an EMPTY header map, and a
    /// login-flow controller's credential is a captured session token living
    /// in the FRONTEND (`apiVariablesStore`'s in-memory `captured` layer), not
    /// a keychain-backed `AppliedAuth`. So every agent GET against ACI /
    /// SD-WAN / Apstra / Aruba came back 401/403 while the human pane worked
    /// fine. Meraki was unaffected — its static Bearer key resolves
    /// backend-side.
    ///
    /// This adds NO new credential flow: the value already crosses IPC on
    /// every human request as an ordinary header (`api_send_request`'s
    /// `headers` argument) — it was simply discarded. Here it is merely
    /// RETAINED. In memory only, never persisted, never returned over IPC,
    /// never written to the ring (`record_exchange` frames method/path/status
    /// and the RESPONSE body only), and dropped with the entry on `close`.
    /// `(origin, header name, value)`. The ORIGIN it was established against
    /// is part of the record: a controller's base URL can be edited in place
    /// (`update_api_session` does not close the session, and the pane stays
    /// mounted), so an id alone would let tenant A's cookie ride the agent's
    /// next GET to tenant B's controller. `session_auth` refuses — and clears —
    /// on any origin mismatch. Fail-closed by data shape rather than by a
    /// close() hook someone must remember to call.
    pub session_auth: Option<(String, String, SecretString)>,
}

/// All API sessions with recorded history, keyed by inventory id. A plain
/// `std::sync::Mutex` (not the tokio one the SSH/console maps use) because
/// the only writer holds it for a lock-push-unlock with no `.await`, and the
/// sync `ScrollbackSource` reader can then take it without `try_lock`.
#[derive(Default)]
pub struct ApiSessionState {
    pub sessions: Mutex<HashMap<String, ApiSessionEntry>>,
}

impl ApiSessionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one request/response exchange to the controller's ring,
    /// creating the entry on first use. RAW bytes — the dispatcher redacts
    /// before the agent sees any of it (§9 redact-before-anything).
    // An HTTP exchange genuinely has these fields; a wrapper struct would
    // add ceremony without clarity.
    #[allow(clippy::too_many_arguments)]
    pub fn record_exchange(
        &self,
        api_session_id: &str,
        name: &str,
        vendor: &Vendor,
        method: &str,
        path: &str,
        status: u16,
        body: &str,
    ) {
        // Recover a poisoned lock (`into_inner`) rather than cascade a panic
        // into every later human `api_send_request` — matches `SharedScope`.
        // The critical sections here are trivial (get_mut + `ring.push`,
        // remove, snapshot), so the guarded map is always a consistent value.
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // NON-RESURRECTING (L1, adversarial review). Record ONLY into an
        // already-OPEN session's ring — `open()` (register-on-open, on tab
        // mount) always precedes a human send from that tab, so the entry
        // exists. If it's ABSENT, the tab was closed / the controller deleted
        // (possibly mid-GET, via `close`/`delete_api_session`), and we DROP
        // this exchange rather than re-create the entry: a close/delete
        // landing during an in-flight GET must actually purge the
        // agent-visible ring, not have the late response resurrect it.
        let Some(entry) = guard.get_mut(api_session_id) else {
            return;
        };
        // Refresh the display name/vendor cheaply, so a rename between `open`
        // and this send isn't stale for the agent's `list_open_sessions`.
        entry.name = name.to_string();
        entry.vendor = vendor.clone();
        // Frame each exchange so the agent can parse the history.
        let framed = format!("> {method} {path} -> HTTP {status}\n{body}\n\n");
        entry.ring.push(framed.as_bytes());
    }

    /// Register a controller as an OPEN session with an EMPTY ring — called
    /// when its API tab opens (`register_api_session`), so the agent sees it
    /// via `list_open_sessions` and can propose the FIRST GET itself, without
    /// the human having to send a request first. Idempotent: a no-op if the
    /// entry already exists, so it never wipes history a prior send recorded.
    pub fn open(&self, api_session_id: &str, name: &str, vendor: &Vendor) {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(api_session_id.to_string())
            .or_insert_with(|| ApiSessionEntry {
                api_session_id: api_session_id.to_string(),
                name: name.to_string(),
                vendor: vendor.clone(),
                opened_at: OffsetDateTime::now_utc(),
                ring: ScrollbackRing::new(),
                known_endpoints: Vec::new(),
                session_auth: None,
            });
    }

    /// Replace an OPEN controller's known GET endpoints (`(name, path)` from
    /// its collection). A no-op if the entry isn't open — non-resurrecting,
    /// like `record_exchange`, so a late register after a close can't re-create
    /// the ring. `register_api_session` calls this right after `open`, so the
    /// entry exists.
    pub fn set_known_endpoints(&self, api_session_id: &str, endpoints: Vec<(String, String)>) {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(api_session_id) {
            entry.known_endpoints = endpoints;
        }
    }

    /// Auth header names worth replaying to the agent. Deliberately NOT
    /// `x-api-key`: that one is injected server-side from the keychain by
    /// `AppliedAuth`, so retaining a caller-supplied copy would shadow the
    /// real credential rather than help.
    const REPLAYABLE_AUTH_HEADERS: [&'static str; 4] =
        ["cookie", "authorization", "authtoken", "x-auth-token"];

    /// Shared by BOTH the retention path and the `api_set_session_auth` IPC, so
    /// the IPC cannot be used to install a header the retention path would
    /// refuse. Without this a hostile/careless imported collection could name
    /// any header: `Host` reaches the wire and picks the controller's vhost,
    /// and a bogus `Content-Length` makes hyper frame a body that never
    /// arrives, stalling EVERY agent GET for the full 60s request timeout.
    fn is_replayable_auth_header(name: &str) -> bool {
        Self::REPLAYABLE_AUTH_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
    }

    /// Retain the human's session auth header for agent replay. Called with
    /// the FINAL outgoing headers of a human request; picks the first
    /// auth-shaped one. A no-op if the entry isn't open (non-resurrecting,
    /// like `record_exchange`) or if no header qualifies — so an ordinary
    /// unauthenticated request never clears a good session.
    pub fn remember_session_auth(
        &self,
        api_session_id: &str,
        origin: &str,
        headers: &[(String, String)],
    ) {
        let found = headers
            .iter()
            .find(|(k, v)| !v.trim().is_empty() && Self::is_replayable_auth_header(k));
        let Some((k, v)) = found else { return };
        self.set_session_auth(api_session_id, origin, k, v.clone());
    }

    /// Set the session auth header directly, from the frontend's
    /// `api_set_session_auth` — called the moment a capture rule extracts a
    /// login token, which is the only point at which the token exists but no
    /// authenticated request has been sent yet. Without this the agent could
    /// only ride a session AFTER the human happened to click an investigation
    /// request, which is not how anyone uses it.
    ///
    /// Non-resurrecting (no-op if the controller is not open), and an empty
    /// value is ignored so a blank cannot shadow a live session.
    pub fn set_session_auth(
        &self,
        api_session_id: &str,
        origin: &str,
        header: &str,
        value: String,
    ) {
        if value.trim().is_empty() || origin.trim().is_empty() {
            return;
        }
        // Same allowlist as the retention path — the IPC is not a way around it.
        if !Self::is_replayable_auth_header(header) {
            return;
        }
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(api_session_id) {
            entry.session_auth = Some((
                origin.to_string(),
                header.to_string(),
                SecretString::from(value),
            ));
        }
    }

    /// The retained auth header for an agent GET, if the human has
    /// authenticated this session. Returns a CLONE so the caller does not hold
    /// the lock across an await.
    pub fn session_auth(
        &self,
        api_session_id: &str,
        origin: &str,
    ) -> Option<(String, SecretString)> {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get_mut(api_session_id)?;
        match &entry.session_auth {
            Some((bound, header, value)) if bound.eq_ignore_ascii_case(origin) => {
                Some((header.clone(), value.clone()))
            }
            // Origin changed under us (base URL edited to another controller).
            // Drop the stale credential rather than carry it forward.
            Some(_) => {
                entry.session_auth = None;
                None
            }
            None => None,
        }
    }

    /// The controller's full RAW request/response ring as text, for the HUMAN
    /// session-history view. The human sees raw — it's their own controller's
    /// data, and redaction is only the agent boundary (§9). `None` if the
    /// controller isn't open. The API key never appears here: it's an injected
    /// header, never part of the recorded path or body.
    pub fn history(&self, api_session_id: &str) -> Option<String> {
        let guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get(api_session_id)
            .map(|e| String::from_utf8_lossy(&e.ring.snapshot()).into_owned())
    }

    /// Drop a controller's recorded history + open-session registration.
    /// Called when its API tab closes (`close_api_session`) or its inventory
    /// entry is deleted, so the agent can't surface a closed/removed
    /// controller.
    pub fn close(&self, api_session_id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(api_session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret;

    const ORIGIN: &str = "https://apic.example";
    const OTHER_ORIGIN: &str = "https://tenant-b.example";

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- session-auth replay (v4.3.0) ---
    //
    // A login-flow controller's credential is a session token the HUMAN
    // captured, not a keychain-backed AppliedAuth. The agent must be able to
    // ride it, or every agent GET against ACI / SD-WAN / Apstra / Aruba 403s
    // while the human pane works fine.

    #[test]
    fn remembers_the_humans_session_auth_header_for_agent_replay() {
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.remember_session_auth(
            "apic",
            ORIGIN,
            &hdrs(&[
                ("Accept", "application/json"),
                ("Cookie", "APIC-cookie=tok123"),
            ]),
        );
        let (name, value) = st.session_auth("apic", ORIGIN).expect("retained");
        assert_eq!(name, "Cookie");
        assert_eq!(value.expose_secret(), "APIC-cookie=tok123");
    }

    #[test]
    fn an_unauthenticated_request_does_not_clear_a_good_session() {
        // The human sends plenty of requests with no auth header (the login
        // POST itself, a health check). Those must not wipe the token the
        // agent is riding.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "APIC-cookie=tok123")]));
        st.remember_session_auth(
            "apic",
            ORIGIN,
            &hdrs(&[("Content-Type", "application/json")]),
        );
        assert_eq!(
            st.session_auth("apic", ORIGIN).unwrap().1.expose_secret(),
            "APIC-cookie=tok123"
        );
        // …but a FRESH login replaces it.
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "APIC-cookie=tok456")]));
        assert_eq!(
            st.session_auth("apic", ORIGIN).unwrap().1.expose_secret(),
            "APIC-cookie=tok456"
        );
    }

    #[test]
    fn an_empty_auth_header_is_not_retained() {
        // An unfilled `{{token}}` substitutes to nothing; retaining that would
        // shadow a good session with a blank one.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "   ")]));
        assert!(st.session_auth("apic", ORIGIN).is_none());
    }

    #[test]
    fn x_api_key_is_not_replayed_it_is_injected_server_side() {
        // Retaining a caller copy would shadow the real keychain-backed
        // credential that `AppliedAuth` injects.
        let st = ApiSessionState::new();
        st.open("unifi", "UniFi", &Vendor::Custom("unifi".into()));
        st.remember_session_auth("unifi", ORIGIN, &hdrs(&[("X-API-KEY", "should-not-stick")]));
        assert!(st.session_auth("unifi", ORIGIN).is_none());
    }

    #[test]
    fn set_session_auth_works_at_capture_time_before_any_authed_request() {
        // The real flow: human logs in → capture fires → human asks the agent.
        // No investigation request has been sent, so header-retention alone
        // would leave the agent unauthenticated (the ACI bug). The explicit
        // setter is what closes that window.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.set_session_auth("apic", ORIGIN, "Cookie", "APIC-cookie=tok123".into());
        let (name, value) = st
            .session_auth("apic", ORIGIN)
            .expect("retained at capture time");
        assert_eq!(name, "Cookie");
        assert_eq!(value.expose_secret(), "APIC-cookie=tok123");
    }

    #[test]
    fn set_session_auth_ignores_blanks_and_closed_controllers() {
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.set_session_auth("apic", ORIGIN, "Cookie", "   ".into());
        assert!(st.session_auth("apic", ORIGIN).is_none());
        st.set_session_auth("apic", ORIGIN, "  ", "APIC-cookie=x".into());
        assert!(st.session_auth("apic", ORIGIN).is_none());
        // non-resurrecting
        st.set_session_auth("never-opened", ORIGIN, "Cookie", "APIC-cookie=x".into());
        assert!(st.session_auth("never-opened", ORIGIN).is_none());
    }

    #[test]
    fn session_auth_dies_with_the_controller_and_never_resurrects() {
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "APIC-cookie=tok123")]));
        st.close("apic");
        assert!(st.session_auth("apic", ORIGIN).is_none());
        // Non-resurrecting: a late send after close must not re-create it.
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "APIC-cookie=tok789")]));
        assert!(st.session_auth("apic", ORIGIN).is_none());
    }

    #[test]
    fn a_token_is_never_replayed_to_a_different_origin() {
        // The MSP case: a controller's base URL is edited from tenant A to
        // tenant B. `update_api_session` does not close the session and the
        // pane stays mounted, so an id-only binding would ship tenant A's
        // cookie to tenant B on the agent's next GET. Fail closed, and clear.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.set_session_auth("apic", ORIGIN, "Cookie", "APIC-cookie=tenantA".into());
        assert!(st.session_auth("apic", OTHER_ORIGIN).is_none());
        // …and the stale credential is dropped, not merely withheld, so it
        // cannot resurface if the base URL is edited back.
        assert!(st.session_auth("apic", ORIGIN).is_none());
    }

    #[test]
    fn only_allowlisted_auth_headers_can_be_installed_via_the_setter() {
        // The IPC must not be a way around the retention path's allowlist: a
        // hostile collection naming `Host` picks the controller's vhost, and a
        // bogus `Content-Length` stalls every agent GET for the full timeout.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        for bad in ["Host", "Content-Length", "Transfer-Encoding", "X-Whatever"] {
            st.set_session_auth("apic", ORIGIN, bad, "evil".into());
            assert!(
                st.session_auth("apic", ORIGIN).is_none(),
                "{bad} must be refused"
            );
        }
        st.set_session_auth("apic", ORIGIN, "AuthToken", "ok".into());
        assert!(st.session_auth("apic", ORIGIN).is_some());
    }

    #[test]
    fn the_session_token_never_reaches_the_agent_visible_ring() {
        // `record_exchange` frames method/path/status + the RESPONSE body.
        // The auth header is not part of any of those.
        let st = ApiSessionState::new();
        st.open("apic", "APIC", &Vendor::Custom("aci".into()));
        st.remember_session_auth("apic", ORIGIN, &hdrs(&[("Cookie", "APIC-cookie=tok123")]));
        st.record_exchange(
            "apic",
            "APIC",
            &Vendor::Custom("aci".into()),
            "GET",
            "api/class/topSystem.json",
            200,
            "{\"totalCount\":\"1\"}",
        );
        let history = st.history("apic").expect("open");
        assert!(!history.contains("tok123"), "{history}");
        assert!(!history.to_lowercase().contains("cookie"), "{history}");
    }

    #[test]
    fn records_and_snapshots_history() {
        let st = ApiSessionState::new();
        let v = Vendor::Custom("unifi".into());
        st.open("office-unifi", "Office UniFi", &v);
        st.record_exchange(
            "office-unifi",
            "Office UniFi",
            &v,
            "GET",
            "/v1/sites",
            200,
            r#"{"data":[]}"#,
        );
        let guard = st.sessions.lock().unwrap();
        let entry = guard.get("office-unifi").expect("entry created");
        assert_eq!(entry.name, "Office UniFi");
        let text = String::from_utf8_lossy(&entry.ring.snapshot()).into_owned();
        assert!(text.contains("GET /v1/sites -> HTTP 200"));
        assert!(text.contains(r#"{"data":[]}"#));
    }

    #[test]
    fn second_call_appends_to_the_same_ring() {
        let st = ApiSessionState::new();
        let v = Vendor::Custom("unifi".into());
        st.open("c", "C", &v);
        st.record_exchange("c", "C", &v, "GET", "/v1/sites", 200, "a");
        st.record_exchange("c", "C", &v, "GET", "/v1/devices", 200, "b");
        let guard = st.sessions.lock().unwrap();
        let text = String::from_utf8_lossy(&guard.get("c").unwrap().ring.snapshot()).into_owned();
        assert!(text.contains("/v1/sites") && text.contains("/v1/devices"));
    }

    #[test]
    fn record_on_a_closed_session_is_dropped_not_resurrected() {
        // L1: a send/GET whose response lands AFTER the tab closed must not
        // re-create the agent-visible ring.
        let st = ApiSessionState::new();
        let v = Vendor::Custom("unifi".into());
        st.record_exchange("gone", "Gone", &v, "GET", "/v1/sites", 200, "late");
        assert!(
            st.sessions.lock().unwrap().get("gone").is_none(),
            "record_exchange must NOT resurrect a closed/absent controller"
        );
    }

    #[test]
    fn close_drops_history() {
        let st = ApiSessionState::new();
        st.open("c", "C", &Vendor::Custom("unifi".into()));
        st.record_exchange(
            "c",
            "C",
            &Vendor::Custom("unifi".into()),
            "GET",
            "/x",
            200,
            "y",
        );
        st.close("c");
        assert!(st.sessions.lock().unwrap().get("c").is_none());
    }

    #[test]
    fn open_registers_empty_session_idempotently() {
        // register-on-open: an opened controller is agent-visible with an
        // empty ring, and a later `open` never wipes recorded history.
        let st = ApiSessionState::new();
        let v = Vendor::Custom("unifi".into());
        st.open("c", "Office UniFi", &v);
        {
            let guard = st.sessions.lock().unwrap();
            let entry = guard.get("c").expect("open registers an entry");
            assert_eq!(entry.name, "Office UniFi");
            assert!(entry.ring.snapshot().is_empty(), "ring starts empty");
        }
        // A send, then a second open, must be a no-op (history preserved).
        st.record_exchange("c", "Office UniFi", &v, "GET", "/v1/sites", 200, "data");
        st.open("c", "Office UniFi", &v);
        let guard = st.sessions.lock().unwrap();
        let text = String::from_utf8_lossy(&guard.get("c").unwrap().ring.snapshot()).into_owned();
        assert!(
            text.contains("/v1/sites"),
            "open is a no-op on an existing entry"
        );
    }
}
