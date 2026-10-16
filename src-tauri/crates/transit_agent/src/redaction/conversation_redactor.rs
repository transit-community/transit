//! Per-Conversation redactor that lets the agent reason about secret
//! *equivalence* without ever seeing the value.
//!
//! Markers emitted by [`ConversationRedactor::redact`] have the shape
//! `[REDACTED:<class>#<n>]` where `<n>` is an ordinal sourced from a
//! per-Conversation `(class, secret_bytes) → ordinal` map:
//!
//! - same secret bytes within the same `ConversationRedactor` →
//!   same ordinal forever (lets the agent say "vEX1's BGP MD5 matches
//!   vEX2's" → likely not the failure cause)
//! - different secret bytes → different ordinals
//! - same byte sequence under two different classes → two ordinals
//!   (BGP MD5 `password X` and SNMP community `community X` are not
//!   equivalent in the agent's mental model)
//!
//! The map is in-memory only. Never persisted, never serialized,
//! never sent to cloud — the cloud only ever sees the rendered
//! marker (just `class#n`, zero bits of the secret value).
//!
//! ## Why ordinals, not hashes
//!
//! Hashing weak network-engineer secrets (`cisco123`, vendor defaults)
//! is brute-forceable from SHA-256 even with rainbow tables. Identical
//! hashes across conversations would also become a stable cloud-side
//! fingerprint. Ordinals reset per Conversation, leak zero bits about
//! the value, and only preserve the diagnostic the user actually asked
//! for: "are these two redacted secrets equal?" — Phase 5a planning,
//! 2026-05-08.

use std::collections::HashMap;

use crate::redaction::Catalogue;

#[derive(Debug)]
pub struct ConversationRedactor {
    catalogue: Catalogue,
    /// Per-Conversation map from `(class, raw secret bytes)` to the
    /// ordinal we've assigned it. Owned data on the secret side
    /// because `Catalogue::redact_with` hands the callback a
    /// borrowed `&str` from the regex match — we have to clone to
    /// keep it across calls. The borrow is short-lived (only inside
    /// the closure), so the clone is the right tradeoff.
    secret_index: HashMap<(&'static str, String), u32>,
    /// Next ordinal to assign on a fresh secret. Starts at 1 because
    /// human-facing identifiers expect 1-indexing — `#0` looks like
    /// a sentinel.
    next: u32,
}

impl ConversationRedactor {
    pub fn new() -> Self {
        Self {
            catalogue: Catalogue::standard(),
            secret_index: HashMap::new(),
            next: 1,
        }
    }

    /// Run `input` through the catalogue's patterns; emit
    /// `[REDACTED:<class>#<n>]` markers, looking up or assigning
    /// ordinals as needed. Idempotent — `r.redact(r.redact(x))`
    /// equals `r.redact(x)` (the markers themselves are not
    /// caught by any pattern in the catalogue, since the secret
    /// capture group rejects strings starting with `[`).
    pub fn redact(&mut self, input: &str) -> String {
        self.redact_impl(input, &[])
    }

    /// Redact an API-JSON response (v4.1.0). Like [`redact`](Self::redact)
    /// but skips the bare `hex-blob` catch-all, so a hex IDENTIFIER (a
    /// UniFi hostId/consoleId the agent needs for the next request path)
    /// survives. Every key-anchored secret pattern, PEM, and `base64-blob`
    /// still run, and API secrets are always key-labeled — so real secrets
    /// are still stripped. Use ONLY on structured API responses; terminal
    /// output must use `redact` (a bare token there can be a keyless
    /// secret). Ordinals are shared with `redact` (same counter/index), so
    /// a secret seen on both paths keeps one stable `#n`.
    pub fn redact_json(&mut self, input: &str) -> String {
        self.redact_impl(input, &["hex-blob"])
    }

    fn redact_impl(&mut self, input: &str, skip: &[&'static str]) -> String {
        // Split-borrow: the closure needs &mut access to the index
        // and the counter, but we still need &self.catalogue to drive
        // the apply loop. These three fields are disjoint, so destructure
        // through individual references.
        let secret_index = &mut self.secret_index;
        let next = &mut self.next;
        self.catalogue
            .redact_with_skipping(input, skip, move |class, secret| {
                let n = match secret_index.get(&(class, secret.to_string())) {
                    Some(existing) => *existing,
                    None => {
                        let assigned = *next;
                        *next += 1;
                        secret_index.insert((class, secret.to_string()), assigned);
                        assigned
                    }
                };
                format!("[REDACTED:{class}#{n}]")
            })
    }

    /// How many distinct (class, secret) pairs this redactor has seen.
    /// Useful for tests and Conversation-state introspection; not
    /// sent to the cloud.
    pub fn distinct_secrets(&self) -> usize {
        self.secret_index.len()
    }
}

impl Default for ConversationRedactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalence_within_session() {
        // Same secret bytes in two redact() calls produce identical
        // ordinals. This is THE diagnostic property — without it the
        // agent can't tell whether two BGP peers share an MD5 key.
        let mut r = ConversationRedactor::new();
        let a = r.redact("neighbor 10.0.0.1 password BgpKey");
        let b = r.redact("neighbor 10.0.0.2 password BgpKey");
        assert!(a.contains("[REDACTED:bgp-md5#1]"));
        assert!(b.contains("[REDACTED:bgp-md5#1]"));
    }

    #[test]
    fn distinctness() {
        let mut r = ConversationRedactor::new();
        let a = r.redact("neighbor 10.0.0.1 password KeyA");
        let b = r.redact("neighbor 10.0.0.2 password KeyB");
        assert!(a.contains("[REDACTED:bgp-md5#1]"));
        assert!(b.contains("[REDACTED:bgp-md5#2]"));
    }

    #[test]
    fn redact_json_passes_hex_id_but_still_redacts_keyed_secret() {
        // The ordinal path mirrors RedactionFilter::redact_json: a bare
        // hex hostId survives while a key-labeled PSK is redacted.
        let mut r = ConversationRedactor::new();
        let host_id = "900a6f00a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let out = r.redact_json(&format!(
            r#"{{"hostId":"{host_id}","x_passphrase":"WifiPass99"}}"#
        ));
        assert!(out.contains(host_id), "hostId passes on the ordinal path");
        assert!(!out.contains("WifiPass99"), "keyed PSK still redacted");
    }

    #[test]
    fn next_ordinal_advances_only_for_new_secret() {
        // Repeated redact of the same secret doesn't move the
        // counter — pins the contract that ordinals are stable
        // across reads.
        let mut r = ConversationRedactor::new();
        r.redact("neighbor 10.0.0.1 password KeyA");
        let after_first = r.next;
        r.redact("neighbor 10.0.0.1 password KeyA");
        r.redact("neighbor 10.0.0.1 password KeyA");
        assert_eq!(
            r.next, after_first,
            "counter must not advance on duplicate secret"
        );
    }

    #[test]
    fn dropping_redactor_resets_ordinals() {
        // Two fresh redactors, redacted with the same input, both
        // produce `#1`. Pins the per-Conversation scope — the
        // ordinal state is bounded by the redactor's lifetime.
        let mut r1 = ConversationRedactor::new();
        let mut r2 = ConversationRedactor::new();
        let a = r1.redact("neighbor 10.0.0.1 password KeyA");
        let b = r2.redact("neighbor 10.0.0.1 password KeyA");
        assert!(a.contains("#1"));
        assert!(b.contains("#1"));
    }

    #[test]
    fn multi_class_same_bytes() {
        // Same byte sequence under two different classes gets
        // two ordinals. BGP MD5 `password SHARED` and SNMP
        // `community SHARED` aren't equivalent in the agent's
        // mental model.
        let mut r = ConversationRedactor::new();
        let bgp = r.redact("neighbor 10.0.0.1 password SHARED");
        let snmp = r.redact("snmp-server community SHARED RO");
        assert!(bgp.contains("[REDACTED:bgp-md5#1]"));
        assert!(snmp.contains("[REDACTED:snmp-community#2]"));
        assert_eq!(r.distinct_secrets(), 2);
    }

    #[test]
    fn idempotency() {
        // Running redact twice on the same input must produce
        // byte-identical output — markers must not get re-clobbered
        // by a pattern that thinks `[REDACTED:foo#3]` looks like
        // a secret. The catalogue's secret class `[^\[\s]\S*`
        // already rejects strings starting with `[`, so this is
        // a regression-pin on that property.
        let mut r = ConversationRedactor::new();
        let once = r.redact("snmp-server community SuperSecret RO");
        let twice = r.redact(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn pem_block_gets_ordinal_too() {
        // PEM blocks ride the same ordinal scheme. Two identical
        // PEM blocks across different "scrollback" reads collapse
        // to the same ordinal — useful if the same SSH key is
        // shown by `show host-keys` on two different devices.
        let mut r = ConversationRedactor::new();
        let block_a = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj
-----END RSA PRIVATE KEY-----";
        let block_b = block_a; // same bytes
        let a = r.redact(block_a);
        let b = r.redact(block_b);
        assert!(a.contains("[REDACTED:pem-block#1]"));
        assert!(b.contains("[REDACTED:pem-block#1]"));
    }

    #[test]
    fn cross_call_counter_is_monotonic() {
        // Distinct secrets across many calls receive monotonically
        // increasing ordinals. Pin to catch a refactor that
        // accidentally resets `next` per-call.
        let mut r = ConversationRedactor::new();
        let _ = r.redact("snmp-server community A RO");
        let _ = r.redact("snmp-server community B RO");
        let _ = r.redact("snmp-server community C RO");
        let last = r.redact("snmp-server community D RO");
        assert!(last.contains("#4"));
    }
}
