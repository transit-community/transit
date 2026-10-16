//! Reusable redaction-pattern application.
//!
//! `Catalogue` owns the standard pattern catalogue (line-oriented vendor
//! patterns + the multi-line PEM block special case) and exposes a
//! single entry point — [`Catalogue::redact_with`] — that walks every
//! pattern and lets the caller decide what marker to emit for each
//! matched secret. Two callers ride this:
//!
//! - [`super::RedactionFilter`] — emits `[REDACTED:<class>]` (no
//!   ordinal). The Phase 5a behavior, byte-for-byte preserved.
//! - [`super::ConversationRedactor`] (Phase 5b) — emits
//!   `[REDACTED:<class>#<n>]` with `<n>` an ordinal sourced from a
//!   per-Conversation map. Lets the agent reason about secret
//!   *equivalence* across sessions without ever seeing the value.
//!
//! Refactoring the apply loop out of `RedactionFilter` is what made the
//! ordinal scheme possible without duplicating the pattern catalogue
//! across two filter types.

use regex::{Captures, Regex};

use super::patterns::{self, Pattern};
use super::pem;

#[derive(Debug, Clone)]
pub struct Catalogue {
    patterns: Vec<Pattern>,
    pem: Regex,
}

impl Catalogue {
    /// The standard catalogue — exactly the patterns shipped in
    /// Phase 5a. New pattern additions go through `super::patterns`
    /// and the audit gates documented in `CLAUDE.md` §8.
    pub fn standard() -> Self {
        Self {
            patterns: patterns::standard(),
            pem: pem::pem_block_regex(),
        }
    }

    /// Run `input` through every pattern. For every match, the
    /// callback receives `(class, secret_bytes)` and returns the
    /// marker to substitute in.
    ///
    /// The PEM block special case runs first so its multi-line eat
    /// happens before any line-oriented pattern can fire on the
    /// inner base64. For the line-oriented patterns the callback's
    /// returned marker is concatenated AFTER capture group 1 (the
    /// verb / key prefix), so the surrounding syntax survives —
    /// only the secret payload is replaced.
    ///
    /// `replace_all` only rewrites matched bytes, so any suffix
    /// (e.g. ` RO` after a community string) is preserved without
    /// the regex needing to capture it.
    pub fn redact_with<F>(&self, input: &str, on_secret: F) -> String
    where
        // `class` is `&'static str` because every pattern's `class`
        // field is a string literal — surfacing the static lifetime
        // lets `ConversationRedactor` use the class as a stable
        // HashMap key without cloning.
        F: FnMut(&'static str /* class */, &str /* secret */) -> String,
    {
        self.redact_with_skipping(input, &[], on_secret)
    }

    /// Like [`redact_with`](Self::redact_with), but skips any pattern
    /// whose `class` is in `skip_classes`. The PEM block special case
    /// ALWAYS runs (a private key can never be an "identifier"), and
    /// only the trailing bare-token catch-alls are ever skip candidates.
    ///
    /// v4.1.0 — API-JSON redaction passes `["hex-blob"]` so a bare 40+
    /// hex run that is an IDENTIFIER (a UniFi hostId / consoleId, needed
    /// to build the next request path) isn't eaten by the CLI-oriented
    /// bare-hex net. Real secrets in these responses are ALWAYS
    /// key-labeled — the key-anchored `api-json-*` patterns catch them —
    /// and `base64-blob` still runs, so a bare high-entropy base64 token
    /// is still redacted. Terminal/CLI redaction passes `&[]` (skips
    /// nothing), so its bare-hex protection is unchanged. See
    /// `docs/security/threat-model.md` T_API_READ_REDACTION.
    pub fn redact_with_skipping<F>(
        &self,
        input: &str,
        skip_classes: &[&'static str],
        mut on_secret: F,
    ) -> String
    where
        F: FnMut(&'static str /* class */, &str /* secret */) -> String,
    {
        let after_pem = self
            .pem
            .replace_all(input, |caps: &Captures<'_>| {
                let block = caps.get(0).map_or("", |m| m.as_str());
                on_secret("pem-block", block)
            })
            .into_owned();

        let mut current = after_pem;
        for pat in &self.patterns {
            if skip_classes.contains(&pat.class) {
                continue;
            }
            // Semantically pure short-circuit: `replace_all` returns
            // `Cow::Borrowed` on zero matches, but the unconditional
            // `.into_owned()` below still copies the ENTIRE input — one
            // full copy per pattern, ~75 copies per call, which dominates
            // hot callers (session_log per chunk; chat_history per turn,
            // where a large transcript measured ~112 MB copied per
            // persist). No match ⇒ the replacer closure never runs ⇒
            // marker ordinals and output bytes are identical either way.
            if !pat.re.is_match(&current) {
                continue;
            }
            current = pat
                .re
                .replace_all(&current, |caps: &Captures<'_>| {
                    let prefix = caps.get(1).map_or("", |m| m.as_str());
                    let secret = caps.get(2).map_or("", |m| m.as_str());
                    // Optional capture group 3 is a preserved SUFFIX —
                    // matched bytes that must survive AFTER the marker
                    // (e.g. the `@` that terminates a URL userinfo
                    // password: `scheme://u:PASS@host`). Every pattern on
                    // the 2-group `(prefix)(secret)` convention leaves
                    // this `None` → "", so their output is byte-identical.
                    let suffix = caps.get(3).map_or("", |m| m.as_str());
                    let marker = on_secret(pat.class, secret);
                    format!("{prefix}{marker}{suffix}")
                })
                .into_owned();
        }
        current
    }
}

impl Default for Catalogue {
    fn default() -> Self {
        Self::standard()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_with_class_only_matches_phase_5a_behavior() {
        // Spot-check: the legacy `[REDACTED:<class>]` marker shape
        // produced by passing a class-only replacer through the
        // catalogue must equal what `RedactionFilter::redact` used
        // to emit before the refactor.
        let cat = Catalogue::standard();
        let out = cat.redact_with("snmp-server community PUBLIC RO", |class, _| {
            format!("[REDACTED:{class}]")
        });
        assert_eq!(out, "snmp-server community [REDACTED:snmp-community] RO");
    }

    #[test]
    fn redact_with_passes_secret_to_callback() {
        let cat = Catalogue::standard();
        let mut seen: Vec<(String, String)> = Vec::new();
        let _ = cat.redact_with("snmp-server community PUBLIC RO", |class, secret| {
            seen.push((class.to_string(), secret.to_string()));
            format!("[REDACTED:{class}]")
        });
        assert_eq!(
            seen,
            vec![("snmp-community".to_string(), "PUBLIC".to_string())]
        );
    }

    #[test]
    fn redact_with_handles_pem_block_through_callback() {
        // PEM blocks call the callback with class="pem-block" and
        // the entire matched block as the secret — so Phase 5b's
        // ConversationRedactor can ordinal-tag PEM blocks too.
        let cat = Catalogue::standard();
        let input = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj
-----END RSA PRIVATE KEY-----";
        let mut got_class = String::new();
        let mut got_secret_starts_with_begin = false;
        let _ = cat.redact_with(input, |class, secret| {
            got_class = class.to_string();
            got_secret_starts_with_begin = secret.starts_with("-----BEGIN");
            format!("[REDACTED:{class}]")
        });
        assert_eq!(got_class, "pem-block");
        assert!(got_secret_starts_with_begin);
    }
}
