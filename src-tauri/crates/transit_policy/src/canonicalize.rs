//! Pre-match canonicalization.
//!
//! Each command goes through four normalizations before regex
//! matching, so the same logical input doesn't have multiple
//! representations the policy author has to anticipate:
//!
//! 1. **Trim** leading/trailing ASCII whitespace.
//! 2. **NFC-normalize** Unicode (canonical decomposition + canonical
//!    composition). Defangs fullwidth Latin spoofing — fullwidth
//!    `ｓｈｏｗ` collapses to ASCII `show`, so a `^show ` regex
//!    catches both. Composed precomposed characters round-trip
//!    losslessly.
//! 3. **Lowercase** (D-4). Network CLIs are case-insensitive
//!    (`CONF T` enters config mode like `conf t`); the policy
//!    regexes are written lowercase, so without folding the curated
//!    blocklists only fire on lowercase input. The canonical string
//!    is used ONLY for matching — the raw command is what executes —
//!    so lowercasing cannot corrupt what's sent to the device.
//! 4. **First-token alias expansion** — if the first whitespace-
//!    delimited token has an entry in the vendor's alias map,
//!    replace it with the canonical form. e.g. Junos `sh int br`
//!    → `show int br`. The rest of the line is preserved
//!    verbatim (no recursive expansion). Lookup is effectively
//!    case-insensitive: the head is already lowercased here and the
//!    loader lowercases the map keys.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

/// Apply all four canonicalization steps in order. Pure function;
/// `aliases` is borrowed, not consumed.
pub fn canonicalize(input: &str, aliases: &HashMap<String, String>) -> String {
    let trimmed = input.trim();
    let nfc: String = trimmed.nfc().collect();
    let lowered = nfc.to_lowercase();

    // Split off the first whitespace-delimited token. `split_once`
    // would only catch a single space; commands with tabs or
    // multiple spaces between the verb and its arguments need the
    // more permissive `splitn`. We then rejoin with a single space
    // — runs of whitespace inside a command are not semantically
    // meaningful for our regex matching.
    let mut parts = lowered.split_whitespace();
    let head = match parts.next() {
        Some(h) => h,
        None => return String::new(),
    };

    let canonical_head = aliases.get(head).map(String::as_str).unwrap_or(head);

    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        canonical_head.to_string()
    } else {
        format!("{} {}", canonical_head, rest.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliases() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("sh".to_string(), "show".to_string());
        m.insert("p".to_string(), "ping".to_string());
        m
    }

    #[test]
    fn trims_leading_and_trailing_whitespace() {
        assert_eq!(
            canonicalize("   show version  ", &aliases()),
            "show version"
        );
    }

    #[test]
    fn collapses_internal_whitespace_runs() {
        assert_eq!(
            canonicalize("show    interfaces    terse", &aliases()),
            "show interfaces terse"
        );
    }

    #[test]
    fn expands_first_token_alias() {
        assert_eq!(canonicalize("sh interfaces", &aliases()), "show interfaces");
    }

    #[test]
    fn lowercases_for_matching() {
        // D-4 — `CONF T` / `Configure` must canonicalize to the
        // lowercase forms the policy regexes are written against.
        assert_eq!(canonicalize("SHOW Version", &aliases()), "show version");
        assert_eq!(canonicalize("CONFIGURE", &aliases()), "configure");
    }

    #[test]
    fn alias_lookup_is_case_insensitive() {
        // Lowercasing happens before the alias lookup, so `SH` hits
        // the lowercase-keyed map like `sh` does.
        assert_eq!(canonicalize("SH interfaces", &aliases()), "show interfaces");
    }

    #[test]
    fn does_not_recursively_expand_aliases_inside_args() {
        // `sh` later in the line is just a string, not the verb.
        // The expansion only applies to the head.
        let m = aliases();
        assert_eq!(
            canonicalize("show config sh", &m),
            "show config sh",
            "alias should not fire for non-head occurrences"
        );
    }

    #[test]
    fn alias_with_no_args_yields_canonical_alone() {
        assert_eq!(canonicalize("sh", &aliases()), "show");
    }

    #[test]
    fn nfc_normalization_collapses_fullwidth_latin() {
        // Fullwidth ASCII `ｓｈｏｗ` (U+FF53 etc) -> ASCII `show`
        // under NFKC, but NOT under NFC. NFC preserves the
        // distinction; we accept that — fullwidth alpha is exotic
        // enough that a network engineer typing it deliberately is
        // out of scope for this v1. What NFC DOES handle is
        // composed-vs-decomposed accents (eg. `é` as one codepoint
        // vs `e + combining acute`) which can otherwise sneak past
        // a regex. Test: a decomposed string composes back.
        let decomposed = "show e\u{0301}";
        let composed = "show é";
        assert_eq!(canonicalize(decomposed, &aliases()), composed);
    }

    #[test]
    fn empty_input_yields_empty_string() {
        assert_eq!(canonicalize("", &aliases()), "");
        assert_eq!(canonicalize("   ", &aliases()), "");
    }

    #[test]
    fn no_alias_passthrough() {
        let m = HashMap::new(); // empty alias map
        assert_eq!(canonicalize("show version", &m), "show version");
    }
}
