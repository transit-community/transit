//! Multi-line PEM / SSH-key block redaction.
//!
//! PEM-formatted private-key material spans many lines:
//!
//! ```text
//! -----BEGIN RSA PRIVATE KEY-----
//! MIIBOgIBAAJBA...
//! ...many lines of base64...
//! -----END RSA PRIVATE KEY-----
//! ```
//!
//! Single-line patterns can't catch this — the secret bytes are on
//! interior lines that match no vendor verb. The patterns module
//! does have long-base64 / long-hex catch-alls (64+ / 40+ char runs,
//! at the end of the catalogue), but they're defense in depth, not
//! the primary mechanism for PEM: an interior line shorter than the
//! catch-all floor would slip through them. We collapse the entire
//! `BEGIN ... END` block to one `[REDACTED:pem-block]` marker so
//! the model sees that a key was here without seeing any of its
//! bytes.
//!
//! This handler runs *first* in `RedactionFilter::redact` so that
//! line-oriented patterns don't get a chance to fire on the inner
//! base64 (which would produce many small redaction markers
//! instead of one clean one).
//!
//! ## Tag breadth
//!
//! `BEGIN <TAG>` covers RSA, DSA, EC, OPENSSH, PRIVATE KEY,
//! ENCRYPTED PRIVATE KEY, ED25519, X25519, and any future variant
//! that follows the standard armoring. We match `[A-Z0-9 ]+` for
//! the tag because some tags (`OPENSSH PRIVATE KEY`,
//! `ENCRYPTED PRIVATE KEY`) include spaces.
//!
//! ## Why a separate module
//!
//! Keeping the multi-line regex isolated from the line-oriented
//! `Pattern` catalogue makes ordering explicit and lets the
//! filter run PEM stripping as a distinct pre-pass. The single-line
//! patterns then operate on a guaranteed-PEM-free string.

use regex::Regex;

/// Matches a `-----BEGIN ...-----` ... `-----END ...-----` block
/// across newlines. `(?s)` enables `.` to match `\n`.
pub(super) fn pem_block_regex() -> Regex {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----")
        .expect("PEM regex must compile")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rsa_private_key_block() {
        let input = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----";
        let re = pem_block_regex();
        let m = re.find(input).expect("must match RSA block");
        assert_eq!(m.start(), 0);
        assert_eq!(m.end(), input.len());
    }

    #[test]
    fn matches_openssh_private_key_block() {
        let input = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----";
        let re = pem_block_regex();
        assert!(re.is_match(input));
    }

    #[test]
    fn matches_encrypted_private_key_block() {
        let input = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6T...
-----END ENCRYPTED PRIVATE KEY-----";
        let re = pem_block_regex();
        assert!(re.is_match(input));
    }

    #[test]
    fn matches_certificate_block_too() {
        // CERTIFICATE blocks aren't strictly secret, but they often
        // appear next to keys and the model rarely needs the bytes.
        // We match-then-redact for consistency.
        let input = "\
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUTest
-----END CERTIFICATE-----";
        let re = pem_block_regex();
        assert!(re.is_match(input));
    }

    #[test]
    fn does_not_match_isolated_marker_lines() {
        // A stray `-----BEGIN X-----` without an `-----END X-----`
        // shouldn't match — we don't want to over-redact partial
        // scrollback (could happen if the user pastes a snippet).
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg...\n";
        let re = pem_block_regex();
        assert!(!re.is_match(input));
    }

    #[test]
    fn matches_two_blocks_independently() {
        let input = "\
-----BEGIN RSA PRIVATE KEY-----
AAA
-----END RSA PRIVATE KEY-----
some prose
-----BEGIN OPENSSH PRIVATE KEY-----
BBB
-----END OPENSSH PRIVATE KEY-----";
        let re = pem_block_regex();
        let count = re.find_iter(input).count();
        assert_eq!(count, 2);
    }
}
