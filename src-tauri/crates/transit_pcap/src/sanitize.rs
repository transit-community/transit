//! The T45 boundary: **every string that came off the wire is hostile.**
//!
//! `transit_files::sanitize` exists because a malicious device controls
//! the names in a directory listing. This module exists for a strictly
//! wider reason: a capture's strings are controlled by *anyone who can put
//! a frame on the monitored segment*. A guest-VLAN laptop, a printer, an
//! IoT thermostat — none of them need a Transit account, a device login,
//! or any relationship to the user at all. They just need to emit a
//! packet whose DNS QNAME, TLS SNI, HTTP `Host`/`User-Agent`, DHCP
//! hostname, LLDP port description, or syslog body says something the
//! attacker wants read.
//!
//! Those strings land in the packet list, in the analysis views, and — via
//! `query_capture` — in the model's context. So no wire-derived string
//! reaches any of those without passing through here first.
//!
//! Three properties, each earning its place:
//!
//! - **Control bytes are replaced, not passed through.** An ANSI CSI
//!   sequence in a DHCP hostname would repaint the packet list (the exact
//!   T12/T43 concern); a newline would let one field forge what looks like
//!   two rows of a table in the model's context, which is a framing
//!   escape. Tabs go the same way, for the same reason: our tabular
//!   answers are column-aligned text, and a tab inside a value shifts
//!   every column after it.
//! - **Length is capped per field.** A 4 KB `User-Agent` is legal on the
//!   wire and is a context-flooding primitive on its own.
//! - **Replacement is visible.** A stripped byte becomes `.` and a
//!   truncated value gains an explicit `…`, so a reader (human or model)
//!   can tell that the original was altered rather than silently
//!   believing a cleaned-up string is verbatim.
//!
//! What this module deliberately does *not* do is decide whether a value
//! is a secret. That is the dissector's job (never emit a known-credential
//! field) and the redaction filter's job (catch secret *shapes*). Three
//! layers, distinct responsibilities — see `docs/security/threat-model.md`
//! T45.

/// Per-field ceiling. Generous enough for a real URL, a full certificate
/// subject, or a long syslog line; far short of a context-flooding blob.
pub const MAX_FIELD_LEN: usize = 256;

/// Ceiling for the deliberately-longer fields (a reassembled request
/// line, a certificate subject DN). Still bounded.
pub const MAX_LONG_FIELD_LEN: usize = 1024;

/// Byte that replaces a stripped control character. Chosen over dropping
/// so the field's length still hints at what was there.
const STRIP_CHAR: char = '.';

/// Clean one wire-derived string for display and for the model.
///
/// Applies the control-byte rule and caps at [`MAX_FIELD_LEN`].
pub fn field(s: &str) -> String {
    clamp(strip_controls(s), MAX_FIELD_LEN)
}

/// Clean a wire-derived string that is legitimately longer than a normal
/// field (URLs, certificate subjects). Caps at [`MAX_LONG_FIELD_LEN`].
pub fn long_field(s: &str) -> String {
    clamp(strip_controls(s), MAX_LONG_FIELD_LEN)
}

/// Clean raw bytes that are *supposed* to be text (a DNS label, an SNI
/// host, an HTTP header value) but are attacker-chosen and may be
/// anything at all.
///
/// Invalid UTF-8 is replaced rather than refused: a hostname with one bad
/// byte is still worth showing as `exampl.e.com`, and refusing would let
/// an attacker hide a field from the analyst by corrupting one byte.
pub fn bytes(b: &[u8]) -> String {
    field(&String::from_utf8_lossy(b))
}

/// [`bytes`] with the longer ceiling.
pub fn long_bytes(b: &[u8]) -> String {
    long_field(&String::from_utf8_lossy(b))
}

/// Replace every control character (and the Unicode bidi/format
/// characters that can visually reorder a line) with [`STRIP_CHAR`].
///
/// `char::is_control` covers C0, DEL, and C1. The explicit list adds the
/// bidi overrides and invisible formatting characters, which are not
/// "control" by Unicode's definition but reorder or hide text just as
/// effectively — a `U+202E` in a filename-shaped field renders the rest
/// of the line backwards.
fn strip_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_bidi_or_invisible(c) {
                STRIP_CHAR
            } else {
                c
            }
        })
        .collect()
}

/// Format/bidi characters that are not `is_control` but alter how the
/// rest of a line renders.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        | '\u{FEFF}'              // BOM / zero-width no-break space
    )
}

/// Truncate to `max` **characters** (not bytes — slicing a `String` at a
/// byte index would panic mid-codepoint) and mark that we did.
fn clamp(mut s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let cut = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    s.truncate(cut);
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The T45 corpus: strings an attacker on the monitored segment can
    /// place in a field Transit will render and hand to the model.
    #[test]
    fn strips_escape_sequences_and_line_breaks() {
        let cases = [
            // A CSI erase-line in a DHCP hostname would repaint the row.
            // Only the ESC itself is a control character; the `[2K` that
            // follows is ordinary text and stays visible, which is what
            // we want — the analyst can see an escape was attempted.
            ("\u{1b}[2Kspoofed", ".[2Kspoofed"),
            // A newline forges an extra table row in the model's context.
            ("host\nrow2", "host.row2"),
            ("a\r\nb", "a..b"),
            // Tab breaks column alignment in a fixed-width answer.
            ("col1\tcol2", "col1.col2"),
            ("nul\0byte", "nul.byte"),
            ("bell\u{7}", "bell."),
            // RLO renders the remainder of the line right-to-left.
            ("safe\u{202E}gnp.exe", "safe.gnp.exe"),
            ("zero\u{200B}width", "zero.width"),
        ];
        for (input, expected) in cases {
            assert_eq!(field(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn passes_ordinary_wire_strings_through_unchanged() {
        for s in [
            "www.example.com",
            "api.internal.corp",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "GET /v1/sites?limit=100",
            "CN=vex1.lab.local,O=Transit,C=US",
            "ge-0/0/1.0",
            "конфиг.example.com",
            "xn--n3h.example",
        ] {
            assert_eq!(field(s), s, "expected {s:?} to survive verbatim");
        }
    }

    #[test]
    fn caps_length_and_marks_the_truncation() {
        // Long enough to overflow BOTH ceilings, so each is exercised.
        let long = "a".repeat(MAX_LONG_FIELD_LEN * 2);
        let out = field(&long);
        assert_eq!(out.chars().count(), MAX_FIELD_LEN + 1);
        assert!(out.ends_with('…'), "truncation must be visible");

        let out_long = long_field(&long);
        assert_eq!(out_long.chars().count(), MAX_LONG_FIELD_LEN + 1);
        assert!(out_long.ends_with('…'));

        // A value between the two ceilings is full-length as a long
        // field and clipped as a normal one.
        let mid = "b".repeat(MAX_FIELD_LEN * 2);
        assert_eq!(long_field(&mid), mid);
        assert_eq!(field(&mid).chars().count(), MAX_FIELD_LEN + 1);
    }

    #[test]
    fn exactly_at_the_cap_is_not_marked() {
        let exact = "b".repeat(MAX_FIELD_LEN);
        assert_eq!(field(&exact), exact);
    }

    /// Multi-byte characters must not be sliced mid-codepoint, and the
    /// cap counts characters rather than bytes.
    #[test]
    fn truncation_is_codepoint_safe() {
        let wide = "é".repeat(MAX_FIELD_LEN * 2);
        let out = field(&wide);
        assert_eq!(out.chars().count(), MAX_FIELD_LEN + 1);
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn invalid_utf8_is_replaced_not_refused() {
        // A hostname with one corrupt byte still renders.
        let raw = b"exampl\xffe.com";
        let out = bytes(raw);
        assert!(out.contains("exampl"), "prefix must survive: {out}");
        assert!(out.contains("e.com"), "suffix must survive: {out}");
    }

    /// The property that matters: whatever goes in, what comes out has no
    /// control characters and is bounded. Everything downstream — the
    /// table renderer, the `<capture>` framing, the model — depends on it.
    #[test]
    fn output_is_always_control_free_and_bounded() {
        proptest::proptest!(|(s: String)| {
            let out = field(&s);
            proptest::prop_assert!(!out.chars().any(char::is_control));
            proptest::prop_assert!(!out.chars().any(is_bidi_or_invisible));
            proptest::prop_assert!(out.chars().count() <= MAX_FIELD_LEN + 1);
        });
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        proptest::proptest!(|(b: Vec<u8>)| {
            let out = bytes(&b);
            proptest::prop_assert!(!out.chars().any(char::is_control));
        });
    }
}
