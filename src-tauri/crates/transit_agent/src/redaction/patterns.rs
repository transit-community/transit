//! Pattern catalogue for [`super::RedactionFilter`].
//!
//! Each `Pattern` is a regex + replacement template. The regex
//! captures the *prefix* (verb / key, group 1) and the *secret*
//! (group 2). The replacement is `${1}[REDACTED:<class>]`, so the
//! verb survives and only the credential payload is masked. Any
//! suffix (e.g. ` RO` after a community string, ` address 10.0.0.1`
//! after an isakmp key) is automatically preserved because regex
//! `replace_all` only rewrites matched bytes.
//!
//! Patterns are deliberately written so the *secret* group is
//! anchored to a non-secret terminator — usually whitespace, a
//! double-quote, or end-of-line. Otherwise a greedy `.+` would
//! swallow the rest of the line and produce `[REDACTED]` markers
//! that ate context the model needs (interface names, route status,
//! etc.). Tests in `mod.rs` confirm the surrounding syntax survives.
//!
//! ## Pattern ordering
//!
//! Vendor-specific patterns run first; generic catch-alls last. We
//! never *remove* a pattern when adding a more specific one — the
//! catch-all is defense in depth.
//!
//! ## Adding a pattern
//!
//! 1. Identify the credential class (vendor + kind, e.g. `nxos-tacacs-key`).
//! 2. Add a `Pattern::new(class, regex, ...)` entry below.
//! 3. Add a unit test in `mod.rs` covering the verb survival + the
//!    secret being absent from the redacted output.
//! 4. Add a proptest generator entry so random secrets of this shape
//!    are caught.
//! 5. Run the `transit-security-audit` skill on the diff.

use regex::Regex;

/// A single redaction rule. `re` MUST have a prefix capture (group 1)
/// and a secret capture (group 2); `Catalogue::redact_with` wires the
/// secret through the caller's replacer fn. Phase 5b moved the apply
/// loop into [`super::catalogue::Catalogue`] so `ConversationRedactor`
/// can hook the same patterns with a different replacer that emits
/// ordinal-suffixed markers.
#[derive(Debug, Clone)]
pub(super) struct Pattern {
    pub(super) re: Regex,
    /// e.g. `cisco-type-7`. Passed verbatim to the catalogue's
    /// replacer callback.
    pub(super) class: &'static str,
}

impl Pattern {
    fn new(class: &'static str, re: &str) -> Self {
        Self {
            re: Regex::new(re).expect("static redaction pattern must compile"),
            class,
        }
    }
}

/// Build the catalogue. Order matters: vendor-specific first,
/// generic catch-alls last.
///
/// **Re-clobber prevention.** The secret capture group is `S` (defined
/// below) — "one non-bracket non-space character followed by any non-
/// space chars". The `[^[\s]` lead means the group can never match a
/// `[REDACTED:...]` marker we already wrote, so a downstream pattern
/// can't rewrite an upstream redaction's class. The `redaction_is_idempotent`
/// test confirms this end-to-end.
///
/// **Optional level/type tokens go INSIDE the secret group, never the
/// preserved prefix.** Many carriers accept an optional encryption
/// level or algorithm token between the keyword and the secret
/// (`enable secret 5 …`, `enable secret sha512 …`, `neighbor X
/// password encrypted …`, `key-string 7 …`). These are written as
/// `(KEYWORD\s+)((?:LEVEL\s+)?S)` — the level is captured in group 2
/// (redacted away), NOT in group 1 (preserved). Two reasons: (1) it
/// keeps the filter idempotent — if the level were preserved, a second
/// pass over `KEYWORD LEVEL [REDACTED:…]` would let the regex backtrack
/// the optional level and re-capture the bare LEVEL token as a fresh
/// "secret" (double marker); absorbing it leaves nothing to re-grab;
/// (2) it defends against the level being mistaken for the secret when
/// the real secret is a hash the group would otherwise skip. This
/// mirrors how `cisco-type-7` has always absorbed its `7`. Patterns
/// whose level is *required* (not optional) — `aaa-key`'s `key \d+`,
/// `ntp-key`'s key-id, SNMPv3's algorithm — are already idempotent and
/// keep the token in the prefix.
pub(super) fn standard() -> Vec<Pattern> {
    // Secret capture: at least one non-`[` non-space char, then any
    // non-space chars. Stops a later pattern from chewing up a marker.
    const S: &str = r"[^\[\s]\S*";

    vec![
        // -----------------------------------------------------------
        // Junos local-account passwords.
        //
        // Quoted-form patterns deliberately do NOT consume the closing
        // `"` so the regex's match boundary excludes it; the trailing
        // quote is preserved in the output (regex `replace_all` only
        // rewrites matched bytes).
        // -----------------------------------------------------------
        Pattern::new(
            "junos-encrypted-password",
            r#"(encrypted-password\s+")([^"]+)"#,
        ),
        Pattern::new("junos-crypto-password", r#"(crypto-password\s+")([^"]+)"#),
        // -----------------------------------------------------------
        // Cisco IOS / IOS-XE local-account passwords + secrets.
        // `enable secret [<level>] <hash>` — level optional.
        // `username <name> password 7 <hex>` — type-7 reversible.
        // `username <name> secret [<level>] <hash>`.
        //
        // `cisco-type-7` runs before `cisco-username-password` so the
        // type-7 class label survives. The general username-password
        // pattern still uses the re-clobber-safe secret class so even
        // if it ran second on a type-7 line, it couldn't overwrite the
        // marker (the secret group rejects strings starting with `[`).
        // -----------------------------------------------------------
        // The optional token at the head of the secret group is either
        // Cisco's numeric type (`5` MD5-crypt, `8` PBKDF2, `9` scrypt)
        // OR an Arista / IOS `algorithm-type` algorithm NAME (`sha512`,
        // `sha256`, `md5`). Arista's `enable secret sha512 $6$…` puts
        // the algorithm where Cisco puts a level digit. Captured in
        // group 2 (redacted + idempotent), not the prefix: this stops
        // the secret group from grabbing the algorithm keyword and
        // leaving the real `$6$salt$digest` hash in cleartext.
        Pattern::new(
            "cisco-enable-secret",
            &format!(r"(enable\s+secret\s+)((?:(?:\d+|sha512|sha256|md5)\s+)?{S})"),
        ),
        // Cisco `enable password [level] <value>` — the weak,
        // deprecated cleartext/type-0 enable password. Distinct from
        // `enable secret`; without this the type-0 form (`enable
        // password 0 X` / `enable password X`) leaks entirely. Runs
        // AFTER cisco-type-7 so the `enable password 7 <hex>` form
        // keeps the cisco-type-7 label; the re-clobber-safe secret
        // class then refuses to rewrite that marker.
        // cisco-type-7 absorbs the level digit `7` into the matched
        // region so downstream username-password patterns can't grab
        // it as a 1-char "secret" via greedy backtracking. The class
        // label `cisco-type-7` encodes the level information that
        // would otherwise live in the surrounding text.
        Pattern::new("cisco-type-7", r"(password\s+)(7\s+[0-9A-Fa-f]+)"),
        Pattern::new(
            "cisco-enable-password",
            &format!(r"(enable\s+password\s+)((?:\d+\s+)?{S})"),
        ),
        // -----------------------------------------------------------
        // PPP authentication credentials on serial/dialer interfaces.
        //
        // `ppp chap password [0|7] <secret>`
        // `ppp pap sent-username <user> password [0|7] <secret>`
        //
        // Runs BEFORE the cisco-username-* rules: their unanchored
        // `username\s+…` would otherwise match inside `sent-username`
        // and claim the pap form under the wrong class. Runs AFTER
        // cisco-type-7, which absorbs the `password 7 <hex>` form
        // (and wins that class label, same contract as username
        // lines); this rule adds the cleartext / type-0 forms. The
        // sent-username itself is an identifier, not a secret — it
        // stays in the preserved prefix.
        // -----------------------------------------------------------
        Pattern::new(
            "ppp-password",
            &format!(
                r"(ppp\s+(?:chap\s+password|pap\s+sent-username\s+\S+\s+password)\s+)((?:\d+\s+)?{S})"
            ),
        ),
        // The `(?:.*?\s+)?` between the username and `password|secret`
        // tolerates the optional `privilege N`, `role ROLE`, `view V`,
        // and other modifier words Cisco IOS / NX-OS allow on a
        // `username` line (e.g. `username admin privilege 15 secret …`,
        // `username alice role network-admin password …`). The lazy
        // quantifier prefers the empty match so a no-modifiers line
        // still matches.
        //
        // The `(?:(?:\d+|sha512|sha256|md5)\s+)?` at the head of the
        // secret group absorbs Cisco's numeric type OR Arista's
        // algorithm name (`username admin … secret sha512 $6$…`) —
        // captured in group 2 (redacted + idempotent), not preserved
        // in the prefix. Without it the secret group grabs the
        // `sha512` keyword and the `$6$…` hash leaks.
        Pattern::new(
            "cisco-username-secret",
            &format!(
                r"(username\s+\S+\s+(?:.*?\s+)?secret\s+)((?:(?:\d+|sha512|sha256|md5)\s+)?{S})"
            ),
        ),
        // NX-OS uses `password 5 $hash` and `password 7 …` is handled
        // upstream by cisco-type-7 (which absorbs the `7 <hex>` block
        // into its match, leaving a `[REDACTED:cisco-type-7]` marker
        // here). The re-clobber-safe secret class then prevents this
        // pattern from rewriting that marker, so accepting any
        // numeric level is safe.
        Pattern::new(
            "cisco-username-password",
            &format!(r"(username\s+\S+\s+(?:.*?\s+)?password\s+)((?:\d+\s+)?{S})"),
        ),
        // -----------------------------------------------------------
        // SNMP community strings.
        //
        // Cisco / NX-OS / Arista all use `snmp-server community
        // <string> <suffix>`; suffix is RO/RW/group/use-acl/etc.
        // We capture only the community, not the suffix.
        //
        // Junos one-liner: `set snmp community "..."` or bare.
        // Junos display-block: `community "..." {` inside an `snmp { … }` stanza.
        // -----------------------------------------------------------
        Pattern::new(
            "snmp-community",
            &format!(r"(snmp-server\s+community\s+)({S})"),
        ),
        Pattern::new("snmp-community", r#"(set\s+snmp\s+community\s+")([^"]+)"#),
        Pattern::new(
            "snmp-community",
            &format!(r"(set\s+snmp\s+community\s+)({S})"),
        ),
        // Junos display-block format: an indented `community "X"`
        // line. Anchor at line-start with optional leading whitespace
        // so we don't false-match BGP community-list configs that
        // sit elsewhere on a line.
        Pattern::new("snmp-community", r#"(?m)^(\s*community\s+")([^"]+)"#),
        // `snmp-server host <host> [vrf X] [traps|informs] [version 1|2c|3]
        // <community>` — the trap/inform DESTINATION line carries the
        // community as an argument; the `snmp-server community` rule above
        // does not cover this carrier. The community is the token right
        // after the (optional) version; `{S}` stops at whitespace so a
        // trailing `udp-port <n>` survives. (v3 puts a username there — an
        // accepted over-redaction.)
        Pattern::new(
            "snmp-community",
            &format!(
                r"(snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:traps|informs))?(?:\s+version\s+(?:1|2c|3))?\s+)({S})"
            ),
        ),
        // -----------------------------------------------------------
        // SNMPv3 auth + priv passwords.
        //
        // Cisco/NX-OS: `snmp-server user X group v3 auth (md5|sha) PASSWORD priv (aes \d+|des) PASSWORD`.
        // Capture each independently; both can appear on one line.
        // -----------------------------------------------------------
        Pattern::new(
            "snmpv3-auth",
            &format!(r"(auth\s+(?:md5|sha|sha-256|sha-512|sha-384|sha-224)\s+)({S})"),
        ),
        // `aes-128` (NX-OS hyphenated form) and `aes 128` (Cisco
        // space-separated form) are both real wild syntaxes. Match
        // either by allowing a `-` or whitespace between `aes` and
        // the bit length.
        Pattern::new(
            "snmpv3-priv",
            &format!(r"(priv\s+)((?:aes-\d+|aes(?:\s+\d+)?|des|3des)\s+{S})"),
        ),
        Pattern::new("snmpv3-auth-password", &format!(r"(auth-password\s+)({S})")),
        Pattern::new("snmpv3-priv-password", &format!(r"(priv-password\s+)({S})")),
        // -----------------------------------------------------------
        // TACACS+ keys.
        //
        // Cisco classic: `tacacs-server key [<n>] <key>`.
        // Cisco named:   `tacacs server NAME` then `key ...` on next line — caught by the
        //                generic indented-key pattern below (`aaa-key` class).
        // Cisco group:   `aaa group server tacacs+ NAME` then `key ...` — same.
        // Junos:         `set system tacplus-server <ip> secret "..."`.
        // -----------------------------------------------------------
        Pattern::new(
            "tacacs-key",
            &format!(r"(tacacs-server\s+key\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new(
            "tacacs-key",
            r#"(set\s+system\s+tacplus-server\s+\S+\s+secret\s+")([^"]+)"#,
        ),
        Pattern::new(
            "tacacs-key",
            &format!(r"(set\s+system\s+tacplus-server\s+\S+\s+secret\s+)({S})"),
        ),
        // -----------------------------------------------------------
        // RADIUS keys.
        // -----------------------------------------------------------
        Pattern::new(
            "radius-key",
            &format!(r"(radius-server\s+key\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new(
            "radius-key",
            &format!(
                r"(radius-server\s+host\s+\S+(?:\s+(?:auth-port|acct-port)\s+\d+)*\s+key\s+)((?:\d+\s+)?{S})"
            ),
        ),
        Pattern::new(
            "radius-key",
            r#"(set\s+system\s+radius-server\s+\S+\s+secret\s+")([^"]+)"#,
        ),
        Pattern::new(
            "radius-key",
            &format!(r"(set\s+system\s+radius-server\s+\S+\s+secret\s+)({S})"),
        ),
        // Junos block-display format: indented `<ip-or-hostname> secret "…";`
        // inside a `radius-server { … }` or `tacplus-server { … }` stanza.
        // Tagged `aaa-key` since the line itself doesn't say
        // tacacs-vs-radius (mirroring the indented-`key` rule below).
        Pattern::new("aaa-key", r#"(?m)^(\s*\S+\s+secret\s+")([^"]+)"#),
        // -----------------------------------------------------------
        // Indented `key (\d+ )?<value>` line within a `tacacs server
        // NAME` / `radius server NAME` / `aaa group server` block. We
        // can't tell from a single line whether the surrounding
        // context is tacacs or radius, so we tag with a generic
        // `aaa-key` class. The single-line `tacacs-server key …` and
        // `radius-server key …` patterns above keep their specific
        // class labels.
        //
        // Two forms, deliberately NOT collapsed into `(?:\s+\d+)?`:
        // a `key chain NAME` / `key <id>` header inside a key-chain
        // block must survive un-redacted (the secret lives on the
        // indented `key-string` line below, which has its own rule).
        // `[ \t]+` instead of `\s+` so the match can never cross a
        // newline and eat the next line's first token as a "secret".
        //
        //   typed: `key <level> <secret>` — level digit(s) + a secret
        //          on the SAME line (a bare `key 1` header has no
        //          same-line payload, so it can't match);
        //   bare:  `key <secret>` anchored at end-of-line, secret
        //          must not start with a digit (else a `key 1`
        //          header's id would be taken for a secret). A bare
        //          all-numeric key is the one shape this sacrifices —
        //          syntactically indistinguishable from a key-chain
        //          header.
        //
        // Also matches `server-private <ip> key (<n>)? <value>`, the
        // IOS aaa group syntax for nested per-server keys.
        // -----------------------------------------------------------
        Pattern::new("aaa-key", &format!(r"(?m)^(\s*key[ \t]+\d+[ \t]+)({S})")),
        Pattern::new("aaa-key", r"(?m)^(\s*key[ \t]+)([^\[\s\d]\S*)[ \t]*\r?$"),
        Pattern::new(
            "aaa-key",
            &format!(r"(?m)^(\s*server-private\s+\S+\s+key\s+)((?:\d+\s+)?{S})"),
        ),
        // -----------------------------------------------------------
        // Routing-protocol authentication.
        //
        // BGP MD5: `neighbor X.X.X.X password <secret>` (Cisco/NX-OS).
        // OSPF auth: `ip ospf authentication-key <secret>`.
        // OSPF MD5:  `ip ospf message-digest-key <id> md5 <secret>`.
        // IS-IS auth: `isis authentication-key <secret>`.
        // IS-IS pwd:  `isis password <pwd> [level-1|level-2]`.
        // EIGRP:     `ip authentication key-string <secret>`.
        // Junos BGP: `set protocols bgp ... authentication-key "..."`.
        // -----------------------------------------------------------
        // The optional token at the head of the secret group is a
        // Cisco numeric type OR an IOS-XR keyword (`encrypted` /
        // `clear`): IOS-XR renders BGP MD5 as `neighbor X password
        // encrypted <type-7-hex>`. Captured in group 2 (redacted +
        // idempotent) so the secret group can't grab the word
        // `encrypted` and leave the (short, sub-catch-all) hash.
        Pattern::new(
            "bgp-md5",
            &format!(r"(neighbor\s+\S+\s+password\s+)((?:(?:\d+|encrypted|clear)\s+)?{S})"),
        ),
        // Standalone `password (encrypted|clear) <secret>` — IOS-XR
        // renders BGP-neighbor (and other) passwords hierarchically,
        // so the secret sits on its OWN indented line under `neighbor
        // <ip>` with `remote-as` etc. in between; the neighbor-anchored
        // bgp-md5 rule above (which needs `neighbor <ip> … password` on
        // one contiguous run) can't reach it. The `encrypted`/`clear`
        // keyword is specific enough to anchor on directly — and the
        // `password 7 <hex>` sibling form is already caught anywhere by
        // cisco-type-7. Runs AFTER bgp-md5 so the single-line neighbor
        // form keeps the `bgp-md5` label; the keyword is absorbed into
        // group 2 (redacted + idempotent). A type-7 hash here is short
        // (< the hex-blob floor), so without this it would leak.
        Pattern::new(
            "password-encrypted",
            &format!(r"(password\s+)((?:encrypted|clear)\s+{S})"),
        ),
        Pattern::new(
            "ospf-md5",
            &format!(r"(message-digest-key\s+\d+\s+md5\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new(
            "ospf-auth",
            &format!(r"(ip\s+ospf\s+authentication-key\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new(
            "isis-auth",
            &format!(r"(isis\s+authentication-key\s+)({S})"),
        ),
        Pattern::new("isis-auth", &format!(r"(isis\s+password\s+)({S})")),
        Pattern::new(
            "eigrp-key",
            &format!(r"(ip\s+authentication\s+key-string\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new("bgp-md5", r#"(authentication-key\s+")([^"]+)"#),
        // -----------------------------------------------------------
        // Key-chain `key-string` lines (EIGRP/OSPF/IS-IS key chains).
        //
        // `key chain NAME` → ` key <id>` → `  key-string [type] <secret>`.
        // The eigrp-key rule above requires an `ip authentication`
        // prefix, so it never sees this form. Line-anchored, optional
        // encryption-type digit absorbed into the SECRET group (so it
        // is redacted and the rule stays idempotent). `[ \t]+` so the
        // match can't cross a newline (same rationale as aaa-key).
        // -----------------------------------------------------------
        Pattern::new(
            "key-string",
            &format!(r"(?m)^(\s*key-string[ \t]+)((?:\d+[ \t]+)?{S})"),
        ),
        // -----------------------------------------------------------
        // IPSec / IKE pre-shared keys.
        //
        // Junos pattern runs first because the Cisco IKEv2 form is
        // syntactically a subset (`pre-shared-key SECRET`) and would
        // mis-match Junos's `pre-shared-key ascii-text "..."` if the
        // ordering were flipped.
        //
        // Junos:         `set security ike policy NAME pre-shared-key (ascii-text|hexadecimal) "<psk>"`.
        // Cisco classic: `crypto isakmp key <psk> (address ... | hostname ...)`.
        // Cisco IKEv2:   `pre-shared-key local|remote <psk>` inside a keyring.
        // PAN-OS:        `set network ike gateway NAME authentication pre-shared-key
        //                key <psk>` — the `key` qualifier. In `show config` the value
        //                is the `-AQ…` encrypted blob (also caught by panos-encrypted),
        //                but a cleartext PSK (as typed, or in a non-encrypted echo)
        //                only has this keyword rule in front of it.
        //
        // The qualifier (`ascii-text`/`hexadecimal`/`local`/`remote`/`key`) is what
        // distinguishes the vendors; the truly bare form (`pre-shared-key SECRET`
        // with NO qualifier) is left to the generic catch-alls, because a bare
        // `pre-shared-key\s+({S})` would mis-grab the qualifier itself as the secret
        // on the qualified forms above.
        // -----------------------------------------------------------
        Pattern::new(
            "ipsec-psk",
            r#"(pre-shared-key\s+(?:ascii-text|hexadecimal)\s+")([^"]+)"#,
        ),
        Pattern::new(
            "ipsec-psk",
            &format!(r"(crypto\s+isakmp\s+key\s+)((?:\d+\s+)?{S})"),
        ),
        Pattern::new(
            "ipsec-psk",
            // The optional `0`/`6` encryption-type token MUST be absorbed
            // into group 2 (the `(?:\d+\s+)?` convention shared by the
            // isakmp/enable/username rules). Without it the rule captured
            // the type indicator AS the secret and left the real PSK in
            // cleartext (`pre-shared-key remote 0 <psk>`).
            &format!(r"(pre-shared-key\s+(?:local|remote)\s+)((?:\d+\s+)?{S})"),
        ),
        // PAN-OS `pre-shared-key key <psk>`. Runs before the PAN-OS
        // panos-encrypted rule, so an `-AQ…` PSK here is labeled the
        // (more specific) `ipsec-psk` rather than the generic encrypted
        // class; a cleartext PSK is caught here and nowhere else.
        Pattern::new("ipsec-psk", &format!(r"(pre-shared-key\s+key\s+)({S})")),
        // Wireless / WPA pre-shared keys (IOS-XE embedded wireless,
        // Aruba, etc.): `wpa-psk ascii|hex [<type>] <psk>`. The optional
        // type digit rides into group 2 (same convention as the PSK
        // rules above), so the actual passphrase is redacted.
        Pattern::new(
            "wpa-psk",
            &format!(r"(wpa-psk\s+(?:ascii|hex)\s+)((?:\d+\s+)?{S})"),
        ),
        // -----------------------------------------------------------
        // NTP authentication keys.
        //
        // Cisco: `ntp authentication-key <id> md5 <key>`.
        // Junos: `set system ntp authentication-key <id> type md5 value "..."`.
        // -----------------------------------------------------------
        Pattern::new(
            "ntp-key",
            &format!(r"(ntp\s+authentication-key\s+\d+\s+(?:md5|sha1|sha256)\s+)({S})"),
        ),
        Pattern::new(
            "ntp-key",
            r#"(ntp\s+authentication-key\s+\d+\s+type\s+\S+\s+value\s+")([^"]+)"#,
        ),
        // -----------------------------------------------------------
        // Palo Alto PAN-OS.
        //
        // `phash <hash>` — the local-admin password hash under
        // `mgt-config { users { <name> { phash … } } }`. PAN-OS
        // renders it in crypt(3) form (`$5$…`, legacy `$1$…`) and
        // terminates the line with `;` in the config-display format.
        // The generic `password-hash` catch-all below would also
        // catch the `$5$…` body, but a `phash`-anchored rule wins the
        // vendor label and preserves the trailing `;` structure (the
        // secret class stops at `;` / whitespace). Its char class
        // excludes `[` so it can never rewrite a `[REDACTED:…]` marker.
        //
        // `-AQ…` — PAN-OS's proprietary AES-encrypted secret encoding
        // used for RADIUS/TACACS/LDAP-bind/IKE-PSK values. Always
        // begins with the literal `-AQ` header (base64 of the version
        // + IV) followed by base64. Anchored on a leading boundary
        // (`^`, whitespace, `>`, or `"`) so it can't bite mid-token;
        // 16+ trailing chars keeps benign flags from matching.
        // -----------------------------------------------------------
        Pattern::new("panos-phash", r"(phash\s+)([^\[\s;]+)"),
        Pattern::new("panos-encrypted", r#"(^|[\s>"])(-AQ[A-Za-z0-9+/=]{16,})"#),
        // -----------------------------------------------------------
        // AWS keys.
        //
        // Access-key IDs follow `AKIA[0-9A-Z]{16}`. Secret keys are
        // 40-char base64ish; we capture the assignment form.
        // -----------------------------------------------------------
        // Real AWS credentials files use lowercase `aws_access_key_id`
        // by spec; uppercase env-var assignments are also common. The
        // assignment patterns are case-insensitive on the variable
        // name; the AKIA prefix itself is uppercase by AWS spec.
        Pattern::new(
            "aws-access-key",
            r"(?i)(AWS_ACCESS_KEY_ID\s*[:=]\s*)(AKIA[0-9A-Z]{16})",
        ),
        Pattern::new("aws-access-key", r"(\b)(AKIA[0-9A-Z]{16})\b"),
        Pattern::new(
            "aws-secret",
            r"(?i)(AWS_SECRET_ACCESS_KEY\s*[:=]\s*)([A-Za-z0-9/+=]{40})",
        ),
        // -----------------------------------------------------------
        // Cloud / SaaS provider API tokens.
        //
        // Modern secrets an engineer may paste into a session (webhook
        // config, on-box automation, cloud onboarding). Each has a
        // distinctive prefix, so we anchor on it — same idea as the AWS
        // `AKIA` rule above. Group 1 is a zero-width `\b` (so a run in
        // the middle of a longer identifier never matches); group 2 is
        // the token. Length floors keep benign identifiers out; over-
        // redacting a look-alike is an accepted cost. All bodies exclude
        // `[`, so a `[REDACTED:…]` marker is never re-matched.
        // -----------------------------------------------------------
        // GitHub: PAT (ghp_), OAuth (gho_), app-server (ghs_), refresh
        // (ghr_), user-to-server (ghu_).
        Pattern::new("github-token", r"(\b)(gh[posru]_[A-Za-z0-9]{20,})"),
        // Stripe secret (sk_) + restricted (rk_) live/test keys. The
        // publishable `pk_` is not a secret and is intentionally omitted.
        Pattern::new(
            "stripe-key",
            r"(\b)((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})",
        ),
        // Slack bot/user/app/refresh/legacy tokens (xoxb/p/a/r/s/e-).
        Pattern::new("slack-token", r"(\b)(xox[baprse]-[0-9A-Za-z-]{10,})"),
        // OpenAI keys. Two forms:
        //  - Modern project keys `sk-proj-…` whose body DOES contain `_`
        //    and `-`. Scoped to the `sk-proj-` prefix + a high length
        //    floor (40) so the widened class can't grab a hyphenated
        //    hostname. (The old single rule's base62-only body left these
        //    keys — which start `sk-proj-` and embed `_`/`-` — unredacted.)
        //  - Legacy bare `sk-` keys: base62 body with no `-`/`_`, so a
        //    hyphenated hostname (`sk-us-west-…`) still can't match; 20+.
        Pattern::new("openai-key", r"(\b)(sk-proj-[A-Za-z0-9_-]{20,})"),
        Pattern::new("openai-key", r"(\b)(sk-[A-Za-z0-9]{20,})"),
        // GitLab personal / project access tokens.
        Pattern::new("gitlab-token", r"(\b)(glpat-[0-9A-Za-z_-]{20,})"),
        // Google API keys.
        Pattern::new("google-api-key", r"(\b)(AIza[0-9A-Za-z_-]{35})"),
        // -----------------------------------------------------------
        // JWTs.
        //
        // Three base64url segments separated by `.`. Header alg is
        // commonly `eyJ...`. We require the leading `eyJ` so plain
        // sentences with periods don't match.
        // -----------------------------------------------------------
        Pattern::new(
            "jwt",
            r"(\b)(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        ),
        // -----------------------------------------------------------
        // Bearer tokens (Authorization header).
        // -----------------------------------------------------------
        Pattern::new("bearer-token", r"(?i)(bearer\s+)([A-Za-z0-9._\-/+=]{8,})"),
        // HTTP Basic auth: `Authorization: Basic <base64(user:pass)>`.
        // Anchored on the `authorization:` header so the common English
        // word "basic" (e.g. "basic configuration") can never false-match.
        Pattern::new(
            "basic-auth",
            r"(?i)(authorization:\s*basic\s+)([A-Za-z0-9+/=]{8,})",
        ),
        // Credentials in connection-string / URL userinfo:
        // `scheme://user:PASSWORD@host`. Ubiquitous in `.env` files, DB
        // connection strings, and `docker inspect` output on the
        // unrestricted Linux vendor. Group 3 is the literal `@`, preserved
        // (via the catalogue's suffix support) so the host survives:
        // `postgres://u:[REDACTED:url-password]@host/db`. The password
        // class excludes `@` (stops at the userinfo boundary) and `[`
        // (marker-safe). A password with a literal *unencoded* `@` is only
        // partially redacted — such URLs are malformed; well-formed
        // (percent-encoded) URLs redact fully.
        Pattern::new(
            "url-password",
            r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)([^@\s/\[]+)(@)",
        ),
        // -----------------------------------------------------------
        // Generic English: "password is X", "password: X".
        // -----------------------------------------------------------
        Pattern::new("generic-password", &format!(r"(?i)(password\s+is\s+)({S})")),
        Pattern::new(
            "generic-password",
            &format!(r"(?i)(password\s*[:=]\s*)({S})"),
        ),
        // -----------------------------------------------------------
        // Line / standalone cleartext passwords + VTP.
        //
        // Runs AFTER every specific carrier rule (enable / username /
        // neighbor / ppp — all earlier), so those keep their labels;
        // this catches the leftover config forms they don't:
        //   `password 0 <cleartext>` — explicit type-0 (e.g. `line con`
        //     / `line vty`). `password 7 <hex>` is cisco-type-7 and
        //     `password 5|8|9 $hash` is the MCF catch-all, so the `0`
        //     here is a required literal (not `\d+`), which also keeps
        //     the rule idempotent — nothing to backtrack.
        //   indented bare `password <cleartext>` at EOL — the implicit
        //     type-0 line password. Line-anchored + a single non-digit,
        //     non-`[` token (mirrors the aaa-key bare rule) to bound
        //     false positives and stay marker-safe; a leading digit is
        //     excluded so `password 0|7 …` route to their own rules.
        //   `vtp password <cleartext>` — VTP domain password.
        // -----------------------------------------------------------
        Pattern::new("cleartext-password", &format!(r"(password\s+0\s+)({S})")),
        Pattern::new(
            "cleartext-password",
            r"(?m)^(\s*password[ \t]+)([^\[\s\d]\S*)[ \t]*\r?$",
        ),
        Pattern::new("vtp-password", &format!(r"(vtp\s+password\s+)({S})")),
        // -----------------------------------------------------------
        // Modular-crypt-format (MCF) password hashes — structured
        // catch-all with NO required carrier keyword. This is the
        // cross-vendor safety net for any credential hash whose
        // carrier verb we don't explicitly recognize:
        //
        //   $1$  MD5-crypt        $5$  SHA-256-crypt   $6$  SHA-512-crypt
        //   $2a$/$2b$/$2y$ bcrypt $8$  Cisco PBKDF2    $9$  Cisco scrypt
        //   $9$  Juniper Type-9 (reversible!)          $y$  yescrypt
        //   $argon2id$ …          $sha1$ …
        //
        // Covers PAN-OS `phash $5$…` (belt-and-suspenders with the
        // vendor rule above), Juniper `$9$…` secrets on carriers we
        // don't name (interface/PPPoE passwords), Linux `/etc/shadow`
        // `root:$6$…:` lines, and Cisco/Arista `$8$/$9$` hashes echoed
        // by an unrecognized verb. Runs AFTER every keyword-anchored
        // rule (so they win their specific labels and re-clobber the
        // `$id$…` before it reaches here) and BEFORE the hex/base64
        // catch-alls (so `password-hash` wins over the generic runs).
        //
        // Group 1 preserves the `$id$` algorithm prefix — a public
        // identifier, not a secret, and useful signal for the agent
        // ("this is a reversible Juniper $9$" / "a SHA-512 crypt") —
        // and group 2 redacts the salt + digest. The body class
        // `[A-Za-z0-9./=$+-]` spans every crypt/bcrypt/`rounds=`/`$`
        // -delimited field and stops at whitespace, `;`, `"`, `,`, or
        // `:` (so a shadow line's trailing `:19000:…` survives). It
        // excludes `[` so a `[REDACTED:…]` marker can never re-match —
        // idempotency holds (the id needs a body of `{6,}` after
        // `$id$`, and a written marker starts with `[`). The `{6,}`
        // floor rejects trivial `$a$bc` noise; every real hash body is
        // ≥ 20 chars, so no false negative. Over-redaction of a
        // `$`-shaped non-secret is an accepted cost (see module docs).
        // -----------------------------------------------------------
        // Argon2 (`$argon2i$` / `$argon2d$` / `$argon2id$`) puts `,`
        // inside its parameter list (`m=…,t=…,p=…`), which the general
        // MCF body class below stops at — leaving the salt+digest after
        // the first comma exposed. A dedicated rule whose body admits
        // `,` redacts the whole string; runs BEFORE the general rule so
        // it wins. Same `password-hash` class.
        Pattern::new(
            "password-hash",
            r"(\$argon2(?:id|i|d)\$)([A-Za-z0-9$=,./+-]{6,})",
        ),
        Pattern::new(
            "password-hash",
            r"(\$[A-Za-z0-9]{1,9}\$)([A-Za-z0-9./=$+-]{6,})",
        ),
        // -----------------------------------------------------------
        // High-entropy catch-alls — ALWAYS LAST, so every keyword-
        // anchored class above wins the class label (and the ordinal
        // naming in `ConversationRedactor`) before these fire. They
        // exist for secrets with NO recognized carrier keyword — a
        // pasted token, a hash echoed by an unknown vendor verb.
        //
        // Boundary handling: the regex crate has no lookaround, so
        // "standalone token" is enforced by capturing one preceding
        // non-token character (or `^`) as the preserved prefix —
        // a run embedded mid-word (preceded by another token char)
        // never matches, and greedy matching stops at the first
        // non-token char on the right. `[` is a valid boundary, but
        // no `[REDACTED:…]` marker contains a 40+ char unbroken run
        // (`:`/`-`/`#` split them), so the markers themselves can
        // never re-match — idempotency holds (pinned by the
        // `redact_is_idempotent_on_arbitrary_text` proptest).
        //
        // Thresholds:
        //   hex 40+    — SHA-1 length; fingerprints / hashes / hex
        //                PSKs. Over-redacting a cert fingerprint is
        //                an accepted cost.
        //   base64 64+ — body chars (padding `=` excluded from the
        //                body class, consumed as an up-to-2 suffix).
        //                40 was the first cut, but the prompt-
        //                injection corpus deliberately pins a 62-
        //                char base64 injection payload as SURVIVING
        //                redaction (the redactor strips secrets, not
        //                injection text, and must never decode
        //                base64) — so the floor sits above that at
        //                the next power of two.
        //
        // hex-blob runs first: pure-hex runs are a subset of the
        // base64 alphabet, so reversing the order would dead-letter
        // the hex class. Its boundary excludes the FULL base64
        // alphabet (not just hex) so it can't bite a 40-hex window
        // out of the middle of a longer mixed-base64 word.
        // -----------------------------------------------------------
        // -----------------------------------------------------------
        // JSON-value secrets (v4.0.0). API/UniFi responses are JSON, not
        // CLI text, so `read_scrollback` over an API session can carry a
        // WLAN PSK / device SSH password / RADIUS secret in a
        // `"key": "value"` field. Match a credential-named key, redact the
        // VALUE, preserve the key + the closing `"` (not consumed, like the
        // quoted CLI patterns above).
        //
        // Three hardenings over the naive form (adversarial review
        // 2026-07-30 — each was an empirically-confirmed leak):
        //   * `(?i)` — UniFi/JSON keys vary in case (`PSK`, `X_Passphrase`,
        //     `Password`); a case-sensitive alternation silently leaks them.
        //   * affix-tolerant key `"[a-z0-9_]*<core>[a-z0-9_]*"` — an exact
        //     allow-list misses real fields (`x_ssh_password` — the SSH
        //     password UniFi pushes to every adopted AP — `wpa_passphrase`,
        //     `x_ca_key`, `sharedSecret`, `presharedKey`, …). We match any
        //     key whose NAME contains a credential core, not one spelling.
        //   * escape-aware value `(?:[^"\\\[]|\\.)(?:[^"\\]|\\.)*` — the
        //     naive `[^"]*` stopped at a JSON-escaped `\"` INSIDE the value
        //     and leaked the tail of a PSK (a `"` is legal in an 8–63-char
        //     passphrase). This consumes `\"` and stops only at the real
        //     closing quote.
        // The value's first char still excludes `"`/`\`/`[`, so a written
        // `[REDACTED:…]` marker can't re-match — idempotent (mirrors the `S`
        // lead convention). Runs BEFORE the generic hex/base64 floor.
        //
        // Deliberate over-redaction (SAFE direction). Because the key match
        // is affix-tolerant, `api-json-key-token` also redacts benign
        // `"key":"<section>"` labels (UniFi `/rest/setting` section names
        // like `mgmt`) and non-secret `"publicKey"` values. Leaking a secret
        // is far worse than blinding the agent to a section label, and this
        // catches any `*key*`/`*secret*`/`*token*` field — present or future
        // — without enumerating every UniFi spelling. If preserving section
        // labels ever matters, carve an exact `"key"` value shape; do NOT
        // drop the affix tolerance. See docs/security/threat-model.md
        // T_API_READ_REDACTION.
        // -----------------------------------------------------------
        Pattern::new(
            "api-json-wifi-secret",
            r#"(?i)("[a-z0-9_]*(?:passphrase|password|psk|wpa[_-]?psk)[a-z0-9_]*"\s*:\s*")((?:[^"\\\[]|\\.)(?:[^"\\]|\\.)*)"#,
        ),
        Pattern::new(
            "api-json-radius-secret",
            r#"(?i)("[a-z0-9_]*(?:radius[_-]?secret|auth[_-]?key|community|shared[_-]?secret|preshared[_-]?key)[a-z0-9_]*"\s*:\s*")((?:[^"\\\[]|\\.)(?:[^"\\]|\\.)*)"#,
        ),
        Pattern::new(
            "api-json-key-token",
            r#"(?i)("[a-z0-9_]*(?:secret|token|key)[a-z0-9_]*"\s*:\s*")((?:[^"\\\[]|\\.)(?:[^"\\]|\\.)*)"#,
        ),
        // A JSON `"session"`-family field (FortiManager/Analyzer login return
        // `"session":"<long token>"`; ACI/vManage cookies are Set-Cookie
        // headers, which are NOT recorded to the ring, so only the body case
        // matters). `session` lacks a secret/token/key substring, so the key
        // pattern above misses it. VALUE-LENGTH-GATED to 16+ token chars so a
        // real session TOKEN is redacted while short session METADATA
        // (`"sessionType":"web"`, `"session_count":5`) — which the agent
        // legitimately investigates — is left visible. The value's first char
        // is a token char, never `[`, so a `[REDACTED:…]` marker can't re-match
        // (idempotent). See threat-model T38 / T40.
        Pattern::new(
            "api-json-session-token",
            r#"(?i)("[a-z0-9_]*session[a-z0-9_]*"\s*:\s*")([A-Za-z0-9._\-/+=]{16,})"#,
        ),
        Pattern::new("hex-blob", r"(^|[^A-Za-z0-9+/])([0-9A-Fa-f]{40,})"),
        Pattern::new(
            "base64-blob",
            r"(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{64,}={0,2})",
        ),
    ]
}
