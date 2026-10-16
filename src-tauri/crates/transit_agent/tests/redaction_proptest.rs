//! Property tests: random secrets in known carrier syntaxes must
//! be redacted 100% of the time.
//!
//! Each strategy below builds a synthetic device config line by
//! splicing a random secret into a real vendor syntax. The
//! invariant is uniform: the filter MUST remove the secret bytes
//! and produce a `[REDACTED:` marker.
//!
//! Why this lives next to the corpus tests instead of replacing
//! them: the corpus pins the *class label* (so a refactor that
//! demotes `cisco-type-7` → generic `cisco-username-password`
//! breaks loud), while the proptest pins the *contract* (no random
//! secret of this shape escapes). Both layers shake out different
//! regressions.

use proptest::prelude::*;
use transit_agent::RedactionFilter;

/// Secret-shaped strings: 6–48 ASCII non-space chars excluding
/// `[` (which the catalogue's secret class explicitly rejects to
/// prevent re-clobbering of redaction markers — generating those
/// here would make the test self-referential and useless).
fn secret() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[A-Za-z0-9!@#%^&*()_=/.+\-]{6,48}")
        .expect("static secret regex must compile")
}

/// Hex-only secrets for type-7-style patterns.
fn hex_secret() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[0-9A-Fa-f]{8,40}").unwrap()
}

/// Quoted-form secrets (no embedded `"`, otherwise the carrier
/// syntax would be malformed).
fn quoted_secret() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[A-Za-z0-9!@#%^&*()_=/.+\-]{6,48}").unwrap()
}

/// crypt(3) / modular-crypt-format hash components: `(scheme_id,
/// salt, digest)`. The salt is 4–16 and the digest 20–60 chars of the
/// crypt base64 alphabet (`.` and `/` included) — the shapes real
/// `$1$`/`$5$`/`$6$`/`$8$`/`$9$`/bcrypt hashes take.
fn crypt_hash_parts() -> impl Strategy<Value = (String, String, String)> {
    (
        prop::sample::select(vec!["1", "5", "6", "8", "9", "2a", "2b", "2y", "y"]),
        prop::string::string_regex(r"[A-Za-z0-9./]{4,16}").unwrap(),
        prop::string::string_regex(r"[A-Za-z0-9./]{20,60}").unwrap(),
    )
        .prop_map(|(id, salt, digest)| (id.to_string(), salt, digest))
}

/// SNMPv3 / crypt algorithm keyword (Arista `secret <algo>` form).
fn algo_keyword() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["sha512", "sha256", "md5"]).prop_map(|s| s.to_string())
}

/// v4.0.0 — credential-named JSON keys the three `api-json-*` patterns
/// must catch. Spans casing (HIGH-1a) and affix / spelling variants
/// (HIGH-1b): each entry is a real UniFi field or a case/affix mutation
/// of one. The invariant under test is that the VALUE of any of these is
/// always redacted, regardless of spelling.
fn credential_json_key() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        // wifi / device-password family
        "x_passphrase",
        "X_Passphrase",
        "xPassphrase",
        "wpa_passphrase",
        "password",
        "Password",
        "x_ssh_password",
        "PSK",
        "psk",
        "wpa_psk",
        // radius / snmp family
        "radius_secret",
        "x_authkey",
        "authkey",
        "snmp_community",
        "community",
        "sharedSecret",
        "presharedKey",
        // key / token family
        "apiKey",
        "api_key",
        "x_ca_key",
        "x_iapp_key",
        "token",
        "clientSecret",
        "x_secret",
        "access_key",
    ])
    .prop_map(|s| s.to_string())
}

/// A JSON string-value fragment with NO `"`, `\`, or `[` — safe to splice
/// between quotes and unambiguous for the "did this survive?" assertion.
fn json_value_frag() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[A-Za-z0-9!@#%^&*()_=/.+\-]{6,32}").unwrap()
}

fn assert_redacted(line: &str, secret: &str) {
    let f = RedactionFilter::standard();
    let out = f.redact(line);
    prop_assert_no_secret(line, secret, &out);
}

#[track_caller]
fn prop_assert_no_secret(line: &str, secret: &str, out: &str) {
    assert!(
        !out.contains(secret),
        "secret survived\ninput:  {line}\noutput: {out}\nsecret: {secret}"
    );
    assert!(
        out.contains("[REDACTED:"),
        "no marker emitted\ninput:  {line}\noutput: {out}"
    );
}

proptest! {
    // -----------------------------------------------------------------
    // Junos.
    // -----------------------------------------------------------------

    #[test]
    fn junos_encrypted_password_always_redacted(s in quoted_secret()) {
        let line = format!(r#"set system root-authentication encrypted-password "{s}""#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_set_snmp_community_always_redacted(s in quoted_secret()) {
        let line = format!(r#"set snmp community "{s}" authorization read-only"#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_block_community_always_redacted(s in quoted_secret()) {
        let line = format!(r#"    community "{s}" {{"#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_tacplus_secret_always_redacted(s in quoted_secret()) {
        let line = format!(r#"set system tacplus-server 10.0.0.1 secret "{s}""#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_radius_secret_always_redacted(s in quoted_secret()) {
        let line = format!(r#"set system radius-server 10.0.0.1 secret "{s}""#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_ike_psk_always_redacted(s in quoted_secret()) {
        let line = format!(r#"set security ike policy IKE-POL pre-shared-key ascii-text "{s}""#);
        assert_redacted(&line, &s);
    }

    #[test]
    fn junos_ntp_key_always_redacted(s in quoted_secret()) {
        let line = format!(
            r#"set system ntp authentication-key 1 type md5 value "{s}""#
        );
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // Cisco IOS / IOS-XE.
    // -----------------------------------------------------------------

    #[test]
    fn cisco_enable_secret_always_redacted(s in secret()) {
        let line = format!("enable secret 5 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_username_secret_always_redacted(s in secret()) {
        let line = format!("username admin secret 5 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_username_password_always_redacted(s in secret()) {
        let line = format!("username admin password 0 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_username_with_modifiers_always_redacted(s in secret()) {
        // Real-world: `username NAME privilege N secret …`
        let line = format!("username admin privilege 15 secret 5 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_type_7_always_redacted(s in hex_secret()) {
        let line = format!("username admin password 7 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_snmp_community_always_redacted(s in secret()) {
        let line = format!("snmp-server community {s} RO");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_tacacs_server_key_always_redacted(s in secret()) {
        let line = format!("tacacs-server key 7 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_radius_server_key_always_redacted(s in secret()) {
        let line = format!("radius-server key {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_radius_host_key_always_redacted(s in secret()) {
        let line = format!(
            "radius-server host 10.0.0.1 auth-port 1812 acct-port 1813 key {s}"
        );
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_indented_key_always_redacted(s in secret()) {
        let line = format!(" key 7 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn cisco_server_private_key_always_redacted(s in secret()) {
        let line = format!(" server-private 10.0.0.1 key 7 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn bgp_neighbor_password_always_redacted(s in secret()) {
        let line = format!("neighbor 10.0.0.1 password {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ospf_authentication_key_always_redacted(s in secret()) {
        let line = format!("ip ospf authentication-key {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ospf_message_digest_key_always_redacted(s in secret()) {
        let line = format!("ip ospf message-digest-key 1 md5 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn isis_password_always_redacted(s in secret()) {
        let line = format!("isis password {s} level-2");
        assert_redacted(&line, &s);
    }

    #[test]
    fn eigrp_key_always_redacted(s in secret()) {
        let line = format!("ip authentication key-string {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn key_chain_key_string_always_redacted(s in secret()) {
        // Indented `key-string` inside a `key chain` block — no
        // `ip authentication` prefix.
        let line = format!("  key-string {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ppp_chap_password_always_redacted(s in secret()) {
        let line = format!(" ppp chap password 0 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ppp_pap_sent_username_password_always_redacted(s in secret()) {
        let line = format!(" ppp pap sent-username Edge-R1 password {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn isakmp_psk_always_redacted(s in secret()) {
        let line = format!("crypto isakmp key {s} address 1.2.3.4");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ikev2_local_psk_always_redacted(s in secret()) {
        let line = format!("  pre-shared-key local {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn ntp_md5_key_always_redacted(s in secret()) {
        let line = format!("ntp authentication-key 1 md5 {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // SNMPv3.
    // -----------------------------------------------------------------

    #[test]
    fn snmpv3_auth_always_redacted(s in secret()) {
        let line = format!("snmp-server user alice grp v3 auth sha {s} priv aes 128 OtherSecret");
        assert_redacted(&line, &s);
    }

    #[test]
    fn snmpv3_priv_aes_hyphenated_always_redacted(s in secret()) {
        // NX-OS hyphenated form: `aes-128`.
        let line = format!("snmp-server user alice grp auth sha AuthSecret priv aes-128 {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // Generic.
    // -----------------------------------------------------------------

    #[test]
    fn generic_password_phrase_always_redacted(s in secret()) {
        let line = format!("the password is {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn generic_password_assignment_always_redacted(s in secret()) {
        let line = format!("password={s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn bearer_token_always_redacted(
        s in prop::string::string_regex(r"[A-Za-z0-9._\-/+=]{16,64}").unwrap()
    ) {
        let line = format!("Authorization: Bearer {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // Modular-crypt-format hashes — any `$id$salt$digest`, on a named
    // carrier or bare, has its salt + digest removed.
    // -----------------------------------------------------------------

    #[test]
    fn panos_phash_always_redacted((id, salt, digest) in crypt_hash_parts()) {
        let line = format!("        phash ${id}${salt}${digest};");
        assert_redacted(&line, &digest);
    }

    #[test]
    fn bare_crypt_hash_always_redacted((id, salt, digest) in crypt_hash_parts()) {
        // No recognized carrier keyword anywhere — the MCF catch-all
        // must still strip the salt + digest.
        let line = format!("observed hash ${id}${salt}${digest} on device");
        assert_redacted(&line, &digest);
    }

    #[test]
    fn linux_shadow_hash_always_redacted((id, salt, digest) in crypt_hash_parts()) {
        let line = format!("svcacct:${id}${salt}${digest}:19000:0:99999:7:::");
        assert_redacted(&line, &digest);
    }

    #[test]
    fn juniper_type9_always_redacted(
        body in prop::string::string_regex(r"[A-Za-z0-9./]{8,48}").unwrap()
    ) {
        let line = format!(r#"set interfaces ge-0/0/0 unit 0 pppoe-options password "$9${body}""#);
        assert_redacted(&line, &body);
    }

    // -----------------------------------------------------------------
    // Arista EOS — algorithm-name typed secrets.
    // -----------------------------------------------------------------

    #[test]
    fn arista_enable_secret_algo_always_redacted(
        algo in algo_keyword(),
        (id, salt, digest) in crypt_hash_parts(),
    ) {
        let line = format!("enable secret {algo} ${id}${salt}${digest}");
        assert_redacted(&line, &digest);
    }

    #[test]
    fn arista_username_secret_algo_always_redacted(
        algo in algo_keyword(),
        (id, salt, digest) in crypt_hash_parts(),
    ) {
        let line = format!("username admin privilege 15 secret {algo} ${id}${salt}${digest}");
        assert_redacted(&line, &digest);
    }

    // -----------------------------------------------------------------
    // Cisco `enable password` + IOS-XR BGP `password encrypted`.
    // -----------------------------------------------------------------

    #[test]
    fn cisco_enable_password_always_redacted(s in secret()) {
        let line = format!("enable password 0 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn iosxr_bgp_password_encrypted_always_redacted(s in hex_secret()) {
        let line = format!(" neighbor 10.0.0.1 password encrypted {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn standalone_password_encrypted_always_redacted(s in hex_secret()) {
        // IOS-XR hierarchical form: `password encrypted <hex>` on its
        // own indented line, no `neighbor <ip>` prefix — caught by the
        // standalone `password-encrypted` rule, not neighbor-anchored
        // bgp-md5.
        let line = format!("  password encrypted {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn standalone_password_clear_always_redacted(s in secret()) {
        let line = format!("  password clear {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // PAN-OS proprietary `-AQ…` encrypted secret.
    // -----------------------------------------------------------------

    #[test]
    fn panos_encrypted_always_redacted(
        b64 in prop::string::string_regex(r"[A-Za-z0-9+/]{16,48}={0,2}").unwrap()
    ) {
        let line = format!("set shared server-profile radius grp secret -AQ=={b64}");
        assert_redacted(&line, &b64);
    }

    #[test]
    fn panos_ike_pre_shared_key_always_redacted(s in secret()) {
        // PAN-OS `pre-shared-key key <psk>` — cleartext form (the
        // `-AQ…` encrypted form is exercised by panos_encrypted above).
        let line =
            format!("set network ike gateway GW authentication pre-shared-key key {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // Cloud / SaaS provider API tokens (v2.2.3).
    // -----------------------------------------------------------------

    #[test]
    fn github_token_always_redacted(b in prop::string::string_regex(r"[A-Za-z0-9]{30,40}").unwrap()) {
        let tok = format!("ghp_{b}");
        assert_redacted(&format!("gh token {tok}"), &tok);
    }

    #[test]
    fn stripe_key_always_redacted(b in prop::string::string_regex(r"[0-9A-Za-z]{20,30}").unwrap()) {
        let tok = format!("sk_live_{b}");
        assert_redacted(&format!("STRIPE_SECRET_KEY={tok}"), &tok);
    }

    #[test]
    fn slack_token_always_redacted(b in prop::string::string_regex(r"[0-9A-Za-z][0-9A-Za-z-]{14,29}").unwrap()) {
        let tok = format!("xoxb-{b}");
        assert_redacted(&format!("slack {tok}"), &tok);
    }

    #[test]
    fn openai_key_always_redacted(b in prop::string::string_regex(r"[A-Za-z0-9]{24,40}").unwrap()) {
        let tok = format!("sk-{b}");
        assert_redacted(&format!("OPENAI_API_KEY={tok}"), &tok);
    }

    #[test]
    fn gitlab_token_always_redacted(b in prop::string::string_regex(r"[0-9A-Za-z][0-9A-Za-z_-]{20,29}").unwrap()) {
        let tok = format!("glpat-{b}");
        assert_redacted(&format!("gitlab {tok}"), &tok);
    }

    // -----------------------------------------------------------------
    // Line / standalone cleartext passwords + VTP (v2.2.3).
    // -----------------------------------------------------------------

    #[test]
    fn cleartext_password_type0_always_redacted(s in secret()) {
        let line = format!(" password 0 {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn bare_line_password_always_redacted(
        s in prop::string::string_regex(r"[A-Za-z][A-Za-z0-9!@#%^&*()_=/.+-]{5,40}").unwrap()
    ) {
        // Indented bare `password <cleartext>`; value starts with a
        // letter (the rule excludes a leading digit so `password 0|7 …`
        // route to their own rules).
        let line = format!("  password {s}");
        assert_redacted(&line, &s);
    }

    #[test]
    fn vtp_password_always_redacted(s in secret()) {
        let line = format!("vtp password {s}");
        assert_redacted(&line, &s);
    }

    // -----------------------------------------------------------------
    // v4.0.0 — JSON credential values in API (UniFi) responses.
    // -----------------------------------------------------------------

    #[test]
    fn api_json_credential_value_always_redacted(
        key in credential_json_key(),
        val in json_value_frag(),
    ) {
        // Any credential-named key (any casing / affix) → value gone.
        let body = format!(r#"{{"name":"benign","{key}":"{val}"}}"#);
        assert_redacted(&body, &val);
    }

    #[test]
    fn api_json_escaped_quote_tail_never_leaks(
        key in credential_json_key(),
        head in json_value_frag(),
        tail in json_value_frag(),
    ) {
        // HIGH-1c property: a JSON-escaped `\"` mid-value must not split
        // the capture and leak the tail. `head\"tail` — assert the tail
        // (the part the naive `[^"]*` left behind) is gone.
        let body = format!("{{\"{key}\":\"{head}\\\"{tail}\"}}");
        let out = RedactionFilter::standard().redact(&body);
        prop_assert!(
            !out.contains(&tail),
            "escaped-quote tail leaked\ninput:  {body}\noutput: {out}\ntail:   {tail}"
        );
        prop_assert!(
            out.contains("[REDACTED:"),
            "no marker emitted\ninput:  {body}\noutput: {out}"
        );
    }

    // -----------------------------------------------------------------
    // Idempotency: redact ∘ redact == redact.
    // -----------------------------------------------------------------

    #[test]
    fn redact_is_idempotent_on_crypt_carriers(
        (id, salt, digest) in crypt_hash_parts(),
        algo in algo_keyword(),
    ) {
        // Leveled / typed carriers used to double-redact on a second
        // pass; pin idempotency across the `$id$` shapes and the
        // algorithm-name form.
        let f = RedactionFilter::standard();
        for line in [
            format!("enable secret 5 ${id}${salt}${digest}"),
            format!("enable secret {algo} ${id}${salt}${digest}"),
            format!("username admin secret {algo} ${id}${salt}${digest}"),
            format!("phash ${id}${salt}${digest};"),
            format!("root:${id}${salt}${digest}:19000:0:99999:7:::"),
        ] {
            let once = f.redact(&line);
            let twice = f.redact(&once);
            prop_assert_eq!(&once, &twice, "not idempotent for: {}", line);
        }
    }

    #[test]
    fn redact_is_idempotent_on_arbitrary_text(
        input in r#"[\sA-Za-z0-9!@#%^&*()_=/.+\-:\[\]\{\}";]{0,200}"#
    ) {
        let f = RedactionFilter::standard();
        let once = f.redact(&input);
        let twice = f.redact(&once);
        prop_assert_eq!(once, twice);
    }
}
