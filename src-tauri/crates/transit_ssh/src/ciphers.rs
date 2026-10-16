//! Cipher / KEX / MAC strict allowlist (+ opt-in legacy bypass).
//!
//! Transit's SSH transport refuses to negotiate any algorithm
//! weaker than the floor declared here. The floor:
//!
//! - No CBC ciphers (`3des-cbc`, `aes*-cbc`).
//! - No SHA1 anywhere — KEX, MAC, or host-key signature.
//! - No MD5.
//! - No `none` auth (cipher / mac / kex).
//! - No DSA host keys.
//! - No `ssh-rsa` (RSA-SHA1) host-key signatures.
//!
//! The lists are written out explicitly rather than derived from
//! [`russh::negotiation::Preferred::DEFAULT`]. A future russh that
//! quietly broadens its defaults will not silently weaken Transit;
//! the floor stays firm across upgrades.
//!
//! ## Legacy opt-in
//!
//! Cisco IOS-XE (vIOS, CSR1000v) and older Junos ship with SHA1-only
//! KEX defaults that fall below the floor. To support these without
//! permanently weakening the strict path, [`legacy_client_config`]
//! returns a permissive [`Config`] that includes the SHA1 KEX
//! variants, CBC ciphers, HMAC-SHA1 MACs, and `ssh-rsa` host-key
//! signatures alongside the modern algorithms, and requests DH
//! group-exchange bounds a 2048-bit-era server can satisfy (see
//! [`LEGACY_GEX_MIN_BITS`]). `none`/`clear`/DSA stay excluded —
//! those are non-negotiable (DSA reaffirmed 2026-07-04; see
//! threat-model T20).
//!
//! The legacy config is **only** reached after an explicit user
//! click on [`WeakCryptoConfirmDialog`]; see `T_WEAK_CRYPTO_OPTIN`
//! in `docs/security/threat-model.md` for the MITM-downgrade risk
//! analysis.
//!
//! [`WeakCryptoConfirmDialog`]: ../../../../../../src/components/dialogs/WeakCryptoConfirmDialog.tsx

use std::borrow::Cow;
use std::time::Duration;

use russh::client::{Config, GexParams};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{cipher, kex, mac, Preferred};

/// SSH-level keepalive cadence. Dead-path detection: a wedged
/// transport surfaces `KeepaliveTimeout` after
/// `KEEPALIVE_INTERVAL × KEEPALIVE_MAX` of post-auth silence instead
/// of blocking writers forever. russh only counts missed keepalives
/// once the session is authenticated, so this cannot fire during the
/// TOFU user-wait mid-KEX or a secret-backend prompt pre-auth.
/// `inactivity_timeout` stays `None` — unlike keepalive, it WOULD
/// fire during those user-waits.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Missed-keepalive budget before russh declares the path dead.
pub const KEEPALIVE_MAX: usize = 3;

/// Key-exchange allowlist, in preference order. Elliptic-curve
/// first; `mlkem768x25519-sha256` advertised first for the
/// post-quantum hybrid future. Strong DH groups (SHA2 only) retained
/// as a fallback for older network gear that hasn't shipped EC KEX.
///
/// Intentionally excluded: every `*-sha1` variant, `dh-g1`,
/// `dh-gex-sha1`, `kex::NONE`. The two extension sentinels are
/// included to opt into OpenSSH's strict-KEX hardening
/// (mitigates Terrapin / CVE-2023-48795) and ext-info negotiation.
pub const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP521,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP256,
    kex::DH_G18_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::DH_GEX_SHA256,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
];

/// Symmetric cipher allowlist. AEAD first (ChaCha20-Poly1305,
/// AES-GCM); AES-CTR retained for older network gear that hasn't
/// shipped GCM yet. 192-bit dropped — nobody deploys it.
///
/// Intentionally excluded: every `*-cbc`, `3des-*`, `cipher::NONE`,
/// `cipher::CLEAR`.
pub const CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_128_CTR,
];

/// MAC allowlist. HMAC-SHA2 only; encrypt-then-MAC preferred per
/// RFC 7366 (provides authenticity over the entire ciphertext, not
/// just the plaintext).
///
/// Intentionally excluded: `hmac-sha1`, `hmac-sha1-etm`, `mac::NONE`,
/// every `hmac-md5*`.
pub const MACS: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

/// Host-key signature allowlist. Ed25519, ECDSA-P256/384/521,
/// RSA-SHA2-256, RSA-SHA2-512. No DSA. No `ssh-rsa`
/// (`Algorithm::Rsa { hash: None }`) — that's the legacy SHA1 RSA
/// signature that NIST deprecated for SSH in 2022.
pub fn host_key_algos() -> Vec<Algorithm> {
    vec![
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    ]
}

/// Build the russh client [`Config`] preloaded with Transit's
/// algorithm floor. Compression is left at the russh default
/// (`none` only unless `flate2` is enabled, which we don't).
pub fn client_config() -> Config {
    let preferred = Preferred {
        kex: Cow::Borrowed(KEX),
        // No host CERTIFICATE algorithms (russh 0.63+). Transit pins host
        // KEYS (TOFU, threat-model T11) and has no CA trust store, so it
        // must never negotiate a certificate — russh treats one as
        // REPLACING the key check. `check_server_key` refuses any that
        // arrives anyway (defense in depth).
        host_key_certificates: Cow::Borrowed(&[]),
        key: Cow::Owned(host_key_algos()),
        cipher: Cow::Borrowed(CIPHERS),
        mac: Cow::Borrowed(MACS),
        compression: Preferred::DEFAULT.compression.clone(),
    };

    Config {
        preferred,
        // Dead-path detection (see KEEPALIVE_INTERVAL docs): a wedged
        // transport eventually errors instead of blocking forever.
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Config::default()
    }
}

/// Legacy KEX list — strict floor PLUS SHA1 variants. Used when the
/// user explicitly opts in via the weak-crypto warning dialog.
/// `kex::NONE` stays out; no encryption is no SSH.
pub const LEGACY_KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP521,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP256,
    kex::DH_G18_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::DH_GEX_SHA256,
    // SHA1 fallbacks for legacy gear (Cisco IOS-XE, older Junos, and
    // small-business switches). Fixed-group DH is ordered BEFORE
    // group-exchange on purpose: russh's client GEX floor is
    // `min_group_size = 2048` (and `GexParams` validation refuses to
    // build a client config below that), but legacy switches — Cisco
    // SG300/SG500, FS.com S5500 — answer a GEX request with a 1024-bit
    // modulus. russh then rejects the undersized group with
    // `Error::KexInit` (or the switch drops the connection →
    // `Error::Disconnect`), so the connect fails even AFTER the user
    // opts into weak crypto. Fixed group14 (2048) / group1 (1024) skip
    // GEX entirely, so negotiation completes. Negotiation is
    // client-preference-first (russh `negotiation::Client::select`),
    // and these switches advertise `group14-sha1`/`group1-sha1`
    // alongside `gex-sha1`, so preferring the fixed group is all it
    // takes. `gex-sha1` stays LAST as a fallback for servers that offer
    // only it — reachable since v2.3.3, when the legacy config started
    // requesting [`LEGACY_GEX_MIN_BITS`]-bit GEX bounds a 2048-bit-era
    // server can actually satisfy (russh's default request is min 3072,
    // which GEX-only gear answers with a disconnect). See T20
    // (`T_WEAK_CRYPTO_OPTIN`).
    kex::DH_G14_SHA1,
    kex::DH_G1_SHA1,
    kex::DH_GEX_SHA1,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
];

/// Legacy cipher list — strict floor PLUS AES-CBC variants.
/// `cipher::NONE`/`cipher::CLEAR` stay out — those are unencrypted.
pub const LEGACY_CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_128_CTR,
    // CBC fallbacks for legacy gear.
    cipher::AES_256_CBC,
    cipher::AES_128_CBC,
];

/// Legacy MAC list — strict floor PLUS HMAC-SHA1 variants.
/// `mac::NONE` stays out.
pub const LEGACY_MACS: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA1,
];

/// Legacy host-key allowlist — strict floor PLUS `ssh-rsa`
/// (RSA-SHA1 signatures). DSA stays excluded.
pub fn legacy_host_key_algos() -> Vec<Algorithm> {
    let mut algos = host_key_algos();
    algos.push(Algorithm::Rsa { hash: None });
    algos
}

/// DH group-exchange request bounds for the legacy path.
///
/// russh's default `GexParams` asks for min 3072 / preferred 8192 bits.
/// Legacy GEX-only gear (BDCOM-based FS.com campus switches among them)
/// tops out at a 2048-bit modulus and answers an unsatisfiable request
/// by disconnecting mid-handshake — the same `Error::Disconnect` shape
/// as a pre-KEXINIT drop, so the weak-crypto opt-in appeared to "not
/// work" on such devices even after consent (they offer no fixed group
/// to prefer instead).
///
/// 2048 is simultaneously russh's hard client-config floor (`GexParams`
/// validation) and the strength the legacy list already accepts via
/// `diffie-hellman-group14-sha1`, so requesting min=preferred=2048 adds
/// compatibility without lowering the accepted key-exchange floor.
/// Servers whose largest GEX modulus is 1024 bits remain unreachable
/// via GEX (russh cannot request below 2048); they connect only if they
/// also advertise a fixed group (`group1`/`group14`), which the legacy
/// KEX list prefers anyway.
pub const LEGACY_GEX_MIN_BITS: usize = 2048;
/// See [`LEGACY_GEX_MIN_BITS`]. Preferred == min so a legacy server
/// hands us its smallest acceptable (most compatible) group instead of
/// hunting for a large one it may not have.
pub const LEGACY_GEX_PREFERRED_BITS: usize = 2048;
/// See [`LEGACY_GEX_MIN_BITS`]. Upper bound kept at russh's default.
pub const LEGACY_GEX_MAX_BITS: usize = 8192;

/// Build the legacy path's [`GexParams`] from the constants above.
fn legacy_gex_params() -> GexParams {
    GexParams::new(
        LEGACY_GEX_MIN_BITS,
        LEGACY_GEX_PREFERRED_BITS,
        LEGACY_GEX_MAX_BITS,
    )
    .expect("2048/2048/8192 satisfies russh's client GexParams floor")
}

/// Build the russh client [`Config`] with the legacy allowlist.
/// Returned only when the user has opted into weak crypto for the
/// target device via the warning dialog. See module docs.
pub fn legacy_client_config() -> Config {
    let preferred = Preferred {
        kex: Cow::Borrowed(LEGACY_KEX),
        // Same as the strict config: host keys only, never certificates.
        host_key_certificates: Cow::Borrowed(&[]),
        key: Cow::Owned(legacy_host_key_algos()),
        cipher: Cow::Borrowed(LEGACY_CIPHERS),
        mac: Cow::Borrowed(LEGACY_MACS),
        compression: Preferred::DEFAULT.compression.clone(),
    };

    Config {
        preferred,
        // GEX request bounds a 2048-bit-era server can satisfy — see
        // LEGACY_GEX_MIN_BITS. The strict config keeps russh's
        // defaults (its GEX entry is SHA2-only and aimed at gear that
        // has real 3072+ moduli).
        gex: legacy_gex_params(),
        // Dead-path detection (see KEEPALIVE_INTERVAL docs) — the
        // legacy path keeps the same liveness floor as the strict one.
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor — assert the *absence* of weak entries. If any of
    /// these slip in, the test fails loudly.
    #[test]
    fn kex_list_excludes_weak_algorithms() {
        for weak in [
            kex::DH_GEX_SHA1,
            kex::DH_G1_SHA1,
            kex::DH_G14_SHA1,
            kex::NONE,
        ] {
            assert!(
                !KEX.contains(&weak),
                "weak KEX algorithm {:?} leaked into Transit's allowlist",
                weak
            );
        }
    }

    #[test]
    fn cipher_list_excludes_cbc_and_none() {
        // `cipher::TRIPLE_DES_CBC` is gated behind russh's `des`
        // feature; we don't enable it, so 3des-cbc isn't even
        // compiled into the binary. Belt-and-braces: if we ever do
        // enable that feature, the entries below still fail loudly.
        for weak in [
            cipher::AES_128_CBC,
            cipher::AES_192_CBC,
            cipher::AES_256_CBC,
            cipher::NONE,
            cipher::CLEAR,
        ] {
            assert!(
                !CIPHERS.contains(&weak),
                "weak cipher {:?} leaked into Transit's allowlist",
                weak
            );
        }
    }

    #[test]
    fn mac_list_excludes_sha1_and_none() {
        for weak in [mac::HMAC_SHA1, mac::HMAC_SHA1_ETM, mac::NONE] {
            assert!(
                !MACS.contains(&weak),
                "weak MAC {:?} leaked into Transit's allowlist",
                weak
            );
        }
    }

    #[test]
    fn host_key_algos_exclude_dsa_and_rsa_sha1() {
        let algos = host_key_algos();
        assert!(!algos.contains(&Algorithm::Dsa), "DSA host keys disallowed");
        assert!(
            !algos.contains(&Algorithm::Rsa { hash: None }),
            "RSA-SHA1 (ssh-rsa) host-key signatures disallowed"
        );
    }

    #[test]
    fn host_key_algos_include_modern() {
        let algos = host_key_algos();
        assert!(algos.contains(&Algorithm::Ed25519));
        assert!(algos.contains(&Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }));
        assert!(algos.contains(&Algorithm::Rsa {
            hash: Some(HashAlg::Sha512)
        }));
    }

    #[test]
    fn client_config_carries_the_allowlist() {
        let cfg = client_config();
        assert_eq!(cfg.preferred.kex.as_ref(), KEX);
        assert_eq!(cfg.preferred.cipher.as_ref(), CIPHERS);
        assert_eq!(cfg.preferred.mac.as_ref(), MACS);
        assert_eq!(cfg.preferred.key.as_ref(), host_key_algos().as_slice());
    }

    /// Both configs carry the keepalive floor (dead-path detection)
    /// and leave `inactivity_timeout` off — inactivity would fire
    /// during the TOFU user-wait mid-KEX, keepalive cannot (russh
    /// only counts misses post-auth).
    #[test]
    fn configs_enable_keepalive_but_not_inactivity_timeout() {
        for cfg in [client_config(), legacy_client_config()] {
            assert_eq!(cfg.keepalive_interval, Some(KEEPALIVE_INTERVAL));
            assert_eq!(cfg.keepalive_max, KEEPALIVE_MAX);
            assert_eq!(cfg.inactivity_timeout, None);
        }
    }

    /// Ed25519 sits at position 0 in the host-key list. Network
    /// engineers regenerate vEX host keys frequently; Ed25519 is
    /// the modern default and we want it negotiated first.
    #[test]
    fn ed25519_is_preferred_host_key() {
        let algos = host_key_algos();
        assert_eq!(algos[0], Algorithm::Ed25519);
    }

    /// AEAD ciphers come before AES-CTR. Defense in depth — even if
    /// the MAC negotiation somehow lands on a weak entry (it can't,
    /// per the MAC test), the AEAD cipher carries its own
    /// authenticity guarantee.
    #[test]
    fn aead_ciphers_preferred() {
        assert_eq!(CIPHERS[0], cipher::CHACHA20_POLY1305);
        assert_eq!(CIPHERS[1], cipher::AES_256_GCM);
    }

    /// Legacy KEX includes SHA1 variants. The point of the opt-in.
    #[test]
    fn legacy_kex_includes_sha1_variants() {
        assert!(LEGACY_KEX.contains(&kex::DH_GEX_SHA1));
        assert!(LEGACY_KEX.contains(&kex::DH_G14_SHA1));
        assert!(LEGACY_KEX.contains(&kex::DH_G1_SHA1));
    }

    /// Fixed-group DH MUST precede group-exchange in the legacy list.
    /// russh's client can't request a GEX group smaller than 2048 bits
    /// (`GexParams` validation floor), but legacy switches (Cisco
    /// SG300/SG500, FS.com S5500) answer GEX with a 1024-bit group →
    /// `Error::KexInit` / `Error::Disconnect`. Because negotiation is
    /// client-preference-first, preferring the fixed group14/group1 is
    /// what actually lets the weak-crypto opt-in complete the handshake.
    /// Regressing this ordering silently re-breaks those devices (the
    /// v2.3.0→v2.3.2 bug), so pin it.
    #[test]
    fn legacy_kex_prefers_fixed_dh_over_group_exchange_sha1() {
        let pos = |name: kex::Name| {
            LEGACY_KEX
                .iter()
                .position(|k| *k == name)
                .expect("algorithm present in LEGACY_KEX")
        };
        let gex_sha1 = pos(kex::DH_GEX_SHA1);
        assert!(
            pos(kex::DH_G14_SHA1) < gex_sha1,
            "group14-sha1 must be preferred over group-exchange-sha1"
        );
        assert!(
            pos(kex::DH_G1_SHA1) < gex_sha1,
            "group1-sha1 must be preferred over group-exchange-sha1"
        );
    }

    /// Legacy KEX still excludes `none`. No encryption is no SSH.
    #[test]
    fn legacy_kex_excludes_none() {
        assert!(!LEGACY_KEX.contains(&kex::NONE));
    }

    /// Legacy ciphers include CBC; still exclude unencrypted.
    #[test]
    fn legacy_ciphers_include_cbc_exclude_unencrypted() {
        assert!(LEGACY_CIPHERS.contains(&cipher::AES_128_CBC));
        assert!(LEGACY_CIPHERS.contains(&cipher::AES_256_CBC));
        assert!(!LEGACY_CIPHERS.contains(&cipher::NONE));
        assert!(!LEGACY_CIPHERS.contains(&cipher::CLEAR));
    }

    /// Legacy MACs include HMAC-SHA1 variants; still exclude `none`.
    #[test]
    fn legacy_macs_include_sha1_exclude_none() {
        assert!(LEGACY_MACS.contains(&mac::HMAC_SHA1));
        assert!(LEGACY_MACS.contains(&mac::HMAC_SHA1_ETM));
        assert!(!LEGACY_MACS.contains(&mac::NONE));
    }

    /// Legacy host-key list adds ssh-rsa (SHA1); still excludes DSA.
    #[test]
    fn legacy_host_keys_include_ssh_rsa_exclude_dsa() {
        let algos = legacy_host_key_algos();
        assert!(algos.contains(&Algorithm::Rsa { hash: None }));
        assert!(!algos.contains(&Algorithm::Dsa));
    }

    /// Strong algorithms still come first in every legacy list —
    /// negotiation prefers them when the server offers both modern
    /// and weak entries (e.g. dual-stack gear during a vendor's
    /// rolling deprecation).
    #[test]
    fn legacy_lists_prefer_strong_algorithms_first() {
        assert_eq!(LEGACY_KEX[0], kex::MLKEM768X25519_SHA256);
        assert_eq!(LEGACY_CIPHERS[0], cipher::CHACHA20_POLY1305);
        assert_eq!(LEGACY_MACS[0], mac::HMAC_SHA512_ETM);
        assert_eq!(legacy_host_key_algos()[0], Algorithm::Ed25519);
    }

    #[test]
    fn legacy_client_config_carries_legacy_lists() {
        let cfg = legacy_client_config();
        assert_eq!(cfg.preferred.kex.as_ref(), LEGACY_KEX);
        assert_eq!(cfg.preferred.cipher.as_ref(), LEGACY_CIPHERS);
        assert_eq!(cfg.preferred.mac.as_ref(), LEGACY_MACS);
        assert_eq!(
            cfg.preferred.key.as_ref(),
            legacy_host_key_algos().as_slice()
        );
    }

    /// The legacy path requests GEX bounds a 2048-bit-era server can
    /// satisfy. russh's default (min 3072) makes GEX-only legacy gear
    /// disconnect mid-handshake even after the weak-crypto opt-in —
    /// the v2.3.2→v2.3.3 bug — so pin the request.
    #[test]
    fn legacy_config_requests_2048_bit_gex_bounds() {
        let cfg = legacy_client_config();
        assert_eq!(cfg.gex.min_group_size(), LEGACY_GEX_MIN_BITS);
        assert_eq!(cfg.gex.preferred_group_size(), LEGACY_GEX_PREFERRED_BITS);
        assert_eq!(cfg.gex.max_group_size(), LEGACY_GEX_MAX_BITS);
        assert_eq!(LEGACY_GEX_MIN_BITS, 2048, "russh's hard client floor");
    }

    /// The strict path keeps russh's default GEX request — the tuned
    /// bounds are a legacy-opt-in concession only. If a russh upgrade
    /// changes its defaults, this fails loudly so the change is
    /// reviewed instead of silently shifting the strict posture.
    #[test]
    fn strict_config_keeps_default_gex_request() {
        let cfg = client_config();
        let default = GexParams::default();
        assert_eq!(cfg.gex.min_group_size(), default.min_group_size());
        assert_eq!(
            cfg.gex.preferred_group_size(),
            default.preferred_group_size()
        );
        assert_eq!(cfg.gex.max_group_size(), default.max_group_size());
        assert_eq!(default.min_group_size(), 3072, "russh default at this pin");
    }

    /// Neither config may offer a host-CERTIFICATE algorithm: Transit's
    /// trust model is a pinned host key (T11), and russh lets a
    /// negotiated certificate replace the key check outright. Pinned so a
    /// future edit can't quietly opt in.
    #[test]
    fn neither_config_offers_host_certificates() {
        assert!(client_config().preferred.host_key_certificates.is_empty());
        assert!(legacy_client_config()
            .preferred
            .host_key_certificates
            .is_empty());
    }
}
