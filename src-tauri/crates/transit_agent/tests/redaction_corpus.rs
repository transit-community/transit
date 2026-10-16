//! Redaction filter corpus.
//!
//! Each fixture is a chunk of realistic device scrollback containing
//! one or more credential-shaped tokens. Every assertion is the same
//! shape: the secret bytes MUST NOT appear in the redacted output,
//! and AT LEAST ONE redaction marker MUST appear. Beyond that, we
//! assert benign surrounding context (vendor strings, device names,
//! interface IDs, IP addresses) survives — over-redaction destroys
//! the model's ability to reason about the device.

use transit_agent::RedactionFilter;

fn assert_redacted(input: &str, secret: &str) {
    let f = RedactionFilter::standard();
    let out = f.redact(input);
    assert!(
        !out.contains(secret),
        "secret {secret:?} survived redaction\ninput:  {input}\noutput: {out}"
    );
    assert!(
        out.contains("[REDACTED:"),
        "no redaction marker emitted\ninput:  {input}\noutput: {out}"
    );
}

fn assert_unchanged(input: &str) {
    let f = RedactionFilter::standard();
    let out = f.redact(input);
    assert_eq!(out, input, "benign content was modified by filter");
}

// =====================================================================
// Realistic Junos `show configuration` excerpts.
// =====================================================================

#[test]
fn junos_show_config_authentication() {
    let scrollback = r#"alice@vEX1> show configuration system root-authentication
encrypted-password "$6$rounds=999$abcdef.ghijkl/secrethashvalue1234567890"; ## SECRET-DATA
"#;
    assert_redacted(
        scrollback,
        "$6$rounds=999$abcdef.ghijkl/secrethashvalue1234567890",
    );
    let out = RedactionFilter::standard().redact(scrollback);
    assert!(out.contains("alice@vEX1"), "device prompt must survive");
    assert!(out.contains("encrypted-password"), "verb must survive");
}

#[test]
fn junos_show_config_snmp() {
    let scrollback = r#"
[edit]
alice@vEX1# show snmp
community "publicReadOnly" {
    authorization read-only;
}
"#;
    assert_redacted(scrollback, "publicReadOnly");
}

#[test]
fn junos_show_config_radius() {
    let scrollback = r#"
[edit system]
radius-server {
    10.0.0.1 secret "RadiusSharedSecret";
    10.0.0.2 secret "OtherSecret";
}
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    assert!(!out.contains("RadiusSharedSecret"));
    assert!(!out.contains("OtherSecret"));
    assert!(out.contains("10.0.0.1"), "IP context must survive");
    assert!(out.contains("10.0.0.2"));
}

#[test]
fn junos_set_format_excerpt() {
    let scrollback = r#"
set system root-authentication encrypted-password "$6$rounds=999$abcdef$secretpw"
set snmp community "publicCommunity" authorization read-only
set system tacplus-server 10.0.0.1 secret "TacacsKey1"
set system radius-server 10.0.0.2 secret "RadiusKey1"
set protocols bgp group EXT neighbor 1.2.3.4 authentication-key "BgpAuthKey"
set security ike policy IKE-POL pre-shared-key ascii-text "JunosPsk"
set system ntp authentication-key 1 type md5 value "NtpKey1"
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "secretpw",
        "publicCommunity",
        "TacacsKey1",
        "RadiusKey1",
        "BgpAuthKey",
        "JunosPsk",
        "NtpKey1",
    ] {
        assert!(
            !out.contains(secret),
            "secret {secret:?} survived\noutput: {out}"
        );
    }
    assert!(out.contains("10.0.0.1"));
    assert!(out.contains("1.2.3.4"));
}

// =====================================================================
// Realistic Cisco IOS / IOS-XE `show running-config` excerpts.
// =====================================================================

#[test]
fn cisco_running_config_users() {
    let scrollback = r#"
hostname Edge-Router
!
username admin privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
username readonly privilege 1 password 7 110A1016141D1212
enable secret 5 $1$abcd$ffggffggffggffggffggffgg
!
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    assert!(!out.contains("$1$mERr"));
    assert!(!out.contains("110A1016141D1212"));
    assert!(!out.contains("$1$abcd"));
    assert!(out.contains("hostname Edge-Router"));
    assert!(out.contains("username admin"));
    assert!(out.contains("[REDACTED:cisco-username-secret]"));
    assert!(out.contains("[REDACTED:cisco-type-7]"));
    assert!(out.contains("[REDACTED:cisco-enable-secret]"));
}

#[test]
fn cisco_running_config_aaa() {
    let scrollback = r#"
aaa group server tacacs+ TAC-PLUS
 server-private 10.0.0.10 key 7 094F471A1A0A
 server-private 10.0.0.11 key TacacsCleartext
!
tacacs-server key 7 0822455D0A16
!
radius-server host 10.0.0.20 auth-port 1812 acct-port 1813 key RadiusSharedSecret
radius-server key Radius2ndKey
!
ip tacacs source-interface Loopback0
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "094F471A1A0A",
        "TacacsCleartext",
        "0822455D0A16",
        "RadiusSharedSecret",
        "Radius2ndKey",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("Loopback0"), "non-secret context must survive");
}

#[test]
fn cisco_running_config_routing_auth() {
    let scrollback = r#"
router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 password BgpMd5Secret
 neighbor 10.0.0.2 remote-as 65003
 neighbor 10.0.0.2 password 7 094F471A1A0A
!
interface GigabitEthernet0/0/0
 ip ospf authentication-key OspfPlainKey
 ip ospf message-digest-key 1 md5 OspfMd5Secret
 ip authentication key-string EigrpSecret
!
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "BgpMd5Secret",
        "094F471A1A0A",
        "OspfPlainKey",
        "OspfMd5Secret",
        "EigrpSecret",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("router bgp 65001"));
    assert!(out.contains("GigabitEthernet0/0/0"));
}

#[test]
fn cisco_running_config_key_chain() {
    let scrollback = r#"
key chain TRANSIT-CHAIN
 key 1
  key-string FirstKeySecret99
 key 2
  key-string 7 06070D22484B0F1E
!
interface GigabitEthernet0/1
 ip authentication key-chain eigrp 100 TRANSIT-CHAIN
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["FirstKeySecret99", "06070D22484B0F1E"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("[REDACTED:key-string]"));
    assert!(
        out.contains("key chain TRANSIT-CHAIN"),
        "block header must survive\n{out}"
    );
    assert!(out.contains("\n key 1\n"), "key id header must survive");
    assert!(out.contains("\n key 2\n"), "key id header must survive");
    assert!(
        out.contains("key-chain eigrp 100 TRANSIT-CHAIN"),
        "key-chain reference (a name, not a secret) must survive"
    );
}

#[test]
fn cisco_running_config_ppp() {
    let scrollback = r#"
interface Serial0/1/0
 encapsulation ppp
 ppp authentication chap
 ppp chap hostname Edge-R1
 ppp chap password 0 ChapSecret77
!
interface Serial0/1/1
 encapsulation ppp
 ppp pap sent-username Edge-R1 password 7 095C4F104C0B14004E
!
interface Serial0/1/2
 ppp pap sent-username Edge-R2 password PapPlain88
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["ChapSecret77", "095C4F104C0B14004E", "PapPlain88"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    // Cleartext / type-0 forms carry the ppp class; the `password 7
    // <hex>` form is absorbed upstream by cisco-type-7 (class label
    // encodes the level — same contract as username lines).
    assert!(out.contains("[REDACTED:ppp-password]"));
    assert!(out.contains("[REDACTED:cisco-type-7]"));
    assert!(out.contains("Serial0/1/0"));
    assert!(
        out.contains("ppp chap hostname Edge-R1"),
        "hostname is an identifier, not a secret"
    );
    assert!(
        out.contains("sent-username Edge-R1"),
        "sent-username survives"
    );
}

// Negative: key-chain structure lines are NOT secrets. `key chain
// NAME` headers, `key <id>` headers, and lifetime/algorithm lines
// must round-trip verbatim — only the `key-string` payload (tested
// above) is credential-shaped.
#[test]
fn key_chain_headers_unchanged() {
    let s = "\
key chain TRANSIT-CHAIN
 key 1
  cryptographic-algorithm hmac-sha-256
  send-lifetime 00:00:00 Jan 1 2026 infinite
 key 25
";
    assert_unchanged(s);
}

#[test]
fn cisco_running_config_ipsec() {
    let scrollback = r#"
crypto isakmp policy 10
 encr aes 256
 hash sha256
 authentication pre-share
 group 14
!
crypto isakmp key MyPreSharedKey1234 address 1.2.3.4
crypto isakmp key OtherPSK hostname remote-vpn.example.com
!
crypto ikev2 keyring KEYRING1
 peer PEER1
  address 5.6.7.8
  pre-shared-key local LocalPSK
  pre-shared-key remote RemotePSK
!
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["MyPreSharedKey1234", "OtherPSK", "LocalPSK", "RemotePSK"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("1.2.3.4"));
    assert!(out.contains("5.6.7.8"));
    assert!(out.contains("remote-vpn.example.com"));
}

#[test]
fn cisco_running_config_snmp() {
    let scrollback = r#"
snmp-server community publicRO RO 1
snmp-server community privateRW RW MGMT-ACL
snmp-server user alice SNMP-GROUP v3 auth sha AuthSecret priv aes 128 PrivSecret
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["publicRO", "privateRW", "AuthSecret", "PrivSecret"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
}

// =====================================================================
// NX-OS excerpts.
// =====================================================================

#[test]
fn nxos_show_running_config() {
    let scrollback = r#"
username alice role network-admin password 5 $5$abcdef$NxOsPasswordHash
snmp-server community publicNxos use-acl SNMP-MGMT
snmp-server user nxosuser network-operator auth sha NxosAuth priv aes-128 NxosPriv
tacacs-server key 7 121A0C041104
!
router ospf 1
 area 0
!
interface Ethernet1/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 NxosOspfKey
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "$5$abcdef",
        "publicNxos",
        "NxosAuth",
        "NxosPriv",
        "121A0C041104",
        "NxosOspfKey",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("Ethernet1/1"));
    assert!(out.contains("router ospf 1"));
}

// =====================================================================
// Palo Alto PAN-OS `show config` excerpts.
// =====================================================================

#[test]
fn panos_show_config_mgt_users() {
    // The reported scenario verbatim: `mgt-config` local-admin
    // password hashes rendered as `phash $5$…;`.
    let scrollback = r#"alice@PA-VM# show mgt-config
config {
  mgt-config {
    users {
      admin {
        phash $5$gpomlmea$.nAnIg.kuzdrLLQtpHvYiFNu0pCR2gPKIcDgT5w0fY7;
        permissions {
          role-based {
            superuser yes;
          }
        }
      }
      alice {
        phash $5$cukcbkbd$9hGSrflkTXXTk8k5YfzIBuN5d0lbIcSqFsAWcDPf4s.;
        permissions {
          role-based {
            superuser yes;
          }
        }
      }
    }
  }
}
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "$5$gpomlmea",
        ".nAnIg.kuzdrLLQtpHvYiFNu0pCR2gPKIcDgT5w0fY7",
        "$5$cukcbkbd",
        "9hGSrflkTXXTk8k5YfzIBuN5d0lbIcSqFsAWcDPf4s.",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("[REDACTED:panos-phash]"));
    // Non-secret config structure + the account names survive.
    assert!(out.contains("superuser yes"), "role structure must survive");
    assert!(out.contains("admin {"), "account name is not a secret");
    assert!(out.contains("alice {"));
}

#[test]
fn panos_set_format_encrypted_secrets() {
    // PAN-OS `set`-format with the proprietary `-AQ…` AES-encrypted
    // secret encoding (RADIUS shared secret + IKE gateway PSK).
    let scrollback = r#"
set shared server-profile radius CorpRADIUS server auth1 secret -AQ==bDB1234567890ABCDEFabcdefGHIJ==
set network ike gateway VPN-GW authentication pre-shared-key key -AQ==pAnPsK0987654321ZYXWvuTSRqpo==
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["bDB1234567890ABCDEF", "pAnPsK0987654321"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("[REDACTED:panos-encrypted]"));
    assert!(out.contains("CorpRADIUS"), "profile name is not a secret");
    assert!(out.contains("VPN-GW"), "gateway name is not a secret");
}

// =====================================================================
// Arista EOS `show running-config` excerpts.
// =====================================================================

#[test]
fn arista_running_config_users() {
    // Arista puts the algorithm NAME (`sha512`) where Cisco puts a
    // numeric type. Both the salt and the digest must be redacted.
    let scrollback = r#"
hostname arista-leaf1
!
username admin privilege 15 role network-admin secret sha512 $6$Km2eR9uP$Q3xN.wZ1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uVwXyZ.abcdEFGHij
username monitor privilege 1 secret sha512 $6$aB1cD2eF$mNoPqRsTuVwXyZ0123456789abcdefABCDEF./ghijklmnopqrstuvwx
enable secret sha512 $6$Zz9Yy8Xx$0011223344556677./aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvv
!
snmp-server community AristaMonitorRO ro
!
ip route 0.0.0.0/0 10.0.0.1
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "$6$Km2eR9uP",
        "Q3xN.wZ1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uVwXyZ",
        "$6$aB1cD2eF",
        "$6$Zz9Yy8Xx",
        "AristaMonitorRO",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("[REDACTED:cisco-username-secret]"));
    assert!(out.contains("[REDACTED:cisco-enable-secret]"));
    // Non-secret context survives.
    assert!(out.contains("hostname arista-leaf1"));
    assert!(out.contains("ip route 0.0.0.0/0 10.0.0.1"));
    assert!(out.contains("username admin"));
}

// =====================================================================
// Cisco IOS-XR `show running-config` excerpts (nested user config +
// BGP `password encrypted`).
// =====================================================================

#[test]
fn iosxr_running_config_users_and_bgp() {
    let scrollback = r#"
username alice
 group root-lr
 secret 10 $6$XrSaltXr$XrHashXrHashXrHashXrHashXrHashXrHashXrHashXrHashXrHash./abcABC
 password 7 13061E010803
!
router bgp 65000
 neighbor 10.1.1.1
  remote-as 65001
  password encrypted 060506324F41
!
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &[
        "$6$XrSaltXr",
        "XrHashXrHashXrHash",
        "13061E010803",
        "060506324F41",
    ] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    // Nested user secret + type-7 + the standalone BGP `password
    // encrypted` line (hierarchical IOS-XR form, not neighbor-anchored).
    assert!(out.contains("[REDACTED:cisco-username-secret]"));
    assert!(out.contains("[REDACTED:cisco-type-7]"));
    assert!(out.contains("[REDACTED:password-encrypted]"));
    // Non-secret context survives.
    assert!(out.contains("router bgp 65000"));
    assert!(out.contains("remote-as 65001"));
    assert!(out.contains("group root-lr"), "user group is not a secret");
}

// =====================================================================
// PEM keys + cloud / generic.
// =====================================================================

#[test]
fn ssh_key_dump() {
    let scrollback = "\
host key fingerprint:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBfakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake==
-----END OPENSSH PRIVATE KEY-----
done.";
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    assert!(!out.contains("b3BlbnNzaC1rZXktdjE"));
    assert!(!out.contains("FakeFakeFakeFakeFakeFakeFake"));
    assert!(out.contains("[REDACTED:pem-block]"));
    assert!(out.contains("done."));
    assert!(out.contains("host key fingerprint:"));
}

#[test]
fn aws_credentials_blob() {
    let scrollback = "\
[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region=us-east-1";
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!out.contains("wJalrXUtnFEMI"));
    assert!(out.contains("region=us-east-1"));
}

#[test]
fn jwt_in_curl_output() {
    let scrollback = "\
HTTP/1.1 200 OK
content-type: application/json

{\"access_token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4eXoifQ.signature_part_here\"}";
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    assert!(!out.contains("eyJhbGc"));
    assert!(out.contains("HTTP/1.1 200 OK"));
}

#[test]
fn cloud_provider_tokens_pasted_in_session() {
    // Modern SaaS/cloud tokens an engineer might paste (e.g. into an
    // on-box script or a `cat`'d .env). Each token is assembled from
    // (prefix + body) at RUNTIME so no contiguous token literal lands
    // in source — GitHub push protection / secret-scanning flags
    // example tokens otherwise. The filter sees the full token.
    let tokens = [
        format!("ghp_{}", "016C7f8aAbBcCdDeEfFgGhHiIjJkKlLmMnN12"),
        format!("sk_live_{}", "ExampleStripeKeyBodyNotReal99"),
        format!("xoxb-{}", "ExampleSlackTokenBodyNotReal"),
        format!("sk-proj-{}", "AbCdEf1234567890AbCdEf1234567890T3Blbk"),
        format!("glpat-{}", "ExampleGitlabTokenBodyNotReal"),
        format!("AIza{}", "SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q"),
    ];
    let scrollback = format!(
        "GITHUB_TOKEN={}\nSTRIPE_KEY={}\nSLACK_BOT_TOKEN={}\n\
         OPENAI_API_KEY={}\nGITLAB_TOKEN={}\nGOOGLE_API_KEY={}\n\
         region=us-east-1",
        tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5],
    );
    let f = RedactionFilter::standard();
    let out = f.redact(&scrollback);
    for secret in &tokens {
        assert!(!out.contains(secret.as_str()), "{secret:?} survived\n{out}");
    }
    for class in &[
        "github-token",
        "stripe-key",
        "slack-token",
        "openai-key",
        "gitlab-token",
        "google-api-key",
    ] {
        assert!(
            out.contains(&format!("[REDACTED:{class}]")),
            "missing {class}\n{out}"
        );
    }
    // Non-secret context (the env var NAMES + region) survives.
    assert!(out.contains("GITHUB_TOKEN="));
    assert!(out.contains("region=us-east-1"));
}

#[test]
fn cisco_line_and_vtp_cleartext_passwords() {
    let scrollback = r#"
vtp domain LAB
vtp password VtpDomainSecret
!
line con 0
 password ConsoleCleartextPw
 login
line vty 0 4
 password 0 VtyType0Pw
 transport input ssh
!
"#;
    let f = RedactionFilter::standard();
    let out = f.redact(scrollback);
    for secret in &["VtpDomainSecret", "ConsoleCleartextPw", "VtyType0Pw"] {
        assert!(!out.contains(secret), "{secret:?} survived\n{out}");
    }
    assert!(out.contains("[REDACTED:vtp-password]"));
    assert!(out.contains("[REDACTED:cleartext-password]"));
    // Non-secret structure survives.
    assert!(
        out.contains("vtp domain LAB"),
        "domain name is not a secret"
    );
    assert!(out.contains("transport input ssh"));
    assert!(out.contains("login"));
}

// =====================================================================
// Negative — benign device output is preserved verbatim.
// =====================================================================

#[test]
fn show_version_unchanged() {
    let s = r#"
Hostname: vEX1
Model: vmx
Junos: 21.4R1.12
JUNOS Software Release [21.4R1.12]
Uptime: 5 days, 2 hours, 34 minutes
Last reboot reason: 0x1:power cycle/failure
"#;
    assert_unchanged(s);
}

#[test]
fn show_interfaces_unchanged() {
    let s = "\
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Interface index: 130, SNMP ifIndex: 502
  Description: WAN-link-to-spine-1
  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps, BPDU Error: None
  Flags: Internal: 0x0
  Last link change: 2026-04-12 11:33:18 PDT (3w0d 02:14 ago)
  Statistics last cleared: never
  Interface MAC address: 00:50:56:bf:11:22";
    assert_unchanged(s);
}

#[test]
fn show_route_unchanged() {
    let s = "\
inet.0: 12 destinations, 12 routes (12 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

10.0.0.0/24       *[Direct/0] 5d 02:14:33
                    > via ge-0/0/0.0
192.168.0.0/16    *[Static/5] 2w0d 11:14:22
                    > to 10.0.0.1 via ge-0/0/0.0";
    assert_unchanged(s);
}

#[test]
fn show_bgp_summary_unchanged() {
    let s = "\
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.1              65002       1234       1300       0       0          5d3:14 Establ
10.0.0.2              65003       1100       1200       0       1          2d1:00 Establ";
    assert_unchanged(s);
}

// =====================================================================
// 2026-07 security review — redaction catalogue gaps (finding #3).
// =====================================================================

#[test]
fn ipsec_psk_with_encryption_type_token_is_redacted() {
    // The `0`/`6` type token must NOT be mistaken for the secret — the
    // actual PSK after it must be redacted.
    assert_redacted(
        "pre-shared-key remote 0 CleartextRemotePsk",
        "CleartextRemotePsk",
    );
    assert_redacted(
        "pre-shared-key local 6 EncryptedPskBlobHere",
        "EncryptedPskBlobHere",
    );
}

#[test]
fn modern_openai_project_key_is_redacted() {
    // `sk-proj-` keys embed `_` and `-`; the legacy base62 body class
    // missed them. Assembled from prefix + body at RUNTIME so no
    // contiguous `sk-proj-…` literal lands in source — GitHub push
    // protection flags example tokens otherwise (same reason the mod.rs
    // cloud-token test splits prefix+body). The filter sees the full
    // token when it runs.
    let key = format!(
        "{}{}",
        "sk-proj-", "Ab_1234567890abcdefghij_KLMNOPqrst_uvwxyz1234_T3BlbkFJ"
    );
    let out = RedactionFilter::standard().redact(&format!("OPENAI_API_KEY={key}"));
    assert!(!out.contains(&key), "sk-proj key must be redacted");
    assert!(
        out.contains("[REDACTED:openai-key]"),
        "expected openai-key class marker"
    );
}

#[test]
fn snmp_trap_host_community_is_redacted() {
    assert_redacted(
        "snmp-server host 192.168.1.5 traps version 2c SecretTrapCommunity",
        "SecretTrapCommunity",
    );
    // The host + version context must survive (over-redaction hurts).
    let out = RedactionFilter::standard()
        .redact("snmp-server host 192.168.1.5 traps version 2c SecretTrapCommunity");
    assert!(out.contains("192.168.1.5"), "trap host must survive");
}

#[test]
fn url_userinfo_password_is_redacted_host_preserved() {
    let out = RedactionFilter::standard()
        .redact("DATABASE_URL=postgres://transit:hunter2pw@10.0.0.5:5432/mydb");
    assert!(!out.contains("hunter2pw"), "URL password must be redacted");
    assert!(
        out.contains("@10.0.0.5:5432/mydb"),
        "the host/path after the password must survive"
    );
}

#[test]
fn http_basic_auth_is_redacted() {
    assert_redacted(
        "Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=",
        "YWRtaW46c3VwZXJzZWNyZXQ=",
    );
}

#[test]
fn wpa_psk_is_redacted() {
    assert_redacted("wpa-psk ascii 0 MyWifiPassphrase123", "MyWifiPassphrase123");
}

#[test]
fn new_rules_do_not_over_redact_benign_context() {
    // The URL rule requires an `@` (userinfo), so a host:port URL with no
    // credentials is untouched — a port must never be mistaken for a
    // password.
    assert_unchanged("fetching http://example.com:8080/path/to/resource");
    // `basic-auth` is anchored on the `authorization:` header, so the
    // English word "basic" is never a false positive.
    assert_unchanged("show basic configuration on GigabitEthernet0/1");
}

// =====================================================================
// v4.0.0 — JSON-value secrets in API (UniFi) responses. `read_scrollback`
// over an API session carries JSON, not CLI text, so the value of a
// credential-named key must be redacted while the key + benign fields
// survive.
// =====================================================================

#[test]
fn api_json_wlan_passphrase_redacted() {
    let body = r#"{"name":"Guest WiFi","enabled":true,"x_passphrase":"SuperSecretWiFiPass123","security":"wpapsk"}"#;
    assert_redacted(body, "SuperSecretWiFiPass123");
    let out = RedactionFilter::standard().redact(body);
    assert!(out.contains("Guest WiFi"), "benign SSID name must survive");
    assert!(
        out.contains("\"x_passphrase\""),
        "the key name must survive"
    );
}

#[test]
fn api_json_radius_and_token_redacted() {
    let body = r#"{"radius_secret":"shared-radius-secret","apiKey":"ak_live_abcdef123456","site":"default"}"#;
    assert_redacted(body, "shared-radius-secret");
    assert_redacted(body, "ak_live_abcdef123456");
    assert!(
        RedactionFilter::standard().redact(body).contains("default"),
        "benign site field must survive"
    );
}

#[test]
fn api_json_benign_id_fields_are_not_over_redacted() {
    // A List hosts response is all ids/macs/timestamps — none should trip
    // the credential-key patterns (the model needs this data to reason).
    assert_unchanged(
        r#"{"id":"E4388380F0D1","hardwareId":"ebcae715","mac":"E4:43:88","ipAddress":"10.0.0.48"}"#,
    );
}

#[test]
fn api_json_secret_redaction_is_idempotent() {
    let body = r#"{"psk":"p4ssw0rd-here"}"#;
    let f = RedactionFilter::standard();
    let once = f.redact(body);
    let twice = f.redact(&once);
    assert_eq!(once, twice, "second pass must not re-redact the marker");
    assert!(!once.contains("p4ssw0rd-here"));
}

// --- Adversarial-review hardenings (2026-07-30). Each was a confirmed
// leak before the fix; these pin them shut. ---

#[test]
fn api_json_credential_key_casing_is_redacted() {
    // HIGH-1a: keys arrive in any case. A case-sensitive alternation let
    // `PSK` / `X_Passphrase` / `Password` values through verbatim.
    for (body, secret) in [
        (r#"{"PSK":"UpperKeyLeak11"}"#, "UpperKeyLeak11"),
        (r#"{"X_Passphrase":"MixedCaseLeak22"}"#, "MixedCaseLeak22"),
        (r#"{"Password":"CapPassLeak33"}"#, "CapPassLeak33"),
    ] {
        assert_redacted(body, secret);
    }
}

#[test]
fn api_json_affix_variant_secret_fields_are_redacted() {
    // HIGH-1b: real UniFi secret-bearing fields the old exact allow-list
    // missed. `x_ssh_password` is the SSH password UniFi propagates to
    // every adopted AP/switch — the highest-value miss.
    for (body, secret) in [
        (
            r#"{"x_ssh_username":"admin","x_ssh_password":"Sup3rSecretSSH"}"#,
            "Sup3rSecretSSH",
        ),
        (r#"{"wpa_passphrase":"MyWifiPass2026"}"#, "MyWifiPass2026"),
        (r#"{"x_iapp_key":"iappKeySecret12"}"#, "iappKeySecret12"),
        (r#"{"x_ca_key":"caPrivKeyLeak99"}"#, "caPrivKeyLeak99"),
        (r#"{"sharedSecret":"radiusSharedXyz"}"#, "radiusSharedXyz"),
        (r#"{"presharedKey":"vpnPreshared88"}"#, "vpnPreshared88"),
        (r#"{"xPassphrase":"CamelWifiSecret9"}"#, "CamelWifiSecret9"),
    ] {
        assert_redacted(body, secret);
    }
}

#[test]
fn api_json_escaped_quote_value_is_fully_redacted() {
    // HIGH-1c: a JSON-escaped `\"` inside the value stopped the naive
    // `[^"]*` capture, leaking everything after it. A `"` is legal in an
    // 8–63-char WPA passphrase, so this was a real PSK-tail leak.
    let body = "{\"x_passphrase\":\"a\\\"SuperSecretRest\"}";
    assert_eq!(body, r#"{"x_passphrase":"a\"SuperSecretRest"}"#);
    assert_redacted(body, "SuperSecretRest");
    let out = RedactionFilter::standard().redact(body);
    assert!(
        out.contains("\"x_passphrase\""),
        "key name must survive: {out}"
    );
}

#[test]
fn api_json_section_label_over_redacted_by_design() {
    // MEDIUM-3, documented tradeoff: the affix-tolerant `key` match also
    // redacts benign `"key":"<section>"` labels. Verifying it here makes
    // the over-redaction an INTENTIONAL, tested choice (safe direction) —
    // not an accident. A boolean sibling field still survives so the agent
    // retains the surrounding structure.
    let body = r#"{"key":"mgmt","x_ssh_enabled":true}"#;
    assert_redacted(body, "mgmt");
    assert!(
        RedactionFilter::standard()
            .redact(body)
            .contains("\"x_ssh_enabled\":true"),
        "benign non-string sibling must survive"
    );
}
