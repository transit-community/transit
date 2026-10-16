//! TLS record and handshake headers (RFC 8446, RFC 5246).
//!
//! **Metadata only — nothing here decrypts anything.** Transit reads the
//! cleartext parts of a TLS conversation: the record framing, the
//! handshake type, the negotiated version, the SNI host a client asked
//! for, and the alert that killed a failed handshake. That is exactly the
//! set that answers "why did this connection fail", which is why a
//! capture gets opened.
//!
//! Certificate *bodies* are deliberately not decoded. They are large,
//! they are base64-shaped blobs that would dominate any answer they
//! appeared in, and — the reason that matters — a multi-line
//! certificate-shaped field is precisely the thing the redaction filter's
//! PEM matcher is built to catch. Not emitting them keeps the field tree
//! free of any value that could be sheared into looking like a key.

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;

/// Cheap content sniff, so TLS on a non-standard port is still TLS.
///
/// A TLS record starts with a content type in 20..=23 followed by a
/// two-byte legacy version whose major is always 3. That is a narrow
/// enough shape to beat port guessing and wide enough to catch 8443.
pub(crate) fn looks_like_tls(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }
    let content = payload[0];
    let (major, minor) = (payload[1], payload[2]);
    (CONTENT_CHANGE_CIPHER_SPEC..=CONTENT_APPLICATION_DATA).contains(&content)
        && major == 3
        && minor <= 4
}

pub(crate) fn dissect(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Tls);
    if !ctx.full() {
        return;
    }

    let mut r = Reader::new(payload);
    let (Some(content), Some(version), Some(len)) = (r.u8(), r.u16(), r.u16()) else {
        return;
    };

    let mut l = Layer::new(Proto::Tls, format!("TLS {}", content_name(content)));
    l.push(Field::u64(
        "tls.record.content_type",
        "Content type",
        u64::from(content),
    ))
    .push(Field::u64(
        "tls.record.version",
        "Record version",
        u64::from(version),
    ))
    .push(Field::text(
        "tls.record.version.name",
        "Record version name",
        version_name(version),
    ))
    .push(Field::u64(
        "tls.record.length",
        "Record length",
        u64::from(len),
    ));

    let mut info = format!("TLS {}", content_name(content));

    // The record's declared length bounds everything inside it. A record
    // claiming more than it has is a snapped packet, which is normal.
    let body_len = (len as usize).min(r.remaining());
    let Some(mut body) = r.sub(body_len) else {
        ctx.push_layer(l);
        ctx.set_info(info);
        return;
    };

    match content {
        CONTENT_HANDSHAKE => {
            if let (Some(hs_type), Some(hs_len)) = (body.u8(), body.u24()) {
                l.push(Field::u64(
                    "tls.handshake.type",
                    "Handshake type",
                    u64::from(hs_type),
                ))
                .push(Field::text(
                    "tls.handshake.type.name",
                    "Handshake type name",
                    handshake_name(hs_type),
                ));
                info = handshake_name(hs_type).to_string();

                let inner_len = (hs_len as usize).min(body.remaining());
                if let Some(mut hs) = body.sub(inner_len) {
                    match hs_type {
                        HS_CLIENT_HELLO => {
                            if let Some(sni) = client_hello_sni(&mut hs) {
                                l.push(Field::text(
                                    "tls.handshake.extensions_server_name",
                                    "Server name (SNI)",
                                    &sni,
                                ));
                                info = format!("Client Hello (SNI={sni})");
                            }
                        }
                        HS_SERVER_HELLO => {
                            if let Some(suite) = server_hello_cipher(&mut hs) {
                                l.push(Field::u64(
                                    "tls.handshake.ciphersuite",
                                    "Cipher suite",
                                    u64::from(suite),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        CONTENT_ALERT => {
            // The alert is the whole point of dissecting a failed
            // handshake: `tls.alert.description == 40` is "the peer
            // rejected us", and the digest counts these.
            if let (Some(level), Some(desc)) = (body.u8(), body.u8()) {
                l.push(Field::u64(
                    "tls.alert.level",
                    "Alert level",
                    u64::from(level),
                ))
                .push(Field::u64(
                    "tls.alert.description",
                    "Alert description",
                    u64::from(desc),
                ))
                .push(Field::text(
                    "tls.alert.description.name",
                    "Alert description name",
                    alert_name(desc),
                ));
                let level_name = if level == 2 { "Fatal" } else { "Warning" };
                info = format!("Alert ({level_name}: {})", alert_name(desc));
            }
        }
        _ => {}
    }

    ctx.push_layer(l);
    ctx.set_info(info);
}

/// Walk a ClientHello to its `server_name` extension.
fn client_hello_sni(hs: &mut Reader<'_>) -> Option<String> {
    hs.u16()?; // legacy_version
    hs.skip(32)?; // random
    let sid_len = hs.u8()? as usize;
    hs.skip(sid_len)?; // legacy_session_id
    let suites_len = hs.u16()? as usize;
    hs.skip(suites_len)?; // cipher_suites
    let comp_len = hs.u8()? as usize;
    hs.skip(comp_len)?; // legacy_compression_methods

    let ext_total = hs.u16()? as usize;
    let mut exts = hs.sub(ext_total.min(hs.remaining()))?;
    while exts.remaining() >= 4 {
        let ext_type = exts.u16()?;
        let ext_len = exts.u16()? as usize;
        let mut ext = exts.sub(ext_len.min(exts.remaining()))?;
        if ext_type == 0 {
            // ServerNameList: list_len(2), then entries of
            // name_type(1) + name_len(2) + name.
            ext.u16()?;
            let name_type = ext.u8()?;
            let name_len = ext.u16()? as usize;
            let name = ext.bytes(name_len)?;
            if name_type == 0 {
                return Some(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    None
}

/// Read the negotiated cipher suite out of a ServerHello.
fn server_hello_cipher(hs: &mut Reader<'_>) -> Option<u16> {
    hs.u16()?; // legacy_version
    hs.skip(32)?; // random
    let sid_len = hs.u8()? as usize;
    hs.skip(sid_len)?;
    hs.u16()
}

fn content_name(c: u8) -> &'static str {
    match c {
        CONTENT_CHANGE_CIPHER_SPEC => "Change Cipher Spec",
        CONTENT_ALERT => "Alert",
        CONTENT_HANDSHAKE => "Handshake",
        CONTENT_APPLICATION_DATA => "Application Data",
        _ => "Record",
    }
}

fn version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

/// Alert descriptions (RFC 8446 §6). These names are what turn "the VPN
/// is broken" into "the peer rejected our certificate".
fn alert_name(d: u8) -> &'static str {
    match d {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        90 => "user_canceled",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ClientHello record carrying `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // extension: server_name
        let name = sni.as_bytes();
        let sni_body_len = 1 + 2 + name.len();
        ext.extend_from_slice(&((sni_body_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(sni_body_len as u16).to_be_bytes()); // list len
        ext.push(0); // name_type = host_name
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);

        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hs.extend_from_slice(&0x1301u16.to_be_bytes());
        hs.push(1); // compression methods len
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut body = vec![HS_CLIENT_HELLO];
        body.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]); // u24
        body.extend_from_slice(&hs);

        let mut rec = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn sniffs_tls_by_content_not_port() {
        assert!(looks_like_tls(&client_hello("a.example")));
        assert!(!looks_like_tls(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_tls(&[0x16, 0x09, 0x01, 0x00, 0x10]));
        assert!(!looks_like_tls(&[0x16]));
    }

    #[test]
    fn extracts_the_sni_host() {
        let rec = client_hello("api.internal.corp");
        let mut hs_body = Reader::new(&rec[5..]);
        hs_body.u8().unwrap();
        let len = hs_body.u24().unwrap() as usize;
        let mut hs = hs_body.sub(len).unwrap();
        assert_eq!(
            client_hello_sni(&mut hs).as_deref(),
            Some("api.internal.corp")
        );
    }

    #[test]
    fn alert_names_cover_the_failures_engineers_chase() {
        assert_eq!(alert_name(40), "handshake_failure");
        assert_eq!(alert_name(48), "unknown_ca");
        assert_eq!(alert_name(45), "certificate_expired");
        assert_eq!(alert_name(200), "unknown");
    }

    #[test]
    fn version_names_are_right() {
        assert_eq!(version_name(0x0303), "TLS 1.2");
        assert_eq!(version_name(0x0304), "TLS 1.3");
    }

    /// A truncated or hostile handshake must never panic and never read
    /// past its declared inner length.
    #[test]
    fn arbitrary_handshake_bytes_never_panic() {
        proptest::proptest!(|(b: Vec<u8>)| {
            let mut r = Reader::new(&b);
            let _ = client_hello_sni(&mut r);
            let mut r2 = Reader::new(&b);
            let _ = server_hello_cipher(&mut r2);
        });
    }

    /// Every prefix of a real ClientHello — i.e. every way a snaplen can
    /// cut it — must parse to *something* without panicking.
    #[test]
    fn every_truncation_of_a_client_hello_is_safe() {
        let full = client_hello("www.example.com");
        for n in 0..full.len() {
            let mut r = Reader::new(&full[..n]);
            let _ = r.u8();
            let mut r2 = Reader::new(&full[..n]);
            let _ = client_hello_sni(&mut r2);
        }
    }
}
