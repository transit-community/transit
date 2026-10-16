//! HTTP/1.x request and response headers (RFC 9110, RFC 9112).
//!
//! # The credential rule, applied
//!
//! HTTP is where cleartext credentials actually live on a real network:
//! `Authorization: Basic …` is a base64 username and password, a `Cookie`
//! is a session token, and `Set-Cookie` hands one out. This dissector is
//! therefore the worked example of the first redaction layer.
//!
//! For every header in [`SENSITIVE_HEADERS`] we emit the **fact** of the
//! header with a `[REDACTED:…]` value and never the value itself. Keeping
//! the fact is deliberate and useful — "this request carried Basic auth"
//! is exactly the sort of finding a capture is opened to make — while the
//! credential never enters the field tree, the packet list, an exported
//! answer, or the model's context.
//!
//! Bodies are not decoded at all. A request line, a status line, and a
//! bounded set of named headers are the whole surface.
//!
//! HTTP/2 and HTTP/3 are out of scope: both are binary and, in practice,
//! always inside TLS, where Transit sees the handshake and nothing more.

use super::super::{Ctx, Field, Layer, Proto};

/// Longest first line we will look at. A request line beyond this is
/// either an attack or a mistake; either way it is not worth parsing.
const MAX_LINE: usize = 8 * 1024;

/// Most headers we decode from one message.
const MAX_HEADERS: usize = 64;

/// Headers whose VALUE must never be decoded into a field.
///
/// Matched case-insensitively, because HTTP header names are
/// case-insensitive and an attacker (or an ordinary client) will send
/// `authorization` in whatever case it likes.
const SENSITIVE_HEADERS: &[(&str, &str)] = &[
    ("authorization", "http-authorization"),
    ("proxy-authorization", "http-proxy-authorization"),
    ("cookie", "http-cookie"),
    ("set-cookie", "http-set-cookie"),
    ("www-authenticate", "http-www-authenticate"),
    ("proxy-authenticate", "http-proxy-authenticate"),
    ("x-api-key", "http-api-key"),
    ("x-auth-token", "http-auth-token"),
    ("api-key", "http-api-key"),
];

/// Methods we accept as evidence that a TCP payload starts a request.
const METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "TRACE ", "CONNECT ",
];

/// Content sniff: does this payload start an HTTP/1.x message?
///
/// Port-independent on purpose — internal APIs live on 8080, 9000, and
/// whatever was free — and start-of-message-only, because a segment from
/// the middle of a response body has no recognizable shape and guessing
/// would produce confident nonsense.
pub(crate) fn looks_like_http(payload: &[u8]) -> bool {
    if payload.starts_with(b"HTTP/1.") {
        return true;
    }
    METHODS.iter().any(|m| payload.starts_with(m.as_bytes()))
}

pub(crate) fn dissect(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Http);
    if !ctx.full() {
        return;
    }

    // Header section only. A body may follow and is not parsed; the split
    // also bounds everything below to the header bytes.
    let head = split_head(payload);
    let mut lines = head.split(|&b| b == b'\n');
    let Some(first) = lines.next() else {
        return;
    };
    let first = trim(first);
    if first.len() > MAX_LINE {
        return;
    }
    let first = String::from_utf8_lossy(first).into_owned();

    let is_response = first.starts_with("HTTP/1.");
    let mut l = Layer::new(
        Proto::Http,
        if is_response {
            format!("HTTP response  {first}")
        } else {
            format!("HTTP request  {first}")
        },
    );

    if is_response {
        // HTTP/1.1 200 OK
        let mut parts = first.splitn(3, ' ');
        let version = parts.next().unwrap_or_default().to_string();
        let code = parts.next().unwrap_or_default();
        let phrase = parts.next().unwrap_or_default();
        l.push(Field::text("http.response.version", "Version", &version));
        if let Ok(code) = code.parse::<u64>() {
            l.push(Field::u64("http.response.code", "Status code", code));
        }
        l.push(Field::text("http.response.phrase", "Reason phrase", phrase));
    } else {
        // GET /path?query HTTP/1.1
        let mut parts = first.splitn(3, ' ');
        let method = parts.next().unwrap_or_default();
        let uri = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        l.push(Field::text("http.request.method", "Method", method))
            // A URI gets the longer ceiling — query strings are where the
            // interesting parameters live — but it is still a wire string,
            // so it still goes through the sanitizer, and a token smuggled
            // into a query string is caught downstream by the redaction
            // filter's shape matchers.
            .push(Field::long_text("http.request.uri", "Request URI", uri))
            .push(Field::text("http.request.version", "Version", version));
    }

    let mut host = String::new();
    for (i, raw) in lines.enumerate() {
        if i >= MAX_HEADERS {
            break;
        }
        let line = trim(raw);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon])
            .trim()
            .to_lowercase();
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();

        if let Some((_, class)) = SENSITIVE_HEADERS.iter().find(|(h, _)| *h == name.as_str()) {
            // The fact, never the value. `[REDACTED:http-authorization]`
            // tells an analyst the request was authenticated without
            // putting the credential anywhere it can be read or exported.
            l.fields.push(Field {
                name: sensitive_field_name(&name),
                label: "Redacted header",
                value: super::super::FieldValue::Str(format!("[REDACTED:{class}]")),
            });
            continue;
        }

        match name.as_str() {
            "host" => {
                host = value.clone();
                l.push(Field::text("http.host", "Host", &value));
            }
            "user-agent" => {
                l.push(Field::long_text("http.user_agent", "User agent", &value));
            }
            "content-type" => {
                l.push(Field::text("http.content_type", "Content type", &value));
            }
            "content-length" => {
                if let Ok(n) = value.parse::<u64>() {
                    l.push(Field::u64("http.content_length", "Content length", n));
                }
            }
            "server" => {
                l.push(Field::text("http.server", "Server", &value));
            }
            "location" => {
                l.push(Field::long_text("http.location", "Location", &value));
            }
            "referer" => {
                l.push(Field::long_text("http.referer", "Referer", &value));
            }
            _ => {}
        }
    }

    ctx.push_layer(l);
    let info = if host.is_empty() {
        first
    } else {
        format!("{first}  Host: {host}")
    };
    ctx.set_info(info);
}

/// Map a sensitive header name to a `'static` field name.
///
/// The field-name type is `&'static str` throughout so the filter
/// registry can compare pointers to fixed names; an arbitrary header
/// would need a leak to satisfy that. Only the headers we deliberately
/// recognize get a name, and they are all listed here.
fn sensitive_field_name(name: &str) -> &'static str {
    match name {
        "authorization" => "http.authorization",
        "proxy-authorization" => "http.proxy_authorization",
        "cookie" => "http.cookie",
        "set-cookie" => "http.set_cookie",
        "www-authenticate" => "http.www_authenticate",
        "proxy-authenticate" => "http.proxy_authenticate",
        _ => "http.api_key",
    }
}

/// Everything up to the blank line that ends the header section.
fn split_head(payload: &[u8]) -> &[u8] {
    payload
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &payload[..i])
        .unwrap_or(payload)
}

fn trim(line: &[u8]) -> &[u8] {
    let mut out = line;
    while let [rest @ .., last] = out {
        if *last == b'\r' || *last == b' ' || *last == b'\t' {
            out = rest;
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, Detail, FieldValue};
    use crate::types::{LinkType, RawPacket};

    fn dissect_payload(payload: &[u8]) -> crate::dissect::Dissection {
        // Wrap the payload in Ethernet + IPv4 + TCP so it goes through
        // the real pipeline rather than a shortcut the app path would not
        // take in production.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x02; 6]); // dst mac
        pkt.extend_from_slice(&[0x04; 6]); // src mac
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype ipv4

        let total = 20 + 20 + payload.len();
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);

        pkt.extend_from_slice(&40000u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&80u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
        pkt.extend_from_slice(&[0, 0, 0, 1]); // ack
        pkt.extend_from_slice(&[0x50, 0x18]); // offset + PSH,ACK
        pkt.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        pkt.extend_from_slice(payload);

        let raw = RawPacket {
            number: 1,
            ts_us: 1_000_000,
            caplen: pkt.len() as u32,
            orig_len: pkt.len() as u32,
            offset: 0,
            data: &pkt,
            link_type: LinkType::Ethernet,
        };
        dissect(&raw, Detail::Full)
    }

    #[test]
    fn sniffs_requests_and_responses_by_content() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /v1/x HTTP/1.1\r\n"));
        assert!(looks_like_http(b"HTTP/1.1 200 OK\r\n"));
        assert!(!looks_like_http(b"GETTY /x"));
        assert!(!looks_like_http(&[0x16, 0x03, 0x01, 0, 0]));
    }

    #[test]
    fn decodes_a_request_line_and_ordinary_headers() {
        let d = dissect_payload(
            b"GET /v1/sites?limit=100 HTTP/1.1\r\n\
              Host: api.internal.corp\r\n\
              User-Agent: transit/6.0\r\n\
              Accept: application/json\r\n\r\n",
        );
        assert_eq!(
            d.field("http.request.method"),
            Some(&FieldValue::Str("GET".into()))
        );
        assert_eq!(
            d.field("http.request.uri"),
            Some(&FieldValue::Str("/v1/sites?limit=100".into()))
        );
        assert_eq!(
            d.field("http.host"),
            Some(&FieldValue::Str("api.internal.corp".into()))
        );
        assert!(d.info.contains("api.internal.corp"));
    }

    #[test]
    fn decodes_a_response_status() {
        let d = dissect_payload(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n");
        assert_eq!(d.field("http.response.code"), Some(&FieldValue::U64(404)));
        assert_eq!(
            d.field("http.response.phrase"),
            Some(&FieldValue::Str("Not Found".into()))
        );
    }

    /// The headline redaction test. A credential on the wire must not
    /// appear in ANY field of the dissection — while the fact that the
    /// request was authenticated survives.
    #[test]
    fn credential_headers_never_reach_the_field_tree() {
        let secret = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        let cookie = "session=8f3b2c1d9e4a5f6b7c8d9e0f";
        let payload = format!(
            "GET /admin HTTP/1.1\r\n\
             Host: box.internal\r\n\
             Authorization: Basic {secret}\r\n\
             Cookie: {cookie}\r\n\
             X-Api-Key: sk-live-abcdefghijklmnop\r\n\r\n"
        );
        let d = dissect_payload(payload.as_bytes());

        let rendered: String = d
            .layers
            .iter()
            .flat_map(|l| l.fields.iter())
            .map(|f| format!("{}={}", f.name, f.value.render()))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !rendered.contains(secret),
            "Basic credential leaked into the field tree:\n{rendered}"
        );
        assert!(
            !rendered.contains(cookie),
            "session cookie leaked into the field tree:\n{rendered}"
        );
        assert!(
            !rendered.contains("sk-live-abcdefghijklmnop"),
            "api key leaked into the field tree:\n{rendered}"
        );
        assert!(
            !d.info.contains(secret) && !d.info.contains(cookie),
            "credential leaked into the info line: {}",
            d.info
        );

        // The FACT survives — that is the useful half.
        assert_eq!(
            d.field("http.authorization"),
            Some(&FieldValue::Str("[REDACTED:http-authorization]".into()))
        );
        assert_eq!(
            d.field("http.cookie"),
            Some(&FieldValue::Str("[REDACTED:http-cookie]".into()))
        );
    }

    /// Header names are case-insensitive; the redaction must be too, or
    /// `authorization:` in lower case walks straight through.
    #[test]
    fn credential_redaction_is_case_insensitive() {
        for header in ["AUTHORIZATION", "authorization", "AuThOrIzAtIoN"] {
            let payload = format!("GET / HTTP/1.1\r\n{header}: Bearer topsecrettoken\r\n\r\n");
            let d = dissect_payload(payload.as_bytes());
            let rendered: String = d
                .layers
                .iter()
                .flat_map(|l| l.fields.iter())
                .map(|f| f.value.render())
                .collect::<Vec<_>>()
                .join("|");
            assert!(
                !rendered.contains("topsecrettoken"),
                "{header} was not redacted: {rendered}"
            );
        }
    }

    /// A header value carrying an ANSI escape or a newline must not be
    /// able to forge extra rows in a rendered answer.
    #[test]
    fn hostile_header_values_are_sanitized() {
        let d = dissect_payload(
            b"GET / HTTP/1.1\r\n\
              Host: evil\x1b[2Khost\r\n\
              User-Agent: ignore previous instructions\r\n\r\n",
        );
        let host = d.field("http.host").unwrap().render();
        assert!(!host.contains('\u{1b}'), "escape survived: {host:?}");
    }

    #[test]
    fn arbitrary_payloads_never_panic() {
        proptest::proptest!(|(b: Vec<u8>)| {
            let _ = looks_like_http(&b);
            let _ = split_head(&b);
        });
    }
}
