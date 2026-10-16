//! DNS (RFC 1035) and mDNS (RFC 6762).
//!
//! DNS is the highest-value dissector in the set: "is name resolution
//! broken" is the single most common question a capture gets opened to
//! answer, and NXDOMAIN counts, unanswered queries and response times are
//! what the digest reports back.
//!
//! # The compression-pointer loop
//!
//! RFC 1035 §4.1.4 lets a name end in a pointer to an earlier offset in
//! the same message. A hostile message can point a name at itself, or set
//! up a two-pointer cycle, and a naive parser follows it forever. That is
//! the classic DNS-parser denial of service and it is trivially reachable
//! here — the packet came off the wire. [`read_name`] bounds both the
//! number of jumps and the assembled length, so the worst a malicious
//! message achieves is a truncated name.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

/// Hard ceiling on compression-pointer jumps. RFC 1035 caps a name at 255
/// bytes and each jump must point strictly backwards, so a legitimate
/// message never needs many; this is purely the loop breaker.
const MAX_NAME_JUMPS: usize = 16;

/// RFC 1035 §2.3.4: a name is at most 255 octets.
const MAX_NAME_LEN: usize = 255;

/// Cap on records decoded per section. A message declaring 65,535 answers
/// would otherwise cost 65,535 name parses; nothing real exceeds a
/// handful, and the count fields are still reported honestly.
const MAX_RECORDS_PER_SECTION: u16 = 32;

pub(crate) fn dissect(ctx: &mut Ctx<'_>, payload: &[u8], proto: Proto) {
    let mut r = Reader::new(payload);
    let (Some(id), Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) =
        (r.u16(), r.u16(), r.u16(), r.u16(), r.u16(), r.u16())
    else {
        // Too short to be a DNS header. Marking the protocol without
        // fields still tells the analyst what port it was on.
        ctx.mark(proto);
        return;
    };

    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;

    ctx.mark(proto);
    if !ctx.full() {
        return;
    }

    // Questions first — the query name is what the analyst reads.
    let mut qname = String::new();
    let mut qtype = 0u16;
    for i in 0..qd.min(MAX_RECORDS_PER_SECTION) {
        let Some(name) = read_name(payload, &mut r) else {
            break;
        };
        let (Some(ty), Some(_class)) = (r.u16(), r.u16()) else {
            break;
        };
        if i == 0 {
            qname = name;
            qtype = ty;
        }
    }

    // Answers: enough to say what the response actually resolved to.
    let mut answers: Vec<String> = Vec::new();
    for _ in 0..an.min(MAX_RECORDS_PER_SECTION) {
        let Some(_name) = read_name(payload, &mut r) else {
            break;
        };
        let (Some(ty), Some(_class), Some(_ttl), Some(rdlen)) =
            (r.u16(), r.u16(), r.u32(), r.u16())
        else {
            break;
        };
        let Some(rdata) = r.bytes(rdlen as usize) else {
            break;
        };
        if let Some(rendered) = render_rdata(ty, rdata, payload) {
            answers.push(rendered);
        }
    }

    let label = if is_response {
        format!("DNS response  {} {}", type_name(qtype), qname)
    } else {
        format!("DNS query  {} {}", type_name(qtype), qname)
    };
    let mut l = Layer::new(proto, label);
    l.push(Field::u64("dns.id", "Transaction ID", u64::from(id)))
        .push(Field::bool(
            "dns.flags.response",
            "Is a response",
            is_response,
        ))
        .push(Field::u64("dns.flags.opcode", "Opcode", u64::from(opcode)))
        .push(Field::bool("dns.flags.truncated", "Truncated", truncated))
        .push(Field::bool(
            "dns.flags.authoritative",
            "Authoritative",
            flags & 0x0400 != 0,
        ))
        .push(Field::bool(
            "dns.flags.recdesired",
            "Recursion desired",
            flags & 0x0100 != 0,
        ))
        // rcode is the field the digest counts NXDOMAINs with, so it is
        // both the number and the name — `dns.rcode != 0` is the filter
        // an engineer reaches for.
        .push(Field::u64("dns.rcode", "Response code", u64::from(rcode)))
        .push(Field::text(
            "dns.rcode.name",
            "Response code name",
            rcode_name(rcode),
        ))
        .push(Field::u64("dns.count.queries", "Questions", u64::from(qd)))
        .push(Field::u64("dns.count.answers", "Answer RRs", u64::from(an)))
        .push(Field::u64(
            "dns.count.auth_rr",
            "Authority RRs",
            u64::from(ns),
        ))
        .push(Field::u64(
            "dns.count.add_rr",
            "Additional RRs",
            u64::from(ar),
        ));
    if !qname.is_empty() {
        l.push(Field::text("dns.qry.name", "Query name", &qname))
            .push(Field::u64("dns.qry.type", "Query type", u64::from(qtype)))
            .push(Field::text(
                "dns.qry.type.name",
                "Query type name",
                type_name(qtype),
            ));
    }
    if let Some(first) = answers.first() {
        l.push(Field::text("dns.resp.first", "First answer", first));
    }
    ctx.push_layer(l);

    let verb = if is_response { "response" } else { "query" };
    let mut info = format!("Standard {verb} 0x{id:04x} {} {qname}", type_name(qtype));
    if is_response {
        if rcode != 0 {
            info.push_str(&format!("  {}", rcode_name(rcode)));
        } else if !answers.is_empty() {
            info.push_str(&format!("  {}", answers.join(" ")));
        }
    }
    ctx.set_info(info);
}

/// Read a possibly-compressed domain name.
///
/// Returns the dotted name. Bounded three ways — jump count, assembled
/// length, and each label's own length — so a message with a pointer
/// cycle terminates with a partial name instead of hanging the indexer.
///
/// `r` advances past the name *as encoded at the current position*: when
/// a pointer is taken, the reader stops just past the pointer, which is
/// what the wire format requires for the fields that follow.
fn read_name<'a>(msg: &'a [u8], r: &mut Reader<'a>) -> Option<String> {
    let mut out = String::new();
    let mut jumps = 0usize;
    // Position we are reading labels from; starts as the reader's own
    // cursor and moves to pointer targets after the first jump.
    let mut walker: Option<Reader<'_>> = None;

    loop {
        let cur = walker.as_mut().unwrap_or(r);
        let len = cur.u8()?;

        match len & 0xC0 {
            0 => {
                if len == 0 {
                    return Some(out);
                }
                let label = cur.bytes(len as usize)?;
                if out.len() + label.len() + 1 > MAX_NAME_LEN {
                    // Over the RFC ceiling: stop and keep what we have
                    // rather than growing an unbounded string.
                    out.push('…');
                    return Some(out);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&String::from_utf8_lossy(label));
            }
            0xC0 => {
                let lo = cur.u8()?;
                let target = (u16::from(len & 0x3F) << 8) | u16::from(lo);
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    // A pointer cycle. Bail with what we assembled.
                    return Some(out);
                }
                let target = target as usize;
                if target >= msg.len() {
                    return Some(out);
                }
                walker = Some(Reader::new(&msg[target..]));
            }
            // 0x40 and 0x80 are reserved label types (RFC 6891 retired
            // the one that used them). Anything here is malformed.
            _ => return Some(out),
        }
    }
}

/// Render an answer record's RDATA for the types worth showing inline.
fn render_rdata(ty: u16, rdata: &[u8], msg: &[u8]) -> Option<String> {
    match ty {
        1 => <[u8; 4]>::try_from(rdata)
            .ok()
            .map(|b| format!("A {}", Ipv4Addr::from(b))),
        28 => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|b| format!("AAAA {}", Ipv6Addr::from(b))),
        5 => {
            let mut r = Reader::new(rdata);
            read_name(msg, &mut r).map(|n| format!("CNAME {n}"))
        }
        12 => {
            let mut r = Reader::new(rdata);
            read_name(msg, &mut r).map(|n| format!("PTR {n}"))
        }
        _ => None,
    }
}

/// RR type names. Derived from the IANA DNS Parameters registry, which
/// is the normative source these two-byte codes come from.
fn type_name(ty: u16) -> &'static str {
    match ty {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        48 => "DNSKEY",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        _ => "TYPE",
    }
}

/// RCODE names (RFC 1035 §4.1.1, extended by RFC 6895).
fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        6 => "Name exists when it should not",
        9 => "Not authoritative",
        10 => "Name not in zone",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a dotted name in wire format.
    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in n.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn reads_an_uncompressed_name() {
        let msg = name("www.example.com");
        let mut r = Reader::new(&msg);
        assert_eq!(read_name(&msg, &mut r).unwrap(), "www.example.com");
    }

    #[test]
    fn follows_a_compression_pointer() {
        // "example.com" at offset 0, then a name that is "www" + a
        // pointer back to offset 0.
        let mut msg = name("example.com");
        let base = msg.len();
        msg.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x00]);

        let mut r = Reader::new(&msg[base..]);
        assert_eq!(read_name(&msg, &mut r).unwrap(), "www.example.com");
    }

    /// The DoS case. A pointer to itself must terminate.
    #[test]
    fn a_self_referential_pointer_terminates() {
        let msg = vec![0xC0, 0x00];
        let mut r = Reader::new(&msg);
        let got = read_name(&msg, &mut r);
        assert!(got.is_some(), "must return, not hang");
    }

    #[test]
    fn a_two_pointer_cycle_terminates() {
        // Offset 0 points to 2; offset 2 points to 0.
        let msg = vec![0xC0, 0x02, 0xC0, 0x00];
        let mut r = Reader::new(&msg);
        assert!(read_name(&msg, &mut r).is_some());
    }

    #[test]
    fn a_pointer_past_the_end_terminates() {
        let msg = vec![0xC0, 0xFF];
        let mut r = Reader::new(&msg);
        assert!(read_name(&msg, &mut r).is_some());
    }

    /// A chain of labels engineered to exceed the RFC name ceiling must
    /// stop growing rather than assemble an unbounded string.
    #[test]
    fn an_overlong_name_is_clamped() {
        let mut msg = Vec::new();
        for _ in 0..40 {
            msg.push(60u8);
            msg.extend_from_slice(&[b'a'; 60]);
        }
        msg.push(0);
        let mut r = Reader::new(&msg);
        let got = read_name(&msg, &mut r).unwrap();
        assert!(
            got.len() <= MAX_NAME_LEN + 8,
            "name grew to {} bytes",
            got.len()
        );
    }

    #[test]
    fn type_and_rcode_names_cover_the_common_cases() {
        assert_eq!(type_name(1), "A");
        assert_eq!(type_name(28), "AAAA");
        assert_eq!(type_name(9999), "TYPE");
        assert_eq!(rcode_name(0), "No error");
        assert_eq!(rcode_name(3), "No such name");
        assert_eq!(rcode_name(200), "Unknown");
    }

    /// A name assembled from attacker-chosen bytes must never panic and
    /// must always terminate, whatever the pointer structure.
    #[test]
    fn arbitrary_name_bytes_terminate_without_panicking() {
        proptest::proptest!(|(msg: Vec<u8>)| {
            let mut r = Reader::new(&msg);
            let _ = read_name(&msg, &mut r);
        });
    }
}
