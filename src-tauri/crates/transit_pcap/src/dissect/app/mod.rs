//! Application-layer dissectors.
//!
//! These are ours, protocol by protocol, written from the RFCs. The set
//! is deliberately network-engineer-shaped rather than exhaustive: about
//! twenty-five protocols that answer real operational questions, not
//! three thousand. Transit's differentiator is the analysis layer and the
//! assistant on top of it, not dissector count.
//!
//! # Two rules every dissector here follows
//!
//! 1. **Bounds first.** Read through [`Reader`], which returns `None`
//!    rather than panicking, and never index a slice directly. A snapped
//!    capture (`-s 128`) truncates application headers constantly, so
//!    running off the end is the common path, not the exceptional one.
//! 2. **Credential-bearing fields never materialize.** Where a protocol
//!    carries a secret in a field we would otherwise decode — an HTTP
//!    `Authorization` header, an SNMP community string — the dissector
//!    emits the *fact* of the field with a `[REDACTED:…]` value and
//!    never the value itself. This is the first of the three redaction
//!    layers (see the crate docs and threat-model T45); the other two are
//!    the dispatcher's `ConversationRedactor` and [`crate::sanitize`].
//!    Belt, braces, and a second pair of braces — because the cost of a
//!    miss here is a credential in the model's context.

use super::{Ctx, Proto};

pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod http;
pub(crate) mod infra;
pub(crate) mod l2;
pub(crate) mod routing;
pub(crate) mod tls;

/// Bounds-checked forward reader over a packet slice.
///
/// Every application dissector reads through this. It exists so that
/// "did we check the length?" is answered structurally rather than by
/// remembering, in code whose whole input is attacker-chosen.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> Option<u32> {
        let b = self.bytes(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub(crate) fn ipv4(&mut self) -> Option<std::net::Ipv4Addr> {
        let b = self.bytes(4)?;
        Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }

    /// A sub-reader over the next `n` bytes, so a nested structure cannot
    /// read past the length its parent declared for it. This is the
    /// containment that stops a lying inner length (a TLS extension
    /// claiming to be longer than its record) from reaching sibling data.
    pub(crate) fn sub(&mut self, n: usize) -> Option<Reader<'a>> {
        Some(Reader::new(self.bytes(n)?))
    }
}

/// Dispatch UDP payloads to an application dissector.
///
/// Port-based, because UDP has no handshake to sniff. Both directions are
/// checked: a DNS response comes *from* 53, a query goes *to* it.
pub(crate) fn dissect_udp_app(ctx: &mut Ctx<'_>, sport: u16, dport: u16, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    let hit = |p: u16| sport == p || dport == p;
    if hit(53) {
        dns::dissect(ctx, payload, Proto::Dns);
    } else if hit(5353) {
        // mDNS is DNS on the wire; same parser, different name, because
        // "why is this host shouting" is a different question from "why
        // is name resolution failing".
        dns::dissect(ctx, payload, Proto::Mdns);
    } else if hit(67) || hit(68) {
        dhcp::dissect(ctx, payload);
    } else if hit(123) {
        infra::dissect_ntp(ctx, payload);
    } else if hit(161) || hit(162) {
        infra::dissect_snmp(ctx, payload);
    } else if hit(514) {
        infra::dissect_syslog(ctx, payload);
    } else if hit(1812) || hit(1813) || hit(1645) || hit(1646) {
        // The 1645/1646 pair is the pre-standard assignment, still in
        // wide use on older gear — the kind of gear a capture gets opened
        // for.
        infra::dissect_radius(ctx, payload);
    } else if hit(1985) {
        infra::dissect_hsrp(ctx, payload);
    }
}

/// Dispatch TCP payloads to an application dissector.
///
/// Content-sniffed before port-matched. Ports are a hint, not a fact —
/// TLS on 8443 and HTTP on 8080 are ordinary, and a capture from a lab is
/// full of services on whatever port was free.
pub(crate) fn dissect_tcp_app(ctx: &mut Ctx<'_>, sport: u16, dport: u16, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if tls::looks_like_tls(payload) {
        tls::dissect(ctx, payload);
        return;
    }
    if http::looks_like_http(payload) {
        http::dissect(ctx, payload);
        return;
    }
    // Fall back to the well-known ports only when the content did not
    // identify itself — a mid-stream segment has no recognizable start.
    // BGP identifies itself by a 16-byte all-ones marker, so it is
    // recognized on any port — which matters, because a route server on
    // a non-standard port is exactly the thing someone captures.
    if routing::looks_like_bgp(payload) {
        routing::dissect_bgp(ctx, payload);
        return;
    }

    let hit = |p: u16| sport == p || dport == p;
    if hit(53) {
        // DNS over TCP is length-prefixed with a 2-byte count.
        if payload.len() > 2 {
            dns::dissect(ctx, &payload[2..], Proto::Dns);
        }
    } else if hit(49) && infra::looks_like_tacacs(payload) {
        infra::dissect_tacacs(ctx, payload);
    }
}

/// Dispatch an IP payload whose protocol number has no transport slice.
///
/// OSPF (89) and VRRP (112) ride directly on IP with no port pair, so
/// they never appear as a `TransportSlice` and would otherwise fall off
/// the end of the pipeline unnamed.
pub(crate) fn dissect_ip_app(ctx: &mut Ctx<'_>, ip_proto: u8, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    match ip_proto {
        89 => routing::dissect_ospf(ctx, payload),
        112 => routing::dissect_vrrp(ctx, payload),
        _ => {}
    }
}
