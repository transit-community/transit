//! Routing protocols: BGP (RFC 4271) and OSPFv2 (RFC 2328).
//!
//! Both are here for one question each, and both answers live in a
//! handful of header bytes:
//!
//! - **BGP**: *why did the session drop?* A NOTIFICATION carries an error
//!   code and subcode that name the cause outright — hold timer expired,
//!   bad peer AS, administrative shutdown — and it is the last thing a
//!   dying session sends.
//! - **OSPF**: *why won't they form an adjacency?* Mismatched area ids,
//!   hello/dead intervals or authentication show up in the Hello packets
//!   long before the neighbour state machine gives up.

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

/// BGP messages start with a 16-byte all-ones marker (RFC 4271 §4.1).
/// Checking it is what lets us dissect BGP on a non-standard port
/// without misreading an arbitrary TCP stream as one.
const BGP_MARKER: [u8; 16] = [0xff; 16];

pub(crate) fn looks_like_bgp(payload: &[u8]) -> bool {
    payload.len() >= 19 && payload[..16] == BGP_MARKER
}

pub(crate) fn dissect_bgp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Bgp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(_marker), Some(len), Some(msg_type)) = (r.bytes(16), r.u16(), r.u8()) else {
        return;
    };

    let mut l = Layer::new(Proto::Bgp, format!("BGP {}", bgp_type_name(msg_type)));
    l.push(Field::u64("bgp.type", "Message type", u64::from(msg_type)))
        .push(Field::text(
            "bgp.type.name",
            "Message type name",
            bgp_type_name(msg_type),
        ))
        .push(Field::u64("bgp.len", "Length", u64::from(len)));

    let mut info = format!("BGP {}", bgp_type_name(msg_type));

    match msg_type {
        1 => {
            // OPEN: version(1) my_as(2) holdtime(2) bgp_id(4) opt_len(1)
            if let (Some(version), Some(asn), Some(hold), Some(id)) =
                (r.u8(), r.u16(), r.u16(), r.ipv4())
            {
                l.push(Field::u64(
                    "bgp.open.version",
                    "Version",
                    u64::from(version),
                ))
                .push(Field::u64("bgp.open.myas", "My AS", u64::from(asn)))
                .push(Field::u64(
                    "bgp.open.holdtime",
                    "Hold time",
                    u64::from(hold),
                ))
                .push(Field::ip(
                    "bgp.open.identifier",
                    "BGP identifier",
                    id.into(),
                ));
                info = format!("BGP OPEN  AS{asn}  hold {hold}s  id {id}");
            }
        }
        3 => {
            // NOTIFICATION: the answer to "why did the session drop".
            if let (Some(major), Some(minor)) = (r.u8(), r.u8()) {
                let reason = notification_reason(major, minor);
                l.push(Field::u64(
                    "bgp.notify.major_error",
                    "Error code",
                    u64::from(major),
                ))
                .push(Field::u64(
                    "bgp.notify.minor_error",
                    "Error subcode",
                    u64::from(minor),
                ))
                .push(Field::text("bgp.notify.reason", "Reason", reason));
                info = format!("BGP NOTIFICATION  {reason}");
            }
        }
        2 => {
            // UPDATE: withdrawn(2) + routes, then path attrs. The counts
            // are what an engineer scans for during a churn event; the
            // NLRI itself is a whole parser and is not decoded here.
            if let Some(withdrawn_len) = r.u16() {
                l.push(Field::u64(
                    "bgp.update.withdrawn_len",
                    "Withdrawn routes length",
                    u64::from(withdrawn_len),
                ));
                if withdrawn_len > 0 {
                    info = format!("BGP UPDATE  withdrawing {withdrawn_len} bytes of routes");
                }
            }
        }
        _ => {}
    }

    ctx.push_layer(l);
    ctx.set_info(info);
}

fn bgp_type_name(t: u8) -> &'static str {
    match t {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "message",
    }
}

/// RFC 4271 §4.5 error codes, plus the subcodes worth naming.
///
/// These strings are the finding: "hold timer expired" and "peer AS
/// mismatch" are different problems with different fixes, and the wire
/// distinguishes them precisely.
fn notification_reason(major: u8, minor: u8) -> &'static str {
    match (major, minor) {
        (1, _) => "Message header error",
        (2, 1) => "OPEN: unsupported version",
        (2, 2) => "OPEN: bad peer AS",
        (2, 3) => "OPEN: bad BGP identifier",
        (2, 4) => "OPEN: unsupported optional parameter",
        (2, 6) => "OPEN: unacceptable hold time",
        (2, _) => "OPEN message error",
        (3, 1) => "UPDATE: malformed attribute list",
        (3, 2) => "UPDATE: unrecognized well-known attribute",
        (3, 11) => "UPDATE: malformed AS_PATH",
        (3, _) => "UPDATE message error",
        (4, _) => "Hold timer expired",
        (5, _) => "Finite state machine error",
        (6, 2) => "Cease: administrative shutdown",
        (6, 3) => "Cease: peer de-configured",
        (6, 4) => "Cease: administrative reset",
        (6, 5) => "Cease: connection rejected",
        (6, 6) => "Cease: other configuration change",
        (6, 7) => "Cease: connection collision resolution",
        (6, 8) => "Cease: out of resources",
        (6, 1) => "Cease: maximum prefixes reached",
        (6, _) => "Cease",
        _ => "Unknown error",
    }
}

// ---------------------------------------------------------------------
// OSPFv2
// ---------------------------------------------------------------------

pub(crate) fn dissect_ospf(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Ospf);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(version), Some(msg_type), Some(len), Some(router), Some(area)) =
        (r.u8(), r.u8(), r.u16(), r.ipv4(), r.ipv4())
    else {
        return;
    };

    let name = ospf_type_name(msg_type);
    let mut l = Layer::new(Proto::Ospf, format!("OSPF {name}"));
    l.push(Field::u64("ospf.version", "Version", u64::from(version)))
        .push(Field::u64("ospf.msg", "Message type", u64::from(msg_type)))
        .push(Field::text("ospf.msg.name", "Message type name", name))
        .push(Field::u64("ospf.packet_length", "Length", u64::from(len)))
        .push(Field::ip("ospf.srcrouter", "Source router", router.into()))
        .push(Field::ip("ospf.area_id", "Area", area.into()));

    let mut info = format!("OSPF {name}  router {router}  area {area}");

    // Hello carries the timers and masks that must match for an adjacency
    // to form — the usual reason two routers stare at each other.
    if msg_type == 1 {
        let (Some(_checksum), Some(_autype), Some(_auth_hi), Some(_auth_lo)) =
            (r.u16(), r.u16(), r.u32(), r.u32())
        else {
            ctx.push_layer(l);
            ctx.set_info(info);
            return;
        };
        if let (Some(mask), Some(hello_int)) = (r.ipv4(), r.u16()) {
            l.push(Field::ip(
                "ospf.hello.network_mask",
                "Network mask",
                mask.into(),
            ))
            .push(Field::u64(
                "ospf.hello.hello_interval",
                "Hello interval",
                u64::from(hello_int),
            ));
            if let (Some(_opts), Some(prio), Some(dead)) = (r.u8(), r.u8(), r.u32()) {
                l.push(Field::u64(
                    "ospf.hello.router_priority",
                    "Router priority",
                    u64::from(prio),
                ))
                .push(Field::u64(
                    "ospf.hello.router_dead_interval",
                    "Dead interval",
                    u64::from(dead),
                ));
                info = format!(
                    "OSPF Hello  area {area}  hello {hello_int}s  dead {dead}s  prio {prio}"
                );
            }
        }
    }

    ctx.push_layer(l);
    ctx.set_info(info);
}

fn ospf_type_name(t: u8) -> &'static str {
    match t {
        1 => "Hello",
        2 => "Database Description",
        3 => "Link State Request",
        4 => "Link State Update",
        5 => "Link State Acknowledgment",
        _ => "packet",
    }
}

// ---------------------------------------------------------------------
// VRRP (RFC 5798)
// ---------------------------------------------------------------------

pub(crate) fn dissect_vrrp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Vrrp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(vers_type), Some(vrid), Some(prio), Some(count)) = (r.u8(), r.u8(), r.u8(), r.u8())
    else {
        return;
    };
    let version = vers_type >> 4;

    let mut l = Layer::new(Proto::Vrrp, format!("VRRP group {vrid} priority {prio}"));
    l.push(Field::u64("vrrp.version", "Version", u64::from(version)))
        .push(Field::u64(
            "vrrp.virt_rtr_id",
            "Virtual router id",
            u64::from(vrid),
        ))
        // Priority is the whole story in a redundancy investigation: 255
        // is the address owner, 0 means "I am resigning", and a pair of
        // routers trading advertisements at the same priority is a
        // misconfiguration.
        .push(Field::u64("vrrp.prio", "Priority", u64::from(prio)))
        .push(Field::u64(
            "vrrp.ip_count",
            "Address count",
            u64::from(count),
        ));

    let note = match prio {
        0 => "  (resigning)",
        255 => "  (address owner)",
        _ => "",
    };
    ctx.push_layer(l);
    ctx.set_info(format!("VRRP  group {vrid}  priority {prio}{note}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bgp_message_is_recognized_by_its_marker() {
        let mut msg = vec![0xffu8; 16];
        msg.extend_from_slice(&19u16.to_be_bytes());
        msg.push(4); // KEEPALIVE
        assert!(looks_like_bgp(&msg));

        // An arbitrary TCP stream must not be read as BGP.
        assert!(!looks_like_bgp(b"GET / HTTP/1.1\r\n\r\nxxxxx"));
        assert!(!looks_like_bgp(&[0u8; 32]));
        assert!(!looks_like_bgp(&[0xff; 8]));
    }

    #[test]
    fn notification_reasons_name_the_actual_cause() {
        // These are the ones an engineer is looking for, and they are
        // different problems with different fixes.
        assert_eq!(notification_reason(4, 0), "Hold timer expired");
        assert_eq!(notification_reason(2, 2), "OPEN: bad peer AS");
        assert_eq!(notification_reason(6, 2), "Cease: administrative shutdown");
        assert_eq!(notification_reason(6, 1), "Cease: maximum prefixes reached");
        assert_eq!(notification_reason(99, 0), "Unknown error");
    }

    #[test]
    fn message_and_packet_type_names_are_right() {
        assert_eq!(bgp_type_name(1), "OPEN");
        assert_eq!(bgp_type_name(3), "NOTIFICATION");
        assert_eq!(bgp_type_name(9), "message");
        assert_eq!(ospf_type_name(1), "Hello");
        assert_eq!(ospf_type_name(4), "Link State Update");
    }
}
