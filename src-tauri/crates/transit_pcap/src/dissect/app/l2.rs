//! Layer-2 discovery and topology: LLDP, CDP, STP.
//!
//! These three answer the questions you cannot answer from a routing
//! table: *what is actually plugged in where*, and *why did the network
//! pause for thirty seconds*.
//!
//! # They do not arrive the way everything else does
//!
//! LLDP has its own EtherType (0x88CC), but **CDP and STP are 802.3 LLC
//! frames** — the two bytes where an Ethernet II frame keeps its
//! EtherType hold a *length* instead, so a parser that reads them as a
//! type sees garbage and gives up. That is why [`super::super::Ctx`]
//! checks for these before handing the frame to the general path: they
//! would otherwise be invisible, and "no CDP in this capture" is a
//! conclusion an engineer would act on.

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

/// The multicast address CDP is sent to.
pub(crate) const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
/// The multicast address spanning-tree BPDUs are sent to.
pub(crate) const STP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
/// EtherType for LLDP.
pub(crate) const LLDP_ETHERTYPE: u16 = 0x88cc;
/// The largest value the type/length field can hold as a LENGTH. Above
/// this it is an EtherType (RFC 894 / 802.3).
pub(crate) const MAX_802_3_LENGTH: u16 = 1500;

// ---------------------------------------------------------------------
// LLDP (IEEE 802.1AB)
// ---------------------------------------------------------------------

/// Cap on TLVs walked. The TLV chain is length-driven and the lengths
/// come off the wire.
const MAX_TLVS: usize = 64;

pub(crate) fn dissect_lldp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Lldp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let mut l = Layer::new(Proto::Lldp, "LLDP");
    let mut system = String::new();
    let mut port = String::new();

    for _ in 0..MAX_TLVS {
        // type(7 bits) + length(9 bits), packed into two bytes.
        let Some(header) = r.u16() else { break };
        let tlv_type = (header >> 9) as u8;
        let tlv_len = usize::from(header & 0x01ff);
        if tlv_type == 0 {
            break; // End of LLDPDU
        }
        let Some(value) = r.bytes(tlv_len) else { break };

        match tlv_type {
            1 => {
                // Chassis ID: subtype(1) then the id.
                if let Some(id) = value.split_first() {
                    l.push(Field::text(
                        "lldp.chassis.id",
                        "Chassis id",
                        &render_id(*id.0, id.1),
                    ));
                }
            }
            2 => {
                if let Some(id) = value.split_first() {
                    port = render_id(*id.0, id.1);
                    l.push(Field::text("lldp.port.id", "Port id", &port));
                }
            }
            3 if value.len() >= 2 => {
                l.push(Field::u64(
                    "lldp.time.to.live",
                    "Time to live",
                    u64::from(u16::from_be_bytes([value[0], value[1]])),
                ));
            }
            4 => {
                l.push(Field::text(
                    "lldp.port.desc",
                    "Port description",
                    &String::from_utf8_lossy(value),
                ));
            }
            5 => {
                system = String::from_utf8_lossy(value).into_owned();
                l.push(Field::text("lldp.tlv.system.name", "System name", &system));
            }
            6 => {
                l.push(Field::long_text(
                    "lldp.tlv.system.desc",
                    "System description",
                    &String::from_utf8_lossy(value),
                ));
            }
            _ => {}
        }
    }

    ctx.push_layer(l);
    let mut info = String::from("LLDP");
    if !system.is_empty() {
        info.push_str(&format!("  {system}"));
    }
    if !port.is_empty() {
        info.push_str(&format!("  port {port}"));
    }
    ctx.set_info(info);
}

/// Render a chassis/port id according to its subtype.
///
/// Subtypes 3 (MAC) and 4 (network address) are binary; the rest are
/// text. Rendering a MAC as UTF-8 would produce mojibake where an
/// engineer expects an address.
fn render_id(subtype: u8, value: &[u8]) -> String {
    match subtype {
        3 if value.len() == 6 => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            value[0], value[1], value[2], value[3], value[4], value[5]
        ),
        4 if value.len() == 5 && value[0] == 1 => {
            format!("{}.{}.{}.{}", value[1], value[2], value[3], value[4])
        }
        _ => String::from_utf8_lossy(value).into_owned(),
    }
}

// ---------------------------------------------------------------------
// CDP (Cisco Discovery Protocol)
// ---------------------------------------------------------------------

pub(crate) fn dissect_cdp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Cdp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(version), Some(ttl), Some(_checksum)) = (r.u8(), r.u8(), r.u16()) else {
        return;
    };

    let mut l = Layer::new(Proto::Cdp, "CDP");
    l.push(Field::u64("cdp.version", "Version", u64::from(version)))
        .push(Field::u64("cdp.ttl", "Time to live", u64::from(ttl)));

    let mut device = String::new();
    let mut port = String::new();

    for _ in 0..MAX_TLVS {
        let (Some(tlv_type), Some(tlv_len)) = (r.u16(), r.u16()) else {
            break;
        };
        // The length INCLUDES the four header bytes; a shorter one would
        // mean a negative body and is malformed.
        if tlv_len < 4 {
            break;
        }
        let Some(value) = r.bytes(usize::from(tlv_len) - 4) else {
            break;
        };
        match tlv_type {
            0x0001 => {
                device = String::from_utf8_lossy(value).into_owned();
                l.push(Field::text("cdp.deviceid", "Device id", &device));
            }
            0x0003 => {
                port = String::from_utf8_lossy(value).into_owned();
                l.push(Field::text("cdp.portid", "Port id", &port));
            }
            0x0004 if value.len() >= 4 => {
                l.push(Field::u64(
                    "cdp.capabilities",
                    "Capabilities",
                    u64::from(u32::from_be_bytes([value[0], value[1], value[2], value[3]])),
                ));
            }
            0x0005 => {
                l.push(Field::long_text(
                    "cdp.software_version",
                    "Software version",
                    &String::from_utf8_lossy(value),
                ));
            }
            0x0006 => {
                l.push(Field::text(
                    "cdp.platform",
                    "Platform",
                    &String::from_utf8_lossy(value),
                ));
            }
            0x000a if value.len() >= 2 => {
                l.push(Field::u64(
                    "cdp.native_vlan",
                    "Native VLAN",
                    u64::from(u16::from_be_bytes([value[0], value[1]])),
                ));
            }
            _ => {}
        }
    }

    ctx.push_layer(l);
    let mut info = String::from("CDP");
    if !device.is_empty() {
        info.push_str(&format!("  {device}"));
    }
    if !port.is_empty() {
        info.push_str(&format!("  {port}"));
    }
    ctx.set_info(info);
}

// ---------------------------------------------------------------------
// STP (IEEE 802.1D)
// ---------------------------------------------------------------------

pub(crate) fn dissect_stp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Stp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(proto_id), Some(version), Some(bpdu_type)) = (r.u16(), r.u8(), r.u8()) else {
        return;
    };
    if proto_id != 0 {
        return; // not an STP BPDU
    }

    let mut l = Layer::new(Proto::Stp, "STP");
    l.push(Field::u64(
        "stp.protocol",
        "Protocol identifier",
        u64::from(proto_id),
    ))
    .push(Field::u64("stp.version", "Version", u64::from(version)))
    .push(Field::u64("stp.type", "BPDU type", u64::from(bpdu_type)));

    // 0x80 is a Topology Change Notification and carries nothing else.
    // A burst of these is the direct answer to "why did the network stop
    // forwarding for thirty seconds" — every TCN flushes MAC tables.
    if bpdu_type == 0x80 {
        l.push(Field::bool(
            "stp.flags.tcn",
            "Topology change notification",
            true,
        ));
        ctx.push_layer(l);
        ctx.set_info("STP  Topology Change Notification".into());
        return;
    }

    let Some(flags) = r.u8() else {
        ctx.push_layer(l);
        return;
    };
    let (Some(root), Some(cost), Some(bridge), Some(port)) =
        (r.bytes(8), r.u32(), r.bytes(8), r.u16())
    else {
        ctx.push_layer(l);
        return;
    };
    let root_id = bridge_id(root);
    let bridge_id_s = bridge_id(bridge);

    l.push(Field::bool(
        "stp.flags.tc",
        "Topology change",
        flags & 0x01 != 0,
    ))
    .push(Field::bool(
        "stp.flags.tca",
        "Topology change acknowledgment",
        flags & 0x80 != 0,
    ))
    .push(Field::text("stp.root.hw", "Root bridge", &root_id))
    .push(Field::u64(
        "stp.root.cost",
        "Root path cost",
        u64::from(cost),
    ))
    .push(Field::text(
        "stp.bridge.hw",
        "Transmitting bridge",
        &bridge_id_s,
    ))
    .push(Field::u64("stp.port", "Port identifier", u64::from(port)));

    if let (Some(age), Some(max_age), Some(hello), Some(fwd)) = (r.u16(), r.u16(), r.u16(), r.u16())
    {
        // Timers are in 1/256-second units on the wire.
        l.push(Field::u64(
            "stp.msg_age",
            "Message age (1/256s)",
            u64::from(age),
        ))
        .push(Field::u64(
            "stp.max_age",
            "Max age (1/256s)",
            u64::from(max_age),
        ))
        .push(Field::u64(
            "stp.hello",
            "Hello time (1/256s)",
            u64::from(hello),
        ))
        .push(Field::u64(
            "stp.forward",
            "Forward delay (1/256s)",
            u64::from(fwd),
        ));
    }

    let tc = if flags & 0x01 != 0 {
        "  TOPOLOGY CHANGE"
    } else {
        ""
    };
    ctx.push_layer(l);
    ctx.set_info(format!("STP  root {root_id}  cost {cost}{tc}"));
}

/// An 802.1D bridge id: two bytes of priority, six of MAC.
fn bridge_id(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return String::new();
    }
    let priority = u16::from_be_bytes([bytes[0], bytes[1]]);
    format!(
        "{priority}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chassis_ids_render_by_subtype() {
        // Subtype 4 (MAC) must not be read as text.
        assert_eq!(
            render_id(3, &[0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]),
            "00:1b:21:3c:4d:5e"
        );
        assert_eq!(render_id(4, &[1, 10, 0, 0, 1]), "10.0.0.1");
        assert_eq!(render_id(7, b"GigabitEthernet0/1"), "GigabitEthernet0/1");
    }

    #[test]
    fn bridge_ids_split_priority_from_mac() {
        assert_eq!(
            bridge_id(&[0x80, 0x00, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]),
            "32768/00:1b:21:3c:4d:5e"
        );
        assert_eq!(bridge_id(&[0, 0]), "");
    }

    #[test]
    fn the_multicast_addresses_are_the_documented_ones() {
        // These are how CDP and STP are recognized at all, since their
        // frames carry a length where an EtherType would be.
        assert_eq!(CDP_MULTICAST, [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
        assert_eq!(STP_MULTICAST, [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
        assert_eq!(LLDP_ETHERTYPE, 0x88cc);
        assert_eq!(MAX_802_3_LENGTH, 1500);
    }
}
