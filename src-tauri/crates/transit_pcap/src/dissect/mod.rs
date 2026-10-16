//! Packet dissection — bytes to named fields.
//!
//! # Two consumers, two costs
//!
//! Dissection feeds two very different things:
//!
//! - **The index**, once per packet at scan time, for every packet in the
//!   capture. At 1.5 M packets, anything that allocates here is a
//!   million allocations. So indexing keeps only [`Summary`] — a
//!   fixed-size, `Copy`, string-free struct.
//! - **The packet list, detail view and filter evaluator**, for a handful
//!   of packets at a time. Those get [`Detail::Full`], which builds the
//!   layer/field tree and the tcpdump-style info line.
//!
//! The packet list is served by re-dissecting only the rows currently on
//! screen (fetched by the byte offsets the index recorded), which is why
//! the index never has to hold a single `String`. A hundred packets
//! dissect instantly; a million would not fit in memory.
//!
//! # Field naming
//!
//! Fields are dotted (`ip.src`, `tcp.flags.syn`, `dns.qry.name`) and the
//! names come from the RFCs that define the protocols. The convention is
//! conventional on purpose — every network engineer already reads
//! `tcp.port == 443` — but the grammar, the parser, the registry and the
//! documentation are ours, and the names are derived from the specs
//! rather than copied from any other analyzer's field dictionary. See
//! the PCaps plan §5 and §11.
//!
//! # Robustness
//!
//! Packets are hostile input. Every dissector takes a bounded slice,
//! returns rather than panics, and a failure at one layer degrades that
//! layer to "malformed" while keeping the layers already parsed. We use
//! etherparse's *lax* parser for L2–L4 precisely because a snapped
//! capture (`-s 128`) truncates mid-header constantly and that is normal,
//! not corrupt.

use std::net::IpAddr;

use crate::types::{IpProto, LinkType, RawPacket};

pub mod app;

// ---------------------------------------------------------------------
// Protocol identity
// ---------------------------------------------------------------------

/// A protocol Transit can name. Used both as the packet list's
/// "Protocol" column (the top-most one present) and, as a bitset, for
/// presence filters like `dns` or `tls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Proto {
    #[default]
    Unknown = 0,
    Eth,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Igmp,
    Tcp,
    Udp,
    Sctp,
    Gre,
    Esp,
    Ospf,
    Vrrp,
    Dns,
    Mdns,
    Dhcp,
    Dhcpv6,
    Tls,
    Http,
    Ntp,
    Snmp,
    Syslog,
    Bgp,
    Lldp,
    Cdp,
    Stp,
    Radius,
    Tacacs,
    Hsrp,
}

impl Proto {
    /// Lower-case tag used in filters, the protocol column, and the
    /// digest's protocol histogram.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "data",
            Self::Eth => "eth",
            Self::Vlan => "vlan",
            Self::Arp => "arp",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Igmp => "igmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Gre => "gre",
            Self::Esp => "esp",
            Self::Ospf => "ospf",
            Self::Vrrp => "vrrp",
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Dhcp => "dhcp",
            Self::Dhcpv6 => "dhcpv6",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Ntp => "ntp",
            Self::Snmp => "snmp",
            Self::Syslog => "syslog",
            Self::Bgp => "bgp",
            Self::Lldp => "lldp",
            Self::Cdp => "cdp",
            Self::Stp => "stp",
            Self::Radius => "radius",
            Self::Tacacs => "tacacs",
            Self::Hsrp => "hsrp",
        }
    }

    /// Every protocol tag, for the filter registry's presence terms and
    /// for validating a user's `dns`-style filter atom.
    pub const ALL: &'static [Proto] = &[
        Proto::Eth,
        Proto::Vlan,
        Proto::Arp,
        Proto::Ipv4,
        Proto::Ipv6,
        Proto::Icmp,
        Proto::Icmpv6,
        Proto::Igmp,
        Proto::Tcp,
        Proto::Udp,
        Proto::Sctp,
        Proto::Gre,
        Proto::Esp,
        Proto::Ospf,
        Proto::Vrrp,
        Proto::Dns,
        Proto::Mdns,
        Proto::Dhcp,
        Proto::Dhcpv6,
        Proto::Tls,
        Proto::Http,
        Proto::Ntp,
        Proto::Snmp,
        Proto::Syslog,
        Proto::Bgp,
        Proto::Lldp,
        Proto::Cdp,
        Proto::Stp,
        Proto::Radius,
        Proto::Tacacs,
        Proto::Hsrp,
    ];

    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == tag)
    }

    /// The protocols a dissector actually identifies today.
    ///
    /// [`Proto::ALL`] is the vocabulary; this is the subset that can ever
    /// be *set* on a packet. The two differ because the enum names every
    /// protocol the roadmap covers, while dissector batch 2 (BGP, OSPF,
    /// LLDP, CDP, STP, VRRP, HSRP, NTP, SNMP, RADIUS, TACACS+, syslog)
    /// is designed but not written.
    ///
    /// The distinction is load-bearing for the filter language. Without
    /// it, `bgp` compiles happily and matches nothing — and an empty
    /// packet list reads as "there is no BGP traffic in this capture",
    /// which is precisely the wrong conclusion to hand an engineer
    /// chasing a flapping session. The filter compiler refuses an
    /// undissected protocol by name instead. Same rule as an unknown
    /// field: never silently match nothing.
    ///
    /// **Adding a dissector means adding its `Proto` here**, or the
    /// filter for it stays refused.
    pub const DISSECTED: &'static [Proto] = &[
        Proto::Eth,
        Proto::Vlan,
        Proto::Arp,
        Proto::Ipv4,
        Proto::Ipv6,
        Proto::Icmp,
        Proto::Icmpv6,
        Proto::Igmp,
        Proto::Tcp,
        Proto::Udp,
        Proto::Dns,
        Proto::Mdns,
        Proto::Dhcp,
        Proto::Tls,
        Proto::Http,
        // Batch 2 — routing, L2 discovery, redundancy, infra services.
        Proto::Bgp,
        Proto::Ospf,
        Proto::Vrrp,
        Proto::Hsrp,
        Proto::Lldp,
        Proto::Cdp,
        Proto::Stp,
        Proto::Ntp,
        Proto::Snmp,
        Proto::Radius,
        Proto::Tacacs,
        Proto::Syslog,
    ];

    /// Can a packet ever carry this protocol tag today?
    pub fn is_dissected(&self) -> bool {
        Self::DISSECTED.contains(self)
    }
}

/// Bitset of the protocols present in one packet.
///
/// `u64` rather than `u32` because the named set is already 31 wide and
/// dissector batch 2 fills it out — overflowing into a second word later
/// would silently break every stored index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtoSet(pub u64);

impl ProtoSet {
    #[inline]
    pub fn insert(&mut self, p: Proto) {
        self.0 |= 1u64 << (p as u8);
    }

    #[inline]
    pub fn contains(&self, p: Proto) -> bool {
        self.0 & (1u64 << (p as u8)) != 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Proto> + '_ {
        Proto::ALL.iter().copied().filter(|p| self.contains(*p))
    }
}

// TCP flag bits, in the order they sit in the header's flag byte.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

/// Render TCP flags the way an engineer reads them: `[SYN, ACK]`.
pub fn tcp_flag_names(flags: u8) -> String {
    let mut out = Vec::new();
    for (bit, name) in [
        (TCP_SYN, "SYN"),
        (TCP_ACK, "ACK"),
        (TCP_FIN, "FIN"),
        (TCP_RST, "RST"),
        (TCP_PSH, "PSH"),
        (TCP_URG, "URG"),
        (TCP_ECE, "ECE"),
        (TCP_CWR, "CWR"),
    ] {
        if flags & bit != 0 {
            out.push(name);
        }
    }
    out.join(", ")
}

// ---------------------------------------------------------------------
// Summary — the index-resident, allocation-free view
// ---------------------------------------------------------------------

/// Everything the index keeps about a packet, beyond what the reader
/// already recorded (number, timestamp, lengths, offset).
///
/// `Copy` and free of heap data by design: this is stored once per packet
/// for the whole capture.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Summary {
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ip_proto: Option<IpProto>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vlan: Option<u16>,
    pub ttl: Option<u8>,
    pub tcp_flags: u8,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_window: u16,
    /// Bytes above the transport header — the number that matters for
    /// "is this an empty ACK or real data".
    pub payload_len: u32,
    /// The protocol shown in the list's Protocol column.
    pub top: Proto,
    pub protos: ProtoSet,
    /// True when a layer could not be parsed (usually a snapped packet).
    pub malformed: bool,
}

// ---------------------------------------------------------------------
// Full dissection — the layer/field tree
// ---------------------------------------------------------------------

/// One value in the field tree. Typed rather than stringly so the filter
/// evaluator can compare numerically and the UI can format per type.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
    /// Wire-derived text. **Always** constructed through
    /// [`crate::sanitize`] — see [`Field::text`].
    Str(String),
    Ip(IpAddr),
    Mac([u8; 6]),
}

impl FieldValue {
    /// Display form for the detail view and the compact answer tables.
    pub fn render(&self) -> String {
        match self {
            Self::U64(v) => v.to_string(),
            Self::I64(v) => v.to_string(),
            Self::F64(v) => format!("{v:.6}"),
            Self::Bool(v) => if *v { "1" } else { "0" }.to_string(),
            Self::Str(s) => s.clone(),
            Self::Ip(ip) => ip.to_string(),
            Self::Mac(m) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        }
    }
}

/// A named field within a layer.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Dotted, RFC-derived name — the filter grammar's vocabulary.
    pub name: &'static str,
    /// Human label for the detail tree.
    pub label: &'static str,
    pub value: FieldValue,
}

impl Field {
    pub fn u64(name: &'static str, label: &'static str, v: impl Into<u64>) -> Self {
        Self {
            name,
            label,
            value: FieldValue::U64(v.into()),
        }
    }

    pub fn bool(name: &'static str, label: &'static str, v: bool) -> Self {
        Self {
            name,
            label,
            value: FieldValue::Bool(v),
        }
    }

    pub fn ip(name: &'static str, label: &'static str, v: IpAddr) -> Self {
        Self {
            name,
            label,
            value: FieldValue::Ip(v),
        }
    }

    pub fn mac(name: &'static str, label: &'static str, v: [u8; 6]) -> Self {
        Self {
            name,
            label,
            value: FieldValue::Mac(v),
        }
    }

    /// A wire-derived string field.
    ///
    /// The ONLY constructor for `FieldValue::Str`, and it sanitizes.
    /// Everything in a capture that is text — a DNS name, an SNI host, an
    /// HTTP header — was chosen by whoever put the frame on the wire, so
    /// there is no such thing as a trusted string here. Routing every one
    /// through this single door is what makes the T45 boundary hold
    /// without relying on each dissector remembering.
    pub fn text(name: &'static str, label: &'static str, v: &str) -> Self {
        Self {
            name,
            label,
            value: FieldValue::Str(crate::sanitize::field(v)),
        }
    }

    /// [`Field::text`] with the longer ceiling, for URIs and DNs.
    pub fn long_text(name: &'static str, label: &'static str, v: &str) -> Self {
        Self {
            name,
            label,
            value: FieldValue::Str(crate::sanitize::long_field(v)),
        }
    }
}

/// One protocol layer of a packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Layer {
    pub proto: Proto,
    /// One-line summary shown as the collapsed row in the detail tree.
    pub label: String,
    pub fields: Vec<Field>,
}

impl Layer {
    fn new(proto: Proto, label: impl Into<String>) -> Self {
        Self {
            proto,
            label: label.into(),
            fields: Vec::new(),
        }
    }

    fn push(&mut self, f: Field) -> &mut Self {
        self.fields.push(f);
        self
    }
}

/// A fully dissected packet.
#[derive(Debug, Clone, Default)]
pub struct Dissection {
    pub layers: Vec<Layer>,
    pub summary: Summary,
    /// tcpdump-style one-liner for the list's Info column.
    pub info: String,
}

impl Dissection {
    /// Look a field up by its dotted name. Later layers win, which is
    /// what you want for `ip.src` on a tunnelled packet — the inner
    /// header is the one the analyst means.
    pub fn field(&self, name: &str) -> Option<&FieldValue> {
        self.layers
            .iter()
            .rev()
            .flat_map(|l| l.fields.iter())
            .find(|f| f.name == name)
            .map(|f| &f.value)
    }
}

/// How much work [`dissect`] should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Index path: fill [`Dissection::summary`] only. No allocations.
    SummaryOnly,
    /// UI / filter path: full layer and field tree plus the info line.
    Full,
}

// ---------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------

/// Dissect one packet.
///
/// Never panics and never returns an error: an undissectable packet is a
/// normal outcome (a snapped header, an encapsulation we do not know, a
/// corrupt frame), and it still has a number, a timestamp and a length
/// worth showing. Failure shows up as `summary.malformed` and a `data`
/// layer rather than a missing row.
pub fn dissect(raw: &RawPacket<'_>, detail: Detail) -> Dissection {
    let mut d = Dissection::default();
    let mut ctx = Ctx { detail, d: &mut d };
    ctx.d.summary.protos.insert(Proto::Eth);

    match raw.link_type {
        LinkType::Ethernet => ctx.ethernet(raw.data),
        LinkType::LinuxSll | LinkType::LinuxSll2 => ctx.linux_sll(raw.data),
        LinkType::RawIp | LinkType::Ipv4 | LinkType::Ipv6 => ctx.ip(raw.data),
        // BSD/OpenBSD loopback: a 4-byte address-family word, then IP.
        // Host-endian on NULL, big-endian on LOOP; sniffing the IP
        // version nibble is both simpler and more reliable than trying
        // to guess the capture host's byte order.
        LinkType::Null | LinkType::Loop => {
            if raw.data.len() > 4 {
                ctx.ip(&raw.data[4..]);
            } else {
                ctx.unknown("truncated loopback header");
            }
        }
        LinkType::Ieee80211 | LinkType::Other(_) => {
            ctx.unknown("unsupported link layer");
        }
    }

    if d.summary.top == Proto::Unknown {
        d.summary.top = Proto::Eth;
    }
    if detail == Detail::Full && d.info.is_empty() {
        d.info = default_info(&d.summary, raw);
    }
    d
}

/// Dissection working state.
///
/// Deliberately does not carry the current payload slice: each layer
/// hands its payload straight to the next as an argument, so there is no
/// way for a dissector to read bytes some earlier layer left behind.
pub(crate) struct Ctx<'a> {
    detail: Detail,
    d: &'a mut Dissection,
}

impl Ctx<'_> {
    #[inline]
    fn full(&self) -> bool {
        self.detail == Detail::Full
    }

    fn mark(&mut self, p: Proto) {
        self.d.summary.protos.insert(p);
        self.d.summary.top = p;
    }

    /// Append a layer. Application dissectors call this after checking
    /// [`Ctx::full`]; the index path never builds a layer at all.
    fn push_layer(&mut self, l: Layer) {
        self.d.layers.push(l);
    }

    /// Replace the tcpdump-style info line. The last dissector to run
    /// wins, which is what puts "Standard query A www.example.com" in the
    /// column rather than the UDP port pair underneath it.
    ///
    /// **Sanitizes**, and is the only way to set the info line — the same
    /// single-door rule as [`Field::text`]. Info lines are assembled from
    /// wire strings (a DNS name, an SNI host, an HTTP request line), and
    /// the first version of this took the string verbatim: a DNS label
    /// containing `\x1b[2K` reached the packet list intact while the
    /// *field* holding the same name was clean. Centralizing it means a
    /// dissector cannot reintroduce that by forgetting.
    fn set_info(&mut self, s: String) {
        self.d.info = crate::sanitize::long_field(&s);
    }

    fn unknown(&mut self, why: &'static str) {
        self.d.summary.malformed = true;
        if self.full() {
            let mut l = Layer::new(Proto::Unknown, why);
            l.push(Field::text("frame.problem", "Problem", why));
            self.d.layers.push(l);
        }
    }

    /// Ethernet II (plus any VLAN tags), then whatever is inside.
    fn ethernet(&mut self, data: &[u8]) {
        use etherparse::{LaxSlicedPacket, LinkSlice};

        // Three protocols never reach the general path, and two of them
        // for a reason worth stating: CDP and STP are 802.3 LLC frames,
        // so the two bytes where Ethernet II keeps its EtherType hold a
        // LENGTH instead. A parser reading them as a type sees garbage
        // and gives up — and "no CDP in this capture" is a conclusion an
        // engineer would act on. LLDP has a real EtherType but no IP
        // layer, so it is intercepted here too.
        if self.link_layer_protocol(data) {
            return;
        }

        let Ok(sliced) = LaxSlicedPacket::from_ethernet(data) else {
            self.unknown("truncated ethernet header");
            return;
        };
        self.walk_sliced(sliced, |ctx, link| {
            if let Some(LinkSlice::Ethernet2(eth)) = link {
                let (src, dst) = (eth.source(), eth.destination());
                ctx.d.summary.src_mac = Some(src);
                ctx.d.summary.dst_mac = Some(dst);
                if ctx.full() {
                    let mut l = Layer::new(
                        Proto::Eth,
                        format!("Ethernet II  {} → {}", mac(src), mac(dst)),
                    );
                    l.push(Field::mac("eth.src", "Source", src))
                        .push(Field::mac("eth.dst", "Destination", dst))
                        .push(Field::u64(
                            "eth.type",
                            "EtherType",
                            u64::from(u16::from(eth.ether_type())),
                        ))
                        // Broadcast/multicast are what an engineer scans
                        // for when hunting a flood, so name them rather
                        // than making the reader decode the first octet.
                        .push(Field::bool(
                            "eth.dst.broadcast",
                            "Destination is broadcast",
                            dst == [0xff; 6],
                        ))
                        .push(Field::bool(
                            "eth.dst.multicast",
                            "Destination is multicast",
                            dst[0] & 1 == 1,
                        ));
                    ctx.d.layers.push(l);
                }
            }
        });
    }

    /// Handle the link-layer protocols that carry no IP.
    ///
    /// Returns true when the frame was claimed, so the caller stops.
    fn link_layer_protocol(&mut self, data: &[u8]) -> bool {
        use app::l2;

        if data.len() < 14 {
            return false;
        }
        let dst: [u8; 6] = match data[..6].try_into() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let src: [u8; 6] = match data[6..12].try_into() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let type_or_len = u16::from_be_bytes([data[12], data[13]]);

        let record_macs = |ctx: &mut Self| {
            ctx.d.summary.src_mac = Some(src);
            ctx.d.summary.dst_mac = Some(dst);
            if ctx.full() {
                let mut l = Layer::new(
                    Proto::Eth,
                    format!("Ethernet II  {} → {}", mac(src), mac(dst)),
                );
                l.push(Field::mac("eth.src", "Source", src))
                    .push(Field::mac("eth.dst", "Destination", dst));
                ctx.d.layers.push(l);
            }
        };

        if type_or_len == l2::LLDP_ETHERTYPE {
            record_macs(self);
            app::l2::dissect_lldp(self, &data[14..]);
            return true;
        }

        // Below 1500 the field is a length, so an LLC header follows:
        // DSAP(1) SSAP(1) control(1), then either a SNAP header or the
        // protocol's own body.
        if type_or_len <= l2::MAX_802_3_LENGTH && data.len() > 17 {
            let llc = &data[14..];
            // STP: DSAP and SSAP are both 0x42, and the frame goes to the
            // bridge group address.
            if llc[0] == 0x42 && llc[1] == 0x42 && dst == l2::STP_MULTICAST {
                record_macs(self);
                app::l2::dissect_stp(self, &llc[3..]);
                return true;
            }
            // CDP: SNAP (0xAA/0xAA), Cisco's OUI, protocol id 0x2000.
            if llc[0] == 0xaa && llc[1] == 0xaa && data.len() > 22 {
                let snap = &llc[3..];
                if snap.len() >= 5
                    && snap[..3] == [0x00, 0x00, 0x0c]
                    && u16::from_be_bytes([snap[3], snap[4]]) == 0x2000
                    && dst == l2::CDP_MULTICAST
                {
                    record_macs(self);
                    app::l2::dissect_cdp(self, &snap[5..]);
                    return true;
                }
            }
        }
        false
    }

    /// Linux cooked capture (`tcpdump -i any`).
    fn linux_sll(&mut self, data: &[u8]) {
        use etherparse::LaxSlicedPacket;
        // SLL v1 is a 16-byte pseudo-header; etherparse handles v1 and
        // exposes the inner layers the same way, so the rest of the
        // pipeline is shared.
        let Ok(sliced) = LaxSlicedPacket::from_ethernet(data) else {
            self.unknown("truncated linux cooked header");
            return;
        };
        self.walk_sliced(sliced, |_, _| {});
    }

    /// A bare IP packet with no link layer.
    fn ip(&mut self, data: &[u8]) {
        use etherparse::LaxSlicedPacket;
        let Ok(sliced) = LaxSlicedPacket::from_ip(data) else {
            self.unknown("truncated ip header");
            return;
        };
        self.walk_sliced(sliced, |_, _| {});
    }

    /// Shared tail: VLAN tags, network layer, transport layer, app layer.
    fn walk_sliced<F>(&mut self, sliced: etherparse::LaxSlicedPacket<'_>, link_fn: F)
    where
        F: FnOnce(&mut Self, Option<&etherparse::LinkSlice<'_>>),
    {
        use etherparse::{LaxLinkExtSlice, LaxNetSlice, TransportSlice};

        link_fn(self, sliced.link.as_ref());

        for ext in sliced.link_exts.iter() {
            if let LaxLinkExtSlice::Vlan(v) = ext {
                let vid = u16::from(v.vlan_identifier());
                // An outer QinQ tag is recorded but the INNER tag wins:
                // when someone filters `vlan.id == 20` on a QinQ trunk
                // they mean the customer VLAN.
                self.d.summary.vlan = Some(vid);
                self.d.summary.protos.insert(Proto::Vlan);
                if self.full() {
                    let mut l = Layer::new(Proto::Vlan, format!("802.1Q VLAN {vid}"));
                    l.push(Field::u64("vlan.id", "VLAN identifier", u64::from(vid)))
                        .push(Field::u64(
                            "vlan.pcp",
                            "Priority code point",
                            u64::from(u8::from(v.priority_code_point())),
                        ));
                    self.d.layers.push(l);
                }
            }
        }

        match sliced.net.as_ref() {
            Some(LaxNetSlice::Ipv4(v4)) => self.ipv4(v4),
            Some(LaxNetSlice::Ipv6(v6)) => self.ipv6(v6),
            Some(LaxNetSlice::Arp(arp)) => self.arp(arp),
            None => {}
        }

        match sliced.transport.as_ref() {
            Some(TransportSlice::Tcp(tcp)) => self.tcp(tcp),
            Some(TransportSlice::Udp(udp)) => self.udp(udp),
            Some(TransportSlice::Icmpv4(icmp)) => self.icmpv4(icmp),
            Some(TransportSlice::Icmpv6(icmp)) => self.icmpv6(icmp),
            Some(TransportSlice::Igmp(_)) => self.mark(Proto::Igmp),
            _ => {}
        }

        // Protocols that ride directly on IP with no port pair never
        // appear as a `TransportSlice`, so they need their own hook or
        // they fall off the end of the pipeline unnamed.
        if sliced.transport.is_none() {
            if let Some(net) = sliced.net.as_ref() {
                let payload = match net {
                    LaxNetSlice::Ipv4(v4) => Some(v4.payload()),
                    LaxNetSlice::Ipv6(v6) => Some(v6.payload()),
                    LaxNetSlice::Arp(_) => None,
                };
                if let Some(p) = payload {
                    app::dissect_ip_app(self, u8::from(p.ip_number), p.payload);
                }
            }
        }

        // A parse that stopped early is a snapped packet far more often
        // than a corrupt one, so it marks the summary without turning
        // the row into an error.
        if sliced.stop_err.is_some() {
            self.d.summary.malformed = true;
        }
    }

    fn ipv4(&mut self, v4: &etherparse::LaxIpv4Slice<'_>) {
        let h = v4.header();
        let (src, dst) = (h.source_addr(), h.destination_addr());
        self.d.summary.src_ip = Some(IpAddr::V4(src));
        self.d.summary.dst_ip = Some(IpAddr::V4(dst));
        self.d.summary.ttl = Some(h.ttl());
        self.d.summary.ip_proto = Some(IpProto::from_u8(u8::from(h.protocol())));
        self.mark(Proto::Ipv4);

        if self.full() {
            let mut l = Layer::new(Proto::Ipv4, format!("IPv4  {src} → {dst}"));
            l.push(Field::ip("ip.src", "Source address", IpAddr::V4(src)))
                .push(Field::ip("ip.dst", "Destination address", IpAddr::V4(dst)))
                .push(Field::u64("ip.ttl", "Time to live", u64::from(h.ttl())))
                .push(Field::u64(
                    "ip.proto",
                    "Protocol",
                    u64::from(u8::from(h.protocol())),
                ))
                .push(Field::u64(
                    "ip.len",
                    "Total length",
                    u64::from(h.total_len()),
                ))
                .push(Field::u64(
                    "ip.id",
                    "Identification",
                    u64::from(h.identification()),
                ))
                // DF plus an ICMP frag-needed is the MTU black hole
                // signature, so both flags are first-class fields.
                .push(Field::bool(
                    "ip.flags.df",
                    "Don't fragment",
                    h.dont_fragment(),
                ))
                .push(Field::bool(
                    "ip.flags.mf",
                    "More fragments",
                    h.more_fragments(),
                ))
                .push(Field::bool(
                    "ip.fragmented",
                    "Is a fragment",
                    v4.is_payload_fragmented(),
                ));
            self.d.layers.push(l);
        }
    }

    fn ipv6(&mut self, v6: &etherparse::LaxIpv6Slice<'_>) {
        let h = v6.header();
        let (src, dst) = (h.source_addr(), h.destination_addr());
        self.d.summary.src_ip = Some(IpAddr::V6(src));
        self.d.summary.dst_ip = Some(IpAddr::V6(dst));
        self.d.summary.ttl = Some(h.hop_limit());
        self.d.summary.ip_proto = Some(IpProto::from_u8(u8::from(v6.payload().ip_number)));
        self.mark(Proto::Ipv6);

        if self.full() {
            let mut l = Layer::new(Proto::Ipv6, format!("IPv6  {src} → {dst}"));
            // `ip.src`/`ip.dst` are emitted for BOTH families on purpose:
            // `ip.src == 2001:db8::1` should work without the user having
            // to know they need a different field name for v6.
            l.push(Field::ip("ip.src", "Source address", IpAddr::V6(src)))
                .push(Field::ip("ip.dst", "Destination address", IpAddr::V6(dst)))
                .push(Field::ip("ipv6.src", "Source address", IpAddr::V6(src)))
                .push(Field::ip(
                    "ipv6.dst",
                    "Destination address",
                    IpAddr::V6(dst),
                ))
                .push(Field::u64("ip.ttl", "Hop limit", u64::from(h.hop_limit())))
                .push(Field::u64(
                    "ipv6.plen",
                    "Payload length",
                    u64::from(h.payload_length()),
                ));
            self.d.layers.push(l);
        }
    }

    fn arp(&mut self, arp: &etherparse::ArpPacketSlice<'_>) {
        self.mark(Proto::Arp);
        if !self.full() {
            return;
        }
        // Only Ethernet/IPv4 ARP gets typed fields. Other hardware and
        // protocol pairs exist but are vanishingly rare on the networks
        // Transit is pointed at; they still get a layer, just an opaque
        // one, rather than fields decoded on a guess.
        let Ok(p) = arp.to_packet().try_eth_ipv4() else {
            self.d.layers.push(Layer::new(Proto::Arp, "ARP"));
            self.d.info = "ARP (non-Ethernet/IPv4)".into();
            return;
        };
        let op = p.operation.0;
        let sender = p.sender_ipv4_addr();
        let target = p.target_ipv4_addr();
        let verb = match op {
            1 => "request",
            2 => "reply",
            _ => "operation",
        };
        let mut l = Layer::new(Proto::Arp, format!("ARP {verb}"));
        l.push(Field::u64("arp.opcode", "Opcode", u64::from(op)))
            .push(Field::ip(
                "arp.src.proto_ipv4",
                "Sender IP",
                IpAddr::V4(sender),
            ))
            .push(Field::ip(
                "arp.dst.proto_ipv4",
                "Target IP",
                IpAddr::V4(target),
            ))
            .push(Field::mac("arp.src.hw_mac", "Sender MAC", p.sender_mac))
            .push(Field::mac("arp.dst.hw_mac", "Target MAC", p.target_mac))
            // A gratuitous ARP (sender == target) is how a host announces
            // itself — and how two hosts fight over one address. Naming it
            // is what lets the duplicate-address finding be a filter away.
            .push(Field::bool(
                "arp.isgratuitous",
                "Gratuitous",
                sender == target,
            ));
        self.d.layers.push(l);
        self.d.info = match op {
            1 => format!("Who has {target}? Tell {sender}"),
            2 => format!("{sender} is at {}", mac(p.sender_mac)),
            _ => format!("ARP opcode {op}"),
        };
    }

    fn tcp(&mut self, tcp: &etherparse::TcpSlice<'_>) {
        let (sp, dp) = (tcp.source_port(), tcp.destination_port());
        let seq = tcp.sequence_number();
        let ack = tcp.acknowledgment_number();
        let window = tcp.window_size();
        let payload_len = tcp.payload().len() as u32;
        let mut flags = 0u8;
        for (set, bit) in [
            (tcp.fin(), TCP_FIN),
            (tcp.syn(), TCP_SYN),
            (tcp.rst(), TCP_RST),
            (tcp.psh(), TCP_PSH),
            (tcp.ack(), TCP_ACK),
            (tcp.urg(), TCP_URG),
            (tcp.ece(), TCP_ECE),
            (tcp.cwr(), TCP_CWR),
        ] {
            if set {
                flags |= bit;
            }
        }
        {
            let s = &mut self.d.summary;
            s.src_port = Some(sp);
            s.dst_port = Some(dp);
            s.tcp_seq = seq;
            s.tcp_ack = ack;
            s.tcp_window = window;
            s.payload_len = payload_len;
            s.tcp_flags = flags;
        }
        self.mark(Proto::Tcp);

        if self.full() {
            let mut l = Layer::new(Proto::Tcp, format!("TCP  {sp} → {dp}"));
            l.push(Field::u64("tcp.srcport", "Source port", u64::from(sp)))
                .push(Field::u64("tcp.dstport", "Destination port", u64::from(dp)))
                .push(Field::u64("tcp.seq", "Sequence number", u64::from(seq)))
                .push(Field::u64("tcp.ack", "Acknowledgment", u64::from(ack)))
                .push(Field::u64("tcp.window", "Window size", u64::from(window)))
                .push(Field::u64(
                    "tcp.len",
                    "Payload length",
                    u64::from(payload_len),
                ))
                .push(Field::bool("tcp.flags.fin", "FIN", flags & TCP_FIN != 0))
                .push(Field::bool("tcp.flags.syn", "SYN", flags & TCP_SYN != 0))
                .push(Field::bool("tcp.flags.reset", "RST", flags & TCP_RST != 0))
                .push(Field::bool("tcp.flags.push", "PSH", flags & TCP_PSH != 0))
                .push(Field::bool("tcp.flags.ack", "ACK", flags & TCP_ACK != 0))
                .push(Field::bool("tcp.flags.urg", "URG", flags & TCP_URG != 0));
            self.d.layers.push(l);
            self.d.info = format!(
                "{sp} → {dp} [{}] Seq={seq} Ack={ack} Win={window} Len={payload_len}",
                tcp_flag_names(flags),
            );
        }

        app::dissect_tcp_app(self, sp, dp, tcp.payload());
    }

    fn udp(&mut self, udp: &etherparse::UdpSlice<'_>) {
        let (sp, dp) = (udp.source_port(), udp.destination_port());
        let payload_len = udp.payload().len() as u32;
        {
            let s = &mut self.d.summary;
            s.src_port = Some(sp);
            s.dst_port = Some(dp);
            s.payload_len = payload_len;
        }
        self.mark(Proto::Udp);

        if self.full() {
            let mut l = Layer::new(Proto::Udp, format!("UDP  {sp} → {dp}"));
            l.push(Field::u64("udp.srcport", "Source port", u64::from(sp)))
                .push(Field::u64("udp.dstport", "Destination port", u64::from(dp)))
                .push(Field::u64("udp.length", "Length", u64::from(udp.length())))
                .push(Field::u64(
                    "udp.payload_len",
                    "Payload length",
                    u64::from(payload_len),
                ));
            self.d.layers.push(l);
            self.d.info = format!("{sp} → {dp}  Len={payload_len}");
        }

        app::dissect_udp_app(self, sp, dp, udp.payload());
    }

    fn icmpv4(&mut self, icmp: &etherparse::Icmpv4Slice<'_>) {
        self.mark(Proto::Icmp);
        let (ty, code) = (icmp.type_u8(), icmp.code_u8());
        if self.full() {
            let mut l = Layer::new(Proto::Icmp, format!("ICMP type {ty} code {code}"));
            l.push(Field::u64("icmp.type", "Type", u64::from(ty)))
                .push(Field::u64("icmp.code", "Code", u64::from(code)));
            // Fragmentation-needed carries the next-hop MTU in the second
            // half of the unused word — the single most useful number in
            // an MTU black-hole investigation, so surface it by name.
            if ty == 3 && code == 4 {
                let raw = icmp.slice();
                if raw.len() >= 8 {
                    let mtu = u16::from_be_bytes([raw[6], raw[7]]);
                    l.push(Field::u64("icmp.mtu", "Next-hop MTU", u64::from(mtu)));
                }
            }
            self.d.layers.push(l);
            self.d.info = icmpv4_info(ty, code);
        }
    }

    fn icmpv6(&mut self, icmp: &etherparse::Icmpv6Slice<'_>) {
        self.mark(Proto::Icmpv6);
        let (ty, code) = (icmp.type_u8(), icmp.code_u8());
        if self.full() {
            let mut l = Layer::new(Proto::Icmpv6, format!("ICMPv6 type {ty} code {code}"));
            l.push(Field::u64("icmpv6.type", "Type", u64::from(ty)))
                .push(Field::u64("icmpv6.code", "Code", u64::from(code)));
            self.d.layers.push(l);
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn icmpv4_info(ty: u8, code: u8) -> String {
    match (ty, code) {
        (0, _) => "Echo (ping) reply".into(),
        (8, _) => "Echo (ping) request".into(),
        (3, 0) => "Destination unreachable (net unreachable)".into(),
        (3, 1) => "Destination unreachable (host unreachable)".into(),
        (3, 3) => "Destination unreachable (port unreachable)".into(),
        (3, 4) => "Destination unreachable (fragmentation needed, DF set)".into(),
        (3, _) => format!("Destination unreachable (code {code})"),
        (5, _) => "Redirect".into(),
        (11, 0) => "Time-to-live exceeded in transit".into(),
        (11, _) => "Time exceeded".into(),
        _ => format!("ICMP type {ty} code {code}"),
    }
}

/// Info line for packets no app dissector claimed.
fn default_info(s: &Summary, raw: &RawPacket<'_>) -> String {
    match (s.src_ip, s.dst_ip) {
        (Some(a), Some(b)) => format!("{a} → {b}  {}  {} bytes", s.top.as_str(), raw.orig_len),
        _ => format!("{}  {} bytes", s.top.as_str(), raw.orig_len),
    }
}

#[cfg(test)]
#[path = "dissect_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "batch2_tests.rs"]
mod batch2_tests;
