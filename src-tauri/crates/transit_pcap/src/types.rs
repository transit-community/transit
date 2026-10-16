//! Core types shared by the reader, the dissectors, the index and the
//! query layer.

use serde::Serialize;

/// Link-layer encapsulation of a capture, from the pcap file header's
/// `network` field or a pcapng Interface Description Block.
///
/// Numbering is the LINKTYPE_* registry (tcpdump.org / IANA). We name the
/// handful a network engineer actually meets and keep the rest as
/// `Other`, which dissects to "unsupported link layer" rather than
/// guessing — a wrong guess produces confidently wrong field values,
/// which is worse than an honest gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    /// LINKTYPE_NULL (0) — BSD loopback: 4-byte host-endian AF_ value.
    Null,
    /// LINKTYPE_ETHERNET (1) — the overwhelming majority of captures.
    Ethernet,
    /// LINKTYPE_RAW (101) — bare IPv4/IPv6, version sniffed from the
    /// first nibble.
    RawIp,
    /// LINKTYPE_IEEE802_11 (105).
    Ieee80211,
    /// LINKTYPE_LOOP (108) — OpenBSD loopback: 4-byte big-endian AF_.
    Loop,
    /// LINKTYPE_LINUX_SLL (113) — `tcpdump -i any` on Linux.
    LinuxSll,
    /// LINKTYPE_IPV4 (228).
    Ipv4,
    /// LINKTYPE_IPV6 (229).
    Ipv6,
    /// LINKTYPE_LINUX_SLL2 (276) — the wider `-i any` header.
    LinuxSll2,
    /// Anything else, preserved so the UI can name the number.
    Other(u16),
}

impl LinkType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Ethernet,
            101 => Self::RawIp,
            105 => Self::Ieee80211,
            108 => Self::Loop,
            113 => Self::LinuxSll,
            228 => Self::Ipv4,
            229 => Self::Ipv6,
            276 => Self::LinuxSll2,
            other => Self::Other(other),
        }
    }

    /// Short tag for the UI and the capture digest.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Ethernet => "EN10MB",
            Self::RawIp => "RAW",
            Self::Ieee80211 => "IEEE802_11",
            Self::Loop => "LOOP",
            Self::LinuxSll => "LINUX_SLL",
            Self::Ipv4 => "IPV4",
            Self::Ipv6 => "IPV6",
            Self::LinuxSll2 => "LINUX_SLL2",
            Self::Other(_) => "UNKNOWN",
        }
    }

    /// Whether the dissect pipeline knows how to strip this link layer.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Other(_) | Self::Ieee80211)
    }
}

/// Byte order of a capture file, read from its magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    #[inline]
    pub fn u16(&self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }

    #[inline]
    pub fn u32(&self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
}

/// Which on-disk format a capture uses, plus the details needed to
/// re-read one packet at a byte offset without re-scanning the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    /// Classic libpcap. `nanos` distinguishes the `0xa1b23c4d` variant
    /// whose second field is nanoseconds rather than microseconds.
    Pcap { endian: Endian, nanos: bool },
    /// pcapng. Timestamp resolution is per-interface, so it lives on the
    /// interface table rather than here.
    PcapNg { endian: Endian },
}

impl CaptureFormat {
    pub fn endian(&self) -> Endian {
        match self {
            Self::Pcap { endian, .. } | Self::PcapNg { endian } => *endian,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pcap { .. } => "pcap",
            Self::PcapNg { .. } => "pcapng",
        }
    }
}

/// One packet, borrowed from the reader's buffer.
///
/// `offset` is the byte position of the packet's *record header* (the
/// classic 16-byte record header, or the pcapng block's first byte). The
/// index keeps it so a detail view re-reads and re-dissects exactly one
/// packet instead of holding every packet's bytes in memory — the single
/// decision that makes a 5-million-packet capture fit in a few hundred
/// megabytes.
#[derive(Debug, Clone, Copy)]
pub struct RawPacket<'a> {
    /// 1-based, in file order. The number the UI and the model use.
    pub number: u64,
    /// Microseconds since the Unix epoch.
    pub ts_us: i64,
    /// Bytes actually stored (may be less than `orig_len` under a snaplen).
    pub caplen: u32,
    /// Bytes on the wire.
    pub orig_len: u32,
    /// Byte offset of the record header within the (decompressed) file.
    pub offset: u64,
    /// The captured bytes, starting at the link layer.
    pub data: &'a [u8],
    /// Link type for this packet. Per-packet rather than per-file because
    /// a pcapng section can describe several interfaces with different
    /// encapsulations.
    pub link_type: LinkType,
}

impl RawPacket<'_> {
    /// Was this packet cut short by the capture snaplen?
    pub fn is_snapped(&self) -> bool {
        self.caplen < self.orig_len
    }
}

/// Static facts about an opened capture file.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureFileMeta {
    /// Display name (file stem + extension), never the full path — the
    /// path can contain a username and reaches the model via the digest.
    pub name: String,
    pub format: &'static str,
    pub link_type: LinkType,
    /// Declared snaplen, or 0 when the format does not state one.
    pub snaplen: u32,
    /// Size of the (decompressed) capture in bytes.
    pub file_bytes: u64,
    /// True when the on-disk file was gzipped and we decompressed it.
    pub was_compressed: bool,
}

/// A transport-layer port pair, kept as a distinct type so flow keys
/// cannot silently swap src and dst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ports {
    pub src: u16,
    pub dst: u16,
}

/// IP protocol numbers we name. Anything else keeps its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpProto {
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Ipv6Icmp,
    Gre,
    Esp,
    Ah,
    Ospf,
    Vrrp,
    Sctp,
    Other(u8),
}

impl IpProto {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Icmp,
            2 => Self::Igmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            47 => Self::Gre,
            50 => Self::Esp,
            51 => Self::Ah,
            58 => Self::Ipv6Icmp,
            89 => Self::Ospf,
            112 => Self::Vrrp,
            132 => Self::Sctp,
            other => Self::Other(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Igmp => "igmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ipv6Icmp => "icmpv6",
            Self::Gre => "gre",
            Self::Esp => "esp",
            Self::Ah => "ah",
            Self::Ospf => "ospf",
            Self::Vrrp => "vrrp",
            Self::Sctp => "sctp",
            Self::Other(_) => "ip",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_types_round_trip_the_registry_numbers_we_name() {
        for (n, expected) in [
            (0u16, LinkType::Null),
            (1, LinkType::Ethernet),
            (101, LinkType::RawIp),
            (108, LinkType::Loop),
            (113, LinkType::LinuxSll),
            (228, LinkType::Ipv4),
            (229, LinkType::Ipv6),
            (276, LinkType::LinuxSll2),
        ] {
            assert_eq!(LinkType::from_u16(n), expected);
            assert!(expected.is_supported(), "{expected:?} must dissect");
        }
        assert_eq!(LinkType::from_u16(9999), LinkType::Other(9999));
        assert!(!LinkType::from_u16(9999).is_supported());
    }

    #[test]
    fn endian_reads_both_orders() {
        assert_eq!(Endian::Little.u32([1, 0, 0, 0]), 1);
        assert_eq!(Endian::Big.u32([0, 0, 0, 1]), 1);
        assert_eq!(Endian::Little.u16([2, 0]), 2);
        assert_eq!(Endian::Big.u16([0, 2]), 2);
    }

    #[test]
    fn ip_protocol_numbers_map_to_names() {
        assert_eq!(IpProto::from_u8(6), IpProto::Tcp);
        assert_eq!(IpProto::from_u8(17), IpProto::Udp);
        assert_eq!(IpProto::from_u8(89), IpProto::Ospf);
        assert_eq!(IpProto::from_u8(200), IpProto::Other(200));
        assert_eq!(IpProto::from_u8(200).as_str(), "ip");
    }
}
