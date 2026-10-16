//! Classic-pcap writer.
//!
//! Two callers, and they are why this is production code rather than a
//! test helper:
//!
//! - **`pcap_export`** — save the packets matching the current view
//!   filter as a new capture the user can hand to someone else.
//! - **The test corpus.** Every capture Transit's tests read is one this
//!   writer produced from RFC field layouts (`tests/synth.rs`). We
//!   deliberately import no third-party sample captures: the ones on the
//!   Wireshark wiki carry other people's licenses, and reflexively
//!   copying them into a closed-source commercial repo is the easiest IP
//!   mistake to make here (plan §11).
//!
//! Classic pcap rather than pcapng because it is the universally-readable
//! format: every tool made in the last twenty-five years opens it, and an
//! exported subset is something the user will hand to a vendor TAC.

use std::io::{BufWriter, Write};
use std::path::Path;

use crate::error::Result;
use crate::types::LinkType;

/// Microsecond-resolution little-endian magic.
const MAGIC_LE_US: u32 = 0xa1b2_c3d4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;

/// Writes packets to a classic pcap file, little-endian, microseconds.
pub struct PcapWriter<W: Write> {
    out: W,
    snaplen: u32,
}

impl PcapWriter<BufWriter<std::fs::File>> {
    /// Create `path` and write the file header.
    pub fn create(path: &Path, link_type: LinkType, snaplen: u32) -> Result<Self> {
        let file = std::fs::File::create(path)?;
        Self::new(BufWriter::new(file), link_type, snaplen)
    }
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut out: W, link_type: LinkType, snaplen: u32) -> Result<Self> {
        let network = link_type_number(link_type);
        let snaplen = if snaplen == 0 { 262_144 } else { snaplen };
        out.write_all(&MAGIC_LE_US.to_le_bytes())?;
        out.write_all(&VERSION_MAJOR.to_le_bytes())?;
        out.write_all(&VERSION_MINOR.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // thiszone — always UTC
        out.write_all(&0u32.to_le_bytes())?; // sigfigs — always 0 in practice
        out.write_all(&snaplen.to_le_bytes())?;
        out.write_all(&u32::from(network).to_le_bytes())?;
        Ok(Self { out, snaplen })
    }

    /// Append one packet.
    ///
    /// `orig_len` is the on-the-wire length, which may exceed `data.len()`
    /// when the source capture was snapped — preserving it keeps byte
    /// counts honest in anything that reads the export back.
    pub fn write_packet(&mut self, ts_us: i64, orig_len: u32, data: &[u8]) -> Result<()> {
        // Negative timestamps (a capture with a bogus clock) would wrap
        // when cast to u32; clamp at the epoch rather than emitting a
        // record that reads as the year 2106.
        let ts_us = ts_us.max(0);
        let secs = (ts_us / 1_000_000) as u32;
        let micros = (ts_us % 1_000_000) as u32;
        let caplen = data.len().min(self.snaplen as usize) as u32;

        self.out.write_all(&secs.to_le_bytes())?;
        self.out.write_all(&micros.to_le_bytes())?;
        self.out.write_all(&caplen.to_le_bytes())?;
        self.out.write_all(&orig_len.max(caplen).to_le_bytes())?;
        self.out.write_all(&data[..caplen as usize])?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

/// Map back to the LINKTYPE_* number for the header.
fn link_type_number(lt: LinkType) -> u16 {
    match lt {
        LinkType::Null => 0,
        LinkType::Ethernet => 1,
        LinkType::RawIp => 101,
        LinkType::Ieee80211 => 105,
        LinkType::Loop => 108,
        LinkType::LinuxSll => 113,
        LinkType::Ipv4 => 228,
        LinkType::Ipv6 => 229,
        LinkType::LinuxSll2 => 276,
        LinkType::Other(n) => n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_type_numbers_round_trip() {
        for lt in [
            LinkType::Null,
            LinkType::Ethernet,
            LinkType::RawIp,
            LinkType::Loop,
            LinkType::LinuxSll,
            LinkType::Ipv4,
            LinkType::Ipv6,
            LinkType::LinuxSll2,
            LinkType::Other(147),
        ] {
            assert_eq!(LinkType::from_u16(link_type_number(lt)), lt);
        }
    }

    #[test]
    fn header_is_twenty_four_bytes_with_the_expected_magic() {
        let mut buf = Vec::new();
        PcapWriter::new(&mut buf, LinkType::Ethernet, 262_144)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[..4], &MAGIC_LE_US.to_le_bytes());
        assert_eq!(u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]), 1);
    }

    #[test]
    fn a_snapped_packet_keeps_its_original_length() {
        let mut buf = Vec::new();
        let mut w = PcapWriter::new(&mut buf, LinkType::Ethernet, 16).unwrap();
        w.write_packet(1_000_000, 1514, &[0xAAu8; 100]).unwrap();
        w.finish().unwrap();
        // 24 header + 16 record header + 16 snapped bytes.
        assert_eq!(buf.len(), 24 + 16 + 16);
        let caplen = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let orig = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        assert_eq!(caplen, 16, "caplen is clamped to the snaplen");
        assert_eq!(orig, 1514, "wire length survives the snap");
    }

    #[test]
    fn negative_timestamps_clamp_instead_of_wrapping() {
        let mut buf = Vec::new();
        let mut w = PcapWriter::new(&mut buf, LinkType::Ethernet, 0).unwrap();
        w.write_packet(-5_000_000, 4, &[1, 2, 3, 4]).unwrap();
        w.finish().unwrap();
        let secs = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        assert_eq!(secs, 0, "a bogus clock must not read as the year 2106");
    }
}
