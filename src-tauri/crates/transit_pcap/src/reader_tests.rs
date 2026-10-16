//! Reader corpus.
//!
//! Every capture here is synthesized byte-by-byte from the format specs.
//! We import no third-party sample captures — see `writer.rs` for why
//! that is a deliberate rule and not an oversight.
//!
//! The tests fall into three groups:
//!
//! 1. **Round-trips** — what the writer wrote, the scanner reads back,
//!    with the offsets the fetcher can then seek to.
//! 2. **Hostile input** — absurd lengths, impossible blocks, garbage
//!    magic. Each must produce an error, never an allocation the size of
//!    the field that asked for it, and never a panic.
//! 3. **Live-capture shapes** — a file that ends mid-record is the normal
//!    state of a capture in progress, not corruption.

use std::io::Write;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use super::*;
use crate::error::PcapError;
use crate::types::{LinkType, RawPacket};
use crate::writer::PcapWriter;

// ---------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------

fn tmp(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    (dir, path)
}

/// A recognizable Ethernet+IPv4+UDP-ish payload of `len` bytes. The
/// content only has to be distinguishable per packet for the round-trip
/// assertions; real protocol shapes live in the dissector corpus.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

/// Classic pcap with `count` packets, one second apart.
fn write_classic(path: &Path, count: u64, packet_len: usize) {
    let mut w = PcapWriter::create(path, LinkType::Ethernet, 262_144).unwrap();
    for i in 0..count {
        w.write_packet(
            (i as i64 + 1) * 1_000_000,
            packet_len as u32,
            &payload(i as u8, packet_len),
        )
        .unwrap();
    }
    w.finish().unwrap();
}

/// Minimal pcapng builder — SHB, one IDB, then Enhanced Packet Blocks.
struct NgBuilder {
    buf: Vec<u8>,
    ts_per_second: u64,
}

impl NgBuilder {
    /// `tsresol` is the `if_tsresol` option value: `6` = microseconds
    /// (the default), `9` = nanoseconds.
    fn new(link_type: u16, tsresol: Option<u8>) -> Self {
        let mut buf = Vec::new();

        // Section Header Block. 28 bytes with no options.
        buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
        buf.extend_from_slice(&1u16.to_le_bytes()); // major
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor
        buf.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
        buf.extend_from_slice(&28u32.to_le_bytes());

        // Interface Description Block.
        let mut opts = Vec::new();
        if let Some(v) = tsresol {
            opts.extend_from_slice(&9u16.to_le_bytes()); // if_tsresol
            opts.extend_from_slice(&1u16.to_le_bytes()); // length
            opts.push(v);
            opts.extend_from_slice(&[0, 0, 0]); // pad to 4
            opts.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
            opts.extend_from_slice(&0u16.to_le_bytes());
        }
        let idb_len = 20 + opts.len() as u32;
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&idb_len.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&opts);
        buf.extend_from_slice(&idb_len.to_le_bytes());

        let ts_per_second = match tsresol {
            Some(v) if v & 0x80 == 0 => 10u64.pow(u32::from(v)),
            Some(v) => 1u64 << (v & 0x7f),
            None => 1_000_000,
        };
        Self { buf, ts_per_second }
    }

    /// Append an Enhanced Packet Block. `ts_us` is converted into the
    /// interface's tick resolution so the reader has to undo it.
    fn epb(&mut self, ts_us: i64, orig_len: u32, data: &[u8]) -> &mut Self {
        let ticks = (ts_us as u128 * self.ts_per_second as u128 / 1_000_000) as u64;
        let padded = data.len().div_ceil(4) * 4;
        let total = 32 + padded as u32;

        self.buf.extend_from_slice(&6u32.to_le_bytes());
        self.buf.extend_from_slice(&total.to_le_bytes());
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // interface id
        self.buf
            .extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&((ticks & 0xFFFF_FFFF) as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&orig_len.to_le_bytes());
        self.buf.extend_from_slice(data);
        self.buf.extend_from_slice(&vec![0u8; padded - data.len()]);
        self.buf.extend_from_slice(&total.to_le_bytes());
        self
    }

    /// A Simple Packet Block — no timestamp, no interface id.
    fn spb(&mut self, orig_len: u32, data: &[u8]) -> &mut Self {
        let padded = data.len().div_ceil(4) * 4;
        let total = 16 + padded as u32;
        self.buf.extend_from_slice(&3u32.to_le_bytes());
        self.buf.extend_from_slice(&total.to_le_bytes());
        self.buf.extend_from_slice(&orig_len.to_le_bytes());
        self.buf.extend_from_slice(data);
        self.buf.extend_from_slice(&vec![0u8; padded - data.len()]);
        self.buf.extend_from_slice(&total.to_le_bytes());
        self
    }

    fn write(&self, path: &Path) {
        std::fs::write(path, &self.buf).unwrap();
    }
}

/// Collect every packet a scan yields, as owned copies.
fn collect(file: &CaptureFile) -> (Vec<OwnedPacket>, ScanSummary, Vec<Interface>) {
    let mut scanner = file.scanner().unwrap();
    let mut out = Vec::new();
    let summary = scanner.for_each(|p| {
        out.push(OwnedPacket {
            number: p.number,
            ts_us: p.ts_us,
            caplen: p.caplen,
            orig_len: p.orig_len,
            offset: p.offset,
            link_type: p.link_type,
            data: p.data.to_vec(),
        });
        ControlFlow::Continue(())
    });
    let interfaces = scanner.interfaces.clone();
    (out, summary, interfaces)
}

// ---------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------

#[test]
fn classic_pcap_round_trips_with_offsets() {
    let (_d, path) = tmp("classic.pcap");
    write_classic(&path, 5, 64);

    let file = CaptureFile::open(&path).unwrap();
    assert_eq!(file.meta.format, "pcap");
    assert_eq!(file.meta.link_type, LinkType::Ethernet);
    assert_eq!(file.meta.snaplen, 262_144);
    assert!(!file.meta.was_compressed);

    let (packets, summary, _) = collect(&file);
    assert_eq!(summary.packets, 5);
    assert!(!summary.truncated_tail);
    assert!(!summary.stopped_on_error);
    assert_eq!(packets.len(), 5);

    // Numbering is 1-based and in file order; the first record sits
    // immediately after the 24-byte file header, and each record is
    // 16 bytes of header plus its payload.
    assert_eq!(packets[0].number, 1);
    assert_eq!(packets[0].offset, 24);
    assert_eq!(packets[1].offset, 24 + 16 + 64);
    assert_eq!(packets[0].ts_us, 1_000_000);
    assert_eq!(packets[4].ts_us, 5_000_000);
    assert_eq!(packets[0].data, payload(0, 64));
    assert_eq!(packets[3].data, payload(3, 64));
}

#[test]
fn classic_pcap_fetches_a_single_packet_by_offset() {
    let (_d, path) = tmp("fetch.pcap");
    write_classic(&path, 200, 100);

    let file = CaptureFile::open(&path).unwrap();
    let (packets, _, interfaces) = collect(&file);
    let mut fetcher = file.fetcher(interfaces).unwrap();

    // The whole point of storing offsets: reach packet 137 without
    // walking the 136 before it.
    for want in [0usize, 1, 42, 137, 199] {
        let expected = &packets[want];
        let got = fetcher.fetch(expected.number, expected.offset).unwrap();
        assert_eq!(got.number, expected.number);
        assert_eq!(got.ts_us, expected.ts_us);
        assert_eq!(got.caplen, expected.caplen);
        assert_eq!(got.data, expected.data, "packet {} bytes", expected.number);
    }
}

#[test]
fn pcapng_round_trips_enhanced_packet_blocks() {
    let (_d, path) = tmp("basic.pcapng");
    let mut b = NgBuilder::new(1, Some(6));
    b.epb(1_000_000, 74, &payload(1, 74))
        .epb(2_500_000, 128, &payload(2, 128))
        .epb(3_000_000, 60, &payload(3, 60));
    b.write(&path);

    let file = CaptureFile::open(&path).unwrap();
    assert_eq!(file.meta.format, "pcapng");
    assert_eq!(file.meta.link_type, LinkType::Ethernet);

    let (packets, summary, interfaces) = collect(&file);
    assert_eq!(summary.packets, 3);
    assert_eq!(interfaces.len(), 1);
    assert_eq!(packets[0].ts_us, 1_000_000);
    assert_eq!(packets[1].ts_us, 2_500_000);
    assert_eq!(packets[1].data, payload(2, 128));
    assert_eq!(packets[2].orig_len, 60);

    // SHB (28) + IDB with if_tsresol (32) = 60.
    assert_eq!(packets[0].offset, 60);
}

#[test]
fn pcapng_fetches_a_single_packet_by_offset() {
    let (_d, path) = tmp("fetch.pcapng");
    let mut b = NgBuilder::new(1, Some(6));
    for i in 0..50u8 {
        b.epb((i as i64 + 1) * 1_000, 80, &payload(i, 80));
    }
    b.write(&path);

    let file = CaptureFile::open(&path).unwrap();
    let (packets, _, interfaces) = collect(&file);
    let mut fetcher = file.fetcher(interfaces).unwrap();
    for want in [0usize, 17, 49] {
        let expected = &packets[want];
        let got = fetcher.fetch(expected.number, expected.offset).unwrap();
        assert_eq!(got.data, expected.data);
        assert_eq!(got.ts_us, expected.ts_us);
    }
}

#[test]
fn pcapng_nanosecond_resolution_is_converted() {
    let (_d, path) = tmp("nanos.pcapng");
    let mut b = NgBuilder::new(1, Some(9));
    b.epb(1_234_567, 64, &payload(7, 64));
    b.write(&path);

    let (packets, _, _) = collect(&CaptureFile::open(&path).unwrap());
    assert_eq!(packets[0].ts_us, 1_234_567, "nanosecond ticks → micros");
}

#[test]
fn pcapng_simple_packet_blocks_are_read() {
    let (_d, path) = tmp("spb.pcapng");
    let mut b = NgBuilder::new(1, None);
    b.spb(64, &payload(9, 64));
    b.write(&path);

    let (packets, summary, _) = collect(&CaptureFile::open(&path).unwrap());
    assert_eq!(summary.packets, 1);
    assert_eq!(packets[0].data, payload(9, 64));
    assert_eq!(packets[0].ts_us, 0, "an SPB carries no timestamp");
}

#[test]
fn nanosecond_classic_magic_is_understood() {
    let (_d, path) = tmp("nanos.pcap");
    // Hand-build the 0xa1b23c4d variant: the fractional field is nanos.
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_3c4du32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&262_144u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&7u32.to_le_bytes()); // ts_sec
    buf.extend_from_slice(&500_000_000u32.to_le_bytes()); // 0.5 s in nanos
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4]);
    std::fs::write(&path, &buf).unwrap();

    let (packets, _, _) = collect(&CaptureFile::open(&path).unwrap());
    assert_eq!(packets[0].ts_us, 7_500_000);
}

#[test]
fn big_endian_classic_captures_are_read() {
    let (_d, path) = tmp("be.pcap");
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&65_535u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&3u32.to_be_bytes());
    buf.extend_from_slice(&250_000u32.to_be_bytes());
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&[9, 8, 7, 6, 5]);
    std::fs::write(&path, &buf).unwrap();

    let file = CaptureFile::open(&path).unwrap();
    assert_eq!(file.meta.snaplen, 65_535);
    let (packets, _, _) = collect(&file);
    assert_eq!(packets[0].ts_us, 3_250_000);
    assert_eq!(packets[0].caplen, 5);
    assert_eq!(
        packets[0].orig_len, 9,
        "snapped packet keeps its wire length"
    );
}

#[test]
fn gzipped_captures_are_decompressed_transparently() {
    let (_d, path) = tmp("plain.pcap");
    write_classic(&path, 4, 48);
    let raw = std::fs::read(&path).unwrap();

    let gz_path = path.with_extension("pcap.gz");
    let mut enc =
        flate2::write::GzEncoder::new(std::fs::File::create(&gz_path).unwrap(), Default::default());
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap();

    let file = CaptureFile::open(&gz_path).unwrap();
    assert!(file.meta.was_compressed);
    let (packets, summary, _) = collect(&file);
    assert_eq!(summary.packets, 4);
    assert_eq!(packets[2].data, payload(2, 48));

    // Random access must work against the decompressed copy too — this
    // is why the gz path materializes a temp file instead of streaming.
    let interfaces = vec![Interface::default()];
    let mut fetcher = file.fetcher(interfaces).unwrap();
    let got = fetcher.fetch(3, packets[2].offset).unwrap();
    assert_eq!(got.data, packets[2].data);
}

// ---------------------------------------------------------------------
// Live-capture shapes
// ---------------------------------------------------------------------

#[test]
fn a_file_ending_mid_record_reports_truncation_not_corruption() {
    let (_d, path) = tmp("partial.pcap");
    write_classic(&path, 6, 80);

    // Lop off the last packet's payload, as if tcpdump were mid-write.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 40);
    std::fs::write(&path, &bytes).unwrap();

    let file = CaptureFile::open(&path).unwrap();
    let (packets, summary, _) = collect(&file);
    assert_eq!(summary.packets, 5, "the five complete packets still arrive");
    assert!(
        summary.truncated_tail,
        "the partial sixth is a truncated tail"
    );
    assert!(
        !summary.stopped_on_error,
        "mid-write is not corruption — the UI must not say the file is damaged"
    );
    assert_eq!(packets.len(), 5);
    // Resuming here is what the live indexer does on the next tick.
    assert_eq!(summary.end_offset, 24 + 5 * (16 + 80));
}

#[test]
fn a_scan_can_resume_at_a_recorded_offset() {
    let (_d, path) = tmp("resume.pcap");
    write_classic(&path, 10, 32);
    let file = CaptureFile::open(&path).unwrap();

    // First pass: stop after three packets, as a live tick would.
    let mut first = file.scanner().unwrap();
    let mut seen = 0;
    first.for_each(|_| {
        seen += 1;
        if seen == 3 {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    let resume_at = first.position();
    let resume_number = first.last_number();
    assert_eq!(resume_number, 3);

    // Second pass picks up exactly where the first stopped, with the
    // numbering continuing rather than restarting at 1.
    let mut second = file
        .scanner_from(resume_at, resume_number, first.interfaces.clone())
        .unwrap();
    let mut rest = Vec::new();
    second.for_each(|p| {
        rest.push(p.number);
        ControlFlow::Continue(())
    });
    assert_eq!(rest, (4..=10).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------

#[test]
fn a_caplen_over_the_ceiling_is_refused_before_allocating() {
    let (_d, path) = tmp("huge.pcap");
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&262_144u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    // A record header claiming a 4 GB packet in a 44-byte file.
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    std::fs::write(&path, &buf).unwrap();

    let file = CaptureFile::open(&path).unwrap();
    let (packets, summary, _) = collect(&file);
    assert!(packets.is_empty());
    assert!(
        summary.stopped_on_error,
        "an impossible length is corruption, not a truncated tail"
    );
}

#[test]
fn impossible_pcapng_block_lengths_are_refused() {
    for bad_len in [0u32, 4, 11, 13 /* unaligned */, 0xFFFF_FFFF] {
        let mut buf = Vec::new();
        // Valid SHB so the file opens, then a hostile block.
        buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&bad_len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);

        let (_d, path) = tmp("bad-block.pcapng");
        std::fs::write(&path, &buf).unwrap();
        let file = CaptureFile::open(&path).unwrap();
        let (packets, summary, _) = collect(&file);
        assert!(packets.is_empty(), "bad_len {bad_len} yielded packets");
        assert!(summary.stopped_on_error, "bad_len {bad_len} was accepted");
    }
}

#[test]
fn an_epb_claiming_more_data_than_its_block_holds_is_refused() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    // EPB whose declared caplen (9000) exceeds its 32-byte block.
    buf.extend_from_slice(&6u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&9000u32.to_le_bytes()); // caplen — a lie
    buf.extend_from_slice(&9000u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());

    let (_d, path) = tmp("liar.pcapng");
    std::fs::write(&path, &buf).unwrap();
    let file = CaptureFile::open(&path).unwrap();
    let (packets, summary, _) = collect(&file);
    assert!(packets.is_empty());
    assert!(summary.stopped_on_error);
}

#[test]
fn unrecognized_magic_and_empty_files_are_named_clearly() {
    let (_d, path) = tmp("garbage.pcap");
    std::fs::write(&path, b"this is not a capture file at all").unwrap();
    assert!(matches!(
        CaptureFile::open(&path),
        Err(PcapError::UnknownFormat)
    ));

    let (_d2, empty) = tmp("empty.pcap");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(CaptureFile::open(&empty), Err(PcapError::Empty)));
}

#[test]
fn a_file_over_the_size_ceiling_is_refused() {
    let (_d, path) = tmp("big.pcap");
    write_classic(&path, 10, 100);
    let err = CaptureFile::open_with_limits(&path, 64, 1024).unwrap_err();
    assert!(matches!(err, PcapError::TooLarge { .. }), "got {err:?}");
}

#[test]
fn a_gzip_bomb_is_refused_at_the_decompressed_ceiling() {
    let (_d, path) = tmp("bomb.pcap.gz");
    // Highly compressible input that expands well past the limit we pass.
    let mut enc =
        flate2::write::GzEncoder::new(std::fs::File::create(&path).unwrap(), Default::default());
    enc.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
    enc.finish().unwrap();

    let err = CaptureFile::open_with_limits(&path, u64::MAX, 64 * 1024).unwrap_err();
    assert!(matches!(err, PcapError::TooLarge { .. }), "got {err:?}");
}

#[test]
fn an_undescribed_interface_id_does_not_drop_the_packet() {
    // A packet referencing interface 7 when only interface 0 exists is
    // malformed. Defaulting keeps it visible; dropping it silently would
    // hide traffic from an analyst who has no way to know.
    let mut b = NgBuilder::new(1, Some(6));
    b.epb(1_000_000, 64, &payload(1, 64));
    // Rewrite the interface id of the EPB we just wrote (it starts at
    // offset 60; the interface id is 8 bytes into the block).
    let idx = 60 + 8;
    b.buf[idx..idx + 4].copy_from_slice(&7u32.to_le_bytes());

    let (_d, path) = tmp("ghost-iface.pcapng");
    b.write(&path);
    let (packets, summary, _) = collect(&CaptureFile::open(&path).unwrap());
    assert_eq!(summary.packets, 1);
    assert_eq!(packets[0].data, payload(1, 64));
}

/// The headline robustness property. A capture file arrives from anywhere
/// — an email attachment, a bug tracker, a vendor. No byte sequence may
/// panic the reader, and none may make it allocate without bound.
#[test]
fn arbitrary_bytes_never_panic() {
    proptest::proptest!(|(body: Vec<u8>, ng: bool)| {
        let mut buf = Vec::new();
        if ng {
            buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
            buf.extend_from_slice(&28u32.to_le_bytes());
            buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
            buf.extend_from_slice(&1u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&(-1i64).to_le_bytes());
            buf.extend_from_slice(&28u32.to_le_bytes());
        } else {
            buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
            buf.extend_from_slice(&2u16.to_le_bytes());
            buf.extend_from_slice(&4u16.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&262_144u32.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes());
        }
        buf.extend_from_slice(&body);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuzz.cap");
        std::fs::write(&path, &buf).unwrap();

        if let Ok(file) = CaptureFile::open(&path) {
            let mut scanner = file.scanner().unwrap();
            scanner.for_each(|p: &RawPacket<'_>| {
                // Whatever the file claimed, what we hand out is coherent:
                // the byte slice is exactly caplen long and the wire
                // length is never smaller than what we captured. Every
                // downstream consumer indexes on those two facts.
                assert_eq!(p.caplen as usize, p.data.len());
                assert!(p.orig_len >= p.caplen);
                ControlFlow::Continue(())
            });
        }
    });
}
