//! Capture-file reader for classic pcap and pcapng.
//!
//! # Why this is ours rather than a crate
//!
//! Three requirements no off-the-shelf reader gives us at once:
//!
//! 1. **A byte offset for every packet.** The index stores it so a detail
//!    view re-reads and re-dissects exactly one packet. Without offsets
//!    we would have to keep every packet's bytes resident, and a 1.2 GB
//!    capture would cost 1.2 GB of RAM instead of ~50 MB of index.
//! 2. **Tolerance for a truncated tail.** A live capture is read while
//!    `tcpdump` is still writing it. A half-written record at the end is
//!    the normal case, not corruption: the scan stops cleanly, reports
//!    how far it got, and resumes from there on the next tick.
//! 3. **Total control of bounds checking.** This is an untrusted-input
//!    parser by definition — a capture file can be handed to a user by
//!    anyone, and every length field in it is attacker-chosen. Every
//!    read here is bounded against both the declared block length and an
//!    absolute ceiling before a single byte is allocated.
//!
//! Both formats are small and frozen, which is what makes owning them
//! reasonable: classic pcap is a 24-byte file header plus a 16-byte
//! record header, and pcapng is a chain of length-prefixed blocks of
//! which four matter.
//!
//! # Robustness contract
//!
//! Nothing in this module panics on any input. Malformed lengths, absurd
//! block sizes, an interface id that was never described, a caplen larger
//! than the block containing it — each returns an error or is skipped
//! with a count, never an unwrap. `tests::arbitrary_bytes_never_panic`
//! pins that with proptest.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::error::{PcapError, Result};
use crate::types::{CaptureFileMeta, CaptureFormat, Endian, LinkType, RawPacket};

// ---------------------------------------------------------------------
// Ceilings. Every one of these bounds an allocation driven by a number
// read out of the file.
// ---------------------------------------------------------------------

/// Largest single packet we will hold. Real snaplens top out at 262144;
/// this leaves generous headroom for jumbo/USB captures while keeping a
/// corrupt 4 GB length field from becoming a 4 GB allocation.
pub const MAX_PACKET_BYTES: u32 = 16 * 1024 * 1024;

/// Largest pcapng block. Options and name-resolution blocks can be big;
/// nothing legitimate approaches this.
const MAX_BLOCK_BYTES: u32 = 32 * 1024 * 1024;

/// Default ceiling on the capture file itself.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// A gz-compressed capture is decompressed on open; this bounds the
/// decompressed size so a zip-bomb cannot fill the disk.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

const PCAP_MAGIC_LE_US: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const PCAP_MAGIC_BE_US: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const PCAP_MAGIC_LE_NS: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const PCAP_MAGIC_BE_NS: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
const PCAPNG_SHB_TYPE: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

const BLOCK_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_PACKET_LEGACY: u32 = 0x0000_0002;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_EPB: u32 = 0x0000_0006;

// ---------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------

/// A capture file opened and ready to scan.
///
/// Holds the temp file for a gz-decompressed capture, so the decompressed
/// bytes live exactly as long as the capture is open and are removed when
/// it closes.
#[derive(Debug)]
pub struct CaptureFile {
    path: PathBuf,
    /// Dropped (and unlinked) when the capture closes.
    _temp: Option<tempfile::TempPath>,
    pub format: CaptureFormat,
    pub meta: CaptureFileMeta,
}

impl CaptureFile {
    /// Open `path`, transparently decompressing a gzipped capture.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_limits(path, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_DECOMPRESSED_BYTES)
    }

    pub fn open_with_limits(path: &Path, max_file: u64, max_decompressed: u64) -> Result<Self> {
        let display_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "capture".to_string());

        let mut probe = [0u8; 2];
        let read = File::open(path)?.read(&mut probe)?;
        if read == 0 {
            return Err(PcapError::Empty);
        }

        let (work_path, temp, was_compressed) = if read == 2 && probe == GZIP_MAGIC {
            let (p, t) = gunzip_to_temp(path, max_decompressed)?;
            (p, Some(t), true)
        } else {
            (path.to_path_buf(), None, false)
        };

        let file_bytes = std::fs::metadata(&work_path)?.len();
        if file_bytes > max_file {
            return Err(PcapError::TooLarge {
                size: file_bytes,
                limit: max_file,
            });
        }

        let (format, link_type, snaplen) = probe_header(&work_path)?;

        Ok(Self {
            path: work_path,
            _temp: temp,
            format,
            meta: CaptureFileMeta {
                name: crate::sanitize::field(&display_name),
                format: format.as_str(),
                link_type,
                snaplen,
                file_bytes,
                was_compressed,
            },
        })
    }

    /// Current size of the backing file. Grows while a live capture runs.
    pub fn current_len(&self) -> Result<u64> {
        Ok(std::fs::metadata(&self.path)?.len())
    }

    /// A sequential scanner positioned at the first packet.
    pub fn scanner(&self) -> Result<Scanner> {
        Scanner::new(&self.path, self.format)
    }

    /// A sequential scanner that resumes at `offset` with packet
    /// numbering continuing from `next_number`. Used by the live indexer
    /// to pick up where the previous tick stopped.
    pub fn scanner_from(
        &self,
        offset: u64,
        next_number: u64,
        interfaces: Vec<Interface>,
    ) -> Result<Scanner> {
        let mut s = Scanner::new(&self.path, self.format)?;
        s.file.seek(SeekFrom::Start(offset))?;
        s.pos = offset;
        s.number = next_number;
        s.interfaces = interfaces;
        Ok(s)
    }

    /// A random-access fetcher for single packets.
    pub fn fetcher(&self, interfaces: Vec<Interface>) -> Result<Fetcher> {
        Ok(Fetcher {
            file: File::open(&self.path)?,
            format: self.format,
            interfaces,
        })
    }
}

/// Decompress a gzipped capture into a temp file, bounded.
fn gunzip_to_temp(path: &Path, max_bytes: u64) -> Result<(PathBuf, tempfile::TempPath)> {
    let src = File::open(path)?;
    let mut decoder = flate2::read::MultiGzDecoder::new(BufReader::new(src));
    let mut out = tempfile::Builder::new()
        .prefix("transit-pcap-")
        .suffix(".pcap")
        .tempfile()
        .map_err(|e| PcapError::Gunzip {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    // `take` is the bomb guard: we copy at most max_bytes+1 and refuse if
    // the extra byte materialized, so the disk can never be filled by a
    // small input.
    let mut limited = (&mut decoder).take(max_bytes.saturating_add(1));
    let written =
        std::io::copy(&mut limited, out.as_file_mut()).map_err(|e| PcapError::Gunzip {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    if written > max_bytes {
        return Err(PcapError::TooLarge {
            size: written,
            limit: max_bytes,
        });
    }

    let temp_path = out.into_temp_path();
    Ok((temp_path.to_path_buf(), temp_path))
}

/// Read just enough of the file header to name the format, link type and
/// snaplen, without scanning packets.
fn probe_header(path: &Path) -> Result<(CaptureFormat, LinkType, u32)> {
    let mut f = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .map_err(|_| PcapError::UnknownFormat)?;

    if magic == PCAPNG_SHB_TYPE {
        // Section Header Block: type(4) total_len(4) byte-order-magic(4).
        // The byte-order magic decides the endianness of everything,
        // including the total_len we just read past.
        let mut rest = [0u8; 8];
        f.read_exact(&mut rest)
            .map_err(|_| PcapError::BadHeader("truncated section header"))?;
        let bom = [rest[4], rest[5], rest[6], rest[7]];
        let endian = match bom {
            [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
            [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
            _ => return Err(PcapError::BadHeader("bad byte-order magic")),
        };
        // The first IDB carries the link type. Scan for it rather than
        // assuming block order; a capture with no IDB has no packets.
        let (link_type, snaplen) = first_interface(path, CaptureFormat::PcapNg { endian })
            .unwrap_or((LinkType::Ethernet, 0));
        return Ok((CaptureFormat::PcapNg { endian }, link_type, snaplen));
    }

    let (endian, nanos) = match magic {
        PCAP_MAGIC_LE_US => (Endian::Little, false),
        PCAP_MAGIC_BE_US => (Endian::Big, false),
        PCAP_MAGIC_LE_NS => (Endian::Little, true),
        PCAP_MAGIC_BE_NS => (Endian::Big, true),
        _ => return Err(PcapError::UnknownFormat),
    };
    let mut rest = [0u8; 20];
    f.read_exact(&mut rest)
        .map_err(|_| PcapError::BadHeader("truncated pcap header"))?;
    let snaplen = endian.u32([rest[12], rest[13], rest[14], rest[15]]);
    let network = endian.u32([rest[16], rest[17], rest[18], rest[19]]);
    let link_type = LinkType::from_u16((network & 0xFFFF) as u16);
    Ok((CaptureFormat::Pcap { endian, nanos }, link_type, snaplen))
}

/// Walk a pcapng file for its first Interface Description Block.
fn first_interface(path: &Path, format: CaptureFormat) -> Option<(LinkType, u32)> {
    let mut scanner = Scanner::new(path, format).ok()?;
    // Scanning to the first packet is enough — an IDB always precedes the
    // packets that reference it.
    let _ = scanner.for_each(|_| ControlFlow::Break(()));
    scanner.interfaces.first().map(|i| (i.link_type, i.snaplen))
}

// ---------------------------------------------------------------------
// pcapng interface table
// ---------------------------------------------------------------------

/// One pcapng Interface Description Block.
#[derive(Debug, Clone, Copy)]
pub struct Interface {
    pub link_type: LinkType,
    pub snaplen: u32,
    /// Divisor turning a raw 64-bit timestamp into seconds, from the
    /// `if_tsresol` option. Default 1e6 (microseconds).
    pub ts_per_second: u64,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            snaplen: 0,
            ts_per_second: 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------
// Sequential scanning
// ---------------------------------------------------------------------

/// Where a scan stopped and what it skipped.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanSummary {
    /// Packets handed to the callback.
    pub packets: u64,
    /// Byte offset just past the last complete record. A live re-scan
    /// resumes here.
    pub end_offset: u64,
    /// True when the file ended mid-record. Normal for a live capture
    /// still being written — the next tick resumes at `end_offset`.
    pub truncated_tail: bool,
    /// True when the scan stopped because a record was structurally
    /// impossible rather than merely incomplete.
    ///
    /// Distinct from `truncated_tail` because the two mean opposite
    /// things to a user: one is "still recording", the other is "this
    /// file is damaged past packet N". Conflating them would show a
    /// corrupt capture as though it were mid-flight forever.
    pub stopped_on_error: bool,
    /// Blocks skipped because they were a type we do not index, had an
    /// impossible length, or referenced an undescribed interface.
    pub skipped_blocks: u64,
}

/// Sequential reader over a capture file.
pub struct Scanner {
    file: BufReader<File>,
    format: CaptureFormat,
    /// pcapng interface table, filled in as IDBs are met.
    pub interfaces: Vec<Interface>,
    /// Link type for classic pcap (constant for the whole file).
    pcap_link: LinkType,
    pos: u64,
    number: u64,
    /// Reusable packet buffer. On return from a `stage_*` helper its
    /// first `cur_caplen` bytes are the packet, starting at the link
    /// layer — the pcapng helpers `copy_within` the payload down to zero
    /// so every format presents the same shape here.
    buf: Vec<u8>,

    // Fields staged by the `stage_*` helpers for the packet currently in
    // `buf`, read by `for_each` when it builds the borrowed `RawPacket`.
    // Plain fields rather than a returned struct so the packet's bytes
    // never leave the reusable buffer.
    cur_offset: u64,
    cur_caplen: u32,
    cur_orig_len: u32,
    cur_ts_us: i64,
    cur_link: LinkType,
}

impl Scanner {
    fn new(path: &Path, format: CaptureFormat) -> Result<Self> {
        let mut file = BufReader::with_capacity(1 << 20, File::open(path)?);
        let (pos, pcap_link) = match format {
            CaptureFormat::Pcap { endian, .. } => {
                let mut hdr = [0u8; 24];
                file.read_exact(&mut hdr)
                    .map_err(|_| PcapError::BadHeader("truncated pcap header"))?;
                let network = endian.u32([hdr[20], hdr[21], hdr[22], hdr[23]]);
                (24u64, LinkType::from_u16((network & 0xFFFF) as u16))
            }
            // pcapng blocks are self-describing; start at zero and let the
            // block loop consume the section header.
            CaptureFormat::PcapNg { .. } => (0u64, LinkType::Ethernet),
        };
        Ok(Self {
            file,
            format,
            interfaces: Vec::new(),
            pcap_link,
            pos,
            number: 0,
            buf: Vec::with_capacity(64 * 1024),
            cur_offset: 0,
            cur_caplen: 0,
            cur_orig_len: 0,
            cur_ts_us: 0,
            cur_link: pcap_link,
        })
    }

    /// Offset just past the last complete record read.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Number of the last packet handed out.
    pub fn last_number(&self) -> u64 {
        self.number
    }

    /// Feed every packet to `f` until the file ends or `f` breaks.
    ///
    /// A callback rather than an `Iterator` because each packet borrows
    /// the scanner's reusable buffer — the lending-iterator shape Rust
    /// cannot express with `Iterator` today. The alternative (a `Vec` per
    /// packet) would be a million allocations on a large capture.
    pub fn for_each<F>(&mut self, mut f: F) -> ScanSummary
    where
        F: FnMut(&RawPacket<'_>) -> ControlFlow<()>,
    {
        let mut summary = ScanSummary {
            end_offset: self.pos,
            ..Default::default()
        };
        loop {
            match self.next_record() {
                Ok(Some(Record::Packet)) => {
                    let packet = RawPacket {
                        number: self.number,
                        ts_us: self.cur_ts_us,
                        caplen: self.cur_caplen,
                        orig_len: self.cur_orig_len,
                        offset: self.cur_offset,
                        data: &self.buf[..self.cur_caplen as usize],
                        link_type: self.cur_link,
                    };
                    summary.packets += 1;
                    summary.end_offset = self.pos;
                    if f(&packet).is_break() {
                        return summary;
                    }
                }
                Ok(Some(Record::Other)) => {
                    summary.skipped_blocks += 1;
                    summary.end_offset = self.pos;
                }
                Ok(None) => return summary,
                Err(PcapError::Truncated { .. }) => {
                    summary.truncated_tail = true;
                    return summary;
                }
                Err(_) => {
                    // A structurally impossible record. Every subsequent
                    // offset derives from this one's length, so there is
                    // nothing trustworthy to resynchronize on — stop and
                    // say so, rather than guessing and emitting packets
                    // assembled from the middle of other packets.
                    summary.stopped_on_error = true;
                    return summary;
                }
            }
        }
    }
}

/// What `next_record` produced.
enum Record {
    /// A packet; its fields are staged on the scanner.
    Packet,
    /// A non-packet block that advanced the position.
    Other,
}

impl Scanner {
    fn next_record(&mut self) -> Result<Option<Record>> {
        match self.format {
            CaptureFormat::Pcap { endian, nanos } => self.next_pcap_record(endian, nanos),
            CaptureFormat::PcapNg { endian } => self.next_ng_block(endian),
        }
    }

    /// Classic pcap: a 16-byte record header then `caplen` bytes.
    fn next_pcap_record(&mut self, endian: Endian, nanos: bool) -> Result<Option<Record>> {
        let offset = self.pos;
        let mut hdr = [0u8; 16];
        match read_full(&mut self.file, &mut hdr)? {
            0 => return Ok(None),
            16 => {}
            _ => return Err(PcapError::Truncated { at: offset }),
        }
        let ts_sec = endian.u32([hdr[0], hdr[1], hdr[2], hdr[3]]) as i64;
        let ts_frac = endian.u32([hdr[4], hdr[5], hdr[6], hdr[7]]) as i64;
        let caplen = endian.u32([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let orig_len = endian.u32([hdr[12], hdr[13], hdr[14], hdr[15]]);

        if caplen > MAX_PACKET_BYTES {
            return Err(PcapError::BadHeader("packet length over ceiling"));
        }
        self.buf.resize(caplen as usize, 0);
        if read_full(&mut self.file, &mut self.buf)? != caplen as usize {
            return Err(PcapError::Truncated { at: offset });
        }

        self.pos = offset + 16 + caplen as u64;
        self.number += 1;
        self.cur_offset = offset;
        self.cur_caplen = caplen;
        // A capture whose orig_len is smaller than caplen is malformed;
        // trust the bytes we actually have.
        self.cur_orig_len = orig_len.max(caplen);
        self.cur_ts_us = ts_sec.saturating_mul(1_000_000).saturating_add(if nanos {
            ts_frac / 1_000
        } else {
            ts_frac
        });
        self.cur_link = self.pcap_link;
        Ok(Some(Record::Packet))
    }

    /// pcapng: every block is `type(4) length(4) body length(4)`.
    fn next_ng_block(&mut self, endian: Endian) -> Result<Option<Record>> {
        let offset = self.pos;
        let mut head = [0u8; 8];
        match read_full(&mut self.file, &mut head)? {
            0 => return Ok(None),
            8 => {}
            _ => return Err(PcapError::Truncated { at: offset }),
        }
        let block_type = endian.u32([head[0], head[1], head[2], head[3]]);
        let total_len = endian.u32([head[4], head[5], head[6], head[7]]);

        // 12 = the three framing words. A shorter or unaligned length is
        // structurally impossible, and an enormous one is a corrupt or
        // hostile file — refuse before allocating.
        if total_len < 12 || !total_len.is_multiple_of(4) || total_len > MAX_BLOCK_BYTES {
            return Err(PcapError::BadHeader("bad pcapng block length"));
        }

        let body_len = (total_len - 12) as usize;
        self.buf.resize(body_len, 0);
        if read_full(&mut self.file, &mut self.buf)? != body_len {
            return Err(PcapError::Truncated { at: offset });
        }
        let mut trailer = [0u8; 4];
        if read_full(&mut self.file, &mut trailer)? != 4 {
            return Err(PcapError::Truncated { at: offset });
        }
        self.pos = offset + total_len as u64;

        match block_type {
            BLOCK_SHB => {
                // A new section resets the interface table: interface ids
                // are section-scoped, so carrying them over would map a
                // packet to the wrong link type.
                self.interfaces.clear();
                Ok(Some(Record::Other))
            }
            BLOCK_IDB => {
                self.interfaces.push(parse_idb(&self.buf, endian));
                Ok(Some(Record::Other))
            }
            BLOCK_EPB => self.stage_epb(endian, offset),
            BLOCK_SPB => self.stage_spb(endian, offset),
            BLOCK_PACKET_LEGACY => self.stage_legacy_packet(endian, offset),
            _ => Ok(Some(Record::Other)),
        }
    }

    fn stage_epb(&mut self, endian: Endian, offset: u64) -> Result<Option<Record>> {
        // interface_id(4) ts_high(4) ts_low(4) caplen(4) origlen(4) data…
        if self.buf.len() < 20 {
            return Err(PcapError::BadHeader("short enhanced packet block"));
        }
        let b = &self.buf;
        let iface_id = endian.u32([b[0], b[1], b[2], b[3]]);
        let ts_high = endian.u32([b[4], b[5], b[6], b[7]]) as u64;
        let ts_low = endian.u32([b[8], b[9], b[10], b[11]]) as u64;
        let caplen = endian.u32([b[12], b[13], b[14], b[15]]);
        let orig_len = endian.u32([b[16], b[17], b[18], b[19]]);

        if caplen > MAX_PACKET_BYTES || 20usize.saturating_add(caplen as usize) > b.len() {
            return Err(PcapError::BadHeader("packet longer than its block"));
        }
        let iface = self.interface(iface_id);
        self.cur_ts_us = ticks_to_micros((ts_high << 32) | ts_low, iface.ts_per_second);
        self.buf.copy_within(20..20 + caplen as usize, 0);
        self.finish_ng_packet(offset, caplen, orig_len, iface.link_type);
        Ok(Some(Record::Packet))
    }

    fn stage_spb(&mut self, endian: Endian, offset: u64) -> Result<Option<Record>> {
        // orig_len(4) data… — no timestamp, no interface id. Rare, but
        // legal, and refusing would drop real packets.
        if self.buf.len() < 4 {
            return Err(PcapError::BadHeader("short simple packet block"));
        }
        let b = &self.buf;
        let orig_len = endian.u32([b[0], b[1], b[2], b[3]]);
        let available = (b.len() - 4) as u32;
        let iface = self.interface(0);
        let caplen = orig_len.min(available).min(MAX_PACKET_BYTES);
        self.cur_ts_us = 0;
        self.buf.copy_within(4..4 + caplen as usize, 0);
        self.finish_ng_packet(offset, caplen, orig_len, iface.link_type);
        Ok(Some(Record::Packet))
    }

    fn stage_legacy_packet(&mut self, endian: Endian, offset: u64) -> Result<Option<Record>> {
        // Obsolete Packet Block: interface_id(2) drops(2) ts_high(4)
        // ts_low(4) caplen(4) origlen(4) data…
        if self.buf.len() < 20 {
            return Err(PcapError::BadHeader("short legacy packet block"));
        }
        let b = &self.buf;
        let iface_id = endian.u16([b[0], b[1]]) as u32;
        let ts_high = endian.u32([b[4], b[5], b[6], b[7]]) as u64;
        let ts_low = endian.u32([b[8], b[9], b[10], b[11]]) as u64;
        let caplen = endian.u32([b[12], b[13], b[14], b[15]]);
        let orig_len = endian.u32([b[16], b[17], b[18], b[19]]);
        if caplen > MAX_PACKET_BYTES || 20usize.saturating_add(caplen as usize) > b.len() {
            return Err(PcapError::BadHeader("packet longer than its block"));
        }
        let iface = self.interface(iface_id);
        self.cur_ts_us = ticks_to_micros((ts_high << 32) | ts_low, iface.ts_per_second);
        self.buf.copy_within(20..20 + caplen as usize, 0);
        self.finish_ng_packet(offset, caplen, orig_len, iface.link_type);
        Ok(Some(Record::Packet))
    }

    fn finish_ng_packet(&mut self, offset: u64, caplen: u32, orig_len: u32, link: LinkType) {
        self.buf.truncate(caplen as usize);
        self.number += 1;
        self.cur_offset = offset;
        self.cur_caplen = caplen;
        self.cur_orig_len = orig_len.max(caplen);
        self.cur_link = link;
    }

    /// Interface `id`, or a default. A packet referencing an interface
    /// that was never described is malformed; defaulting keeps the packet
    /// visible (with an Ethernet guess) rather than dropping it silently.
    fn interface(&self, id: u32) -> Interface {
        self.interfaces
            .get(id as usize)
            .copied()
            .unwrap_or_default()
    }
}

/// Parse an Interface Description Block body: link_type(2) reserved(2)
/// snaplen(4) then options.
fn parse_idb(body: &[u8], endian: Endian) -> Interface {
    let mut iface = Interface::default();
    if body.len() < 8 {
        return iface;
    }
    iface.link_type = LinkType::from_u16(endian.u16([body[0], body[1]]));
    iface.snaplen = endian.u32([body[4], body[5], body[6], body[7]]);

    // Options: code(2) len(2) value(len, padded to 4). We want if_tsresol
    // (code 9), a single byte: high bit clear → 10^-v, set → 2^-(v&0x7f).
    let mut at = 8usize;
    while at + 4 <= body.len() {
        let code = endian.u16([body[at], body[at + 1]]);
        let len = endian.u16([body[at + 2], body[at + 3]]) as usize;
        let value_at = at + 4;
        if code == 0 {
            break; // opt_endofopt
        }
        if value_at + len > body.len() {
            break;
        }
        if code == 9 && len == 1 {
            let v = body[value_at];
            iface.ts_per_second = if v & 0x80 == 0 {
                10u64.checked_pow(u32::from(v & 0x7f)).unwrap_or(1_000_000)
            } else {
                1u64.checked_shl(u32::from(v & 0x7f)).unwrap_or(1_000_000)
            };
            if iface.ts_per_second == 0 {
                iface.ts_per_second = 1_000_000;
            }
        }
        // Options are padded to a 4-byte boundary.
        at = value_at + len.div_ceil(4) * 4;
    }
    iface
}

/// Convert a raw pcapng tick count to microseconds since the epoch.
fn ticks_to_micros(ticks: u64, per_second: u64) -> i64 {
    if per_second == 0 {
        return 0;
    }
    if per_second == 1_000_000 {
        return ticks as i64;
    }
    let secs = ticks / per_second;
    let rem = ticks % per_second;
    let micros = (rem as u128 * 1_000_000 / per_second as u128) as u64;
    (secs.saturating_mul(1_000_000).saturating_add(micros)) as i64
}

/// Read until `buf` is full or EOF. Returns how many bytes landed.
///
/// `Read::read` is permitted to return short reads even before EOF, so a
/// single call is not enough to distinguish "file ended mid-record" from
/// "the OS felt like returning less". Getting this wrong would report a
/// perfectly good capture as truncated.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(PcapError::Io(e)),
        }
    }
    Ok(filled)
}

// ---------------------------------------------------------------------
// Random access
// ---------------------------------------------------------------------

/// One packet read back from the file, owned.
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    pub number: u64,
    pub ts_us: i64,
    pub caplen: u32,
    pub orig_len: u32,
    pub offset: u64,
    pub link_type: LinkType,
    pub data: Vec<u8>,
}

impl OwnedPacket {
    pub fn as_raw(&self) -> RawPacket<'_> {
        RawPacket {
            number: self.number,
            ts_us: self.ts_us,
            caplen: self.caplen,
            orig_len: self.orig_len,
            offset: self.offset,
            data: &self.data,
            link_type: self.link_type,
        }
    }
}

/// Random-access reader: given the offset the index recorded, read back
/// exactly one packet.
///
/// This is what makes lazy dissection work. The index holds ~48 bytes per
/// packet; a detail view costs one seek and one packet's bytes.
pub struct Fetcher {
    file: File,
    format: CaptureFormat,
    interfaces: Vec<Interface>,
}

impl Fetcher {
    pub fn fetch(&mut self, number: u64, offset: u64) -> Result<OwnedPacket> {
        self.file.seek(SeekFrom::Start(offset))?;
        match self.format {
            CaptureFormat::Pcap { endian, nanos } => self.fetch_pcap(number, offset, endian, nanos),
            CaptureFormat::PcapNg { endian } => self.fetch_ng(number, offset, endian),
        }
    }

    fn fetch_pcap(
        &mut self,
        number: u64,
        offset: u64,
        endian: Endian,
        nanos: bool,
    ) -> Result<OwnedPacket> {
        let mut hdr = [0u8; 16];
        if read_full(&mut self.file, &mut hdr)? != 16 {
            return Err(PcapError::UnknownPacket(number));
        }
        let ts_sec = endian.u32([hdr[0], hdr[1], hdr[2], hdr[3]]) as i64;
        let ts_frac = endian.u32([hdr[4], hdr[5], hdr[6], hdr[7]]) as i64;
        let caplen = endian.u32([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let orig_len = endian.u32([hdr[12], hdr[13], hdr[14], hdr[15]]);
        if caplen > MAX_PACKET_BYTES {
            return Err(PcapError::UnknownPacket(number));
        }
        let mut data = vec![0u8; caplen as usize];
        if read_full(&mut self.file, &mut data)? != caplen as usize {
            return Err(PcapError::UnknownPacket(number));
        }
        let link_type = self
            .interfaces
            .first()
            .map(|i| i.link_type)
            .unwrap_or(LinkType::Ethernet);
        Ok(OwnedPacket {
            number,
            ts_us: ts_sec.saturating_mul(1_000_000).saturating_add(if nanos {
                ts_frac / 1_000
            } else {
                ts_frac
            }),
            caplen,
            orig_len: orig_len.max(caplen),
            offset,
            link_type,
            data,
        })
    }

    fn fetch_ng(&mut self, number: u64, offset: u64, endian: Endian) -> Result<OwnedPacket> {
        let mut head = [0u8; 8];
        if read_full(&mut self.file, &mut head)? != 8 {
            return Err(PcapError::UnknownPacket(number));
        }
        let block_type = endian.u32([head[0], head[1], head[2], head[3]]);
        let total_len = endian.u32([head[4], head[5], head[6], head[7]]);
        if total_len < 12 || !total_len.is_multiple_of(4) || total_len > MAX_BLOCK_BYTES {
            return Err(PcapError::UnknownPacket(number));
        }
        let mut body = vec![0u8; (total_len - 12) as usize];
        if read_full(&mut self.file, &mut body)? != body.len() {
            return Err(PcapError::UnknownPacket(number));
        }

        let (data_at, caplen, orig_len, ts_us, link_type) = match block_type {
            BLOCK_EPB | BLOCK_PACKET_LEGACY => {
                if body.len() < 20 {
                    return Err(PcapError::UnknownPacket(number));
                }
                let iface_id = if block_type == BLOCK_EPB {
                    endian.u32([body[0], body[1], body[2], body[3]])
                } else {
                    endian.u16([body[0], body[1]]) as u32
                };
                let ts_high = endian.u32([body[4], body[5], body[6], body[7]]) as u64;
                let ts_low = endian.u32([body[8], body[9], body[10], body[11]]) as u64;
                let caplen = endian.u32([body[12], body[13], body[14], body[15]]);
                let orig_len = endian.u32([body[16], body[17], body[18], body[19]]);
                let iface = self
                    .interfaces
                    .get(iface_id as usize)
                    .copied()
                    .unwrap_or_default();
                (
                    20usize,
                    caplen,
                    orig_len,
                    ticks_to_micros((ts_high << 32) | ts_low, iface.ts_per_second),
                    iface.link_type,
                )
            }
            BLOCK_SPB => {
                if body.len() < 4 {
                    return Err(PcapError::UnknownPacket(number));
                }
                let orig_len = endian.u32([body[0], body[1], body[2], body[3]]);
                let available = (body.len() - 4) as u32;
                let iface = self.interfaces.first().copied().unwrap_or_default();
                (
                    4usize,
                    orig_len.min(available),
                    orig_len,
                    0,
                    iface.link_type,
                )
            }
            // The index only ever records offsets of packet-bearing
            // blocks, so landing here means the file changed under us.
            _ => return Err(PcapError::PacketNotAddressable(number)),
        };

        if caplen > MAX_PACKET_BYTES || data_at.saturating_add(caplen as usize) > body.len() {
            return Err(PcapError::UnknownPacket(number));
        }
        let data = body[data_at..data_at + caplen as usize].to_vec();
        Ok(OwnedPacket {
            number,
            ts_us,
            caplen,
            orig_len: orig_len.max(caplen),
            offset,
            link_type,
            data,
        })
    }
}

// The staging fields live on Scanner; declared here to keep the parsing
// code above uncluttered.
impl Scanner {
    #[inline]
    fn _staged_marker(&self) {}
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
