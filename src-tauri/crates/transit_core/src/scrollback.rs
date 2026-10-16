//! `ScrollbackRing` — fixed-size circular buffer for PTY output.
//!
//! Capped by **whichever fills first**: 32 768 lines OR 4 MiB.
//! Append-only from the session writer task; read by xterm.js
//! (Phase 2c) on session attach and (Phase 5a) by the agent's
//! `read_scrollback` tool.
//!
//! Concurrency model: a `std::sync::Mutex` guards a `VecDeque<u8>`
//! plus a cached newline count. Lock hold time is bounded by the
//! length of a single push or snapshot — never held across an
//! `.await`.
//!
//! Lifted from `transit_ssh::scrollback` in Phase 7b C15 so the new
//! `transit_console` crate can share the same buffer type without
//! taking a dependency on `transit_ssh`. The type is identical;
//! `transit_ssh::scrollback` now re-exports from here for source
//! compatibility.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Default soft cap: 32 768 lines. Picked to give a network engineer
/// roughly half-a-day of `show interface` output without truncation,
/// while keeping the buffer cheap to copy.
pub const DEFAULT_MAX_LINES: usize = 32_768;

/// Default hard cap: 4 MiB. A modern terminal session rarely fills
/// this with text; the cap is the failsafe for a runaway producer
/// (a `find /` against a misconfigured device, e.g.).
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;

pub struct ScrollbackRing {
    inner: Mutex<Inner>,
    max_lines: usize,
    max_bytes: usize,
}

struct Inner {
    buf: VecDeque<u8>,
    line_count: usize,
}

impl ScrollbackRing {
    /// Production defaults: 32K lines / 4 MiB.
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_MAX_LINES, DEFAULT_MAX_BYTES)
    }

    /// Custom caps. Exposed for tests and a future user-tunable
    /// preference (`scrollback.max_lines` in settings).
    pub fn with_caps(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                buf: VecDeque::new(),
                line_count: 0,
            }),
            max_lines,
            max_bytes,
        }
    }

    /// Append `bytes` to the buffer. Evicts from the front until
    /// both caps are satisfied. Newlines are counted by scanning
    /// the input — single pass, no recount of the whole buffer.
    pub fn push(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let added_newlines = bytes.iter().filter(|b| **b == b'\n').count();
        let mut inner = self.inner.lock().expect("scrollback mutex poisoned");
        inner.buf.extend(bytes);
        inner.line_count += added_newlines;

        // Evict from the front until we satisfy both caps.
        while inner.buf.len() > self.max_bytes || inner.line_count > self.max_lines {
            match inner.buf.pop_front() {
                Some(b'\n') => inner.line_count = inner.line_count.saturating_sub(1),
                Some(_) => {}
                None => break,
            }
        }
    }

    /// Wipe the buffer back to empty (contents + cached line count).
    /// The caps (`max_lines` / `max_bytes`) are immutable fields and
    /// are untouched, so the ring is fully reusable afterward.
    ///
    /// Backs the user-driven "Clear terminal" action. Because the
    /// agent's `read_scrollback` reads this *same* `Arc<ScrollbackRing>`
    /// live on every call, a clear means a subsequent read returns only
    /// post-clear bytes — there is no separate agent-side cache to
    /// invalidate. Bytes the reader task appends after the clear
    /// accumulate normally.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("scrollback mutex poisoned");
        inner.buf.clear();
        inner.line_count = 0;
    }

    /// Copy the current buffer contents into a contiguous `Vec<u8>`.
    /// Allocates fresh — callers that need a string view do
    /// `String::from_utf8_lossy(&snapshot)`.
    pub fn snapshot(&self) -> Vec<u8> {
        let inner = self.inner.lock().expect("scrollback mutex poisoned");
        let (a, b) = inner.buf.as_slices();
        let mut out = Vec::with_capacity(inner.buf.len());
        out.extend_from_slice(a);
        out.extend_from_slice(b);
        out
    }

    pub fn len_bytes(&self) -> usize {
        self.inner
            .lock()
            .expect("scrollback mutex poisoned")
            .buf
            .len()
    }

    /// v6.1.x — non-blocking, non-panicking byte count for the
    /// roster's `scrollback:` field. `None` when the ring is contended
    /// OR poisoned, so a caller inside a deliberately non-blocking
    /// `list()` (SSH/console sources use `try_lock`) never blocks a
    /// tokio worker on a busy ring and never panics on a poisoned one
    /// — it just omits the occupancy hint that turn.
    pub fn try_len_bytes(&self) -> Option<usize> {
        self.inner.try_lock().ok().map(|g| g.buf.len())
    }

    pub fn line_count(&self) -> usize {
        self.inner
            .lock()
            .expect("scrollback mutex poisoned")
            .line_count
    }

    pub fn is_empty(&self) -> bool {
        self.len_bytes() == 0
    }

    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

impl Default for ScrollbackRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ring_starts_clean() {
        let ring = ScrollbackRing::new();
        assert!(ring.is_empty());
        assert_eq!(ring.len_bytes(), 0);
        assert_eq!(ring.line_count(), 0);
        assert_eq!(ring.snapshot(), Vec::<u8>::new());
    }

    #[test]
    fn small_push_round_trips() {
        let ring = ScrollbackRing::new();
        ring.push(b"hello world\n");
        assert_eq!(ring.len_bytes(), 12);
        assert_eq!(ring.line_count(), 1);
        assert_eq!(ring.snapshot(), b"hello world\n".to_vec());
    }

    #[test]
    fn multiple_pushes_concatenate() {
        let ring = ScrollbackRing::new();
        ring.push(b"first\n");
        ring.push(b"second\n");
        ring.push(b"trailing");
        assert_eq!(ring.snapshot(), b"first\nsecond\ntrailing".to_vec());
        assert_eq!(ring.line_count(), 2, "trailing has no newline");
    }

    #[test]
    fn empty_push_is_noop() {
        let ring = ScrollbackRing::new();
        ring.push(b"abc");
        ring.push(b"");
        assert_eq!(ring.snapshot(), b"abc".to_vec());
    }

    #[test]
    fn byte_cap_evicts_from_front() {
        let ring = ScrollbackRing::with_caps(usize::MAX, 8);
        ring.push(b"abcdefghij"); // 10 bytes; cap is 8
                                  // Front 2 bytes should be gone.
        assert_eq!(ring.len_bytes(), 8);
        assert_eq!(ring.snapshot(), b"cdefghij".to_vec());
    }

    #[test]
    fn line_cap_evicts_from_front() {
        let ring = ScrollbackRing::with_caps(2, usize::MAX);
        ring.push(b"a\nb\nc\nd\n"); // 4 newlines; cap is 2
        let s = ring.snapshot();
        assert_eq!(ring.line_count(), 2);
        // Should have dropped "a\nb\n" — keeping the most recent.
        assert_eq!(s, b"c\nd\n".to_vec());
    }

    #[test]
    fn whichever_cap_fills_first_evicts() {
        // Byte cap fires first.
        let ring = ScrollbackRing::with_caps(1000, 4);
        ring.push(b"hello world\n"); // 12 bytes, 1 line
        assert_eq!(ring.len_bytes(), 4);

        // Line cap fires first.
        let ring = ScrollbackRing::with_caps(1, 1000);
        ring.push(b"a\nb\nc\nd\n");
        assert_eq!(ring.line_count(), 1);
    }

    #[test]
    fn single_push_larger_than_byte_cap_keeps_tail() {
        let ring = ScrollbackRing::with_caps(usize::MAX, 4);
        ring.push(b"0123456789");
        assert_eq!(ring.snapshot(), b"6789".to_vec());
    }

    #[test]
    fn line_count_decrements_only_for_dropped_newlines() {
        // 5-byte push, 4-byte cap: pop_front runs once, drops `a`
        // (not a newline), then len=4 satisfies cap. Line count
        // stays at 2.
        let ring = ScrollbackRing::with_caps(usize::MAX, 4);
        ring.push(b"a\nb\nc");
        assert_eq!(ring.len_bytes(), 4);
        assert_eq!(ring.line_count(), 2);
        assert_eq!(ring.snapshot(), b"\nb\nc".to_vec());

        // Push 4 more bytes — eviction runs 4 times, dropping
        // `\n`, `b`, `\n`, `c` from the front. Both newlines drop,
        // so line_count → 0.
        ring.push(b"defg");
        assert_eq!(ring.snapshot(), b"defg".to_vec());
        assert_eq!(ring.line_count(), 0);
    }

    #[test]
    fn clear_wipes_contents_and_line_count() {
        let ring = ScrollbackRing::new();
        ring.push(b"line one\nline two\n");
        assert!(!ring.is_empty());

        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.len_bytes(), 0);
        assert_eq!(ring.line_count(), 0);
        assert_eq!(ring.snapshot(), Vec::<u8>::new());

        // Reusable after a clear: caps preserved, pushes resume cleanly.
        ring.push(b"after\n");
        assert_eq!(ring.snapshot(), b"after\n".to_vec());
        assert_eq!(ring.line_count(), 1);
        assert_eq!(ring.max_lines(), DEFAULT_MAX_LINES);
        assert_eq!(ring.max_bytes(), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn clear_on_empty_ring_is_noop() {
        let ring = ScrollbackRing::new();
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.line_count(), 0);
    }

    #[test]
    fn max_caps_accessible() {
        let ring = ScrollbackRing::new();
        assert_eq!(ring.max_lines(), DEFAULT_MAX_LINES);
        assert_eq!(ring.max_bytes(), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn snapshot_handles_wrap_after_eviction() {
        // VecDeque is internally a ring; eviction + new push
        // forces the head/tail pointers to wrap. Confirm
        // snapshot reassembles correctly.
        let ring = ScrollbackRing::with_caps(usize::MAX, 6);
        ring.push(b"abcdef"); // fills exactly
        ring.push(b"ghij"); // evicts 4, pushes 4; internal wrap likely
        assert_eq!(ring.snapshot(), b"efghij".to_vec());
    }
}
