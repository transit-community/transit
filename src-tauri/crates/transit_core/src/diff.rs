//! Minimal line-based diff for comparing captured command output —
//! `show run` now vs. a saved capture, or one device against another.
//!
//! An LCS (longest-common-subsequence) line diff. Enough for config-sized
//! text and dependency-free; the output is a flat op list the frontend
//! renders as a unified +/- view. O(n·m) time and memory — fine for the
//! hundreds-to-low-thousands of lines a device config runs to; callers
//! deal in captured command output, not arbitrary large files.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffOp {
    /// Line present, unchanged, in both sides.
    Equal,
    /// Line present only in the new side (added).
    Insert,
    /// Line present only in the old side (removed).
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffLine {
    pub op: DiffOp,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffResult {
    pub lines: Vec<DiffLine>,
    pub added: usize,
    pub removed: usize,
}

/// Line-based LCS diff of `old` vs `new`. Trailing newlines are handled by
/// `str::lines` (a final newline does not yield an extra empty line).
pub fn diff_lines(old: &str, new: &str) -> DiffResult {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let n = a.len();
    let m = b.len();

    // lcs[i][j] = length of the LCS of a[i..] and b[j..].
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut lines = Vec::with_capacity(n.max(m));
    let mut added = 0;
    let mut removed = 0;
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            lines.push(DiffLine {
                op: DiffOp::Equal,
                text: a[i].to_string(),
            });
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            lines.push(DiffLine {
                op: DiffOp::Delete,
                text: a[i].to_string(),
            });
            removed += 1;
            i += 1;
        } else {
            lines.push(DiffLine {
                op: DiffOp::Insert,
                text: b[j].to_string(),
            });
            added += 1;
            j += 1;
        }
    }
    while i < n {
        lines.push(DiffLine {
            op: DiffOp::Delete,
            text: a[i].to_string(),
        });
        removed += 1;
        i += 1;
    }
    while j < m {
        lines.push(DiffLine {
            op: DiffOp::Insert,
            text: b[j].to_string(),
        });
        added += 1;
        j += 1;
    }

    DiffResult {
        lines,
        added,
        removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(r: &DiffResult) -> Vec<(DiffOp, &str)> {
        r.lines.iter().map(|l| (l.op, l.text.as_str())).collect()
    }

    #[test]
    fn identical_input_is_all_equal() {
        let r = diff_lines("a\nb\nc\n", "a\nb\nc\n");
        assert_eq!(r.added, 0);
        assert_eq!(r.removed, 0);
        assert!(r.lines.iter().all(|l| l.op == DiffOp::Equal));
        assert_eq!(r.lines.len(), 3);
    }

    #[test]
    fn pure_insertion() {
        let r = diff_lines("a\nc\n", "a\nb\nc\n");
        assert_eq!(r.added, 1);
        assert_eq!(r.removed, 0);
        assert_eq!(
            ops(&r),
            vec![
                (DiffOp::Equal, "a"),
                (DiffOp::Insert, "b"),
                (DiffOp::Equal, "c"),
            ]
        );
    }

    #[test]
    fn pure_deletion() {
        let r = diff_lines("a\nb\nc\n", "a\nc\n");
        assert_eq!(r.added, 0);
        assert_eq!(r.removed, 1);
        assert_eq!(
            ops(&r),
            vec![
                (DiffOp::Equal, "a"),
                (DiffOp::Delete, "b"),
                (DiffOp::Equal, "c"),
            ]
        );
    }

    #[test]
    fn replacement_is_delete_then_insert() {
        // A changed line reads as the old line removed + the new added.
        let r = diff_lines("ip address 10.0.0.1\n", "ip address 10.0.0.2\n");
        assert_eq!(r.added, 1);
        assert_eq!(r.removed, 1);
        assert_eq!(r.lines[0].op, DiffOp::Delete);
        assert_eq!(r.lines[1].op, DiffOp::Insert);
    }

    #[test]
    fn empty_sides() {
        assert_eq!(diff_lines("", "").lines.len(), 0);
        assert_eq!(diff_lines("", "x\n").added, 1);
        assert_eq!(diff_lines("x\n", "").removed, 1);
    }
}
