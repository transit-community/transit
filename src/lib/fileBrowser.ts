import type { FileEntry } from "@/lib/api";

/**
 * Pure helpers for the v5.0.0 Files panes — formatting, path arithmetic,
 * and listing order. Kept free of React/IPC so the semantics that decide
 * what a row SAYS and where a click GOES are unit-testable on their own.
 */

/** Which column a pane is sorted by. Directories always sort before files
 *  regardless (the file-manager convention), so this only orders within
 *  each of those two blocks. */
export type SortKey = "name" | "size" | "mtime";

export interface PaneSort {
  key: SortKey;
  /** Ascending (A→Z, small→large, old→new) when true. */
  asc: boolean;
}

export const DEFAULT_SORT: PaneSort = { key: "name", asc: true };

/** Binary units, matching how every file manager reads sizes. `null`
 *  (a directory, or a server that reports no size) renders as an em dash
 *  rather than a misleading "0 B". */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "—";
  if (bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // One decimal below 10 (2.4 MiB), none above (348 MiB) — the density a
  // file listing wants.
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** `YYYY-MM-DD HH:mm` in LOCAL time. Deliberately not `toLocaleString`:
 *  a fixed layout keeps the column width stable (and the tests
 *  locale-independent) while still reading naturally. */
export function formatMtime(epochSeconds: number | null | undefined): string {
  if (epochSeconds === null || epochSeconds === undefined || !Number.isFinite(epochSeconds)) {
    return "—";
  }
  const d = new Date(epochSeconds * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/** Transfer rate for the queue strip. `null` (no rate yet, or a stalled
 *  job) renders as nothing rather than a misleading "0 B/s". */
export function formatRate(bytesPerSecond: number | null | undefined): string | null {
  if (bytesPerSecond === null || bytesPerSecond === undefined) return null;
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return null;
  return `${formatBytes(bytesPerSecond)}/s`;
}

/** `m:ss`, or `h:mm:ss` past the hour. */
export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.round(seconds));
  const s = total % 60;
  const m = Math.floor(total / 60) % 60;
  const h = Math.floor(total / 3600);
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/**
 * Time left on the CURRENT FILE — `bytes_total`/`bytes_done` describe one
 * file (a recursive job has no pre-scan, so no job-wide total exists), and
 * `rate_bps` is the job-wide rate. `null` whenever either input is missing,
 * so the strip omits the field instead of inventing a number.
 */
export function formatEta(
  bytesDone: number,
  bytesTotal: number | null | undefined,
  bytesPerSecond: number | null | undefined,
): string | null {
  if (bytesTotal === null || bytesTotal === undefined) return null;
  if (bytesPerSecond === null || bytesPerSecond === undefined || bytesPerSecond <= 0) return null;
  if (!Number.isFinite(bytesTotal) || !Number.isFinite(bytesPerSecond)) return null;
  return formatDuration(Math.max(0, bytesTotal - bytesDone) / bytesPerSecond);
}

/** Percentage complete for the current file, clamped to 0–100. `null` when
 *  the total is unknown (the strip then shows an indeterminate bar). */
export function transferPercent(
  bytesDone: number,
  bytesTotal: number | null | undefined,
): number | null {
  if (bytesTotal === null || bytesTotal === undefined || !Number.isFinite(bytesTotal)) return null;
  if (bytesTotal <= 0) return bytesDone > 0 ? 100 : 0;
  return Math.min(100, Math.max(0, Math.round((bytesDone / bytesTotal) * 100)));
}

/**
 * Shorten with an ellipsis in the MIDDLE, keeping both ends.
 *
 * A queue row needs the tail of a name as much as the head — the extension
 * and any `-2` / date suffix are what tell two rows apart — and CSS
 * `text-overflow` can only cut the end. Done in JS rather than with a
 * `direction: rtl` trick, which visually reorders leading punctuation.
 */
export function truncateMiddle(text: string, max = 34): string {
  if (max < 5 || text.length <= max) return text;
  const keep = max - 1;
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}

/**
 * Last component of a path, tolerating either separator and a trailing one.
 *
 * Needed for paths that did NOT come from a listing row: the full
 * destination paths `files_check_conflicts` returns, and the absolute paths
 * an OS file drop hands over.
 */
export function baseName(path: string): string {
  const trimmed = path.replace(/[/\\]+$/, "");
  const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  return cut === -1 ? trimmed : trimmed.slice(cut + 1);
}

/** The separator `dir` is written with. Remote (SFTP) paths are always
 *  POSIX; a local Windows path arrives back-slashed from
 *  `std::fs::canonicalize`, so the child must match or the round-trip to
 *  the backend canonicalizer changes the path the user sees. */
function separatorFor(dir: string): "/" | "\\" {
  return dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
}

/**
 * Append a single component to a directory path. `name` is always one
 * component (the backend rejects separators in remote names before they
 * reach the UI), so this never needs to normalize `..`.
 */
export function joinChildPath(dir: string, name: string): string {
  const sep = separatorFor(dir);
  if (dir.length === 0) return name;
  return dir.endsWith(sep) ? `${dir}${name}` : `${dir}${sep}${name}`;
}

/**
 * The parent of a directory path, or `null` at the true root.
 *
 * The listing response's `parent` is authoritative and preferred; this is
 * the FALLBACK for when no listing resolved — most importantly a listing that
 * ERRORED (permission-denied on a subdir), where the pane must still let the
 * user walk back up rather than trapping them (F6). POSIX for remote paths,
 * platform separator for local, mirroring `joinChildPath`/`separatorFor`.
 */
export function parentDir(path: string): string | null {
  const sep = separatorFor(path);
  // Drop trailing separators first ("/etc/ssh/" → "/etc/ssh"), so the last
  // real component is what we strip.
  const trimmed = path.replace(/[/\\]+$/, "");
  if (trimmed.length === 0) return null; // path was all separators → root
  const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  if (cut === -1) return null; // a bare name or a drive letter → treat as root
  if (cut === 0) return sep; // "/foo" → "/" (POSIX root keeps its slash)
  const parent = trimmed.slice(0, cut);
  // A Windows drive root ("C:") needs its separator back to stay a real path.
  return /^[A-Za-z]:$/.test(parent) ? `${parent}${sep}` : parent;
}

/** Dotfile heuristic (v1) — `.ssh`, `.bashrc`, … Windows hidden
 *  ATTRIBUTES aren't reported by the backend, so this is the whole rule. */
export function isHiddenName(name: string): boolean {
  return name.startsWith(".");
}

/**
 * Validate a name the user typed for a new folder or a rename. Returns an
 * error message, or `null` when the name is acceptable.
 *
 * This mirrors the backend's `sanitize` boundary (which rejects the same
 * shapes coming FROM a remote server, T43) on the outbound side: a name
 * with a separator in it would silently retarget the operation at a
 * different directory, and `.`/`..` at the directory itself. The backend
 * remains the enforcement point — this exists so the user gets a message
 * instead of an opaque SFTP error.
 */
export function validateEntryName(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return "Enter a name.";
  if (trimmed === "." || trimmed === "..") return "That name is reserved.";
  if (trimmed.includes("/") || trimmed.includes("\\")) {
    return "A name can't contain a path separator.";
  }
  return null;
}

function compare(a: FileEntry, b: FileEntry, sort: PaneSort): number {
  let delta: number;
  if (sort.key === "size") {
    delta = (a.size ?? -1) - (b.size ?? -1);
  } else if (sort.key === "mtime") {
    delta = (a.mtime ?? -1) - (b.mtime ?? -1);
  } else {
    delta = a.name.localeCompare(b.name);
  }
  // Stable, predictable tiebreak: equal sizes/times fall back to name so
  // the row order can't shuffle between renders of the same listing.
  if (delta === 0 && sort.key !== "name") delta = a.name.localeCompare(b.name);
  return sort.asc ? delta : -delta;
}

/**
 * The rows a pane renders: hidden entries filtered (unless shown),
 * directories first, then the chosen sort inside each block. Symlinks are
 * ordered with files — the backend reports them as their own kind and the
 * walker refuses to follow remote links (T43), so treating one as a
 * directory here would misrepresent it.
 */
export function sortEntries(
  entries: FileEntry[],
  sort: PaneSort,
  showHidden: boolean,
): FileEntry[] {
  const visible = showHidden ? entries : entries.filter((e) => !isHiddenName(e.name));
  const dirs = visible.filter((e) => e.kind === "dir");
  const rest = visible.filter((e) => e.kind !== "dir");
  dirs.sort((a, b) => compare(a, b, sort));
  rest.sort((a, b) => compare(a, b, sort));
  return [...dirs, ...rest];
}
