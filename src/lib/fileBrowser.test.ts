import { describe, expect, it } from "vitest";

import type { FileEntry } from "@/lib/api";
import {
  baseName,
  formatBytes,
  formatDuration,
  formatEta,
  formatMtime,
  formatRate,
  isHiddenName,
  joinChildPath,
  sortEntries,
  transferPercent,
  truncateMiddle,
  validateEntryName,
} from "@/lib/fileBrowser";

function entry(partial: Partial<FileEntry> & Pick<FileEntry, "name">): FileEntry {
  return {
    kind: "file",
    size: null,
    mtime: null,
    perms: null,
    symlink_target: null,
    ...partial,
  };
}

describe("formatBytes", () => {
  it("renders an em dash for an absent or nonsense size", () => {
    // A directory reports no size; so does a server that omits the attr.
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(undefined)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
    expect(formatBytes(-1)).toBe("—");
  });

  it("keeps raw bytes below 1 KiB", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("uses binary units with one decimal below 10 and none above", () => {
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(10 * 1024)).toBe("10 KiB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MiB");
    expect(formatBytes(365 * 1024 * 1024)).toBe("365 MiB");
    expect(formatBytes(3 * 1024 ** 4)).toBe("3.0 TiB");
  });

  it("saturates at the largest unit rather than inventing one", () => {
    expect(formatBytes(4096 * 1024 ** 5)).toContain("PiB");
  });
});

describe("formatMtime", () => {
  it("renders LOCAL time as YYYY-MM-DD HH:mm", () => {
    // Build the expectation from the same Date so the assertion holds in
    // any timezone (the formatter is deliberately local-time).
    const d = new Date(2026, 7, 4, 9, 5); // 2026-08-04 09:05 local
    expect(formatMtime(Math.floor(d.getTime() / 1000))).toBe("2026-08-04 09:05");
  });

  it("renders an em dash for an absent or unparseable mtime", () => {
    expect(formatMtime(null)).toBe("—");
    expect(formatMtime(undefined)).toBe("—");
    expect(formatMtime(Number.NaN)).toBe("—");
  });
});

describe("joinChildPath", () => {
  it("joins POSIX paths and never doubles the separator", () => {
    expect(joinChildPath("/var/tmp", "a.conf")).toBe("/var/tmp/a.conf");
    expect(joinChildPath("/", "etc")).toBe("/etc");
  });

  it("matches a Windows path's separator so the round-trip stays canonical", () => {
    expect(joinChildPath("C:\\Users\\alice", "notes.txt")).toBe("C:\\Users\\alice\\notes.txt");
    expect(joinChildPath("C:\\", "Windows")).toBe("C:\\Windows");
  });

  it("keeps POSIX separators for a mixed path (a UNC-ish or msys path)", () => {
    // Contains both, so the POSIX default wins — the backend canonicalizer
    // is the arbiter and every remote path is POSIX.
    expect(joinChildPath("/c/Users\\weird", "x")).toBe("/c/Users\\weird/x");
  });
});

describe("isHiddenName", () => {
  it("treats dotfiles as hidden", () => {
    expect(isHiddenName(".ssh")).toBe(true);
    expect(isHiddenName("config")).toBe(false);
    // Not a special case: the backend never emits "." or ".." as an entry,
    // but if one arrived it would read as hidden, not as navigation.
    expect(isHiddenName("..")).toBe(true);
  });
});

describe("validateEntryName", () => {
  it("accepts an ordinary name", () => {
    expect(validateEntryName("configs")).toBeNull();
    expect(validateEntryName("  spaced  ")).toBeNull();
  });

  it("rejects empty, reserved, and separator-bearing names", () => {
    expect(validateEntryName("")).toMatch(/Enter a name/);
    expect(validateEntryName("   ")).toMatch(/Enter a name/);
    expect(validateEntryName(".")).toMatch(/reserved/);
    expect(validateEntryName("..")).toMatch(/reserved/);
    // A separator would silently retarget the operation at another
    // directory — the same shape the backend's `sanitize` refuses inbound.
    expect(validateEntryName("../../.ssh/authorized_keys")).toMatch(/path separator/);
    expect(validateEntryName("a/b")).toMatch(/path separator/);
    expect(validateEntryName("a\\b")).toMatch(/path separator/);
  });
});

describe("sortEntries", () => {
  const rows = [
    entry({ name: "zeta.txt", size: 10, mtime: 300 }),
    entry({ name: "Alpha", kind: "dir", mtime: 100 }),
    entry({ name: ".hidden", size: 5, mtime: 200 }),
    entry({ name: "beta.txt", size: 999, mtime: 100 }),
    entry({ name: "link", kind: "symlink", size: 1, mtime: 400 }),
    entry({ name: "zulu", kind: "dir", mtime: 500 }),
  ];

  it("hides dotfiles unless asked, and puts directories first", () => {
    expect(sortEntries(rows, { key: "name", asc: true }, false).map((e) => e.name)).toEqual([
      "Alpha",
      "zulu",
      "beta.txt",
      "link",
      "zeta.txt",
    ]);
  });

  it("includes dotfiles when showHidden is on", () => {
    expect(sortEntries(rows, { key: "name", asc: true }, true).map((e) => e.name)).toEqual([
      "Alpha",
      "zulu",
      ".hidden",
      "beta.txt",
      "link",
      "zeta.txt",
    ]);
  });

  it("keeps directories first even when reversed", () => {
    expect(sortEntries(rows, { key: "name", asc: false }, false).map((e) => e.name)).toEqual([
      "zulu",
      "Alpha",
      "zeta.txt",
      "link",
      "beta.txt",
    ]);
  });

  it("sorts by size within each block, treating an absent size as smallest", () => {
    expect(sortEntries(rows, { key: "size", asc: true }, false).map((e) => e.name)).toEqual([
      // Both directories have no size → the name tiebreak orders them.
      "Alpha",
      "zulu",
      "link",
      "zeta.txt",
      "beta.txt",
    ]);
  });

  it("sorts by mtime and breaks ties on name", () => {
    expect(sortEntries(rows, { key: "mtime", asc: true }, false).map((e) => e.name)).toEqual([
      "Alpha",
      "zulu",
      // beta (100) < zeta (300) < link (400)
      "beta.txt",
      "zeta.txt",
      "link",
    ]);
  });

  it("orders a symlink with FILES, never as a directory", () => {
    // The recursive walker refuses to follow remote links (T43); grouping
    // one with directories in the UI would misrepresent it.
    const only = [
      entry({ name: "a-link", kind: "symlink" }),
      entry({ name: "z-dir", kind: "dir" }),
    ];
    expect(sortEntries(only, { key: "name", asc: true }, false).map((e) => e.name)).toEqual([
      "z-dir",
      "a-link",
    ]);
  });

  it("returns an empty list for an empty listing", () => {
    expect(sortEntries([], { key: "name", asc: true }, false)).toEqual([]);
  });
});

describe("transfer formatting (v5.0.0 Commit C)", () => {
  it("formatRate appends /s and omits a missing or stalled rate", () => {
    expect(formatRate(1_258_291)).toBe("1.2 MiB/s");
    expect(formatRate(512)).toBe("512 B/s");
    // No rate yet, or a job making no progress: say nothing rather than
    // "0 B/s", which reads like a broken transfer.
    expect(formatRate(null)).toBeNull();
    expect(formatRate(undefined)).toBeNull();
    expect(formatRate(0)).toBeNull();
    expect(formatRate(Number.NaN)).toBeNull();
  });

  it("formatDuration reads as a clock, growing an hours field only when needed", () => {
    expect(formatDuration(4)).toBe("0:04");
    expect(formatDuration(62)).toBe("1:02");
    expect(formatDuration(3723)).toBe("1:02:03");
    expect(formatDuration(-5)).toBe("0:00");
  });

  it("formatEta divides the CURRENT FILE's remaining bytes by the job rate", () => {
    expect(formatEta(0, 1000, 100)).toBe("0:10");
    expect(formatEta(900, 1000, 100)).toBe("0:01");
    // Already past the total (a server that under-reported size): clamp to 0.
    expect(formatEta(2000, 1000, 100)).toBe("0:00");
    // A recursive job has no per-file total until the file opens, and a
    // just-started job has no rate — no ETA in either case.
    expect(formatEta(10, null, 100)).toBeNull();
    expect(formatEta(10, 1000, null)).toBeNull();
    expect(formatEta(10, 1000, 0)).toBeNull();
  });

  it("transferPercent is per-file and clamped; null without a total", () => {
    expect(transferPercent(0, 100)).toBe(0);
    expect(transferPercent(62, 100)).toBe(62);
    expect(transferPercent(150, 100)).toBe(100);
    expect(transferPercent(5, null)).toBeNull();
    expect(transferPercent(5, undefined)).toBeNull();
    // A zero-byte file is done the moment it exists.
    expect(transferPercent(0, 0)).toBe(0);
  });

  it("truncateMiddle keeps both ends of a long name", () => {
    expect(truncateMiddle("short.conf")).toBe("short.conf");
    const long = "juniper-vex1-2026-08-04-full-configuration-backup.conf";
    const cut = truncateMiddle(long, 20);
    expect(cut).toHaveLength(20);
    expect(cut.startsWith("juniper-ve")).toBe(true);
    // The tail — the extension — survives, which is what tells rows apart.
    expect(cut.endsWith(".conf")).toBe(true);
    expect(cut).toContain("…");
  });

  it("baseName takes the last component of either separator style", () => {
    expect(baseName("/var/tmp/juniper.conf")).toBe("juniper.conf");
    expect(baseName("C:\\Users\\alice\\notes.txt")).toBe("notes.txt");
    expect(baseName("/var/tmp/configs/")).toBe("configs");
    expect(baseName("bare.conf")).toBe("bare.conf");
    expect(baseName("/")).toBe("");
  });
});
