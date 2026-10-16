import { describe, expect, it } from "vitest";

import {
  findMatches,
  type MatchRange,
  nextMatchIndex,
  replaceAllMatches,
  replaceRange,
} from "@/lib/terminal/pasteEdit";

const loose = { caseSensitive: false, wholeWord: false };
const cased = { caseSensitive: true, wholeWord: false };
const word = { caseSensitive: false, wholeWord: true };

describe("findMatches", () => {
  it("empty query → no matches (even in non-empty text)", () => {
    expect(findMatches("show version", "", loose)).toEqual([]);
    expect(findMatches("", "x", loose)).toEqual([]);
  });

  it("case-insensitive by default, offsets index the ORIGINAL string", () => {
    expect(findMatches("Interface up\ninterface down", "interface", loose)).toEqual([
      { start: 0, end: 9 },
      { start: 13, end: 22 },
    ]);
  });

  it("case-sensitive keeps only exact-case occurrences", () => {
    expect(findMatches("Interface up\ninterface down", "interface", cased)).toEqual([
      { start: 13, end: 22 },
    ]);
  });

  it("regex metacharacters in the query are literal", () => {
    // The '.' must not wildcard: 'ge-0/0/1x0' would match a regex '0/0/1.0'.
    expect(findMatches("ge-0/0/1.0 ge-0/0/1x0", "0/0/1.0", loose)).toEqual([{ start: 3, end: 10 }]);
    expect(findMatches("a+b aab", "a+b", loose)).toEqual([{ start: 0, end: 3 }]);
  });

  it("whole-word treats network punctuation (/ . : -) as boundaries", () => {
    const text = "ge-0/0/1 xe-0/0/10 10.0.0.1:22 vlan_10 gear";
    // '-' and '/' neighbors are boundaries; the '0' after '0/0/1' in
    // 'xe-0/0/10' is a word char, so that occurrence is rejected.
    expect(findMatches(text, "0/0/1", word)).toEqual([{ start: 3, end: 8 }]);
    // 'ge' in 'gear' is rejected (followed by a word char).
    expect(findMatches(text, "ge", word)).toEqual([{ start: 0, end: 2 }]);
    // '1' next to '.', '/', ':' counts; the '1' inside '10' does not.
    expect(findMatches(text, "1", word)).toEqual([
      { start: 7, end: 8 },
      { start: 26, end: 27 },
    ]);
    // '_' is a word char: 'vlan' inside 'vlan_10' is NOT whole-word.
    expect(findMatches(text, "vlan", word)).toEqual([]);
  });

  it("whole-word accepts matches flush with the text edges", () => {
    expect(findMatches("up", "up", word)).toEqual([{ start: 0, end: 2 }]);
  });

  it("adjacent occurrences scan left-to-right without overlap", () => {
    expect(findMatches("aaaa", "aa", loose)).toEqual([
      { start: 0, end: 2 },
      { start: 2, end: 4 },
    ]);
    expect(findMatches("aaa", "aa", loose)).toEqual([{ start: 0, end: 2 }]);
  });

  it("CRLF payloads match across line boundaries by offset", () => {
    expect(findMatches("foo\r\nfoo", "foo", loose)).toEqual([
      { start: 0, end: 3 },
      { start: 5, end: 8 },
    ]);
  });

  it("offsets are UTF-16 code units — multi-byte chars before a match count double", () => {
    // Two emoji (2 code units each) + space = 5 units before 'error'.
    expect(findMatches("🚀🚀 error", "error", loose)).toEqual([{ start: 5, end: 10 }]);
  });
});

describe("replaceRange / replaceAllMatches", () => {
  it("dollar patterns in the replacement stay verbatim (no interpolation)", () => {
    expect(replaceRange("abc", { start: 0, end: 3 }, "$&-$1-$$")).toBe("$&-$1-$$");
    const matches = findMatches("abc abc", "abc", loose);
    expect(replaceAllMatches("abc abc", matches, "$&")).toBe("$& $&");
  });

  it("replacement containing the query substitutes once per original match", () => {
    const text = "sh sh sh";
    const matches = findMatches(text, "sh", loose);
    expect(replaceAllMatches(text, matches, "ssh")).toBe("ssh ssh ssh");
  });

  it("empty replacement deletes the matches", () => {
    const text = "a-b-a";
    expect(replaceAllMatches(text, findMatches(text, "a", loose), "")).toBe("-b-");
  });

  it("preserves CRLF outside the replaced ranges", () => {
    const text = "foo\r\nfoo";
    expect(replaceAllMatches(text, findMatches(text, "foo", loose), "bar")).toBe("bar\r\nbar");
  });

  it("replaceRange splices one range only", () => {
    expect(replaceRange("one two one", { start: 4, end: 7 }, "2")).toBe("one 2 one");
  });
});

describe("nextMatchIndex", () => {
  const matches: MatchRange[] = [
    { start: 0, end: 2 },
    { start: 10, end: 12 },
    { start: 20, end: 22 },
  ];

  it("returns the first match at or after the offset", () => {
    expect(nextMatchIndex(matches, 0)).toBe(0);
    expect(nextMatchIndex(matches, 3)).toBe(1);
    expect(nextMatchIndex(matches, 10)).toBe(1);
  });

  it("wraps to 0 past the last match", () => {
    expect(nextMatchIndex(matches, 23)).toBe(0);
  });

  it("returns -1 for an empty match set", () => {
    expect(nextMatchIndex([], 5)).toBe(-1);
  });
});
