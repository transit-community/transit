import { describe, expect, it } from "vitest";

import { applyCaptureRules, readCookie, readHeader, readJsonPath } from "./apiCapture";

describe("readJsonPath", () => {
  it("follows dotted paths incl. array indices (ACI login token)", () => {
    const body = JSON.stringify({ imdata: [{ aaaLogin: { attributes: { token: "TOK123" } } }] });
    expect(readJsonPath(body, "imdata.0.aaaLogin.attributes.token")).toBe("TOK123");
    expect(readJsonPath(body, "$.imdata.0.aaaLogin.attributes.token")).toBe("TOK123");
  });
  it("returns null for missing paths, non-scalar leaves, and bad JSON", () => {
    expect(readJsonPath(JSON.stringify({ a: 1 }), "b.c")).toBeNull();
    expect(readJsonPath(JSON.stringify({ a: { b: 1 } }), "a")).toBeNull(); // object, not scalar
    expect(readJsonPath("not json", "a")).toBeNull();
  });
  it("stringifies numeric + boolean leaves", () => {
    expect(readJsonPath(JSON.stringify({ n: 42, ok: true }), "n")).toBe("42");
    expect(readJsonPath(JSON.stringify({ ok: true }), "ok")).toBe("true");
  });
});

describe("readHeader / readCookie", () => {
  const headers: [string, string][] = [
    ["Content-Type", "application/json"],
    ["X-Auth-Token", "HDR456"],
    ["Set-Cookie", "JSESSIONID=SESS789; Path=/; HttpOnly"],
  ];
  it("reads a header case-insensitively", () => {
    expect(readHeader(headers, "x-auth-token")).toBe("HDR456");
    expect(readHeader(headers, "missing")).toBeNull();
  });
  it("reads a cookie value out of Set-Cookie (SD-WAN JSESSIONID)", () => {
    expect(readCookie(headers, "JSESSIONID")).toBe("SESS789");
    expect(readCookie(headers, "OTHER")).toBeNull();
  });
});

describe("applyCaptureRules", () => {
  const resp = {
    body: JSON.stringify({ token: "BODYTOK" }),
    headers: [["Set-Cookie", "JSESSIONID=CK; Path=/"]] as [string, string][],
  };
  it("captures body + cookie into their variables; skips unresolved + blank targets", () => {
    const out = applyCaptureRules(
      [
        { from: "body", key: "token", into: "apstraToken" },
        { from: "cookie", key: "JSESSIONID", into: "jsessionid" },
        { from: "body", key: "missing", into: "x" }, // unresolved → skipped
        { from: "body", key: "token", into: "  " }, // blank target → skipped
      ],
      resp,
    );
    expect(out).toEqual([
      { into: "apstraToken", value: "BODYTOK" },
      { into: "jsessionid", value: "CK" },
    ]);
  });
  it("returns [] for no rules", () => {
    expect(applyCaptureRules(undefined, resp)).toEqual([]);
    expect(applyCaptureRules([], resp)).toEqual([]);
  });
});
