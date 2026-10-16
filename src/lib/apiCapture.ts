import type { CaptureRule } from "@/lib/apiCollections";

/**
 * Declarative response capture — the no-JS analog of Postman "tests"
 * (v4.3.0). A request's `capture` rules pull a value out of the response
 * (a JSON body field, a response header, or a Set-Cookie value) into a
 * `{{variable}}`, so a login token auto-populates for downstream requests
 * without a manual right-click. Deliberately NOT arbitrary JS. Capture rules
 * ship ONLY in bundled (Transit-shipped) collections — the Postman importer
 * never emits one and the user-collections store drops any `capture` on load
 * (`sanitizeRequest`), so an imported or hand-edited collection can't introduce
 * one. Even if it could, a rule can only READ + store a value into a variable —
 * it can't execute, reach another host, or exfiltrate.
 */

/** The response, as capture rules see it. */
export interface CaptureResponse {
  body: string;
  headers: [string, string][];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Follow a dotted path into a parsed-JSON body: `imdata.0.aaaLogin.attributes.token`
 * (a leading `$.` or `$` is ignored). Numeric segments index arrays. Returns the
 * value stringified if it resolves to a scalar, else null.
 */
export function readJsonPath(body: string, path: string): string | null {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return null;
  }
  const segments = path
    .replace(/^\$\.?/, "")
    .split(".")
    .filter((s) => s !== "");
  let cur: unknown = json;
  for (const seg of segments) {
    if (cur == null) return null;
    if (Array.isArray(cur)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0) return null;
      cur = cur[idx];
    } else if (typeof cur === "object") {
      cur = (cur as Record<string, unknown>)[seg];
    } else {
      return null;
    }
  }
  if (typeof cur === "string" || typeof cur === "number" || typeof cur === "boolean") {
    return String(cur);
  }
  return null;
}

/** First response header value matching `name` (case-insensitive), or null. */
export function readHeader(headers: [string, string][], name: string): string | null {
  const lower = name.toLowerCase();
  for (const [k, v] of headers) {
    if (k.toLowerCase() === lower) return v;
  }
  return null;
}

/** Value of cookie `name` from any `Set-Cookie` response header, or null. */
export function readCookie(headers: [string, string][], name: string): string | null {
  const re = new RegExp(`(?:^|[;,\\s])${escapeRegExp(name)}=([^;,\\s]+)`);
  for (const [k, v] of headers) {
    if (k.toLowerCase() !== "set-cookie") continue;
    const m = v.match(re);
    if (m) return m[1];
  }
  return null;
}

/**
 * Evaluate a request's capture rules against its response, returning the
 * `{ into, value }` pairs to store. Rules that don't resolve (missing field,
 * non-JSON body, blank target) are skipped, never throwing — a failed capture
 * must never break the response the operator already got.
 */
export function applyCaptureRules(
  rules: CaptureRule[] | undefined,
  resp: CaptureResponse,
): { into: string; value: string }[] {
  if (!rules || rules.length === 0) return [];
  const out: { into: string; value: string }[] = [];
  for (const rule of rules) {
    if (!rule || rule.into.trim() === "" || rule.key.trim() === "") continue;
    let value: string | null = null;
    if (rule.from === "body") value = readJsonPath(resp.body, rule.key);
    else if (rule.from === "header") value = readHeader(resp.headers, rule.key);
    else if (rule.from === "cookie") value = readCookie(resp.headers, rule.key);
    if (value != null) out.push({ into: rule.into.trim(), value });
  }
  return out;
}
