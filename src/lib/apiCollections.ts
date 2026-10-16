/**
 * v4.0.0 — the API-collection data model + a Postman Collection v2.1
 * importer.
 *
 * A collection is a tree of saved request templates (method + path +
 * headers + body) that a human can run against an api_session's
 * controller. It is NOT inventory and NOT a secret store: templates hold
 * only non-secret request shapes. The `X-API-KEY` is injected Rust-side
 * at send time and is never part of a template — the importer strips any
 * auth header a source collection carries so a foreign key can never be
 * stored or shadow the session's own.
 *
 * Paths are stored HOST-ABSOLUTE (leading `/`), the form Postman exports
 * and the form `Endpoint::confine` resolves unambiguously: a UniFi
 * Network request's `/proxy/network/integration/v1/sites` lands under the
 * local base prefix, and a Site Manager `/v1/hosts` lands under `/`. The
 * controller host is always the session's — never the collection's — so
 * importing a vendor collection and pointing it at your own controller is
 * the whole point.
 */
import { isSensitiveVarName } from "@/stores/apiVariablesStore";

/** A saved request template. `method` is free-form so the human can save
 *  any verb; the agent's GET-only gate is enforced elsewhere and never
 *  consults a template. */
export interface ApiRequestTemplate {
  id: string;
  name: string;
  method: string;
  /** Host-absolute path incl. any query string (`/v1/hosts?limit=10`).
   *  The host is pinned to the session's controller at send time. */
  path: string;
  headers: { key: string; value: string }[];
  /** Raw request body, or null for bodyless requests. */
  body: string | null;
  description?: string;
  /** True for non-GET verbs — the UI flags these and confirms on send.
   *  Purely a human affordance; the agent can never run one. */
  destructive: boolean;
  /** After a response, extract values into {{variables}} — the declarative,
   *  no-JS analog of Postman "tests". Used to auto-populate a login token
   *  (body `$.token` → `{{apicToken}}`, or `Set-Cookie` JSESSIONID →
   *  `{{jsessionid}}`) so downstream requests authenticate without a manual
   *  right-click capture. */
  capture?: CaptureRule[];
}

/**
 * One declarative response-capture rule. Evaluated after a response with a
 * tiny, safe extractor (no arbitrary JS — that would be a code-execution
 * surface an imported collection could abuse).
 */
export interface CaptureRule {
  /** Where to read the value from. */
  from: "body" | "header" | "cookie";
  /** For `body`: a dotted path into the JSON (`imdata.0.aaaLogin.attributes.token`,
   *  a leading `$.` is ignored). For `header`: the response header name. For
   *  `cookie`: the cookie name to read out of `Set-Cookie`. */
  key: string;
  /** The variable name to store the extracted value into (referenced as
   *  `{{into}}` by later requests). */
  into: string;
}

/** A folder of requests + nested folders (mirrors Postman's item tree). */
export interface ApiFolder {
  id: string;
  name: string;
  requests: ApiRequestTemplate[];
  folders: ApiFolder[];
}

/** A named collection: a root folder plus non-secret variables. */
export interface ApiCollection {
  id: string;
  name: string;
  /** Vendor tag for a bundled collection (e.g. "unifi"); absent for
   *  user-imported ones. */
  vendor?: string;
  /** Shipped-with-the-app + read-only. User collections omit this. */
  bundled?: boolean;
  /** Non-secret substitution variables (site ids, base paths). Never the
   *  API key. Carried through import; substitution wiring is later. */
  variables: { key: string; value: string }[];
  root: ApiFolder;
}

const NON_GET_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Auth headers a source collection may carry that we must NOT store —
 *  the key is injected Rust-side. Matched case-insensitively. */
const STRIPPED_HEADERS = new Set(["x-api-key", "authorization"]);

/** True for an auth header we never persist in a saved template (the API key
 *  is injected server-side). Shared by the Postman importer and the
 *  save-request flow so a manually-typed key can't land in a collection. */
export function isStrippedHeader(key: string): boolean {
  return STRIPPED_HEADERS.has(key.trim().toLowerCase());
}

/**
 * Rewrite literal credential values in a request body to `{{variable}}`
 * templates, so they route through the masked, memory-only credential path
 * instead of being persisted.
 *
 * User + imported collections are saved verbatim to localStorage
 * (`apiCollectionsStore`). The importer already strips auth HEADERS, but it
 * never looked at BODIES — so a Postman collection exported with a real
 * password sitting in its login body (`{"username":"admin","password":"hunter2"}`)
 * wrote that password to disk in plaintext. Header-stripping created a false
 * sense that import was credential-safe.
 *
 * Rewriting (rather than blanking) lands the operator in the supported flow:
 * `{{password}}` is masked in the Variables bar, held in memory only, and on a
 * `login_credentials` controller is filled from the keychain at send time.
 *
 * Handles JSON and urlencoded bodies — the two modes the importer produces. A
 * body it cannot parse is left ALONE rather than mangled; the credential-shaped
 * *key* is the signal, so an unparseable blob has no reliable signal to act on.
 *
 * Returns the (possibly rewritten) body plus the keys it touched, for the
 * warning the import/save flow surfaces.
 */
export function scrubCredentialsFromBody(body: string | null): {
  body: string | null;
  scrubbed: string[];
} {
  if (!body || body.trim() === "") return { body, scrubbed: [] };
  const scrubbed: string[] = [];
  // A value that is already a {{template}} is nothing to scrub.
  const isTemplate = (v: string) => /^\s*\{\{\w+\}\}\s*$/.test(v);

  // 1. JSON (raw mode) — walk nested objects + arrays.
  try {
    const parsed: unknown = JSON.parse(body);
    const walk = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(walk);
      if (typeof node !== "object" || node === null) return node;
      // `Object.create(null)`: a plain `{}` routes `out["__proto__"] = …`
      // through Object.prototype's setter, so that member never becomes an own
      // property and JSON.stringify silently DROPS it — corrupting the body we
      // hand back. (No prototype pollution occurs either way; this is about
      // not mangling the user's request.)
      const out = Object.create(null) as Record<string, unknown>;
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (isSensitiveVarName(k) && typeof v === "string" && v !== "" && !isTemplate(v)) {
          scrubbed.push(k);
          out[k] = `{{${k}}}`;
        } else {
          out[k] = walk(v);
        }
      }
      return out;
    };
    const next = walk(parsed);
    return scrubbed.length > 0
      ? { body: JSON.stringify(next, null, 2), scrubbed }
      : { body, scrubbed };
  } catch {
    // not JSON — fall through
  }

  // 2. urlencoded (`j_username=admin&j_password=hunter2`).
  if (/^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(body.trim())) {
    const parts = body
      .trim()
      .split("&")
      .map((pair) => {
        const eq = pair.indexOf("=");
        const k = pair.slice(0, eq);
        const v = pair.slice(eq + 1);
        let key: string;
        try {
          key = decodeURIComponent(k);
        } catch {
          key = k;
        }
        if (isSensitiveVarName(key) && v !== "" && !isTemplate(decodeURIComponent(v))) {
          scrubbed.push(key);
          return `${k}={{${key}}}`;
        }
        return pair;
      });
    if (scrubbed.length > 0) return { body: parts.join("&"), scrubbed };
  }

  return { body, scrubbed };
}

/** Bounds on an imported file so a hostile/huge collection can't exhaust
 *  memory or the UI. Exceeding either truncates with a warning. */
const MAX_REQUESTS = 2000;
const MAX_DEPTH = 20;

export function isDestructiveMethod(method: string): boolean {
  return NON_GET_METHODS.has(method.trim().toUpperCase());
}

/** Tailwind text-color class for an HTTP method badge (Postman-style). */
export function methodColor(method: string): string {
  switch (method.trim().toUpperCase()) {
    case "GET":
      return "text-emerald-600 dark:text-emerald-400";
    case "POST":
      return "text-amber-600 dark:text-amber-400";
    case "PUT":
    case "PATCH":
      return "text-blue-600 dark:text-blue-400";
    case "DELETE":
      return "text-destructive";
    default:
      return "text-muted-foreground";
  }
}

/** All GET endpoints (`[name, path]`) across a set of collections, walked
 *  recursively through folders. For the #12 known-endpoints agent hint —
 *  GET-only (the agent is GET-only, so writes are noise). Deduped by path,
 *  first-seen order. */
export function collectGetEndpoints(collections: ApiCollection[]): [string, string][] {
  const out: [string, string][] = [];
  const seen = new Set<string>();
  const walk = (f: ApiFolder) => {
    for (const r of f.requests) {
      if (r.method.toUpperCase() === "GET" && !seen.has(r.path)) {
        seen.add(r.path);
        out.push([r.name, r.path]);
      }
    }
    for (const sub of f.folders) walk(sub);
  };
  for (const c of collections) walk(c.root);
  return out;
}

/** Every `{{variable}}` token used anywhere in a set of collections — path,
 *  body, or header value, across every method (a login POST's credentials
 *  live in the body, and a token usually rides a header). Sorted + deduped.
 *
 *  This is what the response right-click "Set selection as variable" menu
 *  offers, so the list reflects the OPEN controller's own vocabulary instead
 *  of a fixed one. */
export function collectVarTokens(collections: ApiCollection[]): string[] {
  const out = new Set<string>();
  const scan = (text: string | null | undefined) => {
    if (!text) return;
    for (const m of text.matchAll(/\{\{(\w+)\}\}/g)) out.add(m[1]);
  };
  const walk = (f: ApiFolder) => {
    for (const r of f.requests) {
      scan(r.path);
      scan(r.body);
      for (const h of r.headers) scan(h.value);
    }
    for (const sub of f.folders) walk(sub);
  };
  for (const c of collections) walk(c.root);
  return [...out].sort();
}

/**
 * The auth header a collection uses to carry a captured session token —
 * `("Cookie", "APIC-cookie={{apicToken}}")` for ACI, `("AuthToken",
 * "{{apstraToken}}")` for Apstra, and so on.
 *
 * Found by looking for the first request header whose value references
 * `{{varName}}`, so it is derived from the shipped collection rather than a
 * per-vendor table that could drift from it. Returns the header NAME and its
 * value TEMPLATE (still containing the token); the caller substitutes.
 *
 * This is what lets the backend replay the human's session on the agent's
 * GETs: without it the token exists only as a `{{variable}}` in the frontend,
 * and every agent call against a login-flow controller 403s.
 */
export function sessionAuthHeaderFor(
  collections: ApiCollection[],
  varName: string,
): { name: string; template: string } | null {
  const token = `{{${varName}}}`;
  let found: { name: string; template: string } | null = null;
  const walk = (f: ApiFolder) => {
    if (found) return;
    for (const r of f.requests) {
      for (const h of r.headers) {
        if (h.value.includes(token)) {
          found = { name: h.key, template: h.value };
          return;
        }
      }
    }
    for (const sub of f.folders) walk(sub);
  };
  for (const c of collections) walk(c.root);
  return found;
}

type IdFactory = () => string;

// ---------------------------------------------------------------------
// Postman Collection v2.1 import
// ---------------------------------------------------------------------

/** Result of an import: the collection plus any non-fatal warnings
 *  (stripped auth headers, unsupported body modes, truncation). */
export interface ImportResult {
  collection: ApiCollection;
  warnings: string[];
}

/**
 * Parse a Postman Collection v2.1 (leniently also v2.0) document into an
 * {@link ApiCollection}. Throws `Error` with a human message when the
 * input is not a recognizable collection; accumulates non-fatal issues
 * into `warnings`.
 *
 * `makeId` is injectable so callers/tests can supply deterministic ids;
 * it defaults to `crypto.randomUUID`.
 */
export function importPostmanCollection(
  raw: unknown,
  makeId: IdFactory = () => crypto.randomUUID(),
): ImportResult {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Not a Postman collection: expected a JSON object.");
  }
  const doc = raw as Record<string, unknown>;

  // v1 collections have `requests`/`order` and no `item` array. Give a
  // targeted message rather than a generic parse failure.
  if (!Array.isArray(doc.item)) {
    if (Array.isArray((doc as { requests?: unknown }).requests)) {
      throw new Error(
        "This looks like a Postman v1 collection. Export it as Collection v2.1 and try again.",
      );
    }
    throw new Error("Not a Postman collection: missing an `item` array.");
  }

  const info = (typeof doc.info === "object" && doc.info !== null ? doc.info : {}) as Record<
    string,
    unknown
  >;
  const schema = typeof info.schema === "string" ? info.schema : "";
  const warnings: string[] = [];
  if (schema && !/v2\.[01]\.0/.test(schema)) {
    warnings.push(`Unrecognized collection schema (${schema}); importing as best-effort v2.1.`);
  }

  const name =
    typeof info.name === "string" && info.name.trim() !== ""
      ? info.name.trim()
      : "Imported collection";

  const counter = { requests: 0, truncated: false };
  const root: ApiFolder = {
    id: makeId(),
    name,
    requests: [],
    folders: [],
  };
  walkItems(doc.item, root, 0, counter, warnings, makeId);
  if (counter.truncated) {
    warnings.push(
      `Collection exceeded ${MAX_REQUESTS} requests or ${MAX_DEPTH} folders deep; the rest was skipped.`,
    );
  }

  const variables = parseVariables(doc.variable, warnings);

  return {
    collection: { id: makeId(), name, variables, root },
    warnings,
  };
}

/** Recursively classify Postman items into folders vs requests. An item
 *  with a nested `item` array is a folder; one with a `request` is a
 *  leaf. Anything else is skipped with a warning. */
function walkItems(
  items: unknown[],
  into: ApiFolder,
  depth: number,
  counter: { requests: number; truncated: boolean },
  warnings: string[],
  makeId: IdFactory,
): void {
  if (depth > MAX_DEPTH) {
    counter.truncated = true;
    return;
  }
  for (const it of items) {
    if (counter.requests >= MAX_REQUESTS) {
      counter.truncated = true;
      return;
    }
    if (typeof it !== "object" || it === null) continue;
    const item = it as Record<string, unknown>;
    const itemName = typeof item.name === "string" ? item.name : "";

    if (Array.isArray(item.item)) {
      // Folder.
      const folder: ApiFolder = {
        id: makeId(),
        name: itemName || "Folder",
        requests: [],
        folders: [],
      };
      walkItems(item.item, folder, depth + 1, counter, warnings, makeId);
      into.folders.push(folder);
    } else if (typeof item.request === "object" && item.request !== null) {
      const tmpl = parseRequest(
        item.request as Record<string, unknown>,
        itemName || "Request",
        warnings,
        makeId,
      );
      if (tmpl) {
        into.requests.push(tmpl);
        counter.requests += 1;
      }
    } else if (typeof item.request === "string") {
      // Shorthand: `request` is a bare URL string, method defaults to GET.
      const path = pathFromUrl(item.request, warnings);
      into.requests.push({
        id: makeId(),
        name: itemName || "Request",
        method: "GET",
        path,
        headers: [],
        body: null,
        destructive: false,
      });
      counter.requests += 1;
    }
    // else: not a folder or request (e.g. a bare description) — skip.
  }
}

/** Convert one Postman `request` object into a template. Returns null
 *  only if it is unusable (no URL at all). */
function parseRequest(
  request: Record<string, unknown>,
  name: string,
  warnings: string[],
  makeId: IdFactory,
): ApiRequestTemplate | null {
  const method =
    typeof request.method === "string" && request.method.trim() !== ""
      ? request.method.trim().toUpperCase()
      : "GET";

  const url = request.url;
  if (url === undefined) {
    warnings.push(`Request "${name}" has no URL; skipped.`);
    return null;
  }
  const path = pathFromUrl(url, warnings, name);

  const headers = parseHeaders(request.header, name, warnings);
  const rawBody = parseBody(request.body, name, warnings);
  // Never persist a literal credential from an imported collection (the
  // header-strip above covers auth HEADERS only).
  const { body, scrubbed } = scrubCredentialsFromBody(rawBody);
  if (scrubbed.length > 0) {
    warnings.push(
      `Request "${name}": replaced a literal ${[...new Set(scrubbed)].join(", ")} value with a {{variable}} — credentials are never saved to disk.`,
    );
  }

  const description = typeof request.description === "string" ? request.description : undefined;

  return {
    id: makeId(),
    name,
    method,
    path,
    headers,
    body,
    destructive: isDestructiveMethod(method),
    ...(description ? { description } : {}),
  };
}

/** Extract a host-absolute path (+ query) from a Postman URL, which may
 *  be a raw string or a `{ raw, host, path, query }` object. The host is
 *  always discarded — the session pins it. */
function pathFromUrl(url: unknown, warnings: string[], reqName?: string): string {
  if (typeof url === "string") {
    return pathFromRawUrl(url);
  }
  if (typeof url === "object" && url !== null) {
    const u = url as Record<string, unknown>;

    let path = "/";
    if (Array.isArray(u.path)) {
      const segs = u.path
        .map((s) =>
          typeof s === "string" ? s : typeof s === "object" && s !== null ? "" : String(s),
        )
        .filter((s) => s !== "");
      path = "/" + segs.join("/");
    } else if (typeof u.path === "string") {
      path = u.path.startsWith("/") ? u.path : "/" + u.path;
    } else if (typeof u.raw === "string") {
      return pathFromRawUrl(u.raw);
    }

    const query = buildQuery(u.query);
    return path + query;
  }
  if (reqName) warnings.push(`Request "${reqName}" has an unreadable URL; used "/".`);
  return "/";
}

/** Parse a raw URL string, keeping only its path + query. Tolerates a
 *  bare path ("/v1/hosts"), a `{{host}}`-templated URL, and a full URL. */
function pathFromRawUrl(raw: string): string {
  const trimmed = raw.trim();
  // Strip a scheme + authority if present, without a URL parser (the
  // host may be a `{{var}}` that `new URL` rejects). Everything from the
  // first single "/" after an optional "scheme://authority" is the path.
  const afterScheme = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  const slash = afterScheme.indexOf("/");
  let rest: string;
  if (afterScheme === trimmed) {
    // No scheme. If it already starts with "/", it's a path; otherwise
    // it's "authority/path" or a bare path segment.
    if (trimmed.startsWith("/")) return stripFragment(trimmed);
    const s = trimmed.indexOf("/");
    rest = s >= 0 ? trimmed.slice(s) : "/";
  } else {
    rest = slash >= 0 ? afterScheme.slice(slash) : "/";
  }
  return stripFragment(rest.startsWith("/") ? rest : "/" + rest);
}

function stripFragment(pathAndMaybeFragment: string): string {
  const hash = pathAndMaybeFragment.indexOf("#");
  return hash >= 0 ? pathAndMaybeFragment.slice(0, hash) : pathAndMaybeFragment;
}

/** Build a `?k=v&...` string from Postman's query array (enabled only). */
function buildQuery(query: unknown): string {
  if (!Array.isArray(query)) return "";
  const parts: string[] = [];
  for (const q of query) {
    if (typeof q !== "object" || q === null) continue;
    const item = q as Record<string, unknown>;
    if (item.disabled === true) continue;
    const key = typeof item.key === "string" ? item.key : "";
    if (key === "") continue;
    const value = typeof item.value === "string" ? item.value : "";
    parts.push(`${key}=${value}`);
  }
  return parts.length ? "?" + parts.join("&") : "";
}

/** Parse + sanitize headers: drop disabled, drop auth headers (we inject
 *  the key), keep the rest verbatim. */
function parseHeaders(
  header: unknown,
  reqName: string,
  warnings: string[],
): { key: string; value: string }[] {
  if (!Array.isArray(header)) return [];
  const out: { key: string; value: string }[] = [];
  let strippedAuth = false;
  for (const h of header) {
    if (typeof h !== "object" || h === null) continue;
    const item = h as Record<string, unknown>;
    if (item.disabled === true) continue;
    const key = typeof item.key === "string" ? item.key.trim() : "";
    if (key === "") continue;
    if (isStrippedHeader(key)) {
      strippedAuth = true;
      continue;
    }
    const value = typeof item.value === "string" ? item.value : "";
    out.push({ key, value });
  }
  if (strippedAuth) {
    warnings.push(
      `Request "${reqName}": removed an auth header — the API key is injected automatically.`,
    );
  }
  return out;
}

/** Parse a Postman body. Supports `raw` and `urlencoded`; other modes
 *  (formdata/file/graphql) are dropped with a warning. */
function parseBody(body: unknown, reqName: string, warnings: string[]): string | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  const mode = typeof b.mode === "string" ? b.mode : "";
  if (mode === "raw") {
    return typeof b.raw === "string" ? b.raw : null;
  }
  if (mode === "urlencoded" && Array.isArray(b.urlencoded)) {
    const parts: string[] = [];
    for (const p of b.urlencoded) {
      if (typeof p !== "object" || p === null) continue;
      const item = p as Record<string, unknown>;
      if (item.disabled === true) continue;
      const key = typeof item.key === "string" ? item.key : "";
      if (key === "") continue;
      const value = typeof item.value === "string" ? item.value : "";
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
    return parts.join("&");
  }
  if (mode && mode !== "raw") {
    warnings.push(`Request "${reqName}": body mode "${mode}" isn't supported and was dropped.`);
  }
  return null;
}

/** Parse collection-level variables (non-secret). */
function parseVariables(variable: unknown, warnings: string[]): { key: string; value: string }[] {
  if (!Array.isArray(variable)) return [];
  const out: { key: string; value: string }[] = [];
  for (const v of variable) {
    if (typeof v !== "object" || v === null) continue;
    const item = v as Record<string, unknown>;
    const key = typeof item.key === "string" ? item.key.trim() : "";
    if (key === "") continue;
    const raw = typeof item.value === "string" ? item.value : "";
    // A collection-level variable is persisted verbatim to localStorage with
    // the collection, so a credential-shaped one must NOT keep its value.
    // `{"key":"password","value":"hunter2"}` is the commonest way a Postman
    // user parameterizes a login — the old behaviour warned and stored it
    // anyway, while the identical value typed into the Variables bar is
    // redirected to memory. Keep the KEY (the requests reference it) and drop
    // the VALUE; the operator re-enters it in the bar, where it is masked.
    if (isSensitiveVarName(key) && raw !== "") {
      warnings.push(
        `Variable "${key}" holds a credential; its value was dropped and is never saved to disk — re-enter it in the Variables bar.`,
      );
      out.push({ key, value: "" });
      continue;
    }
    out.push({ key, value: raw });
  }
  return out;
}
