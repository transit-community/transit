#!/usr/bin/env node
/**
 * Generate a Transit bundled UniFi collection from the official UniFi Postman
 * collection + OpenAPI spec (developer.ui.com downloads). Works for any
 * surface that follows UniFi's `/proxy/<surface>/integration/v1/…` connector
 * shape. Run on a UniFi API update:
 *
 *   node scripts/gen-unifi-collection.mjs network ~/Downloads/network_vX_postman-collection.json ~/Downloads/network_vX_openapi.json
 *   node scripts/gen-unifi-collection.mjs protect ~/Downloads/protect_vX_postman-collection.json ~/Downloads/protect_vX_openapi.json
 *
 * Output: src/lib/collections/unifi<Surface>.generated.json — our DERIVED
 * catalog (ApiFolder shape), two forms of every request:
 *   - `cloud`: from a Site Manager (cloud) controller via the connector →
 *     host-absolute
 *     `/v1/connector/consoles/{{consoleId}}/proxy/<surface>/integration` + path.
 *   - `local`: RELATIVE to `…/proxy/<surface>/integration/v1/` (leading /v1/
 *     stripped). (Only `network` uses the local form today; `protect` is
 *     cloud-only until a direct protect_local base + kind exists.)
 *
 * We commit the DERIVED JSON + this script, NOT UniFi's raw files (endpoint
 * paths/methods are factual API data). Postman `:param` → our `{{param}}`
 * variables (settable + reused via the pane's Variables bar, like the
 * pre-existing `{{consoleId}}`). OpenAPI
 * (optional) supplies clean summaries (names) + one-line descriptions; Postman
 * supplies the folder structure + example bodies.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SURFACES = {
  network: {
    idTag: "net",
    cloudName: "Network (via connector)",
    localName: "UniFi Network",
    out: "unifiNetwork.generated.json",
  },
  protect: {
    idTag: "prot",
    cloudName: "Protect (via connector)",
    localName: "UniFi Protect",
    out: "unifiProtect.generated.json",
  },
};
const NON_GET = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const surface = process.argv[2];
const src = process.argv[3];
const openapiPath = process.argv[4];
if (!SURFACES[surface] || !src) {
  console.error(
    "usage: node scripts/gen-unifi-collection.mjs <network|protect> <postman.json> [<openapi.json>]",
  );
  process.exit(1);
}
const cfg = SURFACES[surface];
const CONNECTOR_PREFIX = `/v1/connector/consoles/{{consoleId}}/proxy/${surface}/integration`;

const doc = JSON.parse(readFileSync(src, "utf8"));
if (!Array.isArray(doc.item)) {
  console.error("not a Postman collection (no item[] array)");
  process.exit(1);
}

// Optional OpenAPI spec: clean summary (→ name) + one-line description per
// endpoint. Bodies stay from Postman (OpenAPI bodies are $ref schemas).
const openapi = new Map(); // "METHOD /path" -> { summary, description }
if (openapiPath) {
  const spec = JSON.parse(readFileSync(openapiPath, "utf8"));
  for (const [p, ops] of Object.entries(spec.paths || {})) {
    for (const [m, op] of Object.entries(ops)) {
      if (typeof op !== "object" || op === null || !op.summary) continue;
      openapi.set(`${m.toUpperCase()} ${p}`, {
        summary: typeof op.summary === "string" ? op.summary : undefined,
        description: typeof op.description === "string" ? firstLine(op.description) : undefined,
      });
    }
  }
}

/** First clean line of an OpenAPI description: HTML-stripped, capped. */
function firstLine(d) {
  const line = d
    .split(/\r?\n/)[0]
    .replace(/<[^>]*>/g, "")
    .trim();
  return line.length > 200 ? line.slice(0, 197) + "…" : line;
}

const slug = (s) =>
  String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .slice(0, 48);

/** Official path segments → "/v1/cameras/{{id}}" (colon `:id` → `{{id}}`
 *  variable, so every path param is settable/reused in the pane's Variables
 *  bar — consistent with `{{consoleId}}`, no confusing single-brace inline). */
function bracePath(url) {
  const segs = Array.isArray(url?.path)
    ? url.path.map((s) => (typeof s === "string" ? s : (s && s.value) || ""))
    : [];
  const joined = "/" + segs.filter((s) => s !== "").join("/");
  return joined.replace(/:([A-Za-z0-9_]+)/g, "{{$1}}");
}

function toTemplate(item, form) {
  const r = item.request;
  const method = (r.method || "GET").toUpperCase();
  const bp = bracePath(r.url);
  const path =
    form === "cloud" ? CONNECTOR_PREFIX + bp : bp.replace(/^\/v1\//, "").replace(/^\/v1$/, "");
  const body =
    r.body && r.body.mode === "raw" && typeof r.body.raw === "string" ? r.body.raw : null;
  const enrich = openapi.get(`${method} ${bp}`);
  const name = (enrich && enrich.summary) || item.name || `${method} ${bp}`;
  const description =
    (enrich && enrich.description) ||
    (typeof item.description === "string"
      ? item.description
      : typeof r.description === "string"
        ? r.description
        : undefined);
  return {
    id: `${cfg.idTag}-${form}-${method.toLowerCase()}-${slug(bp)}`,
    name,
    method,
    path,
    headers: [],
    body,
    destructive: NON_GET.has(method),
    ...(description ? { description } : {}),
  };
}

/** Walk one Postman folder → our ApiFolder (requests + nested folders). */
function toFolder(item, form, idBase) {
  const requests = [];
  const folders = [];
  for (const child of item.item || []) {
    if (Array.isArray(child.item))
      folders.push(toFolder(child, form, `${idBase}-${slug(child.name)}`));
    else if (child.request) requests.push(toTemplate(child, form));
  }
  return { id: idBase, name: item.name || "Folder", requests, folders };
}

function buildRoot(form, name) {
  const requests = [];
  const folders = [];
  for (const item of doc.item) {
    if (Array.isArray(item.item))
      folders.push(toFolder(item, form, `${cfg.idTag}-${form}-${slug(item.name)}`));
    else if (item.request) requests.push(toTemplate(item, form));
  }
  return { id: `${cfg.idTag}-${form}-root`, name, requests, folders };
}

const out = {
  generatedFrom: doc.info?.name
    ? `${doc.info.name} (official Postman + OpenAPI)`
    : `UniFi ${surface}`,
  note: "DERIVED from the official UniFi Postman collection + OpenAPI by scripts/gen-unifi-collection.mjs — do not edit by hand.",
  cloud: buildRoot("cloud", cfg.cloudName),
  local: buildRoot("local", cfg.localName),
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(__dirname, `../src/lib/collections/${cfg.out}`);
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");

const count = (f) => f.requests.length + f.folders.reduce((n, s) => n + count(s), 0);
console.log(`wrote ${outPath}`);
console.log(`cloud: ${count(out.cloud)} requests in ${out.cloud.folders.length} folders`);
console.log(`local: ${count(out.local)} requests in ${out.local.folders.length} folders`);
