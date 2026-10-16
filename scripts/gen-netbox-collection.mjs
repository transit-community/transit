#!/usr/bin/env node
/**
 * Generate the Transit bundled NetBox collection from a NetBox instance's
 * OpenAPI schema. NetBox publishes no downloadable spec — every install
 * serves its own at `<instance>/api/schema/?format=json`. Run on a NetBox
 * API update:
 *
 *   curl -o /tmp/netbox-openapi.json "https://<instance>/api/schema/?format=json"
 *   node scripts/gen-netbox-collection.mjs /tmp/netbox-openapi.json
 *
 * Output: src/lib/collections/netbox.generated.json (ApiCollection shape,
 * vendor "netbox"). We commit the DERIVED JSON + this script, never the raw
 * spec (~13 MB; endpoint paths/params are factual API data).
 *
 * Unlike the UniFi generator (which mirrors everything in the vendor's
 * Postman) this is an INCLUDE-LIST: NetBox's spec has ~300 GET paths, and
 * the bundled collection is a curated investigation surface (~30) — the
 * list/detail calls plus the filtered variants an outage walk actually uses
 * (circuit → terminations → devices → interfaces → IPs). KnownEndpoints
 * already tells the model the list is a starting point, not an allowlist,
 * so breadth lives in the model's own NetBox knowledge; the curation here
 * is prompt economy.
 *
 * Every include entry and every query-variant param is VALIDATED against
 * the spec — a typo'd path or a filter the API doesn't document fails the
 * run instead of shipping a request that 400s in the field.
 *
 * Paths are emitted RELATIVE (leading `/api/` stripped, no leading slash)
 * because the session's base URL carries the prefix
 * (`https://netbox.example/api`) — a leading-slash path would ESCAPE a
 * prefixed base under RFC 3986 join semantics; see
 * bundled_collections_confine.rs (the v4.3.0 Meraki lesson).
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const src = process.argv[2];
if (!src) {
  console.error("usage: node scripts/gen-netbox-collection.mjs <netbox-openapi.json>");
  process.exit(1);
}

const spec = JSON.parse(readFileSync(src, "utf8"));
if (!spec.paths || !spec.info) {
  console.error("not an OpenAPI document (no paths/info)");
  process.exit(1);
}

/**
 * The curated surface. Per entry:
 *   path    — the spec path, verbatim (leading /api/, trailing slash).
 *   name    — curated display name; "id → {{var}}" hints follow the Meraki
 *             convention so the model learns the traversal vocabulary.
 *   idVar   — replaces the spec's `{id}` path param with `{{<idVar>}}`.
 *   query   — filtered variant: [param, value] pairs appended as a query
 *             string. Values are usually `{{var}}` templates; each PARAM
 *             name must exist on the spec's GET op or generation fails.
 *   desc    — optional override; default is the spec description's first line.
 */
const FOLDERS = [
  {
    name: "Start here",
    entries: [
      {
        path: "/api/status/",
        name: "NetBox status & version (start here)",
        desc: "Instance version + plugins — confirms the token works and which NetBox you're talking to.",
      },
    ],
  },
  {
    name: "Circuits",
    entries: [
      { path: "/api/circuits/circuits/", name: "List circuits (id → {{circuitId}})" },
      {
        path: "/api/circuits/circuits/",
        name: "Find circuit by CID",
        query: [["cid", "{{cid}}"]],
      },
      {
        path: "/api/circuits/circuits/",
        name: "Circuits at a site",
        query: [["site_id", "{{siteId}}"]],
      },
      { path: "/api/circuits/circuits/{id}/", idVar: "circuitId", name: "Get circuit" },
      {
        path: "/api/circuits/circuit-terminations/",
        name: "Terminations of a circuit (→ site/endpoint of {{circuitId}})",
        query: [["circuit_id", "{{circuitId}}"]],
        desc: "The circuit-outage pivot: which site + termination points {{circuitId}} lands on — then list that site's devices.",
      },
      { path: "/api/circuits/providers/", name: "List providers" },
    ],
  },
  {
    name: "Devices (DCIM)",
    entries: [
      { path: "/api/dcim/devices/", name: "List devices (id → {{deviceId}})" },
      {
        path: "/api/dcim/devices/",
        name: "Devices at a site",
        query: [["site_id", "{{siteId}}"]],
      },
      {
        path: "/api/dcim/devices/",
        name: "Devices by role",
        query: [["role_id", "{{roleId}}"]],
      },
      {
        path: "/api/dcim/devices/",
        name: "Find device by name (contains)",
        query: [["name__ic", "{{name}}"]],
      },
      { path: "/api/dcim/devices/", name: "Devices by tag", query: [["tag", "{{tag}}"]] },
      { path: "/api/dcim/devices/", name: "Search devices", query: [["q", "{{query}}"]] },
      {
        path: "/api/dcim/devices/",
        name: "List devices (compact)",
        query: [["fields", "id,name,status,primary_ip4,site,role"]],
        desc: "fields= trims each object to the named fields — prefer this when you only need identity + reachability.",
      },
      {
        path: "/api/dcim/devices/{id}/",
        idVar: "deviceId",
        name: "Get device (primary IP, platform, site, rack)",
      },
      {
        path: "/api/dcim/interfaces/",
        name: "Interfaces of a device",
        query: [["device_id", "{{deviceId}}"]],
        desc: "Each interface carries its cable and connected endpoint — the physical-topology hop.",
      },
      { path: "/api/dcim/cables/{id}/", idVar: "cableId", name: "Get cable (both terminations)" },
      { path: "/api/dcim/device-roles/", name: "List device roles (id → {{roleId}})" },
      { path: "/api/dcim/platforms/", name: "List platforms" },
    ],
  },
  {
    name: "Sites (DCIM)",
    entries: [
      { path: "/api/dcim/sites/", name: "List sites (id → {{siteId}})" },
      {
        path: "/api/dcim/sites/",
        name: "Find site by slug",
        query: [["slug", "{{siteSlug}}"]],
      },
      { path: "/api/dcim/sites/{id}/", idVar: "siteId", name: "Get site" },
      { path: "/api/dcim/regions/", name: "List regions" },
    ],
  },
  {
    name: "IPAM",
    entries: [
      {
        path: "/api/ipam/ip-addresses/",
        name: "Who has this IP? (find by address)",
        query: [["address", "{{address}}"]],
      },
      {
        path: "/api/ipam/ip-addresses/",
        name: "IPs assigned to a device",
        query: [["device_id", "{{deviceId}}"]],
      },
      { path: "/api/ipam/prefixes/", name: "List prefixes (id → {{prefixId}})" },
      {
        path: "/api/ipam/prefixes/",
        name: "Prefixes containing an IP",
        query: [["contains", "{{address}}"]],
      },
      {
        path: "/api/ipam/prefixes/",
        name: "Prefixes at a site",
        query: [["site_id", "{{siteId}}"]],
      },
      { path: "/api/ipam/prefixes/{id}/", idVar: "prefixId", name: "Get prefix" },
      { path: "/api/ipam/vlans/", name: "VLANs at a site", query: [["site_id", "{{siteId}}"]] },
      { path: "/api/ipam/vrfs/", name: "List VRFs" },
    ],
  },
];

/** First clean line of an OpenAPI description: HTML-stripped, capped. */
function firstLine(d) {
  const line = String(d)
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

/** The spec's GET op for a path, with parameter $refs resolved to names. */
function specGet(path) {
  const op = spec.paths[path]?.get;
  if (!op) return null;
  const params = new Set();
  for (let p of op.parameters ?? []) {
    if (p.$ref) {
      const key = p.$ref.split("/").pop();
      p = spec.components?.parameters?.[key];
      if (!p) continue;
    }
    params.add(p.name);
  }
  return { op, params };
}

const errors = [];
const seenIds = new Set();

function toTemplate(entry) {
  const got = specGet(entry.path);
  if (!got) {
    errors.push(`no GET ${entry.path} in the spec`);
    return null;
  }
  for (const [param] of entry.query ?? []) {
    if (!got.params.has(param)) {
      errors.push(`GET ${entry.path}: query param "${param}" is not documented in the spec`);
    }
  }

  // /api/dcim/devices/{id}/ → dcim/devices/{{deviceId}}/ — relative to the
  // session base (…/api), path params as {{var}} (settable in the pane's
  // Variables bar; never single-brace).
  let path = entry.path.replace(/^\/api\//, "");
  if (path.includes("{id}")) {
    if (!entry.idVar) errors.push(`GET ${entry.path}: {id} path needs an idVar`);
    path = path.replace("{id}", `{{${entry.idVar}}}`);
  }
  if (entry.query?.length) {
    path += "?" + entry.query.map(([k, v]) => `${k}=${v}`).join("&");
  }

  const id = `netbox-get-${slug(path)}`;
  if (seenIds.has(id)) errors.push(`duplicate request id ${id} — differentiate the entry`);
  seenIds.add(id);

  const description =
    entry.desc ?? (got.op.description ? firstLine(got.op.description) : undefined);
  return {
    id,
    name: entry.name,
    method: "GET",
    path,
    headers: [],
    body: null,
    destructive: false,
    ...(description ? { description } : {}),
  };
}

const root = {
  id: "netbox-root",
  name: "NetBox",
  requests: [],
  folders: FOLDERS.map((f) => ({
    id: `netbox-${slug(f.name)}`,
    name: f.name,
    requests: f.entries.map(toTemplate).filter(Boolean),
    folders: [],
  })),
};

if (errors.length) {
  console.error("generation FAILED — the include-list disagrees with the spec:");
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}

const out = {
  generatedFrom:
    `${spec.info.title ?? "NetBox REST API"} ${spec.info.version ?? ""} OpenAPI (/api/schema/)`.trim(),
  note: "DERIVED from a NetBox instance's OpenAPI schema by scripts/gen-netbox-collection.mjs — do not edit by hand.",
  id: "netbox",
  name: "NetBox",
  vendor: "netbox",
  bundled: true,
  variables: [],
  root,
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(__dirname, "../src/lib/collections/netbox.generated.json");
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");

const count = root.folders.reduce((n, f) => n + f.requests.length, 0);
console.log(`wrote ${outPath}`);
console.log(`${count} requests in ${root.folders.length} folders (from ${out.generatedFrom})`);
