/**
 * v4.0.0 — bundled endpoint catalogs shipped with the app.
 *
 * When a controller is launched, the matching collection is nested under it
 * in the APIs sidebar (collapsed by default). These are for the HUMAN
 * (Postman) surface, which is UNGATED like the SSH terminal, so the catalog
 * includes WRITE endpoints (POST/PUT/PATCH/DELETE), flagged `destructive`
 * (the pane confirms before sending one). The AI agent's GET-only gate is
 * enforced elsewhere and never consults a template.
 *
 * The UniFi Developer portal groups its APIs into Site Manager / Network /
 * Protect. A **Site Manager (cloud)** controller can reach ALL THREE from
 * the one `api.ui.com` key: Site Manager endpoints directly, and Network +
 * Protect via the cloud CONNECTOR proxy
 * (`/v1/connector/consoles/{consoleId}/proxy/{network|protect}/integration/v1/…`).
 * All are host-absolute paths under the pinned `api.ui.com/` base, so one
 * collection covers the lot — Endpoint::confine allows them and the host is
 * never caller-chosen. Grab {consoleId} from Site Manager → List hosts.
 *
 * A **network_local** / **connector_proxy** controller pins a single
 * console's Network base, so it gets the Network-only catalog with RELATIVE
 * paths (which resolve under either of those bases). Direct-to-console
 * Protect would need its own base + kind (a follow-up); the cloud path above
 * is the way to reach Protect today.
 *
 * Endpoints track the UniFi Site Manager + Network Integration + Protect
 * Integration references; `/v1/{hosts,sites,devices}` are verified live.
 * UniFi's API is version-pinned, so a stale path just 404s and is editable.
 */

import type { ApiEndpointKind, ApiSessionMeta } from "@/lib/api";
import {
  isDestructiveMethod,
  type ApiCollection,
  type ApiFolder,
  type ApiRequestTemplate,
} from "@/lib/apiCollections";
// The full UniFi Network catalog (73 endpoints, 13 folders) is DERIVED from
// the official UniFi Network Postman collection by scripts/gen-unifi-network.mjs
// — cloud (connector) + local (relative) forms. Regenerate on a UniFi update.
import unifiNetwork from "@/lib/collections/unifiNetwork.generated.json";
import unifiProtect from "@/lib/collections/unifiProtect.generated.json";
// v4.3.0 — first-class REST vendors. Each is a curated investigation collection
// DERIVED from the vendor's official Postman export by scripts/gen-*-collection
// (GET-only for the RESTful vendors + a "Log in first" folder for the login-flow
// ones; Meraki is Bearer/no-login). The generated JSON already is our
// ApiCollection shape, so it's imported + returned directly.
import merakiCollection from "@/lib/collections/meraki.generated.json";
import apstraCollection from "@/lib/collections/apstra.generated.json";
import arubaCollection from "@/lib/collections/aruba.generated.json";
import aciCollection from "@/lib/collections/aci.generated.json";
import sdwanCollection from "@/lib/collections/sdwan.generated.json";
import fortimanagerCollection from "@/lib/collections/fortimanager.generated.json";
import fortianalyzerCollection from "@/lib/collections/fortianalyzer.generated.json";
// v6.2.0 — NetBox (CMDB/IPAM): DERIVED from a NetBox instance's own OpenAPI
// schema by scripts/gen-netbox-collection.mjs (NetBox publishes no spec file;
// every install serves /api/schema/). GET-only by design — the session's
// target is a source of truth ABOUT devices, not a controller OF them; the
// curated ~30 requests are the circuit → terminations → devices → interfaces
// → IPs outage walk plus the everyday lookups.
import netboxCollection from "@/lib/collections/netbox.generated.json";

function req(
  id: string,
  name: string,
  method: string,
  path: string,
  description: string,
  body: string | null = null,
): ApiRequestTemplate {
  return {
    id,
    name,
    method,
    path,
    headers: [],
    body,
    destructive: isDestructiveMethod(method),
    description,
  };
}

function folder(id: string, name: string, requests: ApiRequestTemplate[]): ApiFolder {
  return { id, name, requests, folders: [] };
}

// Network + Protect catalogs are GENERATED from the official UniFi Postman +
// OpenAPI files (scripts/gen-unifi-collection.mjs). Cast because the JSON is
// our own derived ApiFolder shape (produced + tested via the generator).
// Cloud folders are named "<Surface> (via connector)" and use host-absolute
// connector paths with `{{consoleId}}` (set once in the pane's Variables bar);
// the Network local root is the network_local collection.
const NETWORK_CLOUD_FOLDER = unifiNetwork.cloud as unknown as ApiFolder;
const NETWORK_LOCAL_ROOT = unifiNetwork.local as unknown as ApiFolder;
const PROTECT_CLOUD_FOLDER = unifiProtect.cloud as unknown as ApiFolder;

/** Site Manager direct endpoints (account-wide read/monitor + SD-WAN). */
const SITE_MANAGER_FOLDER = folder("unifi-sm", "Site Manager", [
  req(
    "sm-hosts",
    "List hosts (consoles)",
    "GET",
    "/v1/hosts",
    "Every UniFi console / network app on the account. A host id is your {{consoleId}} variable for Network/Protect below.",
  ),
  req(
    "sm-host-by-id",
    "Get host by ID",
    "GET",
    "/v1/hosts/{{consoleId}}",
    "One host's metadata + status — reuses the {{consoleId}} variable (a host id).",
  ),
  req(
    "sm-sites",
    "List sites",
    "GET",
    "/v1/sites",
    "All sites with health, ISP info + device counts.",
  ),
  req(
    "sm-devices",
    "List devices",
    "GET",
    "/v1/devices",
    "All adopted devices across the account.",
  ),
  req(
    "sm-isp-5m",
    "ISP metrics (5-minute)",
    "GET",
    "/ea/isp-metrics/5m",
    "WAN / ISP metrics in 5-minute buckets.",
  ),
  req(
    "sm-isp-1h",
    "ISP metrics (hourly)",
    "GET",
    "/ea/isp-metrics/1h",
    "WAN / ISP metrics in 1-hour buckets.",
  ),
  req(
    "sm-isp-query",
    "Filtered ISP query",
    "POST",
    "/ea/isp-metrics/5m/query",
    "Filtered ISP metrics — reads, with a JSON filter body.",
    '{\n  "sites": [],\n  "interval": "5m"\n}',
  ),
  req(
    "sm-sdwan-list",
    "List SD-WAN configs",
    "GET",
    "/v1/sdwan-configs",
    "All SD-WAN configurations.",
  ),
  req(
    "sm-sdwan-status",
    "SD-WAN status",
    "GET",
    "/v1/sdwan-configs/{{sdwanConfigId}}/status",
    "Deployment status for a config — set {{sdwanConfigId}} from List SD-WAN configs.",
  ),
]);

/** Unified UniFi collection for a Site Manager (cloud) controller: all three
 *  surfaces, reachable from the one cloud key (Network/Protect via the
 *  connector proxy). Rendered as three collapsible folders under it. */
const UNIFI_CLOUD: ApiCollection = {
  id: "unifi-cloud",
  name: "UniFi (cloud)",
  vendor: "unifi",
  bundled: true,
  variables: [],
  root: {
    id: "unifi-cloud-root",
    name: "UniFi",
    requests: [],
    folders: [SITE_MANAGER_FOLDER, NETWORK_CLOUD_FOLDER, PROTECT_CLOUD_FOLDER],
  },
};

/** Network-only catalog for a direct console (`network_local`) or the
 *  network connector-proxy (`connector_proxy`). The generated local root
 *  uses RELATIVE paths, which resolve under either base. */
const UNIFI_NETWORK_DIRECT: ApiCollection = {
  id: "unifi-network",
  name: "UniFi Network (self-hosted)",
  vendor: "unifi",
  bundled: true,
  variables: [],
  root: NETWORK_LOCAL_ROOT,
};

/**
 * The bundled collection for a controller's vendor + surface, or null when
 * none ships for it (a non-UniFi or fully-custom controller still gets the
 * raw path box).
 */
/**
 * v4.3.0 first-class REST vendors: vendor tag → its single bundled collection.
 * These are base-URL controllers (kind=generic), so the collection is the same
 * regardless of kind (unlike UniFi's per-surface split). Cast because the
 * generated JSON is our own derived ApiCollection shape.
 */
const VENDOR_COLLECTIONS: Record<string, ApiCollection> = {
  meraki: merakiCollection as unknown as ApiCollection,
  apstra: apstraCollection as unknown as ApiCollection,
  aruba: arubaCollection as unknown as ApiCollection,
  aci: aciCollection as unknown as ApiCollection,
  sdwan: sdwanCollection as unknown as ApiCollection,
  fortimanager: fortimanagerCollection as unknown as ApiCollection,
  fortianalyzer: fortianalyzerCollection as unknown as ApiCollection,
  netbox: netboxCollection as unknown as ApiCollection,
};

export function bundledCollectionFor(vendor: string, kind: ApiEndpointKind): ApiCollection | null {
  // UniFi splits by surface: cloud (Site Manager) reaches all three surfaces
  // via the connector; a direct/proxied Network base gets the Network catalog.
  if (vendor === "unifi") {
    return kind === "site_manager" ? UNIFI_CLOUD : UNIFI_NETWORK_DIRECT;
  }
  return VENDOR_COLLECTIONS[vendor] ?? null;
}

/**
 * The fixed base every request in this session is pinned to, for display
 * only (the real pin is server-side in `Endpoint`). Shows the operator
 * what their path is appended to.
 */
export function apiBaseDisplay(meta: ApiSessionMeta): string {
  switch (meta.kind) {
    case "site_manager":
      return "https://api.ui.com";
    case "network_local":
      return `https://${meta.host ?? "<host>"}/proxy/network/integration/v1`;
    case "connector_proxy":
      return `https://api.ui.com/v1/connector/consoles/${meta.console_id ?? "<console>"}/proxy/network/integration/v1`;
    case "generic":
      return meta.base_url ?? "<base URL>";
  }
}
