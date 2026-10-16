import fs from "fs";
const SRC = process.argv[2],
  OUT = process.argv[3];
const j = JSON.parse(fs.readFileSync(SRC, "utf8"));
function pathOf(u) {
  let p = "/";
  if (!u) return p;
  if (typeof u === "string") p = u.replace(/^\{\{[^}]+\}\}/, "").replace(/^https?:\/\/[^/]+/, "");
  else if (Array.isArray(u.path))
    p = "/" + u.path.map((s) => (typeof s === "string" ? s : (s && s.value) || "")).join("/");
  else if (typeof u.raw === "string")
    p = u.raw.replace(/^\{\{[^}]+\}\}/, "").replace(/^https?:\/\/[^/]+/, "");
  p = p.split("?")[0].replace(/:([a-zA-Z][a-zA-Z0-9]*)/g, "{{$1}}");
  if (!p.startsWith("/")) p = "/" + p;
  return p;
}
/**
 * Emit paths RELATIVE to the controller's base, which for Meraki carries a
 * path prefix (`https://api.meraki.com/api/v1`). `Endpoint::confine` resolves
 * a request path with `Url::join`, and per RFC 3986 a LEADING-SLASH path is an
 * absolute-path reference that REPLACES the base path — so `/organizations`
 * resolves to `https://api.meraki.com/organizations`, escapes `/api/v1/`, and
 * is refused as `PathEscape` before any HTTP happens. Relative (`organizations`)
 * resolves under the base, which is why the UniFi *local* roots are relative
 * too (see `bundledCollections.ts`: "The generated local root uses RELATIVE
 * paths, which resolve under either base"). `pathOf` keeps the absolute form
 * because `cat()`'s folder regexes anchor on the leading `/`; strip it only at
 * emission.
 */
const rel = (p) => p.replace(/^\/+/, "");
function cat(p) {
  const m = p.match(/\/(?:networks|devices|organizations)\/[^/]+\/([a-zA-Z]+)/);
  if (m) return m[1];
  const t = p.match(/\/(organizations|networks|devices)\b/);
  return t ? t[1] : "other";
}
const ACR = {
  ssid: "SSID",
  ssids: "SSIDs",
  vpn: "VPN",
  dhcp: "DHCP",
  vlan: "VLAN",
  vlans: "VLANs",
  rf: "RF",
  arp: "ARP",
  lldp: "LLDP",
  cdp: "CDP",
  api: "API",
  dns: "DNS",
  ip: "IP",
  mac: "MAC",
  wan: "WAN",
  lan: "LAN",
  snmp: "SNMP",
  poe: "PoE",
  qos: "QoS",
  ids: "IDS",
  ssh: "SSH",
  pii: "PII",
  stp: "STP",
  ssids2: "SSIDs",
  v4: "v4",
  v6: "v6",
};
function friendly(op) {
  let s = op.replace(/^get/, "");
  s = s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");
  let w = s.split(/\s+/).filter(Boolean);
  if (["Organization", "Network", "Device", "Devices"].includes(w[0])) w = w.slice(1);
  if (!w.length) w = [op];
  w = w.map((x, i) => {
    const l = x.toLowerCase();
    if (ACR[l]) return ACR[l];
    return i === 0 ? x[0].toUpperCase() + x.slice(1).toLowerCase() : x.toLowerCase();
  });
  return w.join(" ");
}
const EXCLUDE = new Set([
  "camera",
  "sm",
  "sensor",
  "cellularGateway",
  "wirelessController",
  "webhooks",
  "insight",
  "saml",
  "brandingPolicies",
  "earlyAccess",
  "pii",
  "floorPlans",
  "adaptivePolicy",
  "mqttBrokers",
  "bluetoothClients",
  "campusGateway",
  "spaces",
  "licensing",
  "licenses",
  "admins",
  "integrations",
  "configTemplates",
  "apiRequests",
  "openapiSpec",
  "firmwareUpgrades",
  "firmware",
  "groupPolicies",
  "merakiAuthUsers",
  "samlRoles",
  "policyObjects",
  "vlanProfiles",
  "snmp",
  "actionBatches",
  "configurationChanges",
  "assurance",
  "alerts",
  "liveTools",
]);
/**
 * Discovery listings the MONITOR filter rejects — they don't read as
 * "diagnostic", so curation dropped them — but WITHOUT which nothing else in
 * the collection is reachable: 56 paths need `{{organizationId}}` and 84 need
 * `{{networkId}}`, and neither could be obtained from inside the collection.
 * Forced into Organization, first, with explicit names (`friendly()` would
 * flatten "Get Organizations" to a bare "Organizations").
 *
 * Deliberately NO capture rule on the org listing: `GET organizations` returns
 * an ARRAY, so a dotted-path capture would silently pick `organizations[0]` —
 * the wrong default for an MSP whose key sees many client orgs. The operator
 * right-clicks the id they want → "Set selection as variable".
 */
const BOOTSTRAP = new Map([
  ["/organizations", "List organizations (start here — id → {{organizationId}})"],
  ["/organizations/{{organizationId}}/networks", "List networks (id → {{networkId}})"],
  ["/organizations/{{organizationId}}/devices", "List devices (serial → {{serial}})"],
  ["/networks/{{networkId}}/switch/stacks", "List switch stacks (id → {{switchStackId}})"],
]);
const BOOT_ORDER = [...BOOTSTRAP.values()];
const MONITOR =
  /(status|\bclients?\b|health|connectivity|latenc|\bloss\b|uplink|\bevents?\b|airMarshal|failedConnection|connectionStat|channelUtilization|\bports?\b|splash|\bvpn\b|topology|lldpCdp|packetLoss|byDevice|overview|\btraffic\b|signalQualit|dataRate|rfProfile|\bssids?\b|\bdhcp\b|\bvlans?\b|routing|\barp\b|usageHistory|counters|history|latencyStat)/i;
const FOLDER = {
  switch: "Switch (MS)",
  wireless: "Wireless & captive portal (MR)",
  appliance: "Appliance & SD-WAN (MX)",
  organizations: "Organization",
  networks: "Network",
  devices: "Devices",
  clients: "Clients",
  summary: "Organization",
  uplinks: "Appliance & SD-WAN (MX)",
  events: "Network",
  topology: "Network",
  lldpCdp: "Devices",
  traffic: "Network",
  cellular: "Appliance & SD-WAN (MX)",
  networkHealth: "Network",
  lossAndLatencyHistory: "Appliance & SD-WAN (MX)",
  splash: "Wireless & captive portal (MR)",
  splashLoginAttempts: "Wireless & captive portal (MR)",
  trafficShaping: "Appliance & SD-WAN (MX)",
  policies: "Network",
  other: "Organization",
};
let id = 0;
const nid = () => "meraki-" + id++;
const folders = {};
function walk(items) {
  for (const it of items || []) {
    if (it.item) walk(it.item);
    else if (it.request) {
      const m = (it.request.method || "GET").toUpperCase();
      if (m !== "GET") continue;
      const p = pathOf(it.request.url);
      const c = cat(p);
      if (EXCLUDE.has(c)) continue;
      const op = (it.name || "").trim();
      const boot = BOOTSTRAP.get(p);
      if (!boot && !(MONITOR.test(p) || MONITOR.test(op))) continue;
      // A bootstrap listing goes in Organization regardless of what `cat()`
      // says (".../networks" would otherwise land in Network, away from the
      // other discovery calls).
      const fn = boot ? "Organization" : FOLDER[c];
      if (!fn) continue;
      const desc =
        typeof it.request.description === "string"
          ? it.request.description.split("\n")[0].slice(0, 160)
          : undefined;
      (folders[fn] = folders[fn] || []).push({
        id: nid(),
        name: boot ?? friendly(op),
        method: "GET",
        path: rel(p),
        headers: [],
        body: null,
        destructive: false,
        ...(desc ? { description: desc } : {}),
        _op: op,
        _boot: Boolean(boot),
      });
    }
  }
}
walk(j.item);
for (const f in folders) {
  const seen = new Set();
  folders[f] = folders[f]
    .filter((r) => (seen.has(r.path) ? false : (seen.add(r.path), true)))
    // Discovery listings first in their folder, in BOOTSTRAP declaration
    // order — they are the entry point, and "List organizations" must lead
    // (everything else in the collection needs an id one of them yields).
    .sort((a, b) => {
      const rank = (r) => (r._boot ? BOOT_ORDER.indexOf(r.name) : Number.MAX_SAFE_INTEGER);
      return rank(a) - rank(b);
    })
    .map(({ _op, _boot, ...r }) => r);
}
/**
 * Human-only write requests (v4.3.0). Hand-authored — the Meraki export's
 * write surface is thousands of endpoints, so we ship a small set of the
 * changes an operator actually makes by hand. Kept HERE rather than patched
 * into the generated JSON so the generator stays the single source of truth
 * (they were previously appended post-generation, which meant re-running the
 * generator silently dropped them).
 *
 * The AI agent cannot reach these regardless of collection content — the tool
 * has no `method` field and `evaluate_agent_get` is GET-locked (Rule 3).
 */
const WRITES = [
  ["w901", "Blink device LEDs", "POST", "devices/{{serial}}/blinkLeds", '{\n  "duration": 20\n}'],
  ["w902", "Reboot device", "POST", "devices/{{serial}}/reboot", null],
  ["w903", "Update device", "PUT", "devices/{{serial}}", '{\n  "name": "",\n  "tags": []\n}'],
  [
    "w904",
    "Update switch port",
    "PUT",
    "devices/{{serial}}/switch/ports/{{portId}}",
    '{\n  "enabled": true,\n  "name": ""\n}',
  ],
  [
    "w905",
    "Cycle switch ports",
    "POST",
    "devices/{{serial}}/switch/ports/cycle",
    '{\n  "ports": [\n    "1"\n  ]\n}',
  ],
  [
    "w906",
    "Update SSID",
    "PUT",
    "networks/{{networkId}}/wireless/ssids/{{number}}",
    '{\n  "enabled": true,\n  "name": ""\n}',
  ],
  [
    "w907",
    "Update appliance VLAN",
    "PUT",
    "networks/{{networkId}}/appliance/vlans/{{vlanId}}",
    '{\n  "name": ""\n}',
  ],
  [
    "w908",
    "Claim devices into network",
    "POST",
    "networks/{{networkId}}/devices/claim",
    '{\n  "serials": []\n}',
  ],
];
folders["Common changes (writes)"] = WRITES.map(([wid, name, method, path, body]) => ({
  id: "meraki-" + wid,
  name,
  method,
  path,
  headers: [],
  body,
  destructive: true,
}));

const order = [
  "Organization",
  "Network",
  "Devices",
  "Clients",
  "Switch (MS)",
  "Wireless & captive portal (MR)",
  "Appliance & SD-WAN (MX)",
  "Common changes (writes)",
];
const root = {
  id: nid(),
  name: "Meraki",
  requests: [],
  folders: order
    .filter((f) => folders[f]?.length)
    .map((f) => ({ id: nid(), name: f, requests: folders[f], folders: [] })),
};
const collection = {
  id: "meraki",
  name: "Meraki Dashboard",
  vendor: "meraki",
  bundled: true,
  variables: [],
  root,
};
let total = 0;
for (const f of root.folders) total += f.requests.length;
console.log(`${total} endpoints. Friendly-name samples:`);
for (const f of root.folders) {
  console.log(`\n  [${f.name}]`);
  f.requests.slice(0, 5).forEach((r) => console.log(`    ${r.name}`));
}
fs.writeFileSync(OUT, JSON.stringify(collection, null, 2));
console.log("\nwrote " + OUT);
