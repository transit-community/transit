# NetBox

NetBox is the first bundled API integration whose target is a **source of
truth about your devices** (CMDB/IPAM) rather than a controller of them.
Add your instance as an API session and the AI agent can answer "which
devices hang off circuit CID-1234?" from NetBox, then investigate those
devices over the SSH sessions you open — one chat, two evidence sources.

Everything here rides the existing API-session machinery: the agent's
NetBox access is the same structurally GET-only, host-pinned
`propose_api_call` as every other controller (threat model T39). Nothing
about NetBox loosens a gate.

## Adding the session

APIs rail → **New API controller** → Vendor: **NetBox**.

- **Base URL**: your instance root **plus `/api`** — e.g.
  `https://netbox.example/api` (or `https://tools.example/netbox/api` for a
  sub-path install). The base URL is the confinement root: every request,
  human or agent, is pinned under it.
- **Auth**: NetBox has two token forms, and the preset covers the common one:
  - **Classic tokens** (any NetBox version): sent as
    `Authorization: Token <key>`. The preset fills this — API-key scheme,
    header `Authorization`, value prefix `Token ` (the trailing space
    matters; the preset includes it).
  - **v2 tokens** (`nbt_…`, NetBox 4.4+): plain Bearer — switch Auth to
    **Bearer token** and paste the `nbt_…` value.

  Create the token in NetBox under **Profile → API Tokens**. A read-only
  token is the right shape for Transit: the agent can only ever GET, and
  unless you plan to use the human request pane for writes, the token
  doesn't need write permission at all.

## The bundled collection

A curated ~31-request, all-GET collection generated from NetBox's own
OpenAPI schema (`scripts/gen-netbox-collection.mjs` — every path and every
filter parameter is validated against the spec at generation time). Folders:

- **Start here** — `status/`: version + plugins; confirms the token works.
- **Circuits** — list/find circuits (by CID, by site), circuit detail, and
  the outage pivot: **terminations of a circuit** (`?circuit_id=`), plus
  providers.
- **Devices (DCIM)** — list/search devices (by site, role, name, tag, free
  search), device detail (primary IP, platform, site, rack), interfaces of
  a device (each carries its cable + connected endpoint), cable detail,
  device roles, platforms.
- **Sites (DCIM)** — list sites, find by slug, site detail, regions.
- **IPAM** — "who has this IP?" (`?address=`), IPs assigned to a device,
  prefixes (list, containing an IP, at a site), prefix detail, VLANs at a
  site, VRFs.

The collection is a starting point, not an allowlist — the agent (and you)
can request any documented NetBox GET; an unknown path just 404s. Two
entries demonstrate `?fields=` (server-side payload trimming), which is
worth preferring in agent chats to keep responses small.

NetBox paginates: responses carry `count` / `next` / `previous`, and
`?limit=` + `?offset=` walk large result sets.

## Worked example — circuit outage → SSH investigation

The flow regional ISPs run daily, as one chat:

1. Open the NetBox session (APIs rail) and any SSH sessions you already
   have up. Ask the agent: *"Circuit CID-1234 is reporting down. Find the
   impacted devices in NetBox, then check their interface state."*
2. The agent proposes GETs against NetBox — find the circuit
   (`circuits/circuits/?cid=CID-1234`), pull its terminations
   (`circuits/circuit-terminations/?circuit_id=…`), then the devices at the
   terminating site (`dcim/devices/?site_id=…`). Each call is GET-only and
   host-pinned; approve them per-call, or enable **auto-approve GETs** for
   the chat (safe precisely because the tool cannot express anything but a
   read).
3. **Opening SSH sessions to the named devices is yours to do** — the agent
   has no tool that creates a connection, by design. If the devices are in
   your inventory, multi-select them in the sidebar and **Launch all**; the
   agent picks them up on its next `list_open_sessions` and continues with
   gated `propose_command` investigation (interface state, OSPF neighbors,
   logs).
4. If NetBox names a device Transit doesn't know yet, pull it in with
   **Sync from NetBox** (below) — then Launch and continue.

## Syncing your inventory from NetBox

Sidebar → the import icon (or the command palette's "Import connections…")
→ **NetBox**. Pick your NetBox API session and fetch — active devices only,
or all statuses. Transit pages the device list read-only and diffs it
against your inventory on a stable per-device NetBox id (stored as
`netbox_id` in `transit.toml`), then shows three buckets:

- **New** — NetBox devices Transit doesn't know. They land in the standard
  import grid: per-row name/host/vendor/group/auth editing, bulk edits,
  collision handling. The proposed host is the device's primary IP (falling
  back to its name as DNS); NetBox's site becomes the group, its platform
  slug maps to a Transit vendor (unmapped slugs become custom vendors, so
  your BYOP policy file lines up), and NetBox tags plus `role:<slug>` carry
  over. Pick the auth profile these devices use — NetBox holds no device
  credentials, ever, so nothing is imported on that axis.
- **Changed** — matched devices whose NetBox-owned fields drifted (host,
  vendor, group). Each field is a separate accept/skip; your local-only
  settings (colors, fonts, terminal prefs, extra tags) are never touched.
- **Stale** — local devices whose NetBox id vanished from the pull.
  **Keep** (default) leaves them alone, **Unlink** clears the NetBox link,
  **Delete** removes the device from Transit — and any deletes are
  re-confirmed by name before the commit.

One **Apply** commits everything atomically (a failed row writes nothing).
Re-running the sync later diffs instead of duplicating — that's what the
stored id is for. Nothing is ever written to NetBox, there is no scheduled
sync, and the AI agent has no path to any of this (threat model T49).

## A caution about what lives in your NetBox

Some NetBox deployments stash device credentials in custom fields, config
contexts, or the community secrets plugin — against NetBox's own guidance.
Treat NetBox-sourced text like any other controller output: it is data,
not instructions, and it may contain things that shouldn't reach a model.
Transit's redaction filter runs on every API response before the agent
sees it (the same boundary every session's output crosses), but the better
posture is a NetBox token scoped to the DCIM/IPAM/circuits data the
investigation actually needs.

## Version notes

- Generated + verified against **NetBox 4.6** (the schema source is
  recorded in the collection's `generatedFrom` field). The endpoints used
  are stable across NetBox 3.x/4.x.
- Regenerating after a NetBox upgrade:
  `curl -o /tmp/netbox-openapi.json "https://<instance>/api/schema/?format=json"`
  then `node scripts/gen-netbox-collection.mjs /tmp/netbox-openapi.json`.
