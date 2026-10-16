//! NetBox inventory sync — parse + diff (v6.2.0, Part B of
//! the netbox integration design notes (not included in this repository)).
//!
//! **Pure**: no HTTP, no Tauri. The command layer pages
//! `GET /api/dcim/devices/` through the confined `transit_api` client and
//! hands the raw JSON pages here; this module parses them into
//! [`NetBoxDevice`]s and diffs those against the local inventory on the
//! stable match key `Device::netbox_id`.
//!
//! **Rule 1:** NetBox is a CMDB, not a credential store — nothing here
//! carries or requests a secret. Candidates name an auth PROFILE chosen by
//! the human in the grid.
//!
//! Diff doctrine (matches the mutator's preserve-over-overwrite stance):
//! - **New** — in the pull, no local device carries the id → offered.
//! - **Changed** — id matched; `host` / vendor / `group` differ →
//!   per-field accept/skip. Cosmetic local edits the pull can't see
//!   (color, fonts, terminal prefs, extra tags) are never touched.
//! - **Stale** — a local `netbox_id` absent from the pull → flagged;
//!   Keep is the default, Unlink and Delete are explicit per-row opt-ins.
//! - Nothing is ever written here — the caller commits decisions through
//!   the inventory mutator, atomically.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::inventory::Device;

use super::sanitize_id;

/// One device as pulled from NetBox — only the fields the sync consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct NetBoxDevice {
    /// NetBox's primary key, stringified (opaque to Transit; see
    /// [`Device::netbox_id`]).
    pub id: String,
    /// Device name; NetBox allows unnamed devices (null).
    pub name: Option<String>,
    /// `status.value` — `active`, `offline`, `planned`, … Surfaced in the
    /// grid so a human can skip non-active rows; never filtered here.
    pub status: String,
    /// Site display name → proposed `Device::group`.
    pub site_name: Option<String>,
    /// Device-role slug → proposed `role:<slug>` tag.
    pub role_slug: Option<String>,
    /// Platform slug → proposed vendor tag via [`vendor_tag_for_platform`].
    pub platform_slug: Option<String>,
    /// Primary IP (v4 preferred, else v6), CIDR suffix stripped.
    pub primary_ip: Option<String>,
    /// NetBox tag slugs.
    pub tags: Vec<String>,
}

/// Parse the JSON pages of a paginated `dcim/devices/` pull. Accepts the
/// standard `{count, next, previous, results: […]}` envelope (and, for
/// resilience, a bare array). Malformed entries are skipped with a
/// warning, never fatal — one odd device must not kill a 5,000-device
/// sync.
pub fn parse_devices(pages: &[Value]) -> (Vec<NetBoxDevice>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (page_idx, page) in pages.iter().enumerate() {
        let results = match (
            page.get("results").and_then(Value::as_array),
            page.as_array(),
        ) {
            (Some(r), _) => r,
            (None, Some(bare)) => bare,
            (None, None) => {
                warnings.push(format!(
                    "page {}: not a NetBox device list (no `results` array)",
                    page_idx + 1
                ));
                continue;
            }
        };
        for entry in results {
            match parse_device(entry) {
                Some(d) => out.push(d),
                None => warnings.push(format!(
                    "page {}: skipped a device entry with no usable id",
                    page_idx + 1
                )),
            }
        }
    }
    (out, warnings)
}

fn parse_device(v: &Value) -> Option<NetBoxDevice> {
    // The spec types `id` as an integer; tolerate a string for forward
    // compatibility (the field is opaque to Transit either way).
    let id = match v.get("id") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return None,
    };
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let status = v
        .pointer("/status/value")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let site_name = v
        .pointer("/site/name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let role_slug = v
        .pointer("/role/slug")
        .and_then(Value::as_str)
        .map(String::from);
    let platform_slug = v
        .pointer("/platform/slug")
        .and_then(Value::as_str)
        .map(String::from);
    let primary_ip = v
        .pointer("/primary_ip4/address")
        .and_then(Value::as_str)
        .or_else(|| v.pointer("/primary_ip6/address").and_then(Value::as_str))
        .map(strip_cidr)
        .map(String::from);
    let tags = v
        .get("tags")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("slug").and_then(Value::as_str))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    Some(NetBoxDevice {
        id,
        name,
        status,
        site_name,
        role_slug,
        platform_slug,
        primary_ip,
        tags,
    })
}

/// `192.0.2.1/24` → `192.0.2.1` (NetBox stores primary IPs with their
/// prefix length; an SSH host wants the bare address).
fn strip_cidr(addr: &str) -> &str {
    addr.split('/').next().unwrap_or(addr)
}

/// Map a NetBox platform slug onto a Transit vendor TAG (the string the
/// grid edits and `Vendor::from_tag` consumes). Covers the common
/// community slug conventions; anything unmapped is SANITIZED to the
/// canonical custom-vendor charset (`^[a-z0-9_]+$`, the frontend's
/// `CUSTOM_VENDOR_PATTERN`) and becomes `Vendor::Custom` — name your BYOP
/// `<tag>.yaml` after the sanitized form (`ios-xr-old` → `ios_xr_old`).
/// The per-command modal stays mandatory for customs either way (Rule 3's
/// carve-out). No platform at all → `unknown`.
///
/// Sanitizing here (not just in the grid) matters adversarially: the
/// Changed bucket writes vendor updates without passing the New-row grid
/// validation, and a hostile NetBox chooses its platform slugs (T49) —
/// NetBox's own slug charset is not a contract Transit can lean on.
pub fn vendor_tag_for_platform(slug: Option<&str>) -> String {
    let Some(raw) = slug else {
        return "unknown".to_string();
    };
    let norm = raw.trim().to_ascii_lowercase().replace('-', "_");
    let tag = match norm.as_str() {
        "ios" | "cisco_ios" => "cisco_ios",
        "iosxe" | "ios_xe" | "cisco_iosxe" | "cisco_ios_xe" => "cisco_ios_xe",
        "iosxr" | "ios_xr" | "cisco_iosxr" | "cisco_ios_xr" => "cisco_ios_xr",
        "nxos" | "nx_os" | "cisco_nxos" | "cisco_nx_os" => "nxos",
        "junos" | "juniper_junos" => "junos",
        "eos" | "arista_eos" => "arista_eos",
        "panos" | "pan_os" | "paloalto_panos" | "paloalto_pan_os" => "pan_os",
        "unifi" | "ubiquiti_unifi" => "unifi",
        "linux" => "linux",
        _ => return sanitize_vendor_tag(&norm),
    };
    tag.to_string()
}

/// Collapse an arbitrary (attacker-chosen, T49) platform slug onto the
/// canonical custom-vendor charset `^[a-z0-9_]+$`: runs of anything else
/// become one `_`, leading/trailing `_` trimmed, empty → `unknown`.
fn sanitize_vendor_tag(norm: &str) -> String {
    let mut out = String::with_capacity(norm.len());
    let mut prev_us = false;
    for ch in norm.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' {
            prev_us = ch == '_';
            out.push(ch);
        } else if !out.is_empty() && !prev_us {
            out.push('_');
            prev_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// A "New" row — a NetBox device with no local counterpart, mapped to an
/// importable proposal. Every field is editable in the grid before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct NetBoxCandidate {
    pub netbox_id: String,
    /// `sanitize_id(name, host)` — the command layer owns collision
    /// handling against the live inventory (the `preview_import` pattern).
    pub proposed_device_id: String,
    /// Derived host: primary IP, else the device name as a DNS name.
    pub host: String,
    /// Display name (falls back to the host).
    pub name: String,
    pub status: String,
    pub vendor_tag: String,
    /// Site name → proposed group path.
    pub group: Option<String>,
    /// NetBox tag slugs + `role:<slug>`.
    pub tags: Vec<String>,
}

/// One field-level difference on a matched device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct FieldChange {
    /// `host` | `vendor` | `group`.
    pub field: &'static str,
    pub current: String,
    pub incoming: String,
}

/// A matched device whose NetBox-owned fields drifted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct NetBoxChange {
    pub device_id: String,
    pub netbox_id: String,
    pub changes: Vec<FieldChange>,
}

/// A local device whose `netbox_id` no longer appears in the pull.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct NetBoxStale {
    pub device_id: String,
    pub netbox_id: String,
    pub host: String,
}

/// The computed sync preview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct NetBoxDiff {
    pub new: Vec<NetBoxCandidate>,
    pub changed: Vec<NetBoxChange>,
    pub stale: Vec<NetBoxStale>,
    /// Matched devices with nothing to do (count only — no rows rendered).
    pub unchanged: usize,
    /// Remote devices that cannot become sessions (no primary IP and no
    /// usable name) — surfaced so "covered everything" is never implied.
    pub skipped: Vec<String>,
}

/// Diff the local inventory against a NetBox pull. Pure; first-seen order
/// preserved within each bucket.
pub fn diff(local: &[Device], remote: &[NetBoxDevice]) -> NetBoxDiff {
    let by_netbox_id: HashMap<&str, &Device> = local
        .iter()
        .filter_map(|d| d.netbox_id.as_deref().map(|id| (id, d)))
        .collect();
    let remote_ids: HashSet<&str> = remote.iter().map(|r| r.id.as_str()).collect();

    let mut out = NetBoxDiff::default();

    for r in remote {
        match by_netbox_id.get(r.id.as_str()) {
            Some(existing) => match diff_one(existing, r) {
                Some(change) => out.changed.push(change),
                None => out.unchanged += 1,
            },
            None => match candidate_for(r) {
                Some(c) => out.new.push(c),
                None => out.skipped.push(format!(
                    "NetBox device {} ({}) has no primary IP and no usable name — nothing to \
                     connect to",
                    r.id,
                    r.name.as_deref().unwrap_or("unnamed")
                )),
            },
        }
    }

    for d in local {
        if let Some(nb) = d.netbox_id.as_deref() {
            if !remote_ids.contains(nb) {
                out.stale.push(NetBoxStale {
                    device_id: d.id.clone(),
                    netbox_id: nb.to_string(),
                    host: d.host.clone(),
                });
            }
        }
    }

    out
}

/// Host for a remote device: primary IP first, else the (whitespace-free)
/// name as a DNS name. `None` = unimportable.
fn derive_host(r: &NetBoxDevice) -> Option<String> {
    if let Some(ip) = &r.primary_ip {
        return Some(ip.clone());
    }
    r.name
        .as_deref()
        .filter(|n| !n.contains(char::is_whitespace))
        .map(String::from)
}

fn candidate_for(r: &NetBoxDevice) -> Option<NetBoxCandidate> {
    let host = derive_host(r)?;
    let name = r.name.clone().unwrap_or_else(|| host.clone());
    let mut tags = r.tags.clone();
    if let Some(role) = &r.role_slug {
        tags.push(format!("role:{role}"));
    }
    Some(NetBoxCandidate {
        netbox_id: r.id.clone(),
        proposed_device_id: sanitize_id(&name, &host),
        host,
        name,
        status: r.status.clone(),
        vendor_tag: vendor_tag_for_platform(r.platform_slug.as_deref()),
        group: r.site_name.clone(),
        tags,
    })
}

/// Field-level compare for a matched pair. Only NetBox-owned fields are
/// compared; a field the pull can't derive (no primary IP → no host
/// opinion, no platform → no vendor opinion) is left alone rather than
/// churned.
fn diff_one(local: &Device, remote: &NetBoxDevice) -> Option<NetBoxChange> {
    let mut changes = Vec::new();

    if let Some(host) = derive_host(remote) {
        if host != local.host {
            changes.push(FieldChange {
                field: "host",
                current: local.host.clone(),
                incoming: host,
            });
        }
    }

    if remote.platform_slug.is_some() {
        let incoming = vendor_tag_for_platform(remote.platform_slug.as_deref());
        let current = local.vendor.as_str().to_string();
        if incoming != current {
            changes.push(FieldChange {
                field: "vendor",
                current,
                incoming,
            });
        }
    }

    if let Some(site) = &remote.site_name {
        if local.group.as_deref() != Some(site.as_str()) {
            changes.push(FieldChange {
                field: "group",
                current: local.group.clone().unwrap_or_default(),
                incoming: site.clone(),
            });
        }
    }

    if changes.is_empty() {
        None
    } else {
        Some(NetBoxChange {
            device_id: local.id.clone(),
            netbox_id: remote.id.clone(),
            changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Vendor;
    use serde_json::json;

    /// A realistic envelope page in the NetBox 4.x response shape
    /// (`Brief*` nested objects, CIDR'd primary IPs, `{value,label}`
    /// status) — field shapes verified against a live 4.6.8 instance's
    /// OpenAPI schema.
    fn page(results: Vec<Value>) -> Value {
        json!({ "count": results.len(), "next": null, "previous": null, "results": results })
    }

    fn nb_device(id: u64, name: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "status": { "value": "active", "label": "Active" },
            "site": { "id": 1, "name": "Springfield HQ", "slug": "springfield-hq" },
            "role": { "id": 2, "name": "Access Switch", "slug": "access-switch" },
            "platform": { "id": 3, "name": "Juniper Junos", "slug": "junos" },
            "primary_ip4": { "id": 7, "address": "10.140.0.11/24", "family": 4 },
            "primary_ip6": null,
            "tags": [ { "id": 9, "name": "Lab", "slug": "lab" } ]
        })
    }

    fn local_device(id: &str, host: &str, netbox_id: Option<&str>) -> Device {
        Device {
            id: id.to_string(),
            host: host.to_string(),
            port: 22,
            vendor: Vendor::Junos,
            group: Some("Springfield HQ".to_string()),
            color: None,
            tags: Vec::new(),
            auth: "lab".to_string(),
            syntax_highlighting: None,
            quick_copy_paste: None,
            font_family: None,
            font_size: None,
            bold_color: None,
            allow_weak_crypto: None,
            netbox_id: netbox_id.map(String::from),
            jump_via: None,
            forward_agent: None,
        }
    }

    #[test]
    fn parse_devices_reads_the_envelope_and_nested_shapes() {
        let (devs, warnings) = parse_devices(&[page(vec![nb_device(11, "vEX1")])]);
        assert!(warnings.is_empty());
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.id, "11");
        assert_eq!(d.name.as_deref(), Some("vEX1"));
        assert_eq!(d.status, "active");
        assert_eq!(d.site_name.as_deref(), Some("Springfield HQ"));
        assert_eq!(d.role_slug.as_deref(), Some("access-switch"));
        assert_eq!(d.platform_slug.as_deref(), Some("junos"));
        assert_eq!(d.primary_ip.as_deref(), Some("10.140.0.11"));
        assert_eq!(d.tags, vec!["lab".to_string()]);
    }

    #[test]
    fn parse_devices_tolerates_nulls_and_junk_without_dying() {
        let mut no_platform = nb_device(12, "sw2");
        no_platform["platform"] = Value::Null;
        no_platform["primary_ip4"] = Value::Null;
        no_platform["primary_ip6"] = json!({ "id": 8, "address": "2001:db8::11/64", "family": 6 });
        let unnamed = json!({ "id": 13, "name": null, "status": { "value": "planned" } });
        let junk = json!({ "name": "no id at all" });

        let (devs, warnings) = parse_devices(&[page(vec![no_platform, unnamed, junk])]);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].platform_slug, None);
        assert_eq!(devs[0].primary_ip.as_deref(), Some("2001:db8::11"));
        assert_eq!(devs[1].name, None);
        assert_eq!(devs[1].status, "planned");
        assert_eq!(warnings.len(), 1, "the id-less entry warns: {warnings:?}");

        // A non-envelope page warns rather than panicking.
        let (none, w2) = parse_devices(&[json!({"detail": "Invalid token"})]);
        assert!(none.is_empty());
        assert_eq!(w2.len(), 1);
    }

    #[test]
    fn vendor_map_covers_common_slugs_and_sanitizes_the_fallback() {
        for (slug, want) in [
            ("ios", "cisco_ios"),
            ("ios-xe", "cisco_ios_xe"),
            ("iosxr", "cisco_ios_xr"),
            ("nx-os", "nxos"),
            ("junos", "junos"),
            ("eos", "arista_eos"),
            ("panos", "pan_os"),
            ("linux", "linux"),
        ] {
            assert_eq!(vendor_tag_for_platform(Some(slug)), want, "{slug}");
        }
        assert_eq!(vendor_tag_for_platform(None), "unknown");
        // Unmapped slugs land on the canonical custom-vendor charset
        // (^[a-z0-9_]+$ — the frontend's CUSTOM_VENDOR_PATTERN), never
        // verbatim: the Changed bucket writes vendor without the New-row
        // grid validation, and a hostile NetBox picks its own slugs (T49).
        assert_eq!(vendor_tag_for_platform(Some("routeros")), "routeros");
        assert_eq!(vendor_tag_for_platform(Some("routeros-v7")), "routeros_v7");
        assert_eq!(vendor_tag_for_platform(Some("Vyatta-VyOS")), "vyatta_vyos");
        assert_eq!(
            vendor_tag_for_platform(Some("weird slug! 🚀 /../etc")),
            "weird_slug_etc"
        );
        assert_eq!(vendor_tag_for_platform(Some("🚀🚀")), "unknown");
        assert_eq!(vendor_tag_for_platform(Some("  ")), "unknown");
    }

    #[test]
    fn diff_buckets_new_changed_stale_unchanged_and_skipped() {
        // Local: 20 matches remote-20 exactly; 21 drifted; 99 is stale;
        // "hand" has no netbox_id and must be ignored entirely.
        let locals = vec![
            local_device("vEX1", "10.140.0.11", Some("20")),
            local_device("vEX2", "10.140.0.12", Some("21")),
            local_device("old-box", "10.9.9.9", Some("99")),
            local_device("hand-added", "192.168.1.1", None),
        ];

        let r20 = {
            let mut v = nb_device(20, "vEX1");
            v["primary_ip4"]["address"] = json!("10.140.0.11/24");
            v
        };
        // 21: host moved + platform now EOS + site renamed.
        let r21 = {
            let mut v = nb_device(21, "vEX2");
            v["primary_ip4"]["address"] = json!("10.140.0.99/24");
            v["platform"]["slug"] = json!("eos");
            v["site"]["name"] = json!("Riverside POP");
            v
        };
        // 30: brand new, importable.
        let r30 = nb_device(30, "vQFX1");
        // 31: unimportable (no IP, whitespace name).
        let r31 = json!({
            "id": 31, "name": "core router (planned)",
            "status": { "value": "planned" },
            "primary_ip4": null, "primary_ip6": null
        });

        let (remote, _) = parse_devices(&[page(vec![r20, r21, r30, r31])]);
        let d = diff(&locals, &remote);

        assert_eq!(d.unchanged, 1);

        assert_eq!(d.new.len(), 1);
        let c = &d.new[0];
        assert_eq!(c.netbox_id, "30");
        assert_eq!(c.proposed_device_id, "vQFX1");
        assert_eq!(c.host, "10.140.0.11");
        assert_eq!(c.vendor_tag, "junos");
        assert_eq!(c.group.as_deref(), Some("Springfield HQ"));
        assert_eq!(
            c.tags,
            vec!["lab".to_string(), "role:access-switch".to_string()]
        );

        assert_eq!(d.changed.len(), 1);
        let ch = &d.changed[0];
        assert_eq!(ch.device_id, "vEX2");
        let fields: Vec<&str> = ch.changes.iter().map(|c| c.field).collect();
        assert_eq!(fields, vec!["host", "vendor", "group"]);
        assert_eq!(ch.changes[0].incoming, "10.140.0.99");
        assert_eq!(ch.changes[1].current, "junos");
        assert_eq!(ch.changes[1].incoming, "arista_eos");

        assert_eq!(d.stale.len(), 1);
        assert_eq!(d.stale[0].device_id, "old-box");
        assert_eq!(d.stale[0].netbox_id, "99");

        assert_eq!(d.skipped.len(), 1);
        assert!(d.skipped[0].contains("31"));
    }

    #[test]
    fn diff_without_an_opinion_leaves_the_field_alone() {
        // Remote has NO primary IP and NO platform: the name still derives
        // a host (it's whitespace-free), but a missing platform must not
        // churn vendor toward unknown/custom.
        let locals = vec![local_device("vEX1", "10.140.0.11", Some("20"))];
        let r = json!({
            "id": 20, "name": "vEX1",
            "status": { "value": "active" },
            "site": { "id": 1, "name": "Springfield HQ", "slug": "springfield-hq" },
            "platform": null, "primary_ip4": null, "primary_ip6": null
        });
        let (remote, _) = parse_devices(&[page(vec![r])]);
        let d = diff(&locals, &remote);
        // Name-derived host "vEX1" differs from the IP → that IS a real
        // opinion and surfaces; vendor does not.
        assert_eq!(d.changed.len(), 1);
        let fields: Vec<&str> = d.changed[0].changes.iter().map(|c| c.field).collect();
        assert_eq!(fields, vec!["host"]);
    }

    #[test]
    fn unnamed_candidate_falls_back_to_host_for_name_and_id() {
        let r = json!({
            "id": 40, "name": null,
            "status": { "value": "active" },
            "primary_ip4": { "address": "10.0.0.40/32" }
        });
        let (remote, _) = parse_devices(&[page(vec![r])]);
        let d = diff(&[], &remote);
        assert_eq!(d.new.len(), 1);
        assert_eq!(d.new[0].name, "10.0.0.40");
        assert_eq!(d.new[0].proposed_device_id, "10-0-0-40");
    }
}
