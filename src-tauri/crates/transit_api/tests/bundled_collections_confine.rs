//! Every path in every SHIPPED collection must resolve under its controller's
//! API base.
//!
//! This exists because v4.3.0 shipped a Meraki collection whose 163 paths all
//! carried a leading slash while its base URL carried a `/api/v1` prefix. Per
//! RFC 3986 a leading-slash path is an absolute-path reference that REPLACES
//! the base path, so `Url::join` resolved `/organizations` to
//! `https://api.meraki.com/organizations` — outside `/api/v1/` — and
//! [`Endpoint::confine`] refused every single request with `PathEscape`,
//! for the HUMAN send path as well as the agent gate. Nobody noticed because
//! almost every Meraki endpoint also needed an `{{organizationId}}` the
//! collection gave no way to obtain, so the pane's unfilled-token guard
//! blocked Send before anything ever reached `confine`.
//!
//! The invariant is therefore: **a collection path must be relative when its
//! base carries a path prefix, and may be absolute only when the base is at
//! the host root.** UniFi already honours it (its *local* roots are relative,
//! its *cloud* roots absolute under `https://api.ui.com/`); this test makes
//! that structural instead of a convention someone has to remember.
//!
//! It reads the real JSON the app ships (`src/lib/collections/`) and runs the
//! real `confine`, so neither the data nor the rule can drift out from under
//! it. Reading repo data from outside the cargo workspace mirrors how the
//! `transit_policy` corpus tests read `policies/`.

use std::path::PathBuf;

use transit_api::Endpoint;

/// Repo-root-relative directory holding the shipped collection JSON.
fn collections_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/lib/collections")
        .canonicalize()
        .expect("src/lib/collections must exist relative to the transit_api crate")
}

/// Every `path` string in a collection tree, with the request's display name
/// for a legible assertion message.
fn walk(node: &serde_json::Value, out: &mut Vec<(String, String)>) {
    if let Some(obj) = node.as_object() {
        if let (Some(p), m) = (obj.get("path"), obj.get("method")) {
            if m.is_some() {
                out.push((
                    obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unnamed>")
                        .to_string(),
                    p.as_str().unwrap_or_default().to_string(),
                ));
            }
        }
        for key in ["folders", "requests"] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                for child in arr {
                    walk(child, out);
                }
            }
        }
    }
}

fn load(file: &str, roots: &[&str]) -> Vec<(String, String)> {
    let raw = std::fs::read_to_string(collections_dir().join(file))
        .unwrap_or_else(|e| panic!("read {file}: {e}"));
    let json: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {file}: {e}"));
    let mut out = Vec::new();
    for root in roots {
        walk(&json[root], &mut out);
    }
    assert!(!out.is_empty(), "{file}: no requests found under {roots:?}");
    out
}

/// Substitute `{{var}}` / `{placeholder}` tokens the way the pane does before
/// sending. Required: `Url::join` percent-encodes `{`/`}`, and `confine`
/// refuses ANY `%` in a resolved path, so a raw template would fail for that
/// reason rather than the one under test. (The pane's `unfilledTokens` guard
/// exists for exactly this — it blocks Send on an unfilled token so the user
/// never sees a confusing "escapes the API base" error.)
fn substitute(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = match after.find('}') {
            Some(e) => e,
            None => break,
        };
        // consume `{{name}}` or `{name}` wholesale
        let close = after[end..]
            .strip_prefix("}}")
            .map(|_| end + 2)
            .unwrap_or(end + 1);
        out.push_str("SUBST");
        rest = &after[close..];
    }
    out.push_str(rest);
    out
}

fn assert_all_confine(label: &str, endpoint: &Endpoint, requests: &[(String, String)]) {
    let mut failures = Vec::new();
    for (name, path) in requests {
        if let Err(e) = endpoint.confine(&substitute(path)) {
            failures.push(format!("  {path}  ({name}) -> {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{label}: {} of {} bundled paths do NOT confine to the API base.\n{}\n\n\
         A path is relative-or-absolute-sensitive: when the base has a path prefix \
         (e.g. https://api.meraki.com/api/v1), the collection MUST use relative paths \
         (`organizations`), because a leading slash replaces the base path and escapes it.",
        failures.len(),
        requests.len(),
        failures.join("\n"),
    );
}

/// The base each vendor's controller is created with.
///
/// ⚠️ Two entries have teeth (path-prefixed bases, where a leading-slash path
/// escapes):
/// - Meraki must stay in sync with `VENDOR_PRESETS.meraki.base_url` in
///   `src/components/dialogs/AddApiSessionDialog.tsx`
///   (`https://api.meraki.com/api/v1`). Change the preset without changing
///   this and the regression this whole file exists for silently stops being
///   tested.
/// - NetBox has no preset base (self-hosted, operator-supplied) but the
///   dialog placeholder + docs/integrations/netbox.md both steer to
///   `https://<instance>/api`, so the row tests that documented shape.
///
/// The other six take an operator-supplied bare-host base, represented here by
/// a host-root base (the shape the dialog guides toward). Against a host-root
/// base almost any path confines, so those rows only exercise host-escape and
/// the `%`/`;` rules — they are a guard against a future vendor being given a
/// path-prefixed base, not a strong check today.
const GENERIC_VENDORS: &[(&str, &str, &str)] = &[
    (
        "meraki",
        "meraki.generated.json",
        "https://api.meraki.com/api/v1",
    ),
    ("apstra", "apstra.generated.json", "https://apstra.example"),
    ("aruba", "aruba.generated.json", "https://central.example"),
    ("aci", "aci.generated.json", "https://apic.example"),
    ("sdwan", "sdwan.generated.json", "https://vmanage.example"),
    (
        "fortimanager",
        "fortimanager.generated.json",
        "https://fmg.example",
    ),
    (
        "fortianalyzer",
        "fortianalyzer.generated.json",
        "https://faz.example",
    ),
    (
        "netbox",
        "netbox.generated.json",
        "https://netbox.example/api",
    ),
];

#[test]
fn every_bundled_vendor_path_confines_to_its_base() {
    for (vendor, file, base) in GENERIC_VENDORS {
        let endpoint = Endpoint::generic(base).expect("valid base URL");
        assert_all_confine(vendor, &endpoint, &load(file, &["root"]));
    }
}

#[test]
fn every_unifi_path_confines_on_both_surfaces() {
    // UniFi's two roots pair with two different bases: the cloud root is
    // absolute under the Site Manager host root, the local root is relative
    // under the `/proxy/network/integration/v1/` prefix. Each must confine
    // against ITS base — that pairing is the invariant Meraki broke.
    let cloud = Endpoint::site_manager();
    let local = Endpoint::network_local("192.168.1.1").expect("valid host");
    for file in ["unifiNetwork.generated.json", "unifiProtect.generated.json"] {
        assert_all_confine(&format!("{file} (cloud)"), &cloud, &load(file, &["cloud"]));
        assert_all_confine(&format!("{file} (local)"), &local, &load(file, &["local"]));
    }
}

#[test]
fn netbox_paths_are_relative_because_its_base_has_a_prefix() {
    // Same shape-pin as Meraki's below: NetBox's documented base carries the
    // `/api` prefix, so a regeneration that emits absolute paths must fail
    // with a message naming the cause rather than 31 confine errors.
    let leading: Vec<String> = load("netbox.generated.json", &["root"])
        .into_iter()
        .map(|(_, p)| p)
        .filter(|p| p.starts_with('/'))
        .collect();
    assert!(
        leading.is_empty(),
        "NetBox's base URL carries the `/api` prefix, so its collection paths must be \
         RELATIVE. {} path(s) start with `/` and would be refused as PathEscape, e.g. {:?}",
        leading.len(),
        &leading[..leading.len().min(3)],
    );
}

#[test]
fn netbox_query_templates_confine_with_query_strings_intact() {
    // The NetBox collection is the first bundled one whose paths carry query
    // strings (`dcim/devices/?site_id={{siteId}}`). `confine` checks the PATH
    // component only (query strings are exempt from the `%`/`;` rules), so a
    // templated query must never be the thing that fails confinement — pinned
    // here against a future confine change quietly breaking every filtered
    // variant.
    let endpoint = Endpoint::generic("https://netbox.example/api").expect("valid base");
    let with_query: Vec<(String, String)> = load("netbox.generated.json", &["root"])
        .into_iter()
        .filter(|(_, p)| p.contains('?'))
        .collect();
    assert!(
        !with_query.is_empty(),
        "expected filtered query-string variants in the NetBox collection"
    );
    assert_all_confine("netbox (query variants)", &endpoint, &with_query);
}

#[test]
fn meraki_paths_are_relative_because_its_base_has_a_prefix() {
    // The specific regression, pinned by shape as well as by behaviour: if
    // someone regenerates the Meraki collection with absolute paths, this
    // fails with a message naming the cause rather than 167 confine errors.
    let leading: Vec<String> = load("meraki.generated.json", &["root"])
        .into_iter()
        .map(|(_, p)| p)
        .filter(|p| p.starts_with('/'))
        .collect();
    assert!(
        leading.is_empty(),
        "Meraki's base URL carries the `/api/v1` prefix, so its collection paths must be \
         RELATIVE. {} path(s) start with `/` and would be refused as PathEscape, e.g. {:?}",
        leading.len(),
        &leading[..leading.len().min(3)],
    );
}
