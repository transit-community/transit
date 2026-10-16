//! In-place inventory mutation that preserves comments, ordering, and
//! whitespace via `toml_edit::DocumentMut`.
//!
//! Each public mutator function operates on `&mut DocumentMut`. After
//! the structural edit, the result is serialized and re-parsed through
//! the same validation chain `load()` uses (inline-secret prescan +
//! TOML parse + cross-validation). A mutation that would produce a
//! file the loader would reject returns the corresponding
//! [`InventoryError`] without leaving the document in an inconsistent
//! state — the bad edit IS visible on the in-memory document, so the
//! caller MUST treat the error as a signal to discard or reload the
//! document rather than persist it.
//!
//! Atomic write helper [`write_atomic`] performs `tempfile + rename`
//! into the same parent directory so a crash mid-write can never leave
//! a half-written `transit.toml` on disk.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;
use toml_edit::{value, Array, ArrayOfTables, InlineTable, Item, Table, Value};

pub use toml_edit::DocumentMut;

use super::errors::InventoryError;
use super::loader::parse_and_validate;
use super::types::{ApiSession, AuthProfile, AuthScheme, Device, SecretRef};

/// Sentinel path used in error messages produced by mutator-side
/// validation. Real on-disk path is attached by the caller layer
/// (commands.rs) when the error is surfaced to the user.
fn doc_path() -> PathBuf {
    PathBuf::from("<inventory>")
}

// ---------------------------------------------------------------------
// Device operations.
// ---------------------------------------------------------------------

/// Append a new `[[device]]` entry. Returns
/// [`InventoryError::DeviceIdConflict`] if `device.id` is already
/// present and [`InventoryError::UnknownAuth`] if `device.auth` does
/// not name an existing auth profile.
pub fn add_device(doc: &mut DocumentMut, device: &Device) -> Result<(), InventoryError> {
    add_device_no_revalidate(doc, device)?;
    revalidate(doc)
}

/// Structural half of [`add_device`]: shape guard + id-conflict +
/// auth-ref checks + append, WITHOUT the trailing [`revalidate`].
///
/// The batch import path (`import_connections` in `transit_app`) calls
/// this for every device and runs a single [`revalidate`] at the end, so
/// a 100-device import re-serializes the whole document once rather than
/// once per device (O(n²) → O(n)). The eager conflict/auth checks stay
/// here, so an in-batch duplicate id or a device referencing a
/// not-yet-added profile still fails fast at insert time. Single-device
/// callers MUST use [`add_device`] (which revalidates).
pub fn add_device_no_revalidate(
    doc: &mut DocumentMut,
    device: &Device,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    if find_device_index(doc, &device.id).is_some() {
        return Err(InventoryError::DeviceIdConflict {
            id: device.id.clone(),
        });
    }
    if !auth_profile_exists(doc, &device.auth) {
        return Err(InventoryError::UnknownAuth {
            id: device.id.clone(),
            auth: device.auth.clone(),
        });
    }
    // Self-jump is intrinsically wrong, so it fails fast here. A
    // DANGLING `jump_via` is deliberately NOT checked eagerly: batch
    // callers legitimately add a device before its jump target lands
    // (import order isn't topological), and the trailing `revalidate`
    // enforces resolution with the same `UnknownJumpHost` error.
    if device.jump_via.as_deref() == Some(device.id.as_str()) {
        return Err(InventoryError::JumpCycle {
            chain: vec![device.id.clone(), device.id.clone()],
        });
    }
    let array = device_array_mut(doc)?;
    array.push(build_device_table(device));
    Ok(())
}

/// Replace the device with id `id` with `new`. The id may itself
/// change (the entry is found by `id` and rewritten with `new.id`).
/// Errors if no device matches `id`, if the new id collides with a
/// different existing device, or if the new auth ref does not exist.
pub fn update_device(doc: &mut DocumentMut, id: &str, new: &Device) -> Result<(), InventoryError> {
    // Rename guard (v6.5.0): changing the id of a device that others
    // jump through would silently dangle their `jump_via`. Refuse with
    // the referent list. Only here, not in the `_no_revalidate` batch
    // half — a batch may legitimately rewrite referrers in the same
    // transaction, and its trailing revalidate still catches any ref
    // left dangling.
    if id != new.id {
        let referents = jump_referents(doc, id);
        if !referents.is_empty() {
            return Err(InventoryError::JumpHostInUse {
                id: id.to_string(),
                devices: referents,
            });
        }
    }
    update_device_no_revalidate(doc, id, new)?;
    revalidate(doc)
}

/// Structural half of [`update_device`]: shape guard + lookup +
/// id-collision + auth-ref checks + rewrite, WITHOUT the trailing
/// [`revalidate`]. For batch callers (NetBox sync's "Changed"/"Unlink"
/// buckets, v6.2.0) that apply many edits and revalidate once — same
/// O(n²) → O(n) rationale as [`add_device_no_revalidate`]. Single-device
/// callers MUST use [`update_device`] (which revalidates).
pub fn update_device_no_revalidate(
    doc: &mut DocumentMut,
    id: &str,
    new: &Device,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let target_idx = find_device_index(doc, id)
        .ok_or_else(|| InventoryError::DeviceNotFound { id: id.to_string() })?;

    if id != new.id {
        if let Some(other_idx) = find_device_index(doc, &new.id) {
            if other_idx != target_idx {
                return Err(InventoryError::DeviceIdConflict { id: new.id.clone() });
            }
        }
    }

    if !auth_profile_exists(doc, &new.auth) {
        return Err(InventoryError::UnknownAuth {
            id: new.id.clone(),
            auth: new.auth.clone(),
        });
    }

    // Same fail-fast/deferred split as `add_device_no_revalidate`:
    // self-jump refused eagerly, dangling refs left to `revalidate`.
    if new.jump_via.as_deref() == Some(new.id.as_str()) {
        return Err(InventoryError::JumpCycle {
            chain: vec![new.id.clone(), new.id.clone()],
        });
    }

    let array = device_array_mut(doc)?;
    *array.get_mut(target_idx).expect("checked above") = build_device_table(new);
    Ok(())
}

/// Remove the device with id `id`. Errors if no device matches, or
/// (v6.5.0) with [`InventoryError::JumpHostInUse`] if other devices
/// still jump through it — refuse-don't-cascade, listing the referents.
pub fn delete_device(doc: &mut DocumentMut, id: &str) -> Result<(), InventoryError> {
    let referents = jump_referents(doc, id);
    if !referents.is_empty() {
        return Err(InventoryError::JumpHostInUse {
            id: id.to_string(),
            devices: referents,
        });
    }
    delete_device_no_revalidate(doc, id)?;
    revalidate(doc)
}

/// Structural half of [`delete_device`], WITHOUT the trailing
/// [`revalidate`] — for the NetBox sync's opt-in Stale deletes (v6.2.0),
/// which batch with adds/updates and revalidate once. Single-device
/// callers MUST use [`delete_device`].
pub fn delete_device_no_revalidate(doc: &mut DocumentMut, id: &str) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let idx = find_device_index(doc, id)
        .ok_or_else(|| InventoryError::DeviceNotFound { id: id.to_string() })?;
    let array = device_array_mut(doc)?;
    array.remove(idx);
    Ok(())
}

// ---------------------------------------------------------------------
// API session operations (v4.0.0).
// ---------------------------------------------------------------------

/// Append a new `[[api_session]]` entry. Errors with
/// [`InventoryError::ApiSessionIdConflict`] if `session.id` already
/// exists.
pub fn add_api_session(doc: &mut DocumentMut, session: &ApiSession) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    if find_api_session_index(doc, &session.id).is_some() {
        return Err(InventoryError::ApiSessionIdConflict {
            id: session.id.clone(),
        });
    }
    let array = api_session_array_mut(doc)?;
    array.push(build_api_session_table(session));
    revalidate(doc)
}

/// Replace the api session with id `id` with `new` (the id may itself
/// change — the entry is found by `id` and rewritten with `new.id`).
/// Errors if no session matches `id`, or if the new id collides with a
/// different existing session.
pub fn update_api_session(
    doc: &mut DocumentMut,
    id: &str,
    new: &ApiSession,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let target_idx = find_api_session_index(doc, id)
        .ok_or_else(|| InventoryError::ApiSessionNotFound { id: id.to_string() })?;
    if id != new.id {
        if let Some(other_idx) = find_api_session_index(doc, &new.id) {
            if other_idx != target_idx {
                return Err(InventoryError::ApiSessionIdConflict { id: new.id.clone() });
            }
        }
    }
    let array = api_session_array_mut(doc)?;
    let target = array.get_mut(target_idx).expect("checked above");
    // Preserve a user-established cert pin across the edit ATOMICALLY — the edit
    // form never carries it, and reading it here (inside the same doc mutation)
    // rather than a separate read-then-write in the command closes a
    // concurrent-trust lost-update found in the v4.3.0 review. The pin is
    // written ONLY by `set_api_session_pin` (the trust flow); an edit just keeps
    // whatever is already there.
    let existing_pin = target
        .get("pinned_cert_sha256")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mut table = build_api_session_table(new);
    match existing_pin {
        Some(pin) => table["pinned_cert_sha256"] = value(pin.as_str()),
        None => {
            table.remove("pinned_cert_sha256");
        }
    }
    *target = table;
    revalidate(doc)
}

/// Remove the api session with id `id`. Errors if none matches.
pub fn delete_api_session(doc: &mut DocumentMut, id: &str) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let idx = find_api_session_index(doc, id)
        .ok_or_else(|| InventoryError::ApiSessionNotFound { id: id.to_string() })?;
    let array = api_session_array_mut(doc)?;
    array.remove(idx);
    revalidate(doc)
}

/// Set (or clear) `pinned_cert_sha256` on an existing api_session, in place —
/// touches ONLY that key, so it can't disturb the rest of the record. Used by
/// the untrusted-cert trust flow (`api_trust_cert`). Errors if no id matches.
pub fn set_api_session_pin(
    doc: &mut DocumentMut,
    id: &str,
    sha256: Option<&str>,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let idx = find_api_session_index(doc, id)
        .ok_or_else(|| InventoryError::ApiSessionNotFound { id: id.to_string() })?;
    let array = api_session_array_mut(doc)?;
    let table = array.get_mut(idx).expect("checked above");
    match sha256 {
        Some(hex) => table["pinned_cert_sha256"] = value(hex),
        None => {
            table.remove("pinned_cert_sha256");
        }
    }
    revalidate(doc)
}

// ---------------------------------------------------------------------
// Auth profile operations.
// ---------------------------------------------------------------------

/// Insert a new `[auth.<name>]` entry. Errors if `name` already exists.
pub fn add_auth_profile(
    doc: &mut DocumentMut,
    name: &str,
    profile: &AuthProfile,
) -> Result<(), InventoryError> {
    add_auth_profile_no_revalidate(doc, name, profile)?;
    revalidate(doc)
}

/// Structural half of [`add_auth_profile`] (no trailing [`revalidate`]).
/// See [`add_device_no_revalidate`] for why the batch import path needs
/// this. Single-profile callers MUST use [`add_auth_profile`].
pub fn add_auth_profile_no_revalidate(
    doc: &mut DocumentMut,
    name: &str,
    profile: &AuthProfile,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    if auth_profile_exists(doc, name) {
        return Err(InventoryError::AuthProfileConflict {
            name: name.to_string(),
        });
    }
    let auth = auth_table_mut(doc)?;
    auth.insert(name, Item::Table(build_auth_profile_table(profile)));
    Ok(())
}

/// Replace the auth profile at `name` with `profile`. Errors if no
/// profile by that name exists.
pub fn update_auth_profile(
    doc: &mut DocumentMut,
    name: &str,
    profile: &AuthProfile,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    if !auth_profile_exists(doc, name) {
        return Err(InventoryError::AuthProfileNotFound {
            name: name.to_string(),
        });
    }
    let auth = auth_table_mut(doc)?;
    auth.insert(name, Item::Table(build_auth_profile_table(profile)));
    revalidate(doc)
}

/// Remove the auth profile at `name`. Errors with
/// [`InventoryError::AuthProfileInUse`] (listing every device that
/// still references it) if any `[[device]]` entry's `auth` field
/// equals `name`. Errors with [`InventoryError::AuthProfileNotFound`]
/// if no profile matches.
pub fn delete_auth_profile(doc: &mut DocumentMut, name: &str) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    if !auth_profile_exists(doc, name) {
        return Err(InventoryError::AuthProfileNotFound {
            name: name.to_string(),
        });
    }

    let referencing: Vec<String> = devices_iter(doc)
        .filter_map(|t| {
            let auth = t.get("auth")?.as_str()?;
            if auth == name {
                Some(t.get("id")?.as_str()?.to_string())
            } else {
                None
            }
        })
        .collect();

    if !referencing.is_empty() {
        return Err(InventoryError::AuthProfileInUse {
            name: name.to_string(),
            devices: referencing,
        });
    }

    let auth = auth_table_mut(doc)?;
    auth.remove(name);
    revalidate(doc)
}

// ---------------------------------------------------------------------
// Group operations.
// ---------------------------------------------------------------------

/// Rename a group path. Every device whose `group` equals `old_path`
/// becomes `new_path`; every device whose `group` starts with
/// `old_path + "/"` gets that prefix swapped. The `groups` registry is
/// rewritten the same way (and de-duped). Other devices are untouched.
/// Empty `new_path` removes the `group` field on matching devices
/// ("ungroup") and drops matching registry entries.
///
/// Renaming into an existing group path is permitted — the resulting
/// file simply has more devices under that path. The caller decides
/// whether to confirm with the user (the UI does; the backend stays
/// permissive so power users editing the file see the same outcome).
pub fn rename_group(
    doc: &mut DocumentMut,
    old_path: &str,
    new_path: &str,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let old = old_path.trim_matches('/');
    if old.is_empty() {
        return Err(InventoryError::InvalidGroupPath {
            path: old_path.to_string(),
        });
    }
    let new = new_path.trim_matches('/');
    rewrite_group_paths(doc, old, new)
}

/// Add a known group path to the `groups` registry so it renders even
/// with no devices ("create an empty group"). Idempotent: a no-op
/// success if the path is already registered OR already implied by a
/// device's `group` (the UI may "create" a group a device already
/// lives in — that must not error). Only the leaf path is stored;
/// `buildTree` on the frontend synthesizes intermediate ancestors.
pub fn add_group(doc: &mut DocumentMut, path: &str) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let canonical = validate_group_path(path)?;
    if group_exists(doc, &canonical) {
        return Ok(());
    }
    let array = groups_array_mut(doc)?;
    array.push(canonical.as_str());
    revalidate(doc)
}

/// Delete a group, reparenting its contents up one level. Devices and
/// registry entries under `path` are rewritten so the deleted segment
/// is collapsed out: `Lab/Junos` → `Lab`, `Lab/Junos/Edge` → `Lab/Edge`.
/// A top-level group is removed entirely (its devices become ungrouped).
/// This is exactly the rename rewrite with `new = parent(path)`, so the
/// group simply disappears and its contents lift to the parent.
pub fn delete_group(doc: &mut DocumentMut, path: &str) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let canonical = validate_group_path(path)?;
    let parent = match canonical.rsplit_once('/') {
        Some((p, _)) => p.to_string(),
        None => String::new(),
    };
    rewrite_group_paths(doc, &canonical, &parent)
}

/// Set (or clear) a single device's `group`. The drop target for
/// drag-and-drop moves. `None`/empty ungroups the device. Errors with
/// [`InventoryError::DeviceNotFound`] if no device matches `id`. Unlike
/// [`update_device`] this is a surgical edit that leaves every other
/// field of the device untouched.
pub fn set_device_group(
    doc: &mut DocumentMut,
    id: &str,
    group: Option<&str>,
) -> Result<(), InventoryError> {
    ensure_editable_shapes(doc)?;
    let idx = find_device_index(doc, id)
        .ok_or_else(|| InventoryError::DeviceNotFound { id: id.to_string() })?;
    let canonical: Option<String> = match group {
        Some(g) if !g.trim_matches('/').is_empty() => Some(validate_group_path(g)?),
        _ => None,
    };
    let array = device_array_mut(doc)?;
    let table = array.get_mut(idx).expect("index checked above");
    match canonical {
        Some(g) => {
            table["group"] = value(g);
        }
        None => {
            table.remove("group");
        }
    }
    revalidate(doc)
}

/// Shared path-rewrite used by [`rename_group`] and [`delete_group`].
/// `old`/`new` are already trimmed (`new` may be empty = ungroup).
/// Rewrites both device `group` fields and the `groups` registry, then
/// revalidates.
fn rewrite_group_paths(doc: &mut DocumentMut, old: &str, new: &str) -> Result<(), InventoryError> {
    let prefix = format!("{old}/");

    let array = device_array_mut(doc)?;
    for table in array.iter_mut() {
        let current = match table.get("group").and_then(|i| i.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let updated: Option<String> = if current == old {
            Some(new.to_string())
        } else {
            current.strip_prefix(&prefix).map(|rest| {
                if new.is_empty() {
                    rest.to_string()
                } else {
                    format!("{new}/{rest}")
                }
            })
        };
        match updated {
            Some(s) if s.is_empty() => {
                table.remove("group");
            }
            Some(s) => {
                table["group"] = value(s);
            }
            None => {}
        }
    }

    rewrite_registry(doc, old, new, &prefix);
    revalidate(doc)
}

/// Apply the same exact/prefix rewrite to the `groups` registry,
/// de-duping (a rename can fold two entries together or onto an
/// existing one) and dropping entries that become empty. Leaves the
/// document untouched when there is no registry. Removes the key
/// entirely if the rewrite empties it (no `groups = []` clutter).
fn rewrite_registry(doc: &mut DocumentMut, old: &str, new: &str, prefix: &str) {
    let existing: Vec<String> = match doc.get("groups").and_then(|i| i.as_array()) {
        Some(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        None => return,
    };
    let mut rewritten: Vec<String> = Vec::new();
    for cur in existing {
        let updated = if cur == old {
            new.to_string()
        } else if let Some(rest) = cur.strip_prefix(prefix) {
            if new.is_empty() {
                rest.to_string()
            } else {
                format!("{new}/{rest}")
            }
        } else {
            cur
        };
        if !updated.is_empty() && !rewritten.contains(&updated) {
            rewritten.push(updated);
        }
    }
    if rewritten.is_empty() {
        doc.remove("groups");
    } else {
        let mut arr = Array::new();
        for s in &rewritten {
            arr.push(s.as_str());
        }
        doc["groups"] = Item::Value(Value::Array(arr));
    }
}

/// Trim surrounding slashes and reject empty paths / empty interior
/// segments (`A//B`). Returns the canonical trimmed path. Used by the
/// group ops that take a user-supplied path (`add_group`,
/// `set_device_group`); `rename_group`/`delete_group` derive their
/// targets internally.
fn validate_group_path(raw: &str) -> Result<String, InventoryError> {
    let trimmed = raw.trim().trim_matches('/').trim();
    if trimmed.is_empty() || trimmed.split('/').any(|seg| seg.trim().is_empty()) {
        return Err(InventoryError::InvalidGroupPath {
            path: raw.to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// True if `path` is already a known group — either in the `groups`
/// registry or implied by some device's `group` (exact match or an
/// ancestor of it).
fn group_exists(doc: &DocumentMut, path: &str) -> bool {
    if let Some(arr) = doc.get("groups").and_then(|i| i.as_array()) {
        if arr.iter().any(|v| v.as_str() == Some(path)) {
            return true;
        }
    }
    let prefix = format!("{path}/");
    devices_iter(doc).any(|t| match t.get("group").and_then(|i| i.as_str()) {
        Some(g) => g == path || g.starts_with(&prefix),
        None => false,
    })
}

/// Get (or insert) the top-level `groups` array. Errors with
/// [`InventoryError::UnsupportedTomlShape`] if `groups` holds a
/// non-array form.
fn groups_array_mut(doc: &mut DocumentMut) -> Result<&mut Array, InventoryError> {
    if !doc.contains_key("groups") {
        doc.insert("groups", Item::Value(Value::Array(Array::new())));
    }
    doc["groups"]
        .as_array_mut()
        .ok_or_else(|| InventoryError::UnsupportedTomlShape {
            key: "groups".to_string(),
        })
}

// ---------------------------------------------------------------------
// Atomic write.
// ---------------------------------------------------------------------

/// Atomically replace `path` with `contents`. Creates the parent
/// directory if missing. Implementation: write to a sibling tempfile,
/// fsync, then rename — the rename is atomic on every supported OS so
/// readers never see a partial file.
pub fn write_atomic(path: &Path, contents: &str) -> Result<(), InventoryError> {
    let parent = path.parent().ok_or_else(|| InventoryError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inventory path has no parent directory",
        ),
    })?;

    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|source| InventoryError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut tmp = NamedTempFile::new_in(parent).map_err(|source| InventoryError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    tmp.write_all(contents.as_bytes())
        .map_err(|source| InventoryError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| InventoryError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
    tmp.persist(path).map_err(|e| InventoryError::Io {
        path: path.to_path_buf(),
        source: e.error,
    })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------

/// Re-parse the document as a string and run the loader's validation
/// chain. Returns the structural error if the edit produced something
/// the loader would reject.
///
/// Public so the batch import path can run ONE validation pass after a
/// run of `*_no_revalidate` inserts (see [`add_device_no_revalidate`]).
pub fn revalidate(doc: &DocumentMut) -> Result<(), InventoryError> {
    let serialized = doc.to_string();
    parse_and_validate(&serialized, &doc_path()).map(|_| ())
}

/// Verify the top-level `device` / `auth` keys (when present) use the
/// standard `[[device]]` array-of-tables / `[auth.<name>]` table
/// syntax. The loader's `toml::from_str` also accepts the inline forms
/// `device = [{ ... }]` and `auth = { name = { ... } }`, but `toml_edit`
/// parses those as plain `Item::Value`s the structural editors here
/// cannot see — `find_device_index` / `auth_profile_exists` would
/// report zero entries and the `*_mut` accessors would panic. Every
/// mutator op calls this first so a loader-valid-but-inline file is
/// refused up front with a fix-it-by-hand error instead of panicking
/// or mis-reporting (`DeviceNotFound` for a device that exists).
fn ensure_editable_shapes(doc: &DocumentMut) -> Result<(), InventoryError> {
    if let Some(item) = doc.get("device") {
        if !item.is_none() && item.as_array_of_tables().is_none() {
            return Err(InventoryError::UnsupportedTomlShape {
                key: "device".to_string(),
            });
        }
    }
    if let Some(item) = doc.get("auth") {
        if !item.is_none() && item.as_table().is_none() {
            return Err(InventoryError::UnsupportedTomlShape {
                key: "auth".to_string(),
            });
        }
    }
    if let Some(item) = doc.get("groups") {
        if !item.is_none() && item.as_array().is_none() {
            return Err(InventoryError::UnsupportedTomlShape {
                key: "groups".to_string(),
            });
        }
    }
    if let Some(item) = doc.get("api_session") {
        if !item.is_none() && item.as_array_of_tables().is_none() {
            return Err(InventoryError::UnsupportedTomlShape {
                key: "api_session".to_string(),
            });
        }
    }
    Ok(())
}

/// Get (or insert) the `[[device]]` array of tables. Errors with
/// [`InventoryError::UnsupportedTomlShape`] if the key holds an inline
/// form (`device = [{ ... }]`) the editor cannot mutate in place.
fn device_array_mut(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables, InventoryError> {
    if !doc.contains_key("device") {
        doc.insert("device", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["device"]
        .as_array_of_tables_mut()
        .ok_or_else(|| InventoryError::UnsupportedTomlShape {
            key: "device".to_string(),
        })
}

/// Get (or insert) the top-level `[auth]` table. Errors with
/// [`InventoryError::UnsupportedTomlShape`] if the key holds an inline
/// form (`auth = { name = { ... } }`) the editor cannot mutate in place.
fn auth_table_mut(doc: &mut DocumentMut) -> Result<&mut Table, InventoryError> {
    if !doc.contains_key("auth") {
        let mut t = Table::new();
        // `[auth.<name>]` headers require the parent to be implicit.
        t.set_implicit(true);
        doc.insert("auth", Item::Table(t));
    }
    doc["auth"]
        .as_table_mut()
        .ok_or_else(|| InventoryError::UnsupportedTomlShape {
            key: "auth".to_string(),
        })
}

/// Linear scan over `[[device]]` entries by id. Returns the array index.
fn find_device_index(doc: &DocumentMut, id: &str) -> Option<usize> {
    doc.get("device")?
        .as_array_of_tables()?
        .iter()
        .position(|t| t.get("id").and_then(|i| i.as_str()) == Some(id))
}

/// True if `[auth.<name>]` is present.
fn auth_profile_exists(doc: &DocumentMut, name: &str) -> bool {
    doc.get("auth")
        .and_then(|i| i.as_table())
        .and_then(|t| t.get(name))
        .is_some()
}

/// Iterate every `[[device]]` entry as `&Table`.
fn devices_iter(doc: &DocumentMut) -> Box<dyn Iterator<Item = &Table> + '_> {
    match doc.get("device").and_then(|i| i.as_array_of_tables()) {
        Some(a) => Box::new(a.iter()),
        None => Box::new(std::iter::empty()),
    }
}

/// Build a `[[device]]` table in the same field order
/// `transit.toml.example` uses, omitting defaulted/absent fields.
fn build_device_table(d: &Device) -> Table {
    let mut t = Table::new();
    t["id"] = value(d.id.as_str());
    t["host"] = value(d.host.as_str());
    if d.port != 22 {
        t["port"] = value(d.port as i64);
    }
    t["vendor"] = value(d.vendor.as_str());
    if let Some(g) = &d.group {
        t["group"] = value(g.as_str());
    }
    if let Some(c) = &d.color {
        t["color"] = value(c.as_str());
    }
    if !d.tags.is_empty() {
        let mut arr = toml_edit::Array::new();
        for tag in &d.tags {
            arr.push(tag.as_str());
        }
        t["tags"] = value(arr);
    }
    t["auth"] = value(d.auth.as_str());
    // Per-device terminal preferences, written only when explicitly set.
    // `None` round-trips as a missing field, matching the loader's
    // `serde(default)` behavior — no synthetic `false` clutter on
    // devices the user never opened the dialog for.
    if let Some(sh) = d.syntax_highlighting {
        t["syntax_highlighting"] = value(sh);
    }
    if let Some(qcp) = d.quick_copy_paste {
        t["quick_copy_paste"] = value(qcp);
    }
    if let Some(ff) = &d.font_family {
        t["font_family"] = value(ff.as_str());
    }
    if let Some(fs) = d.font_size {
        t["font_size"] = value(fs as i64);
    }
    if let Some(bc) = d.bold_color {
        t["bold_color"] = value(bc);
    }
    if let Some(awc) = d.allow_weak_crypto {
        t["allow_weak_crypto"] = value(awc);
    }
    if let Some(nb) = &d.netbox_id {
        t["netbox_id"] = value(nb.as_str());
    }
    if let Some(jv) = &d.jump_via {
        t["jump_via"] = value(jv.as_str());
    }
    if let Some(fa) = d.forward_agent {
        t["forward_agent"] = value(fa);
    }
    t
}

/// Devices whose `jump_via` references `id` (excluding the device that
/// IS `id` — self-reference is refused elsewhere). Used by
/// [`delete_device`] and [`update_device`]'s rename guard to refuse
/// operations that would dangle a jump reference, listing every
/// referent so the user knows what to fix (the `AuthProfileInUse`
/// refuse-don't-cascade house style). `pub` since the NetBox sync's
/// batch delete pre-checks it to surface the SAME remediation-shaped
/// error instead of the trailing revalidate's generic dangling-ref one.
pub fn jump_referents(doc: &DocumentMut, id: &str) -> Vec<String> {
    devices_iter(doc)
        .filter_map(|t| {
            let jump = t.get("jump_via")?.as_str()?;
            let own_id = t.get("id")?.as_str()?;
            if jump == id && own_id != id {
                Some(own_id.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Linear scan over `[[api_session]]` entries by id. Returns the index.
fn find_api_session_index(doc: &DocumentMut, id: &str) -> Option<usize> {
    doc.get("api_session")?
        .as_array_of_tables()?
        .iter()
        .position(|t| t.get("id").and_then(|i| i.as_str()) == Some(id))
}

/// Get (or insert) the `[[api_session]]` array of tables. Errors with
/// [`InventoryError::UnsupportedTomlShape`] if the key holds an inline
/// form the editor cannot mutate in place.
fn api_session_array_mut(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables, InventoryError> {
    if !doc.contains_key("api_session") {
        doc.insert("api_session", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["api_session"].as_array_of_tables_mut().ok_or_else(|| {
        InventoryError::UnsupportedTomlShape {
            key: "api_session".to_string(),
        }
    })
}

/// Build an `[[api_session]]` table in the field order
/// `transit.toml.example` uses, omitting absent optional fields.
fn build_api_session_table(s: &ApiSession) -> Table {
    let mut t = Table::new();
    t["id"] = value(s.id.as_str());
    t["name"] = value(s.name.as_str());
    t["vendor"] = value(s.vendor.as_str());
    t["kind"] = value(s.kind.as_str());
    if let Some(h) = &s.host {
        t["host"] = value(h.as_str());
    }
    if let Some(c) = &s.console_id {
        t["console_id"] = value(c.as_str());
    }
    if let Some(b) = &s.base_url {
        t["base_url"] = value(b.as_str());
    }
    if let Some(g) = &s.group {
        t["group"] = value(g.as_str());
    }
    if let Some(c) = &s.color {
        t["color"] = value(c.as_str());
    }
    if !s.tags.is_empty() {
        let mut arr = toml_edit::Array::new();
        for tag in &s.tags {
            arr.push(tag.as_str());
        }
        t["tags"] = value(arr);
    }
    t["auth"] = Item::Value(Value::InlineTable(build_auth_scheme_inline(&s.auth)));
    if let Some(secret) = &s.secret {
        t["secret"] = Item::Value(Value::InlineTable(build_secret_inline(secret)));
    }
    if let Some(pin) = &s.pinned_cert_sha256 {
        t["pinned_cert_sha256"] = value(pin.as_str());
    }
    t
}

/// Build the inline table for `auth = { scheme = "...", ... }`.
fn build_auth_scheme_inline(a: &AuthScheme) -> InlineTable {
    let mut t = InlineTable::new();
    match a {
        AuthScheme::None => {
            t.insert("scheme", "none".into());
        }
        AuthScheme::ApiKey {
            header,
            value_prefix,
        } => {
            t.insert("scheme", "api_key".into());
            t.insert("header", header.as_str().into());
            // Omitted when empty so pre-existing sessions round-trip
            // byte-identically (the field is `#[serde(default)]` on load).
            if !value_prefix.is_empty() {
                t.insert("value_prefix", value_prefix.as_str().into());
            }
        }
        AuthScheme::Bearer => {
            t.insert("scheme", "bearer".into());
        }
        AuthScheme::Basic { username } => {
            t.insert("scheme", "basic".into());
            t.insert("username", username.as_str().into());
        }
        AuthScheme::LoginCredentials { username } => {
            t.insert("scheme", "login_credentials".into());
            t.insert("username", username.as_str().into());
        }
    }
    t
}

/// Build an `[auth.<name>]` table.
fn build_auth_profile_table(p: &AuthProfile) -> Table {
    let mut t = Table::new();
    t["username"] = value(p.username.as_str());
    t["secret"] = Item::Value(Value::InlineTable(build_secret_inline(&p.secret)));
    t
}

/// Build the inline table for `secret = { backend = "...", ... }`.
fn build_secret_inline(s: &SecretRef) -> InlineTable {
    let mut t = InlineTable::new();
    match s {
        SecretRef::Keyring { key } => {
            t.insert("backend", "keyring".into());
            t.insert("key", key.as_str().into());
        }
        SecretRef::SshAgent {
            public_key_fingerprint,
        } => {
            t.insert("backend", "ssh_agent".into());
            if let Some(fp) = public_key_fingerprint {
                t.insert("public_key_fingerprint", fp.as_str().into());
            }
        }
        SecretRef::Op { reference } => {
            t.insert("backend", "op".into());
            t.insert("reference", reference.as_str().into());
        }
        SecretRef::Env { var } => {
            t.insert("backend", "env".into());
            t.insert("var", var.as_str().into());
        }
        SecretRef::SshKey { path, passphrase } => {
            t.insert("backend", "ssh_key".into());
            t.insert("path", path.to_string_lossy().as_ref().into());
            if let Some(pp) = passphrase {
                t.insert(
                    "passphrase",
                    Value::InlineTable(build_secret_inline(pp.as_ref())),
                );
            }
        }
        SecretRef::EncryptedFile { path } => {
            t.insert("backend", "encrypted_file".into());
            t.insert("path", path.to_string_lossy().as_ref().into());
        }
        // Interactive auth carries no stored reference — the whole point
        // is that there is nothing to write down. `backend = "prompt"`
        // round-trips as a bare discriminant.
        SecretRef::Prompt => {
            t.insert("backend", "prompt".into());
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{
        load,
        types::{ApiEndpointKind, AuthScheme, Vendor},
    };

    /// A small but realistic starting document with a comment, two
    /// devices, two auth profiles. Used as the baseline for most tests.
    fn baseline() -> DocumentMut {
        let raw = r#"# Lab inventory — keep one device per environment for the sanity tests.

[[device]]
id = "vEX1"
host = "192.0.2.35"
vendor = "junos"
group = "Lab/Junos"
auth = "lab-pw"

[[device]]
id = "rt-edge-1"
host = "10.0.0.1"
port = 2222
vendor = "cisco_ios"
group = "Prod/Routers"
auth = "prod-key"

[auth.lab-pw]
username = "alice"
secret = { backend = "keyring", key = "transit/lab-pw" }

[auth.prod-key]
username = "ops"
secret = { backend = "ssh_agent" }
"#;
        raw.parse().expect("baseline parses")
    }

    fn keyring_profile(user: &str, key: &str) -> AuthProfile {
        AuthProfile {
            username: user.to_string(),
            secret: SecretRef::Keyring {
                key: key.to_string(),
            },
        }
    }

    fn device(id: &str, host: &str, group: Option<&str>, auth: &str) -> Device {
        Device {
            id: id.to_string(),
            host: host.to_string(),
            port: 22,
            vendor: Vendor::Junos,
            group: group.map(str::to_string),
            color: None,
            tags: Vec::new(),
            auth: auth.to_string(),
            syntax_highlighting: None,
            quick_copy_paste: None,
            font_family: None,
            font_size: None,
            bold_color: None,
            allow_weak_crypto: None,
            netbox_id: None,
            jump_via: None,
            forward_agent: None,
        }
    }

    /// Round-trip: write the document to a tempfile, run the real
    /// loader, return the parsed InventoryFile so tests can assert on
    /// shape without re-parsing manually.
    fn loaded(doc: &DocumentMut) -> crate::inventory::InventoryFile {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        write_atomic(&path, &doc.to_string()).unwrap();
        load(&path).expect("loader accepts mutator output")
    }

    fn api_session(
        id: &str,
        kind: ApiEndpointKind,
        host: Option<&str>,
        console_id: Option<&str>,
    ) -> ApiSession {
        ApiSession {
            id: id.to_string(),
            name: format!("{id} controller"),
            vendor: Vendor::Custom("unifi".into()),
            kind,
            host: host.map(str::to_string),
            console_id: console_id.map(str::to_string),
            base_url: None,
            group: None,
            color: None,
            tags: Vec::new(),
            auth: AuthScheme::ApiKey {
                header: "X-API-KEY".to_string(),
                value_prefix: String::new(),
            },
            secret: Some(SecretRef::Keyring {
                key: format!("transit/api-{id}"),
            }),
            pinned_cert_sha256: None,
        }
    }

    #[test]
    fn add_api_session_round_trips_through_loader() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session(
                "udm",
                ApiEndpointKind::NetworkLocal,
                Some("192.168.1.1"),
                None,
            ),
        )
        .expect("add");
        let inv = loaded(&doc);
        assert_eq!(inv.api_sessions.len(), 1);
        assert_eq!(inv.api_sessions[0].id, "udm");
        assert_eq!(inv.api_sessions[0].kind, ApiEndpointKind::NetworkLocal);
        assert_eq!(inv.api_sessions[0].host.as_deref(), Some("192.168.1.1"));
        // Devices are untouched.
        assert_eq!(inv.devices.len(), 2);
    }

    #[test]
    fn api_key_value_prefix_round_trips_and_is_omitted_when_empty() {
        // The NetBox shape (`Authorization: Token <key>`) survives the
        // writer → loader round trip…
        let mut doc = baseline();
        let mut netbox = api_session("netbox", ApiEndpointKind::Generic, None, None);
        netbox.base_url = Some("https://netbox.example/api".to_string());
        netbox.auth = AuthScheme::ApiKey {
            header: "Authorization".to_string(),
            value_prefix: "Token ".to_string(),
        };
        add_api_session(&mut doc, &netbox).expect("add");
        let inv = loaded(&doc);
        assert_eq!(
            inv.api_sessions[0].auth,
            AuthScheme::ApiKey {
                header: "Authorization".to_string(),
                value_prefix: "Token ".to_string(),
            }
        );

        // …while an empty prefix writes NO `value_prefix` key at all, so a
        // pre-existing session's TOML round-trips byte-identically.
        let serialized = doc.to_string();
        assert!(serialized.contains("value_prefix"));
        let mut doc2 = baseline();
        add_api_session(
            &mut doc2,
            &api_session("udm", ApiEndpointKind::SiteManager, None, None),
        )
        .expect("add");
        assert!(!doc2.to_string().contains("value_prefix"));
    }

    #[test]
    fn hostile_netbox_strings_round_trip_as_inert_data_never_toml_structure() {
        // T49: netbox_id / host / group arrive from a server an attacker may
        // control. toml_edit must escape them into plain string VALUES — a
        // payload shaped like TOML syntax must never mint a second device or
        // any other table on the way through write → load.
        let mut doc = baseline();
        let mut d = device("nb-torture", "10.0.0.9", None, "lab-pw");
        d.netbox_id = Some("20\"\n[[device]]\nid = \"evil\"\nhost = \"6.6.6.6\"".to_string());
        d.host = "10.0.0.9\"\n[auth.evil]\nusername = \"x".to_string();
        d.group = Some("Site \"A\"\nwith newline".to_string());
        add_device(&mut doc, &d).expect("hostile strings are storable data");

        let inv = loaded(&doc);
        // Exactly the baseline devices + this one — no injected entries.
        assert_eq!(inv.devices.len(), 3);
        assert!(inv.devices.iter().all(|dev| dev.id != "evil"));
        let back = inv
            .devices
            .iter()
            .find(|dev| dev.id == "nb-torture")
            .unwrap();
        assert_eq!(back.netbox_id, d.netbox_id, "data preserved verbatim");
        assert_eq!(back.host, d.host);
        assert_eq!(back.group, d.group);
        assert_eq!(inv.auth_profiles.len(), 2, "no injected auth table");
    }

    #[test]
    fn add_api_session_rejects_duplicate_id() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("dup", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        let err = add_api_session(
            &mut doc,
            &api_session("dup", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap_err();
        assert!(matches!(err, InventoryError::ApiSessionIdConflict { id } if id == "dup"));
    }

    #[test]
    fn set_api_session_pin_persists_then_clears_through_loader() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("apic", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        // Absent by default.
        assert_eq!(loaded(&doc).api_sessions[0].pinned_cert_sha256, None);
        // Set → persists through a serialize + load round-trip.
        set_api_session_pin(&mut doc, "apic", Some("ab12cd")).expect("set pin");
        assert_eq!(
            loaded(&doc).api_sessions[0].pinned_cert_sha256.as_deref(),
            Some("ab12cd")
        );
        // Clear → gone again.
        set_api_session_pin(&mut doc, "apic", None).expect("clear pin");
        assert_eq!(loaded(&doc).api_sessions[0].pinned_cert_sha256, None);
        // Unknown id → not-found error, not a silent no-op.
        assert!(matches!(
            set_api_session_pin(&mut doc, "nope", Some("x")).unwrap_err(),
            InventoryError::ApiSessionNotFound { id } if id == "nope"
        ));
    }

    #[test]
    fn update_api_session_preserves_the_pin_across_an_edit() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("apic", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        let pin = "ab".repeat(32); // 64 hex chars
        set_api_session_pin(&mut doc, "apic", Some(&pin)).unwrap();
        // A normal edit: the form-built session carries pin=None. The mutator
        // must preserve the existing pin atomically (v4.3.0 review fix).
        let mut edited = api_session("apic", ApiEndpointKind::SiteManager, None, None);
        edited.name = "renamed".to_string();
        assert_eq!(edited.pinned_cert_sha256, None);
        update_api_session(&mut doc, "apic", &edited).unwrap();
        let inv = loaded(&doc);
        assert_eq!(inv.api_sessions[0].name, "renamed");
        assert_eq!(
            inv.api_sessions[0].pinned_cert_sha256.as_deref(),
            Some(pin.as_str())
        );
    }

    #[test]
    fn update_api_session_changes_fields() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("c1", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        let mut updated = api_session("c1", ApiEndpointKind::NetworkLocal, Some("10.0.0.5"), None);
        updated.name = "Renamed".to_string();
        update_api_session(&mut doc, "c1", &updated).expect("update");
        let inv = loaded(&doc);
        assert_eq!(inv.api_sessions.len(), 1);
        assert_eq!(inv.api_sessions[0].name, "Renamed");
        assert_eq!(inv.api_sessions[0].kind, ApiEndpointKind::NetworkLocal);
        assert_eq!(inv.api_sessions[0].host.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn update_api_session_rejects_id_collision() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("a", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        add_api_session(
            &mut doc,
            &api_session("b", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        let renamed = api_session("b", ApiEndpointKind::SiteManager, None, None);
        let err = update_api_session(&mut doc, "a", &renamed).unwrap_err();
        assert!(matches!(err, InventoryError::ApiSessionIdConflict { id } if id == "b"));
    }

    #[test]
    fn update_api_session_not_found() {
        let mut doc = baseline();
        let err = update_api_session(
            &mut doc,
            "ghost",
            &api_session("ghost", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap_err();
        assert!(matches!(err, InventoryError::ApiSessionNotFound { id } if id == "ghost"));
    }

    #[test]
    fn delete_api_session_removes_entry() {
        let mut doc = baseline();
        add_api_session(
            &mut doc,
            &api_session("gone", ApiEndpointKind::SiteManager, None, None),
        )
        .unwrap();
        delete_api_session(&mut doc, "gone").expect("delete");
        let inv = loaded(&doc);
        assert!(inv.api_sessions.is_empty());
        assert_eq!(inv.devices.len(), 2); // devices untouched
    }

    #[test]
    fn delete_api_session_not_found() {
        let mut doc = baseline();
        let err = delete_api_session(&mut doc, "ghost").unwrap_err();
        assert!(matches!(err, InventoryError::ApiSessionNotFound { id } if id == "ghost"));
    }

    // ----- add_device --------------------------------------------------

    #[test]
    fn add_device_appends_and_preserves_comments() {
        let mut doc = baseline();
        let new = device("vEX3", "192.0.2.36", Some("Lab/Junos"), "lab-pw");
        add_device(&mut doc, &new).unwrap();

        let serialized = doc.to_string();
        assert!(
            serialized.starts_with("# Lab inventory"),
            "leading comment must survive: {serialized}"
        );

        let parsed = loaded(&doc);
        assert_eq!(parsed.devices.len(), 3);
        assert_eq!(parsed.devices[2].id, "vEX3");
        assert_eq!(parsed.devices[2].group.as_deref(), Some("Lab/Junos"));
    }

    #[test]
    fn add_device_rejects_duplicate_id() {
        let mut doc = baseline();
        let dup = device("vEX1", "1.2.3.4", None, "lab-pw");
        match add_device(&mut doc, &dup) {
            Err(InventoryError::DeviceIdConflict { id }) => assert_eq!(id, "vEX1"),
            other => panic!("expected DeviceIdConflict, got {other:?}"),
        }
    }

    #[test]
    fn add_device_rejects_unknown_auth() {
        let mut doc = baseline();
        let bad = device("vEX9", "h", None, "does-not-exist");
        match add_device(&mut doc, &bad) {
            Err(InventoryError::UnknownAuth { auth, .. }) => assert_eq!(auth, "does-not-exist"),
            other => panic!("expected UnknownAuth, got {other:?}"),
        }
    }

    #[test]
    fn add_device_omits_default_port_in_serialized_output() {
        let mut doc = baseline();
        let d = device("vEX3", "h", None, "lab-pw");
        add_device(&mut doc, &d).unwrap();
        let s = doc.to_string();
        // The new entry block should NOT carry an explicit `port = 22`.
        let block = s.split("[[device]]").nth(3).unwrap();
        assert!(
            !block.contains("port = 22"),
            "default port should be omitted from serialized output: {block}"
        );
    }

    #[test]
    fn add_device_omits_unset_syntax_highlighting() {
        let mut doc = baseline();
        // `syntax_highlighting: None` must not produce a `false` line.
        let d = device("vEX3", "192.0.2.36", None, "lab-pw");
        add_device(&mut doc, &d).unwrap();
        let block = doc
            .to_string()
            .split("[[device]]")
            .nth(3)
            .unwrap()
            .to_string();
        assert!(
            !block.contains("syntax_highlighting"),
            "unset preference must not appear in serialized output: {block}"
        );
    }

    #[test]
    fn add_device_writes_explicit_syntax_highlighting() {
        let mut doc = baseline();
        let mut d = device("vEX3", "192.0.2.36", None, "lab-pw");
        d.syntax_highlighting = Some(true);
        add_device(&mut doc, &d).unwrap();
        let parsed = loaded(&doc);
        let added = parsed.devices.iter().find(|x| x.id == "vEX3").unwrap();
        assert_eq!(added.syntax_highlighting, Some(true));

        // And literal serialized form pins the surface so a future
        // toml_edit version that pretty-prints differently doesn't
        // silently change behavior.
        assert!(doc.to_string().contains("syntax_highlighting = true"));
    }

    #[test]
    fn add_device_writes_explicit_quick_copy_paste() {
        let mut doc = baseline();
        let mut d = device("vEX3", "192.0.2.36", None, "lab-pw");
        d.quick_copy_paste = Some(true);
        add_device(&mut doc, &d).unwrap();
        let parsed = loaded(&doc);
        let added = parsed.devices.iter().find(|x| x.id == "vEX3").unwrap();
        assert_eq!(added.quick_copy_paste, Some(true));
        assert!(doc.to_string().contains("quick_copy_paste = true"));
    }

    #[test]
    fn add_device_omits_unset_quick_copy_paste() {
        let mut doc = baseline();
        let d = device("vEX3", "192.0.2.36", None, "lab-pw");
        add_device(&mut doc, &d).unwrap();
        let block = doc
            .to_string()
            .split("[[device]]")
            .nth(3)
            .unwrap()
            .to_string();
        assert!(
            !block.contains("quick_copy_paste"),
            "unset preference must not appear in serialized output: {block}"
        );
    }

    #[test]
    fn add_device_writes_both_terminal_prefs_independently() {
        // Two new devices: one with both prefs on, one with only highlighting on.
        // Asserts the fields don't bleed between devices and stay paired with
        // the right [[device]] block in the output.
        let mut doc = baseline();

        let mut both = device("vEX3", "10.0.0.3", None, "lab-pw");
        both.syntax_highlighting = Some(true);
        both.quick_copy_paste = Some(true);
        add_device(&mut doc, &both).unwrap();

        let mut hl_only = device("vEX4", "10.0.0.4", None, "lab-pw");
        hl_only.syntax_highlighting = Some(true);
        add_device(&mut doc, &hl_only).unwrap();

        let parsed = loaded(&doc);
        let v3 = parsed.devices.iter().find(|d| d.id == "vEX3").unwrap();
        assert_eq!(v3.syntax_highlighting, Some(true));
        assert_eq!(v3.quick_copy_paste, Some(true));

        let v4 = parsed.devices.iter().find(|d| d.id == "vEX4").unwrap();
        assert_eq!(v4.syntax_highlighting, Some(true));
        assert_eq!(v4.quick_copy_paste, None);
    }

    #[test]
    fn update_device_can_toggle_syntax_highlighting() {
        let mut doc = baseline();
        // Turn ON for vEX1.
        let mut on = device("vEX1", "192.0.2.35", Some("Lab/Junos"), "lab-pw");
        on.syntax_highlighting = Some(true);
        update_device(&mut doc, "vEX1", &on).unwrap();
        let parsed = loaded(&doc);
        assert_eq!(
            parsed
                .devices
                .iter()
                .find(|d| d.id == "vEX1")
                .unwrap()
                .syntax_highlighting,
            Some(true)
        );

        // Turn it OFF (None) — field should disappear from serialized output.
        let off = device("vEX1", "192.0.2.35", Some("Lab/Junos"), "lab-pw");
        update_device(&mut doc, "vEX1", &off).unwrap();
        let parsed = loaded(&doc);
        assert_eq!(
            parsed
                .devices
                .iter()
                .find(|d| d.id == "vEX1")
                .unwrap()
                .syntax_highlighting,
            None
        );
        let v1_block = doc
            .to_string()
            .split("[[device]]")
            .find(|b| b.contains("vEX1"))
            .unwrap()
            .to_string();
        assert!(
            !v1_block.contains("syntax_highlighting"),
            "field should be absent after toggle off: {v1_block}"
        );
    }

    // ----- update_device -----------------------------------------------

    #[test]
    fn update_device_mutates_target_only() {
        let mut doc = baseline();
        let mut updated = device("vEX1", "192.168.1.1", Some("Lab/Junos"), "lab-pw");
        updated.port = 2200;
        update_device(&mut doc, "vEX1", &updated).unwrap();

        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        assert_eq!(v1.host, "192.168.1.1");
        assert_eq!(v1.port, 2200);

        // Other device untouched.
        let r1 = parsed.devices.iter().find(|d| d.id == "rt-edge-1").unwrap();
        assert_eq!(r1.host, "10.0.0.1");
        assert_eq!(r1.port, 2222);
    }

    #[test]
    fn update_device_can_rename_id() {
        let mut doc = baseline();
        let renamed = device("vEX1-renamed", "192.0.2.35", Some("Lab/Junos"), "lab-pw");
        update_device(&mut doc, "vEX1", &renamed).unwrap();

        let parsed = loaded(&doc);
        assert!(parsed.devices.iter().any(|d| d.id == "vEX1-renamed"));
        assert!(!parsed.devices.iter().any(|d| d.id == "vEX1"));
    }

    #[test]
    fn update_device_rejects_rename_into_existing_id() {
        let mut doc = baseline();
        let conflict = device("rt-edge-1", "192.0.2.35", None, "lab-pw");
        match update_device(&mut doc, "vEX1", &conflict) {
            Err(InventoryError::DeviceIdConflict { id }) => assert_eq!(id, "rt-edge-1"),
            other => panic!("expected DeviceIdConflict, got {other:?}"),
        }
    }

    #[test]
    fn update_device_rejects_unknown_target() {
        let mut doc = baseline();
        let new = device("ghost", "h", None, "lab-pw");
        match update_device(&mut doc, "ghost", &new) {
            Err(InventoryError::DeviceNotFound { id }) => assert_eq!(id, "ghost"),
            other => panic!("expected DeviceNotFound, got {other:?}"),
        }
    }

    // ----- delete_device -----------------------------------------------

    #[test]
    fn delete_device_removes_only_target() {
        let mut doc = baseline();
        delete_device(&mut doc, "vEX1").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(parsed.devices.len(), 1);
        assert_eq!(parsed.devices[0].id, "rt-edge-1");
    }

    #[test]
    fn delete_device_unknown_errors() {
        let mut doc = baseline();
        match delete_device(&mut doc, "ghost") {
            Err(InventoryError::DeviceNotFound { id }) => assert_eq!(id, "ghost"),
            other => panic!("expected DeviceNotFound, got {other:?}"),
        }
    }

    // ----- auth profile ops --------------------------------------------

    #[test]
    fn add_auth_profile_round_trips() {
        let mut doc = baseline();
        let p = keyring_profile("alice", "transit/alice");
        add_auth_profile(&mut doc, "alice-pw", &p).unwrap();

        let parsed = loaded(&doc);
        assert_eq!(parsed.auth_profiles.len(), 3);
        let alice = &parsed.auth_profiles["alice-pw"];
        assert_eq!(alice.username, "alice");
        match &alice.secret {
            SecretRef::Keyring { key } => assert_eq!(key, "transit/alice"),
            other => panic!("expected Keyring, got {other:?}"),
        }
    }

    #[test]
    fn add_auth_profile_rejects_duplicate_name() {
        let mut doc = baseline();
        let p = keyring_profile("x", "k");
        match add_auth_profile(&mut doc, "lab-pw", &p) {
            Err(InventoryError::AuthProfileConflict { name }) => assert_eq!(name, "lab-pw"),
            other => panic!("expected AuthProfileConflict, got {other:?}"),
        }
    }

    #[test]
    fn update_auth_profile_replaces_in_place() {
        let mut doc = baseline();
        let p = keyring_profile("alice-renamed", "transit/lab-pw-v2");
        update_auth_profile(&mut doc, "lab-pw", &p).unwrap();

        let parsed = loaded(&doc);
        assert_eq!(parsed.auth_profiles["lab-pw"].username, "alice-renamed");
    }

    #[test]
    fn delete_auth_profile_succeeds_when_unreferenced() {
        let mut doc = baseline();
        // First detach all references by deleting devices.
        delete_device(&mut doc, "vEX1").unwrap();
        delete_auth_profile(&mut doc, "lab-pw").unwrap();
        let parsed = loaded(&doc);
        assert!(!parsed.auth_profiles.contains_key("lab-pw"));
    }

    #[test]
    fn delete_auth_profile_rejects_when_referenced() {
        let mut doc = baseline();
        match delete_auth_profile(&mut doc, "lab-pw") {
            Err(InventoryError::AuthProfileInUse { name, devices }) => {
                assert_eq!(name, "lab-pw");
                assert_eq!(devices, vec!["vEX1".to_string()]);
            }
            other => panic!("expected AuthProfileInUse, got {other:?}"),
        }
    }

    #[test]
    fn delete_auth_profile_unknown_errors() {
        let mut doc = baseline();
        match delete_auth_profile(&mut doc, "ghost") {
            Err(InventoryError::AuthProfileNotFound { name }) => assert_eq!(name, "ghost"),
            other => panic!("expected AuthProfileNotFound, got {other:?}"),
        }
    }

    // ----- jump hosts (v6.5.0) ------------------------------------------

    fn jump_device(id: &str, jump: Option<&str>, forward_agent: Option<bool>) -> Device {
        let mut d = device(id, "10.9.9.9", None, "lab-pw");
        d.jump_via = jump.map(String::from);
        d.forward_agent = forward_agent;
        d
    }

    #[test]
    fn jump_fields_round_trip_through_writer_and_loader() {
        let mut doc = baseline();
        add_device(&mut doc, &jump_device("bastion", None, Some(true))).unwrap();
        add_device(&mut doc, &jump_device("r1", Some("bastion"), None)).unwrap();

        // The hand-rolled writer must emit both fields — release Device
        // has no Serialize, so ONLY this test catches an omission.
        let text = doc.to_string();
        assert!(text.contains("jump_via = \"bastion\""));
        assert!(text.contains("forward_agent = true"));

        let parsed = loaded(&doc);
        let r1 = parsed.devices.iter().find(|d| d.id == "r1").unwrap();
        assert_eq!(r1.jump_via.as_deref(), Some("bastion"));
        assert_eq!(r1.forward_agent, None);
        let bastion = parsed.devices.iter().find(|d| d.id == "bastion").unwrap();
        assert_eq!(bastion.forward_agent, Some(true));
    }

    #[test]
    fn add_device_rejects_self_jump_eagerly() {
        let mut doc = baseline();
        match add_device(&mut doc, &jump_device("solo", Some("solo"), None)) {
            Err(InventoryError::JumpCycle { chain }) => {
                assert_eq!(chain, vec!["solo".to_string(), "solo".to_string()]);
            }
            other => panic!("expected JumpCycle, got {other:?}"),
        }
    }

    #[test]
    fn add_device_dangling_jump_fails_at_revalidate() {
        let mut doc = baseline();
        match add_device(&mut doc, &jump_device("r1", Some("ghost"), None)) {
            Err(InventoryError::UnknownJumpHost { id, jump_via }) => {
                assert_eq!(id, "r1");
                assert_eq!(jump_via, "ghost");
            }
            other => panic!("expected UnknownJumpHost, got {other:?}"),
        }
    }

    #[test]
    fn batch_add_allows_forward_jump_reference() {
        // The import path adds devices in file order, which is not
        // topological — r1 may land before its bastion. The eager check
        // deliberately skips dangling refs; the batch's single trailing
        // revalidate enforces them.
        let mut doc = baseline();
        add_device_no_revalidate(&mut doc, &jump_device("r1", Some("bastion"), None)).unwrap();
        add_device_no_revalidate(&mut doc, &jump_device("bastion", None, None)).unwrap();
        revalidate(&doc).expect("forward reference resolves at batch end");
    }

    #[test]
    fn delete_device_refuses_while_jump_referenced_then_succeeds() {
        let mut doc = baseline();
        add_device(&mut doc, &jump_device("bastion", None, None)).unwrap();
        add_device(&mut doc, &jump_device("r1", Some("bastion"), None)).unwrap();
        add_device(&mut doc, &jump_device("r2", Some("bastion"), None)).unwrap();

        match delete_device(&mut doc, "bastion") {
            Err(InventoryError::JumpHostInUse { id, devices }) => {
                assert_eq!(id, "bastion");
                assert_eq!(devices, vec!["r1".to_string(), "r2".to_string()]);
            }
            other => panic!("expected JumpHostInUse, got {other:?}"),
        }

        delete_device(&mut doc, "r1").unwrap();
        delete_device(&mut doc, "r2").unwrap();
        delete_device(&mut doc, "bastion").expect("unreferenced bastion deletes");
    }

    #[test]
    fn update_device_rename_refuses_while_jump_referenced() {
        let mut doc = baseline();
        add_device(&mut doc, &jump_device("bastion", None, None)).unwrap();
        add_device(&mut doc, &jump_device("r1", Some("bastion"), None)).unwrap();

        // Renaming the referenced id would dangle r1's jump_via: refused.
        let renamed = jump_device("bastion2", None, None);
        match update_device(&mut doc, "bastion", &renamed) {
            Err(InventoryError::JumpHostInUse { id, devices }) => {
                assert_eq!(id, "bastion");
                assert_eq!(devices, vec!["r1".to_string()]);
            }
            other => panic!("expected JumpHostInUse, got {other:?}"),
        }

        // Same-id update of the referenced device stays allowed.
        let mut same_id = jump_device("bastion", None, None);
        same_id.host = "10.0.0.254".to_string();
        update_device(&mut doc, "bastion", &same_id).expect("non-rename update allowed");
    }

    #[test]
    fn update_device_rejects_self_jump_eagerly() {
        let mut doc = baseline();
        add_device(&mut doc, &jump_device("bastion", None, None)).unwrap();
        match update_device(
            &mut doc,
            "bastion",
            &jump_device("bastion", Some("bastion"), None),
        ) {
            Err(InventoryError::JumpCycle { .. }) => {}
            other => panic!("expected JumpCycle, got {other:?}"),
        }
    }

    // ----- rename_group ------------------------------------------------

    #[test]
    fn rename_group_updates_exact_match() {
        let mut doc = baseline();
        rename_group(&mut doc, "Lab/Junos", "Laboratory/Junos").unwrap();
        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        assert_eq!(v1.group.as_deref(), Some("Laboratory/Junos"));
    }

    #[test]
    fn rename_group_updates_prefix_descendants() {
        let mut doc = baseline();
        // Add a device deeper under Lab/* so we can verify prefix replacement.
        let d = device("vEX2", "192.0.2.36", Some("Lab/Junos/Sandbox"), "lab-pw");
        add_device(&mut doc, &d).unwrap();

        rename_group(&mut doc, "Lab", "Laboratory").unwrap();

        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        let v2 = parsed.devices.iter().find(|d| d.id == "vEX2").unwrap();
        assert_eq!(v1.group.as_deref(), Some("Laboratory/Junos"));
        assert_eq!(v2.group.as_deref(), Some("Laboratory/Junos/Sandbox"));

        // Unrelated device untouched.
        let r1 = parsed.devices.iter().find(|d| d.id == "rt-edge-1").unwrap();
        assert_eq!(r1.group.as_deref(), Some("Prod/Routers"));
    }

    #[test]
    fn rename_group_into_existing_path_concatenates() {
        let mut doc = baseline();
        // Source: Lab/Junos (vEX1). Destination: Prod/Routers (rt-edge-1
        // already there).
        rename_group(&mut doc, "Lab/Junos", "Prod/Routers").unwrap();
        let parsed = loaded(&doc);
        // Both devices should now share the same group path.
        assert_eq!(
            parsed
                .devices
                .iter()
                .find(|d| d.id == "vEX1")
                .unwrap()
                .group
                .as_deref(),
            Some("Prod/Routers")
        );
        assert_eq!(
            parsed
                .devices
                .iter()
                .find(|d| d.id == "rt-edge-1")
                .unwrap()
                .group
                .as_deref(),
            Some("Prod/Routers")
        );
    }

    #[test]
    fn rename_group_to_empty_ungroups() {
        let mut doc = baseline();
        rename_group(&mut doc, "Lab/Junos", "").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(
            parsed
                .devices
                .iter()
                .find(|d| d.id == "vEX1")
                .unwrap()
                .group,
            None
        );
    }

    #[test]
    fn rename_group_empty_old_path_errors() {
        let mut doc = baseline();
        match rename_group(&mut doc, "", "anything") {
            Err(InventoryError::InvalidGroupPath { .. }) => {}
            other => panic!("expected InvalidGroupPath, got {other:?}"),
        }
    }

    #[test]
    fn rename_group_no_matches_is_noop() {
        let mut doc = baseline();
        let before = doc.to_string();
        rename_group(&mut doc, "Nonexistent/Path", "Whatever").unwrap();
        // No matching device → no field rewrite, but document is still
        // valid (which revalidate confirmed) and structurally identical.
        assert_eq!(doc.to_string(), before);
    }

    // ----- groups registry: add_group / delete_group / set_device_group -

    #[test]
    fn baseline_has_no_groups_registry() {
        // Backward-compat: a file with no `groups` key loads with an
        // empty registry (proves `#[serde(default)]` under
        // `deny_unknown_fields`).
        let parsed = loaded(&baseline());
        assert!(parsed.groups.is_empty());
    }

    #[test]
    fn add_group_registers_an_empty_group() {
        let mut doc = baseline();
        add_group(&mut doc, "Staging").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(parsed.groups, vec!["Staging".to_string()]);
        // Devices untouched.
        assert_eq!(parsed.devices.len(), 2);
    }

    #[test]
    fn add_group_trims_and_round_trips_nested_path() {
        let mut doc = baseline();
        add_group(&mut doc, "/Lab/Empty/").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(parsed.groups, vec!["Lab/Empty".to_string()]);
    }

    #[test]
    fn add_group_idempotent_when_device_implied() {
        // vEX1 already lives in "Lab/Junos"; "creating" it (or an
        // ancestor) must be a no-op success, not an error, and must NOT
        // add a registry entry.
        let mut doc = baseline();
        add_group(&mut doc, "Lab/Junos").unwrap();
        add_group(&mut doc, "Lab").unwrap();
        let parsed = loaded(&doc);
        assert!(parsed.groups.is_empty());
    }

    #[test]
    fn add_group_idempotent_on_existing_registry_entry() {
        let mut doc = baseline();
        add_group(&mut doc, "Staging").unwrap();
        add_group(&mut doc, "Staging").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(parsed.groups, vec!["Staging".to_string()]);
    }

    #[test]
    fn add_group_rejects_invalid_paths() {
        for bad in ["", "   ", "///", "A//B"] {
            let mut doc = baseline();
            match add_group(&mut doc, bad) {
                Err(InventoryError::InvalidGroupPath { .. }) => {}
                other => panic!("{bad:?}: expected InvalidGroupPath, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_device_group_moves_a_device() {
        let mut doc = baseline();
        set_device_group(&mut doc, "vEX1", Some("Prod/Routers")).unwrap();
        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        assert_eq!(v1.group.as_deref(), Some("Prod/Routers"));
        // Other fields preserved (surgical edit, not full replace).
        assert_eq!(v1.host, "192.0.2.35");
        assert_eq!(v1.auth, "lab-pw");
    }

    #[test]
    fn set_device_group_none_ungroups() {
        let mut doc = baseline();
        set_device_group(&mut doc, "vEX1", None).unwrap();
        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        assert_eq!(v1.group, None);
    }

    #[test]
    fn set_device_group_unknown_device_errors() {
        let mut doc = baseline();
        match set_device_group(&mut doc, "nope", Some("Lab")) {
            Err(InventoryError::DeviceNotFound { id }) => assert_eq!(id, "nope"),
            other => panic!("expected DeviceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn delete_group_reparents_contents_up_one_level() {
        let mut doc = baseline();
        // A deeper device + an empty registry subgroup, both under Lab/Junos.
        add_device(
            &mut doc,
            &device("vEX2", "192.0.2.36", Some("Lab/Junos/Edge"), "lab-pw"),
        )
        .unwrap();
        add_group(&mut doc, "Lab/Junos/Empty").unwrap();

        delete_group(&mut doc, "Lab/Junos").unwrap();

        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        let v2 = parsed.devices.iter().find(|d| d.id == "vEX2").unwrap();
        assert_eq!(v1.group.as_deref(), Some("Lab")); // exact → parent
        assert_eq!(v2.group.as_deref(), Some("Lab/Edge")); // prefix collapsed
        assert_eq!(parsed.groups, vec!["Lab/Empty".to_string()]); // registry reparented
    }

    #[test]
    fn delete_top_level_group_lifts_children_to_root() {
        let mut doc = baseline();
        delete_group(&mut doc, "Lab").unwrap();
        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        // "Lab/Junos" had parent "Lab"; deleting Lab (parent "") lifts the
        // Junos subgroup to the root level.
        assert_eq!(v1.group.as_deref(), Some("Junos"));
    }

    #[test]
    fn rename_group_rewrites_the_registry() {
        let mut doc = baseline();
        add_group(&mut doc, "Lab/Empty").unwrap();
        rename_group(&mut doc, "Lab", "Laboratory").unwrap();
        let parsed = loaded(&doc);
        let v1 = parsed.devices.iter().find(|d| d.id == "vEX1").unwrap();
        assert_eq!(v1.group.as_deref(), Some("Laboratory/Junos"));
        assert_eq!(parsed.groups, vec!["Laboratory/Empty".to_string()]);
    }

    #[test]
    fn rename_group_dedupes_registry_on_collision() {
        let mut doc = baseline();
        add_group(&mut doc, "Lab/Empty").unwrap();
        add_group(&mut doc, "Other").unwrap();
        // Rename folds "Lab/Empty" onto the existing "Other" entry.
        rename_group(&mut doc, "Lab/Empty", "Other").unwrap();
        let parsed = loaded(&doc);
        assert_eq!(parsed.groups, vec!["Other".to_string()]);
    }

    #[test]
    fn empty_group_survives_a_device_passing_through_it() {
        // Create empty group → add a device into it → move the device
        // back out → the group still exists (the whole point of the
        // registry).
        let mut doc = baseline();
        add_group(&mut doc, "Transient").unwrap();
        add_device(
            &mut doc,
            &device("vEX9", "192.0.2.99", Some("Transient"), "lab-pw"),
        )
        .unwrap();
        set_device_group(&mut doc, "vEX9", None).unwrap();
        let parsed = loaded(&doc);
        assert!(parsed.groups.contains(&"Transient".to_string()));
        let v9 = parsed.devices.iter().find(|d| d.id == "vEX9").unwrap();
        assert_eq!(v9.group, None);
    }

    #[test]
    fn non_array_groups_shape_is_refused() {
        // `groups` as a non-array (a string) must be refused up front by
        // every group op, never panic.
        let raw = r#"groups = "not-an-array"

[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let mut doc: DocumentMut = raw.parse().unwrap();
        match add_group(&mut doc, "Lab") {
            Err(InventoryError::UnsupportedTomlShape { key }) => assert_eq!(key, "groups"),
            other => panic!("expected UnsupportedTomlShape, got {other:?}"),
        }
    }

    // ----- unsupported (inline) TOML shapes -----------------------------

    /// `toml::from_str` (the loader) accepts `device = [{ ... }]` and
    /// `auth = { name = { ... } }`, but `toml_edit` parses those as
    /// plain values the structural editors can't touch. Every mutator
    /// op must refuse with `UnsupportedTomlShape` — never panic, never
    /// mis-report `DeviceNotFound` — and leave the document unchanged.
    #[test]
    fn inline_toml_shapes_load_but_refuse_every_mutation() {
        let raw = r#"device = [ { id = "x", host = "h", vendor = "junos", auth = "p" } ]
auth = { p = { username = "u", secret = { backend = "ssh_agent" } } }
"#;

        // Pin current loader behavior: the inline forms parse + validate.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        std::fs::write(&path, raw).unwrap();
        let inv = load(&path).expect("loader accepts inline TOML shapes");
        assert_eq!(inv.devices.len(), 1);
        assert!(inv.auth_profiles.contains_key("p"));

        let mut doc: DocumentMut = raw.parse().expect("toml_edit parses inline shapes");
        let before = doc.to_string();

        let d = device("y", "h2", None, "p");
        let p = keyring_profile("u2", "transit/u2");

        let unsupported = |r: Result<(), InventoryError>, op: &str| match r {
            Err(InventoryError::UnsupportedTomlShape { .. }) => {}
            other => panic!("{op}: expected UnsupportedTomlShape, got {other:?}"),
        };

        unsupported(add_device(&mut doc, &d), "add_device");
        // update/delete target the EXISTING inline device "x": the shape
        // error must win over DeviceNotFound (the editor merely can't
        // see the device — it does exist).
        unsupported(update_device(&mut doc, "x", &d), "update_device");
        unsupported(delete_device(&mut doc, "x"), "delete_device");
        unsupported(add_auth_profile(&mut doc, "q", &p), "add_auth_profile");
        unsupported(
            update_auth_profile(&mut doc, "p", &p),
            "update_auth_profile",
        );
        unsupported(delete_auth_profile(&mut doc, "p"), "delete_auth_profile");
        unsupported(rename_group(&mut doc, "Lab", "Laboratory"), "rename_group");
        unsupported(add_group(&mut doc, "Lab/New"), "add_group");
        unsupported(delete_group(&mut doc, "Lab"), "delete_group");
        unsupported(
            set_device_group(&mut doc, "x", Some("Lab")),
            "set_device_group",
        );

        assert_eq!(
            doc.to_string(),
            before,
            "failed ops must leave the document byte-identical"
        );
    }

    #[test]
    fn inline_auth_only_still_refuses_device_ops() {
        // Devices use the standard [[device]] tables; only `auth` is
        // inline. Without the shape guard, add_device would *wrongly*
        // report UnknownAuth ("p" exists — the editor just can't see
        // it). The guard refuses everything up front instead.
        let raw = r#"auth = { p = { username = "u", secret = { backend = "ssh_agent" } } }

[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"
"#;
        let mut doc: DocumentMut = raw.parse().expect("valid TOML");
        let before = doc.to_string();
        let d = device("y", "h2", None, "p");
        match add_device(&mut doc, &d) {
            Err(InventoryError::UnsupportedTomlShape { key }) => assert_eq!(key, "auth"),
            other => panic!("expected UnsupportedTomlShape(auth), got {other:?}"),
        }
        assert_eq!(doc.to_string(), before);
    }

    // ----- inline-secret prescan as guardrail --------------------------

    #[test]
    fn add_auth_profile_blocked_if_username_field_smells_like_password() {
        // The prescan checks `password = "..."` patterns at line start.
        // No mutator path can synthesize those because AuthProfile only
        // has username + SecretRef, but verify the safety net by
        // hand-injecting a literal into the document.
        let mut doc = baseline();
        let auth = doc["auth"].as_table_mut().unwrap();
        let mut t = Table::new();
        t["username"] = value("u");
        t["password"] = value("hunter2"); // <- bypasses the typed API
        t["secret"] = Item::Value(Value::InlineTable(build_secret_inline(
            &SecretRef::Keyring { key: "k".into() },
        )));
        auth.insert("rogue", Item::Table(t));

        match revalidate(&doc) {
            Err(InventoryError::InlineSecret { pattern, .. }) => {
                assert!(pattern.contains("password"));
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    // ----- write_atomic ------------------------------------------------

    #[test]
    fn write_atomic_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("TransitCommunity").join("transit.toml");
        write_atomic(&nested, "# placeholder\n").unwrap();
        assert!(nested.exists());
        assert_eq!(std::fs::read_to_string(&nested).unwrap(), "# placeholder\n");
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        write_atomic(&path, "v1").unwrap();
        write_atomic(&path, "v2").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "v2");
    }

    // ----- no-revalidate batch primitives (import path) ----------------

    #[test]
    fn no_revalidate_batch_then_single_revalidate_validates_whole() {
        // Add a profile + a device that references it, WITHOUT per-op
        // revalidation, then validate once — mirrors the import command's
        // single closure (profiles before devices).
        let mut doc = baseline();
        add_auth_profile_no_revalidate(&mut doc, "imp-p1", &keyring_profile("a", "k1")).unwrap();
        add_device_no_revalidate(&mut doc, &device("imp-n1", "h1", None, "imp-p1")).unwrap();
        revalidate(&doc).unwrap();

        let parsed = loaded(&doc);
        assert!(parsed.auth_profiles.contains_key("imp-p1"));
        assert!(parsed.devices.iter().any(|d| d.id == "imp-n1"));
    }

    #[test]
    fn no_revalidate_add_device_checks_conflicts_eagerly() {
        // The batch must fail FAST on a duplicate id (before the final
        // revalidate), so the import rolls back cleanly.
        let mut doc = baseline();
        match add_device_no_revalidate(&mut doc, &device("vEX1", "h", None, "lab-pw")) {
            Err(InventoryError::DeviceIdConflict { id }) => assert_eq!(id, "vEX1"),
            other => panic!("expected DeviceIdConflict, got {other:?}"),
        }
    }

    #[test]
    fn no_revalidate_add_device_checks_auth_ref_eagerly() {
        let mut doc = baseline();
        match add_device_no_revalidate(&mut doc, &device("nope", "h", None, "ghost-auth")) {
            Err(InventoryError::UnknownAuth { auth, .. }) => assert_eq!(auth, "ghost-auth"),
            other => panic!("expected UnknownAuth, got {other:?}"),
        }
    }
}
