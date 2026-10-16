//! YAML schema + load path for `policies/<vendor>.yaml`.
//!
//! `deny_unknown_fields` is set on every struct: a typo in a policy
//! file (`pipe_allowd: ...`) fails the load loudly at startup
//! instead of silently degrading to "default-deny on the missing
//! list" — which would be a security regression flying under the
//! radar.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use transit_core::inventory::Vendor;

use crate::engine::{PolicyMode, Precedence, VendorPolicy};
use crate::error::PolicyError;

/// On-disk schema. Mirrors `policies/junos.yaml`.
///
/// `mode: gated` (the default) requires `precedence` + `allowed` +
/// `blocked` and runs the regex gate. `mode: unrestricted` (Phase 8b)
/// makes them all optional / empty and carries a user-facing
/// `warning` instead — the gate then short-circuits to
/// `Decision::AllowUnrestricted { warning }` and the dispatcher
/// keeps the per-command modal mandatory while refusing the
/// always-allow regex shortcut. See `docs/security/threat-model.md`
/// T_UNRESTRICTED_VENDOR for the carve-out rationale.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    mode: PolicyFileMode,

    /// Tie-breaker when both `allowed` and `blocked` match the
    /// command head. Default-deny on no-match is unaffected.
    /// Required for `mode: gated`, ignored for `mode: unrestricted`.
    #[serde(default)]
    precedence: Option<Precedence>,

    #[serde(default)]
    canonicalization: Canonicalization,

    /// Allowed-command head patterns. Required (may be empty) for
    /// `mode: gated`. Unused for `mode: unrestricted`.
    #[serde(default)]
    allowed: Vec<String>,

    /// Blocked-command head patterns.
    #[serde(default)]
    blocked: Vec<String>,

    #[serde(default)]
    pipe_allowed: Vec<String>,

    #[serde(default)]
    pipe_blocked: Vec<String>,

    /// User-facing warning rendered in the per-command modal when
    /// `mode: unrestricted`. Required for unrestricted; ignored for
    /// gated. Surfaces in the Tauri payload so the frontend can
    /// render it verbatim.
    #[serde(default)]
    warning: Option<String>,

    /// v6.1.x #1 — the vendor PHRASEBOOK: canonical, economical,
    /// KNOWN-ALLOWED command forms rendered into the agent's cached
    /// PolicySummary ("Known-good forms"). Plain command strings, not
    /// regexes; prompt-side only — the gate never consults this list
    /// (Rule 3 unaffected), and a per-vendor test asserts every entry
    /// passes the gate so the phrasebook can never teach a command the
    /// policy would deny. Seeded from the vendor's allowed-corpus test
    /// file; keep entries ≤ ~60 chars and the list ≤ 20 (the prompt
    /// renderer truncates beyond that).
    #[serde(default)]
    phrasebook: Vec<String>,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum PolicyFileMode {
    /// Default — the four (now five) vendor policies all run the
    /// regex gate.
    #[default]
    Gated,
    /// Phase 8b — vendor has no enumerable safe-command surface
    /// (generic Linux/Unix). Gate short-circuits to allow; modal
    /// + warning take over.
    Unrestricted,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Canonicalization {
    /// First-token alias map. Single-word aliases only in v1
    /// (multi-word like `sh int br` → `show interfaces brief`
    /// deferred). Applied after trim + NFC.
    #[serde(default)]
    aliases: HashMap<String, String>,
}

/// Load a single `policies/<vendor>.yaml` into a compiled
/// `VendorPolicy`. Bubble up any parse / regex error with the
/// originating path attached for clear startup diagnostics.
pub fn load_file(path: &Path) -> Result<(Vendor, VendorPolicy), PolicyError> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .unwrap_or_default();
    let vendor = vendor_from_stem(&stem).ok_or_else(|| PolicyError::UnknownVendor {
        path: path.to_path_buf(),
        stem: stem.clone(),
    })?;

    let raw = std::fs::read_to_string(path).map_err(|source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: PolicyFile = serde_yaml_bw::from_str(&raw).map_err(|source| PolicyError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;

    let mode = match parsed.mode {
        PolicyFileMode::Gated => PolicyMode::Gated,
        PolicyFileMode::Unrestricted => {
            // Unrestricted mode requires a warning string the modal
            // renders; refuse the load if it's missing so a future
            // typo in `policies/linux.yaml` surfaces at startup
            // rather than as a blank warning at chat time.
            let warning = parsed
                .warning
                .clone()
                .filter(|w| !w.trim().is_empty())
                .ok_or_else(|| PolicyError::Schema {
                    path: path.to_path_buf(),
                    detail: "mode: unrestricted requires a non-empty `warning:` field".into(),
                })?;
            PolicyMode::Unrestricted { warning }
        }
    };

    // Gated mode requires precedence. Unrestricted ignores it but we
    // still synthesize a placeholder so VendorPolicy's shape stays
    // uniform across modes. The placeholder is never read on the
    // unrestricted path (evaluate short-circuits).
    let precedence = match (&mode, parsed.precedence) {
        (PolicyMode::Gated, Some(p)) => p,
        (PolicyMode::Gated, None) => {
            return Err(PolicyError::Schema {
                path: path.to_path_buf(),
                detail: "mode: gated requires `precedence:` (block-wins or allow-wins)".into(),
            })
        }
        (PolicyMode::Unrestricted { .. }, _) => Precedence::BlockWins,
    };

    let allowed = compile_each(&parsed.allowed, path)?;
    let blocked = compile_each(&parsed.blocked, path)?;
    let pipe_allowed = compile_each(&parsed.pipe_allowed, path)?;
    let pipe_blocked = compile_each(&parsed.pipe_blocked, path)?;

    // Alias lookup happens AFTER canonicalization lowercases the
    // head (D-4), so normalize the map to lowercase at load time:
    // keys so a YAML author writing `SH: show` can't silently never
    // fire, values so an expansion can't reintroduce uppercase past
    // the case-fold. All shipped policies already use lowercase —
    // this is belt-and-braces.
    let aliases = parsed
        .canonicalization
        .aliases
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    Ok((
        vendor,
        VendorPolicy {
            mode,
            precedence,
            aliases,
            allowed,
            blocked,
            pipe_allowed,
            pipe_blocked,
            // Loader-side hygiene (not just the repo test, which user
            // BYOP files never run): entries are trimmed, single-line,
            // ≤ 60 chars, control-char-free. Anything else is dropped
            // HERE — phrasebook text reaches the model's cached prompt,
            // and while a user policy is user-trust-domain content
            // (its allowed-regexes already render there), a prose
            // string is a wider smuggling surface than a regex, so it
            // gets a tighter shape. Silent-drop matches the lenient
            // user-layer posture; the gate-pass test still hard-fails
            // the BUNDLED set.
            phrasebook: parsed
                .phrasebook
                .into_iter()
                // Backticks are stripped so an entry can't break out of
                // the ``…`` code span it renders inside (the render
                // wraps each entry in backticks); control chars and
                // brackets are stripped so it can't forge a newline or a
                // `[Transit …]`-shaped line in the cached prompt. len/
                // take() bound the cached-prefix cost. Gate validation is
                // done at ENGINE build (prune_phrasebooks_to_gate),
                // which sees the merged/custom effective policy this
                // per-file loader cannot.
                .map(|e| {
                    e.trim()
                        .chars()
                        .filter(|c| !c.is_control() && !matches!(c, '`' | '[' | ']'))
                        .collect::<String>()
                })
                .filter(|e| !e.is_empty() && e.len() <= 60)
                .take(20)
                .collect(),
        },
    ))
}

fn compile_each(patterns: &[String], path: &Path) -> Result<Vec<Regex>, PolicyError> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|source| PolicyError::Regex {
                path: path.to_path_buf(),
                pattern: p.clone(),
                source,
            })
        })
        .collect()
}

/// Map a filename stem (no `.yaml`) to a `Vendor`. Built-in stems map
/// to their variants via the canonical [`Vendor::from_tag`]; any other
/// non-empty stem becomes [`Vendor::Custom`] (BYOP Phase 2b) so a
/// `fortios.yaml` loads as a custom vendor instead of erroring.
///
/// Two stems are rejected (→ `None` → `PolicyError::UnknownVendor`):
/// the empty stem (a bare `.yaml`) and `unknown` — neither names a
/// policy-bearing vendor (`unknown` is the no-policy sentinel; a policy
/// file for it is meaningless and almost certainly a mistake).
fn vendor_from_stem(stem: &str) -> Option<Vendor> {
    if stem.is_empty() || stem == "unknown" {
        return None;
    }
    Some(Vendor::from_tag(stem))
}

/// Iterate every `*.yaml` file in `dir` and load each. Missing
/// `dir` is not an error (an inventory pointing at vendors with no
/// shipped policy still works — those vendors just default-deny);
/// other I/O errors propagate.
pub fn load_dir(dir: &Path) -> Result<Vec<(Vendor, VendorPolicy)>, PolicyError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(source) => {
            return Err(PolicyError::Io {
                path: dir.to_path_buf(),
                source,
            })
        }
    };

    for entry in entries {
        let entry = entry.map_err(|source| PolicyError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path: PathBuf = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        out.push(load_file(&path)?);
    }
    Ok(out)
}

/// The successfully-loaded user policies plus non-fatal diagnostics.
/// Fields are `pub(crate)` — `engine::from_layers` consumes them.
pub(crate) struct UserLayer {
    pub(crate) policies: Vec<(Vendor, VendorPolicy)>,
    pub(crate) warnings: Vec<String>,
}

/// Load a USER policy directory **leniently** (BYOP Phase 2a). Unlike
/// [`load_dir`] (the bundled layer, fail-loud), every per-file failure
/// — unparseable YAML, bad regex, unknown vendor stem — is collected as
/// a non-fatal warning and the file skipped, so one broken or malicious
/// file (e.g. on a shared NAS) can neither brick the app nor drop the
/// bundled floor. A missing directory is the common case (no user
/// policies configured) and produces an empty layer with no warning.
///
/// Subdirectories and non-`.yaml` files are skipped by the extension
/// check, same as [`load_dir`].
pub(crate) fn load_user_dir(dir: &Path) -> UserLayer {
    let mut policies = Vec::new();
    let mut warnings = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return UserLayer { policies, warnings }
        }
        Err(source) => {
            warnings.push(format!(
                "user policy directory {} could not be read: {source}",
                dir.display()
            ));
            return UserLayer { policies, warnings };
        }
    };

    for entry in entries {
        let path = match entry {
            Ok(e) => e.path(),
            Err(source) => {
                warnings.push(format!("user policy directory entry error: {source}"));
                continue;
            }
        };
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        // Reuse the strict loader and downgrade ANY error to a skip +
        // warning. In Phase 2a an unknown stem (`fortios.yaml`) lands
        // here as `UnknownVendor` and is skipped; Phase 2b changes
        // `vendor_from_stem` so unknown stems become custom vendors and
        // load instead — this loop is unchanged either way.
        match load_file(&path) {
            Ok(loaded) => policies.push(loaded),
            Err(e) => warnings.push(format!("skipped user policy {}: {e}", path.display())),
        }
    }

    UserLayer { policies, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_from_stem_recognizes_every_known_vendor() {
        // Pin every arm so a future Vendor variant is forced through
        // a test before this map silently lags behind the enum.
        // Drops the `arista_eos` mutation cargo-mutants flagged.
        assert_eq!(vendor_from_stem("junos"), Some(Vendor::Junos));
        assert_eq!(vendor_from_stem("cisco_ios"), Some(Vendor::CiscoIos));
        assert_eq!(vendor_from_stem("cisco_ios_xe"), Some(Vendor::CiscoIosXe));
        assert_eq!(vendor_from_stem("cisco_ios_xr"), Some(Vendor::CiscoIosXr));
        assert_eq!(vendor_from_stem("nxos"), Some(Vendor::NxOs));
        assert_eq!(vendor_from_stem("cisco_nxos"), Some(Vendor::NxOs));
        assert_eq!(vendor_from_stem("arista_eos"), Some(Vendor::AristaEos));
        assert_eq!(vendor_from_stem("pan_os"), Some(Vendor::PanOs));
        assert_eq!(vendor_from_stem("linux"), Some(Vendor::Linux));
    }

    #[test]
    fn vendor_from_stem_maps_novel_stems_to_custom() {
        // BYOP Phase 2b: a non-built-in stem is a CUSTOM vendor, not an
        // error. (Case matters — `JUNOS` isn't the built-in `junos`, so
        // it becomes Custom("JUNOS"), matching `from_tag`.)
        assert_eq!(
            vendor_from_stem("totally-novel"),
            Some(Vendor::Custom("totally-novel".into()))
        );
        assert_eq!(
            vendor_from_stem("JUNOS"),
            Some(Vendor::Custom("JUNOS".into()))
        );
    }

    #[test]
    fn vendor_from_stem_rejects_empty_and_unknown_sentinel() {
        // The only stems that don't name a policy-bearing vendor.
        assert_eq!(vendor_from_stem(""), None);
        assert_eq!(vendor_from_stem("unknown"), None);
    }

    #[test]
    fn load_dir_returns_empty_on_missing_directory() {
        // Pins the NotFound branch — distinguishing it from the
        // generic I/O error path. Without this, mutating the guard
        // `e.kind() == NotFound` to `true` (always early-return Ok)
        // or `false` (always propagate Err) survives all other tests.
        let nonexistent = std::env::temp_dir().join("transit-policy-nonexistent-12345-xyzzy");
        // Best-effort cleanup so a leftover from a flaky run doesn't
        // accidentally exist.
        let _ = std::fs::remove_dir_all(&nonexistent);
        let result = load_dir(&nonexistent);
        match result {
            Ok(v) => assert!(v.is_empty(), "missing dir → empty vec"),
            Err(e) => panic!("missing dir should be Ok([]), got {e}"),
        }
    }

    #[test]
    fn alias_map_normalized_to_lowercase_at_load() {
        // Belt-and-braces for D-4: an uppercase alias key (or value)
        // in the YAML would silently never fire / reintroduce
        // uppercase after the canonicalizer's case-fold. The loader
        // lowercases both at load time.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junos.yaml");
        std::fs::write(
            &path,
            "precedence: block-wins\n\
             canonicalization:\n\
             \x20 aliases:\n\
             \x20   SH: SHOW\n\
             allowed:\n\
             \x20 - \"^show( |$)\"\n",
        )
        .unwrap();
        let (vendor, policy) = load_file(&path).expect("loads cleanly");
        assert_eq!(vendor, Vendor::Junos);
        assert_eq!(
            policy.aliases.get("sh").map(String::as_str),
            Some("show"),
            "alias key AND value must be lowercased at load"
        );
        assert!(!policy.aliases.contains_key("SH"));
    }

    #[test]
    fn load_dir_ignores_subdirectories() {
        // `policies/samples/` ships BYOP template policies inside the
        // repo's policies dir. Dev builds resolve the policies dir to
        // the repo checkout (`commands.rs::resolve_policies_dir`), so
        // load_dir MUST skip directory entries (no `.yaml` extension
        // match) rather than recursing or erroring — a regression here
        // bricks dev startup on stems like `fortios` that
        // `vendor_from_stem` rejects. (The release bundle glob
        // `../policies/*.yaml` never ships the subdir at all.)
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("samples");
        std::fs::create_dir(&sub).unwrap();
        // Would fail loudly if loaded: unknown stem AND invalid YAML.
        std::fs::write(sub.join("fortios.yaml"), "not: [valid").unwrap();
        std::fs::write(
            dir.path().join("junos.yaml"),
            "precedence: block-wins\nallowed:\n  - \"^show( |$)\"\n",
        )
        .unwrap();

        let loaded = load_dir(dir.path()).expect("subdirectory must be skipped, not loaded");
        assert_eq!(loaded.len(), 1, "only the top-level junos.yaml loads");
        assert_eq!(loaded[0].0, Vendor::Junos);
    }

    #[test]
    fn load_dir_propagates_other_io_errors() {
        // Pin the OTHER half of the same guard. Pointing at a path
        // that exists but is not a directory yields ENOTDIR (or
        // similar), which is NOT NotFound — must surface as Err.
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, "").unwrap();
        let result = load_dir(&not_a_dir);
        assert!(result.is_err(), "non-directory path must surface Err");
    }

    // ---- BYOP user-layer lenient loader (Phase 2a) -----------------

    #[test]
    fn load_user_dir_missing_is_empty_no_warning() {
        let nonexistent = std::env::temp_dir().join("transit-user-policies-absent-9f3a2b");
        let _ = std::fs::remove_dir_all(&nonexistent);
        let layer = load_user_dir(&nonexistent);
        assert!(layer.policies.is_empty());
        assert!(
            layer.warnings.is_empty(),
            "missing user dir is the common case — no warning"
        );
    }

    #[test]
    fn load_user_dir_non_notfound_io_error_warns() {
        // Pin the OTHER half of the NotFound guard (mirror of
        // `load_dir_propagates_other_io_errors`). A path that EXISTS but
        // is not a directory yields ENOTDIR — NOT NotFound — so it must
        // produce a warning, not be silently treated as "no user layer".
        // Without this, mutating the `e.kind() == NotFound` guard to
        // `true` (always empty, no warning) survives — cargo-mutants
        // flagged exactly this gap. The lenient loader never propagates
        // an Err, so the warning is the observable signal.
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, "").unwrap();
        let layer = load_user_dir(&not_a_dir);
        assert!(layer.policies.is_empty());
        assert_eq!(
            layer.warnings.len(),
            1,
            "a non-NotFound IO error must surface as a warning, got {:?}",
            layer.warnings
        );
        assert!(layer.warnings[0].contains("could not be read"));
    }

    #[test]
    fn load_user_dir_skips_broken_file_keeps_good_one() {
        // A broken user file must NOT fail the load (contrast load_dir,
        // which is fail-loud for the bundled layer). It's skipped with a
        // warning and the good file still loads — so a malicious/typo'd
        // NAS file can't drop the whole user layer or the bundled floor.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("junos.yaml"), "not: [valid yaml").unwrap();
        std::fs::write(
            dir.path().join("cisco_ios.yaml"),
            "precedence: block-wins\nallowed:\n  - \"^show( |$)\"\n",
        )
        .unwrap();

        let layer = load_user_dir(dir.path());
        assert_eq!(layer.policies.len(), 1, "the good file still loads");
        assert_eq!(layer.policies[0].0, Vendor::CiscoIos);
        assert_eq!(
            layer.warnings.len(),
            1,
            "the broken file produced a warning"
        );
        assert!(layer.warnings[0].contains("junos.yaml"));
    }

    #[test]
    fn load_user_dir_loads_custom_vendor() {
        // BYOP Phase 2b: an unknown stem is a custom vendor and LOADS
        // (no warning) — `vendor_from_stem` maps it to Vendor::Custom.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("fortios.yaml"),
            "precedence: block-wins\nallowed:\n  - \"^get( |$)\"\n",
        )
        .unwrap();
        let layer = load_user_dir(dir.path());
        assert_eq!(layer.policies.len(), 1);
        assert_eq!(layer.policies[0].0, Vendor::Custom("fortios".into()));
        assert!(
            layer.warnings.is_empty(),
            "a well-formed custom vendor loads cleanly, got {:?}",
            layer.warnings
        );
    }

    #[test]
    fn load_user_dir_skips_unknown_sentinel_stem() {
        // `unknown.yaml` is rejected (the no-policy sentinel can't have
        // a policy) — skipped with a warning, not loaded as Custom.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("unknown.yaml"),
            "precedence: block-wins\nallowed:\n  - \"^x\"\n",
        )
        .unwrap();
        let layer = load_user_dir(dir.path());
        assert!(layer.policies.is_empty());
        assert_eq!(layer.warnings.len(), 1);
        assert!(layer.warnings[0].contains("unknown"));
    }

    #[test]
    fn load_user_dir_ignores_subdirectories() {
        // Same subdir-skip guarantee as load_dir.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested").join("junos.yaml"), "bad").unwrap();
        let layer = load_user_dir(dir.path());
        assert!(layer.policies.is_empty());
        assert!(layer.warnings.is_empty(), "subdir is skipped, not read");
    }
}
