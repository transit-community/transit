//! The default-deny command gate.
//!
//! Per Inviolable Rule 3 (CLAUDE.md §3): every `propose_command`
//! the agent emits passes through this gate AND the UI approval
//! modal. This file is the gate. It must be:
//!
//! - **Default-deny on no-match.** Adding a new policy or vendor
//!   must not silently allow new commands; an unknown command is
//!   refused.
//! - **Pure / total.** No errors, no panics: every input produces
//!   a `Decision`. Errors live in the loader, not here.
//! - **Free of side effects.** No logging from inside `evaluate` —
//!   the caller logs the decision; the gate stays testable.
//!
//! Algorithm overview (see `evaluate` for the implementation):
//! 0. Refuse any command containing a control character (C0 incl.
//!    `\n`/`\r`/`\t`/NUL/ESC, DEL, C1 incl. U+0085 NEL). Runs before
//!    the vendor lookup AND the unrestricted short-circuit: the
//!    dispatcher sends the RAW bytes to the PTY, so an embedded
//!    newline is a second command the regex gate never saw.
//! 1. Look up the vendor's `VendorPolicy`. None → `Deny`.
//! 2. Canonicalize: trim + NFC + lowercase + first-token alias.
//! 3. Split on `|`: head + zero-or-more pipe stages.
//! 4. Apply head allowlist / blocklist with `precedence` tiebreaker.
//! 5. For each pipe stage: must match `pipe_allowed` AND not match
//!    `pipe_blocked`. Block-wins is hard-coded for pipes (see
//!    `loader.rs` for the rationale).

use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use transit_core::inventory::Vendor;

use crate::canonicalize::canonicalize;
use crate::error::PolicyError;
use crate::loader;
use crate::pipe::{contains_unquoted_redirect, split_pipe, split_pipe_quote_agnostic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precedence {
    /// When both lists match the head, deny. The safer default.
    BlockWins,
    /// When both lists match the head, allow. Only used when a
    /// blocklist intentionally over-shoots and an allowlist
    /// carve-out trims it back.
    AllowWins,
}

/// How the policy gate treats this vendor.
///
/// `Gated` runs the regex allow/block lists as documented. `Unrestricted`
/// (Phase 8b) short-circuits to allow with a user-facing warning — used
/// for vendors with no enumerable safe surface (generic Linux/Unix).
/// The `ApprovalDispatcher` MUST keep the per-command modal mandatory
/// AND refuse always-allow regex registration on the unrestricted path
/// — see `docs/security/threat-model.md` T_UNRESTRICTED_VENDOR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMode {
    Gated,
    Unrestricted { warning: String },
}

#[derive(Debug)]
pub struct VendorPolicy {
    pub(crate) mode: PolicyMode,
    pub(crate) precedence: Precedence,
    pub(crate) aliases: HashMap<String, String>,
    pub(crate) allowed: Vec<Regex>,
    pub(crate) blocked: Vec<Regex>,
    pub(crate) pipe_allowed: Vec<Regex>,
    pub(crate) pipe_blocked: Vec<Regex>,
    /// v6.1.x #1 — prompt-side known-allowed command forms. NEVER
    /// consulted by `evaluate` (the gate's subject is the regexes);
    /// tested against the gate so it cannot drift permissive.
    pub(crate) phrasebook: Vec<String>,
}

/// Human-readable rendering of a vendor's policy, for surfacing in
/// `transit_agent`'s system prompt so the model knows what's blockable.
/// Built via [`PolicyEngine::summary`].
///
/// Source-of-truth for the regex sources: `Regex::as_str()` round-trips
/// the original pattern, so the model sees byte-for-byte what the gate
/// will enforce. Stripping regex syntax to "examples" was rejected
/// during Phase 5b planning because it introduced translation bugs
/// (`^show( |$)` → "show" loses boundary semantics).
///
/// `mode` carries the loader's [`PolicyMode`] verbatim so the prompt
/// renderer can branch (the unrestricted carve-out needs distinct
/// phrasing — rendering an empty `allowed:` list would mislead the
/// LLM into thinking nothing is allowed when in fact everything is,
/// gated only by the per-command modal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    pub mode: PolicyMode,
    pub precedence: Precedence,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub pipe_allowed: Vec<String>,
    pub pipe_blocked: Vec<String>,
    /// v6.1.x #1 — known-allowed command forms for the prompt's
    /// "Known-good forms" list. Prompt-side only; gate-tested.
    pub phrasebook: Vec<String>,
}

/// Why a command was denied. Load-bearing for the **read-only floor**
/// (BYOP Phase 2a): under a layered policy a `Blocked` denial from the
/// bundled (shipped) layer is **terminal** — a user layer can never
/// relax it — whereas a `DefaultDeny` MAY be relaxed by a user `allowed`
/// addition. The floor logic in [`PolicyEngine::evaluate`] keys on this
/// enum, never on the `reason` string (string-matching to drive a
/// security decision is exactly the bypass this type exists to prevent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyKind {
    /// The command matched a curated `blocked` / `pipe_blocked` pattern
    /// (head block, block-wins tiebreak, or a blocked pipe stage). In a
    /// layered policy this is the non-overridable shipped floor.
    Blocked,
    /// No `allowed` pattern matched, or the input was structurally
    /// refused (empty command/stage, control character, no policy
    /// registered). A user layer's `allowed` additions MAY turn a
    /// bundled `DefaultDeny` into an `Allow`.
    DefaultDeny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Phase 8b — the vendor's policy is `mode: unrestricted`, so the
    /// regex gate did not run. The dispatcher MUST still surface the
    /// per-command modal (carrying `warning`) AND refuse the
    /// always-allow regex shortcut for this decision shape. Every
    /// pattern-match site on `Decision` must explicitly handle this
    /// variant — the compiler enforcement is what stops a future
    /// refactor from treating `AllowUnrestricted` like `Allow` and
    /// quietly skipping the warning.
    AllowUnrestricted {
        warning: String,
    },
    /// `kind` drives the read-only floor (see [`DenyKind`]). `reason`
    /// is a human-readable, log-safe string for surfacing in UI deny
    /// dialogs and tracing logs. It MUST NOT include the command body —
    /// callers can log the body separately.
    Deny {
        kind: DenyKind,
        reason: String,
    },
}

impl Decision {
    /// A curated-block denial (terminal under a layered floor).
    fn deny_blocked<S: Into<String>>(reason: S) -> Self {
        Decision::Deny {
            kind: DenyKind::Blocked,
            reason: reason.into(),
        }
    }

    /// A default-deny / structural-refusal denial (a user layer may
    /// relax a vendor `DefaultDeny` by adding an `allowed` pattern).
    fn deny_default<S: Into<String>>(reason: S) -> Self {
        Decision::Deny {
            kind: DenyKind::DefaultDeny,
            reason: reason.into(),
        }
    }
}

/// One vendor's compiled policy as the engine holds it.
///
/// `effective` is what `evaluate` adjudicates against and what
/// `summary` renders — for a bundled-only vendor it IS the bundled
/// policy; for a shipped vendor with a user override it's the merged
/// policy (`bundled ∪ user`); for a custom vendor (BYOP Phase 2b) it's
/// the user policy alone.
///
/// `floor` is the **read-only floor** (BYOP Phase 2a): the bundled
/// policy, present ONLY when a distinct user layer overrides a shipped
/// vendor. When present, its `Blocked` denials are terminal — a user
/// `allowed` addition can never punch through a shipped block. `None`
/// means there is no separate floor to enforce: either no user layer
/// (bundled-only — `effective` already IS the bundled policy, so its
/// blocks bind), or a custom vendor (no shipped floor exists; the
/// dispatcher refuses the always-allow shortcut for those instead).
#[derive(Debug)]
struct VendorEntry {
    floor: Option<VendorPolicy>,
    effective: VendorPolicy,
}

/// Result of a layered load: the engine plus non-fatal user-layer
/// diagnostics. A broken USER policy never fails the load (it's
/// user-controllable) — it's dropped with a warning here, leaving the
/// bundled floor intact. Contrast a broken BUNDLED policy, which is a
/// fatal `PolicyError` (an installer bug).
#[derive(Debug)]
pub struct LayeredLoad {
    pub engine: PolicyEngine,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    policies: HashMap<Vendor, VendorEntry>,
}

impl PolicyEngine {
    /// Construct from a single directory of `<vendor>.yaml` files (the
    /// bundled layer, no user overrides). Missing directory is OK
    /// (every vendor default-denies); malformed content surfaces as
    /// `PolicyError`. No `floor` is stored — with no user layer the
    /// `effective` policy IS the bundled policy, so its blocks bind
    /// directly.
    pub fn load_from_dir(dir: &Path) -> Result<Self, PolicyError> {
        let entries = loader::load_dir(dir)?;
        let mut policies = HashMap::new();
        for (vendor, policy) in entries {
            policies.insert(
                vendor,
                VendorEntry {
                    floor: None,
                    effective: policy,
                },
            );
        }
        let mut engine = Self { policies };
        engine.prune_phrasebooks_to_gate();
        Ok(engine)
    }

    /// v6.1.x #1 — enforce the phrasebook↔gate tie at RUNTIME, on every
    /// layer. The repo test (`phrasebook_gate.rs`) only sees the
    /// bundled `policies/` dir; production also loads user/custom layers
    /// that never run it. Phrasebook text renders verbatim into the
    /// cached system prompt as "safe to propose", so an entry the
    /// vendor's own gate would DENY is dropped here — a phrasebook can
    /// never advertise a command the modal then refuses (that would
    /// only add modal-fatigue pressure, exactly where BYOP/custom
    /// vendors already can't use the always-allow shortcut). Runs after
    /// the effective policy is built, so it adjudicates the MERGED
    /// gate. Prompt-side only; never touches adjudication.
    fn prune_phrasebooks_to_gate(&mut self) {
        let vendors: Vec<Vendor> = self.policies.keys().cloned().collect();
        for vendor in vendors {
            let keep: Vec<String> = {
                let entry = &self.policies[&vendor];
                entry
                    .effective
                    .phrasebook
                    .iter()
                    .filter(|e| {
                        matches!(
                            self.evaluate(&vendor, e),
                            Decision::Allow | Decision::AllowUnrestricted { .. }
                        )
                    })
                    .cloned()
                    .collect()
            };
            if let Some(entry) = self.policies.get_mut(&vendor) {
                entry.effective.phrasebook = keep;
            }
        }
    }

    /// Construct from a bundled layer (`bundled_dir`, fail-loud) plus a
    /// user layer (`user_dir`, lenient — see [`loader::load_user_dir`]).
    /// User policies for shipped vendors are merged over the bundled
    /// floor (BYOP Phase 2a); user policies for unknown stems become
    /// custom vendors with no floor (Phase 2b). Returns the engine plus
    /// any non-fatal user-layer warnings for the caller to surface.
    pub fn from_layers(bundled_dir: &Path, user_dir: &Path) -> Result<LayeredLoad, PolicyError> {
        let bundled = loader::load_dir(bundled_dir)?; // fatal on error
        let user_layer = loader::load_user_dir(user_dir); // never fatal
        let mut warnings = user_layer.warnings;

        let mut bundled_map: HashMap<Vendor, VendorPolicy> = bundled.into_iter().collect();
        let mut policies: HashMap<Vendor, VendorEntry> = HashMap::new();

        for (vendor, user_policy) in user_layer.policies {
            match bundled_map.remove(&vendor) {
                // Shipped vendor + user override → merge over the floor.
                Some(bundled_policy) => {
                    if matches!(bundled_policy.mode, PolicyMode::Unrestricted { .. }) {
                        // An unrestricted vendor evaluates no lists, so a
                        // user layer over it is inert. Don't silently
                        // pretend it took effect (the loader's whole
                        // ethos is loud failure).
                        warnings.push(format!(
                            "user policy for '{}' ignored — the shipped vendor is \
                             unrestricted (no allow/block lists are evaluated; every \
                             command is gated by the per-command approval modal)",
                            vendor.as_str()
                        ));
                        policies.insert(
                            vendor,
                            VendorEntry {
                                floor: None,
                                effective: bundled_policy,
                            },
                        );
                    } else {
                        let (merged, mut merge_warnings) =
                            merge_over_floor(&bundled_policy, &user_policy, &vendor);
                        warnings.append(&mut merge_warnings);
                        policies.insert(
                            vendor,
                            VendorEntry {
                                floor: Some(bundled_policy),
                                effective: merged,
                            },
                        );
                    }
                }
                // Custom vendor — no shipped floor (Phase 2b). The user
                // policy stands alone; the dispatcher refuses the
                // always-allow shortcut for custom vendors as the
                // compensating control.
                None => {
                    policies.insert(
                        vendor,
                        VendorEntry {
                            floor: None,
                            effective: user_policy,
                        },
                    );
                }
            }
        }

        // Bundled vendors with no user override.
        for (vendor, bundled_policy) in bundled_map {
            policies.insert(
                vendor,
                VendorEntry {
                    floor: None,
                    effective: bundled_policy,
                },
            );
        }

        let mut engine = Self { policies };
        engine.prune_phrasebooks_to_gate();
        Ok(LayeredLoad { engine, warnings })
    }

    /// True when at least one vendor policy was loaded. Used by the
    /// startup path to log a warning when policies are entirely
    /// absent — that's almost certainly a deployment misconfiguration
    /// rather than an intentional state.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Every vendor with a registered (effective) policy — bundled,
    /// merged, or custom (BYOP Phase 2b). The agent's system-prompt
    /// builder enumerates these for `PolicySummary` so a user's custom
    /// vendor is surfaced to the model exactly like a shipped one,
    /// rather than a hardcoded built-in list missing it. Order is
    /// unspecified (HashMap); callers that need determinism sort by
    /// `Vendor::as_str` (the prompt builder does).
    pub fn vendors(&self) -> Vec<Vendor> {
        self.policies.keys().cloned().collect()
    }

    /// Render a vendor's policy as a [`PolicySummary`] suitable for
    /// embedding in the agent's system prompt. Returns `None` if the
    /// vendor has no registered policy (matches `evaluate`'s
    /// behavior — no policy means default-deny everything; the
    /// caller can still tell the model "this vendor has no
    /// allowed commands"). Regex sources are returned in the order
    /// they appear in the YAML so policy snapshots round-trip
    /// byte-for-byte and the agent's prompt prefix stays cache-stable
    /// across reloads.
    pub fn summary(&self, vendor: &Vendor) -> Option<PolicySummary> {
        // The EFFECTIVE (merged) policy is what the model should be told
        // about — a user's added `allowed` patterns ARE proposable, so
        // surfacing only the bundled set would make the LLM over-cautious.
        let policy = &self.policies.get(vendor)?.effective;
        Some(PolicySummary {
            mode: policy.mode.clone(),
            precedence: policy.precedence,
            allowed: policy
                .allowed
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            blocked: policy
                .blocked
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            pipe_allowed: policy
                .pipe_allowed
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            pipe_blocked: policy
                .pipe_blocked
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            phrasebook: policy.phrasebook.clone(),
        })
    }

    /// Adjudicate a single command for a single vendor. See module
    /// doc-comment for the algorithm. Total function: every input
    /// returns a `Decision`.
    ///
    /// **Read-only floor (BYOP Phase 2a):** when the vendor has a
    /// `floor` (a bundled policy being overridden by a user layer), the
    /// command is first run against the bundled policy verbatim; if that
    /// yields a `Blocked` denial it is **terminal** — the merged policy
    /// is never consulted, so a user `allowed` addition can never punch
    /// through a shipped block. A bundled `DefaultDeny` (no allow match)
    /// is NOT terminal — it falls through to the merged policy, which is
    /// exactly the relaxation a user layer exists to provide. The floor
    /// runs the *bundled* canonicalization (its own alias map), so a
    /// user alias cannot rewrite a blocked head to dodge the floor.
    pub fn evaluate(&self, vendor: &Vendor, command: &str) -> Decision {
        // Step 0 — refuse control characters outright, before ANY
        // other processing (incl. the floor and the unrestricted
        // short-circuit). The dispatcher sends the RAW bytes to the
        // device PTY, so an embedded `\n`/`\r` smuggles a second line
        // past a gate that only adjudicated the flattened text
        // (canonicalization's `split_whitespace` collapses control
        // chars into single spaces). Tab is included deliberately:
        // canonicalization would mask it the same way, and the device
        // may interpret a raw TAB as command completion. The reason
        // names only the offending code point, never the command body
        // (see the `Decision::Deny` doc).
        if let Some(c) = command.chars().find(|c| c.is_control()) {
            return Decision::deny_default(format!(
                "control character U+{:04X} in command — single-line commands only",
                u32::from(c)
            ));
        }

        let entry = match self.policies.get(vendor) {
            Some(e) => e,
            None => {
                return Decision::deny_default(format!(
                    "no policy registered for vendor {}",
                    vendor.as_str()
                ))
            }
        };

        // The floor: a shipped `Blocked` is non-negotiable. We re-emit
        // the variant explicitly (rather than returning the value) so
        // the terminality is visible at the call site and a future
        // refactor can't accidentally let it fall through.
        if let Some(floor) = &entry.floor {
            if let Decision::Deny {
                kind: DenyKind::Blocked,
                reason,
            } = eval_policy(floor, command)
            {
                return Decision::deny_blocked(reason);
            }
        }

        eval_policy(&entry.effective, command)
    }
}

/// Adjudicate `command` against a single compiled `policy`. The pure
/// core shared by the floor pass and the effective pass — it assumes
/// the control-character gate has already run (so it never re-checks).
fn eval_policy(policy: &VendorPolicy, command: &str) -> Decision {
    // Phase 8b — unrestricted vendors short-circuit. The regex gate is
    // structurally inapplicable (no enumerable safe surface); the caller
    // is responsible for the modal + warning + no-always-allow contract.
    if let PolicyMode::Unrestricted { warning } = &policy.mode {
        return Decision::AllowUnrestricted {
            warning: warning.clone(),
        };
    }

    let canonical = canonicalize(command, &policy.aliases);
    if canonical.is_empty() {
        return Decision::deny_default("default-deny: empty command");
    }

    let (head, pipe_stages) = split_pipe(&canonical);

    // --- Structural guards against gate-vs-device parser differentials.
    // Both run for the floor AND effective passes (a user policy can't
    // dissolve them) and AFTER the unrestricted short-circuit above (so
    // the Linux shell vendor, where `>`/quoted-`|` are legitimate, is
    // unaffected — it returned `AllowUnrestricted` already).
    //
    // (1) Output redirection. `split_pipe` models only `|`; an unquoted
    //     `>`/`>>` is native file redirection on NX-OS et al. that would
    //     otherwise ride the head's allow match straight to a device
    //     write (`show running-config > bootflash:cfg`).
    if contains_unquoted_redirect(&canonical) {
        return Decision::deny_blocked(
            "blocked: output redirection ('>' / '>>') writes to the device filesystem",
        );
    }
    // (2) Quote-agnostic pipe-block scan. `split_pipe` is quote-aware so
    //     a legitimate quoted `|` in a filter arg (`egrep '(vlan|vrf)'`)
    //     doesn't false-deny the ALLOW side below. But network-OS
    //     output-modifier parsers generally do NOT honor shell quoting,
    //     so a `|` we treated as quoted is a real stage boundary to the
    //     device. Re-split on EVERY `|` and deny if any segment matches a
    //     `pipe_blocked` verb — quoting must never hide a blocked stage
    //     (`show run | include x" | redirect tftp://…`). Trade-off: a
    //     blocked-verb token inside a balanced quoted filter arg can
    //     false-deny, which is the safe direction for a default-deny gate.
    for seg in split_pipe_quote_agnostic(&canonical) {
        if let Some(b) = first_match(&policy.pipe_blocked, seg) {
            return Decision::deny_blocked(format!(
                "pipe stage blocked (quote-agnostic): matched {b}"
            ));
        }
    }

    // Head allow/block. Find the FIRST match in each list (so deny
    // reasons reference an actual pattern, not a synthetic one).
    // `first_match` returns the matched pattern's source string for the
    // error message.
    let head_blocked = first_match(&policy.blocked, head);
    let head_allowed = first_match(&policy.allowed, head);

    match (head_allowed, head_blocked) {
        (None, None) => return Decision::deny_default("default-deny: no allowed match"),
        (None, Some(b)) => return Decision::deny_blocked(format!("blocked: matched {b}")),
        (Some(_), Some(b)) if policy.precedence == Precedence::BlockWins => {
            return Decision::deny_blocked(format!("blocked (block-wins): matched {b}"));
        }
        // Either Some(_), None  OR  Some(_), Some(_) with allow-wins.
        // Both fall through to the pipe-stage check.
        _ => {}
    }

    for stage in &pipe_stages {
        if stage.is_empty() {
            return Decision::deny_default("default-deny: empty pipe stage");
        }
        if let Some(b) = first_match(&policy.pipe_blocked, stage) {
            return Decision::deny_blocked(format!("pipe stage blocked: matched {b}"));
        }
        if first_match(&policy.pipe_allowed, stage).is_none() {
            return Decision::deny_default("pipe stage default-deny: no allowed match");
        }
    }

    Decision::Allow
}

/// Merge a `user` policy over a `bundled` one for a SHIPPED vendor,
/// producing the `effective` policy. The read-only-floor invariants:
///
/// - `allowed` / `blocked` / `pipe_*` = `bundled ∪ user` (user may add
///   allows and add/tighten blocks; the separate floor pass guarantees
///   bundled blocks still bind even if a user `allowed` would match).
/// - `aliases` = `bundled ∪ user`, **bundled wins** on key collision
///   (defense in depth — a user alias can't shadow a bundled
///   contraction in the merged map; the floor pass uses bundled aliases
///   regardless, so this is belt-and-braces).
/// - `mode` / `precedence` come from `bundled` and are NOT
///   user-overridable; a differing user value is dropped with a warning.
fn merge_over_floor(
    bundled: &VendorPolicy,
    user: &VendorPolicy,
    vendor: &Vendor,
) -> (VendorPolicy, Vec<String>) {
    let mut warnings = Vec::new();

    if bundled.precedence != user.precedence {
        warnings.push(format!(
            "user policy for '{}' set precedence {:?}; ignored — a shipped vendor's \
             precedence ({:?}) is not user-overridable (it would dissolve the floor)",
            vendor.as_str(),
            user.precedence,
            bundled.precedence,
        ));
    }
    // A user file can only reach this path with `mode: gated` (an
    // unrestricted bundled vendor is handled before merge, and a user
    // `mode: unrestricted` over a gated shipped vendor is the dangerous
    // case to refuse loudly).
    if matches!(user.mode, PolicyMode::Unrestricted { .. }) {
        warnings.push(format!(
            "user policy for '{}' set mode: unrestricted; ignored — a shipped vendor \
             cannot be downgraded to unrestricted (it would dissolve the floor)",
            vendor.as_str(),
        ));
    }

    // aliases: clone user's, then overlay bundled's so bundled wins.
    let mut aliases = user.aliases.clone();
    for (k, v) in &bundled.aliases {
        aliases.insert(k.clone(), v.clone());
    }

    let cat =
        |b: &[Regex], u: &[Regex]| -> Vec<Regex> { b.iter().chain(u.iter()).cloned().collect() };

    let merged = VendorPolicy {
        mode: bundled.mode.clone(),
        precedence: bundled.precedence,
        aliases,
        allowed: cat(&bundled.allowed, &user.allowed),
        blocked: cat(&bundled.blocked, &user.blocked),
        pipe_allowed: cat(&bundled.pipe_allowed, &user.pipe_allowed),
        pipe_blocked: cat(&bundled.pipe_blocked, &user.pipe_blocked),
        // Prompt-side only: user phrasebook entries append after the
        // bundled set, same order rule as `allowed`. The merged list is
        // gate-pruned at ENGINE build (prune_phrasebooks_to_gate), so a
        // user entry the merged gate would deny is dropped there — the
        // repo `phrasebook_gate.rs` test only covers the bundled dir and
        // cannot see this layer, which is why the enforcement is
        // runtime, not test-time.
        phrasebook: bundled
            .phrasebook
            .iter()
            .chain(user.phrasebook.iter())
            .cloned()
            .collect(),
    };
    (merged, warnings)
}

/// Return the first regex in `patterns` that matches `s`, as its
/// source-string form. Used to build descriptive deny reasons.
fn first_match<'a>(patterns: &'a [Regex], s: &str) -> Option<&'a str> {
    patterns.iter().find(|r| r.is_match(s)).map(|r| r.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny fake policy that exercises every code path
    /// without depending on the on-disk Junos policy.
    fn fake_policy(precedence: Precedence) -> VendorPolicy {
        let mut aliases = HashMap::new();
        aliases.insert("sh".to_string(), "show".to_string());
        VendorPolicy {
            mode: PolicyMode::Gated,
            precedence,
            aliases,
            allowed: vec![Regex::new(r"^show( |$)").unwrap()],
            blocked: vec![
                Regex::new(r"^configure").unwrap(),
                // Deliberate overlap: also blocks "show" so we can
                // exercise the precedence tiebreaker.
                Regex::new(r"^show secret").unwrap(),
            ],
            pipe_allowed: vec![
                Regex::new(r"^match ").unwrap(),
                Regex::new(r"^count$").unwrap(),
            ],
            pipe_blocked: vec![Regex::new(r"^save ").unwrap()],
            phrasebook: vec![],
        }
    }

    fn unrestricted_policy() -> VendorPolicy {
        VendorPolicy {
            mode: PolicyMode::Unrestricted {
                warning: "test-only warning".into(),
            },
            precedence: Precedence::BlockWins,
            aliases: HashMap::new(),
            allowed: Vec::new(),
            blocked: Vec::new(),
            pipe_allowed: Vec::new(),
            pipe_blocked: Vec::new(),
            phrasebook: vec![],
        }
    }

    fn engine_with_junos(policy: VendorPolicy) -> PolicyEngine {
        let mut policies = HashMap::new();
        policies.insert(
            Vendor::Junos,
            VendorEntry {
                floor: None,
                effective: policy,
            },
        );
        PolicyEngine { policies }
    }

    #[test]
    fn prune_phrasebooks_drops_gate_denied_entries() {
        // v6.1.x #1 — the RUNTIME enforcement the repo build test can't
        // provide for user/custom layers: a phrasebook entry the
        // vendor's own gate denies is pruned at engine construction, so
        // the cached prompt never advertises a refused command. `^show(
        // |$)` allows "show version" and (block-wins) denies "show
        // secret"/"configure".
        let mut policy = fake_policy(Precedence::BlockWins);
        policy.phrasebook = vec![
            "show version".into(),      // allowed → kept
            "show secret".into(),       // blocked → dropped
            "configure".into(),         // blocked → dropped
            "reboot the router".into(), // default-deny → dropped
        ];
        let mut engine = engine_with_junos(policy);
        engine.prune_phrasebooks_to_gate();
        let pb = engine.summary(&Vendor::Junos).unwrap().phrasebook;
        assert_eq!(pb, vec!["show version".to_string()]);
    }

    /// Build a Junos engine with a distinct bundled floor + merged
    /// effective policy — the shape `from_layers` produces for a
    /// shipped vendor with a user override.
    fn engine_with_junos_floor(floor: VendorPolicy, effective: VendorPolicy) -> PolicyEngine {
        let mut policies = HashMap::new();
        policies.insert(
            Vendor::Junos,
            VendorEntry {
                floor: Some(floor),
                effective,
            },
        );
        PolicyEngine { policies }
    }

    #[test]
    fn unknown_vendor_default_denies_with_reason() {
        let engine = PolicyEngine::default();
        let d = engine.evaluate(&Vendor::Junos, "show version");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("no policy registered")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn unknown_vendor_variant_default_denies() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::CiscoIos, "show version");
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn allowed_head_passes() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "show version"),
            Decision::Allow
        );
    }

    #[test]
    fn blocked_head_denies() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "configure");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("blocked")),
            _ => panic!(),
        }
    }

    #[test]
    fn no_match_default_denies() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "telnet 1.2.3.4");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("default-deny")),
            _ => panic!(),
        }
    }

    #[test]
    fn block_wins_when_both_match() {
        // "show secret" matches both ^show and ^show secret;
        // block-wins precedence picks deny.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "show secret");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("block-wins")),
            _ => panic!(),
        }
    }

    #[test]
    fn allow_wins_when_both_match() {
        let engine = engine_with_junos(fake_policy(Precedence::AllowWins));
        let d = engine.evaluate(&Vendor::Junos, "show secret");
        // With allow-wins we expect Allow if no pipe issues. There
        // are none here.
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn pipe_stage_allowed_passes() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "show route | match BGP | count"),
            Decision::Allow
        );
    }

    #[test]
    fn pipe_stage_blocked_denies_even_with_allowed_head() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "show config | save /tmp/foo");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("pipe stage blocked")),
            _ => panic!(),
        }
    }

    #[test]
    fn pipe_stage_default_denies_unknown() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "show route | weird-pipe-thing");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("default-deny")),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_pipe_stage_default_denies() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "show |");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("empty pipe stage")),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_input_default_denies() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        let d = engine.evaluate(&Vendor::Junos, "");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("empty command")),
            _ => panic!(),
        }
        let d = engine.evaluate(&Vendor::Junos, "   ");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("empty command")),
            _ => panic!(),
        }
    }

    #[test]
    fn alias_canonicalization_routes_to_allowed() {
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        // `sh interfaces` aliases to `show interfaces` which matches
        // `^show( |$)`.
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "sh interfaces"),
            Decision::Allow
        );
    }

    #[test]
    fn matching_is_case_insensitive_for_allowed() {
        // D-4 — network CLIs accept `SHOW VERSION` / `Show Version`;
        // canonicalization lowercases before matching so the
        // lowercase-written policy regexes fire on any casing.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "SHOW VERSION"),
            Decision::Allow
        );
    }

    #[test]
    fn matching_is_case_insensitive_for_blocked() {
        // D-4 — the load-bearing half: uppercase config-mode entry
        // must hit the curated blocklist PATTERN ("blocked: matched
        // ..."), not merely fall through to default-deny. Under
        // allow-wins precedence a default-deny-only catch would be a
        // latent bypass.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        for cmd in ["CONFIGURE", "Configure terminal"] {
            match engine.evaluate(&Vendor::Junos, cmd) {
                Decision::Deny { reason, .. } => assert!(
                    reason.contains("blocked: matched"),
                    "{cmd:?} should hit the blocklist pattern, got reason {reason:?}"
                ),
                other => panic!("expected Deny for {cmd:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn alias_lookup_is_case_insensitive() {
        // `SH` lowercases to `sh` before the alias map is consulted,
        // so it expands to `show` like the lowercase form.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "SH interfaces"),
            Decision::Allow
        );
    }

    /// One representative per control-character class step 0 must
    /// refuse: LF, CR, CRLF, NUL, TAB, ESC, C1 NEL. Shared by the
    /// gated and unrestricted control-char tests below.
    const CONTROL_CHAR_SMUGGLES: &[&str] = &[
        "show version\nconfigure terminal",
        "show version\rrun bash",
        "show version\r\nreload",
        "show\u{0000}version",
        "show\tversion",
        "show \u{1b}[2J version",
        "show\u{0085}version",
    ];

    #[test]
    fn control_characters_deny_before_gate() {
        // D-1 — an embedded newline makes the PTY execute a second
        // line the regex gate never saw (canonicalization flattens
        // control chars into spaces). Step 0 refuses the raw bytes
        // before canonicalization can mask them.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        for cmd in CONTROL_CHAR_SMUGGLES {
            match engine.evaluate(&Vendor::Junos, cmd) {
                Decision::Deny { reason, .. } => assert!(
                    reason.contains("control character"),
                    "{cmd:?} should deny on the control char, got reason {reason:?}"
                ),
                other => panic!("expected Deny for {cmd:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn control_characters_deny_even_for_unrestricted_vendor() {
        // Step 0 beats the Phase 8b short-circuit. On an unrestricted
        // Linux device every embedded line would execute, and the
        // approval modal would render the newline collapsed — so the
        // control-char refusal must fire before the mode check.
        let engine = engine_with_junos(unrestricted_policy());
        for cmd in CONTROL_CHAR_SMUGGLES {
            match engine.evaluate(&Vendor::Junos, cmd) {
                Decision::Deny { reason, .. } => assert!(
                    reason.contains("control character"),
                    "{cmd:?} should deny on the control char, got reason {reason:?}"
                ),
                other => panic!(
                    "unrestricted vendor must still deny control chars for {cmd:?}, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn control_character_deny_reason_does_not_echo_command_body() {
        // The `Decision::Deny` contract: reasons are log-safe and
        // never include the command body. Step 0 names only the
        // offending code point.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        match engine.evaluate(&Vendor::Junos, "show version\nconfigure terminal") {
            Decision::Deny { reason, .. } => {
                assert!(reason.contains("U+000A"), "reason names the code point");
                assert!(
                    !reason.contains("show") && !reason.contains("configure"),
                    "reason must not echo the command body: {reason:?}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn unrestricted_mode_short_circuits_to_allow_unrestricted() {
        // Phase 8b — `mode: unrestricted` returns AllowUnrestricted
        // for ANY control-char-free command (including the empty
        // string and what would otherwise be a blocklist hit); step 0
        // still refuses control characters first. The dispatcher is
        // what enforces "modal still runs, no always-allow"; the
        // gate's job is just to surface the warning.
        let engine = engine_with_junos(unrestricted_policy());
        for cmd in &["show version", "rm -rf /", "configure terminal", ""] {
            match engine.evaluate(&Vendor::Junos, cmd) {
                Decision::AllowUnrestricted { warning } => {
                    assert!(warning.contains("test-only warning"));
                }
                other => panic!("unrestricted vendor should return AllowUnrestricted for {cmd:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn is_empty_reflects_loaded_count() {
        assert!(PolicyEngine::default().is_empty());
        let e = engine_with_junos(fake_policy(Precedence::BlockWins));
        assert!(!e.is_empty());
    }

    // ---- Read-only floor (BYOP Phase 2a) ---------------------------
    //
    // These pin the floor at the `evaluate` level using a hand-built
    // floor+effective entry. The cross-vendor corpus + proptest live in
    // `tests/` (per CLAUDE.md §7 step 7); here we pin the mechanics and
    // the DenyKind contract.

    /// An "effective" policy that allows EVERYTHING (`^` matches any
    /// head) with no blocks — the maximally-permissive user merge. Used
    /// to prove the floor still bites even when `effective` would allow.
    fn allow_everything_policy() -> VendorPolicy {
        VendorPolicy {
            mode: PolicyMode::Gated,
            precedence: Precedence::BlockWins,
            aliases: HashMap::new(),
            allowed: vec![Regex::new("^").unwrap()],
            blocked: vec![],
            pipe_allowed: vec![Regex::new("^").unwrap()],
            pipe_blocked: vec![],
            phrasebook: vec![],
        }
    }

    #[test]
    fn floor_blocked_is_terminal_even_when_effective_allows() {
        // The headline guarantee: bundled blocks `^configure`; the
        // (merged) effective policy allows everything. `configure`
        // must STILL deny — the floor's Blocked is terminal.
        let engine = engine_with_junos_floor(
            fake_policy(Precedence::BlockWins),
            allow_everything_policy(),
        );
        match engine.evaluate(&Vendor::Junos, "configure terminal") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("floor block must be terminal, got {other:?}"),
        }
    }

    #[test]
    fn floor_blocked_terminal_for_block_wins_overlap() {
        // `show secret` matches both ^show (allow) and ^show secret
        // (block) in the floor under block-wins → floor Deny{Blocked}.
        // Effective allows everything; floor still wins.
        let engine = engine_with_junos_floor(
            fake_policy(Precedence::BlockWins),
            allow_everything_policy(),
        );
        match engine.evaluate(&Vendor::Junos, "show secret stuff") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("block-wins floor overlap must deny, got {other:?}"),
        }
    }

    #[test]
    fn floor_pipe_block_is_terminal() {
        // Floor blocks the `save` pipe stage; effective allows every
        // stage. `show config | save x` must still deny on the floor.
        let engine = engine_with_junos_floor(
            fake_policy(Precedence::BlockWins),
            allow_everything_policy(),
        );
        match engine.evaluate(&Vendor::Junos, "show config | save /tmp/x") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("floor pipe block must be terminal, got {other:?}"),
        }
    }

    #[test]
    fn floor_default_deny_falls_through_to_effective_allow() {
        // The relaxation BYOP exists for: the floor DEFAULT-denies
        // `traceroute` (no allow match, not a block), and the user's
        // effective policy allows it. Result: Allow. A floor
        // default-deny is NOT terminal.
        let mut effective = fake_policy(Precedence::BlockWins);
        effective
            .allowed
            .push(Regex::new(r"^traceroute( |$)").unwrap());
        let engine = engine_with_junos_floor(fake_policy(Precedence::BlockWins), effective);
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "traceroute 10.0.0.1"),
            Decision::Allow,
            "a bundled default-deny must be relaxable by a user allow"
        );
    }

    #[test]
    fn floor_uses_bundled_aliases_not_effective_aliases() {
        // The alias-bypass attack the floor design defeats: the
        // effective (merged) policy carries a malicious alias remapping
        // the blocked head `configure` → an allowed head `show`. If the
        // floor evaluated with effective's aliases, `configure` would
        // canonicalize to `show` and sail past. Because the floor runs
        // with BUNDLED aliases (which have no such remap), `^configure`
        // still matches and denies.
        let floor = fake_policy(Precedence::BlockWins); // blocks ^configure, no `configure` alias
        let mut effective = allow_everything_policy();
        effective
            .aliases
            .insert("configure".to_string(), "show".to_string());
        let engine = engine_with_junos_floor(floor, effective);
        match engine.evaluate(&Vendor::Junos, "configure terminal") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("user alias must not dodge the floor, got {other:?}"),
        }
    }

    #[test]
    fn no_floor_behaves_like_single_layer() {
        // A bundled-only engine (floor: None) must behave exactly as
        // before the floor existed: effective's own blocks bind.
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        match engine.evaluate(&Vendor::Junos, "configure") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("single-layer block must deny, got {other:?}"),
        }
        assert_eq!(
            engine.evaluate(&Vendor::Junos, "show version"),
            Decision::Allow
        );
    }

    #[test]
    fn merge_over_floor_unions_lists_and_warns_on_precedence_override() {
        let mut bundled = fake_policy(Precedence::BlockWins);
        bundled.aliases.insert("c".into(), "configure".into());
        let mut user = fake_policy(Precedence::AllowWins); // differs → warning
        user.allowed.push(Regex::new(r"^ping( |$)").unwrap());
        user.aliases.insert("c".into(), "clear".into()); // collides → bundled wins
        user.aliases.insert("p".into(), "ping".into()); // new → kept

        let (merged, warnings) = merge_over_floor(&bundled, &user, &Vendor::Junos);

        // precedence is bundled's, with a warning about the ignored override.
        assert_eq!(merged.precedence, Precedence::BlockWins);
        assert!(
            warnings.iter().any(|w| w.contains("precedence")),
            "expected a precedence-override warning, got {warnings:?}"
        );
        // user allow merged in.
        assert!(merged.allowed.iter().any(|r| r.as_str() == "^ping( |$)"));
        // alias collision: bundled wins; user-only alias kept.
        assert_eq!(
            merged.aliases.get("c").map(String::as_str),
            Some("configure")
        );
        assert_eq!(merged.aliases.get("p").map(String::as_str), Some("ping"));
    }

    #[test]
    fn deny_kind_distinguishes_block_from_default_deny() {
        // Pin the DenyKind contract used by the floor: a block match is
        // Blocked; a no-match is DefaultDeny. (Single-layer engine.)
        let engine = engine_with_junos(fake_policy(Precedence::BlockWins));
        match engine.evaluate(&Vendor::Junos, "configure") {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!("block → Blocked, got {other:?}"),
        }
        match engine.evaluate(&Vendor::Junos, "telnet 1.2.3.4") {
            Decision::Deny {
                kind: DenyKind::DefaultDeny,
                ..
            } => {}
            other => panic!("no-match → DefaultDeny, got {other:?}"),
        }
    }

    #[test]
    fn summary_carries_mode_for_both_variants() {
        // Pin: PolicyMode round-trips from the loader's VendorPolicy
        // through PolicySummary so the prompt renderer can branch.
        // Without this the unrestricted carve-out collapses to an
        // empty `allowed: ()` block — the LLM would conclude nothing
        // is allowed (false) when actually everything is, gated only
        // by the per-command modal.
        let gated = engine_with_junos(fake_policy(Precedence::BlockWins))
            .summary(&Vendor::Junos)
            .expect("gated summary");
        assert_eq!(gated.mode, PolicyMode::Gated);

        let un = engine_with_junos(unrestricted_policy())
            .summary(&Vendor::Junos)
            .expect("unrestricted summary");
        match un.mode {
            PolicyMode::Unrestricted { warning } => {
                assert_eq!(warning, "test-only warning");
            }
            other => panic!("expected Unrestricted, got {other:?}"),
        }
    }
}
