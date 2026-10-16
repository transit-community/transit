//! Errors raised by the policy loader.
//!
//! Evaluation itself does not return errors — it always produces a
//! `Decision`. Errors are reserved for the load path (bad YAML, bad
//! regex, missing file, etc.), which runs once at startup and should
//! fail loud if a policy file is broken rather than silently
//! degrading to "deny everything".

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy file {path} could not be read: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("policy file {path} failed to parse: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml_bw::Error,
    },

    /// A regex in the policy file did not compile. Includes the
    /// offending pattern so the error message points the operator
    /// at the exact line to fix.
    #[error("policy file {path}: invalid regex {pattern:?}: {source}")]
    Regex {
        path: PathBuf,
        pattern: String,
        #[source]
        source: regex::Error,
    },

    /// Policy filename's stem did not match a known `Vendor` variant.
    /// E.g. `policies/foobar.yaml` — we don't know what `foobar` is,
    /// so refuse to load rather than silently mis-route.
    #[error("policy file {path}: unknown vendor stem {stem:?}")]
    UnknownVendor { path: PathBuf, stem: String },

    /// Cross-field schema constraint violated — e.g.
    /// `mode: unrestricted` without a `warning:`, or `mode: gated`
    /// without a `precedence:`. Distinct from a YAML parse error
    /// because the YAML itself is well-formed; only the field
    /// combination is invalid.
    #[error("policy file {path} schema: {detail}")]
    Schema { path: PathBuf, detail: String },
}
