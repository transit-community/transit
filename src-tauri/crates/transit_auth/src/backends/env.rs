//! `env` backend — read from environment variable.
//!
//! Trivial. The shell owns enrollment; we just look the variable up
//! and wrap the value. No preflight needed — env access is reliable
//! on every platform.

use async_trait::async_trait;
use secrecy::SecretString;
use transit_core::inventory::SecretRef;

use crate::{BackendAvailability, BackendError, SecretBackend};

const KIND: &str = "env";

pub(crate) struct EnvBackend;

impl EnvBackend {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn availability(&self) -> BackendAvailability {
        BackendAvailability::Ready
    }
}

#[async_trait]
impl SecretBackend for EnvBackend {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn supports(&self, refp: &SecretRef) -> bool {
        matches!(refp, SecretRef::Env { .. })
    }

    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        let SecretRef::Env { var } = refp else {
            return Err(BackendError::unsupported(
                KIND,
                "resolve_value (wrong kind)",
            ));
        };
        match std::env::var(var) {
            Ok(value) => Ok(SecretString::from(value)),
            Err(std::env::VarError::NotPresent) => Err(BackendError::NotFound { kind: KIND }),
            Err(std::env::VarError::NotUnicode(_)) => Err(BackendError::ResolveFailed {
                detail: format!("env var '{var}' is not valid UTF-8"),
            }),
        }
    }

    async fn enroll(&self, _refp: &SecretRef, _value: SecretString) -> Result<(), BackendError> {
        // The shell owns the env var. We can't `setenv` from inside
        // our process and have it visible to a future Transit launch.
        Err(BackendError::unsupported(KIND, "enroll"))
    }
}
