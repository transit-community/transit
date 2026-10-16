//! Concrete backend implementations.
//!
//! Each backend is a separate file. The registry constructs one of
//! each at startup and routes `SecretRef` → first-supports.

pub(crate) mod env;
pub(crate) mod keyring;
pub(crate) mod op;
pub(crate) mod ssh_agent;
pub(crate) mod ssh_key;
