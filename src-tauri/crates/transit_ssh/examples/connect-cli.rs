//! Connect to a device from `transit.toml` and bridge stdin/stdout
//! to the remote PTY. Run from the workspace root:
//!
//! ```text
//! cd src-tauri
//! cargo run --example connect-cli -- vEX1
//! ```
//!
//! Useful for smoke-testing the russh + secret-backend integration
//! without launching Tauri. The example auto-trusts on first-seen
//! host keys (writes them to `known_hosts.toml`); subsequent runs
//! enforce the pin.
//!
//! Exit with Ctrl-D (sends EOF to the remote shell).

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};
use transit_auth::SecretRegistry;
use transit_core::inventory::load;
use transit_ssh::{ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, Session};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let Some(device_id) = args.get(1).cloned() else {
        eprintln!("usage: connect-cli <device-id>");
        return ExitCode::FAILURE;
    };

    let inventory_path = std::env::var("TRANSIT_INVENTORY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Default: <project_root>/transit.toml when run from src-tauri.
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("transit.toml"))
                .unwrap_or_else(|| std::path::PathBuf::from("transit.toml"))
        });

    let inv = match load(&inventory_path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("failed to load {}: {e}", inventory_path.display());
            return ExitCode::FAILURE;
        }
    };

    let device = match inv.devices.iter().find(|d| d.id == device_id) {
        Some(d) => d,
        None => {
            eprintln!("device '{device_id}' not in inventory");
            return ExitCode::FAILURE;
        }
    };
    let auth = match inv.auth_profiles.get(&device.auth) {
        Some(a) => a,
        None => {
            eprintln!("auth profile '{}' not found for device", device.auth);
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "connecting to {}@{}:{} (vendor={}, auth_backend={})",
        auth.username,
        device.host,
        device.port,
        device.vendor.as_str(),
        match &auth.secret {
            transit_core::inventory::SecretRef::Keyring { .. } => "keyring",
            transit_core::inventory::SecretRef::SshAgent { .. } => "ssh_agent",
            transit_core::inventory::SecretRef::Op { .. } => "op",
            transit_core::inventory::SecretRef::Env { .. } => "env",
            transit_core::inventory::SecretRef::SshKey { .. } => "ssh_key",
            transit_core::inventory::SecretRef::EncryptedFile { .. } => "encrypted_file",
            transit_core::inventory::SecretRef::Prompt => "prompt (interactive)",
        }
    );

    let secrets = Arc::new(SecretRegistry::standard());
    let host_keys_path = match HostKeyStore::default_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not resolve known_hosts path: {e}");
            return ExitCode::FAILURE;
        }
    };
    let host_keys = match HostKeyStore::open(host_keys_path).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("could not open known_hosts: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Auto-trust on first-seen ONLY. The example is for smoke testing,
    // not for production use — the GUI flow makes the user confirm. A
    // CHANGED key is never auto-approved, even here: rotate via the
    // GUI's changed-key warning dialog.
    let (confirm_tx, mut confirm_rx) = mpsc::channel::<HostKeyConfirmRequest>(4);
    // The example drives stored-credential auth only; an interactive
    // prompt has no console UI here, so the request channel is inert.
    let (kbi_tx, _kbi_rx) = mpsc::channel::<transit_ssh::KbiPromptRequest>(1);
    tokio::spawn(async move {
        while let Some(req) = confirm_rx.recv().await {
            match &req.previous_fingerprint {
                Some(prev) => {
                    eprintln!(
                        "[example] HOST KEY CHANGED for {}:{} — pinned {}, server sent {} ({}). \
                         Declining; verify and replace via the GUI dialog.",
                        req.host, req.port, prev, req.fingerprint, req.algorithm
                    );
                    let _ = req.responder.send(false);
                }
                None => {
                    eprintln!(
                        "[example] auto-trusting first-seen host key for {}:{} ({}: {})",
                        req.host, req.port, req.algorithm, req.fingerprint
                    );
                    let _ = req.responder.send(true);
                }
            }
        }
    });

    let connection = match Connection::connect(ConnectParams {
        device_id: device.id.clone(),
        host: device.host.clone(),
        port: device.port,
        username: auth.username.clone(),
        secret_ref: auth.secret.clone(),
        auth: secrets,
        host_keys,
        confirm_tx,
        kbi_tx,
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("authenticated; opening PTY shell");

    // Example CLI is vendor-agnostic; pass `Unknown` so no
    // paging-init bytes get sent. Real connects (via the desktop
    // shell) source vendor from inventory.
    let session = match Session::open(
        &connection,
        "xterm-256color",
        80,
        24,
        transit_core::inventory::Vendor::Unknown,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("session open failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut output = session.subscribe();
    let mut stdout = tokio::io::stdout();

    // Forward PTY → stdout.
    let printer = tokio::spawn(async move {
        loop {
            match output.recv().await {
                Ok(bytes) => {
                    let _ = stdout.write_all(&bytes).await;
                    let _ = stdout.flush().await;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("[example] lagged: dropped {n} chunks");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Forward stdin → PTY. Ctrl-D in raw stdin sends EOF to the
    // line-buffered reader, which closes the loop cleanly.
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = stdin_lines.next_line().await {
        let mut payload = line.into_bytes();
        payload.push(b'\n');
        if session.send_input(Bytes::from(payload)).await.is_err() {
            break;
        }
    }

    eprintln!("\n[example] stdin closed; tearing down session");
    let _ = session.close().await;
    printer.abort();
    drop(connection);

    ExitCode::SUCCESS
}
