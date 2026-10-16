//! v4.4.0 — Tauri wiring for `transit_localpty` (the local OS terminal).
//!
//! IPC commands:
//! - `list_available_shells() -> Vec<ShellInfo>` — the "look under the
//!   hood" discovery: which shells/REPLs are installed, with versions.
//! - `open_local_shell(params) -> LocalShellResult` — spawn a shell in a
//!   PTY; returns the backend session id + the tab label.
//! - `disconnect_local_session(session_id)` — direct teardown (the
//!   frontend's standard tab-close uses `ssh::disconnect_session`, which
//!   falls through here).
//!
//! Output rides the SAME `pty:{id}:output` / `pty:{id}:closed` topics as
//! SSH + console (via `ssh::spawn_output_bridge`), so `TerminalPane`
//! needs no transport branch.
//!
//! # Agent-blindness (load-bearing — plan §2, threat model T42)
//!
//! A local shell is HUMAN-only. This module is deliberately NOT wired
//! into the agent's `UnifiedScrollbackSource` / `UnifiedSessionExecutor`
//! (built per-turn in `chat.rs`). That omission is the whole safety
//! story: with no `LocalScrollbackSource` and no local arm on the
//! executor, the agent's `list_open_sessions` / `read_scrollback` /
//! `propose_command` can never reach a local shell. Defense in depth:
//! every local session's vendor is `Vendor::LocalShell`, which ships
//! with no policy and default-denies if it were ever routed to the gate.
//! Do NOT add a `LocalPtyState` argument to any agent-side seam.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;
use transit_localpty::{LocalPtyError, OpenParams, Session};
use uuid::Uuid;

use crate::ssh::spawn_output_bridge;

pub struct LocalPtyState {
    pub sessions: Mutex<HashMap<String, LocalSessionEntry>>,
}

pub struct LocalSessionEntry {
    pub session: Arc<Session>,
    /// Bridge task — translates the session's broadcast output into
    /// `pty:{id}:output` events. Aborted on disconnect.
    pub bridge: tokio::task::JoinHandle<()>,
    /// Tab label (the shell's friendly name, e.g. "zsh").
    pub label: String,
    /// The params this shell was opened with — retained so
    /// `restart_local_shell` can re-spawn the same shell under the SAME
    /// session id (the dead-shell "process exited — press Enter for a new
    /// shell" affordance; plan §3).
    pub params: OpenParams,
}

impl LocalPtyState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for LocalPtyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Stash the state on the app. Called from `lib.rs::setup` alongside
/// `console::install`. No watchers — a local shell has no hot-plug.
pub fn install(app: &AppHandle) {
    app.manage(Arc::new(LocalPtyState::new()));
}

// ---------------------------------------------------------------------
// IPC — open / close
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct LocalShellResult {
    pub session_id: String,
    pub label: String,
}

#[tauri::command]
pub async fn open_local_shell(
    app: AppHandle,
    state: State<'_, Arc<LocalPtyState>>,
    params: OpenParams,
) -> Result<LocalShellResult, String> {
    // Defense in depth: the `[terminal] enabled` off-switch is enforced here
    // too (the frontend also hides the rail). A disabled deployment can't spawn
    // a local shell even via a direct IPC call.
    if !crate::commands::resolve_terminal_enabled() {
        return Err("the local terminal is disabled by configuration".to_string());
    }
    let label = params.label.clone();

    // `Session::open` allocates the PTY, spawns the shell, and starts
    // its own OS threads — quick syscalls, no runtime-blocking wait, so
    // no `spawn_blocking` needed (unlike the console serial open).
    let params_for_restart = params.clone();
    let session = Session::open(params).map_err(|e: LocalPtyError| e.to_string())?;
    let session_id = Uuid::new_v4().to_string();

    let bridge = spawn_output_bridge(
        app.clone(),
        session.subscribe(),
        session.closed_rx(),
        session_id.clone(),
    );

    let entry = LocalSessionEntry {
        session: Arc::new(session),
        bridge,
        label: label.clone(),
        params: params_for_restart,
    };

    state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), entry);

    Ok(LocalShellResult { session_id, label })
}

/// Restart a local shell IN PLACE — re-spawn the same shell under the
/// SAME session id, so the frontend tab/pane resume (the `pty:{id}:*`
/// topics are unchanged). Backs the dead-shell "process exited — press
/// Enter for a new shell" affordance. Mirrors console's reconnect swap.
#[tauri::command]
pub async fn restart_local_shell(
    app: AppHandle,
    state: State<'_, Arc<LocalPtyState>>,
    session_id: String,
) -> Result<(), String> {
    // Same off-switch as `open_local_shell`: if the config flips the terminal
    // off mid-session, don't re-spawn a shell even for an existing tab.
    if !crate::commands::resolve_terminal_enabled() {
        return Err("the local terminal is disabled by configuration".to_string());
    }
    // Snapshot the params (don't hold the lock across Session::open).
    let params = {
        let guard = state.sessions.lock().await;
        let Some(entry) = guard.get(&session_id) else {
            return Err(format!("local session {session_id} not found"));
        };
        entry.params.clone()
    };

    let new_session = Session::open(params).map_err(|e: LocalPtyError| e.to_string())?;
    let new_bridge = spawn_output_bridge(
        app.clone(),
        new_session.subscribe(),
        new_session.closed_rx(),
        session_id.clone(),
    );
    let new_session = Arc::new(new_session);

    let mut guard = state.sessions.lock().await;
    match guard.get_mut(&session_id) {
        Some(entry) => {
            // Abort the old (exited) session's bridge + swap in the new one.
            entry.bridge.abort();
            let old = std::mem::replace(&mut entry.session, new_session);
            entry.bridge = new_bridge;
            drop(guard);
            if let Ok(old_session) = Arc::try_unwrap(old) {
                let _ = old_session.close().await;
            }
            Ok(())
        }
        None => {
            // Closed by the user between the two locks — discard the new one.
            drop(guard);
            new_bridge.abort();
            if let Ok(s) = Arc::try_unwrap(new_session) {
                let _ = s.close().await;
            }
            Err(format!("local session {session_id} was closed"))
        }
    }
}

/// Direct disconnect — symmetric with `open_local_shell`. The frontend's
/// standard tab-close flow uses `ssh::disconnect_session` (which falls
/// through here); this exists for callers that already know the session
/// is local-backed.
#[tauri::command]
pub async fn disconnect_local_session(
    state: State<'_, Arc<LocalPtyState>>,
    session_id: String,
) -> Result<(), String> {
    let entry = state.sessions.lock().await.remove(&session_id);
    let Some(entry) = entry else {
        return Err(format!("local session {session_id} not found"));
    };
    entry.bridge.abort();
    match Arc::try_unwrap(entry.session) {
        Ok(session) => session.close().await.map_err(|e| e.to_string())?,
        Err(_) => {
            tracing::warn!(
                "local session {session_id} had outstanding Arc references at disconnect; \
                 relying on Drop to clean up"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// IPC — shell discovery ("look under the hood")
// ---------------------------------------------------------------------

/// A discovered shell/REPL the user can launch.
#[derive(Debug, Clone, Serialize)]
pub struct ShellInfo {
    /// Stable id (`zsh`, `pwsh`, `wsl-ubuntu`, `python3`).
    pub id: String,
    /// Friendly label for the launcher.
    pub label: String,
    /// Resolved absolute path (transparency — the "under the hood" view).
    pub path: String,
    /// The program string handed to the PTY (bare name or path).
    pub program: String,
    /// Default argv (e.g. `["-l"]` for a login shell).
    pub args: Vec<String>,
    pub kind: ShellKind,
    /// Best-effort version string from `<prog> --version`; `None` when
    /// the shell has no clean version flag or the probe failed.
    pub version: Option<String>,
    /// True for the platform's default interactive shell.
    pub is_default: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    Shell,
    Repl,
    Wsl,
}

/// Enumerate installed shells + versions. Async + `spawn_blocking`: it
/// scans `PATH` and runs `--version` subprocesses, so — like
/// `list_console_driver_status` — it must not run on the Tauri main
/// thread. Treat it as a TanStack query, not per-render.
#[tauri::command]
pub async fn list_available_shells() -> Vec<ShellInfo> {
    // Off-switch consistency: a disabled deployment discloses no shell
    // inventory (the frontend already hides the rail; this closes the
    // direct-IPC path). Skips the subprocess probing entirely.
    if !crate::commands::resolve_terminal_enabled() {
        return Vec::new();
    }
    tokio::task::spawn_blocking(discover_shells)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(?e, "shell discovery task panicked; reporting empty");
            Vec::new()
        })
}

struct Candidate {
    id: &'static str,
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    kind: ShellKind,
    version_arg: Option<&'static str>,
}

#[cfg(not(target_os = "windows"))]
fn candidates() -> Vec<Candidate> {
    vec![
        Candidate {
            id: "zsh",
            label: "Zsh",
            program: "zsh",
            args: &["-l"],
            kind: ShellKind::Shell,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "bash",
            label: "Bash",
            program: "bash",
            args: &["-l"],
            kind: ShellKind::Shell,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "fish",
            label: "fish",
            program: "fish",
            args: &["-l"],
            kind: ShellKind::Shell,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "sh",
            label: "sh",
            program: "sh",
            args: &[],
            kind: ShellKind::Shell,
            version_arg: None,
        },
        Candidate {
            id: "pwsh",
            label: "PowerShell",
            program: "pwsh",
            args: &[],
            kind: ShellKind::Shell,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "python3",
            label: "Python 3",
            program: "python3",
            args: &[],
            kind: ShellKind::Repl,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "node",
            label: "Node.js",
            program: "node",
            args: &[],
            kind: ShellKind::Repl,
            version_arg: Some("--version"),
        },
    ]
}

#[cfg(target_os = "windows")]
fn candidates() -> Vec<Candidate> {
    vec![
        Candidate {
            id: "pwsh",
            label: "PowerShell 7",
            program: "pwsh.exe",
            args: &[],
            kind: ShellKind::Shell,
            version_arg: Some("--version"),
        },
        Candidate {
            id: "powershell",
            label: "Windows PowerShell",
            program: "powershell.exe",
            args: &[],
            kind: ShellKind::Shell,
            version_arg: None,
        },
        Candidate {
            id: "cmd",
            label: "Command Prompt",
            program: "cmd.exe",
            args: &[],
            kind: ShellKind::Shell,
            version_arg: None,
        },
        Candidate {
            id: "python",
            label: "Python",
            program: "python.exe",
            args: &[],
            kind: ShellKind::Repl,
            version_arg: Some("--version"),
        },
    ]
}

fn discover_shells() -> Vec<ShellInfo> {
    let default_program = default_shell_program();
    let default_base = basename(&default_program);

    let mut out: Vec<ShellInfo> = candidates()
        .into_iter()
        .filter_map(|c| {
            let path = resolve_on_path(c.program)?;
            // Apple's CLT shim: on a Mac without the Command Line Tools,
            // `/usr/bin/python3` is an installer trampoline — EXECUTING it
            // (even `--version`) pops the OS "install the developer tools"
            // dialog. Skip it entirely (don't list, don't probe) so opening
            // the Terminal tab can never trigger an install prompt; a real
            // interpreter elsewhere on PATH still lists normally.
            #[cfg(target_os = "macos")]
            if is_clt_stub_python3(&path, clt_installed) {
                return None;
            }
            let version = c.version_arg.and_then(|arg| probe_version(&path, arg));
            let is_default = basename(&path) == default_base;
            Some(ShellInfo {
                id: c.id.to_string(),
                label: c.label.to_string(),
                path,
                program: c.program.to_string(),
                args: c.args.iter().map(|s| s.to_string()).collect(),
                kind: c.kind,
                version,
                is_default,
            })
        })
        .collect();

    out.append(&mut platform_extra());
    out
}

/// WSL distros on Windows; nothing elsewhere. A function (not a cfg'd
/// statement) so `out` is always mutated — never trips `unused_mut` on
/// Unix under `clippy -D warnings`.
#[cfg(target_os = "windows")]
fn platform_extra() -> Vec<ShellInfo> {
    discover_wsl_distros()
}
#[cfg(not(target_os = "windows"))]
fn platform_extra() -> Vec<ShellInfo> {
    Vec::new()
}

/// The platform default interactive shell program.
#[cfg(not(target_os = "windows"))]
fn default_shell_program() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/zsh".to_string())
}

#[cfg(target_os = "windows")]
fn default_shell_program() -> String {
    if resolve_on_path("pwsh.exe").is_some() {
        "pwsh.exe".to_string()
    } else {
        "powershell.exe".to_string()
    }
}

/// Enumerate installed WSL distributions (`wsl -l -q`), each launchable
/// as `wsl.exe -d <distro>`. Best-effort; empty on any failure.
#[cfg(target_os = "windows")]
fn discover_wsl_distros() -> Vec<ShellInfo> {
    let Some(wsl) = resolve_on_path("wsl.exe") else {
        return Vec::new();
    };
    let Ok(output) = std::process::Command::new(&wsl).args(["-l", "-q"]).output() else {
        return Vec::new();
    };
    // `wsl -l -q` emits UTF-16LE. Decode leniently: strip NULs and CRs.
    let text: String = output
        .stdout
        .chunks(2)
        .filter_map(|c| c.first().copied())
        .map(|b| b as char)
        .collect();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // Docker Desktop's plumbing distros are real WSL entries but not
        // user shells — launching them lands in a BusyBox jail (or fails);
        // seen on the first Windows smoke test (2026-08-04). Hide them.
        .filter(|l| {
            let lower = l.to_lowercase();
            lower != "docker-desktop" && lower != "docker-desktop-data"
        })
        .map(|distro| ShellInfo {
            id: format!("wsl-{}", distro.to_lowercase().replace(' ', "-")),
            label: format!("{distro} (WSL)"),
            path: wsl.clone(),
            program: "wsl.exe".to_string(),
            args: vec!["-d".to_string(), distro.to_string()],
            kind: ShellKind::Wsl,
            version: None,
            is_default: false,
        })
        .collect()
}

/// Resolve `program` to an absolute path via `PATH` (respecting
/// `PATHEXT` on Windows). Returns `None` when not installed.
fn resolve_on_path(program: &str) -> Option<String> {
    let p = std::path::Path::new(program);
    if p.is_absolute() {
        return p.is_file().then(|| program.to_string());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let direct = dir.join(program);
        if direct.is_file() {
            return Some(direct.to_string_lossy().into_owned());
        }
        #[cfg(target_os = "windows")]
        if std::path::Path::new(program).extension().is_none() {
            for ext in std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
                .split(';')
            {
                let with_ext = dir.join(format!("{program}{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

/// Best-effort version string: run `<path> <arg>`, take the first
/// non-empty line (some tools print to stderr).
///
/// BOUNDED. A hostile or broken PATH entry that ignores `--version` and blocks
/// (drops into an interactive prompt, waits on stdin, etc.) must not hang shell
/// discovery — which runs on a shared blocking-pool thread. So we spawn with a
/// null stdin (an ignored `--version` then hits EOF and exits) and poll for
/// exit with a hard deadline, killing a runaway child rather than waiting on an
/// unbounded `.output()`. `--version` output is tiny, so reading the pipes
/// after exit can't deadlock in practice; a pathological flood just trips the
/// deadline and yields `None`.
fn probe_version(path: &str, arg: &str) -> Option<String> {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let mut child = std::process::Command::new(path)
        .arg(arg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }

    let mut buf = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut buf);
    }
    if buf.trim().is_empty() {
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut buf);
        }
    }
    buf.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// True when `resolved_path` is Apple's Xcode Command Line Tools shim for
/// `python3` rather than a real interpreter. macOS ships `/usr/bin/python3`
/// on every install; without the CLT it is not a Python — it is the
/// installer trampoline. `clt_installed` is a closure so the (subprocess)
/// check runs only when the path actually is the shim location.
#[cfg(any(target_os = "macos", test))]
fn is_clt_stub_python3(resolved_path: &str, clt_installed: impl FnOnce() -> bool) -> bool {
    resolved_path == "/usr/bin/python3" && !clt_installed()
}

/// Whether the Xcode Command Line Tools are actually installed.
/// `xcode-select -p` reports the active developer directory and exits
/// non-zero when there is none; unlike executing a shim, it never
/// triggers the OS install dialog — which is the point of asking it
/// before any probe. Errs toward `false` (skip the shim) on any failure.
#[cfg(target_os = "macos")]
fn clt_installed() -> bool {
    std::process::Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Lowercased final path component, for case-insensitive default match.
fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_on_path_finds_a_real_shell() {
        // Every CI platform has *some* shell on PATH. On Unix `sh`
        // exists; on Windows `cmd.exe` does.
        #[cfg(not(target_os = "windows"))]
        let probe = "sh";
        #[cfg(target_os = "windows")]
        let probe = "cmd.exe";
        assert!(
            resolve_on_path(probe).is_some(),
            "expected to resolve {probe} on PATH"
        );
    }

    #[test]
    fn resolve_on_path_rejects_missing() {
        assert!(resolve_on_path("transit-no-such-shell-xyzzy").is_none());
    }

    #[test]
    fn discovery_marks_exactly_one_default() {
        // Not asserting *which* shell (CI-dependent), only that discovery
        // runs and never marks two defaults.
        let shells = discover_shells();
        let defaults = shells.iter().filter(|s| s.is_default).count();
        assert!(defaults <= 1, "at most one default shell, got {defaults}");
    }

    #[test]
    fn clt_stub_python3_is_skipped_when_tools_absent() {
        // The shim path with no CLT: this is the exact configuration that
        // pops the macOS install dialog if executed — must be skipped.
        assert!(is_clt_stub_python3("/usr/bin/python3", || false));
    }

    #[test]
    fn usr_bin_python3_is_kept_when_tools_present() {
        // With the CLT installed the shim resolves to a real interpreter.
        assert!(!is_clt_stub_python3("/usr/bin/python3", || true));
    }

    #[test]
    fn non_shim_python3_is_kept_even_without_tools() {
        // A Homebrew/pyenv/user interpreter is a real binary, not Apple's
        // shim — the CLT check must not even run for it (the closure
        // panics to prove laziness).
        assert!(!is_clt_stub_python3("/opt/homebrew/bin/python3", || {
            panic!("CLT check must not run for a non-shim path")
        }));
    }

    #[test]
    fn basename_is_case_insensitive_final_component() {
        assert_eq!(basename("/bin/zsh"), "zsh");
        // Lowercasing, tested portably (backslashes aren't separators on
        // Unix, so a Windows path case is gated to Windows).
        assert_eq!(basename("/usr/local/bin/PWSH"), "pwsh");
        #[cfg(target_os = "windows")]
        assert_eq!(basename("C:\\Windows\\System32\\cmd.EXE"), "cmd.exe");
    }
}
