pub mod agent_dispatch;
pub mod api_scrollback_source;
pub mod api_session;
pub mod app_lifecycle;
pub mod capture;
pub mod chat;
pub mod chat_history;
pub mod chat_snippet;
pub mod chatgpt_auth;
pub mod commands;
pub mod console;
pub mod console_scrollback_source;
pub mod files;
pub mod fonts;
pub mod local_models;
pub mod local_shell;
pub mod menu;
mod pcap;
pub mod provider_keys;
pub mod scoped_session_view;
pub mod session_export;
pub mod session_log;
pub mod ssh;
pub mod ssh_scrollback_source;

use std::sync::Arc;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Wire the tracing subscriber before anything can emit — without
    // this every backend `tracing` line is a silent no-op.
    // The diagnostic-log settings are read BEFORE the subscriber exists,
    // which is why they come from config rather than from an IPC call: a
    // toggle that needed the app running could not configure the app's own
    // startup logging. Applies on next launch, and the UI says so.
    transit_core::log::init(commands::resolve_file_logging());

    // AppState — which loads the policy YAMLs from the bundled
    // resources dir — is constructed inside the `.setup()` callback
    // below, because resolving `app.path().resource_dir()` is the
    // canonical way to find bundled assets on every OS and that API
    // needs an `AppHandle`.
    //
    // The chat state's client factory reads the user's provider key from
    // the OS keychain and the Strict-TLS setting from config PER SEND, so
    // nothing network-shaped is built at startup and nothing is contacted
    // until the user sends a message.
    // Sign in with ChatGPT state: shared by the chat factory (tokens per
    // send) and the IPC commands (sign-in / sign-out / status).
    let chatgpt_state = Arc::new(chatgpt_auth::ChatGptState::new());
    let chat_state = chat::ChatState::new(Arc::clone(&chatgpt_state));

    let mut builder = tauri::Builder::default()
        // Clipboard plugin — needed for the Phase 2c quick-copy-paste
        // feature. macOS WKWebView blocks `navigator.clipboard.readText`
        // by default; routing through this plugin's `readText` /
        // `writeText` IPC commands bypasses the WebKit gate. The
        // capability surface (`capabilities/default.json`) restricts
        // the frontend to those two specific commands — no clipboard
        // history / image / clear access.
        .plugin(tauri_plugin_clipboard_manager::init());

    builder = builder
        // Opener plugin — `openUrl(url)` from `@tauri-apps/plugin-opener`
        // routes the few documentation links (Settings → About) through
        // the OS default browser. The capability allow-list in
        // `capabilities/default.json` pins WHICH URLs may be opened.
        .plugin(tauri_plugin_opener::init())
        // Dialog plugin — session export / settings bundle / pcap /
        // import flows use the native Save + Open dialogs from the
        // webview; capabilities/default.json grants `dialog:allow-save`
        // + `dialog:allow-open` (no open-multiple / message / ask).
        // v6.3.0's save_chat_snippet drives the Save dialog RUST-side
        // (DialogExt), which the capability surface doesn't govern —
        // capabilities gate webview→plugin IPC only.
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // Build AppState here so we have an AppHandle for path
            // resolution. `resolve_policies_dir(app)` routes through
            // Tauri's `PathResolver::resource_dir()` in release —
            // the OS-agnostic API that knows where the installer
            // actually placed bundled assets. AppState construction
            // is async (HostKeyStore reads from disk) so we spin a
            // dedicated single-thread runtime to block on it; Tauri's
            // async_runtime is reserved for tasks that need to outlive
            // setup.
            let policies_dir = commands::resolve_policies_dir(app);
            let user_policies_dir = commands::resolve_user_policies_dir();
            let inventory_path = commands::inventory_path();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let app_state = runtime
                .block_on(commands::AppState::new(
                    inventory_path,
                    policies_dir,
                    user_policies_dir,
                ))
                .map_err(std::io::Error::other)?;
            drop(runtime);
            app.manage(app_state);

            if cfg!(debug_assertions) {
                // Best-effort: `transit_core::log::init()` (top of
                // `run()`) claims the global `log` facade via its
                // tracing-log bridge, so this plugin's logger can no
                // longer attach. Warn-and-continue instead of `?` —
                // failing app startup over a duplicate dev logger
                // would be absurd; backend logs already flow through
                // the tracing subscriber.
                if let Err(e) = app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                ) {
                    tracing::warn!(error = %e, "tauri_plugin_log attach skipped");
                }
            }
            // Spawn the cache sweeper on Tauri's async runtime. Setup
            // runs before `app.run()` enters the event loop, so a raw
            // `tokio::spawn` panics with "no reactor running" — but
            // `tauri::async_runtime::spawn` queues onto the runtime
            // that comes up moments later. Must run AFTER
            // `app.manage(app_state)` above so the state lookup
            // succeeds.
            let secrets = Arc::clone(&app.state::<commands::AppState>().secrets);
            tauri::async_runtime::spawn(async move {
                secrets.run_cache_sweep_loop().await;
            });

            // Phase 7b C18 — start the USB-to-serial hot-plug watcher
            // and forward Add/Remove events as `console:plug`. Cable
            // discovery is best-effort; an OS that returns an empty
            // port list just means an empty sidebar section.
            console::install(app.handle());

            // v4.4.0 — stash the local-shell (PTY) session table. No
            // watcher (a local shell has no hot-plug). HUMAN-ONLY surface,
            // deliberately absent from the agent's session sources (§2).
            crate::local_shell::install(app.handle());

            // v5.0.0 — stash the Files (SFTP) session table. Also a
            // HUMAN-ONLY surface: passed to no agent-side constructor and
            // part of no shared transport dispatch (plan §2, T43).
            crate::files::install(app.handle());
            // v6.0.0 — the PCaps surface's capture registry.
            crate::pcap::install(app.handle());

            // v1.4.0 — install the native menu (Transit's first; the
            // View → Button Bar vehicle) and round-trip its toggle to the
            // frontend, which owns the `showButtonBar` pref. See `menu`.
            let (button_bar_item, broadcast_bar_item) = crate::menu::install(app.handle())?;
            app.manage(crate::menu::MenuState::new(
                button_bar_item,
                broadcast_bar_item,
            ));
            app.on_menu_event(|app, event| {
                if event.id.as_ref() == crate::menu::MENU_ID_BUTTON_BAR {
                    let _ = app.emit("menu:toggle-button-bar", ());
                } else if event.id.as_ref() == crate::menu::MENU_ID_BROADCAST_BAR {
                    let _ = app.emit("menu:toggle-broadcast-bar", ());
                } else if event.id.as_ref() == crate::menu::MENU_ID_CLEAR_TERMINAL {
                    let _ = app.emit("menu:clear-terminal", ());
                } else if event.id.as_ref() == crate::menu::MENU_ID_JUMP_TO_SESSION {
                    let _ = app.emit("menu:jump-to-session", ());
                } else if event.id.as_ref() == crate::menu::MENU_ID_SORT_TABS {
                    let _ = app.emit("menu:sort-tabs", ());
                } else if event.id.as_ref() == crate::menu::MENU_ID_ABOUT {
                    // Non-macOS "About Transit" (macOS uses the native
                    // panel). The frontend opens Settings → About.
                    let _ = app.emit("menu:about", ());
                }
            });

            Ok(())
        })
        .manage(chat_state)
        .manage(chatgpt_state)
        // Phase 6: pending propose-command + ask-user oneshots,
        // keyed by request_id (uuid). C8's IPC commands look up
        // entries here when the user clicks Approve / Deny / Send
        // in the modal / inline card.
        .manage(agent_dispatch::ApprovalState::new())
        // v1.4.0 — "warn before quit" confirm latch (app_lifecycle).
        .manage(app_lifecycle::ExitState::new())
        // Phase 3 — active session-log writer tasks.
        .manage(session_log::SessionLogState::default())
        .invoke_handler(tauri::generate_handler![
            commands::list_devices,
            commands::list_auth_profiles,
            commands::add_device,
            commands::update_device,
            commands::bulk_update_devices,
            commands::delete_device,
            commands::add_auth_profile,
            commands::update_auth_profile,
            commands::delete_auth_profile,
            commands::rename_group,
            commands::add_group,
            commands::delete_group,
            commands::set_device_group,
            commands::list_groups,
            // v4.0.0 — API sessions (UniFi & other REST controllers).
            commands::list_api_sessions,
            commands::add_api_session,
            commands::update_api_session,
            commands::delete_api_session,
            commands::enroll_api_session_secret,
            commands::api_send_request,
            commands::register_api_session,
            commands::close_api_session,
            commands::api_session_history,
            // Self-signed controller cert-pin TOFU (v4.3.0, threat-model T40).
            commands::api_pending_cert,
            commands::api_trust_cert,
            commands::api_set_session_auth,
            // Bulk connection import (ssh_config / CSV / SecureCRT).
            commands::preview_import,
            commands::import_connections,
            // v6.2.0 — NetBox inventory sync (diff + atomic apply; T49).
            commands::preview_netbox_sync,
            commands::apply_netbox_sync,
            // v2.3.0 — CSV export of the inventory (reverse of import).
            commands::export_connections,
            // v6.1.0 — Transit-to-Transit settings bundle. References
            // only (Rule 1); no secrets, no host-key pins.
            commands::export_settings_bundle,
            commands::import_settings_bundle,
            commands::probe_ssh_keys,
            // BYOP Phase 2 — read/persist the user policy directory.
            commands::get_policy_settings,
            commands::set_user_policies_dir,
            // Network — Strict TLS (provider trust anchors; threat-model T27).
            commands::get_network_settings,
            commands::set_strict_tls,
            // Phase 2a — secret backends, enrollment, availability.
            commands::secret_backend_availability,
            commands::test_secret_resolve,
            commands::enroll_secret,
            // Phase 2b — SSH connect / disconnect / TOFU.
            ssh::connect_device,
            ssh::disconnect_session,
            ssh::list_open_sessions,
            ssh::send_input,
            ssh::resize_pty,
            ssh::clear_scrollback,
            ssh::verify_host_key,
            ssh::weak_crypto_decision,
            // Interactive auth (v6.1.0). `submit_kbi_answers` is the
            // SECOND command that accepts a credential across IPC —
            // write-only, nothing persisted (Rule 1; threat-model T46).
            ssh::submit_kbi_answers,
            ssh::cancel_kbi,
            // Phase 5d.A5 — chat sessions backed by LlmClient.
            chat::chat_create,
            chat::chat_list,
            chat::chat_destroy,
            chat::chat_messages,
            chat::chat_set_model,
            chat::chat_send_message,
            chat::chat_cancel,
            // v2.7.0 — per-chat device scope (T31). User-only write;
            // enforcement is the scoped wrappers built per turn.
            chat::chat_set_scope,
            // v4.0.0 — per-chat opt-in to auto-approve the agent's read-only
            // GETs (propose_api_call). User-only write; the gate still runs.
            chat::chat_set_auto_approve_gets,
            // Provider API keys (kept in the OS keychain, never
            // round-tripped back over IPC — Rule 1).
            provider_keys::provider_key_set,
            provider_keys::provider_key_clear,
            provider_keys::provider_keys_status,
            // Live model catalogue per enrolled key (metadata only).
            provider_keys::provider_models_list,
            // Sign in with ChatGPT (preview): browser OAuth on a loopback
            // callback; tokens stay Rust-side (Rule 1). T55.
            chatgpt_auth::chatgpt_signin_start,
            chatgpt_auth::chatgpt_signin_cancel,
            chatgpt_auth::chatgpt_signout,
            chatgpt_auth::chatgpt_status,
            chatgpt_auth::provider_openai_method_set,
            // Phase 6 C8 — propose-command modal + ask-user inline
            // card reply paths. Mirrors `verify_host_key`'s
            // pending-tofu HashMap pattern.
            agent_dispatch::respond_propose_command,
            agent_dispatch::respond_ask_user,
            // Phase 7b C18 — console cable IPCs.
            console::list_console_cables,
            console::connect_console_cable,
            console::disconnect_console_session,
            // Phase 5 — serial BREAK signal (interrupt boot / ROMMON).
            console::console_send_break,
            // Phase 7b C22 — DriverKit detection.
            console::list_console_driver_status,
            local_shell::open_local_shell,
            local_shell::disconnect_local_session,
            local_shell::restart_local_shell,
            local_shell::list_available_shells,
            commands::terminal_enabled,
            // v5.0.0 — Files (SFTP). A HUMAN surface: none of these is an
            // agent tool (Rule 2 stays at five) and none returns a
            // credential (Rule 1). Disjoint `files_*` namespace — Files
            // sessions never enter the shared terminal dispatch.
            commands::files_enabled,
            commands::pcap_enabled,
            commands::pcap_agent_access_enabled,
            pcap::pcap_open_file,
            pcap::pcap_list_open,
            pcap::pcap_close,
            pcap::pcap_rows,
            pcap::pcap_packet_detail,
            pcap::pcap_packet_bytes,
            pcap::pcap_conversations,
            pcap::pcap_findings,
            pcap::pcap_protocol_tree,
            pcap::pcap_overview,
            pcap::pcap_validate_filter,
            pcap::pcap_filter_fields,
            pcap::pcap_list_interfaces,
            pcap::pcap_open_captures_dir,
            pcap::pcap_captures_dir,
            commands::pcap_configured_dir,
            commands::set_pcap_dir,
            commands::developer_settings,
            commands::set_developer_settings,
            commands::get_agent_chat_settings,
            commands::set_agent_chat_settings,
            chat_snippet::save_chat_snippet,
            commands::open_log_dir,
            pcap::pcap_capture_start,
            pcap::pcap_capture_stop,
            files::files_connect,
            files::files_reconnect,
            files::files_disconnect,
            files::files_list_dir,
            files::files_mkdir,
            files::files_rename,
            files::files_delete,
            files::files_local_list_dir,
            files::files_local_roots,
            files::files_local_mkdir,
            files::files_local_rename,
            files::files_local_delete,
            files::files_check_conflicts,
            files::files_enqueue,
            files::files_cancel,
            // Phase 8b — session-export with re-redaction + optional
            // age-passphrase encryption.
            session_export::export_session,
            // Phase 3 — continuous session logging (start/stop/list).
            session_log::start_session_log,
            session_log::stop_session_log,
            session_log::list_session_logs,
            // Phase 3 — command-output capture + comparison (diffing).
            capture::capture_command,
            capture::run_collection,
            capture::list_captures,
            capture::read_capture,
            capture::delete_capture,
            capture::diff_captures,
            capture::captures_dir_path,
            // v1.0.2 — Settings font picker. Read-only enumeration of
            // installed monospace family names.
            fonts::list_monospace_fonts,
            // v1.4.0 — warn-before-quit confirm reply.
            app_lifecycle::confirm_quit,
            // v1.4.0 — native-menu checkmark sync (View → Button Bar).
            menu::set_menu_checked,
            // v3.0.0 BYOM (A2) — local-models config + status probe.
            // User-facing IPC, NOT agent tools (Rule 2 surface stays 4);
            // the agent has no path to endpoint configuration.
            commands::get_local_models_settings,
            commands::set_local_models_settings,
            local_models::local_models_status,
            // v3.0.0 BYOM (A3) — custom endpoints (remote Ollama /
            // OpenAI-compat) + write-only bearer tokens (Rule 1).
            local_models::local_endpoints_list,
            local_models::local_endpoint_upsert,
            local_models::local_endpoint_delete,
            local_models::local_endpoint_set_token,
            local_models::local_endpoint_clear_token,
            local_models::local_endpoints_status,
        ]);

    // v1.4.0 — build then run with a RunEvent handler so Cmd+Q /
    // window-close can be vetoed for a "quit anyway?" confirm while
    // sessions are still open (app_lifecycle::handle_run_event).
    builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(app_lifecycle::handle_run_event);
}
