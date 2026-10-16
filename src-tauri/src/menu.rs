//! Native application menu (v1.4.0). Transit's first menu bar — the vehicle
//! for SecureCRT-style **View → Button Bar**.
//!
//! Because a custom menu replaces the macOS default, the standard App / Edit /
//! Window items are re-added via `PredefinedMenuItem` so Quit / Copy / Paste /
//! Undo keep working. The macOS-only Hide / Hide Others / Show All items are
//! gated to macOS (see `install` — they orphan the window on Windows). The
//! ONE custom item is the checkable "Button
//! Bar"; its state lives in the frontend (`preferences.showButtonBar`, a
//! localStorage pref Rust can't read at startup), so:
//!
//!   - clicking it emits `menu:toggle-button-bar`; the frontend flips the pref;
//!   - the frontend mirrors the pref back into the checkmark via the
//!     `set_menu_checked` command (also covers the bar's own "Hide" affordance
//!     and the initial post-load sync).

use tauri::menu::{
    CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItemBuilder, PredefinedMenuItem,
    SubmenuBuilder,
};
use tauri::{AppHandle, State, Wry};

/// Menu id for the checkable View → Button Bar item. Shared with the
/// `set_menu_checked` command + the frontend's `useNativeMenu` sync.
pub const MENU_ID_BUTTON_BAR: &str = "view-button-bar";

/// Menu id for the checkable View → Broadcast Input item (v2.4.0). Same
/// round-trip pattern as the Button Bar: click emits
/// `menu:toggle-broadcast-bar`, the frontend flips `showBroadcastBar`, and
/// `set_menu_checked` mirrors the checkmark back.
pub const MENU_ID_BROADCAST_BAR: &str = "view-broadcast-bar";

/// Menu id for the View → Clear Terminal action item (CmdOrCtrl+Shift+K).
/// A plain action item (no checkable state), so unlike the Button Bar it
/// needs no `MenuState`/`set_menu_checked` wiring — clicking it emits
/// `menu:clear-terminal` and the frontend clears the active session.
pub const MENU_ID_CLEAR_TERMINAL: &str = "view-clear-terminal";

/// Window → Jump to Session… — emits `menu:jump-to-session`, which the
/// frontend turns into "open the command palette" (its Sessions group is
/// already a per-session focus list). The menu item exists purely for
/// DISCOVERABILITY: the palette has always been Cmd/Ctrl+K, but a user
/// with thirty tabs has no way to learn that from the UI.
pub const MENU_ID_JUMP_TO_SESSION: &str = "window-jump-to-session";

/// Window → Sort Tabs Alphabetically — emits `menu:sort-tabs`. A
/// one-shot reorder; new tabs still append.
pub const MENU_ID_SORT_TABS: &str = "window-sort-tabs";

/// Menu id for the App → About Transit action item on **non-macOS**.
///
/// macOS keeps the native `PredefinedMenuItem::about` panel (rendered by
/// AppKit from the `.app` bundle's Info.plist). On Windows/Linux a
/// predefined `About(None)` is a no-op — muda's Windows handler only
/// fires for `About(Some(metadata))` and predefined items don't emit a
/// `MenuEvent` there either, so "About Transit" did nothing (bug through
/// v2.2.7). We instead use a custom action item that emits `menu:about`
/// via `on_menu_event`; the frontend opens Settings → About (which
/// already shows the version, license, and Report-an-issue link).
pub const MENU_ID_ABOUT: &str = "app-about";

/// Managed handle to the checkable menu item(s), so `set_menu_checked` can
/// reflect frontend state changes back into the native menu. `CheckMenuItem`
/// is an Arc-backed handle, so the stored copy shares state with the one
/// rendered in the menu.
pub struct MenuState {
    button_bar: CheckMenuItem<Wry>,
    broadcast_bar: CheckMenuItem<Wry>,
}

impl MenuState {
    pub fn new(button_bar: CheckMenuItem<Wry>, broadcast_bar: CheckMenuItem<Wry>) -> Self {
        Self {
            button_bar,
            broadcast_bar,
        }
    }
}

/// Build the application menu, install it app-wide, and return the checkable
/// View menu handles (Button Bar, Broadcast Input) for the caller to `manage`
/// via [`MenuState`]. Called once from `setup`. Both start unchecked; the
/// frontend syncs the real values on load.
pub fn install(app: &AppHandle) -> tauri::Result<(CheckMenuItem<Wry>, CheckMenuItem<Wry>)> {
    // "About Transit" — native panel on macOS, custom `menu:about`
    // emitter elsewhere (see MENU_ID_ABOUT). `PredefinedMenuItem::about`
    // and `MenuItem` differ in type but both implement `IsMenuItem`, so
    // the builder is assembled step-by-step under a cfg split.
    let mut app_menu = SubmenuBuilder::new(app, "Transit Community Edition");
    #[cfg(target_os = "macos")]
    {
        app_menu = app_menu.item(&PredefinedMenuItem::about(app, None, None)?);
    }
    #[cfg(not(target_os = "macos"))]
    {
        app_menu =
            app_menu.item(&MenuItemBuilder::with_id(MENU_ID_ABOUT, "About Transit").build(app)?);
    }
    app_menu = app_menu.separator();
    // hide / hide_others / show_all are macOS NSApplication concepts. On
    // macOS they're reversible (Dock, Cmd-Tab, Show All). On Windows/Linux
    // there is NO restore path — muda's `hide` calls ShowWindow(SW_HIDE),
    // which (with no tray icon) orphans the window: the process keeps
    // running but the window is unreachable, forcing a Task-Manager kill to
    // recover (user report, Windows Server 2019). So they are macOS-only;
    // Windows/Linux get just About + Exit and rely on normal window
    // minimize/restore. DO NOT re-add these off macOS.
    #[cfg(target_os = "macos")]
    {
        app_menu = app_menu
            .item(&PredefinedMenuItem::hide(app, None)?)
            .item(&PredefinedMenuItem::hide_others(app, None)?)
            .item(&PredefinedMenuItem::show_all(app, None)?)
            .separator();
    }
    let app_menu = app_menu
        .item(&PredefinedMenuItem::quit(app, None)?)
        .build()?;

    // Edit menu — keeps Cmd+C / Cmd+V / Cmd+Z working in the webview's text
    // inputs (chat box, dialogs) now that we own the menu.
    let edit_menu = SubmenuBuilder::new(app, "Edit")
        .item(&PredefinedMenuItem::undo(app, None)?)
        .item(&PredefinedMenuItem::redo(app, None)?)
        .separator()
        .item(&PredefinedMenuItem::cut(app, None)?)
        .item(&PredefinedMenuItem::copy(app, None)?)
        .item(&PredefinedMenuItem::paste(app, None)?)
        .item(&PredefinedMenuItem::select_all(app, None)?)
        .build()?;

    let button_bar = CheckMenuItemBuilder::with_id(MENU_ID_BUTTON_BAR, "Button Bar")
        .checked(false)
        .build(app)?;

    // CmdOrCtrl+Shift+K — NOT +K (that's the command palette, hotkeys.ts);
    // Shift disambiguates it from the palette.
    //
    // This accelerator only fires the menu on macOS, where the global menu
    // bar gets the keystroke first. On Windows/Linux the focused WebView2
    // swallows menu accelerators, so the real keyboard handling lives in the
    // webview (hotkeys.ts + TerminalPane's xterm key handler) — which also
    // has to stop xterm from translating Ctrl+Shift+K into 0x0B and sending
    // it to the PTY (it computes the control byte as keyCode-64 regardless of
    // Shift, i.e. the same byte as Ctrl+K / kill-line). The menu item is kept
    // for discoverability, mouse access, and the macOS shortcut hint; clicking
    // it emits `menu:clear-terminal` on every platform.
    let clear_terminal = MenuItemBuilder::with_id(MENU_ID_CLEAR_TERMINAL, "Clear Terminal")
        .accelerator("CmdOrCtrl+Shift+K")
        .build(app)?;

    let broadcast_bar = CheckMenuItemBuilder::with_id(MENU_ID_BROADCAST_BAR, "Broadcast Input")
        .checked(false)
        .build(app)?;

    let view_menu = SubmenuBuilder::new(app, "View")
        .item(&button_bar)
        .item(&broadcast_bar)
        .item(&clear_terminal)
        .build()?;

    // Static items only — a DYNAMIC list of open sessions here would mean
    // rebuilding the native menu on every session open/close/rename, so
    // the palette owns the list and the menu just opens it. Like Clear
    // Terminal above, the accelerator fires the menu on macOS only; the
    // webview handles Cmd/Ctrl+K itself (hotkeys.ts) on every platform.
    let jump_to_session =
        MenuItemBuilder::with_id(MENU_ID_JUMP_TO_SESSION, "Jump to Session\u{2026}")
            .accelerator("CmdOrCtrl+K")
            .build(app)?;
    let sort_tabs =
        MenuItemBuilder::with_id(MENU_ID_SORT_TABS, "Sort Tabs Alphabetically").build(app)?;

    let window_menu = SubmenuBuilder::new(app, "Window")
        .item(&PredefinedMenuItem::minimize(app, None)?)
        .item(&PredefinedMenuItem::maximize(app, None)?)
        .separator()
        .item(&jump_to_session)
        .item(&sort_tabs)
        .separator()
        .item(&PredefinedMenuItem::close_window(app, None)?)
        .build()?;

    let menu = MenuBuilder::new(app)
        .items(&[&app_menu, &edit_menu, &view_menu, &window_menu])
        .build()?;

    app.set_menu(menu)?;

    Ok((button_bar, broadcast_bar))
}

/// Frontend → native sync: reflect a checkable menu item's state. Driven by
/// the frontend's `useNativeMenu` effect whenever the mirrored pref changes
/// (menu click, the bar's own hide, or the initial load).
#[tauri::command]
pub fn set_menu_checked(
    id: String,
    checked: bool,
    menu_state: State<'_, MenuState>,
) -> Result<(), String> {
    if id == MENU_ID_BUTTON_BAR {
        menu_state
            .button_bar
            .set_checked(checked)
            .map_err(|e| e.to_string())?;
    } else if id == MENU_ID_BROADCAST_BAR {
        menu_state
            .broadcast_bar
            .set_checked(checked)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three custom menu ids must stay distinct and non-empty — a
    /// copy-paste collision would route two menu items to the same
    /// `on_menu_event` branch (e.g. About accidentally toggling the
    /// button bar). The frontend `menu.ts` mirrors these strings.
    #[test]
    fn menu_ids_are_distinct_and_nonempty() {
        let ids = [
            MENU_ID_BUTTON_BAR,
            MENU_ID_BROADCAST_BAR,
            MENU_ID_CLEAR_TERMINAL,
            MENU_ID_ABOUT,
            MENU_ID_JUMP_TO_SESSION,
            MENU_ID_SORT_TABS,
        ];
        for id in ids {
            assert!(!id.is_empty(), "menu id must not be empty");
        }
        assert_eq!(
            ids.len(),
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            "menu ids must be unique"
        );
    }
}
